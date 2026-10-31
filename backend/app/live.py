"""Odyssey Live: the system running continuously, not a static build.

Every tick (5 s) the engine
  - reads the national decoy grid and enterprise firewall flows (SIM, accelerated: one tick is one sensor-hour) and
    runs detectors on them: the pipeline's surge rule (robust z on sessions AND unique sources, breadth across
    sensors), RITA-style beacon periodicity, and an IsolationForest over per-host flow features;
  - turns detections into actions through the same graduated-autonomy policy as the pipeline (the Autopilot):
    evidence of compromise acts at once (notice, CERT-In draft, hunt, SOC incident case), sensor-only early warnings
    and regulator escalations wait for an analyst;
  - samples host telemetry, so every chart has history even when nobody is watching.
Every 15 minutes it re-reads the small real feeds (CISA KEV, abuse.ch Feodo Tracker C2s, OpenPhish) when the network
is up, matches anything new against the inventory and reports each feed's freshness; if the network is down the
feeds say so and the snapshot keeps serving.
Attack drills (scanning surge, implant beacon, full intrusion chain) inject DRILL-labelled traffic, so anyone can
watch detection and response end to end and read the time to detect. Everything lands in the hash-chained ledger
and reaches every open screen through the live stream.
"""

from __future__ import annotations

import asyncio
import collections
import datetime as dt
import json
import math
import random
import sqlite3
import statistics
import threading
import time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
TICK_S = 5.0
BASELINE = 72            # ticks (sensor-hours) behind every z-score
FEED_EVERY_S = 900
FEEDS = {
    "CISA KEV": ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "kev.json"),
    "abuse.ch Feodo Tracker": ("https://feodotracker.abuse.ch/downloads/ipblocklist.json", "feodo_ipblocklist.json"),
    "OpenPhish": ("https://openphish.com/feed.txt", "openphish.txt"),
}
DRILLS = {
    "scan": {"title": "Mass scanning of Fortinet FortiGate", "tag": "fortios",
             "what": "Scanners hit FortiGate SSL-VPN decoys across the grid. Expect a surge detection and an early-warning "
                     "proposal that waits for you."},
    "beacon": {"title": "Implant beaconing to a known C2", "tag": None,
               "what": "An exposed FortiGate at one of our operators starts calling a real Feodo Tracker C2 every 60 s. "
                       "Expect a compromise notice, a CERT-In draft, a hunt and an incident case, with no human needed."},
    "chain": {"title": "Full intrusion: scan, implant, lateral movement", "tag": "fortios",
              "what": "Scanning, then an implant on an exposed FortiGate, then the host sweeping the internal network. "
                      "Expect all three detectors to fire in order."},
}


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def _pois(rng: random.Random, lam: float) -> int:
    if lam > 60:
        return max(0, int(rng.gauss(lam, lam ** 0.5)))
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _robust_z(x: float, history: list[float]) -> float:
    med = statistics.median(history)
    mad = statistics.median(abs(h - med) for h in history) or 1.0
    return (x - med) / (1.4826 * mad)


class Live:
    def __init__(self, connect: Callable[[], sqlite3.Connection]):
        from .sim import telemetry as simtel
        self.connect, self.simtel = connect, simtel
        self.rng = random.Random(20261101)
        self.lock = threading.RLock()
        self.started = dt.datetime.now(dt.timezone.utc)
        self.ticks = 0
        self.last_tick: str | None = None
        self.tick_ms: collections.deque = collections.deque(maxlen=120)
        world = json.loads((ROOT / "data" / "sim" / "world.json").read_text(encoding="utf-8"))
        self.orgs = {o["id"]: o for o in world["orgs"]}
        self.assets = {a["id"]: a for a in world["assets"]}
        self.labels = {}
        for a in self.assets.values():
            self.labels.setdefault(a["product_key"], a["label"])
        self.internal = [a for a in self.assets.values() if a["zone"] == "internal"]
        self.internal_ips = {a["ip"] for a in self.internal}
        self.infra = sorted(self.internal, key=lambda a: a["id"])[:3]  # stand-ins for DNS, directory and file servers
        # sensor history per tag: (tick, sessions, ips, z_sessions, z_ips, hot sensors)
        self.series = {tag: collections.deque(maxlen=BASELINE) for tag in simtel.TAGS}
        self.sensor_hist = {(tag, s): collections.deque(maxlen=BASELINE) for tag in simtel.TAGS for s in simtel.SENSORS}
        self.flows: collections.deque = collections.deque(maxlen=6000)
        self.flow_counts: collections.deque = collections.deque(maxlen=BASELINE)
        self.detections: collections.deque = collections.deque(maxlen=60)
        self.cooldown: dict[str, int] = {}
        self.feeds: dict[str, dict] = {n: {"name": n, "url": u, "mode": "live", "status": "waiting", "last_try": None,
                                          "last_ok": None, "items": None, "new": None, "matched": [], "ms": None,
                                          "detail": "first check shortly after start"} for n, (u, _) in FEEDS.items()}
        self.next_feed = time.time() + 8
        self.drill: dict | None = None
        self.drills: collections.deque = collections.deque(maxlen=12)
        self.forest = None
        self._task: asyncio.Task | None = None
        self.sensor_clock = dt.datetime(2026, 11, 1, 0, 0, tzinfo=dt.timezone.utc)
        for _ in range(BASELINE):  # warm start: a full baseline, so detection works from the first tick
            self._sensors(None, record=True)
            self._flows(None)
        self._fit_forest()

    # ------------------------------------------------------------------ simulated sensors (SIM, accelerated)
    def _sensors(self, drill: dict | None, record: bool = True) -> dict[str, dict]:
        out = {}
        hour = self.sensor_clock.hour
        diurnal = 1.0 + 0.08 * math.sin((hour - 6) / 24 * 2 * math.pi)  # internet scanning is nearly flat over a day
        for tag, (base_s, base_ip) in self.simtel.TAGS.items():
            boosted = set(drill["sensors"]) if drill and drill.get("scan_ticks", 0) > 0 and drill.get("tag") == tag else set()
            per, ips = {}, 0
            for s in self.simtel.SENSORS:
                m_s, m_i = (6.0, 4.0) if s in boosted else (1.0, 1.0)
                per[s] = _pois(self.rng, base_s / 24 * diurnal * m_s)
                ips += _pois(self.rng, base_ip / 24 * diurnal * m_i)
            total = sum(per.values())
            hist = list(self.series[tag])
            zs = _robust_z(total, [h["sessions"] for h in hist]) if len(hist) >= 24 else 0.0
            zi = _robust_z(ips, [h["ips"] for h in hist]) if len(hist) >= 24 else 0.0
            hot = [s for s, n in per.items() if n >= 4 and n > 3 * statistics.median(self.sensor_hist[(tag, s)] or [n])]
            row = {"tick": self.ticks, "sessions": total, "ips": ips, "z": round(zs, 1), "zi": round(zi, 1), "hot": len(hot),
                   "drill": bool(boosted)}
            out[tag] = row
            if record:
                self.series[tag].append(row)
                for s, n in per.items():
                    self.sensor_hist[(tag, s)].append(n)
        self.sensor_clock += dt.timedelta(hours=1)
        return out

    # ------------------------------------------------------------------ simulated firewall flows (SIM)
    def _flows(self, drill: dict | None) -> list[dict]:
        t0 = self.sensor_clock - dt.timedelta(hours=1)
        rows = []
        for a in self.rng.sample(self.internal, min(45, len(self.internal))):
            if self.rng.random() < 0.6:
                srv = self.infra[self.rng.randrange(len(self.infra))]
                for _ in range(1 + _pois(self.rng, 1.0)):
                    rows.append({"ts": (t0 + dt.timedelta(seconds=self.rng.uniform(0, 3600))).isoformat().replace("+00:00", "Z"),
                                 "src": a["ip"], "dst": srv["ip"], "dport": self.rng.choice([53, 88, 445]),
                                 "bytes": int(self.rng.lognormvariate(7, 0.8))})
            for _ in range(_pois(self.rng, 3.0)):
                rows.append({"ts": (t0 + dt.timedelta(seconds=self.rng.uniform(0, 3600))).isoformat().replace("+00:00", "Z"),
                             "src": a["ip"], "dst": f"198.18.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}",
                             "dport": self.rng.choice([443, 443, 443, 80, 53, 123]),
                             "bytes": int(self.rng.lognormvariate(8, 1.0))})
        if drill and drill.get("beacon_ticks", 0) > 0:
            victim, c2 = self.assets[drill["victim"]], drill["c2"]
            t = t0 + dt.timedelta(seconds=self.rng.uniform(0, 20))
            while t < t0 + dt.timedelta(hours=1):
                rows.append({"ts": t.isoformat().replace("+00:00", "Z"), "src": victim["ip"], "dst": c2["ip"],
                             "dport": c2["port"], "bytes": int(self.rng.gauss(310, 12))})
                t += dt.timedelta(seconds=60 * self.rng.uniform(0.9, 1.1))
        if drill and drill.get("lateral_ticks", 0) > 0:
            victim = self.assets[drill["victim"]]
            for b in self.rng.sample(self.internal, min(60, len(self.internal))):
                rows.append({"ts": (t0 + dt.timedelta(seconds=self.rng.uniform(0, 600))).isoformat().replace("+00:00", "Z"),
                             "src": victim["ip"], "dst": b["ip"], "dport": 445, "bytes": int(self.rng.lognormvariate(11, 0.5))})
        rows.sort(key=lambda r: r["ts"])
        self.flows.extend(rows)
        self.flow_counts.append(len(rows))
        return rows

    def _features(self, rows: list[dict]) -> dict[str, list[float]]:
        """Per host and sensor-hour: connections, distinct destinations, distinct internal destinations (fan-out),
        distinct ports, bytes sent (log)."""
        by: dict[str, list[dict]] = collections.defaultdict(list)
        for r in rows:
            by[r["src"]].append(r)
        return {src: [math.log1p(len(rs)), len({r["dst"] for r in rs}),
                      len({r["dst"] for r in rs if r["dst"] in self.internal_ips}), len({r["dport"] for r in rs}),
                      math.log1p(sum(r["bytes"] for r in rs))] for src, rs in by.items()}

    FEATURES = ["connections (log)", "destinations", "internal destinations", "ports", "bytes sent (log)"]

    def _fit_forest(self, hours: int = 240) -> None:
        """Train on ten sensor-days of ordinary traffic (per host and hour). An IsolationForest scores how unusual a
        host-hour is; because its scores saturate beyond the training range, an alert also needs one feature far
        outside its robust baseline (z >= 6) among fan-out, ports and bytes, which is also the reason shown."""
        from sklearn.ensemble import IsolationForest
        X = [f for _ in range(hours) for f in self._features(self._flows(None)).values()]
        self.forest = IsolationForest(n_estimators=200, random_state=7).fit(X)
        scores = sorted(self.forest.decision_function(X))
        self.forest_threshold = float(scores[len(scores) // 1000])
        cols = list(zip(*X))
        self.feature_med = [statistics.median(c) for c in cols]
        self.feature_mad = [statistics.median(abs(v - m) for v in c) * 1.4826 or 1.0 for c, m in zip(cols, self.feature_med)]
        self.forest_trained_on = len(X)

    GATE = (2, 3, 4)  # fan-out, ports, bytes: what lateral movement and exfiltration change; busy browsing does not

    def _reason(self, f: list[float]) -> tuple[float, str]:
        zs = {i: (f[i] - self.feature_med[i]) / self.feature_mad[i] for i in self.GATE}
        i = max(zs, key=zs.get)
        return zs[i], self.FEATURES[i]

    # ------------------------------------------------------------------ one tick
    def tick(self) -> None:
        started = time.perf_counter()
        from . import telemetry
        from .engine import detectors
        now = dt.datetime.now(dt.timezone.utc)
        with self.lock:
            self.ticks += 1
            drill = self.drill
            readings = self._sensors(drill)
            rows = self._flows(drill)
            window = [r for r in self.flows if r["ts"] >= (self.sensor_clock - dt.timedelta(hours=2)).isoformat().replace("+00:00", "Z")]
        telemetry.host()
        found: list[dict] = []
        for tag, r in readings.items():
            if r["z"] >= 4 and r["zi"] >= 3 and r["hot"] >= 3 and self.cooldown.get(f"surge:{tag}", -99) < self.ticks - 24:
                self.cooldown[f"surge:{tag}"] = self.ticks
                found.append({"kind": "surge", "tag": tag, **r})
        for b in detectors.detect_beacons(window, min_conns=30, max_cv=0.2):
            key = f"beacon:{b['src']}>{b['dst']}"
            if self.cooldown.get(key, -99) < self.ticks - 60:
                self.cooldown[key] = self.ticks
                found.append({"kind": "beacon", **b})
        # flows already explained by a beacon are not evidence of anything else
        beacon_pairs = {(f["src"], f["dst"]) for f in found if f["kind"] == "beacon"} | {
            tuple(k.split(":", 1)[1].split(">")) for k, v in self.cooldown.items() if k.startswith("beacon:") and v >= self.ticks - 3}
        if self.forest is not None:
            feats = self._features([r for r in rows if (r["src"], r["dst"]) not in beacon_pairs])
            srcs = list(feats)
            if srcs:
                scores = self.forest.decision_function([feats[s] for s in srcs])
                for s, sc in zip(srcs, scores):
                    z, why = self._reason(feats[s])
                    if sc < self.forest_threshold and z >= 6 and self.cooldown.get(f"anomaly:{s}", -99) < self.ticks - 60:
                        self.cooldown[f"anomaly:{s}"] = self.ticks
                        f = feats[s]
                        found.append({"kind": "anomaly", "src": s, "score": round(float(sc), 3), "z": round(z, 1), "why": why,
                                      "connections": int(round(math.expm1(f[0]))), "destinations": int(f[1]),
                                      "internal": int(f[2]), "ports": int(f[3])})
        if found:
            conn = self.connect()
            try:
                for f in found:
                    self._act(conn, f, now, drill)
            finally:
                conn.close()
        with self.lock:
            self._advance_drill(now)
        if time.time() >= self.next_feed:
            self.next_feed = time.time() + FEED_EVERY_S
            self._check_feeds(now)
        self.last_tick = _iso(now)
        self.tick_ms.append(round((time.perf_counter() - started) * 1000, 1))

    # ------------------------------------------------------------------ detections -> actions (graduated autonomy)
    def _pilot(self, conn, now):
        from .engine.ledger import Ledger
        from .engine.scoring import config
        from .engine.sentinel import Autopilot
        return Autopilot(conn, Ledger(conn=conn), config()[0], self.orgs, self.assets, now=now)

    def _detected(self, conn, now, kind: str, subject: str, title: str, payload: dict, drill: dict | None) -> dict:
        from .engine.ledger import Ledger
        seconds = round((now - dt.datetime.fromisoformat(drill["started_at"])).total_seconds(), 1) if drill else None
        det = {"id": f"DET-{self.ticks:05d}-{len(self.detections) + 1}", "ts": _iso(now), "kind": kind, "title": title,
               "drill": drill["id"] if drill else None, "seconds_to_detect": seconds, **payload}
        Ledger(conn=conn).append(ts=_iso(now), kind=f"live.detect.{kind}", subject=subject, source="DETECTOR",
                                 provenance="SIM", payload={k: v for k, v in det.items() if k not in ("id",)})
        conn.commit()
        with self.lock:
            self.detections.appendleft(det)
            if drill and kind not in drill["detected"]:
                drill["detected"][kind] = {"at": _iso(now), "seconds": seconds}
        return det

    def _act(self, conn, f: dict, now: dt.datetime, drill: dict | None) -> None:
        tag_drill = {"drill": drill["id"]} if drill else {}
        if f["kind"] == "surge":
            tag, label = f["tag"], self.labels.get(f["tag"], f["tag"])
            running = [a for a in self.assets.values() if a["product_key"] == tag]
            orgs = sorted({a["org_id"] for a in running})
            self._detected(conn, now, "surge", f"product:{tag}",
                           f"Scanning surge against {label} on {f['hot']} decoy sensors (z = {f['z']})",
                           {"product": label, "z": f["z"], "z_sources": f["zi"], "sensors": f["hot"],
                            "sessions": f["sessions"], "orgs_exposed": len(orgs)}, drill)
            pilot = self._pilot(conn, now)
            group = f"live-warn:{tag}:{_iso(now)}"
            for org_id in orgs:
                n = sum(a["org_id"] == org_id for a in running)
                pilot.emit(now, "warn", f"product:{tag}", org_id=org_id, product=label, channels=["email"], z=f["z"],
                           sensors=f["hot"], assets=n, basis="live decoy-grid scanning surge", provenance="SIM",
                           group=group, **tag_drill,
                           proposal=f"Send an early warning on the live {label} scanning surge to {len(orgs)} organisation(s)",
                           title=f"Early warning: coordinated scanning of {label} on {f['hot']} national decoy sensors "
                                 f"right now (z={f['z']}). No CVE yet; {n} of your assets run it.",
                           actions=["Restrict management interfaces to trusted networks",
                                    "Run the vendor's integrity checker and keep logs for 90 days",
                                    "Pre-stage the vendor's emergency patch process"])
            pilot.flush()
            conn.commit()
        elif f["kind"] == "beacon":
            asset = next((a for a in self.assets.values() if a["ip"] == f["src"]), None)
            if not asset:
                return
            org = self.orgs[asset["org_id"]]
            c2 = f["dst"].replace(".", "[.]")
            self._detected(conn, now, "beacon", asset["id"],
                           f"{asset['hostname']} is beaconing to C2 {c2} every {f['mean_interval_s']:.0f} s",
                           {"asset": asset["hostname"], "org_id": org["id"], "c2": c2, "interval_s": f["mean_interval_s"],
                            "cv": f["cv"], "connections": f["connections"]}, drill)
            pilot = self._pilot(conn, now)
            alert = f"{org['id']}:{asset['id']}"
            to = ["CERT-In incident response desk"] + pilot.csirt(org)
            common = {"org_id": org["id"], "alert": alert, "asset": asset["hostname"], "c2": c2,
                      "basis": "live C2 beacon detector", "provenance": "SIM", **tag_drill}
            pilot.emit(now, "notify", alert, **common, tier="Compromise", channels=["phone", "secure-email"],
                       title=f"Suspected compromise: {asset['hostname']} ({asset['label']}) is calling C2 {c2} every "
                             f"{f['mean_interval_s']:.0f} s. Isolate it now and keep it powered for forensics; the "
                             f"CERT-In 6-hour reporting clock has started.")
            pilot.emit(now + dt.timedelta(minutes=1), "report", alert, **common, channels=[],
                       title=f"CERT-In incident report drafted for {asset['hostname']} from the live evidence "
                             f"(fields pre-filled, awaiting analyst sign-off).")
            others = {r["src"] for r in self.flows if r["dst"] == f["dst"]} - {f["src"]}
            pilot.emit(now + dt.timedelta(minutes=2), "hunt", alert, **common, channels=[], hits=1 + len(others),
                       assets_scanned=len(self.assets), orgs_scanned=len(self.orgs),
                       title=f"Hunt: swept {len(self.assets)} assets in {len(self.orgs)} organisations for C2 {c2}: "
                             f"{1 + len(others)} hit(s).")
            pilot.emit(now + dt.timedelta(minutes=2), "escalate", alert, **common, tier="Compromise", recipients=to,
                       channels=["secure-email"],
                       proposal=f"Report the suspected compromise of {asset['hostname']} to {', '.join(to)}",
                       title=f"Escalated to {', '.join(to)}: suspected compromise of {asset['hostname']} (live C2 "
                             f"beacon to {c2}).")
            pilot.flush()
            rescored = self._rescore(conn, asset, f, now, drill)
            from .engine import soc
            case = soc.open_case(conn, "incident", f"Suspected compromise of {asset['hostname']} ({asset['label']})",
                                 org["id"], "Compromise", "m.khan", 6, [f"{org['id']}:{x['cve']}" for x in rescored],
                                 asset["label"], [asset["hostname"]],
                                 f"Opened automatically by the live C2 beacon detector{' during ' + drill['id'] if drill else ''}: "
                                 f"{f['connections']} connections to {c2}, every {f['mean_interval_s']:.0f} s (cv {f['cv']}). "
                                 f"{len(rescored)} warning(s) on this host re-scored to suspected compromise.")
            with self.lock:
                if drill:
                    drill["case"] = case["id"]
                    drill["rescored"] = len(rescored)
        elif f["kind"] == "anomaly":
            asset = next((a for a in self.assets.values() if a["ip"] == f["src"]), None)
            if not asset:
                return
            self._detected(conn, now, "anomaly", asset["id"],
                           f"Unusual traffic from {asset['hostname']}: {f['connections']} connections to "
                           f"{f['destinations']} destinations, {f['internal']} of them internal",
                           {"asset": asset["hostname"], "org_id": asset["org_id"], "score": f["score"],
                            "connections": f["connections"], "destinations": f["destinations"],
                            "internal": f["internal"], "ports": f["ports"], "z": f["z"], "why": f["why"]}, drill)
            pilot = self._pilot(conn, now)
            pilot.emit(now, "hunt", f"{asset['org_id']}:{asset['id']}", org_id=asset["org_id"], asset=asset["hostname"],
                       channels=[], basis="IsolationForest flow anomaly", provenance="SIM", **tag_drill,
                       title=f"Hunt: {asset['hostname']} reached {f['internal']} internal hosts on {f['ports']} "
                             f"port(s) in one hour, unlike anything in its baseline (possible lateral movement). "
                             f"Its peers were added to the sweep.")
            pilot.flush()
            conn.commit()

    def _rescore(self, conn, asset: dict, f: dict, now: dt.datetime, drill: dict | None) -> list[dict]:
        """Live re-scoring: a C2 beacon from a host is new evidence for every warning on it. Each is re-decided now,
        through the same Bayesian model with the beacon observed, instead of waiting for the next build; the clock of
        a new suspected compromise starts at detection."""
        from .engine.bayes import posterior
        from .engine.ledger import Ledger
        from .engine.scoring import config
        cfg = config()[0]
        conn.execute("CREATE TABLE IF NOT EXISTS live_issued (alert_id TEXT PRIMARY KEY, issued_at TEXT NOT NULL)")
        rows = conn.execute("SELECT cve_id, org_id, R, tier, detail FROM assessments WHERE asset_id = ? AND R > 0",
                            (asset["id"],)).fetchall()
        changed = []
        for cve, org_id, R, tier, detail in rows:
            d = json.loads(detail)
            if tier == "Compromise":
                continue
            exploited = any(r.get("id") in ("KEV", "SSVC_ACTIVE", "DECOY_EXPLOIT", "ITW_CLAIM") for r in d.get("rules", []))
            b = posterior(cfg, exposed=R >= 0.6, exploited=exploited, internet=asset["zone"] == "internet", beacon=True)
            if b["decision"] != "compromised":
                continue
            comp = cfg["compromise"]
            d.update(tier=comp["tier"], decision="Act", deadline_hours=comp["deadline_hours"],
                     deadline_basis=comp["basis"], bayes=b, live=True)
            d["rules"] = d.get("rules", []) + [{
                "id": "IOC_SIGHTING", "crit": 4, "text": "Own telemetry: periodic beacon to a known C2 address",
                "evidence": f"{f['connections']} connections every ~{f['mean_interval_s']:.0f}s, detected live"
                            + (f" ({drill['id']})" if drill else ""), "source": "SIM_LOGS"}]
            d["decision_path"] = d.get("decision_path", []) + [
                f"Live re-score: Bayesian model with the beacon observed: P(compromise) = {b['p_compromise']:.1%} "
                f">= {cfg['bayes']['threshold_compromise']:.0%} -> suspected compromise"]
            conn.execute("UPDATE assessments SET tier = ?, decision = ?, deadline_hours = ?, detail = ? "
                         "WHERE asset_id = ? AND cve_id = ?",
                         (comp["tier"], "Act", comp["deadline_hours"], json.dumps(d), asset["id"], cve))
            conn.execute("INSERT OR REPLACE INTO live_issued VALUES (?, ?)", (f"{org_id}:{cve}", _iso(now)))
            changed.append({"cve": cve, "from": tier, "to": comp["tier"], "p": round(b["p_compromise"], 3)})
        if changed:
            Ledger(conn=conn).append(ts=_iso(now), kind="live.rescore", subject=asset["id"], source="ODYSSEY",
                                     provenance="AUTO", payload={"org_id": asset["org_id"], "asset": asset["hostname"],
                                                                 "changed": changed, "drill": drill["id"] if drill else None,
                                                                 "title": f"{len(changed)} warning(s) on {asset['hostname']} "
                                                                          f"re-scored to suspected compromise"})
        conn.commit()
        return changed

    # ------------------------------------------------------------------ drills
    def start_drill(self, scenario: str) -> dict:
        if scenario not in DRILLS:
            raise KeyError(scenario)
        with self.lock:
            if self.drill and self.drill["status"] == "running":
                raise ValueError(f"{self.drill['id']} is still running")
            spec = DRILLS[scenario]
            now = dt.datetime.now(dt.timezone.utc)
            self.n_drills = getattr(self, "n_drills", 0) + 1
            n = self.n_drills
            # every drill gets its own exposed host and C2, so no traffic left over from an earlier drill counts
            exposed = sorted((a for a in self.assets.values() if a["product_key"] == "fortios" and a["zone"] in ("internet", "dmz")),
                             key=lambda a: (not a["org_id"].startswith("PWR"), a["id"]))
            victim = exposed[(n - 1) % len(exposed)]
            c2s = [dict(self.simtel.C2)] + [{"ip": x["ip_address"], "port": x["port"], "malware": x["malware"],
                                            "source": "Feodo Tracker (abuse.ch)"} for x in self._feodo()]
            c2 = c2s[(n - 1) % len(c2s)]
            self.cooldown.pop(f"surge:{spec['tag']}", None)  # product-level: judged afresh for each drill
            self.drill = {"id": f"DRILL-{now:%H%M%S}-{n}", "scenario": scenario, "title": spec["title"], "what": spec["what"],
                          "status": "running", "started_at": _iso(now), "tick0": self.ticks, "tag": spec["tag"],
                          "sensors": self.rng.sample(self.simtel.SENSORS, 9), "victim": victim["id"],
                          "victim_host": victim["hostname"], "victim_org": self.orgs[victim["org_id"]]["name"],
                          "c2": c2, "scan_ticks": 4 if scenario in ("scan", "chain") else 0,
                          "beacon_ticks": 3 if scenario == "beacon" else 0, "lateral_ticks": 0,
                          "detected": {}, "case": None, "expect": {"scan": ["surge"], "beacon": ["beacon"],
                                                                     "chain": ["surge", "beacon", "anomaly"]}[scenario]}
            from .engine.ledger import Ledger
            conn = self.connect()
            try:
                Ledger(conn=conn).append(ts=_iso(now), kind="live.drill.start", subject=self.drill["id"], source="ANALYST",
                                         provenance="HUMAN", payload={k: self.drill[k] for k in ("scenario", "title", "victim_host")})
                conn.commit()
            finally:
                conn.close()
            return dict(self.drill)

    @staticmethod
    def _feodo() -> list[dict]:
        p = ROOT / "data" / "raw" / "feodo_ipblocklist.json"
        try:
            return [x for x in json.loads(p.read_text(encoding="utf-8")) if x.get("ip_address")]
        except (OSError, ValueError):
            return []

    def _advance_drill(self, now: dt.datetime) -> None:
        d = self.drill
        if not d or d["status"] != "running":
            return
        for k in ("scan_ticks", "beacon_ticks", "lateral_ticks"):
            if d[k] > 0:
                d[k] -= 1
        age = self.ticks - d["tick0"]
        if d["scenario"] == "chain":
            if age == 4 and "beacon" not in d["detected"]:
                d["beacon_ticks"] = 3
            if "beacon" in d["detected"] and not d.get("lateral_started"):
                d["lateral_started"], d["lateral_ticks"] = True, 2
        done = all(k in d["detected"] for k in d["expect"])
        if done or age > 20:
            d["status"] = "passed" if done else "missed"
            d["ended_at"] = _iso(now)
            d["seconds"] = round((now - dt.datetime.fromisoformat(d["started_at"])).total_seconds(), 1)
            self.drills.appendleft(dict(d))
            from .engine.ledger import Ledger
            conn = self.connect()
            try:
                Ledger(conn=conn).append(ts=_iso(now), kind="live.drill.end", subject=d["id"], source="DETECTOR",
                                         provenance="SIM", payload={"status": d["status"], "detected": d["detected"],
                                                                    "case": d["case"], "seconds": d["seconds"]})
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------ real feeds (passive, public)
    def _check_feeds(self, now: dt.datetime) -> None:
        import httpx
        for name, (url, snap) in FEEDS.items():
            f = self.feeds[name]
            f["last_try"] = _iso(now)
            t0 = time.perf_counter()
            try:
                r = httpx.get(url, timeout=25, follow_redirects=True, headers={"User-Agent": "Odyssey-EWS/0.2 (research)"})
                r.raise_for_status()
                f["ms"] = round((time.perf_counter() - t0) * 1000)
                f.update(self._read_feed(name, r, ROOT / "data" / "raw" / snap))
                f["status"], f["last_ok"] = "fresh", _iso(now)
            except Exception as exc:  # noqa: BLE001 - a feed outage is reported, never fatal
                f["status"], f["detail"] = "offline", f"{type(exc).__name__}: {str(exc)[:120]}; serving the snapshot"

    def _read_feed(self, name: str, r, snap: Path) -> dict:
        if name == "CISA KEV":
            data = r.json()["vulnerabilities"]
            known = {v["cveID"] for v in json.loads(snap.read_text(encoding="utf-8"))["vulnerabilities"]} if snap.exists() else set()
            new = [v for v in data if v["cveID"] not in known]
            from .engine.products import same_product
            matched = []
            for v in new:
                hit = [a for a in self.assets.values()
                       if same_product(a["vendor"], a["product"], v["vendorProject"], v["product"])]
                if hit:
                    matched.append({"cve": v["cveID"], "product": f"{v['vendorProject']} {v['product']}",
                                    "vendor": v["vendorProject"], "name": v["product"],
                                    "orgs": len({a["org_id"] for a in hit}), "assets": len(hit), "added": v["dateAdded"]})
            if matched:
                self._kev_proposals(matched)
            return {"items": len(data), "new": len(new), "matched": matched,
                    "newest": max((v["dateAdded"] for v in data), default=None),
                    "detail": f"{len(new)} new since the snapshot; {len(matched)} touch the inventory"}
        if name == "abuse.ch Feodo Tracker":
            data = r.json()
            ips = {d["ip_address"] for d in data}
            seen = {x["dst"] for x in list(self.flows)} & ips
            return {"items": len(data), "new": None, "matched": sorted(seen),
                    "detail": f"{len(ips)} C2 addresses; {len(seen)} seen in the last hours of firewall flows"}
        lines = [x.strip() for x in r.text.splitlines() if x.strip()]
        from .engine.intel import lookalikes
        hosts = {x.split("/")[2].lower() for x in lines if "://" in x}
        hits = sorted({o["name"] for o in self.orgs.values()
                       if any(lab in h for lab in lookalikes(o["domain"]) for h in hosts)})
        return {"items": len(lines), "new": None, "matched": hits,
                "detail": f"{len(lines)} live phishing URLs; look-alikes of our organisations: {len(hits)}"}

    def _kev_proposals(self, matched: list[dict]) -> None:
        conn = self.connect()
        try:
            now = dt.datetime.now(dt.timezone.utc)
            done = {r[0] for r in conn.execute("SELECT subject FROM approvals WHERE kind = 'auto.warn' AND subject LIKE 'kev:%'")}
            pilot = self._pilot(conn, now)
            from .engine.products import same_product
            for m in matched:
                if f"kev:{m['cve']}" in done:
                    continue
                vendor, product = m["vendor"], m["name"]
                hit = [a for a in self.assets.values() if same_product(a["vendor"], a["product"], vendor, product)]
                for org_id in sorted({a["org_id"] for a in hit}):
                    n = sum(a["org_id"] == org_id for a in hit)
                    pilot.emit(now, "warn", f"kev:{m['cve']}", org_id=org_id, product=m["product"], cve_id=m["cve"],
                               assets=n, basis="CISA KEV (live)", provenance="REAL", group=f"kev:{m['cve']}",
                               channels=["email"],
                               proposal=f"Notify {m['orgs']} organisation(s): CISA now lists {m['cve']} ({m['product']}) "
                                        f"as exploited; installed versions not yet verified",
                               title=f"CISA lists {m['cve']} ({m['product']}) as exploited in the wild. {n} of your "
                                     f"assets run it: verify the installed version and patch.")
            pilot.flush()
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ status for the interface
    def status(self) -> dict:
        with self.lock:
            tags = [{"tag": t, "label": self.labels.get(t, t), "series": [{"s": r["sessions"], "z": r["z"], "d": r["drill"]}
                                                                         for r in list(s)[-48:]],
                     "z": s[-1]["z"] if s else 0, "sessions": s[-1]["sessions"] if s else 0}
                    for t, s in self.series.items()]
            per_tick = list(self.flow_counts)[-48:]
            drill = dict(self.drill) if self.drill else None
            return {
                "running": self._task is not None and not self._task.done(),
                "started_at": _iso(self.started), "ticks": self.ticks, "tick_s": TICK_S, "last_tick": self.last_tick,
                "tick_ms_p50": statistics.median(self.tick_ms) if self.tick_ms else None,
                "sensors": len(self.simtel.SENSORS), "tags": tags,
                "flows": {"per_tick": per_tick, "hosts": len(self.internal)},
                "detectors": [{"name": "Scanning surge", "how": "robust z on sessions and unique sources, breadth >= 3 sensors"},
                              {"name": "C2 beacon", "how": "periodicity: >= 30 connections, interval cv <= 0.2"},
                              {"name": "Flow anomaly", "how": "IsolationForest on per-host connections, destinations, ports, bytes"}],
                "detections": list(self.detections)[:30],
                "feeds": list(self.feeds.values()),
                "drill": drill, "drills": list(self.drills),
                "catalogue": [{"id": k, **{x: v[x] for x in ("title", "what")}} for k, v in DRILLS.items()],
            }

    # ------------------------------------------------------------------ the loop
    async def run(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.tick)
            except Exception as exc:  # noqa: BLE001 - the loop must survive any single bad tick
                print(f"live: tick failed: {exc!r}", flush=True)
            await asyncio.sleep(TICK_S)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self.run())


ENGINE: Live | None = None
