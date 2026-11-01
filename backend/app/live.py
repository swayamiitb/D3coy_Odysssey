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
    "SANS ISC DShield": ("https://isc.sans.edu/api/topports/records/50?json", "dshield/topports.json"),
    "CISA advisories": ("https://www.cisa.gov/cybersecurity-advisories/all.xml", "cisa_advisories.xml"),
}
# A feed's own cadence where the 15-minute cycle would be impolite or pointless: DShield's API is a community service
# and its port history is daily; CISA's advisory feed changes a few times a day. Everything else runs every cycle.
FEED_CADENCE_S = {"SANS ISC DShield": 3600, "CISA advisories": 3600}
DSHIELD_SOURCES = "https://isc.sans.edu/api/sources/attacks/100?json"
UA = "Odyssey-EWS/0.2 (D3COY 1.0 hackathon research; passive feed snapshot)"  # the same identification scripts/snapshot_feeds.py sends
STDLIB_FEEDS = {"CISA advisories"}  # read with the standard library, exactly as the snapshot script reads them


class _Fetched:
    """What _read_feed needs of a response, for a feed read with urllib instead of httpx."""

    def __init__(self, url: str, content: bytes):
        self.url, self.content = url, content

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.content)
DSHIELD_HISTORY_DAYS = 100  # enough for the 7-day-against-28-day-median trend and the port x day heatmap
DRILLS = {
    "scan": {"title": "Mass scanning of Fortinet FortiGate", "tag": "fortios",
             "what": "Scanners hit FortiGate SSL-VPN decoys across the grid. Expect a surge detection and an early-warning "
                     "proposal that waits for you."},
    "beacon": {"title": "Implant beaconing to a known C2", "tag": None,
               "what": "An exposed FortiGate at one of our operators starts calling a real Feodo Tracker C2 every 60 s. "
                       "Expect a compromise notice, a CERT-In draft, a hunt and an incident case, with no human needed."},
    "cve": {"title": "A new CVE is published for FortiGate", "tag": "fortios",
            "what": "A critical FortiOS CVE appears in NVD (simulated, exact NVD format, labelled DRILL). Expect it matched to "
                    "installed versions, scored and forecast within seconds, with notices sent to the exposed operators."},
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


def _write_snapshot(path: Path, body: bytes, url: str | None = None) -> None:
    """Write-through: a feed read live replaces its offline snapshot (atomically) and is noted in the manifest with the
    time it was taken, so every reader of data/raw (the aggregation table, the port trends and heatmaps, the threat
    maps, the organisation OSINT, the drills' C2 list) serves the fresh copy and can say how old it is. A failed or
    malformed read never reaches this point: the snapshot stands."""
    import hashlib
    import os
    raw = ROOT / "data" / "raw"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(body)
    os.replace(tmp, path)
    manifest = raw / "manifest.json"
    try:
        m = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {"items": []}
        rel = path.relative_to(raw).as_posix()
        items = m.setdefault("items", [])
        item = next((i for i in items if str(i.get("file", "")).replace("\\", "/") == rel), None)
        if item is None:
            item = {"file": rel, "url": url}
            items.append(item)
        item.update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), ok=True,
                    refreshed_at=dt.datetime.now().astimezone().isoformat(timespec="seconds"))
        if url and not item.get("url"):
            item["url"] = url
        tmp_m = manifest.with_name("manifest.json.tmp")
        tmp_m.write_text(json.dumps(m, indent=2), encoding="utf-8")
        os.replace(tmp_m, manifest)
    except (OSError, ValueError) as exc:
        print(f"live: manifest not updated for {path.name}: {exc!r}", flush=True)


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
                                          "every_s": FEED_CADENCE_S.get(n, FEED_EVERY_S), "next_at": 0.0,
                                          "detail": "first check shortly after start"} for n, (u, _) in FEEDS.items()}
        self.feeds["NVD (new CVEs)"] = {"name": "NVD (new CVEs)", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                                        "mode": "live", "status": "waiting", "last_try": None, "last_ok": None, "items": None,
                                        "new": None, "matched": [], "ms": None, "detail": "first check shortly after start"}
        manifest = ROOT / "data" / "raw" / "manifest.json"
        try:  # take in everything NVD changed since the offline snapshot, then only what is new
            self.nvd_since = dt.datetime.fromisoformat(json.loads(manifest.read_text(encoding="utf-8"))["snapshot_at"])
        except (OSError, ValueError, KeyError):
            self.nvd_since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
        self.nvd_since = max(self.nvd_since, dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7))
        self.kev_live: dict[str, dict] = {}
        self.intakes: collections.deque = collections.deque(maxlen=40)
        self.ioc_sets: dict[str, set[str]] = {"ipv4-addr": set(), "domain-name": set()}  # bulk-imported indicators, matched per tick
        self.next_feed = time.time() + 8
        self._feed_thread: threading.Thread | None = None
        self.drill: dict | None = None
        self.drills: collections.deque = collections.deque(maxlen=12)
        from .engine.adaptive import Adaptive
        self.adaptive = Adaptive(list(simtel.TAGS), list(self.orgs))
        self.ip_org = {a["ip"]: a["org_id"] for a in self.assets.values()}
        self.ip_asset = {a['ip']: a for a in self.assets.values()}
        self.forest = None
        self._task: asyncio.Task | None = None
        # the accelerated sensor clock (one tick = one sensor-hour) starts a full baseline behind the real clock
        self.sensor_clock = (dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
                             - dt.timedelta(hours=BASELINE))
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
            gate = self.adaptive.surge_z(tag)
            if r["z"] >= gate and r["zi"] >= 3 and r["hot"] >= 3 and self.cooldown.get(f"surge:{tag}", -99) < self.ticks - 24:
                self.cooldown[f"surge:{tag}"] = self.ticks
                found.append({"kind": "surge", "tag": tag, "threshold": gate, **r})
        for b in detectors.detect_beacons(window, min_conns=20, max_cv=0.2):
            key = f"beacon:{b['src']}>{b['dst']}"
            if b["connections"] < self.adaptive.beacon_min(self.ip_org.get(b["src"])):
                continue  # 30 connections, or 20 where the organisation already has a suspected compromise
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
                    gate = self.adaptive.anomaly_z(self.ip_org.get(s))
                    if sc < self.forest_threshold and z >= gate and self.cooldown.get(f"anomaly:{s}", -99) < self.ticks - 60:
                        self.cooldown[f"anomaly:{s}"] = self.ticks
                        f = feats[s]
                        found.append({"kind": "anomaly", "src": s, "score": round(float(sc), 3), "z": round(z, 1), "why": why,
                                      "threshold": gate,
                                      "connections": int(round(math.expm1(f[0]))), "destinations": int(f[1]),
                                      "internal": int(f[2]), "ports": int(f[3])})
        if self.ioc_sets["ipv4-addr"]:  # imported indicators against this tick's flows (the matching engine, live)
            for r in rows:
                hit = r["dst"] if r["dst"] in self.ioc_sets["ipv4-addr"] else r["src"] if r["src"] in self.ioc_sets["ipv4-addr"] else None
                if hit and self.cooldown.get(f"ioc:{hit}", -99) < self.ticks - 60:
                    self.cooldown[f"ioc:{hit}"] = self.ticks
                    found.append({"kind": "ioc", "value": hit, "src": r["src"], "dst": r["dst"], "dport": r["dport"]})
        if found:
            conn = self.connect()
            try:
                for f in found:
                    self._act(conn, f, now, drill)
            finally:
                conn.close()
        with self.lock:
            self._advance_drill(now)
        if self.ticks % 3 == 0:  # watchlists: evaluate every analyst's rule against the current graph (edge-triggered)
            conn = self.connect()
            try:
                from .engine import iocs, watch
                self.ioc_sets = iocs.live_sets(conn)
                fired = watch.evaluate(conn, self.status(), now)
                for f in fired:
                    with self.lock:
                        self.detections.appendleft({"id": f"DET-{self.ticks:05d}-W{f['watch_id']}", "ts": _iso(now), "kind": "watch",
                                                    "title": f"Watchlist: {f['label']}: {'; '.join(f['reasons'])}", "drill": None,
                                                    "seconds_to_detect": None, "target": f["target"], "severity": f["severity"]})
            except Exception as exc:  # noqa: BLE001 - a watch must never stop detection
                print(f"live: watch evaluation failed: {exc!r}", flush=True)
            finally:
                conn.close()
        if self.ticks == 1 or self.ticks % 12 == 0:  # re-learn thresholds from the record every minute
            conn = self.connect()
            try:
                self.adaptive.learn(conn, now)
            except Exception as exc:  # noqa: BLE001 - learning must never stop detection
                print(f"live: adaptive learn failed: {exc!r}", flush=True)
            finally:
                conn.close()
        if time.time() >= self.next_feed and not (self._feed_thread and self._feed_thread.is_alive()):
            self.next_feed = time.time() + self.adaptive.feed_interval(now)
            self._feed_thread = threading.Thread(target=self._check_feeds, args=(now,), daemon=True)
            self._feed_thread.start()
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
        if f["kind"] == "ioc":  # an imported indicator seen in live flows: record, no automatic action
            from .engine import iocs
            inside = self.ip_asset.get(f["src"]) or self.ip_asset.get(f["dst"])
            host = inside["hostname"] if inside else f["src"]
            title = f"Imported indicator {f['value'].replace('.', '[.]')} seen in flows ({host} -> {f['dst'].replace('.', '[.]')}:{f['dport']})"
            payload = {"value": f["value"].replace(".", "[.]"), "src": f["src"], "dst": f["dst"], "dport": f["dport"], "asset": host,
                       "org_id": inside["org_id"] if inside else None, **tag_drill}
            self._detected(conn, now, "ioc", f"ioc:{f['value']}", title, payload, drill)
            iocs.mark_live_match(conn, f["value"], {"title": title, **payload}, now)
            return
        if f["kind"] == "surge":
            tag, label = f["tag"], self.labels.get(f["tag"], f["tag"])
            running = [a for a in self.assets.values() if a["product_key"] == tag]
            orgs = sorted({a["org_id"] for a in running})
            self._detected(conn, now, "surge", f"product:{tag}",
                           f"Scanning surge against {label} on {f['hot']} decoy sensors (z = {f['z']}, threshold {f['threshold']})",
                           {"product": label, "z": f["z"], "threshold": f["threshold"], "z_sources": f["zi"], "sensors": f["hot"],
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
            self.adaptive.focus(now, f"suspected compromise at {org['name']}")
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
                                                                     "chain": ["surge", "beacon", "anomaly"],
                                                                     "cve": ["intake"]}[scenario]}
            if scenario == "cve":  # a fresh id every time, so the drill works again after a restart or on a copy
                self.drill["cve"] = f"CVE-2026-9{now:%H%M%S}"
            self.adaptive.focus(now, f"{spec['title']} drill running", hours=0.5)
            from .engine.ledger import Ledger
            conn = self.connect()
            try:
                Ledger(conn=conn).append(ts=_iso(now), kind="live.drill.start", subject=self.drill["id"], source="ANALYST",
                                         provenance="HUMAN", payload={k: self.drill[k] for k in ("scenario", "title", "victim_host")})
                conn.commit()
            finally:
                conn.close()
        if scenario == "cve":
            self._drill_cve()
        return dict(self.drill)

    def _drill_cve(self) -> None:
        d = self.drill
        cid, now = d["cve"], dt.datetime.now(dt.timezone.utc)
        published = (now - dt.timedelta(minutes=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
        cve = {"id": cid, "published": published, "lastModified": published, "vulnStatus": "Awaiting Analysis",
               "descriptions": [{"lang": "en", "value": f"[DRILL {d['id']}] A heap-based buffer overflow in Fortinet FortiOS "
                                                         "SSL-VPN allows a remote unauthenticated attacker to execute arbitrary "
                                                         "code via crafted requests. Exploitation in the wild has been observed."}],
               "metrics": {"cvssMetricV31": [{"source": "drill", "type": "Secondary", "cvssData": {"version": "3.1",
                           "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}]},
               "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                   {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionEndExcluding": "7.4.9"}]}]}]}
        taken = self.ingest([cve], now, source=f"DRILL {d['id']} (NVD format)")
        with self.lock:
            if taken:
                t = taken[0]
                d["detected"]["intake"] = {"at": _iso(now), "seconds": round((now - dt.datetime.fromisoformat(d["started_at"])).total_seconds(), 1)}
                d["intake"] = {k: t[k] for k in ("cve", "exposed", "orgs", "worst", "action", "minutes_since_publication")}
            self.detections.appendleft({"id": f"DET-{self.ticks:05d}-{len(self.detections) + 1}", "ts": _iso(now), "kind": "intake",
                                        "title": f"{cid} taken in: {taken[0]['exposed'] if taken else 0} exposed assets at "
                                                 f"{len(taken[0]['orgs']) if taken else 0} organisations, {taken[0]['worst'] if taken else '—'}",
                                        "drill": d["id"], "seconds_to_detect": d["detected"].get("intake", {}).get("seconds")})

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
            if f.get("next_at", 0) > time.time():
                continue  # this feed keeps its own, slower cadence; its last reading stands
            f["next_at"] = time.time() + FEED_CADENCE_S.get(name, 0)
            f["last_try"] = _iso(now)
            t0 = time.perf_counter()
            try:
                if name in STDLIB_FEEDS:
                    import urllib.request
                    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=60) as resp:
                        r = _Fetched(url, resp.read())
                else:
                    r = httpx.get(url, timeout=25, follow_redirects=True, headers={"User-Agent": UA})
                    r.raise_for_status()
                f["ms"] = round((time.perf_counter() - t0) * 1000)
                f.update(self._read_feed(name, r, ROOT / "data" / "raw" / snap))
                f["status"], f["last_ok"] = "fresh", _iso(now)
            except Exception as exc:  # noqa: BLE001 - a feed outage is reported, never fatal
                f["status"], f["detail"] = "offline", f"{type(exc).__name__}: {str(exc)[:120]}; serving the snapshot"
        self._check_nvd(now)

    def _check_nvd(self, now: dt.datetime) -> None:
        """New real CVEs since the last check, taken into the running system (engine/intake.py)."""
        from .engine import intake
        f = self.feeds["NVD (new CVEs)"]
        f["last_try"] = _iso(now)
        t0 = time.perf_counter()
        try:
            cves = intake.fetch_recent(self.nvd_since - dt.timedelta(minutes=5), now)
            f["ms"] = round((time.perf_counter() - t0) * 1000)
            taken = self.ingest(cves, now)
            self.nvd_since = now
            f.update(items=len(cves), new=len(taken), matched=[t["cve"] for t in taken],
                     status="fresh", last_ok=_iso(now),
                     detail=f"{len(cves)} CVEs published or changed since the last check; {len(taken)} name a product we "
                            f"run and were taken in" + (f", {sum(1 for t in taken if t['exposed'])} with exposed assets"
                                                         if taken else ""))
        except Exception as exc:  # noqa: BLE001
            f["status"], f["detail"] = "offline", f"{type(exc).__name__}: {str(exc)[:120]}; the snapshot keeps serving"

    def ingest(self, cves: list[dict], now: dt.datetime | None = None, source: str = "NVD (live)") -> list[dict]:
        """Take NVD-format CVE objects into the running system; also the entry point for tests and drills."""
        from .engine import intake
        conn = self.connect()
        try:
            taken = intake.intake(conn, cves, self.kev_live, now or dt.datetime.now(dt.timezone.utc), source)
        finally:
            conn.close()
        with self.lock:
            for t in taken:
                self.intakes.appendleft(t)
                if t["worst"] in ("Critical", "Compromise"):
                    self.adaptive.focus(now or dt.datetime.now(dt.timezone.utc), f"Critical CVE {t['cve']} taken in")
        return taken

    def _read_feed(self, name: str, r, snap: Path) -> dict:
        if name == "CISA KEV":
            data = r.json()["vulnerabilities"]
            self.kev_live = {v["cveID"]: v for v in data}
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
        if name == "SANS ISC DShield":
            return self._read_dshield(r, snap)
        if name == "CISA advisories":
            return self._read_cisa(r, snap)
        if name == "abuse.ch Feodo Tracker":
            data = r.json()
            _write_snapshot(snap, r.content, str(r.url))
            ips = {d["ip_address"] for d in data}
            seen = {x["dst"] for x in list(self.flows)} & ips
            return {"items": len(data), "new": None, "matched": sorted(seen),
                    "detail": f"{len(ips)} C2 addresses; {len(seen)} seen in the last hours of firewall flows"}
        lines = [x.strip() for x in r.text.splitlines() if x.strip()]
        if lines and not lines[0].startswith("<"):  # a text list, never an error page
            _write_snapshot(snap, r.content, str(r.url))
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

    def _read_dshield(self, r, snap: Path) -> dict:
        """SANS ISC DShield, live: today's top attacked ports (the body just read), the top attacking sources and the
        daily history of every port the constituency's services listen on, each written through to its snapshot, so
        the port trends, the heatmaps, the threat maps and the organisation OSINT all move with it."""
        import httpx
        from .engine import intel
        json.loads(r.content)  # never replace a good snapshot with an error page
        _write_snapshot(snap, r.content, str(r.url))
        raw = ROOT / "data" / "raw" / "dshield"
        headers = {"User-Agent": UA}
        ok, failed = 1, []
        try:
            s = httpx.get(DSHIELD_SOURCES, timeout=25, follow_redirects=True, headers=headers)
            s.raise_for_status()
            json.loads(s.content)
            _write_snapshot(raw / "sources.json", s.content, DSHIELD_SOURCES)
            ok += 1
        except Exception as exc:  # noqa: BLE001 - the earlier snapshot of this file stands
            failed.append(f"sources: {type(exc).__name__}")
        today = dt.date.today()
        since = (today - dt.timedelta(days=DSHIELD_HISTORY_DAYS)).isoformat()
        for port in sorted(intel.PORT_NAMES):  # sequential and unhurried: a community service
            url = f"https://isc.sans.edu/api/porthistory/{port}/{since}/{today.isoformat()}?json"
            try:
                h = httpx.get(url, timeout=25, follow_redirects=True, headers=headers)
                h.raise_for_status()
                json.loads(h.content)
                _write_snapshot(raw / f"port_{port}.json", h.content, url)
                ok += 1
            except Exception as exc:  # noqa: BLE001
                failed.append(f"port {port}: {type(exc).__name__}")
            time.sleep(0.5)
        intel.dshield.cache_clear()
        ds = intel.dshield()
        trends = [t for p in sorted(intel.PORT_NAMES) if (t := intel.port_trend(p))]
        elevated = [f"{t['service']} :{t['port']}" for t in trends if t["elevated"]]
        records = sum(int(p.get("records") or 0) for p in ds["top_ports"])
        return {"items": records, "new": None, "matched": elevated,
                "detail": f"{records:,} attack records on today's top ports; {len(trends)} of our service ports tracked daily, "
                          f"{len(elevated)} elevated against their 28-day median; {ok} files refreshed"
                          + (f", {len(failed)} kept from the snapshot ({'; '.join(failed[:3])})" if failed else "")}

    def _read_cisa(self, r, snap: Path) -> dict:
        """CISA's advisory feed (ICS advisories and alerts), live: parsed before it is written through, then matched to
        the inventory the same way the snapshot is."""
        import xml.etree.ElementTree as ET
        from .engine import intel
        ET.fromstring(r.content)  # well-formed, or the snapshot stands
        _write_snapshot(snap, r.content, str(r.url))
        intel.cisa_advisories.cache_clear()
        conn = self.connect()
        try:
            adv = intel.advisories_matched(conn)
        finally:
            conn.close()
        relevant = [a for a in adv if a["relevant"]]
        return {"items": len(adv), "new": None, "matched": [a["id"] for a in relevant][:12],
                "newest": max((a["published"] or "" for a in adv), default="") or None,
                "detail": f"{len(adv)} current CISA advisories; {len(relevant)} name a product we run or a CVE in the record"}

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
                "intakes": list(self.intakes),
                "adaptive": self.adaptive.status(dt.datetime.now(dt.timezone.utc)),
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
