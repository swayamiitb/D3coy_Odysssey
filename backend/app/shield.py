"""Odyssey HTTP Shield: the live WAF/IDS that protects a *real* connected web application.

A drop-in agent (see agent/) sits in the target app and forwards every request's metadata to `POST /api/sensor/http`.
Each event passes through the signature engine (engine/webattack.py) and the stateful detectors here (brute force and
scanning sweeps, which need a per-source window), and the shield:
  - keeps a live ring of recent requests and detections, and a per-attacker profile, for the dashboard;
  - writes each new detection to the hash-chained ledger and drives the same graduated-autonomy autopilot as the rest
    of Odyssey - an evidence-based block and a SOC incident run on their own; a sensor-only warning is proposed and
    waits for an analyst;
  - maintains a blocklist that agents enforce (GET /api/sensor/policy) and that the ingest response echoes, so in
    block mode the offending request is dropped inline. Nothing here reaches outside this laptop.

The shield is deliberately separate from the decoy/network Live engine: this is the application layer (HTTP requests
to a protected app), that is the network/sensor layer. They share the ledger, the autopilot and the live stream.
"""

from __future__ import annotations

import collections
import datetime as dt
import ipaddress
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from .engine import webattack

ROOT = Path(__file__).resolve().parents[2]
WINDOW_S = 120.0                 # per-source behavioural window
BRUTE_LOGINS = 8                 # login attempts in the window -> brute force
SWEEP_PATHS = 15                 # distinct paths in the window -> scanning sweep
SWEEP_404 = 12                   # 4xx responses in the window -> enumeration
DETECT_COOLDOWN_S = 20.0         # one ledger event per (source, family) at most this often, so a burst is one incident
LOGIN_HINT = ("login", "signin", "sign-in", "auth", "session", "token", "oauth", "admin")


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class Source:
    """A rolling profile of one client IP seen by the shield."""

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = time.time()
        self.events: collections.deque = collections.deque(maxlen=400)   # (ts, path, status, is_login, attack)
        self.requests = 0
        self.attacks = 0
        self.families: set[str] = set()
        self.worst: str | None = None
        self.blocked = False
        self.block_reason: str | None = None
        self.last_ua = ""

    def window(self) -> list[tuple]:
        cut = time.time() - WINDOW_S
        return [e for e in self.events if e[0] >= cut]


class Shield:
    def __init__(self, connect: Callable[[], sqlite3.Connection]):
        self.connect = connect
        self.lock = threading.RLock()
        self.started = dt.datetime.now(dt.timezone.utc)
        self.apps: dict[str, dict] = {}
        self.sources: dict[str, Source] = {}
        self.events: collections.deque = collections.deque(maxlen=300)   # recent requests (for the stream)
        self.findings: collections.deque = collections.deque(maxlen=120)  # recent detections
        self.blocklist: dict[str, dict] = {}
        self.cooldown: dict[str, float] = {}
        self.autopilot_seen: set = set()   # (app_id, src_ip) already driven to the autopilot: propose a block once
        self.n_events = 0
        self.n_attacks = 0
        self.n_blocked = 0            # block events (sources added to the list)
        self.requests_blocked = 0     # requests actually dropped inline
        self.redteam_hits: dict[str, list[dict]] = collections.defaultdict(list)  # run_id -> findings seen
        world_path = ROOT / "data" / "sim" / "world.json"
        world = json.loads(world_path.read_text(encoding="utf-8")) if world_path.exists() else {"orgs": [], "assets": []}
        self.orgs = {o["id"]: o for o in world["orgs"]}
        self.assets = {a["id"]: a for a in world["assets"]}

    # ------------------------------------------------------------------ app registry
    def register(self, app_id: str, meta: dict, announced: bool = True) -> dict:
        """An agent announces its app (on start and every 10 s), or the first event from an app the shield does not
        know hydrates it from the metadata the agent sends with every request (announced=False for a bare webhook
        that carries only an id). The agent's own mode ("enforce" forwards synchronously and honours the decision;
        "monitor" cannot drop anything) is kept as agent_mode. The shield's policy ("monitor" / "block") is set only
        from the dashboard, so an agent re-announcing itself never undoes an analyst's Block."""
        now = _iso(dt.datetime.now(dt.timezone.utc))
        with self.lock:
            app = self.apps.get(app_id)
            if app is None:
                policy = meta.get("mode") if meta.get("mode") in ("monitor", "block") else "monitor"
                app = self.apps[app_id] = {
                    "id": app_id, "name": meta.get("name") or app_id, "base_url": meta.get("base_url"), "mode": policy,
                    "agent_mode": meta.get("mode"), "org_id": meta.get("org_id"), "framework": meta.get("framework"),
                    "first_seen": now, "last_seen": now, "announced": announced,
                    "requests": 0, "attacks": 0, "blocked": 0}
            else:
                for k in ("name", "base_url", "org_id", "framework"):
                    if meta.get(k):
                        app[k] = meta[k]
                if meta.get("mode"):
                    app["agent_mode"] = meta["mode"]
                app["announced"] = app["announced"] or announced
                app["last_seen"] = now
            return dict(app)

    def set_mode(self, app_id: str, mode: str) -> dict:
        if mode not in ("monitor", "block"):
            raise ValueError("mode must be 'monitor' or 'block'")
        with self.lock:
            if app_id not in self.apps:
                raise KeyError(app_id)
            self.apps[app_id]["mode"] = mode
            return dict(self.apps[app_id])

    # ------------------------------------------------------------------ ingest
    def _source_ip(self, event: dict) -> str:
        ip = event.get("source_ip")
        if not ip:
            xff = str((event.get("headers") or {}).get("x-forwarded-for", ""))
            ip = xff.split(",")[0].strip() if xff else ""
        return ip or "unknown"

    def _behavioural(self, src: Source) -> list[dict]:
        """Stateful detections that a single request cannot show: credential brute force and scanning sweeps."""
        win = src.window()
        out: list[dict] = []
        logins = sum(1 for _, path, _, is_login, _ in win if is_login)
        if logins >= BRUTE_LOGINS:
            out.append({"family": "bruteforce", "category": "Credential brute force", "cwe": "CWE-307",
                        "cwe_name": webattack.CWE_NAMES["CWE-307"], "attack": "T1110",
                        "attack_name": webattack.ATTACK_NAMES["T1110"], "severity": "High", "surface": "behaviour",
                        "param": "login", "evidence": f"{logins} login attempts in {int(WINDOW_S)}s",
                        "why": "Many authentication attempts from one source in a short window is credential stuffing or brute force."})
        paths = {path for _, path, _, _, _ in win}
        errs = sum(1 for _, _, status, _, _ in win if isinstance(status, int) and 400 <= status < 500)
        if len(paths) >= SWEEP_PATHS or errs >= SWEEP_404:
            out.append({"family": "scan", "category": "Scanning sweep", "cwe": "CWE-1595",
                        "cwe_name": webattack.CWE_NAMES["CWE-1595"], "attack": "T1595.002",
                        "attack_name": webattack.ATTACK_NAMES["T1595"], "severity": "Medium", "surface": "behaviour",
                        "param": "paths", "evidence": f"{len(paths)} distinct paths, {errs} 4xx in {int(WINDOW_S)}s",
                        "why": "One source touching many distinct paths and drawing many 4xx responses is automated enumeration."})
        return out

    def ingest(self, event: dict) -> dict:
        """Inspect one forwarded request. Returns {decision, findings, worst, source_ip, blocked, action}.

        decision is 'block' when the app is in block mode and the request is an attack (or the source is already
        blocked); the agent drops it inline. In monitor mode the decision is always 'allow' and the attack is still
        recorded and, where consequential, proposed for a human to act on."""
        now = dt.datetime.now(dt.timezone.utc)
        ts = event.get("ts") or _iso(now)
        app_id = event.get("app") or "unregistered"
        src_ip = self._source_ip(event)
        headers = {str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()}
        redteam = headers.get("x-odyssey-redteam") or event.get("redteam")
        rt_case = headers.get("x-odyssey-rt-case") or event.get("rt_case")
        path = str(event.get("path") or "")
        status = event.get("status")
        is_login = event.get("method", "GET").upper() == "POST" and any(h in path.lower() for h in LOGIN_HINT)

        result = webattack.inspect(event)
        findings = list(result["findings"])

        with self.lock:
            app = self.apps.get(app_id)
            if app is None or not app["announced"]:
                # The agent sends its metadata with every request, so an app the shield has forgotten (the API was
                # restarted; the registry is in memory) comes back whole on its first request. Work on the stored
                # dict, not the copy register() returns, or that first request is not counted on the app.
                meta = {k: event.get(k) for k in ("name", "base_url", "org_id", "framework", "mode")}
                self.register(app_id, meta, announced=any(meta[k] for k in ("name", "base_url", "org_id")))
                app = self.apps[app_id]
            mode = app["mode"]
            src = self.sources.get(src_ip) or self.sources.setdefault(src_ip, Source(src_ip))
            src.requests += 1
            src.last_ua = headers.get("user-agent", src.last_ua)
            self.n_events += 1
            app["requests"] += 1
            app["last_seen"] = _iso(now)  # any request proves the agent is alive, heartbeat or not
            announced = app["announced"]

            findings += self._behavioural(src)
            worst = _worst([f["severity"] for f in findings]) if findings else None
            attack = worst is not None
            # Evidence of likely success escalates a High to Critical / Compromise handling.
            success = attack and isinstance(status, int) and 200 <= status < 300 and \
                any(f["family"].split(".")[0] in ("sqli", "cmdi", "jndi", "traversal", "lfi") for f in findings)

            already_blocked = src_ip in self.blocklist
            decision = "allow"
            if already_blocked:
                decision = "block"
            elif attack and mode == "block" and (_rank(worst) >= _rank("High") or success):
                decision = "block"
                self._block(src_ip, now, reason=f"{findings[0]['category']} ({findings[0]['cwe']})", auto=True)

            if decision == "block":
                self.requests_blocked += 1
                app["blocked"] += 1

            src.events.append((time.time(), path, status, is_login, attack))
            event_row = {"ts": ts, "app": app_id, "method": event.get("method", "GET"), "path": webattack.redact(path, 120),
                         "status": status, "source_ip": src_ip, "ua": webattack.redact(headers.get("user-agent", ""), 60),
                         "worst": worst, "decision": decision, "families": result["families"],
                         "n": len(findings), "redteam": redteam}
            self.events.appendleft(event_row)

            if not attack:
                return {"decision": decision, "findings": [], "worst": None, "source_ip": src_ip,
                        "blocked": decision == "block", "action": None, "announced": announced}

            src.attacks += 1
            app["attacks"] += 1
            self.n_attacks += 1
            src.families.update(f["family"].split(".")[0] for f in findings)
            src.worst = _worst([src.worst, worst]) if src.worst else worst
            if success and _rank(src.worst) < _rank("Critical"):
                src.worst = "Critical"

            top = findings[0]
            detection = {"id": f"WAF-{self.n_attacks:05d}", "ts": ts, "app": app_id, "source_ip": src_ip,
                         "method": event.get("method", "GET"), "path": webattack.redact(path, 120),
                         "category": top["category"], "severity": "Compromise" if success else worst,
                         "cwe": top["cwe"], "cwe_name": top["cwe_name"], "attack": top["attack"],
                         "attack_name": top["attack_name"], "families": result["families"], "findings": findings,
                         "decision": decision, "success": success, "redteam": redteam, "rt_case": rt_case}
            self.findings.appendleft(detection)
            if redteam:
                self.redteam_hits[redteam].append(detection)

        # Ledger + autopilot outside the lock (they take their own DB transaction).
        self._record(detection, app, src_ip, success, now, redteam)
        return {"decision": decision, "findings": findings, "worst": detection["severity"], "source_ip": src_ip,
                "blocked": decision == "block", "action": detection["id"], "announced": announced}

    # ------------------------------------------------------------------ persistence / autopilot
    def _record(self, det: dict, app: dict, src_ip: str, success: bool, now: dt.datetime, redteam: str | None) -> None:
        """Write a ledger event and drive the autopilot, but at most once per (source, family) per cooldown, so a
        red-team burst of 30 requests becomes one auditable incident, not 30."""
        fam = det["families"][0] if det["families"] else "web"
        key = f"{src_ip}:{fam}"
        with self.lock:
            last = self.cooldown.get(key, 0.0)
            if time.time() - last < DETECT_COOLDOWN_S:
                return
            self.cooldown[key] = time.time()
            # The autopilot proposes one block per attacker source, not one per attack type; later families from the
            # same source are still written to the ledger below but do not re-propose.
            first_from_source = (app["id"], src_ip) not in self.autopilot_seen
            self.autopilot_seen.add((app["id"], src_ip))

        prov = "SIM" if redteam else "REAL"
        from .engine.ledger import Ledger
        from .engine.sentinel import Autopilot
        from .engine.scoring import config
        conn = self.connect()
        try:
            led = Ledger(conn=conn, autocommit=False)
            conn.execute("BEGIN IMMEDIATE")
            led.append(ts=det["ts"], kind=f"shield.detect.{fam}", subject=f"{app['id']}:{src_ip}",
                       source="HTTP_SHIELD", provenance=prov,
                       payload={"app": app["id"], "source_ip": src_ip, "category": det["category"],
                                "severity": det["severity"], "cwe": det["cwe"], "attack": det["attack"],
                                "path": det["path"], "decision": det["decision"], "success": success,
                                "evidence": det["findings"][0]["evidence"], "redteam": redteam})
            conn.commit()

            org_id = app.get("org_id")
            app_name = app["name"]
            tag = {"redteam": redteam} if redteam else {}
            subject = f"{app['id']}:{src_ip}"
            if first_from_source:
                pilot = Autopilot(conn, Ledger(conn=conn, autocommit=False), config()[0], self.orgs, self.assets, now=now)
                if det["decision"] == "block":
                    pilot.emit(now, "notify", subject, org_id=org_id, alert=subject, app=app_name, tier="Critical",
                               channels=["soc"], basis=f"HTTP shield {det['cwe']}", provenance=prov, **tag,
                               title=f"Blocked an attack on {app_name} from {src_ip} ({det['category']}, {det['cwe']}, "
                                     f"path {det['path']}). The source is now on the block list and its traffic is dropped inline.")
                else:
                    pilot.emit(now, "warn", subject, org_id=org_id, alert=subject, app=app_name, channels=["soc"],
                               basis=f"HTTP shield {det['cwe']}", provenance=prov, **tag,
                               group=f"shield-block:{app['id']}:{src_ip}",
                               proposal=f"Block {src_ip} at {app_name} (attacking the app)",
                               title=f"{src_ip} is attacking {app_name} ({det['category']}, {det['cwe']}, path "
                                     f"{det['path']}). Propose blocking the source; monitor mode took no action.")
                pilot.flush()
                conn.commit()

            if success or _rank(det["severity"]) >= _rank("Critical"):
                self._open_case(conn, det, app, src_ip, redteam)
        finally:
            conn.close()

    def _open_case(self, conn: sqlite3.Connection, det: dict, app: dict, src_ip: str, redteam: str | None) -> None:
        from .engine import soc
        exists = conn.execute("SELECT id FROM soc_cases WHERE title LIKE ? AND status NOT IN ('resolved','false_positive')",
                              (f"%{app['name']}%{src_ip}%",)).fetchone() if _has_cases(conn) else None
        if exists:
            return
        note = (f"Opened automatically by the HTTP shield{' during red-team ' + redteam if redteam else ''}: "
                f"{det['category']} ({det['cwe']}) against {app['name']} from {src_ip} on {det['path']}, with a "
                f"2xx response (likely successful). Evidence: {det['findings'][0]['evidence']}")
        soc.open_case(conn, "incident", f"Web attack on {app['name']} from {src_ip}", app.get("org_id") or "",
                      "Compromise", "m.khan", 6, [], app["name"], [app["name"]], note)

    def _block(self, ip: str, now: dt.datetime, reason: str, auto: bool, by: str = "autopilot") -> dict:
        entry = {"ip": ip, "reason": reason, "at": _iso(now), "by": by, "auto": auto}
        self.blocklist[ip] = entry
        if ip in self.sources:
            self.sources[ip].blocked = True
            self.sources[ip].block_reason = reason
        self.n_blocked += 1
        return entry

    def block(self, ip: str, reason: str = "analyst decision") -> dict:
        from .engine.ledger import Ledger
        now = dt.datetime.now(dt.timezone.utc)
        with self.lock:
            entry = self._block(ip, now, reason, auto=False, by="analyst")
        conn = self.connect()
        try:
            Ledger(conn=conn).append(ts=_iso(now), kind="shield.block", subject=ip, source="ANALYST",
                                     provenance="HUMAN", payload={"ip": ip, "reason": reason})
        finally:
            conn.close()
        return entry

    def unblock(self, ip: str) -> dict:
        from .engine.ledger import Ledger
        now = dt.datetime.now(dt.timezone.utc)
        with self.lock:
            self.blocklist.pop(ip, None)
            if ip in self.sources:
                self.sources[ip].blocked = False
                self.sources[ip].block_reason = None
        conn = self.connect()
        try:
            Ledger(conn=conn).append(ts=_iso(now), kind="shield.unblock", subject=ip, source="ANALYST",
                                     provenance="HUMAN", payload={"ip": ip})
        finally:
            conn.close()
        return {"ip": ip, "unblocked": True}

    def policy(self) -> dict:
        with self.lock:
            return {"blocklist": sorted(self.blocklist.keys()),
                    "entries": list(self.blocklist.values()), "updated": _iso(dt.datetime.now(dt.timezone.utc))}

    # ------------------------------------------------------------------ view
    def status(self) -> dict:
        with self.lock:
            attackers = sorted(
                [{"ip": s.ip, "requests": s.requests, "attacks": s.attacks, "worst": s.worst,
                  "families": sorted(s.families), "blocked": s.blocked, "block_reason": s.block_reason,
                  "ua": webattack.redact(s.last_ua, 50), "first_seen": _iso(dt.datetime.fromtimestamp(s.first_seen, dt.timezone.utc))}
                 for s in self.sources.values() if s.attacks > 0],
                key=lambda a: (-_rank(a["worst"]), -a["attacks"]))
            return {
                "running": True, "started": _iso(self.started),
                "apps": list(self.apps.values()),
                "stats": {"events": self.n_events, "attacks": self.n_attacks, "blocked": self.requests_blocked,
                          "sources": len(self.sources), "attackers": len(attackers),
                          "blocklist": len(self.blocklist)},
                "events": list(self.events)[:60],
                "findings": list(self.findings)[:40],
                "attackers": attackers[:20],
                "blocklist": list(self.blocklist.values()),
                "families": sorted({fam for s in self.sources.values() for fam in s.families}),
            }


def _rank(sev: str | None) -> int:
    order = {"Watch": 0, "Medium": 1, "High": 2, "Critical": 3, "Compromise": 4}
    return order.get(sev or "", -1)


def _worst(sevs: list[str | None]) -> str | None:
    vals = [s for s in sevs if s]
    return max(vals, key=_rank) if vals else None


def _has_cases(conn: sqlite3.Connection) -> bool:
    return bool(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='soc_cases'").fetchone())


ENGINE: Shield | None = None
