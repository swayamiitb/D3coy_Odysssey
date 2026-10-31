"""Adaptive telemetry: the live detectors tune themselves from what people decided, and the engine pays more
attention where something is happening. Everything is a small, bounded, explainable rule; every change is a
ledger event with its reason, and the current settings are shown on screen next to their defaults.

  surge threshold (per product)      base 4.0 robust z; +0.5 per false alarm on that product in the last 45 days
                                     (a stand-down, or an analyst rejecting its early warning); −0.25 per confirmed
                                     surge (one followed by a real disclosure); bounded to [3.5, 7.0].
  anomaly gate (per organisation)    base 6.0 robust z; +1.0 per hunt or warning the organisation closed as a false
                                     positive in the last 30 days; bounded to [6.0, 10.0].
  beacon evidence                    30 connections; 20 while an organisation has an open suspected compromise
                                     (a second implant is likelier and the cost of a miss is higher).
  feed cadence                       every 15 min; every 5 min for an hour after a Critical intake, a live
                                     compromise or a running drill (focus), so KEV and NVD changes land sooner.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3

BASE_SURGE_Z, MIN_SURGE_Z, MAX_SURGE_Z = 4.0, 3.5, 7.0
BASE_ANOMALY_Z, MAX_ANOMALY_Z = 6.0, 10.0
BASE_BEACON, FOCUS_BEACON = 30, 20
BASE_FEED_S, FOCUS_FEED_S = 900, 300


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


class Adaptive:
    def __init__(self, tags: list[str], org_ids: list[str]):
        self.tags, self.org_ids = list(tags), list(org_ids)
        self.surge: dict[str, dict] = {t: {"z": BASE_SURGE_Z, "false_alarms": 0, "confirmed": 0, "why": "default"} for t in tags}
        self.anomaly: dict[str, dict] = {o: {"z": BASE_ANOMALY_Z, "false_positives": 0, "why": "default"} for o in org_ids}
        self.compromised: set[str] = set()
        self.focus_until: dt.datetime | None = None
        self.focus_why: str | None = None
        self.changes: list[dict] = []
        self.learned_at: str | None = None

    # ------------------------------------------------------------------ what the detectors ask
    def surge_z(self, tag: str) -> float:
        return self.surge.get(tag, {}).get("z", BASE_SURGE_Z)

    def anomaly_z(self, org_id: str | None) -> float:
        return self.anomaly.get(org_id or "", {}).get("z", BASE_ANOMALY_Z)

    def beacon_min(self, org_id: str | None) -> int:
        return FOCUS_BEACON if org_id in self.compromised else BASE_BEACON

    def feed_interval(self, now: dt.datetime) -> int:
        return FOCUS_FEED_S if self.focus_until and now < self.focus_until else BASE_FEED_S

    def focus(self, now: dt.datetime, why: str, hours: float = 1.0) -> None:
        self.focus_until, self.focus_why = now + dt.timedelta(hours=hours), why

    # ------------------------------------------------------------------ learning from the record
    def learn(self, conn: sqlite3.Connection, now: dt.datetime) -> list[dict]:
        """Re-derive every setting from the ledger and the workflow; log what changed and why."""
        d45, d30 = _iso(now - dt.timedelta(days=45)), _iso(now - dt.timedelta(days=30))
        rows = conn.execute("""SELECT ts, kind, subject, payload FROM ledger
                               WHERE ts >= ? AND kind IN ('auto.stand_down', 'auto.confirm', 'analyst.reject')""", (d45,)).fetchall()
        fa: dict[str, int] = {t: 0 for t in self.tags}
        ok: dict[str, int] = {t: 0 for t in self.tags}
        for ts, kind, subject, payload in rows:
            tag = subject.split(":", 1)[1] if subject.startswith("product:") else None
            p = json.loads(payload)
            if kind == "auto.stand_down" and tag in fa:
                fa[tag] += 1
            elif kind == "auto.confirm" and tag in ok:
                ok[tag] += 1
            elif kind == "analyst.reject" and p.get("action") == "auto.warn" and tag in fa:
                fa[tag] += 1
        changed = []
        for tag in self.tags:
            z = min(MAX_SURGE_Z, max(MIN_SURGE_Z, BASE_SURGE_Z + 0.5 * fa[tag] - 0.25 * ok[tag]))
            why = ("default" if not fa[tag] and not ok[tag] else
                   f"{fa[tag]} false alarm(s) and {ok[tag]} confirmed surge(s) in 45 days")
            if abs(z - self.surge[tag]["z"]) >= 0.01:
                changed.append({"what": f"surge threshold · {tag}", "from": self.surge[tag]["z"], "to": z, "why": why})
            self.surge[tag] = {"z": round(z, 2), "false_alarms": fa[tag], "confirmed": ok[tag], "why": why}
        have_wf = conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'workflow'").fetchone()
        fp: dict[str, int] = {o: 0 for o in self.org_ids}
        if have_wf:
            for (alert_id,) in conn.execute("SELECT alert_id FROM workflow WHERE outcome = 'false_positive' AND updated_at >= ?", (d30,)):
                org = alert_id.split(":", 1)[0]
                if org in fp:
                    fp[org] += 1
        for ts, kind, subject, payload in conn.execute(
                "SELECT ts, kind, subject, payload FROM ledger WHERE ts >= ? AND kind = 'analyst.case_status'", (d30,)):
            p = json.loads(payload)
            if p.get("to") == "false_positive" and p.get("org_id") in fp:
                fp[p["org_id"]] += 1
        for org in self.org_ids:
            z = min(MAX_ANOMALY_Z, BASE_ANOMALY_Z + 1.0 * fp[org])
            why = "default" if not fp[org] else f"{fp[org]} false positive(s) closed by the organisation in 30 days"
            if abs(z - self.anomaly[org]["z"]) >= 0.01:
                changed.append({"what": f"anomaly gate · {org}", "from": self.anomaly[org]["z"], "to": z, "why": why})
            self.anomaly[org] = {"z": round(z, 2), "false_positives": fp[org], "why": why}
        self.compromised = {r[0] for r in conn.execute(
            "SELECT DISTINCT org_id FROM assessments WHERE tier = 'Compromise' AND R > 0")}
        self.learned_at = _iso(now)
        if changed:
            from .ledger import Ledger
            Ledger(conn=conn).append(ts=_iso(now), kind="live.adapt", subject="detectors", source="ODYSSEY", provenance="AUTO",
                                     payload={"changes": changed})
            conn.commit()
            self.changes = (changed + self.changes)[:40]
        return changed

    # ------------------------------------------------------------------ for the interface
    def status(self, now: dt.datetime) -> dict:
        return {
            "learned_at": self.learned_at,
            "surge": [{"tag": t, **v, "base": BASE_SURGE_Z} for t, v in self.surge.items()],
            "anomaly": [{"org_id": o, **v, "base": BASE_ANOMALY_Z} for o, v in self.anomaly.items()],
            "beacon": {"base": BASE_BEACON, "focus": FOCUS_BEACON, "focused_orgs": sorted(self.compromised)},
            "feed": {"base_s": BASE_FEED_S, "focus_s": FOCUS_FEED_S, "current_s": self.feed_interval(now),
                     "focus_until": _iso(self.focus_until) if self.focus_until else None, "focus_why": self.focus_why},
            "changes": self.changes[:12],
            "rules": [
                "surge threshold: 4.0 z + 0.5 per false alarm − 0.25 per confirmed surge on that product (45 days), within 3.5–7.0",
                "anomaly gate: 6.0 z + 1.0 per false positive the organisation closed (30 days), up to 10.0",
                "beacon evidence: 30 connections, 20 while the organisation has an open suspected compromise",
                "feed cadence: 15 min, 5 min for an hour after a Critical intake, a live compromise or a drill",
            ],
        }
