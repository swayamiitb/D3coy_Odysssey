"""Mitigation workflow: every warning is a tracked journey with a clock, like a ride from request to drop-off.

  new -> acknowledged -> mitigating -> verifying -> closed(resolved | risk_accepted | false_positive)
  any non-new state -> reopened -> mitigating

Every transition is an analyst event in the hash-chained ledger (who, what, when, note), so the response is
auditable end to end. The SLA clock starts when the warning is issued (pipeline build time).
"""

from __future__ import annotations

import datetime as dt
import sqlite3

from .ledger import Ledger

STATES = ["new", "acknowledged", "mitigating", "verifying", "closed"]
TRANSITIONS = {
    "acknowledge": ({"new", "reopened"}, "acknowledged"),
    "start": ({"acknowledged", "reopened"}, "mitigating"),
    "verify": ({"mitigating"}, "verifying"),
    "resolve": ({"verifying", "mitigating"}, "closed"),
    "accept_risk": ({"new", "acknowledged", "mitigating", "verifying"}, "closed"),
    "false_positive": ({"new", "acknowledged", "mitigating", "verifying"}, "closed"),
    "reopen": ({"closed"}, "reopened"),
}
NEXT_ACTION = {"new": "acknowledge", "reopened": "start", "acknowledged": "start", "mitigating": "verify",
               "verifying": "resolve", "closed": None}

SCHEMA = """CREATE TABLE IF NOT EXISTS workflow (
    alert_id TEXT PRIMARY KEY, state TEXT NOT NULL, outcome TEXT, owner TEXT, issued_at TEXT NOT NULL,
    updated_at TEXT NOT NULL, note TEXT)"""


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def ensure(conn: sqlite3.Connection) -> None:
    conn.execute(SCHEMA)


def get(conn: sqlite3.Connection, alert_id: str, issued_at: str) -> dict:
    ensure(conn)
    row = conn.execute("SELECT alert_id, state, outcome, owner, issued_at, updated_at, note FROM workflow "
                       "WHERE alert_id = ?", (alert_id,)).fetchone()
    if not row:
        return {"alert_id": alert_id, "state": "new", "outcome": None, "owner": None, "issued_at": issued_at,
                "updated_at": issued_at, "note": None, "next_action": "acknowledge"}
    keys = ["alert_id", "state", "outcome", "owner", "issued_at", "updated_at", "note"]
    rec = dict(zip(keys, row))
    rec["next_action"] = NEXT_ACTION.get(rec["state"])
    return rec


def act(conn: sqlite3.Connection, alert_id: str, action: str, actor: str, note: str | None,
        issued_at: str) -> dict:
    if action not in TRANSITIONS:
        raise ValueError(f"unknown action '{action}'")
    allowed, target = TRANSITIONS[action]
    current = get(conn, alert_id, issued_at)
    if current["state"] not in allowed:
        raise ValueError(f"cannot '{action}' from state '{current['state']}'")
    outcome = {"resolve": "resolved", "accept_risk": "risk_accepted", "false_positive": "false_positive"}.get(action)
    ts = now_iso()
    conn.execute("INSERT OR REPLACE INTO workflow VALUES (?,?,?,?,?,?,?)",
                 (alert_id, target, outcome, actor, current["issued_at"], ts, note))
    Ledger(conn=conn).append(ts=ts, kind=f"analyst.{action}", subject=alert_id, source="ANALYST",
                             provenance="HUMAN", payload={"actor": actor, "from": current["state"], "to": target,
                                                          "outcome": outcome, "note": note})
    conn.commit()
    return get(conn, alert_id, issued_at)
