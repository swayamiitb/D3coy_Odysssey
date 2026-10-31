"""SOC system: assignment, status flow, playbook steps and notes are audited to the ledger as HUMAN actions, and the
metrics (MTTA, MTTR, SLA) come from those recorded actions."""

import datetime as dt
import json
import sqlite3

import pytest

from backend.app.engine import soc
from backend.app.engine.ledger import Ledger


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    Ledger(conn=conn)
    conn.execute("CREATE TABLE orgs (id TEXT PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO orgs VALUES ('PWR-01', 'Northern Grid Corporation')")
    conn.execute(soc.SCHEMA)
    now = dt.datetime.now(dt.timezone.utc)
    for cid, kind, sev, owner, due_h in (("CASE-0001", "incident", "Compromise", "m.khan", 6),
                                          ("CASE-0002", "vuln", "Critical", None, 72)):
        playbook = [{"step": s, "done": False, "by": None, "at": None} for s in soc.PLAYBOOKS[kind]]
        conn.execute("INSERT INTO soc_cases (id, kind, title, org_id, severity, status, owner, created_at, due_at, "
                     "alerts, playbook, notes, product, assets) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (cid, kind, f"{kind} case", "PWR-01", sev, "new", owner,
                      (now - dt.timedelta(hours=1)).isoformat(timespec="seconds"),
                      (now + dt.timedelta(hours=due_h)).isoformat(timespec="seconds"),
                      json.dumps(["PWR-01:CVE-2026-0001"]), json.dumps(playbook), "[]", "Gate", json.dumps(["gw01"])))
    conn.commit()
    return conn


def _human_events(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return conn.execute("SELECT kind, provenance FROM ledger WHERE kind LIKE 'analyst.case_%' ORDER BY seq").fetchall()


def test_cases_carry_the_organisation_and_the_next_step():
    conn = _db()
    rows = soc.cases(conn, "open")
    assert [c["id"] for c in rows] == ["CASE-0001", "CASE-0002"]  # compromise before critical
    assert rows[0]["org_name"] == "Northern Grid Corporation"
    assert rows[0]["next"] == {"status": "in_progress", "label": "Start response"}
    assert soc.metrics(conn)["unassigned"] == 1


def test_assignment_and_flow_are_audited_and_measured():
    conn = _db()
    c = soc.assign(conn, "CASE-0002", "analyst@ncew", "analyst@ncew")
    assert c["owner"] == "analyst@ncew" and c["notes"][-1]["text"] == "Assigned to You."
    with pytest.raises(ValueError):
        soc.assign(conn, "CASE-0002", "intruder", "analyst@ncew")

    for expected in ("in_progress", "contained", "resolved"):
        c = soc.advance(conn, "CASE-0001", "m.khan")
        assert c["status"] == expected
    assert c["next"] is None and c["resolved_at"] and c["acknowledged_at"]
    with pytest.raises(ValueError):
        soc.advance(conn, "CASE-0001", "m.khan", to="contained")  # closed: only reopening is allowed

    m = soc.metrics(conn)
    assert m["resolved"] == 1 and m["sla_pct"] == 100.0  # closed before its 6 h deadline
    assert 0.9 < m["mtta_h"] < 1.1  # acknowledged about an hour after the case opened
    events = _human_events(conn)
    assert len(events) == 4 and {p for _, p in events} == {"HUMAN"}
    assert Ledger(conn=conn).verify()[0]


def test_playbook_step_acknowledges_and_starts_work():
    conn = _db()
    c = soc.step(conn, "CASE-0002", 0, True, "a.rao")
    assert c["status"] == "in_progress" and c["acknowledged_at"]
    assert c["playbook"][0]["done"] and c["playbook"][0]["by"] == "a.rao"
    assert c["progress"] == {"done": 1, "total": len(soc.PLAYBOOKS["vuln"])}
    c = soc.note(conn, "CASE-0002", "  Vendor fix staged for tonight's window.  ", "a.rao")
    assert c["notes"][-1]["text"] == "Vendor fix staged for tonight's window."
    with pytest.raises(ValueError):
        soc.step(conn, "CASE-0002", 99, True, "a.rao")
    assert [k for k, _ in _human_events(conn)] == ["analyst.case_step", "analyst.case_note"]
