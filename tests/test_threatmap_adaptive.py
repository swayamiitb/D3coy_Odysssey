"""The organisation threat map is a faithful subset of the record (every edge joins real nodes, every element carries
provenance) and the adaptive layer moves thresholds only from recorded decisions, within bounds."""

import datetime as dt
import sqlite3
from pathlib import Path

import pytest

from backend.app.engine.adaptive import BASE_ANOMALY_Z, BASE_SURGE_Z, MAX_SURGE_Z, Adaptive
from backend.app.engine.ledger import Ledger
from backend.app.engine.threatmap import org_threatmap

DB = Path(__file__).resolve().parents[1] / "data" / "ews.db"


@pytest.fixture
def copy(tmp_path):
    if not DB.exists():
        pytest.skip("no built database")
    path = tmp_path / "ews.db"
    src, dst = sqlite3.connect(f"file:{DB}?mode=ro", uri=True), sqlite3.connect(path)
    src.backup(dst)
    src.close()
    dst.close()
    return sqlite3.connect(path, timeout=30)


def test_threat_map_is_a_consistent_subset_of_the_record(copy):
    m = org_threatmap(copy, "PWR-01")
    ids = {n["id"] for n in m["nodes"]} | {t["id"] for t in m["threats"]} | {c["id"] for c in m["c2"]} \
        | {s["id"] for s in m["suppliers"]} | {"org", "crown"}
    assert m["nodes"] and all(e["from"] in ids and e["to"] in ids for e in m["edges"])
    assert all(e["provenance"] in ("REAL", "SIM") for e in m["edges"])
    assert all(t["provenance"] in ("REAL", "SIM") for t in m["threats"])
    assert {n["column"] for n in m["nodes"]} <= {"perimeter", "dmz", "internal", "crown"}
    vpn = next(n for n in m["nodes"] if n["hostname"].startswith("vpn-gw01"))
    assert vpn["worst"] == "Compromise" and vpn["beacon"] and vpn["kev"] >= 1
    assert any(e["kind"] == "beacon" and e["from"] == vpn["id"] for e in m["edges"])
    assert any(t["kind"] == "attack" and t["label"].startswith("HTTPS") for t in m["threats"])
    assert m["summary"]["shown"] <= m["summary"]["assets"] and m["summary"]["beacons"] >= 1
    with pytest.raises(KeyError):
        org_threatmap(copy, "NOPE-99")


def test_closed_warnings_leave_the_map(copy):
    m = org_threatmap(copy, "PWR-01")
    cve = next(t for t in m["threats"] if t["kind"] == "exploited")["label"]
    copy.execute("CREATE TABLE IF NOT EXISTS workflow (alert_id TEXT PRIMARY KEY, state TEXT NOT NULL, outcome TEXT, owner TEXT, "
                 "issued_at TEXT NOT NULL, updated_at TEXT NOT NULL, note TEXT)")
    copy.execute("INSERT OR REPLACE INTO workflow VALUES (?, 'closed', 'resolved', 'a', '2026-11-01T00:00:00', '2026-11-01T00:00:00', NULL)",
                 (f"PWR-01:{cve}",))
    copy.commit()
    after = org_threatmap(copy, "PWR-01")
    assert cve not in {t["label"] for t in after["threats"] if t["kind"] == "exploited"}


def test_thresholds_follow_recorded_decisions_within_bounds(copy):
    now = dt.datetime(2026, 11, 1, 4, 0, tzinfo=dt.timezone.utc)
    a = Adaptive(["fortios", "confluence", "ivanti_cs"], ["PWR-01", "BFS-01"])
    a.learn(copy, now)
    assert a.surge_z("confluence") > BASE_SURGE_Z            # the planted false alarm was stood down in the record
    assert a.surge_z("ivanti_cs") < BASE_SURGE_Z             # its surge was confirmed by a real disclosure
    assert a.surge_z("fortios") == BASE_SURGE_Z and a.anomaly_z("BFS-01") == BASE_ANOMALY_Z
    led = Ledger(conn=copy)
    for i in range(12):  # an analyst keeps rejecting fortios early warnings as false positives
        led.append(ts=f"2026-10-3{1 if i < 5 else 0}T0{i % 10}:00:00Z", kind="analyst.reject", subject="product:fortios",
                   source="ANALYST", provenance="HUMAN", payload={"action": "auto.warn", "note": "False positive"})
    led.append(ts="2026-10-31T10:00:00Z", kind="analyst.case_status", subject="CASE-0003", source="ANALYST",
               provenance="HUMAN", payload={"org_id": "BFS-01", "from": "new", "to": "false_positive"})
    changes = a.learn(copy, now)
    assert a.surge_z("fortios") == MAX_SURGE_Z               # bounded, however many rejections
    assert a.anomaly_z("BFS-01") == BASE_ANOMALY_Z + 1.0
    assert any(c["what"].endswith("fortios") for c in changes)
    assert copy.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'live.adapt'").fetchone()[0] >= 1
    assert a.beacon_min("PWR-01") == 20 and a.beacon_min("BFS-01") == 30   # PWR-01 has the open compromise
    assert a.feed_interval(now) == 900
    a.focus(now, "drill")
    assert a.feed_interval(now) == 300 and a.feed_interval(now + dt.timedelta(hours=2)) == 900
