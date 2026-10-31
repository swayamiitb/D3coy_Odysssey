"""Live CVE intake: a newly published CVE (NVD 2.0 shape) is matched to the inventory, version-checked, scored,
forecast and acted on while the system runs, without a rebuild. Runs on a private copy of the built database."""

import datetime as dt
import sqlite3
from pathlib import Path

import pytest

from backend.app.engine.intake import intake

DB = Path(__file__).resolve().parents[1] / "data" / "ews.db"


def _cve(cid: str, vendor: str, product: str, end_excl: str, published: str, text: str) -> dict:
    return {"id": cid, "published": published, "lastModified": published, "vulnStatus": "Awaiting Analysis",
            "descriptions": [{"lang": "en", "value": text}],
            "metrics": {"cvssMetricV31": [{"source": "cna@example", "type": "Secondary", "cvssData": {
                "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}]},
            "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                {"vulnerable": True, "criteria": f"cpe:2.3:o:{vendor}:{product}:*:*:*:*:*:*:*:*",
                 "versionEndExcluding": end_excl}]}]}]}


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


def test_new_cve_is_taken_in_scored_and_acted_on(copy):
    now = dt.datetime(2026, 11, 1, 3, 0, tzinfo=dt.timezone.utc)
    fresh = _cve("CVE-2026-999001", "fortinet", "fortios", "7.4.9", "2026-11-01T02:10:00.000",
                 "An authentication bypass in Fortinet FortiOS SSL-VPN allows a remote unauthenticated attacker to "
                 "execute arbitrary code. Exploitation in the wild has been observed.")
    irrelevant = _cve("CVE-2026-999002", "acme", "widget", "1.0", "2026-11-01T02:10:00.000", "A bug in Acme Widget.")
    taken = intake(copy, [fresh, irrelevant, fresh], now=now, source="test")
    assert [t["cve"] for t in taken] == ["CVE-2026-999001"]          # irrelevant skipped, duplicate skipped
    t = taken[0]
    assert t["assets_running"] > 0 and t["exposed"] > 0 and t["orgs"]
    assert t["minutes_since_publication"] == 50
    assert t["worst"] in ("Critical", "High")                         # exploited-in-the-wild text sets the floor
    assert copy.execute("SELECT COUNT(*) FROM vulns WHERE id = 'CVE-2026-999001'").fetchone()[0] == 1
    n = copy.execute("SELECT COUNT(*) FROM assessments WHERE cve_id = 'CVE-2026-999001' AND R > 0").fetchone()[0]
    assert n == t["exposed"]
    kinds = {r[0] for r in copy.execute("SELECT kind FROM ledger WHERE subject LIKE '%CVE-2026-999001%'").fetchall()}
    assert {"vuln.published", "live.intake"} <= kinds
    if t["worst"] == "Critical":
        assert "notified" in t["action"] and "auto.notify" in kinds
    else:
        assert t["action"].startswith("recorded") or "proposed" in t["action"]


def test_patched_versions_are_cleared_not_warned(copy):
    now = dt.datetime(2026, 11, 1, 3, 0, tzinfo=dt.timezone.utc)
    old = _cve("CVE-2026-999003", "fortinet", "fortios", "7.0.0", "2026-11-01T02:10:00.000",
               "A flaw in Fortinet FortiOS before 7.0.0 allows denial of service.")
    taken = intake(copy, [old], now=now, source="test")
    assert taken and taken[0]["exposed"] == 0 and taken[0]["action"] == "no exposure"
    assert copy.execute("SELECT COUNT(*) FROM assessments WHERE cve_id = 'CVE-2026-999003' AND R > 0").fetchone()[0] == 0
