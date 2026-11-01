"""Channels: selected audit-trail events become one alert card each and reach the apps a team configures (Slack,
Discord, Teams, a webhook, e-mail), with a severity floor, de-duplication, a per-minute cap and a summary of what was
held back, back-off for a dead destination, secrets never written back, and every delivery audited in the ledger."""

import json
import shutil
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from backend.app import notify
from backend.app.engine.ledger import Ledger

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "ews.db"
SQLI = {"app": "citypower-portal", "source_ip": "203.0.113.66", "category": "SQL injection", "severity": "High", "cwe": "CWE-89",
        "attack": "T1190", "path": "/search", "decision": "block", "success": False, "evidence": "q=' OR 1=1--"}


class Receiver:
    """A real HTTP destination on loopback: records every JSON body; `fail` makes it answer 500."""

    def __init__(self):
        self.bodies, self.fail = [], False
        recv = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                recv.bodies.append(json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}"))
                self.send_response(500 if recv.fail else 200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}/hooks/odyssey"

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def receiver():
    r = Receiver()
    yield r
    r.close()


@pytest.fixture
def notifier(tmp_path, receiver):
    if not DB.exists():
        pytest.skip("data/ews.db not built")
    copy = tmp_path / "ews.db"
    shutil.copy(DB, copy)

    def connect():
        conn = sqlite3.connect(copy, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    cfg = tmp_path / "notify.json"
    cfg.write_text(json.dumps({
        "public_url": "http://127.0.0.1:5173",
        "routing": {"min_severity": "High", "kinds": ["shield.detect.*", "live.detect.*", "auto.proposed", "auto.case_opened"],
                    "dedupe_minutes": 10, "per_minute_cap": 20},
        "channels": [{"name": "console", "type": "webhook", "url": "${HOOK}", "enabled": True},
                     {"name": "slack", "type": "slack", "url": "${ODYSSEY_SLACK_WEBHOOK:}", "enabled": True}]}), encoding="utf-8")
    n = notify.Notifier(connect, config_path=cfg, local_path=tmp_path / "none.json", env={"HOOK": receiver.url})
    n.connect = connect
    return n


def _append(n, kind, subject, payload, provenance="REAL"):
    conn = n.connect()
    try:
        Ledger(conn=conn).append(ts="2026-11-01T00:00:00Z", kind=kind, subject=subject, source="TEST", provenance=provenance, payload=payload)
    finally:
        conn.close()


def _ledger(n, kind, channel="console"):
    """This file's own audit events. The fixture copies the live database, which may already hold deliveries the
    running system made to its channels, so only the channel configured here is counted."""
    conn = n.connect()
    try:
        rows = conn.execute("SELECT payload FROM ledger WHERE kind = ? ORDER BY seq", (kind,)).fetchall()
    finally:
        conn.close()
    return [p for p in (json.loads(r[0]) for r in rows) if p.get("channel") == channel]


# --- cards -------------------------------------------------------------------------------------------------------
def test_cards_from_the_events_people_should_hear_about():
    url = "http://127.0.0.1:5173"
    c = notify.card({"kind": "shield.detect.sqli", "subject": "citypower-portal:203.0.113.66", "provenance": "REAL", "payload": SQLI}, url)
    assert c["title"] == "Blocked: SQL injection on citypower-portal from 203.0.113.66" and c["severity"] == "High"
    assert any("CWE-89" in x for x in c["lines"]) and c["link"].startswith(url)
    assert notify.card({"kind": "live.detect.beacon", "subject": "A1", "payload": {"title": "vpn-gw01 is beaconing", "seconds_to_detect": 12.5}}, url)["severity"] == "Compromise"
    assert notify.card({"kind": "live.intake", "subject": "CVE-2026-1", "payload": {"cve": "CVE-2026-1", "worst": "Critical", "exposed": 3, "orgs": ["PWR-01"], "action": "notified"}}, url)["severity"] == "Critical"
    assert notify.card({"kind": "auto.proposed", "subject": "x", "payload": {"title": "Block 203.0.113.66", "orgs": ["PWR-01"]}}, url)["title"].startswith("Decision needed:")
    assert notify.card({"kind": "auto.case_opened", "subject": "CASE-0191", "payload": {"title": "Web attack", "severity": "Compromise", "owner": "m.khan", "due_hours": 6}}, url)["title"].startswith("Case CASE-0191 opened")
    assert notify.card({"kind": "vuln.published", "subject": "CVE-2026-2", "payload": {}}, url) is None
    assert notify.card({"kind": "notify.sent", "subject": "console:x", "payload": {}}, url) is None


def test_one_card_five_shapes():
    c = notify.card({"kind": "shield.detect.sqli", "subject": "s", "ts": "2026-11-01T00:00:00Z", "provenance": "REAL",
                     "payload": {**SQLI, "severity": "Critical"}}, "http://127.0.0.1:5173")
    slack = notify.fmt_slack(c)
    assert slack["text"].startswith("[Odyssey] Critical:") and slack["blocks"][0]["type"] == "section"
    discord = notify.fmt_discord(c)
    assert discord["embeds"][0]["color"] == 0xE11900 and discord["embeds"][0]["url"] == c["link"]
    teams = notify.fmt_teams(c)
    assert teams["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert teams["attachments"][0]["content"]["actions"][0]["type"] == "Action.OpenUrl"
    hook = notify.fmt_webhook(c)
    assert hook["source"] == "odyssey" and hook["event"]["kind"] == "shield.detect.sqli" and hook["when_ist"].endswith("IST")
    subject, body = notify.fmt_email(c)
    assert subject.startswith("[Odyssey] Critical:") and c["link"] in body


# --- configuration -----------------------------------------------------------------------------------------------
def test_local_file_and_environment_configure_channels_and_secrets_stay_masked(tmp_path):
    base = tmp_path / "notify.json"
    base.write_text(json.dumps({"public_url": "${ODYSSEY_PUBLIC_URL:http://127.0.0.1:5173}", "routing": {"min_severity": "High"},
                                "channels": [{"name": "slack", "type": "slack", "url": "${ODYSSEY_SLACK_WEBHOOK:}", "enabled": True},
                                             {"name": "discord", "type": "discord", "url": "", "enabled": True}]}), encoding="utf-8")
    local = tmp_path / "notify.local.json"
    local.write_text(json.dumps({"channels": [{"name": "discord", "url": "https://discord.com/api/webhooks/123/SECRETTOKEN"}]}), encoding="utf-8")
    cfg = notify.load_config(base, local, env={"ODYSSEY_PUBLIC_URL": "https://odyssey.example.org"})
    by = {c["name"]: c for c in cfg["channels"]}
    assert cfg["public_url"] == "https://odyssey.example.org"
    assert not notify.configured(by["slack"]) and notify.configured(by["discord"])
    assert notify.destination(by["discord"]) == "discord.com/…" and "SECRETTOKEN" not in notify.destination(by["discord"])
    assert notify.destination({"type": "webhook", "url": "http://127.0.0.1:8090/hooks/odyssey"}) == "127.0.0.1:8090/hooks/odyssey"
    assert base.read_text(encoding="utf-8").count("SECRETTOKEN") == 0  # nothing is ever written back


# --- delivery ----------------------------------------------------------------------------------------------------
def test_delivers_each_new_event_once_and_audits_it(notifier, receiver):
    assert notifier.poll_once() == 0  # nothing before the start is replayed
    _append(notifier, "shield.detect.sqli", "citypower-portal:203.0.113.66", SQLI)
    assert notifier.poll_once() == 1
    assert receiver.bodies[-1]["title"].startswith("Blocked: SQL injection") and receiver.bodies[-1]["source"] == "odyssey"
    sent = _ledger(notifier, "notify.sent")
    assert len(sent) == 1 and sent[0]["channel"] == "console" and "url" not in sent[0] and "127.0.0.1" in sent[0]["destination"]
    st = notifier.status()
    console, slack = (next(c for c in st["channels"] if c["name"] == n) for n in ("console", "slack"))
    assert console["sent"] == 1 and console["status"] == "ok" and not slack["configured"] and slack["sent"] == 0
    assert notifier.poll_once() == 0 and len(receiver.bodies) == 1
    _append(notifier, "shield.detect.sqli", "citypower-portal:203.0.113.66", SQLI)   # the same source again: folded
    assert notifier.poll_once() == 0 and notifier.suppressed_dupes == 1
    _append(notifier, "shield.detect.sqli", "citypower-portal:203.0.113.67", {**SQLI, "source_ip": "203.0.113.67"})
    assert notifier.poll_once() == 1 and len(receiver.bodies) == 2


def test_severity_floor_and_unrouted_kinds(notifier, receiver):
    _append(notifier, "shield.detect.scanner", "p:198.51.100.9", {**SQLI, "severity": "Medium", "category": "Scanner fingerprint"})
    _append(notifier, "vuln.published", "CVE-2026-7", {"cvss_vector": None})
    _append(notifier, "auto.notify", "PWR-01:CVE-2026-7", {"title": "not in this policy's kinds", "tier": "Critical"})
    assert notifier.poll_once() == 0 and receiver.bodies == []


def test_cap_holds_the_flood_and_sends_one_summary(notifier, receiver):
    notifier.cfg["routing"]["per_minute_cap"] = 2
    t = 1_800_000_000.0
    for i in range(4):
        _append(notifier, "shield.detect.xss", f"p:10.0.0.{i}", {**SQLI, "category": "Cross-site scripting", "source_ip": f"10.0.0.{i}"})
    assert notifier.poll_once(now=t) == 2 and notifier.held == 2 and len(receiver.bodies) == 2
    assert notifier.poll_once(now=t + 61) == 0          # the window rolled: the summary goes out
    assert len(receiver.bodies) == 3 and "2 more alert(s)" in receiver.bodies[-1]["title"]
    assert notifier.status()["stats"]["held_by_cap"] == 2


def test_dead_destination_is_audited_and_backed_off(notifier, receiver):
    receiver.fail = True
    _append(notifier, "shield.detect.sqli", "p:10.1.0.1", {**SQLI, "source_ip": "10.1.0.1"})
    assert notifier.poll_once() == 0
    c = next(x for x in notifier.status()["channels"] if x["name"] == "console")
    assert c["status"] == "failing" and c["failed"] == 1 and c["backing_off"] and "HTTPStatusError" in c["last_error"]
    assert len(_ledger(notifier, "notify.failed")) == 1
    receiver.fail = False
    _append(notifier, "shield.detect.sqli", "p:10.1.0.2", {**SQLI, "source_ip": "10.1.0.2"})
    assert notifier.poll_once() == 0 and len(receiver.bodies) == 1   # still backing off: one dead URL never blocks the loop
    assert notifier.test("console")["ok"]                              # a test ignores the back-off, and clears it
    assert next(x for x in notifier.status()["channels"] if x["name"] == "console")["status"] == "ok"


def test_test_alert_only_for_a_configured_channel(notifier, receiver):
    rec = notifier.test("console")
    assert rec["ok"] and rec["test"] and receiver.bodies[-1]["title"].startswith("Test alert from Odyssey")
    assert _ledger(notifier, "notify.sent")[-1]["test"] is True
    with pytest.raises(ValueError):
        notifier.test("slack")
    with pytest.raises(KeyError):
        notifier.test("nope")


def test_mute_from_the_dashboard_outlives_a_restart(notifier, receiver):
    notifier.set_enabled("console", False)
    assert not next(c for c in notifier.status()["channels"] if c["name"] == "console")["enabled"]
    _append(notifier, "shield.detect.sqli", "p:10.2.0.1", {**SQLI, "source_ip": "10.2.0.1"})
    assert notifier.poll_once() == 0 and receiver.bodies == []
    again = notify.Notifier(notifier.connect, config_path=notifier.paths[0], local_path=notifier.paths[1], env=notifier.env)
    assert not next(c for c in again.status()["channels"] if c["name"] == "console")["enabled"]
    again.set_enabled("console", True)
    assert notify.Notifier(notifier.connect, config_path=notifier.paths[0], local_path=notifier.paths[1], env=notifier.env) \
        .status()["channels"][0]["enabled"]
