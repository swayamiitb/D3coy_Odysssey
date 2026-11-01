"""SACHET connector: NDMA's public-domain CAP feed read and matched to the operators' states, Odyssey's SACHET-compatible
CAP writer, and the hardened inbound CAP guard (DTDs and entities refused before parsing, size, well-formedness, required
fields, authorised senders, replay, stale, flood), every decision one hash-chained ledger row. The red-team cases fire
only at Odyssey's own loopback endpoint; the planted secret proves XXE never reached the parser."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from backend.app import sachet
from backend.app.engine.ledger import Ledger
from backend.app.sachet import CAP_NS, CapGuard, infer_states, match_orgs, parse_cap, parse_rss, safe_parse, sender_allowed, write_cap

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "ews.db"
RSS = ROOT / "data" / "raw" / "sachet_rss.xml"
CAP_SAMPLE = ROOT / "data" / "raw" / "sachet_cap_sample.xml"
NOW = dt.datetime(2026, 11, 1, 2, 0, tzinfo=dt.timezone.utc)
TRUSTED = "IMD-Chennai"
LIVE = "http://127.0.0.1:8000"
TELUGU = "మీ ప్రాంతంలో"  # Telugu script only, no state or district named
HINDI = "वीपीएन गेटवे को पैच करें"


@pytest.fixture(scope="module")
def connect(tmp_path_factory):
    if not DB.exists():
        pytest.skip("no built database")
    path = tmp_path_factory.mktemp("sachet") / "ews.db"
    src, dst = sqlite3.connect(f"file:{DB}?mode=ro", uri=True), sqlite3.connect(path)
    src.backup(dst)
    src.close()
    dst.close()
    return lambda: sqlite3.connect(path, timeout=30, check_same_thread=False)


@pytest.fixture(scope="module")
def guard(connect):
    return CapGuard(connect)


@pytest.fixture(scope="module")
def orgs(connect):
    conn = connect()
    try:
        return [dict(zip(("id", "name", "sector", "state"), r)) for r in conn.execute("SELECT id, name, sector, state FROM orgs")]
    finally:
        conn.close()


def _ident(tag: str) -> str:
    return f"TEST-{tag}-{uuid.uuid4().hex[:8]}"


def _alert(identifier: str, sender: str | None = TRUSTED, expires: str | None = None, headline: str = "Odyssey CAP test",
           area: str = "Chennai, Tamil Nadu", ns: str = CAP_NS) -> bytes:
    snd = f"<sender>{sender}</sender>" if sender is not None else ""
    exp = f"<expires>{expires}</expires>" if expires else ""
    return (f'<?xml version="1.0" encoding="UTF-8"?><alert xmlns="{ns}"><identifier>{identifier}</identifier>{snd}'
            f"<sent>2026-11-01T06:44:49+05:30</sent><status>Exercise</status><msgType>Alert</msgType><scope>Public</scope>"
            f"<info><language>en-IN</language><category>Met</category><event>Heavy Rain</event><urgency>Expected</urgency>"
            f"<severity>Moderate</severity><certainty>Likely</certainty>{exp}<headline>{headline}</headline>"
            f"<area><areaDesc>{area}</areaDesc></area></info></alert>").encode("utf-8")


def _head(connect) -> int:
    conn = connect()
    try:
        return conn.execute("SELECT COALESCE(MAX(seq), 0) FROM ledger").fetchone()[0]
    finally:
        conn.close()


def _ledger(connect, since: int) -> list[dict]:
    conn = connect()
    try:
        rows = conn.execute("SELECT seq, kind, subject, provenance, payload FROM ledger WHERE seq > ? ORDER BY seq", (since,)).fetchall()
        return [{"seq": r[0], "kind": r[1], "subject": r[2], "provenance": r[3], "payload": json.loads(r[4])} for r in rows]
    finally:
        conn.close()


def _api_up() -> bool:
    """GET /api/health answers within 2 s (two attempts: the endpoint re-verifies the whole ledger and can be busy)."""
    import httpx
    for _ in range(2):
        try:
            if httpx.get(f"{LIVE}/api/health", timeout=2).status_code == 200:
                return True
        except Exception:  # noqa: BLE001
            pass
    return False


# ------------------------------------------------------------------------------------------------------ the reader
def test_rss_snapshot_parses_and_matches_operators(orgs):
    if not RSS.exists():
        pytest.skip("no SACHET RSS snapshot")
    items = parse_rss(RSS.read_bytes())
    assert len(items) == 100
    assert all(i["identifier"] and i["published"] and i["title"] and i["link"].startswith("https://sachet.ndma.gov.in/") for i in items)
    assert all(i["published"].endswith("Z") for i in items)
    states = [infer_states(i["title"], i["author"]) for i in items]
    with_state = [s for s in states if s]
    assert len(with_state) >= 95
    assert all(s["basis"] and 0 < s["confidence"] <= 1 and s["state"] in sachet.STATES for st in with_state for s in st)
    matched = [m for m in (match_orgs(s, orgs) for s in states) if m]
    assert len(matched) >= 50
    known = {o["id"] for o in orgs}
    assert all(m["org_id"] in known and m["basis"] and m["state"] and m["sector"] for ms in matched for m in ms)


def test_cap_sample_parses_and_names_tamil_nadu(guard):
    if not CAP_SAMPLE.exists():
        pytest.skip("no SACHET CAP sample")
    raw = CAP_SAMPLE.read_bytes()
    cap = parse_cap(raw)
    assert cap["identifier"] and cap["sender"] == "IMD-Chennai" and cap["status"] == "Actual" and cap["namespace"] == CAP_NS
    assert cap["msgType"] == "Alert" and cap["sent"] and cap["expires"]
    assert len(cap["infos"]) == 1
    info = cap["infos"][0]
    assert info["event"] and info["severity"] and info["areas"]
    assert "Tamil Nadu" in info["areas"][0] and "Coimbatore" in info["areas"][0]
    states = infer_states(info["headline"] or info["event"], cap["sender"], info["areas"], cap["sender"])
    assert states and states[0]["state"] == "Tamil Nadu" and states[0]["confidence"] >= 0.9
    # the same message through fetch_cap with an injected fetch: SACHET's own host only
    got = guard.fetch_cap("https://sachet.ndma.gov.in/cap_public_website/FetchXMLFile?identifier=1793495717294007", fetch=lambda url: raw)
    assert got["identifier"] == cap["identifier"] and got["states"][0]["state"] == "Tamil Nadu"
    with pytest.raises(ValueError, match="sachet.ndma.gov.in"):
        guard.fetch_cap("https://example.com/alert.xml", fetch=lambda url: raw)


def test_infer_states_carries_basis_and_confidence():
    odisha = infer_states("Heavy rain very likely over coastal Odisha in the next 3 hours")
    assert odisha == [{"state": "Odisha", "basis": "state named: Odisha", "confidence": 0.95}]
    kolkata = infer_states("Thunderstorm with lightning likely", "controlroom@ndma.gov.in (IMD Kolkata)")
    assert [s["state"] for s in kolkata] == ["West Bengal"]
    assert kolkata[0]["basis"].startswith("sender office:") and kolkata[0]["confidence"] == 0.85
    sdma = infer_states("Lightning likely in your area", "controlroom@ndma.gov.in (Andhra Pradesh SDMA)")
    assert [s["state"] for s in sdma] == ["Andhra Pradesh"]
    assert sdma[0]["basis"].startswith("sender:") and sdma[0]["confidence"] == 0.9
    district = infer_states("Light to moderate rain likely over Coimbatore in the next 3 hours")
    assert district == [{"state": "Tamil Nadu", "basis": "district named: Coimbatore", "confidence": 0.75}]
    assert infer_states("Thunderstorm with lightning likely in the next 3 hours") == []
    # strongest basis first; a stronger basis replaces a weaker one for the same state
    both = infer_states("Rain over Chennai, Tamil Nadu and Kolkata", "IMD-Chennai")
    assert [s["state"] for s in both] == ["Tamil Nadu", "West Bengal"] and both[0]["basis"] == "state named: Tamil Nadu"


def test_infer_states_script_hint_for_a_pure_telugu_title():
    got = infer_states(TELUGU)
    assert {s["state"] for s in got} == {"Andhra Pradesh", "Telangana"}
    assert all(s["basis"] == "text in Telugu script" and s["confidence"] == 0.4 for s in got)


def test_sender_allow_list():
    table = {"IMD-Chennai": True, "controlroom@ndma.gov.in (IMD Chennai)": True, "a@imd.gov.in": True, "odyssey@ncew.local": True,
             "IMD": False, "EVIL": False, "x@evil-ndma.gov.in.attacker.com": False, "a@ndma.gov.in.evil.com": False, "": False}
    assert {s: sender_allowed(s) for s in table} == table


# ------------------------------------------------------------------------------------------------------- the guard
def test_xxe_is_refused_before_parsing_and_the_secret_never_leaks(guard, connect, tmp_path):
    secret = f"PLANTED-{uuid.uuid4().hex}"
    secret_path = tmp_path / "planted-secret.txt"
    secret_path.write_text(secret, encoding="utf-8")
    body = (f'<?xml version="1.0"?><!DOCTYPE alert [<!ENTITY xxe SYSTEM "{secret_path.resolve().as_uri()}">]><alert xmlns="{CAP_NS}">'
            f"<identifier>{_ident('xxe')}</identifier><sender>{TRUSTED}</sender><sent>2026-11-01T06:44:49+05:30</sent>"
            f"<status>Exercise</status><msgType>Alert</msgType><scope>Public</scope><info><headline>&xxe;</headline></info></alert>").encode()
    with pytest.raises(ValueError, match="xxe"):
        safe_parse(body)
    with pytest.raises(ValueError, match="xxe"):
        safe_parse(b'<?xml version="1.0"?><!doctype x><alert/>')
    head, before = _head(connect), guard.counts["xxe"]
    out = guard.ingest(body, source_ip="10.9.0.1")
    assert out["accepted"] is False and out["reason"] == "xxe" and "before parsing" in out["detail"]
    assert out["states"] == [] and out["orgs"] == [] and secret not in json.dumps(out)
    rows = _ledger(connect, head)
    assert len(rows) == 1 and rows[0]["kind"] == "cap.ingest.refused" and rows[0]["provenance"] == "REAL"
    assert rows[0]["payload"]["reason"] == "xxe" and secret not in json.dumps(rows[0]["payload"])
    assert guard.counts["xxe"] == before + 1
    assert secret_path.read_text(encoding="utf-8") == secret


def test_entity_expansion_and_oversize_are_refused(guard):
    lol = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
           '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>'
           f'<alert xmlns="{CAP_NS}"><identifier>{_ident("lol")}</identifier><sender>{TRUSTED}</sender><sent>2026-11-01T06:44:49+05:30</sent>'
           "<info><headline>&lol3;</headline></info></alert>").encode()
    out = guard.ingest(lol, source_ip="10.9.0.2")
    assert out["accepted"] is False and out["reason"] == "xxe"
    big = _alert(_ident("big"), headline="x" * (3 * 1024 * 1024))
    assert len(big) > sachet.MAX_XML_BYTES
    out = guard.ingest(big, source_ip="10.9.0.2")
    assert out["accepted"] is False and out["reason"] == "oversize" and str(sachet.MAX_XML_BYTES) in out["detail"]


def test_malformed_and_incomplete_alerts_are_refused(guard):
    assert guard.ingest(b"<html/>", source_ip="10.9.0.3")["reason"] == "malformed"
    assert guard.ingest(b"<alert><identifier>x</identifier", source_ip="10.9.0.3")["reason"] == "malformed"
    assert guard.ingest(b"", source_ip="10.9.0.3")["reason"] == "malformed"
    out = guard.ingest(_alert(_ident("nosender"), sender=None), source_ip="10.9.0.3")
    assert out["accepted"] is False and out["reason"] == "missing_fields" and "sender" in out["detail"]
    out = guard.ingest(_alert(_ident("ns"), ns="urn:example:not-cap"), source_ip="10.9.0.3")
    assert out["reason"] == "malformed" and "namespace" in out["detail"]


def test_forged_sender_is_refused(guard):
    out = guard.ingest(_alert(_ident("forged"), sender="EVIL-Agency"), source_ip="10.9.0.4")
    assert out["accepted"] is False and out["reason"] == "untrusted_sender" and "EVIL-Agency" in out["detail"]
    assert out["states"] == [] and out["orgs"] == []
    out = guard.ingest(_alert(_ident("lookalike"), sender="ops@ndma.gov.in.evil.com"), source_ip="10.9.0.4")
    assert out["reason"] == "untrusted_sender"


def test_trusted_alert_is_accepted_once_then_replay_is_refused(guard):
    ident = _ident("ok")
    body = _alert(ident)
    out = guard.ingest(body, source_ip="10.9.0.5")
    assert out["accepted"] is True and out["reason"] is None and out["detail"] is None
    assert out["identifier"] == ident and out["sender"] == TRUSTED and out["event"] == "Heavy Rain" and out["severity"] == "Moderate"
    assert [s["state"] for s in out["states"]] == ["Tamil Nadu"] and out["states"][0]["basis"] == "state named: Tamil Nadu"
    assert out["orgs"] and all(o["state"] == "Tamil Nadu" for o in out["orgs"]) and "BFS-02" in {o["org_id"] for o in out["orgs"]}
    again = guard.ingest(body, source_ip="10.9.0.5")
    assert again["accepted"] is False and again["reason"] == "replay" and ident in again["detail"]
    dec = guard.decisions(5)
    assert dec[0]["identifier"] == ident and dec[0]["accepted"] is False and dec[0]["reason"] == "replay"
    assert dec[1]["identifier"] == ident and dec[1]["accepted"] is True and dec[1]["states"][0]["state"] == "Tamil Nadu"
    assert dec[1]["areas"] == ["Chennai, Tamil Nadu"] and dec[1]["source_ip"] == "10.9.0.5" and dec[1]["bytes"] == len(body)
    assert all("raw" not in d for d in dec)
    assert guard.inbound_alerts(1)[0]["identifier"] == ident


def test_stale_alert_is_refused(guard):
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    out = guard.ingest(_alert(_ident("stale"), expires=past), source_ip="10.9.0.6")
    assert out["accepted"] is False and out["reason"] == "stale" and past in out["detail"]
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    assert guard.ingest(_alert(_ident("fresh"), expires=future), source_ip="10.9.0.6")["accepted"] is True


def test_flood_is_rate_limited_per_source(guard):
    before = guard.counts["rate_limited"]
    outs = [guard.ingest(_alert(_ident(f"flood{i}")), source_ip="10.9.0.7") for i in range(sachet.RATE_MAX + 1)]
    limited = [o for o in outs if o["reason"] == "rate_limited"]
    assert limited and outs[-1]["reason"] == "rate_limited" and str(sachet.RATE_MAX) in outs[-1]["detail"]
    assert sum(1 for o in outs if o["accepted"]) == sachet.RATE_MAX
    assert guard.counts["rate_limited"] == before + len(limited)
    assert guard.ingest(_alert(_ident("other")), source_ip="10.9.0.8")["accepted"] is True


def test_every_ingest_writes_one_ledger_row_with_its_provenance(guard, connect):
    head = _head(connect)
    real = guard.ingest(_alert(_ident("real")), source_ip="10.9.0.9")
    sim = guard.ingest(_alert(_ident("sim")), source_ip="10.9.0.9", redteam="CAPRT-TEST")
    guard.ingest(_alert(_ident("bad"), sender="EVIL"), source_ip="10.9.0.9", redteam="CAPRT-TEST")
    rows = _ledger(connect, head)
    assert [r["kind"] for r in rows] == ["cap.ingest.accepted", "cap.ingest.accepted", "cap.ingest.refused"]
    assert [r["provenance"] for r in rows] == ["REAL", "SIM", "SIM"]
    assert rows[0]["subject"] == real["identifier"] and rows[0]["payload"]["redteam"] is None and rows[0]["payload"]["states"] == ["Tamil Nadu"]
    assert "BFS-02" in rows[0]["payload"]["orgs"] and rows[0]["payload"]["sender"] == TRUSTED
    assert rows[1]["payload"]["redteam"] == "CAPRT-TEST" and sim["redteam"] == "CAPRT-TEST"
    assert rows[2]["payload"]["reason"] == "untrusted_sender" and rows[2]["payload"]["source_ip"] == "10.9.0.9"
    assert all(r["payload"]["bytes"] > 0 for r in rows)
    conn = connect()
    try:
        assert Ledger(conn=conn).verify() == (True, None)
    finally:
        conn.close()


# ------------------------------------------------------------------------------------------------------ the writer
def test_write_cap_round_trips_two_languages():
    alert = {"identifier": "ODY-TEST-CVE-2026-104935", "tier": "Compromise", "event": "Cyber threat warning: CVE-2026-104935 on Vidyut Grid West Corp",
             "areas": ["Vidyut Grid West Corp, Maharashtra", "Maharashtra"], "parameters": {"cve": "CVE-2026-104935", "odyssey:tier": "Compromise"},
             "web": "http://127.0.0.1:5173/?view=soc", "contact": "duty officer", "note": "SACHET-compatible CAP produced by the Odyssey prototype"}
    infos = [{"language": "en-IN", "headline": "Patch the VPN gateway", "description": "why it matters", "instruction": "what to do"},
             {"language": "hi-IN", "headline": HINDI, "description": HINDI, "instruction": HINDI}]
    xml = write_cap(alert, infos, now=NOW)
    assert xml.startswith('<?xml version="1.0" encoding="UTF-8"?>') and f'xmlns="{CAP_NS}"' in xml
    cap = parse_cap(xml)
    assert cap["namespace"] == CAP_NS and cap["identifier"] == alert["identifier"] and cap["sender"] == sachet.OWN_SENDER
    assert cap["status"] == "Exercise" and cap["msgType"] == "Alert" and cap["scope"] == "Restricted"
    assert [i["language"] for i in cap["infos"]] == ["en-IN", "hi-IN"]
    assert all(i["severity"] == "Extreme" and i["urgency"] == "Immediate" and i["category"] == "Security" for i in cap["infos"])
    assert cap["infos"][1]["headline"] == HINDI and cap["infos"][1]["instruction"] == HINDI
    assert all(i["areas"] == alert["areas"] for i in cap["infos"])
    assert "<parameter>" in xml and "<valueName>cve</valueName>" in xml and "<value>CVE-2026-104935</value>" in xml
    assert sachet._when(cap["expires"]) == NOW + dt.timedelta(hours=24) and cap["sent"].endswith("+05:30")
    assert "not NDMA" in xml and sender_allowed(cap["sender"])
    assert parse_cap(write_cap(alert, infos, status="Actual", now=NOW))["status"] == "Actual"


def test_write_cap_escapes_markup_and_maps_tiers():
    alert = {"identifier": "ODY-TEST-XSS", "tier": "High", "event": "Cyber threat warning", "areas": ["Chennai, Tamil Nadu"]}
    infos = [{"language": "en-IN", "headline": "<script>alert(1)</script>", "description": "a & b <c>", "instruction": "x"}]
    xml = write_cap(alert, infos, now=NOW)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in xml and "<script>" not in xml
    cap = parse_cap(xml)
    assert cap["infos"][0]["headline"] == "<script>alert(1)</script>" and cap["infos"][0]["description"] == "a & b <c>"
    assert cap["infos"][0]["severity"] == "Moderate" and cap["infos"][0]["urgency"] == "Expected" and cap["status"] == "Exercise"
    for tier, sev in (("Compromise", "Extreme"), ("Critical", "Severe"), ("High", "Moderate"), ("Medium", "Minor"), ("Watch", "Minor")):
        assert parse_cap(write_cap(dict(alert, tier=tier), infos, now=NOW))["infos"][0]["severity"] == sev
    bare = write_cap({"identifier": "ODY-BARE"}, infos, now=NOW)
    assert "<parameter>" not in bare and parse_cap(bare)["infos"][0]["areas"] == ["India"]


# ---------------------------------------------------------------------------------------------------- the red team
def test_read_feed_serves_the_snapshot_offline_and_live_when_the_fetch_works(connect):
    if not RSS.exists():
        pytest.skip("no SACHET RSS snapshot")
    g = CapGuard(connect)

    def boom(url):
        raise ConnectionError("no route to host")

    off = g.read_feed(live=True, now=NOW, fetch=boom, force=True)
    assert off["status"] == "offline" and "ConnectionError" in off["detail"] and "snapshot" in off["detail"]
    assert off["count"] == 100 and off["matched"] >= 50 and off["fetched_at"] is None and off["last_try"] == "2026-11-01T02:00:00Z"
    assert off["provenance"] == "REAL" and off["source"].startswith("NDMA SACHET") and off["url"] == sachet.RSS_URL
    assert all(isinstance(i["states"], list) and isinstance(i["orgs"], list) for i in off["items"])
    assert off["by_state"] and sum(off["by_state"].values()) <= off["count"] and all(s in sachet.STATES for s in off["by_state"])
    seen = []

    def fake(url):
        seen.append(url)
        return RSS.read_bytes()

    fresh = g.read_feed(live=True, now=NOW, fetch=fake, force=True)
    assert seen == [sachet.RSS_URL] and fresh["status"] == "fresh" and "read live" in fresh["detail"]
    assert fresh["fetched_at"] == "2026-11-01T02:00:00Z" and fresh["ms"] is not None and fresh["count"] == 100
    cached = g.read_feed(live=True, fetch=boom)  # not due again for 15 minutes: no fetch, same answer
    assert cached["status"] == "fresh" and cached["count"] == 100
    snap = g.read_feed(live=False, fetch=boom, force=True)
    assert snap["status"] == "snapshot" and snap["count"] == 100 and "snapshot" in snap["detail"]


def test_status_shape(guard):
    s = guard.status()
    assert set(s) == {"feed", "ingest", "trusted", "limits", "how"}
    assert "items" not in s["feed"] and s["feed"]["status"] in ("fresh", "snapshot", "offline")
    assert {"status", "fetched_at", "last_try", "detail", "ms", "count", "matched", "by_state"} <= set(s["feed"])
    assert set(s["ingest"]) == {"accepted", "refused", "total"} and set(s["ingest"]["refused"]) == set(sachet.REFUSALS)
    assert s["ingest"]["total"] == s["ingest"]["accepted"] + sum(s["ingest"]["refused"].values())
    assert s["ingest"]["accepted"] == guard.counts["accepted"] and s["ingest"]["refused"]["xxe"] == guard.counts["xxe"]
    assert s["trusted"] == {"domains": list(sachet.TRUSTED_DOMAINS), "prefixes": list(sachet.TRUSTED_PREFIXES), "own": sachet.OWN_SENDER}
    assert s["limits"] == {"max_bytes": 2 * 1024 * 1024, "rate_per_minute": 30}
    assert "validate, don't trust" in s["how"]


# ------------------------------------------------------------------------------------- the red team, adversarial review
import re  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402
import time as _time  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402


class _FakeCap:
    """A loopback stand-in for the ingest whose behaviour the test picks: a JSON list, HTML, a redirect, a slow answer,
    a parser that expanded the external entity (and echoes what the real ingest echoes), or a limiter with a chosen cap."""

    def __init__(self):
        self.mode, self.limit, self.seen, self.count, self.read_secret = "json_list", 30, [], 0, None
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                srv.seen.append(body)
                srv.count += 1
                status, ct, out, extra = 200, "application/json", b"{}", {}
                if srv.mode == "json_list":
                    out = b"[1, 2]"
                elif srv.mode == "html":
                    status, ct, out = 500, "text/html", b"<h1>boom</h1>"
                elif srv.mode == "redirect":
                    status, out, extra = 307, b"", {"location": "http://example.invalid/collect"}
                elif srv.mode == "slow":
                    _time.sleep(1.0)
                    out = b'{"accepted": false, "reason": "late"}'
                elif srv.mode == "vulnerable":
                    txt = body.decode("utf-8", "replace")
                    m = re.search(r'<!ENTITY xxe SYSTEM "([^"]+)"', txt)
                    if m:
                        srv.read_secret = Path.from_uri(m.group(1)).read_text(encoding="utf-8")
                        txt = txt.replace("&xxe;", srv.read_secret)
                    ev = re.search(r"<event>(.*?)</event>", txt, re.S)
                    out = json.dumps({"accepted": True, "reason": None, "detail": None, "identifier": "x", "sender": TRUSTED,
                                      "event": ev.group(1) if ev else None, "severity": None, "states": [], "orgs": [], "redteam": "r"}).encode()
                elif srv.mode == "limiter":
                    refused = srv.count > srv.limit
                    out = json.dumps({"accepted": not refused, "reason": "rate_limited" if refused else None}).encode()
                self.send_response(status)
                self.send_header("content-type", ct)
                self.send_header("content-length", str(len(out)))
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(out)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api/sensor/cap"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake_cap():
    f = _FakeCap()
    yield f
    f.close()



def _dtd_body(identifier: str, decl: str = '<?xml version="1.0"?>') -> str:
    """A CAP alert carrying a DTD with an entity; used to prove a DOCTYPE cannot hide behind any encoding."""
    return (f'{decl}<!DOCTYPE alert [<!ENTITY lol "lol">]><alert xmlns="{CAP_NS}"><identifier>{identifier}</identifier>'
            f'<sender>{TRUSTED}</sender><sent>2026-11-01T06:44:49+05:30</sent><status>Exercise</status><msgType>Alert</msgType>'
            f'<scope>Public</scope><info><headline>&lol;</headline></info></alert>')


def test_review_dtd_is_refused_whatever_the_encoding(guard):
    """A UTF-16 body hid <!DOCTYPE from the byte search (as '<', NUL, '!', NUL, ...) and expat parsed the DTD, entity expanded."""
    body = _dtd_body(_ident("enc"))
    hostile = {"utf-16 BOM": body.encode("utf-16"), "utf-16-le": body.encode("utf-16-le"), "utf-16-be": body.encode("utf-16-be"),
               "utf-16-be BOM": b"\xfe\xff" + body.encode("utf-16-be"), "utf-32 BOM": body.encode("utf-32"), "utf-32-le": body.encode("utf-32-le"),
               "utf-8 BOM": b"\xef\xbb\xbf" + body.encode(),
               "latin-1 declared": _dtd_body(_ident("l1"), '<?xml version="1.0" encoding="ISO-8859-1"?>').encode("latin-1"),
               "utf-7 declared": _dtd_body(_ident("u7"), '<?xml version="1.0" encoding="utf-7"?>').encode("utf-7"),
               "utf-16 declared, no BOM": _dtd_body(_ident("d16"), '<?xml version="1.0" encoding="UTF-16"?>').encode("utf-16-le")}
    for name, raw in hostile.items():
        with pytest.raises(ValueError, match="xxe"):
            safe_parse(raw)
        out = guard.ingest(raw, source_ip="10.9.1.1", redteam="REVIEW")
        assert out["reason"] == "xxe", (name, out)
    # nothing legitimate is lost: the same alert without a DTD parses in UTF-16 with its text intact
    clean = body.replace('<!DOCTYPE alert [<!ENTITY lol "lol">]>', "").replace("&lol;", "café మీ")
    assert parse_cap(clean.encode("utf-16"))["infos"][0]["headline"] == "café మీ"
    assert parse_cap(clean.encode("utf-16-be"))["sender"] == TRUSTED
    # the size cap is applied to the raw bytes before any decoding
    with pytest.raises(ValueError, match="oversize"):
        safe_parse(("<a>" + "x" * (sachet.MAX_XML_BYTES // 2) + "</a>").encode("utf-16-le"))
    # an unreadable or unknown encoding is malformed, never parsed
    assert guard.ingest(b"<alert>\xff\xfe\xfa</alert>", source_ip="10.9.1.1", redteam="REVIEW")["reason"] == "malformed"
    bogus = _alert(_ident("bogus")).replace(b'encoding="UTF-8"', b'encoding="x-no-such"')
    assert guard.ingest(bogus, source_ip="10.9.1.1", redteam="REVIEW")["reason"] == "malformed"


def test_review_naive_expires_is_stale_not_a_crash(guard, connect):
    """RFC 2822 '-0000' parses to a naive datetime; comparing it with the aware `now` raised TypeError: HTTP 500, no ledger row."""
    assert sachet._when("Sun, 01 Nov 2026 01:15:19 -0000") == dt.datetime(2026, 11, 1, 1, 15, 19, tzinfo=dt.timezone.utc)
    assert sachet._when("2026-11-01T06:44:49").tzinfo is not None
    for odd in (b"2026-11-01T00:00:00Z", 123, "garbage", "", None, "99999-01-01T00:00:00Z"):
        got = sachet._when(odd)
        assert got is None or got.tzinfo is not None
    head = _head(connect)
    out = guard.ingest(_alert(_ident("naive"), expires="Sun, 01 Nov 2020 01:15:19 -0000"), source_ip="10.9.1.2", redteam="REVIEW")
    assert out["accepted"] is False and out["reason"] == "stale"
    rows = _ledger(connect, head)
    assert len(rows) == 1 and rows[0]["kind"] == "cap.ingest.refused" and rows[0]["payload"]["reason"] == "stale"


def test_review_sender_allow_list_bypasses_are_refused():
    """Three accepted forgeries: a trusted address in the display name, an agency prefix inside a local part, a second '@'."""
    refused = ['"ops@ndma.gov.in" <evil@attacker.com>', "IMD-evil@attacker.com", "IMD-x <evil@attacker.com>", "b@ndma.gov.in, a@evil.com",
               "a@ndma.gov.in@evil.com", "x@ndma.gov.in\n<y@evil.com>", "a@ndma.gov.in\x00@evil.com", "<evil@attacker.com>",
               "controlroom@ndmа.gov.in", "x@ｎｄｍａ.gov.in", "a@ndma.gov.in.evil.com", "x@evil-ndma.gov.in", "IMD", "NDM",
               "", None, 42]
    allowed = ["controlroom@ndma.gov.in (IMD Chennai)", "IMD-Chennai <controlroom@ndma.gov.in>", "a@sub.ndma.gov.in", "a@imd.gov.in", "a@NDMA.GOV.IN",
               "IMD-Chennai", "CWC-Delhi", "SDMA-Odisha", "NDMA", sachet.OWN_SENDER, "ndma.gov.in", b"IMD-Chennai"]
    assert [s for s in refused if sender_allowed(s)] == []
    assert [s for s in allowed if not sender_allowed(s)] == []


def test_review_replay_memory_survives_restart_for_long_identifiers(connect):
    """The table keeps 120 characters of an identifier; the reloaded set held the truncation while the check used the full string."""
    g = CapGuard(connect)
    ident = _ident("long") + "-" + "x" * 150
    assert g.ingest(_alert(ident), source_ip="10.9.1.3", redteam="REVIEW")["accepted"] is True
    assert g.ingest(_alert(ident), source_ip="10.9.1.3", redteam="REVIEW")["reason"] == "replay"
    again = CapGuard(connect)  # a restart: seen is reloaded from cap_ingest
    out = again.ingest(_alert(ident), source_ip="10.9.1.3", redteam="REVIEW")
    assert out["accepted"] is False and out["reason"] == "replay"
    stored = again.decisions(1)[0]["identifier"]
    assert len(stored) <= 120 and stored.startswith(ident[:55]) and "#" in stored
    short = _ident("short")
    assert CapGuard(connect).ingest(_alert(short), source_ip="10.9.1.3", redteam="REVIEW")["accepted"] is True
    assert CapGuard(connect).decisions(1)[0]["identifier"] == short  # short identifiers are stored as they are


def test_review_concurrent_copies_of_one_identifier_accept_exactly_one(connect, monkeypatch):
    """Check-then-record let every concurrent copy of one identifier through (8 of 8 accepted); the claim is now made under the lock."""
    import threading
    import time

    g = CapGuard(connect)
    real = sachet.match_orgs

    def slow(*a, **k):  # widen the window between the replay check and the write, as a busy database would
        time.sleep(0.05)
        return real(*a, **k)

    monkeypatch.setattr(sachet, "match_orgs", slow)
    body, results, barrier = _alert(_ident("race")), [], threading.Barrier(8)

    def worker(i):
        barrier.wait()
        results.append(g.ingest(body, source_ip=f"10.9.2.{i}", redteam="REVIEW"))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for r in results if r["accepted"]) == 1 and sum(1 for r in results if r["reason"] == "replay") == 7
    ident = results[0]["identifier"]
    conn = connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM cap_ingest WHERE identifier = ? AND accepted = 1", (ident,)).fetchone()[0] == 1
    finally:
        conn.close()


def test_review_a_refused_copy_does_not_poison_its_identifier(guard, connect):
    """The claim is released when the copy is refused (stale) or the write fails, so the identifier can still be accepted once."""
    ident = _ident("stale-then-fresh")
    assert guard.ingest(_alert(ident, expires="2020-01-01T00:00:00Z"), source_ip="10.9.1.4", redteam="REVIEW")["reason"] == "stale"
    assert guard.ingest(_alert(ident, expires="2099-01-01T00:00:00Z"), source_ip="10.9.1.4", redteam="REVIEW")["accepted"] is True
    g = CapGuard(connect)

    class Broken:
        def execute(self, *a, **k):
            raise sqlite3.OperationalError("database or disk is full")

        executescript = execute

        def commit(self):
            pass

        def close(self):
            pass

    good, g.connect = g.connect, lambda: Broken()
    ident = _ident("write-fails")
    with pytest.raises(sqlite3.OperationalError):
        g.ingest(_alert(ident), source_ip="10.9.1.4", redteam="REVIEW")
    g.connect = good
    assert g.ingest(_alert(ident), source_ip="10.9.1.4", redteam="REVIEW")["accepted"] is True


def test_review_snapshot_read_never_degrades_the_live_schedule(connect):
    """A live=False read (the graph, status()) at the 15-minute mark replaced the fresh feed with the snapshot and blocked
    the next live read for another 15 minutes."""
    if not RSS.exists():
        pytest.skip("no SACHET RSS snapshot")
    g, calls = CapGuard(connect), []

    def fake(url):
        calls.append(url)
        return RSS.read_bytes()

    assert g.read_feed(live=True, now=NOW, fetch=fake, force=True)["status"] == "fresh"
    g.next_feed = 0.0  # fifteen minutes pass
    assert g.read_feed(live=False, fetch=fake)["status"] == "fresh" and len(calls) == 1  # served from memory, schedule untouched
    assert g.status()["feed"]["status"] == "fresh"
    assert g.read_feed(live=True, now=NOW, fetch=fake)["status"] == "fresh" and len(calls) == 2  # the due live read still fetches
    snap = g.read_feed(live=False, fetch=fake, force=True)
    assert snap["status"] == "snapshot" and len(calls) == 2
    g.next_feed = 0.0
    assert g.read_feed(live=True, now=NOW, fetch=fake)["status"] == "fresh" and len(calls) == 3


def test_review_fetch_cap_loopback_only_with_an_injected_fetch(guard, monkeypatch):
    """Through the public endpoint, loopback URLs made /api/sachet/alert a probe of local ports (ConnectError vs malformed)."""

    def no_request(url):
        raise AssertionError("a request was attempted")

    monkeypatch.setattr(CapGuard, "_fetch", staticmethod(no_request))
    for url in ("http://127.0.0.1:11434/api/tags", "http://localhost:8000/api/sachet", "https://127.0.0.1@evil.com/", "https://sachet.ndma.gov.in.evil.com/x",
                "http://sachet.ndma.gov.in/x", "https://sachet.ndma.gov.in。evil.com/", "ftp://127.0.0.1/x", "file:///etc/passwd", "", None):
        with pytest.raises(ValueError, match="sachet.ndma.gov.in"):
            guard.fetch_cap(url)
    raw = CAP_SAMPLE.read_bytes() if CAP_SAMPLE.exists() else _alert(_ident("loop"))
    assert guard.fetch_cap("http://127.0.0.1:8000/x", fetch=lambda url: raw)["sender"] == TRUSTED  # tests inject their fetch


def test_review_infer_states_never_raises_and_skips_dictionary_words():
    for args in ((None,), (b"Heavy rain over Odisha",), (42,), ("x", 123), ("x", b"IMD-Chennai"), ("x", "", [None, b"Odisha", 7]), ("x", "", "Odisha"),
                 ("\U0001F327⚡", "\U0001F3E2"), ("x", None, None, None), ("x", "", [], b"")):
        out = infer_states(*args)
        assert isinstance(out, list) and all(s["state"] in sachet.STATES for s in out)
    assert infer_states(b"Heavy rain over Odisha")[0]["state"] == "Odisha"
    # "erode" the verb is not Erode the district; "Puri" the place still is
    assert infer_states("Heavy rain may erode the river embankment near Patna") == []
    assert [s["state"] for s in infer_states("Sea surges may erode Puri beach")] == ["Odisha"]
    assert infer_states("Rain over Erode and Coimbatore")[0] == {"state": "Tamil Nadu", "basis": "district named: Erode", "confidence": 0.75}
    # the SDMA rule matches whole state names: a Goalpara (Assam) district authority is not Goa
    assert infer_states("Flood alert", "controlroom@ndma.gov.in (Goalpara District Disaster Management Authority)") == []
    assert infer_states("Flood alert", "controlroom@ndma.gov.in (Goa SDMA)")[0]["state"] == "Goa"
    # the script hint now fires (the Indic blocks start at U+0900): the real CWC item in Telugu from the snapshot gets its states
    got = infer_states(TELUGU)
    assert {s["state"] for s in got} == {"Andhra Pradesh", "Telangana"} and all(s["confidence"] == 0.4 for s in got)
    if RSS.exists():
        items = parse_rss(RSS.read_bytes())
        cwc = [i for i in items if i["author"].endswith("(CWC)") and "శ్రీ" in i["title"]]
        assert cwc and all(infer_states(i["title"], i["author"]) for i in cwc)
        assert all(infer_states(i["title"], i["author"]) for i in items if not i["title"].isascii())


def test_review_write_cap_strips_xml_illegal_characters_from_every_field():
    """Control characters in any field made the CAP unparseable (a form feed in a CVE description is enough); None values crashed."""
    alert = {"identifier": "ODY-1\x00", "note": "a\x0cb", "references": "r\x03", "restriction": "r\x06", "event": "e\x04", "certainty": "c\x05",
             "sender_name": "s\x08", "web": "w\x01", "contact": "c\x02", "areas": ["Chennai\x07, Tamil Nadu", None], "parameters": {"k\x1b": "v\x07", None: 3},
             "expires_hours": "bad"}
    infos = [{"language": None, "headline": None, "description": "a\ud800b", "instruction": 5}]
    xml = write_cap(alert, infos, now=NOW)
    cap = parse_cap(xml)
    assert cap["identifier"] == "ODY-1" and cap["references"] == "r"
    info = cap["infos"][0]
    assert info["event"] == "e" and info["certainty"] == "c" and info["headline"] == "" and info["description"] == "ab" and info["instruction"] == "5"
    assert info["areas"] == ["Chennai, Tamil Nadu"] and info["language"] == "en-US"
    assert "<valueName>k</valueName>" in xml and "<value>v</value>" in xml and "<valueName></valueName>" in xml and "<value>3</value>" in xml
    assert "\x00" not in xml and "\x0c" not in xml and "\x1b" not in xml and "<note>ab</note>" in xml
    assert sachet._when(cap["expires"]) == NOW + dt.timedelta(hours=24)  # an unusable expires_hours falls back to 24
    assert "\t" in write_cap({"identifier": "ODY-2", "note": "tab\tkept"}, infos, now=NOW)


def test_review_rate_window_forgets_quiet_sources(connect):
    import time

    g = CapGuard(connect)
    for i in range(5000):
        g.window[f"2001:db8::{i:x}"].append(time.time() - 3600)
    assert len(g.window) == 5000
    assert g.ingest(_alert(_ident("prune")), source_ip="10.9.1.5", redteam="REVIEW")["accepted"] is True
    assert len(g.window) == 1
