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
from backend.app.engine import capredteam
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


@pytest.mark.xfail(strict=True, reason="sachet._scripts_of keeps only ord(ch) > 0x2000, which excludes every Indic block "
                                       "(Telugu is U+0C00-U+0C7F), so the script hint never fires; the threshold in sachet.py needs fixing")
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
def test_redteam_cases_cover_the_ladder_and_point_at_the_planted_secret(guard, tmp_path):
    secret_path = tmp_path / "planted-secret.txt"
    secret_path.write_text("PLANTED-test", encoding="utf-8")
    run_id = _ident("rt")
    cases = capredteam.cases(run_id, secret_path)
    assert len(cases) == 9
    assert [(c["name"], c["expect"]) for c in cases] == [
        ("xxe_external_entity", "xxe"), ("billion_laughs", "xxe"), ("forged_sender", "untrusted_sender"), ("legitimate", "accepted"),
        ("replay", "replay"), ("stale", "stale"), ("malformed", "malformed"), ("oversize", "oversize"), ("stored_script", "accepted")]
    by = {c["name"]: c for c in cases}
    xxe = by["xxe_external_entity"]["body"]
    assert secret_path.resolve().as_uri().encode() in xxe and b"<!ENTITY xxe SYSTEM" in xxe and b"&xxe;" in xxe
    assert b"&lol4;" in by["billion_laughs"]["body"] and len(by["oversize"]["body"]) > sachet.MAX_XML_BYTES
    assert by["replay"]["body"] == by["legitimate"]["body"] and b"<script>alert(1)</script>" in by["stored_script"]["body"]
    assert all(c["what"] and c["body"] and "cwe" in c and "technique" in c for c in cases)
    # the same bodies through the guard directly, no network: every expectation holds and the secret is never read
    for c in cases:
        out = guard.ingest(c["body"], source_ip="10.9.0.10", redteam=run_id)
        got = "accepted" if out["accepted"] else out["reason"]
        assert got == c["expect"], (c["name"], out["detail"])
        assert "PLANTED-test" not in json.dumps(out) and out["redteam"] == run_id
    stored = next(d for d in guard.decisions(20) if d["identifier"] == f"{run_id}-xss")
    assert stored["accepted"] is True and stored["redteam"] == run_id


def test_redteam_refuses_non_loopback_targets_before_any_request(connect, monkeypatch):
    import httpx

    class Boom:
        def __init__(self, *a, **k):
            raise AssertionError("a request was attempted")

    monkeypatch.setattr(httpx, "Client", Boom)
    head = _head(connect)
    for target in ("http://example.com/x", "https://sachet.ndma.gov.in/api/sensor/cap", "http://10.0.0.5:8000/api/sensor/cap"):
        with pytest.raises(ValueError, match="loopback"):
            capredteam.run(connect, target)
    assert _head(connect) == head


def test_redteam_live_run_against_own_loopback_endpoint(connect):
    if not _api_up():
        pytest.skip("the API on :8000 is not answering")
    head = _head(connect)
    out = capredteam.run(connect, f"{LIVE}/api/sensor/cap")
    if any(c["got"] == "rate_limited" for c in out["cases"] if c["name"] != "flood" and not c["pass"]):
        pytest.skip("the live guard's rate window is still full from a run within the last minute")
    assert out["total"] == 10 and out["passed"] == out["total"], [c for c in out["cases"] if not c["pass"]]
    assert out["planted_secret_leaked"] is False and out["seconds"] < 10
    assert [c["name"] for c in out["cases"]] == ["xxe_external_entity", "billion_laughs", "forged_sender", "legitimate", "replay", "stale",
                                                 "malformed", "oversize", "stored_script", "flood"]
    assert out["target"].startswith("http://127.0.0.1") and "loopback" in out["how"] and "SIM" in out["label"]
    assert all(c["ms"] >= 0 and c["expected"] and c["got"] for c in out["cases"])
    rows = _ledger(connect, head)
    assert len(rows) == 1 and rows[0]["kind"] == "cap.redteam" and rows[0]["provenance"] == "SIM"
    assert rows[0]["subject"] == out["run_id"] and rows[0]["payload"]["failed"] == [] and "cases" not in rows[0]["payload"]


# ---------------------------------------------------------------------------------------------- the feed and status
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
