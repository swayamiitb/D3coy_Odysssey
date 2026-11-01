"""Watchlists fire once on a change in the graph and are ledgered; bulk indicator import extracts, refangs, matches
our telemetry and exposure, and records every match; the graph replays to an instant; TAXII 2.1 serves the record
read-only with paging, filters and an optional bearer token.

Every test runs on a private copy of data/ews.db (the live demo keeps writing to the real one), so counts are
asserted as deltas, never as absolute ledger totals. The graph cache is switched off here: it keys on the focus only,
so a cached picture from one call would otherwise hide the live dict handed to the next."""

from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
from pathlib import Path

import pytest

from backend.app.engine import graph, iocs, watch
from backend.app.engine.graph import MIXED, REAL, SIM, intel_graph, node_card, replay_steps
from backend.app.engine.intel import lookalikes
from backend.app.engine.ledger import Ledger
from backend.app.engine.watch import DEFAULT_RULE, RULE_KINDS, _reasons

DATA = Path(__file__).resolve().parents[1] / "data"
FORTIOS = "Fortinet FortiGate (FortiOS)"
TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
VARIANT = sorted(lookalikes("vgwc.example"))[0]  # a dnstwist-style look-alike label of PWR-01's domain
ADVISORY = f"""# pasted from a partner CSIRT advisory (TLP:AMBER)
ioc,type,comment
50[.]16[.]16[.]211,ip,QakBot C2
192.0.2.148,ip,our own host?
198.18.77.7,ip,seen in partner telemetry
8.8.8.8,ip,benign resolver
login-{VARIANT}.com,domain,phishing kit
hxxps://update-{VARIANT}.com/kyc/verify,url,phishing page
CVE-2026-104935,cve,Ivanti exploited
{SHA256},sha256,sample
"""


# ------------------------------------------------------------------------------------------------------ fixtures
@pytest.fixture(scope="module")
def paths(tmp_path_factory):
    if not (DATA / "ews.db").exists():
        pytest.skip("no built database")
    d = tmp_path_factory.mktemp("wit")
    for name in ("ews.db", "cache.db"):
        if not (DATA / name).exists():
            continue
        src, dst = sqlite3.connect(f"file:{DATA / name}?mode=ro", uri=True), sqlite3.connect(d / name)
        src.backup(dst)
        src.close()
        dst.close()
    return d


@pytest.fixture(scope="module")
def copy(paths):
    conn = sqlite3.connect(paths / "ews.db", timeout=30, check_same_thread=False)
    watch.ensure(conn)
    iocs.ensure(conn)
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def no_graph_cache(monkeypatch):
    monkeypatch.setattr(graph, "CACHE_S", 0.0)
    graph._CACHE.clear()


@pytest.fixture(scope="module")
def client(paths):
    """The API on the copy, live engine off; no startup event, so no sensors, warm-ups or channels run."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("ODYSSEY_LIVE", "0")
        mp.setenv("ODYSSEY_NOTIFY", "0")
        import backend.app.cache as cache
        import backend.app.main as main
        from fastapi.testclient import TestClient
        mp.setattr(main, "DB_PATH", paths / "ews.db")
        mp.setattr(cache, "PATH", paths / "cache.db")
        yield TestClient(main.app)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _iso(d: dt.datetime) -> str:
    return d.isoformat().replace("+00:00", "Z")


def _count(conn, kind: str, where: str = "", args: tuple = ()) -> int:
    return conn.execute(f"SELECT COUNT(*) FROM ledger WHERE kind = ? {where}", (kind, *args)).fetchone()[0]


def _ledger_rows(conn, kind: str, n: int) -> list[dict]:
    rows = conn.execute("SELECT ts, kind, subject, source, provenance, payload FROM ledger WHERE kind = ? ORDER BY seq DESC LIMIT ?",
                        (kind, n)).fetchall()
    return [{"ts": r[0], "kind": r[1], "subject": r[2], "source": r[3], "provenance": r[4], "payload": json.loads(r[5])} for r in rows]


def _surge(det_id: str, ts: str) -> dict:
    return {"ticks": 3, "detections": [{"id": det_id, "ts": ts, "kind": "surge", "product": FORTIOS, "z": 12.0, "sensors": 5,
                                        "title": f"Scanning surge on {FORTIOS}"}]}


def _mine(fired: list[dict], watch_id: int) -> list[dict]:
    return [f for f in fired if f["watch_id"] == watch_id]


def _fired_rows(conn, watch_id: int) -> list[dict]:
    """The ledger's watch.fired events for one watch (payloads are compact, key-sorted JSON: parse, do not pattern-match)."""
    return [r for r in _ledger_rows(conn, "watch.fired", 10000) if r["payload"].get("watch_id") == watch_id]


# ----------------------------------------------------------------------------------------------------- watchlists
def test_watch_add_lists_rules_and_suggestions(copy):
    added_before = _count(copy, "watch.added")
    w = watch.add(copy, "cve:CVE-2026-104935", {"kind": "tier", "tier": "Critical"}, label="Ivanti CS", note="patch window Monday")
    assert w["target"] == "cve:CVE-2026-104935" and w["kind"] == "cve" and w["label"] == "Ivanti CS" and w["note"] == "patch window Monday"
    assert w["owner"] == "analyst" and w["status"] == "active" and w["fired"] == 0 and w["last_fired"] is None
    assert w["rule"] == {"kind": "tier", "pulse": 0.5, "tier": "Critical"} and w["rule_text"] == RULE_KINDS["tier"]
    assert set(w["last_state"]) == {"pulse", "tier", "last_seen", "degree", "risk"} and w["last_state"]["degree"] >= 1
    assert _count(copy, "watch.added") - added_before == 1
    row = _ledger_rows(copy, "watch.added", 1)[0]
    assert row["subject"] == "cve:CVE-2026-104935" and row["source"] == "ANALYST" and row["provenance"] == "HUMAN"
    assert row["payload"]["watch_id"] == w["id"] and row["payload"]["rule"]["kind"] == "tier"
    # an asset lives only in its organisation's graph; the watch finds it there
    a = watch.add(copy, "asset:PWR-01-A001")
    assert a["kind"] == "asset" and a["label"] == "vpn-gw01" and a["rule"] == DEFAULT_RULE
    rows = watch.list_watches(copy)
    assert {w["id"], a["id"]} <= {r["id"] for r in rows} and all("recent" in r and "neighbours" not in r["last_state"] for r in rows)
    flags = [r["status"] == "active" for r in rows]
    assert flags == sorted(flags, reverse=True), "active watches are listed first"
    assert [r["id"] for r in watch.list_watches(copy, "active")] and all(r["status"] == "active" for r in watch.list_watches(copy, "active"))
    with pytest.raises(KeyError):
        watch.add(copy, "product:nope")
    with pytest.raises(ValueError):
        watch.add(copy, "product:fortios", {"kind": "weird"})
    with pytest.raises(ValueError):
        watch.add(copy, "product:fortios", {"kind": "tier", "tier": "Severe"})
    watched = {r["target"] for r in watch.list_watches(copy)}
    sugg = watch.suggestions(copy)
    assert 1 <= len(sugg) <= 6 and all({"target", "label", "kind", "tier", "pulse", "sub"} <= set(s) for s in sugg)
    assert all(s["target"] not in watched for s in sugg) and all(s["kind"] in ("indicator", "campaign", "product", "actor", "cve") for s in sugg)
    assert watch.set_status(copy, a["id"], "deleted") is None


def test_watch_rules_are_edge_triggered():
    quiet = {"pulse": 0.1, "tier": "High", "last_seen": "2026-10-01T00:00:00Z", "neighbours": ["product:a", "cve:b"]}
    fresh = {**quiet, "pulse": 0.9, "last_seen": "2026-11-01T02:00:00Z"}
    assert _reasons({"kind": "fresh", "pulse": 0.5}, quiet, fresh) == ["fresh evidence: pulse 0.90 rose above 0.50"]
    assert _reasons({"kind": "fresh", "pulse": 0.5}, fresh, fresh) == [], "a condition that merely holds is not a change"
    assert _reasons({"kind": "fresh", "pulse": 0.5}, fresh, {**fresh, "last_seen": "2026-11-01T03:00:00Z"}) == ["new evidence recorded at 03:00 UTC"]
    assert _reasons({"kind": "fresh", "pulse": 0.95}, quiet, fresh) == [], "below the analyst's threshold"
    worse = {**quiet, "tier": "Critical"}
    assert _reasons({"kind": "tier", "tier": "Critical"}, quiet, worse) == ["tier worsened to Critical from High"]
    assert _reasons({"kind": "tier", "tier": "Critical"}, worse, quiet) == [], "improving never fires"
    assert _reasons({"kind": "tier", "tier": "Compromise"}, quiet, worse) == [], "below the floor"
    more = {**quiet, "neighbours": ["product:a", "cve:b", "signal:DET-1"]}
    assert _reasons({"kind": "connect"}, quiet, more) == ["1 new connection(s): DET-1"]
    assert _reasons({"kind": "connect"}, more, quiet) == [], "a connection that disappears is not an alert"
    assert _reasons({"kind": "connect"}, {"pulse": 0.1}, more) == [], "no recorded neighbours yet: nothing to compare"
    everything = {**fresh, "tier": "Critical", "neighbours": more["neighbours"]}
    assert len(_reasons(DEFAULT_RULE, quiet, everything)) == 3 and _reasons(DEFAULT_RULE, everything, everything) == []


def test_watch_fires_once_on_fresh_live_evidence(copy):
    w = watch.add(copy, "product:fortios", {"kind": "connect"}, owner="duty-officer", note="FortiGate: scanning expected")
    assert w["label"] == FORTIOS and w["kind"] == "product" and w["rule"]["kind"] == "connect"
    assert _fired_rows(copy, w["id"]) == []
    assert _mine(watch.evaluate(copy, None), w["id"]) == [], "nothing changed: nothing fires"
    live = _surge("DET-TEST-SURGE-1", _iso(_now()))
    fired = _mine(watch.evaluate(copy, live), w["id"])
    assert len(fired) == 1
    f = fired[0]
    assert f["target"] == "product:fortios" and f["label"] == FORTIOS and f["kind"] == "product" and f["owner"] == "duty-officer"
    assert f["reasons"] == ["1 new connection(s): DET-TEST-SURGE-1"] and f["pulse"] >= 0.99 and f["tier"] == "Critical"
    assert f["severity"] == "High" and f["provenance"] == MIXED and f["rule"]["kind"] == "connect"
    assert _mine(watch.evaluate(copy, live), w["id"]) == [], "edge-triggered: the same picture does not fire again"
    rows = _fired_rows(copy, w["id"])
    assert len(rows) == 1, "one firing, one ledger event"
    row = rows[0]
    assert row["subject"] == "product:fortios" and row["source"] == "WATCHLIST" and row["provenance"] == "AUTO" and row["payload"]["reasons"] == f["reasons"]
    got = watch.get(copy, w["id"])
    assert got["fired"] == 1 and got["last_fired"] and got["last_state"]["pulse"] >= 0.99 and got["last_state"]["degree"] == w["last_state"]["degree"] + 1
    ev = [e for e in watch.events(copy, 100) if e["watch_id"] == w["id"]]
    assert len(ev) == 1 and ev[0]["reason"] == f["reasons"][0] and ev[0]["severity"] == "High" and ev[0]["payload"]["target"] == "product:fortios"
    listed = next(r for r in watch.list_watches(copy) if r["id"] == w["id"])
    assert listed["recent"][0]["reason"] == ev[0]["reason"] and listed["fired"] == 1
    # the signal that fired it has its own card, with the live detection behind it
    card = node_card(copy, "signal:DET-TEST-SURGE-1", live=live)
    assert card["node"]["kind"] == "signal" and card["node"]["facts"]["signal"] == "surge" and card["node"]["provenance"] == SIM
    assert card["live"] == live["detections"] and {n["id"] for n in card["neighbours"]} >= {"product:fortios", "technique:T1595.002"}
    assert "detector output" in card["record"]["how"]


def test_watch_pause_resume_delete_are_ledgered_and_paused_watches_sleep(copy):
    w = watch.add(copy, "product:fortios", {"kind": "connect"})
    before = {k: _count(copy, k) for k in ("watch.paused", "watch.active", "watch.deleted")}
    p = watch.set_status(copy, w["id"], "paused")
    assert p["status"] == "paused" and p["id"] == w["id"]
    live = _surge("DET-TEST-SURGE-2", _iso(_now()))
    assert _mine(watch.evaluate(copy, live), w["id"]) == [], "a paused watch is not evaluated"
    assert watch.get(copy, w["id"])["last_eval"] == p["last_eval"] and watch.get(copy, w["id"])["fired"] == 0
    r = watch.set_status(copy, w["id"], "active")
    assert r["status"] == "active"
    fired = _mine(watch.evaluate(copy, live), w["id"])
    assert len(fired) == 1 and fired[0]["reasons"] == ["1 new connection(s): DET-TEST-SURGE-2"], "resumed: the change that happened meanwhile fires"
    with pytest.raises(ValueError):
        watch.set_status(copy, w["id"], "weird")
    assert watch.set_status(copy, w["id"], "deleted") is None
    with pytest.raises(KeyError):
        watch.get(copy, w["id"])
    with pytest.raises(KeyError):
        watch.set_status(copy, w["id"], "paused")
    assert w["id"] not in {r["id"] for r in watch.list_watches(copy)}
    assert {k: _count(copy, k) - before[k] for k in before} == {"watch.paused": 1, "watch.active": 1, "watch.deleted": 1}
    for k in before:
        row = _ledger_rows(copy, k, 1)[0]
        assert row["subject"] == "product:fortios" and row["provenance"] == "HUMAN" and row["payload"]["watch_id"] == w["id"]
    ok, bad = Ledger(conn=copy).verify()
    assert ok and bad is None, "the hash chain survives every watch write"


# ----------------------------------------------------------------------------------------------------- indicators
def test_ioc_parse_handles_csv_defanged_text_and_hashes():
    found, fmt = iocs.parse(ADVISORY)
    assert fmt == "csv" and len(found) == len(set(found)) == 8
    d = dict(found)
    assert d[f"https://update-{VARIANT}.com/kyc/verify"] == "url", "the URL stops at the CSV separator: no trailing fields"
    assert f"update-{VARIANT}.com" not in d, "a URL's host is not also a domain indicator"
    assert d["50.16.16.211"] == "ipv4-addr" and d["192.0.2.148"] == "ipv4-addr" and d["8.8.8.8"] == "ipv4-addr"
    assert d[f"login-{VARIANT}.com"] == "domain-name" and d["CVE-2026-104935"] == "vulnerability" and d[SHA256] == "file:sha256"
    assert "ioc,type,comment" not in str(found) and not any(t == "domain-name" and "." not in v for v, t in found)
    noisy = ("sha1 " + "a" * 40 + " md5 " + "b" * 32 + " skip 0.0.0.1 and 255.255.255.255, see readme.txt and evil[dot]example[.]org "
             "or hxxp://x[.]io/p, plus cve-2024-3400 twice CVE-2024-3400.")
    f2 = dict(iocs.parse(noisy)[0])
    assert f2["a" * 40] == "file:sha1" and f2["b" * 32] == "file:md5" and f2["evil.example.org"] == "domain-name"
    assert f2["http://x.io/p"] == "url" and f2["CVE-2024-3400"] == "vulnerability" and "x.io" not in f2
    assert "0.0.0.1" not in f2 and "255.255.255.255" not in f2 and "readme.txt" not in f2
    assert list(f2.values()).count("vulnerability") == 1, "upper- and lower-case CVE ids are one indicator"
    assert iocs.parse("") == ([], "text") and iocs.parse("nothing to see here") == ([], "text")
    assert iocs.refang("hxxps://a[.]b[dot]c(.)d{.}e[:]8443/x") == "https://a.b.c.d.e:8443/x"
    assert iocs.defang("1.2.3.4", "ipv4-addr") == "1[.]2[.]3[.]4" and iocs.defang("evil.example", "domain-name") == "evil[.]example"
    assert iocs.defang("https://a.b/c.d", "url") == "hxxps://a[.]b/c.d" and iocs.defang(SHA256, "file:sha256") == SHA256


def test_ioc_parse_reads_stix_bundles():
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.77']"},
        {"type": "indicator", "pattern": "[domain-name:value = 'Evil-VGWC.example'] OR [url:value = 'https://Evil-VGWC.example/Login']"},
        {"type": "indicator", "pattern": f"[file:hashes.'SHA-256' = '{SHA256.upper()}'] AND [file:hashes.MD5 = '{'c' * 32}']"},
        {"type": "vulnerability", "name": "CVE-2024-3400", "external_references": [{"source_name": "cve", "external_id": "CVE-2024-3400"}]},
        {"type": "vulnerability", "name": "Ivanti Connect Secure cve-2026-104935", "external_references": []},
        {"type": "malware", "name": "QakBot"},
    ]}
    found, fmt = iocs.parse(json.dumps(bundle))
    assert fmt == "stix"
    assert set(found) == {("203.0.113.77", "ipv4-addr"), ("evil-vgwc.example", "domain-name"), ("https://Evil-VGWC.example/Login", "url"),
                          (SHA256, "file:sha256"), ("c" * 32, "file:md5"), ("CVE-2024-3400", "vulnerability"), ("CVE-2026-104935", "vulnerability")}
    assert iocs.parse('{"type": "bundle", "objects": []}') == ([], "stix")
    found, fmt = iocs.parse("{ not json, but 198.51.100.9 is in it")
    assert fmt == "text" and found == [("198.51.100.9", "ipv4-addr")], "malformed JSON falls back to free text"


def test_ioc_import_matches_telemetry_and_records_the_ledger(copy):
    ip, host, aid = copy.execute("SELECT ip, hostname, id FROM assets WHERE id = 'PWR-01-A001'").fetchone()
    assert ip == "192.0.2.148", "the advisory names this asset's address"
    found, _ = iocs.parse(ADVISORY)
    already = {(v, t) for v, t in found if copy.execute("SELECT 1 FROM iocs WHERE value = ? AND type = ?", (v, t)).fetchone()}
    previously_matched = {v for v, t in found if copy.execute("SELECT 1 FROM iocs WHERE value = ? AND type = ? AND matched = 1", (v, t)).fetchone()}
    match_before, import_before = _count(copy, "ioc.match"), _count(copy, "ioc.import")
    live = {"flow_rows": [{"src": "10.20.17.219", "dst": "198.18.77.7", "dport": 443, "bytes": 1200}]}
    r = iocs.import_text(copy, ADVISORY, "partner CSIRT", "amber", live=live, tags=["qakbot"])
    assert r["format"] == "csv" and r["found"] == 8 and r["new"] == 8 - len(already) and r["tlp"] == "AMBER" and r["source"] == "partner CSIRT"
    assert r["by_type"] == {"url": 1, "ipv4-addr": 4, "file:sha256": 1, "vulnerability": 1, "domain-name": 1} and r["seconds"] >= 0
    rows = {x["value"]: x for x in r["indicators"]}
    c2 = rows["50.16.16.211"]
    assert c2["matched"] and c2["severity"] == "Critical" and c2["defanged"] == "50[.]16[.]16[.]211"
    assert [m["where"] for m in c2["matches"]] == ["C2 sighting"] and c2["matches"][0]["provenance"] == SIM and c2["matches"][0]["asset_id"] == aid
    assert any(e["source"] == "abuse.ch Feodo Tracker" and e["provenance"] == REAL and "QakBot" in e["detail"] for e in c2["enrich"])
    own = rows[ip]
    assert own["matched"] and own["severity"] == "Critical" and own["matches"][0]["where"] == "constituency asset"
    assert own["matches"][0]["org_id"] == "PWR-01" and own["matches"][0]["asset_id"] == aid and host in own["matches"][0]["detail"]
    flow = rows["198.18.77.7"]
    assert flow["matched"] and flow["severity"] == "High" and flow["matches"][0]["where"] == "firewall flows" and flow["matches"][0]["flows"] == 1
    assert "10.20.17.219" in flow["matches"][0]["detail"]
    assert not rows["8.8.8.8"]["matched"] and rows["8.8.8.8"]["severity"] is None and rows["8.8.8.8"]["matches"] == []
    look = rows[f"login-{VARIANT}.com"]
    assert look["matched"] and look["severity"] == "High" and look["matches"][0]["where"] == "look-alike" and look["matches"][0]["provenance"] == REAL
    assert look["matches"][0]["org_id"] == "PWR-01" and "vgwc.example" in look["matches"][0]["detail"]
    url = rows[f"https://update-{VARIANT}.com/kyc/verify"]
    assert url["type"] == "url" and url["matched"] and url["matches"][0]["where"] == "look-alike" and url["defanged"].startswith(f"hxxps://update-{VARIANT}[.]com/")
    cve = rows["CVE-2026-104935"]
    assert cve["matched"] and cve["severity"] == "Critical" and cve["matches"][0]["where"] == "exposure record" and cve["matches"][0]["assets"] >= 1
    assert cve["matches"][0]["provenance"] == MIXED and any(e["source"] == "CISA KEV" for e in cve["enrich"])
    sha = rows[SHA256]
    assert not sha["matched"] and sha["enrich"][0]["source"] == "Odyssey" and "no file telemetry" in sha["enrich"][0]["detail"]
    assert r["matched"] == 6 and [x["matched"] for x in r["indicators"]] == [True] * 6 + [False] * 2, "matched rows first"
    newly = {v for v, x in rows.items() if x["matched"]} - previously_matched
    assert _count(copy, "ioc.match") - match_before == len(newly) and _count(copy, "ioc.import") - import_before == 1
    for row in _ledger_rows(copy, "ioc.match", len(newly)):
        assert row["subject"].startswith("ioc:") and row["source"] == "IOC_IMPORT" and row["payload"]["where"]
        if row["payload"]["type"] in ("ipv4-addr", "domain-name", "url"):
            assert "[.]" in row["payload"]["value"], "the ledger shows indicators defanged"
    imp = _ledger_rows(copy, "ioc.import", 1)[0]
    assert imp["subject"] == "partner CSIRT" and imp["provenance"] == "HUMAN" and imp["payload"] == {
        "format": "csv", "found": 8, "new": r["new"], "matched": 6, "by_type": r["by_type"], "tlp": "AMBER"}
    # the same advisory again: nothing new, no second match event, one more import record
    r2 = iocs.import_text(copy, ADVISORY, "partner CSIRT", live=live)
    assert r2["new"] == 0 and r2["found"] == 8 and r2["matched"] == 6
    assert _count(copy, "ioc.match") - match_before == len(newly) and _count(copy, "ioc.import") - import_before == 2
    lst = iocs.list_iocs(copy)
    assert lst["total"] >= 8 and lst["matched"] >= 6 and sum(lst["by_type"].values()) == lst["total"]
    assert lst["imports"][0]["source"] == "partner CSIRT" and lst["imports"][0]["format"] == "csv" and lst["imports"][0]["by_type"] == r["by_type"]
    stored = next(x for x in lst["indicators"] if x["value"] == "198.18.77.7")
    assert stored["tlp"] == "AMBER" and stored["first_seen"] <= stored["last_seen"] and stored["matches"][0]["where"] == "firewall flows"
    if ("198.18.77.7", "ipv4-addr") not in already:
        assert stored["source"] == "partner CSIRT" and stored["tags"] == ["qakbot"]
    only = iocs.list_iocs(copy, matched_only=True, limit=5)
    assert len(only["indicators"]) == 5 and all(x["matched"] for x in only["indicators"])


def test_ioc_live_sets_live_match_and_export_rows(copy):
    iocs.import_text(copy, f"198.18.77.7 and login-{VARIANT}.com from a unit test", "unit")
    sets = iocs.live_sets(copy)
    assert set(sets) == {"ipv4-addr", "domain-name"} and "198.18.77.7" in sets["ipv4-addr"] and f"login-{VARIANT}.com" in sets["domain-name"]
    assert not any("[.]" in v for v in sets["ipv4-addr"] | sets["domain-name"]), "the engine matches on refanged values"
    now = _now()
    before = _count(copy, "ioc.match")
    detail = {"title": "flow from scada-hmi01 to 198[.]18[.]77[.]7:443", "src": "10.20.17.219", "dst": "198.18.77.7", "dport": 443,
              "asset": "scada-hmi01.vgwc.example", "org_id": "PWR-01", "ignored": "not copied"}
    iocs.mark_live_match(copy, "198.18.77.7", detail, now)
    assert _count(copy, "ioc.match") - before == 1
    row = copy.execute("SELECT matched, matches, severity, last_seen FROM iocs WHERE value = '198.18.77.7' AND type = 'ipv4-addr'").fetchone()
    live_hits = [m for m in json.loads(row[1]) if m["where"] == "live flows"]
    assert row[0] == 1 and row[2] in ("High", "Critical") and row[3] == _iso(now) and len(live_hits) == 1
    assert live_hits[0] == {"where": "live flows", "detail": detail["title"], "provenance": SIM, "severity": "High", "ts": _iso(now),
                            "src": "10.20.17.219", "dst": "198.18.77.7", "dport": 443, "asset": "scada-hmi01.vgwc.example", "org_id": "PWR-01"}
    led = _ledger_rows(copy, "ioc.match", 1)[0]
    assert led["subject"] == "ioc:198.18.77.7" and led["source"] == "LIVE_FLOWS" and led["provenance"] == SIM
    assert led["payload"]["value"] == "198[.]18[.]77[.]7" and led["payload"]["where"] == ["live flows"] and led["payload"]["org_id"] == "PWR-01"
    iocs.mark_live_match(copy, "198.18.77.7", detail, now + dt.timedelta(seconds=5))
    again = json.loads(copy.execute("SELECT matches FROM iocs WHERE value = '198.18.77.7' AND type = 'ipv4-addr'").fetchone()[0])
    assert len([m for m in again if m["where"] == "live flows"]) == 1 and _count(copy, "ioc.match") - before == 2, "one live entry per indicator, every sighting ledgered"
    iocs.mark_live_match(copy, "203.0.113.250", detail, now)
    assert _count(copy, "ioc.match") - before == 2, "an address nobody imported is not a match"
    rows = iocs.export_rows(copy)
    assert list(rows[0]) == ["value", "defanged", "type", "source", "tlp", "severity", "matched", "where", "enrichment", "first_seen", "last_seen"]
    exported = next(x for x in rows if x["value"] == "198.18.77.7")
    assert "live flows" in exported["where"] and exported["defanged"] == "198[.]18[.]77[.]7" and exported["matched"] == 1
    matched_rows = iocs.export_rows(copy, matched_only=True)
    assert matched_rows and all(x["matched"] == 1 and x["where"] for x in matched_rows) and len(matched_rows) <= len(rows)
    from backend.app.engine.export import to_csv
    csv_text = to_csv(rows)
    assert csv_text.splitlines()[0] == "value,defanged,type,source,tlp,severity,matched,where,enrichment,first_seen,last_seen"
    assert len(csv_text.splitlines()) == len(rows) + 1
    ok, bad = Ledger(conn=copy).verify()
    assert ok and bad is None


# --------------------------------------------------------------------------------------------------------- replay
def test_replay_as_of_removes_later_evidence(copy):
    now = _now()
    steps = replay_steps(copy, now=now)
    assert [s["id"] for s in steps] == ["snapshot", "d30", "d14", "d7", "d3", "d1", "h6", "h1", "now"]
    assert steps[-1] == {"id": "now", "label": "now", "at": None} and steps[0]["at"].endswith("T23:59:59Z")
    ats = [s["at"] for s in steps[1:-1]]
    assert ats == sorted(ats) and ats[-1] == _iso(now - dt.timedelta(hours=1))
    as_of = dt.datetime.fromisoformat(steps[1]["at"].replace("Z", "+00:00"))
    # an indicator imported now (a look-alike of PWR-01's domain, so it matches and is drawn) is evidence dated today
    imported = iocs.import_text(copy, f"replay-{VARIANT}.example seen in a phishing kit", "replay test")
    assert imported["matched"] == 1 and imported["indicators"][0]["matches"][0]["org_id"] == "PWR-01"
    nid = f"indicator:replay-{VARIANT}[.]example"
    live = {"ticks": 9, "detections": [_surge("DET-REPLAY-NOW", _iso(now))["detections"][0],
                                       _surge("DET-REPLAY-OLD", _iso(as_of - dt.timedelta(minutes=30)))["detections"][0]]}
    g_now = intel_graph(copy, None, live, now=now)
    g_then = intel_graph(copy, None, live, now=now, as_of=as_of)
    ids_now, ids_then = {n["id"] for n in g_now["nodes"]}, {n["id"] for n in g_then["nodes"]}
    assert "as_of" not in g_now and g_then["as_of"] == steps[1]["at"] and g_then["built_at"] == steps[1]["at"]
    assert {"signal:DET-REPLAY-NOW", "signal:DET-REPLAY-OLD"} <= ids_now and g_now["breath"]["live_detections"] == 2
    assert "signal:DET-REPLAY-NOW" not in ids_then and "signal:DET-REPLAY-OLD" in ids_then and g_then["breath"]["live_detections"] == 1
    old = next(n for n in g_then["nodes"] if n["id"] == "signal:DET-REPLAY-OLD")
    assert old["phase"] == "fresh" and old["age_h"] == 0.5 and old["pulse"] > 0.98, "pulse is aged to the replayed instant, not to the clock"
    cut = as_of.date().isoformat()
    assert all(n["facts"]["published"] <= cut for n in g_then["nodes"] if n["kind"] == "cve")
    assert all(e["from"] in ids_then and e["to"] in ids_then for e in g_then["edges"]) and g_then["edges"]
    drawn = next(n for n in g_now["nodes"] if n["id"] == nid)
    assert drawn["facts"]["imported"] is True and drawn["provenance"] == MIXED and drawn["phase"] == "fresh"
    assert any((e["from"], e["to"]) == ("org:PWR-01", nid) for e in g_now["edges"]), "linked to the organisation it resembles"
    assert nid not in ids_then, "an indicator imported after the instant was not in anyone's picture then"
    assert g_then["focus"] == g_now["focus"] and g_then["snapshot"] == g_now["snapshot"]


# ------------------------------------------------------------------------------------------------------- the API
def test_api_graph_replay_and_cards(client):
    steps = client.get("/api/graph/replay").json()["steps"]
    assert len(steps) == 9 and steps[-1] == {"id": "now", "label": "now", "at": None}
    r = client.get("/api/graph", params={"as_of": steps[1]["at"]})
    assert r.status_code == 200 and r.json()["as_of"] == steps[1]["at"] and r.json()["breath"]["live_detections"] == 0
    bad = client.get("/api/graph", params={"as_of": "yesterday"})
    assert bad.status_code == 400 and "ISO-8601" in bad.json()["detail"]
    assert client.get("/api/graph", params={"focus": "NOPE-99"}).status_code == 404
    card = client.get("/api/graph/node", params={"id": "product:fortios"}).json()
    assert card["node"]["id"] == "product:fortios" and card["neighbours"] and card["record"]["kind"] == "product" and card["focus"]["kind"] == "national"
    assert client.get("/api/graph/node", params={"id": "cve:CVE-1900-0000"}).status_code == 404


def test_api_watches_validate_and_manage(client):
    assert client.post("/api/watches", json={"target": "product:nope"}).status_code == 404
    assert client.post("/api/watches", json={"target": "product:fortios", "rule": {"kind": "weird"}}).status_code == 400
    assert client.post("/api/watches", json={"target": "product:fortios", "rule": {"kind": "tier", "tier": "Severe"}}).status_code == 400
    r = client.post("/api/watches", json={"target": "product:fortios", "owner": "duty-officer", "note": "FortiGate: scanning expected"})
    assert r.status_code == 200
    w = r.json()
    assert w["target"] == "product:fortios" and w["rule"] == DEFAULT_RULE and w["owner"] == "duty-officer" and w["status"] == "active"
    assert w["note"] == "FortiGate: scanning expected" and w["label"] == FORTIOS and w["rule_text"] == RULE_KINDS["any"]
    v = client.get("/api/watches").json()
    assert w["id"] in {x["id"] for x in v["watches"]} and set(v["rules"]) == {"any", "fresh", "tier", "connect"}
    assert v["default_rule"] == {"kind": "any", "pulse": 0.5, "tier": "Critical"} and isinstance(v["events"], list)
    assert v["suggestions"] and all(s["target"] != "product:fortios" for s in v["suggestions"])
    ev = client.post("/api/watches/evaluate").json()
    assert isinstance(ev["fired"], list) and all({"watch_id", "target", "reasons", "severity"} <= set(f) for f in ev["fired"])
    p = client.post(f"/api/watches/{w['id']}/pause").json()
    assert p["status"] == "paused" and p["watch"]["status"] == "paused" and p["watch"]["id"] == w["id"]
    assert client.post(f"/api/watches/{w['id']}/resume").json()["watch"]["status"] == "active"
    assert client.post(f"/api/watches/{w['id']}/dance").status_code == 400
    assert client.post(f"/api/watches/{w['id']}/delete").json() == {"watch": None, "status": "deleted"}
    assert client.post(f"/api/watches/{w['id']}/pause").status_code == 404
    assert w["id"] not in {x["id"] for x in client.get("/api/watches").json()["watches"]}


def test_api_ioc_import_list_and_export(client):
    assert client.post("/api/iocs/import", json={"text": "   "}).status_code == 400
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.77']"},
        {"type": "indicator", "pattern": "[domain-name:value = 'evil-vgwc.example']"},
        {"type": "vulnerability", "name": "CVE-2024-3400", "external_references": [{"source_name": "cve", "external_id": "CVE-2024-3400"}]}]}
    r = client.post("/api/iocs/import", json={"text": json.dumps(bundle), "source": "STIX feed", "tlp": "GREEN"})
    assert r.status_code == 200
    body = r.json()
    assert body["format"] == "stix" and body["found"] == 3 and body["tlp"] == "GREEN" and body["source"] == "STIX feed"
    assert body["by_type"] == {"ipv4-addr": 1, "domain-name": 1, "vulnerability": 1}
    assert {x["value"] for x in body["indicators"]} == {"203.0.113.77", "evil-vgwc.example", "CVE-2024-3400"}
    assert all({"id", "value", "defanged", "type", "matched", "severity", "matches", "enrich"} <= set(x) for x in body["indicators"])
    c2 = client.post("/api/iocs/import", json={"text": "50[.]16[.]16[.]211 QakBot C2, from a partner", "source": "partner CSIRT"}).json()
    assert c2["format"] == "text" and c2["found"] == 1 and c2["matched"] == 1 and c2["indicators"][0]["matches"][0]["where"] == "C2 sighting"
    lst = client.get("/api/iocs", params={"matched_only": "true", "limit": 50}).json()
    assert lst["indicators"] and all(x["matched"] for x in lst["indicators"]) and 1 <= lst["matched"] <= lst["total"]
    assert sum(lst["by_type"].values()) == lst["total"] and lst["imports"][0]["source"] == "partner CSIRT" and lst["imports"][0]["format"] == "text"
    assert lst["imports"][1]["source"] == "STIX feed" and lst["imports"][1]["format"] == "stix"
    csv_r = client.get("/api/iocs/export", params={"format": "csv"})
    assert csv_r.status_code == 200 and csv_r.headers["content-type"].startswith("text/csv") and "attachment" in csv_r.headers["content-disposition"]
    assert csv_r.text.startswith("value,defanged,type,") and "50[.]16[.]16[.]211" in csv_r.text
    stix = client.get("/api/iocs/export", params={"format": "stix"}).json()
    assert stix["type"] == "bundle" and stix["id"].startswith("bundle--")
    inds = [o for o in stix["objects"] if o["type"] == "indicator"]
    assert inds and all("imported" in o["labels"] and o["pattern_type"] == "stix" for o in inds)
    assert any(o["pattern"] == "[ipv4-addr:value = '50.16.16.211']" and o["confidence"] == 90 for o in inds)
    assert any(o["type"] == "identity" for o in stix["objects"]) and all(o["spec_version"] == "2.1" for o in stix["objects"])


# ------------------------------------------------------------------------------------------------------- TAXII 2.1
def test_taxii_discovery_root_and_collections(client):
    r = client.get("/taxii2/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/taxii+json") and "version=2.1" in r.headers["content-type"]
    disc = r.json()
    assert disc["api_roots"] == ["/taxii2/odyssey/"] and disc["default"] == "/taxii2/odyssey/" and "Read-only" in disc["description"]
    root = client.get("/taxii2/odyssey/").json()
    assert root["versions"] == [TAXII_MEDIA] and root["max_content_length"] > 0 and root["title"]
    cols = client.get("/taxii2/odyssey/collections/").json()["collections"]
    assert [c["alias"] for c in cols] == ["graph", "indicators", "vulnerabilities"] and len({c["id"] for c in cols}) == 3
    assert all(c["can_read"] and not c["can_write"] and c["media_types"] == [STIX_MEDIA] and c["title"] and c["description"] for c in cols)
    assert "not attribution" in cols[0]["description"]
    by_alias, by_id = client.get("/taxii2/odyssey/collections/indicators/").json(), client.get(f"/taxii2/odyssey/collections/{cols[1]['id']}/").json()
    assert by_alias == by_id and by_id["id"] == cols[1]["id"] and by_id["alias"] == "indicators"
    assert client.get("/taxii2/odyssey/collections/nope/").status_code == 404
    assert client.get("/taxii2/odyssey/collections/nope/objects/").status_code == 404
    assert client.get("/taxii2/odyssey/collections/nope/manifest/").status_code == 404


def test_taxii_objects_page_filter_manifest_and_single_objects(client):
    base = "/taxii2/odyssey/collections/graph/objects/"
    r = client.get(base, params={"limit": 5})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/taxii+json")
    page1 = r.json()
    assert len(page1["objects"]) == 5 and page1["more"] is True and page1["next"] == "5"
    assert r.headers["X-TAXII-Date-Added-First"] <= r.headers["X-TAXII-Date-Added-Last"]
    assert all(o["spec_version"] == "2.1" and "--" in o["id"] and o["id"].startswith(o["type"] + "--") for o in page1["objects"])
    page2 = client.get(base, params={"limit": 5, "next": "5"}).json()
    assert len(page2["objects"]) == 5 and not ({o["id"] for o in page1["objects"]} & {o["id"] for o in page2["objects"]})
    man = client.get("/taxii2/odyssey/collections/graph/manifest/", params={"limit": 3}).json()
    assert man["more"] is True and man["next"] == "3" and len(man["objects"]) == 3
    assert all(set(o) == {"id", "date_added", "version", "media_type"} and o["media_type"] == STIX_MEDIA and o["date_added"] == o["version"] for o in man["objects"])
    assert [o["id"] for o in man["objects"]] == [o["id"] for o in page1["objects"][:3]], "the manifest walks the same order as the objects"
    only = client.get(base, params={"match[type]": "intrusion-set"}).json()
    assert only["objects"] and all(o["type"] == "intrusion-set" and "not attribute" in o["description"] for o in only["objects"])
    oid = only["objects"][0]["id"]
    byid = client.get(base, params={"match[id]": oid}).json()
    assert [o["id"] for o in byid["objects"]] == [oid] and byid["more"] is False and "next" not in byid
    two = client.get(base, params={"match[type]": "intrusion-set,malware"}).json()
    assert {o["type"] for o in two["objects"]} == {"intrusion-set", "malware"}
    future = client.get(base, params={"added_after": "9999-01-01T00:00:00.000Z"}).json()
    assert future == {"more": False, "objects": []}
    assert client.get(base, params={"limit": "lots"}).status_code == 400
    one = client.get(f"{base}{oid}/").json()
    assert one["more"] is False and [o["id"] for o in one["objects"]] == [oid] and one["objects"][0]["type"] == "intrusion-set"
    ver = client.get(f"{base}{oid}/versions/").json()
    # graph objects are stamped with the build time of the request that served them, so the version is checked for
    # shape (one STIX 2.1 timestamp), not for equality with an object fetched by an earlier request
    assert ver["more"] is False and len(ver["versions"]) == 1 and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", ver["versions"][0])
    assert client.get(f"{base}intrusion-set--00000000-0000-0000-0000-000000000000/").status_code == 404
    assert client.get(f"{base}intrusion-set--00000000-0000-0000-0000-000000000000/versions/").status_code == 404
    assert client.get(f"/taxii2/odyssey/collections/vulnerabilities/objects/{oid}/").status_code == 404, "an object lives in its own collection"
    vulns = client.get("/taxii2/odyssey/collections/vulnerabilities/objects/", params={"limit": 5}).json()["objects"]
    assert len(vulns) == 5 and all(o["type"] in ("identity", "vulnerability") for o in vulns)
    v = next(o for o in vulns if o["type"] == "vulnerability")
    assert v["external_references"][0]["source_name"] == "cve" and v["name"].startswith("CVE-") and 0 <= v["x_odyssey_risk"] <= 100 and v["x_odyssey_tier"]


def test_taxii_indicators_collection_carries_seen_and_imported(client):
    imp = client.post("/api/iocs/import", json={"text": "50[.]16[.]16[.]211", "source": "partner CSIRT", "tlp": "AMBER"}).json()
    assert imp["matched"] == 1
    url = "/taxii2/odyssey/collections/indicators/objects/"
    objs = client.get(url, params={"limit": 1000}).json()["objects"]
    inds = [o for o in objs if o["type"] == "indicator"]
    assert inds and sum(o["type"] == "identity" for o in objs) == 1
    assert all(o["pattern_type"] == "stix" and o["pattern"].startswith("[") and 0 <= o["confidence"] <= 100 and o["labels"] for o in inds)
    assert all(o["created_by_ref"] == next(x["id"] for x in objs if x["type"] == "identity") and o["object_marking_refs"] for o in inds)
    seen = [o for o in inds if "c2_seen" in o["labels"]]
    assert seen and all(o["pattern"].startswith("[ipv4-addr:value = '") and "Provenance" in o["description"] for o in seen)
    imported = [o for o in inds if "imported" in o["labels"] and o["pattern"] == "[ipv4-addr:value = '50.16.16.211']"]
    assert len(imported) == 1
    assert imported[0]["name"].startswith("imported ipv4-addr 50[.]16[.]16[.]211") and "AMBER" in imported[0]["labels"]
    assert imported[0]["description"].startswith("Matched in Odyssey: C2 sighting") and imported[0]["confidence"] == 90
    again = client.get(url, params={"limit": 1000}).json()["objects"]
    assert {o["id"] for o in again} == {o["id"] for o in objs}, "deterministic ids: a consumer sees updates, not duplicates"
    typed = client.get(url, params={"match[type]": "indicator", "limit": 3}).json()
    assert len(typed["objects"]) == 3 and all(o["type"] == "indicator" for o in typed["objects"]) and typed["more"] is True


def test_taxii_bearer_token_when_configured(client, monkeypatch):
    monkeypatch.setenv("ODYSSEY_TAXII_TOKEN", "secret")
    r = client.get("/taxii2/")
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer"
    assert client.get("/taxii2/odyssey/collections/", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/taxii2/odyssey/collections/graph/objects/", params={"limit": 1}).status_code == 401
    assert client.get("/taxii2/", headers={"Authorization": "Bearer secret"}).status_code == 200
    assert client.get("/taxii2/odyssey/collections/", headers={"Authorization": "Bearer secret"}).status_code == 200
    monkeypatch.delenv("ODYSSEY_TAXII_TOKEN")
    assert client.get("/taxii2/").status_code == 200, "no token configured: open, as the demo runs it"


# ------------------------------------------------------------------------------ watchlists: adversarial review regressions
def test_watch_add_rejects_malformed_rules_and_fields(copy, client):
    """A rule that cannot be evaluated must be refused at the door (400), never stored: `_reasons` would otherwise raise on
    it at every evaluation and silence every watch behind it."""
    for rule in ({"kind": "fresh", "pulse": "abc"}, {"kind": "fresh", "pulse": None}, {"kind": "any", "pulse": float("nan")},
                 {"kind": "any", "pulse": [1]}, {"kind": "any", "pulse": 1.5}, {"kind": "any", "pulse": -0.1}, {"kind": "any", "pulse": True},
                 "x", [], {"kind": ["any"]}, {"kind": "any", "tier": []}, {"kind": "any", "tier": None}):
        with pytest.raises(ValueError):
            watch.add(copy, "product:fortios", rule)
    for kw in (dict(label={"a": 1}), dict(owner=5), dict(note=[])):
        with pytest.raises(ValueError):
            watch.add(copy, "product:fortios", None, **kw)
    with pytest.raises(ValueError):
        watch.add(copy, 5)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        watch.add(copy, "   ")
    assert client.post("/api/watches", json={"target": "product:fortios", "rule": {"kind": "fresh", "pulse": "abc"}}).status_code == 400
    assert client.post("/api/watches", json={"target": "product:fortios", "rule": "x"}).status_code == 400
    assert client.post("/api/watches", json={"target": "product:fortios", "rule": {"kind": "any", "tier": []}}).status_code == 400
    assert client.post("/api/watches", json={"target": "product:fortios", "label": {"a": 1}}).status_code == 400
    assert client.post("/api/watches", json={"target": 5}).status_code == 400
    # the boundaries stay open: a pulse of 0 or 1 and an int are numbers
    w = watch.add(copy, "product:fortios", {"kind": "fresh", "pulse": 1, "tier": "Watch"})
    assert w["rule"] == {"kind": "fresh", "pulse": 1, "tier": "Watch"}
    assert watch.set_status(copy, w["id"], "deleted") is None


def test_watch_one_malformed_row_cannot_halt_evaluation(copy, capsys):
    """A stored rule that raises (a tampered or legacy row) is skipped and reported; the watches behind it still fire."""
    now = _iso(_now())
    state = json.dumps({"pulse": 0.1, "tier": "High", "last_seen": "2026-10-01T00:00:00Z", "degree": 1, "neighbours": ["x:y"], "risk": 10})
    cur = copy.execute("INSERT INTO watches (created_at, target, rule, status, last_state, last_eval) VALUES (?,?,?,?,?,?)",
                       (now, "product:fortios", json.dumps({"kind": "fresh", "pulse": "abc"}), "active", state, "2026-10-01T00:00:00Z"))
    copy.commit()
    bad = cur.lastrowid  # a raw rowid: it may be one an earlier, deleted watch used, so its ledger rows are counted as deltas
    bad_rows_before = len(_fired_rows(copy, bad))
    good = watch.add(copy, "product:fortios", {"kind": "connect"})
    assert good["id"] > bad, "the malformed row is evaluated first"
    fired = _mine(watch.evaluate(copy, _surge("DET-TEST-SURGE-BAD-ROW", now)), good["id"])
    assert len(fired) == 1 and fired[0]["reasons"] == ["1 new connection(s): DET-TEST-SURGE-BAD-ROW"], "the watch behind the bad row fires"
    b = watch.get(copy, bad)
    assert b["fired"] == 0 and b["last_eval"] > "2026-10-01T00:00:00Z", "the bad row is skipped, not fired, and marked evaluated"
    assert len(_fired_rows(copy, bad)) == bad_rows_before
    assert f"watch {bad} on product:fortios" in capsys.readouterr().out
    assert watch.set_status(copy, bad, "deleted") is None and watch.set_status(copy, good["id"], "deleted") is None


def test_watch_concurrent_evaluations_fire_once(copy, paths, monkeypatch):
    """The live engine (its own connection, every 15 s) and an analyst's 'evaluate now' both read the same recorded state;
    the one that advances it first owns the firing. Before the compare-and-set, one change produced two events."""
    other = sqlite3.connect(paths / "ews.db", timeout=30, check_same_thread=False)
    try:
        live0 = _surge("DET-TEST-RACE-0", _iso(_now()))
        w = watch.add(copy, "product:fortios", {"kind": "connect"}, live=live0)
        assert _mine(watch.evaluate(copy, live0), w["id"]) == [], "the picture the watch was added on does not fire"
        live1 = {**live0, "detections": live0["detections"] + [{**live0["detections"][0], "id": "DET-TEST-RACE-1"}]}
        real, seen = watch.intel_graph, {"other_fired": None}

        def interleaved(conn, focus, live, now=None):
            g = real(conn, focus, live, now=now)
            if conn is copy and seen["other_fired"] is None:  # the other evaluator runs to completion while this one is mid-flight
                seen["other_fired"] = _mine(watch.evaluate(other, live), w["id"])
            return g

        monkeypatch.setattr(watch, "intel_graph", interleaved)
        mine = _mine(watch.evaluate(copy, live1), w["id"])
        monkeypatch.setattr(watch, "intel_graph", real)
        assert len(seen["other_fired"]) == 1 and seen["other_fired"][0]["reasons"] == ["1 new connection(s): DET-TEST-RACE-1"]
        assert mine == [], "the change was already claimed by the other evaluation"
        assert copy.execute("SELECT COUNT(*) FROM watch_events WHERE watch_id = ?", (w["id"],)).fetchone()[0] == 1
        assert watch.get(copy, w["id"])["fired"] == 1 and len(_fired_rows(copy, w["id"])) == 1, "one change, one event, one ledger row"
        assert _mine(watch.evaluate(copy, live1), w["id"]) == [] and _mine(watch.evaluate(other, live1), w["id"]) == []
        assert not copy.in_transaction and not other.in_transaction, "evaluation leaves no transaction open"
        ok, bad = Ledger(conn=copy).verify()
        assert ok and bad is None
        assert watch.set_status(copy, w["id"], "deleted") is None
    finally:
        other.close()


def test_watch_asset_focus_comes_from_the_inventory(copy):
    """An asset lives in its organisation's graph; the organisation is read from the inventory, so an asset id that does not
    follow the <org>-<n>-A<nnn> convention still resolves, and an unknown one falls back to the convention."""
    from backend.app.engine.watch import _focus_for
    assert _focus_for(copy, "product:fortios") is None and _focus_for(copy, "asset:PWR-01-A001") == "PWR-01"
    assert _focus_for(copy, "asset:ZZZ-99-A001") == "ZZZ-99" and _focus_for(copy, "asset:") == ""
    copy.execute("INSERT INTO assets (id, org_id, hostname) VALUES (?,?,?)", ("X-A001", "PWR-01", "x-a001.vgwc.example"))
    copy.commit()
    try:
        assert _focus_for(copy, "asset:X-A001") == "PWR-01", "the inventory wins over the id convention"
    finally:
        copy.execute("DELETE FROM assets WHERE id = ?", ("X-A001",))
        copy.commit()
    with pytest.raises(KeyError):
        watch.add(copy, "asset:ZZZ-99-A001")  # no such organisation: the graph has no such node
    with pytest.raises(KeyError):
        watch.add(copy, "asset:PWR-01-A999")  # known organisation, unknown asset


# ------------------------------------------------------------------------------- TAXII 2.1: adversarial review regressions
def test_taxii_added_after_compares_instants_not_strings(client):
    """added_after is an RFC 3339 instant, not a string: no fraction, .000, six digits, an offset, and the '+' that URL
    decoding turns into a space all name the same instant and filter identically; strictly after, never at. Garbage is 400."""
    url = "/taxii2/odyssey/collections/indicators/objects/"
    objs = client.get(url, params={"limit": 1000}).json()["objects"]
    stamp = lambda o: o.get("modified") or o.get("created")  # noqa: E731
    pivot = "2026-10-31T00:00:00.000Z"  # the producer identity's fixed version; every generated object is stamped later
    at, after = [o for o in objs if stamp(o) == pivot], [o for o in objs if stamp(o) > pivot]
    assert at and after and len(at) + len(after) == len(objs)
    for form in ("2026-10-31T00:00:00Z", "2026-10-31T00:00:00.000Z", "2026-10-31T00:00:00.000000Z", "2026-10-31T05:30:00%2B05:30",
                 "2026-10-31T05:30:00+05:30", "2026-10-30T19:00:00-05:00"):
        got = client.get(f"{url}?added_after={form}&limit=1000").json()["objects"]
        assert len(got) == len(after) and not any(stamp(o) == pivot for o in got), form
    got = client.get(url, params={"added_after": "2026-10-31 00:00:00Z", "limit": 1000}).json()["objects"]
    assert len(got) == len(after), "a space between date and time is tolerated"
    assert len(client.get(url, params={"added_after": "2026-10-30T23:59:59.999Z", "limit": 1000}).json()["objects"]) == len(objs)
    for bad in ("yesterday", "2026-13-01T00:00:00Z", "2026-10-31T00:00:00+25:00"):
        r = client.get(url, params={"added_after": bad})
        assert r.status_code == 400 and r.headers["content-type"] == TAXII_MEDIA and r.json()["http_status"] == "400" and r.json()["title"], bad


def test_taxii_added_after_fraction_boundary_and_stable_order(client):
    """An object 308 ms after a whole second is after that second (the string comparison dropped it); rows come back by
    (date_added, id), so two requests walk the collection in the same order."""
    from fastapi import HTTPException
    from starlette.datastructures import QueryParams
    from backend.app import taxii
    objs = [{"id": "x--b", "type": "x", "spec_version": "2.1", "modified": "2026-11-01T02:35:17.308Z"},
            {"id": "x--a", "type": "x", "spec_version": "2.1", "modified": "2026-11-01T02:35:17.308Z"},
            {"id": "x--c", "type": "x", "spec_version": "2.1", "created": "2026-11-01T02:35:17.000Z"}]
    ids = lambda q: [o["id"] for o in taxii._filter(QueryParams(q), objs)]  # noqa: E731
    assert ids("added_after=2026-11-01T02:35:17Z") == ["x--a", "x--b"]
    assert ids("added_after=2026-11-01T02:35:17.000Z") == ["x--a", "x--b"] and ids("added_after=2026-11-01T02:35:17.307Z") == ["x--a", "x--b"]
    assert ids("added_after=2026-11-01T02:35:17.308Z") == [] and ids("added_after=2026-11-01T08:05:17.308%2B05:30") == []
    assert ids("added_after=2026-11-01T08:05:16.999%2B05:30") == ["x--c", "x--a", "x--b"] == ids("") == ids("added_after=")
    assert ids("match[version]=2026-11-01T02:35:17.308Z") == ["x--a", "x--b"] and ids("match[version]=2026-11-01T08:05:17%2B05:30") == ["x--c"]
    assert ids("match[spec_version]=2.1&match[id]=x--c,x--a") == ["x--c", "x--a"] and ids("match[spec_version]=2.0") == []
    with pytest.raises(HTTPException) as exc:
        ids("added_after=2026-13-01T00:00:00Z")
    assert exc.value.status_code == 400
    with pytest.raises(HTTPException):
        ids("match[version]=latest")
    assert objs[0]["id"] == "x--b", "filtering never reorders or mutates the caller's list"
    base = "/taxii2/odyssey/collections/graph/objects/"
    a = [o["id"] for o in client.get(base, params={"limit": 1000}).json()["objects"]]
    b = [o["id"] for o in client.get(base, params={"limit": 1000}).json()["objects"]]
    assert a == b and len(a) > 5


def test_taxii_next_cursor_must_be_the_servers(client):
    """next is opaque and comes from the server: a negative offset sliced from the end of the list and paged on into nonsense."""
    base = "/taxii2/odyssey/collections/graph/objects/"
    bad = client.get(base, params={"limit": 2, "next": "-3"})
    assert bad.status_code == 400 and bad.headers["content-type"] == TAXII_MEDIA
    assert bad.json() == {"title": "next must be a value this server returned", "http_status": "400"}
    assert client.get(base, params={"limit": 100, "next": "-1"}).status_code == 400
    assert client.get(base, params={"limit": 2, "next": "1e2"}).status_code == 400
    assert client.get(base, params={"limit": 2, "next": "999999"}).json() == {"more": False, "objects": []}
    man = client.get("/taxii2/odyssey/collections/graph/manifest/", params={"limit": 2, "next": "-1"})
    assert man.status_code == 400


def test_taxii_match_filters_version_spec_version_and_repeats(client):
    """match[version], match[spec_version] and a repeated match[] field (equivalent to a comma list) are honoured, on the
    collection and on a single object."""
    base = "/taxii2/odyssey/collections/graph/objects/"
    n = len(client.get(base, params={"limit": 1000}).json()["objects"])
    both = client.get(f"{base}?match[type]=intrusion-set&match[type]=malware").json()["objects"]
    assert {o["type"] for o in both} == {"intrusion-set", "malware"}
    assert client.get(base, params={"match[spec_version]": "2.0", "limit": 1000}).json() == {"more": False, "objects": []}
    assert len(client.get(base, params={"match[spec_version]": "2.1", "limit": 1000}).json()["objects"]) == n
    for v in ("first", "last", "all", "first,last"):
        assert len(client.get(base, params={"match[version]": v, "limit": 1000}).json()["objects"]) == n, v
    assert client.get(base, params={"match[version]": "1999-01-01T00:00:00.000Z"}).json() == {"more": False, "objects": []}
    fixed = client.get(base, params={"match[version]": "2026-10-31T00:00:00Z", "limit": 1000}).json()["objects"]
    assert fixed and all((o.get("modified") or o.get("created") or "2026-10-31T00:00:00.000Z") == "2026-10-31T00:00:00.000Z" for o in fixed)
    assert client.get(base, params={"match[version]": "latest"}).status_code == 400
    oid = both[0]["id"]
    assert client.get(f"{base}{oid}/", params={"match[spec_version]": "2.0"}).status_code == 404
    one = client.get(f"{base}{oid}/", params={"match[version]": "all"})
    assert one.status_code == 200 and one.headers["X-TAXII-Date-Added-First"] == one.headers["X-TAXII-Date-Added-Last"] == one.json()["objects"][0]["modified"]
    ver = client.get(f"{base}{oid}/versions/")
    assert ver.headers["X-TAXII-Date-Added-First"] == ver.json()["versions"][0]


def test_taxii_manifest_headers_error_messages_and_content_negotiation(client):
    """Manifests carry the date-added headers; errors leave as TAXII error messages with the TAXII media type; an Accept
    header this server cannot satisfy is 406, while browsers, curl and plain JSON clients stay welcome."""
    r = client.get("/taxii2/odyssey/collections/graph/manifest/", params={"limit": 4})
    man = r.json()["objects"]
    assert len(man) == 4 and r.headers["X-TAXII-Date-Added-First"] == man[0]["date_added"] and r.headers["X-TAXII-Date-Added-Last"] == man[-1]["date_added"]
    empty = client.get("/taxii2/odyssey/collections/graph/manifest/", params={"added_after": "9999-01-01T00:00:00Z"})
    assert empty.json() == {"more": False, "objects": []} and "X-TAXII-Date-Added-First" not in empty.headers
    for path, status, title in (("/taxii2/odyssey/collections/nope/", 404, "unknown collection"),
                                ("/taxii2/odyssey/collections/graph/objects/indicator--00000000-0000-0000-0000-000000000000/", 404, "unknown object"),
                                ("/taxii2/odyssey/collections/graph/objects/indicator--00000000-0000-0000-0000-000000000000/versions/", 404, "unknown object"),
                                ("/taxii2/odyssey/collections/graph/objects/?limit=lots", 400, "limit and next must be integers")):
        r = client.get(path)
        assert r.status_code == status and r.headers["content-type"] == TAXII_MEDIA and r.json() == {"title": title, "http_status": str(status)}, path
    for accept, status in (("application/taxii+json;version=2.1", 200), ("application/taxii+json", 200), ("*/*", 200), ("application/json", 200),
                           ("text/html,application/xhtml+xml,*/*;q=0.8", 200), ("application/taxii+json; version=2.1, */*;q=0.1", 200),
                           ("text/html", 406), ("application/taxii+json;version=2.0", 406), ("application/vnd.oasis.taxii+json", 406)):
        r = client.get("/taxii2/odyssey/collections/", headers={"Accept": accept})
        assert r.status_code == status, accept
        if status == 406:
            assert r.headers["content-type"] == TAXII_MEDIA and r.json()["http_status"] == "406" and TAXII_MEDIA in r.json()["title"]


def test_taxii_bearer_scheme_is_case_insensitive_and_401_is_taxii(client, monkeypatch):
    monkeypatch.setenv("ODYSSEY_TAXII_TOKEN", "secret")
    for header in ("bearer secret", "BEARER secret", "Bearer secret", "Bearer  secret "):
        assert client.get("/taxii2/", headers={"Authorization": header}).status_code == 200, header
    for header in ("Basic secret", "Bearer", "Bearer secre", "Bearer secret2", "secret", "Bearersecret", ""):
        r = client.get("/taxii2/", headers={"Authorization": header})
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer" and r.headers["content-type"] == TAXII_MEDIA, header
        assert r.json() == {"title": "bearer token required", "http_status": "401"}
    assert client.get("/taxii2/odyssey/collections/nope/").status_code == 401, "the token gate comes before the lookup: no existence leak"
    assert client.get("/taxii2/", headers={"Accept": "text/html"}).status_code == 401, "and before content negotiation"
    monkeypatch.delenv("ODYSSEY_TAXII_TOKEN")
    assert client.get("/taxii2/").status_code == 200


def test_taxii_timestamps_treat_naive_records_as_utc(client, paths):
    """NVD publication dates and DShield first-seen dates carry no zone and mean UTC: read as local time on an IST machine
    they landed on the previous day. Unparseable records fall back to the project epoch instead of a 500."""
    from backend.app import taxii
    assert taxii._ts("2024-01-15") == "2024-01-15T00:00:00.000Z" and taxii._ts("2026-10-31T12:00:00") == "2026-10-31T12:00:00.000Z"
    assert taxii._ts("2026-10-31T12:00:00+05:30") == "2026-10-31T06:30:00.000Z" == taxii._ts("2026-10-31T06:30:00Z") == taxii._ts("2026-10-31 06:30:00Z")
    assert taxii._ts("2026-10-31T06:30:00.123456Z") == "2026-10-31T06:30:00.123Z"
    assert taxii._ts("garbage") == taxii._ts(None) == taxii._ts("") == "2026-10-31T00:00:00.000Z"
    vulns = [o for o in client.get("/taxii2/odyssey/collections/vulnerabilities/objects/", params={"limit": 1000}).json()["objects"] if o["type"] == "vulnerability"]
    conn = sqlite3.connect(f"file:{paths / 'ews.db'}?mode=ro", uri=True)
    try:
        published = {r[0]: r[1] for r in conn.execute("SELECT id, published FROM vulns WHERE published IS NOT NULL AND published != ''")}
    finally:
        conn.close()
    checked = [o for o in vulns if o["name"] in published]
    assert checked and all(o["created"] == published[o["name"]][:10] + "T00:00:00.000Z" for o in checked), "created is the UTC publication day"
    inds = client.get("/taxii2/odyssey/collections/indicators/objects/", params={"match[type]": "indicator", "limit": 1000}).json()["objects"]
    assert inds and all(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", o["valid_from"]) for o in inds)
    assert all(o["valid_from"].endswith("T00:00:00.000Z") for o in inds if "global_attack_source" in o["labels"]), "DShield dates are whole UTC days"


def test_taxii_pattern_literals_are_escaped(client):
    """A matched value holding a backslash (a sloppy producer's STIX pattern) becomes a valid STIX pattern literal."""
    from backend.app import taxii
    bs = chr(92)
    assert taxii._lit(f"a{bs}b'c") == f"a{bs}{bs}b{bs}'c" and taxii._lit("plain.example") == "plain.example"
    bundle = {"type": "bundle", "id": "bundle--00000000-0000-0000-0000-00000000c0de", "objects": [
        {"type": "indicator", "spec_version": "2.1", "id": "indicator--00000000-0000-0000-0000-00000000c0de", "pattern_type": "stix",
         "pattern": f"[url:value = 'http://login-{VARIANT}.com/kyc{bs}verify']", "created": "2026-01-01T00:00:00.000Z",
         "modified": "2026-01-01T00:00:00.000Z", "valid_from": "2026-01-01T00:00:00.000Z"}]}
    imp = client.post("/api/iocs/import", json={"text": json.dumps(bundle), "source": "review bundle", "tlp": "GREEN"}).json()
    assert [(i["type"], i["matched"]) for i in imp["indicators"]] == [("url", True)]
    value = imp["indicators"][0]["value"]
    assert value.count(bs) == 1, "the record holds one backslash"
    objs = client.get("/taxii2/odyssey/collections/indicators/objects/", params={"match[type]": "indicator", "limit": 1000}).json()["objects"]
    pats = [o["pattern"] for o in objs if f"login-{VARIANT}.com/kyc" in o["pattern"]]
    assert pats == [f"[url:value = '{value.replace(bs, bs + bs)}']"]
    assert all(o["pattern"].count("'") == 2 or "hashes." in o["pattern"] for o in objs), "no stray quote in any pattern"


def test_taxii_identity_is_a_copy_of_the_producer(client):
    """The producer identity in a response is equal to, never the same object as, the module constant."""
    from backend.app import taxii
    from backend.app.engine.reports import PRODUCER
    for alias in ("indicators", "vulnerabilities"):
        ids = [o for o in taxii.objects_for(alias) if o["type"] == "identity" and o["id"] == PRODUCER["id"]]
        assert len(ids) == 1 and ids[0] == PRODUCER and ids[0] is not PRODUCER, alias


def test_watch_ids_are_never_reused_after_delete(copy):
    """A deleted watch leaves its events and ledger rows behind (the audit trail); the next watch must not inherit its id,
    or the interface shows the old watch's firings under a stranger."""
    w1 = watch.add(copy, "product:fortios", {"kind": "connect"}, label="first watch")
    fired = _mine(watch.evaluate(copy, _surge("DET-TEST-SURGE-REUSE", _iso(_now()))), w1["id"])
    assert len(fired) == 1
    assert watch.set_status(copy, w1["id"], "deleted") is None
    w2 = watch.add(copy, "product:panos", {"kind": "tier"}, label="second watch")
    assert w2["id"] > w1["id"], "the deleted watch's id stays with its events"
    listed = next(r for r in watch.list_watches(copy) if r["id"] == w2["id"])
    assert listed["fired"] == 0 and listed["recent"] == [], "no firing of the deleted watch is shown under the new one"
    assert all(e["label"] == "first watch" for e in watch.events(copy, 200) if e["watch_id"] == w1["id"])
    assert all(e["watch_id"] != w2["id"] for e in watch.events(copy, 200))
    assert _fired_rows(copy, w2["id"]) == []
    # deleting the newest watch and adding again still moves forward: the ledger remembers every id ever handed out
    assert watch.set_status(copy, w2["id"], "deleted") is None
    w3 = watch.add(copy, "product:panos", {"kind": "tier"})
    assert w3["id"] > w2["id"]
    assert watch.set_status(copy, w3["id"], "deleted") is None
    ok, bad = Ledger(conn=copy).verify()
    assert ok and bad is None


# ------------------------------------------------------------------------------------ adversarial review of iocs.py
def test_ioc_review_refang_order_case_and_dot_forms():
    assert iocs.refang("hxxp[://]evil[.]com/x") == "http://evil.com/x" and iocs.refang("hxxp[:]//evil[.]com/x") == "http://evil.com/x"
    assert iocs.refang("hXXps://evil[.]com/x") == "https://evil.com/x" and iocs.refang("evil(dot)com and bad[DOT]org") == "evil.com and bad.org"
    found = dict(iocs.parse("hxxp[://]evil[.]com/x and hXXps://c2[.]evil[.]org/p")[0])
    assert found == {"http://evil.com/x": "url", "https://c2.evil.org/p": "url"}, "a bracketed scheme separator is still a URL, not a bare domain"
    for v, t in (("https://a.b.c.d/e.f", "url"), ("http://1.2.3.4:8080/x.php", "url"), ("10.1.2.3", "ipv4-addr"), ("a.b.c", "domain-name")):
        d = iocs.defang(v, t)
        assert iocs.refang(d) == v and "[.]" in d, (v, d)
    assert iocs.defang("http://1.2.3.4:8080/x.php", "url") == "hxxp://1[.]2[.]3[.]4:8080/x.php", "every dot of the host is bracketed; the path keeps its own"
    assert iocs.defang("https://a.b/c.d", "url") == "hxxps://a[.]b/c.d"


def test_ioc_review_url_hosts_trailing_punctuation_and_file_names():
    d = dict(iocs.parse("see [https://evil.com:8443/login], **https://evil.com/x** and https://user@evil.com/p: done")[0])
    assert set(d) == {"https://evil.com:8443/login", "https://evil.com/x", "https://user@evil.com/p"}, d
    assert all(t == "url" for t in d.values()), "a host with a port or userinfo is not duplicated as a domain indicator"
    assert iocs._host("https://User@Evil.com:8443/p?q#f") == "evil.com" and iocs._host("evil.com.") == "evil.com"
    names = "payload.bat update.xml a.vbs x.msi k.lnk doc.docx s.xlsx shell.jar img.iso r.rar t.gz b.bin c.ini d.cfg go.sh pic.jpeg k.gif"
    assert iocs.parse(names)[0] == [], "file names are not domains"
    assert dict(iocs.parse("drop.evil.com. and _dmarc.evil.org and foo_bar.evil.net")[0]) == {
        "drop.evil.com": "domain-name", "evil.org": "domain-name", "evil.net": "domain-name"}


def test_ioc_review_stix_values_are_validated_and_sco_objects_read():
    def bundle(*objs):
        return json.dumps({"type": "bundle", "objects": list(objs)})

    def ind(p):
        return {"type": "indicator", "pattern": p}

    hostile = bundle(ind("[url:value = '=HYPERLINK(1)']"), ind("[ipv4-addr:value = 'not an ip ] OR [x']"),
                     {"type": "vulnerability", "external_references": [{"source_name": "cve", "external_id": "garbage"}]})
    assert iocs.parse(hostile) == ([], "stix"), "a bundle's values must be what their type says they are"
    ok, fmt = iocs.parse(bundle(ind("[ipv4-addr:value = '203.0.113.9/32']"), ind(f"[file:hashes.MD5 = '{SHA256}']"),
                                ind(f"[file:hashes.SHA256 = '{SHA256}']"), ind("[ipv4-addr:value != '203.0.113.10']"),
                                {"type": "ipv4-addr", "value": "203.0.113.11"}, {"type": "domain-name", "value": "Sco.Example."},
                                {"type": "url", "value": "https://sco.example/x"},
                                {"type": "file", "hashes": {"SHA-256": SHA256.upper(), "SSDEEP": "3:abc:def"}}))
    assert fmt == "stix" and set(ok) == {("203.0.113.9", "ipv4-addr"), (SHA256, "file:sha256"), ("203.0.113.11", "ipv4-addr"),
                                         ("sco.example", "domain-name"), ("https://sco.example/x", "url")}
    for broken in ('{"objects": "notalist"}', '{"objects": [1, 2]}', bundle({"type": "indicator", "pattern": 5}),
                   bundle({"type": "vulnerability", "name": 5, "external_references": "x"})):
        found, fmt = iocs.parse(broken)
        assert found == [] and fmt in ("stix", "text"), broken
    assert iocs.parse('{"ip": "203.0.113.12", "note": "plain JSON, not a bundle"}') == ([("203.0.113.12", "ipv4-addr")], "text")


def test_ioc_review_hostile_pastes_parse_in_linear_time():
    import hashlib
    import time
    t = time.perf_counter()
    assert iocs.parse("a." * 200000)[0] == []  # 400 KB of 'a.a.a.': the old whole-text regex backtracked for ~30 minutes
    a = time.perf_counter() - t
    t = time.perf_counter()
    found, _ = iocs.parse("\n".join(hashlib.md5(str(i).encode()).hexdigest() for i in range(20000)))
    b = time.perf_counter() - t
    assert len(found) == 20000 and all(t_ == "file:md5" for _, t_ in found)
    assert a < 5 and b < 5, (a, b)


def test_ioc_review_reimport_keeps_live_flow_evidence(copy):
    now = _now()
    ip = "198.18.123.45"
    iocs.import_text(copy, f"{ip} review probe", "review", now=now)
    detail = {"title": "flow to 198[.]18[.]123[.]45:443", "src": "10.20.17.219", "dst": ip, "dport": 443, "org_id": "PWR-01"}
    iocs.mark_live_match(copy, ip, detail, now)
    before = _count(copy, "ioc.match")
    r = iocs.import_text(copy, f"{ip} review probe again", "review", now=now + dt.timedelta(minutes=1))
    row = r["indicators"][0]
    assert row["matched"] and row["severity"] == "High" and [m["where"] for m in row["matches"]] == ["live flows"]
    db = copy.execute("SELECT matched, severity, matches FROM iocs WHERE value = ? AND type = 'ipv4-addr'", (ip,)).fetchone()
    assert db[0] == 1 and db[1] == "High" and [m["where"] for m in json.loads(db[2])] == ["live flows"]
    live = {"flow_rows": [{"src": "10.20.17.219", "dst": ip, "dport": 443}]}
    r2 = iocs.import_text(copy, ip, "review", live=live, now=now + dt.timedelta(minutes=2))
    assert [m["where"] for m in r2["indicators"][0]["matches"]] == ["firewall flows", "live flows"]
    assert _count(copy, "ioc.match") == before, "an indicator that was already matched is not ledgered again on re-import"


def test_ioc_review_own_hosts_are_not_lookalikes_and_url_ports_match(copy):
    tel = iocs._telemetry(copy, None)
    m, _, sev = iocs.match_one(copy, "vpn.lokseva.example", "domain-name", tel)
    assert [x["where"] for x in m] == ["constituency domain"] and sev == "High", "an organisation's own subdomain is not a look-alike of itself"
    m, _, _ = iocs.match_one(copy, "https://vgwc.example:8443/x", "url", tel)
    assert [x["where"] for x in m] == ["constituency domain"] and m[0]["org_id"] == "PWR-01"
    m, _, _ = iocs.match_one(copy, f"https://login-{VARIANT}.com:8080/kyc", "url", tel)
    assert [x["where"] for x in m] == ["look-alike"] and m[0]["org_id"] == "PWR-01"
    assert tel["exposure"]["CVE-2026-104935"][0] >= 1, "the exposure record is read once for every CVE, not per pasted id"
    m, _, _ = iocs.match_one(copy, "CVE-2026-104935", "vulnerability", tel)
    assert m and m[0]["where"] == "exposure record" and m[0]["assets"] == tel["exposure"]["CVE-2026-104935"][0]


def test_ioc_review_csv_cells_cannot_run_and_tlp_is_a_vocabulary(copy):
    import csv
    import io
    ip = "198.18.200.213"
    r = iocs.import_text(copy, f"{ip} review", "=cmd|' /C calc'!A0", "+1-1", now=_now())
    assert r["tlp"] == "AMBER", "an unknown TLP is stored as the default, not as pasted text"
    assert tuple(copy.execute("SELECT tlp, source FROM iocs WHERE value = ?", (ip,)).fetchone()) == ("AMBER", "=cmd|' /C calc'!A0")
    row = next(x for x in iocs.export_rows(copy) if x["value"] == ip)
    assert row["source"] == "'=cmd|' /C calc'!A0" and row["tlp"] == "AMBER" and row["defanged"] == "198[.]18[.]200[.]213"
    from backend.app.engine.export import to_csv
    for cells in list(csv.reader(io.StringIO(to_csv(iocs.export_rows(copy)))))[1:]:
        assert all(c[:1] not in ("=", "+", "-", "@") for c in cells), cells
    assert iocs.import_text(copy, "198.18.200.214", "review", "green", now=_now())["tlp"] == "GREEN"
    assert len(iocs.list_iocs(copy, limit=-1)["indicators"]) == 0 and len(iocs.list_iocs(copy, limit=1)["indicators"]) == 1
