"""Brand/social monitoring and consented surface self-assessment: passive sources scored and stored with provenance,
high hits audited, duplicates suppressed, and the surface scan refusing anything that is not the operator's own."""

import datetime as dt
import json
import sqlite3
from pathlib import Path

import pytest

from backend.app.engine import brand, surface

DB = Path(__file__).resolve().parents[1] / "data" / "ews.db"
NOW = dt.datetime(2026, 11, 1, 2, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def conn(tmp_path):
    if not DB.exists():
        pytest.skip("no built database")
    path = tmp_path / "ews.db"
    src, dst = sqlite3.connect(f"file:{DB}?mode=ro", uri=True), sqlite3.connect(path)
    src.backup(dst)
    src.close()
    dst.close()
    c = sqlite3.connect(path, timeout=30)
    brand.ensure(c)
    surface.ensure(c)
    return c


# ------------------------------------------------------------------------------------------------------- brand
def _brand_fetch(url, timeout=20):
    ts = NOW.strftime("%Y-%m-%dT%H:%M:%S")
    rss_date = NOW.strftime("%a, %d %b %Y %H:%M:%S GMT")
    if "crt.sh" in url:
        return 200, json.dumps([{"id": 1, "common_name": "vidyut-login.example.com", "issuer_name": "R3",
                                 "not_before": ts, "name_value": "vidyut-login.example.com"}])
    if "urlhaus" in url:
        return 200, json.dumps({"1": [{"id": "9", "dateadded": ts, "url": "http://vidyut-secure.example/pay",
                                       "url_status": "online", "threat": "malware_download", "tags": ["phish"],
                                       "urlhaus_link": "https://urlhaus.abuse.ch/url/9/"}]})
    if "openphish" in url:
        return 200, "http://vidyut-verify.example/login\nhttp://unrelated.example/x"
    if "news.google" in url:
        return 200, f'<rss><channel><item><title>Vidyut grid reports data breach</title><link>http://n.example/1</link>' \
                    f'<pubDate>{rss_date}</pubDate><description>breach exposed records</description></item></channel></rss>'
    if "hn.algolia" in url:
        return 200, json.dumps({"hits": [{"objectID": "42", "title": "Vidyut outage discussion", "created_at": ts + "Z",
                                          "author": "x", "points": 5, "url": "http://hn.example"}]})
    if "reddit" in url:
        return 200, f'<rss><channel><item><title>vidyut down again</title><link>http://r.example</link>' \
                    f'<pubDate>{rss_date}</pubDate><description>outage</description></item></channel></rss>'
    return 500, ""


def test_brand_scan_collects_scores_stores_and_audits(conn):
    r = brand.scan(conn, term="vidyut", now=NOW, fetch=_brand_fetch)
    assert r["hits"] == 6 and r["new_hits"] == 6 and r["offline"] == 0
    by_kind = {h["kind"]: h for h in r["top"]}
    assert set(by_kind) == {"lookalike_cert", "malicious_url", "phishing_url", "mention"}
    assert by_kind["lookalike_cert"]["score"] == 90.0  # 55 + 20 recent + 15 lure word "login"
    assert by_kind["malicious_url"]["score"] == 85.0 and by_kind["phishing_url"]["score"] == 80.0
    # indicators are defanged for display, raw kept in the stored row
    assert "[.]" in by_kind["malicious_url"]["value"] and by_kind["malicious_url"]["value"].startswith("hxxp")
    # the three high hits (>= 70) entered the audit trail
    led = conn.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'brand.hit'").fetchone()[0]
    assert led == 3 and r["ledger_events"] == 3
    assert all(e[0] == "REAL" for e in conn.execute("SELECT provenance FROM ledger WHERE kind = 'brand.hit'"))


def test_brand_second_scan_makes_no_duplicates(conn):
    brand.scan(conn, term="vidyut", now=NOW, fetch=_brand_fetch)
    before = conn.execute("SELECT COUNT(*) FROM brand_hits").fetchone()[0]
    r2 = brand.scan(conn, term="vidyut", now=NOW, fetch=_brand_fetch)
    after = conn.execute("SELECT COUNT(*) FROM brand_hits").fetchone()[0]
    assert r2["new_hits"] == 0 and before == after
    s = brand.summary(conn)
    assert any(t["term"] == "vidyut" and t["max_score"] == 90.0 for t in s["terms"])


def test_brand_sources_offline_do_not_fail_the_scan(conn):
    r = brand.scan(conn, term="nomatchbrandxyz", now=NOW, fetch=lambda u, timeout=20: (500, ""))
    # crt.sh / news / hn / reddit error out and are offline; openphish and urlhaus fall back to snapshot/cache
    assert any(s["status"] == "offline" for s in r["sources"].values())
    assert "hits" in r and r["hits"] >= 0  # returned, never raised


def test_terms_for_org_drops_generic_words(conn):
    terms = brand.terms_for_org(conn, "PWR-01")
    assert "vidyut" in terms and "grid" not in terms and "west" not in terms and "corp" not in terms


# ------------------------------------------------------------------------------------------------------- surface
def test_surface_gate_refuses_what_is_not_ours(conn):
    assert surface.allowed("http://example.com", conn)[0] is False
    assert surface.allowed("http://8.8.8.8", conn)[0] is False
    assert surface.allowed("http://127.0.0.1:8080", conn)[0] is True
    assert surface.allowed("https://10.0.0.5", conn)[0] is True
    assert surface.allowed("http://192.168.1.10", conn)[0] is True
    assert surface.scan(conn, "http://127.0.0.1:9", consent=False)["status"] == "refused"
    assert surface.scan(conn, "http://example.com", consent=True)["status"] == "refused"


def _surface_fetch(url, method="GET"):
    if url.endswith("/.git/HEAD"):
        return {"status": 200, "headers": {"content-type": "text/plain"}, "body": "ref: refs/heads/main\n", "url": url}
    if url.rstrip("/").endswith("8080"):
        return {"status": 200, "headers": {"server": "uvicorn/0.30", "content-type": "text/html"},
                "body": "<html><body>portal</body></html>", "url": url}
    return {"status": 404, "headers": {}, "body": "", "url": url}


def test_surface_scan_finds_and_audits(conn):
    surface._COOLDOWN.clear()
    r = surface.scan(conn, "http://127.0.0.1:8080", consent=True, org_id="PWR-01", now=NOW, fetch=_surface_fetch)
    assert r["status"] == "done" and r["requests"] <= surface.MAX_REQUESTS
    titles = {f["title"] for f in r["findings"]}
    assert "/.git/HEAD is reachable" in titles and "Served over plain HTTP" in titles
    assert "No Content-Security-Policy header" in titles
    git = next(f for f in r["findings"] if f["title"].startswith("/.git"))
    assert git["severity"] == "Critical" and git["cwe"] and git["fix"] and git["provenance"] == "REAL"
    assert 0 <= r["score"] <= 100 and r["grade"] in ("A", "B", "C", "D", "E", "F")
    assert conn.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'surface.scan'").fetchone()[0] >= 1
    assert conn.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'surface.finding'").fetchone()[0] >= 1
    assert surface.get(conn, r["scan_id"])["findings_list"]


def test_surface_cooldown_blocks_a_quick_rescan(conn):
    surface._COOLDOWN.clear()
    surface.scan(conn, "http://127.0.0.1:8080", consent=True, now=NOW, fetch=_surface_fetch)
    again = surface.scan(conn, "http://127.0.0.1:8080", consent=True, now=NOW, fetch=_surface_fetch)
    assert again["status"] == "refused" and "cooldown" in again["reason"]


@pytest.mark.parametrize("target", ["http://127.0.0.1:8080"])
def test_surface_real_scan_of_the_portal_if_up(conn, target):
    import httpx
    try:
        httpx.get(target + "/", timeout=2)
    except Exception:  # noqa: BLE001
        pytest.skip("portal not running on :8080")
    surface._COOLDOWN.clear()
    r = surface.scan(conn, target, consent=True, org_id="PWR-01", now=NOW)
    assert r["status"] == "done" and r["requests"] <= surface.MAX_REQUESTS and r["grade"]


# --------------------------------------------------------------------------- brand: adversarial-review regressions
def test_brand_default_fetch_refuses_hosts_outside_the_source_allowlist():
    for url in ("http://127.0.0.1/", "https://crt.sh.evil.example/?q=x", "https://crt.sh@evil.example/?q=x", "file:///etc/passwd"):
        with pytest.raises(ValueError):
            brand._default_fetch(url)
    assert brand._allowed_url("https://crt.sh/?q=%25x%25&output=json") and brand._allowed_url("https://www.reddit.com/search.rss?q=x")


def test_brand_default_fetch_caps_size_and_refuses_redirects_off_the_allowlist(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/big":
                self.send_response(200)
                self.end_headers()
                try:
                    for _ in range(150):  # ~9.8 MB, past the 8 MB cap
                        self.wfile.write(b"x" * 65536)
                except OSError:
                    pass
            elif self.path == "/go":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.end_headers()
            elif self.path == "/hop":
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"fine")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(brand, "ALLOWED_DOMAINS", brand.ALLOWED_DOMAINS + ("127.0.0.1",))
    try:
        assert brand._default_fetch(f"http://127.0.0.1:{port}/ok", timeout=5) == (200, "fine")
        assert brand._default_fetch(f"http://127.0.0.1:{port}/hop", timeout=5) == (200, "fine")
        with pytest.raises(RuntimeError, match="redirect refused"):
            brand._default_fetch(f"http://127.0.0.1:{port}/go", timeout=5)
        with pytest.raises(RuntimeError, match="refused"):
            brand._default_fetch(f"http://127.0.0.1:{port}/big", timeout=5)
    finally:
        srv.shutdown()


def test_brand_rss_entity_check_covers_the_whole_document():
    pad = "<!--" + " " * 5000 + "-->"  # a long prolog comment used to push the DTD past the old 4000-char window
    hostile = '<?xml version="1.0"?>' + pad + '<!DOCTYPE rss [<!ENTITY a "AAAA">]><rss><channel><item><title>&a;</title></item></channel></rss>'
    with pytest.raises(ValueError):
        brand._rss_items(hostile)
    with pytest.raises(ValueError):
        brand._rss_items("<rss>" + " " * 4_000_001 + "</rss>")
    with pytest.raises(Exception):
        brand._rss_items("<rss><channel><item>")  # malformed: raises in the adapter, which _run_source reports as offline
    atom = ('<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>t</title><link rel="self" href="https://www.reddit.com/self"/>'
            '<link href="https://www.reddit.com/r/x/comments/1"/><updated>2026-10-31T00:00:00+00:00</updated></entry></feed>')
    assert brand._rss_items(atom)[0]["link"] == "https://www.reddit.com/r/x/comments/1"


def test_brand_links_handed_to_the_ui_are_http_only():
    rss = '<rss><channel><item><title>vidyut leak</title><link>javascript:alert(1)</link><description>x</description></item></channel></rss>'
    assert brand._reddit("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, rss))[0]["url"] == "https://www.reddit.com/"
    assert brand._news("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, rss))[0]["url"] == "https://news.google.com/"
    hn = json.dumps({"hits": [{"objectID": "7", "title": "vidyut hack", "url": "javascript:alert(1)", "created_at": "2026-10-31T00:00:00Z"}]})
    h = brand._hn("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, hn))[0]
    assert h["url"] == "https://news.ycombinator.com/item?id=7" and "javascript" in h["raw"]  # outbound URL kept in raw only
    uh = json.dumps({"1": [{"id": 2, "url": "http://vidyut-x.test/a", "urlhaus_link": "javascript:x"}]})
    assert brand._urlhaus("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, uh))[0]["url"] == "https://urlhaus.abuse.ch/"
    with pytest.raises(RuntimeError):
        brand._hn("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, "[]"))


def test_brand_indicators_are_defanged_in_title_snippet_and_evidence():
    crt = json.dumps([{"id": 5, "common_name": "vidyut-login.test", "issuer_name": "R3", "not_before": "2026-10-30T00:00:00",
                       "name_value": "vidyut-login.test\nwww.vidyut-login.test"}])
    h = brand._crtsh("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, crt))[0]
    for field in ("value", "title", "snippet", "evidence"):
        assert "vidyut-login.test" not in h[field] and "vidyut-login[.]test" in h[field]
    assert "vidyut-login.test" in h["raw"]  # the raw form stays for exports
    o = next(x for x in brand._openphish("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, "http://vidyut-verify.test/login")) if "verify" in x["value"])
    assert o["title"] == "vidyut-verify[.]test" and "vidyut-verify.test" not in o["evidence"]
    u = brand._urlhaus("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, json.dumps({"1": [{"id": 2, "url": "http://vidyut-x.test/a"}]})))[0]
    assert u["title"] == "vidyut-x[.]test" and "vidyut-x.test" not in u["evidence"]
    assert brand.defang("HTTP://EVIL.COM/x").lower() == "hxxp://evil[.]com/x" and brand.defang(brand.defang("a.b")) == "a[.]b"
    assert brand._refang("hxxps://a[.]b/c") == "https://a.b/c"


def test_brand_crtsh_tolerates_nulls_finds_san_only_names_and_scores_the_latest_issuance():
    rows = json.dumps([{"id": 2, "common_name": "sni.cloudflaressl.com", "issuer_name": None, "not_before": "2026-10-30T00:00:00",
                        "name_value": "sni.cloudflaressl.com\nvidyut-login.test"}, "junk",
                       {"id": 3, "common_name": "vidyut.test", "issuer_name": "R3", "not_before": "2024-01-01T00:00:00", "name_value": "vidyut.test"},
                       {"id": 4, "common_name": "*.vidyut.test", "issuer_name": "R3", "not_before": "2026-10-30T00:00:00", "name_value": "*.vidyut.test"}])
    out = {h["value"]: h for h in brand._crtsh("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, rows))}
    assert set(out) == {"vidyut-login[.]test", "vidyut[.]test"}
    assert out["vidyut-login[.]test"]["score"] == 90.0  # SAN-only name: 55 + 20 recent + 15 "login"
    assert out["vidyut[.]test"]["score"] == 75.0 and out["vidyut[.]test"]["url"].endswith("id=4")  # latest issuance, not the first row
    with pytest.raises(RuntimeError):
        brand._crtsh("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, '{"error": "x"}'))


def test_brand_scoring_ignores_dates_in_the_future_and_bad_timestamps():
    assert brand._parse(123) is None and brand._parse("9999-12-31T23:59:59-05:00") is None and brand._parse("") is None
    assert brand._score_cert("x.test", "2030-01-01T00:00:00", NOW) == 55.0
    assert brand._score_cert("x.test", (NOW - dt.timedelta(days=3)).isoformat(), NOW) == 75.0
    assert brand._score_mention("t", "s", "2030-01-01T00:00:00", NOW) == 20.0
    assert brand._score_mention("breach", "s", (NOW - dt.timedelta(days=1)).isoformat(), NOW) == 55.0


def test_brand_urlhaus_cache_is_only_for_the_real_fetcher_and_survives_corruption(tmp_path, monkeypatch):
    monkeypatch.setattr(brand, "CACHE", tmp_path)
    fixture = lambda u, timeout=20: (200, json.dumps({"1": [{"id": "1", "url": "http://vidyut-fixture.test/x"}]}))  # noqa: E731
    assert len(brand._urlhaus("vidyut", ["vidyut"], NOW, fixture)) == 1
    assert not (tmp_path / "urlhaus_recent.json").exists()  # a fixture never lands in the cache a live scan reads
    (tmp_path / "urlhaus_recent.json").write_text("{not json", encoding="utf-8")
    calls = []

    def real(url, timeout=20):
        calls.append(url)
        return 200, json.dumps({"1": [{"id": "2", "url": "http://vidyut-live.test/y", "tags": "single"}]})

    monkeypatch.setattr(brand, "_default_fetch", real)
    hits = brand._urlhaus("vidyut", ["vidyut"], NOW, real)
    assert len(hits) == 1 and hits[0]["title"] == "vidyut-live[.]test" and len(calls) == 1  # corrupt cache ignored, refetched
    assert json.loads((tmp_path / "urlhaus_recent.json").read_text(encoding="utf-8"))["1"][0]["id"] == "2"
    assert brand._urlhaus("vidyut", ["vidyut"], NOW, real) and len(calls) == 1  # the second read is served from the cache
    assert not list(tmp_path.glob("*.tmp"))


def test_brand_urlhaus_skips_malformed_rows_instead_of_going_offline():
    payload = json.dumps({"1": [{"id": 1, "url": 12345, "tags": "abc"}, None, {"id": 2, "url": "http://vidyut-x.test/a", "tags": "abc", "threat": None}]})
    out = brand._urlhaus("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, payload))
    assert [h["title"] for h in out] == ["vidyut-x[.]test"] and out[0]["snippet"].startswith("malware · ? · tags abc")
    with pytest.raises(RuntimeError):
        brand._urlhaus("vidyut", ["vidyut"], NOW, lambda u, timeout=20: (200, '"a string"'))


def test_brand_scan_rejects_blank_short_or_non_string_terms(conn):
    off = lambda u, timeout=20: (500, "")  # noqa: E731
    before = conn.execute("SELECT COUNT(*) FROM brand_scans").fetchone()[0]
    for bad in ("   ", "a", "ab", 12, "x" * 101):
        with pytest.raises(ValueError):
            brand.scan(conn, term=bad, now=NOW, fetch=off)
    assert conn.execute("SELECT COUNT(*) FROM brand_scans").fetchone()[0] == before
    assert brand.scan(conn, term="  Vidyut   Grid ", now=NOW, fetch=off)["terms"] == ["vidyut grid"]


def test_brand_org_scan_does_not_flag_the_organisations_own_certificates(conn):
    dom = conn.execute("SELECT domain FROM orgs WHERE id = 'PWR-01'").fetchone()[0]
    ts = NOW.strftime("%Y-%m-%dT%H:%M:%S")
    crt = json.dumps([{"id": 1, "common_name": f"login.{dom}", "issuer_name": "R3", "not_before": ts, "name_value": f"login.{dom}"},
                      {"id": 2, "common_name": f"login-{dom}", "issuer_name": "R3", "not_before": ts, "name_value": f"login-{dom}"}])
    own = brand.defang(f"login.{dom}")
    before = conn.execute("SELECT COUNT(*) FROM brand_hits WHERE value = ?", (own,)).fetchone()[0]
    r = brand.scan(conn, org_id="PWR-01", now=NOW, fetch=lambda u, timeout=20: (200, crt) if "crt.sh" in u else (500, ""), sources=["crt.sh"])
    assert [h["value"] for h in r["top"]] == [brand.defang(f"login-{dom}")] and r["sources"]["crt.sh"]["count"] == 1
    assert conn.execute("SELECT COUNT(*) FROM brand_hits WHERE value = ?", (own,)).fetchone()[0] == before


def test_brand_store_handles_a_concurrent_insert_of_the_same_hit(conn):
    other = sqlite3.connect(conn.execute("PRAGMA database_list").fetchone()[2], timeout=30)
    hit = {"ts": "2026-11-01T00:00:00Z", "source": "OpenPhish", "kind": "phishing_url", "channel": "x", "value": "hxxp://race[.]test",
           "url": "https://openphish.com/", "title": "race[.]test", "snippet": "", "score": 80.0, "evidence": "e", "raw": "{}"}

    class Racing:  # the other connection stores the same hit between our SELECT and our INSERT
        def __init__(self, inner):
            self.inner, self.fired = inner, False

        def execute(self, sql, params=()):
            cur = self.inner.execute(sql, params)
            if not self.fired and sql.lstrip().startswith("SELECT id FROM brand_hits"):
                self.fired = True
                brand._store(other, hit, "race", None, "2026-11-01T00:00:00Z")
                other.commit()
            return cur

        def __getattr__(self, name):
            return getattr(self.inner, name)

    try:
        assert brand._store(Racing(conn), hit, "race", None, "2026-11-01T00:00:01Z") is False
        conn.commit()
        assert conn.execute("SELECT COUNT(*), MAX(last_seen) FROM brand_hits WHERE term = 'race'").fetchone() == (1, "2026-11-01T00:00:01Z")
    finally:
        other.close()


def test_brand_hits_clamps_limit_and_normalises_the_term(conn):
    brand.scan(conn, term="vidyut", now=NOW, fetch=_brand_fetch)
    assert brand.hits(conn, term=" Vidyut ") == brand.hits(conn, term="vidyut") != []
    assert len(brand.hits(conn, limit=10**9)) <= 1000  # the SQL LIMIT is clamped to 1..1000
    assert len(brand.hits(conn, term="vidyut", limit=-1)) == 1  # a negative limit no longer means "unlimited"
    assert len(brand.hits(conn, term="vidyut", limit=0)) == len(brand.hits(conn, term="vidyut", limit=100))  # 0 falls back to the default


def test_brand_summary_keeps_scan_terms_whole_and_drops_blanks(conn):
    conn.execute("INSERT INTO brand_scans (ts, term, org_id, sources, hits, new_hits, seconds) VALUES ('2026-11-01T00:00:00Z', '', 'X-1', '{}', 0, 0, 0.1)")
    conn.commit()
    hn = json.dumps({"hits": [{"objectID": "1", "title": "acme, inc hack", "created_at": "2026-10-31T00:00:00Z"}]})
    brand.scan(conn, term="acme, inc", now=NOW, fetch=lambda u, timeout=20: (200, hn) if "algolia" in u else (500, ""), sources=["Hacker News"])
    names = [t["term"] for t in brand.summary(conn)["terms"]]
    assert "" not in names and "acme, inc" in names and "inc" not in names


# ------------------------------------------------------------------------------- surface: adversarial review additions
# Appended by the surface.py review. Each test is a regression for a defect that was reproduced against a copy of the
# database before the fix: malformed URLs raising, DNS rebinding between gate and request, catch-all pages reported as
# Critical exposures, self-signed HTTPS targets unscannable, credentials written to the audit tables, refusals missing
# from the ledger, cooldown bypass by aliasing, and a prohibited CWE category.
import http.server
import os
import shutil
import socket
import ssl
import subprocess
import threading

PUBLIC = "93.184.216.34"  # routable and not ours (TEST-NET ranges such as 203.0.113.x count as non-routable, so they do not test the gate)


class _Echo(http.server.BaseHTTPRequestHandler):
    """A loopback web server that records the address, Host header and path of every request it receives."""
    seen: list = []

    def do_GET(self):
        _Echo.seen.append((self.server.server_address[0], self.headers.get("Host"), self.path))
        if self.path == "/go":
            self.send_response(302)
            self.send_header("Location", f"http://{PUBLIC}/")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # keep pytest output clean
        pass


def _serve(addr: str, port: int = 0, tls: tuple | None = None):
    srv = http.server.HTTPServer((addr, port), _Echo)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _resolver(mapping: dict):
    """A getaddrinfo stand-in: names in `mapping` resolve to the listed addresses (a callable yields one list per
    call); everything else goes to the real resolver."""
    real = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host in mapping:
            ips = mapping[host]() if callable(mapping[host]) else mapping[host]
            out = []
            for ip in ips:
                out.extend(real(ip, *args, **kwargs))
            return out
        return real(host, *args, **kwargs)
    return fake


def test_surface_malformed_urls_are_refused_not_raised(conn):
    for url in ("http://127.0.0.1:abc", "http://[::1", "http://127.0.0.1:65536"):
        ok, reason = surface.allowed(url, conn)
        assert ok is False and "malformed" in reason
        r = surface.scan(conn, url, consent=True)
        assert r["status"] == "refused" and "malformed" in r["reason"]


def test_surface_gate_ipv6_cgnat_and_transition_forms(conn):
    ours = ["http://[::1]:8000", "http://[fe80::1]/", "http://[fc00::1]/", "http://[::ffff:127.0.0.1]/", "http://100.64.0.1", "http://[::ffff:10.0.0.5]/"]
    not_ours = ["http://[::ffff:8.8.8.8]/", "http://[2002:808:808::1]/", "http://[2001:0:4136:e378::1]/", "http://[64:ff9b::808:808]/", f"http://{PUBLIC}", "http://[2606:4700::1111]/"]
    assert all(surface.allowed(u, conn)[0] for u in ours), [u for u in ours if not surface.allowed(u, conn)[0]]
    assert not any(surface.allowed(u, conn)[0] for u in not_ours), [u for u in not_ours if surface.allowed(u, conn)[0]]


def test_surface_gate_hostname_with_any_public_address_is_refused(conn, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({"mixed.test": ["127.0.0.1", PUBLIC], "private.test": ["10.0.0.5", "192.168.1.9"]}))
    assert surface.allowed("http://mixed.test", conn)[0] is False
    assert surface.allowed("http://private.test:8443", conn)[0] is True


def test_surface_consent_is_checked_before_any_lookup(conn, monkeypatch):
    def never(host, *a, **k):
        raise AssertionError(f"resolver called for {host} without consent")
    monkeypatch.setattr(socket, "getaddrinfo", never)
    r = surface.scan(conn, "http://never.test:8080", consent=False)
    assert r["status"] == "refused" and "consent" in r["reason"]


def test_surface_connections_are_pinned_to_the_gate_approved_address(conn, monkeypatch):
    """DNS rebinding: the name answers 127.0.0.1 when the gate asks and another address for every later lookup.
    Every request of the scan must still reach the address the gate approved, with the original Host header."""
    try:
        owned = _serve("127.0.0.1")
        decoy = _serve("127.0.0.2", owned.server_address[1])
    except OSError:
        pytest.skip("this host has no second loopback address")
    port = owned.server_address[1]
    calls = {"n": 0}

    def flip():
        calls["n"] += 1
        return ["127.0.0.1"] if calls["n"] == 1 else ["127.0.0.2"]
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({"rebind.test": flip}))
    _Echo.seen.clear()
    surface._COOLDOWN.clear()
    try:
        r = surface.scan(conn, f"http://rebind.test:{port}", consent=True, now=NOW)
    finally:
        owned.shutdown()
        decoy.shutdown()
    assert r["status"] == "done" and 1 <= r["requests"] <= surface.MAX_REQUESTS
    assert calls["n"] == 1, "the hostname must be resolved exactly once, at the gate"
    assert {a for a, _, _ in _Echo.seen} == {"127.0.0.1"} and len(_Echo.seen) == r["requests"]
    assert all(h == f"rebind.test:{port}" for _, h, _ in _Echo.seen)


def test_surface_default_fetch_never_follows_redirects_and_sends_only_get_head(conn):
    srv = _serve("127.0.0.1")
    port = srv.server_address[1]
    _Echo.seen.clear()
    try:
        r = surface._default_fetch(f"http://127.0.0.1:{port}/go", "GET", pin="127.0.0.1")
        assert r["status"] == 302 and PUBLIC in r["headers"]["location"]
        assert len(_Echo.seen) == 1, "a redirect is reported, never followed"
        with pytest.raises(ValueError):
            surface._default_fetch(f"http://127.0.0.1:{port}/", "POST", pin="127.0.0.1")
        with pytest.raises(PermissionError):
            surface._default_fetch(f"http://{PUBLIC}/", "GET")  # unpinned: decides for itself and fails closed
        assert len(_Echo.seen) == 1
    finally:
        srv.shutdown()


_SPA = '<!doctype html><html><head><title>app</title></head><body><div id="app"></div><script src="/assets/index.js"></script></body></html>'


def _spa_fetch(url, method="GET"):  # a Vue/Angular style single-page app: every path answers 200 with index.html
    return {"status": 200, "headers": {"content-type": "text/html"}, "body": _SPA, "url": url}


def _soft404_fetch(url, method="GET"):  # a server whose "not found" page is a 200 HTML page echoing the path, plus one real leak
    path = url.split(":8098", 1)[1]
    if path == "/":
        return {"status": 200, "headers": {}, "body": "<html><body>home</body></html>", "url": url}
    if path == "/.git/HEAD":
        return {"status": 200, "headers": {"content-type": "text/plain"}, "body": "ref: refs/heads/main\n", "url": url}
    return {"status": 200, "headers": {"content-type": "text/html"}, "body": f"<html><body><h1>Not found: {path}</h1></body></html>", "url": url}


def test_surface_catch_all_and_soft_404_pages_are_not_exposures(conn):
    surface._COOLDOWN.clear()
    r = surface.scan(conn, "http://127.0.0.1:8099", consent=True, now=NOW, fetch=_spa_fetch)
    assert r["status"] == "done" and r["requests"] <= surface.MAX_REQUESTS
    assert [f for f in r["findings"] if f["check"] == "exposure"] == []
    r = surface.scan(conn, "http://127.0.0.1:8098", consent=True, now=NOW, fetch=_soft404_fetch)
    exposures = [f for f in r["findings"] if f["check"] == "exposure"]
    assert [(f["path"], f["severity"], f["cwe"]) for f in exposures] == [("/.git/HEAD", "Critical", "CWE-538")]
    valid = {"CWE-200", "CWE-284", "CWE-295", "CWE-298", "CWE-319", "CWE-489", "CWE-538", "CWE-693", "CWE-1004", "CWE-1021"}
    assert {f["cwe"] for f in r["findings"]} <= valid  # CWE-16 is a category whose use for mapping is prohibited


def test_surface_self_signed_https_target_is_scanned_and_flagged(conn, tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not on PATH to mint a throwaway certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "365", "-subj", "/CN=localhost"], check=True, capture_output=True, env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    srv = _serve("127.0.0.1", tls=(str(cert), str(key)))
    port = srv.server_address[1]
    surface._COOLDOWN.clear()
    try:
        days, self_signed = surface._cert_days("127.0.0.1", port, "127.0.0.1")
        assert self_signed is True and days is not None and 360 <= days <= 365
        r = surface.scan(conn, f"https://127.0.0.1:{port}", consent=True, now=NOW)
    finally:
        srv.shutdown()
    assert r["status"] == "done", r["reason"]  # was "unreachable": certificate verification refused the operator's own cert
    titles = {f["title"] for f in r["findings"]}
    assert "Self-signed certificate" in titles and "No HSTS header" in titles
    assert "Served over plain HTTP" not in titles and "Certificate expiring or expired" not in titles


def test_surface_refusals_are_audited_and_credentials_never_leave_the_url(conn):
    before = conn.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'surface.refused'").fetchone()[0]
    r = surface.scan(conn, f"http://admin:S3cret@{PUBLIC}/", consent=True, org_id="PWR-01", now=NOW)
    assert r["status"] == "refused" and "S3cret" not in r["target"] and r["host"] == PUBLIC
    row = conn.execute("SELECT consent, status, target FROM surface_scans ORDER BY id DESC LIMIT 1").fetchone()
    assert row == ("yes", "refused", f"http://{PUBLIC}/")
    kind, subject, payload = conn.execute("SELECT kind, subject, payload FROM ledger WHERE kind = 'surface.refused' ORDER BY seq DESC LIMIT 1").fetchone()
    assert kind == "surface.refused" and subject == PUBLIC and "S3cret" not in payload and json.loads(payload)["consent"] is True
    assert conn.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'surface.refused'").fetchone()[0] == before + 1
    fetched: list[str] = []

    def record(url, method="GET"):
        fetched.append(url)
        return {"status": 404, "headers": {}, "body": "", "url": url}
    surface._COOLDOWN.clear()
    r = surface.scan(conn, "http://u:p@127.0.0.1:8097/", consent=True, now=NOW, fetch=record)
    assert r["status"] == "done" and fetched and not any("u:p@" in u for u in fetched) and r["target"] == "http://127.0.0.1:8097/"
    r = surface.scan(conn, "http://127.0.0.1:8097/", consent=False, now=NOW)
    assert r["status"] == "refused" and conn.execute("SELECT consent FROM surface_scans ORDER BY id DESC LIMIT 1").fetchone()[0] == "no"


def test_surface_cooldown_covers_every_name_of_the_same_address(conn, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver({"alias.test": ["127.0.0.1"]}))
    surface._COOLDOWN.clear()
    assert surface.scan(conn, "http://127.0.0.1:8080", consent=True, now=NOW, fetch=_surface_fetch)["status"] == "done"
    again = surface.scan(conn, "http://alias.test:8080", consent=True, now=NOW, fetch=_surface_fetch)
    assert again["status"] == "refused" and "cooldown" in again["reason"]
