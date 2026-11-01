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
