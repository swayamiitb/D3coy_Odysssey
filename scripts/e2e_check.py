"""End-to-end check: every screen's data and every button's action, on a private copy of the live database.

Run:  .venv/Scripts/python scripts/e2e_check.py [--no-ai]

The live data/ews.db and data/cache.db are copied with SQLite's online backup (consistent even while the API is
writing), the API is pointed at the copies, and the script makes the same HTTP calls the interface makes:
  - loads every view (Now, SOC, Intel, Organisations, Proof) and an alert's detail sheet;
  - watches a graph entity and sees the rule fire on a drill; pastes indicators and matches them against telemetry and
    exposure (CSV and STIX out, a STIX bundle in); replays the graph as it stood; reads the TAXII 2.1 server; runs a
    brand scan against public sources (which may be offline) and a consented attack-surface scan of the demo portal;
  - reads NDMA's SACHET feed (public domain, snapshot here) matched to the operators' states, walks the inbound CAP
    guard's ladder (forged sender, a trusted alert, its replay, an XXE body), exports a warning as SACHET-compatible
    CAP marked Exercise, and sees the disaster alerts drawn on the intelligence graph;
  - approves one proposal and rejects another (human in the loop), and checks that the notices went out;
  - works the top warning through its lifecycle, and a SOC case from new to closed;
  - analyses a pasted advisory (guard model and encoders; skipped with --no-ai);
  - connects an app to the HTTP shield through the agents' webhook, detects an attack, drops the next one in block
    mode, and checks that the red-team runner refuses a public target;
  - routes alerts to a real webhook receiver (the stand-in for Slack / Discord / Teams / your app): a test alert, then
    an attack on the protected app, each audited; an unconfigured channel refuses;
  - re-verifies the hash-chained audit trail.
The live databases are never touched. Exit code 1 if any check fails.
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import os  # noqa: E402

os.environ.setdefault("ODYSSEY_LIVE", "0")  # the copy is driven by this script, not by a second live engine
os.environ.setdefault("ODYSSEY_NOTIFY", "0")  # channels are built here against a local receiver, never the real destinations

from fastapi.testclient import TestClient  # noqa: E402

import backend.app.cache as cache  # noqa: E402
import backend.app.main as main  # noqa: E402

RESULTS: list[tuple[bool | None, str, str, float]] = []


def _scratch() -> None:
    """The database copies are large: keep them beside the data (the repository's drive), not in the system temp, and
    drop what an earlier run left behind."""
    root = ROOT / "data" / ".tmp"
    root.mkdir(parents=True, exist_ok=True)
    cutoff = time.time() - 3600
    for d in root.glob("odyssey-*"):
        if d.stat().st_mtime < cutoff:
            shutil.rmtree(d, ignore_errors=True)
    tempfile.tempdir = str(root)


def _copy(src: Path, dst: Path) -> Path:
    a, b = sqlite3.connect(src), sqlite3.connect(dst)
    a.backup(b)
    a.close()
    b.close()
    return dst


def check(name: str, fn) -> object:
    started = time.perf_counter()
    try:
        out = fn()
        detail = out if isinstance(out, str) else ""
        RESULTS.append((True, name, detail, time.perf_counter() - started))
        return out
    except Skip as exc:
        RESULTS.append((None, name, f"skipped: {exc}", time.perf_counter() - started))
    except Exception as exc:  # noqa: BLE001 - report every failure, keep going
        RESULTS.append((False, name, f"{type(exc).__name__}: {exc}"[:300], time.perf_counter() - started))
    return None


class Skip(Exception):
    pass


def main_() -> int:
    no_ai = "--no-ai" in sys.argv
    _scratch()
    tmp = Path(tempfile.mkdtemp(prefix="odyssey-e2e-"))
    main.DB_PATH = _copy(main.DB_PATH, tmp / "ews.db")
    cache.PATH = _copy(cache.PATH, tmp / "cache.db")

    with TestClient(main.app) as c:
        def get(path: str):
            r = c.get(path)
            assert r.status_code == 200, f"GET {path} -> {r.status_code} {r.text[:160]}"
            return r.json()

        def post(path: str, body: dict | None = None):
            r = c.post(path, json=body) if body is not None else c.post(path)
            assert r.status_code == 200, f"POST {path} -> {r.status_code} {r.text[:160]}"
            return r.json()

        def ledger_size() -> int:
            return get("/api/telemetry")["ledger"]["events"]

        # ---------------------------------------------------------------- every screen loads with data
        screens = {
            "Now": ["/api/health", "/api/feed", "/api/soc", "/api/forecast", "/api/approvals"],
            "SOC": ["/api/soc/metrics", "/api/cases?status=open", "/api/heatmaps", "/api/autopilot",
                    "/api/alerts?limit=400", "/api/telemetry", "/api/soc/handover"],
            "Intel": ["/api/intel/technologies", "/api/intel/sources", "/api/intel/advisories", "/api/campaigns",
                      "/api/riskplan", "/api/advisories", "/api/sachet?live=false", "/api/graph", "/api/watches", "/api/iocs", "/api/brand",
                      "/api/surface"],
            "Organisations": ["/api/orgs"],
            "Proof": ["/api/scorecard", "/api/tests/last", "/api/ledger/verify", "/api/languages"],
        }
        for screen, paths in screens.items():
            def load(paths=paths):
                empty = [p for p in paths if get(p) in ([], {}, None)]
                assert not empty, f"empty: {empty}"
                return f"{len(paths)} endpoints"
            check(f"screen loads: {screen}", load)

        feed = get("/api/feed")
        top = feed["cards"][0]
        org, cve = top["org_id"], top["cve_id"]

        def org_page():
            oid = get("/api/orgs")[0]["id"]
            p = get(f"/api/orgs/{oid}/profile")
            assert p["alerts"] and p["risk"]["plan"], "profile without warnings or plan"
            get(f"/api/heatmaps?org_id={oid}")
            return f"{p['org']['name']}: {len(p['alerts'])} warnings, {p['risk']['tickets']} tickets"
        check("screen loads: organisation profile", org_page)

        def alert_sheet():
            for suffix in ("", "/related", "/workflow", "/certin-report", "/stix"):
                get(f"/api/alerts/{org}/{cve}{suffix}")
            get(f"/api/replay/{org}/{cve}")
            return f"{org}:{cve}"
        check("alert sheet: detail, related, workflow, CERT-In report, STIX, replay", alert_sheet)

        def graph():
            from urllib.parse import quote
            g = get("/api/graph")
            ids = {n["id"] for n in g["nodes"]}
            assert g["nodes"] and all(e["from"] in ids and e["to"] in ids for e in g["edges"]), "edge without a node"
            kinds = {k["id"] for k in g["kinds"]}
            assert {"org", "product", "cve", "technique", "actor"} <= kinds, f"kinds: {sorted(kinds)}"
            oid = get("/api/orgs")[0]["id"]
            focused = get(f"/api/graph?focus={oid}")
            assert focused["focus"]["id"] == oid and all(n["facts"].get("org_id") == oid for n in focused["nodes"] if n["kind"] == "org")
            cve_node = next(n["id"] for n in g["nodes"] if n["kind"] == "cve")
            card = get(f"/api/graph/node?id={quote(cve_node)}")
            assert card["neighbours"] and card["events"], "card without neighbours or evidence"
            actor = next(n for n in g["nodes"] if n["kind"] == "actor")
            assert "not attribution" in actor["sub"], actor["sub"]
            assert c.get("/api/graph?focus=NOPE-99").status_code == 404
            lists = get("/api/risklists")
            assert {x["id"] for x in lists["lists"]} == {"cves", "ips", "domains", "products"}
            ips = get("/api/risklists/ips")["rows"]
            assert ips and ips[0]["score"] >= ips[-1]["score"] and all(r["provenance"] for r in ips)
            csv_text = c.get("/api/risklists/cves?format=csv")
            assert csv_text.status_code == 200 and csv_text.text.startswith("cve,score,tier,kev")
            stix = get("/api/graph/stix")
            sids = {o["id"] for o in stix["objects"]}
            assert stix["type"] == "bundle" and all(o["source_ref"] in sids and o["target_ref"] in sids
                                                    for o in stix["objects"] if o["type"] == "relationship")
            assert any(o["type"] == "intrusion-set" and "not attribute" in o["description"] for o in stix["objects"])
            return (f"{g['summary']['nodes']} nodes, {g['summary']['edges']} edges ({g['summary']['real_edges']} REAL); "
                    f"{oid}: {focused['summary']['nodes']} nodes; card {card['node']['label']}: {len(card['events'])} events; "
                    f"{len(ips)} addresses; STIX {len(stix['objects'])} objects")
        check("intelligence graph: national, one organisation in focus, an entity card, risk lists, STIX", graph)

        # ---------------------------------------------------------------- watchlists, indicators, replay, TAXII, OSINT
        def _engine_for_drills():
            """The copy runs with ODYSSEY_LIVE=0 (no engine thread): the first flow that needs the live engine builds one
            and drives its ticks by hand, as the drills flow below does. When an engine is already running (ODYSSEY_LIVE=1)
            the ticks come on their own and we only wait. Returns (engine, advance)."""
            from backend.app import live
            if live.ENGINE is not None and live.ENGINE.status()["running"]:
                return live.ENGINE, lambda: time.sleep(3)
            if live.ENGINE is None:
                live.ENGINE = live.Live(main.db)
                live.ENGINE.next_feed = float("inf")
            return live.ENGINE, live.ENGINE.tick

        def watchlists():
            eng, advance = _engine_for_drills()
            w = post("/api/watches", {"target": "product:fortios", "owner": "duty-officer", "note": "FortiGate: scanning expected"})
            assert w["target"] == "product:fortios" and w["status"] == "active" and w["rule"]["kind"] == "any", w
            wid = w["id"]
            assert c.post("/api/watches", json={"target": "product:nope"}).status_code == 404, "an entity not in the graph must be 404"
            assert c.post("/api/watches", json={"target": "product:fortios", "rule": {"kind": "weird"}}).status_code == 400, "a bad rule must be 400"
            listed = get("/api/watches")
            assert any(x["id"] == wid for x in listed["watches"]) and "any" in listed["rules"] and listed["default_rule"]["kind"] == "any", "watch not listed"
            assert not [f for f in post("/api/watches/evaluate")["fired"] if f["watch_id"] == wid], "fired before anything changed"
            d = post("/api/live/drill/scan")
            deadline, fired = time.time() + 90, []
            while time.time() < deadline and not fired:
                advance()
                fired = [e for e in get("/api/watches")["events"] if e["target"] == "product:fortios" and e["watch_id"] == wid]
                if not fired:
                    fired = [f for f in post("/api/watches/evaluate")["fired"] if f["watch_id"] == wid]
            assert fired, f"fortios watch did not fire within 90 s of {d['id']} (drill {(eng.drill or {}).get('status')})"
            reason = fired[0].get("reason") or "; ".join(fired[0].get("reasons", []))
            assert any(e["kind"] == "watch.fired" for e in get("/api/events/recent?limit=80")), "watch.fired missing from the ledger"
            row = next(x for x in get("/api/watches")["watches"] if x["id"] == wid)
            assert row["fired"] >= 1 and row["recent"] and row["last_fired"], row
            assert post(f"/api/watches/{wid}/pause")["status"] == "paused"
            assert next(x for x in get("/api/watches")["watches"] if x["id"] == wid)["status"] == "paused"
            assert post(f"/api/watches/{wid}/resume")["status"] == "active"
            assert post(f"/api/watches/{wid}/delete")["status"] == "deleted"
            assert not any(x["id"] == wid for x in get("/api/watches")["watches"]), "deleted watch still listed"
            assert c.post(f"/api/watches/{wid}/pause").status_code == 404, "a deleted watch must be 404"
            return f"fired on '{reason[:70]}'; paused, resumed, deleted; unknown entity 404, bad rule 400"
        check("watchlists: watch, rule fires on a drill, pause and delete", watchlists)

        def indicators():
            import json as _json
            from backend.app import live
            from backend.app.engine.intel import lookalikes
            conn = sqlite3.connect(main.DB_PATH)
            asset_ip = conn.execute("SELECT ip FROM assets WHERE org_id = 'PWR-01' AND ip IS NOT NULL LIMIT 1").fetchone()[0]
            conn.close()
            variant = sorted(lookalikes("vgwc.example"))[0]
            c2, cve_id = "50.16.16.211", "CVE-2026-104935"
            sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ext = None  # a destination from the live firewall flows, when an engine is up
            if live.ENGINE is not None:
                with live.ENGINE.lock:
                    ext = next((f["dst"] for f in live.ENGINE.flows if f["dst"].startswith("198.18.")), None)
            text = ("# pasted from a partner CSIRT advisory (TLP:AMBER)\nioc,type,comment\n"
                    f"50[.]16[.]16[.]211,ip,QakBot C2\n{asset_ip},ip,our own host?\n"
                    + (f"{ext},ip,seen in partner telemetry\n" if ext else "")
                    + f"8.8.8.8,ip,benign resolver\nlogin-{variant}.com,domain,phishing kit\n"
                    f"hxxps://update-{variant}.com/kyc/verify,url,phishing page\n{cve_id},cve,Ivanti exploited\n{sha},sha256,sample\n")
            out = post("/api/iocs/import", {"text": text, "source": "partner CSIRT", "tlp": "AMBER"})
            rows = {x["value"]: x for x in out["indicators"]}
            assert out["found"] >= 7 and out["tlp"] == "AMBER" and len(rows) == out["found"], (out["found"], out["by_type"])
            assert rows[c2]["defanged"] == "50[.]16[.]16[.]211" and rows[c2]["type"] == "ipv4-addr", rows[c2]
            assert rows[c2]["matched"] and any(m["where"] == "C2 sighting" for m in rows[c2]["matches"]), rows[c2]["matches"]
            assert any(e["source"].startswith("abuse.ch") for e in rows[c2]["enrich"]), rows[c2]["enrich"]
            assert rows[asset_ip]["matched"] and rows[asset_ip]["severity"] == "Critical" \
                and any(m["where"] == "constituency asset" for m in rows[asset_ip]["matches"]), rows[asset_ip]["matches"]
            if ext:
                assert rows[ext]["matched"] and any(m["where"] == "firewall flows" for m in rows[ext]["matches"]), rows[ext]["matches"]
            assert not rows["8.8.8.8"]["matched"], "a benign resolver must not match"
            look = rows[f"login-{variant}.com"]
            assert look["matched"] and any(m["where"] == "look-alike" and m["provenance"] == "REAL" for m in look["matches"]), look["matches"]
            assert rows[cve_id]["matched"] and rows[cve_id]["severity"] == "Critical" \
                and any(m["where"] == "exposure record" for m in rows[cve_id]["matches"]), rows[cve_id]["matches"]
            assert not rows[sha]["matched"] and rows[sha]["type"] == "file:sha256", rows[sha]
            assert all(m["provenance"] for r in out["indicators"] for m in r["matches"]), "a match without provenance"
            assert post("/api/iocs/import", {"text": text, "source": "partner CSIRT"})["new"] == 0, "a re-import must add nothing new"
            assert c.post("/api/iocs/import", json={"text": "   "}).status_code == 400, "an empty paste must be 400"
            lst = get("/api/iocs")
            assert lst["total"] >= out["found"] and lst["matched"] >= 5 and lst["imports"] and lst["imports"][0]["source"] == "partner CSIRT", \
                (lst["total"], lst["matched"], len(lst["imports"]))
            only = get("/api/iocs?matched_only=true")
            assert only["indicators"] and all(r["matched"] for r in only["indicators"]), "matched_only returned an unmatched row"
            csv_r = c.get("/api/iocs/export?format=csv")
            assert csv_r.status_code == 200 and csv_r.text.startswith("value,defanged,type"), csv_r.text[:80]
            assert "50[.]16[.]16[.]211" in csv_r.text, "export must carry the defanged form"
            stix = get("/api/iocs/export?format=stix")
            n_ind = sum(1 for o in stix["objects"] if o["type"] == "indicator")
            assert stix["type"] == "bundle" and n_ind >= 1, (stix["type"], n_ind)
            kinds = {e["kind"] for e in get("/api/events/recent?limit=80")}
            assert {"ioc.import", "ioc.match"} <= kinds, sorted(kinds)[:12]
            bundle = {"type": "bundle", "id": "bundle--e2e", "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.77']"},
                {"type": "indicator", "pattern": "[domain-name:value = 'evil-vgwc.example']"},
                {"type": "vulnerability", "name": "CVE-2024-3400", "external_references": [{"source_name": "cve", "external_id": "CVE-2024-3400"}]}]}
            r3 = post("/api/iocs/import", {"text": _json.dumps(bundle), "source": "STIX feed"})
            assert r3["format"] == "stix" and r3["found"] == 3, (r3["format"], r3["found"], r3["by_type"])
            return (f"{out['found']} extracted ({out['format']}), {out['matched']} matched: C2 sighting, own asset, "
                    f"{'flow destination, ' if ext else ''}look-alike, exposed CVE; benign and hash kept unmatched; "
                    f"CSV + STIX ({n_ind} indicators) out; STIX bundle in: {r3['found']}")
        check("indicators: paste, extract, match telemetry and exposure, export, STIX in", indicators)

        def replay():
            from urllib.parse import quote
            steps = get("/api/graph/replay")["steps"]
            assert len(steps) >= 5 and steps[-1]["id"] == "now" and steps[-1]["at"] is None, [s["id"] for s in steps]
            now_g = get("/api/graph")
            then = get(f"/api/graph?as_of={quote(steps[1]['at'])}")
            assert then.get("as_of") and len(then["nodes"]) <= len(now_g["nodes"]), (then.get("as_of"), len(then["nodes"]), len(now_g["nodes"]))
            ids = {n["id"] for n in then["nodes"]}
            assert then["nodes"] and all(e["from"] in ids and e["to"] in ids for e in then["edges"]), "replayed edge without a node"
            assert "as_of" not in now_g or not now_g["as_of"], "the live graph must not claim an as_of"
            assert c.get("/api/graph?as_of=yesterday").status_code == 400, "a bad as_of must be 400"
            return (f"{len(steps)} instants; {steps[1]['label']}: {len(then['nodes'])} nodes / {len(then['edges'])} edges "
                    f"vs {len(now_g['nodes'])} / {len(now_g['edges'])} now; bad as_of refused (400)")
        check("graph replay: the record as it stood", replay)

        def taxii():
            r = c.get("/taxii2/")
            assert r.status_code == 200 and r.headers["content-type"].startswith("application/taxii+json"), (r.status_code, r.headers.get("content-type"))
            assert r.json()["api_roots"] == ["/taxii2/odyssey/"], r.json()
            assert c.get("/taxii2/odyssey/").json()["versions"] == ["application/taxii+json;version=2.1"]
            cols = c.get("/taxii2/odyssey/collections/").json()["collections"]
            assert [x["alias"] for x in cols] == ["graph", "indicators", "vulnerabilities"] and all(x["can_read"] and not x["can_write"] for x in cols), cols
            sizes = {}
            for col in cols:
                r = c.get(f"/taxii2/odyssey/collections/{col['id']}/objects/", params={"limit": 5})
                env = r.json()
                assert r.status_code == 200 and env["objects"] and len(env["objects"]) <= 5, (col["alias"], r.status_code, len(env.get("objects", [])))
                assert (env.get("next") == "5") == bool(env["more"]), (col["alias"], env.get("next"), env["more"])
                assert "X-TAXII-Date-Added-First" in r.headers and "X-TAXII-Date-Added-Last" in r.headers, dict(r.headers)
                man = c.get(f"/taxii2/odyssey/collections/{col['alias']}/manifest/", params={"limit": 3}).json()
                assert man["objects"] and all({"id", "date_added", "version", "media_type"} <= set(o) for o in man["objects"]), man["objects"][:1]
                sizes[col["alias"]] = len(env["objects"])
            first = c.get("/taxii2/odyssey/collections/graph/objects/", params={"limit": 5}).json()
            page2 = c.get("/taxii2/odyssey/collections/graph/objects/", params={"limit": 5, "next": "5"}).json()
            assert first["more"] and page2["objects"], "the graph collection must page"
            assert {o["id"] for o in page2["objects"]}.isdisjoint({o["id"] for o in first["objects"]}), "paging repeated objects"
            only = c.get("/taxii2/odyssey/collections/graph/objects/", params={"match[type]": "intrusion-set"}).json()
            assert only["objects"] and all(o["type"] == "intrusion-set" for o in only["objects"]), len(only["objects"])
            oid = only["objects"][0]["id"]
            assert c.get(f"/taxii2/odyssey/collections/graph/objects/{oid}/").json()["objects"][0]["id"] == oid
            assert c.get(f"/taxii2/odyssey/collections/graph/objects/{oid}/versions/").json()["versions"]
            byid = c.get("/taxii2/odyssey/collections/graph/objects/", params={"match[id]": oid}).json()["objects"]
            assert [o["id"] for o in byid] == [oid], byid
            assert c.get("/taxii2/odyssey/collections/graph/objects/", params={"added_after": "2999-01-01T00:00:00Z"}).json()["objects"] == []
            assert c.get("/taxii2/odyssey/collections/graph/objects/", params={"limit": "many"}).status_code == 400
            assert c.get("/taxii2/odyssey/collections/nope/").status_code == 404
            assert c.get(f"/taxii2/odyssey/collections/graph/objects/{oid}x/").status_code == 404
            ind = c.get("/taxii2/odyssey/collections/indicators/objects/", params={"limit": 500}).json()["objects"]
            assert any("imported" in o.get("labels", []) for o in ind), "imported indicators missing from the TAXII collection"
            prev = os.environ.get("ODYSSEY_TAXII_TOKEN")
            os.environ["ODYSSEY_TAXII_TOKEN"] = "e2e-secret"
            try:
                assert c.get("/taxii2/").status_code == 401, "a set token must be enforced"
                assert c.get("/taxii2/", headers={"Authorization": "Bearer e2e-secret"}).status_code == 200
            finally:
                if prev is None:
                    os.environ.pop("ODYSSEY_TAXII_TOKEN", None)
                else:
                    os.environ["ODYSSEY_TAXII_TOKEN"] = prev
            return (f"3 collections; first pages {sizes}; paging and match[type]/match[id]/added_after filter; manifest, one object, "
                    f"versions; {len(ind)} indicator objects; token enforced (401)")
        check("TAXII 2.1: discovery, collections, paging, filters, manifest", taxii)

        def brand():
            s = get("/api/brand")
            assert s["provenance"] == "REAL" and {"terms", "totals", "sources", "how"} <= set(s), sorted(s)
            t0 = time.perf_counter()
            r = c.post("/api/brand/scan", json={"term": "irctc"})
            took = time.perf_counter() - t0
            assert r.status_code == 200, f"scan -> {r.status_code} {r.text[:160]}"
            assert took < 60, f"scan took {took:.0f}s; sources must time out, not hang"
            out = r.json()
            assert out["terms"] == ["irctc"] and out["provenance"] == "REAL" and out["sources"], out
            assert all(v["status"] in ("fresh", "offline") and "ms" in v for v in out["sources"].values()), out["sources"]
            assert out["online"] + out["offline"] == len(out["sources"]), (out["online"], out["offline"])
            assert all(h["provenance"] == "REAL" and 0 <= h["score"] <= 100 and h["kind"] for h in out["top"]), out["top"][:1]
            hits = get("/api/brand/hits?term=irctc")
            assert hits["term"] == "irctc" and isinstance(hits["rows"], list) and len(hits["rows"]) >= min(out["hits"], 1), len(hits["rows"])
            after = get("/api/brand")
            term = next((t for t in after["terms"] if t["term"] == "irctc"), None)
            assert term is not None and term["last_scan"] and after["totals"]["scans"] >= s["totals"]["scans"] + 1, "the scan is not in the summary"
            assert c.post("/api/brand/scan", json={}).status_code == 400, "neither term nor org_id must be 400"
            offline = sorted(n for n, v in out["sources"].items() if v["status"] != "fresh")
            return (f"{out['online']}/{len(out['sources'])} sources answered in {out['seconds']}s"
                    + (f" (offline: {', '.join(offline)})" if offline else "")
                    + f"; {out['hits']} hits ({out['new_hits']} new, {out['ledger_events']} audited); {len(hits['rows'])} rows for irctc")
        check("brand and social watch: summary, scan with sources possibly offline", brand)

        def surface():
            r = c.post("/api/surface/scan", json={"url": "http://example.com", "consent": True})
            assert r.status_code == 400 and r.json().get("detail"), f"a public target must be refused: {r.status_code} {r.text[:120]}"
            refused = r.json()["detail"]
            assert c.post("/api/surface/scan", json={"url": "http://127.0.0.1:8080"}).status_code == 400, "no consent must be refused"
            can = get("/api/surface/can-scan?url=http://127.0.0.1:8080")
            assert isinstance(can["allowed"], bool) and can["allowed"] and can["reason"], can
            assert get("/api/surface/can-scan?url=http://example.com")["allowed"] is False
            import httpx
            try:
                httpx.get("http://127.0.0.1:8080/", timeout=2)
            except Exception:  # noqa: BLE001 - the demo portal is a separate process and may not be up
                return f"public target refused (400: {refused[:60]}); no consent refused; loopback allowed; portal down, skipped"
            s = post("/api/surface/scan", {"url": "http://127.0.0.1:8080", "consent": True, "org_id": "PWR-01"})
            assert s["status"] == "done" and s["grade"] in list("ABCDEF") and s["findings"] and s["requests"] <= 40, \
                (s["status"], s["grade"], s["n_findings"], s["requests"])
            assert s["provenance"] == "REAL" and s["org_id"] == "PWR-01" and 0 <= s["score"] <= 100, (s["provenance"], s["org_id"], s["score"])
            assert all(f["cwe"] and f["fix"] and f["evidence"] and f["severity"] for f in s["findings"]), "a finding without CWE, fix or evidence"
            latest = get("/api/surface?org_id=PWR-01")["scans"]
            assert latest and latest[0]["status"] == "done" and latest[0]["findings_list"], latest[:1]
            one = get(f"/api/surface/{s['scan_id']}")
            assert one["id"] == s["scan_id"] and len(one["findings_list"]) == s["n_findings"], (one["id"], len(one["findings_list"]))
            assert c.get("/api/surface/999999").status_code == 404
            kinds = {e["kind"] for e in get("/api/events/recent?limit=80")}
            assert "surface.scan" in kinds, sorted(kinds)[:12]
            worst = s["findings"][0]
            return (f"public target refused (400); no consent refused; loopback allowed; portal scored {s['score']} grade {s['grade']}: "
                    f"{s['n_findings']} findings ({worst['severity']} {worst['cwe']} first) in {s['requests']} requests, {s['seconds']}s")
        check("attack surface: refuse a public target, scan the portal with consent", surface)

        def sachet_flow():
            import datetime as _dt
            import uuid
            from backend.app.engine import graph as _graph
            # the public feed, read-only (live=false: the snapshot, so the check does not depend on NDMA being reachable)
            s = get("/api/sachet?live=false")
            f = s["feed"]
            assert f["count"] > 0 and f["provenance"] == "REAL" and f["status"] in ("fresh", "snapshot", "offline"), \
                (f.get("count"), f.get("status"), f.get("detail"))
            matched = s["matched_alerts"]
            assert matched and all(m["orgs"] for m in matched), f"{f['matched']} of {f['count']} alerts matched to operators"
            assert all(o["org_id"] and o["state"] and o["basis"] and 0 < o["confidence"] <= 1 for m in matched for o in m["orgs"]), matched[0]["orgs"]
            assert all(m["states"] and m["states"][0]["basis"] for m in matched), "a matched alert without the basis of its state"
            assert s["endpoint"] == "/api/sensor/cap" and {"xxe", "untrusted_sender", "replay", "stale"} <= set(s["ingest"]["refused"]), s["ingest"]
            before = {"accepted": s["ingest"]["accepted"], **s["ingest"]["refused"]}

            # the inbound guard: the same POST an upstream makes. Status Exercise and the red-team header on every message,
            # so the ledger carries them as SIM and nothing here can pass for a real agency's alert.
            now = _dt.datetime.now(_dt.timezone.utc)
            sent = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            expires = (now + _dt.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            ident = f"E2E-{now:%Y%m%d%H%M%S}-{uuid.uuid4().hex[:8]}"

            def cap(sender: str, identifier: str) -> bytes:
                # the shape of data/raw/sachet_cap_sample.xml (a real IMD Chennai message), as an exercise
                return ('<?xml version="1.0" encoding="UTF-8"?>\n'
                        '<cap:alert xmlns:cap="urn:oasis:names:tc:emergency:cap:1.2">'
                        f'<cap:identifier>{identifier}</cap:identifier><cap:sender>{sender}</cap:sender><cap:sent>{sent}</cap:sent>'
                        '<cap:status>Exercise</cap:status><cap:msgType>Alert</cap:msgType><cap:scope>Public</cap:scope>'
                        '<cap:info><cap:language>en-IN</cap:language><cap:category>Met</cap:category><cap:event>Moderate Rain</cap:event>'
                        '<cap:urgency>Expected</cap:urgency><cap:severity>Moderate</cap:severity><cap:certainty>Likely</cap:certainty>'
                        f'<cap:expires>{expires}</cap:expires>'
                        '<cap:headline>Light to Moderate Rain with Thunderstorm is very likely over Coimbatore, Erode, The Nilgiris in next 3 hours.</cap:headline>'
                        '<cap:instruction>Please follow SDMA guidelines.</cap:instruction>'
                        '<cap:area><cap:areaDesc>Coimbatore, Erode, The Nilgiris districts of Tamil Nadu</cap:areaDesc></cap:area>'
                        '</cap:info></cap:alert>').encode("utf-8")

            def send(body: bytes) -> dict:
                r = c.post("/api/sensor/cap", content=body, headers={"content-type": "application/xml", "x-odyssey-redteam": "e2e"})
                assert r.status_code == 200, f"POST /api/sensor/cap -> {r.status_code} {r.text[:160]}"
                return r.json()

            forged = send(cap("attacker@evil.example", f"{ident}-forged"))
            assert not forged["accepted"] and forged["reason"] == "untrusted_sender" and forged["redteam"] == "e2e", forged
            ok = send(cap("IMD-Chennai", ident))
            assert ok["accepted"] and ok["reason"] is None and ok["identifier"] == ident, ok
            assert ok["states"] and ok["states"][0]["state"] == "Tamil Nadu" and ok["states"][0]["basis"], ok["states"]
            again = send(cap("IMD-Chennai", ident))
            assert not again["accepted"] and again["reason"] == "replay", again
            xxe = send(b'<?xml version="1.0"?><!DOCTYPE alert [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                       b'<cap:alert xmlns:cap="urn:oasis:names:tc:emergency:cap:1.2"><cap:identifier>&xxe;</cap:identifier>'
                       b'<cap:sender>IMD-Chennai</cap:sender><cap:sent>2026-01-01T00:00:00Z</cap:sent></cap:alert>')
            assert not xxe["accepted"] and xxe["reason"] == "xxe" and not xxe.get("identifier"), xxe  # refused before parsing: nothing was read

            after = get("/api/sachet?live=false")
            counts = {"accepted": after["ingest"]["accepted"], **after["ingest"]["refused"]}
            grew = {k: counts[k] - before[k] for k in ("accepted", "untrusted_sender", "replay", "xxe")}
            assert grew == {"accepted": 1, "untrusted_sender": 1, "replay": 1, "xxe": 1}, grew
            latest = after["decisions"][:4]
            assert [d["reason"] for d in latest] == ["xxe", "replay", None, "untrusted_sender"] and all(d["redteam"] == "e2e" for d in latest), \
                [(d["reason"], d["redteam"]) for d in latest]
            assert any(a["identifier"] == ident and a["states"] for a in after["inbound"]), "the accepted alert is not among the inbound rows"
            kinds = {e["kind"] for e in get("/api/events/recent?limit=80")}
            assert {"cap.ingest.accepted", "cap.ingest.refused"} <= kinds, sorted(kinds)[:12]

            # our own warning as SACHET-compatible CAP: Exercise unless a desk routes it otherwise, and it says what it is
            r = c.get(f"/api/warnings/{org}/{cve}/cap")
            assert r.status_code == 200, f"GET /api/warnings/{org}/{cve}/cap -> {r.status_code} {r.text[:160]}"
            assert r.headers["content-type"].startswith("application/cap+xml"), r.headers.get("content-type")
            assert "<status>Exercise</status>" in r.text and "urn:oasis:names:tc:emergency:cap:1.2" in r.text, r.text[:300]
            langs = r.headers.get("x-odyssey-languages", "")
            assert langs.startswith("en-IN") and "attachment" in r.headers.get("content-disposition", ""), dict(r.headers)
            assert "not an NDMA/SACHET message" in r.text and "<!DOCTYPE" not in r.text, "the export must say what it is and carry no DTD"
            rt = send(r.content)  # the export is itself CAP the guard admits (our own sender is on the allow-list)
            assert rt["accepted"] or rt["reason"] == "replay", rt

            # the graph: matched SACHET alerts as REAL disaster signals on their operators; the accepted inbound CAP as a signal too
            def pick(g):
                return ([n for n in g["nodes"] if n["kind"] == "signal" and n["facts"].get("signal") == "disaster"],
                        [n for n in g["nodes"] if n["facts"].get("signal") == "cap_inbound" and n["facts"].get("identifier") == ident])
            g = get("/api/graph")
            disasters, inbound = pick(g)
            if not disasters or not inbound:
                time.sleep(_graph.CACHE_S + 0.5)  # the graph is cached for a few seconds; the inbound alert postdates any cached build
                g = get("/api/graph")
                disasters, inbound = pick(g)
            assert disasters, "no SACHET disaster signal in the graph"
            assert all(d["provenance"] == "REAL" and d["facts"]["operators"] and d["facts"]["basis"] for d in disasters), \
                [(d["id"], d["provenance"]) for d in disasters]
            dids = {d["id"] for d in disasters}
            orgs_linked = {e["to"] for e in g["edges"] if e["from"] in dids and e["to"].startswith("org:")}
            assert orgs_linked, "a disaster signal without an operator"
            assert inbound and inbound[0]["provenance"] == "SIM", inbound  # an exercise, so never REAL
            linked = {e["to"] for e in g["edges"] if e["from"] == inbound[0]["id"]}
            assert linked >= {f"org:{o['org_id']}" for o in ok["orgs"]}, (sorted(linked), ok["orgs"])
            return (f"feed {f['status']}: {f['count']} alerts, {f['matched']} on operators' states (most: {next(iter(f['by_state']), '?')}); "
                    f"guard: forged sender refused, IMD-Chennai accepted for {', '.join(x['state'] for x in ok['states'])}, replay and XXE refused, "
                    f"all audited; CAP export {org}:{cve} ({langs}) is Exercise{' and round-trips through the guard' if rt['accepted'] else ''}; "
                    f"graph: {len(disasters)} disaster signal(s) on {len(orgs_linked)} operator(s), inbound CAP drawn as {inbound[0]['provenance']}")
        check("SACHET: feed matched to operators, CAP guard ladder, CAP export", sachet_flow)

        # ---------------------------------------------------------------- human in the loop
        def approve():
            pending = get("/api/approvals")
            assert pending, "nothing pending"
            before, n = ledger_size(), len(pending)
            out = post(f"/api/approvals/{pending[0]['id']}/approve")
            assert len(get("/api/approvals")) == n - 1, "proposal still pending"
            assert any(a["id"] == pending[0]["id"] for a in get("/api/approvals?status=approved")), "not recorded"
            grew = ledger_size() - before
            assert grew >= 2, f"ledger grew by {grew}: expected the decision plus the actions it released"
            return f"'{pending[0]['title'][:60]}' approved; {grew} audit events ({out.get('executed', '?')} actions)"
        check("approve a proposal: actions released and audited", approve)

        def reject():
            pending = get("/api/approvals")
            assert pending, "nothing pending"
            post(f"/api/approvals/{pending[0]['id']}/reject?note=not%20relevant%20to%20this%20org")
            row = next(a for a in get("/api/approvals?status=rejected") if a["id"] == pending[0]["id"])
            assert row["note"], "rejection reason lost"
            return f"rejected with reason '{row['note']}'"
        check("reject a proposal: reason kept for calibration", reject)

        # ---------------------------------------------------------------- a warning, issued to closed
        def lifecycle():
            seen = []
            for _ in range(6):
                state = get(f"/api/alerts/{org}/{cve}/workflow")
                nxt = state.get("next_action")
                if not nxt:
                    break
                post(f"/api/alerts/{org}/{cve}/workflow/{nxt}")
                seen.append(nxt)
            final = get(f"/api/alerts/{org}/{cve}/workflow")
            assert final["state"] == "closed", f"ended in {final['state']} after {seen}"
            return " → ".join(seen)
        check("warning lifecycle: acknowledge to closed", lifecycle)

        # ---------------------------------------------------------------- a SOC case, new to closed
        def case_flow():
            case = next(x for x in get("/api/cases?status=open") if x["kind"] == "vuln")
            cid = case["id"]
            post(f"/api/cases/{cid}/assign?owner=analyst@ncew")
            post(f"/api/cases/{cid}/advance")
            for i in range(case["progress"]["total"]):
                post(f"/api/cases/{cid}/step?index={i}&done=true")
            post(f"/api/cases/{cid}/note", {"text": "Patched in tonight's window; verified the fixed build."})
            done = post(f"/api/cases/{cid}/advance")
            assert done["status"] == "resolved", done["status"]
            m = get("/api/soc/metrics")
            assert m["resolved"] >= 1 and m["mtta_h"] is not None, "metrics not measured"
            return f"{cid} closed; MTTA {m['mtta_h']} h, SLA met {m['sla_pct']}%"
        check("SOC case: assign, work the playbook, note, close", case_flow)

        # ---------------------------------------------------------------- AI paths
        def advisory():
            if no_ai:
                raise Skip("--no-ai")
            text = ("Fortinet has observed active exploitation of a heap-based buffer overflow in FortiOS SSL-VPN "
                    "(CVE-2026-24858) affecting FortiOS 7.2.0 through 7.2.8 and 7.4.0 through 7.4.4. Upgrade to 7.2.9 "
                    "or 7.4.5. Attackers connected from 185.220.101.4 and used the domain fortiupdate-check.com.")
            out = post("/api/advisories/analyze", {"text": text, "title": "E2E pasted advisory"})
            exposed = out.get("exposed") or []
            assert exposed, "no exposed assets matched"
            ips = out["iocs"]["ips"]
            assert "185[.]220[.]101[.]4" in ips, f"indicator missing or not defanged: {ips}"
            assert not any("7.2" in i for i in ips), "a version number was taken for an IP"
            assert "fortiupdate-check[.]com" in out["iocs"]["domains"], f"attacker domain missed: {out['iocs']['domains']}"
            return f"{len(exposed)} exposed matches · IOCs {ips + out['iocs']['domains']} · guard {out['guard']['verdict']}"
        check("advisory analysis: matched to the inventory", advisory)

        def overlays():
            d = get(f"/api/alerts/{org}/{cve}")
            clocks = {c["who"] for c in d["assets"][0]["obligations"]}
            assert "CERT-In" in clocks or d["assets"][0]["tier"] != "Compromise", f"clocks: {clocks}"
            hostile = next(a for a in get("/api/advisories") if a["id"] == "CIVN-SIM-2026-0431")
            assert hostile["analysis"]["guard"]["verdict"] == "blocked", hostile["analysis"]["guard"]
            reached = sum(len(s["dependents"]) for s in d.get("supply_chain", []))
            return (f"{org}:{cve} clocks {sorted(clocks)}; supplier fan-out reaches {reached} organisation(s); "
                    f"hostile advisory blocked by the guard")
        check("compliance clocks, supplier fan-out, prompt-injection advisory", overlays)

        def threatmap():
            m = get("/api/orgs/PWR-01/threatmap")
            ids = {n["id"] for n in m["nodes"]} | {t["id"] for t in m["threats"]} | {c["id"] for c in m["c2"]}                 | {x["id"] for x in m["suppliers"]} | {"org", "crown"}
            assert m["nodes"] and all(e["from"] in ids and e["to"] in ids for e in m["edges"]), "dangling edge"
            assert all(e["provenance"] in ("REAL", "SIM") for e in m["edges"]), "edge without provenance"
            kinds = {e["kind"] for e in m["edges"]}
            assert {"attack", "exploited", "beacon"} <= kinds, kinds
            return (f"{m['summary']['shown']}/{m['summary']['assets']} assets, {len(m['threats'])} threats, {len(m['edges'])} edges "
                    f"({', '.join(sorted(kinds))}); worst {m['summary']['worst']}")
        check("organisation threat map: consistent, provenance on every edge", threatmap)

        def live_drills():
            from backend.app import live
            live.ENGINE = eng = live.Live(main.db)
            eng.next_feed = float("inf")
            pending, cases = len(get("/api/approvals")), get("/api/soc/metrics")["open"]
            compromise_before = get("/api/feed")["counts"]["compromise"]
            seen = []
            for scenario in ("scan", "beacon", "chain"):
                d = post(f"/api/live/drill/{scenario}")
                for _ in range(25):
                    eng.tick()
                    st = get("/api/live")
                    if st["drill"]["status"] != "running":
                        break
                assert st["drill"]["status"] == "passed", f"{d['id']} {st['drill']['status']}: {st['drill']['detected']}"
                seen.append(f"{scenario}: {'+'.join(st['drill']['detected'])}")
            # the PS use case, live: a CVE published an hour ago (NVD shape, no network needed) names a product we run
            fresh = {"id": "CVE-2026-999100", "published": "2026-11-01T02:10:00.000", "vulnStatus": "Awaiting Analysis",
                     "descriptions": [{"lang": "en", "value": "An authentication bypass in Fortinet FortiOS SSL-VPN allows "
                                                              "remote code execution. Exploitation in the wild has been observed."}],
                     "metrics": {"cvssMetricV31": [{"source": "cna", "type": "Secondary", "cvssData": {"version": "3.1",
                                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}]},
                     "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                         {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionEndExcluding": "7.4.9"}]}]}]}
            taken = eng.ingest([fresh], source="e2e")
            assert taken and taken[0]["exposed"] > 0, taken
            listed = [a for a in get("/api/alerts?limit=4000") if a["cve_id"] == "CVE-2026-999100"]
            assert listed, "ingested CVE missing from the warnings list"
            get("/api/alerts/" + listed[0]["org_id"] + "/CVE-2026-999100")  # its evidence sheet opens
            assert any(t["cve"] == "CVE-2026-999100" for t in get("/api/live")["intakes"]), "intake not on the Live page"
            seen.append(f"intake: {taken[0]['exposed']} exposed at {len(taken[0]['orgs'])} orgs, {taken[0]['worst']}, {taken[0]['action']}")
            ad = get("/api/adaptive")
            assert ad["feed"]["current_s"] == 300 and ad["feed"]["focus_why"], "engine did not focus after the drills"
            assert any(s["z"] != s["base"] for s in ad["surge"]), "no threshold learned from the record"
            seen.append(f"adaptive: feed every {ad['feed']['current_s'] // 60} min ({ad['feed']['focus_why']}), "
                        f"{sum(1 for s in ad['surge'] if s['z'] != s['base'])} surge thresholds tuned")
            grew = len(get("/api/approvals")) - pending
            opened = get("/api/soc/metrics")["open"] - cases
            assert grew >= 3 and opened == 2, f"{grew} new proposals, {opened} new cases"
            comp = get("/api/feed")["counts"]["compromise"]
            assert comp > compromise_before, "live evidence did not re-score any warning"
            return (f"{' · '.join(seen)}; {grew} proposals wait for a person, {opened} incident cases opened, "
                    f"suspected compromises {compromise_before} → {comp} (re-scored live)")
        check("live engine: three attack drills answered; a new CVE taken in live", live_drills)

        def http_shield():
            # the same calls an in-process agent makes: announce the app, then forward each request
            reg = post("/api/sensor/register", {"app": "e2e-portal", "name": "E2E Portal", "org_id": "PWR-01",
                                                "base_url": "http://127.0.0.1:8080", "mode": "enforce", "framework": "asgi"})
            assert reg["mode"] == "monitor" and reg["agent_mode"] == "enforce", reg  # the agent's mode is not the policy
            ok = post("/api/sensor/http", {"app": "e2e-portal", "method": "GET", "path": "/search", "query": "q=lamp",
                                           "status": 200, "source_ip": "198.51.100.23"})
            assert ok["decision"] == "allow" and not ok["findings"], ok
            cases_before = len(get("/api/cases?status=open"))
            hit = post("/api/sensor/http", {"app": "e2e-portal", "method": "GET", "path": "/search", "query": "q=' OR 1=1--",
                                            "status": 200, "source_ip": "203.0.113.66", "headers": {"x-odyssey-redteam": "e2e"}})
            assert hit["decision"] == "allow" and hit["worst"] in ("High", "Critical", "Compromise"), hit  # monitor: detect only
            assert len(get("/api/cases?status=open")) == cases_before + 1, "a likely-successful web attack must open a case"
            post("/api/shield/apps/e2e-portal/mode?mode=block")
            blk = post("/api/sensor/http", {"app": "e2e-portal", "method": "GET", "path": "/d",
                                            "query": "file=../../../../etc/passwd", "source_ip": "203.0.113.66"})
            assert blk["decision"] == "block" and blk["blocked"], blk
            st = get("/api/shield")
            app = next(a for a in st["apps"] if a["id"] == "e2e-portal")
            assert (app["mode"], app["requests"], app["attacks"], app["blocked"]) == ("block", 3, 2, 1), app
            assert "203.0.113.66" in get("/api/sensor/policy")["blocklist"], "blocked source missing from the agents' policy"
            r = c.post("/api/redteam/run", json={"target": "http://example.com"})
            assert r.status_code == 400, f"the runner must refuse a public target: {r.status_code} {r.text[:120]}"
            return (f"{hit['worst']} {hit['findings'][0]['cwe']} detected in monitor mode and a case opened; "
                    f"block mode dropped the next attack and listed the source; public target refused (400)")
        check("HTTP shield: announce, detect, open a case, block inline, refuse a public target", http_shield)

        def channels():
            # the alerts leave the laptop: a webhook receiver on loopback stands in for Slack / Discord / Teams / your app
            import json as _json
            import threading
            from http.server import BaseHTTPRequestHandler, HTTPServer
            got: list[dict] = []

            class H(BaseHTTPRequestHandler):
                def do_POST(self):
                    got.append(_json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}"))
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"{}")

                def log_message(self, *a):
                    pass
            srv = HTTPServer(("127.0.0.1", 0), H)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                from backend.app import notify
                cfg = tmp / "notify.json"
                cfg.write_text(_json.dumps({
                    "public_url": "http://127.0.0.1:5173",
                    "routing": {"min_severity": "High", "kinds": ["shield.detect.*", "auto.proposed", "auto.case_opened"], "dedupe_minutes": 10, "per_minute_cap": 20},
                    "channels": [{"name": "ops-console", "type": "webhook", "url": f"http://127.0.0.1:{srv.server_port}/hooks/odyssey", "enabled": True},
                                 {"name": "slack", "type": "slack", "url": "", "enabled": True}]}), encoding="utf-8")
                notify.ENGINE = eng = notify.Notifier(main.db, config_path=cfg, local_path=tmp / "none.json")
                st = get("/api/notify")
                assert st["stats"]["configured"] == 1 and not next(x for x in st["channels"] if x["name"] == "slack")["configured"], st["channels"]
                t = post("/api/notify/test/ops-console")
                assert t["ok"] and got and got[-1]["title"].startswith("Test alert"), (t, got[-1:])
                r = c.post("/api/notify/test/slack")
                assert r.status_code == 400, "an unconfigured channel must refuse a test, not pretend"
                post("/api/sensor/http", {"app": "e2e-portal", "method": "GET", "path": "/download", "query": "file=../../../../etc/passwd",
                                          "source_ip": "203.0.113.77", "status": 200, "headers": {"x-odyssey-redteam": "e2e-channels"}})
                n = eng.poll_once()
                titles = [g.get("title", "") for g in got]
                assert any("203.0.113.77" in x for x in titles), titles
                st = get("/api/notify")
                real = [d for d in st["recent"] if not d["test"]]
                assert real and real[0]["ok"] and "127.0.0.1" in real[0]["destination"], real[:1]
                post("/api/notify/channels/ops-console/enabled?on=false")
                assert not next(x for x in get("/api/notify")["channels"] if x["name"] == "ops-console")["enabled"]
                post("/api/notify/channels/ops-console/enabled?on=true")
                kinds = sorted({g["event"]["kind"] for g in got if "event" in g and g["event"].get("kind") != "notify.test"})
                return (f"test alert received; an attack on the protected app became {n} card(s) ({', '.join(kinds)}); "
                        f"unconfigured Slack refused (400); muted and unmuted; {st['stats']['sent']} deliveries audited")
            finally:
                srv.shutdown()
        check("channels: alerts reach a real webhook and are audited; an unconfigured channel refuses", channels)

        def ledger():
            v = get("/api/ledger/verify")
            assert v["intact"], f"chain broken at seq {v['first_bad_seq']}"
            return f"{v['events']} events, hash chain verified"
        check("audit trail still intact after every action", ledger)

    width = max(len(n) for _, n, _, _ in RESULTS)
    for ok, name, detail, secs in RESULTS:
        mark = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
        print(f"{mark}  {name.ljust(width)}  {secs:6.1f}s  {detail}")
    failed = sum(1 for ok, *_ in RESULTS if ok is False)
    print(f"\n{sum(1 for ok, *_ in RESULTS if ok)} passed, {failed} failed, "
          f"{sum(1 for ok, *_ in RESULTS if ok is None)} skipped · live databases untouched ({tmp})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main_())
