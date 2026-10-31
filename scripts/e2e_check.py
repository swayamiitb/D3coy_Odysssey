"""End-to-end check: every screen's data and every button's action, on a private copy of the live database.

Run:  .venv/Scripts/python scripts/e2e_check.py [--no-ai]

The live data/ews.db and data/cache.db are copied with SQLite's online backup (consistent even while the API is
writing), the API is pointed at the copies, and the script makes the same HTTP calls the interface makes:
  - loads every view (Now, SOC, Intel, Organisations, Proof) and an alert's detail sheet;
  - approves one proposal and rejects another (human in the loop), and checks that the notices went out;
  - works the top warning through its lifecycle, and a SOC case from new to closed;
  - analyses a pasted advisory (guard model and encoders; skipped with --no-ai);
  - re-verifies the hash-chained audit trail.
The live databases are never touched. Exit code 1 if any check fails.
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import os  # noqa: E402

os.environ.setdefault("ODYSSEY_LIVE", "0")  # the copy is driven by this script, not by a second live engine

from fastapi.testclient import TestClient  # noqa: E402

import backend.app.cache as cache  # noqa: E402
import backend.app.main as main  # noqa: E402

RESULTS: list[tuple[bool | None, str, str, float]] = []


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
                      "/api/riskplan", "/api/advisories"],
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
