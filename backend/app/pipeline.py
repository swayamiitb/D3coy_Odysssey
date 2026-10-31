"""Build the working state from the offline snapshot: candidates -> exposure -> assessment -> SQLite + ledger.

Run: .venv/Scripts/python -m backend.app.pipeline   (writes data/ews.db)
"""

from __future__ import annotations

import datetime as dt
import gzip
import json
import sqlite3
import time
from pathlib import Path

import networkx as nx

from .engine import detectors, forecast, sentinel
from .engine import replay as replay_mod
from .engine.exposure import reconcile
from .engine.ledger import Ledger
from .engine.products import mentions, same_product
from .engine.scoring import assess, config as scoring_config
from .ingest.cve_records import RAW, build_record, load_cve5, load_epss, load_kev, load_nvd
from .sim import telemetry

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "ews.db"
WORLD = ROOT / "data" / "sim" / "world.json"
RECENT_DAYS = 90
SNAPSHOT_DATE = dt.date(2026, 10, 31)

SCHEMA = """
CREATE TABLE orgs (id TEXT PRIMARY KEY, name TEXT, sector TEXT, state TEXT, domain TEXT, cii INTEGER);
CREATE TABLE assets (id TEXT PRIMARY KEY, org_id TEXT, hostname TEXT, ip TEXT, zone TEXT, role TEXT, label TEXT,
                     vendor TEXT, product TEXT, version TEXT, cpe TEXT, tier INTEGER, owner TEXT,
                     tier1_reachable INTEGER, product_key TEXT);
CREATE TABLE vulns (id TEXT PRIMARY KEY, published TEXT, description TEXT, kev TEXT, epss REAL, ssvc TEXT,
                    cvss_vector TEXT, cvss_source TEXT, nvd_status TEXT, record TEXT);
CREATE TABLE assessments (asset_id TEXT, cve_id TEXT, org_id TEXT, sector TEXT, status TEXT, R REAL, risk REAL,
                          tier TEXT, decision TEXT, deadline_hours INTEGER, detail TEXT,
                          PRIMARY KEY (asset_id, cve_id));
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX assessments_risk ON assessments(risk DESC);
"""


def tier1_reachability(world: dict) -> dict[str, int]:
    g = nx.DiGraph()
    g.add_edges_from((e["src"], e["dst"]) for e in world["edges"])
    tier1 = {a["id"] for a in world["assets"] if a["tier"] == 1}
    return {a["id"]: len(nx.descendants(g, a["id"]) & tier1) if a["id"] in g else 0 for a in world["assets"]}


def select_candidates(products: set[tuple[str, str]], kev: dict) -> tuple[set[str], dict]:
    """KEV entries for our products (any year) + recent CVEs that NVD maps to, or whose text names, our products."""
    ids = {cid for cid, k in kev.items()
           if any(same_product(v, p, k["vendorProject"], k["product"]) for v, p in products)}
    cutoff = (SNAPSHOT_DATE - dt.timedelta(days=RECENT_DAYS)).isoformat()
    month_counts: dict[str, int] = {}
    for name in ("nvdcve-2.0-2026.json.gz", "nvdcve-2.0-modified.json.gz"):
        with gzip.open(RAW / "nvd" / name, "rt", encoding="utf-8") as fh:
            for item in json.load(fh)["vulnerabilities"]:
                c = item["cve"]
                if c.get("vulnStatus") == "Rejected":
                    continue
                if name.startswith("nvdcve-2.0-2026"):
                    month_counts[c["published"][:7]] = month_counts.get(c["published"][:7], 0) + 1
                if c["published"][:10] < cutoff:
                    continue
                cpes = {tuple(m["criteria"].split(":")[3:5]) for cfg in c.get("configurations", [])
                        for n in cfg.get("nodes", []) for m in n.get("cpeMatch", []) if m.get("vulnerable")}
                desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
                hit = any(same_product(v, p, cv, cp) for v, p in products for cv, cp in cpes) or (
                    not cpes and any(mentions(v, p, desc) for v, p in products))
                if hit and not (("linux", "linux_kernel") in products and "linux kernel" in desc.lower()
                                and c["id"] not in kev):
                    ids.add(c["id"])
    return ids, month_counts


def main() -> None:
    started = time.time()
    world = json.loads(WORLD.read_text(encoding="utf-8"))
    orgs = {o["id"]: o for o in world["orgs"]}
    reach = tier1_reachability(world)
    products = {(a["vendor"], a["product"]) for a in world["assets"]}
    kev = load_kev()
    epss, epss_header = load_epss()

    ids, month_counts = select_candidates(products, kev)
    nvd = load_nvd(ids)
    print(f"{len(ids)} candidate CVEs ({sum(1 for i in ids if i in kev)} in KEV); NVD records for {len(nvd)}")
    # Day-0 exploitation forecast, only where it is out-of-sample (published after the model was frozen).
    model = forecast.load()
    fresh = [forecast.day0_fields(nvd[c]) for c in sorted(ids) if c in nvd and model
             and nvd[c]["published"][:10] > model["frozen"]]
    forecasts = dict(zip((f["id"] for f in fresh), forecast.predict(fresh)))
    print(f"forecast: {len(forecasts)} CVEs published after {model['frozen'] if model else '-'}, "
          f"{sum(f['flag'] for f in forecasts.values())} flagged likely-to-be-exploited")

    if DB_PATH.exists():
        DB_PATH.unlink()
    for suffix in ("-wal", "-shm"):
        Path(str(DB_PATH) + suffix).unlink(missing_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    ledger = Ledger(conn=db, autocommit=False)  # one connection; single commit at the end

    db.executemany("INSERT INTO orgs VALUES (?,?,?,?,?,?)",
                   [(o["id"], o["name"], o["sector"], o["state"], o["domain"], int(o["cii"])) for o in world["orgs"]])
    db.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   [(a["id"], a["org_id"], a["hostname"], a["ip"], a["zone"], a["role"], a["label"], a["vendor"],
                     a["product"], a["version"], a["cpe"], a["tier"], a["owner"], reach[a["id"]], a["product_key"])
                    for a in world["assets"]])

    by_product: dict[tuple[str, str], list[dict]] = {}
    for a in world["assets"]:
        by_product.setdefault((a["vendor"], a["product"]), []).append({**a, "tier1_reachable": reach[a["id"]]})

    # ---- SIM telemetry -> detectors -> ledger events + live signals
    rollups = telemetry.decoy_rollups()
    surges = detectors.detect_surges(rollups)
    exploits = detectors.detect_exploit_tags(telemetry.decoy_exploit_hits())
    beacon_asset = next(a for a in world["assets"] if a["id"] == telemetry.BEACON["asset_id"])
    beacons = detectors.detect_beacons(telemetry.firewall_logs(beacon_asset["ip"]))
    surge_runs: dict[str, list[dict]] = {}
    for s in surges:  # one ledger event per contiguous surge run (first day), with the peak z
        runs = surge_runs.setdefault(s["tag"], [])
        if runs and (dt.date.fromisoformat(s["date"]) - dt.date.fromisoformat(runs[-1]["last"])).days <= 1:
            runs[-1].update(last=s["date"], z_sessions=max(runs[-1]["z_sessions"], s["z_sessions"]),
                            sensors=max(runs[-1]["sensors"], s["sensors"]))
        else:
            runs.append({**s, "first": s["date"], "last": s["date"]})
    for tag, runs in surge_runs.items():
        for r in runs:
            ledger.append(ts=r["first"] + "T06:00:00Z", kind="decoy.surge", subject=f"product:{tag}",
                          source="DECOY_GRID", provenance="SIM",
                          payload={"tag": tag, "z_sessions": r["z_sessions"], "z_ips": r["z_ips"],
                                   "sensors": r["sensors"], "until": r["last"]})
    for e in exploits:
        ledger.append(ts=e["ts"], kind="decoy.exploit", subject=e["cve"], source="DECOY_GRID", provenance="SIM",
                      payload={"sensors": e["sensors"]})
    sightings = {}
    for b in beacons:
        payload = {**b, "dst_defanged": replay_mod.defang(b["dst"]), "c2_source": telemetry.C2["source"],
                   "malware": telemetry.C2["malware"], "asset_id": beacon_asset["id"]}
        ledger.append(ts=b["confirmed_at"], kind="ioc.sighting", subject=beacon_asset["id"], source="SIM_LOGS",
                      provenance="SIM", payload=payload)
        sightings[beacon_asset["id"]] = payload
    db.execute("CREATE TABLE decoy_daily (date TEXT, tag TEXT, sessions INTEGER, unique_ips INTEGER, sensors INTEGER)")
    daily: dict[tuple[str, str], list[int]] = {}
    for r in rollups:
        agg = daily.setdefault((r["date"], r["tag"]), [0, 0, 0])
        agg[0], agg[1], agg[2] = agg[0] + r["sessions"], agg[1] + r["unique_ips"], agg[2] + 1
    db.executemany("INSERT INTO decoy_daily VALUES (?,?,?,?,?)", [(d, t, *v) for (d, t), v in daily.items()])
    db.execute("CREATE TABLE decoy_surges (tag TEXT, first TEXT, last TEXT, z_sessions REAL, z_ips REAL, sensors INTEGER)")
    db.executemany("INSERT INTO decoy_surges VALUES (?,?,?,?,?,?)",
                   [(t, r["first"], r["last"], r["z_sessions"], r["z_ips"], r["sensors"])
                    for t, runs in surge_runs.items() for r in runs])
    print(f"SIM: {sum(len(r) for r in surge_runs.values())} decoy surges, {len(exploits)} exploit tags, "
          f"{len(beacons)} beacon(s)")

    def signals_for(asset: dict, rec: dict) -> dict:
        sig: dict = {}
        published = (rec.get("published") or "")[:10]
        for r in surge_runs.get(asset.get("product_key", ""), []):
            # a surge counts as early evidence for this product's CVEs disclosed within 21 days after it
            if published and 0 <= (dt.date.fromisoformat(published) - dt.date.fromisoformat(r["first"])).days <= 21:
                sig["decoy_surge"] = r["z_sessions"]
        sig["decoy_exploit"] = next((e["sensors"] for e in exploits if e["cve"] == rec["id"]), 0)
        exploited = bool(rec.get("kev")) or (rec.get("ssvc") or {}).get("Exploitation") == "active"
        if asset["id"] in sightings and exploited:
            sig["ioc_sighting"] = sightings[asset["id"]]
        return sig

    n_assess = 0
    recs: dict[str, dict] = {}
    product_cves: dict[str, set[str]] = {}
    for cid in sorted(ids):
        rec = build_record(cid, nvd.get(cid), kev.get(cid), epss.get(cid))
        rec["forecast"] = forecasts.get(cid)
        recs[cid] = rec
        db.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (cid, rec["published"], rec["description"], json.dumps(rec["kev"]), rec["epss"],
                    json.dumps(rec["ssvc"]), rec["cvss_vector"], rec["cvss_source"], rec["nvd_status"],
                    json.dumps({k: rec[k] for k in ("cna_affected", "nvd_configurations", "forecast")})))
        # REAL evidence events, each at its own timestamp (drives replay and the early-warning timeline)
        if rec["published"]:
            ledger.append(ts=rec["published"], kind="vuln.published", subject=cid, source="CNA",
                          payload={"cvss_vector": rec["cvss_vector"], "cvss_source": rec["cvss_source"]})
        cve5 = load_cve5(cid)
        for adp in (cve5 or {}).get("containers", {}).get("adp", []):
            if rec["ssvc"] and "CISA" in json.dumps(adp.get("providerMetadata", {})) and "Exploitation" in json.dumps(adp):
                ledger.append(ts=adp["providerMetadata"].get("dateUpdated", rec["published"]), kind="ssvc.updated",
                              subject=cid, source="CISA_ADP", payload=rec["ssvc"])
                break
        if rec["kev"]:
            # KEV publishes a date, not a time: never order a same-day listing before the CVE itself.
            kev_day = rec["kev"]["dateAdded"] + "T00:00:00Z"
            kev_ts = max(kev_day, rec["published"][:19] + "Z") if rec["published"] else kev_day
            ledger.append(ts=kev_ts, kind="kev.added", subject=cid,
                          source="CISA_KEV", payload={k: rec["kev"][k] for k in
                                                       ("dateAdded", "dueDate", "requiredAction",
                                                        "knownRansomwareCampaignUse")})

        # exposure + assessment for every asset running a product this CVE names
        named = {tuple(m["criteria"].split(":")[3:5]) for cfg in rec["nvd_configurations"] for n in cfg.get("nodes", [])
                 for m in n.get("cpeMatch", [])}
        for (vendor, product), assets in by_product.items():
            relevant = (any(same_product(vendor, product, v, p) for v, p in named)
                        or any(same_product(vendor, product, e.get("vendor", ""), e.get("product", ""))
                               for e in rec["cna_affected"])
                        or (rec["kev"] and same_product(vendor, product, rec["kev"]["vendorProject"],
                                                        rec["kev"]["product"]))
                        or (not named and not rec["cna_affected"] and mentions(vendor, product, rec["description"])))
            if not relevant:
                continue
            for asset in assets:
                org = orgs[asset["org_id"]]
                exp = reconcile(asset, rec)
                if exp.relevance > 0:
                    product_cves.setdefault(asset["product_key"], set()).add(cid)
                a = assess(rec, asset, org, exp, signals_for(asset, rec))
                detail = {**a.to_dict(), "exposure": {"status": exp.status, "votes": [vars(v) for v in exp.votes]}}
                db.execute("INSERT OR REPLACE INTO assessments VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (asset["id"], cid, org["id"], org["sector"], exp.status, exp.relevance, a.risk, a.tier,
                            a.decision, a.deadline_hours, json.dumps(detail)))
                n_assess += 1

    stats = run_sentinel(db, ledger, recs, orgs, {a["id"]: {**a, "tier1_reachable": reach[a["id"]]}
                                                  for a in world["assets"]}, surge_runs, product_cves, sightings)
    meta = {"snapshot_date": SNAPSHOT_DATE.isoformat(), "epss_header": epss_header, "sentinel": json.dumps(stats),
            "nvd_month_counts": json.dumps(month_counts), "built_at": dt.datetime.now().isoformat(timespec="seconds"),
            "candidates": str(len(ids))}
    db.executemany("INSERT INTO meta VALUES (?,?)", meta.items())
    db.commit()
    ok, bad = ledger.verify()
    tiers = dict(db.execute("SELECT tier, COUNT(*) FROM assessments WHERE R > 0 GROUP BY tier").fetchall())
    print(f"{n_assess} asset x CVE assessments; exposed by tier: {tiers}; ledger ok={ok}; "
          f"{time.time() - started:.0f}s -> {DB_PATH}")


def run_sentinel(db, ledger, recs, orgs, assets, surge_runs, product_cves, sightings) -> dict:
    """Autopilot over every alert's time line: what Odyssey would have done on its own, and when."""
    pilot = sentinel.Autopilot(db, ledger, scoring_config()[0], orgs, assets)
    pilot.surges([r for runs in surge_runs.values() for r in runs], recs, product_cves)
    rows = db.execute("""SELECT org_id, cve_id, asset_id FROM assessments WHERE R > 0
                         AND tier IN ('High', 'Critical', 'Compromise') ORDER BY risk DESC""").fetchall()
    top: dict[tuple[str, str], str] = {}
    exposed_orgs: dict[str, set[str]] = {}
    for org_id, cid, asset_id in rows:
        top.setdefault((org_id, cid), asset_id)
        exposed_orgs.setdefault(cid, set()).add(org_id)
    items = []
    for (org_id, cid), asset_id in top.items():
        asset, org = assets[asset_id], {**orgs[org_id], "cii": bool(orgs[org_id]["cii"])}
        steps = replay_mod.replay(recs[cid], asset, org, replay_mod.evidence(ledger, cid, asset))
        items.append({"org": org, "asset": asset, "rec": recs[cid], "steps": steps, "sighting": sightings.get(asset_id)})
    peers = {cid: sorted(o - {org_id for (org_id, c), a in top.items() if c == cid and a in sightings})
             for cid, o in exposed_orgs.items()}
    pilot.alerts(items, peers, (len(assets), len(orgs)))
    pilot.kev_at = {cid: r["kev"]["dateAdded"] + "T00:00:00Z" for cid, r in recs.items() if r.get("kev")}
    pilot.flush()
    kev_ts = {r[0]: r[1] for r in db.execute("SELECT subject, ts FROM ledger WHERE kind = 'kev.added'").fetchall()}
    lead = sentinel.lead_times(pilot.actions, kev_ts, pilot.go_live, {cid for _, cid in top})
    go = pilot.go_live.date()
    db.execute("INSERT INTO meta VALUES ('pressure', ?)",
               (json.dumps(sentinel.pressure(items, go - dt.timedelta(days=14), SNAPSHOT_DATE)),))
    counts: dict[str, int] = {}
    for a in pilot.actions:
        counts[a["kind"]] = counts.get(a["kind"], 0) + 1
    langs = sorted({a["payload"]["lang"] for a in pilot.actions if a["payload"].get("lang")})
    print(f"sentinel: {len(pilot.actions)} autonomous actions {counts}; KEV after go-live {lead['kev_after_go_live']}, "
          f"acted before KEV on {lead['acted_before_kev']} (median lead {lead['median_lead_days']} d); "
          f"languages {langs}")
    pending = db.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]
    print(f"sentinel: {pending} proposals pending analyst approval (live window); REAL signals only: "
          f"{lead['real_signals_only']}")
    return {"go_live": pilot.s["go_live"], "actions": len(pilot.actions), "by_kind": counts, "languages": langs,
            "lead": lead, "pending": pending,
            "by_mode": {m: sum(a["mode"] == m for a in pilot.actions) for m in ("auto", "approve")}}


if __name__ == "__main__":
    main()
