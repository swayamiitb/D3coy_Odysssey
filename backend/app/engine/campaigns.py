"""Campaigns: relate individual signals into the attack activity analysts actually track.

A campaign is keyed by product (the thing attackers are going after) and assembled from evidence that already
sits in the ledger and the assessment tables:
  - exploited CVEs for the product (CISA KEV / SSVC active), ordered in time -> exploit chain when several hit the
    same exposed asset
  - decoy-grid scanning surges for the product tag (pre-disclosure interest)
  - advisories that name the product or its CVEs
  - the organisations, sectors and assets currently exposed
Status: ACTIVE when exploitation evidence is <= 30 days old, EMERGING when only scanning/advisories exist.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from collections import defaultdict

WINDOW_DAYS = 60
ACTIVE_DAYS = 30


def build(conn: sqlite3.Connection, today: dt.date) -> list[dict]:
    conn.row_factory = sqlite3.Row
    since = (today - dt.timedelta(days=WINDOW_DAYS)).isoformat()
    products = {r["product_key"]: dict(r) for r in conn.execute(
        "SELECT product_key, vendor, product, label FROM assets GROUP BY product_key")}

    # exploited CVEs per product: CVEs with KEV/active evidence that hit assets of that product
    exploited: dict[str, dict[str, dict]] = defaultdict(dict)
    for r in conn.execute("""SELECT s.product_key, v.id, v.kev, v.ssvc, v.published, v.description
                             FROM assessments a JOIN assets s ON s.id = a.asset_id JOIN vulns v ON v.id = a.cve_id
                             WHERE v.kev != 'null' OR v.ssvc LIKE '%active%' GROUP BY s.product_key, v.id"""):
        kev = json.loads(r["kev"]) if r["kev"] and r["kev"] != "null" else None
        when = (kev or {}).get("dateAdded") or (r["published"] or "")[:10]
        if when >= since:
            exploited[r["product_key"]][r["id"]] = {"cve": r["id"], "date": when,
                                                    "name": (kev or {}).get("vulnerabilityName") or r["description"][:90]}
    surges: dict[str, list[dict]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM decoy_surges"):
        if r["last"] >= since:
            surges[r["tag"]].append(dict(r))

    campaigns = []
    for key in sorted(set(exploited) | set(surges)):
        cves = sorted(exploited.get(key, {}).values(), key=lambda c: c["date"])
        cve_ids = [c["cve"] for c in cves]
        exposure_rows = conn.execute(
            f"""SELECT a.org_id, a.sector, a.asset_id, a.cve_id, a.tier, a.risk FROM assessments a
                JOIN assets s ON s.id = a.asset_id WHERE s.product_key = ? AND a.R >= 0.6
                {"AND a.cve_id IN (%s)" % ",".join("?" * len(cve_ids)) if cve_ids else ""}""",
            [key, *cve_ids]).fetchall() if cve_ids else []
        per_asset: dict[str, set] = defaultdict(set)
        for e in exposure_rows:
            per_asset[e["asset_id"]].add(e["cve_id"])
        chains = sorted([{"asset_id": a, "cves": sorted(c)} for a, c in per_asset.items() if len(c) >= 2],
                        key=lambda x: -len(x["cves"]))
        first_signal = min([s["first"] for s in surges.get(key, [])] + [c["date"] for c in cves] or [None])
        last_exploit = cves[-1]["date"] if cves else None
        status = ("ACTIVE" if last_exploit and (today - dt.date.fromisoformat(last_exploit)).days <= ACTIVE_DAYS
                  else "EMERGING" if surges.get(key) else "DORMANT")
        p = products.get(key, {"label": key})
        first_disclosure = cves[0]["date"] if cves else None
        lead = ((dt.date.fromisoformat(first_disclosure) - dt.date.fromisoformat(first_signal)).days
                if first_disclosure and first_signal else None)
        campaigns.append({
            "id": f"CAMP-{key}", "product_key": key, "title": f"{'Exploitation' if cves else 'Reconnaissance'} of "
                                                              f"{p['label']}",
            "status": status, "first_signal": first_signal, "last_exploit": last_exploit,
            "early_warning_days": lead if lead and lead > 0 else 0,
            "cves": cves, "decoy_surges": surges.get(key, []), "chains": chains,
            "orgs_exposed": sorted({e["org_id"] for e in exposure_rows}),
            "sectors_exposed": sorted({e["sector"] for e in exposure_rows}),
            "assets_exposed": len(per_asset), "max_risk": max([e["risk"] for e in exposure_rows] or [0]),
        })
    order = {"ACTIVE": 0, "EMERGING": 1, "DORMANT": 2}
    campaigns.sort(key=lambda c: (order[c["status"]], -c["max_risk"], -c["early_warning_days"], -len(c["orgs_exposed"])))
    return campaigns
