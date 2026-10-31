"""Risk management: from a ranked list of warnings to the shortest plan that removes the most risk.

  - Asset risk is its worst open path (an attacker needs one way in), so a pile of medium issues never outranks one
    exploited flaw; the count of open CVEs is reported alongside.
  - A remediation ticket is one change: upgrade one product version at one organisation, which clears every open
    CVE of that product on every asset running that version. Effort grows with hosts (1 + 0.25 per extra host).
  - Order: urgency class first (suspected compromise, then known-exploited Critical, Critical, High, Medium), then
    risk removed per unit of effort, which is the optimal greedy order for disjoint tickets within a class. The
    cumulative curve answers "which N changes remove 80% of the risk?".
  - Target release: the lowest vendor-published fixed release (newer than installed, never a downgrade) that clears
    every ticket CVE with a published fix; coverage says how many CVEs that is ("4/6": two need the vendor advisory). Closed warnings drop out; accepted risk is reported apart.
"""

from __future__ import annotations

import json
import sqlite3

from .versions import Version

OPEN_TIERS = ("Compromise", "Critical", "High", "Medium")
_TIER_RANK = {"Compromise": 4, "Critical": 3, "High": 2, "Medium": 1}


def _fixed(record: dict, installed: str, product: str = "") -> list[Version]:
    """Fixed releases newer than the installed one: the CNA record's explicit 'unaffected' versions, upper bounds of
    affected ranges ('lessThan'), 'changes' that flip to unaffected, and NVD's versionEndExcluding for this product."""
    found = []
    for cfg in record.get("nvd_configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable") and f":{product}:" in m.get("criteria", "") and m.get("versionEndExcluding"):
                    found.append(m["versionEndExcluding"])
    for e in record.get("cna_affected", []):
        for v in e.get("versions", []):
            if v.get("status") == "unaffected":
                found.append(v.get("version"))
            elif v.get("status") == "affected":
                found.append(v.get("lessThan"))
                found += [c.get("at") for c in v.get("changes", []) if c.get("status") == "unaffected"]
    out = []
    for raw in found:
        if raw in (None, "", "0", "n/a", "*") or not any(ch.isdigit() for ch in raw):
            continue
        try:
            if Version(raw) > Version(installed):
                out.append(Version(raw))
        except (TypeError, ValueError):
            continue
    return out


def plan(conn: sqlite3.Connection, org_id: str | None = None, limit: int = 25) -> dict:
    where = "AND a.org_id = ?" if org_id else ""
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    rows = cur.execute(f"""
        SELECT a.org_id, a.cve_id, a.risk, a.tier, a.deadline_hours, s.id AS asset_id, s.hostname, s.label,
               s.vendor, s.product, s.version, s.zone, s.owner, o.name AS org, v.kev, v.record
        FROM assessments a JOIN assets s ON s.id = a.asset_id JOIN orgs o ON o.id = a.org_id
        JOIN vulns v ON v.id = a.cve_id
        WHERE a.R > 0 AND a.tier IN {OPEN_TIERS} {where}""", (org_id,) if org_id else ()).fetchall()
    states = {}
    try:
        states = {r[0]: (r[1], r[2]) for r in conn.execute("SELECT alert_id, state, outcome FROM workflow")}
    except sqlite3.OperationalError:
        pass
    records: dict[str, dict] = {}
    assets: dict[str, dict] = {}
    accepted = 0.0
    for r in rows:
        state, outcome = states.get(f"{r['org_id']}:{r['cve_id']}", ("new", None))
        if state == "closed":
            if outcome == "risk_accepted":
                accepted += r["risk"]
            continue
        a = assets.setdefault(r["asset_id"], {"asset_id": r["asset_id"], "hostname": r["hostname"],
                                              "org_id": r["org_id"], "org": r["org"], "label": r["label"],
                                              "vendor": r["vendor"], "product": r["product"], "version": r["version"],
                                              "zone": r["zone"], "owner": r["owner"], "cves": {}})
        a["cves"][r["cve_id"]] = {"risk": r["risk"], "tier": r["tier"], "deadline": r["deadline_hours"],
                                  "kev": r["kev"] not in (None, "null")}
        if r["cve_id"] not in records:
            records[r["cve_id"]] = json.loads(r["record"])
    for a in assets.values():
        a["risk"] = max(min(c["risk"], 100) for c in a["cves"].values())
    total = sum(a["risk"] for a in assets.values())

    tickets: dict[tuple, dict] = {}
    for a in assets.values():
        key = (a["org_id"], a["vendor"], a["product"], a["version"])
        t = tickets.setdefault(key, {"org_id": a["org_id"], "org": a["org"], "label": a["label"],
                                     "product": f"{a['vendor']}:{a['product']}", "version": a["version"],
                                     "assets": [], "zones": set(), "owners": set(), "cves": {}, "risk": 0.0})
        t["assets"].append(a["hostname"])
        t["zones"].add(a["zone"])
        t["owners"].add(a["owner"])
        t["cves"].update(a["cves"])
        t["risk"] += a["risk"]
    out = []
    for t in tickets.values():
        n = len(t["assets"])
        effort = 1 + 0.25 * (n - 1)
        # lowest fixed release that clears every CVE: the max over CVEs of each CVE's lowest fix
        per_cve = [min(f) for c in t["cves"] if (f := _fixed(records[c], t["version"], t["product"]))]
        target = max(per_cve).raw if per_cve else None
        deadlines = [c["deadline"] for c in t["cves"].values() if c["deadline"]]
        top = max(t["cves"].values(), key=lambda c: _TIER_RANK[c["tier"]])["tier"]
        kev_n = sum(c["kev"] for c in t["cves"].values())
        urgency = _TIER_RANK[top] * 2 + (1 if kev_n else 0)
        out.append({**{k: t[k] for k in ("org_id", "org", "label", "product", "version")},
                    "assets": sorted(t["assets"]), "n_assets": n, "zones": sorted(t["zones"]),
                    "owners": sorted(t["owners"]), "cves": sorted(t["cves"]), "n_cves": len(t["cves"]),
                    "kev_cves": kev_n, "top_tier": top, "urgency": urgency,
                    "deadline_hours": min(deadlines) if deadlines else None, "target_version": target,
                    "fix_coverage": f"{len(per_cve)}/{len(t['cves'])}",
                    "effort": effort, "risk_removed": round(t["risk"], 1),
                    "pct": round(100 * t["risk"] / total, 2) if total else 0.0})
    out.sort(key=lambda x: (-x["urgency"], -x["risk_removed"] / x["effort"], x["deadline_hours"] or 9999))
    cum = 0.0
    curve = [{"k": 0, "cum_pct": 0.0}]
    for i, x in enumerate(out, 1):
        cum += x["pct"]
        x["rank"], x["cum_pct"] = i, round(min(cum, 100.0), 1)
        if i <= 400:
            curve.append({"k": i, "cum_pct": x["cum_pct"]})

    def needed(share: float) -> int | None:
        return next((x["rank"] for x in out if x["cum_pct"] >= share), None)

    return {"scope": org_id or "national", "total_risk": round(total, 1), "accepted_risk": round(accepted, 1),
            "assets_at_risk": len(assets), "tickets": len(out), "for_50_pct": needed(50), "for_80_pct": needed(80),
            "curve": curve, "plan": out[:limit],
            "method": "asset risk = worst open path; one ticket per (organisation, product, installed version); "
                      "urgency class first, then risk removed per unit of effort"}
