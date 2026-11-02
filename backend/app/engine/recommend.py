"""Recommendations: what deserves this analyst's attention first, with the reasons, and the next steps.

Four lists, each ranked with a transparent score and every entry carrying its reasons: the organisations most at
risk, the technologies under the most pressure, the threat groups and malware families the record overlaps with, and
the campaigns running. Then the next steps that remove the most risk, each one a decision the analyst can take
through the step-by-step decision support (engine/decide.py). Built only from what the record already holds
(assessments, the risk plan, campaigns, live detections, the intelligence graph's ATT&CK overlap); nothing is
invented, and threat groups are overlap with the public ATT&CK record, never attribution. A profile (organisations,
sectors) lifts what touches the analyst's own constituency to the top and says so.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3

PROFILE_BOOST = 30


def _profile_hit(profile: dict, org_id: str | None, sector: str | None) -> bool:
    return bool((org_id and org_id in set(profile.get("orgs") or [])) or (sector and sector in set(profile.get("sectors") or [])))


def recommendations(conn: sqlite3.Connection, live: dict | None, profile: dict, cfg: dict) -> dict:
    conn.row_factory = sqlite3.Row
    from . import soc, workflow
    workflow.ensure(conn)
    soc.ensure(conn)
    closed = {r[0] for r in conn.execute("SELECT alert_id FROM workflow WHERE state = 'closed'").fetchall()}
    detections = (live or {}).get("detections") or []
    live_by_org: dict[str, list[dict]] = {}
    for d in detections:
        if d.get("org_id"):
            live_by_org.setdefault(d["org_id"], []).append(d)
    pending = {r[0]: r[1] for r in conn.execute("SELECT org_id, COUNT(*) FROM approvals WHERE status = 'pending' GROUP BY org_id").fetchall()}
    cases = [c for c in soc.cases(conn, "open")]
    cases_by_org: dict[str, list[dict]] = {}
    for c in cases:
        cases_by_org.setdefault(c["org_id"], []).append(c)

    # ---- organisations
    orgs = []
    for o in conn.execute("SELECT id, name, sector, state, cii FROM orgs").fetchall():
        rows = conn.execute("""SELECT cve_id, MAX(CASE tier WHEN 'Compromise' THEN 4 WHEN 'Critical' THEN 3 WHEN 'High' THEN 2
                                      WHEN 'Medium' THEN 1 ELSE 0 END) t, MAX(risk) risk, COUNT(DISTINCT asset_id) assets
                               FROM assessments WHERE org_id = ? AND R > 0 GROUP BY cve_id""", (o["id"],)).fetchall()
        rows = [r for r in rows if f"{o['id']}:{r['cve_id']}" not in closed]
        comp = sum(1 for r in rows if r["t"] == 4)
        crit = sum(1 for r in rows if r["t"] == 3)
        high = sum(1 for r in rows if r["t"] == 2)
        max_risk = max((r["risk"] for r in rows), default=0.0)
        top = max(rows, key=lambda r: (r["t"], r["risk"]), default=None)
        lv = live_by_org.get(o["id"], [])
        beacons = sum(1 for d in lv if d.get("kind") == "beacon")
        opened = cases_by_org.get(o["id"], [])
        incidents = sum(1 for c in opened if c["kind"] == "incident")
        score = 100 * comp + 12 * crit + 3 * high + max_risk / 5 + 25 * beacons + 8 * (len(lv) - beacons) + 6 * incidents + 2 * len(opened)
        reasons = []
        if comp:
            reasons.append(f"{comp} suspected compromise{'s' if comp > 1 else ''} (CERT-In 6-hour clock running)")
        if beacons:
            reasons.append(f"{beacons} live C2 beacon detection{'s' if beacons > 1 else ''}")
        if crit:
            reasons.append(f"{crit} Critical warning{'s' if crit > 1 else ''}")
        if high:
            reasons.append(f"{high} High")
        if incidents:
            reasons.append(f"{incidents} incident case{'s' if incidents > 1 else ''} open")
        if pending.get(o["id"]):
            reasons.append(f"{pending[o['id']]} proposal{'s' if pending[o['id']] > 1 else ''} waiting for you")
        if lv and not beacons:
            reasons.append(f"{len(lv)} live detection{'s' if len(lv) > 1 else ''} this session")
        hit = _profile_hit(profile, o["id"], o["sector"])
        orgs.append({"org_id": o["id"], "name": o["name"], "sector": o["sector"], "state": o["state"], "cii": bool(o["cii"]),
                     "score": round(score + (PROFILE_BOOST if hit else 0), 1), "in_profile": hit, "compromise": comp,
                     "critical": crit, "high": high, "max_risk": round(max_risk, 1), "live": len(lv), "beacons": beacons,
                     "open_cases": len(opened), "pending": pending.get(o["id"], 0), "reasons": reasons or ["no open Critical warning"],
                     "top_cve": top["cve_id"] if top else None,
                     "top_tier": {4: "Compromise", 3: "Critical", 2: "High", 1: "Medium"}.get(top["t"] if top else 0, "Watch")})
    orgs.sort(key=lambda x: -x["score"])

    # ---- technologies
    techs = []
    try:
        from .campaigns import build
        from .intel import technologies
        snap = conn.execute("SELECT value FROM meta WHERE key = 'snapshot_date'").fetchone()[0]
        prof_orgs = set(profile.get("orgs") or [])
        prof_sectors = set(profile.get("sectors") or [])
        runs = {}
        for r in conn.execute("SELECT s.product_key, s.org_id, o.sector FROM assets s JOIN orgs o ON o.id = s.org_id").fetchall():
            runs.setdefault(r[0], set()).add((r[1], r[2]))
        for t in technologies(conn, build(conn, dt.date.fromisoformat(snap))):
            trend = t.get("attack_trend") or {}
            score = 40 * t["compromised_assets"] + 8 * t["critical"] + 4 * t["kev_cves"] + 2 * t["forecast_cves"] + 2 * t["high"] \
                + (10 * (trend.get("ratio") or 0) if trend else 0) + (10 if t.get("campaign") == "ACTIVE" else 4 if t.get("campaign") == "EMERGING" else 0)
            if score <= 0:
                continue
            hit = any(o in prof_orgs or s in prof_sectors for o, s in runs.get(t["product_key"], set()))
            reasons = []
            if t["compromised_assets"]:
                reasons.append(f"{t['compromised_assets']} asset{'s' if t['compromised_assets'] > 1 else ''} suspected compromised")
            if t["critical"]:
                reasons.append(f"{t['critical']} Critical warning{'s' if t['critical'] > 1 else ''}")
            if t["kev_cves"]:
                reasons.append(f"{t['kev_cves']} CVE{'s' if t['kev_cves'] > 1 else ''} in CISA KEV")
            if t["forecast_cves"]:
                reasons.append(f"{t['forecast_cves']} forecast likely to be exploited")
            if t.get("campaign"):
                reasons.append(f"campaign {t['campaign'].lower()}")
            if trend and trend.get("ratio", 0) >= 1.5:
                reasons.append(f"attacks on {trend['service']} :{trend['port']} at {trend['ratio']}x their 28-day median (DShield, REAL)")
            techs.append({"label": t["label"], "product_key": t["product_key"], "score": round(score + (PROFILE_BOOST if hit else 0), 1),
                          "in_profile": hit, "assets": t["assets"], "orgs": t["orgs"], "internet_facing": t["internet_facing"],
                          "critical": t["critical"], "kev_cves": t["kev_cves"], "forecast_cves": t["forecast_cves"],
                          "compromised_assets": t["compromised_assets"], "campaign": t.get("campaign"), "attack_trend": trend or None,
                          "reasons": reasons})
        techs.sort(key=lambda x: -x["score"])
    except Exception as exc:  # noqa: BLE001 - the list is advisory; its failure must not hide the others
        techs = [{"error": f"{type(exc).__name__}: {exc}"}]

    # ---- threat groups and malware, from the graph's ATT&CK overlap (never attribution)
    actors, malware = [], []
    try:
        from .graph import intel_graph
        g = intel_graph(conn, None, live)
        for n in g.get("nodes", []):
            f = n.get("facts") or {}
            if n.get("kind") == "actor":
                mal, overlap = f.get("malware") or [], f.get("overlap") or []
                actors.append({"id": n["id"], "name": n["label"], "group_id": f.get("group_id"), "aliases": (f.get("aliases") or [])[:4],
                               "url": f.get("url"), "malware": [m.title() for m in mal], "overlap": overlap, "techniques_documented": f.get("techniques_documented"),
                               "score": round(3 * len(mal) + len(overlap) + 2 * float(n.get("pulse") or 0), 1), "pulse": n.get("pulse"),
                               "basis": n.get("sub"), "note": f.get("note") or "Technique overlap with the public ATT&CK record, not attribution.",
                               "provenance": "REAL"})
            elif n.get("kind") == "malware":
                malware.append({"id": n["id"], "name": n["label"], "attack_id": f.get("attack_id"), "url": f.get("url"), "sub": n.get("sub"),
                                "pulse": n.get("pulse"), "tier": n.get("tier"), "score": round(2 * float(n.get("pulse") or 0) + (3 if n.get("tier") == "Compromise" else 0), 1),
                                "provenance": n.get("provenance")})
        actors.sort(key=lambda x: -x["score"])
        malware.sort(key=lambda x: -x["score"])
    except Exception as exc:  # noqa: BLE001
        actors = [{"error": f"{type(exc).__name__}: {exc}"}]

    # ---- campaigns
    camps = []
    try:
        from .campaigns import build
        snap = conn.execute("SELECT value FROM meta WHERE key = 'snapshot_date'").fetchone()[0]
        for c in build(conn, dt.date.fromisoformat(snap)):
            if c["status"] == "DORMANT":
                continue
            camps.append({k: c[k] for k in ("id", "title", "status", "first_signal", "last_exploit", "early_warning_days",
                                            "orgs_exposed", "sectors_exposed", "assets_exposed", "max_risk")}
                         | {"cves": [x["cve"] for x in c["cves"]][:4]})
    except Exception as exc:  # noqa: BLE001
        camps = [{"error": f"{type(exc).__name__}: {exc}"}]

    # ---- next steps: the decisions that remove the most risk, each one a Decide
    steps = []
    for o in orgs:
        if o["compromise"] and o["top_cve"]:
            steps.append({"kind": "contain", "org_id": o["org_id"], "org": o["name"], "cve": o["top_cve"], "tier": "Compromise",
                          "title": f"Contain and report: suspected compromise at {o['name']}",
                          "why": "CERT-In's 6-hour incident clock is running; isolate, preserve evidence, report, hunt",
                          "recommended": "escalate"})
    try:
        from .riskplan import plan
        scope = (profile.get("orgs") or [None])[0] if len(profile.get("orgs") or []) == 1 else None
        for t in plan(conn, scope, 8)["plan"]:
            if not t.get("cves"):
                continue
            steps.append({"kind": "patch", "org_id": t["org_id"], "org": t["org"], "cve": t["cves"][0], "tier": t["top_tier"],
                          "title": f"Patch {t['label']} {t['version']}{' to ' + t['target_version'] if t.get('target_version') else ''} at {t['org']}",
                          "why": f"{t['n_assets']} asset{'s' if t['n_assets'] != 1 else ''}, {len(t['cves'])} CVE{'s' if len(t['cves']) != 1 else ''}"
                                 f"{', ' + str(t['kev_cves']) + ' exploited' if t.get('kev_cves') else ''}; removes {t['pct']}% of the risk"
                                 f"{'; deadline ' + str(t['deadline_hours']) + ' h' if t.get('deadline_hours') else ''}",
                          "recommended": "patch" if t.get("target_version") else "mitigate"})
    except Exception as exc:  # noqa: BLE001
        steps.append({"kind": "error", "title": f"risk plan unavailable: {type(exc).__name__}"})
    total_pending = sum(pending.values())
    if total_pending:
        steps.insert(0 if not steps or steps[0]["kind"] != "contain" else 1,
                     {"kind": "decide", "title": f"Decide the {total_pending} proposal{'s' if total_pending > 1 else ''} waiting for a person",
                      "why": "notices, escalations and predictions Odyssey will not send on its own", "view": "soc", "tab": "overview"})
    return {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "profile": {"orgs": sorted(profile.get("orgs") or []), "sectors": sorted(profile.get("sectors") or [])},
            "orgs": orgs[:6], "technologies": techs[:6], "actors": actors[:5], "malware": malware[:5], "campaigns": camps[:4],
            "next_steps": steps[:8],
            "how": {"orgs": "100 per suspected compromise + 12 per Critical + 3 per High + max risk / 5 + 25 per live C2 beacon + 8 per other live detection + 6 per open incident; +30 inside your profile",
                    "technologies": "40 per compromised asset + 8 per Critical + 4 per KEV CVE + 2 per forecast + 10 x attack ratio + campaign; +30 inside your profile",
                    "actors": "3 per malware family seen + 1 per overlapping ATT&CK technique + 2 x evidence pulse; overlap with the public record, never attribution",
                    "next_steps": "containment first, then the risk plan's change tickets in order of risk removed per unit of effort"}}
