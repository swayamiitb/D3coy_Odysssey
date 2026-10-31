"""National cyber threat situation report: the document a national CERT issues, written from the live state.

Everything in it is a number the interface already shows, so the report can be checked line by line against the
screens. It is plain Markdown: pasteable into an email, a ticket or a regulator's portal, and printable."""

from __future__ import annotations

import datetime as dt

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def _n(v) -> str:
    return "—" if v is None else f"{v:,}"


def render(d: dict) -> str:
    now = dt.datetime.now(IST)
    feed, soc, metrics, plan = d["feed"], d["soc"], d["metrics"], d["plan"]
    live, campaigns, obligations = d.get("live") or {}, d.get("campaigns") or [], d.get("obligations") or []
    tiers = soc["tiers"]
    lead = (soc["autopilot"].get("lead") or {}).get("real_signals_only") or {}
    L: list[str] = []
    L += [f"# National Cyber Threat Situation Report",
          f"**Odyssey national early-warning desk · {now:%d %b %Y, %H:%M} IST · TLP:AMBER**",
          "",
          f"Distribution: CERT-In, NCIIPC, sector CSIRTs ({', '.join(sorted(d['csirts']))}). "
          f"Simulated organisations and sensors are marked SIM; all vulnerability, exploitation and feed data is real.",
          "",
          "## 1. Headline",
          "",
          f"- **{_n(feed['counts']['needs_action'])} warnings need action** across {len(soc['orgs'])} operators in "
          f"{len({o['sector'] for o in soc['orgs']})} critical sectors: {_n(tiers.get('Compromise', 0))} suspected compromise, "
          f"{_n(tiers.get('Critical', 0))} Critical, {_n(tiers.get('High', 0))} High, {_n(tiers.get('Medium', 0))} Medium.",
          f"- **{_n(soc['pending'])} decisions** wait for an analyst (predictions, early warnings, regulator escalations, advisory notices).",
          f"- **SOC:** {_n(metrics['open'])} open cases ({_n(metrics['incidents'])} incident response), {_n(metrics['overdue'])} past their SLA"
          + (f", mean time to acknowledge {metrics['mtta_h']} h" if metrics.get("mtta_h") is not None else "") + ".",
          f"- **Lead over CISA KEV on real signals:** {lead.get('acted_before_kev', 0)} CVEs, median {lead.get('median_lead_days', '—')} days, "
          f"up to {lead.get('max_lead_days', '—')} days.",
          ""]
    comp = [c for c in feed["cards"] if c["tier"] == "Compromise"]
    L += ["## 2. Suspected compromises (CERT-In 6-hour reporting clock)", ""]
    if comp:
        for c in comp:
            L.append(f"- **{c['org_name']}** ({c['sector']}): {c['cve_id']}, {c['assets']} asset(s). "
                     f"Status: {c['workflow']['state'].replace('_', ' ')}. Report due {c['deadline_hours']} h after issue.")
    else:
        L.append("- None open.")
    L += ["", "## 3. Most urgent warnings", ""]
    for c in feed["cards"][:8]:
        L.append(f"- {c['tier']} · **{c['cve_id']}** at {c['org_name']} ({c['sector']}), {c['assets']} asset(s), "
                 f"due in {c['deadline_hours']} h{' · exploited in the wild' if c.get('kev') else ''}"
                 + (f": {c['headline']}" if c.get("headline") else ""))
    if obligations:
        L += ["", "## 4. Regulatory clocks running", ""]
        for o in obligations[:10]:
            L.append(f"- {o['who']}: {o['what']}" + (f" · within {o['hours']} h" if o.get("hours") else "") + f" ({o['for']})")
    L += ["", "## 5. Threat activity, last 24 hours", ""]
    dets = live.get("detections") or []
    L.append(f"- Live detections: {len(dets)} (scanning surges, C2 beacons, flow anomalies) on {live.get('sensors', 24)} decoy sensors (SIM).")
    for x in dets[:5]:
        L.append(f"  - {x['ts'][11:16]} UTC · {x['title']}")
    intakes = live.get("intakes") or []
    L.append(f"- New CVEs taken in live from NVD that name a product we run: {len(intakes)}.")
    for t in intakes[:5]:
        L.append(f"  - {t['cve']} ({t.get('product') or 'named in text'}): {t['exposed']} exposed asset(s) at "
                 f"{len(t['orgs'])} organisation(s), {t['worst']}; {t['action']}.")
    active = [c for c in campaigns if c.get("status") == "ACTIVE"]
    L.append(f"- Active campaigns against our technologies: {len(active)}.")
    for c in active[:5]:
        L.append(f"  - {c['title']}: {len(c.get('cves', []))} exploited CVE(s), {len(c.get('orgs_exposed', []))} organisation(s) exposed"
                 + (f", first signal {c['early_warning_days']} d before disclosure" if c.get("early_warning_days") else "") + ".")
    feeds = live.get("feeds") or []
    if feeds:
        L.append("- Feeds: " + "; ".join(f"{f['name']} {f['status']}" for f in feeds) + ".")
    L += ["", "## 6. National risk plan: the fewest changes that remove the most risk", "",
          f"{_n(plan['tickets'])} change tickets cover {_n(plan['assets_at_risk'])} assets at risk. "
          f"**{plan['for_50_pct']} changes remove half of the national risk; {plan['for_80_pct']} remove 80%.**", ""]
    for t in plan["plan"][:8]:
        L.append(f"{t['rank']}. Upgrade {t['label']} {t['version']}"
                 + (f" to {t['target_version']}" if t.get("target_version") else " (vendor advisory)")
                 + f" at {t['org_id']}: {t['n_assets']} host(s), {t['n_cves']} CVE(s)"
                 + (f" ({t['kev_cves']} exploited)" if t.get("kev_cves") else "") + f", −{t['pct']:.1f}% national risk, due {t['deadline_hours']} h.")
    L += ["", "## 7. Exposure by sector", ""]
    by_sector: dict[str, dict] = {}
    for o in soc["orgs"]:
        s = by_sector.setdefault(o["sector"], {"orgs": 0, "critical": 0, "compromise": 0})
        s["orgs"] += 1
        s["critical"] += o["critical"]
        s["compromise"] += o["compromise"]
    L.append("| Sector | Operators | Critical warnings | Suspected compromise |")
    L.append("|---|---|---|---|")
    for sec, s in sorted(by_sector.items(), key=lambda kv: -kv[1]["critical"]):
        L.append(f"| {sec} | {s['orgs']} | {s['critical']} | {s['compromise']} |")
    L += ["", "## 8. Recommended national actions", "",
          "1. Operators with a suspected compromise: isolate the host, preserve evidence, report to CERT-In within 6 hours; Odyssey has pre-filled the report.",
          "2. All operators: apply the risk plan above in order; each ticket names the fixed release, the owner and the deadline.",
          "3. Sector CSIRTs: confirm receipt of today's notices (sent in each organisation's language) and chase overdue acknowledgements.",
          "4. Suppliers running affected products for several operators: confirm their patch status to every dependent (supplier fan-out).",
          "", f"_Generated by Odyssey from its live state at {now:%H:%M:%S} IST. Every figure is reproducible on the Proof page; "
              f"the audit trail is hash-chained ({_n(d.get('ledger_events'))} events)._"]
    return "\n".join(L)
