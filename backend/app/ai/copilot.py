"""Analyst copilot: ask in plain language, get an answer grounded in Odyssey's own data.

  1. Route   the local security model picks one read-only tool from a closed set (it cannot invent one); the
             arguments (CVE ids, organisations, sectors, tiers, products, "exploited") are resolved deterministically
             from the question, because small models choose tools well but fill entities unreliably;
  2. Query   the tool runs deterministically against the database (no model involved);
  3. Facts   results become numbered facts F1..Fn;
  4. Answer  the model answers using only those facts, citing them; the same validator as the analyst brief rejects
             uncited claims and any CVE id, hostname, version or number not present in the facts. One repair round,
             otherwise the answer is withheld and the facts are shown as they are.
"""

from __future__ import annotations

import json
import re
import sqlite3

from .llm import chat, resolve
from .narrate import _GROUNDED

TOOLS = {
    "alerts": "list open warnings, filtered by organisation, sector, product, tier or known-exploited only",
    "org": "profile one organisation: exposure, warnings by tier, compromise, language, top remediation steps",
    "cve": "everything known about one CVE: description, exploitation evidence, forecast, who is exposed",
    "forecast": "new CVEs the day-0 model expects to be exploited, on exposed assets",
    "plan": "risk-reduction plan: which changes remove the most risk, nationally or for one organisation",
    "campaigns": "active threat campaigns against constituency products",
    "autopilot": "what Odyssey did on its own recently, and its lead over CISA KEV",
    "pending": "proposals waiting for an analyst's decision",
}
SECTORS = ["Power & Energy", "BFSI", "Telecom", "Transport", "Government", "Strategic & Public Enterprises"]
TIERS = ["Compromise", "Critical", "High", "Medium"]

ROUTE_SCHEMA = {"type": "object", "properties": {"tool": {"type": "string", "enum": list(TOOLS)}},
                "required": ["tool"]}
_SECTOR_WORDS = {"Power & Energy": r"power|energy|electric|grid|utilit", "BFSI": r"bank|bfsi|financ|insur|payment",
                 "Telecom": r"telecom|telco|\bisp\b|fibre|fiber", "Transport": r"transport|rail|metro|\bports?\b|airport|aviation",
                 "Government": r"government|govt|ministry|treasury|public service",
                 "Strategic & Public Enterprises": r"strategic|defen[cs]e|space|\bpsu|public enterprise"}
_GENERIC_PRODUCT = {"power", "server", "secure", "data", "center", "remote", "support", "email", "gateway",
                    "firewall", "http", "database", "commerce", "alliance", "access", "application", "delivery",
                    "controller", "transact", "core", "banking", "management", "connect", "operation", "scada", "hmi",
                    "multiple", "products", "the", "and", "kernel"}
_GENERIC = {"corporation", "limited", "services", "service", "finance", "insurance", "energy", "power", "networks",
            "airports", "telecom", "directorate", "centre", "center", "computing", "treasury", "state", "precision",
            "defence", "works", "space", "components", "thermal", "hydro", "digital", "fibre", "metro", "authority",
            "operative", "west", "rail", "bank", "link", "grid", "port", "corp"}
ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "points": {"type": "array", "items": {"type": "object", "properties": {
            "text": {"type": "string"}, "cites": {"type": "array", "items": {"type": "string"}}},
            "required": ["text", "cites"]}},
    },
    "required": ["answer", "points"],
}
ANSWER_SYSTEM = (
    "You are the analyst copilot of India's national cyber early-warning centre. Answer the question using ONLY the "
    "numbered facts. Give a one-sentence direct answer, then 2-5 points; every point cites the fact IDs it uses, for "
    "example [\"F2\"]. Copy CVE ids, hostnames, versions, dates and numbers exactly as written in the facts; never "
    "introduce any that are not there. If the facts do not answer the question, say so."
)


def _entities(question: str, orgs: list[tuple[str, str]], products: list[str]) -> dict:
    """Deterministic argument resolution: exact ids, distinctive organisation and product names, keyword sectors."""
    q = question.lower()
    cve = re.search(r"cve-\d{4}-\d{4,}", q)
    org = next((oid for oid, name in orgs if oid.lower() in q or any(
        w.lower() in q for w in re.findall(r"[A-Za-z]{4,}", name) if w.lower() not in _GENERIC)), "")
    sector = "" if org else next((s for s, rx in _SECTOR_WORDS.items() if re.search(rx, q)), "")
    tier = next((t for t in TIERS if t.lower() in q), "")
    product = next((p for p in products if any(re.search(rf"\b{w.lower()}", q) for w in re.findall(r"[A-Za-z]{3,}", p)
                                                if w.lower() not in _GENERIC_PRODUCT)), "")
    return {"cve": cve.group(0).upper() if cve else "", "org_id": org, "sector": sector, "tier": tier,
            "product": product, "exploited_only": bool(re.search(r"exploit|\bkev\b|in the wild|actively|attacked", q))}


def _route(question: str, orgs: list[tuple[str, str]], products: list[str]) -> dict:
    tools = "\n".join(f"- {k}: {v}" for k, v in TOOLS.items())
    system = "Choose the one tool that best answers the analyst's question. Tools:\n" + tools
    r = chat([{"role": "system", "content": system}, {"role": "user", "content": question}], role="copilot",
             schema=ROUTE_SCHEMA, max_tokens=40, temperature=0.0, timeout=120)
    tool = r.data.get("tool") if isinstance(r.data, dict) else None
    route = {"tool": tool if tool in TOOLS else "alerts", "_seconds": r.seconds, **_entities(question, orgs, products)}
    if (route["tool"] == "org" and not route["org_id"]) or (route["tool"] == "cve" and not route["cve"]):
        route["tool"] = "alerts"  # nothing specific named: answer across the constituency
    if route["tool"] == "org" and route["product"]:
        route["tool"] = "alerts"  # "is <org> exposed to <product>?" is a filtered warning list
    return route


def _facts(conn: sqlite3.Connection, route: dict, api) -> tuple[list[str], list[dict]]:
    """Run the chosen tool through the API's own functions (no model involved) and render numbered facts."""
    tool, org = route.get("tool"), route.get("org_id") or None
    facts: list[str] = []
    rows: list[dict] = []
    if tool == "alerts":
        where, args = [], []
        if org:
            where.append("a.org_id = ?"), args.append(org)
        if route.get("sector"):
            where.append("o.sector = ?"), args.append(route["sector"])
        if route.get("tier"):
            where.append("a.tier = ?"), args.append(route["tier"])
        else:
            where.append("a.tier IN ('Compromise','Critical','High')")
        if route.get("exploited_only"):
            where.append("v.kev != 'null'")
        if route.get("product"):
            where.append("LOWER(s.label) LIKE ?"), args.append(f"%{route['product'].lower()}%")
        if route.get("cve"):
            where.append("a.cve_id = ?"), args.append(route["cve"])
        q = f"""SELECT a.org_id, o.name, a.cve_id, a.tier, ROUND(MAX(a.risk)) risk, s.label, MIN(a.deadline_hours) dl,
                       COUNT(*) n, v.kev != 'null' AS kev
                FROM assessments a JOIN assets s ON s.id = a.asset_id JOIN orgs o ON o.id = a.org_id
                JOIN vulns v ON v.id = a.cve_id WHERE a.R > 0 AND {' AND '.join(where)}
                GROUP BY a.org_id, a.cve_id ORDER BY MAX(a.risk) DESC LIMIT 10"""
        rows = [dict(r) for r in conn.execute(q, args).fetchall()]
        total = conn.execute(f"""SELECT COUNT(DISTINCT a.org_id || a.cve_id) FROM assessments a JOIN assets s ON
                                 s.id = a.asset_id JOIN orgs o ON o.id = a.org_id JOIN vulns v ON v.id = a.cve_id
                                 WHERE a.R > 0 AND {' AND '.join(where)}""", args).fetchone()[0]
        scope = ", ".join(f"{k}={v}" for k, v in route.items() if k in ("org_id", "sector", "tier", "product", "cve")
                          and v) or "whole constituency"
        orgs_all = [r[0] for r in conn.execute(f"""SELECT o.name FROM assessments a JOIN assets s ON s.id = a.asset_id
                       JOIN orgs o ON o.id = a.org_id JOIN vulns v ON v.id = a.cve_id
                       WHERE a.R > 0 AND {' AND '.join(where)} GROUP BY o.name ORDER BY MAX(a.risk) DESC""",
                                                args).fetchall()]
        facts.append(f"{total} open warning(s) match ({scope}"
                     + (", known-exploited only" if route.get("exploited_only") else "") + f") at {len(orgs_all)} "
                     f"organisation(s): {', '.join(orgs_all)}. The {len(rows)} highest-risk warnings follow.")
        facts += [f"{r['cve_id']} at {r['name']} ({r['org_id']}): tier {r['tier']}, risk {int(r['risk'])}, product "
                  f"{r['label']}, {r['n']} asset(s), {'known exploited (CISA KEV)' if r['kev'] else 'not in KEV'}, "
                  f"deadline {r['dl']} hours." for r in rows]
    elif tool == "org" and org:
        p = api.org_profile(org)
        t = p["tiers"]
        facts.append(f"{p['org']['name']} ({org}): {p['org']['sector']} sector, {p['org']['state']}; alerts are sent "
                     f"in language code {p['language']}; sector CSIRT {p['csirt']}.")
        facts.append(f"Warnings by tier: Compromise {t.get('Compromise', 0)}, Critical {t.get('Critical', 0)}, "
                     f"High {t.get('High', 0)}, Medium {t.get('Medium', 0)}.")
        facts.append(f"{p['surface']['internet']} internet-facing and {p['surface']['dmz']} DMZ assets out of "
                     f"{p['surface']['assets']}.")
        for tk in p["risk"]["plan"][:3]:
            facts.append(f"Remediation step {tk['rank']}: upgrade {tk['label']} {tk['version']}"
                         + (f" to {tk['target_version']}" if tk["target_version"] else "")
                         + f" on {tk['n_assets']} host(s), clearing {tk['n_cves']} CVE(s), {tk['pct']}% of the risk.")
        for s in p["indicators"]["c2_sightings"]:
            facts.append(f"C2 beacon: {s['asset']} to {s['c2']} ({s['malware']}) since {s['ts'][:10]}.")
        rows = p["alerts"][:5]
    elif tool == "cve" and route.get("cve"):
        cve = route["cve"].upper().strip()
        v = conn.execute("SELECT * FROM vulns WHERE id = ?", (cve,)).fetchone()
        if v:
            rec = json.loads(v["record"])
            kev = json.loads(v["kev"]) if v["kev"] not in (None, "null") else None
            facts.append(f"{cve}: {v['description'][:300]}")
            facts.append(f"{cve} CISA KEV: " + (f"added {kev['dateAdded']}, due {kev['dueDate']}." if kev else "not listed."))
            ssvc = json.loads(v["ssvc"] or "{}")
            if ssvc:
                facts.append(f"{cve} CISA SSVC: Exploitation={ssvc.get('Exploitation')}, Automatable={ssvc.get('Automatable')}.")
            if (fc := rec.get("forecast")):
                facts.append(f"{cve} day-0 forecast: probability {fc['p']} of exploitation; flagged={fc['flag']}.")
            for r in conn.execute("""SELECT a.tier, COUNT(DISTINCT a.org_id) orgs, COUNT(*) assets FROM assessments a
                                     WHERE a.cve_id = ? AND a.R > 0 GROUP BY a.tier""", (cve,)).fetchall():
                facts.append(f"{cve} exposure: {r['orgs']} organisation(s), {r['assets']} asset(s) at tier {r['tier']}.")
        else:
            facts.append(f"{cve} is not among the CVEs that affect this constituency.")
    elif tool == "forecast":
        f = api.forecast_view()
        pending = [i for i in f["items"] if not i["kev_added"]]
        done = [i for i in f["items"] if i["kev_added"]]
        facts.append(f"{f['flagged']} recent CVEs on exposed assets are flagged likely-to-be-exploited; "
                     f"{f['since_exploited']} have since been confirmed exploited (added to CISA KEV), "
                     f"{f['flagged'] - f['since_exploited']} not yet.")
        facts += [f"Not yet exploited: {i['cve']} ({i['product']}), forecast probability {i['p']}, "
                  f"{i['orgs']} organisation(s), {i['assets']} asset(s)." for i in
                  sorted(pending, key=lambda i: -i["p"])[:6]]
        facts += [f"Already confirmed: {i['cve']} ({i['product']}) was flagged on day 0 and added to CISA KEV on "
                  f"{i['kev_added']}." for i in done[:3]]
    elif tool == "plan":
        p = api.riskplan(org, 6)
        facts.append(f"Scope {p['scope']}: {p['tickets']} change tickets; {p['for_50_pct']} remove 50% of the risk and "
                     f"{p['for_80_pct']} remove 80%.")
        facts += [f"Step {t['rank']}: upgrade {t['label']} {t['version']} at {t['org_id']}"
                  + (f" to {t['target_version']}" if t["target_version"] else "")
                  + f" ({t['n_assets']} host(s), {t['n_cves']} CVE(s), top tier {t['top_tier']}), removing "
                    f"{t['pct']}% of the risk." for t in p["plan"]]
    elif tool == "campaigns":
        for c in api.campaigns(6):
            facts.append(f"Campaign '{c['title']}' ({c['status']}): {len(c['cves'])} exploited CVE(s), "
                         f"{len(c['orgs_exposed'])} organisation(s) exposed"
                         + (f", first signal {c['early_warning_days']} days before disclosure." if c["early_warning_days"]
                            else "."))
    elif tool == "autopilot":
        a = api.autopilot(limit=8, org_id=org)
        lead = a["summary"].get("lead") or {}
        real = lead.get("real_signals_only") or {}
        facts.append(f"Since go-live Odyssey acted on {lead.get('acted_before_kev')} KEV-listed CVE(s) at least a day "
                     f"before CISA listed them; on public signals alone {real.get('acted_before_kev')} CVE(s), median "
                     f"{real.get('median_lead_days')} days.")
        facts += [f"{e['ts'][:16]}: {e['payload'].get('title', e['kind'])}" for e in a["events"][:8]
                  if e["payload"].get("title")]
    elif tool == "pending":
        waiting = api.approvals()
        facts.append(f"{len(waiting)} proposal(s) are waiting for an analyst's decision (approve or reject).")
        facts += [f"Waiting: {p['title']} ({len(p['orgs'])} organisation(s))." for p in waiting[:8]]
    if not facts:
        facts.append("The question could not be mapped to Odyssey's data; try naming an organisation, sector, product or CVE.")
    return facts, rows


def _validate(out: dict, facts: dict[str, str]) -> list[str]:
    problems, corpus = [], " ".join(facts.values())
    points = out.get("points") or []
    for p in points:
        if not p.get("cites"):
            problems.append(f"uncited point: {p.get('text', '')[:50]}")
        if bad := [c for c in p.get("cites", []) if c not in facts]:
            problems.append(f"cites unknown facts {bad}")
    for text in [out.get("answer", "")] + [p.get("text", "") for p in points]:
        for token in _GROUNDED.findall(text):
            if token not in corpus:
                problems.append(f"ungrounded token '{token}'")
    return problems


def ask(conn: sqlite3.Connection, question: str, api) -> dict:
    orgs = [(r[0], r[1]) for r in conn.execute("SELECT id, name FROM orgs ORDER BY id").fetchall()]
    products = [r[0] for r in conn.execute("SELECT DISTINCT label FROM assets ORDER BY label").fetchall()]
    route = _route(question, orgs, products)
    fact_list, rows = _facts(conn, route, api)
    facts = {f"F{i}": f for i, f in enumerate(fact_list, 1)}
    messages = [{"role": "system", "content": ANSWER_SYSTEM},
                {"role": "user", "content": "Facts:\n" + "\n".join(f"[{k}] {v}" for k, v in facts.items())
                                            + f"\n\nQuestion: {question}"}]
    seconds, out, problems = route.get("_seconds", 0.0), {}, ["not run"]
    for _ in range(2):  # one self-repair round with the same model, never a different model
        r = chat(messages, role="copilot", schema=ANSWER_SCHEMA, max_tokens=600, temperature=0.0, timeout=180)
        seconds += r.seconds
        out = r.data if isinstance(r.data, dict) else {}
        problems = [r.error] if r.error else _validate(out, facts)
        if not problems:
            break
        messages += [{"role": "assistant", "content": r.content},
                     {"role": "user", "content": "Your answer failed validation: " + "; ".join(problems)
                                                 + ". Rewrite it using only text that appears in the facts."}]
    return {"question": question, "model": resolve("copilot"),
            "route": {k: v for k, v in route.items() if not k.startswith("_") and v not in ("", False, None)},
            "facts": facts, "rows": rows, "status": "validated" if not problems else "withheld",
            "answer": out if not problems else None, "problems": problems, "seconds": round(seconds, 1)}


def protected_terms(result: dict) -> list[str]:
    """Identifiers an answer translation must keep verbatim (organisation names, hostnames, products)."""
    text = " ".join(result["facts"].values())
    names = re.findall(r"at ([A-Z][\w&.\- ]+?) \(", text)
    return sorted(set(names))
