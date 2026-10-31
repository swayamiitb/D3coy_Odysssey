"""Odyssey - national cyber threat early-warning system: API.

Run: .venv/Scripts/python -m uvicorn backend.app.main:app --port 8000
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .engine.ledger import Ledger
from .engine.scoring import config as scoring_config

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "ews.db"
MODELS = json.loads((ROOT / "config" / "models.json").read_text(encoding="utf-8"))
TIER_RANK = {"Compromise": 4, "Critical": 3, "High": 2, "Medium": 1, "Watch": 0}
EXPOSED = 0.6

app = FastAPI(title="Odyssey - National Cyber Threat Early Warning System", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _alerts(where: str = "", args: tuple = (), limit: int = 200) -> list[dict]:
    """Alerts are grouped per (organisation, CVE): one actionable unit with its affected assets."""
    q = f"""
        SELECT a.org_id, o.name AS org_name, a.sector, a.cve_id, MAX(a.risk) AS risk, COUNT(*) AS assets,
               MIN(a.deadline_hours) AS deadline_hours, v.kev, v.epss, v.ssvc, v.description, v.published,
               GROUP_CONCAT(a.tier) AS tiers, GROUP_CONCAT(a.status) AS statuses
        FROM assessments a JOIN orgs o ON o.id = a.org_id JOIN vulns v ON v.id = a.cve_id
        WHERE a.R >= ? {where}
        GROUP BY a.org_id, a.cve_id ORDER BY risk DESC LIMIT ?"""
    rows = db().execute(q, (EXPOSED, *args, limit)).fetchall()
    out = []
    for r in rows:
        tier = max(r["tiers"].split(","), key=lambda t: TIER_RANK[t])
        kev = json.loads(r["kev"]) if r["kev"] and r["kev"] != "null" else None
        out.append({
            "id": f"{r['org_id']}:{r['cve_id']}", "org_id": r["org_id"], "org_name": r["org_name"],
            "sector": r["sector"], "cve_id": r["cve_id"], "risk": r["risk"], "tier": tier, "assets": r["assets"],
            "deadline_hours": r["deadline_hours"], "kev": bool(kev), "kev_due": (kev or {}).get("dueDate"),
            "epss": r["epss"], "ssvc": json.loads(r["ssvc"] or "{}"), "published": r["published"],
            "disputed": "disputed" in r["statuses"].split(","),
            "title": (r["description"] or "")[:160],
        })
    return out


@app.get("/api/health")
def health() -> dict:
    ok, bad = Ledger(DB_PATH).verify()
    return {"status": "ok", "ledger_intact": ok, "first_bad_seq": bad, "models": MODELS["roles"],
            "scoring_config_hash": scoring_config()[1]}


@app.get("/api/summary")
def summary() -> dict:
    conn = db()
    meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    months = json.loads(meta.get("nvd_month_counts", "{}"))
    alerts = _alerts(" AND a.tier IN ('Compromise','Critical','High','Medium')", limit=100000)
    by_tier: dict[str, int] = {}
    heat: dict[str, dict[str, int]] = {}
    for a in alerts:
        by_tier[a["tier"]] = by_tier.get(a["tier"], 0) + 1
        heat.setdefault(a["sector"], {}).setdefault(a["tier"], 0)
        heat[a["sector"]][a["tier"]] += 1
    exposed_pairs = conn.execute("SELECT COUNT(*) FROM assessments WHERE R >= ?", (EXPOSED,)).fetchone()[0]
    return {
        "snapshot_date": meta.get("snapshot_date"),
        "funnel": {
            "cves_published_this_month": months.get("2026-10"),
            "candidate_cves": int(meta.get("candidates", 0)),
            "exposed_asset_cve_pairs": exposed_pairs,
            "actionable_alerts": len(alerts),
            "critical_alerts": by_tier.get("Critical", 0) + by_tier.get("Compromise", 0),
            "suspected_compromise": by_tier.get("Compromise", 0),
        },
        "alerts_by_tier": by_tier,
        "sector_heatmap": heat,
        "orgs_exposed": len({a["org_id"] for a in alerts if a["tier"] in ("Critical", "High")}),
        "top_alerts": alerts[:10],
        "nvd_month_counts": months,
        "epss_model": meta.get("epss_header"),
    }


@app.get("/api/alerts")
def alerts(tier: str | None = None, sector: str | None = None, org: str | None = None,
           limit: int = Query(200, le=5000)) -> list[dict]:
    where, args = "", []
    if tier:
        where, args = where + " AND a.tier = ?", args + [tier]
    if sector:
        where, args = where + " AND a.sector = ?", args + [sector]
    if org:
        where, args = where + " AND a.org_id = ?", args + [org]
    return _alerts(where, tuple(args), limit)


def _actions(vuln: dict, kev: dict | None, record: dict, installed: list[str] | None = None) -> list[dict]:
    """Deterministic, sourced actions. The LLM never invents these; it may only explain them.
    Fixed releases are only those newer than the oldest installed version (never suggest a downgrade)."""
    from .engine.versions import Version
    actions = []
    floor = min((Version(v) for v in installed or []), default=None)
    fixed = sorted({v["version"] for e in record.get("cna_affected", []) for v in e.get("versions", [])
                    if v.get("status") == "unaffected" and (floor is None or Version(v["version"]) > floor)},
                   key=Version)
    if kev:
        actions.append({"type": "patch", "step": kev["requiredAction"], "source": "CISA KEV requiredAction",
                        "due": kev["dueDate"]})
    if fixed:
        actions.append({"type": "patch", "step": f"Upgrade to a fixed release: {', '.join(fixed)}",
                        "source": "Vendor CVE record (unaffected versions)"})
    if kev and kev.get("forensicTriage", "").lower() == "yes":
        actions.append({"type": "investigate", "step": "Perform forensic triage for signs of prior compromise "
                        "before and after patching (CISA marks this CVE for forensic triage).",
                        "source": "CISA KEV forensicTriage"})
    if (vuln.get("ssvc") or {}).get("Exploitation") == "active" or kev:
        actions.append({"type": "investigate", "step": "Hunt for exploitation indicators on affected assets: "
                        "review authentication, web and command-execution logs since the publication date.",
                        "source": "Playbook: known-exploited vulnerability"})
    actions.append({"type": "block", "step": "If patching is delayed, restrict management and VPN interfaces "
                    "to trusted networks and block indicators linked to this campaign at the perimeter.",
                    "source": "Playbook: compensating control"})
    return actions


@app.get("/api/alerts/{org_id}/{cve_id}")
def alert_detail(org_id: str, cve_id: str) -> dict:
    conn = db()
    v = conn.execute("SELECT * FROM vulns WHERE id = ?", (cve_id,)).fetchone()
    o = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    if not v or not o:
        raise HTTPException(404, "unknown organisation or CVE")
    kev = json.loads(v["kev"]) if v["kev"] and v["kev"] != "null" else None
    record = json.loads(v["record"])
    rows = conn.execute("""SELECT a.detail, s.hostname, s.ip, s.zone, s.role, s.label, s.version, s.owner, s.tier
                           FROM assessments a JOIN assets s ON s.id = a.asset_id
                           WHERE a.org_id = ? AND a.cve_id = ? ORDER BY a.risk DESC""", (org_id, cve_id)).fetchall()
    assets = [{**json.loads(r["detail"]), "hostname": r["hostname"], "ip": r["ip"], "zone": r["zone"],
               "role": r["role"], "label": r["label"], "version": r["version"], "owner": r["owner"],
               "asset_tier": r["tier"]} for r in rows]
    vuln = {"id": v["id"], "published": v["published"], "description": v["description"], "kev": kev,
            "epss": v["epss"], "ssvc": json.loads(v["ssvc"] or "{}"), "cvss_vector": v["cvss_vector"],
            "cvss_source": v["cvss_source"], "nvd_status": v["nvd_status"], "forecast": record.get("forecast")}
    timeline = Ledger(conn=conn).events(subject=cve_id)
    from .engine.attack import map_alert
    top = assets[0] if assets else {}
    fired = {r["id"] for r in top.get("rules", [])}
    attack = map_alert(v["description"], top, v["cvss_vector"],
                       exploited=bool(kev) or vuln["ssvc"].get("Exploitation") == "active",
                       decoy_surge="DECOY_SURGE" in fired or "DECOY_EXPLOIT" in fired,
                       beacon="IOC_SIGHTING" in fired) if top else None
    return {"org": dict(o), "vulnerability": vuln, "assets": assets, "actions": _actions(vuln, kev, record, [x["version"] for x in assets]),
            "timeline": timeline, "attack": attack, "scoring_config_hash": scoring_config()[1]}


@app.get("/api/alerts/{org_id}/{cve_id}/brief")
def alert_brief(org_id: str, cve_id: str, refresh: bool = False) -> dict:
    """AI analyst brief (local security LLM, grounded + validated). Cached by a hash of model + prompt + facts, so
    it survives database rebuilds but is never reused for changed facts. Each generation is a ledger event."""
    from datetime import datetime, timezone

    from . import cache
    from .ai.llm import resolve
    from .ai.narrate import SYSTEM, build_facts, generate

    detail = alert_detail(org_id, cve_id)
    model = resolve("narrate")
    key = cache.key_of("brief", model, SYSTEM, build_facts(detail))
    subject = f"{org_id}:{cve_id}"
    if not refresh and (hit := cache.get("brief", key)):
        return {**hit, "cached": True}
    result = generate(detail)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["ledger_hash"] = Ledger(conn=db()).append(
        ts=now, kind="model.output", subject=subject, source=f"MODEL:{model}", provenance="AI",
        payload={"role": "narrate", "status": result["status"], "brief": result["brief"], "problems": result["problems"]})
    cache.put("brief", key, result, now, subject)
    return {**result, "cached": False}


@app.get("/api/replay/{org_id}/{cve_id}")
def replay_alert(org_id: str, cve_id: str) -> dict:
    """Re-score the organisation's most exposed asset for this CVE as of every evidence event (REAL + SIM)."""
    from .engine.replay import replay
    from .ingest.cve_records import build_record

    conn = db()
    row = conn.execute("""SELECT s.* FROM assessments a JOIN assets s ON s.id = a.asset_id
                          WHERE a.org_id = ? AND a.cve_id = ? ORDER BY a.risk DESC LIMIT 1""", (org_id, cve_id)).fetchone()
    v = conn.execute("SELECT * FROM vulns WHERE id = ?", (cve_id,)).fetchone()
    o = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    if not row or not v or not o:
        raise HTTPException(404, "unknown organisation, CVE or exposure")
    asset, org = dict(row), {**dict(o), "cii": bool(o["cii"])}
    rec = {**build_record(cve_id), **json.loads(v["record"]), "id": cve_id, "description": v["description"],
           "kev": json.loads(v["kev"]) if v["kev"] and v["kev"] != "null" else None,
           "ssvc": json.loads(v["ssvc"] or "{}"), "cvss_vector": v["cvss_vector"], "cvss_source": v["cvss_source"],
           "published": v["published"]}
    from .engine.replay import evidence
    steps = replay(rec, asset, org, evidence(Ledger(conn=conn), cve_id, asset))
    first_warning = next((s for s in steps if s["tier"] != "Watch" or s["stage"] == "pre-disclosure warning"), None)
    return {"org": dict(o), "asset": {k: asset[k] for k in ("id", "hostname", "label", "version", "zone")},
            "cve_id": cve_id, "published": v["published"], "steps": steps,
            "lead_days_before_disclosure": ((
                __import__("datetime").date.fromisoformat(v["published"][:10])
                - __import__("datetime").date.fromisoformat(first_warning["ts"][:10])).days
                if first_warning and v["published"] else None)}


def _context(org_id: str, cve_id: str) -> tuple[dict, dict | None, dict | None, dict | None]:
    """Alert detail plus the evidence the outbound artefacts need: beacon sighting, workflow, cached AI brief."""
    conn = db()
    detail = alert_detail(org_id, cve_id)
    asset_ids = {a["asset_id"] for a in detail["assets"]}
    sighting = None
    for aid in asset_ids:
        ev = Ledger(conn=conn).events(subject=aid, kind="ioc.sighting")
        if ev:
            sighting = ev[-1]["payload"]
    wf = workflow_state(org_id, cve_id)
    from . import cache
    return detail, sighting, wf, cache.latest("brief", f"{org_id}:{cve_id}")


@app.get("/api/alerts/{org_id}/{cve_id}/certin-report")
def certin_report(org_id: str, cve_id: str) -> dict:
    from .engine.reports import certin_report as build
    detail, sighting, wf, brief = _context(org_id, cve_id)
    return build(detail, sighting, wf, brief)


@app.get("/api/alerts/{org_id}/{cve_id}/stix")
def stix(org_id: str, cve_id: str, tlp: str = "AMBER") -> dict:
    from .engine.reports import stix_bundle
    detail, sighting, _, brief = _context(org_id, cve_id)
    return stix_bundle(detail, sighting, brief, tlp.upper())


MT_URL = "http://127.0.0.1:8010"
TRANSLATOR_VERSION = "mt-v2"  # XQZn placeholders + Latin grounding; bump to invalidate cached translations
_LANGS_CACHE: list = []


@app.get("/api/languages")
def languages() -> list[dict]:
    """The 22 scheduled Indian languages served by the local IndicTrans2 service (code, native name, script, RTL)."""
    import httpx
    if not _LANGS_CACHE:
        try:
            _LANGS_CACHE.extend(httpx.get(f"{MT_URL}/languages", timeout=10).json())
        except httpx.HTTPError as exc:
            raise HTTPException(503, f"translation service unavailable: {exc}") from exc
    return _LANGS_CACHE


@app.get("/api/alerts/{org_id}/{cve_id}/brief/translate")
def brief_translate(org_id: str, cve_id: str, lang: str = "hi") -> dict:
    """The *validated* brief in any of the 22 scheduled Indian languages via the local IndicTrans2 service.
    Protected identifiers are preserved and every sentence is validated; failures are withheld, never guessed."""
    import httpx
    from datetime import datetime, timezone

    from . import cache

    codes = {x["code"] for x in languages()}
    if lang not in codes:
        raise HTTPException(400, f"lang must be one of {sorted(codes)}")
    conn = db()
    brief = alert_brief(org_id, cve_id)
    if not brief.get("brief"):
        raise HTTPException(409, "no validated English brief to translate")
    b = brief["brief"]
    texts = [b["headline"]] + [x["text"] for x in b["why_it_matters"]] + [x["text"] for x in b["what_to_do"]]
    detail = alert_detail(org_id, cve_id)
    protect = sorted({a["label"] for a in detail["assets"]} | {detail["org"]["name"]})
    key = cache.key_of("translate", TRANSLATOR_VERSION, lang, texts, protect)
    if hit := cache.get("translate", key):
        return {**hit, "cached": True}
    try:
        r = httpx.post(f"{MT_URL}/translate", json={"texts": texts, "lang": lang, "protect": protect}, timeout=300)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(503, f"translation service unavailable: {exc}") from exc
    out = r.json()
    res = out["results"]
    n_why = len(b["why_it_matters"])
    body = {"lang": lang, "model": out["model"], "seconds": out["seconds"], "rtl": out.get("rtl", False),
            "headline": res[0], "why_it_matters": res[1:1 + n_why], "what_to_do": res[1 + n_why:],
            "validated": sum(x["status"] == "validated" for x in res), "total": len(res)}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    Ledger(conn=conn).append(ts=now, kind="model.output", subject=f"{org_id}:{cve_id}", source=f"MODEL:{out['model']}",
                             provenance="AI", payload={"role": "translate", "lang": lang,
                                                       "validated": body["validated"], "total": body["total"]})
    cache.put("translate", key, body, now, f"{org_id}:{cve_id}:{lang}")
    return {**body, "cached": False}


ADVISORIES = ROOT / "data" / "sim" / "advisories.json"
ANALYSER_VERSION = "advisory-v3"  # v3: VERS ranges in CISA CSAF advisories


def _analyse_advisory(adv: dict) -> dict:
    from datetime import datetime, timezone

    from . import cache
    from .ai.advisory import analyse
    from .ai.llm import resolve

    key = cache.key_of(ANALYSER_VERSION, resolve("extract"), adv["text"])
    if hit := cache.get("advisory", key):
        _propose_advisory(adv, hit)  # idempotent per advisory
        return {**hit, "cached": True}
    conn = db()
    assets = [dict(r) for r in conn.execute("SELECT * FROM assets").fetchall()]
    orgs = {r["id"]: {**dict(r), "cii": bool(r["cii"])} for r in conn.execute("SELECT * FROM orgs").fetchall()}
    result = analyse(adv, assets, orgs)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    Ledger(conn=conn).append(ts=now, kind="advisory.analysed", subject=adv["id"], source="ANALYST_INPUT"
                             if adv.get("provenance") == "USER" else "CERTIN_SIM", provenance=adv.get("provenance", "USER"),
                             payload={"product": result["product"]["label"], "exposed": len(result["exposed"]),
                                      "cleared": len(result["cleared"]), "iocs": sum(map(len, result["iocs"].values()))})
    cache.put("advisory", key, result, now, adv["id"])
    _propose_advisory(adv, result)
    return {**result, "cached": False}


def _propose_advisory(adv: dict, result: dict) -> None:
    """A new advisory that hits exposed assets becomes one proposal: notify each affected organisation, in its own
    language, with the recommended steps. An analyst approves it (human in the loop); idempotent per advisory."""
    from datetime import datetime, timezone

    from .engine.sentinel import APPROVALS, SOURCE
    conn = db()
    conn.execute(APPROVALS)
    subject = f"advisory:{adv['id']}"
    if conn.execute("SELECT 1 FROM approvals WHERE subject = ?", (subject,)).fetchone():
        return
    hits = result["exposed"] or result["unknown"]
    if not hits or not result["product"].get("label"):
        return
    s = scoring_config()[0]["sentinel"]
    orgs = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM orgs").fetchall()}
    world = json.loads((ROOT / "data" / "sim" / "world.json").read_text(encoding="utf-8"))
    ciso = {o["id"]: o["ciso"] for o in world["orgs"]}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    label, verify = result["product"]["label"], not result["exposed"]
    actions = []
    by_org: dict[str, list[dict]] = {}
    for e in hits:
        by_org.setdefault(e["org_id"], []).append(e)
    for org_id, rows in by_org.items():
        hosts = ", ".join(sorted({r["hostname"] for r in rows})[:4])
        worst = max(rows, key=lambda r: r["risk"])
        steps = ("verify the installed version and apply the vendor fix if affected" if verify else
                 "patch to the vendor's fixed release; restrict management interfaces until patched")
        if any(result["iocs"].get(k) for k in ("ips", "domains", "urls", "sha256")):
            steps += "; block the advisory's indicators at the perimeter and hunt for them in logs"
        actions.append({"ts": now, "kind": "auto.advisory", "subject": f"{org_id}:{adv['id']}", "payload": {
            "org_id": org_id, "advisory": adv["id"], "alert": f"{org_id}:{adv['id']}", "tier": worst["tier"],
            "deadline_hours": worst["deadline_hours"], "lang": s["state_language"].get(orgs[org_id]["state"], "hi"),
            "recipients": [ciso.get(org_id, "")], "channels": ["email"], "basis": "advisory analysis",
            "provenance": adv.get("provenance", "USER"),
            "title": f"Advisory '{adv['title']}': {len(rows)} of your assets ({hosts}) run {label}"
                     + (" (version not stated: verify)" if verify else f", {worst['tier']} risk") + f". Recommended: {steps}."}})
    title = (f"Notify {len(by_org)} organisation(s) about '{adv['title']}' ({label}, {len(hits)} "
             f"{'possibly ' if verify else ''}exposed asset(s))")
    payload = {"group": subject, "action": "auto.advisory", "orgs": sorted(by_org), "count": len(actions),
               "title": title, "basis": "advisory analysis", "provenance": adv.get("provenance", "USER"),
               "actions": actions}
    conn.execute("INSERT INTO approvals (proposed_at, kind, subject, org_id, title, payload, status) "
                 "VALUES (?,?,?,?,?,?, 'pending')", (now, "auto.advisory", subject,
                                                      next(iter(by_org)) if len(by_org) == 1 else None, title,
                                                      json.dumps(payload)))
    Ledger(conn=conn).append(ts=now, kind="auto.proposed", subject=subject, source=SOURCE, provenance="AUTO",
                             payload={k: v for k, v in payload.items() if k != "actions"})
    conn.commit()


@app.get("/api/advisories")
def advisories() -> list[dict]:
    """Advisory inbox with Odyssey's analysis of each: real CISA ICS advisories that name an inventory product,
    plus sample national advisories (SIM, CERT-In style)."""
    from .engine.intel import advisories_matched, cisa_advisories
    text = {a["link"]: a["text"] for a in cisa_advisories()}
    real = [{"id": a["id"].upper(), "title": a["title"], "severity": "—", "published": a["published"],
             "provenance": "REAL", "note": f"CISA {'ICS advisory' if a['kind'] == 'ics' else 'alert'} (real, {a['link']})",
             "text": text[a["link"]][:8000]} for a in advisories_matched(db()) if a["matches"]]
    items = real + json.loads(ADVISORIES.read_text(encoding="utf-8"))
    return [{**{k: a[k] for k in ("id", "title", "severity", "published", "provenance", "note", "text")},
             "analysis": _analyse_advisory(a)} for a in items]


@app.post("/api/advisories/analyze")
def analyze_advisory(body: dict) -> dict:
    """Analyse any pasted advisory text against the national inventory (closed-set, evidence-grounded)."""
    import hashlib
    text = (body.get("text") or "").strip()
    if len(text) < 40:
        raise HTTPException(400, "paste the advisory text (at least a sentence or two)")
    adv = {"id": "USER-" + hashlib.sha256(text.encode()).hexdigest()[:10], "title": body.get("title") or "Pasted advisory",
           "provenance": "USER", "text": text[:8000]}
    return _analyse_advisory(adv)


@app.get("/api/alerts/{org_id}/{cve_id}/related")
def related_threats(org_id: str, cve_id: str, k: int = 6) -> dict:
    """Nearest threats by SecureBERT 2.0 embedding of the advisory text, with this organisation's exposure."""
    from .ai.embed import MODEL_ID, related
    conn = db()
    out = []
    for rid, sim in related(cve_id, k):
        v = conn.execute("SELECT id, description, kev FROM vulns WHERE id = ?", (rid,)).fetchone()
        exp = conn.execute("SELECT MAX(risk), MAX(R) FROM assessments WHERE org_id = ? AND cve_id = ?",
                           (org_id, rid)).fetchone()
        out.append({"cve_id": rid, "similarity": sim, "kev": bool(v["kev"] and v["kev"] != "null"),
                    "title": (v["description"] or "")[:140], "org_risk": exp[0], "org_exposed": (exp[1] or 0) >= 0.6})
    return {"model": MODEL_ID, "related": out}


@app.get("/api/campaigns")
def campaigns(limit: int = 12) -> list[dict]:
    """Related threats grouped into campaigns per targeted product (exploited CVEs, chains, decoy surges)."""
    import datetime as _dt
    from .engine.campaigns import build
    conn = db()
    snap = conn.execute("SELECT value FROM meta WHERE key='snapshot_date'").fetchone()[0]
    return build(conn, _dt.date.fromisoformat(snap))[:limit]


_SCORECARD_CACHE: dict = {}


@app.get("/api/scorecard")
def scorecard_view(refresh: bool = False) -> dict:
    """Measured proof: model evals, noise reduction, exposure precision, brief grounding, real KEV backtest."""
    from .engine.scorecard import scorecard
    if refresh or "data" not in _SCORECARD_CACHE:
        _SCORECARD_CACHE["data"] = scorecard(db())
    return _SCORECARD_CACHE["data"]


def _issued_at(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT value FROM meta WHERE key = 'built_at'").fetchone()
    return (row[0] if row else "") + "+05:30"


@app.get("/api/alerts/{org_id}/{cve_id}/workflow")
def workflow_state(org_id: str, cve_id: str) -> dict:
    from .engine import workflow
    conn = db()
    state = workflow.get(conn, f"{org_id}:{cve_id}", _issued_at(conn))
    history = [e for e in Ledger(conn=conn).events(subject=f"{org_id}:{cve_id}") if e["kind"].startswith("analyst.")]
    return {**state, "history": history}


@app.post("/api/alerts/{org_id}/{cve_id}/workflow/{action}")
def workflow_action(org_id: str, cve_id: str, action: str, actor: str = "analyst@ncew", note: str | None = None) -> dict:
    from .engine import workflow
    conn = db()
    try:
        workflow.act(conn, f"{org_id}:{cve_id}", action, actor, note, _issued_at(conn))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return workflow_state(org_id, cve_id)


@app.get("/api/feed")
def feed(limit: int = 6) -> dict:
    """The 'now' view: warnings that need a human, most urgent first, each with its journey state and clock."""
    from .engine import workflow
    conn = db()
    workflow.ensure(conn)
    issued = _issued_at(conn)
    states = {r[0]: r[1] for r in conn.execute("SELECT alert_id, state FROM workflow").fetchall()}
    rows = _alerts(" AND a.tier IN ('Compromise','Critical')", limit=400)
    open_rows = [r for r in rows if states.get(r["id"], "new") != "closed"]
    open_rows.sort(key=lambda r: (-TIER_RANK[r["tier"]], r["deadline_hours"] or 9999, -r["risk"]))
    from . import cache
    cards = []
    for r in open_rows[:limit]:
        cached = cache.latest("brief", r["id"])
        headline = (cached.get("brief") or {}).get("headline") if cached else None
        cards.append({**r, "headline": headline, "workflow": workflow.get(conn, r["id"], issued)})
    counts = {"needs_action": len(open_rows),
              "compromise": sum(r["tier"] == "Compromise" for r in open_rows),
              "closed": sum(1 for s in states.values() if s == "closed")}
    return {"issued_at": issued, "counts": counts, "cards": cards}


@app.get("/api/events/recent")
def recent_events(after_seq: int = 0, limit: int = 30) -> list[dict]:
    """Live ticker: newest ledger events (REAL feeds, SIM telemetry, AI outputs, analyst actions)."""
    conn = db()
    q = ("SELECT seq, ts, kind, subject, source, provenance FROM ledger WHERE seq > ? ORDER BY seq DESC LIMIT ?"
         if after_seq else
         "SELECT seq, ts, kind, subject, source, provenance FROM ledger WHERE seq > ? ORDER BY ts DESC LIMIT ?")
    return [dict(zip(["seq", "ts", "kind", "subject", "source", "provenance"], r))
            for r in conn.execute(q, (after_seq, limit)).fetchall()]


@app.get("/api/stream")
async def stream():
    """Server-sent events: pushes every new ledger entry, so all screens update live without refresh."""
    import asyncio

    from sse_starlette.sse import EventSourceResponse

    async def gen():
        last = db().execute("SELECT COALESCE(MAX(seq), 0) FROM ledger").fetchone()[0]
        while True:
            rows = db().execute("SELECT seq, ts, kind, subject, source, provenance FROM ledger WHERE seq > ? "
                                "ORDER BY seq", (last,)).fetchall()
            for r in rows:
                last = r[0]
                yield {"event": "ledger", "data": json.dumps(dict(zip(
                    ["seq", "ts", "kind", "subject", "source", "provenance"], r)))}
            await asyncio.sleep(1.0)

    return EventSourceResponse(gen(), ping=15)


@app.get("/api/orgs")
def orgs() -> list[dict]:
    rows = db().execute("""SELECT o.*, COUNT(s.id) AS assets FROM orgs o LEFT JOIN assets s ON s.org_id = o.id
                           GROUP BY o.id ORDER BY o.sector, o.id""").fetchall()
    return [dict(r) for r in rows]


@app.get("/api/ledger/verify")
def ledger_verify() -> dict:
    conn = db()
    ok, bad = Ledger(conn=conn).verify()
    n = conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
    head = conn.execute("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
    return {"intact": ok, "first_bad_seq": bad, "events": n, "head": head[0] if head else None}


# ---------------------------------------------------------------- proactive layer: autopilot, human in the loop
def _events(where: str, args: tuple, limit: int) -> list[dict]:
    rows = db().execute(f"""SELECT seq, ts, kind, subject, source, provenance, payload FROM ledger
                            WHERE (kind LIKE 'auto.%' OR kind IN ('analyst.approve', 'analyst.reject')) {where}
                            ORDER BY ts DESC, seq DESC LIMIT ?""", (*args, limit)).fetchall()
    return [{**{k: r[k] for k in ("seq", "ts", "kind", "subject", "source", "provenance")},
             "payload": json.loads(r["payload"])} for r in rows]


@app.get("/api/autopilot")
def autopilot(limit: int = 200, org_id: str | None = None, kind: str | None = None) -> dict:
    """Everything Odyssey did without being asked (and every human decision on its proposals), newest first."""
    from .engine.sentinel import summary
    where, args = "", ()
    if org_id:
        where, args = "AND json_extract(payload, '$.org_id') = ?", (org_id,)
    if kind:
        where, args = where + " AND kind = ?", (*args, kind)
    return {"summary": summary(db()), "events": _events(where, args, limit)}


@app.get("/api/approvals")
def approvals(status: str = "pending", limit: int = 50) -> list[dict]:
    rows = db().execute("""SELECT id, proposed_at, kind, subject, org_id, title, payload, status, decided_by,
                                  decided_at, note FROM approvals WHERE status = ? ORDER BY proposed_at DESC LIMIT ?""",
                        (status, limit)).fetchall()
    out = []
    for r in rows:
        p = json.loads(r["payload"])
        acts = p.get("actions", [])
        out.append({**{k: r[k] for k in ("id", "proposed_at", "kind", "subject", "org_id", "title", "status",
                                          "decided_by", "decided_at", "note")},
                    "orgs": p.get("orgs", []), "count": p.get("count"), "basis": p.get("basis"),
                    "provenance": p.get("provenance"), "p": p.get("p"),
                    "preview": [a["payload"].get("title") for a in acts][:3],
                    "items": (acts[0]["payload"].get("items") or [])[:6] if acts else [],
                    "recipients": sorted({x for a in acts for x in a["payload"].get("recipients", [])}),
                    "langs": sorted({a["payload"]["lang"] for a in acts if a["payload"].get("lang")})})
    return out


@app.post("/api/approvals/{approval_id}/{decision}")
def decide_approval(approval_id: int, decision: str, actor: str = "analyst@ncew", note: str | None = None) -> dict:
    """Human in the loop: approve executes the grouped actions now; reject records the reason for calibration."""
    from .engine.sentinel import decide
    if decision not in ("approve", "reject"):
        raise HTTPException(400, "decision must be approve or reject")
    try:
        return decide(db(), approval_id, decision == "approve", actor, note)
    except KeyError as exc:
        raise HTTPException(404, "unknown proposal") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/forecast")
def forecast_view(days: int = 45, limit: int = 40) -> dict:
    """Ahead of the threat: recent CVEs the day-0 model flags, affecting exposed assets, with what happened next."""
    import datetime as _dt
    conn = db()
    snap = conn.execute("SELECT value FROM meta WHERE key = 'snapshot_date'").fetchone()[0]
    since = (_dt.date.fromisoformat(snap) - _dt.timedelta(days=days)).isoformat()
    rows = conn.execute("""SELECT v.id, v.published, v.kev, substr(v.description, 1, 220) AS description,
                                  json_extract(v.record, '$.forecast') AS fc,
                                  COUNT(DISTINCT a.org_id) AS orgs, COUNT(DISTINCT a.asset_id) AS assets,
                                  GROUP_CONCAT(DISTINCT a.org_id) AS org_ids, MIN(a.asset_id) AS first_asset
                           FROM vulns v JOIN assessments a ON a.cve_id = v.id AND a.R > 0
                           WHERE json_extract(v.record, '$.forecast.flag') = 1 AND v.published >= ?
                           GROUP BY v.id ORDER BY v.published DESC""", (since,)).fetchall()
    items = []
    for r in rows:
        fc = json.loads(r["fc"])
        kev = json.loads(r["kev"]) if r["kev"] not in (None, "null") else None
        label = conn.execute("SELECT label FROM assets WHERE id = ?", (r["first_asset"],)).fetchone()
        items.append({"cve": r["id"], "published": r["published"], "product": label[0] if label else None,
                      "p": fc["p"], "reasons": fc.get("reasons", []),
                      "median_days_to_exploit": fc.get("median_days_to_exploit"), "orgs": r["orgs"],
                      "assets": r["assets"], "org_ids": sorted((r["org_ids"] or "").split(",")),
                      "description": r["description"], "kev_added": kev["dateAdded"] if kev else None})
    meta = json.loads((conn.execute("SELECT value FROM meta WHERE key = 'sentinel'").fetchone() or ["{}"])[0])
    from .engine.scorecard import _read
    ev = _read("eval_exploit_forecast.json") or {}
    return {"since": since, "flagged": len(items), "since_exploited": sum(1 for i in items if i["kev_added"]),
            "items": items[:limit], "lead": meta.get("lead"),
            "model": {"threshold": ev.get("threshold"), "features": ev.get("features"), "live": ev.get("live"),
                      "test": ev.get("test")}}


@app.get("/api/riskplan")
def riskplan(org_id: str | None = None, limit: int = 25) -> dict:
    from .engine.riskplan import plan
    return plan(db(), org_id, limit)


@app.get("/api/intel/sources")
def intel_sources() -> list[dict]:
    from .engine.intel import sources
    return sources(db(), scoring_config()[0])


@app.get("/api/intel/advisories")
def intel_advisories() -> list[dict]:
    from .engine.intel import advisories_matched
    return advisories_matched(db())


@app.get("/api/intel/technologies")
def intel_technologies() -> list[dict]:
    """Affected technologies across the constituency (dashboard: active threats by technology)."""
    import datetime as _dt

    from .engine.campaigns import build
    from .engine.intel import technologies
    conn = db()
    snap = conn.execute("SELECT value FROM meta WHERE key='snapshot_date'").fetchone()[0]
    return technologies(conn, build(conn, _dt.date.fromisoformat(snap)))


@app.get("/api/intel/attacks")
def intel_attacks() -> dict:
    """Real global attack telemetry (SANS ISC DShield) next to the national decoy grid (SIM)."""
    from .engine.intel import PORTS, dshield, port_trend
    conn = db()
    ports = sorted({p for ps in PORTS.values() for p in ps})
    decoy = [dict(r) for r in conn.execute("SELECT date, tag, sessions, unique_ips FROM decoy_daily ORDER BY date")]
    surges = [dict(r) for r in conn.execute("SELECT * FROM decoy_surges")]
    ds = dshield()
    return {"dshield": {"top_ports": ds["top_ports"][:12], "top_sources": ds["top_sources"][:10],
                        "trends": [t for p in ports if (t := port_trend(p))]},
            "decoy": {"daily": decoy, "surges": surges}}


@app.get("/api/orgs/{org_id}/profile")
def org_profile(org_id: str) -> dict:
    """Organisation-based view: OSINT exposure, threat activity, risk plan, and everything Odyssey sent them."""
    from .engine.intel import org_osint
    from .engine.riskplan import plan
    conn = db()
    try:
        osint = org_osint(conn, org_id)
    except KeyError as exc:
        raise HTTPException(404, "unknown organisation") from exc
    s = scoring_config()[0]["sentinel"]
    lang = s["state_language"].get(osint["org"]["state"], "hi")
    tiers = dict(conn.execute("""SELECT tier, COUNT(DISTINCT cve_id) FROM assessments WHERE org_id = ? AND R > 0
                                 GROUP BY tier""", (org_id,)).fetchall())
    return {**osint, "language": lang, "csirt": s["sector_csirt"].get(osint["org"]["sector"]), "tiers": tiers,
            "alerts": _alerts(" AND a.org_id = ? AND a.tier IN ('Compromise','Critical','High')", (org_id,), limit=8),
            "risk": plan(conn, org_id, 8),
            "inbox": _events("AND json_extract(payload, '$.org_id') = ? AND kind != 'auto.proposed'", (org_id,), 40)}


@app.get("/api/soc")
def soc() -> dict:
    """One-screen SOC picture: posture, intake, autonomy, the human queue and the risk headline."""
    from .engine.riskplan import plan
    from .engine.sentinel import summary
    conn = db()
    meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    rp = plan(conn, None, 5)
    worst = conn.execute("""SELECT org_id, cve_id, MAX(CASE tier WHEN 'Compromise' THEN 4 WHEN 'Critical' THEN 3
                            WHEN 'High' THEN 2 WHEN 'Medium' THEN 1 ELSE 0 END) FROM assessments WHERE R > 0
                            GROUP BY org_id, cve_id""").fetchall()
    names = {4: "Compromise", 3: "Critical", 2: "High", 1: "Medium"}
    tiers: dict[str, int] = {}
    for _, _, t in worst:
        if t in names:
            tiers[names[t]] = tiers.get(names[t], 0) + 1
    orgs_rows = conn.execute("""SELECT o.id, o.name, o.sector, o.state,
                                COUNT(DISTINCT CASE WHEN a.tier IN ('Compromise','Critical') THEN a.cve_id END) AS critical,
                                COUNT(DISTINCT CASE WHEN a.tier = 'Compromise' THEN a.cve_id END) AS compromise
                                FROM orgs o LEFT JOIN assessments a ON a.org_id = o.id AND a.R > 0
                                GROUP BY o.id ORDER BY compromise DESC, critical DESC""").fetchall()
    lang = scoring_config()[0]["sentinel"]["state_language"]
    return {"built_at": meta.get("built_at"), "tiers": tiers, "pressure": json.loads(meta.get("pressure", "[]")),
            "autopilot": summary(conn),
            "pending": conn.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0],
            "risk": {k: rp[k] for k in ("total_risk", "tickets", "for_50_pct", "for_80_pct", "assets_at_risk")},
            "orgs": [{**dict(r), "lang": lang.get(r["state"], "hi")} for r in orgs_rows]}


_TESTS: dict = {}


@app.post("/api/tests/run")
def tests_run() -> dict:
    """Run the test bench now: engine tests, detection checks with negative controls, audit-trail integrity."""
    from .engine.testbench import run
    _TESTS["last"] = run(db())
    (ROOT / "data" / "testbench_last.json").write_text(json.dumps(_TESTS["last"]), encoding="utf-8")
    return _TESTS["last"]


@app.get("/api/tests/last")
def tests_last() -> dict:
    saved = ROOT / "data" / "testbench_last.json"  # survives API restarts
    if "last" not in _TESTS and saved.exists():
        _TESTS["last"] = json.loads(saved.read_text(encoding="utf-8"))
    return _TESTS.get("last") or {"ran_at": None, "results": []}


COPILOT_VERSION = "copilot-v7"  # tool chosen by the model; entities resolved deterministically; loop-safe decoding


@app.post("/api/copilot")
def copilot(body: dict) -> dict:
    """Analyst copilot: plain-language question -> one read-only tool -> numbered facts -> grounded, validated answer
    (optionally delivered in an Indian language through the validated translation path)."""
    import sys
    from datetime import datetime, timezone

    import httpx

    from . import cache
    from .ai.copilot import ask, protected_terms
    question = (body.get("question") or "").strip()[:500]
    lang = body.get("lang") or "en"
    if len(question) < 4:
        raise HTTPException(400, "ask a question")
    conn = db()
    built = conn.execute("SELECT value FROM meta WHERE key = 'built_at'").fetchone()[0]
    key = cache.key_of("copilot", COPILOT_VERSION, built, question)
    result = cache.get("copilot", key)
    if result:
        result = {**result, "cached": True}
    else:
        result = {**ask(conn, question, sys.modules[__name__]), "cached": False}
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        Ledger(conn=conn).append(ts=now, kind="model.output", subject="copilot", source=f"MODEL:{result['model']}",
                                 provenance="AI", payload={"role": "copilot", "question": question,
                                                           "tool": result["route"].get("tool"), "status": result["status"]})
        cache.put("copilot", key, result, now, question[:80])
    if lang != "en" and result.get("answer"):
        a = result["answer"]
        texts = [a["answer"]] + [p["text"] for p in a["points"]]
        protect = protected_terms(result) + [r[0] for r in conn.execute("SELECT name FROM orgs").fetchall()]
        try:
            r = httpx.post(f"{MT_URL}/translate", json={"texts": texts, "lang": lang, "protect": protect}, timeout=300)
            r.raise_for_status()
            result["translation"] = {"lang": lang, **{k: r.json()[k] for k in ("model", "rtl", "results")}}
        except httpx.HTTPError as exc:
            result["translation"] = {"lang": lang, "error": str(exc)}
    return result
