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


def _actions(vuln: dict, kev: dict | None, record: dict) -> list[dict]:
    """Deterministic, sourced actions. The LLM never invents these; it may only explain them."""
    actions = []
    fixed = sorted({v["version"] for e in record.get("cna_affected", []) for v in e.get("versions", [])
                    if v.get("status") == "unaffected"})
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
            "cvss_source": v["cvss_source"], "nvd_status": v["nvd_status"]}
    timeline = Ledger(conn=conn).events(subject=cve_id)
    return {"org": dict(o), "vulnerability": vuln, "assets": assets, "actions": _actions(vuln, kev, record),
            "timeline": timeline, "scoring_config_hash": scoring_config()[1]}


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
    led = Ledger(conn=conn)
    labels = {
        "decoy.surge": lambda p: f"Decoy grid: scanning surge on {p['tag']} (z={p['z_sessions']}, {p['sensors']} sensors)",
        "vuln.published": lambda p: f"CVE published by the vendor (CNA), CVSS vector {p.get('cvss_vector') or 'n/a'}",
        "ssvc.updated": lambda p: f"CISA SSVC: Exploitation={p.get('Exploitation')}, Automatable={p.get('Automatable')}",
        "kev.added": lambda p: f"Added to CISA KEV (due {p.get('dueDate')})",
        "decoy.exploit": lambda p: f"Decoy grid: exploit payloads for {cve_id} on {p['sensors']} sensors",
        "ioc.sighting": lambda p: (f"Firewall logs: {p['connections']} beacons every ~{p['mean_interval_s']}s from "
                                   f"{asset['hostname']} to {p['dst_defanged']} ({p['malware']} C2, {p['c2_source']})"),
    }
    events = []
    for ev in (led.events(subject=cve_id) + led.events(subject=f"product:{asset['product_key']}", kind="decoy.surge")
               + led.events(subject=asset["id"], kind="ioc.sighting")):
        if ev["kind"] in labels:
            events.append({**ev, "label": labels[ev["kind"]](ev["payload"])})
    steps = replay(rec, asset, org, events)
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


@app.get("/api/alerts/{org_id}/{cve_id}/brief/translate")
def brief_translate(org_id: str, cve_id: str, lang: str = "hi") -> dict:
    """Hindi/Marathi version of the *validated* brief via the local IndicTrans2 service. Protected identifiers
    are preserved and every sentence is validated; failures are withheld, never guessed."""
    import httpx
    from datetime import datetime, timezone

    from . import cache

    if lang not in {"hi", "mr"}:
        raise HTTPException(400, "lang must be hi or mr")
    conn = db()
    brief = alert_brief(org_id, cve_id)
    if not brief.get("brief"):
        raise HTTPException(409, "no validated English brief to translate")
    b = brief["brief"]
    texts = [b["headline"]] + [x["text"] for x in b["why_it_matters"]] + [x["text"] for x in b["what_to_do"]]
    detail = alert_detail(org_id, cve_id)
    protect = sorted({a["label"] for a in detail["assets"]} | {detail["org"]["name"]})
    key = cache.key_of("translate", lang, texts, protect)
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
    body = {"lang": lang, "model": out["model"], "seconds": out["seconds"],
            "headline": res[0], "why_it_matters": res[1:1 + n_why], "what_to_do": res[1 + n_why:],
            "validated": sum(x["status"] == "validated" for x in res), "total": len(res)}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    Ledger(conn=conn).append(ts=now, kind="model.output", subject=f"{org_id}:{cve_id}", source=f"MODEL:{out['model']}",
                             provenance="AI", payload={"role": "translate", "lang": lang,
                                                       "validated": body["validated"], "total": body["total"]})
    cache.put("translate", key, body, now, f"{org_id}:{cve_id}:{lang}")
    return {**body, "cached": False}


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
