"""Step-by-step decision support for one warning (organisation x CVE), human in the loop by construction.

brief():   the evidence (what is known, from which source), the clocks that apply, the options open to the analyst
           with the one Odyssey recommends and why, and who an escalation goes to.
execute(): the analyst's choice carried out through the engine's own mechanisms and nothing else: the decision in
           the hash-chained audit trail, the warning's workflow moved, a SOC case opened or advanced with the
           playbook, an escalation recorded and routed to the channels, a notice to the organisation in its own
           language. Every step is returned with its reference, so the analyst sees exactly what happened.
Nothing here runs until a person chooses; the recommendation is advice, never an action.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3

from . import soc, workflow
from .ledger import Ledger

EXPLOIT_RULES = {"KEV", "SSVC_ACTIVE", "DECOY_EXPLOIT", "ITW_CLAIM"}
SEV_OK = {"Compromise", "Critical", "High", "Medium"}
TRANSITIONS = {"patch": ["acknowledge", "start"], "mitigate": ["acknowledge", "start"], "hunt": ["acknowledge", "start"],
               "escalate": ["acknowledge"], "verify": ["acknowledge"], "accept_risk": ["accept_risk"], "false_positive": ["false_positive"]}
LABEL = {"patch": "Patch", "mitigate": "Mitigate", "hunt": "Hunt", "escalate": "Escalate", "verify": "Verify first",
         "accept_risk": "Accept the risk", "false_positive": "Close as not affected"}


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def escalation_targets(cfg: dict, org: dict, tier: str, exploited: bool) -> list[dict]:
    s = cfg["sentinel"]
    out = []
    if tier == "Compromise":
        out.append({"to": "CERT-In", "why": "suspected compromise: incident report within 6 hours (Directions, 28 Apr 2022)", "default": True})
    out.append({"to": s["sector_csirt"].get(org.get("sector", ""), "CERT-In"), "why": "the sector CSIRT coordinates the sector's response",
                "default": tier in ("Compromise", "Critical")})
    if org.get("cii"):
        out.append({"to": "NCIIPC", "why": "the organisation is notified critical information infrastructure", "default": tier == "Compromise"})
    if tier == "Critical" and exploited and not any(t["to"] == "CERT-In" for t in out):
        out.append({"to": "CERT-In", "why": "known-exploited Critical exposure on national infrastructure", "default": False})
    seen, uniq = set(), []
    for t in out:
        if t["to"] not in seen:
            seen.add(t["to"])
            uniq.append(t)
    return uniq


def _open_case_for(conn: sqlite3.Connection, alert_id: str) -> dict | None:
    for c in soc.cases(conn, "open"):
        if alert_id in c.get("alerts", []):
            return c
    return None


def brief(conn: sqlite3.Connection, cfg: dict, detail: dict, issued_at: str, live: dict | None = None) -> dict:
    org, v = detail["org"], detail["vulnerability"]
    assets = detail["assets"]
    if not assets:
        raise KeyError("no assessment for this organisation and CVE")
    a = assets[0]
    alert_id = f"{org['id']}:{v['id']}"
    tier, rules = a["tier"], a.get("rules", [])
    exploited = bool(v.get("kev")) or (v.get("ssvc") or {}).get("Exploitation") == "active" or any(r.get("id") in EXPLOIT_RULES for r in rules)
    exposure = (a.get("exposure") or {}).get("status", "unknown")
    fixed = [x for x in detail.get("actions", []) if x["type"] == "patch" and "fixed release" in x["step"]]
    kev_step = [x for x in detail.get("actions", []) if x.get("source") == "CISA KEV requiredAction"]
    wf = workflow.get(conn, alert_id, issued_at)
    case = _open_case_for(conn, alert_id)
    pending = [dict(r) for r in conn.execute("SELECT id, kind, title, proposed_at FROM approvals WHERE status = 'pending' AND "
                                             "(subject = ? OR json_extract(payload, '$.cve_id') = ?) ORDER BY proposed_at DESC",
                                             (alert_id, v["id"])).fetchall()] if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name = 'approvals'").fetchone() else []
    hosts = {x["hostname"] for x in assets}
    live_hits = [d for d in ((live or {}).get("detections") or []) if d.get("org_id") == org["id"] or d.get("asset") in hosts][:6]

    evidence = [
        {"label": "Tier and risk", "value": f"{tier} · risk {a['risk']:.0f} of 100", "source": "Odyssey scoring (config/scoring.json)", "provenance": "REAL+SIM"},
        {"label": "SSVC decision", "value": f"{a.get('decision')} · {' · '.join((a.get('decision_path') or [])[:3])}", "source": "CISA SSVC tree", "provenance": "REAL"},
        {"label": "Exposure", "value": f"{exposure.replace('_', ' ')} · {len(assets)} asset{'s' if len(assets) != 1 else ''}: "
                                        + ", ".join(f"{x['hostname'].split('.')[0]} {x['version']} ({x['zone']})" for x in assets[:4]),
         "source": "installed versions against NVD, CNA and advisory text", "provenance": "SIM inventory · REAL records"},
    ]
    for r in rules[:6]:
        evidence.append({"label": r.get("id", "rule"), "value": r.get("text", ""), "detail": r.get("evidence"), "source": r.get("source"), "provenance": "REAL"})
    if v.get("kev"):
        evidence.append({"label": "CISA KEV", "value": f"listed {v['kev'].get('dateAdded')} · due {v['kev'].get('dueDate')} · ransomware use: {v['kev'].get('knownRansomwareCampaignUse', '?')}",
                         "source": "CISA Known Exploited Vulnerabilities", "provenance": "REAL"})
    if v.get("epss") is not None:
        evidence.append({"label": "EPSS", "value": f"{v['epss']:.3f}", "source": "FIRST EPSS", "provenance": "REAL"})
    fc = v.get("forecast") or {}
    if fc.get("p") is not None:
        evidence.append({"label": "Day-0 forecast", "value": f"{fc['p']:.0%} likely to be exploited{' (flagged)' if fc.get('flag') else ''}", "source": "Odyssey forecast model", "provenance": "REAL (prediction)"})
    if a.get("bayes"):
        evidence.append({"label": "P(compromise)", "value": f"{a['bayes']['p_compromise']:.1%}", "source": "Bayesian compromise model", "provenance": "REAL+SIM"})
    for d in live_hits:
        evidence.append({"label": "Live detection", "value": d.get("title", d.get("kind")), "source": "live engine", "provenance": "SIM sighting"})

    targets = escalation_targets(cfg, org, tier, exploited)
    clocks = a.get("obligations") or []
    deadline = a.get("deadline_hours")
    options = []
    patch_steps = [x["step"] for x in kev_step + fixed] or ["Apply the vendor's fix when it ships; until then mitigate"]
    options.append({"id": "patch", "label": "Patch to a fixed release" if fixed else ("Apply CISA's required action" if kev_step else "Patch when the vendor ships a fix"),
                    "why": f"removes the exposure on {len(assets)} asset{'s' if len(assets) != 1 else ''}" + (f"; deadline {deadline} h ({a.get('deadline_basis', '')})" if deadline else ""),
                    "steps": patch_steps + ["Verify the fixed version is running", "Close with evidence"],
                    "effects": ["workflow: acknowledged, then mitigating", "SOC remediation case with the patch playbook", "notice to the organisation if chosen"],
                    "available": True})
    options.append({"id": "mitigate", "label": "Mitigate now: restrict and block",
                    "why": "when the patch must wait: cut the reachable surface and block the campaign's indicators",
                    "steps": [x["step"] for x in detail.get("actions", []) if x["type"] == "block"] or ["Restrict management and VPN interfaces to trusted networks", "Block the campaign's indicators at the perimeter"],
                    "effects": ["workflow: mitigating", "SOC case with the compensating-control playbook"], "available": True})
    if exploited:
        options.append({"id": "hunt", "label": "Hunt for exploitation since publication",
                        "why": "the vulnerability is exploited in the wild: assume attempts and look for them",
                        "steps": [x["step"] for x in detail.get("actions", []) if x["type"] == "investigate"] or ["Review authentication, web and command logs since publication"],
                        "effects": ["workflow: mitigating", "SOC case with the hunt playbook"], "available": True})
    options.append({"id": "escalate", "label": f"Escalate to {', '.join(t['to'] for t in targets if t['default']) or targets[0]['to']}",
                    "why": "; ".join(t["why"] for t in targets if t["default"]) or targets[0]["why"],
                    "steps": [f"{c['who']}: {c['what']}" + (f" within {c['hours']} h" if c.get("hours") else "") for c in clocks] or ["Notify the sector CSIRT"],
                    "effects": ["escalation in the audit trail", "a card to every configured channel", "the CERT-In report draft is one click away"],
                    "available": True, "targets": targets})
    if exposure != "affected":
        options.append({"id": "verify", "label": "Verify the installed version first",
                        "why": f"the exposure is {exposure.replace('_', ' ')}: confirm on the host before spending the team's time",
                        "steps": ["Confirm the running version on each listed host", "Re-run the assessment"], "effects": ["workflow: acknowledged"], "available": True})
        options.append({"id": "false_positive", "label": "Close: installed version not affected",
                        "why": "the record says the installed version is outside the affected range", "steps": ["Close with the version evidence attached"],
                        "effects": ["workflow: closed (false positive), recorded for calibration"], "available": True})
    options.append({"id": "accept_risk", "label": "Accept the risk for now",
                    "why": "a documented decision with an owner, revisited when the evidence changes",
                    "steps": ["Record the justification", "Set a review date"], "effects": ["workflow: closed (risk accepted), in the audit trail"],
                    "available": tier in ("Medium", "High") and not exploited})
    if tier == "Compromise":
        rec, why = "escalate", "a suspected compromise starts CERT-In's 6-hour clock: contain, preserve evidence and report before anything else"
    elif exposure != "affected" and exposure != "unknown":
        rec, why = "verify", "the installed version is disputed or outside the range: verify before acting"
    elif tier == "Critical" and exploited:
        rec, why = "patch", f"known exploited and {len(assets)} installed version{'s' if len(assets) != 1 else ''} affected: patch within the deadline" + (f" of {deadline} h" if deadline else "")
    elif exploited:
        rec, why = "hunt", "exploited in the wild: hunt for attempts while the patch is scheduled"
    elif tier in ("Critical", "High"):
        rec, why = "patch", "exposed and severe: schedule the fix within its window"
    else:
        rec, why = "patch", "schedule the fix in the next maintenance window"
    for o in options:
        o["recommended"] = o["id"] == rec
    return {"alert": alert_id, "org": {k: org.get(k) for k in ("id", "name", "sector", "state", "cii")}, "cve": v["id"], "tier": tier,
            "risk": a["risk"], "exploited": exploited, "exposure": exposure, "deadline_hours": deadline, "deadline_basis": a.get("deadline_basis"),
            "evidence": evidence, "clocks": clocks, "options": options, "recommended": rec, "recommended_why": why, "targets": targets,
            "workflow": wf, "case": {k: case[k] for k in ("id", "title", "status", "owner", "due_at")} if case else None,
            "pending": pending, "fixed_releases": [x["step"] for x in fixed], "provenance": {"REAL": ["CVE record, KEV, SSVC, EPSS, forecast"], "SIM": ["organisation, assets, sightings"]}}


def execute(conn: sqlite3.Connection, cfg: dict, detail: dict, decision: str, actor: str, note: str | None,
            escalate_to: list[str], notify_org: bool, issued_at: str, now: dt.datetime | None = None) -> dict:
    if decision not in TRANSITIONS:
        raise ValueError(f"unknown decision '{decision}'")
    now = now or dt.datetime.now(dt.timezone.utc)
    org, v = detail["org"], detail["vulnerability"]
    assets = detail["assets"]
    a = assets[0] if assets else {}
    tier = a.get("tier", "High")
    alert_id = f"{org['id']}:{v['id']}"
    label = a.get("label") or "the product"
    ledger = Ledger(conn=conn)
    steps: list[dict] = []
    h = ledger.append(ts=_iso(now), kind="analyst.decision", subject=alert_id, source="ANALYST", provenance="HUMAN",
                      payload={"actor": actor, "decision": decision, "note": note, "org_id": org["id"], "cve_id": v["id"], "tier": tier,
                               "escalate_to": escalate_to, "notify_org": notify_org, "title": f"{LABEL[decision]}: {v['id']} at {org['name']}"})
    conn.commit()
    steps.append({"step": f"Decision recorded: {LABEL[decision]}", "detail": note or "no note", "ref": h[:12], "kind": "ledger"})
    wf = workflow.get(conn, alert_id, issued_at)
    for act in TRANSITIONS[decision]:
        allowed, _target = workflow.TRANSITIONS[act]
        if wf["state"] in allowed:
            wf = workflow.act(conn, alert_id, act, actor, note, issued_at)
            steps.append({"step": f"Warning moved to {wf['state']}", "detail": f"workflow action '{act}'", "kind": "workflow"})
    case = _open_case_for(conn, alert_id)
    if decision in ("patch", "mitigate", "hunt", "escalate", "verify"):
        if case:
            soc.note(conn, case["id"], f"Decision by {actor}: {LABEL[decision]}." + (f" {note}" if note else ""), actor)
            if case["status"] == "new" and decision != "verify":
                case = soc.advance(conn, case["id"], actor)
                steps.append({"step": f"Case {case['id']} started", "detail": case["title"], "kind": "case", "case": case["id"]})
            else:
                steps.append({"step": f"Case {case['id']} noted", "detail": case["title"], "kind": "case", "case": case["id"]})
        elif decision in ("patch", "mitigate", "hunt"):
            sev = tier if tier in SEV_OK else "High"
            kind = "vuln"
            title = {"patch": f"Patch {label} {a.get('version', '')} ({v['id']})", "mitigate": f"Mitigate {v['id']} on {label} (restrict and block)",
                     "hunt": f"Hunt for exploitation of {v['id']} on {label}"}[decision]
            case = soc.open_case(conn, kind, title.strip(), org["id"], sev, actor, float(a.get("deadline_hours") or 72), [alert_id], label,
                                 [x["hostname"] for x in assets], f"Opened by {actor} through the decision support: {LABEL[decision]}." + (f" {note}" if note else ""))
            steps.append({"step": f"Case {case['id']} opened with the {kind} playbook", "detail": case["title"], "kind": "case", "case": case["id"]})
    recipients = list(dict.fromkeys(escalate_to or ([t["to"] for t in escalation_targets(cfg, org, tier, True) if t["default"]] if decision == "escalate" else [])))
    if recipients:
        h2 = ledger.append(ts=_iso(now), kind="analyst.escalate", subject=alert_id, source="ANALYST", provenance="HUMAN",
                           payload={"actor": actor, "org_id": org["id"], "cve_id": v["id"], "tier": tier, "severity": tier if tier in SEV_OK else "High",
                                    "recipients": recipients, "note": note,
                                    "title": f"Escalated by {actor}: {tier} {v['id']} at {org['name']} to {', '.join(recipients)}"})
        conn.commit()
        steps.append({"step": f"Escalated to {', '.join(recipients)}", "detail": "a card goes to every configured channel; the CERT-In report draft is on the warning", "ref": h2[:12], "kind": "escalate"})
    if notify_org and decision in ("patch", "mitigate", "hunt", "escalate"):
        lang = cfg["sentinel"]["state_language"].get(org.get("state", ""), "hi")
        text = {"patch": f"Patch {label} on {len(assets)} asset{'s' if len(assets) != 1 else ''}: {'; '.join(x['step'] for x in detail.get('actions', []) if x['type'] == 'patch')[:300] or 'apply the vendor fix'}",
                "mitigate": "Restrict management and VPN interfaces to trusted networks and block the campaign's indicators until patched",
                "hunt": "Hunt for exploitation indicators since publication: authentication, web and command logs",
                "escalate": f"The warning has been escalated to {', '.join(recipients) or 'the sector CSIRT'}; isolate and preserve evidence"}[decision]
        h3 = ledger.append(ts=_iso(now), kind="analyst.notify", subject=alert_id, source="ANALYST", provenance="HUMAN",
                           payload={"actor": actor, "org_id": org["id"], "cve_id": v["id"], "tier": tier, "severity": tier if tier in SEV_OK else "High",
                                    "lang": lang, "recipients": [f"ciso@{org.get('domain') or org['id'].lower() + '.example'}"], "channels": ["email"],
                                    "title": f"Notice to {org['name']} ({lang}): {v['id']} on {label}: {text}"})
        conn.commit()
        steps.append({"step": f"Notice to {org['name']} in its own language ({lang})", "detail": text[:160], "ref": h3[:12], "kind": "notify"})
    return {"alert": alert_id, "decision": decision, "executed": steps, "workflow": wf,
            "case": {k: case[k] for k in ("id", "title", "status", "owner", "due_at")} if case else None,
            "ts": _iso(now), "audit": "every step above is a hash-chained ledger event; see SOC > Log"}
