"""SOC system: cases, owners, SLAs, playbooks, notes and metrics on top of Odyssey's warnings.

A case is the unit a SOC works: Odyssey opens one per suspected compromise (incident response) and one per
known-exploited Critical exposure (remediation; one per organisation x product x installed version, matching the
risk plan's change ticket). Each case links its warnings, gets an owner by rule (IR lead for incidents, L2 for
internet-facing known-exploited, L1 otherwise), an SLA from the warnings' deadlines, and a playbook checklist.
Every assignment, status change, checklist step and note is appended to the hash-chained audit trail, so MTTA,
MTTR and SLA compliance are measured from what analysts actually did, never assumed.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3

from .ledger import Ledger

SCHEMA = """CREATE TABLE IF NOT EXISTS soc_cases (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL, org_id TEXT NOT NULL, severity TEXT NOT NULL,
    status TEXT NOT NULL, owner TEXT, created_at TEXT NOT NULL, due_at TEXT, acknowledged_at TEXT, resolved_at TEXT,
    alerts TEXT NOT NULL, playbook TEXT NOT NULL, notes TEXT NOT NULL, product TEXT, assets TEXT)"""

ROSTER = [
    {"id": "m.khan", "name": "Mohammed Khan", "role": "Incident response lead"},
    {"id": "s.iyer", "name": "Sneha Iyer", "role": "L2 analyst"},
    {"id": "a.rao", "name": "Ananya Rao", "role": "L1 analyst"},
    {"id": "r.das", "name": "Rohit Das", "role": "L1 analyst"},
    {"id": "analyst@ncew", "name": "You", "role": "Analyst on duty"},
]
PLAYBOOKS = {
    "incident": [
        "Isolate the affected host from the network (keep it powered for forensics)",
        "Preserve evidence: memory capture, disk image, device and VPN logs",
        "Block the C2 indicators at the perimeter and in DNS",
        "Report to CERT-In within 6 hours (draft is pre-filled)",
        "Hunt for lateral movement from the host since the first beacon",
        "Rotate credentials and session secrets that touched the device",
        "Eradicate: rebuild or factory-reset, then patch to the fixed release",
        "Recover and monitor for 14 days; close with lessons learned",
    ],
    "vuln": [
        "Confirm the installed version on every listed host",
        "Apply the vendor fix (or the compensating control if patching must wait)",
        "Hunt for exploitation indicators since the CVE was published",
        "Verify the fixed version is running and the exposure is gone",
        "Close with evidence attached",
    ],
}
FLOW = {  # kind -> status -> (next status, button label)
    "incident": {"new": ("in_progress", "Start response"), "in_progress": ("contained", "Mark contained"),
                 "contained": ("resolved", "Close incident")},
    "vuln": {"new": ("in_progress", "Start remediation"), "in_progress": ("resolved", "Mark patched and close")},
}
_SEV = {"Compromise": 0, "Critical": 1, "High": 2, "Medium": 3}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def ensure(conn: sqlite3.Connection) -> None:
    conn.execute(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM soc_cases").fetchone()[0] == 0:
        seed(conn)


def seed(conn: sqlite3.Connection) -> None:
    """Open cases from the current state: incidents for compromised assets, remediation cases for known-exploited
    Critical exposures (one per organisation x product x version)."""
    from .riskplan import plan
    built = conn.execute("SELECT value FROM meta WHERE key = 'built_at'").fetchone()[0]
    created = dt.datetime.fromisoformat(built).replace(tzinfo=dt.timezone(dt.timedelta(hours=5, minutes=30)))
    rows, n = [], 0
    comp = conn.execute("""SELECT a.asset_id, a.org_id, s.hostname, s.label, GROUP_CONCAT(a.cve_id)
                           FROM assessments a JOIN assets s ON s.id = a.asset_id
                           WHERE a.tier = 'Compromise' GROUP BY a.asset_id""").fetchall()
    for asset_id, org_id, host, label, cves in comp:
        n += 1
        alerts = [f"{org_id}:{c}" for c in sorted(set(cves.split(",")))]
        rows.append((f"CASE-{n:04d}", "incident", f"Suspected compromise of {host} ({label})", org_id, "Compromise",
                     "new", "m.khan", _iso(created), _iso(created + dt.timedelta(hours=6)), alerts, label, [host]))
    for t in plan(conn, None, 2000)["plan"]:
        if t["top_tier"] == "Compromise" or not t["kev_cves"] or t["top_tier"] != "Critical":
            continue
        n += 1
        owner = "s.iyer" if "internet" in t["zones"] else ("a.rao", "r.das", None)[n % 3]
        alerts = [f"{t['org_id']}:{c}" for c in t["cves"]]
        due = created + dt.timedelta(hours=t["deadline_hours"] or 72)
        rows.append((f"CASE-{n:04d}", "vuln", f"Patch known-exploited {t['label']} {t['version']}",
                     t["org_id"], "Critical", "new", owner, _iso(created), _iso(due), alerts, t["label"], t["assets"]))
    for cid, kind, title, org_id, sev, status, owner, c_at, due, alerts, product, assets in rows:
        playbook = [{"step": s, "done": False, "by": None, "at": None} for s in PLAYBOOKS[kind]]
        conn.execute("INSERT INTO soc_cases (id, kind, title, org_id, severity, status, owner, created_at, due_at, "
                     "alerts, playbook, notes, product, assets) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (cid, kind, title, org_id, sev, status, owner, c_at, due, json.dumps(alerts),
                      json.dumps(playbook), json.dumps([{"ts": c_at, "by": "Odyssey", "text":
                                                         "Case opened automatically from Odyssey's warnings."}]),
                      product, json.dumps(assets)))
    conn.commit()


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("alerts", "playbook", "notes", "assets"):
        d[k] = json.loads(d[k] or "[]")
    flow = FLOW[d["kind"]].get(d["status"])
    d["next"] = {"status": flow[0], "label": flow[1]} if flow else None
    d["overdue"] = bool(d["due_at"] and d["status"] not in ("resolved", "false_positive")
                        and dt.datetime.fromisoformat(d["due_at"]) < dt.datetime.now(dt.timezone.utc))
    done = sum(1 for s in d["playbook"] if s["done"])
    d["progress"] = {"done": done, "total": len(d["playbook"])}
    return d


def _org_names(conn: sqlite3.Connection) -> dict[str, str]:
    return {r[0]: r[1] for r in conn.execute("SELECT id, name FROM orgs").fetchall()}


def cases(conn: sqlite3.Connection, status: str | None = None, owner: str | None = None) -> list[dict]:
    ensure(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    names = _org_names(conn)
    out = [{**_row(r), "org_name": names.get(r["org_id"], r["org_id"])} for r in cur.execute("SELECT * FROM soc_cases").fetchall()]
    if status == "open":
        out = [c for c in out if c["status"] not in ("resolved", "false_positive")]
    elif status:
        out = [c for c in out if c["status"] == status]
    if owner == "unassigned":
        out = [c for c in out if not c["owner"]]
    elif owner:
        out = [c for c in out if c["owner"] == owner]
    out.sort(key=lambda c: (c["status"] in ("resolved", "false_positive"), _SEV.get(c["severity"], 9),
                            not c["overdue"], c["due_at"] or ""))
    return out


def get(conn: sqlite3.Connection, case_id: str) -> dict:
    ensure(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    r = cur.execute("SELECT * FROM soc_cases WHERE id = ?", (case_id,)).fetchone()
    if not r:
        raise KeyError(case_id)
    return {**_row(r), "org_name": _org_names(conn).get(r["org_id"], r["org_id"])}


def _log(conn, case: dict, actor: str, what: str, payload: dict) -> None:
    Ledger(conn=conn).append(ts=_now(), kind=f"analyst.case_{what}", subject=case["id"], source="ANALYST",
                             provenance="HUMAN", payload={"actor": actor, "org_id": case["org_id"], **payload})


def assign(conn, case_id: str, owner: str | None, actor: str) -> dict:
    c = get(conn, case_id)
    if owner and owner not in {a["id"] for a in ROSTER}:
        raise ValueError(f"unknown analyst {owner}")
    conn.execute("UPDATE soc_cases SET owner = ? WHERE id = ?", (owner, case_id))
    _note(conn, c, actor, f"Assigned to {_name(owner)}.")
    _log(conn, c, actor, "assign", {"from": c["owner"], "to": owner})
    conn.commit()
    return get(conn, case_id)


def advance(conn, case_id: str, actor: str, to: str | None = None) -> dict:
    """Move a case along its flow (or to 'false_positive' / back to 'in_progress' when reopening)."""
    c = get(conn, case_id)
    target = to or (c["next"] or {}).get("status")
    allowed = {c["next"]["status"]} if c["next"] else set()
    allowed |= {"false_positive"} if c["status"] not in ("resolved", "false_positive") else {"in_progress"}
    if target not in allowed:
        raise ValueError(f"cannot move {c['status']} -> {target}")
    now = _now()
    ack = c["acknowledged_at"] or (now if c["status"] == "new" else None)
    resolved = now if target in ("resolved", "false_positive") else None
    conn.execute("UPDATE soc_cases SET status = ?, acknowledged_at = ?, resolved_at = ?, owner = COALESCE(owner, ?) "
                 "WHERE id = ?", (target, ack, resolved, actor, case_id))
    _note(conn, c, actor, f"Status: {c['status'].replace('_', ' ')} -> {target.replace('_', ' ')}.")
    _log(conn, c, actor, "status", {"from": c["status"], "to": target})
    conn.commit()
    return get(conn, case_id)


def step(conn, case_id: str, index: int, done: bool, actor: str) -> dict:
    c = get(conn, case_id)
    pb = c["playbook"]
    if not 0 <= index < len(pb):
        raise ValueError("no such playbook step")
    pb[index] = {**pb[index], "done": done, "by": actor if done else None, "at": _now() if done else None}
    ack = c["acknowledged_at"] or _now()
    status = "in_progress" if c["status"] == "new" else c["status"]
    conn.execute("UPDATE soc_cases SET playbook = ?, acknowledged_at = ?, status = ? WHERE id = ?",
                 (json.dumps(pb), ack, status, case_id))
    _log(conn, c, actor, "step", {"step": pb[index]["step"], "done": done})
    conn.commit()
    return get(conn, case_id)


def _note(conn, c: dict, actor: str, text: str) -> None:
    notes = c["notes"] + [{"ts": _now(), "by": _name(actor), "text": text}]
    conn.execute("UPDATE soc_cases SET notes = ? WHERE id = ?", (json.dumps(notes), c["id"]))
    c["notes"] = notes


def note(conn, case_id: str, text: str, actor: str) -> dict:
    c = get(conn, case_id)
    _note(conn, c, actor, text.strip()[:2000])
    _log(conn, c, actor, "note", {"chars": len(text)})
    conn.commit()
    return get(conn, case_id)


def _name(owner: str | None) -> str:
    return next((a["name"] for a in ROSTER if a["id"] == owner), owner or "nobody")


def metrics(conn: sqlite3.Connection) -> dict:
    all_cases = cases(conn)
    open_ = [c for c in all_cases if c["status"] not in ("resolved", "false_positive")]

    def hours(a: str, b: str) -> float:
        return (dt.datetime.fromisoformat(b) - dt.datetime.fromisoformat(a)).total_seconds() / 3600

    acked = [hours(c["created_at"], c["acknowledged_at"]) for c in all_cases if c["acknowledged_at"]]
    closed = [c for c in all_cases if c["resolved_at"]]
    within = [c for c in closed if not c["due_at"] or c["resolved_at"] <= c["due_at"]]
    analysts = []
    for a in ROSTER:
        mine = [c for c in open_ if c["owner"] == a["id"]]
        analysts.append({**a, "open": len(mine), "overdue": sum(c["overdue"] for c in mine),
                         "incidents": sum(c["kind"] == "incident" for c in mine)})
    return {
        "open": len(open_), "incidents": sum(c["kind"] == "incident" for c in open_),
        "overdue": sum(c["overdue"] for c in open_), "unassigned": sum(1 for c in open_ if not c["owner"]),
        "resolved": len(closed),
        "mtta_h": round(sum(acked) / len(acked), 2) if acked else None,
        "mttr_h": round(sum(hours(c["created_at"], c["resolved_at"]) for c in closed) / len(closed), 2) if closed else None,
        "sla_pct": round(100 * len(within) / len(closed), 1) if closed else None,
        "by_status": {s: sum(c["status"] == s for c in all_cases) for s in ("new", "in_progress", "contained", "resolved", "false_positive")},
        "analysts": analysts,
    }


def handover(conn: sqlite3.Connection) -> dict:
    """Shift handover: what the next shift must know, generated from cases, decisions and the audit trail."""
    m = metrics(conn)
    top = [c for c in cases(conn, "open")][:5]
    pending = conn.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]
    lines = [
        f"{m['open']} open cases ({m['incidents']} incident response), {m['overdue']} past their SLA, "
        f"{m['unassigned']} without an owner.",
        f"{pending} proposals wait for an analyst's decision (predictions, escalations, advisory notices).",
        "Priorities for the next shift:",
        *[f"  {i + 1}. {c['title']} at {c['org_name']} ({c['severity']}; {'overdue' if c['overdue'] else 'due ' + (c['due_at'] or '-')[:16].replace('T', ' ')}; "
          f"owner {_name(c['owner'])}; playbook {c['progress']['done']}/{c['progress']['total']})" for i, c in enumerate(top)],
    ]
    if m["mtta_h"] is not None:
        lines.append(f"This shift: mean time to acknowledge {m['mtta_h']} h, to resolve {m['mttr_h'] or '-'} h, "
                     f"SLA met on {m['sla_pct'] if m['sla_pct'] is not None else '-'}% of closed cases.")
    return {"generated_at": _now(), "text": "\n".join(lines), "metrics": m}


def open_case(conn: sqlite3.Connection, kind: str, title: str, org_id: str, severity: str, owner: str | None,
              due_hours: float, alerts: list[str], product: str, assets: list[str], note: str) -> dict:
    """A case opened while the system runs (live detection, drill), not at build time. Audited like every other
    case action, so the SOC's metrics include it."""
    ensure(conn)
    n = conn.execute("SELECT COUNT(*) FROM soc_cases").fetchone()[0] + 1
    while conn.execute("SELECT 1 FROM soc_cases WHERE id = ?", (f"CASE-{n:04d}",)).fetchone():
        n += 1
    cid, now = f"CASE-{n:04d}", dt.datetime.now(dt.timezone.utc)
    playbook = [{"step": s, "done": False, "by": None, "at": None} for s in PLAYBOOKS[kind]]
    conn.execute("INSERT INTO soc_cases (id, kind, title, org_id, severity, status, owner, created_at, due_at, alerts, "
                 "playbook, notes, product, assets) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (cid, kind, title, org_id, severity, "new", owner, _iso(now), _iso(now + dt.timedelta(hours=due_hours)),
                  json.dumps(alerts), json.dumps(playbook), json.dumps([{"ts": _iso(now), "by": "Odyssey", "text": note}]),
                  product, json.dumps(assets)))
    Ledger(conn=conn).append(ts=_iso(now), kind="auto.case_opened", subject=cid, source="ODYSSEY", provenance="AUTO",
                             payload={"org_id": org_id, "title": title, "severity": severity, "owner": owner,
                                      "due_hours": due_hours})
    conn.commit()
    return get(conn, cid)
