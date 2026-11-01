"""Watchlists and alert rules on intelligence-graph entities.

An analyst watches any node of the graph (a technology, a CVE, a C2 address, a threat group, an organisation, an
asset) with a rule: fresh evidence, a worsening tier, a new connection, or any of those. The live engine evaluates
every watch against the current graph every few ticks; when a rule fires the event is written to the hash-chained
ledger (`watch.fired`), so the channels can deliver it and the audit trail keeps it. Rules are edge-triggered: a
watch fires on the change, not on every evaluation while the condition holds.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import sqlite3

from .graph import RANK, intel_graph
from .ledger import Ledger

RULE_KINDS = {
    "any": "fresh evidence, a worsening tier or a new connection",
    "fresh": "fresh evidence (pulse rises above the threshold, or new evidence is recorded)",
    "tier": "the worst open tier reaches the threshold or worse",
    "connect": "a new connection appears in the graph",
}
DEFAULT_RULE = {"kind": "any", "pulse": 0.5, "tier": "Critical"}
SEVERITY = {"Compromise": "Critical", "Critical": "High", "High": "Medium", "Medium": "Low", "Watch": "Low", None: "Low"}


def ensure(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS watches (
            id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, owner TEXT, target TEXT NOT NULL, label TEXT, kind TEXT,
            rule TEXT NOT NULL, note TEXT, status TEXT NOT NULL DEFAULT 'active', last_state TEXT, last_eval TEXT,
            fired INTEGER NOT NULL DEFAULT 0, last_fired TEXT);
        CREATE TABLE IF NOT EXISTS watch_events (
            id INTEGER PRIMARY KEY, ts TEXT NOT NULL, watch_id INTEGER NOT NULL, target TEXT NOT NULL, label TEXT,
            reason TEXT NOT NULL, severity TEXT NOT NULL, payload TEXT NOT NULL);
    """)
    conn.commit()


def _iso(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _focus_for(conn: sqlite3.Connection, target: str) -> str | None:
    """Assets only exist in an organisation's graph: the asset's organisation comes from the inventory, and for an id
    the inventory does not know, from the id convention <org>-<n>-A<nnn>."""
    if not target.startswith("asset:"):
        return None
    aid = target.split(":", 1)[1]
    row = conn.execute("SELECT org_id FROM assets WHERE id = ?", (aid,)).fetchone()
    return (row[0] if row else None) or "-".join(aid.split("-")[:2])


def _clean_rule(rule: dict | None) -> dict:
    """An analyst's rule, validated: a malformed one would otherwise be stored and make every later evaluation fail."""
    if rule is None:
        rule = {}
    if not isinstance(rule, dict):
        raise ValueError("rule must be an object: {kind, pulse, tier}")
    rule = {**DEFAULT_RULE, **rule}
    if not isinstance(rule["kind"], str) or rule["kind"] not in RULE_KINDS:
        raise ValueError(f"unknown rule kind {rule['kind']!r}")
    if not isinstance(rule.get("tier"), str) or rule["tier"] not in RANK:
        raise ValueError("rule.tier must be one of Compromise, Critical, High, Medium, Watch")
    pulse = rule.get("pulse")
    if isinstance(pulse, bool) or not isinstance(pulse, (int, float)) or not math.isfinite(pulse) or not 0 <= pulse <= 1:
        raise ValueError("rule.pulse must be a number between 0 and 1")
    return rule


def _find(conn, target: str, live: dict | None, now: dt.datetime | None = None) -> dict | None:
    g = intel_graph(conn, _focus_for(conn, target), live, now=now)
    return next((n for n in g["nodes"] if n["id"] == target), None), g


def _state(node: dict, g: dict) -> dict:
    nbrs = sorted({e["to"] if e["from"] == node["id"] else e["from"] for e in g["edges"] if node["id"] in (e["from"], e["to"])})
    return {"pulse": node["pulse"], "tier": node["tier"], "last_seen": node["last_seen"], "degree": len(nbrs), "neighbours": nbrs[:300],
            "risk": node["risk"]}


def add(conn: sqlite3.Connection, target: str, rule: dict | None = None, owner: str | None = None, label: str | None = None,
        note: str | None = None, live: dict | None = None, now: dt.datetime | None = None) -> dict:
    ensure(conn)
    now = now or dt.datetime.now(dt.timezone.utc)
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a graph node id, such as product:fortios or cve:CVE-2026-1234")
    for name, value in (("owner", owner), ("label", label), ("note", note)):
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{name} must be text")
    rule = _clean_rule(rule)
    found = _find(conn, target, live, now=None)
    node = found[0] if found else None
    if node is None:
        raise KeyError(target)
    state = _state(node, found[1])
    cur = conn.execute("INSERT INTO watches (created_at, owner, target, label, kind, rule, note, last_state, last_eval) VALUES (?,?,?,?,?,?,?,?,?)",
                       (_iso(now), owner or "analyst", target, label or node["label"], node["kind"], json.dumps(rule), note,
                        json.dumps(state), _iso(now)))
    conn.commit()
    Ledger(conn=conn).append(ts=_iso(now), kind="watch.added", subject=target, source="ANALYST", provenance="HUMAN",
                             payload={"watch_id": cur.lastrowid, "label": label or node["label"], "rule": rule, "owner": owner or "analyst"})
    conn.commit()
    return get(conn, cur.lastrowid)


def get(conn: sqlite3.Connection, watch_id: int) -> dict:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    r = cur.execute("SELECT * FROM watches WHERE id = ?", (watch_id,)).fetchone()
    if not r:
        raise KeyError(watch_id)
    return _row(r)


def _row(r) -> dict:
    d = dict(r)
    d["rule"] = json.loads(d["rule"]) if d["rule"] else DEFAULT_RULE
    st = json.loads(d["last_state"]) if d["last_state"] else {}
    st.pop("neighbours", None)
    d["last_state"] = st
    d["rule_text"] = RULE_KINDS.get(d["rule"].get("kind"), "")
    return d


def list_watches(conn: sqlite3.Connection, status: str | None = None) -> list[dict]:
    ensure(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    q = "SELECT * FROM watches" + (" WHERE status = ?" if status else "") + " ORDER BY status = 'active' DESC, last_fired DESC, id DESC"
    rows = [_row(r) for r in cur.execute(q, (status,) if status else ())]
    recent = {}
    for e in cur.execute("SELECT watch_id, ts, reason, severity FROM watch_events ORDER BY id DESC LIMIT 400"):
        recent.setdefault(e["watch_id"], []).append({"ts": e["ts"], "reason": e["reason"], "severity": e["severity"]})
    for w in rows:
        w["recent"] = recent.get(w["id"], [])[:5]
    return rows


def events(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    ensure(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    out = []
    for r in cur.execute("SELECT * FROM watch_events ORDER BY id DESC LIMIT ?", (limit,)):
        d = dict(r)
        d["payload"] = json.loads(d["payload"])
        out.append(d)
    return out


def set_status(conn: sqlite3.Connection, watch_id: int, status: str, now: dt.datetime | None = None) -> dict | None:
    ensure(conn)
    now = now or dt.datetime.now(dt.timezone.utc)
    w = get(conn, watch_id)
    if status == "deleted":
        conn.execute("DELETE FROM watches WHERE id = ?", (watch_id,))
    else:
        if status not in ("active", "paused"):
            raise ValueError("status must be active, paused or deleted")
        conn.execute("UPDATE watches SET status = ? WHERE id = ?", (status, watch_id))
    conn.commit()
    Ledger(conn=conn).append(ts=_iso(now), kind=f"watch.{status}", subject=w["target"], source="ANALYST", provenance="HUMAN",
                             payload={"watch_id": watch_id, "label": w["label"]})
    conn.commit()
    return None if status == "deleted" else get(conn, watch_id)


def _reasons(rule: dict, before: dict, after: dict) -> list[str]:
    kind = rule.get("kind", "any")
    out = []
    if kind in ("any", "fresh"):
        thr = float(rule.get("pulse", 0.5))
        if after["pulse"] >= thr > (before.get("pulse") or 0):
            out.append(f"fresh evidence: pulse {after['pulse']:.2f} rose above {thr:.2f}")
        elif after.get("last_seen") and before.get("last_seen") and after["last_seen"] > before["last_seen"] and after["pulse"] >= thr:
            out.append(f"new evidence recorded at {after['last_seen'][11:16]} UTC")
    if kind in ("any", "tier"):
        floor = RANK.get(rule.get("tier", "Critical"), 3)
        b, a = RANK.get(before.get("tier") or "", -1), RANK.get(after.get("tier") or "", -1)
        if a >= floor and a > b:
            out.append(f"tier worsened to {after['tier']}" + (f" from {before.get('tier')}" if before.get("tier") else ""))
    if kind in ("any", "connect"):
        new = sorted(set(after.get("neighbours", [])) - set(before.get("neighbours", [])))
        if new and before.get("neighbours") is not None:
            out.append(f"{len(new)} new connection(s): {', '.join(x.split(':', 1)[1] for x in new[:3])}" + (" …" if len(new) > 3 else ""))
    return out


def evaluate(conn: sqlite3.Connection, live: dict | None = None, now: dt.datetime | None = None) -> list[dict]:
    """Evaluate every active watch against the current graph; fire edge-triggered events and return them."""
    ensure(conn)
    now = now or dt.datetime.now(dt.timezone.utc)
    fired = []
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    watches = [dict(r) for r in cur.execute("SELECT * FROM watches WHERE status = 'active'")]
    ledger = Ledger(conn=conn)  # built before any write: its schema script would otherwise commit a transaction in progress
    graphs: dict[str | None, dict] = {}
    for w in watches:
        focus = _focus_for(conn, w["target"])
        if focus not in graphs:
            try:
                graphs[focus] = intel_graph(conn, focus, live)
            except KeyError:
                graphs[focus] = {"nodes": [], "edges": []}
        g = graphs[focus]
        node = next((n for n in g["nodes"] if n["id"] == w["target"]), None)
        if node is None:
            conn.execute("UPDATE watches SET last_eval = ? WHERE id = ?", (_iso(now), w["id"]))
            continue
        after = _state(node, g)
        try:
            before = json.loads(w["last_state"]) if w["last_state"] else {}
            rule = json.loads(w["rule"]) if w["rule"] else DEFAULT_RULE
            reasons = _reasons(rule, before, after) if before else []
        except (TypeError, ValueError, KeyError, AttributeError) as exc:  # one malformed row must not silence every other watch
            print(f"watch {w['id']} on {w['target']}: rule or state not evaluable, skipped: {exc!r}", flush=True)
            conn.execute("UPDATE watches SET last_eval = ? WHERE id = ?", (_iso(now), w["id"]))
            continue
        # Claim the change before firing on it. The live engine and an analyst's "evaluate now" run on separate connections
        # and both read the same recorded state; whichever advances it first owns the firing, the other finds no row to
        # advance and stays quiet. The event, the counter, the new state and the ledger row then commit together.
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        claimed = conn.execute("UPDATE watches SET last_state = ?, last_eval = ? WHERE id = ? AND status = 'active' AND last_state IS ?",
                               (json.dumps(after), _iso(now), w["id"], w["last_state"])).rowcount == 1
        if not (claimed and reasons):
            continue
        severity = SEVERITY.get(after["tier"], "Low")
        payload = {"watch_id": w["id"], "target": w["target"], "label": w["label"], "kind": w["kind"], "reasons": reasons,
                   "severity": severity, "pulse": after["pulse"], "tier": after["tier"], "risk": after["risk"],
                   "owner": w["owner"], "rule": rule, "provenance": node["provenance"]}
        conn.execute("INSERT INTO watch_events (ts, watch_id, target, label, reason, severity, payload) VALUES (?,?,?,?,?,?,?)",
                     (_iso(now), w["id"], w["target"], w["label"], "; ".join(reasons), severity, json.dumps(payload)))
        conn.execute("UPDATE watches SET fired = fired + 1, last_fired = ? WHERE id = ?", (_iso(now), w["id"]))
        ledger.append(ts=_iso(now), kind="watch.fired", subject=w["target"], source="WATCHLIST", provenance="AUTO", payload=payload)
        fired.append(payload)
    conn.commit()
    return fired


def suggestions(conn: sqlite3.Connection, live: dict | None = None, limit: int = 6) -> list[dict]:
    """Entities worth watching right now: the riskiest technologies, every C2 seen, active campaigns, the top group."""
    ensure(conn)
    g = intel_graph(conn, None, live)
    watched = {r[0] for r in conn.execute("SELECT target FROM watches WHERE status != 'deleted'")}
    picks = []
    for kind, n in (("indicator", 2), ("campaign", 2), ("product", 3), ("actor", 1), ("cve", 2)):
        rows = sorted((x for x in g["nodes"] if x["kind"] == kind and x["id"] not in watched), key=lambda x: (-(x["risk"] or 0), -x["pulse"]))
        picks += rows[:n]
    return [{"target": n["id"], "label": n["label"], "kind": n["kind"], "tier": n["tier"], "pulse": n["pulse"], "sub": n["sub"]} for n in picks[:limit]]
