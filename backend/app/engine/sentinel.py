"""Sentinel: Odyssey's autopilot. It acts on evidence the moment it arrives, without waiting to be asked.

Policy (config/scoring.json "sentinel"), applied to every alert's time line (engine/replay.py) from go-live on:
  - early warning   a decoy-grid scanning surge on a product, before any CVE exists -> warn every operator running
                    it; if no remotely exploitable disclosure follows within N days, stand down (logged false alarm)
  - forecast        a newly published CVE the day-0 model expects to be exploited, on an internet/DMZ asset ->
                    pre-emptive advisory with a patch-by date from the vendor's own time-to-exploit history
  - notify          an alert reaches Critical/Compromise -> immediate notice to the CISO, in the state's language
  - digest          High alerts -> one daily digest per organisation (no alert fatigue)
  - escalate        suspected compromise -> CERT-In 6-hour clock, sector CSIRT and NCIIPC; report pre-drafted
  - hunt            on a compromise, sweep every organisation's telemetry for the same C2 and warn exposed peers
  - SLA watch       Critical warnings past their deadline -> escalation to the sector CSIRT, one per organisation
Exposures that predate go-live go into one baseline notice per organisation.

Human in the loop (graduated autonomy, "autonomy" in the policy): evidence-based, time-critical actions run on their
own; predictions, sensor-only warnings and escalations to regulators are *proposed*, one proposal per CVE or
campaign, and wait for an analyst (approvals table, /api/approvals). History before the live window is approved by a
simulated duty officer (SIM, labelled as such); proposals in the live window wait for a real analyst, and a
prediction is withdrawn automatically once evidence-based notices have overtaken it.

Every action is a ledger event, so "what did Odyssey do on its own, and when" is auditable, and the lead time over
CISA KEV is measured per CVE with its basis and provenance (REAL public signal vs SIM sensor). Delivery is
simulated: nothing leaves this laptop.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3

from .ledger import Ledger
from .replay import defang

SOURCE = "ODYSSEY_AUTOPILOT"
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
SIM_OFFICER = "duty-officer (SIM)"
SIM_RULES = {"DECOY_SURGE", "DECOY_EXPLOIT", "IOC_SIGHTING"}  # evidence that only the simulated sensors provide
APPROVALS = """CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY, proposed_at TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, org_id TEXT,
    title TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at TEXT, note TEXT)"""


def _t(ts: str, minutes: float = 0) -> dt.datetime:
    t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)) + dt.timedelta(minutes=minutes)


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Autopilot:
    def __init__(self, conn: sqlite3.Connection, ledger: Ledger, cfg: dict, orgs: dict, assets: dict,
                 now: dt.datetime | None = None):
        self.conn, self.ledger, self.s, self.orgs, self.assets = conn, ledger, cfg["sentinel"], orgs, assets
        self.go_live = _t(self.s["go_live"] + "T00:00:00+05:30")
        self.now = now or dt.datetime.now(dt.timezone.utc)
        self.live_from = self.now - dt.timedelta(hours=self.s["live_window_hours"])
        self.actions: list[dict] = []

    def lang(self, org_id: str) -> str:
        return self.s["state_language"].get(self.orgs[org_id]["state"], "hi")

    def csirt(self, org: dict) -> list[str]:
        to = [self.s["sector_csirt"].get(org["sector"], "CERT-In")] + (["NCIIPC"] if org.get("cii") else [])
        return list(dict.fromkeys(to))

    def emit(self, at: dt.datetime, kind: str, subject: str, **payload) -> None:
        org = self.orgs.get(payload.get("org_id", ""))
        if org:
            payload.setdefault("lang", self.lang(org["id"]))
            payload.setdefault("recipients", [org["ciso"]])
        mode = self.s["autonomy"].get(kind, "approve")  # anything not explicitly automatic needs a human
        self.actions.append({"ts": _iso(at), "kind": f"auto.{kind}", "subject": subject, "mode": mode,
                             "payload": {**payload, "autonomy": mode}})

    # ---- writing: automatic actions, proposals, approvals
    def flush(self) -> None:
        """Ledger in time order. Approval-gated actions are grouped into one proposal per CVE/campaign; history gets a
        SIM duty-officer approval and the executed actions; the live window waits in the approvals table."""
        self.conn.execute(APPROVALS)
        entries = []
        groups: dict[str, list[dict]] = {}
        for a in self.actions:
            if a["mode"] == "auto":
                entries.append((a["ts"], a["kind"], a["subject"], "AUTO", SOURCE, a["payload"]))
            else:
                groups.setdefault(a["payload"].get("group") or f"{a['kind']}|{a['subject']}|{a['ts']}", []).append(a)
        notified = {}  # alert -> first evidence-based notice (a forecast overtaken by evidence is withdrawn)
        for a in self.actions:
            covered = [a["subject"]] if a["kind"] == "auto.notify" else [
                f"{a['payload']['org_id']}:{i['cve']}" for i in a["payload"].get("items", [])]                 if a["kind"] == "auto.digest" else []
            for alert in covered:
                notified[alert] = min(notified.get(alert, a["ts"]), a["ts"])
        for g, acts in groups.items():
            at = min(_t(a["ts"]) for a in acts)
            kind, head = acts[0]["kind"], acts[0]["payload"]
            orgs = sorted({a["payload"]["org_id"] for a in acts if a["payload"].get("org_id")})
            subject = head.get("group_subject", acts[0]["subject"])
            title = head.get("proposal", head["title"])
            proposal = {"group": g, "action": kind, "orgs": orgs, "count": len(acts), "title": title,
                        **{k: head[k] for k in ("cve_id", "product", "p", "basis", "provenance") if k in head}}
            entries.append((_iso(at), "auto.proposed", subject, "AUTO", SOURCE, proposal))
            stored = {**proposal, "actions": [{"ts": a["ts"], "kind": a["kind"], "subject": a["subject"],
                                               "payload": a["payload"]} for a in acts]}
            if at >= self.live_from:
                overtaken = [notified[a["subject"]] for a in acts if a["subject"] in notified]
                if kind == "auto.forecast" and len(overtaken) == len(acts):
                    when = max(overtaken)
                    entries.append((when, "auto.withdrawn", subject, "AUTO", SOURCE,
                                    {**proposal, "reason": "superseded: evidence-based notices already sent"}))
                    self._store(at, kind, subject, orgs, title, stored, "superseded", "Odyssey", when,
                                "Exploitation evidence arrived first; the notices went out automatically.")
                else:
                    self._store(at, kind, subject, orgs, title, stored, "pending", None, None, None)
                continue
            delay = 12 + int(hashlib.sha256(g.encode()).hexdigest(), 16) % 34  # SIM review: 12-45 minutes
            decided = _iso(at + dt.timedelta(minutes=delay))
            entries.append((decided, "analyst.approve", subject, "SIM", "ANALYST",
                            {"actor": SIM_OFFICER, "action": kind, "proposed_at": _iso(at), "review_minutes": delay,
                             "orgs": orgs}))
            for a in acts:
                entries.append((decided, a["kind"], a["subject"], "AUTO", SOURCE,
                                {**a["payload"], "approved_by": SIM_OFFICER, "proposed_at": a["ts"]}))
            self._store(at, kind, subject, orgs, title, stored, "approved", SIM_OFFICER, decided, None)
        for ts, kind, subject, prov, source, payload in sorted(entries, key=lambda e: e[0]):
            self.ledger.append(ts=ts, kind=kind, subject=subject, source=source, provenance=prov, payload=payload)

    def _store(self, at, kind, subject, orgs, title, payload, status, by, when, note) -> None:
        self.conn.execute("INSERT INTO approvals (proposed_at, kind, subject, org_id, title, payload, status, "
                          "decided_by, decided_at, note) VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (_iso(at), kind, subject, orgs[0] if len(orgs) == 1 else None, title, json.dumps(payload),
                           status, by, when, note))

    # ---- early warning: product-level, before any CVE exists
    def surges(self, surges: list[dict], recs: dict, product_cves: dict[str, set[str]]) -> None:
        confirmed: dict[str, str] = {}  # tag -> CVE that already confirmed an earlier wave of the same campaign
        window = self.s["surge_stand_down_days"]
        for sv in sorted(surges, key=lambda x: x["first"]):
            first = _t(sv["first"] + "T06:00:00Z")
            if first < self.go_live:
                continue
            tag = sv["tag"]
            running = [a for a in self.assets.values() if a["product_key"] == tag]
            label = running[0]["label"] if running else tag
            followed = sorted((recs[c]["published"][:10], c) for c in product_cves.get(tag, ())
                              if recs[c].get("published") and _mass_exploitable(recs[c])
                              and 0 <= (dt.date.fromisoformat(recs[c]["published"][:10])
                                        - dt.date.fromisoformat(sv["first"])).days <= window)
            orgs = sorted({a["org_id"] for a in running})
            for org_id in orgs:
                n = sum(a["org_id"] == org_id for a in running)
                self.emit(first + dt.timedelta(minutes=20), "warn", f"product:{tag}", org_id=org_id, product=label,
                          channels=["email"], z=sv["z_sessions"], sensors=sv["sensors"], assets=n,
                          basis="decoy-grid scanning surge", provenance="SIM", group=f"warn:{tag}:{sv['first']}",
                          proposal=f"Send early warning on the {label} scanning surge to {len(orgs)} organisation(s)",
                          title=f"Early warning: coordinated scanning of {label} on {sv['sensors']} national decoy "
                                f"sensors (z={sv['z_sessions']:.1f}). No CVE yet; {n} of your assets run it.",
                          actions=["Restrict management interfaces to trusted networks",
                                   "Run the vendor's integrity checker and keep logs for 90 days",
                                   "Pre-stage the vendor's emergency patch process"])
            if followed and confirmed.get(tag) == followed[0][1]:
                continue  # a later wave of a campaign whose disclosure already confirmed the first warning
            if followed:
                day, cve = followed[0]
                confirmed[tag] = cve
                lead = (dt.date.fromisoformat(day) - dt.date.fromisoformat(sv["first"])).days
                self.emit(_t(recs[cve]["published"], 10), "confirm", f"product:{tag}", product=label, cve_id=cve,
                          lead_days=lead, warned_at=_iso(first + dt.timedelta(minutes=20)), provenance="SIM",
                          title=f"Early warning confirmed: {cve} disclosed for {label} {lead} days after the "
                                f"scanning surge began.")
            else:
                self.emit(first + dt.timedelta(days=window), "stand_down", f"product:{tag}", product=label,
                          provenance="SIM",
                          title=f"Stand-down: no remotely exploitable disclosure followed the {label} scanning surge "
                                f"within {window} days. Warning withdrawn and logged as a false alarm for detector "
                                f"calibration.")

    # ---- per-alert time lines
    def alerts(self, items: list[dict], peers: dict[str, list[str]], n_scanned: tuple[int, int]) -> None:
        baseline: dict[str, list[dict]] = {}
        digest: dict[tuple[str, str], list[dict]] = {}
        overdue: dict[str, list[dict]] = {}
        for it in items:
            org, asset, rec, steps = it["org"], it["asset"], it["rec"], it["steps"]
            alert = f"{org['id']}:{rec['id']}"
            common = {"org_id": org["id"], "cve_id": rec["id"], "alert": alert, "asset": asset["hostname"],
                      "product": asset["label"]}
            first = {t: next((s for s in steps if s["tier"] == t), None) for t in ("High", "Critical", "Compromise")}
            urgent = min((first[t] for t in self.s["notify_now_tiers"] if first[t]), key=lambda s: s["ts"],
                         default=None)
            fc = rec.get("forecast") or {}
            pub = _t(rec["published"]) if rec.get("published") else None
            if fc.get("flag") and pub and pub >= self.go_live and asset["zone"] in self.s["forecast_notify_zones"] \
                    and (not urgent or _t(urgent["ts"]) > pub):
                days = fc.get("median_days_to_exploit")
                by = (pub + dt.timedelta(days=days)).astimezone(IST).date().isoformat() if days is not None else None
                self.emit(pub + dt.timedelta(minutes=15), "forecast", alert, **common, channels=["email"],
                          p=fc["p"], reasons=fc.get("reasons", []), median_days_to_exploit=days, patch_by=by,
                          basis="day-0 exploitation forecast", provenance="REAL", group=f"forecast:{rec['id']}",
                          group_subject=rec["id"],
                          proposal=f"Send a pre-emptive advisory on {rec['id']} ({asset['label']}): the day-0 forecast "
                                   f"puts it among the new CVEs most likely to be exploited (p={fc['p']:.0%})",
                          title=f"Pre-emptive: {rec['id']} in {asset['label']} ({asset['hostname']}) is likely to be "
                                f"exploited ({fc['p']:.0%}, day-0 forecast)."
                                + (f" This vendor's flaws are typically exploited within {days} days of disclosure: "
                                   f"patch by {by}." if by else ""))
            if urgent:
                notified_at = max(_t(urgent["ts"]), self.go_live + dt.timedelta(hours=9))
                if urgent["deadline_hours"] and notified_at + dt.timedelta(hours=urgent["deadline_hours"]) < self.now:
                    overdue.setdefault(org["id"], []).append({"cve": rec["id"], "asset": asset["hostname"],
                                                              "tier": urgent["tier"],
                                                              "due": _iso(notified_at + dt.timedelta(
                                                                  hours=urgent["deadline_hours"]))})
            if urgent and _t(urgent["ts"]) < self.go_live:
                baseline.setdefault(org["id"], []).append({"cve": rec["id"], "tier": urgent["tier"],
                                                           "asset": asset["hostname"]})
            elif urgent:
                self.emit(_t(urgent["ts"], 2), "notify", alert, **common, tier=urgent["tier"],
                          channels=["email", "sms"] + (["phone-bridge"] if urgent["tier"] == "Compromise" else []),
                          deadline_hours=urgent["deadline_hours"], trigger=urgent["event"],
                          basis=urgent["event"], provenance=_provenance(urgent),
                          title=f"{urgent['tier']}: {asset['label']} on {asset['hostname']} is exposed to {rec['id']}"
                                f" ({urgent['event']}). Act within {urgent['deadline_hours']} h.")
            elif first["High"] and _t(first["High"]["ts"]) >= self.go_live:
                day = _t(first["High"]["ts"]).astimezone(IST).date().isoformat()
                digest.setdefault((org["id"], day), []).append(
                    {"cve": rec["id"], "asset": asset["hostname"], "basis": first["High"]["event"],
                     "provenance": _provenance(first["High"]), "ts": first["High"]["ts"]})
            comp = first["Compromise"]
            if comp and _t(comp["ts"]) >= self.go_live:
                self._compromise(_t(comp["ts"], 4), org, asset, rec, it.get("sighting"), peers.get(rec["id"], []),
                                 n_scanned, common)
        for org_id, rows in baseline.items():
            self.emit(self.go_live + dt.timedelta(hours=9), "baseline", f"org:{org_id}", org_id=org_id,
                      channels=["email"], count=len(rows), top=rows[:5],
                      title=f"Go-live baseline: {len(rows)} known-exploited exposures outstanding at "
                            f"{self.orgs[org_id]['name']}; ranked remediation list attached.")
        for (org_id, day), rows in digest.items():
            self.emit(dt.datetime.fromisoformat(f"{day}T18:00:00+05:30"), "digest", f"org:{org_id}", org_id=org_id,
                      channels=["email"], count=len(rows), items=rows[:10], day=day,
                      title=f"Daily digest {day}: {len(rows)} new High warning(s) for {self.orgs[org_id]['name']}.")
        for org_id, rows in sorted(overdue.items(), key=lambda kv: -len(kv[1])):
            org, to = self.orgs[org_id], self.csirt(self.orgs[org_id])
            self.emit(self.now, "escalate_sla", f"org:{org_id}", org_id=org_id, count=len(rows), items=rows[:10],
                      recipients=to, channels=["secure-email"], group=f"sla:{org_id}",
                      proposal=f"Escalate {len(rows)} overdue Critical warning(s) at {org['name']} to {', '.join(to)}",
                      title=f"SLA watch: {len(rows)} Critical warning(s) at {org['name']} are past their deadline "
                            f"with no confirmed remediation.")

    def _compromise(self, at, org, asset, rec, sighting, peers, n_scanned, common) -> None:
        to = ["CERT-In incident response desk"] + self.csirt(org)
        self.emit(at, "escalate", common["alert"], **common, tier="Compromise", recipients=to, channels=["secure-email"],
                  basis="Bayesian decision: suspected compromise", provenance="SIM",
                  proposal=f"Report the suspected compromise of {asset['hostname']} ({rec['id']}) to {', '.join(to)}",
                  title=f"Escalated to {', '.join(to)}: suspected compromise of {asset['hostname']} via {rec['id']}. "
                        f"CERT-In 6-hour reporting clock started.")
        self.emit(at + dt.timedelta(minutes=1), "report", common["alert"], **common, channels=[],
                  title="CERT-In incident report drafted from the evidence (fields pre-filled, awaiting analyst "
                        "sign-off).", link=f"/api/alerts/{org['id']}/{rec['id']}/certin-report")
        c2 = defang(sighting["dst"]) if sighting else None
        self.emit(at + dt.timedelta(minutes=3), "hunt", common["alert"], **common, channels=[],
                  assets_scanned=n_scanned[0], orgs_scanned=n_scanned[1], c2=c2, hits=1 if sighting else 0,
                  peers_warned=len(peers),
                  title=(f"Hunt: swept {n_scanned[0]} assets in {n_scanned[1]} organisations for C2 {c2}: 1 hit "
                         f"(this asset). " if c2 else "")
                        + f"Warned {len(peers)} peer organisation(s) exposed to {rec['id']}.")
        for peer in peers:
            self.emit(at + dt.timedelta(minutes=5), "notify", f"{peer}:{rec['id']}", org_id=peer, cve_id=rec["id"],
                      alert=f"{peer}:{rec['id']}", tier="peer-warning", channels=["email", "sms"],
                      basis="peer compromise in the same sector", provenance="SIM",
                      title=f"Peer warning: an organisation in the {org['sector']} sector shows signs of compromise via "
                            f"{rec['id']}. You are exposed to the same CVE; patch and hunt now.")


def _provenance(step: dict) -> str:
    """A notice is REAL only if no simulated sensor contributed to the tier that triggered it."""
    return "SIM" if step.get("provenance") == "SIM" or SIM_RULES & set(step.get("rules", [])) else "REAL"


def _mass_exploitable(rec: dict) -> bool:
    """Is this disclosure the kind a mass-scanning surge precedes? Judged only on what is known at disclosure:
    remotely reachable without credentials (CVSS AV:N/PR:N), or flagged by the day-0 forecast."""
    v = rec.get("cvss_vector") or ""
    return ("AV:N" in v and "PR:N" in v) or bool((rec.get("forecast") or {}).get("flag"))


def lead_times(actions: list[dict], kev_ts: dict[str, str], go_live: dt.datetime, alerted: set[str]) -> dict:
    """For every CVE CISA added to KEV after go-live that affects an exposed asset: how long before the listing did
    Odyssey first act on it (proposal time for approval-gated actions), and on what basis (REAL or SIM signal)?"""
    first: dict[str, tuple[dt.datetime, str, str]] = {}

    def seen(cve: str, t: dt.datetime, basis: str, prov: str) -> None:
        if cve not in first or t < first[cve][0]:
            first[cve] = (t, basis, prov)

    for a in actions:
        p = a["payload"]
        if a["kind"] in {"auto.forecast", "auto.notify"} and p.get("cve_id") and p.get("tier") != "peer-warning":
            seen(p["cve_id"], _t(a["ts"]), p.get("basis", a["kind"]), p.get("provenance", "REAL"))
        elif a["kind"] == "auto.digest":
            for item in p.get("items", []):
                seen(item["cve"], _t(a["ts"]), item.get("basis", "daily digest"), item.get("provenance", "REAL"))
        elif a["kind"] == "auto.confirm":  # the product-level warning counts for the CVE that confirmed it
            seen(p["cve_id"], _t(p["warned_at"]), "decoy-grid scanning surge", "SIM")
    rows = []
    for cve, ts in kev_ts.items():
        k = _t(ts)
        if k < go_live or cve not in alerted:
            continue
        t, basis, prov = first.get(cve, (None, None, None))
        rows.append({"cve": cve, "kev": ts, "first_action": _iso(t) if t else None, "basis": basis,
                     "provenance": prov, "lead_days": round((k - t).total_seconds() / 86400, 1) if t else None})

    # KEV publishes a date, not a time: only a lead of a day or more is unambiguously "before the listing".
    def stats(rs: list[dict]) -> dict:
        ahead = sorted(r["lead_days"] for r in rs if r["lead_days"] is not None and r["lead_days"] >= 1)
        return {"acted_before_kev": len(ahead), "median_lead_days": ahead[len(ahead) // 2] if ahead else None,
                "max_lead_days": ahead[-1] if ahead else None}

    return {"kev_after_go_live": len(rows), **stats(rows),
            "acted_same_day": sum(1 for r in rows if r["lead_days"] is not None and r["lead_days"] < 1),
            "not_acted": sum(1 for r in rows if r["lead_days"] is None),
            "real_signals_only": stats([r for r in rows if r["provenance"] == "REAL"]),
            "rows": sorted(rows, key=lambda r: r["kev"])}


def pressure(items: list[dict], start: dt.date, end: dt.date) -> list[dict]:
    """Open warnings by tier per day, from every alert's replayed time line (what the SOC faced each day)."""
    out = []
    for i in range((end - start).days + 1):
        day = start + dt.timedelta(days=i)
        cut = dt.datetime.combine(day, dt.time(23, 59), IST)
        row = {"date": day.isoformat(), "Compromise": 0, "Critical": 0, "High": 0}
        for it in items:
            tier = next((s["tier"] for s in reversed(it["steps"]) if _t(s["ts"]) <= cut), None)
            if tier in row:
                row[tier] += 1
        out.append(row)
    return out


def decide(conn: sqlite3.Connection, approval_id: int, approve: bool, actor: str, note: str | None) -> dict:
    """A human decision on a pending proposal. Approval executes every grouped action now (ledger AUTO events
    with approved_by); rejection is recorded with the analyst's reason, which feeds detector calibration."""
    row = conn.execute("SELECT id, kind, subject, payload, status FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    if not row:
        raise KeyError(approval_id)
    if row[4] != "pending":
        raise ValueError(f"proposal {approval_id} is already {row[4]}")
    payload, now = json.loads(row[3]), _iso(dt.datetime.now(dt.timezone.utc))
    led = Ledger(conn=conn)
    led.append(ts=now, kind="analyst.approve" if approve else "analyst.reject", subject=row[2], source="ANALYST",
               provenance="HUMAN", payload={"actor": actor, "action": row[1], "approval_id": approval_id,
                                            "note": note, "orgs": payload.get("orgs", [])})
    if approve:
        for a in payload["actions"]:
            led.append(ts=now, kind=a["kind"], subject=a["subject"], source=SOURCE, provenance="AUTO",
                       payload={**a["payload"], "approved_by": actor, "proposed_at": a["ts"]})
    conn.execute("UPDATE approvals SET status = ?, decided_by = ?, decided_at = ?, note = ? WHERE id = ?",
                 ("approved" if approve else "rejected", actor, now, note, approval_id))
    conn.commit()
    return {"id": approval_id, "status": "approved" if approve else "rejected", "executed": len(payload["actions"])
            if approve else 0}


def summary(conn: sqlite3.Connection) -> dict:
    rows = conn.execute("SELECT kind, COUNT(*) FROM ledger WHERE kind LIKE 'auto.%' GROUP BY kind").fetchall()
    meta = conn.execute("SELECT value FROM meta WHERE key = 'sentinel'").fetchone()
    return {"counts": dict(rows), **(json.loads(meta[0]) if meta else {})}
