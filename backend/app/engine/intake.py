"""Live CVE intake: real CVEs published or modified in the last hours, from the NVD API, matched to the inventory
while the system runs. This is the problem statement's core use case happening live on real data: a new
vulnerability appears, Odyssey finds who runs the product, checks the installed versions, forecasts exploitation on
day 0, scores it and warns through the same graduated-autonomy policy as everything else.

Only CVEs not yet in the database are taken in (KEV status changes on known CVEs come through the KEV feed watch).
Every intake is a ledger event, so the time from publication to warning is measurable.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from collections import defaultdict

from ..ingest.cve_records import build_record, load_epss, load_kev
from . import forecast as fc
from .exposure import reconcile
from .ledger import Ledger
from .products import mentions, same_product
from .scoring import assess, config

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS: dict = {}


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def fetch_recent(since: dt.datetime, until: dt.datetime | None = None, timeout: float = 40.0) -> list[dict]:
    """NVD 2.0 `cve` objects modified in the window (max 120 days). One page of 2000 is enough for hours of
    activity; a longer window is paged."""
    import httpx
    until = until or dt.datetime.now(dt.timezone.utc)
    fmt = lambda t: t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")  # noqa: E731
    out, start = [], 0
    while True:
        r = httpx.get(NVD_API, params={"lastModStartDate": fmt(since), "lastModEndDate": fmt(until),
                                       "resultsPerPage": 2000, "startIndex": start},
                      timeout=timeout, headers={"User-Agent": "Odyssey-EWS/0.2 (research)"})
        r.raise_for_status()
        body = r.json()
        out.extend(item["cve"] for item in body.get("vulnerabilities", []))
        start += body.get("resultsPerPage", 2000)
        if start >= body.get("totalResults", 0) or len(out) >= 6000:
            return out


def intake(conn: sqlite3.Connection, cves: list[dict], kev_live: dict | None = None, now: dt.datetime | None = None,
           source: str = "NVD (live)") -> list[dict]:
    """Take new CVEs into the running system. Returns one summary per CVE that names a constituency product."""
    now = now or dt.datetime.now(dt.timezone.utc)
    cfg = config()[0]
    kev = {**load_kev(), **(kev_live or {})}
    if "epss" not in _EPSS:
        _EPSS["epss"] = load_epss()[0]
    epss = _EPSS["epss"]
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    assets = [dict(r) for r in cur.execute("SELECT * FROM assets").fetchall()]
    orgs = {r["id"]: {**dict(r), "cii": bool(r["cii"])} for r in cur.execute("SELECT * FROM orgs").fetchall()}
    try:  # notice recipients live in the simulated world, not in the database
        from pathlib import Path
        world = json.loads((Path(__file__).resolve().parents[3] / "data" / "sim" / "world.json").read_text(encoding="utf-8"))
        ciso = {o["id"]: o.get("ciso") for o in world["orgs"]}
    except (OSError, ValueError, KeyError):
        ciso = {}
    for oid, o in orgs.items():
        o["ciso"] = ciso.get(oid) or f"ciso@{o.get('domain', oid.lower() + '.example')}"
    by_product: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for a in assets:
        by_product[(a["vendor"], a["product"])].append(a)
    known = {r[0] for r in conn.execute("SELECT id FROM vulns").fetchall()}
    model = fc.load()
    ledger = Ledger(conn=conn)
    taken: list[dict] = []
    for cve in cves:
        cid = cve.get("id")
        if not cid or cid in known:
            continue
        rec = build_record(cid, nvd=cve, kev=kev.get(cid), epss=epss.get(cid))
        named = {tuple(m["criteria"].split(":")[3:5]) for c in rec["nvd_configurations"] for n in c.get("nodes", [])
                 for m in n.get("cpeMatch", [])}
        hit: list[tuple[dict, object, object]] = []
        for (vendor, product), group in by_product.items():
            relevant = (any(same_product(vendor, product, v, p) for v, p in named)
                        or any(same_product(vendor, product, e.get("vendor", ""), e.get("product", ""))
                               for e in rec["cna_affected"])
                        or (rec["kev"] and same_product(vendor, product, rec["kev"]["vendorProject"], rec["kev"]["product"]))
                        or (not named and not rec["cna_affected"] and mentions(vendor, product, rec["description"])))
            if not relevant:
                continue
            for asset in group:
                exp = reconcile(asset, rec)
                hit.append((asset, exp, None))
        if not hit:
            continue
        published = (rec.get("published") or _iso(now))[:19]
        if model and published[:10] > model["frozen"]:
            rec["forecast"] = fc.predict([fc.day0_fields(cve)])[0] or None
        else:
            rec["forecast"] = None
        conn.execute("INSERT OR IGNORE INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (cid, rec["published"], rec["description"], json.dumps(rec["kev"]), rec["epss"], json.dumps(rec["ssvc"]),
                      rec["cvss_vector"], rec["cvss_source"], rec["nvd_status"],
                      json.dumps({k: rec[k] for k in ("cna_affected", "nvd_configurations", "forecast")})))
        if rec["published"]:
            ledger.append(ts=rec["published"], kind="vuln.published", subject=cid, source="NVD",
                          payload={"cvss_vector": rec["cvss_vector"], "cvss_source": rec["cvss_source"], "live": True})
        worst, exposed, org_ids = "Watch", 0, set()
        rank = {"Compromise": 4, "Critical": 3, "High": 2, "Medium": 1, "Watch": 0}
        results = []
        for asset, exp, _ in hit:
            org = orgs[asset["org_id"]]
            a = assess(rec, asset, org, exp)
            detail = {**a.to_dict(), "exposure": {"status": exp.status, "votes": [vars(v) for v in exp.votes]}, "live": True}
            conn.execute("INSERT OR REPLACE INTO assessments VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         (asset["id"], cid, org["id"], org["sector"], exp.status, exp.relevance, a.risk, a.tier,
                          a.decision, a.deadline_hours, json.dumps(detail)))
            if exp.relevance > 0:
                exposed += 1
                org_ids.add(org["id"])
                results.append((asset, org, a))
                if rank[a.tier] > rank[worst]:
                    worst = a.tier
        known.add(cid)
        summary = {"cve": cid, "published": rec["published"], "source": source, "kev": bool(rec["kev"]),
                   "product": next((a["label"] for a, _, _ in hit), None), "assets_running": len(hit),
                   "exposed": exposed, "orgs": sorted(org_ids), "worst": worst,
                   "forecast": {k: rec["forecast"][k] for k in ("p", "flag") if rec["forecast"] and k in rec["forecast"]},
                   "cvss": rec["cvss_vector"], "taken_at": _iso(now),
                   "minutes_since_publication": round((now - dt.datetime.fromisoformat(published).replace(
                       tzinfo=dt.timezone.utc)).total_seconds() / 60) if rec["published"] else None}
        summary["action"] = _act(conn, cfg, rec, results, orgs, assets, now)
        ledger.append(ts=_iso(now), kind="live.intake", subject=cid, source="NVD", provenance="REAL",
                      payload={k: v for k, v in summary.items() if k != "taken_at"})
        conn.commit()
        taken.append(summary)
    return taken


def _act(conn, cfg, rec, results, orgs, assets, now) -> str:
    """The same policy as the build-time autopilot: evidence-based notices go out on their own, a day-0 prediction
    is proposed for an analyst, anything lower waits for the daily digest."""
    from .sentinel import Autopilot
    if not results:
        return "no exposure"
    pilot = Autopilot(conn, Ledger(conn=conn), cfg, orgs, {a["id"]: a for a in assets}, now=now)
    cid, label = rec["id"], results[0][0]["label"]
    by_org: dict[str, list] = defaultdict(list)
    for asset, org, a in results:
        by_org[org["id"]].append((asset, a))
    critical = {o: rows for o, rows in by_org.items() if any(a.tier in ("Critical", "Compromise") for _, a in rows)}
    flagged = (rec.get("forecast") or {}).get("flag")
    if critical:
        for org_id, rows in critical.items():
            worst = max(rows, key=lambda r: r[1].risk)[1]
            pilot.emit(now, "notify", f"{org_id}:{cid}", org_id=org_id, cve_id=cid, alert=f"{org_id}:{cid}", tier=worst.tier,
                       channels=["email", "sms"], basis="live intake: " + ", ".join(r.id for r in worst.rules[:3]),
                       provenance="REAL", product=label, deadline_hours=worst.deadline_hours,
                       title=f"{cid} ({label}) affects {len(rows)} of your assets and is {worst.tier}: "
                             f"{worst.deadline_basis}. Deadline {worst.deadline_hours} h.")
        action = f"notified {len(critical)} organisation(s) at once"
    elif flagged:
        p = rec["forecast"]["p"]
        for org_id, rows in by_org.items():
            pilot.emit(now, "forecast", f"{org_id}:{cid}", org_id=org_id, cve_id=cid, alert=f"{org_id}:{cid}",
                       channels=["email"], basis="day-0 exploitation forecast", provenance="REAL", p=p, product=label,
                       group=f"live-forecast:{cid}",
                       proposal=f"Send a pre-emptive advisory on {cid} ({label}) to {len(by_org)} organisation(s): "
                                f"forecast {p:.0%} likely to be exploited",
                       title=f"Pre-emptive advisory: {cid} ({label}) was published today and Odyssey's day-0 model "
                             f"rates it {p:.0%} likely to be exploited. {len(rows)} of your assets run it; patch early.")
        action = f"pre-emptive advisory proposed for {len(by_org)} organisation(s)"
    else:
        action = "recorded; goes into the daily digest"
    pilot.flush()
    conn.commit()
    return action
