"""Incoming CVE stream: every CVE NVD publishes or changes, the moment the live engine sees it, ranked for the analyst.

Not only the ones that name a product we run (those are taken in and scored by engine/intake.py): the whole stream,
so the desk sees what is arriving and why one entry matters more than another. Every row carries the reasons for its
rank. The rank is a transparent sum, capped at 100:

  severity (CVSS base score x 4)                 up to 40   (15 while NVD has no score yet)
  names a technology in the inventory            35, + 10 when installed versions are affected
  CISA KEV (known exploited)                     20
  vendor or CNA text says exploited in the wild  12
  Odyssey day-0 forecast, when it flags          up to 20 (p x 20)
  published within the last 24 hours             5
  for this analyst (profile)                     15 when it touches an organisation, sector or technology they chose

Provenance: REAL (NVD, CISA KEV, FIRST EPSS, the forecast model); the inventory it is matched against is SIM.
"""

from __future__ import annotations

import datetime as dt
import re
import sqlite3
import threading

from . import forecast as fc
from .products import mentions, same_product

ITW = re.compile(r"exploited in the wild|actively exploited|active exploitation|under active attack", re.I)
MAXLEN = 400
_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def _metric(cve: dict) -> tuple[float | None, str, str | None]:
    m = cve.get("metrics") or {}
    for k in _METRICS:
        for e in m.get(k, []):
            d = e.get("cvssData", {})
            if d.get("baseScore") is not None:
                return float(d["baseScore"]), str(d.get("baseSeverity") or e.get("baseSeverity") or "").upper(), d.get("vectorString")
    return None, "", None


def _cwe(cve: dict) -> str | None:
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if str(d.get("value", "")).startswith("CWE-"):
                return d["value"]
    return None


def _cpes(cve: dict) -> set[tuple[str, str]]:
    return {tuple(m["criteria"].split(":")[3:5]) for c in cve.get("configurations", [])
            for n in c.get("nodes", []) for m in n.get("cpeMatch", []) if m.get("criteria")}


def inventory(conn: sqlite3.Connection) -> list[dict]:
    """The constituency's technologies with who runs them: what every incoming CVE is matched against."""
    rows = conn.execute("""SELECT s.vendor, s.product, s.label, s.product_key, COUNT(*) n, COUNT(DISTINCT s.org_id) orgs,
                                  GROUP_CONCAT(DISTINCT s.org_id) org_ids, GROUP_CONCAT(DISTINCT o.sector) sectors
                           FROM assets s JOIN orgs o ON o.id = s.org_id GROUP BY s.vendor, s.product""").fetchall()
    return [{"vendor": r[0], "product": r[1], "label": r[2], "product_key": r[3], "assets": r[4], "orgs": r[5],
             "org_ids": sorted((r[6] or "").split(",")), "sectors": sorted((r[7] or "").split(","))} for r in rows]


class Incoming:
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.last_check: str | None = None
        self.last_batch = 0
        self.seen_total = 0
        self.model = fc.load()

    # ---- observe one NVD batch (called by the live engine after each poll)
    def observe(self, conn: sqlite3.Connection, cves: list[dict], now: dt.datetime, taken: list[dict] | None = None,
                kev: dict | None = None) -> int:
        inv = inventory(conn)
        taken_by = {t["cve"]: t for t in (taken or [])}
        kev = kev or {}
        made = 0
        for cve in cves:
            cid = cve.get("id")
            if not cid:
                continue
            score, sev, vector = _metric(cve)
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "") or ""
            cpes = _cpes(cve)
            ours = [{k: p[k] for k in ("vendor", "product", "label", "product_key", "assets", "orgs", "org_ids", "sectors")}
                    for p in inv
                    if any(same_product(p["vendor"], p["product"], v, pr) for v, pr in cpes)
                    or (not cpes and mentions(p["vendor"], p["product"], desc))]
            k = kev.get(cid)
            itw = bool(ITW.search(desc))
            published = (cve.get("published") or "")[:19]
            forecast = None
            if self.model and published[:10] > self.model["frozen"]:
                try:
                    f = fc.predict([fc.day0_fields(cve)])[0]
                    forecast = {"p": f["p"], "flag": bool(f.get("flag"))} if f else None
                except Exception:  # noqa: BLE001 - a forecast that fails is simply absent
                    forecast = None
            t = taken_by.get(cid) or (self.rows.get(cid) or {}).get("_taken")
            age_h = None
            if published:
                try:
                    age_h = (now - dt.datetime.fromisoformat(published).replace(tzinfo=dt.timezone.utc)).total_seconds() / 3600
                except ValueError:
                    age_h = None
            reasons, pr = [], 0.0
            if score is not None:
                pr += min(40.0, score * 4)
                reasons.append(f"CVSS {score:g} {sev.title()}" if sev else f"CVSS {score:g}")
            else:
                pr += 15
                reasons.append("no CVSS yet: NVD still analysing")
            if ours:
                pr += 35
                orgs_n = len({o for p in ours for o in p["org_ids"]})
                reasons.append(f"names {', '.join(p['label'] for p in ours[:3])}{' and more' if len(ours) > 3 else ''}, "
                               f"run by {orgs_n} organisation{'s' if orgs_n != 1 else ''}")
            if t and t.get("exposed"):
                pr += 10
                reasons.append(f"{t['exposed']} installed version{'s' if t['exposed'] != 1 else ''} affected, worst {t['worst']}")
            if k:
                pr += 20
                reasons.append(f"CISA KEV since {k.get('dateAdded')}")
            if itw:
                pr += 12
                reasons.append("the text says exploited in the wild")
            if forecast and forecast["flag"]:
                pr += 20 * forecast["p"]
                reasons.append(f"day-0 forecast {forecast['p']:.0%} likely to be exploited")
            if age_h is not None and age_h <= 24:
                pr += 5
                reasons.append("published in the last 24 h")
            row = {"cve": cid, "published": published or None, "last_modified": (cve.get("lastModified") or "")[:19] or None,
                   "status": cve.get("vulnStatus"), "description": desc[:280], "cvss": score, "severity": sev, "vector": vector,
                   "cwe": _cwe(cve), "vendors": sorted({v for v, _ in cpes})[:4], "ours": ours,
                   "exposed": (t or {}).get("exposed", 0), "worst": (t or {}).get("worst"), "orgs": (t or {}).get("orgs", []),
                   "kev": bool(k), "itw": itw, "forecast": forecast, "priority": round(min(100.0, pr)), "reasons": reasons,
                   "seen_at": _iso(now), "provenance": "REAL", "_taken": t}
            with self.lock:
                self.rows[cid] = row
            made += 1
        with self.lock:
            if len(self.rows) > MAXLEN:  # keep the newest by modification time
                keep = sorted(self.rows.values(), key=lambda r: r["last_modified"] or "", reverse=True)[:MAXLEN]
                self.rows = {r["cve"]: r for r in keep}
            self.last_check, self.last_batch, self.seen_total = _iso(now), made, self.seen_total + made
        return made

    # ---- ranked for one analyst
    def query(self, profile: dict, only: str = "all", limit: int = 60) -> dict:
        orgs, sectors, products = set(profile.get("orgs") or []), set(profile.get("sectors") or []), set(profile.get("products") or [])
        with self.lock:
            rows = [dict(r) for r in self.rows.values()]
        out = []
        for r in rows:
            r.pop("_taken", None)
            touched = [p for p in r["ours"] if (orgs & set(p["org_ids"])) or (sectors & set(p["sectors"])) or p["product_key"] in products]
            boost = 15 if touched else 0
            r["for_you"] = min(100, r["priority"] + boost)
            r["profile_reason"] = (f"touches your profile: {', '.join(sorted({p['label'] for p in touched})[:3])}" if touched else None)
            if only == "ours" and not r["ours"]:
                continue
            if only == "exploited" and not (r["kev"] or r["itw"] or (r["forecast"] or {}).get("flag")):
                continue
            if only == "profile" and not touched:
                continue
            out.append(r)
        out.sort(key=lambda r: (-r["for_you"], r["last_modified"] or ""), reverse=False)
        out.sort(key=lambda r: r["for_you"], reverse=True)
        return {"rows": out[:limit], "total": len(rows), "shown": min(limit, len(out)), "matching": len(out),
                "ours": sum(1 for r in rows if r["ours"]),
                "exploited": sum(1 for r in rows if r["kev"] or r["itw"] or (r["forecast"] or {}).get("flag")),
                "last_check": self.last_check, "last_batch": self.last_batch, "seen_total": self.seen_total,
                "profile": {"orgs": sorted(orgs), "sectors": sorted(sectors), "products": sorted(products)},
                "how": "rank = CVSS x 4 (<= 40) + 35 if it names our technology (+10 when installed versions are affected) "
                       "+ 20 KEV + 12 exploited-in-the-wild text + forecast p x 20 + 5 if published today + 15 for your profile; "
                       "capped at 100. Every row lists the terms that applied."}

    def summary(self) -> dict:
        with self.lock:
            rows = list(self.rows.values())
        return {"total": len(rows), "ours": sum(1 for r in rows if r["ours"]),
                "exploited": sum(1 for r in rows if r["kev"] or r["itw"] or (r["forecast"] or {}).get("flag")),
                "last_check": self.last_check, "last_batch": self.last_batch, "seen_total": self.seen_total}
