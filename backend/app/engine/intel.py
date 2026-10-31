"""Threat-intelligence aggregation and organisation-based OSINT.

Aggregation: every source is listed with what it contributes, its provenance (REAL public feed or SIM sensor), its
Admiralty reliability grade, its volume and how much of it is relevant to the constituency, so the funnel from raw
intelligence to warnings is visible. Real attack telemetry comes from SANS ISC DShield (a global network of honeypots
and firewall logs); real advisories from CISA's advisory feed, matched to the inventory by product aliases.

Organisation OSINT: what an outside observer (or attacker) learns about one organisation, built only from passive
sources: its internet-facing services, the real advisories and exploited CVEs that name its products, global attack
activity on the ports those services expose, known C2/phishing indicators seen in its telemetry, and look-alike
domains in live phishing feeds. Nothing here touches the organisation's network.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import re
import sqlite3
import statistics
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

from .products import mentions

RAW = Path(__file__).resolve().parents[3] / "data" / "raw"
# Service ports per product (what DShield sees being attacked globally), including ICS protocols.
PORTS = {
    "ivanti_cs": [443], "fortios": [443, 10443], "panos": [443], "netscaler": [443], "cisco_asa": [443],
    "exchange": [443, 25], "confluence": [8090], "cisco_esa": [25], "openssh": [22], "httpd": [80, 443],
    "tomcat": [8443], "gitlab": [443, 22], "postgres": [5432], "oracle_db": [1521], "esxi": [443],
    "win2022": [445, 3389], "siemens_wincc": [102], "schneider_scada": [502], "swift": [443], "sap": [443],
    "beyondtrust": [443], "php": [80, 443], "nginx": [80, 443], "magento": [443], "core_banking": [443],
}
PORT_NAMES = {22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 443: "HTTPS / SSL-VPN", 445: "SMB", 3389: "RDP",
              8443: "HTTPS-alt", 10443: "FortiGate SSL-VPN", 8090: "Confluence", 5432: "PostgreSQL", 1521: "Oracle",
              102: "Siemens S7 (ICS)", 502: "Modbus (ICS)", 20000: "DNP3 (ICS)", 44818: "EtherNet/IP (ICS)"}


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


@lru_cache(maxsize=1)
def dshield() -> dict:
    """Real global attack telemetry: top attacked ports today, top attacking sources, daily history per port."""
    top = _json(RAW / "dshield" / "topports.json") or {}
    src = _json(RAW / "dshield" / "sources.json") or []
    history = {}
    for path in sorted((RAW / "dshield").glob("port_*.json")):
        port = int(path.stem.split("_")[1])
        rows = [v for k, v in (_json(path) or {}).items() if k.isdigit()]
        history[port] = [{"date": r["date"], "records": int(r["records"] or 0), "sources": int(r["sources"] or 0),
                          "targets": int(r["targets"] or 0)} for r in rows if r.get("date")]
    return {"top_ports": [v for k, v in top.items() if k.isdigit()][:20] if isinstance(top, dict) else [],
            "top_sources": src[:25] if isinstance(src, list) else [], "history": history}


def port_trend(port: int) -> dict | None:
    """Last 7 days against the previous 28-day median: is this service being attacked more than usual?"""
    h = dshield()["history"].get(port) or []
    if len(h) < 21:
        return None
    last, base = h[-7:], h[-35:-7]
    now = statistics.mean(r["records"] for r in last)
    ref = statistics.median(r["records"] for r in base) or 1
    return {"port": port, "service": PORT_NAMES.get(port, str(port)), "last7_mean": round(now),
            "baseline_median": round(ref), "ratio": round(now / ref, 2), "elevated": now / ref >= 1.5,
            "sources_last7": round(statistics.mean(r["sources"] for r in last)),
            "series": [{"date": r["date"], "records": r["records"]} for r in h]}


def _text(raw: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw or ""))).strip()


@lru_cache(maxsize=1)
def cisa_advisories() -> list[dict]:
    path = RAW / "cisa_advisories.xml"
    if not path.exists():
        return []
    out = []
    for it in ET.parse(path).getroot().findall(".//item"):
        link, title = it.findtext("link") or "", it.findtext("title") or ""
        body = _text(it.findtext("description") or "")
        kind = "ics" if "/ics-advisories/" in link else "kev" if "Known Exploited" in title else "other"
        try:
            published = dt.datetime.strptime(it.findtext("pubDate")[:16], "%a, %d %b %y").date().isoformat()
        except (TypeError, ValueError):
            published = None
        out.append({"id": link.rstrip("/").split("/")[-1], "title": title, "link": link, "kind": kind,
                    "published": published, "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", body))),
                    "summary": body[:600], "text": body})
    return out


def advisories_matched(conn: sqlite3.Connection) -> list[dict]:
    """Real CISA advisories, each matched to the constituency's inventory (title first, then body)."""
    products = conn.execute("""SELECT vendor, product, label, product_key, COUNT(*) n, COUNT(DISTINCT org_id) orgs,
                                      GROUP_CONCAT(DISTINCT org_id) org_ids
                               FROM assets GROUP BY vendor, product""").fetchall()
    out = []
    for adv in cisa_advisories():
        hits = []
        for p in products:
            if mentions(p[0], p[1], adv["title"]) or (adv["kind"] == "ics" and mentions(p[0], p[1], adv["text"][:1500])):
                hits.append({"product": p[2], "product_key": p[3], "assets": p[4], "orgs": p[5],
                             "org_ids": sorted(p[6].split(","))})
        known = [c for c in adv["cves"] if conn.execute("SELECT 1 FROM vulns WHERE id = ?", (c,)).fetchone()]
        out.append({**{k: v for k, v in adv.items() if k != "text"}, "matches": hits,
                    "relevant": bool(hits or known), "cves_in_odyssey": known})
    return out


def sources(conn: sqlite3.Connection, cfg: dict) -> list[dict]:
    """The aggregation table: every source, what it adds, how much of it matters here."""
    manifest = _json(RAW / "manifest.json") or {}
    when = {i["file"].replace("\\", "/"): manifest.get("intel_snapshot_at") if i["file"].startswith(("dshield", "cisa"))
            else manifest.get("snapshot_at") for i in manifest.get("items", [])}
    rel = cfg["source_reliability"]
    one = lambda q, *a: conn.execute(q, a).fetchone()[0]  # noqa: E731
    kev_total = len((_json(RAW / "kev.json") or {}).get("vulnerabilities", []))
    feodo = _json(RAW / "feodo_ipblocklist.json") or []
    phish = (RAW / "openphish.txt").read_text(encoding="utf-8").split() if (RAW / "openphish.txt").exists() else []
    ds = dshield()
    adv = advisories_matched(conn)
    meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    month = json.loads(meta.get("nvd_month_counts", "{}"))
    vr = len(list((RAW / "vulnrichment").glob("*.json")))
    forecasts = one("SELECT COUNT(*) FROM vulns WHERE json_extract(record, '$.forecast.p') IS NOT NULL")
    flagged = one("SELECT COUNT(*) FROM vulns WHERE json_extract(record, '$.forecast.flag') = 1")
    decoy_sessions = one("SELECT COALESCE(SUM(sessions), 0) FROM decoy_daily")
    rows = [
        ("NVD CVE feeds", "vulnerabilities", "REAL", rel.get("NVD"), sum(month.values()),
         one("SELECT COUNT(*) FROM vulns"), "CVEs published in 2026 -> candidates naming constituency products",
         "nvd/nvdcve-2.0-2026.json.gz"),
        ("CISA KEV", "confirmed exploitation", "REAL", rel.get("CISA_KEV"), kev_total,
         one("SELECT COUNT(*) FROM vulns WHERE kev != 'null'"), "exploited-in-the-wild catalogue -> affecting our products",
         "kev.json"),
        ("CISA Vulnrichment (SSVC)", "exploitation status", "REAL", rel.get("CISA_ADP"), vr,
         one("SELECT COUNT(*) FROM ledger WHERE kind = 'ssvc.updated'"), "ADP records -> SSVC updates on candidates",
         None),
        ("FIRST EPSS", "exploit likelihood", "REAL", rel.get("EPSS"), None,
         one("SELECT COUNT(*) FROM vulns WHERE epss IS NOT NULL"), "daily scores -> scored candidates",
         "epss_scores-current.csv.gz"),
        ("CISA advisories", "advisories (ICS, alerts)", "REAL", "A", len(adv), sum(a["relevant"] for a in adv),
         "latest advisories -> naming our products or CVEs", "cisa_advisories.xml"),
        ("SANS ISC DShield", "attack telemetry", "REAL", "B", sum(int(p.get("records") or 0) for p in ds["top_ports"]),
         len(ds["history"]), "attack records on today's top ports -> ports our services expose (tracked daily)",
         "dshield/topports.json"),
        ("abuse.ch Feodo Tracker", "C2 indicators", "REAL", rel.get("FEODO"), len(feodo),
         one("SELECT COUNT(*) FROM ledger WHERE kind = 'ioc.sighting'"), "botnet C2 IPs -> seen in our telemetry",
         "feodo_ipblocklist.json"),
        ("OpenPhish", "phishing URLs", "REAL", rel.get("OPENPHISH"), len(phish), 0,
         "live phishing URLs -> impersonating constituency domains", "openphish.txt"),
        ("MITRE ATT&CK", "adversary techniques", "REAL", "A", None, None, "techniques + mitigations used in mapping",
         "enterprise-attack.json"),
        ("Odyssey day-0 forecast", "prediction (model)", "REAL", "B", forecasts, flagged,
         "new CVEs scored on publication day -> flagged likely-to-be-exploited", None),
        ("National decoy grid", "attack telemetry", "SIM", rel.get("DECOY_GRID"), decoy_sessions,
         one("SELECT COUNT(*) FROM decoy_surges"), "decoy sessions -> scanning surges detected", None),
        ("Enterprise firewall logs", "own telemetry", "SIM", rel.get("SIM_LOGS"), None,
         one("SELECT COUNT(*) FROM ledger WHERE kind = 'ioc.sighting'"), "outbound flows -> beacons to known C2", None),
        ("CERT-In style advisories", "advisories", "SIM", rel.get("CERTIN_SIM"), None, None,
         "sample national advisories for the AI analyser", None),
    ]
    out = []
    for name, kind, prov, grade, items, relevant, funnel, file in rows:
        out.append({"name": name, "kind": kind, "provenance": prov, "reliability": grade, "items": items,
                    "relevant": relevant, "funnel": funnel, "updated": when.get(file) if file else meta.get("built_at")})
    return out


def technologies(conn: sqlite3.Connection, campaigns: list[dict]) -> list[dict]:
    """Affected technologies: every product in the constituency with its exposure, open warnings, exploited and
    forecast CVEs, campaign status and global attack activity on its service ports."""
    rows = conn.execute("""
        SELECT s.label, s.vendor, s.product, s.product_key, COUNT(DISTINCT s.id) AS assets,
               COUNT(DISTINCT s.org_id) AS orgs,
               COUNT(DISTINCT CASE WHEN s.zone IN ('internet','dmz') THEN s.id END) AS exposed
        FROM assets s GROUP BY s.label ORDER BY s.label""").fetchall()
    out = []
    status = {c["product_key"]: c["status"] for c in campaigns}
    for r in rows:
        w = conn.execute("""
            SELECT COUNT(DISTINCT CASE WHEN a.tier IN ('Compromise','Critical') THEN a.org_id || a.cve_id END),
                   COUNT(DISTINCT CASE WHEN a.tier = 'High' THEN a.org_id || a.cve_id END),
                   COUNT(DISTINCT CASE WHEN v.kev != 'null' THEN a.cve_id END),
                   COUNT(DISTINCT CASE WHEN json_extract(v.record, '$.forecast.flag') = 1 AND v.kev = 'null'
                                       THEN a.cve_id END),
                   COUNT(DISTINCT CASE WHEN a.tier = 'Compromise' THEN a.asset_id END),
                   COUNT(DISTINCT CASE WHEN a.tier IN ('Compromise','Critical','High') THEN a.asset_id END)
            FROM assessments a JOIN assets s ON s.id = a.asset_id JOIN vulns v ON v.id = a.cve_id
            WHERE a.R > 0 AND s.label = ?""", (r["label"],)).fetchone()
        trend = max((t for p in PORTS.get(r["product_key"], []) if (t := port_trend(p))), key=lambda t: t["ratio"],
                    default=None)
        out.append({"label": r["label"], "vendor": r["vendor"], "product": r["product"],
                    "product_key": r["product_key"], "assets": r["assets"], "orgs": r["orgs"],
                    "internet_facing": r["exposed"], "critical": w[0], "high": w[1], "kev_cves": w[2],
                    "forecast_cves": w[3], "compromised_assets": w[4], "assets_at_risk": w[5],
                    "campaign": status.get(r["product_key"]),
                    "attack_trend": {"port": trend["port"], "service": trend["service"], "ratio": trend["ratio"]}
                    if trend else None})
    return sorted(out, key=lambda x: (-x["compromised_assets"], -x["critical"], -x["kev_cves"]))


_GENERIC = {"corporation", "limited", "services", "service", "finance", "insurance", "energy", "power", "networks",
            "airports", "telecom", "directorate", "centre", "center", "computing", "treasury", "state", "precision",
            "defence", "works", "space", "components", "thermal", "hydro", "digital", "fibre", "metro", "authority",
            "operative", "west", "rail"}


def lookalikes(domain: str) -> set[str]:
    """dnstwist-style permutations of the registrable label: omission, repetition, adjacent swap, homoglyph and
    common phishing affixes. Compared against live phishing hostnames."""
    label = domain.split(".")[0]
    out = {label[:i] + label[i + 1:] for i in range(len(label))}
    out |= {label[:i] + label[i] + label[i:] for i in range(len(label))}
    out |= {label[:i] + label[i + 1] + label[i] + label[i + 2:] for i in range(len(label) - 1)}
    for a, b in (("o", "0"), ("l", "1"), ("i", "1"), ("e", "3"), ("a", "4"), ("s", "5"), ("m", "rn")):
        out.add(label.replace(a, b))
    out |= {f"{label}-{w}" for w in ("login", "secure", "kyc", "update", "verify", "portal", "support")}
    out.discard(label)
    return {x for x in out if len(x) >= 4}


def org_osint(conn: sqlite3.Connection, org_id: str) -> dict:
    org = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    if not org:
        raise KeyError(org_id)
    org = dict(org)
    assets = [dict(r) for r in conn.execute("""SELECT s.*, (SELECT MAX(CASE tier WHEN 'Compromise' THEN 4 WHEN 'Critical'
                    THEN 3 WHEN 'High' THEN 2 WHEN 'Medium' THEN 1 ELSE 0 END) FROM assessments a WHERE a.asset_id = s.id
                    AND a.R > 0) AS worst, (SELECT COUNT(*) FROM assessments a WHERE a.asset_id = s.id AND a.R > 0
                    AND a.tier IN ('Compromise','Critical','High')) AS open_high FROM assets s WHERE s.org_id = ?""",
                                            (org_id,)).fetchall()]
    exposed = [a for a in assets if a["zone"] in ("internet", "dmz")]
    services = {}
    for a in exposed:
        for port in PORTS.get(a["product_key"], []):
            services.setdefault(port, []).append(a["hostname"])
    trends = [t for p in sorted(services) if (t := port_trend(p))]
    for t in trends:
        t["hosts"] = sorted(services[t["port"]])
    keys = {a["product_key"] for a in assets}
    adv = [a for a in advisories_matched(conn) if any(m["product_key"] in keys for m in a["matches"])]
    sightings = [e for e in (dict(r) for r in conn.execute(
        "SELECT ts, subject, payload FROM ledger WHERE kind = 'ioc.sighting'").fetchall())
        if any(e["subject"] == a["id"] for a in assets)]
    phish_hosts = set()
    if (RAW / "openphish.txt").exists():
        for url in (RAW / "openphish.txt").read_text(encoding="utf-8").split():
            host = re.sub(r"^[a-z]+://", "", url).split("/")[0].lower()
            phish_hosts.update(host.split("."))
    variants = lookalikes(org["domain"])
    found = sorted(variants & phish_hosts)
    names = [w.lower() for w in re.findall(r"[A-Za-z]{5,}", org["name"]) if w.lower() not in _GENERIC]
    brand_hits = sorted({h for h in phish_hosts for w in names if w in h})
    feodo = {r["ip_address"] for r in (_json(RAW / "feodo_ipblocklist.json") or [])}
    attackers = {r["ip"] for r in dshield()["top_sources"] if r.get("ip")}
    own_ips = {a["ip"] for a in assets}
    return {
        "org": org,
        "surface": {"assets": len(assets), "internet": sum(a["zone"] == "internet" for a in assets),
                    "dmz": sum(a["zone"] == "dmz" for a in assets),
                    "exposed": sorted(({"hostname": a["hostname"], "product": a["label"], "version": a["version"],
                                        "zone": a["zone"], "open_high": a["open_high"], "worst": a["worst"] or 0,
                                        "ports": PORTS.get(a["product_key"], [])} for a in exposed),
                                      key=lambda x: (-x["worst"], -x["open_high"]))},
        "attack_activity": trends,
        "advisories": [{k: a[k] for k in ("id", "title", "link", "published", "kind", "cves")} for a in adv],
        "indicators": {"c2_sightings": [{"ts": e["ts"], "asset": e["subject"],
                                         "c2": json.loads(e["payload"]).get("dst_defanged"),
                                         "malware": json.loads(e["payload"]).get("malware")} for e in sightings],
                       "own_ips_on_feodo": sorted(own_ips & feodo), "own_ips_in_dshield_top": sorted(own_ips & attackers),
                       "feodo_c2": len(feodo), "dshield_sources": len(attackers)},
        "impersonation": {"domain": org["domain"], "variants_checked": len(variants), "found": found,
                          "brand_hits": brand_hits, "phishing_hosts_scanned": len(phish_hosts)},
    }
