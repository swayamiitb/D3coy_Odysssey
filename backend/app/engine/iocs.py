"""Bulk indicator import and the matching engine.

Paste or upload anything (a CSV, a plain list, an advisory, a STIX 2.1 bundle): every IPv4 address, domain, URL, file
hash and CVE id in it is extracted, refanged, de-duplicated and stored with its source and TLP. Each indicator is then
matched against what Odyssey actually holds: the live firewall flows and C2 sightings (SIM telemetry), the HTTP
shield's attackers, the constituency's own addresses and domains (and their look-alikes), the exposure record for CVEs,
and enriched from the public lists (Feodo Tracker, DShield, OpenPhish, CISA KEV). A match is a ledger event
(`ioc.match`); from then on the live engine also matches new flows against the imported addresses on every tick.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
from pathlib import Path

from .intel import PORTS, dshield, lookalikes  # noqa: F401  (PORTS kept for callers)
from .ledger import Ledger

RAW = Path(__file__).resolve().parents[3] / "data" / "raw"
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN = re.compile(r"\b(?=.{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I)
_URL = re.compile(r"\bhttps?://[^\s'\"<>|]+", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_FILE_EXT = {"json", "txt", "csv", "exe", "dll", "zip", "pdf", "doc", "xls", "py", "js", "html", "php", "png", "jpg", "log", "md", "yml", "yaml"}
TYPES = ("ipv4-addr", "domain-name", "url", "file:sha256", "file:sha1", "file:md5", "vulnerability")


def ensure(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY, value TEXT NOT NULL, type TEXT NOT NULL, defanged TEXT NOT NULL, source TEXT NOT NULL,
            tlp TEXT NOT NULL DEFAULT 'AMBER', tags TEXT, note TEXT, added_at TEXT NOT NULL, first_seen TEXT, last_seen TEXT,
            matched INTEGER NOT NULL DEFAULT 0, matches TEXT NOT NULL DEFAULT '[]', enrich TEXT NOT NULL DEFAULT '[]',
            severity TEXT, UNIQUE(value, type));
        CREATE TABLE IF NOT EXISTS ioc_imports (
            id INTEGER PRIMARY KEY, ts TEXT NOT NULL, source TEXT NOT NULL, tlp TEXT NOT NULL, format TEXT NOT NULL,
            found INTEGER NOT NULL, new INTEGER NOT NULL, matched INTEGER NOT NULL, by_type TEXT NOT NULL, seconds REAL NOT NULL);
    """)
    conn.commit()


def refang(text: str) -> str:
    return (text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[dot]", ".").replace("\\.", ".")
            .replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[:]", ":").replace("[://]", "://"))


def defang(value: str, type_: str) -> str:
    if type_ in ("ipv4-addr", "domain-name"):
        return value.replace(".", "[.]")
    if type_ == "url":
        return re.sub(r"^http", "hxxp", value, flags=re.I).replace(".", "[.]", 1) if "." in value else value
    return value


def _iso(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse(text: str) -> tuple[list[tuple[str, str]], str]:
    """All indicators in free text or a STIX bundle: [(value, type)], and the detected format."""
    text = text or ""
    found: dict[tuple[str, str], None] = {}
    fmt = "text"
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            bundle = json.loads(stripped)
            fmt = "stix"
            for o in bundle.get("objects", []):
                if o.get("type") == "indicator" and o.get("pattern"):
                    for m in re.finditer(r"\[?(ipv4-addr|domain-name|url|file):(?:value|hashes\.'?(SHA-256|SHA-1|MD5)'?)\s*=\s*'([^']+)'", o["pattern"]):
                        kind, hsh, val = m.group(1), m.group(2), m.group(3)
                        t = {"ipv4-addr": "ipv4-addr", "domain-name": "domain-name", "url": "url"}.get(kind) or {"SHA-256": "file:sha256", "SHA-1": "file:sha1", "MD5": "file:md5"}.get(hsh or "", "file:sha256")
                        found[(val.lower() if t != "url" else val, t)] = None
                if o.get("type") == "vulnerability":
                    for ref in o.get("external_references", []):
                        if ref.get("source_name") == "cve" and ref.get("external_id"):
                            found[(ref["external_id"].upper(), "vulnerability")] = None
                    for m in _CVE.finditer(o.get("name", "")):
                        found[(m.group(0).upper(), "vulnerability")] = None
            return list(found), fmt
        except ValueError:
            pass
    body = refang(text)
    if "," in body and "\n" in body:
        fmt = "csv"
    for m in _URL.finditer(body):
        found[(m.group(0).rstrip(".,;)"), "url")] = None
    for m in _IPV4.finditer(body):
        v = m.group(0)
        if not v.startswith(("0.", "255.")):
            found[(v, "ipv4-addr")] = None
    for m in _SHA256.finditer(body):
        found[(m.group(0).lower(), "file:sha256")] = None
    for m in _SHA1.finditer(body):
        if not any(k[0] == m.group(0).lower() for k in found):
            found[(m.group(0).lower(), "file:sha1")] = None
    for m in _MD5.finditer(body):
        if not any(m.group(0).lower() in k[0] for k in found if k[1].startswith("file:")):
            found[(m.group(0).lower(), "file:md5")] = None
    for m in _CVE.finditer(body):
        found[(m.group(0).upper(), "vulnerability")] = None
    urls_hosts = {re.sub(r"^https?://", "", k[0], flags=re.I).split("/")[0].lower() for k in found if k[1] == "url"}
    for m in _DOMAIN.finditer(body):
        d = m.group(0).lower()
        if d.rsplit(".", 1)[-1] in _FILE_EXT or _IPV4.fullmatch(d) or d in urls_hosts:
            continue
        found[(d, "domain-name")] = None
    return list(found), fmt


def _telemetry(conn, live: dict | None) -> dict:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    orgs = {r["id"]: dict(r) for r in cur.execute("SELECT id, name, domain FROM orgs")}
    assets = {r["ip"]: dict(r) for r in cur.execute("SELECT id, ip, hostname, org_id, product_key FROM assets")}
    flows = list((live or {}).get("flow_rows") or [])
    sightings = {}
    for ts, subject, payload in conn.execute("SELECT ts, subject, payload FROM ledger WHERE kind = 'ioc.sighting'"):
        p = json.loads(payload)
        sightings[refang(p.get("dst_defanged") or p.get("dst") or "")] = {"ts": ts, "asset_id": p.get("asset_id", subject), "malware": p.get("malware")}
    shield = {}
    for ts, subject in conn.execute("SELECT ts, subject FROM ledger WHERE kind LIKE 'shield.detect.%' ORDER BY ts"):
        app, _, ip = subject.rpartition(":")
        shield[ip] = {"ts": ts, "app": app}
    feodo = {}
    try:
        for r in json.loads((RAW / "feodo_ipblocklist.json").read_text(encoding="utf-8")):
            if r.get("ip_address"):
                feodo[r["ip_address"]] = r.get("malware")
    except (OSError, ValueError):
        pass
    top = {(s.get("ip") or s.get("ipv4")): s for s in dshield().get("top_sources", []) if (s.get("ip") or s.get("ipv4"))}
    phish = set()
    if (RAW / "openphish.txt").exists():
        phish = {re.sub(r"^[a-z]+://", "", u).split("/")[0].lower() for u in (RAW / "openphish.txt").read_text(encoding="utf-8").split()}
    variants = {}
    for o in orgs.values():
        for v in lookalikes(o["domain"]):
            variants[v] = o["id"]
    kev = {r[0] for r in conn.execute("SELECT id FROM vulns WHERE kev IS NOT NULL AND kev != 'null'")}
    return {"orgs": orgs, "assets": assets, "flows": flows, "sightings": sightings, "shield": shield, "feodo": feodo, "dshield": top,
            "phish": phish, "variants": variants, "kev": kev}


def match_one(conn, value: str, type_: str, tel: dict) -> tuple[list[dict], list[dict], str | None]:
    """(matches in our telemetry, enrichment from public lists, severity)."""
    matches, enrich = [], []
    if type_ == "ipv4-addr":
        if value in tel["assets"]:
            a = tel["assets"][value]
            matches.append({"where": "constituency asset", "detail": f"{a['hostname']} ({a['org_id']}) is one of our own systems", "provenance": "SIM",
                            "org_id": a["org_id"], "asset_id": a["id"], "severity": "Critical"})
        if value in tel["sightings"]:
            s = tel["sightings"][value]
            matches.append({"where": "C2 sighting", "detail": f"beaconed to from {s['asset_id']} at {s['ts'][:16]}", "provenance": "SIM",
                            "asset_id": s["asset_id"], "severity": "Critical"})
        hits = [f for f in tel["flows"] if f.get("dst") == value or f.get("src") == value]
        if hits:
            srcs = sorted({f["src"] for f in hits if f.get("dst") == value})[:5]
            matches.append({"where": "firewall flows", "detail": f"{len(hits)} flow(s) in the live window" + (f" from {', '.join(srcs)}" if srcs else ""),
                            "provenance": "SIM", "severity": "High", "flows": len(hits)})
        if value in tel["shield"]:
            s = tel["shield"][value]
            matches.append({"where": "HTTP shield", "detail": f"attacked {s['app']} at {s['ts'][:16]}", "provenance": "SIM", "severity": "High"})
        if value in tel["feodo"]:
            enrich.append({"source": "abuse.ch Feodo Tracker", "detail": f"known {tel['feodo'][value] or 'botnet'} C2", "provenance": "REAL"})
        if value in tel["dshield"]:
            s = tel["dshield"][value]
            enrich.append({"source": "SANS ISC DShield", "detail": f"top attack source: {s.get('attacks')} records against {s.get('targets')} targets", "provenance": "REAL"})
    elif type_ in ("domain-name", "url"):
        host = re.sub(r"^https?://", "", value, flags=re.I).split("/")[0].lower() if type_ == "url" else value
        for org in tel["orgs"].values():
            if host == org["domain"] or host.endswith("." + org["domain"]):
                matches.append({"where": "constituency domain", "detail": f"{host} is {org['name']}'s own domain", "provenance": "SIM", "org_id": org["id"], "severity": "High"})
        for v, org_id in tel["variants"].items():
            if v in host and host != tel["orgs"][org_id]["domain"]:
                matches.append({"where": "look-alike", "detail": f"resembles {tel['orgs'][org_id]['domain']} ({tel['orgs'][org_id]['name']})", "provenance": "REAL",
                                "org_id": org_id, "severity": "High"})
                break
        if host in tel["phish"]:
            enrich.append({"source": "OpenPhish", "detail": "host in the live phishing feed", "provenance": "REAL"})
    elif type_ == "vulnerability":
        rows = conn.execute("""SELECT COUNT(*), COUNT(DISTINCT org_id), MAX(CASE tier WHEN 'Compromise' THEN 4 WHEN 'Critical' THEN 3
                               WHEN 'High' THEN 2 WHEN 'Medium' THEN 1 ELSE 0 END), MAX(risk) FROM assessments
                               WHERE cve_id = ? AND R > 0 AND tier != 'Watch'""", (value,)).fetchone()
        if rows and rows[0]:
            worst = {4: "Compromise", 3: "Critical", 2: "High", 1: "Medium", 0: "Watch"}[rows[2] or 0]
            matches.append({"where": "exposure record", "detail": f"{rows[0]} exposed asset(s) at {rows[1]} organisation(s), worst {worst}, risk {rows[3]:.0f}",
                            "provenance": "REAL · SIM", "severity": "Critical" if worst in ("Compromise", "Critical") else "High", "assets": rows[0], "orgs": rows[1]})
        if value in tel["kev"]:
            enrich.append({"source": "CISA KEV", "detail": "exploited in the wild", "provenance": "REAL"})
    else:
        enrich.append({"source": "Odyssey", "detail": "no file telemetry is collected; hash kept for exchange and export", "provenance": "SIM"})
    order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    severity = max((m["severity"] for m in matches), key=lambda s: order.get(s, 0), default=None)
    return matches, enrich, severity


def import_text(conn: sqlite3.Connection, text: str, source: str = "analyst paste", tlp: str = "AMBER", live: dict | None = None,
                now: dt.datetime | None = None, tags: list[str] | None = None) -> dict:
    """Extract, store, match and record. Returns the import summary with every indicator and its matches."""
    import time
    ensure(conn)
    t0 = time.perf_counter()
    now = now or dt.datetime.now(dt.timezone.utc)
    found, fmt = parse(text)
    tel = _telemetry(conn, live)
    ledger = Ledger(conn=conn)
    by_type: dict[str, int] = {}
    rows, new, matched = [], 0, 0
    for value, type_ in found:
        by_type[type_] = by_type.get(type_, 0) + 1
        matches, enrich, severity = match_one(conn, value, type_, tel)
        existing = conn.execute("SELECT id, matched FROM iocs WHERE value = ? AND type = ?", (value, type_)).fetchone()
        if existing:
            conn.execute("UPDATE iocs SET last_seen = ?, matches = ?, enrich = ?, matched = ?, severity = ? WHERE id = ?",
                         (_iso(now), json.dumps(matches), json.dumps(enrich), int(bool(matches)), severity, existing[0]))
            ioc_id, was_matched = existing[0], bool(existing[1])
        else:
            cur = conn.execute("""INSERT INTO iocs (value, type, defanged, source, tlp, tags, added_at, first_seen, last_seen, matched, matches, enrich, severity)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (value, type_, defang(value, type_), source, tlp.upper(), json.dumps(tags or []), _iso(now), _iso(now), _iso(now),
                                int(bool(matches)), json.dumps(matches), json.dumps(enrich), severity))
            ioc_id, was_matched, new = cur.lastrowid, False, new + 1
        if matches:
            matched += 1
            if not was_matched:
                conn.commit()
                ledger.append(ts=_iso(now), kind="ioc.match", subject=f"ioc:{value}", source="IOC_IMPORT",
                              provenance="SIM" if all(m["provenance"] == "SIM" for m in matches) else "REAL · SIM",
                              payload={"value": defang(value, type_), "type": type_, "source": source, "tlp": tlp.upper(), "severity": severity,
                                       "where": [m["where"] for m in matches], "matches": matches, "org_id": next((m.get("org_id") for m in matches if m.get("org_id")), None)})
        rows.append({"id": ioc_id, "value": value, "defanged": defang(value, type_), "type": type_, "matched": bool(matches), "severity": severity,
                     "matches": matches, "enrich": enrich})
    conn.commit()
    seconds = round(time.perf_counter() - t0, 2)
    conn.execute("INSERT INTO ioc_imports (ts, source, tlp, format, found, new, matched, by_type, seconds) VALUES (?,?,?,?,?,?,?,?,?)",
                 (_iso(now), source, tlp.upper(), fmt, len(found), new, matched, json.dumps(by_type), seconds))
    conn.commit()
    if found:
        ledger.append(ts=_iso(now), kind="ioc.import", subject=source, source="ANALYST", provenance="HUMAN",
                      payload={"format": fmt, "found": len(found), "new": new, "matched": matched, "by_type": by_type, "tlp": tlp.upper()})
        conn.commit()
    order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0, None: -1}
    rows.sort(key=lambda r: (-int(r["matched"]), -order.get(r["severity"], -1), r["type"], r["value"]))
    return {"source": source, "tlp": tlp.upper(), "format": fmt, "found": len(found), "new": new, "matched": matched, "by_type": by_type,
            "seconds": seconds, "indicators": rows}


def list_iocs(conn: sqlite3.Connection, matched_only: bool = False, limit: int = 200) -> dict:
    ensure(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    q = "SELECT * FROM iocs" + (" WHERE matched = 1" if matched_only else "") + " ORDER BY matched DESC, CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, id DESC LIMIT ?"
    rows = []
    for r in cur.execute(q, (limit,)):
        d = dict(r)
        d["matches"], d["enrich"], d["tags"] = json.loads(d["matches"]), json.loads(d["enrich"]), json.loads(d["tags"] or "[]")
        rows.append(d)
    total = conn.execute("SELECT COUNT(*), SUM(matched) FROM iocs").fetchone()
    by_type = {r[0]: r[1] for r in conn.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type")}
    imports = [dict(r) for r in cur.execute("SELECT * FROM ioc_imports ORDER BY id DESC LIMIT 10")]
    for i in imports:
        i["by_type"] = json.loads(i["by_type"])
    return {"total": total[0] or 0, "matched": total[1] or 0, "by_type": by_type, "imports": imports, "indicators": rows}


def live_sets(conn: sqlite3.Connection) -> dict[str, set[str]]:
    """The imported addresses and domains the live engine matches flows against."""
    ensure(conn)
    ips = {r[0] for r in conn.execute("SELECT value FROM iocs WHERE type = 'ipv4-addr'")}
    domains = {r[0] for r in conn.execute("SELECT value FROM iocs WHERE type = 'domain-name'")}
    return {"ipv4-addr": ips, "domain-name": domains}


def mark_live_match(conn: sqlite3.Connection, value: str, detail: dict, now: dt.datetime) -> None:
    """A live flow touched an imported address: record it on the indicator and in the ledger."""
    ensure(conn)
    row = conn.execute("SELECT id, matches, matched FROM iocs WHERE value = ? AND type = 'ipv4-addr'", (value,)).fetchone()
    if not row:
        return
    matches = json.loads(row[1])
    matches = [m for m in matches if m["where"] != "live flows"] + [{"where": "live flows", "detail": detail.get("title", "seen in live flows"),
                                                                     "provenance": "SIM", "severity": "High", "ts": _iso(now), **{k: v for k, v in detail.items() if k in ("src", "dst", "dport", "asset", "org_id")}}]
    conn.execute("UPDATE iocs SET matched = 1, matches = ?, last_seen = ?, severity = COALESCE(severity, 'High') WHERE id = ?",
                 (json.dumps(matches), _iso(now), row[0]))
    conn.commit()
    Ledger(conn=conn).append(ts=_iso(now), kind="ioc.match", subject=f"ioc:{value}", source="LIVE_FLOWS", provenance="SIM",
                             payload={"value": value.replace(".", "[.]"), "type": "ipv4-addr", "where": ["live flows"], "severity": "High",
                                      "matches": matches[-1:], "org_id": detail.get("org_id")})
    conn.commit()


def export_rows(conn: sqlite3.Connection, matched_only: bool = False) -> list[dict]:
    d = list_iocs(conn, matched_only, limit=100000)
    return [{"value": r["value"], "defanged": r["defanged"], "type": r["type"], "source": r["source"], "tlp": r["tlp"], "severity": r["severity"],
             "matched": r["matched"], "where": "; ".join(m["where"] for m in r["matches"]), "enrichment": "; ".join(e["detail"] for e in r["enrich"]),
             "first_seen": r["first_seen"], "last_seen": r["last_seen"]} for r in d["indicators"]]
