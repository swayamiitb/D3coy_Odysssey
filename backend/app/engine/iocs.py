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
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)
_DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})", re.I)  # checked per token, see _domains
_DOMAIN_TOKEN = re.compile(r"[A-Za-z0-9_.-]{4,253}")  # one linear scan; the strict pattern never backtracks across the text
_URL = re.compile(r"\bhttps?://[^\s'\"<>|,;]+", re.I)  # stops at CSV separators too
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_HEX = re.compile(r"[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_STIX_PAT = re.compile(r"(ipv4-addr|domain-name|url|file):(?:value|hashes\.'?([A-Za-z0-9-]+)'?)\s*=\s*'([^']+)'")
_DOTS = re.compile(r"[\[({](?:\.|dot)[\])}]", re.I)  # [.] (.) {.} [dot] (dot) {dot}
_HXXP = re.compile(r"\bhxxp(s?)(?=://)", re.I)
_FILE_EXT = {"json", "txt", "csv", "exe", "dll", "zip", "pdf", "doc", "xls", "py", "js", "html", "php", "png", "jpg", "log", "md", "yml", "yaml",
             "bat", "cmd", "sh", "vbs", "vbe", "wsf", "hta", "msi", "msp", "lnk", "scr", "sys", "ocx", "cpl", "drv", "inf", "reg", "chm", "jar",
             "class", "swf", "elf", "iso", "img", "dmg", "apk", "pkg", "deb", "rpm", "rar", "gz", "tgz", "tar", "bin", "dat", "ini", "cfg", "conf",
             "tmp", "bak", "rtf", "xml", "docx", "docm", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "jpeg", "gif", "bmp", "ico", "svg", "css",
             "ts", "tsx", "jsx", "avi", "ttf", "woff"}
_TLP = ("CLEAR", "WHITE", "GREEN", "AMBER", "AMBER+STRICT", "RED")
_ORDER = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
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
    text = _DOTS.sub(".", text).replace("\\.", ".")
    text = text.replace("[://]", "://").replace("[:]", ":")  # before the scheme, so hxxp[:]// and hxxp[://] become URLs too
    return _HXXP.sub(lambda m: "http" + m.group(1).lower(), text)


def defang(value: str, type_: str) -> str:
    if type_ in ("ipv4-addr", "domain-name"):
        return value.replace(".", "[.]")
    if type_ == "url":
        m = re.match(r"^(https?://)([^/?#]*)(.*)$", value, flags=re.I | re.S)
        if m:  # the scheme is broken and every dot of the host is bracketed; the path keeps its own dots
            return re.sub(r"^http", "hxxp", m.group(1), flags=re.I) + m.group(2).replace(".", "[.]") + m.group(3)
        return re.sub(r"^http", "hxxp", value, flags=re.I).replace(".", "[.]", 1) if "." in value else value
    return value


def _iso(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _host(url: str) -> str:
    """The host of a URL (or of a bare host name): no scheme, userinfo, port, path or trailing dot, lower-cased."""
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url.strip(), flags=re.I)
    h = re.split(r"[/?#]", h, maxsplit=1)[0].rpartition("@")[2]
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".").lower()


def _tlp(tlp: str | None) -> str:
    """TLP is a controlled vocabulary; anything else (including a spreadsheet formula) is stored as the default."""
    t = (tlp or "AMBER").strip().upper()
    return t if t in _TLP else "AMBER"


def _worst(matches: list[dict]) -> str | None:
    return max((m.get("severity") for m in matches), key=lambda s: _ORDER.get(s, 0), default=None)


def _json_list(text: str | None) -> list:
    try:
        v = json.loads(text or "[]")
    except ValueError:
        return []
    return v if isinstance(v, list) else []


def _domains(body: str):
    """Domain names in free text in one linear pass: candidate tokens first, the strict check per token. A regex over the
    whole text backtracks quadratically on hostile input (megabytes of 'a.a.a.'), which would hold the import for hours."""
    for m in _DOMAIN_TOKEN.finditer(body):
        labels = m.group(0).strip(".-").lower().split(".")
        if len(labels) < 2 or not _DOMAIN.fullmatch(labels[-2] + "." + labels[-1]):
            continue  # the registrable part is not a domain, so no longer suffix is either
        i = len(labels) - 2
        while i > 0 and _LABEL.fullmatch(labels[i - 1]):
            i -= 1
        yield ".".join(labels[i:])


def _typed(found: dict, kind: str, raw: str) -> None:
    """A STIX value is kept only when it is what its type says it is: a bundle is data, not something to trust."""
    v = raw.strip()
    if kind == "ipv4-addr":
        v = v.removesuffix("/32")
        if _IPV4.fullmatch(v) and not v.startswith(("0.", "255.")):
            found[(v, "ipv4-addr")] = None
    elif kind == "domain-name":
        v = v.lower().rstrip(".")
        if _DOMAIN.fullmatch(v):
            found[(v, "domain-name")] = None
    elif kind == "url":
        if re.fullmatch(r"https?://\S+", v, flags=re.I):
            found[(v, "url")] = None
    elif kind == "file":
        v = v.lower()
        if _HEX.fullmatch(v):  # the length decides the algorithm, whatever the label says
            found[(v, {64: "file:sha256", 40: "file:sha1"}.get(len(v), "file:md5"))] = None


def _stix(bundle) -> dict[tuple[str, str], None] | None:
    """Indicators of a STIX 2.1 bundle (patterns, cyber-observables, vulnerabilities), or None when this is not a bundle."""
    objs = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objs, list):
        return None
    found: dict[tuple[str, str], None] = {}
    for o in objs:
        if not isinstance(o, dict):
            continue
        t = o.get("type")
        if t == "indicator" and isinstance(o.get("pattern"), str):
            for m in _STIX_PAT.finditer(o["pattern"]):
                _typed(found, m.group(1), m.group(3))
        elif t in ("ipv4-addr", "domain-name", "url") and isinstance(o.get("value"), str):
            _typed(found, t, o["value"])
        elif t == "file" and isinstance(o.get("hashes"), dict):
            for h in o["hashes"].values():
                if isinstance(h, str):
                    _typed(found, "file", h)
        elif t == "vulnerability":
            refs = o.get("external_references")
            for ref in refs if isinstance(refs, list) else []:
                if isinstance(ref, dict) and ref.get("source_name") == "cve" and isinstance(ref.get("external_id"), str):
                    for m in _CVE.finditer(ref["external_id"]):
                        found[(m.group(0).upper(), "vulnerability")] = None
            if isinstance(o.get("name"), str):
                for m in _CVE.finditer(o["name"]):
                    found[(m.group(0).upper(), "vulnerability")] = None
    return found


def parse(text: str) -> tuple[list[tuple[str, str]], str]:
    """All indicators in free text or a STIX bundle: [(value, type)], and the detected format."""
    text = text or ""
    found: dict[tuple[str, str], None] = {}
    fmt = "text"
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            stix = _stix(json.loads(stripped))
        except (ValueError, RecursionError):
            stix = None
        if stix is not None:
            return list(stix), "stix"
        # valid JSON that is not a bundle, or broken JSON: read it as free text
    body = refang(text)
    if "," in body and "\n" in body:
        fmt = "csv"
    for m in _URL.finditer(body):
        found[(m.group(0).rstrip(".,;:)]}!?*"), "url")] = None
    for m in _IPV4.finditer(body):
        v = m.group(0)
        if not v.startswith(("0.", "255.")):
            found[(v, "ipv4-addr")] = None
    # the word boundaries already keep a shorter hash from being read inside a longer one
    for m in _SHA256.finditer(body):
        found[(m.group(0).lower(), "file:sha256")] = None
    for m in _SHA1.finditer(body):
        found[(m.group(0).lower(), "file:sha1")] = None
    for m in _MD5.finditer(body):
        found[(m.group(0).lower(), "file:md5")] = None
    for m in _CVE.finditer(body):
        found[(m.group(0).upper(), "vulnerability")] = None
    urls_hosts = {_host(k[0]) for k in found if k[1] == "url"}
    for d in _domains(body):
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
        phish = {_host(u) for u in (RAW / "openphish.txt").read_text(encoding="utf-8").split()}
    variants = {}
    for o in orgs.values():
        for v in lookalikes(o["domain"]):
            variants[v] = o["id"]
    kev = {r[0] for r in conn.execute("SELECT id FROM vulns WHERE kev IS NOT NULL AND kev != 'null'")}
    # the exposure record once for every CVE (assessments has no cve_id index: a query per pasted CVE is a table scan each)
    exposure = {r[0]: tuple(r[1:]) for r in conn.execute("""SELECT cve_id, COUNT(*), COUNT(DISTINCT org_id), MAX(CASE tier WHEN 'Compromise' THEN 4
                           WHEN 'Critical' THEN 3 WHEN 'High' THEN 2 WHEN 'Medium' THEN 1 ELSE 0 END), MAX(risk) FROM assessments
                           WHERE R > 0 AND tier != 'Watch' GROUP BY cve_id""")}
    return {"orgs": orgs, "assets": assets, "flows": flows, "sightings": sightings, "shield": shield, "feodo": feodo, "dshield": top,
            "phish": phish, "variants": variants, "kev": kev, "exposure": exposure}


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
        host = _host(value)
        own = [org for org in tel["orgs"].values() if host == org["domain"] or host.endswith("." + org["domain"])]
        for org in own:
            matches.append({"where": "constituency domain", "detail": f"{host} is {org['name']}'s own domain", "provenance": "SIM", "org_id": org["id"], "severity": "High"})
        if not own:  # our own hosts (vpn.vgwc.example) are not look-alikes of ourselves
            for v, org_id in tel["variants"].items():
                if v in host:
                    matches.append({"where": "look-alike", "detail": f"resembles {tel['orgs'][org_id]['domain']} ({tel['orgs'][org_id]['name']})", "provenance": "REAL",
                                    "org_id": org_id, "severity": "High"})
                    break
        if host in tel["phish"]:
            enrich.append({"source": "OpenPhish", "detail": "host in the live phishing feed", "provenance": "REAL"})
    elif type_ == "vulnerability":
        if "exposure" in tel:
            rows = tel["exposure"].get(value)
        else:
            rows = conn.execute("""SELECT COUNT(*), COUNT(DISTINCT org_id), MAX(CASE tier WHEN 'Compromise' THEN 4 WHEN 'Critical' THEN 3
                                   WHEN 'High' THEN 2 WHEN 'Medium' THEN 1 ELSE 0 END), MAX(risk) FROM assessments
                                   WHERE cve_id = ? AND R > 0 AND tier != 'Watch'""", (value,)).fetchone()
        if rows and rows[0]:
            worst = {4: "Compromise", 3: "Critical", 2: "High", 1: "Medium", 0: "Watch"}[rows[2] or 0]
            matches.append({"where": "exposure record", "detail": f"{rows[0]} exposed asset(s) at {rows[1]} organisation(s), worst {worst}, risk {rows[3] or 0:.0f}",
                            "provenance": "REAL · SIM", "severity": "Critical" if worst in ("Compromise", "Critical") else "High", "assets": rows[0], "orgs": rows[1]})
        if value in tel["kev"]:
            enrich.append({"source": "CISA KEV", "detail": "exploited in the wild", "provenance": "REAL"})
    else:
        enrich.append({"source": "Odyssey", "detail": "no file telemetry is collected; hash kept for exchange and export", "provenance": "SIM"})
    return matches, enrich, _worst(matches)


def import_text(conn: sqlite3.Connection, text: str, source: str = "analyst paste", tlp: str = "AMBER", live: dict | None = None,
                now: dt.datetime | None = None, tags: list[str] | None = None) -> dict:
    """Extract, store, match and record. Returns the import summary with every indicator and its matches."""
    import time
    ensure(conn)
    t0 = time.perf_counter()
    now = now or dt.datetime.now(dt.timezone.utc)
    tlp = _tlp(tlp)
    found, fmt = parse(text)
    tel = _telemetry(conn, live)
    ledger = Ledger(conn=conn)
    by_type: dict[str, int] = {}
    rows, new, matched = [], 0, 0
    for value, type_ in found:
        by_type[type_] = by_type.get(type_, 0) + 1
        matches, enrich, severity = match_one(conn, value, type_, tel)
        existing = conn.execute("SELECT id, matched, matches FROM iocs WHERE value = ? AND type = ?", (value, type_)).fetchone()
        if existing:
            # what the live engine saw since the last import (mark_live_match) is not in this import's telemetry view:
            # keep it, or re-importing the same advisory would silently un-match the indicator and re-ledger it later
            live_hits = [m for m in _json_list(existing[2]) if m.get("where") == "live flows"]
            if live_hits:
                matches = matches + live_hits
                severity = _worst(matches)
            conn.execute("UPDATE iocs SET last_seen = ?, matches = ?, enrich = ?, matched = ?, severity = ? WHERE id = ?",
                         (_iso(now), json.dumps(matches), json.dumps(enrich), int(bool(matches)), severity, existing[0]))
            ioc_id, was_matched = existing[0], bool(existing[1])
        else:
            cur = conn.execute("""INSERT INTO iocs (value, type, defanged, source, tlp, tags, added_at, first_seen, last_seen, matched, matches, enrich, severity)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (value, type_, defang(value, type_), source, tlp, json.dumps(tags or []), _iso(now), _iso(now), _iso(now),
                                int(bool(matches)), json.dumps(matches), json.dumps(enrich), severity))
            ioc_id, was_matched, new = cur.lastrowid, False, new + 1
        if matches:
            matched += 1
            if not was_matched:
                conn.commit()
                ledger.append(ts=_iso(now), kind="ioc.match", subject=f"ioc:{value}", source="IOC_IMPORT",
                              provenance="SIM" if all(m["provenance"] == "SIM" for m in matches) else "REAL · SIM",
                              payload={"value": defang(value, type_), "type": type_, "source": source, "tlp": tlp, "severity": severity,
                                       "where": [m["where"] for m in matches], "matches": matches, "org_id": next((m.get("org_id") for m in matches if m.get("org_id")), None)})
        rows.append({"id": ioc_id, "value": value, "defanged": defang(value, type_), "type": type_, "matched": bool(matches), "severity": severity,
                     "matches": matches, "enrich": enrich})
    conn.commit()
    seconds = round(time.perf_counter() - t0, 2)
    conn.execute("INSERT INTO ioc_imports (ts, source, tlp, format, found, new, matched, by_type, seconds) VALUES (?,?,?,?,?,?,?,?,?)",
                 (_iso(now), source, tlp, fmt, len(found), new, matched, json.dumps(by_type), seconds))
    conn.commit()
    if found:
        ledger.append(ts=_iso(now), kind="ioc.import", subject=source, source="ANALYST", provenance="HUMAN",
                      payload={"format": fmt, "found": len(found), "new": new, "matched": matched, "by_type": by_type, "tlp": tlp})
        conn.commit()
    order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0, None: -1}
    rows.sort(key=lambda r: (-int(r["matched"]), -order.get(r["severity"], -1), r["type"], r["value"]))
    return {"source": source, "tlp": tlp, "format": fmt, "found": len(found), "new": new, "matched": matched, "by_type": by_type,
            "seconds": seconds, "indicators": rows}


def list_iocs(conn: sqlite3.Connection, matched_only: bool = False, limit: int = 200) -> dict:
    ensure(conn)
    limit = max(0, int(limit))  # a negative LIMIT means "no limit" to SQLite
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


def _cell(v):
    """A CSV cell a spreadsheet will not execute: a leading = + - @ tab or CR is quoted (CSV formula injection)."""
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def export_rows(conn: sqlite3.Connection, matched_only: bool = False) -> list[dict]:
    d = list_iocs(conn, matched_only, limit=100000)
    return [{k: _cell(v) for k, v in {"value": r["value"], "defanged": r["defanged"], "type": r["type"], "source": r["source"], "tlp": r["tlp"],
                                      "severity": r["severity"], "matched": r["matched"], "where": "; ".join(m["where"] for m in r["matches"]),
                                      "enrichment": "; ".join(e["detail"] for e in r["enrich"]), "first_seen": r["first_seen"], "last_seen": r["last_seen"]}.items()}
            for r in d["indicators"]]
