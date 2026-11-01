"""Consented self-assessment of an operator's own web application: what its own HTTP responses reveal.

This is a defensive posture check, the kind an operator runs against its own site, not a tool for reaching other
people's systems. Two conditions are enforced in code, and both must hold or the request is refused with its reason:

  1. the caller passes `consent=True`, and
  2. the target is provably the operator's own: its host is loopback, RFC 1918 private, link-local or carrier-grade
     NAT space, OR it is an application the HTTP-shield agent has already registered (the running agent is the
     operator's proof of ownership).

A public address with no registered agent is always refused. The check reads only the target's own answers over
plain GET/HEAD, never sends a payload, makes at most a few dozen requests with a short timeout and a pause between
them, and honours a per-target cooldown. It reports missing transport security, missing response-hardening headers,
inadvertently reachable development or metadata endpoints, a technology fingerprint (to link the app to known CVEs
through the existing exposure data) and locally reachable service ports. Every finding carries a CWE, a remediation
and the evidence; every scan and every serious finding is written to the audit ledger.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import socket
import sqlite3
import ssl
import threading
import time
from urllib.parse import urlsplit

MAX_REQUESTS = 40
TIMEOUT_S = 2.0
PAUSE_S = 0.05
COOLDOWN_S = 60
REFUSAL = "Odyssey scans only systems you own: deploy the agent or run from inside the network"
PORTS = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
SENSITIVE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MS SQL", 3306: "MySQL", 3389: "RDP",
                   5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}
WEIGHT = {"Critical": 30, "High": 15, "Medium": 7, "Low": 3, "Info": 0}
_COOLDOWN: dict[str, float] = {}
_LOCK = threading.Lock()

# Development and metadata endpoints that should not answer to an outside GET. Each: (path, severity, short reason).
# These are the standard items an owned-asset posture check looks for (the same set OWASP/Nikto-style self-checks use).
EXPOSURE_PATHS = [
    ("/.git/HEAD", "Critical", "source-control metadata reachable"),
    ("/.env", "Critical", "environment/secrets file reachable"),
    ("/.svn/entries", "High", "source-control metadata reachable"),
    ("/.DS_Store", "Low", "directory listing artefact reachable"),
    ("/backup.zip", "High", "backup archive reachable"),
    ("/config.php.bak", "High", "backup of a config file reachable"),
    ("/phpinfo.php", "High", "PHP configuration page reachable"),
    ("/server-status", "Medium", "web-server status page reachable"),
    ("/actuator", "High", "framework management base reachable"),
    ("/actuator/env", "Critical", "framework environment endpoint reachable"),
    ("/swagger.json", "Medium", "API specification reachable"),
    ("/openapi.json", "Medium", "API specification reachable"),
    ("/api/docs", "Medium", "API documentation reachable"),
    ("/admin", "Info", "admin entry point reachable"),
    ("/login", "Info", "login entry point reachable"),
    ("/wp-login.php", "Info", "WordPress login reachable"),
    ("/console", "Medium", "console endpoint reachable"),
    ("/debug", "Medium", "debug endpoint reachable"),
    ("/robots.txt", "Info", "robots policy published"),
    ("/sitemap.xml", "Info", "sitemap published"),
]
SECURITY_HEADERS = [
    ("content-security-policy", "Medium", "Content-Security-Policy", "Add a Content-Security-Policy to constrain script and frame sources."),
    ("x-content-type-options", "Low", "X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."),
    ("referrer-policy", "Low", "Referrer-Policy", "Set a Referrer-Policy such as strict-origin-when-cross-origin."),
    ("permissions-policy", "Low", "Permissions-Policy", "Set a Permissions-Policy to disable unused browser features."),
]
FRAMEWORK_HINTS = [
    (re.compile(r"django", re.I), "django"), (re.compile(r"flask|werkzeug", re.I), "flask"),
    (re.compile(r"express", re.I), "express"), (re.compile(r"laravel", re.I), "laravel"),
    (re.compile(r"wp-content|wordpress", re.I), "wordpress"), (re.compile(r"fastapi|uvicorn", re.I), "fastapi"),
    (re.compile(r"nginx", re.I), "nginx"), (re.compile(r"apache", re.I), "httpd"),
    (re.compile(r"tomcat|coyote", re.I), "tomcat"), (re.compile(r"iis", re.I), "win2022"),
]


# --------------------------------------------------------------------------------------------------- ownership gate
def _is_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        cgnat = isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10")
        if not (ip.is_private or ip.is_loopback or ip.is_link_local or cgnat):
            return False
    return bool(infos)


def _registered_hostports(conn: sqlite3.Connection) -> set[str]:
    """host:port of every app the HTTP-shield agent has registered this session; the agent proves ownership."""
    out: set[str] = set()
    try:
        from .. import shield
        if shield.ENGINE is not None:
            for app in shield.ENGINE.apps.values():
                base = app.get("base_url")
                if base:
                    u = urlsplit(base if "://" in base else "http://" + base)
                    if u.hostname:
                        out.add(f"{u.hostname.lower()}:{u.port or (443 if u.scheme == 'https' else 80)}")
    except Exception:  # noqa: BLE001 - no shield is just no extra permission
        pass
    return out


def allowed(url: str, conn: sqlite3.Connection | None = None) -> tuple[bool, str]:
    u = urlsplit(url if "://" in url else "http://" + url)
    host = (u.hostname or "").lower()
    if not host:
        return False, "no host in the target URL"
    if u.scheme not in ("http", "https"):
        return False, "only http and https targets are scanned"
    if _is_private(host):
        return True, "private / loopback address (a system on your own network)"
    port = u.port or (443 if u.scheme == "https" else 80)
    if conn is not None and f"{host}:{port}" in _registered_hostports(conn):
        return True, "an application registered by your Odyssey agent (the agent is your proof of ownership)"
    return False, REFUSAL


# ---------------------------------------------------------------------------------------------------------- checks
def _default_fetch(url: str, method: str = "GET") -> dict:
    import httpx
    r = httpx.request(method, url, timeout=TIMEOUT_S, follow_redirects=False,
                      headers={"User-Agent": "Odyssey-EWS/0.2 (owned-asset self-check)"})
    return {"status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()},
            "body": r.text[:2000], "url": str(r.url)}


def _finding(check, severity, title, detail, evidence, cwe, fix, path=None) -> dict:
    return {"check": check, "severity": severity, "title": title, "detail": detail, "evidence": evidence[:300],
            "cwe": cwe, "fix": fix, "path": path, "provenance": "REAL"}


def _grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 55 else "E" if score >= 40 else "F"


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except (OSError, socket.timeout):
        return False


def _cert_days(host: str, port: int) -> tuple[int | None, bool]:
    """Days until the target's own TLS certificate expires, and whether it is self-signed. Verification is off on
    purpose: we are inspecting the operator's own certificate, not trusting a channel to it. Best-effort."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        from cryptography import x509  # type: ignore
        pem = ssl.DER_cert_to_PEM_cert(der)
        c = x509.load_pem_x509_certificate(pem.encode())
        days = (c.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days
        return days, c.issuer == c.subject
    except Exception:  # noqa: BLE001 - cryptography may be absent or the host may not speak TLS; the expiry check is best-effort
        return None, False


def scan(conn: sqlite3.Connection, url: str, consent: bool, org_id: str | None = None, now: dt.datetime | None = None,
         fetch=None) -> dict:
    ensure(conn)
    now = now or dt.datetime.now(dt.timezone.utc)
    now_iso = now.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    u = urlsplit(url if "://" in url else "http://" + url)
    host = (u.hostname or "").lower()
    port = u.port or (443 if u.scheme == "https" else 80)
    base = f"{u.scheme}://{u.netloc}"
    if not consent:
        return _refused(conn, url, host, org_id, now_iso, "consent was not given for this scan")
    ok, reason = allowed(url, conn)
    if not ok:
        return _refused(conn, url, host, org_id, now_iso, reason)
    with _LOCK:
        last = _COOLDOWN.get(f"{host}:{port}", 0)
        if time.time() - last < COOLDOWN_S:
            return _refused(conn, url, host, org_id, now_iso, f"cooldown: this target was scanned under {COOLDOWN_S}s ago")
        _COOLDOWN[f"{host}:{port}"] = time.time()

    fetch = fetch or _default_fetch
    t0 = time.perf_counter()
    findings: list[dict] = []
    requests = 0

    # 1. the base response: transport, hardening headers, version disclosure, cookie flags, fingerprint
    base_resp = None
    try:
        base_resp = fetch(base + "/", "GET")
        requests += 1
    except Exception as exc:  # noqa: BLE001
        return _refused(conn, url, host, org_id, now_iso, f"target did not answer: {type(exc).__name__}", status="unreachable")
    hdr = base_resp.get("headers", {})
    body = base_resp.get("body", "") or ""

    if u.scheme == "http":
        findings.append(_finding("transport", "High", "Served over plain HTTP", "Traffic to this application is not encrypted in transit.",
                                 f"GET {base}/ -> {base_resp['status']} over http", "CWE-319", "Serve the application over HTTPS and redirect HTTP to HTTPS."))
    else:
        if "strict-transport-security" not in hdr:
            findings.append(_finding("headers", "Low", "No HSTS header", "Strict-Transport-Security is not set.",
                                     "no strict-transport-security in the response", "CWE-319", "Set Strict-Transport-Security with a long max-age."))
        days, self_signed = _cert_days(host, port)
        if self_signed:
            findings.append(_finding("tls", "High", "Self-signed certificate", "The TLS certificate is self-signed.",
                                     "issuer equals subject", "CWE-295", "Use a certificate from a trusted CA."))
        if days is not None and days < 30:
            findings.append(_finding("tls", "High" if days >= 0 else "Critical", "Certificate expiring or expired",
                                     f"The TLS certificate expires in {days} day(s).", f"not_valid_after in {days} day(s)", "CWE-298", "Renew the certificate."))

    frame_ok = "x-frame-options" in hdr or "frame-ancestors" in (hdr.get("content-security-policy", "").lower())
    if not frame_ok:
        findings.append(_finding("headers", "Low", "No clickjacking protection", "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
                                 "no x-frame-options and no frame-ancestors", "CWE-1021", "Set X-Frame-Options: DENY or a CSP frame-ancestors directive."))
    for key, severity, label, fix in SECURITY_HEADERS:
        if key not in hdr:
            findings.append(_finding("headers", severity, f"No {label} header", f"{label} is not set on the base response.",
                                     f"no {key} in the response", "CWE-693", fix))
    disclosed = [(h, hdr[h]) for h in ("server", "x-powered-by") if hdr.get(h) and re.search(r"\d", hdr[h])]
    for h, v in disclosed:
        findings.append(_finding("disclosure", "Low", "Software version disclosed", f"The {h} header names a version.",
                                 f"{h}: {v}", "CWE-200", f"Remove the version from the {h} header."))
    cookies = hdr.get("set-cookie", "")
    if cookies and ("secure" not in cookies.lower() or "httponly" not in cookies.lower()):
        findings.append(_finding("cookies", "Medium", "Cookie without Secure/HttpOnly", "A Set-Cookie lacks the Secure and/or HttpOnly attribute.",
                                 cookies[:120], "CWE-1004", "Set Secure, HttpOnly and SameSite on session cookies."))

    products = _fingerprint(conn, hdr, body)

    # 2. reachable development / metadata endpoints (owned-asset check; GET, 200 with a plausible body)
    for path, severity, reason in EXPOSURE_PATHS:
        if requests >= MAX_REQUESTS:
            break
        try:
            r = fetch(base + path, "GET")
            requests += 1
            time.sleep(PAUSE_S)
        except Exception:  # noqa: BLE001
            continue
        if r.get("status") == 200 and (r.get("body") or "").strip() and not _looks_like_spa(r.get("body", "")):
            cwe = "CWE-538" if path in ("/.git/HEAD", "/.svn/entries", "/.DS_Store", "/backup.zip", "/config.php.bak") else \
                  "CWE-200" if path in ("/.env", "/actuator/env", "/phpinfo.php", "/server-status", "/actuator") else "CWE-16"
            findings.append(_finding("exposure", severity, f"{path} is reachable", reason,
                                     f"GET {base}{path} -> 200 ({len(r.get('body',''))} bytes)", cwe,
                                     "Remove the file from the web root or block the path at the proxy.", path=path))

    # 3. locally reachable service ports on the same host
    if _is_private(host):
        for p in PORTS:
            if _port_open(host, p):
                if p in SENSITIVE_PORTS:
                    findings.append(_finding("ports", "High", f"{SENSITIVE_PORTS[p]} port {p} reachable",
                                             f"A {SENSITIVE_PORTS[p]} service answers on port {p}.", f"TCP connect to {host}:{p} succeeded",
                                             "CWE-284", f"Restrict port {p} to trusted networks or close it.", path=str(p)))

    weighted = sum(WEIGHT.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - weighted)
    grade = _grade(score)
    seconds = round(time.perf_counter() - t0, 2)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    result = {"ts": now_iso, "target": url, "host": host, "port": port, "org_id": org_id, "consent": True, "status": "done",
              "reason": reason, "score": score, "grade": grade, "findings": findings, "n_findings": len(findings),
              "severity_counts": {s: sum(1 for f in findings if f["severity"] == s) for s in WEIGHT},
              "products": products, "requests": requests, "seconds": seconds, "provenance": "REAL",
              "how": "Odyssey read only this target's own HTTP responses over GET/HEAD; it sent no payloads. "
                     "The target is yours (private address or an app your agent registered)."}
    _persist(conn, result, now_iso)
    return result


def _looks_like_spa(body: str) -> bool:
    return "<html" in body[:200].lower() and "<div id=\"root\"" in body.lower()


def _fingerprint(conn: sqlite3.Connection, hdr: dict, body: str) -> list[dict]:
    text = " ".join(filter(None, [hdr.get("server"), hdr.get("x-powered-by"), hdr.get("x-generator"),
                                  (re.search(r'<meta[^>]+generator[^>]+content="([^"]+)"', body, re.I) or [None, ""])[1], body[:4000]]))
    keys, seen = [], set()
    for rx, pk in FRAMEWORK_HINTS:
        if rx.search(text) and pk not in seen:
            seen.add(pk)
            cves = conn.execute("""SELECT COUNT(DISTINCT a.cve_id) FROM assessments a JOIN assets s ON s.id = a.asset_id
                                   WHERE s.product_key = ? AND a.R > 0 AND a.tier != 'Watch'""", (pk,)).fetchone()
            keys.append({"product_key": pk, "known_cves_in_constituency": cves[0] if cves else 0})
    return keys


# ----------------------------------------------------------------------------------------------- storage + ledger
def ensure(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS surface_scans (
        id INTEGER PRIMARY KEY, ts TEXT, target TEXT, host TEXT, org_id TEXT, app_id TEXT, consent TEXT, score REAL, grade TEXT,
        findings INTEGER, seconds REAL, requests INTEGER, status TEXT, reason TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS surface_findings (
        id INTEGER PRIMARY KEY, scan_id INTEGER, check_name TEXT, severity TEXT, title TEXT, detail TEXT, evidence TEXT,
        cwe TEXT, fix TEXT, path TEXT, provenance TEXT)""")
    conn.commit()


def _refused(conn, url, host, org_id, now_iso, reason, status="refused") -> dict:
    ensure(conn)
    conn.execute("""INSERT INTO surface_scans (ts, target, host, org_id, consent, score, grade, findings, seconds, requests, status, reason)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (now_iso, url, host, org_id, "no", None, None, 0, 0, 0, status, reason))
    conn.commit()
    return {"ts": now_iso, "target": url, "host": host, "org_id": org_id, "status": status, "reason": reason,
            "score": None, "grade": None, "findings": [], "n_findings": 0, "requests": 0, "provenance": "REAL"}


def _persist(conn, result: dict, now_iso: str) -> None:
    from .ledger import Ledger
    cur = conn.execute("""INSERT INTO surface_scans (ts, target, host, org_id, consent, score, grade, findings, seconds, requests, status, reason)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (result["ts"], result["target"], result["host"], result["org_id"], "yes", result["score"], result["grade"],
                        result["n_findings"], result["seconds"], result["requests"], "done", result["reason"]))
    scan_id = cur.lastrowid
    for f in result["findings"]:
        conn.execute("""INSERT INTO surface_findings (scan_id, check_name, severity, title, detail, evidence, cwe, fix, path, provenance)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (scan_id, f["check"], f["severity"], f["title"], f["detail"], f["evidence"], f["cwe"], f["fix"], f.get("path"), f["provenance"]))
    led = Ledger(conn=conn)
    led.append(ts=now_iso, kind="surface.scan", subject=result["host"], source="SURFACE_SCAN", provenance="REAL",
               payload={"target": result["target"], "org_id": result["org_id"], "score": result["score"], "grade": result["grade"],
                        "findings": result["n_findings"], "severity_counts": result["severity_counts"]})
    for f in result["findings"]:
        if f["severity"] in ("Critical", "High"):
            led.append(ts=now_iso, kind="surface.finding", subject=result["host"], source="SURFACE_SCAN", provenance="REAL",
                       payload={"target": result["target"], "severity": f["severity"], "title": f["title"], "cwe": f["cwe"], "path": f.get("path")})
    result["scan_id"] = scan_id
    conn.commit()


def latest(conn: sqlite3.Connection, org_id: str | None = None, limit: int = 10) -> list[dict]:
    ensure(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    where, args = ("WHERE org_id = ?", (org_id,)) if org_id else ("", ())
    scans = [dict(r) for r in cur.execute(f"SELECT * FROM surface_scans {where} ORDER BY id DESC LIMIT ?", (*args, limit))]
    for s in scans:
        s["findings_list"] = [dict(r) for r in cur.execute(
            "SELECT check_name, severity, title, detail, evidence, cwe, fix, path, provenance FROM surface_findings WHERE scan_id = ?", (s["id"],))]
    return scans


def get(conn: sqlite3.Connection, scan_id: int) -> dict:
    ensure(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    row = cur.execute("SELECT * FROM surface_scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise KeyError(scan_id)
    s = dict(row)
    s["findings_list"] = [dict(r) for r in cur.execute(
        "SELECT check_name, severity, title, detail, evidence, cwe, fix, path, provenance FROM surface_findings WHERE scan_id = ?", (scan_id,))]
    return s
