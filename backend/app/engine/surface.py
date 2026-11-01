"""Consented self-assessment of an operator's own web application: what its own HTTP responses reveal.

This is a defensive posture check, the kind an operator runs against its own site, not a tool for reaching other
people's systems. Two conditions are enforced in code, and both must hold or the request is refused with its reason:

  1. the caller passes `consent=True`, and
  2. the target is provably the operator's own: its host is loopback, RFC 1918 private, link-local or carrier-grade
     NAT space, OR it is an application the HTTP-shield agent has already registered (the running agent is the
     operator's proof of ownership).

A public address with no registered agent is always refused. The check reads only the target's own answers over
plain GET/HEAD, never sends a payload, makes at most a few dozen requests with a short timeout and a pause between
them, and honours a per-target cooldown. The hostname is resolved exactly once, at the gate, and every connection of
the scan goes to that approved address (a DNS answer that changes between the check and the request cannot point the
scan elsewhere); redirects are never followed. It reports missing transport security, missing response-hardening
headers, inadvertently reachable development or metadata endpoints, a technology fingerprint (to link the app to known
CVEs through the existing exposure data) and locally reachable service ports. Every finding carries a CWE, a
remediation and the evidence; every scan (done, refused or unreachable) and every serious finding is written to the
audit ledger.
"""

from __future__ import annotations

import datetime as dt
import functools
import ipaddress
import json
import re
import secrets
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
MAX_BODY = 65536  # bytes read from any one response; the rest is never fetched
REFUSAL = "Odyssey scans only systems you own: deploy the agent or run from inside the network"
PORTS = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
SENSITIVE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MS SQL", 3306: "MySQL", 3389: "RDP",
                   5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}
WEIGHT = {"Critical": 30, "High": 15, "Medium": 7, "Low": 3, "Info": 0}
_COOLDOWN: dict[str, float] = {}
_LOCK = threading.Lock()
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# IPv6 transition prefixes the ipaddress module files as "private" although they encode and reach an IPv4 host
# elsewhere (6to4, Teredo): never treated as the operator's own.
_TRANSIT_V6 = (ipaddress.ip_network("2002::/16"), ipaddress.ip_network("2001::/32"))

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
# Paths whose genuine content is a file, JSON or XML: an HTML page answering 200 there is the server's "not found"
# page (a soft 404), not the artefact.
FILE_PATHS = ("/.git/HEAD", "/.svn/entries", "/.DS_Store", "/backup.zip", "/config.php.bak", "/.env")
NON_HTML_PATHS = FILE_PATHS + ("/actuator", "/actuator/env", "/swagger.json", "/openapi.json", "/robots.txt", "/sitemap.xml")
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
def _parse(url: str):
    """urlsplit that never raises: (parts, host, port, clean_url) or None for a malformed target (a non-numeric or
    out-of-range port, unbalanced IPv6 brackets). clean_url is the target with any user:password@ removed: credentials
    in a URL are neither sent (no payloads, no Authorization) nor written to the audit tables."""
    try:
        u = urlsplit(url if "://" in url else "http://" + url)
        host = (u.hostname or "").lower()
        explicit = u.port
    except ValueError:
        return None
    port = explicit or (443 if u.scheme == "https" else 80)
    authority = (f"[{host}]" if ":" in host else host) + (f":{explicit}" if explicit else "")
    clean = u._replace(netloc=authority).geturl() if "@" in u.netloc else url
    return u, host, port, clean


def _resolve(host: str) -> list[str]:
    """Every address the host resolves to, in resolver order and without duplicates; an IP literal is its own answer;
    [] when the name does not resolve. Called once per scan: the result is what every later connection uses."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in out:
            out.append(addr)
    return out


def _addr_is_ours(addr: str) -> bool:
    """Loopback, RFC 1918 private, link-local or CGNAT, judging an IPv4-mapped IPv6 address by its IPv4 part."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if any(ip in net for net in _TRANSIT_V6):
            return False
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
    cgnat = isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT
    return ip.is_private or ip.is_loopback or ip.is_link_local or cgnat


def _is_private(host: str) -> bool:
    """True only when the host resolves and every address it resolves to is the operator's own."""
    addrs = _resolve(host)
    return bool(addrs) and all(_addr_is_ours(a) for a in addrs)


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


def _gate(url: str, conn: sqlite3.Connection | None):
    """The ownership decision plus the addresses it was made on: (ok, reason, addrs, parsed)."""
    parsed = _parse(url)
    if parsed is None:
        return False, "malformed target URL", [], None
    u, host, port, _clean = parsed
    if not host:
        return False, "no host in the target URL", [], parsed
    if u.scheme not in ("http", "https"):
        return False, "only http and https targets are scanned", [], parsed
    addrs = _resolve(host)
    if addrs and all(_addr_is_ours(a) for a in addrs):
        return True, "private / loopback address (a system on your own network)", addrs, parsed
    if conn is not None and f"{host}:{port}" in _registered_hostports(conn):
        return True, "an application registered by your Odyssey agent (the agent is your proof of ownership)", addrs, parsed
    return False, REFUSAL, addrs, parsed


def allowed(url: str, conn: sqlite3.Connection | None = None) -> tuple[bool, str]:
    ok, reason, _addrs, _parsed = _gate(url, conn)
    return ok, reason


# ---------------------------------------------------------------------------------------------------------- checks
def _default_fetch(url: str, method: str = "GET", pin: str | None = None) -> dict:
    """One GET or HEAD to the operator's own target. The TCP connection goes to `pin`, the address the ownership gate
    approved, carrying the original Host header and SNI, so the hostname is never resolved a second time. Redirects
    are returned, never followed. Certificate verification is off on purpose: the response is the operator's own and
    is read as evidence, nothing in it is trusted; the certificate itself is examined by _cert_days. At most MAX_BODY
    bytes of the body are read."""
    import httpx
    if method not in ("GET", "HEAD"):
        raise ValueError("only GET and HEAD are sent")
    target = httpx.URL(url)
    if not target.host:
        raise ValueError("no host in the target URL")
    if pin is None:  # called outside scan(): decide for ourselves, and fail closed
        ok, reason, addrs, _parsed = _gate(url, None)
        if not ok or not addrs:
            raise PermissionError(reason)
        pin = addrs[0]
    headers = {"User-Agent": "Odyssey-EWS/0.2 (owned-asset self-check)", "Host": target.netloc.decode("ascii")}
    with httpx.Client(timeout=TIMEOUT_S, follow_redirects=False, verify=False) as client:
        with client.stream(method, target.copy_with(host=pin), headers=headers,
                           extensions={"sni_hostname": target.host}) as r:
            chunks, n = [], 0
            for chunk in r.iter_bytes():
                chunks.append(chunk)
                n += len(chunk)
                if n >= MAX_BODY:
                    break
            raw = b"".join(chunks)[:MAX_BODY]
            text = raw.decode(r.charset_encoding or "utf-8", "replace")
            return {"status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": text[:2000], "url": url}


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


def _cert_days(host: str, port: int, pin: str | None = None) -> tuple[int | None, bool]:
    """(days until the target's own TLS certificate expires, whether it is self-signed), over a handshake to the
    gate-approved address with the target's hostname as SNI. No third-party library is needed: a verified handshake
    yields the parsed certificate; when the chain does not verify, OpenSSL's reason says whether the certificate is
    self-signed (code 18/19) or expired (code 10), and the dates are then read by a second handshake that trusts only
    the very leaf we were shown. Best-effort: (None, False) when the target does not speak TLS."""
    addr = pin or host

    def handshake(ctx):
        with socket.create_connection((addr, port), timeout=TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert(), ss.getpeercert(binary_form=True)

    verified = ssl.create_default_context()
    verified.check_hostname = False  # the operator's own certificate: its dates and issuer matter, its names do not
    self_signed = expired = False
    cert: dict = {}
    try:
        cert, _der = handshake(verified)
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        self_signed, expired = code in (18, 19), code == 10
        try:
            plain = ssl.create_default_context()
            plain.check_hostname, plain.verify_mode = False, ssl.CERT_NONE
            _cert, der = handshake(plain)
            leaf = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            leaf.check_hostname = False
            leaf.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
            leaf.verify_flags = (leaf.verify_flags | ssl.VERIFY_X509_PARTIAL_CHAIN) & ~ssl.VERIFY_X509_STRICT
            cert, _der = handshake(leaf)
        except ssl.SSLCertVerificationError as exc2:
            expired = expired or getattr(exc2, "verify_code", None) == 10
        except Exception:  # noqa: BLE001 - best-effort
            pass
    except Exception:  # noqa: BLE001 - not TLS, or the host went away; the expiry check is best-effort
        return None, False
    if cert.get("issuer") and cert.get("issuer") == cert.get("subject"):
        self_signed = True
    days = None
    if cert.get("notAfter"):
        try:
            not_after = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
            days = (not_after - dt.datetime.now(dt.timezone.utc)).days
        except (ValueError, OverflowError, OSError):
            days = None
    if expired and days is None:
        days = -1
    return days, self_signed


def scan(conn: sqlite3.Connection, url: str, consent: bool, org_id: str | None = None, now: dt.datetime | None = None,
         fetch=None) -> dict:
    ensure(conn)
    now = now or dt.datetime.now(dt.timezone.utc)
    now_iso = now.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    parsed = _parse(url)
    if parsed is None:
        return _refused(conn, url, "", org_id, now_iso, "malformed target URL", consent=consent)
    u, host, port, url = parsed  # url is now free of any user:password@
    if not consent:  # before the gate: without consent not even a DNS lookup of the target happens
        return _refused(conn, url, host, org_id, now_iso, "consent was not given for this scan", consent=False)
    ok, reason, addrs, _parsed = _gate(url, conn)
    if not ok:
        return _refused(conn, url, host, org_id, now_iso, reason, consent=True)
    pin = addrs[0] if addrs else None
    base = f"{u.scheme}://" + (f"[{host}]" if ":" in host else host) + (f":{u.port}" if u.port else "")
    keys = {f"{host}:{port}"} | {f"{a}:{port}" for a in addrs}  # the cooldown covers every name of the same address
    with _LOCK:
        if any(time.time() - _COOLDOWN.get(k, 0) < COOLDOWN_S for k in keys):
            return _refused(conn, url, host, org_id, now_iso, f"cooldown: this target was scanned under {COOLDOWN_S}s ago", consent=True)
        for k in keys:
            _COOLDOWN[k] = time.time()

    fetch = fetch or functools.partial(_default_fetch, pin=pin)
    t0 = time.perf_counter()
    findings: list[dict] = []
    requests = 0

    # 1. the base response: transport, hardening headers, version disclosure, cookie flags, fingerprint
    base_resp = None
    try:
        base_resp = fetch(base + "/", "GET")
        requests += 1
    except Exception as exc:  # noqa: BLE001
        return _refused(conn, url, host, org_id, now_iso, f"target did not answer: {type(exc).__name__}", status="unreachable", consent=True)
    hdr = base_resp.get("headers", {})
    body = base_resp.get("body", "") or ""

    if u.scheme == "http":
        findings.append(_finding("transport", "High", "Served over plain HTTP", "Traffic to this application is not encrypted in transit.",
                                 f"GET {base}/ -> {base_resp['status']} over http", "CWE-319", "Serve the application over HTTPS and redirect HTTP to HTTPS."))
    else:
        if "strict-transport-security" not in hdr:
            findings.append(_finding("headers", "Low", "No HSTS header", "Strict-Transport-Security is not set.",
                                     "no strict-transport-security in the response", "CWE-319", "Set Strict-Transport-Security with a long max-age."))
        days, self_signed = _cert_days(host, port, pin)
        if self_signed:
            findings.append(_finding("tls", "High", "Self-signed certificate", "The TLS certificate is self-signed.",
                                     "issuer equals subject", "CWE-295", "Use a certificate from a trusted CA."))
        if days is not None and days < 30:
            detail = f"The TLS certificate expires in {days} day(s)." if days >= 0 else "The TLS certificate has expired."
            evidence = f"not_valid_after in {days} day(s)" if days >= 0 else "not_valid_after has passed"
            findings.append(_finding("tls", "High" if days >= 0 else "Critical", "Certificate expiring or expired",
                                     detail, evidence, "CWE-298", "Renew the certificate."))

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

    # 2. reachable development / metadata endpoints (owned-asset check; GET, 200 with a plausible body). One probe of a
    #    path that cannot exist tells us what this server's "not found" page looks like when it answers 200 (a soft
    #    404 or a catch-all SPA route), so that page is never reported as an exposure.
    soft: tuple[str, str] | None = None
    if requests < MAX_REQUESTS:
        probe_path = f"/odyssey-probe-{secrets.token_hex(4)}"
        try:
            pr = fetch(base + probe_path, "GET")
            requests += 1
            time.sleep(PAUSE_S)
            if pr.get("status") == 200 and (pr.get("body") or "").strip():
                soft = (pr.get("body") or "", probe_path)
        except Exception:  # noqa: BLE001
            pass
    for path, severity, reason_ in EXPOSURE_PATHS:
        if requests >= MAX_REQUESTS:
            break
        try:
            r = fetch(base + path, "GET")
            requests += 1
            time.sleep(PAUSE_S)
        except Exception:  # noqa: BLE001
            continue
        rb = r.get("body") or ""
        if r.get("status") != 200 or not rb.strip():
            continue
        if _looks_like_spa(rb) or _same_page(rb, body, (path,)):
            continue  # a catch-all route: every path answers with the front page
        if soft and _same_page(rb, soft[0], (path, soft[1])):
            continue  # the server's "not found" page, served with 200
        if path in NON_HTML_PATHS and _looks_like_html(rb):
            continue  # an HTML page where a file, JSON or XML document should be: not the artefact
        cwe = "CWE-538" if path in FILE_PATHS else "CWE-489" if path in ("/console", "/debug") else "CWE-200"
        findings.append(_finding("exposure", severity, f"{path} is reachable", reason_,
                                 f"GET {base}{path} -> 200 ({len(rb)} bytes)", cwe,
                                 "Remove the file from the web root or block the path at the proxy.", path=path))

    # 3. locally reachable service ports on the same host (only for a private/loopback target, and only at the
    #    address the gate approved)
    if pin and addrs and all(_addr_is_ours(a) for a in addrs):
        from concurrent.futures import ThreadPoolExecutor  # the probes are independent 1 s connects; serially they cost up to 16 s
        with ThreadPoolExecutor(max_workers=len(PORTS)) as pool:
            open_ports = [p for p, is_open in zip(PORTS, pool.map(lambda p: _port_open(pin, p), PORTS)) if is_open]
        for p in open_ports:
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


def _looks_like_html(body: str) -> bool:
    head = body[:300].lstrip().lower()
    return head.startswith(("<!doctype", "<html")) or "<html" in head


def _same_page(a: str, b: str, strip: tuple[str, ...] = ()) -> bool:
    """Two response bodies are the same page once the requested paths (which soft-404 pages echo) and whitespace
    differences are removed."""
    def norm(s: str) -> str:
        for p in strip:
            if p:
                s = s.replace(p, "")
        return re.sub(r"\s+", " ", s).strip()
    return norm(a) == norm(b)


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


def _refused(conn, url, host, org_id, now_iso, reason, status="refused", consent=False) -> dict:
    """Record a scan that did not run (refused by the gate, by consent or by the cooldown, or an unreachable target)
    in the scan table and in the audit ledger, and return the same shape the UI already handles."""
    from .ledger import Ledger
    ensure(conn)
    conn.execute("""INSERT INTO surface_scans (ts, target, host, org_id, consent, score, grade, findings, seconds, requests, status, reason)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                 (now_iso, url, host, org_id, "yes" if consent else "no", None, None, 0, 0, 0, status, reason))
    try:
        Ledger(conn=conn).append(ts=now_iso, kind=f"surface.{status}", subject=host or url, source="SURFACE_SCAN", provenance="REAL",
                                 payload={"target": url, "org_id": org_id, "consent": bool(consent), "reason": reason})
    except Exception:  # noqa: BLE001 - the refusal itself must still be returned
        pass
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
