"""Web-attack detection engine: Odyssey's HTTP shield, the inline WAF/IDS layer.

This is the deterministic, testable core that inspects one HTTP request and decides whether it carries an attack.
It is what lets Odyssey protect a *real* web application: a drop-in agent (agent/) forwards each request's metadata to
`POST /api/sensor/http`, the request passes through `inspect()`, and a match becomes a ledger event, an autopilot
action and, in block mode, a dropped request. Real WAFs (ModSecurity CRS, libinjection) are signature- and
decode-driven rather than one-LLM-call-per-request, because inline inspection must be sub-millisecond and offline;
Odyssey follows the same shape and keeps the security-tuned LLM for on-demand analyst explanation (ai/narrate).

Design notes
------------
- **Decode before matching.** Attackers evade naive filters with URL-, double-URL-, HTML-entity- and base64-encoding
  and SQL comment padding. Every input surface is normalised through those layers before the signatures run, so the
  same rule catches `' OR 1=1--`, `%27%20OR%201%3D1--` and `'/**/OR/**/1=1`.
- **Every input surface.** Path, each query parameter, each body parameter (urlencoded and JSON), and the headers
  attackers actually abuse (User-Agent, Referer, Cookie, X-Forwarded-For, and any header for Log4Shell/CRLF).
- **Transparent, auditable, pluggable.** Signatures live in one table with a CWE, the matching MITRE ATT&CK
  technique, a weight and a plain-language reason. No opaque model in the inline path; add or tune a family by editing
  the table. Stateful behaviours (brute force, scanning sweeps) live in the shield, which owns the per-source windows.
- **Defanged evidence.** The matched snippet is truncated and stripped of control characters before it is stored or
  shown, so a captured XSS or injection payload is inert in the dashboard and the audit trail.

`inspect(event)` returns the findings and the worst severity; it never raises on malformed input.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote_plus

# Severity lattice used across the shield. The system's alert tiers add "Compromise" on evidence of success; the
# inline engine tops out at Critical and the shield promotes to Compromise from context (e.g. a 200 to an injection).
SEVERITY = {"Watch": 0, "Medium": 1, "High": 2, "Critical": 3}
ORDER = ["Watch", "Medium", "High", "Critical"]

CWE_NAMES = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection (template)",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-917": "Expression Language / JNDI Injection",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-98": "Remote/Local File Inclusion",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-113": "HTTP Response Splitting (CRLF)",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-1595": "Active Scanning",
}
# MITRE ATT&CK technique per family (enterprise matrix).
ATTACK_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1059.007": "JavaScript",
    "T1595": "Active Scanning",
    "T1595.002": "Vulnerability Scanning",
    "T1110": "Brute Force",
    "T1083": "File and Directory Discovery",
}


@dataclass(frozen=True)
class Sig:
    family: str          # detector family / rule id, e.g. "sqli.union"
    category: str        # human category, e.g. "SQL injection"
    cwe: str
    attack: str          # ATT&CK technique id
    severity: str        # base severity for a single hit
    weight: int          # evidence weight; the shield escalates when several fire
    why: str             # plain-language reason, shown to the analyst
    pattern: re.Pattern


def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# --- Signature table -------------------------------------------------------------------------------------------
# Patterns are written against *decoded, comment-stripped* text (see _variants). They are deliberately specific:
# the goal is high precision on real payloads with very few false positives on ordinary query strings.
SIGS: list[Sig] = [
    # SQL injection -------------------------------------------------------------------------------------------
    Sig("sqli.union", "SQL injection", "CWE-89", "T1190", "Critical", 3,
        "UNION SELECT is used to graft the attacker's columns onto the query result.",
        _rx(r"\bunion\b[\s\S]{0,40}?\bselect\b")),
    Sig("sqli.boolean", "SQL injection", "CWE-89", "T1190", "High", 2,
        "A tautology (e.g. OR 1=1) forces every row to match, bypassing the WHERE clause.",
        _rx(r"(['\"]|\b)(\s*)(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+")),
    Sig("sqli.comment", "SQL injection", "CWE-89", "T1190", "High", 2,
        "A quote followed by a SQL comment truncates the rest of the original query.",
        _rx(r"['\"]\s*(--|#|/\*)")),
    Sig("sqli.stacked", "SQL injection", "CWE-89", "T1190", "Critical", 3,
        "A stacked statement (; DROP/INSERT/UPDATE) runs a second, attacker-chosen query.",
        _rx(r";\s*(drop|insert|update|delete|alter|create|truncate)\s")),
    Sig("sqli.func", "SQL injection", "CWE-89", "T1190", "High", 2,
        "SQL functions used in injection (sleep, benchmark, extractvalue, load_file, information_schema).",
        _rx(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay|extractvalue|updatexml|load_file|information_schema|group_concat)\b\s*\(?")),
    # Cross-site scripting ------------------------------------------------------------------------------------
    Sig("xss.script", "Cross-site scripting", "CWE-79", "T1059.007", "High", 3,
        "A <script> tag injects attacker JavaScript into the page.",
        _rx(r"<\s*script[\s>/]")),
    Sig("xss.event", "Cross-site scripting", "CWE-79", "T1059.007", "High", 2,
        "An inline event handler (onerror/onload/onmouseover=) runs attacker JavaScript.",
        _rx(r"\bon(error|load|mouseover|focus|click|toggle|animationstart)\s*=")),
    Sig("xss.tag", "Cross-site scripting", "CWE-79", "T1059.007", "High", 2,
        "An <img>/<svg>/<iframe>/<body> tag is used to carry a scripting payload.",
        _rx(r"<\s*(img|svg|iframe|body|details|object|embed)\b[\s\S]{0,60}?(src|onerror|onload)\s*=")),
    Sig("xss.jsuri", "Cross-site scripting", "CWE-79", "T1059.007", "Medium", 2,
        "A javascript: URI or document/window sink executes script when followed.",
        _rx(r"(javascript:|data:text/html|document\.cookie|window\.location|eval\s*\()")),
    # Path traversal / file inclusion -------------------------------------------------------------------------
    Sig("traversal.dotdot", "Path traversal", "CWE-22", "T1083", "High", 3,
        "../ sequences climb out of the web root to read arbitrary files.",
        _rx(r"(\.\./|\.\.\\){2,}")),
    Sig("traversal.abs", "Path traversal", "CWE-22", "T1083", "High", 3,
        "A reference to a sensitive OS file (/etc/passwd, win.ini, boot.ini).",
        _rx(r"(/etc/passwd|/etc/shadow|boot\.ini|win\.ini|/proc/self/environ)")),
    Sig("lfi.wrapper", "File inclusion", "CWE-98", "T1190", "High", 2,
        "A PHP stream wrapper (php://filter, data://, expect://) is used for local/remote file inclusion.",
        _rx(r"(php://(filter|input)|data://|expect://|phar://|file://)")),
    # OS command injection ------------------------------------------------------------------------------------
    Sig("cmdi.sep", "Command injection", "CWE-78", "T1059", "Critical", 3,
        "A shell separator (; | && $() backtick) chains an attacker command onto the request.",
        _rx(r"(;|\|{1,2}|&{1,2}|\$\(|`|\n)\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|powershell|ping|nslookup|uname|cmd|dir|type)\b")),
    Sig("cmdi.bin", "Command injection", "CWE-78", "T1059", "High", 2,
        "A path to a shell or a reference to a well-known binary used in command injection.",
        _rx(r"(/bin/(ba)?sh|/usr/bin/|%0a\s*(cat|id|ls)|\bIFS\b)")),
    # Server-side template injection / code injection ---------------------------------------------------------
    Sig("ssti", "Template injection", "CWE-94", "T1190", "High", 2,
        "A template expression (e.g. {{7*7}}, ${...}, <%= %>) is evaluated server-side.",
        _rx(r"(\{\{[\s\S]{0,40}?[\*\+][\s\S]{0,40}?\}\}|\$\{[\s\S]{0,40}?\}|<%=[\s\S]{0,40}?%>|#\{[\s\S]{0,40}?\})")),
    # Log4Shell / JNDI ----------------------------------------------------------------------------------------
    Sig("jndi", "JNDI / Log4Shell", "CWE-917", "T1190", "Critical", 3,
        "A ${jndi:ldap://...} lookup triggers remote class loading (Log4Shell-class).",
        _rx(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop|nis|corba)://")),
    # SSRF ----------------------------------------------------------------------------------------------------
    Sig("ssrf.meta", "Server-side request forgery", "CWE-918", "T1190", "High", 2,
        "A URL pointing at a cloud metadata service or localhost coerces the server into a request on the attacker's behalf.",
        _rx(r"(169\.254\.169\.254|metadata\.google|/latest/meta-data/|http://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]))")),
    # Deserialization -----------------------------------------------------------------------------------------
    Sig("deser.java", "Insecure deserialization", "CWE-502", "T1190", "High", 2,
        "A Java serialized-object marker (rO0AB / 0xACED) in input is a deserialization-gadget attempt.",
        _rx(r"(rO0AB|\xac\xed\x00\x05|__reduce__|pickle\.|yaml\.load\b)")),
    # CRLF / response splitting -------------------------------------------------------------------------------
    Sig("crlf", "HTTP response splitting", "CWE-113", "T1190", "Medium", 2,
        "A CR/LF in a header value splits the response or injects a header.",
        _rx(r"(%0d%0a|\r\n)(set-cookie|location|content-length|<script)")),
    # Sensitive-file and admin probing ------------------------------------------------------------------------
    Sig("probe.secret", "Sensitive-file probe", "CWE-200", "T1595.002", "Medium", 2,
        "A request for a secret or VCS file (.env, .git, id_rsa, backup, .sql) is reconnaissance for leaked credentials.",
        _rx(r"(/\.env\b|/\.git/|/\.aws/|id_rsa\b|\.htpasswd\b|/wp-config\.php|\.(sql|bak|old|swp)\b)")),
    Sig("probe.admin", "Admin / shell probe", "CWE-1595", "T1595.002", "Watch", 1,
        "A request for a common admin, setup or planted-shell path, typical of automated scanning.",
        _rx(r"(/wp-(admin|login)|/phpmyadmin|/administrator/|/manager/html|/actuator/|/console/|shell\.(php|jsp|asp))")),
]

# Scanner / attack-tool fingerprints in the User-Agent. Seeing these is itself reportable reconnaissance.
SCANNER_UA = _rx(r"\b(sqlmap|nikto|nmap|masscan|zgrab|nessus|acunetix|nuclei|wpscan|dirbuster|gobuster|hydra|"
                 r"havij|arachni|w3af|openvas|metasploit|fuzz|curl/7\.(?!.*legit)|python-requests)\b")
# Headers worth inspecting for payloads beyond the obvious ones.
INSPECT_HEADERS = ("user-agent", "referer", "referrer", "cookie", "x-forwarded-for", "x-api-version", "content-type")

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SQL_NOISE = re.compile(r"/\*.*?\*/", re.DOTALL)
_B64 = re.compile(r"^[A-Za-z0-9+/=]{16,}$")


def redact(text: str, limit: int = 180) -> str:
    """Make a payload safe to store and display: strip control characters and truncate. React escapes text, so the
    snippet is inert; truncation keeps a captured exploit from bloating the ledger."""
    if text is None:
        return ""
    s = _CONTROL.sub("\ufffd", str(text)).replace("\r", "\\r").replace("\n", "\\n")
    return s if len(s) <= limit else s[:limit] + "…"


def _decode_variants(value: str) -> list[str]:
    """Normalised forms of one input value, so a signature matches regardless of how the payload was encoded.
    Returns the raw value plus URL-decoded (two passes), HTML-entity-decoded, comment-stripped and, when the value
    looks like base64, its decoded text."""
    seen: list[str] = []

    def add(s: str) -> None:
        if s and s not in seen:
            seen.append(s)

    add(value)
    cur = value
    for _ in range(2):  # double URL-encoding is a standard WAF-evasion trick
        dec = unquote_plus(cur)
        if dec == cur:
            break
        add(dec)
        cur = dec
    add(html.unescape(cur))
    add(_SQL_NOISE.sub(" ", cur))          # strip /* */ comments used to break up keywords
    add(cur.replace("/**/", " "))
    if _B64.match(value.strip()):
        try:
            raw = base64.b64decode(value.strip() + "==", validate=False)
            text = raw.decode("utf-8", "ignore")
            if text and sum(c.isprintable() for c in text) / max(len(text), 1) > 0.8:
                add(text)
        except (binascii.Error, ValueError):
            pass
    return seen


@dataclass
class Finding:
    family: str
    category: str
    cwe: str
    cwe_name: str
    attack: str
    attack_name: str
    severity: str
    surface: str          # "path" | "query" | "body" | "header"
    param: str
    evidence: str
    why: str
    weight: int

    def as_dict(self) -> dict:
        return {"family": self.family, "category": self.category, "cwe": self.cwe, "cwe_name": self.cwe_name,
                "attack": self.attack, "attack_name": self.attack_name, "severity": self.severity,
                "surface": self.surface, "param": self.param, "evidence": self.evidence, "why": self.why}


def _surfaces(event: dict) -> list[tuple[str, str, str]]:
    """Flatten a request into (surface, param, value) tuples to inspect."""
    out: list[tuple[str, str, str]] = []
    path = str(event.get("path") or "")
    if path:
        out.append(("path", "path", path))

    def add_query(raw: str) -> None:
        for k, v in parse_qsl(raw, keep_blank_values=True):
            out.append(("query", k, v))

    q = event.get("query")
    if isinstance(q, dict):
        for k, v in q.items():
            out.append(("query", str(k), str(v)))
    elif isinstance(q, str) and q:
        add_query(q.lstrip("?"))
    elif "?" in path:
        add_query(path.split("?", 1)[1])

    body = event.get("body")
    ctype = str((event.get("headers") or {}).get("content-type", "")).lower()
    if isinstance(body, (dict, list)):
        for k, v in _flatten_json(body):
            out.append(("body", k, v))
    elif isinstance(body, str) and body:
        parsed = None
        if "json" in ctype or body.lstrip()[:1] in "{[":
            try:
                parsed = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                parsed = None
        if parsed is not None:
            for k, v in _flatten_json(parsed):
                out.append(("body", k, v))
        elif "form-urlencoded" in ctype or ("=" in body and "&" in body) or ("=" in body and " " not in body):
            for k, v in parse_qsl(body, keep_blank_values=True):
                out.append(("body", k, v))
        else:
            out.append(("body", "body", body))

    headers = {str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()}
    for h, v in headers.items():
        if h in INSPECT_HEADERS or "${" in v or "../" in v:
            out.append(("header", h, v))
    return out


def _flatten_json(obj, prefix: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_flatten_json(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_flatten_json(v, f"{prefix}[{i}]"))
    else:
        out.append((prefix or "body", str(obj)))
    return out


def inspect(event: dict) -> dict:
    """Inspect one HTTP request. Returns {"findings": [...], "worst": severity|None, "families": [...]}.

    Never raises: malformed input yields no findings. Findings are de-duplicated per (family, surface, param) and
    kept with the strongest evidence, so a payload decoded three ways is reported once."""
    best: dict[tuple[str, str, str], Finding] = {}

    for surface, param, value in _surfaces(event):
        if not value:
            continue
        variants = _decode_variants(value)
        for sig in SIGS:
            for variant in variants:
                m = sig.pattern.search(variant)
                if not m:
                    continue
                key = (sig.family, surface, param)
                snippet = redact(variant[max(0, m.start() - 12): m.end() + 28])
                finding = Finding(sig.family, sig.category, sig.cwe, CWE_NAMES.get(sig.cwe, sig.cwe),
                                  sig.attack, ATTACK_NAMES.get(sig.attack, sig.attack), sig.severity,
                                  surface, param, snippet, sig.why, sig.weight)
                prev = best.get(key)
                if prev is None or SEVERITY[finding.severity] > SEVERITY[prev.severity]:
                    best[key] = finding
                break  # one variant matching this signature is enough for this surface/param

    # Scanner user-agent: reconnaissance signal in its own right.
    ua = str((event.get("headers") or {}).get("user-agent", ""))
    if ua and SCANNER_UA.search(ua):
        tool = SCANNER_UA.search(ua).group(1)
        best[("scanner.ua", "header", "user-agent")] = Finding(
            "scanner.ua", "Scanner fingerprint", "CWE-1595", CWE_NAMES["CWE-1595"],
            "T1595", ATTACK_NAMES["T1595"], "Medium", "header", "user-agent", redact(ua),
            f"The User-Agent identifies the attack tool '{tool}', so this traffic is automated scanning or exploitation.", 2)

    findings = sorted(best.values(), key=lambda f: -SEVERITY[f.severity])
    worst = findings[0].severity if findings else None
    return {"findings": [f.as_dict() for f in findings], "worst": worst,
            "families": sorted({f.family.split(".")[0] for f in findings}),
            "weight": sum(f.weight for f in findings)}
