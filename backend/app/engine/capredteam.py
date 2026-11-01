"""Red-team cases for the CAP ingest: hostile alerts fired at Odyssey's *own* endpoint on loopback, measured.

The cases are the attacks an early-warning system's inputs actually face: an XML external entity that would read a
local file, entity expansion (billion laughs), a forged sender, a replayed identifier, a stale cancellation, a
malformed body, an oversize body and a flood. Every request carries the run id in the `x-odyssey-redteam` header so
the ledger labels the exercise, and the planted secret proves XXE never reached the parser. Targets are loopback only.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import secrets
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from .. import sachet
from .ledger import Ledger

ROOT = Path(__file__).resolve().parents[3]
TRUSTED = "IMD-Chennai"


def _valid(identifier: str, sender: str = TRUSTED, expires: str | None = None, headline: str = "Odyssey CAP exercise") -> bytes:
    exp = f"<expires>{expires}</expires>" if expires else ""
    return (f'<?xml version="1.0" encoding="UTF-8"?><alert xmlns="{sachet.CAP_NS}"><identifier>{identifier}</identifier>'
            f"<sender>{sender}</sender><sent>2026-11-01T06:44:49+05:30</sent><status>Exercise</status><msgType>Alert</msgType>"
            f"<scope>Public</scope><info><language>en-IN</language><category>Met</category><event>Heavy Rain</event>"
            f"<urgency>Expected</urgency><severity>Moderate</severity><certainty>Likely</certainty>{exp}<headline>{headline}</headline>"
            f"<area><areaDesc>Chennai, Tamil Nadu</areaDesc></area></info></alert>").encode("utf-8")


def cases(run_id: str, secret_path: Path) -> list[dict]:
    uri = secret_path.resolve().as_uri()
    xxe = (f'<?xml version="1.0"?><!DOCTYPE alert [<!ENTITY xxe SYSTEM "{uri}">]><alert xmlns="{sachet.CAP_NS}">'
           f"<identifier>{run_id}-xxe</identifier><sender>IMD-Chennai</sender><sent>2026-11-01T06:44:49+05:30</sent>"
           f"<status>Exercise</status><msgType>Alert</msgType><scope>Public</scope><info><headline>&xxe;</headline></info></alert>").encode()
    lol = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
           '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]>'
           f'<alert xmlns="{sachet.CAP_NS}"><identifier>{run_id}-lol</identifier><sender>IMD-Chennai</sender><sent>2026-11-01T06:44:49+05:30</sent>'
           "<status>Exercise</status><msgType>Alert</msgType><scope>Public</scope><info><headline>&lol4;</headline></info></alert>").encode()
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    return [
        {"name": "xxe_external_entity", "what": "an external entity pointing at a local secret file", "body": xxe, "expect": "xxe", "technique": "T1190", "cwe": "CWE-611"},
        {"name": "billion_laughs", "what": "nested entity expansion", "body": lol, "expect": "xxe", "technique": "T1499", "cwe": "CWE-776"},
        {"name": "forged_sender", "what": "a well-formed alert from an unauthorised sender", "body": _valid(f"{run_id}-forged", sender="EVIL-Agency"), "expect": "untrusted_sender", "technique": "T1036", "cwe": "CWE-290"},
        {"name": "legitimate", "what": "a well-formed alert from an authorised sender (must be accepted)", "body": _valid(f"{run_id}-ok"), "expect": "accepted", "technique": None, "cwe": None},
        {"name": "replay", "what": "the same identifier again", "body": _valid(f"{run_id}-ok"), "expect": "replay", "technique": "T1557", "cwe": "CWE-294"},
        {"name": "stale", "what": "an alert whose expiry has passed", "body": _valid(f"{run_id}-stale", expires=past), "expect": "stale", "technique": None, "cwe": "CWE-672"},
        {"name": "malformed", "what": "not a CAP alert at all", "body": b"<html><body>not cap</body></html>", "expect": "malformed", "technique": None, "cwe": "CWE-20"},
        {"name": "oversize", "what": "a 3 MB body", "body": _valid(f"{run_id}-big", headline="x" * (3 * 1024 * 1024)), "expect": "oversize", "technique": "T1499", "cwe": "CWE-400"},
        {"name": "stored_script", "what": "a script tag in the headline from an authorised sender (accepted, but stored and shown as text)", "body": _valid(f"{run_id}-xss", headline="<script>alert(1)</script> Heavy rain"), "expect": "accepted", "technique": None, "cwe": "CWE-79"},
    ]


def run(connect, target: str, run_id: str | None = None, flood: int = 40) -> dict:
    """Fire every case at `target` (loopback only) and measure. Returns the scorecard and writes `cap.redteam`."""
    host = urlparse(target).hostname or ""
    try:
        is_loop = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loop = host == "localhost"
    if not is_loop:
        raise ValueError("the CAP red-team runs only against this Odyssey on loopback")
    import httpx
    run_id = run_id or f"CAPRT-{dt.datetime.now(dt.timezone.utc):%H%M%S}-{uuid.uuid4().hex[:4]}"
    secret = secrets.token_hex(16)
    tmpdir = Path(tempfile.mkdtemp(prefix="odyssey-caprt-", dir=ROOT / "data" / ".tmp" if (ROOT / "data" / ".tmp").exists() else None))
    secret_path = tmpdir / "planted-secret.txt"
    secret_path.write_text(f"PLANTED-{secret}", encoding="utf-8")
    results, leaked = [], False
    headers = {"x-odyssey-redteam": run_id, "content-type": "application/xml"}
    t_all = time.perf_counter()
    with httpx.Client(timeout=30) as c:
        for case in cases(run_id, secret_path):
            t0 = time.perf_counter()
            try:
                r = c.post(target, content=case["body"], headers=headers)
                body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text[:300]}
            except Exception as exc:  # noqa: BLE001
                body = {"error": repr(exc)[:200]}
                r = None
            got = "accepted" if body.get("accepted") else body.get("reason") or body.get("detail") or ("http " + str(r.status_code) if r else "error")
            if secret in str(body):
                leaked = True
            results.append({"name": case["name"], "what": case["what"], "expected": case["expect"], "got": got, "pass": got == case["expect"],
                            "ms": round((time.perf_counter() - t0) * 1000), "technique": case["technique"], "cwe": case["cwe"]})
        # flood: a burst of distinct, otherwise valid alerts; the rate cap must refuse the tail
        refused = 0
        t0 = time.perf_counter()
        for i in range(flood):
            try:
                r = c.post(target, content=_valid(f"{run_id}-flood-{i}"), headers=headers)
                if not r.json().get("accepted") and r.json().get("reason") == "rate_limited":
                    refused += 1
            except Exception:  # noqa: BLE001
                pass
        results.append({"name": "flood", "what": f"{flood} distinct alerts in a burst", "expected": "rate_limited", "got": f"{refused} of {flood} refused",
                        "pass": refused > 0, "ms": round((time.perf_counter() - t0) * 1000), "technique": "T1499", "cwe": "CWE-770"})
    try:
        secret_path.unlink()
        tmpdir.rmdir()
    except OSError:
        pass
    passed = sum(1 for x in results if x["pass"])
    out = {"run_id": run_id, "target": target, "cases": results, "passed": passed, "total": len(results), "planted_secret_leaked": leaked,
           "seconds": round(time.perf_counter() - t_all, 2), "label": "exercise (SIM): every request carried the run id; the ledger marks them",
           "how": "hostile CAP against Odyssey's own ingest on loopback; nothing was sent to SACHET or any third party"}
    conn = connect()
    try:
        Ledger(conn=conn).append(ts=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"), kind="cap.redteam", subject=run_id,
                                 source="CAP_REDTEAM", provenance="SIM", payload={k: v for k, v in out.items() if k != "cases"} | {
                                     "failed": [x["name"] for x in results if not x["pass"]]})
        conn.commit()
    finally:
        conn.close()
    return out
