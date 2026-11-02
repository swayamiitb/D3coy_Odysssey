"""Red-team agent: a standalone attacker that exercises an Odyssey lab target over the wire, so the shield can prove it
detects. It is a separate process from Odyssey (the "red-team entity"), and Odyssey detects its traffic independently.

HARD SAFETY RULE: this agent only ever attacks a loopback or RFC-1918 private address - a lab app on this laptop or a
private lab network. It resolves the host and refuses anything else before sending a single byte. It can never be
pointed at a real or third-party service. Every request is labelled as an exercise (x-odyssey-redteam header) so
Odyssey's audit trail marks it. Point it at the Lokseva lab target (target/gov_portal.py), never at anything you do
not own.

Usage:
  .venv\\Scripts\\python scripts\\redteam_agent.py                         # one wave at http://127.0.0.1:8081
  .venv\\Scripts\\python scripts\\redteam_agent.py --waves 5 --delay 20    # five waves, 20 s apart
  .venv\\Scripts\\python scripts\\redteam_agent.py --target http://127.0.0.1:8081 --api http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time
from urllib.parse import urlsplit

import httpx

EXERCISE = "redteam-agent"


def assert_private(url: str) -> str:
    """Refuse any target that is not loopback / private. Resolves the host first, so 'localhost' and a LAN name pass
    but a public host is rejected before any request is sent."""
    host = urlsplit(url).hostname or ""
    if not host:
        raise SystemExit("refusing: no host in the target URL")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SystemExit(f"refusing: cannot resolve {host!r} ({exc})") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_link_local:
            raise SystemExit(f"refusing: {host} resolves to link-local {ip} (e.g. cloud metadata) - never a lab target")
        if not (ip.is_loopback or ip.is_private):
            raise SystemExit(f"refusing: {host} resolves to {ip}, which is not loopback or a private address. "
                             "This agent only attacks a local lab target you own.")
    return url.rstrip("/")


# OAuth-specific attack requests sent directly at the target (the shield inspects every request to the app).
def oauth_cases(base: str) -> list[dict]:
    return [
        {"name": "oauth open-redirect (redirect_uri to an external host)", "method": "GET",
         "url": f"{base}/oauth/authorize", "params": {"client_id": "lokseva-web", "response_type": "code", "state": "s",
         "redirect_uri": "http://169.254.169.254/latest/meta-data/"}, "cwe": "CWE-601 / SSRF"},
        {"name": "oauth redirect_uri tampering", "method": "GET", "url": f"{base}/oauth/authorize",
         "params": {"client_id": "lokseva-web", "response_type": "code", "state": "s", "redirect_uri": "http://127.0.0.1:1/@evil.example/"}, "cwe": "CWE-601"},
        {"name": "oauth state omission (CSRF)", "method": "GET", "url": f"{base}/oauth/authorize",
         "params": {"client_id": "lokseva-web", "response_type": "code", "redirect_uri": f"{base}/callback"}, "cwe": "CWE-352"},
        {"name": "oauth token endpoint SQLi in code", "method": "POST", "url": f"{base}/oauth/token",
         "data": {"grant_type": "authorization_code", "client_id": "lokseva-web", "client_secret": "x", "code": "' OR '1'='1", "redirect_uri": f"{base}/callback"}, "cwe": "CWE-89"},
        {"name": "dashboard access with a forged bearer token", "method": "GET", "url": f"{base}/dashboard",
         "headers": {"authorization": "Bearer ' OR 1=1 --"}, "cwe": "CWE-287"},
        {"name": "login brute force (one of a burst)", "method": "POST", "url": f"{base}/login",
         "data": {"user": "admin", "password": "Password123!"}, "cwe": "CWE-307"},
        {"name": "login SQLi", "method": "POST", "url": f"{base}/login",
         "data": {"user": "admin'--", "password": "x"}, "cwe": "CWE-89"},
        {"name": "XSS in the OAuth scope", "method": "GET", "url": f"{base}/oauth/authorize",
         "params": {"client_id": "lokseva-web", "response_type": "code", "state": "s", "redirect_uri": f"{base}/callback", "scope": "<script>alert(1)</script>"}, "cwe": "CWE-79"},
    ]


def fire_oauth(client: httpx.Client, base: str) -> int:
    sent = 0
    hdr = {"x-odyssey-redteam": EXERCISE}
    for c in oauth_cases(base):
        try:
            if c["method"] == "GET":
                client.get(c["url"], params=c.get("params"), headers={**hdr, **c.get("headers", {})}, timeout=8)
            else:
                client.post(c["url"], data=c.get("data"), headers={**hdr, **c.get("headers", {})}, timeout=8)
            sent += 1
        except httpx.HTTPError:
            pass  # a dropped/refused request is the shield doing its job
    # a short brute-force burst so the shield's brute-force detector has something to see
    for i in range(12):
        try:
            client.post(f"{base}/login", data={"user": "admin", "password": f"guess{i}"}, headers=hdr, timeout=6)
            sent += 1
        except httpx.HTTPError:
            pass
    return sent


def shield_snapshot(api: str) -> dict:
    try:
        d = httpx.get(f"{api}/api/shield", timeout=10).json()
    except httpx.HTTPError:
        return {}
    apps = d.get("apps") if isinstance(d, dict) else d
    lok = next((a for a in (apps or []) if a.get("id") == "lokseva-alert-portal"), {})
    return {"detected": lok.get("attacks"), "blocked": lok.get("blocked"), "requests": lok.get("requests"), "mode": lok.get("mode")}


def main() -> int:
    ap = argparse.ArgumentParser(description="Red-team agent for an Odyssey lab target (loopback/private only).")
    ap.add_argument("--target", default="http://127.0.0.1:8081", help="the lab target (must be loopback/private)")
    ap.add_argument("--api", default="http://127.0.0.1:8000", help="the Odyssey API")
    ap.add_argument("--waves", type=int, default=1, help="number of attack waves to run (you set this; it is not endless)")
    ap.add_argument("--delay", type=float, default=15.0, help="seconds between waves")
    args = ap.parse_args()

    target = assert_private(args.target)
    assert_private(args.api)
    print(f"Red-team agent -> {target} (lab target, loopback/private only). Odyssey detects at {args.api}.")
    print(f"{args.waves} wave(s); every request labelled exercise '{EXERCISE}'. Nothing is sent to any third party.\n")

    with httpx.Client() as client:
        for wave in range(1, args.waves + 1):
            t0 = time.perf_counter()
            # 1. the standard web-attack families, through Odyssey's own red-team runner (loopback-guarded there too)
            web = {}
            try:
                web = httpx.post(f"{args.api}/api/redteam/run", json={"target": target}, timeout=180).json()
            except httpx.HTTPError as exc:
                print(f"  wave {wave}: could not reach the red-team runner ({exc})")
            # 2. OAuth / auth-specific attacks sent straight at the target (the shield inspects them)
            oauth_sent = fire_oauth(client, target)
            snap = shield_snapshot(args.api)
            dt = round(time.perf_counter() - t0, 1)
            wa = web.get("attacks_sent") or web.get("sent") or 0
            wd, wb = web.get("detected", 0), web.get("blocked", 0)
            print(f"  wave {wave}/{args.waves}: {wa} web attacks ({wd} detected, {wb} blocked) + {oauth_sent} auth/OAuth requests; "
                  f"shield now shows {snap.get('detected')} detected / {snap.get('blocked')} blocked, mode {snap.get('mode')}  [{dt}s]")
            if wave < args.waves:
                time.sleep(args.delay)

    print("\nDone. Open Odyssey -> Live to see the detections, the opened case and the alerts delivered to your channels.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
