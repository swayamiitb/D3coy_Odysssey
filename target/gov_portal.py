"""Lokseva Citizen Alert Portal - a FICTIONAL government-agency web app, a lab target for the Odyssey HTTP shield.

This is NOT a real government service and does not impersonate one. "Lokseva Digital Services Directorate" is a made-up
operator in Odyssey's simulated constituency (org GOV-01), the same fictional universe as the CityPower portal. Every
page carries a visible SIMULATION banner and it holds no real database, shell, secret or citizen data. It exists to
give the Odyssey shield a realistic government target to defend: a person (or the red-team agent) fires real web
attacks at it on loopback and Odyssey detects, opens a case and reports.

It includes a self-contained mock OAuth 2.0 authorization-code flow (its own login, authorize, token and a protected
dashboard) so the shield has a realistic authentication surface to watch. The OAuth server is entirely local and
fictional: the only account is a demo one printed on the login page, no real identity provider is contacted, and no
real credential is ever collected. Detection happens at the HTTP layer in the shield, not here.

Run:  .venv\\Scripts\\python -m uvicorn target.gov_portal:app --host 127.0.0.1 --port 8081
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
from hashlib import sha256

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from agent.odyssey_asgi import OdysseyShield

PORT = os.environ.get("GOV_TARGET_PORT", "8081")
SHIELD = os.environ.get("ODYSSEY_SHIELD_URL", "http://127.0.0.1:8000")
BASE = f"http://127.0.0.1:{PORT}"

app = FastAPI(title="Lokseva Citizen Alert Portal (SIMULATED)")
app.add_middleware(
    OdysseyShield,
    app_id="lokseva-alert-portal",
    name="Lokseva Citizen Alert Portal (SIM)",
    base_url=BASE,
    org_id=os.environ.get("GOV_TARGET_ORG", "GOV-01"),
    framework="fastapi",
    mode=os.environ.get("GOV_TARGET_MODE", "enforce"),
    shield_url=SHIELD,
)

# --- A self-contained, fictional OAuth 2.0 server (authorization code). No real IdP, no real credentials. -----------
DEMO_USER, DEMO_PASS = "officer", "demo123"                 # the only account; printed on the login page
OAUTH_CLIENTS = {"lokseva-web": {"secret": "demo-client-secret", "redirects": [f"{BASE}/callback"]}}
_SIGN_KEY = secrets.token_bytes(32)
_codes: dict[str, dict] = {}                                 # code -> {user, client_id, redirect_uri, exp}
_tokens: dict[str, dict] = {}                                # token -> {user, exp}


def _issue_token(user: str) -> str:
    tok = secrets.token_urlsafe(24)
    _tokens[tok] = {"user": user, "exp": time.time() + 3600}
    return tok


def _valid_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    tok = auth[7:] if auth.lower().startswith("bearer ") else request.cookies.get("lok_session", "")
    rec = _tokens.get(tok)
    return rec["user"] if rec and rec["exp"] > time.time() else None


# --- Fictional, clearly-labelled public alerts (CAP-style) ---------------------------------------------------------
ALERTS = [
    {"id": "SIM-LOK-2026-0001", "event": "Heavy Rainfall Warning", "area": "Jalnagar district (fictional)", "severity": "Moderate",
     "sent": "2026-11-01T06:10:00+05:30", "headline": "Moderate to heavy rain likely over Jalnagar in the next 6 hours."},
    {"id": "SIM-LOK-2026-0002", "event": "Grid Maintenance Notice", "area": "Vidyutpur (fictional)", "severity": "Minor",
     "sent": "2026-11-01T05:30:00+05:30", "headline": "Scheduled power maintenance in Vidyutpur, 02:00-04:00 tomorrow."},
    {"id": "SIM-LOK-2026-0003", "event": "Heat Advisory", "area": "Taptinagar (fictional)", "severity": "Minor",
     "sent": "2026-10-31T14:00:00+05:30", "headline": "Daytime temperatures above seasonal normal in Taptinagar this week."},
]
CAP_NS = "urn:oasis:names:tc:emergency:cap:1.2"

BANNER = ('<div style="background:#b45309;color:#fff;padding:8px 28px;font-size:13px;font-weight:600">'
          'SIMULATED LAB TARGET - a fictional agency for security testing. Not a real government service; holds no real data.</div>')
CSS = """<style>body{font-family:system-ui,Segoe UI,sans-serif;margin:0;color:#111}
.nav{background:#0b1f3a;color:#fff;padding:14px 28px;font-weight:700;font-size:20px;display:flex;justify-content:space-between;align-items:center}
.nav span{font-weight:400;font-size:13px;opacity:.85}.nav a{color:#cbd5e1;font-size:13px;text-decoration:none;margin-left:16px}
.wrap{max-width:820px;margin:34px auto;padding:0 20px}.card{background:#f4f5f7;border-radius:16px;padding:22px;margin:16px 0}
.alert{border-left:4px solid #0b1f3a;padding:8px 14px;margin:10px 0;background:#fff;border-radius:8px}
input{padding:10px 12px;border:1px solid #ccc;border-radius:10px;width:58%}
button{padding:10px 18px;border:0;border-radius:10px;background:#0b1f3a;color:#fff;font-weight:600;cursor:pointer}
.muted{color:#555}a{color:#1d4ed8}.demo{background:#fef3c7;border-radius:8px;padding:8px 12px;font-size:13px;margin:12px 0}</style>"""


def _page(title: str, inner: str, nav_right: str = '<a href="/login">Officer sign-in</a>') -> str:
    return (f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{title}</title>{CSS}{BANNER}"
            f"<div class=nav><div>Lokseva Digital Services Directorate</div><div><span>Citizen Alert Portal</span>{nav_right}</div></div>"
            f"<div class=wrap>{inner}</div></html>")


def _alerts_html() -> str:
    return "".join(f'<div class=alert><b>{a["event"]}</b> &middot; {a["area"]}<br><span class=muted>{a["headline"]} '
                   f'({a["severity"]}, {a["sent"][:16]})</span></div>' for a in ALERTS)


@app.get("/", response_class=HTMLResponse)
def home(q: str = ""):
    result = f"<p>Showing advisories for <b>{q}</b></p>" if q else ""
    inner = (f"<h1>Public safety alerts for your area</h1><p class=muted>Search advisories, check active alerts and sign in as an "
             f"officer. A fictional portal protected by the Odyssey HTTP shield; every request is inspected for web attacks.</p>"
             f"<div class=card><form action=/search method=get><label>Search advisories</label><br><br>"
             f"<input name=q placeholder='e.g. rainfall warning' value='{q}'> <button>Search</button></form>{result}</div>"
             f"<div class=card><h3>Active alerts</h3>{_alerts_html()}"
             f"<p class=muted><a href=/alerts.xml>CAP feed (XML)</a> &middot; <a href='/cap?id=SIM-LOK-2026-0001'>one alert as CAP</a></p></div>"
             f"<div class=card><h3>Officer area</h3><p class=muted>Sign in to the operations dashboard (OAuth).</p>"
             f"<a href='/oauth/authorize?client_id=lokseva-web&redirect_uri={BASE}/callback&response_type=code&state=xyz&scope=alerts'><button>Sign in with Lokseva ID</button></a></div>"
             f"<p class=muted>Endpoints: /search /alerts.xml /cap /submit /oauth/authorize /oauth/token /dashboard /login /feedback /download /view /ping /report</p>")
    return _page("Lokseva Citizen Alert Portal (SIM)", inner)


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Reflects the query back (so a real XSS payload would render) - the shield is what stops it.
    inner = f"<h1>Advisory search</h1><div class=card><form action=/search method=get><input name=q value='{q}'> <button>Search</button></form><p>No advisories matched <b>{q}</b>.</p></div>"
    return _page("Search - Lokseva (SIM)", inner)


# --- OAuth 2.0 (authorization code), all local and fictional -------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_form(next: str = "/dashboard"):
    inner = (f"<h1>Officer sign-in</h1><div class=demo>Demo account for this simulated portal: <b>{DEMO_USER}</b> / <b>{DEMO_PASS}</b>. "
             f"This is a lab login; it collects no real credentials.</div>"
             f"<div class=card><form action=/login method=post><label>Username</label><br><input name=user value=''><br><br>"
             f"<label>Password</label><br><input name=password type=password><br><br>"
             f"<input type=hidden name=next value='{next}'><button>Sign in</button></form></div>")
    return _page("Sign in - Lokseva (SIM)", inner)


@app.post("/login")
async def login_submit(request: Request):
    form = await _params(request)
    user, pw = form.get("user", ""), form.get("password", "")
    nxt = form.get("next", "/dashboard")
    if user == DEMO_USER and pw == DEMO_PASS:
        tok = _issue_token(user)
        r = RedirectResponse(nxt if nxt.startswith("/") else "/dashboard", status_code=303)
        r.set_cookie("lok_session", tok, httponly=True, samesite="lax")
        return r
    return JSONResponse({"ok": False, "error": "invalid credentials", "user": user}, status_code=401)


@app.get("/oauth/authorize", response_class=HTMLResponse)
def oauth_authorize(client_id: str = "", redirect_uri: str = "", response_type: str = "code", state: str = "", scope: str = ""):
    client = OAUTH_CLIENTS.get(client_id)
    if not client or response_type != "code":
        return JSONResponse({"error": "invalid_request", "detail": "unknown client_id or response_type"}, status_code=400)
    # A consent screen. 'redirect_uri' is reflected and honoured as sent, which is the classic open-redirect surface
    # the shield watches; the app validates nothing beyond the client existing (the lab point is detection, not safety).
    code = secrets.token_urlsafe(18)
    _codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "exp": time.time() + 120, "user": DEMO_USER}
    inner = (f"<h1>Authorize access</h1><div class=demo>A fictional OAuth consent screen. No real account is involved.</div>"
             f"<div class=card><p><b>{client_id}</b> is requesting access to <b>{scope or 'your alerts'}</b>.</p>"
             f"<form action=/oauth/decision method=get><input type=hidden name=code value='{code}'>"
             f"<input type=hidden name=redirect_uri value='{redirect_uri}'><input type=hidden name=state value='{state}'>"
             f"<button name=allow value=1>Allow</button> <button name=allow value=0 style='background:#777'>Deny</button></form></div>")
    return _page("Authorize - Lokseva (SIM)", inner)


@app.get("/oauth/decision")
def oauth_decision(code: str = "", redirect_uri: str = "", state: str = "", allow: str = "0"):
    if allow != "1" or code not in _codes:
        return RedirectResponse(f"{redirect_uri}?error=access_denied&state={state}", status_code=303)
    return RedirectResponse(f"{redirect_uri}?code={code}&state={state}", status_code=303)


@app.post("/oauth/token")
async def oauth_token(request: Request):
    form = await _params(request)
    code = form.get("code", "")
    rec = _codes.pop(code, None)
    if not rec or rec["exp"] < time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    client = OAUTH_CLIENTS.get(form.get("client_id", ""))
    if not client or form.get("client_secret") != client["secret"]:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    tok = _issue_token(rec["user"])
    return {"access_token": tok, "token_type": "Bearer", "expires_in": 3600, "scope": "alerts"}


@app.get("/callback")
def callback(code: str = "", state: str = "", error: str = ""):
    if error:
        return _page("Sign-in failed", f"<h1>Sign-in failed</h1><p class=muted>{error}</p><a href=/>Home</a>")
    # The demo client exchanges the code for a token server-side, then shows the dashboard link.
    try:
        r = httpx.post(f"{BASE}/oauth/token", data={"code": code, "client_id": "lokseva-web", "client_secret": "demo-client-secret",
                       "grant_type": "authorization_code", "redirect_uri": f"{BASE}/callback"}, timeout=8)
        tok = r.json().get("access_token")
    except Exception:  # noqa: BLE001
        tok = None
    resp = RedirectResponse("/dashboard", status_code=303)
    if tok:
        resp.set_cookie("lok_session", tok, httponly=True, samesite="lax")
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = _valid_token(request)
    if not user:
        return RedirectResponse("/login?next=/dashboard", status_code=303)
    inner = (f"<h1>Operations dashboard</h1><p class=muted>Signed in as <b>{user}</b> (demo).</p>"
             f"<div class=card><h3>Draft an alert</h3><form action=/submit method=post><textarea name=cap rows=4 cols=60 "
             f"placeholder='CAP 1.2 XML'></textarea><br><button>Submit to the alert gateway</button></form>"
             f"<p class=muted>Submitted CAP is forwarded to Odyssey's ingest guard, which validates it.</p></div>")
    return _page("Dashboard - Lokseva (SIM)", inner, nav_right='<a href="/logout">Sign out</a>')


@app.get("/logout")
def logout():
    r = RedirectResponse("/", status_code=303)
    r.delete_cookie("lok_session")
    return r


@app.get("/alerts.xml")
def alerts_feed():
    items = "".join(f"<item><title>{a['event']} - {a['area']}</title><guid>{a['id']}</guid>"
                    f"<description>{a['headline']}</description><pubDate>{a['sent']}</pubDate></item>" for a in ALERTS)
    xml = f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Lokseva Citizen Alert Portal (SIMULATED)</title>{items}</channel></rss>'
    return Response(content=xml, media_type="application/xml")


@app.get("/cap")
def cap(id: str = ""):
    a = next((x for x in ALERTS if x["id"] == id), ALERTS[0])
    xml = (f'<?xml version="1.0" encoding="UTF-8"?><alert xmlns="{CAP_NS}"><identifier>{a["id"]}</identifier>'
           f"<sender>LOK-Control (SIMULATED)</sender><sent>{a['sent']}</sent><status>Exercise</status><msgType>Alert</msgType>"
           f"<scope>Public</scope><info><language>en-IN</language><category>Met</category><event>{a['event']}</event>"
           f"<urgency>Expected</urgency><severity>{a['severity']}</severity><certainty>Likely</certainty><headline>{a['headline']}</headline>"
           f"<area><areaDesc>{a['area']}</areaDesc></area></info></alert>")
    return Response(content=xml, media_type="application/cap+xml")


@app.api_route("/submit", methods=["GET", "POST"])
async def submit(request: Request):
    """A CAP submission, forwarded to Odyssey's CAP ingest guard, which validates it. Nothing is stored here."""
    form = await _params(request)
    body = form.get("cap") or ((await request.body()).decode("utf-8", "replace") if request.method == "POST" else "")
    forwarded = None
    if body and "<" in body:
        try:
            r = httpx.post(f"{SHIELD}/api/sensor/cap", content=body.encode("utf-8", "replace"),
                           headers={"content-type": "application/xml"}, timeout=10)
            forwarded = r.json()
        except Exception as exc:  # noqa: BLE001
            forwarded = {"error": type(exc).__name__}
    return {"received": bool(body), "forwarded_to_cap_guard": forwarded,
            "note": "This fictional portal forwards submitted CAP to Odyssey's ingest guard; it stores nothing."}


@app.api_route("/feedback", methods=["GET", "POST"])
async def feedback(request: Request):
    form = await _params(request)
    return {"received": True, "message": form.get("msg", "")}


@app.get("/download")
def download(file: str = ""):
    if file in ("advisory-2026.pdf", "preparedness-guide.pdf", ""):
        return PlainTextResponse(f"[contents of {file or 'index'}]")
    return PlainTextResponse("file not found", status_code=404)


@app.get("/view")
def view(page: str = "home"):
    return {"page": page, "body": f"rendered {page}"}


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    return {"host": host, "reply": "1 packets transmitted, 1 received"}


@app.api_route("/report", methods=["GET", "POST"])
async def report(request: Request):
    form = await _params(request)
    return {"queued": True, "name": form.get("name", "")}


@app.get("/greet")
def greet(name: str = "citizen"):
    return {"greeting": f"Namaste {name}"}


async def _params(request: Request) -> dict:
    # Parse the body ourselves (no python-multipart dependency): urlencoded or JSON, else fall back to the query string.
    import json as _json
    from urllib.parse import parse_qsl
    out = dict(request.query_params)
    try:
        ctype = request.headers.get("content-type", "")
        raw = (await request.body()).decode("utf-8", "replace")
        if raw and "json" in ctype:
            data = _json.loads(raw)
            if isinstance(data, dict):
                out.update({str(k): v for k, v in data.items()})
        elif raw:
            out.update(dict(parse_qsl(raw, keep_blank_values=True)))
    except Exception:  # noqa: BLE001
        pass
    return out


# Everything else (admin panels, /.env, /.git, /phpmyadmin, ...) is a 404 - the enumeration noise the shield watches.
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
def not_found(path: str):
    return PlainTextResponse("404 Not Found", status_code=404)
