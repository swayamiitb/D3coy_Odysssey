"""Lokseva Digital Services Directorate - a FICTIONAL government-agency web app, a lab target for the Odyssey HTTP shield.

This is NOT a real government service and does not impersonate one. "Lokseva Digital Services Directorate" is a made-up
agency in Odyssey's simulated constituency (org GOV-01), the same fictional universe as the CityPower portal. Every
page carries a visible SIMULATION banner and a footer saying the same, and it holds no real database, shell, secret or
citizen data. It is built to look like a realistic citizen-services portal (masthead, navigation, services, notices,
helplines, an OAuth officer login) so the Odyssey shield has a believable target to defend: a person or the red-team
agent fires real web attacks at it on loopback and Odyssey detects, opens a case and reports.

The OAuth 2.0 flow is a self-contained mock: the only account is a demo one printed on the login page, no real identity
provider is contacted, and no real credential is collected. Detection happens at the HTTP layer in the shield, not
here. Loopback only.

Run:  .venv\\Scripts\\python -m uvicorn target.gov_portal:app --host 127.0.0.1 --port 8081
"""

from __future__ import annotations

import os
import secrets
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from agent.odyssey_asgi import OdysseyShield

PORT = os.environ.get("GOV_TARGET_PORT", "8081")
SHIELD = os.environ.get("ODYSSEY_SHIELD_URL", "http://127.0.0.1:8000")
BASE = f"http://127.0.0.1:{PORT}"

app = FastAPI(title="Lokseva Digital Services Directorate (SIMULATED)")
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
DEMO_USER, DEMO_PASS = "officer", "demo123"
OAUTH_CLIENTS = {"lokseva-web": {"secret": "demo-client-secret", "redirects": [f"{BASE}/callback"]}}
_codes: dict[str, dict] = {}
_tokens: dict[str, dict] = {}


def _issue_token(user: str) -> str:
    tok = secrets.token_urlsafe(24)
    _tokens[tok] = {"user": user, "exp": time.time() + 3600}
    return tok


def _valid_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    tok = auth[7:] if auth.lower().startswith("bearer ") else request.cookies.get("lok_session", "")
    rec = _tokens.get(tok)
    return rec["user"] if rec and rec["exp"] > time.time() else None


# --- Fictional content ---------------------------------------------------------------------------------------------
ALERTS = [
    {"id": "SIM-LOK-2026-0001", "event": "Heavy Rainfall Warning", "area": "Jalnagar district (fictional)", "severity": "Moderate",
     "sent": "2026-11-01T06:10:00+05:30", "headline": "Moderate to heavy rain likely over Jalnagar in the next 6 hours."},
    {"id": "SIM-LOK-2026-0002", "event": "Grid Maintenance Notice", "area": "Vidyutpur (fictional)", "severity": "Minor",
     "sent": "2026-11-01T05:30:00+05:30", "headline": "Scheduled power maintenance in Vidyutpur, 02:00-04:00 tomorrow."},
    {"id": "SIM-LOK-2026-0003", "event": "Heat Advisory", "area": "Taptinagar (fictional)", "severity": "Minor",
     "sent": "2026-10-31T14:00:00+05:30", "headline": "Daytime temperatures above seasonal normal in Taptinagar this week."},
]
NOTICES = [
    ("Monsoon preparedness circular 2026 issued to all district offices", "28 Oct 2026"),
    ("Mock drill for grid-failure response scheduled across Vidyutpur", "24 Oct 2026"),
    ("Revised standard operating procedure for CAP alerts in regional languages", "19 Oct 2026"),
    ("Public consultation: draft heat-action plan for Taptinagar", "12 Oct 2026"),
    ("Recruitment notice: 40 alert-desk officers (contractual, simulated)", "05 Oct 2026"),
]
CAP_NS = "urn:oasis:names:tc:emergency:cap:1.2"

BANNER = ('<div style="background:#b45309;color:#fff;padding:8px 28px;font-size:13px;font-weight:600;text-align:center">'
          'SIMULATED LAB TARGET - a fictional agency for security testing. Not a real government service; holds no real data.</div>')

CSS = """<style>
:root{--navy:#0b1f3a;--navy2:#13325c;--gold:#c79a3a;--ink:#1a2230;--line:#e3e7ee}
*{box-sizing:border-box}body{font-family:'Segoe UI',system-ui,Arial,sans-serif;margin:0;color:var(--ink);background:#fff;line-height:1.5}
a{color:#1d4ed8;text-decoration:none}a:hover{text-decoration:underline}
.topbar{background:#07152a;color:#9fb3cc;font-size:12.5px;padding:6px 28px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.topbar a{color:#cfe0f5}
.mast{background:var(--navy);color:#fff;padding:16px 28px;display:flex;align-items:center;gap:16px}
.mast h1{font-size:21px;margin:0;font-weight:700;letter-spacing:.2px}.mast .sub{font-size:12.5px;color:#b9cce6;margin-top:2px}
.nav{background:var(--navy2);display:flex;flex-wrap:wrap;gap:2px;padding:0 20px}
.nav a{color:#e8eef7;font-size:14px;padding:12px 16px;display:inline-block;border-bottom:3px solid transparent}
.nav a:hover{background:#1b406f;text-decoration:none;border-bottom-color:var(--gold)}
.hero{background:linear-gradient(120deg,#0b1f3a,#1b406f);color:#fff;padding:40px 28px}
.hero h2{font-size:30px;margin:0 0 8px}.hero p{color:#cdddf2;max-width:680px;margin:0 0 18px}
.searchbar{display:flex;gap:8px;max-width:620px}.searchbar input{flex:1;width:auto}
.quick{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}.quick a{background:rgba(255,255,255,.12);color:#fff;padding:8px 14px;border-radius:8px;font-size:13.5px}
.wrap{max-width:1040px;margin:0 auto;padding:26px 20px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.stat{background:#f5f7fb;border:1px solid var(--line);border-radius:12px;padding:16px;text-align:center}
.stat b{display:block;font-size:26px;color:var(--navy)}.stat span{font-size:12.5px;color:#667}
h3.sec{font-size:19px;margin:28px 0 12px;padding-bottom:8px;border-bottom:2px solid var(--line)}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.svc{display:block;background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;color:var(--ink)}
.svc:hover{border-color:var(--navy);text-decoration:none;box-shadow:0 2px 10px rgba(11,31,58,.08)}
.svc .ic{font-size:22px}.svc b{display:block;margin:6px 0 2px}.svc span{font-size:13px;color:#667}
.card{background:#f6f8fb;border:1px solid var(--line);border-radius:14px;padding:20px;margin:14px 0}
.alert{border-left:4px solid var(--gold);padding:10px 14px;margin:10px 0;background:#fff;border:1px solid var(--line);border-radius:8px}
.alert .sev{font-size:11px;font-weight:700;text-transform:uppercase;color:#92400e;background:#fde9c3;padding:1px 7px;border-radius:6px;margin-left:8px}
.notice{padding:9px 0;border-bottom:1px dashed var(--line);font-size:14.5px}.notice span{color:#789;font-size:12.5px;margin-left:8px}
input,textarea{padding:10px 12px;border:1px solid #c7ced9;border-radius:9px;font-size:14px;font-family:inherit}input{width:58%}
button{padding:10px 18px;border:0;border-radius:9px;background:var(--navy);color:#fff;font-weight:600;cursor:pointer}
.muted{color:#667}.demo{background:#fef3c7;border:1px solid #f3d786;border-radius:8px;padding:9px 12px;font-size:13px;margin:12px 0}
.two{display:grid;grid-template-columns:2fr 1fr;gap:20px}
.help{background:#07152a;color:#dbe6f5;border-radius:12px;padding:16px}.help b{color:#fff}.help .num{font-size:20px;color:var(--gold);font-weight:700}
.footer{background:#07152a;color:#9fb3cc;margin-top:30px;padding:28px 0}
.footer .cols{max-width:1040px;margin:0 auto;padding:0 20px;display:grid;grid-template-columns:repeat(4,1fr);gap:20px;font-size:13.5px}
.footer h4{color:#fff;font-size:13px;text-transform:uppercase;letter-spacing:.5px;margin:0 0 10px}
.footer a{color:#b9cce6;display:block;padding:3px 0}
.footer .bottom{border-top:1px solid #1b2f4d;margin-top:20px;padding-top:14px;max-width:1040px;margin:20px auto 0;padding-left:20px;padding-right:20px;font-size:12.5px;color:#7f93ad}
@media(max-width:760px){.stats,.grid,.footer .cols{grid-template-columns:1fr 1fr}.two{grid-template-columns:1fr}.mast h1{font-size:18px}}
</style>"""

EMBLEM = ('<svg width=52 height=52 viewBox="0 0 52 52" aria-hidden=true>'
          '<circle cx=26 cy=26 r=25 fill="#13325c" stroke="#c79a3a" stroke-width=2/>'
          '<circle cx=26 cy=26 r=18 fill="none" stroke="#c79a3a" stroke-width=1 opacity=.6/>'
          '<path d="M26 11 L29.5 22 L41 22 L31.7 29 L35.2 40 L26 33.2 L16.8 40 L20.3 29 L11 22 L22.5 22 Z" fill="#c79a3a"/>'
          '<text x=26 y=50 text-anchor=middle font-size=7 fill="#9fb3cc" font-family=sans-serif>LDS</text></svg>')
TOPBAR = ('<div class=topbar><div>An initiative of the (simulated) Department of Civil Preparedness &middot; Toll-free 1800-SIM-0000</div>'
          '<div><a href="/login">Officer login</a> &nbsp;|&nbsp; <a href="/alerts.xml">CAP feed</a> &nbsp;|&nbsp; A- A A+ &nbsp;|&nbsp; EN | &#2361;&#2367;</div></div>')
NAVBAR = ('<nav class=nav><a href="/">Home</a><a href="/#alerts">Alerts</a><a href="/services">Services</a>'
          '<a href="/notices">Notices &amp; circulars</a><a href="/about">About</a><a href="/contact">Contact</a>{right}</nav>')
FOOTER = ('<footer class=footer><div class=cols>'
          '<div><h4>Services</h4><a href="/services">Report an outage</a><a href="/services">Check application status</a>'
          '<a href="/download">Download forms</a><a href="/contact">Submit feedback</a></div>'
          '<div><h4>Alerts</h4><a href="/#alerts">Active alerts</a><a href="/alerts.xml">CAP feed (XML)</a>'
          '<a href="/cap?id=SIM-LOK-2026-0001">Latest advisory</a><a href="/notices">Notices</a></div>'
          '<div><h4>About</h4><a href="/about">The Directorate</a><a href="/about">Leadership</a>'
          '<a href="/about">Right to Information</a><a href="/contact">Grievance redressal</a></div>'
          '<div><h4>Connect</h4><a href="/contact">Control room</a><a href="/contact">Regional offices</a>'
          '<a href="/login">Officer portal</a><a href="/about">Careers</a></div></div>'
          '<div class=bottom>&copy; 2026 Lokseva Digital Services Directorate (SIMULATED). A fictional agency and a security-testing '
          'lab target - not a real government service, and it holds no real data. Protected by the Odyssey HTTP shield.</div></footer>')


def _page(title: str, inner: str, nav_right: str = "") -> str:
    if "class=hero" not in inner and "class=wrap" not in inner:
        inner = f"<div class=wrap>{inner}</div>"
    nav = NAVBAR.format(right=nav_right or '<a href="/login">Officer login</a>')
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'><title>{title}</title>{CSS}</head><body>"
            f"{BANNER}{TOPBAR}<div class=mast><div>{EMBLEM}</div><div><h1>Lokseva Digital Services Directorate</h1>"
            f"<div class=sub>Citizen Alert &amp; Public Safety Portal &middot; simulated</div></div></div>"
            f"{nav}{inner}{FOOTER}</body></html>")


def _alerts_html() -> str:
    return "".join(f'<div class=alert><b>{a["event"]}</b> <span class=sev>{a["severity"]}</span><br>'
                   f'<span class=muted>{a["area"]} &middot; {a["headline"]} &middot; issued {a["sent"][:16]}</span></div>' for a in ALERTS)


def _notices_html() -> str:
    return "".join(f'<div class=notice><a href="/view?page=notice-{i}">{t}</a><span>{d}</span></div>' for i, (t, d) in enumerate(NOTICES))


SERVICES = [("&#128226;", "Report an outage or hazard", "Tell the control room about a power cut, flood or fire.", "/services"),
            ("&#128196;", "Check application status", "Track a permit, claim or grievance by reference number.", "/services"),
            ("&#11015;", "Download forms &amp; guides", "Preparedness guides, claim forms and circulars.", "/download"),
            ("&#128276;", "Subscribe to alerts", "Get CAP alerts for your district from the public feed.", "/alerts.xml"),
            ("&#128737;", "Officer portal", "Sign in to the operations dashboard (OAuth).", "/login"),
            ("&#9993;", "Grievance &amp; feedback", "Raise a complaint or send feedback to the Directorate.", "/contact")]


@app.get("/", response_class=HTMLResponse)
def home(q: str = ""):
    res = f'<div class=card><b>Showing advisories for &ldquo;{q}&rdquo;</b><p class=muted>No matching advisory in the public index.</p></div>' if q else ""
    cards = "".join(f'<a class=svc href="{u}"><div class=ic>{i}</div><b>{t}</b><span>{d}</span></a>' for i, t, d, u in SERVICES)
    inner = (f'<div class=hero><h2>Public safety, delivered to every district</h2>'
             f'<p>The Lokseva Digital Services Directorate issues early warnings and runs citizen services for the simulated '
             f'union territory of Bharatpur. Search advisories, use a service, or sign in as an officer.</p>'
             f'<form class=searchbar action=/search method=get><input name=q placeholder="Search advisories, forms and services" value="{q}"><button>Search</button></form>'
             f'<div class=quick><a href="/#alerts">View active alerts</a><a href="/services">All services</a><a href="/contact">Contact the control room</a></div></div>'
             f'<div class=wrap>{res}<div class=stats>'
             f'<div class=stat><b>1,284</b><span>advisories issued (2026)</span></div><div class=stat><b>34</b><span>districts covered</span></div>'
             f'<div class=stat><b>24&#215;7</b><span>control room</span></div><div class=stat><b>99.1%</b><span>alerts within 10 min</span></div></div>'
             f'<h3 class=sec>Online services</h3><div class=grid>{cards}</div>'
             f'<div id=alerts></div><h3 class=sec>Active public alerts</h3>{_alerts_html()}'
             f'<p class=muted><a href="/alerts.xml">CAP feed (XML)</a> &middot; <a href="/cap?id=SIM-LOK-2026-0001">latest advisory as CAP 1.2</a></p>'
             f'<div class=two><div><h3 class=sec>Notices &amp; circulars</h3>{_notices_html()}</div>'
             f'<div><h3 class=sec>Emergency helplines</h3><div class=help><div class=num>1800-SIM-0000</div><b>Disaster control room</b>'
             f'<div class=num style="margin-top:10px">1800-SIM-1122</div><b>Power &amp; grid outages</b>'
             f'<div class=num style="margin-top:10px">1800-SIM-0112</div><b>General helpline</b>'
             f'<p style="color:#9fb3cc;margin-top:12px">Fictional numbers for a simulated portal.</p></div></div></div></div>')
    return _page("Lokseva Digital Services Directorate (SIM)", inner)


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Reflects the query back (so a real XSS payload would render) - the shield is what stops it.
    inner = (f'<h3 class=sec>Advisory search</h3>'
             f'<form class=searchbar action=/search method=get style="max-width:620px"><input name=q value="{q}"><button>Search</button></form>'
             f'<div class=card><p>No advisories matched <b>{q}</b>. Showing recent public alerts instead.</p></div>{_alerts_html()}')
    return _page("Search - Lokseva (SIM)", inner)


@app.get("/services", response_class=HTMLResponse)
def services_page(id: str = ""):
    status = f'<div class=card><b>Status for reference {id}</b><p class=muted>No application found with that reference number.</p></div>' if id else ""
    inner = (f'<h3 class=sec>Online services</h3>{status}'
             f'<div class=card><b>Check application status</b><br><form action=/services method=get style="margin-top:10px">'
             f'<input name=id placeholder="Reference number, e.g. LOK-2026-00482"> <button>Check</button></form></div>'
             f'<div class=card><b>Report an outage or hazard</b><br><form action=/report method=post style="margin-top:10px">'
             f'<input name=name placeholder="Your name"> <input name=detail placeholder="What is happening?"> <button>Report</button></form></div>'
             f'<div class=card><b>Download a form or guide</b><p class=muted><a href="/download?file=preparedness-guide.pdf">Preparedness guide</a> '
             f'&middot; <a href="/download?file=advisory-2026.pdf">Advisory 2026</a></p></div>')
    return _page("Services - Lokseva (SIM)", inner)


@app.get("/about", response_class=HTMLResponse)
def about_page():
    inner = ('<h3 class=sec>About the Directorate</h3>'
             '<div class=card><p>The Lokseva Digital Services Directorate is a <b>fictional</b> agency used to demonstrate the Odyssey '
             'cyber early-warning system. In this simulation it coordinates disaster alerts and citizen services for the union territory '
             'of Bharatpur. It is not a real government body and provides no real services.</p>'
             '<p class=muted>Established (in the simulation) 2019 &middot; Headquartered at the Bharatpur Secretariat &middot; '
             'Reports to the simulated Department of Civil Preparedness.</p></div>'
             '<div class=two><div class=card><b>Leadership</b><p class=muted>Director-General (simulated) &middot; Joint Director, Alerts &middot; '
             'Joint Director, Citizen Services</p></div><div class=card><b>Right to Information</b><p class=muted>File an RTI request with the '
             'Public Information Officer via the <a href="/contact">contact form</a>.</p></div></div>')
    return _page("About - Lokseva (SIM)", inner)


@app.api_route("/contact", methods=["GET", "POST"], response_class=HTMLResponse)
async def contact_page(request: Request):
    sent = ""
    if request.method == "POST":
        form = await _params(request)
        ref = abs(hash(form.get("msg", ""))) % 100000
        sent = f'<div class=card><b>Thank you.</b> Your message has been logged (reference SIM-{ref:05d}).</div>'
    inner = (f'<h3 class=sec>Contact &amp; grievances</h3>{sent}'
             f'<div class=two><div class=card><b>Send a message</b><br><form action=/contact method=post style="margin-top:10px">'
             f'<input name=name placeholder="Your name"><br><br><input name=email placeholder="Email"><br><br>'
             f'<textarea name=msg rows=4 style="width:92%" placeholder="Your message or grievance"></textarea><br><br><button>Submit</button></form></div>'
             f'<div class=card><b>Control room</b><p class=muted>Bharatpur Secretariat, Block C (simulated)<br>control-room@lokseva.sim (not a real address)'
             f'<br>Toll-free 1800-SIM-0000</p></div></div>')
    return _page("Contact - Lokseva (SIM)", inner)


@app.get("/notices", response_class=HTMLResponse)
def notices_page():
    return _page("Notices - Lokseva (SIM)", f'<h3 class=sec>Notices &amp; circulars</h3><div class=card>{_notices_html()}</div>')


# --- OAuth 2.0 (authorization code), all local and fictional -------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_form(next: str = "/dashboard"):
    inner = (f"<h3 class=sec>Officer sign-in</h3><div class=demo>Demo account for this simulated portal: <b>{DEMO_USER}</b> / <b>{DEMO_PASS}</b>. "
             f"This is a lab login; it collects no real credentials.</div>"
             f"<div class=card><form action=/login method=post><label>Username</label><br><input name=user><br><br>"
             f"<label>Password</label><br><input name=password type=password><br><br>"
             f"<input type=hidden name=next value='{next}'><button>Sign in</button></form></div>")
    return _page("Sign in - Lokseva (SIM)", inner)


@app.post("/login")
async def login_submit(request: Request):
    form = await _params(request)
    nxt = form.get("next", "/dashboard")
    if form.get("user") == DEMO_USER and form.get("password") == DEMO_PASS:
        r = RedirectResponse(nxt if nxt.startswith("/") else "/dashboard", status_code=303)
        r.set_cookie("lok_session", _issue_token(DEMO_USER), httponly=True, samesite="lax")
        return r
    return JSONResponse({"ok": False, "error": "invalid credentials", "user": form.get("user", "")}, status_code=401)


@app.get("/oauth/authorize", response_class=HTMLResponse)
def oauth_authorize(client_id: str = "", redirect_uri: str = "", response_type: str = "code", state: str = "", scope: str = ""):
    if client_id not in OAUTH_CLIENTS or response_type != "code":
        return JSONResponse({"error": "invalid_request", "detail": "unknown client_id or response_type"}, status_code=400)
    code = secrets.token_urlsafe(18)
    _codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "exp": time.time() + 120, "user": DEMO_USER}
    inner = (f"<h3 class=sec>Authorize access</h3><div class=demo>A fictional OAuth consent screen. No real account is involved.</div>"
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
    rec = _codes.pop(form.get("code", ""), None)
    if not rec or rec["exp"] < time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    client = OAUTH_CLIENTS.get(form.get("client_id", ""))
    if not client or form.get("client_secret") != client["secret"]:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    return {"access_token": _issue_token(rec["user"]), "token_type": "Bearer", "expires_in": 3600, "scope": "alerts"}


@app.get("/callback")
def callback(code: str = "", state: str = "", error: str = ""):
    if error:
        return _page("Sign-in failed", f"<h3 class=sec>Sign-in failed</h3><div class=card>{error}</div>")
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
    inner = (f"<h3 class=sec>Operations dashboard</h3><p class=muted>Signed in as <b>{user}</b> (demo).</p>"
             f"<div class=card><b>Draft and issue an alert</b><br><form action=/submit method=post style='margin-top:10px'>"
             f"<textarea name=cap rows=4 style='width:92%' placeholder='CAP 1.2 XML'></textarea><br><br><button>Submit to the alert gateway</button></form>"
             f"<p class=muted>Submitted CAP is forwarded to Odyssey's ingest guard, which validates it before it is trusted.</p></div>")
    return _page("Dashboard - Lokseva (SIM)", inner, nav_right='<a href="/logout">Sign out</a>')


@app.get("/logout")
def logout():
    r = RedirectResponse("/", status_code=303)
    r.delete_cookie("lok_session")
    return r


# --- Data endpoints and the rest of the attack surface -------------------------------------------------------------
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
            forwarded = httpx.post(f"{SHIELD}/api/sensor/cap", content=body.encode("utf-8", "replace"),
                                   headers={"content-type": "application/xml"}, timeout=10).json()
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
