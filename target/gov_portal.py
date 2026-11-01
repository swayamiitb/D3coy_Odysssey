"""Lokseva Citizen Alert Portal - a FICTIONAL government-agency web app, a lab target for the Odyssey HTTP shield.

This is NOT a real government service and does not impersonate one. "Lokseva Digital Services Directorate" is a made-up
operator in Odyssey's simulated constituency (org GOV-01), the same fictional universe as the CityPower portal. The
page carries a visible SIMULATION banner. It exists for one reason: to give the Odyssey shield a realistic-looking
government target to defend, so a person (or a separate red-team session) can fire real web attacks at it on loopback
and watch Odyssey detect, open a case and report, exactly as with the CityPower portal.

Like that portal it deliberately reflects user input and exposes the endpoints attackers probe, but it holds no real
database, shell, secret or citizen data: detection happens at the HTTP layer in the shield, not here. It binds to
Odyssey via the drop-in agent, so every request is forwarded to the shield at http://127.0.0.1:8000. A submitted
"alert" is additionally forwarded to Odyssey's CAP ingest guard, so CAP-level attacks (forged sender, XXE, replay) are
exercised too. Loopback only.

Run:  .venv\\Scripts\\python -m uvicorn target.gov_portal:app --host 127.0.0.1 --port 8081
"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from agent.odyssey_asgi import OdysseyShield

PORT = os.environ.get("GOV_TARGET_PORT", "8081")
SHIELD = os.environ.get("ODYSSEY_SHIELD_URL", "http://127.0.0.1:8000")

app = FastAPI(title="Lokseva Citizen Alert Portal (SIMULATED)")
app.add_middleware(
    OdysseyShield,
    app_id="lokseva-alert-portal",
    name="Lokseva Citizen Alert Portal (SIM)",
    base_url=f"http://127.0.0.1:{PORT}",
    org_id=os.environ.get("GOV_TARGET_ORG", "GOV-01"),
    framework="fastapi",
    mode=os.environ.get("GOV_TARGET_MODE", "enforce"),
    shield_url=SHIELD,
)

# A handful of clearly fictional, CAP-style public alerts for this made-up agency's made-up districts.
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

PAGE = """<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Lokseva Citizen Alert Portal (SIM)</title>
<style>body{{font-family:system-ui,Segoe UI,sans-serif;margin:0;color:#111}}
.nav{{background:#0b1f3a;color:#fff;padding:14px 28px;font-weight:700;font-size:20px;display:flex;justify-content:space-between}}
.nav span{{font-weight:400;font-size:13px;opacity:.8}}
.wrap{{max-width:820px;margin:34px auto;padding:0 20px}}
.card{{background:#f4f5f7;border-radius:16px;padding:22px;margin:16px 0}}
.alert{{border-left:4px solid #0b1f3a;padding:8px 14px;margin:10px 0;background:#fff;border-radius:8px}}
input{{padding:10px 12px;border:1px solid #ccc;border-radius:10px;width:58%}}
button{{padding:10px 18px;border:0;border-radius:10px;background:#0b1f3a;color:#fff;font-weight:600}}
.muted{{color:#555}} a{{color:#1d4ed8}}</style>
{banner}
<div class=nav><div>Lokseva Digital Services Directorate</div><span>Citizen Alert Portal</span></div>
<div class=wrap>
<h1>Public safety alerts for your area</h1>
<p class=muted>Search advisories, check active alerts and report an issue. A fictional portal protected by the Odyssey
HTTP shield; every request is inspected for web attacks.</p>
<div class=card><form action=/search method=get>
  <label>Search advisories</label><br><br>
  <input name=q placeholder="e.g. rainfall warning" value="{q}"> <button>Search</button>
</form>{result}</div>
<div class=card><h3>Active alerts</h3>{alerts}
  <p class=muted><a href=/alerts.xml>CAP feed (XML)</a> &middot; <a href=/cap?id=SIM-LOK-2026-0001>one alert as CAP</a></p></div>
<div class=card><form action=/login method=post>
  <label>Officer sign-in</label><br><br>
  <input name=user placeholder=username> <button>Sign in</button>
</form></div>
<p class=muted>Endpoints: /search /alerts.xml /cap /submit /login /feedback /download /view /ping /report /greet</p>
</div></html>"""


def _alerts_html() -> str:
    return "".join(f'<div class=alert><b>{a["event"]}</b> &middot; {a["area"]}<br><span class=muted>{a["headline"]} '
                   f'({a["severity"]}, {a["sent"][:16]})</span></div>' for a in ALERTS)


@app.get("/", response_class=HTMLResponse)
def home(q: str = ""):
    result = f"<p>Showing advisories for <b>{q}</b></p>" if q else ""
    return PAGE.format(banner=BANNER, q=q, result=result, alerts=_alerts_html())


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Reflects the query back (so a real XSS payload would render) - the shield is what stops it.
    result = f"<p>No advisories matched <b>{q}</b>.</p>" if q else ""
    return PAGE.format(banner=BANNER, q=q, result=result, alerts=_alerts_html())


@app.get("/alerts.xml")
def alerts_feed():
    items = "".join(f"<item><title>{a['event']} - {a['area']}</title><guid>{a['id']}</guid>"
                    f"<description>{a['headline']}</description><pubDate>{a['sent']}</pubDate></item>" for a in ALERTS)
    xml = (f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
           f"<title>Lokseva Citizen Alert Portal (SIMULATED)</title>{items}</channel></rss>")
    return Response(content=xml, media_type="application/xml")


@app.get("/cap")
def cap(id: str = ""):
    a = next((x for x in ALERTS if x["id"] == id), ALERTS[0])
    sev = {"Extreme": "Extreme", "Severe": "Severe", "Moderate": "Moderate", "Minor": "Minor"}.get(a["severity"], "Minor")
    xml = (f'<?xml version="1.0" encoding="UTF-8"?><alert xmlns="{CAP_NS}"><identifier>{a["id"]}</identifier>'
           f"<sender>LOK-Control (SIMULATED)</sender><sent>{a['sent']}</sent><status>Exercise</status><msgType>Alert</msgType>"
           f"<scope>Public</scope><info><language>en-IN</language><category>Met</category><event>{a['event']}</event>"
           f"<urgency>Expected</urgency><severity>{sev}</severity><certainty>Likely</certainty><headline>{a['headline']}</headline>"
           f"<area><areaDesc>{a['area']}</areaDesc></area></info></alert>")
    return Response(content=xml, media_type="application/cap+xml")


@app.api_route("/submit", methods=["GET", "POST"])
async def submit(request: Request):
    """A citizen/officer submits a CAP alert. It is forwarded to Odyssey's CAP ingest guard, which validates it; the
    HTTP shield has already inspected the request itself. Nothing is stored here."""
    form = await _params(request)
    body = form.get("cap") or (await request.body()).decode("utf-8", "replace") if request.method == "POST" else form.get("cap", "")
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


@app.post("/login")
async def login(request: Request):
    form = await _params(request)
    return JSONResponse({"ok": False, "error": "invalid credentials", "user": form.get("user", "")}, status_code=401)


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
    try:
        if "json" in request.headers.get("content-type", ""):
            return await request.json()
        form = await request.form()
        return {k: v for k, v in form.items()}
    except Exception:  # noqa: BLE001
        return dict(request.query_params)


# Everything else (admin panels, /.env, /.git, /phpmyadmin, ...) is a 404 - the enumeration noise the shield watches.
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
def not_found(path: str):
    return PlainTextResponse("404 Not Found", status_code=404)
