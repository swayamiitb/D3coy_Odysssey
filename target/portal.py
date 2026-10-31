"""CityPower Customer Portal - a small, self-contained web app that stands in for a *real* protected application.

It exists so the Odyssey HTTP shield has something genuine to defend in the demo: the Odyssey agent is mounted in
front of it, so every request (benign or malicious) is forwarded to the shield at http://127.0.0.1:8000. When the
red-team runner fires real SQLi / XSS / traversal / command-injection / scanning / brute-force requests at this app,
the shield detects them over the wire and - in block mode - this app returns 403 because the agent dropped them.

The app deliberately *reflects* user input (so an XSS payload would appear in the response) and exposes the kinds of
endpoints attackers probe, but it holds no real database, shell or secret: the point is to demonstrate detection at
the HTTP layer, not to be exploitable. It is a lab target, meant to run only on this laptop.

Run:  .venv\\Scripts\\python -m uvicorn target.portal:app --host 127.0.0.1 --port 8080
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from agent.odyssey_asgi import OdysseyShield

app = FastAPI(title="CityPower Customer Portal")
app.add_middleware(
    OdysseyShield,
    app_id="citypower-portal",
    name="CityPower Customer Portal",
    base_url=f"http://127.0.0.1:{os.environ.get('TARGET_PORT', '8080')}",
    org_id=os.environ.get("TARGET_ORG", "PWR-01"),
    framework="fastapi",
    mode=os.environ.get("TARGET_MODE", "enforce"),
    shield_url=os.environ.get("ODYSSEY_SHIELD_URL", "http://127.0.0.1:8000"),
)

PAGE = """<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>CityPower Customer Portal</title>
<style>body{{font-family:system-ui,Segoe UI,sans-serif;margin:0;color:#111}}
.nav{{background:#000;color:#fff;padding:14px 28px;font-weight:700;font-size:20px}}
.wrap{{max-width:760px;margin:40px auto;padding:0 20px}}
.card{{background:#f6f6f6;border-radius:16px;padding:22px;margin:16px 0}}
input{{padding:10px 12px;border:1px solid #ccc;border-radius:10px;width:60%}}
button{{padding:10px 18px;border:0;border-radius:10px;background:#000;color:#fff;font-weight:600}}
.muted{{color:#555}} a{{color:#276ef1}}</style>
<div class=nav>⚡ CityPower &nbsp;·&nbsp; Customer Portal</div>
<div class=wrap>
<h1>Your electricity, online</h1>
<p class=muted>Pay bills, report outages and check your connection. This is a demo application protected by the
Odyssey HTTP shield.</p>
<div class=card><form action=/search method=get>
  <label>Search help articles & products</label><br><br>
  <input name=q placeholder="e.g. smart meter" value="{q}"> <button>Search</button>
</form>{result}</div>
<div class=card><form action=/login method=post>
  <label>Account login</label><br><br>
  <input name=user placeholder=username> <button>Sign in</button>
</form></div>
<p class=muted>Endpoints: /search /product /login /feedback /download /view /ping /report /greet /fetch</p>
</div></html>"""


@app.get("/", response_class=HTMLResponse)
def home(q: str = ""):
    result = f"<p>Showing results for <b>{q}</b></p>" if q else ""
    return PAGE.format(q=q, result=result)


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Reflects the query back into the page (so a real XSS payload would render) - the shield is what stops it.
    result = f"<p>No products matched <b>{q}</b>.</p>" if q else ""
    return PAGE.format(q=q, result=result)


@app.get("/product")
def product(id: str = "0"):
    return {"product_id": id, "name": f"Item {id}", "in_stock": True}


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
    # A whitelist of real documents; anything else is "not found" (and the shield has already flagged traversal).
    if file in ("tariff-2026.pdf", "annual-report.pdf", ""):
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
def greet(name: str = "there"):
    return {"greeting": f"Hello {name}"}


@app.get("/fetch")
def fetch(url: str = ""):
    return {"requested": url, "status": "the portal does not proxy external URLs"}


async def _params(request: Request) -> dict:
    try:
        if "json" in request.headers.get("content-type", ""):
            return await request.json()
        form = await request.form()
        return {k: v for k, v in form.items()}
    except Exception:  # noqa: BLE001
        return dict(request.query_params)


# Everything else (admin panels, /.env, /.git, /phpmyadmin, ...) is a 404 - which is exactly the enumeration noise
# the shield's scanning-sweep detector watches for.
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
def not_found(path: str):
    return PlainTextResponse("404 Not Found", status_code=404)
