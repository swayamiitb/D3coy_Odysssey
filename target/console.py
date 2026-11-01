"""CityPower Ops Console - the *destination* app in the lab: where Odyssey's alerts land.

It stands in for whatever a team already watches - Slack, Teams, Discord, a Jira board, its own dashboard - any app
that accepts a webhook. Odyssey's Channels layer (backend/app/notify.py) POSTs one JSON card per alert to
/hooks/odyssey, and this page shows them the moment they arrive. Point the same channel at a real Slack or Discord URL
and the same card lands there: the console is simply the receiver you can run on this laptop with no account.

The webhook contract (what any app of yours receives):
    {"source": "odyssey", "event": {"seq", "ts", "kind", "subject", "provenance"}, "severity": "Critical",
     "title": "...", "lines": ["..."], "link": "http://.../?view=live", "when_ist": "01 Nov 04:58:10 IST"}

Alert text is rendered as text, never as HTML: an XSS payload quoted in an alert's evidence must not run here.

Run:  .venv\\Scripts\\python -m uvicorn target.console:app --host 127.0.0.1 --port 8090
"""

from __future__ import annotations

import collections
import datetime as dt

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI(title="CityPower Ops Console")
ALERTS: collections.deque = collections.deque(maxlen=200)
COUNT = {"received": 0}

PAGE = """<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>CityPower Ops Console</title>
<style>body{font-family:system-ui,Segoe UI,sans-serif;margin:0;color:#111;background:#fff}
.nav{background:#000;color:#fff;padding:14px 28px;font-weight:700;font-size:20px;display:flex;justify-content:space-between;align-items:center}
.nav small{font-weight:500;color:#bbb;font-size:14px}
.wrap{max-width:860px;margin:32px auto;padding:0 20px}
.card{background:#f6f6f6;border-radius:16px;padding:18px 20px 18px 24px;margin:12px 0;border-left:6px solid #a6a6a6}
.sev{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.title{font-size:17px;font-weight:700;margin:4px 0 6px;overflow-wrap:anywhere}
.line{color:#444;font-size:14px;margin:2px 0;overflow-wrap:anywhere}
.meta{color:#777;font-size:12px;margin-top:8px}
.muted{color:#555} a{color:#276ef1}
button{padding:8px 14px;border:0;border-radius:10px;background:#000;color:#fff;font-weight:600;cursor:pointer}
.empty{color:#666;background:#f6f6f6;border-radius:16px;padding:28px;text-align:center}</style>
<div class=nav><span>⚡ CityPower &nbsp;·&nbsp; Ops Console</span><small id=count>waiting for alerts…</small></div>
<div class=wrap>
<p class=muted>The team's console. Alerts arrive here from Odyssey over a webhook, exactly as they would reach Slack,
Teams or Discord. <button onclick="clearAll()">Clear</button></p>
<div id=list></div>
</div>
<script>
const COLOUR = {Compromise: '#7356bf', Critical: '#e11900', High: '#ff6937', Medium: '#ffc043'};
const EMPTY = 'No alerts yet. Attack the protected portal, or send a test alert from Odyssey: Live, "Alerts delivered to your apps".';
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function render(d) {
  document.getElementById('count').textContent = d.received ? `${d.received} alert${d.received === 1 ? '' : 's'} received` : 'waiting for alerts…';
  const list = document.getElementById('list');
  list.replaceChildren();
  if (!d.alerts.length) { list.append(el('div', 'empty', EMPTY)); return; }
  for (const a of d.alerts) {
    const c = el('div', 'card'); c.style.borderLeftColor = COLOUR[a.severity] || '#a6a6a6';
    const s = el('div', 'sev', a.severity || ''); s.style.color = COLOUR[a.severity] || '#555'; c.append(s);
    c.append(el('div', 'title', a.title || ''));
    for (const l of (a.lines || [])) c.append(el('div', 'line', l));
    const m = el('div', 'meta', `${(a.event || {}).kind || ''} · ${a.when_ist || a.received_at || ''} · `);
    if (a.link) { const k = el('a', null, 'open in Odyssey'); k.href = a.link; k.target = '_blank'; k.rel = 'noopener'; m.append(k); }
    c.append(m); list.append(c);
  }
}
async function pull() { try { render(await (await fetch('/api/alerts')).json()); } catch (e) { /* the console keeps the last view */ } }
async function clearAll() { await fetch('/api/clear', {method: 'POST'}); pull(); }
pull(); setInterval(pull, 1500);
</script></html>"""


@app.post("/hooks/odyssey")
async def hook(request: Request) -> dict:
    """Odyssey's webhook lands here: one card per alert."""
    body = await request.json()
    if not isinstance(body, dict):
        body = {"title": str(body)}
    body["received_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ALERTS.appendleft(body)
    COUNT["received"] += 1
    return {"ok": True, "received": COUNT["received"]}


@app.get("/api/alerts")
def alerts() -> dict:
    return {"received": COUNT["received"], "alerts": list(ALERTS)}


@app.post("/api/clear")
def clear() -> dict:
    ALERTS.clear()
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return PAGE
