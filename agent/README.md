# Connect a real app to Odyssey's HTTP shield

Odyssey can protect a **real** web application. A small agent inside (or in front of) your app forwards each
request's metadata to Odyssey's shield, which inspects it for web attacks — SQL injection, XSS, path traversal,
command injection, SSTI/SSRF/Log4Shell, scanning and brute force — records every detection in the hash-chained audit
trail, drives the autopilot, and (in block mode) tells the agent to drop the attack inline with HTTP 403.

```
  [ Your app ] --(Odyssey agent)--> POST /api/sensor/http --> [ Odyssey shield :8000 ]
        ^                                                              |
        └────────────── 403 if the shield says "block" ───────────────┘   detections -> ledger, autopilot, SOC, UI
```

Nothing leaves your machine: the shield is a local service. The shield URL defaults to `http://127.0.0.1:8000`
(override with the `ODYSSEY_SHIELD_URL` environment variable).

## Three ways to connect (pick one)

| Approach | Agent | Blocks inline? | Change to your app |
|---|---|---|---|
| **In-process middleware** (recommended when you own the code) | `odyssey_asgi.py`, `odyssey_wsgi.py`, `odyssey_express.js` | Yes (enforce mode) | 3 lines |
| **Reverse proxy** (any stack: PHP, Java, .NET, a static site, a container) | `odyssey_proxy.py` | Yes (enforce mode) | None — point clients at the proxy |
| **Log tailing** (least invasive) | `tail_logs.py` | No (detect only) | None — read-only on the access log |

### ASGI — FastAPI, Starlette, Quart, Django ASGI
```python
from agent.odyssey_asgi import OdysseyShield
app.add_middleware(OdysseyShield, app_id="citypower-portal", name="CityPower Customer Portal",
                   org_id="PWR-01", mode="enforce")   # "monitor" to detect only
```

### WSGI — Flask, Django WSGI, Pyramid, Bottle
```python
from agent.odyssey_wsgi import OdysseyShield
app.wsgi_app = OdysseyShield(app.wsgi_app, app_id="billing-portal", name="Billing Portal", mode="enforce")
```

### Express / Node
```js
const { odysseyShield } = require('./agent/odyssey_express')
app.use(odysseyShield({ appId: 'ops-console', name: 'Ops Console', mode: 'enforce' }))
```

### Reverse proxy — any app you can't modify, on any stack
```bash
python agent/odyssey_proxy.py --listen 127.0.0.1:9000 --upstream http://127.0.0.1:3000 \
    --app legacy-billing --name "Legacy Billing" --org BFS-01 --mode enforce
```
Clients (and the red-team) use `http://127.0.0.1:9000`; the proxy forwards to the app with `X-Forwarded-For/-Host/-Proto`
set, the shield inspects every request on the way through, and in enforce mode an attack is answered 403 before it
reaches the app. Plain HTTP to the upstream; put the proxy behind your TLS terminator. An unreachable shield never stops
it forwarding (fail-open); an unreachable upstream answers 502.

### Access-log tailing — a server whose log you can read (Nginx, Apache, …)
```bash
python agent/tail_logs.py --app marketing-site --name "Marketing Site" \
    --log /var/log/nginx/access.log --format combined
```

## Monitor vs enforce
- **monitor** — requests are forwarded on a background thread (zero added latency) and attacks are recorded; Odyssey
  *proposes* a block for an analyst but never drops a request. Best for first rollout and for the log tailer.
- **enforce** — each request is forwarded synchronously and the shield's decision is honoured, so an attack is dropped
  inline with 403. Whether the shield blocks is governed by the app's mode **in Odyssey** (Live → *A real app,
  protected* → Monitor / Block), so you can turn blocking on and off from the dashboard without restarting your app.

All agents are **fail-open**: if the shield is unreachable, your app keeps serving. They announce the app when they
start and every 10 s after that (retrying every 2 s while the shield is down), and every forwarded request carries the
app's metadata, so the shield knows your app again the moment it restarts and the dashboard shows whether the agent is
alive.

## Protecting an app on another machine (tunnelling)
The agent only needs to reach the shield's HTTP endpoint. If your app runs elsewhere, expose the shield (or run the
agent where it can reach a tunnelled shield URL):

```bash
# Expose the Odyssey shield with a public HTTPS URL, then set ODYSSEY_SHIELD_URL to it in the app's environment.
cloudflared tunnel --url http://127.0.0.1:8000
#   or
ngrok http 8000
```

Keep the shield private unless you intend otherwise — it accepts request metadata from any agent that can reach it.

## Where the alerts go: your team's apps

The other direction. What Odyssey decides reaches the apps your team already watches, as one card per alert: an attack
blocked at a protected app, a C2 beacon, a new CVE taken in, a case opened, a decision waiting for a person. Channels
(`config/notify.json`): **Slack** and **Discord** incoming webhooks, **Microsoft Teams** (Workflows webhook, Adaptive
Card), **e-mail** over SMTP, and a plain **webhook** for any app of yours. The lab ships a destination you can run with
no account: the **Ops Console** (`target/console.py`, http://127.0.0.1:8090), a team console that renders the cards as
they arrive; `start_all.ps1` launches it.

Put real URLs and credentials in `config/notify.local.json` (git-ignored; same shape as `notify.json`, merged by channel
name) or in the environment, then **Live → Alerts delivered to your apps → Reload channels → Send test**:

```json
{"channels": [
  {"name": "slack",   "url": "https://hooks.slack.com/services/T000/B000/XXXX"},
  {"name": "discord", "url": "https://discord.com/api/webhooks/123/XXXX"},
  {"name": "teams",   "url": "https://prod-00.westus.logic.azure.com:443/workflows/XXXX"},
  {"name": "email",   "smtp_host": "smtp.gmail.com", "smtp_port": "587", "username": "you@gmail.com",
                      "password": "an app password", "from": "you@gmail.com", "to": "soc@example.org"}
]}
```

Environment variables work too: `ODYSSEY_SLACK_WEBHOOK`, `ODYSSEY_DISCORD_WEBHOOK`, `ODYSSEY_TEAMS_WEBHOOK`,
`ODYSSEY_SMTP_HOST` / `_PORT` / `_USER` / `_PASS` / `_FROM`, `ODYSSEY_ALERT_TO`, and `ODYSSEY_CONSOLE_WEBHOOK` for the
console.

What any app of yours receives on the plain webhook (what a Jira or Trello automation, Zapier, n8n or your own dashboard
would consume):

```json
{"source": "odyssey",
 "event": {"seq": 3051, "ts": "2026-11-01T00:12:09Z", "kind": "shield.detect.sqli",
           "subject": "citypower-portal:203.0.113.66", "provenance": "REAL"},
 "severity": "High", "title": "Blocked: SQL injection on citypower-portal from 203.0.113.66",
 "lines": ["CWE-89 · ATT&CK T1190 · REAL", "path /search", "evidence: q=' OR 1=1--"],
 "link": "http://127.0.0.1:5173/?view=live", "when_ist": "01 Nov 05:42:09 IST"}
```

Policy, in `config/notify.json`: which audit-trail kinds route, a severity floor (High), one card per (kind, subject)
per 10 minutes, and a cap of 20 a minute with one summary line for what was held back, so a red-team burst never floods
a real channel. Every delivery, success or failure, is a `notify.sent` / `notify.failed` event in the audit trail (the
destination host only, never the secret). A failing destination is backed off for a minute, so one dead URL never
delays the others. Links in the cards use `ODYSSEY_PUBLIC_URL`: tunnel the dashboard
(`cloudflared tunnel --url http://127.0.0.1:5173`) and set it, and a card on a phone opens the warning. The analysis
stays on this laptop; only the alerts you route leave it.

## Prove it works — red-team the shield
From the dashboard: **Live → Red-team the shield → Run all attacks**. Or via the API:
```bash
curl -s -X POST http://127.0.0.1:8000/api/redteam/run -H 'content-type: application/json' -d '{}' | jq
```
The runner fires real SQLi / XSS / traversal / command-injection / SSTI / SSRF / Log4Shell / scanning / brute-force
requests (plus benign controls) at the target over HTTP and reports the detection rate, block rate, precision and
time-to-detect. **For safety it only targets loopback or private (RFC-1918) addresses** — never a third party — and
every request is labelled as an exercise in the audit trail.
