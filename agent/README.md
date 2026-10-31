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
| **In-process middleware** (recommended) | `odyssey_asgi.py`, `odyssey_wsgi.py`, `odyssey_express.js` | Yes (enforce mode) | 3 lines |
| **Log tailing** (least invasive) | `tail_logs.py` | No (detect only) | None — read-only on the access log |
| **Reverse proxy** | point the log tailer at the proxy's access log, or add the Express agent to a Node proxy | Via the proxy | None to the app |

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

### Access-log tailing — any server you can't modify (Nginx, Apache, …)
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

## Prove it works — red-team the shield
From the dashboard: **Live → Red-team the shield → Run all attacks**. Or via the API:
```bash
curl -s -X POST http://127.0.0.1:8000/api/redteam/run -H 'content-type: application/json' -d '{}' | jq
```
The runner fires real SQLi / XSS / traversal / command-injection / SSTI / SSRF / Log4Shell / scanning / brute-force
requests (plus benign controls) at the target over HTTP and reports the detection rate, block rate, precision and
time-to-detect. **For safety it only targets loopback or private (RFC-1918) addresses** — never a third party — and
every request is labelled as an exercise in the audit trail.
