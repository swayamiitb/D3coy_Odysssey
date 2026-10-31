"""Odyssey Shield agent for ASGI apps (FastAPI, Starlette, Quart, Django ASGI).

Drop this in front of your app and every request's metadata is forwarded to Odyssey's HTTP shield, which detects web
attacks (SQLi, XSS, traversal, command injection, scanning, brute force, ...) and - in block mode - tells the agent to
drop the offending request. This is how you connect a *real* web application to Odyssey.

    from agent.odyssey_asgi import OdysseyShield
    app.add_middleware(OdysseyShield, app_id="citypower-portal", name="CityPower Customer Portal",
                       org_id="PWR-01", mode="enforce")          # "monitor" = detect only; "enforce" = drop when told

Modes:
  - "monitor": every request is forwarded to the shield on a background thread (zero added latency) and recorded;
    the shield never drops a request, it proposes a block for an analyst. Best when you only want visibility.
  - "enforce": every request is forwarded synchronously and the shield's decision is honoured, so a request the
    shield blocks is dropped inline with 403. Whether the shield blocks is governed by the app's mode *in Odyssey*
    (Live -> HTTP shield -> Monitor/Block), so you can turn blocking on and off from the dashboard without a restart.

Design: standard-library only (no extra dependency in your app), non-blocking in monitor mode, and fail-open (if the
shield is unreachable your app keeps serving). Configure the shield URL with ODYSSEY_SHIELD_URL (default
http://127.0.0.1:8000).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import queue
import threading
import urllib.error
import urllib.request

DEFAULT_SHIELD = os.environ.get("ODYSSEY_SHIELD_URL", "http://127.0.0.1:8000")
FORWARD_HEADERS = ("user-agent", "referer", "referrer", "cookie", "x-forwarded-for", "x-real-ip",
                   "content-type", "x-api-version", "x-odyssey-redteam", "x-odyssey-rt-case")
BODY_LIMIT = 64 * 1024


def _iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class OdysseyShield:
    def __init__(self, app, *, app_id: str, name: str | None = None, base_url: str | None = None,
                 mode: str = "monitor", org_id: str | None = None, framework: str = "asgi",
                 shield_url: str = DEFAULT_SHIELD, body_limit: int = BODY_LIMIT):
        self.app = app
        self.meta = {"app": app_id, "name": name or app_id, "base_url": base_url, "mode": mode,
                     "org_id": org_id, "framework": framework}
        self.ingest_url = shield_url.rstrip("/") + "/api/sensor/http"
        self.register_url = shield_url.rstrip("/") + "/api/sensor/register"
        self.mode = mode
        self.body_limit = body_limit
        self._q: queue.Queue = queue.Queue(maxsize=2000)
        self._worker = threading.Thread(target=self._drain, daemon=True, name="odyssey-shield-forward")
        self._worker.start()
        self._register()

    # -- registration --------------------------------------------------------------------------------------
    def _register(self) -> None:
        try:
            self._post(self.register_url, self.meta, timeout=1.5)
        except Exception:  # noqa: BLE001 - registration is best-effort; the first event registers the app anyway
            pass

    # -- ASGI entrypoint -----------------------------------------------------------------------------------
    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        client = scope.get("client") or ("", 0)
        body, receive = await self._buffer_body(receive)
        event = {
            **self.meta, "ts": _iso(), "method": scope.get("method", "GET"),
            "path": scope.get("path", ""), "query": (scope.get("query_string", b"").decode("latin-1")),
            "body": body, "source_ip": headers.get("x-forwarded-for", "").split(",")[0].strip() or client[0],
            "host": headers.get("host"), "headers": {h: headers[h] for h in FORWARD_HEADERS if h in headers},
        }

        if self.mode == "enforce":
            decision = self._ingest_sync(event)
            if decision == "block":
                return await self._forbidden(send, event)
            await self.app(scope, receive, send)  # already ingested synchronously above
            return

        status_holder = {}

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                status_holder["status"] = message.get("status")
            await send(message)

        await self.app(scope, receive, send_wrapper)
        event["status"] = status_holder.get("status")
        self._enqueue(event)

    async def _buffer_body(self, receive):
        """Read and buffer the request body, then hand back a `receive` that replays it so the app is unaffected."""
        messages, chunks, size, more = [], [], 0, True
        while more:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                if size < self.body_limit:
                    chunks.append(chunk[: self.body_limit - size])
                size += len(chunk)
                more = message.get("more_body", False)
            else:
                more = False
        buffered = b"".join(chunks).decode("utf-8", "replace")
        pending = list(messages)

        async def replay():
            return pending.pop(0) if pending else {"type": "http.disconnect"}

        return buffered, replay

    async def _forbidden(self, send, event):
        # The synchronous ingest that returned "block" already recorded this request; do not re-send it.
        payload = json.dumps({"error": "blocked", "by": "Odyssey HTTP shield",
                              "message": "This request was identified as an attack and blocked."}).encode()
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"application/json"), (b"x-blocked-by", b"odyssey-shield")]})
        await send({"type": "http.response.body", "body": payload})

    # -- forwarding ----------------------------------------------------------------------------------------
    def _enqueue(self, event: dict) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            pass  # drop under flood rather than block the app

    def _drain(self) -> None:
        while True:
            event = self._q.get()
            try:
                self._post(self.ingest_url, event, timeout=2.0)
            except Exception:  # noqa: BLE001 - fail open: a down shield never affects the protected app
                pass

    def _ingest_sync(self, event: dict) -> str:
        try:
            resp = self._post(self.ingest_url, event, timeout=2.0)
            return resp.get("decision", "allow")
        except Exception:  # noqa: BLE001
            return "allow"

    def _post(self, url: str, payload: dict, timeout: float) -> dict:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - local, fixed shield URL
            return json.loads(r.read().decode("utf-8") or "{}")
