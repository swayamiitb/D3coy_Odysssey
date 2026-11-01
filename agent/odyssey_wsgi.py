"""Odyssey Shield agent for WSGI apps (Flask, Django WSGI, Pyramid, Bottle, plain WSGI).

Wrap your WSGI app and every request is forwarded to Odyssey's HTTP shield for attack detection; in enforce mode a
request the shield blocks is dropped inline with 403.

    from agent.odyssey_wsgi import OdysseyShield
    app.wsgi_app = OdysseyShield(app.wsgi_app, app_id="billing-portal", name="Billing Portal",
                                 org_id="BFSI-02", mode="enforce")      # or mode="monitor" to only detect

Standard-library only, fail-open, and (in monitor mode) non-blocking - requests are forwarded on a background thread.
Set the shield URL with ODYSSEY_SHIELD_URL (default http://127.0.0.1:8000). See odyssey_asgi.py for the mode notes.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import queue
import threading
import time
import urllib.request

DEFAULT_SHIELD = os.environ.get("ODYSSEY_SHIELD_URL", "http://127.0.0.1:8000")
FORWARD_HEADERS = ("user-agent", "referer", "referrer", "cookie", "x-forwarded-for", "x-real-ip",
                   "content-type", "x-api-version", "x-odyssey-redteam", "x-odyssey-rt-case")
BODY_LIMIT = 64 * 1024
HEARTBEAT_S = 10.0   # re-announce the app this often: the shield's registry is in memory and forgets on a restart
RETRY_S = 2.0        # ...and this often while the shield is unreachable or still starting up


def _iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class OdysseyShield:
    def __init__(self, wsgi_app, *, app_id: str, name: str | None = None, base_url: str | None = None,
                 mode: str = "monitor", org_id: str | None = None, framework: str = "wsgi",
                 shield_url: str = DEFAULT_SHIELD, body_limit: int = BODY_LIMIT):
        self.app = wsgi_app
        self.meta = {"app": app_id, "name": name or app_id, "base_url": base_url, "mode": mode,
                     "org_id": org_id, "framework": framework}
        self.ingest_url = shield_url.rstrip("/") + "/api/sensor/http"
        self.register_url = shield_url.rstrip("/") + "/api/sensor/register"
        self.mode = mode
        self.body_limit = body_limit
        self._q: queue.Queue = queue.Queue(maxsize=2000)
        threading.Thread(target=self._drain, daemon=True, name="odyssey-shield-forward").start()
        threading.Thread(target=self._heartbeat, daemon=True, name="odyssey-shield-heartbeat").start()

    def __call__(self, environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = b""
        if length:
            body = environ["wsgi.input"].read(min(length, self.body_limit))
            # Replay the consumed bytes so the app still reads the full body.
            environ["wsgi.input"] = io.BytesIO(body + environ["wsgi.input"].read(max(0, length - self.body_limit)))

        headers = {}
        for k, v in environ.items():
            if k.startswith("HTTP_"):
                headers[k[5:].replace("_", "-").lower()] = v
        for k in ("CONTENT_TYPE",):
            if environ.get(k):
                headers[k.replace("_", "-").lower()] = environ[k]

        event = {
            **self.meta, "ts": _iso(), "method": environ.get("REQUEST_METHOD", "GET"),
            "path": environ.get("PATH_INFO", ""), "query": environ.get("QUERY_STRING", ""),
            "body": body.decode("utf-8", "replace"),
            "source_ip": headers.get("x-forwarded-for", "").split(",")[0].strip() or environ.get("REMOTE_ADDR", ""),
            "host": environ.get("HTTP_HOST"), "headers": {h: headers[h] for h in FORWARD_HEADERS if h in headers},
        }

        if self.mode == "enforce" and self._ingest_sync(event) == "block":
            # The synchronous ingest already recorded this request; do not re-send it.
            start_response("403 Forbidden", [("Content-Type", "application/json"), ("X-Blocked-By", "odyssey-shield")])
            return [json.dumps({"error": "blocked", "by": "Odyssey HTTP shield"}).encode()]

        captured = {}

        def capture(status, headers_out, exc_info=None):
            captured["status"] = int(status.split(" ", 1)[0])
            return start_response(status, headers_out, exc_info)

        result = self.app(environ, capture if self.mode != "enforce" else start_response)
        if self.mode != "enforce":
            event["status"] = captured.get("status")
            self._enqueue(event)
        return result

    def _enqueue(self, event):
        try:
            self._q.put_nowait(event)
        except queue.Full:
            pass

    def _drain(self):
        while True:
            event = self._q.get()
            try:
                self._post(self.ingest_url, event, 2.0)
            except Exception:  # noqa: BLE001
                pass

    def _heartbeat(self):
        """Announce the app now and every HEARTBEAT_S seconds (the shield's registry is in memory and forgets on a
        restart); retry every RETRY_S while the shield is unreachable. Best-effort, never touches the app."""
        while True:
            try:
                self._post(self.register_url, self.meta, 1.5)
                time.sleep(HEARTBEAT_S)
            except Exception:  # noqa: BLE001
                time.sleep(RETRY_S)

    def _ingest_sync(self, event) -> str:
        try:
            return self._post(self.ingest_url, event, 2.0).get("decision", "allow")
        except Exception:  # noqa: BLE001
            return "allow"

    def _post(self, url, payload, timeout) -> dict:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return json.loads(r.read().decode("utf-8") or "{}")
