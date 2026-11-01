"""Odyssey Shield agent as a reverse proxy - for any app, on any stack, without touching it.

Put this in front of a web application you cannot modify (PHP, Java, .NET, a static site, a container whose code you
do not own): clients call the proxy, the proxy forwards to the app, and the Odyssey shield inspects every request on
the way through. In enforce mode an attack is dropped with 403 before it reaches the app; in monitor mode it is
forwarded and recorded. This is the "middleware / reverse proxy" way of connecting a target.

    python agent/odyssey_proxy.py --listen 127.0.0.1:9000 --upstream http://127.0.0.1:3000 \
        --app legacy-billing --name "Legacy Billing" --org BFS-01 --mode enforce

Then use http://127.0.0.1:9000 in place of :3000 (and point the red-team at it). Standard-library only, threaded,
fail-open (an unreachable shield never stops the proxy forwarding; an unreachable upstream answers 502), plain HTTP to
the upstream (put the proxy behind your TLS terminator). It announces itself to the shield on start and every 10 s,
with the proxy's own address as the app's base URL, exactly like the in-process agents.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DEFAULT_SHIELD = os.environ.get("ODYSSEY_SHIELD_URL", "http://127.0.0.1:8000")
FORWARD_HEADERS = ("user-agent", "referer", "referrer", "cookie", "x-forwarded-for", "x-real-ip",
                   "content-type", "x-api-version", "x-odyssey-redteam", "x-odyssey-rt-case")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te",
              "trailers", "transfer-encoding", "upgrade"}
BODY_LIMIT = 64 * 1024
HEARTBEAT_S = 10.0   # re-announce the app this often: the shield's registry is in memory and forgets on a restart
RETRY_S = 2.0        # ...and this often while the shield is unreachable or still starting up
UPSTREAM_TIMEOUT_S = 30.0


def _iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Relay(urllib.request.HTTPErrorProcessor):
    """Every upstream answer, 3xx/4xx/5xx included, is a response to relay to the client, not an exception."""

    def http_response(self, request, response):
        return response

    https_response = http_response


class Proxy:
    """One protected upstream: build with the app's identity, then serve()."""

    def __init__(self, *, upstream: str, app_id: str, name: str | None = None, listen: str = "127.0.0.1:9000",
                 org_id: str | None = None, mode: str = "enforce", shield_url: str = DEFAULT_SHIELD):
        self.upstream = upstream.rstrip("/")
        self.listen, self.mode = listen, mode
        self.meta = {"app": app_id, "name": name or app_id, "base_url": f"http://{listen}", "mode": mode,
                     "org_id": org_id, "framework": "reverse-proxy"}
        self.ingest_url = shield_url.rstrip("/") + "/api/sensor/http"
        self.register_url = shield_url.rstrip("/") + "/api/sensor/register"
        self.opener = urllib.request.build_opener(_Relay)
        self._q: queue.Queue = queue.Queue(maxsize=2000)
        threading.Thread(target=self._drain, daemon=True, name="odyssey-shield-forward").start()

    # -- the shield (the same calls the in-process agents make) --------------------------------------------
    def _post(self, url: str, payload: dict, timeout: float) -> dict:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - local, fixed shield URL
            return json.loads(r.read().decode("utf-8") or "{}")

    def _heartbeat(self) -> None:
        while True:
            try:
                self._post(self.register_url, self.meta, 1.5)
                time.sleep(HEARTBEAT_S)
            except Exception:  # noqa: BLE001 - best-effort; every forwarded request carries the same metadata anyway
                time.sleep(RETRY_S)

    def _enqueue(self, event: dict) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            pass  # drop under flood rather than block the app

    def _drain(self) -> None:
        while True:
            event = self._q.get()
            try:
                self._post(self.ingest_url, event, 2.0)
            except Exception:  # noqa: BLE001 - fail open
                pass

    def _ingest_sync(self, event: dict) -> str:
        try:
            return self._post(self.ingest_url, event, 2.0).get("decision", "allow")
        except Exception:  # noqa: BLE001 - fail open: a down shield never affects the protected app
            return "allow"

    # -- the upstream ---------------------------------------------------------------------------------------
    def _forward(self, method: str, path_qs: str, headers: dict, body: bytes, client: str) -> tuple[int, list, bytes]:
        up = urlsplit(self.upstream)
        out = {k: v for k, v in headers.items() if k not in HOP_BY_HOP and k not in ("host", "content-length")}
        out["Host"] = up.netloc
        out["X-Forwarded-For"] = (headers["x-forwarded-for"] + ", " if headers.get("x-forwarded-for") else "") + client
        out["X-Forwarded-Host"] = headers.get("host", "")
        out["X-Forwarded-Proto"] = "http"
        req = urllib.request.Request(self.upstream + path_qs, data=body or None, method=method, headers=out)
        try:
            with self.opener.open(req, timeout=UPSTREAM_TIMEOUT_S) as r:  # noqa: S310 - the configured upstream
                data = r.read()
                keep = [(k, v) for k, v in r.headers.items() if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"]
                return r.status, keep, data
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            detail = str(getattr(exc, "reason", exc))[:160]
            return 502, [("Content-Type", "application/json")], json.dumps(
                {"error": "upstream unreachable", "by": "Odyssey shield proxy", "detail": detail}).encode()

    # -- the server -----------------------------------------------------------------------------------------
    def handler(self):
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            server_version, sys_version = "OdysseyShieldProxy/0.2", ""

            def log_message(self, *args):  # quiet; the shield keeps the record
                pass

            def _handle(self):
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k.lower(): v for k, v in self.headers.items()}
                path, _, query = self.path.partition("?")
                client = self.client_address[0]
                event = {**proxy.meta, "ts": _iso(), "method": self.command, "path": path, "query": query,
                         "body": body[:BODY_LIMIT].decode("utf-8", "replace"),
                         "source_ip": headers.get("x-forwarded-for", "").split(",")[0].strip() or client,
                         "host": headers.get("host"), "headers": {h: headers[h] for h in FORWARD_HEADERS if h in headers}}
                if proxy.mode == "enforce" and proxy._ingest_sync(event) == "block":
                    # The synchronous ingest already recorded this request; it never reaches the app.
                    payload = json.dumps({"error": "blocked", "by": "Odyssey HTTP shield",
                                          "message": "This request was identified as an attack and blocked."}).encode()
                    self._reply(403, [("Content-Type", "application/json"), ("X-Blocked-By", "odyssey-shield")], payload)
                    return
                status, out, data = proxy._forward(self.command, self.path, headers, body, client)
                self._reply(status, out, data)
                if proxy.mode != "enforce":
                    proxy._enqueue({**event, "status": status})

            def _reply(self, status: int, headers: list, data: bytes) -> None:
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle

        return Handler

    def serve(self) -> ThreadingHTTPServer:
        """Bind the listener (port 0 picks a free one) and return the server; call serve_forever() on it."""
        host, _, port = self.listen.rpartition(":")
        srv = ThreadingHTTPServer((host or "127.0.0.1", int(port or 0)), self.handler())
        srv.daemon_threads = True
        self.listen = f"{host or '127.0.0.1'}:{srv.server_port}"
        self.meta["base_url"] = f"http://{self.listen}"
        # announce only once the address is real: a listener asked for port 0 learns its port here
        threading.Thread(target=self._heartbeat, daemon=True, name="odyssey-shield-heartbeat").start()
        return srv


def main() -> None:
    ap = argparse.ArgumentParser(description="Put the Odyssey HTTP shield in front of any web app, as a reverse proxy.")
    ap.add_argument("--listen", default="127.0.0.1:9000", help="where clients connect (default 127.0.0.1:9000)")
    ap.add_argument("--upstream", required=True, help="the app to protect, e.g. http://127.0.0.1:3000")
    ap.add_argument("--app", required=True, help="the app's id in Odyssey")
    ap.add_argument("--name")
    ap.add_argument("--org", help="the owning organisation's id, e.g. PWR-01")
    ap.add_argument("--mode", default="enforce", choices=["monitor", "enforce"])
    ap.add_argument("--shield", default=DEFAULT_SHIELD)
    args = ap.parse_args()
    proxy = Proxy(upstream=args.upstream, app_id=args.app, name=args.name, listen=args.listen, org_id=args.org,
                  mode=args.mode, shield_url=args.shield)
    srv = proxy.serve()
    print(f"Odyssey shield proxy: http://{proxy.listen} -> {proxy.upstream} (app={args.app}, mode={args.mode}, "
          f"shield={args.shield})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
