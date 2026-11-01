"""The reverse-proxy agent: any app, on any stack, with no change to it. Requests flow through the proxy to the
upstream and the shield sees every one; in enforce mode an attack is dropped with 403 before it reaches the app; the
proxy fails open when the shield is down and answers 502 when the upstream is."""

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

from agent.odyssey_proxy import Proxy


class Upstream:
    """The app behind the proxy: echoes what it received, with a header of its own; /missing is a 404."""

    def __init__(self):
        self.seen: list[dict] = []
        up = self

        class H(BaseHTTPRequestHandler):
            def _do(self):
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                up.seen.append({"method": self.command, "path": self.path, "body": body, "headers": dict(self.headers)})
                status = 404 if self.path.startswith("/missing") else 200
                out = json.dumps({"path": self.path, "method": self.command, "body": body.decode()}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Upstream", "yes")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = _do

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"


class FakeShield:
    """Answers the agents' two calls: registrations are recorded; an event whose query holds a SQLi marker is 'block'."""

    def __init__(self):
        self.events: list[dict] = []
        self.registrations: list[dict] = []
        sh = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
                if self.path.endswith("/register"):
                    sh.registrations.append(body)
                    out = b"{}"
                else:
                    sh.events.append(body)
                    # the proxy passes the query raw, as the other agents do; the real shield decodes before matching
                    attack = "OR 1=1" in unquote(body.get("query", ""))
                    out = json.dumps({"decision": "block" if attack else "allow"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"


def _run(proxy: Proxy) -> ThreadingHTTPServer:
    srv = proxy.serve()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _get(url: str, headers: dict | None = None, data: bytes | None = None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    return urllib.request.urlopen(req, timeout=5)


@pytest.fixture
def lab():
    up, sh = Upstream(), FakeShield()
    proxy = Proxy(upstream=up.url, app_id="legacy-billing", name="Legacy Billing", listen="127.0.0.1:0", org_id="BFS-01",
                  mode="enforce", shield_url=sh.url)
    srv = _run(proxy)
    yield up, sh, proxy, f"http://{proxy.listen}"
    for s in (srv, up.srv, sh.srv):
        s.shutdown()


def test_requests_flow_through_and_the_shield_sees_each_one(lab):
    up, sh, proxy, base = lab
    with _get(f"{base}/search?q=lamp", headers={"User-Agent": "demo-browser"}) as r:
        assert r.status == 200 and r.headers["X-Upstream"] == "yes"
        echoed = json.loads(r.read())
    assert echoed == {"path": "/search?q=lamp", "method": "GET", "body": ""}
    assert up.seen[-1]["headers"]["X-Forwarded-For"] == "127.0.0.1"
    ev = sh.events[-1]
    assert (ev["app"], ev["name"], ev["framework"], ev["org_id"]) == ("legacy-billing", "Legacy Billing", "reverse-proxy", "BFS-01")
    assert (ev["method"], ev["path"], ev["query"], ev["source_ip"]) == ("GET", "/search", "q=lamp", "127.0.0.1")
    assert ev["headers"]["user-agent"] == "demo-browser" and "status" not in ev  # enforce decides before the app answers


def test_an_attack_is_dropped_before_it_reaches_the_app(lab):
    up, sh, proxy, base = lab
    n = len(up.seen)
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{base}/search?q=%27%20OR%201%3D1--", headers={"X-Forwarded-For": "203.0.113.66"})
    assert exc.value.code == 403 and exc.value.headers["X-Blocked-By"] == "odyssey-shield"
    assert json.loads(exc.value.read())["by"] == "Odyssey HTTP shield"
    assert len(up.seen) == n, "the blocked request must never reach the upstream"
    assert sh.events[-1]["source_ip"] == "203.0.113.66"  # the client behind a load balancer, not the balancer


def test_bodies_and_error_statuses_pass_through(lab):
    up, sh, proxy, base = lab
    with _get(f"{base}/feedback", headers={"Content-Type": "application/x-www-form-urlencoded"}, data=b"msg=hello") as r:
        assert json.loads(r.read())["body"] == "msg=hello"
    assert up.seen[-1]["method"] == "POST" and up.seen[-1]["body"] == b"msg=hello"
    assert sh.events[-1]["body"] == "msg=hello"
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{base}/missing")
    assert exc.value.code == 404 and exc.value.headers["X-Upstream"] == "yes"


def test_monitor_mode_forwards_everything_and_records_the_outcome():
    up, sh = Upstream(), FakeShield()
    proxy = Proxy(upstream=up.url, app_id="m", listen="127.0.0.1:0", mode="monitor", shield_url=sh.url)
    srv = _run(proxy)
    try:
        with _get(f"http://{proxy.listen}/search?q=%27%20OR%201%3D1--") as r:
            assert r.status == 200  # monitor: never drops
        for _ in range(40):
            if any(e.get("status") == 200 for e in sh.events):
                break
            time.sleep(0.05)
        assert any(e.get("status") == 200 and e["query"] == "q=%27%20OR%201%3D1--" for e in sh.events), sh.events
    finally:
        for s in (srv, up.srv, sh.srv):
            s.shutdown()


def test_announces_itself_with_its_own_address(lab):
    up, sh, proxy, base = lab
    for _ in range(60):
        if sh.registrations:
            break
        time.sleep(0.05)
    reg = sh.registrations[-1]
    assert reg["base_url"] == base and reg["framework"] == "reverse-proxy" and reg["mode"] == "enforce"


def test_fails_open_when_the_shield_is_down_and_502_when_the_upstream_is():
    up = Upstream()
    open_proxy = Proxy(upstream=up.url, app_id="x", listen="127.0.0.1:0", mode="enforce", shield_url="http://127.0.0.1:9")
    srv1 = _run(open_proxy)
    dead = Proxy(upstream="http://127.0.0.1:9", app_id="y", listen="127.0.0.1:0", mode="monitor", shield_url="http://127.0.0.1:9")
    srv2 = _run(dead)
    try:
        with _get(f"http://{open_proxy.listen}/search?q=lamp") as r:
            assert r.status == 200, "an unreachable shield must never stop the app serving"
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(f"http://{dead.listen}/")
        assert exc.value.code == 502 and json.loads(exc.value.read())["error"] == "upstream unreachable"
    finally:
        for s in (srv1, srv2, up.srv):
            s.shutdown()
