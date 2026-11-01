"""Odyssey Shield agent by log tailing - for an app you cannot modify.

Point this at a web server's access log and it parses each new line and forwards the request to Odyssey's HTTP shield,
which detects attacks exactly as it does for the in-process agents. This is the least invasive integration: no code
change to the protected app, read-only on its log file. (Detection only - a tailer cannot block inline; use it in
monitor mode and act on the proposals, or add one of the in-process agents when you can.)

    python agent/tail_logs.py --app marketing-site --name "Marketing Site" \
        --log /var/log/nginx/access.log --format combined

Supports Nginx/Apache common & combined log formats and JSON access logs. Standard-library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path

CLF = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[^"]*"\s+'
    r'(?P<status>\d{3})\s+\S+(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?')


def parse(line: str, fmt: str, keys: dict) -> dict | None:
    line = line.strip()
    if not line:
        return None
    if fmt == "json":
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            return None
        uri = o.get(keys["uri"], "")
        return {"ip": o.get(keys["ip"], ""), "method": o.get(keys["method"], "GET"), "uri": uri,
                "status": int(o.get(keys["status"], 0) or 0), "referer": o.get(keys["referer"], ""),
                "ua": o.get(keys["ua"], "")}
    m = CLF.match(line)
    if not m:
        return None
    d = m.groupdict()
    return {"ip": d["ip"], "method": d["method"], "uri": d["uri"], "status": int(d["status"]),
            "referer": d.get("referer") or "", "ua": d.get("ua") or ""}


def to_event(rec: dict, meta: dict) -> dict:
    path, _, query = rec["uri"].partition("?")
    headers = {}
    if rec.get("ua"):
        headers["user-agent"] = rec["ua"]
    if rec.get("referer"):
        headers["referer"] = rec["referer"]
    return {**meta, "ts": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": rec["method"], "path": path, "query": query, "status": rec["status"],
            "source_ip": rec["ip"], "headers": headers}


def post(url: str, payload: dict, timeout: float = 2.0) -> bool:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=timeout).read()  # noqa: S310
        return True
    except Exception:  # noqa: BLE001 - fail open
        return False


def heartbeat(url: str, meta: dict) -> None:
    """Announce the app now and every 10 s (the shield's registry is in memory and forgets on a restart); retry every
    2 s while the shield is unreachable."""
    while True:
        time.sleep(10.0 if post(url, meta) else 2.0)


def tail(path: Path, from_start: bool):
    with path.open("r", encoding="utf-8", errors="replace") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.4)


def main() -> None:
    ap = argparse.ArgumentParser(description="Forward a web server access log to the Odyssey HTTP shield.")
    ap.add_argument("--app", required=True)
    ap.add_argument("--name")
    ap.add_argument("--org")
    ap.add_argument("--log", required=True, type=Path)
    ap.add_argument("--shield", default=os.environ.get("ODYSSEY_SHIELD_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--format", default="combined", choices=["common", "combined", "json"])
    ap.add_argument("--from-start", action="store_true", help="read the whole file, not just new lines")
    ap.add_argument("--json-keys", default="remote_addr,request_method,request_uri,status,http_referer,http_user_agent",
                    help="ip,method,uri,status,referer,ua field names for --format json")
    args = ap.parse_args()

    k = args.json_keys.split(",")
    keys = dict(zip(("ip", "method", "uri", "status", "referer", "ua"), k))
    meta = {"app": args.app, "name": args.name or args.app, "org_id": args.org, "mode": "monitor",
            "framework": "log-tail", "base_url": None}
    ingest = args.shield.rstrip("/") + "/api/sensor/http"
    threading.Thread(target=heartbeat, args=(args.shield.rstrip("/") + "/api/sensor/register", meta), daemon=True).start()
    print(f"Odyssey log tailer: {args.log} -> {ingest} (app={args.app}, format={args.format})", flush=True)

    n = 0
    for line in tail(args.log, args.from_start):
        rec = parse(line, args.format, keys)
        if rec:
            post(ingest, to_event(rec, meta))
            n += 1
            if n % 50 == 0:
                print(f"  forwarded {n} requests", flush=True)


if __name__ == "__main__":
    main()
