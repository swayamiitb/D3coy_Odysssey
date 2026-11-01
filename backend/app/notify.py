"""Odyssey Channels: the alerts leave the laptop, to the apps your team already uses.

A tap on the hash-chained ledger turns selected events (an attack blocked at a protected app, a C2 beacon, a new CVE
taken in, a case opened, an escalation, a decision waiting for a person) into one alert card each and delivers it to
every configured channel: Slack, Discord, Microsoft Teams, a plain webhook (any app of yours, including the lab's Ops
Console in target/console.py), or e-mail over SMTP. Each delivery, success or failure, is itself a ledger event, so
"who was told what, when" is auditable like everything else; the event carries the destination host, never the secret.

Policy (config/notify.json; secrets in config/notify.local.json or the environment): which kinds route, a severity
floor, one alert per (kind, subject) per window, and a per-minute cap with a summary of what was held back, so a
red-team burst or a noisy detector never floods a real channel. A destination that fails is backed off for a minute,
so one dead URL never delays the others. Nothing historical is replayed: the tap starts at the ledger's head when the
API starts. The analysis stays on this laptop; only the alerts you route leave it.

Adding a channel type is one formatter and one entry in SENDERS.
"""

from __future__ import annotations

import collections
import datetime as dt
import fnmatch
import json
import os
import re
import smtplib
import sqlite3
import threading
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlsplit

import httpx

from .engine.ledger import Ledger

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "notify.json"
LOCAL = ROOT / "config" / "notify.local.json"
POLL_S = 1.0
TIMEOUT_S = 6.0
BACKOFF_S = 60.0
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
RANK = {"Watch": 0, "Medium": 1, "High": 2, "Critical": 3, "Compromise": 4}
COLOUR = {"Compromise": "7356bf", "Critical": "e11900", "High": "ff6937", "Medium": "ffc043", "Watch": "a6a6a6"}  # the UI's tiers
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}")


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _when(ts: str | None) -> str:
    try:
        return dt.datetime.fromisoformat((ts or "").replace("Z", "+00:00")).astimezone(IST).strftime("%d %b %H:%M:%S IST")
    except ValueError:
        return ts or ""


def _interp(value, env: dict):
    if isinstance(value, str):
        return _VAR.sub(lambda m: env.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [_interp(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _interp(v, env) for k, v in value.items()}
    return value


def load_config(path: Path = CONFIG, local: Path = LOCAL, env: dict | None = None) -> dict:
    """config/notify.json with config/notify.local.json merged over it (channels by name), then ${VAR} resolved."""
    env = dict(os.environ if env is None else env)
    cfg = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"channels": [], "routing": {}}
    if local.exists():
        over = json.loads(local.read_text(encoding="utf-8"))
        by = {c["name"]: c for c in cfg.get("channels", []) if c.get("name")}
        for c in over.get("channels", []):
            if c.get("name"):
                by.setdefault(c["name"], {"name": c["name"]}).update(c)
        cfg["channels"] = list(by.values())
        if "routing" in over:
            cfg["routing"] = {**cfg.get("routing", {}), **over["routing"]}
        if "public_url" in over:
            cfg["public_url"] = over["public_url"]
    return _interp(cfg, env)


# ---------------------------------------------------------------- from a ledger event to one card
def _graph_link(public_url: str, node: str | None, org_id: str | None = None) -> str:
    """Intel -> Graph, opened on an entity's card when its node id is known (product:fortios, cve:CVE-..., indicator:...,
    actor:G0007). Asset nodes (asset:<ORG>-A001) exist only in their organisation's graph, so they carry focus=<ORG>."""
    link = f"{public_url}/?view=intel&tab=graph"
    if not node:
        return link
    link += f"&node={quote(node, safe='')}"
    m = re.match(r"asset:([A-Za-z]+-\d+)-", node)
    org = org_id or (m.group(1) if m else None)
    return link + (f"&focus={quote(org, safe='')}" if org else "")


def card(event: dict, public_url: str) -> dict | None:
    """One alert card from a ledger event, or None when the kind is not something a person should be told about."""
    kind, p = event["kind"], event.get("payload") or {}
    if isinstance(p, str):
        p = json.loads(p)
    subject = event.get("subject", "")
    link = f"{public_url}/?view=live"
    lines: list[str] = []
    if kind.startswith("shield.detect."):
        verb = "Blocked" if p.get("decision") == "block" else "Detected"
        title = f"{verb}: {p.get('category', kind.split('.')[-1])} on {p.get('app', '?')} from {p.get('source_ip', '?')}"
        sev = p.get("severity") if p.get("severity") in RANK else "High"
        lines = [f"{p.get('cwe', '')} · ATT&CK {p.get('attack', '')} · {event.get('provenance', '')}",
                 f"path {p.get('path', '')}", f"evidence: {p.get('evidence', '')}"]
        if p.get("success"):
            lines.append("the request got a 2xx: likely successful; a SOC incident case was opened")
        if p.get("redteam"):
            lines.append(f"red-team exercise {p['redteam']} (labelled in the audit trail)")
    elif kind in ("shield.block", "shield.unblock"):
        sev = "High"
        title = (f"Analyst {'blocked' if kind == 'shield.block' else 'unblocked'} {p.get('ip', subject)}"
                 + (f": {p['reason']}" if p.get("reason") else ""))
    elif kind.startswith("live.detect."):
        what = kind.split(".")[-1]
        sev = {"beacon": "Compromise", "surge": "High", "anomaly": "High"}.get(what, "High")
        title = p.get("title") or f"{what} detected on {subject}"
        if p.get("seconds_to_detect") is not None:
            lines.append(f"time to detect {p['seconds_to_detect']} s")
        if p.get("drill"):
            lines.append(f"drill {p['drill']} (simulated traffic, labelled DRILL)")
    elif kind == "live.intake":
        sev = p.get("worst") if p.get("worst") in RANK else "High"
        title = (f"New CVE {p.get('cve', subject)} ({p.get('product') or 'product named in text'}): "
                 f"{p.get('exposed', 0)} exposed asset(s) at {len(p.get('orgs') or [])} organisation(s)")
        lines = [p.get("action", "")]
        if p.get("minutes_since_publication") is not None:
            lines.append(f"{p['minutes_since_publication']} min after publication")
    elif kind == "live.rescore":
        sev = "Compromise"
        title = p.get("title") or f"warnings on {p.get('asset', subject)} re-scored to suspected compromise"
        lines = [f"{c['cve']}: {c['from']} -> {c['to']} (P={c['p']:.0%})" for c in (p.get("changed") or [])[:4]]
        link = f"{public_url}/?view=now"
    elif kind == "live.drill.end":
        sev, d = "High", p.get("detected") or {}
        title = f"Drill {subject} {p.get('status', '')}: {len(d)} detection(s) in {p.get('seconds', '?')} s"
        lines = [f"{k} at +{v.get('seconds')} s" for k, v in d.items()] + ([f"case {p['case']}"] if p.get("case") else [])
    elif kind == "auto.notify":
        sev = p.get("tier") if p.get("tier") in RANK else "High"
        title = p.get("title") or f"Notice to {p.get('org_id', '')}"
        if p.get("recipients"):
            lines.append(f"to {', '.join(p['recipients'])} ({p.get('lang', 'en')})")
        if p.get("basis"):
            lines.append(f"basis: {p['basis']}")
        if p.get("alert"):
            link = f"{public_url}/?alert={p['alert']}"
    elif kind == "auto.escalate":
        sev, title = "Compromise", p.get("title") or f"Escalated: {subject}"
        lines = [f"to {', '.join(p.get('recipients') or [])}"]
        if p.get("alert"):
            link = f"{public_url}/?alert={p['alert']}"
    elif kind == "auto.case_opened":
        sev = p.get("severity") if p.get("severity") in RANK else "Critical"
        title = f"Case {subject} opened: {p.get('title', '')}"
        lines = [f"owner {p.get('owner') or 'unassigned'} · due in {p.get('due_hours', '?')} h · {p.get('org_id') or ''}"]
        link = f"{public_url}/?view=soc&tab=cases"
    elif kind == "auto.proposed":
        sev, title = "High", f"Decision needed: {p.get('title', subject)}"
        if p.get("orgs"):
            lines.append(f"{p.get('count', 1)} action(s) for {', '.join(p['orgs'])}")
        if p.get("basis"):
            lines.append(f"basis: {p['basis']}")
        lines.append("Odyssey proposes; a person approves")
        link = f"{public_url}/?view=soc&tab=overview"
    elif kind in ("auto.hunt", "auto.report"):
        sev, title = "Critical", p.get("title") or kind
        if p.get("alert"):
            link = f"{public_url}/?alert={p['alert']}"
    # kinds the graph, indicator, brand-monitoring and attack-surface engines write (values arrive defanged)
    elif kind == "watch.fired":
        sev = p.get("severity") if p.get("severity") in RANK else "High"
        title = f"Watchlist: {p.get('label') or 'rule'} fired on {p.get('target', subject)}"
        lines = [p.get("reason", "")]
        link = _graph_link(public_url, p.get("target") or subject, p.get("org_id"))
    elif kind == "ioc.match":
        sev = p.get("severity") if p.get("severity") in RANK else "High"
        title = f"Indicator matched: {p.get('type', 'indicator')} {p.get('value', subject)} seen in {p.get('where', 'our telemetry')}"
        lines = [f"source: {p['source']}" if p.get("source") else ""]
        link = _graph_link(public_url, f"indicator:{p['value']}" if p.get("value") else None)
    elif kind == "brand.hit":
        try:
            score = float(p.get("score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        sev = "Critical" if score >= 90 else "High"  # the engine emits at score >= 70; 90 and above is a Critical hit
        title = (f"Brand hit for {p.get('org_id') or 'an organisation'}: {p.get('kind') or 'mention'} on "
                 f"{p.get('source') or '?'} names {p.get('term', '')} (score {score:g})")
        lines = [p.get("value", "")]
        link = f"{public_url}/?view=orgs&org={p['org_id']}" if p.get("org_id") else f"{public_url}/?view=orgs"
    elif kind == "surface.finding":
        sev = p.get("severity") if p.get("severity") in RANK else "High"
        title = f"Attack-surface finding on {p.get('host', subject)}: {p.get('check', '')}"
        lines = [p.get("cwe", ""), "consented attack-surface scan"]
        link = f"{public_url}/?view=intel&tab=graph"
    else:
        return None
    return {"seq": event.get("seq"), "ts": event.get("ts"), "kind": kind, "subject": subject, "severity": sev,
            "provenance": event.get("provenance"), "title": title[:300], "lines": [x for x in lines if x][:6], "link": link}


# ---------------------------------------------------------------- one card, five shapes
def fmt_slack(c: dict) -> dict:
    body = "\n".join(f"• {x}" for x in c["lines"])
    return {"text": f"[Odyssey] {c['severity']}: {c['title']}",
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{c['severity']}* · {c['title']}" + (f"\n{body}" if body else "")}},
                       {"type": "context", "elements": [{"type": "mrkdwn",
                                                         "text": f"{c['kind']} · {_when(c['ts'])} · <{c['link']}|open in Odyssey>"}]}]}


def fmt_discord(c: dict) -> dict:
    embed = {"title": f"{c['severity']}: {c['title']}"[:256], "url": c["link"], "color": int(COLOUR.get(c["severity"], "a6a6a6"), 16),
             "footer": {"text": f"{c['kind']} · {_when(c['ts'])} · {c.get('provenance') or ''}"}}
    if c["lines"]:
        embed["description"] = "\n".join(c["lines"])[:2000]
    return {"username": "Odyssey", "embeds": [embed]}


def fmt_teams(c: dict) -> dict:
    body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True, "text": f"{c['severity']}: {c['title']}"}]
    body += [{"type": "TextBlock", "wrap": True, "spacing": "Small", "text": x} for x in c["lines"]]
    body.append({"type": "TextBlock", "isSubtle": True, "size": "Small", "wrap": True, "text": f"{c['kind']} · {_when(c['ts'])}"})
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
        "body": body, "actions": [{"type": "Action.OpenUrl", "title": "Open in Odyssey", "url": c["link"]}]}}]}


def fmt_webhook(c: dict) -> dict:
    return {"source": "odyssey", "event": {k: c.get(k) for k in ("seq", "ts", "kind", "subject", "provenance")},
            "severity": c["severity"], "title": c["title"], "lines": c["lines"], "link": c["link"], "when_ist": _when(c["ts"])}


def fmt_email(c: dict) -> tuple[str, str]:
    body = "\n".join([c["title"], "", *(f"- {x}" for x in c["lines"]), "", f"{c['kind']} · {_when(c['ts'])}", c["link"], "",
                      "Sent by Odyssey, the national cyber threat early-warning system running on this laptop."])
    return f"[Odyssey] {c['severity']}: {c['title']}"[:200], body


def _send_http(url: str, body: dict) -> None:
    httpx.post(url, json=body, timeout=TIMEOUT_S, headers={"User-Agent": "Odyssey-EWS/0.2"}).raise_for_status()


def _send_email(ch: dict, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, ch.get("from") or ch.get("username") or "odyssey@localhost", ch["to"]
    msg.set_content(body)
    port = int(ch.get("smtp_port") or 587)
    smtp = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
    with smtp(ch["smtp_host"], port, timeout=TIMEOUT_S) as s:
        if port != 465:
            s.starttls()
        if ch.get("username"):
            s.login(ch["username"], ch.get("password") or "")
        s.send_message(msg)


SENDERS: dict[str, Callable[[dict, dict], None]] = {
    "slack": lambda ch, c: _send_http(ch["url"], fmt_slack(c)),
    "discord": lambda ch, c: _send_http(ch["url"], fmt_discord(c)),
    "teams": lambda ch, c: _send_http(ch["url"], fmt_teams(c)),
    "webhook": lambda ch, c: _send_http(ch["url"], fmt_webhook(c)),
    "email": lambda ch, c: _send_email(ch, *fmt_email(c)),
}


def configured(ch: dict) -> bool:
    if ch.get("type") == "email":
        return bool(ch.get("smtp_host") and ch.get("to"))
    return str(ch.get("url") or "").startswith(("http://", "https://"))


def destination(ch: dict) -> str:
    """Where a channel points, without its secret: a webhook's path holds the token, so only the host is shown unless
    the destination is this machine."""
    if ch.get("type") == "email":
        return f"{ch.get('smtp_host') or '?'} -> {ch.get('to') or '?'}"
    u = urlsplit(str(ch.get("url") or ""))
    if not u.netloc:
        return "not configured"
    local = u.hostname in ("127.0.0.1", "localhost", "::1")
    return f"{u.netloc}{u.path if local else '/…'}"


# ---------------------------------------------------------------- the engine
class Notifier:
    def __init__(self, connect: Callable[[], sqlite3.Connection], config_path: Path = CONFIG, local_path: Path = LOCAL,
                 env: dict | None = None):
        self.connect, self.paths, self.env = connect, (config_path, local_path), env
        self.lock = threading.RLock()
        self.started = dt.datetime.now(dt.timezone.utc)
        self.cfg: dict = {}
        self.channels: dict[str, dict] = {}
        self.state: dict[str, dict] = {}
        self.recent: collections.deque = collections.deque(maxlen=60)
        self.seen: dict[tuple, float] = {}
        self.window, self.sent_in_window, self.held_in_window = int(time.time() // 60), 0, 0
        self.held, self.suppressed_dupes = 0, 0
        self.cursor = self._head()  # nothing before now is replayed
        self._thread: threading.Thread | None = None
        self.reload()

    def _head(self) -> int:
        conn = self.connect()
        try:
            return conn.execute("SELECT COALESCE(MAX(seq), 0) FROM ledger").fetchone()[0]
        finally:
            conn.close()

    # ---- configuration
    def reload(self) -> dict:
        cfg = load_config(*self.paths, env=self.env)
        conn = self.connect()
        try:  # a mute set from the dashboard outlives an API restart (meta); a rebuild resets it to the config
            muted = dict(conn.execute("SELECT key, value FROM meta WHERE key LIKE 'notify.enabled.%'").fetchall())
        except sqlite3.OperationalError:
            muted = {}
        finally:
            conn.close()
        with self.lock:
            self.cfg = cfg
            self.channels = {c["name"]: c for c in cfg.get("channels", []) if c.get("name") and c.get("type") in SENDERS}
            for name, ch in self.channels.items():
                self.state.setdefault(name, {"status": "idle", "sent": 0, "failed": 0, "last_ok": None, "last_error": None, "skip_until": 0.0})
                if f"notify.enabled.{name}" in muted:
                    ch["enabled"] = muted[f"notify.enabled.{name}"] == "1"
        return self.status()

    def set_enabled(self, name: str, on: bool) -> dict:
        with self.lock:
            if name not in self.channels:
                raise KeyError(name)
            self.channels[name]["enabled"] = on
        conn = self.connect()
        try:
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (f"notify.enabled.{name}", "1" if on else "0"))
            conn.commit()
        finally:
            conn.close()
        return self._view(name)

    # ---- routing: the tap
    def _routes(self, kind: str, sev: str) -> bool:
        r = self.cfg.get("routing", {})
        if kind.startswith("notify."):
            return False
        if not any(fnmatch.fnmatch(kind, pat) for pat in r.get("kinds", [])):
            return False
        return RANK.get(sev, 0) >= RANK.get(r.get("min_severity", "High"), 2)

    def _roll_window(self, now: float) -> None:
        window = int(now // 60)
        if window == self.window:
            return
        if self.held_in_window:
            cap = int(self.cfg.get("routing", {}).get("per_minute_cap", 20))
            self.deliver({"seq": None, "ts": _iso(dt.datetime.now(dt.timezone.utc)), "kind": "notify.summary", "subject": "cap",
                          "severity": "High", "provenance": "AUTO",
                          "title": f"{self.held_in_window} more alert(s) in the last minute were held back (cap {cap} a minute)",
                          "lines": ["every one of them is on the dashboard and in the audit trail"],
                          "link": f"{self.cfg.get('public_url') or 'http://127.0.0.1:5173'}/?view=live"}, summary=True)
        self.window, self.sent_in_window, self.held_in_window = window, 0, 0

    def poll_once(self, now: float | None = None) -> int:
        """Deliver every routable ledger event since the cursor. Returns how many cards reached at least one channel."""
        now = time.time() if now is None else now
        self._roll_window(now)
        conn = self.connect()
        try:
            rows = conn.execute("SELECT seq, ts, kind, subject, source, provenance, payload FROM ledger WHERE seq > ? ORDER BY seq",
                                (self.cursor,)).fetchall()
        finally:
            conn.close()
        r = self.cfg.get("routing", {})
        dedupe_s, cap = 60 * float(r.get("dedupe_minutes", 10)), int(r.get("per_minute_cap", 20))
        delivered = 0
        for row in rows:
            self.cursor = row[0]  # advance first: a bad event is skipped, never retried forever
            try:
                ev = {"seq": row[0], "ts": row[1], "kind": row[2], "subject": row[3], "source": row[4], "provenance": row[5],
                      "payload": json.loads(row[6] or "{}")}
                c = card(ev, self.cfg.get("public_url") or "http://127.0.0.1:5173")
            except (ValueError, KeyError, TypeError):
                continue
            if not c or not self._routes(c["kind"], c["severity"]):
                continue
            key = (c["kind"], c["subject"])
            if now - self.seen.get(key, -1e12) < dedupe_s:
                self.suppressed_dupes += 1
                continue
            self.seen[key] = now
            if self.sent_in_window >= cap:
                self.held += 1
                self.held_in_window += 1
                continue
            self.sent_in_window += 1
            delivered += 1 if self.deliver(c) else 0
        if len(self.seen) > 5000:
            self.seen = {k: t for k, t in self.seen.items() if now - t < dedupe_s}
        return delivered

    # ---- delivery
    def deliver(self, c: dict, summary: bool = False) -> int:
        """Send one card to every enabled, configured channel that is not backing off; audit each attempt."""
        with self.lock:
            targets = [dict(ch) for ch in self.channels.values() if ch.get("enabled", True) and configured(ch)
                       and self.state[ch["name"]]["skip_until"] <= time.time()]
        return sum(self._send(ch, c, summary=summary)["ok"] for ch in targets)

    def _send(self, ch: dict, c: dict, summary: bool = False, test: bool = False) -> dict:
        name, started, err = ch["name"], time.perf_counter(), None
        try:
            SENDERS[ch["type"]](ch, c)
        except Exception as exc:  # noqa: BLE001 - a dead destination is reported and backed off, never raised
            err = f"{type(exc).__name__}: {str(exc)[:160]}"
        ms = round((time.perf_counter() - started) * 1000)
        rec = {"ts": _iso(dt.datetime.now(dt.timezone.utc)), "channel": name, "type": ch["type"], "destination": destination(ch),
               "kind": c["kind"], "subject": c["subject"], "severity": c["severity"], "title": c["title"], "ok": err is None,
               "ms": ms, "error": err, "test": test, "summary": summary}
        with self.lock:
            st = self.state[name]
            if err is None:
                st.update(status="ok", sent=st["sent"] + 1, last_ok=rec["ts"], last_error=None, skip_until=0.0)
            else:
                st.update(status="failing", failed=st["failed"] + 1, last_error=err, skip_until=time.time() + BACKOFF_S)
            self.recent.appendleft(rec)
        conn = self.connect()
        try:
            Ledger(conn=conn).append(ts=rec["ts"], kind="notify.sent" if err is None else "notify.failed",
                                     subject=f"{name}:{c['subject']}", source="ODYSSEY_CHANNELS", provenance="AUTO",
                                     payload={k: rec[k] for k in ("channel", "type", "destination", "kind", "severity", "title", "ms", "error", "test")})
        finally:
            conn.close()
        return rec

    def test(self, name: str) -> dict:
        """A real test alert to one channel, now; it ignores back-off so a fixed destination can be retried at once."""
        with self.lock:
            ch = dict(self.channels.get(name) or {})
        if not ch:
            raise KeyError(name)
        if not configured(ch):
            raise ValueError(f"{name} is not configured. {ch.get('about') or ''} Put its URL in config/notify.local.json or the environment, then reload.")
        c = {"seq": None, "ts": _iso(dt.datetime.now(dt.timezone.utc)), "kind": "notify.test", "subject": name, "severity": "High",
             "provenance": "HUMAN", "title": f"Test alert from Odyssey to {name}",
             "lines": ["If you can read this, Odyssey's alerts reach this channel.",
                       "Real alerts: attacks blocked at a protected app, C2 beacons, new CVEs, cases opened, decisions waiting for you."],
             "link": f"{self.cfg.get('public_url') or 'http://127.0.0.1:5173'}/?view=live"}
        return self._send(ch, c, test=True)

    # ---- for the interface
    def _view(self, name: str) -> dict:
        ch, st = self.channels[name], self.state[name]
        return {"name": name, "type": ch["type"], "enabled": bool(ch.get("enabled", True)), "configured": configured(ch),
                "destination": destination(ch) if configured(ch) else None, "about": ch.get("about"),
                **{k: st[k] for k in ("status", "sent", "failed", "last_ok", "last_error")}, "backing_off": st["skip_until"] > time.time()}

    def _console_url(self) -> str | None:
        ch = self.channels.get("ops-console")
        if not ch or not configured(ch):
            return None
        u = urlsplit(ch["url"])
        return f"{u.scheme}://{u.netloc}/"

    def status(self) -> dict:
        with self.lock:
            chans = [self._view(n) for n in self.channels]
            r = self.cfg.get("routing", {})
            return {"running": self._thread is not None and self._thread.is_alive(), "started": _iso(self.started), "cursor": self.cursor,
                    "public_url": self.cfg.get("public_url"), "channels": chans,
                    "routing": {"min_severity": r.get("min_severity", "High"), "kinds": r.get("kinds", []),
                                "dedupe_minutes": r.get("dedupe_minutes", 10), "per_minute_cap": r.get("per_minute_cap", 20)},
                    "stats": {"sent": sum(c["sent"] for c in chans), "failed": sum(c["failed"] for c in chans),
                              "configured": sum(1 for c in chans if c["configured"]),
                              "live": sum(1 for c in chans if c["configured"] and c["enabled"]),
                              "duplicates_suppressed": self.suppressed_dupes, "held_by_cap": self.held},
                    "recent": list(self.recent)[:30], "console_url": self._console_url()}

    # ---- the loop
    def _run(self) -> None:
        while True:
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001 - delivery must never stop; the next poll retries
                print(f"channels: poll failed: {exc!r}", flush=True)
            time.sleep(POLL_S)

    def start(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, daemon=True, name="odyssey-channels")
            self._thread.start()


ENGINE: Notifier | None = None
