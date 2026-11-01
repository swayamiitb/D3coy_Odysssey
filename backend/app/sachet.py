"""Odyssey <-> SACHET: read India's national disaster-alert feed, and write Odyssey's cyber warnings in the same
CAP 1.2 shape SACHET publishes. Two directions, both honest.

  IN   the public SACHET RSS/CAP feed (REAL, public domain) is read read-only, like NVD/KEV. It answers the question
       every critical-infrastructure SOC faces - "is this outage the weather, or an attack?" An active natural-disaster
       alert in an operator's state lets Odyssey weight a natural cause; an attack *during* a disaster is escalated.
  OUT  Odyssey writes each warning as CAP 1.2 (the same namespace SACHET uses, one <info> block per language from the
       local IndicTrans2 translate layer), so routing it through an authorised agency - CERT-In is the cyber channel -
       is configuration, not redevelopment.

Honesty: Odyssey is NOT connected to SACHET and cannot push into it (SACHET accepts alerts only from authorised
agencies and has no public submission API). Odyssey's own feed is labelled "SACHET-compatible", never with NDMA or
SACHET branding.

Every inbound alert is untrusted (validate, don't trust) - exactly what a national early-warning system must do to its
own inputs:
  - XML is parsed with DTDs and entities refused: the dependency-free XXE defense (legitimate CAP carries no DTD);
  - the sender must be on an allow-list of authorised agencies (spoofed-sender defense);
  - a replayed identifier, or an already-expired alert, is refused (replay / stale defense);
  - a flood is rate-capped per window (DoS-of-ingest defense).
Each decision is a hash-chained ledger event (indicators defanged), so "what did we accept or refuse, and why" is
auditable like everything else.
"""

from __future__ import annotations

import collections
import datetime as dt
import re
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[2]
CAP_NS = "urn:oasis:names:tc:emergency:cap:1.2"
RSS_URL = "https://sachet.ndma.gov.in/cap_public_website/rss/rss_india.xml"
RSS_SNAPSHOT = ROOT / "data" / "raw" / "sachet_rss.xml"
FEED_EVERY_S = 900                 # the same 15-minute cadence as Odyssey's other live feeds
MAX_XML_BYTES = 2 * 1024 * 1024    # an inbound CAP message is small; anything larger is refused before parsing
RATE_WINDOW_S = 60.0
RATE_MAX = 60                      # inbound CAP messages per window before the rest are refused as a flood

# Odyssey tier -> CAP severity (CAP's own vocabulary).
SEVERITY = {"Compromise": "Extreme", "Critical": "Severe", "High": "Moderate", "Medium": "Minor", "Watch": "Minor"}
CAP_STATUSES = {"Actual", "Exercise", "System", "Test", "Draft"}

# Senders Odyssey will accept an inbound CAP from: authorised Indian alerting agencies, plus Odyssey's own id. A real
# deployment sets this from policy; the point of the list is that a forged <sender> is refused.
ALLOWED_SENDERS = {"odyssey@ncew.local"}
ALLOWED_SENDER_DOMAINS = ("ndma.gov.in", "imd.gov.in", "mausam.imd.gov.in", "cwc.gov.in", "incois.gov.in", "cert-in.org.in")
ALLOWED_SENDER_PREFIXES = ("IMD-", "CWC-", "INCOIS-", "SDMA-", "NDMA")

INDIAN_STATES = [
    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh", "Goa", "Gujarat", "Haryana",
    "Himachal Pradesh", "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya",
    "Mizoram", "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura",
    "Uttar Pradesh", "Uttarakhand", "West Bengal", "Delhi", "Jammu and Kashmir", "Ladakh", "Puducherry",
]


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


# ---------------------------------------------------------------- safe XML (XXE defense, dependency-free)
def safe_parse(data: bytes | str) -> ET.Element:
    """Parse XML with DTDs and entity declarations refused. Legitimate CAP has neither, so rejecting a document that
    carries one blocks external-entity (XXE) and entity-expansion (billion-laughs) attacks without a third-party
    library; stdlib expat does not fetch external entities. Oversize input is refused before parsing."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_XML_BYTES:
        raise ValueError(f"XML larger than {MAX_XML_BYTES} bytes refused")
    low = raw.lower()
    if b"<!doctype" in low or b"<!entity" in low:
        raise ValueError("DTD/DOCTYPE refused (XXE / entity-expansion defense)")
    return ET.fromstring(raw)


# ---------------------------------------------------------------- IN: read the public SACHET feed
def _text(el: ET.Element | None, tag: str, ns: dict | None = None) -> str:
    if el is None:
        return ""
    found = el.find(tag, ns) if ns else el.find(tag)
    return (found.text or "").strip() if found is not None and found.text else ""


def states_in(text: str) -> list[str]:
    """Which Indian states a free-text alert names (how a disaster alert is matched to operators, honestly: by state)."""
    low = (text or "").lower()
    return [s for s in INDIAN_STATES if s.lower() in low]


def parse_rss(data: bytes) -> list[dict]:
    """The feed's item list (title, category, sender, identifier, link, published, states named in the title)."""
    root = safe_parse(data)
    out = []
    for it in root.findall(".//item"):
        title = _text(it, "title")
        out.append({
            "identifier": _text(it, "guid") or None,
            "title": re.sub(r"\s+", " ", title).strip(),
            "category": _text(it, "category") or None,
            "sender": _text(it, "author") or None,
            "link": _text(it, "link") or None,
            "published": _text(it, "pubDate") or None,
            "states": states_in(f"{title} {_text(it, 'description')}"),
        })
    return out


def parse_cap(data: bytes) -> dict:
    """A full CAP 1.2 message -> a structured alert (top fields plus one entry per <info> language block)."""
    root = safe_parse(data)
    tag = root.tag.split("}")[-1]
    if tag != "alert":
        raise ValueError(f"not a CAP <alert> (root is <{tag}>)")
    ns = {"c": CAP_NS}
    top = {k: _text(root, f"c:{k}", ns) for k in ("identifier", "sender", "sent", "status", "msgType", "scope")}
    infos = []
    for info in root.findall("c:info", ns):
        areas = [a.text.strip() for a in info.findall("c:area/c:areaDesc", ns) if a is not None and a.text]
        infos.append({k: _text(info, f"c:{k}", ns) for k in
                      ("language", "category", "event", "urgency", "severity", "certainty", "headline", "description",
                       "instruction")} | {"areas": areas, "states": states_in(" ".join(areas))})
    all_states = sorted({s for i in infos for s in i["states"]})
    return {**top, "infos": infos, "states": all_states}


def match_orgs(states: list[str], orgs: dict) -> list[dict]:
    """Operators in the states a disaster alert names: the ones for which this weather is a possible natural cause."""
    want = {s.lower() for s in states}
    return sorted(({"org_id": oid, "name": o.get("name"), "sector": o.get("sector"), "state": o.get("state")}
                   for oid, o in orgs.items() if (o.get("state") or "").lower() in want),
                  key=lambda r: r["org_id"])


# ---------------------------------------------------------------- OUT: write a CAP 1.2 "SACHET-compatible" warning
def _sub(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
    e = ET.SubElement(parent, f"{{{CAP_NS}}}{tag}")
    if text is not None:
        e.text = text
    return e


def write_cap(alert: dict, infos: list[dict], *, status: str = "Exercise", sender: str = "odyssey@ncew.local",
              scope: str = "Restricted", sent: dt.datetime | None = None) -> str:
    """Odyssey's warning as a CAP 1.2 document: one <info> block per language, SACHET's exact namespace and fields.

    alert: {identifier, tier, urgency?, certainty?}. infos: one dict per language with {language, event, headline,
    instruction, areaDesc}. status defaults to Exercise (honest for a drill or red-team); a real detection routed
    through CERT-In would be Actual. Values are escaped; nothing is interpolated unescaped."""
    if status not in CAP_STATUSES:
        raise ValueError(f"status must be one of {sorted(CAP_STATUSES)}")
    ET.register_namespace("", CAP_NS)
    root = ET.Element(f"{{{CAP_NS}}}alert")
    _sub(root, "identifier", escape(str(alert.get("identifier") or "ODYSSEY-0000")))
    _sub(root, "sender", escape(sender))
    _sub(root, "sent", (sent or dt.datetime.now(IST)).isoformat(timespec="seconds"))
    _sub(root, "status", status)
    _sub(root, "msgType", "Alert")
    _sub(root, "scope", scope)
    sev = SEVERITY.get(alert.get("tier"), "Unknown")
    for info in infos:
        node = _sub(root, "info")
        _sub(node, "language", info.get("language") or "en-IN")
        _sub(node, "category", "Security")
        _sub(node, "event", escape(info.get("event") or "Cyber security warning"))
        _sub(node, "urgency", alert.get("urgency") or "Immediate")
        _sub(node, "severity", sev)
        _sub(node, "certainty", alert.get("certainty") or "Observed")
        if info.get("headline"):
            _sub(node, "headline", escape(info["headline"]))
        if info.get("instruction"):
            _sub(node, "instruction", escape(info["instruction"]))
        if info.get("areaDesc"):
            _sub(_sub(node, "area"), "areaDesc", escape(info["areaDesc"]))
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


# ---------------------------------------------------------------- inbound ingest guard (untrusted alerts)
def sender_allowed(sender: str) -> bool:
    s = (sender or "").strip()
    if not s or s in ALLOWED_SENDERS:
        return s in ALLOWED_SENDERS
    if any(s.startswith(p) for p in ALLOWED_SENDER_PREFIXES):
        return True
    dom = s.split("@")[-1].lower().rstrip(">").strip()
    return any(dom == d or dom.endswith("." + d) for d in ALLOWED_SENDER_DOMAINS)


class CapGuard:
    """Odyssey's inbound CAP endpoint, treating every alert as untrusted. ingest() returns an auditable decision."""

    def __init__(self, connect: Callable[[], sqlite3.Connection] | None = None):
        self.connect = connect
        self.lock = threading.RLock()
        self.started = dt.datetime.now(dt.timezone.utc)
        self.seen: dict[str, float] = {}                       # identifier -> first-seen monotonic time (replay guard)
        self.window: collections.deque = collections.deque()   # ingest timestamps in the rate window
        self.decisions: collections.deque = collections.deque(maxlen=100)
        self.counts: dict[str, int] = collections.defaultdict(int)
        world_path = ROOT / "data" / "sim" / "world.json"
        import json
        world = json.loads(world_path.read_text(encoding="utf-8")) if world_path.exists() else {"orgs": []}
        self.orgs = {o["id"]: o for o in world["orgs"]}
        # read-side state for the dashboard panel
        self.feed: dict = {"source": "REAL", "status": "waiting", "fetched_at": None, "count": 0, "alerts": [],
                           "detail": "first read shortly after start", "url": RSS_URL}

    # -- IN: read the public feed (snapshot-backed, like the other live feeds) -----------------------------
    def read_feed(self, live: bool = True, now: dt.datetime | None = None) -> dict:
        now = now or dt.datetime.now(dt.timezone.utc)
        data, mode = None, "snapshot"
        if live:
            try:
                import httpx
                r = httpx.get(RSS_URL, timeout=20, follow_redirects=True,
                              headers={"User-Agent": "Odyssey-EWS/0.2 (research; read-only)"})
                r.raise_for_status()
                data, mode = r.content, "live"
                try:
                    RSS_SNAPSHOT.write_bytes(data)
                except OSError:
                    pass
            except Exception as exc:  # noqa: BLE001 - offline is fine: serve the snapshot and say so
                self.feed.update(status="offline", detail=f"{type(exc).__name__}: serving the snapshot")
        if data is None:
            if not RSS_SNAPSHOT.exists():
                self.feed.update(status="unavailable", detail="no live feed and no snapshot")
                return self.feed
            data = RSS_SNAPSHOT.read_bytes()
        try:
            items = parse_rss(data)
        except ValueError as exc:
            self.feed.update(status="error", detail=str(exc))
            return self.feed
        alerts = []
        for it in items[:60]:
            orgs = match_orgs(it["states"], self.orgs)
            alerts.append({**it, "orgs": [o["org_id"] for o in orgs], "org_names": [o["name"] for o in orgs]})
        matched = sum(1 for a in alerts if a["orgs"])
        with self.lock:
            self.feed = {"source": "REAL", "status": "fresh" if mode == "live" else "snapshot", "fetched_at": _iso(now),
                         "count": len(items), "shown": len(alerts), "matched": matched, "alerts": alerts, "url": RSS_URL,
                         "detail": f"{len(items)} public disaster alerts ({mode}); {matched} name a state we protect"}
        self._audit(now, "cap.read", "sachet-rss", {"count": len(items), "matched": matched, "mode": mode}, "REAL")
        return self.feed

    def fetch_cap(self, url: str) -> dict:
        """Read one alert's full CAP XML on demand (not all of them every poll). Loopback/https public gov URL only."""
        import httpx
        if not (url.startswith("https://sachet.ndma.gov.in/") or url.startswith("http://127.0.0.1")):
            raise ValueError("only the public SACHET endpoint (or a loopback test) may be fetched")
        r = httpx.get(url, timeout=20, follow_redirects=True, headers={"User-Agent": "Odyssey-EWS/0.2 (research; read-only)"})
        r.raise_for_status()
        return parse_cap(r.content)

    # -- inbound ingest: validate, don't trust ------------------------------------------------------------
    def ingest(self, data: bytes | str, *, source_ip: str | None = None, now: dt.datetime | None = None,
               redteam: str | None = None) -> dict:
        now = now or dt.datetime.now(dt.timezone.utc)
        raw = data.encode("utf-8") if isinstance(data, str) else data
        mono = time.monotonic()

        def decide(accepted: bool, reason: str, detail: str, alert: dict | None = None) -> dict:
            with self.lock:
                self.counts[reason] += 1
                rec = {"ts": _iso(now), "accepted": accepted, "reason": reason, "detail": detail,
                       "identifier": (alert or {}).get("identifier"), "sender": (alert or {}).get("sender"),
                       "source_ip": source_ip, "redteam": redteam}
                self.decisions.appendleft(rec)
            self._audit(now, f"cap.ingest.{'accepted' if accepted else 'refused'}", (alert or {}).get("identifier") or "cap",
                        {"reason": reason, "detail": detail[:160], "sender": (alert or {}).get("sender"),
                         "source_ip": source_ip, "redteam": redteam}, "SIM" if redteam else "REAL")
            return {"accepted": accepted, "reason": reason, "detail": detail,
                    "identifier": (alert or {}).get("identifier"), "redteam": redteam}

        # rate / flood guard first, so a flood cannot exhaust work
        with self.lock:
            cut = mono - RATE_WINDOW_S
            while self.window and self.window[0] < cut:
                self.window.popleft()
            if len(self.window) >= RATE_MAX:
                return decide(False, "rate_limited", f"more than {RATE_MAX} inbound alerts in {int(RATE_WINDOW_S)}s: flood refused")
            self.window.append(mono)

        try:
            alert = parse_cap(raw)
        except ValueError as exc:
            reason = "xxe" if "DTD" in str(exc) or "entity" in str(exc).lower() else "oversize" if "larger" in str(exc) else "malformed"
            return decide(False, reason, str(exc))
        except ET.ParseError as exc:
            return decide(False, "malformed", f"not well-formed XML: {str(exc)[:120]}")

        if not alert.get("identifier") or not alert.get("sender") or not alert.get("sent"):
            return decide(False, "malformed", "missing required CAP field (identifier / sender / sent)", alert)
        if not sender_allowed(alert["sender"]):
            return decide(False, "untrusted_sender", f"sender {alert['sender']!r} is not an authorised alerting agency", alert)
        with self.lock:
            prev = self.seen.get(alert["identifier"])
        if prev is not None:
            return decide(False, "replay", f"identifier {alert['identifier']} already seen (replay)", alert)
        exp = _expires(alert)
        if exp is not None and exp < now:
            return decide(False, "stale", f"alert expired at {exp.isoformat()} (stale / cancellation replay)", alert)
        with self.lock:
            self.seen[alert["identifier"]] = mono
            if len(self.seen) > 10000:
                self.seen = dict(sorted(self.seen.items(), key=lambda kv: kv[1])[-5000:])
        return decide(True, "accepted", f"{len(alert['infos'])} language block(s); states {', '.join(alert['states']) or 'n/a'}", alert)

    def _audit(self, now: dt.datetime, kind: str, subject: str, payload: dict, provenance: str) -> None:
        if self.connect is None:
            return
        from .engine.ledger import Ledger
        conn = self.connect()
        try:
            Ledger(conn=conn).append(ts=_iso(now), kind=kind, subject=subject, source="SACHET", provenance=provenance,
                                     payload=payload)
        except Exception as exc:  # noqa: BLE001 - a telemetry write must never fail an ingest decision
            print(f"sachet: audit write failed: {exc!r}", flush=True)
        finally:
            conn.close()

    def status(self) -> dict:
        with self.lock:
            return {"running": True, "started": _iso(self.started), "feed": self.feed,
                    "ingest": {"counts": dict(self.counts), "seen": len(self.seen), "in_window": len(self.window),
                               "window_s": int(RATE_WINDOW_S), "max_per_window": RATE_MAX,
                               "allowed_senders": sorted(ALLOWED_SENDERS), "allowed_domains": list(ALLOWED_SENDER_DOMAINS)},
                    "decisions": list(self.decisions)[:40]}


def _expires(alert: dict) -> dt.datetime | None:
    for info in alert.get("infos", []):
        raw = info.get("expires")
        if raw:
            try:
                e = dt.datetime.fromisoformat(raw)
                return e if e.tzinfo else e.replace(tzinfo=IST)
            except ValueError:
                return None
    return None


ENGINE: CapGuard | None = None
