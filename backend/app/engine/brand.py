"""Brand and social monitoring: passive, public, pluggable.

The digital-risk layer of a threat-intelligence platform, built from sources anyone may read: certificate
transparency (crt.sh), abuse.ch URLhaus, OpenPhish, news search and public social feeds (Hacker News, Reddit).
For a brand term, or for an organisation in the constituency (its name's distinctive words, its domain and the
look-alike permutations of that domain), each source adapter returns normalised hits; hits are scored with explicit
rules, stored once (upsert on term + source + kind + value), and every new high-score hit is written to the audit
ledger as `brand.hit`, which is what the channels, the SOC and the intelligence graph read.

Nothing here touches the monitored organisation or the sites found: every request is a read of a public feed or a
public search, with a 20-second timeout, and a source that does not answer is reported "offline", never raised.
The default fetcher talks only to the allow-listed source hosts (redirects re-checked against the same list), streams
the answer under a byte cap, and the search term only ever travels URL-encoded inside a query string.
Indicators are stored defanged for display, in `value`, `title`, `snippet` and `evidence` alike; the raw form stays
in `raw` for the exports. Links handed to the UI are http(s) URLs of the public source, never anything else.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote, urlsplit

from .intel import _GENERIC, lookalikes

ROOT = Path(__file__).resolve().parents[3]
RAW = ROOT / "data" / "raw"
CACHE = ROOT / "data" / ".tmp"
UA = {"User-Agent": "Odyssey-EWS/0.2 (research)"}
TIMEOUT = 20
MAX_BYTES = 8_000_000  # no public feed or search answer is this big; anything larger is refused before it is parsed
MAX_REDIRECTS = 5
# the only hosts the default fetcher talks to, or follows a redirect to: the public sources named in SOURCES
ALLOWED_DOMAINS = ("crt.sh", "abuse.ch", "openphish.com", "google.com", "algolia.com", "reddit.com", "ycombinator.com")
URLHAUS_TTL_S = 3600
CYBER_WORDS = ("breach", "leak", "hack", "ransomware", "phish", "exposed", "credential", "dump", "vulnerab", "ddos", "defac", "malware")
LURE_WORDS = ("login", "secure", "verify", "update", "support", "kyc", "otp", "bank")
LEDGER_FLOOR = 70.0
MIN_TERM, MAX_TERM = 3, 100  # a one- or two-letter term is a substring of nearly every hostname: it would flood the ledger
SOURCE_NAMES = ["crt.sh", "URLhaus", "OpenPhish", "Google News", "Hacker News", "Reddit"]


# ------------------------------------------------------------------------------------------------------- helpers
def _iso(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(ts) -> dt.datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    ts = ts.strip()
    for fmt in (None, "%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S"):
        try:
            d = dt.datetime.fromisoformat(ts.replace("Z", "+00:00")) if fmt is None else dt.datetime.strptime(ts, fmt)
            d = d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
            d.astimezone(dt.timezone.utc)  # a date that cannot be expressed in UTC is refused here, not inside an adapter
            return d
        except (ValueError, OverflowError):
            continue
    return None


def _recent(d: dt.datetime | None, now: dt.datetime, days: int) -> bool:
    """Within the last `days` days; a day of clock skew is tolerated, a date further in the future is not 'recent'."""
    return d is not None and -1 <= (now - d).days <= days


def defang(value: str) -> str:
    v = re.sub(r"^https?(?=://)", lambda m: m.group(0)[0] + "xx" + m.group(0)[3:], str(value), flags=re.I)
    return re.sub(r"(?<!\[)\.(?!\])", "[.]", v)  # idempotent: an already defanged value is left alone


def _refang(value: str) -> str:
    return re.sub(r"^hxxp", "http", value.replace("[.]", "."), flags=re.I)


def _host(url) -> str:
    if not isinstance(url, str):
        return ""
    try:
        return (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def _allowed_url(url: str) -> bool:
    try:
        p = urlsplit(url)
    except ValueError:
        return False
    host = (p.hostname or "").lower().rstrip(".")
    return p.scheme in ("http", "https") and bool(host) and any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)


def _safe_url(url, fallback: str) -> str:
    """A link the UI may render: http(s) with a host, else the public source's own page."""
    if isinstance(url, str):
        u = url.strip()
        try:
            p = urlsplit(u)
        except ValueError:
            return fallback
        if p.scheme in ("http", "https") and p.hostname and len(u) <= 2000:
            return u
    return fallback


def _default_fetch(url: str, timeout: int = TIMEOUT) -> tuple[int, str]:
    """GET a public source: allow-listed hosts only, redirects re-checked against the same list, the body streamed
    under a byte cap and an overall deadline so an oversized or slow-drip answer cannot hold the scan."""
    import httpx
    if not _allowed_url(url):
        raise ValueError(f"refused: {_host(url) or url[:40]!r} is not a public source of this module")
    deadline = time.monotonic() + timeout * 2
    with httpx.Client(timeout=timeout, follow_redirects=False, headers=UA) as client:
        for _ in range(MAX_REDIRECTS + 1):
            with client.stream("GET", url) as r:
                if r.is_redirect:
                    nxt = str(r.next_request.url) if r.next_request is not None else ""
                    if not _allowed_url(nxt):
                        raise RuntimeError(f"redirect refused: {_host(nxt) or nxt[:40]!r}")
                    url = nxt
                    continue
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        raise RuntimeError(f"response over {MAX_BYTES // 1_000_000} MB refused")
                    if time.monotonic() > deadline:
                        raise RuntimeError("response too slow")
                return r.status_code, bytes(buf).decode(r.encoding or "utf-8", errors="replace")
    raise RuntimeError("too many redirects")


def _matches(host_or_text: str, needles: list[str]) -> str | None:
    s = (host_or_text or "").lower()
    for n in needles:
        if n and n in s:
            return n
    return None


def _trim(obj, n: int = 600) -> str:
    s = json.dumps(obj, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[:n] + "…"


# ------------------------------------------------------------------------------------------------------- storage
def ensure(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS brand_hits (
        id INTEGER PRIMARY KEY, ts TEXT, term TEXT, org_id TEXT, source TEXT, kind TEXT, channel TEXT, value TEXT, url TEXT,
        title TEXT, snippet TEXT, score REAL, provenance TEXT, evidence TEXT, raw TEXT, first_seen TEXT, last_seen TEXT,
        UNIQUE(term, source, kind, value))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS brand_scans (
        id INTEGER PRIMARY KEY, ts TEXT, term TEXT, org_id TEXT, sources TEXT, hits INTEGER, new_hits INTEGER, seconds REAL)""")
    conn.commit()


def terms_for_org(conn: sqlite3.Connection, org_id: str) -> list[str]:
    row = conn.execute("SELECT name, domain FROM orgs WHERE id = ?", (org_id,)).fetchone()
    if not row:
        raise KeyError(org_id)
    name, domain = row[0], row[1]
    words = [w.lower() for w in re.findall(r"[A-Za-z]{5,}", name or "") if w.lower() not in _GENERIC]
    label = (domain or "").split(".")[0].lower()
    out = []
    for t in words + ([label] if label and len(label) >= 4 else []):
        if t not in out:
            out.append(t)
    return out


def _variants(term: str, domain: str | None) -> list[str]:
    base = {term.lower()}
    if domain:
        base |= lookalikes(domain)
    else:
        base |= lookalikes(f"{term}.example")
    return sorted(base, key=len, reverse=True)


def _is_own(name: str, domain: str) -> bool:
    """The organisation's own domain or one of its subdomains: a certificate there is not a look-alike."""
    name, domain = name.lower().strip("."), domain.lower().strip(".")
    return bool(domain) and (name == domain or name.endswith("." + domain))


# ------------------------------------------------------------------------------------------ source adapters
def _score_cert(name: str, not_before: str | None, now: dt.datetime) -> float:
    s = 55.0
    if _recent(_parse(not_before), now, 30):
        s += 20
    if any(w in name.lower() for w in LURE_WORDS):
        s += 15
    return min(100.0, s)


def _score_mention(title: str, snippet: str, published: str | None, now: dt.datetime) -> float:
    s = 20.0
    text = f"{title} {snippet}".lower()
    if any(w in text for w in CYBER_WORDS):
        s += 25
    if _recent(_parse(published), now, 7):
        s += 10
    return min(100.0, s)


def _crtsh(term: str, needles: list[str], now: dt.datetime, fetch) -> list[dict]:
    status, text = fetch(f"https://crt.sh/?q=%25{quote(term)}%25&output=json")
    if status != 200:
        raise RuntimeError(f"HTTP {status}")
    rows = json.loads(text or "[]")
    if not isinstance(rows, list):
        raise RuntimeError("unexpected payload")
    # one hit per look-alike name, whether it is the common name or a SAN, scored on its most recent issuance
    latest: dict[str, tuple[dt.datetime | None, dict]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        issued = _parse(r.get("not_before"))
        for name in {str(r.get("common_name") or "")} | set(str(r.get("name_value") or "").split()):
            name = name.lower().strip().lstrip("*.")
            if not name or not _matches(name, needles):
                continue
            prev = latest.get(name)
            if prev is None or (issued and (prev[0] is None or issued > prev[0])):
                latest[name] = (issued, r)
    out = []
    for name, (issued, r) in latest.items():
        shown, cid = defang(name), r.get("id")
        sans = [defang(s) for s in str(r.get("name_value") or "").split()[:4]]
        out.append({"ts": _iso(issued) if issued else _iso(now), "source": "crt.sh",
                    "kind": "lookalike_cert", "channel": "certificate transparency", "value": shown,
                    "url": f"https://crt.sh/?id={int(cid)}" if str(cid).isdigit() else "https://crt.sh/",
                    "title": shown, "snippet": f"issued by {str(r.get('issuer_name') or '?')[:80]}; names: {', '.join(sans)[:120] or '-'}",
                    "score": _score_cert(name, r.get("not_before"), now),
                    "evidence": f"a TLS certificate was issued for '{shown}', which contains '{_matches(name, needles)}'",
                    "raw": _trim({k: r.get(k) for k in ("id", "issuer_name", "not_before", "not_after", "name_value", "common_name")})})
    return out


def _urlhaus_rows(fetch) -> list[dict]:
    # The hourly cache holds the real feed only: an injected fetcher (tests, fixtures) neither reads nor writes it, so
    # fixture rows can never be served to a live scan; a corrupt or foreign cache file is ignored and refetched, and
    # the file is replaced atomically so a concurrent scan never reads a half-written one.
    path = CACHE / "urlhaus_recent.json"
    data = None
    if fetch is _default_fetch and path.exists() and time.time() - path.stat().st_mtime < URLHAUS_TTL_S:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if not isinstance(data, (dict, list)):
            data = None
    if data is None:
        status, text = fetch("https://urlhaus.abuse.ch/downloads/json_recent/")
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        data = json.loads(text)
        if not isinstance(data, (dict, list)):
            raise RuntimeError("unexpected payload")
        if fetch is _default_fetch:
            CACHE.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(f"urlhaus_recent.{os.getpid()}.tmp")
            try:
                tmp.write_text(json.dumps(data), encoding="utf-8")
                os.replace(tmp, path)
            except OSError:
                tmp.unlink(missing_ok=True)
    rows = []
    if isinstance(data, dict):
        for entries in data.values():
            rows.extend(e for e in (entries or []) if isinstance(e, dict))
    elif isinstance(data, list):
        rows = [e for e in data if isinstance(e, dict)]
    return rows


def _urlhaus(term: str, needles: list[str], now: dt.datetime, fetch) -> list[dict]:
    out, seen = [], set()
    for e in _urlhaus_rows(fetch):
        url = e.get("url")
        if not isinstance(url, str) or not url:
            continue
        host = _host(url)
        hit = _matches(host, needles)
        if not hit or url in seen:
            continue
        seen.add(url)
        tags = e.get("tags")
        tags = [str(t) for t in tags] if isinstance(tags, list) else ([str(tags)] if tags else [])
        shown = defang(host)
        out.append({"ts": _parse(e.get("dateadded")) and _iso(_parse(e.get("dateadded"))) or _iso(now), "source": "URLhaus",
                    "kind": "malicious_url", "channel": "abuse.ch URLhaus", "value": defang(url)[:200],
                    "url": _safe_url(e.get("urlhaus_link"), "https://urlhaus.abuse.ch/"),
                    "title": shown, "snippet": f"{e.get('threat') or 'malware'} · {e.get('url_status') or '?'} · tags {', '.join(tags) or '-'}",
                    "score": 85.0, "evidence": f"URLhaus lists a malware URL on '{shown}', which contains '{hit}'",
                    "raw": _trim({k: e.get(k) for k in ("id", "dateadded", "url", "url_status", "threat", "tags", "reporter")})})
    return out


def _openphish(term: str, needles: list[str], now: dt.datetime, fetch) -> list[dict]:
    urls = []
    snap = RAW / "openphish.txt"
    if snap.exists():
        try:
            urls += snap.read_text(encoding="utf-8", errors="replace").split()
        except OSError:
            pass
    live_ok = True
    try:
        status, text = fetch("https://openphish.com/feed.txt")
        if status == 200:
            urls += text.split()
        else:
            live_ok = False
    except Exception:  # noqa: BLE001 - the snapshot still counts
        live_ok = False
    out, seen = [], set()
    for u in urls:
        host = _host(u)
        hit = _matches(host, needles)
        if not hit or u in seen:
            continue
        seen.add(u)
        shown = defang(host)
        out.append({"ts": _iso(now), "source": "OpenPhish", "kind": "phishing_url", "channel": "OpenPhish" + ("" if live_ok else " (snapshot)"),
                    "value": defang(u)[:200], "url": "https://openphish.com/", "title": shown, "snippet": "live phishing URL",
                    "score": 80.0, "evidence": f"OpenPhish lists a phishing URL on '{shown}', which contains '{hit}'", "raw": _trim({"url": u})})
    return out


def _rss_items(text: str) -> list[dict]:
    # Public RSS/Atom from reputable endpoints; stdlib ElementTree does not resolve external entities, and a size cap
    # plus a whole-document entity check guard against an oversized or entity-expanded payload (defusedxml is not a
    # dependency here). The entity check reads the whole text: a long comment in the prolog must not hide a DTD.
    if len(text) > 4_000_000 or "<!ENTITY" in text:
        raise ValueError("oversized or entity-bearing XML refused")
    root = ET.fromstring(text)
    items = []
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for it in root.iter("item"):
        items.append({"title": (it.findtext("title") or "").strip(), "link": (it.findtext("link") or "").strip(),
                      "published": (it.findtext("pubDate") or "").strip(), "snippet": re.sub(r"<[^>]+>", " ", it.findtext("description") or "")[:300].strip(),
                      "source": (it.findtext("source") or "").strip()})
    for it in root.iter("{http://www.w3.org/2005/Atom}entry"):
        links = it.findall("atom:link", ns)
        link = next((l for l in links if (l.get("rel") or "alternate") == "alternate"), links[0] if links else None)
        items.append({"title": (it.findtext("atom:title", default="", namespaces=ns) or "").strip(),
                      "link": ((link.get("href") if link is not None else "") or "").strip(),
                      "published": (it.findtext("atom:updated", default="", namespaces=ns) or it.findtext("atom:published", default="", namespaces=ns) or "").strip(),
                      "snippet": re.sub(r"<[^>]+>", " ", it.findtext("atom:content", default="", namespaces=ns) or "")[:300].strip(),
                      "source": (it.findtext("atom:author/atom:name", default="", namespaces=ns) or "").strip()})
    return items


def _news(term: str, needles: list[str], now: dt.datetime, fetch) -> list[dict]:
    q = quote(f'"{term}" (breach OR leak OR hack OR ransomware OR phishing OR exposed OR vulnerability)')
    status, text = fetch(f"https://news.google.com/rss/search?q={q}&hl=en-IN&gl=IN&ceid=IN:en")
    if status != 200:
        raise RuntimeError(f"HTTP {status}")
    out = []
    for it in _rss_items(text):
        if not it["title"]:
            continue
        pub = _parse(it["published"])
        out.append({"ts": _iso(pub) if pub else _iso(now), "source": "Google News", "kind": "mention", "channel": "news",
                    "value": it["title"][:200], "url": _safe_url(it["link"], "https://news.google.com/"), "title": it["title"][:200],
                    "snippet": (it["snippet"] or it["source"])[:300], "score": _score_mention(it["title"], it["snippet"], it["published"], now),
                    "evidence": f"a news item names '{term}' with a security term", "raw": _trim(it)})
    return out


def _hn(term: str, needles: list[str], now: dt.datetime, fetch) -> list[dict]:
    status, text = fetch(f"https://hn.algolia.com/api/v1/search_by_date?query={quote(chr(34) + term + chr(34))}&tags=(story,comment)&hitsPerPage=30")
    if status != 200:
        raise RuntimeError(f"HTTP {status}")
    data = json.loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("hits"), list):
        raise RuntimeError("unexpected payload")
    out = []
    for h in data["hits"]:
        if not isinstance(h, dict):
            continue
        title = str(h.get("title") or h.get("story_title") or "")
        snippet = re.sub(r"<[^>]+>", " ", str(h.get("comment_text") or h.get("story_text") or ""))[:300]
        if not (title or snippet):
            continue
        if not _matches(f"{title} {snippet}", [term.lower()]):
            continue
        oid = h.get("objectID")
        # the link is the Hacker News item itself, the public source we read; the story's outbound URL stays in `raw`
        out.append({"ts": _iso(_parse(h.get("created_at"))) if _parse(h.get("created_at")) else _iso(now), "source": "Hacker News", "kind": "mention",
                    "channel": "hn", "value": (title or snippet)[:200],
                    "url": f"https://news.ycombinator.com/item?id={quote(str(oid), safe='')}" if oid else "https://news.ycombinator.com/",
                    "title": (title or snippet[:80])[:200], "snippet": snippet, "score": _score_mention(title, snippet, h.get("created_at"), now),
                    "evidence": f"a Hacker News {'comment' if h.get('comment_text') else 'story'} names '{term}'",
                    "raw": _trim({k: h.get(k) for k in ("objectID", "created_at", "author", "points", "url", "story_id")})})
    return out


def _reddit(term: str, needles: list[str], now: dt.datetime, fetch) -> list[dict]:
    status, text = fetch(f"https://www.reddit.com/search.rss?q={quote(chr(34) + term + chr(34))}&sort=new")
    if status != 200:
        raise RuntimeError(f"HTTP {status}")
    out = []
    for it in _rss_items(text):
        if not it["title"] or not _matches(f"{it['title']} {it['snippet']}", [term.lower()]):
            continue
        out.append({"ts": _iso(_parse(it["published"])) if _parse(it["published"]) else _iso(now), "source": "Reddit", "kind": "mention", "channel": "reddit",
                    "value": it["title"][:200], "url": _safe_url(it["link"], "https://www.reddit.com/"), "title": it["title"][:200], "snippet": it["snippet"],
                    "score": _score_mention(it["title"], it["snippet"], it["published"], now), "evidence": f"a Reddit post names '{term}'", "raw": _trim(it)})
    return out


SOURCES = {"crt.sh": _crtsh, "URLhaus": _urlhaus, "OpenPhish": _openphish, "Google News": _news, "Hacker News": _hn, "Reddit": _reddit}


# ---------------------------------------------------------------------------------------------------------- scan
def _run_source(name, fn, term, needles, now, fetch) -> tuple[str, dict, list[dict]]:
    t0 = time.perf_counter()
    try:
        hits = fn(term, needles, now, fetch)
        return name, {"status": "fresh", "count": len(hits), "ms": round((time.perf_counter() - t0) * 1000)}, hits
    except Exception as exc:  # noqa: BLE001 - one source down never fails the scan
        return name, {"status": "offline", "count": 0, "ms": round((time.perf_counter() - t0) * 1000),
                      "detail": f"{type(exc).__name__}: {str(exc)[:120]}"}, []


def _store(conn: sqlite3.Connection, hit: dict, term: str, org_id: str | None, now_iso: str) -> bool:
    """Upsert one hit; True when it is new."""
    row = conn.execute("SELECT id FROM brand_hits WHERE term = ? AND source = ? AND kind = ? AND value = ?",
                       (term, hit["source"], hit["kind"], hit["value"])).fetchone()
    if row:
        conn.execute("UPDATE brand_hits SET last_seen = ?, score = ?, title = ?, snippet = ?, raw = ?, org_id = COALESCE(org_id, ?) WHERE id = ?",
                     (now_iso, hit["score"], hit["title"], hit["snippet"], hit["raw"], org_id, row[0]))
        return False
    try:
        conn.execute("""INSERT INTO brand_hits (ts, term, org_id, source, kind, channel, value, url, title, snippet, score, provenance, evidence, raw,
                        first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (hit["ts"], term, org_id, hit["source"], hit["kind"], hit["channel"], hit["value"], hit["url"], hit["title"], hit["snippet"],
                      hit["score"], "REAL", hit["evidence"], hit["raw"], now_iso, now_iso))
    except sqlite3.IntegrityError:
        # a concurrent scan stored the same hit between our read and our write: it exists, so it is not new
        conn.execute("UPDATE brand_hits SET last_seen = ?, score = ?, title = ?, snippet = ?, raw = ?, org_id = COALESCE(org_id, ?) "
                     "WHERE term = ? AND source = ? AND kind = ? AND value = ?",
                     (now_iso, hit["score"], hit["title"], hit["snippet"], hit["raw"], org_id, term, hit["source"], hit["kind"], hit["value"]))
        return False
    return True


def scan(conn: sqlite3.Connection, term: str | None = None, org_id: str | None = None, now: dt.datetime | None = None,
         fetch=None, sources: list[str] | None = None) -> dict:
    """Run every source for a term, or for every term of an organisation. Never raises for a source outage."""
    from .ledger import Ledger
    ensure(conn)
    now = now or dt.datetime.now(dt.timezone.utc)
    fetch = fetch or _default_fetch
    domain = None
    if org_id:
        org_id = str(org_id)
        row = conn.execute("SELECT domain FROM orgs WHERE id = ?", (org_id,)).fetchone()
        if not row:
            raise KeyError(org_id)
        domain = (row[0] or "").lower() or None
        terms = terms_for_org(conn, org_id)
    elif term is not None and str(term).strip():
        t = re.sub(r"\s+", " ", str(term).strip().lower())
        if not MIN_TERM <= len(t) <= MAX_TERM:
            raise ValueError(f"term must be {MIN_TERM} to {MAX_TERM} characters")
        terms = [t]
    else:
        raise ValueError("term or org_id required")
    chosen = {k: v for k, v in SOURCES.items() if not sources or k in sources}
    t0 = time.perf_counter()
    status: dict[str, dict] = {}
    all_hits, new_hits, ledger_events = [], 0, 0
    led = Ledger(conn=conn)
    now_iso = _iso(now)
    for t in terms:
        needles = _variants(t, domain)
        with ThreadPoolExecutor(max_workers=len(chosen) or 1) as pool:
            results = list(pool.map(lambda kv: _run_source(kv[0], kv[1], t, needles, now, fetch), chosen.items()))
        for name, st, hits in results:
            if domain:  # the organisation's own certificates are not look-alikes of its domain
                hits = [h for h in hits if not (h["kind"] == "lookalike_cert" and _is_own(_refang(h["value"]), domain))]
                st = {**st, "count": len(hits)}
            prev = status.get(name)
            status[name] = st if not prev else {"status": "fresh" if "fresh" in (prev["status"], st["status"]) else "offline",
                                                "count": prev["count"] + st["count"], "ms": prev["ms"] + st["ms"], **({"detail": st.get("detail") or prev.get("detail")} if st.get("detail") or prev.get("detail") else {})}
            for h in hits:
                h = {**h, "term": t, "org_id": org_id, "provenance": "REAL"}
                is_new = _store(conn, h, t, org_id, now_iso)
                h["new"] = is_new
                all_hits.append(h)
                if is_new:
                    new_hits += 1
                    if h["score"] >= LEDGER_FLOOR:
                        led.append(ts=h["ts"], kind="brand.hit", subject=f"brand:{t}", source=h["source"], provenance="REAL",
                                   payload={k: v for k, v in h.items() if k not in ("raw", "new")})
                        ledger_events += 1
    seconds = round(time.perf_counter() - t0, 2)
    conn.execute("INSERT INTO brand_scans (ts, term, org_id, sources, hits, new_hits, seconds) VALUES (?,?,?,?,?,?,?)",
                 (now_iso, ",".join(terms), org_id, json.dumps(status), len(all_hits), new_hits, seconds))
    conn.commit()
    top = sorted(all_hits, key=lambda h: (-h["score"], h["ts"]), reverse=False)[:10]
    return {"ts": now_iso, "terms": terms, "org_id": org_id, "sources": status, "hits": len(all_hits), "new_hits": new_hits,
            "ledger_events": ledger_events, "seconds": seconds, "provenance": "REAL",
            "top": [{k: v for k, v in h.items() if k != "raw"} for h in top],
            "online": sum(1 for s in status.values() if s["status"] == "fresh"), "offline": sum(1 for s in status.values() if s["status"] != "fresh")}


# --------------------------------------------------------------------------------------------------------- reads
def hits(conn: sqlite3.Connection, term: str | None = None, org_id: str | None = None, limit: int = 100, kind: str | None = None) -> list[dict]:
    ensure(conn)
    where, args = [], []
    if term:
        where.append("term = ?")
        args.append(str(term).strip().lower())
    if org_id:
        where.append("org_id = ?")
        args.append(org_id)
    if kind:
        where.append("kind = ?")
        args.append(kind)
    limit = max(1, min(int(limit or 100), 1000))
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    rows = cur.execute(f"""SELECT id, ts, term, org_id, source, kind, channel, value, url, title, snippet, score, provenance, evidence, first_seen, last_seen
                           FROM brand_hits {('WHERE ' + ' AND '.join(where)) if where else ''} ORDER BY score DESC, last_seen DESC LIMIT ?""",
                      (*args, limit)).fetchall()
    return [dict(r) for r in rows]


def summary(conn: sqlite3.Connection, org_id: str | None = None) -> dict:
    ensure(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    where, args = ("WHERE org_id = ?", (org_id,)) if org_id else ("", ())
    terms = [r[0] for r in cur.execute(f"SELECT DISTINCT term FROM brand_hits {where} ORDER BY term", args)]
    known = set(terms)
    scans = {}
    for r in cur.execute(f"SELECT * FROM brand_scans {where} ORDER BY id DESC", args):
        # a scan row lists its terms comma-joined; a single term that itself holds a comma is kept whole, blanks dropped
        parts = [r["term"]] if r["term"] in known else [p.strip() for p in (r["term"] or "").split(",") if p.strip()]
        for t in parts:
            scans.setdefault(t, {"ts": r["ts"], "sources": json.loads(r["sources"] or "{}"), "hits": r["hits"], "new_hits": r["new_hits"], "seconds": r["seconds"]})
    out_terms = []
    for t in terms:
        by_kind = {r[0]: r[1] for r in cur.execute("SELECT kind, COUNT(*) FROM brand_hits WHERE term = ? GROUP BY kind", (t,))}
        top = hits(conn, term=t, limit=5)
        mx = cur.execute("SELECT MAX(score), COUNT(*) FROM brand_hits WHERE term = ?", (t,)).fetchone()
        out_terms.append({"term": t, "org_id": cur.execute("SELECT org_id FROM brand_hits WHERE term = ? AND org_id IS NOT NULL LIMIT 1", (t,)).fetchone().__getitem__(0)
                          if cur.execute("SELECT 1 FROM brand_hits WHERE term = ? AND org_id IS NOT NULL LIMIT 1", (t,)).fetchone() else None,
                          "hits": mx[1], "max_score": mx[0], "by_kind": by_kind, "top": top, "last_scan": scans.get(t)})
    # terms the last scans covered even when they found nothing
    for t, sc in scans.items():
        if t not in terms:
            out_terms.append({"term": t, "org_id": org_id, "hits": 0, "max_score": None, "by_kind": {}, "top": [], "last_scan": sc})
    high = cur.execute(f"SELECT COUNT(*) FROM brand_hits {where + (' AND' if where else 'WHERE')} score >= ?", (*args, LEDGER_FLOOR)).fetchone()[0]
    last = cur.execute(f"SELECT ts, sources FROM brand_scans {where} ORDER BY id DESC LIMIT 1", args).fetchone()
    return {"generated_at": _iso(dt.datetime.now(dt.timezone.utc)), "org_id": org_id, "terms": out_terms,
            "totals": {"terms": len(out_terms), "hits": sum(t["hits"] for t in out_terms), "high": high,
                       "scans": cur.execute(f"SELECT COUNT(*) FROM brand_scans {where}", args).fetchone()[0]},
            "sources": [{"name": n, **((json.loads(last["sources"]) if last else {}).get(n) or {"status": "not run"})} for n in SOURCE_NAMES],
            "last_scan": last["ts"] if last else None, "provenance": "REAL",
            "how": "Passive reads of public feeds and searches: certificate transparency, URLhaus, OpenPhish, news and public social feeds. "
                   "Hits are scored by explicit rules; new hits scoring 70 or more enter the audit trail as brand.hit."}
