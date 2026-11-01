"""A TAXII 2.1 server over Odyssey's STIX: discovery, one API root, three read-only collections.

Platforms that *pull* intelligence (a TIP, a SIEM's TAXII client, OpenCTI, MISP's TAXII feed) can subscribe to
Odyssey like any other producer. Collections: the intelligence graph (every entity and relationship), the indicators
(C2 and attack sources seen, phishing look-alikes, bulk-imported indicators that matched), and the vulnerabilities on
our exposed assets with their scores. Objects carry Odyssey's deterministic STIX ids, so a consumer sees updates to
the same object, not duplicates. Read-only; a bearer token applies when ODYSSEY_TAXII_TOKEN is set.
"""

from __future__ import annotations

import datetime as dt
import functools
import hmac
import json
import os
import sqlite3

from fastapi import APIRouter, HTTPException, Request, Response

from .engine.export import graph_stix, risk_list
from .engine.graph import intel_graph
from .engine.reports import PRODUCER, TLP, _sid, _stix_ts

router = APIRouter(prefix="/taxii2")
MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
ROOT = "odyssey"
connect = None        # set by main: a callable returning a sqlite3 connection
live_status = None    # set by main: a callable returning the live engine's status dict or None

COLLECTIONS = [
    {"id": "9c4a4f58-8a2e-5b1b-9a0e-0d6c4e2a0001", "alias": "graph", "title": "Odyssey intelligence graph",
     "description": "Every entity Odyssey knows about and how they connect: identities, infrastructure, software, vulnerabilities, "
                    "campaigns, attack patterns, malware, intrusion sets (overlap with ATT&CK, not attribution), indicators, sightings, relationships."},
    {"id": "9c4a4f58-8a2e-5b1b-9a0e-0d6c4e2a0002", "alias": "indicators", "title": "Odyssey indicators",
     "description": "C2 addresses seen in telemetry, HTTP attack sources, global attack sources on our ports, phishing look-alikes, and bulk-imported "
                    "indicators that matched our telemetry or exposure. Each indicator carries its score and provenance."},
    {"id": "9c4a4f58-8a2e-5b1b-9a0e-0d6c4e2a0003", "alias": "vulnerabilities", "title": "Odyssey vulnerabilities",
     "description": "Vulnerabilities version-verified on the constituency's exposed assets, with Odyssey's risk score, tier, KEV, SSVC and EPSS facts."},
]


def _db() -> sqlite3.Connection:
    if connect is None:
        raise HTTPException(503, "TAXII not wired")
    return connect()


def _live() -> dict | None:
    try:
        return live_status() if live_status else None
    except Exception:  # noqa: BLE001
        return None


def _auth(request: Request) -> None:
    token = os.environ.get("ODYSSEY_TAXII_TOKEN")
    if not token:
        return
    scheme, _, given = (request.headers.get("authorization") or "").strip().partition(" ")
    # RFC 7235: the scheme is case-insensitive; the comparison is constant-time so the token cannot be timed out
    if scheme.lower() != "bearer" or not hmac.compare_digest(given.strip().encode(), token.encode()):
        raise HTTPException(401, "bearer token required", headers={"WWW-Authenticate": "Bearer"})


def _accept(request: Request) -> None:
    """TAXII 2.1 content negotiation: a client that asks only for media types we cannot serve gets 406."""
    raw = request.headers.get("accept")
    if not raw:
        return
    for part in raw.split(","):
        mt, *params = [b.strip() for b in part.split(";")]
        version = dict(p.split("=", 1) for p in params if "=" in p).get("version", "2.1").strip().strip('"')
        if mt.lower() in ("*/*", "application/*", "application/json") or (mt.lower() == "application/taxii+json" and version == "2.1"):
            return
    raise HTTPException(406, f"this server speaks {MEDIA}")


def _gate(request: Request) -> None:
    _auth(request)
    _accept(request)


def _resp(body: dict, status: int = 200, headers: dict | None = None) -> Response:
    return Response(content=json.dumps(body, ensure_ascii=False), status_code=status, media_type=MEDIA, headers=headers or {})


def _taxii(fn):
    """Errors leave as TAXII error messages (title, http_status) with the TAXII media type, not as framework JSON."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except HTTPException as exc:
            return _resp({"title": str(exc.detail), "http_status": str(exc.status_code)}, exc.status_code, exc.headers)
    return wrapper


def _collection(cid: str) -> dict:
    for c in COLLECTIONS:
        if cid in (c["id"], c["alias"]):
            return c
    raise HTTPException(404, "unknown collection")


def _parse_ts(s: str) -> dt.datetime:
    """An RFC 3339 timestamp as an aware datetime. A naive one is UTC (NVD, DShield and ISO dates carry no zone); a '+'
    that URL decoding turned into a space is restored. Raises ValueError on anything else."""
    s = str(s).strip()
    if len(s) > 10 and s[10] == " ":
        s = s[:10] + "T" + s[11:]
    s = s.replace(" ", "+")
    if s[-1:] in ("z", "Z"):
        s = s[:-1] + "+00:00"
    t = dt.datetime.fromisoformat(s)
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def _ts(iso: str | None) -> str:
    """A STIX timestamp from whatever the record holds; unparseable input falls back to the project epoch, never a 500."""
    if not iso:
        return _stix_ts(None)
    try:
        return _stix_ts(_parse_ts(iso).isoformat())
    except ValueError:
        return _stix_ts(None)


def _lit(value: str) -> str:
    """A STIX pattern string literal body: backslash and quote escaped, so a hostile value cannot break the pattern."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _indicator_objects(conn: sqlite3.Connection, live: dict | None) -> list[dict]:
    now = _stix_ts(dt.datetime.now(dt.timezone.utc).isoformat())
    base = {"spec_version": "2.1", "created_by_ref": PRODUCER["id"], "object_marking_refs": [TLP["AMBER"]]}
    out = {PRODUCER["id"]: dict(PRODUCER)}
    for r in risk_list(conn, "ips", live):
        o = {**base, "type": "indicator", "id": _sid("indicator", "ip", r["value"]), "created": now, "modified": now,
             "name": f"{r['role'].replace('_', ' ')}: {r['defanged']}" + (f" ({r['malware']})" if r.get("malware") else ""),
             "indicator_types": ["malicious-activity"], "pattern": f"[ipv4-addr:value = '{_lit(r['value'])}']", "pattern_type": "stix",
             "valid_from": _ts(r.get("first_seen")) if r.get("first_seen") else now, "confidence": int(r["score"]),
             "description": f"{r['evidence']}. Source: {r['source']}. Provenance: {r['provenance']}.", "labels": [r["role"], r["provenance"]]}
        out[o["id"]] = o
    for r in risk_list(conn, "domains", live):
        o = {**base, "type": "indicator", "id": _sid("indicator", "domain", r["value"]), "created": now, "modified": now,
             "name": f"phishing look-alike of {r['impersonates']}: {r['value']}", "indicator_types": ["malicious-activity"],
             "pattern": f"[domain-name:value = '{_lit(r['value'])}']", "pattern_type": "stix", "valid_from": now, "confidence": int(r["score"]),
             "description": f"{r['evidence']}. Source: {r['source']}. Provenance: {r['provenance']}.", "labels": [r["role"], r["provenance"]]}
        out[o["id"]] = o
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'iocs'").fetchone():
        cur = conn.cursor()
        cur.row_factory = sqlite3.Row
        for r in cur.execute("SELECT * FROM iocs WHERE matched = 1"):
            v = _lit(r["value"])
            pat = {"ipv4-addr": f"[ipv4-addr:value = '{v}']", "domain-name": f"[domain-name:value = '{v}']",
                   "url": f"[url:value = '{v}']", "file:sha256": f"[file:hashes.'SHA-256' = '{v}']",
                   "file:sha1": f"[file:hashes.'SHA-1' = '{v}']", "file:md5": f"[file:hashes.MD5 = '{v}']"}.get(r["type"])
            if not pat:
                continue
            matches = json.loads(r["matches"] or "[]")
            o = {**base, "type": "indicator", "id": _sid("indicator", "imported", r["type"], r["value"]), "created": _ts(r["added_at"]),
                 "modified": _ts(r["last_seen"] or r["added_at"]), "name": f"imported {r['type']} {r['defanged']} ({r['source']})",
                 "indicator_types": ["malicious-activity"], "pattern": pat, "pattern_type": "stix", "valid_from": _ts(r["first_seen"] or r["added_at"]),
                 "confidence": {"Critical": 90, "High": 75, "Medium": 50}.get(r["severity"] or "", 40),
                 "description": "Matched in Odyssey: " + "; ".join(f"{m['where']}: {m['detail']}" for m in matches[:4]), "labels": ["imported", r["tlp"]]}
            out[o["id"]] = o
    return list(out.values())


def _vulnerability_objects(conn: sqlite3.Connection, live: dict | None) -> list[dict]:
    now = _stix_ts(dt.datetime.now(dt.timezone.utc).isoformat())
    base = {"spec_version": "2.1", "created_by_ref": PRODUCER["id"], "object_marking_refs": [TLP["AMBER"]]}
    out = [dict(PRODUCER)]
    for r in risk_list(conn, "cves", live):
        flags = [x for x, on in (("exploited in the wild (CISA KEV)", r["kev"]), ("day-0 forecast flag", r["forecast_flag"])) if on]
        out.append({**base, "type": "vulnerability", "id": _sid("vulnerability", f"cve:{r['cve']}"), "created": _ts(r["published"]) if r["published"] else now,
                    "modified": now, "name": r["cve"], "external_references": [{"source_name": "cve", "external_id": r["cve"]}],
                    "description": f"Odyssey risk {r['score']:.0f}/100, tier {r['tier']}, {r['assets']} exposed asset(s) at {r['orgs']} organisation(s)"
                                   f"{', deadline ' + str(r['deadline_hours']) + ' h' if r['deadline_hours'] is not None else ''}. "
                                   f"{'; '.join(flags) + '. ' if flags else ''}EPSS {r['epss']}. SSVC exploitation {r['ssvc_exploitation']}. Provenance: {r['provenance']}.",
                    "x_odyssey_risk": r["score"], "x_odyssey_tier": r["tier"], "x_odyssey_kev": r["kev"], "x_odyssey_epss": r["epss"],
                    "x_odyssey_deadline_hours": r["deadline_hours"]})
    return out


def objects_for(alias: str) -> list[dict]:
    conn, live = _db(), _live()
    if alias == "graph":
        return graph_stix(intel_graph(conn, None, live))["objects"]
    if alias == "indicators":
        return _indicator_objects(conn, live)
    return _vulnerability_objects(conn, live)


def _date_added(o: dict) -> str:
    return o.get("modified") or o.get("created") or PRODUCER["modified"]


@router.get("/")
@_taxii
def discovery(request: Request) -> Response:
    _gate(request)
    return _resp({"title": "Odyssey TAXII 2.1", "description": "National cyber threat early warning for India's critical infrastructure, as STIX 2.1. Read-only.",
                  "contact": "Team Odyssey (D3COY 1.0, PS-01)", "default": f"/taxii2/{ROOT}/", "api_roots": [f"/taxii2/{ROOT}/"]})


@router.get(f"/{ROOT}/")
@_taxii
def api_root(request: Request) -> Response:
    _gate(request)
    return _resp({"title": "Odyssey", "description": "The intelligence graph, the indicators and the vulnerabilities, each as a collection.",
                  "versions": [MEDIA], "max_content_length": 10485760})


@router.get(f"/{ROOT}/collections/")
@_taxii
def collections(request: Request) -> Response:
    _gate(request)
    return _resp({"collections": [{"id": c["id"], "title": c["title"], "description": c["description"], "alias": c["alias"],
                                   "can_read": True, "can_write": False, "media_types": [STIX_MEDIA]} for c in COLLECTIONS]})


@router.get(f"/{ROOT}/collections/{{cid}}/")
@_taxii
def collection(cid: str, request: Request) -> Response:
    _gate(request)
    c = _collection(cid)
    return _resp({"id": c["id"], "title": c["title"], "description": c["description"], "alias": c["alias"], "can_read": True, "can_write": False,
                  "media_types": [STIX_MEDIA]})


def _values(q, key: str) -> set[str]:
    """A match[] filter's values: comma-separated and/or repeated, per TAXII 2.1."""
    return {v for v in ",".join(q.getlist(key)).split(",") if v}


def _filter(q, objs: list[dict]) -> list[dict]:
    """added_after and the match[] filters, in the collection's order (date_added ascending, id as the tie-break)."""
    added_after = q.get("added_after")
    try:
        after = _stix_ts(_parse_ts(added_after).isoformat()) if added_after else None
        versions = _values(q, "match[version]")
        wanted = None if not versions or versions & {"first", "last", "all"} else {_stix_ts(_parse_ts(v).isoformat()) for v in versions}
    except ValueError as exc:
        raise HTTPException(400, "added_after and match[version] must be RFC 3339 timestamps") from exc
    types, ids, specs = _values(q, "match[type]"), _values(q, "match[id]"), _values(q, "match[spec_version]")
    rows = [o for o in objs if (not after or _date_added(o) > after) and (not types or o["type"] in types) and (not ids or o["id"] in ids)
            and (not specs or o.get("spec_version") in specs) and (wanted is None or _date_added(o) in wanted)]
    rows.sort(key=lambda o: (_date_added(o), o["id"]))
    return rows


def _page(request: Request, objs: list[dict]) -> tuple[list[dict], bool, str | None]:
    q = request.query_params
    rows = _filter(q, objs)
    try:
        limit = max(1, min(int(q.get("limit", 100)), 1000))
        start = int(q.get("next", 0))
    except ValueError as exc:
        raise HTTPException(400, "limit and next must be integers") from exc
    if start < 0:
        raise HTTPException(400, "next must be a value this server returned")
    page = rows[start:start + limit]
    more = start + limit < len(rows)
    return page, more, str(start + limit) if more else None


def _added_headers(page: list[dict]) -> dict:
    return {"X-TAXII-Date-Added-First": _date_added(page[0]), "X-TAXII-Date-Added-Last": _date_added(page[-1])} if page else {}


@router.get(f"/{ROOT}/collections/{{cid}}/objects/")
@_taxii
def objects(cid: str, request: Request) -> Response:
    _gate(request)
    c = _collection(cid)
    page, more, nxt = _page(request, objects_for(c["alias"]))
    body = {"more": more, "objects": page}
    if nxt:
        body["next"] = nxt
    return _resp(body, headers=_added_headers(page))


@router.get(f"/{ROOT}/collections/{{cid}}/manifest/")
@_taxii
def manifest(cid: str, request: Request) -> Response:
    _gate(request)
    c = _collection(cid)
    page, more, nxt = _page(request, objects_for(c["alias"]))
    body = {"more": more, "objects": [{"id": o["id"], "date_added": _date_added(o), "version": _date_added(o), "media_type": STIX_MEDIA} for o in page]}
    if nxt:
        body["next"] = nxt
    return _resp(body, headers=_added_headers(page))


@router.get(f"/{ROOT}/collections/{{cid}}/objects/{{object_id}}/")
@_taxii
def one_object(cid: str, object_id: str, request: Request) -> Response:
    _gate(request)
    c = _collection(cid)
    hit = _filter(request.query_params, [o for o in objects_for(c["alias"]) if o["id"] == object_id])
    if not hit:
        raise HTTPException(404, "unknown object")
    return _resp({"more": False, "objects": hit}, headers=_added_headers(hit))


@router.get(f"/{ROOT}/collections/{{cid}}/objects/{{object_id}}/versions/")
@_taxii
def versions(cid: str, object_id: str, request: Request) -> Response:
    _gate(request)
    c = _collection(cid)
    hit = [o for o in objects_for(c["alias"]) if o["id"] == object_id]
    if not hit:
        raise HTTPException(404, "unknown object")
    return _resp({"more": False, "versions": [_date_added(hit[0])]}, headers=_added_headers(hit[:1]))
