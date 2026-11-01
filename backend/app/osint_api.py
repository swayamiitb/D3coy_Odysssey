"""OSINT endpoints: brand and social monitoring, and consented owned-asset surface self-assessment.

The router is included by main.py, which sets `osint_api.connect` to the application's `db` factory so this module
never imports main (that would be circular). Every handler opens its own short-lived connection.
"""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Body, HTTPException

from .engine import brand, surface

router = APIRouter()
connect: Callable | None = None


def _db():
    if connect is None:
        raise HTTPException(503, "database not wired")
    return connect()


# --------------------------------------------------------------------------------------------------------- brand
@router.get("/api/brand")
def brand_summary(org_id: str | None = None) -> dict:
    """What public, passive monitoring has found impersonating or discussing a brand or an organisation."""
    conn = _db()
    try:
        brand.ensure(conn)
        return brand.summary(conn, org_id)
    finally:
        conn.close()


@router.post("/api/brand/scan")
def brand_scan(body: dict = Body(default={})) -> dict:
    """Run every source for a term, or for every term of an organisation. Reads public feeds; never raises on an outage."""
    term, org_id = body.get("term"), body.get("org_id")
    if not term and not org_id:
        raise HTTPException(400, "term or org_id is required")
    conn = _db()
    try:
        return brand.scan(conn, term=term, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(404, "unknown organisation") from exc
    finally:
        conn.close()


@router.get("/api/brand/hits")
def brand_hits(term: str | None = None, org_id: str | None = None, limit: int = 100, kind: str | None = None) -> dict:
    conn = _db()
    try:
        brand.ensure(conn)
        return {"term": term, "org_id": org_id, "rows": brand.hits(conn, term=term, org_id=org_id, limit=limit, kind=kind)}
    finally:
        conn.close()


# ------------------------------------------------------------------------------------------------------- surface
@router.post("/api/surface/scan")
def surface_scan(body: dict = Body(default={})) -> dict:
    """Self-assess an application you own (private address or an app your agent registered). Refuses anything else."""
    url = (body.get("url") or "").strip()
    if not url:
        raise HTTPException(400, "url is required")
    consent = bool(body.get("consent"))
    conn = _db()
    try:
        result = surface.scan(conn, url, consent, org_id=body.get("org_id"))
    finally:
        conn.close()
    if result["status"] in ("refused", "unreachable"):
        raise HTTPException(400, result["reason"])
    return result


@router.get("/api/surface")
def surface_latest(org_id: str | None = None, limit: int = 10) -> dict:
    conn = _db()
    try:
        surface.ensure(conn)
        return {"org_id": org_id, "scans": surface.latest(conn, org_id=org_id, limit=limit),
                "how": "Odyssey assesses only systems you own, over GET/HEAD, no payloads. Every finding carries a CWE, a fix and the evidence."}
    finally:
        conn.close()


@router.get("/api/surface/can-scan")
def surface_can_scan(url: str) -> dict:
    """Whether a target would be accepted, and why, without scanning it (for the UI to enable or disable the button)."""
    conn = _db()
    try:
        ok, reason = surface.allowed(url, conn)
    finally:
        conn.close()
    return {"url": url, "allowed": ok, "reason": reason}


@router.get("/api/surface/{scan_id}")
def surface_get(scan_id: int) -> dict:
    conn = _db()
    try:
        surface.ensure(conn)
        return surface.get(conn, scan_id)
    except KeyError as exc:
        raise HTTPException(404, "unknown scan") from exc
    finally:
        conn.close()
