"""Supplier fan-out: an advisory or warning on a product that a shared service provider runs reaches every
organisation that depends on that provider, including those that do not run the product themselves (the C-Edge
lesson). The graph is SIM and lives in config/suppliers.json; the supplier's own versions are not visible to us, so
dependents are asked to confirm the supplier's patch status rather than told they are affected."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

PATH = Path(__file__).resolve().parents[3] / "config" / "suppliers.json"


@lru_cache(maxsize=1)
def graph() -> list[dict]:
    try:
        return json.loads(PATH.read_text(encoding="utf-8"))["suppliers"]
    except (OSError, ValueError, KeyError):
        return []


def reach(product_key: str | None, orgs: dict[str, dict], runs_it: set[str] | None = None) -> list[dict]:
    """Suppliers that run this product, with their dependents. runs_it: organisations that run the product themselves,
    so the fan-out can say how many are reached only through the supplier."""
    if not product_key:
        return []
    runs_it = runs_it or set()
    out = []
    for s in graph():
        if product_key not in s["runs"]:
            continue
        deps = [{"org_id": o, "name": orgs.get(o, {}).get("name", o), "sector": orgs.get(o, {}).get("sector"),
                 "runs_it_too": o in runs_it} for o in s["dependents"]]
        out.append({"id": s["id"], "name": s["name"], "service": s["service"], "provenance": "SIM",
                    "dependents": deps, "only_via_supplier": sum(1 for d in deps if not d["runs_it_too"])})
    return out


def of_org(org_id: str) -> list[dict]:
    """The suppliers an organisation depends on."""
    return [{"id": s["id"], "name": s["name"], "service": s["service"], "runs": s["runs"], "provenance": "SIM"}
            for s in graph() if org_id in s["dependents"]]
