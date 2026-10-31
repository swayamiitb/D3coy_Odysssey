"""CVSS v3.1 helpers (FIRST specification weights)."""

from __future__ import annotations

import math

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_ISS_MAX = 1 - (1 - 0.56) ** 3  # 0.9148


def parse(vector: str | None) -> dict | None:
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        return dict(part.split(":") for part in vector.split("/")[1:])
    except ValueError:
        return None


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def iss(v: dict) -> float:
    return 1 - (1 - _W["CIA"][v["C"]]) * (1 - _W["CIA"][v["I"]]) * (1 - _W["CIA"][v["A"]])


def impact_norm(v: dict) -> float:
    """Normalised impact in [0, 1] from the C/I/A sub-metrics."""
    return round(iss(v) / _ISS_MAX, 3)


def base_score(v: dict) -> float:
    changed = v["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[v["PR"]]
    s = iss(v)
    impact = 7.52 * (s - 0.029) - 3.25 * (s - 0.02) ** 15 if changed else 6.42 * s
    exploit = 8.22 * _W["AV"][v["AV"]] * _W["AC"][v["AC"]] * pr * _W["UI"][v["UI"]]
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploit), 10)) if changed else _roundup(min(impact + exploit, 10))


def automatable_proxy(v: dict) -> bool:
    """CISA's ADP 'Automatable' proxy until ADP data arrives: network, low complexity, no privileges, no user."""
    return v.get("AV") == "N" and v.get("AC") == "L" and v.get("PR") == "N" and v.get("UI") == "N"
