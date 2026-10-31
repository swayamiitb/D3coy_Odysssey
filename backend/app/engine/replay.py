"""Deterministic replay: re-score one (asset, CVE) as of every evidence event, in time order.

This is what makes the warning *early* and auditable: each step shows which event arrived, whether it is REAL
(public record) or SIM (simulated telemetry), and how tier, risk and deadline changed as a result.
"""

from __future__ import annotations

import copy

from .exposure import Exposure, reconcile
from .scoring import assess


def defang(ip: str) -> str:
    return ip.replace(".", "[.]")


_LABELS = {
    "decoy.surge": lambda p, c, h: f"Decoy grid: scanning surge on {p['tag']} (z={p['z_sessions']}, {p['sensors']} sensors)",
    "vuln.published": lambda p, c, h: f"CVE published by the vendor (CNA), CVSS vector {p.get('cvss_vector') or 'n/a'}",
    "ssvc.updated": lambda p, c, h: f"CISA SSVC: Exploitation={p.get('Exploitation')}, Automatable={p.get('Automatable')}",
    "kev.added": lambda p, c, h: f"Added to CISA KEV (due {p.get('dueDate')})",
    "decoy.exploit": lambda p, c, h: f"Decoy grid: exploit payloads for {c} on {p['sensors']} sensors",
    "ioc.sighting": lambda p, c, h: (f"Firewall logs: {p['connections']} beacons every ~{p['mean_interval_s']}s from "
                                     f"{h} to {p['dst_defanged']} ({p['malware']} C2, {p['c2_source']})"),
}


def evidence(ledger, cve_id: str, asset: dict) -> list[dict]:
    """Every evidence event relevant to one (asset, CVE), labelled for people: the CVE's own record, scanning
    surges on the asset's product, and C2 sightings on the asset itself."""
    events = (ledger.events(subject=cve_id) + ledger.events(subject=f"product:{asset['product_key']}", kind="decoy.surge")
              + ledger.events(subject=asset["id"], kind="ioc.sighting"))
    return [{**ev, "label": _LABELS[ev["kind"]](ev["payload"], cve_id, asset["hostname"])}
            for ev in events if ev["kind"] in _LABELS]


def replay(rec: dict, asset: dict, org: dict, events: list[dict]) -> list[dict]:
    """events: dicts with ts, kind, provenance, label and payload, from the ledger and the detectors.
    kinds used: decoy.surge, vuln.published, kev.added, ssvc.updated, decoy.exploit, ioc.sighting."""
    state = {"published": False, "kev": None, "ssvc": {}, "surge": None, "exploit": 0, "sighting": None}
    steps = []
    for ev in sorted(events, key=lambda e: e["ts"]):
        kind, p = ev["kind"], ev.get("payload", {})
        if kind == "decoy.surge":
            state["surge"] = p.get("z_sessions")
        elif kind == "vuln.published":
            state["published"] = True
        elif kind == "kev.added":
            state["kev"] = rec.get("kev")
        elif kind == "ssvc.updated":
            state["ssvc"] = rec.get("ssvc") or p
        elif kind == "decoy.exploit":
            state["exploit"] = p.get("sensors", 2)
        elif kind == "ioc.sighting":
            state["sighting"] = p

        signals = {"decoy_surge": state["surge"], "decoy_exploit": state["exploit"],
                   "ioc_sighting": state["sighting"]}
        if not state["published"]:
            # Pre-disclosure: no CVE yet. The product is under coordinated reconnaissance -> Watch.
            stub = {"id": rec["id"], "description": "", "ssvc": {}, "kev": None, "epss": None,
                    "cvss_vector": None, "cvss_source": None}
            exposure = Exposure(asset["id"], rec["id"], "unknown", 0.3, [])
            a = assess(stub, asset, org, exposure, signals)
            label = "pre-disclosure warning"
        else:
            snap = copy.deepcopy(rec)
            snap["kev"], snap["ssvc"], snap["epss"] = state["kev"], state["ssvc"], None  # no EPSS history offline
            snap["nvd_configurations"] = []  # NVD analysis arrived later; use CNA + text as at publication
            exposure = reconcile(asset, snap)
            a = assess(snap, asset, org, exposure, signals)
            label = a.tier
        steps.append({
            "ts": ev["ts"], "kind": kind, "provenance": ev.get("provenance", "REAL"), "event": ev.get("label", kind),
            "tier": a.tier, "risk": a.risk, "decision": a.decision, "deadline_hours": a.deadline_hours,
            "deadline_basis": a.deadline_basis, "rules": [r.id for r in a.rules], "exposure": exposure.status,
            "stage": label,
        })
    return steps
