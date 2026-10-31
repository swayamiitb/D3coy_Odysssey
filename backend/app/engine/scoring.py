"""Glass-box risk scoring and SSVC-style decisions.

Pure function of (vulnerability evidence, asset context, exposure) + config/scoring.json:
  L  likelihood     = max(evidence floors from named rules, EPSS)
  S  severity       = 1.0 if SSVC Technical Impact = total, else normalised CVSS impact
  V  confidence     = noisy-OR over independent origins, weighted by Admiralty reliability
  R  relevance      = exposure reconciliation (0 = cleared)
  K  asset context  = criticality/5 * exposure multiplier * blast-radius multiplier
  Risk = min(100, 100 * R * K * (wL*L + wS*S + wV*V))
Tier comes from the SSVC decision path, not from score thresholds; the score orders the queue.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import cvss
from .bayes import posterior

CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "scoring.json"
_ITW = re.compile(r"exploited in the wild|actively exploited|active exploitation|has been exploited|"
                  r"exploitation in the wild|limited number of customers", re.I)
OT_ROLES = {"ot-hmi", "ot-scada"}
_ORDER = {"Track": 0, "Track*": 1, "Attend": 2, "Act": 3}


@functools.lru_cache(maxsize=1)
def config() -> tuple[dict, str]:
    raw = CONFIG_PATH.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()[:16]


@dataclass
class Rule:
    id: str
    crit: int
    text: str
    evidence: str
    source: str


@dataclass
class Assessment:
    asset_id: str
    cve_id: str
    L: float
    S: float
    V: float
    R: float
    K: float
    risk: float
    tier: str
    decision: str
    decision_path: list[str]
    rules: list[Rule]
    contributions: dict
    deadline_hours: int | None
    deadline_basis: str
    kev_due: str | None
    config_hash: str
    inputs: dict = field(default_factory=dict)
    bayes: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _rule(rule_id: str, evidence: str, source: str) -> Rule:
    spec = next(r for r in config()[0]["likelihood_rules"] if r["id"] == rule_id)
    return Rule(rule_id, spec["crit"], spec["text"], evidence, source)


def _floor(rule_id: str) -> float:
    return next(r["floor"] for r in config()[0]["likelihood_rules"] if r["id"] == rule_id)


def assess(vuln: dict, asset: dict, org: dict, exposure, signals: dict | None = None) -> Assessment:
    """vuln: id, description, ssvc{}, kev{} | None, epss float | None, cvss_vector, cvss_source.
    asset: id, tier, zone, role, tier1_reachable. exposure: engine.exposure.Exposure.
    signals: optional live evidence, e.g. {"decoy_exploit": n_sensors, "decoy_surge": z, "ioc_sighting": {...}}."""
    cfg, cfg_hash = config()
    signals = signals or {}
    rules: list[Rule] = []
    ssvc = vuln.get("ssvc") or {}
    vec = cvss.parse(vuln.get("cvss_vector"))

    # ---- likelihood: named rules set an evidence floor (Recorded Future pattern)
    if vuln.get("kev"):
        k = vuln["kev"]
        rules.append(_rule("KEV", f"added {k['dateAdded']}, due {k['dueDate']}", "CISA_KEV"))
    if ssvc.get("Exploitation") == "active":
        rules.append(_rule("SSVC_ACTIVE", "Exploitation=active", "CISA_ADP"))
    if signals.get("decoy_exploit", 0) >= 2:
        rules.append(_rule("DECOY_EXPLOIT", f"{signals['decoy_exploit']} sensors saw exploit payloads", "DECOY_GRID"))
    itw = _ITW.search(vuln.get("description", ""))
    if itw:
        rules.append(_rule("ITW_CLAIM", f'"…{itw.group(0)}…"', "CNA"))
    if ssvc.get("Exploitation") == "poc":
        rules.append(_rule("SSVC_POC", "Exploitation=poc", "CISA_ADP"))
    if signals.get("decoy_surge"):
        rules.append(_rule("DECOY_SURGE", f"robust z={signals['decoy_surge']:.1f}", "DECOY_GRID"))
    epss = vuln.get("epss")
    if epss is not None and epss >= 0.5:
        rules.append(_rule("EPSS_HIGH", f"EPSS={epss:.3f}", "EPSS"))
    automatable = ssvc.get("Automatable") or ("yes" if vec and cvss.automatable_proxy(vec) else "no")
    if automatable == "yes":
        rules.append(_rule("AUTOMATABLE", f"Automatable=yes ({'CISA ADP' if ssvc.get('Automatable') else 'CVSS proxy'})",
                           "CISA_ADP" if ssvc.get("Automatable") else "CNA"))
    if vec and cvss.base_score(vec) >= 9.0:
        rules.append(_rule("CVSS_CRIT", f"base {cvss.base_score(vec)}", vuln.get("cvss_source", "CNA")))
    floor = max([_floor(r.id) for r in rules] + [0.0])
    L = round(max(floor, epss or 0.0), 3)

    # ---- severity / impact (never from the LLM)
    tech_impact = ssvc.get("Technical Impact") or ("total" if vec and vec["C"] == "H" and vec["I"] == "H" else "partial")
    if ssvc.get("Technical Impact") == "total":
        S = cfg["impact"]["ssvc_total"]
    elif vec:
        S = cvss.impact_norm(vec)
    else:
        S = cfg["impact"]["unknown_default"]
    if asset.get("role") in OT_ROLES:
        S = max(S, cfg["impact"]["ot_safety_min"])

    # ---- confidence: noisy-OR over independent origins (max reliability per origin)
    rel, origin = cfg["source_reliability"], cfg["independent_origins"]
    weights: dict[str, float] = {}
    sources = {r.source for r in rules} | {v.source if v.source != "TEXT" else "CNA" for v in exposure.votes
                                          if v.verdict == "affected"}
    if epss is not None:
        sources.add("EPSS")
    if signals.get("ioc_sighting"):
        sources.add("SIM_LOGS")
    for s in sources:
        o = origin.get(s, s)
        weights[o] = max(weights.get(o, 0.0), cfg["admiralty_weight"][rel.get(s, "C")])
    V = 1.0
    for w in weights.values():
        V *= 1 - w
    V = round(1 - V, 3) if weights else 0.0

    # ---- asset context
    ac = cfg["asset_context"]
    crit = ac["criticality_by_tier"][str(asset["tier"])]
    if org.get("cii"):
        crit = max(crit, ac["cii_min_criticality"]) if asset["tier"] <= 2 else crit
    network_reachable = (vec or {}).get("AV", "N") == "N" or bool(vuln.get("chained_network"))
    X = ac["exposure"][asset["zone"]] if network_reachable else 1.0
    B = min(ac["blast_radius"]["max"], 1 + ac["blast_radius"]["per_tier1_reachable"] * asset.get("tier1_reachable", 0))
    # Normalise to [0, 1] so the score keeps ranking resolution instead of saturating at 100.
    k_max = max(ac["exposure"].values()) * ac["blast_radius"]["max"]
    K = round(crit / 5 * X * B / k_max, 3)

    R = exposure.relevance
    w = cfg["risk"]["weights"]
    inner = w["L"] * L + w["S"] * S + w["V"] * V
    risk = round(min(100.0, 100 * R * K * inner), 1)
    contributions = {"likelihood": round(100 * R * K * w["L"] * L, 1), "severity": round(100 * R * K * w["S"] * S, 1),
                     "evidence": round(100 * R * K * w["V"] * V, 1)}

    # ---- SSVC-style decision (tier from the path, not the number)
    exploitation = ("active" if any(r.id in {"KEV", "SSVC_ACTIVE", "DECOY_EXPLOIT", "ITW_CLAIM"} for r in rules)
                    else "poc" if any(r.id == "SSVC_POC" for r in rules) else "none")
    exposure_ssvc = {"internet": "open", "dmz": "controlled", "internal": "small"}[asset["zone"]]
    mission = "high" if crit >= 4 else "low"
    path = [f"Exploitation={exploitation}", f"Automatable={automatable}", f"TechnicalImpact={tech_impact}",
            f"Exposure={exposure_ssvc}", f"Mission={mission}"]
    if R == 0:
        decision = "Track"
        path.append("not affected (cleared)")
    elif exploitation == "active":
        decision = "Act" if (exposure_ssvc == "open" or automatable == "yes" or
                             (mission == "high" and tech_impact == "total")) else "Attend"
    elif exploitation == "poc":
        decision = ("Attend" if exposure_ssvc == "open" and automatable == "yes" and tech_impact == "total"
                    else "Track*" if mission == "high" else "Track")
    else:
        decision = ("Attend" if exposure_ssvc == "open" and automatable == "yes" and mission == "high"
                    else "Track*" if tech_impact == "total" and mission == "high" else "Track")
    unverified = exposure.status == "unknown"
    if unverified and _ORDER[decision] > _ORDER["Track*"]:
        decision = "Track*"
        path.append("exposure unverified (product match, no version evidence) -> verify installed version")
    tier = cfg["ssvc_tiers"][decision]

    # ---- India deadlines (CERT-In Blueprint, indicative)
    dl = cfg["deadlines_hours"]
    kev_or_active = exploitation == "active"
    if R == 0:
        hours, basis = None, "not affected"
    elif unverified and decision == "Track":
        hours, basis = None, "monitor (pre-disclosure / unverified exposure)"
    elif unverified:
        hours, basis = ((dl["critical_external_or_kev_internal"], "Verify exposure: known-exploited, version unknown")
                        if kev_or_active else (dl["medium"], "Verify exposure"))
    elif kev_or_active and (asset["zone"] == "internet" or asset["tier"] == 1):
        hours, basis = dl["kev_internet_or_crown"], "Known-exploited on internet-facing / crown-jewel asset"
    elif tier == "Critical" or kev_or_active:
        external = asset["zone"] in {"internet", "dmz"}
        hours, basis = ((dl["critical_external_or_kev_internal"], "Critical external, or known-exploited internal")
                        if external or kev_or_active else
                        (dl["critical_internal_high_value"], "Critical internal, high-value"))
    elif tier == "High":
        hours, basis = dl["high"], "High severity"
    elif tier == "Medium":
        hours, basis = dl["medium"], "Medium (programme default)"
    else:
        hours, basis = None, "monitor"

    # ---- decision model: Bayesian P(compromise | exposure, exploitation, reachability, telemetry)
    sighting = signals.get("ioc_sighting")
    bayes = posterior(cfg, exposed=R >= 0.6, exploited=exploitation == "active", internet=asset["zone"] == "internet",
                      beacon=True if sighting else None, anomaly=signals.get("anomaly"))
    if sighting:
        rules.append(Rule("IOC_SIGHTING", 4, "Own telemetry: periodic beacon to a known C2 address",
                          f"{sighting.get('connections')} connections every ~{sighting.get('mean_interval_s')}s",
                          "SIM_LOGS"))
    if bayes["decision"] == "compromised":
        comp = cfg["compromise"]
        tier, decision, hours, basis = comp["tier"], "Act", comp["deadline_hours"], comp["basis"]
        path.append(f"Bayesian model: P(compromise) = {bayes['p_compromise']:.1%} >= "
                    f"{cfg['bayes']['threshold_compromise']:.0%} -> suspected compromise")
    elif bayes["decision"] == "hunt":
        path.append(f"Bayesian model: P(compromise) = {bayes['p_compromise']:.1%} -> threat hunt recommended")

    return Assessment(
        asset_id=asset["id"], cve_id=vuln["id"], L=L, S=round(S, 3), V=V, R=R, K=K, risk=risk, tier=tier,
        decision=decision, decision_path=path, rules=sorted(rules, key=lambda r: -r.crit),
        contributions=contributions, deadline_hours=hours, deadline_basis=basis,
        kev_due=(vuln.get("kev") or {}).get("dueDate"), config_hash=cfg_hash,
        inputs={"epss": epss, "cvss_vector": vuln.get("cvss_vector"), "crit": crit, "X": X, "B": round(B, 3),
                "zone": asset["zone"], "tier": asset["tier"]},
        bayes=bayes,
    )
