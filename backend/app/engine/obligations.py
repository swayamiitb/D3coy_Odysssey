"""India's reporting and remediation clocks for one warning: the compliance overlay from the prior-art research.

Which clocks apply depends on the tier (a suspected compromise starts the incident-reporting clocks), the sector and
regulators of the organisation (RBI DAKSH for banks, SEBI CSCRF for market entities), whether the asset holds
personal data (DPDP Board) and whether the organisation is notified CII (NCIIPC). The regulator map is SIM and lives
in config/scoring.json; the hours are the published ones.
"""

from __future__ import annotations


def obligations(cfg: dict, org: dict, asset: dict, tier: str, deadline_hours: float | None, deadline_basis: str,
                kev_due: str | None = None) -> list[dict]:
    clocks, regs = cfg["reporting_clocks_hours"], cfg.get("regulated_entities", {}).get(org["id"], [])
    personal = asset.get("role") in set(cfg.get("personal_data_roles", []))
    csirt = cfg["sentinel"]["sector_csirt"].get(org.get("sector", ""), "CERT-In")
    out: list[dict] = []
    if tier == "Compromise":
        out.append({"who": "CERT-In", "what": "Report the incident (CERT-In Directions, 28 Apr 2022)",
                    "hours": clocks["certin_incident"], "route": "incident report; Odyssey pre-fills the form"})
        if "RBI" in regs:
            out.append({"who": "RBI", "what": "Report the cyber incident through DAKSH", "hours": clocks["rbi_daksh"],
                        "route": "RBI DAKSH portal"})
        if "SEBI" in regs:
            out.append({"who": "SEBI", "what": "Report the incident under the Cybersecurity and Cyber Resilience "
                                               "Framework (CSCRF)", "hours": clocks["sebi_cscrf"],
                        "route": "SEBI CSCRF, Market-SOC"})
        if personal:
            out.append({"who": "Data Protection Board", "what": "Intimate a personal-data breach (DPDP Act 2023, "
                                                                "Rules 2025) and inform affected people",
                        "hours": clocks["dpdp_board"], "route": f"this {asset.get('role')} system may hold personal data"})
        if org.get("cii"):
            out.append({"who": "NCIIPC", "what": "Notify: the organisation is notified critical information "
                                                 "infrastructure", "hours": None, "route": "NCIIPC incident desk"})
        out.append({"who": csirt, "what": "Notify the sector CSIRT", "hours": None, "route": "sector CSIRT"})
    elif deadline_hours is not None:
        out.append({"who": org.get("name", "the organisation"), "what": f"Patch or mitigate: {deadline_basis}",
                    "hours": deadline_hours, "route": "CERT-In Blueprint deadline (indicative)"})
    if kev_due:
        out.append({"who": "CISA (reference)", "what": f"KEV due date {kev_due} for US federal agencies, shown for "
                                                       f"reference", "hours": None, "route": "CISA KEV"})
    return out
