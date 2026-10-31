"""Outbound artefacts for an alert: a CERT-In incident-report draft and a STIX 2.1 bundle.

Both are deterministic transforms of the alert detail and the ledger. AI text, if present, is included only as
a machine opinion clearly attributed to the local model. Nothing is sent anywhere; the analyst downloads and files.
"""

from __future__ import annotations

import datetime as dt
import uuid

NS = uuid.UUID("5c1d3c0a-1d3c-4d3c-8d3c-0d3c0a1d3c0a")  # stable namespace -> reproducible STIX ids
TLP = {  # STIX 2.1 TLP v1 marking-definition ids
    "WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
ADMIRALTY_TO_STIX = {"A": 90, "B": 70, "C": 50, "D": 30, "E": 10}
PRODUCER = {"type": "identity", "spec_version": "2.1", "id": "identity--" + str(uuid.uuid5(NS, "d3coy-ncew")),
            "created": "2026-10-31T00:00:00.000Z", "modified": "2026-10-31T00:00:00.000Z",
            "name": "D3COY National Cyber Early Warning (prototype)", "identity_class": "system"}

# CERT-In Directions (28 Apr 2022), Annexure I incident categories used by this system.
CERTIN_TYPES = {
    "compromise": "Compromise of critical systems/information",
    "unauthorised": "Unauthorised access of IT systems/data",
    "malicious_code": "Malicious code attacks (virus/worm/Trojan/bots/spyware/ransomware/cryptominers)",
    "network_device": "Attack on servers (database, mail, DNS) and network devices such as routers",
    "critical_infra": "Attacks on critical infrastructure, SCADA and operational technology systems",
    "scanning": "Targeted scanning/probing of critical networks/systems",
}


def _sid(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, '|'.join(parts))}"


def _stix_ts(iso: str | None) -> str:
    if not iso:
        return "2026-10-31T00:00:00.000Z"
    t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def certin_report(detail: dict, sighting: dict | None, workflow: dict | None, brief: dict | None) -> dict:
    org, v, a = detail["org"], detail["vulnerability"], detail["assets"][0]
    compromised = a["tier"] == "Compromise"
    types = [CERTIN_TYPES["compromise"] if compromised else CERTIN_TYPES["unauthorised"]]
    if sighting:
        types.append(CERTIN_TYPES["malicious_code"])
    if a["role"] in {"vpn", "firewall", "adc", "mail-gateway"}:
        types.append(CERTIN_TYPES["network_device"])
    if org["sector"] == "Power & Energy" or a["role"].startswith("ot-"):
        types.append(CERTIN_TYPES["critical_infra"])
    detected = sighting["confirmed_at"] if sighting else detail["timeline"][-1]["ts"] if detail["timeline"] else None
    deadline = None
    if detected:
        deadline = (dt.datetime.fromisoformat(detected.replace("Z", "+00:00")) + dt.timedelta(hours=6)).isoformat()
    iocs = []
    if sighting:
        iocs.append({"type": "ipv4-addr", "value_defanged": sighting["dst_defanged"], "port": sighting["dport"],
                     "context": f"{sighting['malware']} C2 per {sighting['c2_source']}; {sighting['connections']} "
                                f"connections every ~{sighting['mean_interval_s']}s from {a['hostname']}"})
    actions_taken = [h["kind"].replace("analyst.", "") for h in (workflow or {}).get("history", [])]
    sections = {
        "1. Reporting entity": {
            "Organisation": org["name"], "Sector (NCIIPC)": org["sector"], "State": org["state"],
            "Point of contact": f"CISO, ciso@{org['domain']}", "CII notified": "Yes" if org["cii"] else "No",
        },
        "2. Incident classification": {
            "Incident type(s) (Directions Annexure I)": types,
            "Severity (system assessment)": f"{a['tier']} - SSVC {a['decision']}, risk {a['risk']:.0f}/100",
        },
        "3. Timeline": {
            "Vulnerability published": v.get("published"),
            "Known-exploited (CISA KEV) since": (v.get("kev") or {}).get("dateAdded"),
            "Compromise indicators first observed": sighting["first_seen"] if sighting else "n/a",
            "Detected / confirmed by monitoring": detected,
            "CERT-In reporting deadline (6 h from detection)": deadline,
        },
        "4. Affected systems": [{
            "Hostname": x["hostname"], "IP": x["ip"], "Product": x["label"], "Version": x["version"],
            "Network zone": x["zone"], "Owner": x["owner"]} for x in detail["assets"]],
        "5. Vulnerability exploited (suspected entry vector)": {
            "CVE": v["id"], "Name": (v.get("kev") or {}).get("vulnerabilityName") or v["description"][:140],
            "CVSS": f"{v.get('cvss_vector')} ({v.get('cvss_source')})",
            "CISA SSVC": v.get("ssvc"),
        },
        "6. Indicators of compromise": iocs or "None observed yet",
        "7. Actions taken so far": actions_taken or ["Alert issued; awaiting acknowledgement"],
        "8. Recommended actions": [f"[{x['type']}] {x['step']}" for x in detail["actions"]],
        "9. Routing": [r for r in [
            "CERT-In (incident@cert-in.org.in) - mandatory within 6 hours",
            "CSIRT-Power (sectoral CERT)" if org["sector"] == "Power & Energy" else None,
            "CSIRT-Fin / RBI DAKSH (within 6 hours)" if org["sector"] == "BFSI" else None,
            "NCIIPC (notified CII)" if org["cii"] else None,
        ] if r],
    }
    if brief and brief.get("brief"):
        sections["10. Analyst summary (AI-generated by local model, validated)"] = {
            "Headline": brief["brief"]["headline"],
            "Why it matters": [b["text"] for b in brief["brief"]["why_it_matters"]],
            "Model": brief["model"],
        }
    return {
        "title": f"Cyber security incident report - DRAFT - {org['name']} - {v['id']}",
        "status": "DRAFT for analyst review; not submitted",
        "basis": "Field layout aligned to CERT-In Directions No. 20(3)/2022-CERT-In (28 Apr 2022); verify against "
                 "the current CERT-In incident reporting form before submission.",
        "sections": sections,
    }


def stix_bundle(detail: dict, sighting: dict | None, brief: dict | None, tlp: str = "AMBER") -> dict:
    org, v = detail["org"], detail["vulnerability"]
    now = _stix_ts(dt.datetime.now(dt.timezone.utc).isoformat())
    base = {"spec_version": "2.1", "created_by_ref": PRODUCER["id"], "object_marking_refs": [TLP[tlp]]}
    victim = {**base, "type": "identity", "id": _sid("identity", org["id"]), "created": now, "modified": now,
              "name": org["name"], "identity_class": "organization", "sectors": [org["sector"].lower()]}
    vuln = {**base, "type": "vulnerability", "id": _sid("vulnerability", v["id"]), "created": _stix_ts(v["published"]),
            "modified": now, "name": v["id"], "description": v["description"][:1000],
            "external_references": [{"source_name": "cve", "external_id": v["id"]}]}
    objects = [PRODUCER, victim, vuln]
    rel_ids = []
    for a in detail["assets"]:
        infra = {**base, "type": "infrastructure", "id": _sid("infrastructure", a["asset_id"]), "created": now,
                 "modified": now, "name": a["hostname"], "infrastructure_types": ["workstation" if a["zone"] == "internal"
                                                                                   else "unknown"],
                 "description": f"{a['label']} {a['version']} ({a['zone']}); exposure {a['exposure']['status']}"}
        rel = {**base, "type": "relationship", "id": _sid("relationship", a["asset_id"], v["id"]), "created": now,
               "modified": now, "relationship_type": "has", "source_ref": infra["id"], "target_ref": vuln["id"],
               "confidence": round(100 * a["V"])}
        objects += [infra, rel]
        rel_ids += [infra["id"], rel["id"]]
    for i, act in enumerate(detail["actions"]):
        coa = {**base, "type": "course-of-action", "id": _sid("course-of-action", v["id"], str(i)), "created": now,
               "modified": now, "name": f"{act['type']}: {act['step'][:80]}", "description": f"{act['step']} ({act['source']})"}
        mit = {**base, "type": "relationship", "id": _sid("relationship", coa["id"], vuln["id"]), "created": now,
               "modified": now, "relationship_type": "mitigates", "source_ref": coa["id"], "target_ref": vuln["id"]}
        objects += [coa, mit]
        rel_ids += [coa["id"], mit["id"]]
    if sighting:
        ind = {**base, "type": "indicator", "id": _sid("indicator", sighting["dst"]), "created": now, "modified": now,
               "name": f"{sighting['malware']} C2 {sighting['dst_defanged']}", "indicator_types": ["malicious-activity"],
               "pattern": f"[ipv4-addr:value = '{sighting['dst']}']", "pattern_type": "stix",
               "valid_from": _stix_ts(sighting["first_seen"]), "confidence": ADMIRALTY_TO_STIX["B"]}
        sig = {**base, "type": "sighting", "id": _sid("sighting", sighting["dst"], org["id"]), "created": now,
               "modified": now, "first_seen": _stix_ts(sighting["first_seen"]),
               "last_seen": _stix_ts(sighting["confirmed_at"]), "count": sighting["connections"],
               "sighting_of_ref": ind["id"], "where_sighted_refs": [victim["id"]]}
        objects += [ind, sig]
        rel_ids += [ind["id"], sig["id"]]
    if brief and brief.get("brief"):
        model_id = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", brief["model"]), "created": now,
                    "modified": now, "name": f"Local model {brief['model']}", "identity_class": "system"}
        note = {"type": "note", "spec_version": "2.1", "id": _sid("note", org["id"], v["id"], brief["model"]),
                "created": now, "modified": now, "created_by_ref": model_id["id"], "object_marking_refs": [TLP[tlp]],
                "abstract": brief["brief"]["headline"],
                "content": "\n".join(b["text"] for b in brief["brief"]["why_it_matters"] + brief["brief"]["what_to_do"]),
                "object_refs": [vuln["id"]], "labels": ["machine-generated", "validated-against-facts"]}
        objects += [model_id, note]
        rel_ids += [note["id"]]
    report = {**base, "type": "report", "id": _sid("report", org["id"], v["id"]), "created": now, "modified": now,
              "name": f"Early warning: {v['id']} at {org['name']}", "report_types": ["vulnerability", "threat-report"],
              "published": now, "object_refs": [victim["id"], vuln["id"], *rel_ids]}
    objects.append(report)
    return {"type": "bundle", "id": _sid("bundle", org["id"], v["id"], now), "objects": objects}
