"""Machine-readable intelligence for the tools a SOC already runs: risk lists and a STIX 2.1 bundle of the graph.

Risk lists are the TIP convention (a scored list per indicator type that a SIEM, firewall or EDR ingests on a schedule).
Odyssey's lists hold only what its own record supports: vulnerabilities on our exposed assets, C2 addresses actually
seen in telemetry plus the public attack sources on our ports, phishing hosts impersonating our domains, and the
technologies under pressure. Every row carries its score, its provenance (REAL / SIM) and the evidence behind the score.
The STIX bundle is the intelligence graph itself, typed for exchange (identities, vulnerabilities, software, campaigns,
attack patterns, malware, intrusion sets, indicators, sightings and relationships).
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import sqlite3

from .graph import REAL, SIM, _refang, intel_graph
from .intel import dshield, lookalikes
from .reports import PRODUCER, TLP, _sid, _stix_ts

KINDS = {
    "cves": ("Vulnerabilities on our exposed assets", "SIEM correlation, vulnerability management, patch priority"),
    "ips": ("Addresses: C2 seen in our telemetry, HTTP attack sources, global attack sources on our ports",
            "firewall / proxy block lists, EDR network rules"),
    "domains": ("Phishing hosts impersonating our domains", "mail and DNS filtering, brand protection"),
    "products": ("Technologies under pressure", "asset owners, change advisory boards"),
}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def risk_list(conn: sqlite3.Connection, kind: str, live: dict | None = None) -> list[dict]:
    if kind not in KINDS:
        raise KeyError(kind)
    return {"cves": _cves, "ips": _ips, "domains": _domains, "products": _products}[kind](conn, live or {})


def summary(conn: sqlite3.Connection, live: dict | None = None) -> dict:
    return {"generated_at": _now(), "formats": ["json", "csv"],
            "lists": [{"id": k, "title": t, "for": f, "rows": len(risk_list(conn, k, live))} for k, (t, f) in KINDS.items()],
            "how": "Each row carries score (0-100), provenance (REAL public data / SIM simulated sensors) and the evidence behind it. "
                   "Pull on a schedule, or stream the same events through the channels (webhooks)."}


def to_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    cols = list(rows[0].keys())
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: (json.dumps(v) if isinstance(v, (list, dict)) else v) for k, v in r.items()})
    return out.getvalue()


def _cves(conn, live) -> list[dict]:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    closed = {r[0] for r in conn.execute("SELECT alert_id FROM workflow WHERE state = 'closed'")}
    forecast = {r[0].split(":")[1] for r in conn.execute("SELECT subject FROM ledger WHERE kind = 'auto.forecast'") if ":" in r[0]}
    per: dict[str, dict] = {}
    for r in cur.execute("""SELECT a.cve_id, a.org_id, a.sector, a.asset_id, a.tier, a.risk, a.deadline_hours, v.kev, v.epss, v.ssvc, v.published
                            FROM assessments a JOIN vulns v ON v.id = a.cve_id WHERE a.R > 0 AND a.tier != 'Watch' ORDER BY a.risk DESC"""):
        if f"{r['org_id']}:{r['cve_id']}" in closed:
            continue
        kev = json.loads(r["kev"]) if r["kev"] and r["kev"] != "null" else None
        ssvc = json.loads(r["ssvc"]) if r["ssvc"] and r["ssvc"] not in ("null", "") else {}
        d = per.setdefault(r["cve_id"], {"cve": r["cve_id"], "score": 0.0, "tier": r["tier"], "kev": bool(kev),
                                         "kev_added": (kev or {}).get("dateAdded"), "kev_due": (kev or {}).get("dueDate"),
                                         "ransomware": (kev or {}).get("knownRansomwareCampaignUse"),
                                         "ssvc_exploitation": ssvc.get("Exploitation") if isinstance(ssvc, dict) else None,
                                         "epss": r["epss"], "forecast_flag": r["cve_id"] in forecast, "published": (r["published"] or "")[:10],
                                         "assets": 0, "orgs": set(), "sectors": set(), "deadline_hours": None,
                                         "provenance": "REAL · SIM", "evidence": "REAL vulnerability record, version-verified on SIM inventory"})
        d["score"] = max(d["score"], r["risk"])
        if _rank(r["tier"]) > _rank(d["tier"]):
            d["tier"] = r["tier"]
        d["assets"] += 1
        d["orgs"].add(r["org_id"])
        d["sectors"].add(r["sector"])
        if r["deadline_hours"] is not None:
            d["deadline_hours"] = min(d["deadline_hours"], r["deadline_hours"]) if d["deadline_hours"] is not None else r["deadline_hours"]
    rows = []
    for d in per.values():
        d["score"] = round(d["score"], 1)
        d["orgs"] = len(d["orgs"])
        d["sectors"] = sorted(d["sectors"])
        rows.append(d)
    rows.sort(key=lambda d: (-d["score"], d["cve"]))
    return rows


def _rank(t: str | None) -> int:
    return {"Compromise": 4, "Critical": 3, "High": 2, "Medium": 1, "Watch": 0}.get(t or "", 0)


def _ips(conn, live) -> list[dict]:
    rows: dict[str, dict] = {}
    hosts = {r[0]: (r[1], r[2]) for r in conn.execute("SELECT id, hostname, org_id FROM assets")}
    for ts, subject, payload in conn.execute("SELECT ts, subject, payload FROM ledger WHERE kind = 'ioc.sighting' ORDER BY ts"):
        p = json.loads(payload)
        ip = _refang(p.get("dst_defanged") or p.get("dst"))
        if not ip:
            continue
        host, org = hosts.get(p.get("asset_id", subject), (p.get("asset_id", subject), None))
        r = rows.setdefault(ip, {"value": ip, "defanged": ip.replace(".", "[.]"), "type": "ipv4-addr", "score": 95, "role": "c2_seen",
                                 "malware": p.get("malware"), "first_seen": p.get("first_seen") or ts, "last_seen": ts, "seen_from": host,
                                 "org_id": org, "connections": p.get("connections"), "provenance": "REAL · SIM",
                                 "source": p.get("c2_source") or "Feodo Tracker (abuse.ch)", "evidence": "REAL C2 indicator, sighted in SIM firewall logs"})
        r["last_seen"] = max(r["last_seen"], ts)
    for d in (live or {}).get("detections") or []:
        if d.get("kind") != "beacon" or not d.get("c2"):
            continue
        ip = _refang(d["c2"])
        r = rows.setdefault(ip, {"value": ip, "defanged": ip.replace(".", "[.]"), "type": "ipv4-addr", "score": 95, "role": "c2_seen", "malware": None,
                                 "first_seen": d["ts"], "last_seen": d["ts"], "seen_from": d.get("asset"), "org_id": d.get("org_id"),
                                 "connections": None, "provenance": "REAL · SIM", "source": "live C2 beacon detector",
                                 "evidence": "REAL C2 indicator (Feodo Tracker), live beacon in SIM flows"})
        r["last_seen"] = max(r["last_seen"], d["ts"])
    for ts, subject, prov, payload in conn.execute("SELECT ts, subject, provenance, payload FROM ledger WHERE kind LIKE 'shield.detect.%' ORDER BY ts"):
        p = json.loads(payload)
        app, _, ip = subject.rpartition(":")
        r = rows.setdefault(ip, {"value": ip, "defanged": ip.replace(".", "[.]"), "type": "ipv4-addr", "score": 80 if p.get("decision") == "allow" else 60,
                                 "role": "http_attack_source", "malware": None, "first_seen": ts, "last_seen": ts, "seen_from": app, "org_id": None,
                                 "connections": 0, "provenance": prov, "source": "HTTP shield" + (" (red-team exercise)" if p.get("redteam") else ""),
                                 "evidence": f"{p.get('category')} against {app}"})
        r["last_seen"] = max(r["last_seen"], ts)
        r["connections"] = (r.get("connections") or 0) + 1
    for s in dshield().get("top_sources", []):
        ip = s.get("ip") or s.get("ipv4")
        if not ip or ip in rows:
            continue
        rows[ip] = {"value": ip, "defanged": ip.replace(".", "[.]"), "type": "ipv4-addr", "score": 55, "role": "global_attack_source", "malware": None,
                    "first_seen": s.get("firstseen"), "last_seen": s.get("lastseen"), "seen_from": None, "org_id": None,
                    "connections": int(s.get("attacks") or 0) if str(s.get("attacks", "")).isdigit() else None, "provenance": REAL,
                    "source": "SANS ISC DShield top sources", "evidence": f"{s.get('attacks')} attack records against {s.get('targets')} targets"}
    out = sorted(rows.values(), key=lambda r: (-r["score"], r["value"]))
    return out


def _domains(conn, live) -> list[dict]:
    from pathlib import Path
    import re
    raw = Path(__file__).resolve().parents[3] / "data" / "raw" / "openphish.txt"
    if not raw.exists():
        return []
    hosts = {re.sub(r"^[a-z]+://", "", u).split("/")[0].lower() for u in raw.read_text(encoding="utf-8").split()}
    rows = []
    for org_id, name, domain in conn.execute("SELECT id, name, domain FROM orgs ORDER BY id"):
        variants = lookalikes(domain)
        for h in sorted(h for h in hosts if any(v in h for v in variants)):
            rows.append({"value": h, "type": "domain-name", "score": 70, "role": "phishing_lookalike", "impersonates": domain,
                         "org_id": org_id, "org": name, "provenance": REAL, "source": "OpenPhish", "evidence": "live phishing URL host resembles the domain"})
    return rows


def _products(conn, live) -> list[dict]:
    g = intel_graph(conn, None, live)
    surges = {r[0]: {"last": r[1], "z": r[2]} for r in conn.execute("SELECT tag, last, z_sessions FROM decoy_surges ORDER BY last")}
    camps = {n["id"].split(":", 1)[1]: n["facts"] for n in g["nodes"] if n["kind"] == "campaign"}
    forecast = {}
    for n in g["nodes"]:
        if n["kind"] == "cve" and n["facts"].get("forecast"):
            for e in g["edges"]:
                if e["from"] == n["id"] and e["to"].startswith("product:"):
                    forecast[e["to"][8:]] = forecast.get(e["to"][8:], 0) + 1
    rows = []
    for n in g["nodes"]:
        if n["kind"] != "product":
            continue
        k = n["facts"]["product_key"]
        rows.append({"product_key": k, "product": n["label"], "score": n["risk"] or 0, "tier": n["tier"], "assets": n["facts"]["assets"],
                     "exposed_assets": n["facts"]["exposed_assets"], "orgs": n["facts"]["orgs"], "open_warnings": n["facts"]["open_warnings"],
                     "exploited_cves": n["facts"]["exploited_cves"], "forecast_cves": forecast.get(k, 0),
                     "decoy_surge_last": surges.get(k, {}).get("last"), "decoy_surge_z": surges.get(k, {}).get("z"),
                     "campaign": camps.get(k, {}).get("status"), "last_evidence": n["last_seen"], "provenance": n["provenance"],
                     "evidence": "REAL vulnerability record on SIM inventory; decoy grid and campaigns correlated"})
    rows.sort(key=lambda r: (-(r["score"] or 0), r["product"]))
    return rows


# ------------------------------------------------------------------------------------------------------- STIX 2.1
_REL = {"affects": ("has", True), "exploits": ("targets", False), "targets": ("targets", False), "enables": ("related-to", False),
        "uses": ("uses", False), "family": ("indicates", False), "impersonates": ("related-to", False), "serves": ("related-to", False),
        "runs": ("related-to", False), "owns": ("related-to", False)}


def graph_stix(g: dict, tlp: str = "AMBER") -> dict:
    """The intelligence graph as a STIX 2.1 bundle. Each node becomes the matching STIX object; edges become
    relationships (or sightings for beacons, notes for live signals). Groups are intrusion-sets *as recorded by ATT&CK*
    with the overlap stated in the description, never an attribution."""
    now = _stix_ts(_now())
    base = {"spec_version": "2.1", "created_by_ref": PRODUCER["id"], "object_marking_refs": [TLP.get(tlp, TLP["AMBER"])]}
    sdo = lambda t, nid, **f: {**base, "type": t, "id": _sid(t, nid), "created": now, "modified": now, **f}  # noqa: E731
    objects: dict[str, dict] = {PRODUCER["id"]: PRODUCER}
    ids: dict[str, str] = {}
    for n in g["nodes"]:
        k, f, lab = n["kind"], n["facts"], n["label"]
        prov = f"Provenance: {n['provenance']}. Source: {n['source']}."
        o = None
        if k == "org":
            o = sdo("identity", n["id"], name=lab, identity_class="organization", sectors=[f["sector"].lower()],
                    description=f"{f['sector']}, {f['state']}; CII: {f['cii']}. {prov}")
        elif k == "supplier":
            o = sdo("identity", n["id"], name=lab, identity_class="organization", description=f"Supplier: {f['service']}. {prov}")
        elif k == "asset":
            o = sdo("infrastructure", n["id"], name=f["hostname"], infrastructure_types=["unknown"], description=f"{n['sub']}. {prov}")
        elif k == "product":
            o = {"type": "software", "spec_version": "2.1", "id": _sid("software", n["id"]), "name": lab}
        elif k == "cve":
            o = sdo("vulnerability", n["id"], name=lab, description=f"{n['sub']}. {'; '.join(f.get('flags', []))}. {prov}",
                    external_references=[{"source_name": "cve", "external_id": f["cve_id"]}])
        elif k == "campaign":
            o = sdo("campaign", n["id"], name=lab, description=f"{n['sub']}. {prov}", **({"first_seen": _stix_ts(f["first_signal"])} if f.get("first_signal") else {}),
                    **({"last_seen": _stix_ts(f["last_exploit"])} if f.get("last_exploit") else {}))
        elif k == "technique":
            o = sdo("attack-pattern", n["id"], name=f["name"], description=f"Mapped by rule: {f.get('rule')}. {prov}",
                    external_references=[{"source_name": "mitre-attack", "external_id": f["technique_id"], "url": f.get("url")}],
                    kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": p} for p in f.get("tactics", [])])
        elif k == "malware":
            o = sdo("malware", n["id"], name=lab, is_family=True, malware_types=["bot"], description=f"{n['sub']}. {prov}",
                    **({"external_references": [{"source_name": "mitre-attack", "external_id": f["attack_id"], "url": f["url"]}]} if f.get("attack_id") else {}))
        elif k == "actor":
            o = sdo("intrusion-set", n["id"], name=lab, aliases=f.get("aliases", []),
                    description=f"{f['note']} Overlap: {', '.join(f.get('overlap', []))}. Malware: {', '.join(f.get('malware', [])) or 'none'}. "
                                f"{f.get('description', '')} {prov}",
                    external_references=[{"source_name": "mitre-attack", "external_id": f["group_id"], "url": f["url"]}])
        elif k == "indicator":
            pattern = f"[ipv4-addr:value = '{_refang(f['value'])}']" if f["type"] == "ipv4-addr" else f"[domain-name:value = '{f['value']}']"
            o = sdo("indicator", n["id"], name=f"{n['sub']}: {lab}", indicator_types=["malicious-activity"], pattern=pattern, pattern_type="stix",
                    valid_from=_stix_ts(n.get("last_seen")), description=prov)
        elif k == "signal":
            o = sdo("note", n["id"], abstract=lab, content=f"{n['sub']}. Phase: {n['phase']}, pulse {n['pulse']}. {prov}", object_refs=[])
        if o:
            objects[o["id"]] = o
            ids[n["id"]] = o["id"]
    for e in g["edges"]:
        a, b = ids.get(e["from"]), ids.get(e["to"])
        if not a or not b:
            continue
        kind = e["kind"]
        if kind == "beacons":
            s = sdo("sighting", f"{e['from']}|{e['to']}", sighting_of_ref=b, where_sighted_refs=[a], description=f"{e['label']}. Provenance: {e['provenance']}.",
                    **({"last_seen": _stix_ts(e["last_seen"])} if e.get("last_seen") else {}))
            objects[s["id"]] = s
        elif kind in ("on", "indicates"):
            objects[a]["object_refs"].append(b)
        else:
            rtype, flip = _REL.get(kind, ("related-to", False))
            src, dst = (b, a) if flip else (a, b)
            r = sdo("relationship", f"{e['from']}|{e['to']}|{kind}", relationship_type=rtype, source_ref=src, target_ref=dst,
                    description=f"{e['label']}. Provenance: {e['provenance']}.")
            objects[r["id"]] = r
    for o in list(objects.values()):
        if o["type"] == "note" and not o["object_refs"]:
            o["object_refs"] = [PRODUCER["id"]]
    return {"type": "bundle", "id": _sid("bundle", "graph", g["focus"]["id"] or "national", now), "objects": list(objects.values()),
            "x_odyssey": {"focus": g["focus"], "built_at": g["built_at"], "note": g["provenance"]["note"], "objects": len(objects)}}
