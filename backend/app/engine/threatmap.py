"""Organisation threat map: the national threat picture cut down to one operator, as a graph the interface draws.

Country threat maps draw attack arcs between nations. This draws, for one organisation, what is actually recorded
about it: external attack pressure on the ports its exposed services listen on (REAL, DShield), scanning of its
products on the national decoy grid (SIM), exploited CVEs on its assets (REAL), implants calling out to known C2
(REAL indicator, SIM sighting; live detections), phishing look-alikes of its domain (REAL, OpenPhish), the
suppliers it depends on (SIM), and the blast radius from its perimeter to its crown jewels. Every node and edge
carries its provenance; nothing is interpolated.
"""

from __future__ import annotations

import json
import sqlite3

from .intel import PORT_NAMES, PORTS, dshield, lookalikes, port_trend
from .suppliers import of_org

CROWN_ROLES = {"ot-hmi", "ot-scada", "core-banking", "payments", "database", "erp"}
PER_COLUMN = {"perimeter": 12, "dmz": 10, "internal": 8, "crown": 10}  # drawn individually, worst first
RANK = {"Compromise": 4, "Critical": 3, "High": 2, "Medium": 1, "Watch": 0}
NAMES = {4: "Compromise", 3: "Critical", 2: "High", 1: "Medium", 0: "Watch"}


def _column(a: dict) -> str:
    if a["zone"] == "internet":
        return "perimeter"
    if a["zone"] == "dmz":
        return "dmz"
    return "crown" if a["role"] in CROWN_ROLES or a["tier"] == 1 else "internal"


def org_threatmap(conn: sqlite3.Connection, org_id: str, live: dict | None = None) -> dict:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    org = cur.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    if not org:
        raise KeyError(org_id)
    org = dict(org)
    assets = [dict(r) for r in cur.execute("SELECT * FROM assets WHERE org_id = ? ORDER BY tier, zone, hostname", (org_id,))]
    by_asset: dict[str, dict] = {}
    for r in cur.execute("""SELECT a.asset_id, a.cve_id, a.tier, a.risk, v.kev FROM assessments a JOIN vulns v ON v.id = a.cve_id
                            WHERE a.org_id = ? AND a.R > 0 AND a.tier != 'Watch' ORDER BY a.risk DESC""", (org_id,)):
        d = by_asset.setdefault(r["asset_id"], {"worst": 0, "risk": 0.0, "open": 0, "cves": [], "kev": 0})
        d["worst"] = max(d["worst"], RANK[r["tier"]])
        d["risk"] = max(d["risk"], r["risk"])
        d["open"] += 1
        kev = bool(r["kev"] and r["kev"] != "null")
        d["kev"] += kev
        if len(d["cves"]) < 4:
            d["cves"].append({"cve": r["cve_id"], "tier": r["tier"], "kev": kev})
    closed = {r[0] for r in conn.execute("SELECT alert_id FROM workflow WHERE state = 'closed'")} if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name = 'workflow'").fetchone() else set()

    # implants: build-time sightings and live beacon detections, both on this organisation's assets
    beacons: dict[str, dict] = {}
    for r in conn.execute("SELECT subject, payload FROM ledger WHERE kind = 'ioc.sighting'"):
        p = json.loads(r[1])
        if p.get("asset_id", r[0]) in {a["id"] for a in assets}:
            beacons[p.get("asset_id", r[0])] = {"c2": p.get("dst_defanged"), "malware": p.get("malware"),
                                                 "source": p.get("c2_source"), "interval_s": p.get("mean_interval_s"),
                                                 "provenance": "SIM sighting · REAL indicator", "since": p.get("first_seen")}
    live_hits = []
    for d in (live or {}).get("detections") or []:
        if d.get("org_id") == org_id or any(a["hostname"] == d.get("asset") for a in assets):
            live_hits.append(d)
            if d["kind"] == "beacon":
                aid = next((a["id"] for a in assets if a["hostname"] == d.get("asset")), None)
                if aid:
                    beacons[aid] = {"c2": d.get("c2"), "malware": None, "source": "live C2 beacon detector",
                                    "interval_s": d.get("interval_s"), "provenance": "SIM sighting · REAL indicator", "since": d["ts"]}
    anomalies = {next((a["id"] for a in assets if a["hostname"] == d.get("asset")), None) for d in live_hits if d["kind"] == "anomaly"}

    all_nodes = []
    for a in assets:
        s = by_asset.get(a["id"], {"worst": 0, "risk": 0.0, "open": 0, "cves": [], "kev": 0})
        col = _column(a)
        all_nodes.append({"id": a["id"], "host": a["hostname"].split(".")[0], "hostname": a["hostname"], "label": a["label"],
                      "version": a["version"], "product_key": a["product_key"], "zone": a["zone"], "role": a["role"],
                      "column": col, "asset_tier": a["tier"], "reach": a.get("tier1_reachable", 0),
                      "worst": NAMES[s["worst"]], "risk": s["risk"], "open": s["open"], "kev": s["kev"], "cves": s["cves"],
                      "beacon": beacons.get(a["id"]), "anomaly": a["id"] in anomalies,
                      "ports": PORTS.get(a["product_key"], []) if a["zone"] in ("internet", "dmz") else []})
    nodes, folded = [], {}  # asset id -> the aggregate circle it is folded into
    for col, cap in PER_COLUMN.items():
        group = sorted((n for n in all_nodes if n["column"] == col),
                       key=lambda n: (-RANK[n["worst"]], n["beacon"] is None, -n["open"], n["asset_tier"], n["hostname"]))
        keep, rest = group[:cap], group[cap:]
        nodes += keep
        if rest:
            agg_id = f"agg:{col}"
            worst = max(RANK[n["worst"]] for n in rest)
            opened = sum(n["open"] for n in rest)
            nodes.append({"id": agg_id, "host": f"{len(rest)} more", "column": col, "worst": NAMES[worst], "risk": 0,
                          "open": opened, "kev": sum(n["kev"] for n in rest), "cves": [], "aggregate": len(rest),
                          "hostname": f"{len(rest)} more systems in this zone, {opened} open warning(s), worst {NAMES[worst]}",
                          "label": "", "beacon": None, "anomaly": False, "ports": sorted({p for n in rest for p in n["ports"]}),
                          "zone": col, "role": "", "asset_tier": 5, "reach": 0, "version": "", "product_key": ""})
            for n in rest:
                folded[n["id"]] = agg_id

    def tgt(aid: str) -> str:
        return folded.get(aid, aid)

    exposed = [n for n in all_nodes if n["column"] in ("perimeter", "dmz")]
    threats, edges = [], []
    # 1. external attack pressure per listening port (REAL, SANS ISC DShield)
    ports: dict[int, list[str]] = {}
    for n in exposed:
        for p in n["ports"]:
            ports.setdefault(p, []).append(n["id"])
    for p, targets in sorted(ports.items()):
        t = port_trend(p)
        tid = f"port:{p}"
        threats.append({"id": tid, "kind": "attack", "label": f"{PORT_NAMES.get(p, p)} :{p}", "provenance": "REAL",
                        "source": "SANS ISC DShield", "ratio": t["ratio"] if t else None, "elevated": bool(t and t["elevated"]),
                        "last7_mean": t["last7_mean"] if t else None, "sources_last7": t["sources_last7"] if t else None,
                        "series": [x["records"] for x in (t["series"][-28:] if t else [])]})
        for a in targets:
            edges.append({"from": tid, "to": tgt(a), "kind": "attack", "provenance": "REAL",
                          "weight": min(3.0, (t["ratio"] if t else 1.0))})
    # 2. scanning of its products on the national decoy grid (SIM), build-time surges and the live z
    live_z = {t["tag"]: t for t in ((live or {}).get("tags") or [])}
    seen_products = set()
    for n in exposed:
        pk = n["product_key"]
        if pk in seen_products:
            continue
        seen_products.add(pk)
        surge = conn.execute("SELECT first, last, z_sessions, sensors FROM decoy_surges WHERE tag = ? ORDER BY last DESC LIMIT 1",
                             (pk,)).fetchone()
        lz = live_z.get(pk)
        if not surge and not (lz and lz["z"] >= 2):  # only products with a recorded surge or a live signal
            continue
        tid = f"decoy:{pk}"
        threats.append({"id": tid, "kind": "scanning", "label": f"Decoy grid: {n['label']}", "provenance": "SIM",
                        "source": "national decoy grid (24 sensors)",
                        "surge": {"first": surge[0], "last": surge[1], "z": surge[2], "sensors": surge[3]} if surge else None,
                        "live_z": lz["z"] if lz else None, "live_sessions": lz["sessions"] if lz else None})
        for m in exposed:
            if m["product_key"] == pk:
                edges.append({"from": tid, "to": tgt(m["id"]), "kind": "scanning", "provenance": "SIM",
                              "weight": min(3.0, max(0.6, (surge[2] if surge else 0) / 20))})
    # 3. exploited CVEs on its assets (REAL, CISA KEV)
    kev_cves: dict[str, list[str]] = {}
    for n in all_nodes:
        for c in n["cves"]:
            if c["kev"] and f"{org_id}:{c['cve']}" not in closed:
                kev_cves.setdefault(c["cve"], []).append(n["id"])
    for cve, targets in sorted(kev_cves.items(), key=lambda kv: -len(kv[1]))[:6]:
        tid = f"cve:{cve}"
        threats.append({"id": tid, "kind": "exploited", "label": cve, "provenance": "REAL", "source": "CISA KEV",
                        "assets": len(targets)})
        for a in targets:
            edges.append({"from": tid, "to": tgt(a), "kind": "exploited", "provenance": "REAL", "weight": 1.2})
    # 4. implants calling out (asset -> C2)
    c2s = []
    for aid, b in beacons.items():
        cid = f"c2:{b['c2']}"
        if cid not in {c["id"] for c in c2s}:
            c2s.append({"id": cid, "label": b["c2"], "malware": b.get("malware"), "source": b.get("source"),
                        "provenance": "REAL indicator (abuse.ch Feodo Tracker) · SIM sighting"})
        edges.append({"from": tgt(aid), "to": cid, "kind": "beacon", "provenance": "SIM", "weight": 2.5,
                      "label": f"every {b['interval_s']:.0f} s" if b.get("interval_s") else "periodic"})
    # 5. phishing look-alikes of its domain (REAL, OpenPhish) and its suppliers (SIM)
    phish = _lookalike_hits(org["domain"])
    if phish:
        threats.append({"id": "phish", "kind": "phishing", "label": f"{len(phish)} look-alike domain(s) live", "provenance": "REAL",
                        "source": "OpenPhish", "hosts": phish[:6]})
        edges.append({"from": "phish", "to": "org", "kind": "phishing", "provenance": "REAL", "weight": 1.5})
    suppliers = []
    for sp in of_org(org_id):
        labels = sorted({r[0] for r in conn.execute(f"SELECT DISTINCT label FROM assets WHERE product_key IN "
                                                    f"({','.join('?' * len(sp['runs']))})", sp["runs"])})
        hot = conn.execute(f"""SELECT COUNT(DISTINCT a.cve_id) FROM assessments a JOIN assets s ON s.id = a.asset_id
                               WHERE a.R > 0 AND a.tier IN ('Compromise','Critical') AND s.product_key IN
                               ({','.join('?' * len(sp['runs']))})""", sp["runs"]).fetchone()[0]
        suppliers.append({"id": sp["id"], "label": sp["name"], "service": sp["service"], "runs": labels, "critical_cves": hot,
                          "provenance": "SIM"})
        edges.append({"from": sp["id"], "to": "org", "kind": "supplier", "provenance": "SIM", "weight": 1.0 + min(2.0, hot / 5)})
    # 6. blast radius: exposed assets that can reach tier-1 systems
    edges += [{"from": tgt(n["id"]), "to": "crown", "kind": "reach", "provenance": "SIM", "weight": min(3.0, n["reach"] / 3)}
              for n in exposed if n.get("reach")]
    merged: dict[tuple, dict] = {}  # edges folded onto one circle become one line with the strongest weight
    for e in edges:
        key = (e["kind"], e["from"], e["to"])
        if key not in merged or e["weight"] > merged[key]["weight"]:
            merged[key] = e
    edges = list(merged.values())

    worst = max((RANK[n["worst"]] for n in all_nodes), default=0)
    return {
        "org": {**org, "cii": bool(org["cii"])},
        "columns": [{"id": "perimeter", "label": "Internet-facing"}, {"id": "dmz", "label": "DMZ"},
                    {"id": "internal", "label": "Internal"}, {"id": "crown", "label": "Crown jewels"}],
        "nodes": nodes, "threats": threats, "c2": c2s, "suppliers": suppliers, "edges": edges,
        "live": live_hits[:10],
        "summary": {"assets": len(assets), "shown": len([n for n in nodes if not n.get("aggregate")]),
                    "exposed": len(exposed), "worst": NAMES[worst],
                    "open_high": sum(n["open"] for n in all_nodes if RANK[n["worst"]] >= 2),
                    "exploited_cves": len(kev_cves), "beacons": len(beacons), "elevated_ports": sum(1 for t in threats if t.get("elevated")),
                    "suppliers": len(suppliers), "lookalikes": len(phish)},
        "provenance": {"REAL": ["DShield attack telemetry", "CISA KEV", "OpenPhish", "Feodo Tracker indicators"],
                       "SIM": ["organisation and assets", "decoy grid", "firewall sightings", "supplier graph"]},
    }


def _lookalike_hits(domain: str) -> list[str]:
    import re
    from pathlib import Path
    raw = Path(__file__).resolve().parents[3] / "data" / "raw" / "openphish.txt"
    if not raw.exists():
        return []
    hosts = {re.sub(r"^[a-z]+://", "", u).split("/")[0].lower() for u in raw.read_text(encoding="utf-8").split()}
    variants = lookalikes(domain)
    return sorted({h for h in hosts if any(v in h for v in variants)})
