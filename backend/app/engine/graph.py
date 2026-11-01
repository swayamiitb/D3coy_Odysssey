"""The intelligence graph: every entity Odyssey knows about and how they connect, as one breathing picture.

Nodes are organisations, assets (when one organisation is in focus), technologies, CVEs, campaigns, ATT&CK techniques,
malware families, threat groups, indicators (C2 addresses, phishing look-alikes), suppliers and live signals. Every
node and edge is read from the record (the database, the hash-chained ledger, the live engine, the local ATT&CK and
Feodo snapshots); nothing is interpolated or generated.

Breathing: every node carries the time of its latest evidence. `pulse` decays with that age (1.0 for evidence from
the last hour, about 0.6 after a day, near 0 after a week), so the picture is driven by what is happening now and
fades as evidence ages, the same evidence decay the risk score applies. Threat groups are *technique overlap with the
ATT&CK record, not attribution*, and say so on the node.

The layout is deterministic (rings by entity kind, angles from the circular mean of each node's inner neighbours),
so the picture does not jitter between polls and the same record always draws the same graph.
"""

from __future__ import annotations

import datetime as dt
import functools
import json
import math
import re
import sqlite3
import threading
import time
from collections import defaultdict
from pathlib import Path

from .attack import STIX, _catalog, _ext, map_alert
from .intel import lookalikes
from .suppliers import graph as supplier_graph

RAW = Path(__file__).resolve().parents[3] / "data" / "raw"
RANK = {"Compromise": 4, "Critical": 3, "High": 2, "Medium": 1, "Watch": 0}
NAMES = {v: k for k, v in RANK.items()}
REAL, SIM, MIXED = "REAL", "SIM", "REAL · SIM"
SIGNAL_TECHNIQUE = {"surge": "T1595.002", "beacon": "T1071.001", "anomaly": "T1046"}
KIND_LABELS = {"org": "Organisations", "asset": "Assets", "product": "Technologies", "cve": "Vulnerabilities",
               "campaign": "Campaigns", "technique": "ATT&CK techniques", "malware": "Malware families",
               "actor": "Threat groups", "indicator": "Indicators", "supplier": "Suppliers", "signal": "Live signals"}
RINGS_NATIONAL = {"org": 0, "product": 1, "cve": 2, "campaign": 3, "technique": 3, "malware": 3,
                  "actor": 4, "indicator": 4, "supplier": 4, "signal": 4}
RINGS_ORG = {"org": 0, "asset": 1, "product": 2, "cve": 3, "campaign": 3, "signal": 3,
             "technique": 4, "malware": 4, "indicator": 4, "supplier": 4, "actor": 5}
PULSE_HOURS = 48.0       # e-folding time of a node's pulse
CVE_CAP = {"national": 36, "org": 40}
ACTOR_CAP = 8
MAX_ACTOR_TECHNIQUES = 250  # groups documented with more techniques than this say little about anything in particular

_CACHE: dict[str, tuple[float, dict]] = {}
_LOCK = threading.Lock()
CACHE_S = 4.0


# ----------------------------------------------------------------------------------------------------- time helpers
def _parse(ts: str | None) -> dt.datetime | None:
    if not ts:
        return None
    try:
        if len(ts) == 10:
            return dt.datetime.fromisoformat(ts).replace(tzinfo=dt.timezone.utc)
        d = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _iso(d: dt.datetime | None) -> str | None:
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z") if d else None


def _pulse(age_h: float | None) -> float:
    if age_h is None:
        return 0.0
    return round(math.exp(-max(age_h, 0.0) / PULSE_HOURS), 3)


def _phase(age_h: float | None) -> str:
    if age_h is None:
        return "aged"
    return "fresh" if age_h < 1 else "today" if age_h < 24 else "week" if age_h < 24 * 7 else "fading" if age_h < 24 * 30 else "aged"


# ------------------------------------------------------------------------------------------------- ATT&CK catalogue
@functools.lru_cache(maxsize=1)
def _groups() -> tuple[list[dict], dict[str, dict]]:
    """Threat groups with the techniques and malware ATT&CK records them using, and the malware families by name."""
    objs = json.loads(STIX.read_text(encoding="utf-8"))["objects"]
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")  # noqa: E731
    techniques = {o["id"]: _ext(o) for o in objs if o["type"] == "attack-pattern" and live(o)}
    malware = {o["id"]: o for o in objs if o["type"] in ("malware", "tool") and live(o)}
    groups = {o["id"]: o for o in objs if o["type"] == "intrusion-set" and live(o)}
    uses_t: dict[str, set[str]] = defaultdict(set)
    uses_m: dict[str, set[str]] = defaultdict(set)
    for o in objs:
        if o["type"] != "relationship" or o.get("relationship_type") != "uses" or o["source_ref"] not in groups:
            continue
        if o["target_ref"] in techniques and techniques[o["target_ref"]]:
            uses_t[o["source_ref"]].add(techniques[o["target_ref"]])
        elif o["target_ref"] in malware:
            uses_m[o["source_ref"]].add(malware[o["target_ref"]]["name"].lower())
    out = []
    for sid, g in groups.items():
        desc = re.sub(r"\(Citation:[^)]*\)", "", g.get("description", ""))
        desc = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", desc).strip()
        first = re.split(r"(?<=[.!?])\s", desc, maxsplit=1)[0][:240]
        out.append({"id": _ext(g), "stix": sid, "name": g["name"], "aliases": [a for a in g.get("aliases", []) if a != g["name"]][:4],
                    "description": first, "techniques": uses_t.get(sid, set()), "malware": uses_m.get(sid, set()),
                    "url": f"https://attack.mitre.org/groups/{_ext(g)}/"})
    families = {o["name"].lower(): {"id": _ext(o), "name": o["name"], "url": f"https://attack.mitre.org/software/{_ext(o)}/"}
                for o in malware.values() if _ext(o)}
    return out, families


@functools.lru_cache(maxsize=1)
def _feodo_malware() -> dict[str, str]:
    try:
        rows = json.loads((RAW / "feodo_ipblocklist.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {r["ip_address"]: r.get("malware") for r in rows if r.get("ip_address")}


def _refang(ip: str | None) -> str:
    return (ip or "").replace("[.]", ".")


def _parent(tid: str) -> str:
    return tid.split(".")[0]


# ------------------------------------------------------------------------------------------------------- the build
class _Builder:
    def __init__(self, conn: sqlite3.Connection, focus: str | None, live: dict | None, now: dt.datetime,
                 as_of: dt.datetime | None = None):
        self.conn, self.focus, self.live, self.now = conn, focus, dict(live or {}), now
        self.as_of = as_of  # replay: only evidence recorded up to this instant is drawn
        if as_of is not None:
            cut = _iso(as_of)
            self.live["detections"] = [d for d in self.live.get("detections") or [] if (d.get("ts") or "") <= cut]
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}
        self.seen: dict[str, dt.datetime] = defaultdict(lambda: None)  # node id -> latest evidence time
        self.cur = conn.cursor()
        self.cur.row_factory = sqlite3.Row
        self.scope = "org" if focus else "national"

    # -- primitives
    def node(self, nid: str, kind: str, label: str, **f) -> dict:
        n = self.nodes.get(nid)
        if n is None:
            n = self.nodes[nid] = {"id": nid, "kind": kind, "label": label, "sub": "", "risk": None, "tier": None,
                                   "provenance": SIM, "source": "", "facts": {}}
        n.update({k: v for k, v in f.items() if v is not None})
        return n

    def edge(self, a: str, b: str, kind: str, label: str, provenance: str, weight: float = 1.0, when: str | None = None) -> None:
        key = (a, b, kind)
        e = self.edges.get(key)
        if e is None:
            self.edges[key] = {"from": a, "to": b, "kind": kind, "label": label, "provenance": provenance,
                               "weight": round(weight, 2), "last_seen": when}
        else:
            e["weight"] = round(max(e["weight"], weight), 2)
            if when and (not e["last_seen"] or when > e["last_seen"]):
                e["last_seen"] = when

    def touch(self, nid: str, ts: str | None) -> None:
        d = _parse(ts)
        if d and nid in self.nodes and (self.seen[nid] is None or d > self.seen[nid]):
            self.seen[nid] = d

    def worse(self, nid: str, tier: str | None, risk: float | None) -> None:
        n = self.nodes[nid]
        if tier and (n["tier"] is None or RANK[tier] > RANK[n["tier"]]):
            n["tier"] = tier
        if risk is not None and (n["risk"] is None or risk > n["risk"]):
            n["risk"] = round(risk, 1)

    # -- stages
    def build(self) -> dict:
        orgs = {r["id"]: dict(r) for r in self.cur.execute("SELECT * FROM orgs ORDER BY sector, name")}
        if self.focus and self.focus not in orgs:
            raise KeyError(self.focus)
        closed = {r[0] for r in self.conn.execute("SELECT alert_id FROM workflow WHERE state = 'closed'")}
        where = "AND a.org_id = ?" if self.focus else ""
        args = (self.focus,) if self.focus else ()
        rows = [dict(r) for r in self.cur.execute(f"""
            SELECT a.asset_id, a.cve_id, a.org_id, a.tier, a.risk, s.product_key, s.label, s.zone, s.role, s.hostname,
                   s.tier AS asset_tier, v.kev, v.epss, v.ssvc, v.published, v.description, v.cvss_vector
            FROM assessments a JOIN assets s ON s.id = a.asset_id JOIN vulns v ON v.id = a.cve_id
            WHERE a.R > 0 AND a.tier != 'Watch' {where} ORDER BY a.risk DESC""", args)]
        rows = [r for r in rows if f"{r['org_id']}:{r['cve_id']}" not in closed]
        forecast = {r[0].split(":")[1] for r in self.conn.execute("SELECT subject FROM ledger WHERE kind = 'auto.forecast'")
                    if ":" in r[0]}
        cases = defaultdict(list)
        for r in self.cur.execute("SELECT id, org_id, kind, severity, status, title, created_at FROM soc_cases WHERE status != 'closed'"):
            cases[r["org_id"]].append(dict(r))

        self._orgs(orgs, rows, cases)
        self._products(rows, orgs)
        if self.focus:
            self._assets(rows)
        cve_products = self._cves(rows, forecast)
        self._campaigns(rows, orgs)
        techniques = self._techniques(rows, cve_products)
        families = self._indicators(orgs, rows)
        self._imported(orgs, rows)
        self._suppliers(orgs)
        techniques |= self._signals(rows, orgs)
        self._actors(techniques, families)
        self._evidence_times(rows)
        return self._finish(orgs)

    def _orgs(self, orgs, rows, cases) -> None:
        for o in orgs.values():
            if self.focus and o["id"] != self.focus:
                continue
            mine = [r for r in rows if r["org_id"] == o["id"]]
            n = self.node(f"org:{o['id']}", "org", o["name"], sub=f"{o['sector']} · {o['state']}", provenance=SIM,
                          source="simulated constituency (world.json)",
                          facts={"org_id": o["id"], "sector": o["sector"], "state": o["state"], "cii": bool(o["cii"]),
                                 "domain": o["domain"], "open_warnings": len(mine),
                                 "critical": sum(r["tier"] in ("Compromise", "Critical") for r in mine),
                                 "open_cases": len(cases.get(o["id"], [])),
                                 "worst": NAMES[max((RANK[r["tier"]] for r in mine), default=0)]})
            for r in mine:
                self.worse(n["id"], r["tier"], r["risk"])
            for c in cases.get(o["id"], []):
                self.touch(n["id"], c["created_at"])

    def _products(self, rows, orgs) -> None:
        per: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            per[r["product_key"]].append(r)
        for key, rs in per.items():
            assets = {r["asset_id"] for r in rs}
            exposed = {r["asset_id"] for r in rs if r["zone"] in ("internet", "dmz")}
            orgs_here = sorted({r["org_id"] for r in rs})
            kev = {r["cve_id"] for r in rs if r["kev"] and r["kev"] != "null"}
            n = self.node(f"product:{key}", "product", rs[0]["label"], provenance=MIXED,
                          source="REAL vulnerability record · SIM inventory",
                          sub=f"{len(assets)} asset{'s' if len(assets) != 1 else ''} at {len(orgs_here)} organisation{'s' if len(orgs_here) != 1 else ''}",
                          facts={"product_key": key, "assets": len(assets), "exposed_assets": len(exposed), "orgs": len(orgs_here),
                                 "open_warnings": len(rs), "exploited_cves": len(kev)})
            for r in rs:
                self.worse(n["id"], r["tier"], r["risk"])
            by_org = defaultdict(set)
            for r in rs:
                by_org[r["org_id"]].add(r["asset_id"])
            for org_id, aset in by_org.items():
                if f"org:{org_id}" in self.nodes:
                    self.edge(f"org:{org_id}", n["id"], "runs", f"runs on {len(aset)} asset(s) with open warnings", SIM,
                              weight=min(3.0, 0.6 + len(aset) / 4))

    def _assets(self, rows) -> None:
        per: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            per[r["asset_id"]].append(r)
        ranked = sorted(per.items(), key=lambda kv: -max(x["risk"] for x in kv[1]))[:30]
        for aid, rs in ranked:
            r0 = rs[0]
            n = self.node(f"asset:{aid}", "asset", r0["hostname"].split(".")[0], provenance=SIM, source="simulated inventory",
                          sub=f"{r0['label']} · {r0['zone']} · {r0['role']}",
                          facts={"asset_id": aid, "hostname": r0["hostname"], "zone": r0["zone"], "role": r0["role"],
                                 "product_key": r0["product_key"], "asset_tier": r0["asset_tier"], "open_warnings": len(rs)})
            for r in rs:
                self.worse(n["id"], r["tier"], r["risk"])
            self.edge(f"org:{r0['org_id']}", n["id"], "owns", "asset of this organisation", SIM, 0.8)
            self.edge(n["id"], f"product:{r0['product_key']}", "runs", "runs this technology", SIM, 0.8)

    def _cves(self, rows, forecast) -> dict[str, set[str]]:
        per: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            per[r["cve_id"]].append(r)

        def keep(cid, rs):
            kev = rs[0]["kev"] and rs[0]["kev"] != "null"
            return kev or cid in forecast or any(r["tier"] in ("Compromise", "Critical") for r in rs)

        ranked = sorted(((c, rs) for c, rs in per.items() if keep(c, rs)), key=lambda kv: -max(x["risk"] for x in kv[1]))
        if self.as_of is not None:  # a CVE not yet published at that instant was not in anyone's picture
            cut = self.as_of.date().isoformat()
            ranked = [(c, rs) for c, rs in ranked if (rs[0]["published"] or "")[:10] <= cut]
        products: dict[str, set[str]] = {}
        for cid, rs in ranked[:CVE_CAP[self.scope]]:
            r0 = rs[0]
            kev = json.loads(r0["kev"]) if r0["kev"] and r0["kev"] != "null" else None
            ssvc = json.loads(r0["ssvc"]) if r0["ssvc"] and r0["ssvc"] not in ("null", "") else {}
            flags = []
            if kev:
                flags.append("exploited in the wild (CISA KEV)")
            if cid in forecast:
                flags.append("day-0 forecast flag")
            n = self.node(f"cve:{cid}", "cve", cid, provenance=REAL, source="NVD · CISA KEV · SSVC · EPSS",
                          sub=(kev or {}).get("vulnerabilityName") or (r0["description"] or "")[:90],
                          facts={"cve_id": cid, "published": (r0["published"] or "")[:10], "kev_added": (kev or {}).get("dateAdded"),
                                 "kev_due": (kev or {}).get("dueDate"), "ransomware": (kev or {}).get("knownRansomwareCampaignUse"),
                                 "epss": r0["epss"], "ssvc_exploitation": ssvc.get("Exploitation") if isinstance(ssvc, dict) else None,
                                 "assets": len({r["asset_id"] for r in rs}), "orgs": len({r["org_id"] for r in rs}),
                                 "forecast": cid in forecast, "flags": flags})
            for r in rs:
                self.worse(n["id"], r["tier"], r["risk"])
            self.touch(n["id"], r0["published"])
            if kev:
                self.touch(n["id"], kev.get("dateAdded"))
            products[cid] = {r["product_key"] for r in rs}
            for pk in products[cid]:
                hit = [r for r in rs if r["product_key"] == pk]
                self.edge(n["id"], f"product:{pk}", "affects", f"version-verified on {len({r['asset_id'] for r in hit})} asset(s)",
                          MIXED, weight=min(3.0, 0.8 + len(hit) / 6))
            if self.focus:
                for r in rs:
                    if f"asset:{r['asset_id']}" in self.nodes:
                        self.edge(n["id"], f"asset:{r['asset_id']}", "affects", f"{r['tier']} warning, risk {r['risk']:.0f}", MIXED,
                                  weight=0.6 + RANK[r["tier"]] / 3)
        return products

    def _campaigns(self, rows, orgs) -> None:
        from .campaigns import build
        snap = self.conn.execute("SELECT value FROM meta WHERE key = 'snapshot_date'").fetchone()
        today = dt.date.fromisoformat(snap[0]) if snap else self.now.date()
        products_here = {r["product_key"] for r in rows}
        for c in build(self.conn, today):
            if c["product_key"] not in products_here or c["status"] == "DORMANT":
                continue
            if self.focus and self.focus not in c["orgs_exposed"]:
                continue
            if self.as_of is not None and (c["first_signal"] or "9999") > self.as_of.date().isoformat():
                continue
            n = self.node(f"campaign:{c['product_key']}", "campaign", c["title"].replace("Exploitation of ", "").replace("Reconnaissance of ", ""),
                          provenance=MIXED, source="correlated: CISA KEV · decoy grid · exposure",
                          sub=f"{c['status'].lower()} · {len(c['cves'])} exploited CVE(s) · {len(c['orgs_exposed'])} organisation(s)",
                          risk=c.get("max_risk"), facts={"status": c["status"], "first_signal": c["first_signal"], "last_exploit": c["last_exploit"],
                                                        "early_warning_days": c["early_warning_days"], "cves": [x["cve"] for x in c["cves"]],
                                                        "orgs_exposed": c["orgs_exposed"], "chained_assets": len(c["chains"]),
                                                        "decoy_surges": len(c["decoy_surges"])})
            self.worse(n["id"], "Critical" if c["status"] == "ACTIVE" else "High", None)
            self.touch(n["id"], c["last_exploit"] or c["first_signal"])
            self.edge(n["id"], f"product:{c['product_key']}", "targets", "the technology this campaign targets", MIXED, 1.4)
            for x in c["cves"]:
                if f"cve:{x['cve']}" in self.nodes:
                    self.edge(n["id"], f"cve:{x['cve']}", "exploits", f"exploited since {x['date']}", REAL, 1.2, x["date"])

    def _techniques(self, rows, cve_products) -> set[str]:
        surged = {r[0] for r in self.conn.execute("SELECT DISTINCT tag FROM decoy_surges")}
        per_cve: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            if f"cve:{r['cve_id']}" in self.nodes:
                per_cve[r["cve_id"]].append(r)
        observed: set[str] = set()
        for cid, rs in per_cve.items():
            combos = {(r["zone"], r["role"]) for r in rs}
            kev = bool(rs[0]["kev"] and rs[0]["kev"] != "null")
            found: dict[str, dict] = {}
            for zone, role in sorted(combos)[:6]:
                m = map_alert(rs[0]["description"], {"zone": zone, "role": role}, rs[0]["cvss_vector"], kev,
                              bool(cve_products.get(cid, set()) & surged), False)
                for t in m["techniques"]:
                    found.setdefault(t["id"], t)
            for tid, t in found.items():
                self._technique_node(t)
                observed.add(tid)
                self.edge(f"cve:{cid}", f"technique:{tid}", "enables", t["why"], REAL, 0.9)
                self.worse(f"technique:{tid}", self.nodes[f"cve:{cid}"]["tier"], self.nodes[f"cve:{cid}"]["risk"])
        return observed

    def _technique_node(self, t: dict) -> dict:
        n = self.node(f"technique:{t['id']}", "technique", f"{t['id']} {t['name']}", provenance=REAL,
                      source="MITRE ATT&CK Enterprise (local STIX snapshot), mapped by explicit rules",
                      sub=", ".join(t.get("tactics", [])) or "technique",
                      facts={"technique_id": t["id"], "name": t["name"], "tactics": t.get("tactics", []), "url": t.get("url"),
                             "rule": t.get("why")})
        return n

    def _technique_by_id(self, tid: str) -> dict | None:
        by_tid, _, _ = _catalog()
        o = by_tid.get(tid)
        if not o:
            return None
        return {"id": tid, "name": o["name"], "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/", "why": "observed by a live detector"}

    def _indicators(self, orgs, rows) -> set[str]:
        """C2 addresses seen in telemetry (REAL indicator, SIM sighting) and phishing look-alikes (REAL)."""
        feodo = _feodo_malware()
        _, fam_catalog = _groups()
        families: set[str] = set()
        asset_org = {r["asset_id"]: r["org_id"] for r in rows}
        asset_host = {r["asset_id"]: r["hostname"] for r in rows}
        host_asset = {v: k for k, v in asset_host.items()}
        sightings = [(r[0], r[1], json.loads(r[2])) for r in self.conn.execute(
            "SELECT ts, subject, payload FROM ledger WHERE kind = 'ioc.sighting' ORDER BY ts")]
        if self.as_of is not None:
            sightings = [x for x in sightings if x[0] <= _iso(self.as_of)]
        live_beacons = [(d["ts"], host_asset.get(d.get("asset")), d) for d in self.live.get("detections") or [] if d.get("kind") == "beacon"]
        for ts, aid, p in sightings + [(ts, aid, {"asset_id": aid, "dst_defanged": d.get("c2"), "org_id": d.get("org_id"),
                                                   "c2_source": "live C2 beacon detector", "mean_interval_s": d.get("interval_s")})
                                        for ts, aid, d in live_beacons]:
            aid = p.get("asset_id") or aid
            org_id = asset_org.get(aid) or p.get("org_id")
            if not org_id or (self.focus and org_id != self.focus) or f"org:{org_id}" not in self.nodes:
                continue
            c2 = p.get("dst_defanged") or p.get("dst")
            if not c2:
                continue
            malware = p.get("malware") or feodo.get(_refang(c2))
            n = self.node(f"indicator:{c2}", "indicator", c2, provenance=REAL, source="abuse.ch Feodo Tracker (indicator) · SIM firewall logs (sighting)",
                          sub=f"{malware or 'botnet'} C2 · seen from {asset_host.get(aid, aid or '?').split('.')[0]}", tier="Compromise", risk=95.0,
                          facts={"value": c2, "type": "ipv4-addr", "malware": malware, "seen_from": asset_host.get(aid, aid),
                                 "interval_s": p.get("mean_interval_s"), "source": p.get("c2_source")})
            self.touch(n["id"], ts)
            target = f"asset:{aid}" if f"asset:{aid}" in self.nodes else f"org:{org_id}"
            self.edge(target, n["id"], "beacons", f"periodic beacon every ~{p.get('mean_interval_s') or '?'} s", SIM, 2.4, ts)
            self.touch(target, ts)
            if malware:
                fam = fam_catalog.get(malware.lower())
                m = self.node(f"malware:{malware.lower()}", "malware", fam["name"] if fam else malware, provenance=REAL,
                              source="abuse.ch Feodo Tracker · MITRE ATT&CK software",
                              sub=f"botnet family · {fam['id'] if fam else 'not in ATT&CK'}", tier="Compromise",
                              facts={"name": malware, "attack_id": fam["id"] if fam else None, "url": fam["url"] if fam else None})
                self.touch(m["id"], ts)
                self.edge(n["id"], m["id"], "family", "this C2 serves this family (Feodo Tracker)", REAL, 1.2, ts)
                families.add(malware.lower())
        # phishing look-alikes of constituency domains, from the OpenPhish snapshot
        phish = RAW / "openphish.txt"
        if phish.exists():
            hosts = {re.sub(r"^[a-z]+://", "", u).split("/")[0].lower() for u in phish.read_text(encoding="utf-8").split()}
            for o in orgs.values():
                if f"org:{o['id']}" not in self.nodes:
                    continue
                variants = lookalikes(o["domain"])
                for h in sorted(h for h in hosts if any(v in h for v in variants))[:4]:
                    n = self.node(f"indicator:{h}", "indicator", h, provenance=REAL, source="OpenPhish (live phishing URLs)",
                                  sub=f"phishing host impersonating {o['domain']}", tier="High", risk=70.0,
                                  facts={"value": h, "type": "domain-name", "impersonates": o["domain"]})
                    self.edge(n["id"], f"org:{o['id']}", "impersonates", "look-alike of this organisation's domain in a live phishing feed", REAL, 1.3)
        return families

    def _has(self, table: str) -> bool:
        return self.conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone() is not None

    def _imported(self, orgs, rows) -> None:
        """Bulk-imported indicators that matched our telemetry or exposure, and brand-monitoring hits of weight."""
        asset_host = {r["asset_id"]: r["hostname"] for r in rows}
        cut = _iso(self.as_of) if self.as_of is not None else None
        if self._has("iocs"):
            for r in self.cur.execute("SELECT * FROM iocs WHERE matched = 1 ORDER BY last_seen DESC LIMIT 40"):
                if cut and (r["first_seen"] or "") > cut:
                    continue
                matches = json.loads(r["matches"] or "[]")
                org_ids = {m.get("org_id") for m in matches if m.get("org_id")}
                if self.focus and self.focus not in org_ids and not any(m["where"] in ("firewall flows", "live flows") for m in matches):
                    continue
                tier = {"Critical": "Compromise" if r["type"] == "ipv4-addr" else "Critical", "High": "High", "Medium": "Medium"}.get(r["severity"] or "", "Medium")
                n = self.node(f"indicator:{r['defanged']}", "indicator", r["defanged"], provenance=MIXED,
                              source=f"imported from {r['source']} · matched in Odyssey's telemetry",
                              sub=f"imported {r['type']} · matched: {', '.join(sorted({m['where'] for m in matches}))}", tier=tier,
                              risk={"Compromise": 92.0, "Critical": 85.0, "High": 65.0, "Medium": 40.0}[tier],
                              facts={"value": r["defanged"], "type": r["type"], "source": r["source"], "tlp": r["tlp"], "imported": True,
                                     "matches": matches[:6], "enrichment": json.loads(r["enrich"] or "[]")[:4]})
                self.touch(n["id"], r["last_seen"] or r["added_at"])
                linked = False
                for m in matches:
                    if m.get("asset_id") and f"asset:{m['asset_id']}" in self.nodes:
                        self.edge(f"asset:{m['asset_id']}", n["id"], "seen", m["detail"][:80], m.get("provenance", SIM), 1.6, r["last_seen"])
                        linked = True
                    elif m.get("org_id") and f"org:{m['org_id']}" in self.nodes:
                        self.edge(f"org:{m['org_id']}", n["id"], "seen", m["detail"][:80], m.get("provenance", SIM), 1.4, r["last_seen"])
                        linked = True
                if not linked and r["type"] == "vulnerability" and f"cve:{r['value']}" in self.nodes:
                    self.edge(n["id"], f"cve:{r['value']}", "names", "the imported indicator names this CVE", REAL, 1.0)
                    linked = True
                if not linked and not self.focus:
                    srcs = {m.get("src") for m in matches if m.get("src")}
                    for ip in list(srcs)[:3]:
                        host = next((h for a, h in asset_host.items() if a == ip), None)
                        if host and f"org:{host}" in self.nodes:
                            self.edge(f"org:{host}", n["id"], "seen", "seen in live flows", SIM, 1.4)
        if self._has("brand_hits"):
            per_org: dict[str, int] = defaultdict(int)
            for r in self.cur.execute("SELECT * FROM brand_hits WHERE score >= 70 AND org_id IS NOT NULL ORDER BY score DESC, last_seen DESC LIMIT 60"):
                if cut and (r["first_seen"] or r["ts"] or "") > cut:
                    continue
                if f"org:{r['org_id']}" not in self.nodes or per_org[r["org_id"]] >= 4:
                    continue
                per_org[r["org_id"]] += 1
                n = self.node(f"indicator:{r['value']}", "indicator", r["value"][:60], provenance=REAL, source=f"brand monitoring · {r['source']}",
                              sub=f"{r['kind'].replace('_', ' ')} · score {r['score']:.0f}", tier="High" if r["score"] < 90 else "Critical", risk=float(r["score"]),
                              facts={"value": r["value"], "type": r["kind"], "term": r["term"], "source": r["source"], "title": r["title"], "url": r["url"],
                                     "evidence": r["evidence"], "brand": True})
                self.touch(n["id"], r["last_seen"] or r["ts"])
                self.edge(n["id"], f"org:{r['org_id']}", "impersonates" if r["kind"] != "mention" else "mentions",
                          r["evidence"] or "brand monitoring hit", REAL, 1.2, r["last_seen"] or r["ts"])
        self._disasters(orgs)
        if self._has("surface_scans"):
            seen_hosts = set()
            for r in self.cur.execute("SELECT * FROM surface_scans WHERE status = 'done' ORDER BY ts DESC LIMIT 20"):
                if r["host"] in seen_hosts or (cut and r["ts"] > cut):
                    continue
                seen_hosts.add(r["host"])
                if self.focus and r["org_id"] != self.focus:
                    continue
                sev = "Critical" if (r["score"] or 100) < 40 else "High" if (r["score"] or 100) < 70 else "Medium"
                n = self.node(f"signal:surface:{r['host']}", "signal", f"Attack surface: {r['host']} graded {r['grade']}", provenance=REAL,
                              source="consented attack-surface scan", sub=f"score {r['score']:.0f} · {r['findings']} finding(s) · {r['ts'][:16]}",
                              tier=sev, risk=max(10.0, 100.0 - float(r["score"] or 0)),
                              facts={"signal": "surface", "host": r["host"], "target": r["target"], "score": r["score"], "grade": r["grade"],
                                     "findings": r["findings"], "scan_id": r["id"], "org_id": r["org_id"], "app_id": r["app_id"]})
                self.touch(n["id"], r["ts"])
                if r["org_id"] and f"org:{r['org_id']}" in self.nodes:
                    self.edge(n["id"], f"org:{r['org_id']}", "on", "a system this organisation owns, scanned with consent", REAL, 1.2, r["ts"])
                if len(seen_hosts) >= 5:
                    break

    def _disasters(self, orgs) -> None:
        """SACHET alerts (public domain, REAL) on the states where operators sit: context for 'weather or attack?'."""
        try:
            from .. import sachet
        except ImportError:
            return
        eng = sachet.ENGINE
        if eng is None:
            return
        try:
            feed = eng.read_feed(live=False)
        except Exception:  # noqa: BLE001
            return
        cut = _iso(self.as_of) if self.as_of is not None else None
        shown = 0
        for it in feed.get("items", []):
            if not it.get("orgs") or (cut and (it.get("published") or "") > cut):
                continue
            org_ids = [o["org_id"] for o in it["orgs"] if f"org:{o['org_id']}" in self.nodes]
            if not org_ids:
                continue
            state = it["states"][0]["state"] if it.get("states") else "India"
            sid = f"signal:sachet:{it['identifier']}"
            title = it["title"].strip().split("\n")[0]
            n = self.node(sid, "signal", f"SACHET: {title[:70]}{'…' if len(title) > 70 else ''}", provenance=REAL,
                          source="NDMA SACHET public CAP feed (public domain), read-only",
                          sub=f"disaster alert · {state} · {it.get('category') or 'alert'} · {(it.get('published') or '')[:16]}", tier="Medium", risk=35.0,
                          facts={"signal": "disaster", "identifier": it["identifier"], "title": it["title"][:300], "author": it.get("author"), "category": it.get("category"),
                                 "published": it.get("published"), "link": it.get("link"), "states": it.get("states", [])[:3], "operators": [o["name"] for o in it["orgs"]],
                                 "basis": it["states"][0]["basis"] if it.get("states") else None})
            self.touch(sid, it.get("published"))
            for oid in org_ids:
                self.edge(sid, f"org:{oid}", "on", "a disaster alert for the state this operator sits in (context, not a cyber signal)", REAL, 1.0, it.get("published"))
            shown += 1
            if shown >= 8:
                break
        for a in eng.inbound_alerts(10):
            if cut and a["ts"] > cut:
                continue
            org_ids = [o["org_id"] for o in a.get("orgs", []) if f"org:{o['org_id']}" in self.nodes]
            sid = f"signal:cap:{a['identifier']}"
            n = self.node(sid, "signal", f"Inbound CAP: {a.get('event') or a['identifier']}"[:90], provenance="SIM" if a.get("redteam") else REAL,
                          source="CAP ingest (validated: sender, replay, expiry, DTD refused)" + (" · red-team exercise" if a.get("redteam") else ""),
                          sub=f"accepted from {a.get('sender')} · {a['ts'][:16]}", tier="Medium", risk=30.0,
                          facts={"signal": "cap_inbound", "identifier": a["identifier"], "sender": a.get("sender"), "status": a.get("status"), "event": a.get("event"),
                                 "severity": a.get("severity"), "states": a.get("states", [])[:3], "redteam": a.get("redteam")})
            self.touch(sid, a["ts"])
            for oid in org_ids:
                self.edge(sid, f"org:{oid}", "on", "an accepted inbound alert for this operator's state", REAL, 1.0, a["ts"])

    def _suppliers(self, orgs) -> None:
        for s in supplier_graph():
            deps = [d for d in s.get("dependents", []) if f"org:{d}" in self.nodes]
            if not deps:
                continue
            runs = [k for k in s.get("runs", []) if f"product:{k}" in self.nodes]
            hot = self.conn.execute(f"""SELECT COUNT(DISTINCT a.cve_id) FROM assessments a JOIN assets x ON x.id = a.asset_id
                                        WHERE a.R > 0 AND a.tier IN ('Compromise','Critical') AND x.product_key IN
                                        ({','.join('?' * len(s['runs'])) or "''"})""", s["runs"]).fetchone()[0] if s.get("runs") else 0
            n = self.node(f"supplier:{s['id']}", "supplier", s["name"], provenance=SIM, source="simulated supplier graph (config/suppliers.json)",
                          sub=f"{s['service']} · serves {len(s.get('dependents', []))} organisation(s)",
                          tier="Critical" if hot else "Medium", risk=min(90.0, 40.0 + hot * 8) if hot else 20.0,
                          facts={"service": s["service"], "dependents": s.get("dependents", []), "runs": s.get("runs", []), "critical_cves": hot})
            for d in deps:
                self.edge(n["id"], f"org:{d}", "serves", "a supplier this organisation depends on", SIM, 1.0 + min(2.0, hot / 5))
            for k in runs:
                self.edge(n["id"], f"product:{k}", "runs", "the supplier runs this technology", SIM, 0.8)

    def _signals(self, rows, orgs) -> set[str]:
        """Build-time decoy surges, live detections and HTTP-shield detections; the part of the graph that breathes."""
        observed: set[str] = set()
        products_here = {r["product_key"] for r in rows}
        host_asset = {r["hostname"]: r["asset_id"] for r in rows}
        host_org = {r["hostname"]: r["org_id"] for r in rows}
        labels = {r["product_key"]: r["label"] for r in rows}

        def attach_technique(sid: str, tid: str | None, when: str | None):
            if not tid:
                return
            t = self._technique_by_id(tid)
            if t:
                self._technique_node(t)
                observed.add(tid)
                self.edge(sid, f"technique:{tid}", "indicates", "what this signal looks like in ATT&CK terms", REAL, 0.9, when)
                self.touch(f"technique:{tid}", when)

        for r in self.cur.execute("SELECT tag, first, last, z_sessions, sensors FROM decoy_surges ORDER BY last DESC LIMIT 12"):
            if r["tag"] not in products_here or (self.as_of is not None and r["first"] > self.as_of.date().isoformat()):
                continue
            sid = f"signal:surge:{r['tag']}:{r['first']}"
            n = self.node(sid, "signal", f"Scanning surge: {labels.get(r['tag'], r['tag'])}", provenance=SIM, source="national decoy grid (24 sensors)",
                          sub=f"{r['first']} → {r['last']} · z {r['z_sessions']:.0f} on {r['sensors']} sensors", tier="High", risk=min(90.0, 40 + r["z_sessions"]),
                          facts={"signal": "surge", "tag": r["tag"], "first": r["first"], "last": r["last"], "z": r["z_sessions"], "sensors": r["sensors"]})
            self.touch(sid, r["last"] + "T23:59:00Z" if len(r["last"]) == 10 else r["last"])
            self.edge(sid, f"product:{r['tag']}", "on", "scanning of this technology on the decoy grid", SIM, min(3.0, r["z_sessions"] / 15), r["last"])
            attach_technique(sid, "T1595.002", r["last"])

        for d in list(self.live.get("detections") or [])[:30]:
            kind = d.get("kind")
            if kind == "surge":
                tag = next((k for k, lab in labels.items() if lab == d.get("product")), None)
                if not tag or tag not in products_here:
                    continue
                target, tier = f"product:{tag}", "High"
            elif kind in ("beacon", "anomaly", "ioc", "watch"):
                host = d.get("asset")
                if kind == "watch":
                    target, tier = (d.get("target") if d.get("target") in self.nodes else None), {"Critical": "Critical", "High": "High"}.get(d.get("severity"), "Medium")
                    sid = f"signal:{d['id']}"
                    self.node(sid, "signal", d.get("title", "watch")[:110], provenance=MIXED, source="watchlist rule (analyst) on the live graph",
                              sub="live · watchlist fired", tier=tier, risk={"Critical": 85.0, "High": 65.0}.get(tier, 45.0),
                              facts={"signal": "watch", "detection": d.get("id"), "ts": d.get("ts"), "target": d.get("target"), "severity": d.get("severity")})
                    self.touch(sid, d.get("ts"))
                    if target:
                        self.edge(sid, target, "on", "the watched entity", MIXED, 1.5, d.get("ts"))
                    continue
                org_id = d.get("org_id") or host_org.get(host)
                if not org_id or f"org:{org_id}" not in self.nodes:
                    continue
                aid = host_asset.get(host)
                target = f"asset:{aid}" if aid and f"asset:{aid}" in self.nodes else f"org:{org_id}"
                tier = "Compromise" if kind == "beacon" else "High"
                if kind == "ioc" and d.get("value") and f"indicator:{d['value']}" in self.nodes:
                    self.edge(f"signal:{d['id']}", f"indicator:{d['value']}", "seen", "the imported indicator this flow matched", SIM, 1.6, d.get("ts"))
            elif kind == "intake":
                target, tier = None, "Medium"
            else:
                continue
            sid = f"signal:{d['id']}"
            n = self.node(sid, "signal", d.get("title", kind)[:110], provenance=SIM, source="live detector (5-second ticks)", sub=f"live · {kind}" + (
                f" · drill {d['drill']}" if d.get("drill") else ""), tier=tier, risk={"beacon": 95.0, "anomaly": 70.0, "surge": 75.0, "intake": 50.0, "ioc": 80.0}[kind],
                          facts={"signal": kind, "detection": d.get("id"), "ts": d.get("ts"), "drill": d.get("drill"),
                                 "seconds_to_detect": d.get("seconds_to_detect"), "z": d.get("z"), "c2": d.get("c2"), "asset": d.get("asset")})
            self.touch(sid, d.get("ts"))
            if target:
                self.edge(sid, target, "on", f"live {kind} detection", SIM, 2.0, d.get("ts"))
                self.touch(target, d.get("ts"))
            attach_technique(sid, SIGNAL_TECHNIQUE.get(kind), d.get("ts"))

        if not self.focus:
            for r in self.cur.execute("""SELECT ts, kind, subject, provenance, payload FROM ledger WHERE kind LIKE 'shield.detect.%'
                                         ORDER BY seq DESC LIMIT 60"""):
                if self.as_of is not None and r["ts"] > _iso(self.as_of):
                    continue
                p = json.loads(r["payload"])
                sid = f"signal:shield:{r['subject']}:{p.get('category')}"
                if sid in self.nodes:
                    self.touch(sid, r["ts"])
                    self.nodes[sid]["facts"]["hits"] += 1
                    continue
                app, _, ip = r["subject"].rpartition(":")
                n = self.node(sid, "signal", f"{p.get('category', r['kind'].split('.')[-1])} against {app} from {ip}", provenance=r["provenance"],
                              source="HTTP shield (inline request inspection)" + (" · red-team exercise" if p.get("redteam") else ""),
                              sub=f"HTTP shield · {p.get('decision', 'detected')} · {p.get('cwe', '')}", tier="Critical" if p.get("decision") == "allow" else "High",
                              risk=80.0 if p.get("decision") == "allow" else 55.0,
                              facts={"signal": "shield", "app": app, "source_ip": ip, "category": p.get("category"), "cwe": p.get("cwe"),
                                     "decision": p.get("decision"), "path": p.get("path"), "redteam": p.get("redteam"), "hits": 1})
                self.touch(sid, r["ts"])
                attach_technique(sid, p.get("attack"), r["ts"])
        return observed

    def _actors(self, techniques: set[str], families: set[str]) -> None:
        """Threat groups whose ATT&CK record overlaps what is observed here. Overlap with the public record, not attribution."""
        if not techniques and not families:
            return
        groups, _ = _groups()
        expanded = techniques | {_parent(t) for t in techniques}
        scored = []
        for g in groups:
            if len(g["techniques"]) > MAX_ACTOR_TECHNIQUES or not g["id"]:
                continue
            g_all = g["techniques"] | {_parent(t) for t in g["techniques"]}
            overlap = sorted(t for t in techniques if t in g_all or _parent(t) in g["techniques"])
            mal = sorted(families & g["malware"])
            if not mal and len(overlap) < max(3, math.ceil(0.6 * len(techniques))):
                continue
            score = len(overlap) + 3 * len(mal)
            scored.append((score, -len(g["techniques"]), g, overlap, mal))
        # groups recorded using the malware families actually seen come first; technique overlap fills the rest
        scored.sort(key=lambda x: (not x[4], -x[0], x[1], x[2]["name"]))
        for score, _, g, overlap, mal in scored[:ACTOR_CAP]:
            basis = []
            if mal:
                basis.append(f"uses {', '.join(m.title() for m in mal)}")
            basis.append(f"known to use {len(overlap)} of the {len(techniques)} techniques observed")
            n = self.node(f"actor:{g['id']}", "actor", g["name"], provenance=REAL, source="MITRE ATT&CK group record (local STIX snapshot)",
                          sub="; ".join(basis) + " · overlap, not attribution",
                          facts={"group_id": g["id"], "aliases": g["aliases"], "description": g["description"], "url": g["url"],
                                 "overlap": overlap, "malware": mal, "techniques_documented": len(g["techniques"]),
                                 "note": "Technique overlap with the public ATT&CK record. Odyssey does not attribute activity to a group."})
            for t in overlap:
                self.edge(n["id"], f"technique:{t}", "uses", "ATT&CK records this group using this technique", REAL, 0.7)
                self.touch(n["id"], _iso(self.seen.get(f"technique:{t}")) if self.seen.get(f"technique:{t}") else None)
            for m in mal:
                self.edge(n["id"], f"malware:{m}", "uses", "ATT&CK records this group using this malware", REAL, 1.1)
                self.touch(n["id"], _iso(self.seen.get(f"malware:{m}")) if self.seen.get(f"malware:{m}") else None)

    def _evidence_times(self, rows) -> None:
        """Latest evidence per node from the ledger: autopilot and analyst actions, intake, KEV, surges, adaptation."""
        cve_products = defaultdict(set)
        for r in rows:
            cve_products[r["cve_id"]].add(r["product_key"])
        cutoff = (self.now - dt.timedelta(days=120)).isoformat()
        until = _iso(self.as_of) if self.as_of is not None else "9999"
        for ts, kind, subject, payload in self.conn.execute(
                "SELECT ts, kind, subject, payload FROM ledger WHERE ts >= ? AND ts <= ? ORDER BY seq", (cutoff, until)):
            if kind.startswith("shield.") or kind in ("vuln.published",):
                continue
            targets = []
            if ":" in subject and subject.split(":")[0] in {n["facts"].get("org_id") for n in self.nodes.values() if n["kind"] == "org"}:
                org_id, cve = subject.split(":", 1)
                targets += [f"org:{org_id}", f"cve:{cve}"] + [f"product:{k}" for k in cve_products.get(cve, ())]
            elif subject.startswith("product:"):
                targets.append(subject)
            elif subject.startswith("CVE-"):
                targets += [f"cve:{subject}"] + [f"product:{k}" for k in cve_products.get(subject, ())]
            else:
                targets.append(f"asset:{subject}")
            try:
                p = json.loads(payload) if payload else {}
            except ValueError:
                p = {}
            if isinstance(p, dict):
                if p.get("org_id"):
                    targets.append(f"org:{p['org_id']}")
                if p.get("asset_id"):
                    targets.append(f"asset:{p['asset_id']}")
                if p.get("tag"):
                    targets.append(f"product:{p['tag']}")
                if p.get("dst_defanged"):
                    targets.append(f"indicator:{p['dst_defanged']}")
            for t in targets:
                if t in self.nodes:
                    self.touch(t, ts)

    def _finish(self, orgs) -> dict:
        # drop edges whose ends are missing, then nodes with no edges except organisations (they anchor the picture)
        edges = [e for e in self.edges.values() if e["from"] in self.nodes and e["to"] in self.nodes and e["from"] != e["to"]]
        degree: dict[str, int] = defaultdict(int)
        for e in edges:
            degree[e["from"]] += 1
            degree[e["to"]] += 1
        nodes = [n for n in self.nodes.values() if degree[n["id"]] or n["kind"] == "org"]
        ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["from"] in ids and e["to"] in ids]
        for n in nodes:
            last = self.seen.get(n["id"])
            age = (self.now - last).total_seconds() / 3600 if last else None
            n.update({"last_seen": _iso(last), "age_h": round(age, 1) if age is not None else None, "pulse": _pulse(age),
                      "phase": _phase(age), "degree": degree[n["id"]]})
            if n["risk"] is None and n["tier"]:
                n["risk"] = {"Compromise": 95.0, "Critical": 80.0, "High": 60.0, "Medium": 35.0, "Watch": 10.0}[n["tier"]]
        self._layout(nodes, edges, orgs)
        counts = defaultdict(int)
        for n in nodes:
            counts[n["kind"]] += 1
        phases = defaultdict(int)
        for n in nodes:
            phases[n["phase"]] += 1
        hour_ago = time.time() - 3600
        # events of the last hour: ingested in it and dated in it, so a rebuild's back-dated history does not count
        rate = self.conn.execute("SELECT COUNT(*) FROM ledger WHERE ingested >= ? AND ts >= ?",
                                 (hour_ago, _iso(self.now - dt.timedelta(hours=1)))).fetchone()[0]
        last_event = self.conn.execute("SELECT ts FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        focus = {"kind": "org", "id": self.focus, "label": orgs[self.focus]["name"]} if self.focus else {"kind": "national", "id": None, "label": "India, all operators"}
        return {
            "focus": focus, "built_at": _iso(self.now), "snapshot": self.conn.execute("SELECT value FROM meta WHERE key = 'snapshot_date'").fetchone()[0],
            "nodes": nodes, "edges": edges, "rings": (max(RINGS_ORG.values()) if self.focus else max(RINGS_NATIONAL.values())) + 1,
            "kinds": [{"id": k, "label": KIND_LABELS[k], "count": counts[k]} for k in KIND_LABELS if counts[k]],
            "breath": {"fresh": phases["fresh"], "today": phases["today"], "week": phases["week"], "fading": phases["fading"], "aged": phases["aged"],
                       "events_last_hour": rate, "last_event": last_event[0] if last_event else None,
                       "live_ticks": self.live.get("ticks"), "live_detections": len(self.live.get("detections") or [])},
            "summary": {"nodes": len(nodes), "edges": len(edges), "real_edges": sum(e["provenance"] == REAL for e in edges),
                        "sim_edges": sum(e["provenance"] == SIM for e in edges), "mixed_edges": sum(e["provenance"] == MIXED for e in edges)},
            "provenance": {"REAL": ["NVD, CISA KEV, SSVC, EPSS", "MITRE ATT&CK (techniques, groups, software)", "abuse.ch Feodo Tracker", "OpenPhish"],
                           "SIM": ["organisations, assets and inventory", "decoy grid and firewall sightings", "supplier graph", "live sensor streams"],
                           "note": "Threat groups are technique overlap with the ATT&CK record, not attribution. Pulse is evidence age, not severity."},
        }

    def _layout(self, nodes, edges, orgs) -> None:
        rings = RINGS_ORG if self.focus else RINGS_NATIONAL
        nrings = max(rings.values()) + 1
        by_ring: dict[int, list[dict]] = defaultdict(list)
        for n in nodes:
            n["ring"] = rings.get(n["kind"], nrings - 1)
            by_ring[n["ring"]].append(n)
        angle: dict[str, float] = {}
        adj: dict[str, list[str]] = defaultdict(list)
        for e in edges:
            adj[e["from"]].append(e["to"])
            adj[e["to"]].append(e["from"])
        for ring in range(nrings):
            group = by_ring.get(ring, [])
            if not group:
                continue
            if ring == 0:
                group.sort(key=lambda n: (n["facts"].get("sector", ""), n["label"]))
                for i, n in enumerate(group):
                    angle[n["id"]] = 2 * math.pi * i / len(group) - math.pi / 2
                continue
            desired = []
            for i, n in enumerate(group):
                inner = [angle[m] for m in adj[n["id"]] if m in angle]
                if inner:
                    a = math.atan2(sum(math.sin(x) for x in inner), sum(math.cos(x) for x in inner))
                else:
                    a = 2 * math.pi * (hash(n["id"]) % 1000) / 1000 - math.pi
                desired.append((a, n["label"], n))
            desired.sort(key=lambda x: (x[0], x[1]))
            gap = min(2 * math.pi / len(desired), 0.17)
            placed = []
            for a, _, n in desired:
                if placed and a < placed[-1] + gap:
                    a = placed[-1] + gap
                placed.append(a)
            span = placed[-1] - placed[0] if len(placed) > 1 else 0
            if span > 2 * math.pi - gap:  # no room for the preferred angles at this gap: keep the order, space evenly
                placed = [placed[0] + 2 * math.pi * i / len(placed) for i in range(len(placed))]
            for (_, _, n), a in zip(desired, placed):
                angle[n["id"]] = a
        for n in nodes:
            single_centre = n["ring"] == 0 and len(by_ring[0]) == 1
            n["angle"] = round(angle.get(n["id"], 0.0), 4)
            n["r"] = 0.0 if single_centre else round((n["ring"] + 1) / nrings, 4)


def intel_graph(conn: sqlite3.Connection, focus: str | None = None, live: dict | None = None,
                now: dt.datetime | None = None, as_of: dt.datetime | None = None) -> dict:
    """The graph for the nation (focus=None) or one organisation. Cached for a few seconds per focus.
    `as_of` replays the record as it stood at that instant: later evidence is left out and pulses are aged to it."""
    key = focus or ""
    if as_of is not None:
        g = _Builder(conn, focus, live, as_of, as_of=as_of).build()
        g["as_of"] = _iso(as_of)
        return g
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and now is None and time.time() - hit[0] < CACHE_S:
            return hit[1]
    g = _Builder(conn, focus, live, now or dt.datetime.now(dt.timezone.utc)).build()
    if now is None:
        with _LOCK:
            _CACHE[key] = (time.time(), g)
    return g


def replay_steps(conn: sqlite3.Connection, now: dt.datetime | None = None) -> list[dict]:
    """Instants the interface offers for replay: the snapshot date, then fixed look-backs, then now."""
    now = now or dt.datetime.now(dt.timezone.utc)
    snap = conn.execute("SELECT value FROM meta WHERE key = 'snapshot_date'").fetchone()
    steps = []
    if snap:
        steps.append({"id": "snapshot", "label": f"snapshot {snap[0]}", "at": snap[0] + "T23:59:59Z"})
    for days, label in ((30, "30 days ago"), (14, "14 days ago"), (7, "7 days ago"), (3, "3 days ago"), (1, "yesterday")):
        steps.append({"id": f"d{days}", "label": label, "at": _iso(now - dt.timedelta(days=days))})
    steps.append({"id": "h6", "label": "6 hours ago", "at": _iso(now - dt.timedelta(hours=6))})
    steps.append({"id": "h1", "label": "1 hour ago", "at": _iso(now - dt.timedelta(hours=1))})
    steps.append({"id": "now", "label": "now", "at": None})
    return steps


def node_card(conn: sqlite3.Connection, node_id: str, focus: str | None = None, live: dict | None = None) -> dict:
    """One entity's intelligence card: the node, its neighbours and the evidence behind it, from the record."""
    g = intel_graph(conn, focus, live)
    node = next((n for n in g["nodes"] if n["id"] == node_id), None)
    if node is None:
        raise KeyError(node_id)
    by_id = {n["id"]: n for n in g["nodes"]}
    neighbours = []
    for e in g["edges"]:
        if e["from"] == node_id or e["to"] == node_id:
            other = by_id[e["to"] if e["from"] == node_id else e["from"]]
            neighbours.append({"id": other["id"], "kind": other["kind"], "label": other["label"], "tier": other["tier"], "pulse": other["pulse"],
                               "relation": e["label"], "edge": e["kind"], "provenance": e["provenance"], "direction": "out" if e["from"] == node_id else "in"})
    neighbours.sort(key=lambda x: (-(RANK.get(x["tier"] or "", -1)), -x["pulse"], x["label"]))
    kind, f = node["kind"], node["facts"]
    clauses, args = [], []
    if kind == "org":
        clauses, args = ["subject LIKE ?", "payload LIKE ?"], [f"{f['org_id']}:%", f'%"org_id": "{f["org_id"]}"%']
    elif kind == "cve":
        clauses, args = ["subject = ?", "subject LIKE ?"], [f["cve_id"], f"%:{f['cve_id']}"]
    elif kind == "product":
        cves = [r[0] for r in conn.execute("""SELECT DISTINCT a.cve_id FROM assessments a JOIN assets s ON s.id = a.asset_id
                                              WHERE s.product_key = ? AND a.R > 0 AND a.tier != 'Watch'""", (f["product_key"],))]
        clauses, args = ["subject = ?", "subject = ?"], [f"product:{f['product_key']}", f["product_key"]]
        for c in cves[:200]:
            clauses.append("subject LIKE ?")
            args.append(f"%{c}")
    elif kind == "asset":
        clauses, args = ["subject = ?", "payload LIKE ?"], [f["asset_id"], f'%"{f["hostname"]}"%']
    elif kind == "indicator":
        clauses, args = ["payload LIKE ?"], [f"%{f['value']}%"]
    elif kind == "signal":
        if f.get("detection"):
            clauses, args = ["payload LIKE ?"], [f'%"{f["detection"]}"%']
        elif f.get("tag"):
            clauses, args = ["subject = ?"], [f"product:{f['tag']}"]
        elif f.get("source_ip"):
            clauses, args = ["subject LIKE ?"], [f"%{f['source_ip']}"]
    elif kind == "campaign":
        clauses, args = ["subject = ?"], [f"product:{node_id.split(':', 1)[1]}"]
        for c in f.get("cves", [])[:50]:
            clauses.append("subject LIKE ?")
            args.append(f"%{c}")
    events = []
    if clauses:
        rows = conn.execute(f"""SELECT ts, kind, subject, source, provenance, payload FROM ledger
                                WHERE {' OR '.join(clauses)} ORDER BY ts DESC LIMIT 30""", args).fetchall()
        for ts, k, subject, source, prov, payload in rows:
            try:
                p = json.loads(payload) if payload else {}
            except ValueError:
                p = {}
            text = next((str(p[x]) for x in ("title", "basis", "what", "why", "action", "vulnerabilityName", "requiredAction") if isinstance(p, dict) and p.get(x)), "")
            events.append({"ts": ts, "kind": k, "subject": subject, "source": source, "provenance": prov, "text": text[:200]})
    live_hits = []
    if kind in ("signal",) and f.get("detection"):
        live_hits = [d for d in (live or {}).get("detections") or [] if d.get("id") == f["detection"]]
    return {"node": node, "neighbours": neighbours[:40], "events": events, "live": live_hits, "focus": g["focus"],
            "record": {"kind": kind, "how": {
                "org": "Open warnings, cases and autopilot actions recorded against this organisation.",
                "asset": "Open warnings on this asset and every sighting or action that names it.",
                "product": "Warnings, surges and actions on this technology across the constituency.",
                "cve": "The vulnerability record (NVD, KEV, SSVC, EPSS) and every action Odyssey took on it.",
                "campaign": "Exploited CVEs, decoy surges and chained assets correlated on one technology.",
                "technique": "Mapped by explicit rules from vulnerability text, asset exposure and detector output; mitigations come from ATT&CK's own relationships.",
                "malware": "The family the C2 serves (Feodo Tracker) and its ATT&CK software record.",
                "actor": "ATT&CK records this group using these techniques and software. Overlap with the public record; Odyssey does not attribute.",
                "indicator": "A public indicator (Feodo Tracker or OpenPhish) and where it was seen in our telemetry.",
                "supplier": "A supplier relationship in the simulated supplier graph and the technologies the supplier runs.",
                "signal": "A detector output: what it saw, when, and the threshold that applied."}.get(kind, "")}}
