"""The intelligence graph is a faithful, breathing subset of the record: every edge joins two drawn nodes, every element
carries provenance, pulse is evidence age (fresh live evidence breathes, old evidence lies still), the layout is
deterministic, one organisation in focus shows only that organisation, and threat groups are overlap, not attribution."""

import datetime as dt
import sqlite3
from pathlib import Path

import pytest

from backend.app.engine.graph import MIXED, REAL, SIM, _pulse, intel_graph, node_card

DB = Path(__file__).resolve().parents[1] / "data" / "ews.db"
NOW = dt.datetime(2026, 11, 1, 2, 0, tzinfo=dt.timezone.utc)


@pytest.fixture(scope="module")
def copy(tmp_path_factory):
    if not DB.exists():
        pytest.skip("no built database")
    path = tmp_path_factory.mktemp("graph") / "ews.db"
    src, dst = sqlite3.connect(f"file:{DB}?mode=ro", uri=True), sqlite3.connect(path)
    src.backup(dst)
    src.close()
    dst.close()
    return sqlite3.connect(path, timeout=30, check_same_thread=False)


def _ids(g):
    return {n["id"] for n in g["nodes"]}


def test_national_graph_is_a_consistent_subset_of_the_record(copy):
    g = intel_graph(copy, None, None, now=NOW)
    ids = _ids(g)
    assert len(ids) == len(g["nodes"]) and g["edges"]
    assert all(e["from"] in ids and e["to"] in ids and e["from"] != e["to"] for e in g["edges"])
    assert all(e["provenance"] in (REAL, SIM, MIXED) for e in g["edges"])
    assert all(n["provenance"] in (REAL, SIM, MIXED) and n["label"] and n["kind"] for n in g["nodes"])
    kinds = {k["id"] for k in g["kinds"]}
    assert {"org", "product", "cve", "campaign", "technique", "actor", "indicator", "supplier", "signal"} <= kinds
    assert sum(k["count"] for k in g["kinds"]) == len(g["nodes"])
    assert all(0.0 <= n["pulse"] <= 1.0 and n["phase"] in ("fresh", "today", "week", "fading", "aged") for n in g["nodes"])
    # the C2 the compromised VPN gateway calls is a REAL indicator with its malware family and the groups that use it
    c2 = next(n for n in g["nodes"] if n["kind"] == "indicator" and n["facts"]["type"] == "ipv4-addr")
    assert c2["provenance"] == REAL and c2["facts"]["malware"]
    fam = next(n for n in g["nodes"] if n["kind"] == "malware")
    assert any(e["from"] == c2["id"] and e["to"] == fam["id"] and e["provenance"] == REAL for e in g["edges"])
    users = [n for n in g["nodes"] if n["kind"] == "actor" and n["facts"]["malware"]]
    assert users and all(any(e["from"] == a["id"] and e["to"] == fam["id"] for e in g["edges"]) for a in users)


def test_threat_groups_are_overlap_not_attribution(copy):
    g = intel_graph(copy, None, None, now=NOW)
    actors = [n for n in g["nodes"] if n["kind"] == "actor"]
    assert 1 <= len(actors) <= 8
    for a in actors:
        assert "not attribution" in a["sub"] and "not attribute" in a["facts"]["note"]
        assert a["provenance"] == REAL and a["facts"]["url"].startswith("https://attack.mitre.org/groups/")
        assert a["facts"]["overlap"] or a["facts"]["malware"]
        # every technique edge from a group points at a technique that is actually observed in this graph
        for e in g["edges"]:
            if e["from"] == a["id"] and e["to"].startswith("technique:"):
                assert e["to"].split(":", 1)[1] in a["facts"]["overlap"]


def test_pulse_is_evidence_age_and_live_signals_breathe(copy):
    assert _pulse(0) == 1.0 and 0.55 < _pulse(24) < 0.65 and _pulse(24 * 7) < 0.04 and _pulse(None) == 0.0
    live = {"ticks": 10, "detections": [{"id": "DET-TEST-1", "ts": NOW.isoformat(), "kind": "beacon", "org_id": "PWR-01",
                                         "asset": "vpn-gw01.vgwc.example", "c2": "203[.]0[.]113[.]9", "interval_s": 60.0,
                                         "title": "Periodic beacon from vpn-gw01 to 203[.]0[.]113[.]9"}]}
    g = intel_graph(copy, None, live, now=NOW)
    sig = next(n for n in g["nodes"] if n["id"] == "signal:DET-TEST-1")
    assert sig["pulse"] >= 0.99 and sig["phase"] == "fresh" and sig["tier"] == "Compromise"
    assert any(e["from"] == sig["id"] and e["to"] == "org:PWR-01" for e in g["edges"])
    assert any(e["from"] == sig["id"] and e["to"] == "technique:T1071.001" for e in g["edges"])
    org = next(n for n in g["nodes"] if n["id"] == "org:PWR-01")
    assert org["phase"] == "fresh"
    # the same picture without the live detection: the organisation's evidence is older
    quiet = next(n for n in intel_graph(copy, None, None, now=NOW)["nodes"] if n["id"] == "org:PWR-01")
    assert quiet["pulse"] <= org["pulse"]


def test_layout_is_deterministic_and_keeps_nodes_apart(copy):
    a = intel_graph(copy, None, None, now=NOW)
    b = intel_graph(copy, None, None, now=NOW)
    assert [(n["id"], n["ring"], n["angle"], n["r"]) for n in a["nodes"]] == [(n["id"], n["ring"], n["angle"], n["r"]) for n in b["nodes"]]
    rings: dict[int, list[float]] = {}
    for n in a["nodes"]:
        rings.setdefault(n["ring"], []).append(n["angle"])
        assert 0.0 <= n["r"] <= 1.0
    for ring, angles in rings.items():
        angles.sort()
        gaps = [y - x for x, y in zip(angles, angles[1:])]
        if gaps:
            assert min(gaps) >= min(6.283 / len(angles), 0.17) - 1e-6, f"ring {ring} too crowded"
    assert [n["kind"] for n in a["nodes"] if n["ring"] == 0] == ["org"] * sum(k["count"] for k in a["kinds"] if k["id"] == "org")


def test_one_organisation_in_focus(copy):
    g = intel_graph(copy, "PWR-01", None, now=NOW)
    assert g["focus"] == {"kind": "org", "id": "PWR-01", "label": "Vidyut Grid West Corp"}
    orgs = [n for n in g["nodes"] if n["kind"] == "org"]
    assert len(orgs) == 1 and orgs[0]["r"] == 0.0
    assets = [n for n in g["nodes"] if n["kind"] == "asset"]
    assert assets and all(n["facts"]["hostname"].endswith("vgwc.example") for n in assets)
    ids = _ids(g)
    assert all(e["from"] in ids and e["to"] in ids for e in g["edges"])
    vpn = next(n for n in assets if n["facts"]["hostname"].startswith("vpn-gw01"))
    assert vpn["tier"] == "Compromise"
    assert any(e["from"] == vpn["id"] and e["kind"] == "beacons" for e in g["edges"])
    with pytest.raises(KeyError):
        intel_graph(copy, "NOPE-99", None, now=NOW)


def test_entity_cards_carry_neighbours_and_evidence(copy):
    g = intel_graph(copy, None, None, now=NOW)
    cve = next(n for n in g["nodes"] if n["kind"] == "cve" and n["facts"]["kev_added"])
    card = node_card(copy, cve["id"])
    assert card["node"]["id"] == cve["id"] and card["neighbours"] and card["events"]
    assert any(e["kind"] == "kev.added" for e in card["events"])
    assert all(e["provenance"] for e in card["events"]) and card["record"]["how"]
    org = node_card(copy, "org:PWR-01")
    assert org["events"] and all(e["subject"].startswith("PWR-01") or "PWR-01" in e["subject"] for e in org["events"][:5])
    actor = node_card(copy, next(n["id"] for n in g["nodes"] if n["kind"] == "actor"))
    assert actor["neighbours"] and "not attribute" in actor["record"]["how"]
    with pytest.raises(KeyError):
        node_card(copy, "cve:CVE-1900-0000")


def test_risk_lists_are_scored_and_sourced(copy):
    from backend.app.engine import export
    lists = export.summary(copy)
    assert [x["id"] for x in lists["lists"]] == ["cves", "ips", "domains", "products"]
    cves = export.risk_list(copy, "cves")
    assert cves and cves[0]["score"] >= cves[-1]["score"] and cves[0]["tier"] == "Compromise" and cves[0]["kev"]
    ips = export.risk_list(copy, "ips")
    c2 = next(r for r in ips if r["role"] == "c2_seen")
    assert c2["value"].count(".") == 3 and "[.]" not in c2["value"] and c2["defanged"].count("[.]") == 3 and c2["malware"]
    assert all(r["provenance"] in (REAL, SIM, MIXED) and r["evidence"] for r in ips)
    csv_text = export.to_csv(cves)
    assert csv_text.splitlines()[0].startswith("cve,score,tier,kev") and len(csv_text.splitlines()) == len(cves) + 1
    products = export.risk_list(copy, "products")
    assert products and products[0]["score"] >= products[-1]["score"] and all(r["product_key"] for r in products)
    with pytest.raises(KeyError):
        export.risk_list(copy, "nope")


def test_stix_bundle_of_the_graph_has_no_dangling_reference(copy):
    from backend.app.engine import export
    b = export.graph_stix(intel_graph(copy, None, None, now=NOW))
    ids = {o["id"] for o in b["objects"]}
    assert b["type"] == "bundle" and len(ids) == len(b["objects"])
    types = {o["type"] for o in b["objects"]}
    assert {"identity", "vulnerability", "software", "campaign", "attack-pattern", "malware", "intrusion-set", "indicator",
            "sighting", "relationship"} <= types
    for o in b["objects"]:
        if o["type"] == "relationship":
            assert o["source_ref"] in ids and o["target_ref"] in ids
        if o["type"] == "sighting":
            assert o["sighting_of_ref"] in ids and all(w in ids for w in o["where_sighted_refs"])
        if o["type"] == "note":
            assert o["object_refs"] and all(r in ids for r in o["object_refs"])
        if o["type"] == "intrusion-set":
            assert "not attribute" in o["description"] and o["external_references"][0]["source_name"] == "mitre-attack"
        if o["type"] == "indicator":
            assert o["pattern"].startswith("[ipv4-addr:value = '") or o["pattern"].startswith("[domain-name:value = '")
