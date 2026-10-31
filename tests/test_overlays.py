"""The prior-art items closed in the last pass: evidence decay and age-off, India's reporting clocks, supplier
fan-out, and the hostile advisory in the inbox."""

import json
from pathlib import Path

import pytest

from backend.app.engine.exposure import reconcile
from backend.app.engine.obligations import obligations
from backend.app.engine.scoring import assess, config
from backend.app.engine.suppliers import of_org, reach
from backend.app.ingest.cve_records import build_record, load_epss, load_kev, load_nvd

POWER_ORG = {"id": "PWR-01", "name": "Vidyut Grid West Corp", "sector": "Power & Energy", "cii": True}
VPN = {"id": "PWR-01-A001", "vendor": "ivanti", "product": "connect_secure", "version": "22.8R2.4",
       "tier": 1, "zone": "internet", "role": "vpn", "tier1_reachable": 3}


@pytest.fixture(scope="module")
def auth_bypass():
    cid = "CVE-2026-104935"
    epss, _ = load_epss()
    return build_record(cid, load_nvd({cid}).get(cid), load_kev().get(cid), epss.get(cid))


def _surge(rec, age):
    return assess(rec, VPN, POWER_ORG, reconcile(VPN, rec), {"decoy_surge": 12.0, "ages": {"DECOY_SURGE": age}})


def test_sensor_evidence_fades_then_ages_off(auth_bypass):
    fresh, old, gone = _surge(auth_bypass, 0), _surge(auth_bypass, 28), _surge(auth_bypass, 60)
    by_id = lambda a: {r.id: r for r in a.rules}  # noqa: E731
    assert "weight x1.00" in by_id(fresh)["DECOY_SURGE"].evidence
    assert "weight x0.25" in by_id(old)["DECOY_SURGE"].evidence      # two half-lives of 14 days
    assert "DECOY_SURGE" not in by_id(gone)                           # past the 45-day age-off
    assert {"KEV", "SSVC_ACTIVE"} <= set(by_id(gone))                 # catalogue facts never decay
    assert fresh.V >= old.V >= gone.V


def test_compromise_starts_every_clock_that_applies():
    cfg = config()[0]
    bank = {"id": "BFS-01", "name": "Navnidhi Bank", "sector": "BFSI", "cii": True}
    clocks = {c["who"]: c["hours"] for c in obligations(cfg, bank, {"role": "payments"}, "Compromise", 6, "")}
    assert clocks["CERT-In"] == 6 and clocks["RBI"] == 6 and clocks["Data Protection Board"] == 72
    assert "NCIIPC" in clocks and "CSIRT-Fin" in clocks
    broker = {"id": "BFS-02", "name": "Kshitij Finance & Insurance", "sector": "BFSI", "cii": False}
    assert {c["who"] for c in obligations(cfg, broker, {"role": "vpn"}, "Compromise", 6, "")} >= {"CERT-In", "SEBI"}
    patch = obligations(cfg, bank, {"role": "vpn"}, "Critical", 12, "Known-exploited and internet-facing", "2026-10-16")
    assert patch[0]["hours"] == 12 and "Patch" in patch[0]["what"] and patch[-1]["who"].startswith("CISA")


def test_supplier_fan_out_reaches_dependents_who_do_not_run_the_product():
    names = {o: {"name": o} for o in ("PWR-01", "PWR-02", "PWR-03", "TRN-01", "TRN-02")}
    hit = reach("beyondtrust", names, runs_it={"PWR-01", "PWR-02", "PWR-03"})
    assert [s["name"] for s in hit] == ["GridSys OT Integrators"]
    assert hit[0]["only_via_supplier"] == 2                           # the two transport operators
    assert reach("exchange", names) == [] and reach(None, names) == []
    assert {s["id"] for s in of_org("BFS-03")} == {"SUP-01"}


def test_hostile_advisory_in_the_inbox_is_blocked_before_any_model_reads_it():
    from backend.app.ai.guard import screen
    inbox = json.loads((Path(__file__).resolve().parents[1] / "data" / "sim" / "advisories.json").read_text(encoding="utf-8"))
    hostile = next(a for a in inbox if a["id"] == "CIVN-SIM-2026-0431")
    assert screen(hostile["text"])["verdict"] == "blocked"
