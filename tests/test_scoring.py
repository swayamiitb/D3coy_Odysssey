"""Scoring/decision tests on the real Ivanti chain plus synthetic edge cases."""

import pytest

from backend.app.engine.exposure import Exposure, Vote, reconcile
from backend.app.engine.ledger import Ledger
from backend.app.engine.scoring import assess
from backend.app.ingest.cve_records import build_record, load_epss, load_kev, load_nvd

POWER_ORG = {"id": "PWR-01", "sector": "Power & Energy", "cii": True}
BANK_ORG = {"id": "BFS-01", "sector": "BFSI", "cii": True}
VPN = {"id": "PWR-01-A001", "vendor": "ivanti", "product": "connect_secure", "version": "22.8R2.4",
       "tier": 1, "zone": "internet", "role": "vpn", "tier1_reachable": 3}
PATCHED = {"id": "BFS-01-A001", "vendor": "ivanti", "product": "connect_secure", "version": "25.1.3.0",
           "tier": 2, "zone": "internet", "role": "vpn", "tier1_reachable": 2}


@pytest.fixture(scope="module")
def auth_bypass():
    cid = "CVE-2026-104935"
    epss, _ = load_epss()
    return build_record(cid, load_nvd({cid}).get(cid), load_kev().get(cid), epss.get(cid))


def test_exposed_power_vpn_is_critical_with_12h_deadline(auth_bypass):
    a = assess(auth_bypass, VPN, POWER_ORG, reconcile(VPN, auth_bypass))
    assert a.tier == "Critical" and a.decision == "Act"
    assert a.L == 1.0 and a.R == 1.0
    assert 85 <= a.risk <= 100  # K normalised: crown jewel + internet-facing + 3 tier-1 systems reachable
    assert a.deadline_hours == 12
    assert {r.id for r in a.rules} >= {"KEV", "SSVC_ACTIVE", "AUTOMATABLE"}
    assert a.kev_due == "2026-10-16"


def test_patched_bank_vpn_scores_zero(auth_bypass):
    a = assess(auth_bypass, PATCHED, BANK_ORG, reconcile(PATCHED, auth_bypass))
    assert a.R == 0.0 and a.risk == 0.0 and a.deadline_hours is None
    assert "not affected (cleared)" in a.decision_path


def test_unexploited_but_automatable_on_open_crown_jewel_is_high():
    vuln = {"id": "CVE-TEST-0002", "description": "", "ssvc": {}, "kev": None, "epss": 0.02,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_source": "CNA"}
    exposure = Exposure("PWR-01-A001", "CVE-TEST-0002", "affected", 1.0,
                        [Vote("CNA", "affected", "explicit", "listed")])
    a = assess(vuln, VPN, POWER_ORG, exposure)
    assert a.tier == "High" and a.decision == "Attend"
    assert a.risk < 100  # no exploitation evidence: likelihood stays at EPSS, no floor


def test_ledger_detects_tampering(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.append(ts="2026-10-13T15:31:07Z", kind="vuln.published", subject="CVE-2026-104935", source="CNA",
               payload={"cvss": 8.6})
    led.append(ts="2026-10-13T15:42:00Z", kind="kev.added", subject="CVE-2026-104935", source="CISA_KEV",
               payload={"due": "2026-10-16"})
    assert led.verify() == (True, None)
    led.db.execute("UPDATE ledger SET payload = '{\"cvss\":4.0}' WHERE seq = 1")
    assert led.verify() == (False, 1)
