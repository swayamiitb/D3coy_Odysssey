"""Advisory text parsing: IOC extraction and version constraints (deterministic layers only; no models)."""

import pytest

from backend.app.ai.advisory import iocs
from backend.app.engine.exposure import text_constraints, text_vote
from backend.app.engine.versions import Version


@pytest.mark.parametrize("text,expected", [
    ("Apply the vendor updates 22.8R2.5 or 25.1.3.0 and check integrity.", []),          # versions, not IPs
    ("versions prior to 25.1.3.0 are affected", []),
    ("Implants beacon to 50.16.16.211 every 60 seconds; upgrade to 7.2.9.", ["50[.]16[.]16[.]211"]),
    ("lookalike domains such as abc-kyc-update[.]example hosted on 198.51.100.77",
     ["198[.]51[.]100[.]77"]),                                                             # hyphenated 'update'
])
def test_ip_extraction_distinguishes_versions(text, expected):
    assert iocs(text)["ips"] == expected


def test_defanged_indicators():
    found = iocs("Payload from hxxp://bad-host[.]example/kyc.apk (SHA-256 " + "a" * 64 + ")")
    assert found["urls"] == ["hxxp://bad-host[.]example/kyc.apk"]
    assert found["sha256"] == ["a" * 64]


def test_vendor_update_suffix_versions():
    got = text_constraints("Software Affected: SIMATIC WinCC versions before 8.0 Update 3.")
    assert got[0]["version"] == "8.0 Update 3"
    assert Version("8.0") < Version("8.0 Update 3") and Version("7.5_sp2") < Version("8.0 Update 3")
    vote = text_vote({"vendor": "siemens", "product": "simatic_wincc", "version": "8.0"},
                     "SIMATIC WinCC versions before 8.0 Update 3 are affected.")
    assert vote.verdict == "affected"
