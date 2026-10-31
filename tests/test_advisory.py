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


def test_restated_deadline_must_keep_its_authority():
    from backend.app.ai.narrate import validate
    facts = {"F5": "Decision: tier Compromise (SSVC Act) because suspected compromise: report to cert-in within 6 hours.",
             "F8": "US CISA added this CVE to its Known Exploited Vulnerabilities catalogue on 2026-10-13."}
    ok = {"headline": "h", "why_it_matters": [{"text": "Report findings to CERT-In within 6 hours.", "cites": ["F5"]}],
          "what_to_do": []}
    wrong = {"headline": "h", "why_it_matters": [{"text": "CISA requires a fix within 6 hours.", "cites": ["F5"]}],
             "what_to_do": []}
    assert validate(ok, facts) == []
    assert any("authority" in p for p in validate(wrong, facts))


def test_vers_ranges_from_cisa_csaf_advisories():
    text = ("The following versions of Siemens WinCC are affected: SIMATIC WinCC V7.5 vers:all/* (CVE-2026-59241) "
            "SIMATIC WinCC V8.0 vers:intdot/<8.0.0.11 (CVE-2026-59241) SIMATIC WinCC V8.1 vers:intdot/<8.1.7")
    ranges = {(c["start"], c["version"]) for c in text_constraints(text)}
    assert ranges == {("7.5", "7.6"), ("8.0", "8.0.0.11"), ("8.1", "8.1.7")}
    asset = {"vendor": "siemens", "product": "simatic_wincc"}
    assert text_vote({**asset, "version": "7.5_sp2"}, text).verdict == "affected"   # whole line affected, no fix
    assert text_vote({**asset, "version": "8.0"}, text).verdict == "affected"
    assert text_vote({**asset, "version": "8.1.7"}, text).verdict == "not_affected"  # the fixed release itself


def test_versions_and_vendor_links_are_not_indicators():
    text = ("SIMATIC WinCC V8.0 vers:intdot/<8.0.0.11 is affected. Update to V8.0 Update 11. See "
            "https://www.siemens.com/cert/advisories for details. The campaign's C2 is hosted on 203.0.113.9 and "
            "payloads download from hxxp://evil-cdn[.]example/x.bin")
    found = iocs(text)
    assert found["ips"] == ["203[.]0[.]113[.]9"]                      # not the version bound 8.0.0.11
    assert found["urls"] == ["hxxp://evil-cdn[.]example/x.bin"]          # defanged in the source: an indicator
    assert found["references"] == ["https://www.siemens.com/cert/advisories"]  # vendor guidance: never blocked
    assert all("siemens" not in d for d in found["domains"])
