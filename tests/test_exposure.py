"""Exposure engine tests. The Ivanti cases use the real cached CVE JSON 5 and NVD records."""

import pytest

from backend.app.engine.exposure import reconcile, text_constraints
from backend.app.engine.versions import Version, from_cpe
from backend.app.ingest.cve_records import build_record, load_nvd


@pytest.mark.parametrize("lo,hi", [
    ("22.7R2.14", "22.8R2.4"),      # Ivanti branches
    ("22.8R2", "22.8R2.4"),         # missing element sorts lower
    ("22.8R2.4", "22.8R2.5"),
    ("22.8R2.5", "25.1.3.0"),
    ("13.1-55.29", "14.1-29.72"),   # Citrix build suffix
    ("9.6", "9.6p1"),               # OpenSSH portable release
    ("2.0-beta9", "2.0"),           # pre-release
    ("2.4.58", "2.4.62"),
])
def test_version_order(lo, hi):
    assert Version(lo) < Version(hi)


def test_trailing_zeros_equal():
    assert Version("25.1.3.0") == Version("25.1.3")


def test_cpe_rejoin():
    assert from_cpe("22.8", "r2.4") == "22.8r2.4"
    assert Version(from_cpe("22.8", "r2.4")) == Version("22.8R2.4")
    assert from_cpe("*") is None


def test_text_constraints_ivanti():
    desc = ("Authentication bypass by spoofing in ICS before version 25.1.3.0 allows a remote unauthenticated "
            "attacker to execute arbitrary commands. This does not impact ICS version 22.7R2.14 or prior.")
    got = {(c["op"], c["version"], c["polarity"]) for c in text_constraints(desc)}
    assert ("lt", "25.1.3.0", "affected") in got
    assert ("le", "22.7R2.14", "unaffected") in got


ASSETS = {
    "PWR-01": {"id": "PWR-01-A001", "vendor": "ivanti", "product": "connect_secure", "version": "22.8R2.4"},
    "PWR-02": {"id": "PWR-02-A001", "vendor": "ivanti", "product": "connect_secure", "version": "22.8R2.4"},
    "BFS-01": {"id": "BFS-01-A001", "vendor": "ivanti", "product": "connect_secure", "version": "25.1.3.0"},
    "TEL-01": {"id": "TEL-01-A001", "vendor": "ivanti", "product": "connect_secure", "version": "22.7R2.12"},
}


@pytest.fixture(scope="module")
def records():
    ids = {"CVE-2026-104935", "CVE-2026-111357"}
    nvd = load_nvd(ids)
    return {cid: build_record(cid, nvd.get(cid)) for cid in ids}


@pytest.mark.parametrize("org,expected", [
    ("PWR-01", "affected"), ("PWR-02", "affected"), ("BFS-01", "cleared"), ("TEL-01", "cleared"),
])
def test_ivanti_auth_bypass(records, org, expected):
    exp = reconcile(ASSETS[org], records["CVE-2026-104935"])
    assert exp.status == expected, [vars(v) for v in exp.votes]


def test_tel01_keeps_dissent(records):
    """The CNA's defaultStatus=affected disagrees with NVD and the text; it must stay visible, not vanish."""
    exp = reconcile(ASSETS["TEL-01"], records["CVE-2026-104935"])
    assert any(v.source == "CNA" and v.verdict == "affected" for v in exp.votes)
    assert exp.relevance == 0.0


@pytest.mark.parametrize("org,expected", [
    ("PWR-01", "affected"), ("PWR-02", "affected"), ("BFS-01", "cleared"), ("TEL-01", "cleared"),
])
def test_ivanti_privesc(records, org, expected):
    exp = reconcile(ASSETS[org], records["CVE-2026-111357"])
    assert exp.status == expected, [vars(v) for v in exp.votes]


GITLAB_DESC = ("An issue has been discovered in GitLab CE/EE affecting all versions from 15.0 before 18.4.6, "
               "18.5 before 18.5.4, and 18.6 before 18.6.2. Under certain conditions an attacker could bypass "
               "two-factor authentication.")


@pytest.mark.parametrize("version,expected", [
    ("17.8.1", "affected"),    # inside 15.0 .. <18.4.6
    ("18.4.6", "not_affected"),  # fixed release of the first branch
    ("18.5.3", "affected"),
    ("18.5.4", "not_affected"),
    ("14.9.0", "not_affected"),  # below the first range start
])
def test_text_ranges_with_lower_bounds(version, expected):
    from backend.app.engine.exposure import text_vote
    vote = text_vote({"vendor": "gitlab", "product": "gitlab", "version": version}, GITLAB_DESC)
    assert vote.verdict == expected, vote.reason


def test_bare_bound_inside_range_not_double_counted():
    got = text_constraints("Affects versions 2.4.0 through 2.4.58 and all releases before 2.2.0.")
    ops = sorted((c["op"], c["version"]) for c in got)
    assert ops == [("lt", "2.2.0"), ("range", "2.4.58")]


def test_disputed_when_explicit_sources_conflict():
    cve = {
        "id": "CVE-TEST-0001",
        "description": "",
        "nvd_configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                                          "criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}]}]}],
        "cna_affected": [{"vendor": "Acme", "product": "Widget", "defaultStatus": "unknown",
                          "versions": [{"version": "1.2", "status": "affected"}]}],
    }
    exp = reconcile({"vendor": "acme", "product": "widget", "version": "1.2"}, cve)
    assert exp.status == "disputed" and exp.exposed
