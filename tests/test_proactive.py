"""Proactive layer: day-0 forecast (no look-ahead), forecast as a Bayesian prior, autopilot lead times and
human-in-the-loop approvals, risk plan ordering, look-alike domains."""

import datetime as dt
import json
import sqlite3

from backend.app.engine import sentinel
from backend.app.engine.bayes import posterior
from backend.app.engine.exposure import Exposure, Vote
from backend.app.engine.forecast import History, featurise
from backend.app.engine.intel import lookalikes
from backend.app.engine.ledger import Ledger
from backend.app.engine.riskplan import plan
from backend.app.engine.scoring import assess, config

KEV = {"CVE-A": {"vendorProject": "Acme", "product": "Gate", "dateAdded": "2026-01-10"},
       "CVE-B": {"vendorProject": "Acme", "product": "Gate", "dateAdded": "2026-03-01"},
       "CVE-C": {"vendorProject": "Acme", "product": "Gate", "dateAdded": "2026-05-01"}}


def _f(cid: str, day: str) -> dict:
    return {"id": cid, "published": day, "description": "", "vendor": "acme", "product": "gate", "vector": None,
            "cwe": "none"}


def test_history_counts_only_listings_before_publication():
    h = History(KEV, {})
    c = h.counts(_f("CVE-NEW", "2026-03-01"))  # CVE-B is listed that same day: not yet history
    assert c["vendor_kev"] == 1 and c["product_kev"] == 1
    c = h.counts(_f("CVE-C", "2026-06-01"))     # a CVE's own (earlier) listing never counts as its history
    assert c["vendor_kev"] == 2
    assert featurise(_f("CVE-NEW", "2025-12-31"), h)["vendor_ever_exploited"] == 0.0


def test_forecast_shifts_the_bayesian_prior_between_its_bounds():
    cfg = config()[0]
    low = posterior(cfg, exposed=True, exploited=False, internet=True)["prior"]
    high = posterior(cfg, exposed=True, exploited=True, internet=True)["prior"]
    mid = posterior(cfg, exposed=True, exploited=False, internet=True, p_exploit=0.4)["prior"]
    assert low < mid < high
    assert posterior(cfg, exposed=True, exploited=True, internet=True, p_exploit=0.0)["prior"] == high


def test_forecast_is_a_prediction_not_exploitation_evidence():
    vuln = {"id": "CVE-X", "description": "", "ssvc": {}, "kev": None, "epss": None,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_source": "CNA",
            "forecast": {"p": 0.6, "flag": True, "reasons": ["vendor has a KEV history"]}}
    asset = {"id": "A1", "tier": 1, "zone": "internet", "role": "vpn", "tier1_reachable": 0}
    exp = Exposure("A1", "CVE-X", "affected", 1.0, [Vote("CNA", "affected", "explicit", "in range")])
    a = assess(vuln, asset, {"id": "O1", "cii": True}, exp)
    assert "FORECAST" in {r.id for r in a.rules}
    assert "Exploitation=none" in a.decision_path and a.L >= 0.6
    plain = assess({**vuln, "forecast": None}, asset, {"id": "O1", "cii": True}, exp)
    assert a.V == plain.V  # a prediction is not corroboration


def _action(kind, ts, cve, prov="REAL", **extra):
    return {"kind": kind, "ts": ts, "subject": f"O1:{cve}", "mode": "auto",
            "payload": {"cve_id": cve, "provenance": prov, "basis": kind, **extra}}


def test_lead_time_counts_only_full_days_and_separates_sim():
    go = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
    actions = [_action("auto.forecast", "2026-09-01T10:00:00Z", "CVE-1"),           # 10 days ahead, REAL
               _action("auto.notify", "2026-09-20T20:00:00Z", "CVE-2"),             # hours ahead: same day
               {"kind": "auto.confirm", "ts": "2026-09-05T00:00:00Z", "subject": "product:x", "mode": "auto",
                "payload": {"cve_id": "CVE-3", "warned_at": "2026-08-25T06:20:00Z"}}]  # SIM sensor lead
    kev = {"CVE-1": "2026-09-11T10:00:00Z", "CVE-2": "2026-09-21T00:00:00Z", "CVE-3": "2026-09-10T00:00:00Z",
           "CVE-4": "2026-09-30T00:00:00Z"}
    r = sentinel.lead_times(actions, kev, go, {"CVE-1", "CVE-2", "CVE-3", "CVE-4"})
    assert r["kev_after_go_live"] == 4 and r["acted_before_kev"] == 2 and r["acted_same_day"] == 1
    assert r["not_acted"] == 1
    assert r["real_signals_only"]["acted_before_kev"] == 1 and r["real_signals_only"]["median_lead_days"] == 10.0


def _pilot(now):
    conn = sqlite3.connect(":memory:")
    cfg = config()[0]
    orgs = {"O1": {"id": "O1", "name": "Org One", "sector": "BFSI", "state": "Kerala", "ciso": "ciso@o1.example",
                   "cii": True},
            "O2": {"id": "O2", "name": "Org Two", "sector": "BFSI", "state": "Gujarat", "ciso": "ciso@o2.example",
                   "cii": True}}
    return conn, sentinel.Autopilot(conn, Ledger(conn=conn), cfg, orgs, {}, now=now)


def test_proposals_are_grouped_approved_in_history_and_pending_live():
    now = dt.datetime(2026, 10, 31, 12, tzinfo=dt.timezone.utc)
    conn, p = _pilot(now)
    for org in ("O1", "O2"):  # one CVE, two organisations -> one proposal
        p.emit(dt.datetime(2026, 9, 1, 6, tzinfo=dt.timezone.utc), "forecast", f"{org}:CVE-1", org_id=org,
               cve_id="CVE-1", group="forecast:CVE-1", group_subject="CVE-1", title="t", proposal="send it")
        p.emit(dt.datetime(2026, 10, 31, 6, tzinfo=dt.timezone.utc), "forecast", f"{org}:CVE-2", org_id=org,
               cve_id="CVE-2", group="forecast:CVE-2", group_subject="CVE-2", title="t", proposal="send it")
    p.flush()
    rows = dict(conn.execute("SELECT subject, status FROM approvals").fetchall())
    assert rows == {"CVE-1": "approved", "CVE-2": "pending"}
    kinds = [r[0] for r in conn.execute("SELECT kind FROM ledger ORDER BY seq")]
    assert kinds.count("auto.proposed") == 2 and kinds.count("auto.forecast") == 2  # only history executed
    assert json.loads(conn.execute("SELECT payload FROM ledger WHERE kind = 'analyst.approve'").fetchone()[0])[
        "actor"] == sentinel.SIM_OFFICER
    pid = conn.execute("SELECT id FROM approvals WHERE status = 'pending'").fetchone()[0]
    assert sentinel.decide(conn, pid, True, "analyst@test", None)["executed"] == 2
    try:
        sentinel.decide(conn, pid, False, "analyst@test", "late")
        raise AssertionError("a decided proposal must not be decided again")
    except ValueError:
        pass
    ok, _ = Ledger(conn=conn).verify()
    assert ok


def test_live_prediction_is_withdrawn_once_evidence_notices_went_out():
    now = dt.datetime(2026, 10, 31, 12, tzinfo=dt.timezone.utc)
    conn, p = _pilot(now)
    t = dt.datetime(2026, 10, 30, 6, tzinfo=dt.timezone.utc)
    p.emit(t, "forecast", "O1:CVE-9", org_id="O1", cve_id="CVE-9", group="forecast:CVE-9", group_subject="CVE-9",
           title="t", proposal="send")
    p.emit(t + dt.timedelta(hours=3), "notify", "O1:CVE-9", org_id="O1", cve_id="CVE-9", title="Critical")
    p.flush()
    assert conn.execute("SELECT status FROM approvals").fetchone()[0] == "superseded"


def test_risk_plan_puts_compromise_before_a_pile_of_medium_issues():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE orgs (id TEXT, name TEXT, sector TEXT, state TEXT, domain TEXT, cii INTEGER);
        CREATE TABLE assets (id TEXT, org_id TEXT, hostname TEXT, ip TEXT, zone TEXT, role TEXT, label TEXT,
                             vendor TEXT, product TEXT, version TEXT, cpe TEXT, tier INTEGER, owner TEXT,
                             tier1_reachable INTEGER, product_key TEXT);
        CREATE TABLE vulns (id TEXT, published TEXT, description TEXT, kev TEXT, epss REAL, ssvc TEXT,
                            cvss_vector TEXT, cvss_source TEXT, nvd_status TEXT, record TEXT);
        CREATE TABLE assessments (asset_id TEXT, cve_id TEXT, org_id TEXT, sector TEXT, status TEXT, R REAL,
                                  risk REAL, tier TEXT, decision TEXT, deadline_hours INTEGER, detail TEXT);""")
    conn.execute("INSERT INTO orgs VALUES ('O1','Org','BFSI','Kerala','o1.example',1)")
    for i in range(6):
        conn.execute("INSERT INTO assets VALUES (?, 'O1', ?, '', 'internal', 'db', 'Pg', 'pg', 'pg', '16', '', 3,"
                     " 'db@o1', 0, 'pg')", (f"DB{i}", f"db{i}"))
    conn.execute("INSERT INTO assets VALUES ('VPN', 'O1', 'vpn', '', 'internet', 'vpn', 'Gate', 'acme', 'gate',"
                 " '1.0', '', 1, 'net@o1', 0, 'gate')")
    for c in range(10):
        conn.execute("INSERT INTO vulns VALUES (?, '', '', 'null', NULL, '{}', NULL, NULL, NULL, '{}')", (f"M{c}",))
        for i in range(6):
            conn.execute("INSERT INTO assessments VALUES (?, ?, 'O1', 'BFSI', 'affected', 1, 45, 'Medium', 'Track*',"
                         " 336, '{}')", (f"DB{i}", f"M{c}"))
    conn.execute("INSERT INTO vulns VALUES ('K1', '', '', '{\"dateAdded\": \"2026-10-01\"}', NULL, '{}', NULL, NULL,"
                 " NULL, '{\"cna_affected\": [{\"versions\": [{\"status\": \"affected\", \"lessThan\": \"1.2\"}]}]}')")
    conn.execute("INSERT INTO assessments VALUES ('VPN', 'K1', 'O1', 'BFSI', 'affected', 1, 95, 'Compromise', 'Act',"
                 " 6, '{}')")
    r = plan(conn, "O1")
    assert r["plan"][0]["label"] == "Gate" and r["plan"][0]["target_version"] == "1.2"
    assert r["plan"][1]["risk_removed"] > r["plan"][0]["risk_removed"]  # bigger, but less urgent
    assert r["plan"][-1]["cum_pct"] == 100.0


def test_lookalike_domains():
    v = lookalikes("navnidhibank.example")
    assert {"navnidhibank-kyc", "navnidhbank", "navnidhiibank", "anvnidhibank"} <= v
    assert "navnidhibank" not in v


def test_one_incident_per_compromised_asset_however_many_cves():
    now = dt.datetime(2026, 10, 31, 12, tzinfo=dt.timezone.utc)
    conn, p = _pilot(now)
    asset = {"id": "O1-A1", "hostname": "vpn1.o1.example", "label": "Gate", "zone": "internet"}
    step = {"ts": "2026-10-16T09:30:00Z", "kind": "ioc.sighting", "provenance": "SIM", "event": "beacon",
            "tier": "Compromise", "deadline_hours": 6, "rules": ["IOC_SIGHTING"]}
    items = [{"org": p.orgs["O1"], "asset": asset, "rec": {"id": cve, "published": "2026-10-13T00:00:00Z"},
              "steps": [step], "sighting": {"dst": "50.16.16.211"}} for cve in ("CVE-1", "CVE-2")]
    p.alerts(items, {"CVE-1": ["O2"], "CVE-2": ["O2"]}, (10, 2))
    kinds = [a["kind"] for a in p.actions]
    assert kinds.count("auto.escalate") == 1 and kinds.count("auto.report") == 1 and kinds.count("auto.hunt") == 1
    esc = next(a for a in p.actions if a["kind"] == "auto.escalate")
    assert esc["payload"]["cves"] == ["CVE-1", "CVE-2"] and "CVE-1 and CVE-2" in esc["payload"]["title"]
    assert sum(a["payload"].get("tier") == "peer-warning" for a in p.actions) == 2  # one per shared CVE
