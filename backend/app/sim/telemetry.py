"""Simulated national telemetry (clearly labelled SIM): a decoy-sensor grid and enterprise firewall logs.

Calibrated to published observations, not invented freely:
  - Decoy rollups follow the Shadowserver/GreyNoise pattern: per-sensor daily sessions and unique source IPs per
    product tag, with ~55% research-scanner background (NICTER 2025) and campaign surges that precede disclosure
    by ~11 days (GreyNoise "Ten Days Before Zero", median lead). One surge is NEVER followed by a CVE, so the
    detector's false-positive behaviour is visible.
  - Firewall logs contain ordinary traffic plus one implant beaconing every 60 s with +/-10% jitter to a real
    Feodo Tracker C2 address (REAL indicator, SIM sighting).
All source IPs are drawn from RFC 2544 benchmark space (198.18.0.0/15); no real hosts are represented.
"""

from __future__ import annotations

import datetime as dt
import random

SEED = 1031
START, END = dt.date(2026, 8, 1), dt.date(2026, 10, 31)
SENSORS = [f"DCY-{i:02d}" for i in range(1, 25)]
SENSOR_SECTOR = {s: ["Power & Energy", "BFSI", "Telecom", "Transport", "Government",
                     "Strategic & Public Enterprises"][i % 6] for i, s in enumerate(SENSORS)}
# product tag -> (baseline sessions/sensor/day, baseline unique IPs/sensor/day)
TAGS = {
    "ivanti_cs": (40, 12), "fortios": (60, 18), "panos": (45, 14), "netscaler": (50, 15),
    "cisco_asa": (35, 10), "exchange": (55, 16), "confluence": (30, 9), "cisco_esa": (20, 6),
}
# (tag, first day, days, sensors hit, session multiplier, unique-IP multiplier, linked CVE or None)
CAMPAIGNS = [
    ("ivanti_cs", dt.date(2026, 10, 1), 4, 9, 8.0, 5.0, "CVE-2026-104935"),   # ~12 days before disclosure
    ("ivanti_cs", dt.date(2026, 10, 11), 3, 11, 6.0, 4.0, "CVE-2026-104935"),  # second wave
    ("confluence", dt.date(2026, 9, 14), 3, 7, 6.0, 4.0, None),                # surge with no CVE: false positive
]
EXPLOIT_TAGS = [("CVE-2026-104935", dt.date(2026, 10, 14), 6, 14)]  # (cve, first day, days, sensors)
C2 = {"ip": "50.16.16.211", "port": 443, "malware": "QakBot", "source": "Feodo Tracker (abuse.ch)"}
BEACON = {"asset_id": "PWR-01-A001", "start": dt.datetime(2026, 10, 16, 9, 0, 0), "count": 360,
          "interval_s": 60, "jitter": 0.10}


def _pois(rng: random.Random, lam: float) -> int:
    """Poisson via Knuth for small lambda; normal approximation for large."""
    if lam > 60:
        return max(0, int(rng.gauss(lam, lam ** 0.5)))
    limit, k, p = pow(2.718281828, -lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def decoy_rollups() -> list[dict]:
    rng = random.Random(SEED)
    rows = []
    day = START
    while day <= END:
        weekend = 0.85 if day.weekday() >= 5 else 1.0
        for tag, (base_s, base_ip) in TAGS.items():
            boosted = {}
            for c_tag, first, days, n_sensors, ms, mi, _ in CAMPAIGNS:
                if c_tag == tag and first <= day < first + dt.timedelta(days=days):
                    for s in random.Random(f"{tag}{first}").sample(SENSORS, n_sensors):
                        boosted[s] = (ms, mi)
            for sensor in SENSORS:
                ms, mi = boosted.get(sensor, (1.0, 1.0))
                sessions = _pois(rng, base_s * weekend * ms)
                ips = min(sessions, _pois(rng, base_ip * weekend * mi))
                research = round(0.55 / ms, 2)  # campaigns dilute the research-scanner share
                rows.append({"date": day.isoformat(), "sensor": sensor, "sector": SENSOR_SECTOR[sensor], "tag": tag,
                             "sessions": sessions, "unique_ips": ips, "research_share": research,
                             "asn_profile": "residential/distributed" if ms > 1 else "mixed"})
        day += dt.timedelta(days=1)
    return rows


def decoy_exploit_hits() -> list[dict]:
    rng = random.Random(SEED + 1)
    out = []
    for cve, first, days, n_sensors in EXPLOIT_TAGS:
        for d in range(days):
            day = first + dt.timedelta(days=d)
            for sensor in rng.sample(SENSORS, n_sensors):
                out.append({"ts": f"{day.isoformat()}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:00Z",
                            "sensor": sensor, "cve": cve, "src_ip": f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                            "intent": "exploit", "payload": "auth-bypass request pattern (redacted)"})
    return sorted(out, key=lambda r: r["ts"])


def firewall_logs(asset_ip: str) -> list[dict]:
    rng = random.Random(SEED + 2)
    rows, t = [], BEACON["start"] - dt.timedelta(hours=6)
    end = BEACON["start"] + dt.timedelta(hours=8)
    while t < end:  # ordinary, irregular outbound traffic
        t += dt.timedelta(seconds=rng.expovariate(1 / 40))
        rows.append({"ts": t.isoformat() + "Z", "src": asset_ip, "dst": f"198.19.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                     "dport": rng.choice([443, 443, 443, 80, 53, 123]), "bytes": rng.randint(200, 90000)})
    t = BEACON["start"]
    for _ in range(BEACON["count"]):  # implant check-ins: periodic with jitter
        t += dt.timedelta(seconds=BEACON["interval_s"] * (1 + rng.uniform(-BEACON["jitter"], BEACON["jitter"])))
        rows.append({"ts": t.isoformat() + "Z", "src": asset_ip, "dst": C2["ip"], "dport": C2["port"],
                     "bytes": rng.randint(310, 420)})
    return sorted(rows, key=lambda r: r["ts"])
