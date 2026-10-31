"""Standard-ML / statistical detectors over telemetry. Deterministic, explainable, CPU-only.

surge  : robust z-scores (median / MAD over a trailing 28-day baseline) on national sessions AND unique source
         IPs per product tag; requires breadth across sensors. Counting unique sources, not raw hits, stops a
         single noisy scanner from creating a "surge" (SANS ISC observation).
exploit: exploit payloads for a specific CVE on >= 2 distinct decoy sensors (KEV counts honeypot exploitation).
beacon : RITA-style periodicity on (src, dst, port) flows: low coefficient of variation of inter-arrival times,
         enough connections, small uniform payloads.
"""

from __future__ import annotations

import datetime as dt
import statistics
from collections import defaultdict


def _robust_z(x: float, history: list[float]) -> float:
    med = statistics.median(history)
    mad = statistics.median(abs(h - med) for h in history) or 1.0
    return (x - med) / (1.4826 * mad)


def detect_surges(rollups: list[dict], z_sessions: float = 4.0, z_ips: float = 3.0, min_sensors: int = 3,
                  baseline_days: int = 28) -> list[dict]:
    by_tag_day: dict[tuple[str, str], dict] = defaultdict(lambda: {"sessions": 0, "ips": 0, "sensors": set()})
    per_sensor: dict[tuple[str, str, str], int] = {}
    for r in rollups:
        agg = by_tag_day[(r["tag"], r["date"])]
        agg["sessions"] += r["sessions"]
        agg["ips"] += r["unique_ips"]
        per_sensor[(r["tag"], r["date"], r["sensor"])] = r["sessions"]
    tags = sorted({t for t, _ in by_tag_day})
    days = sorted({d for _, d in by_tag_day})
    sensor_base: dict[tuple[str, str], list[int]] = defaultdict(list)
    out = []
    for i, day in enumerate(days):
        if i < baseline_days:
            for tag in tags:
                for (t, d, s), n in per_sensor.items():
                    if t == tag and d == day:
                        sensor_base[(tag, s)].append(n)
            continue
        window = days[i - baseline_days:i]
        for tag in tags:
            cur = by_tag_day[(tag, day)]
            zs = _robust_z(cur["sessions"], [by_tag_day[(tag, d)]["sessions"] for d in window])
            zi = _robust_z(cur["ips"], [by_tag_day[(tag, d)]["ips"] for d in window])
            hot = [s for (t, d, s), n in per_sensor.items() if t == tag and d == day
                   and n > 3 * statistics.median(sensor_base.get((tag, s), [n]) or [n])]
            if zs >= z_sessions and zi >= z_ips and len(hot) >= min_sensors:
                out.append({"date": day, "tag": tag, "z_sessions": round(zs, 1), "z_ips": round(zi, 1),
                            "sensors": len(hot)})
            for (t, d, s), n in per_sensor.items():
                if t == tag and d == day:
                    sensor_base[(tag, s)] = (sensor_base[(tag, s)] + [n])[-baseline_days:]
    return out


def detect_exploit_tags(hits: list[dict], min_sensors: int = 2) -> list[dict]:
    seen: dict[str, set] = defaultdict(set)
    fired, out = set(), []
    for h in hits:
        seen[h["cve"]].add(h["sensor"])
        if len(seen[h["cve"]]) >= min_sensors and h["cve"] not in fired:
            fired.add(h["cve"])
            out.append({"ts": h["ts"], "cve": h["cve"], "sensors": len(seen[h["cve"]])})
    return out


def detect_beacons(logs: list[dict], min_conns: int = 30, max_cv: float = 0.2) -> list[dict]:
    flows: dict[tuple[str, str, int], list[dict]] = defaultdict(list)
    for r in logs:
        flows[(r["src"], r["dst"], r["dport"])].append(r)
    out = []
    for (src, dst, port), rows in flows.items():
        if len(rows) < min_conns:
            continue
        times = [dt.datetime.fromisoformat(r["ts"].replace("Z", "")) for r in rows]
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1.0
        sizes = [r["bytes"] for r in rows]
        size_cv = statistics.pstdev(sizes) / statistics.mean(sizes)
        score = round((1 - min(cv, 1)) * 0.7 + (1 - min(size_cv, 1)) * 0.3, 3)
        if cv <= max_cv:
            confirm_at = times[min_conns - 1]  # first moment the evidence threshold was met
            out.append({"src": src, "dst": dst, "dport": port, "connections": len(rows),
                        "mean_interval_s": round(mean, 1), "cv": round(cv, 3), "score": score,
                        "first_seen": rows[0]["ts"], "confirmed_at": confirm_at.isoformat() + "Z"})
    return out
