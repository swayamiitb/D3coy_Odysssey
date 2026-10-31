"""Live telemetry: the system measuring itself, and the heatmaps the analyst views are built from.

  - API: every request is timed (per route p50 / p95 / errors), in-memory ring buffers;
  - AI: every model call (LLM via llm.chat, translation via the MT service) with latency, tokens/s and outcome;
  - host: CPU and RAM (Windows kernel counters, no extra dependency), GPU load / VRAM / temperature / power
    (nvidia-smi), models resident in VRAM (Ollama /api/ps); sampled on request, cached for a few seconds;
  - pipeline: per-stage build timings (meta 'build_stages'); ledger: size and growth rate.
Heatmaps: autopilot actions by type x day, critical exposure by technology x sector, real attack volume by
service port x day (SANS ISC DShield), decoy-grid sessions by product x day (SIM), notices per organisation x week.
"""

from __future__ import annotations

import collections
import ctypes
import datetime as dt
import json
import os
import sqlite3
import statistics
import subprocess
import threading
import time

_START = time.time()
_LOCK = threading.Lock()
_API: dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=400))
_AI: collections.deque = collections.deque(maxlen=2000)
_SERIES: collections.deque = collections.deque(maxlen=240)  # host samples, newest last
_CACHE: dict[str, tuple[float, object]] = {}
_LEDGER_MARKS: collections.deque = collections.deque(maxlen=120)  # (time, max seq)


def record_api(route: str, ms: float, status: int) -> None:
    with _LOCK:
        _API[route].append((time.time(), ms, status))


def record_ai(role: str, model: str, seconds: float, tokens_per_s: float, ok: float) -> None:
    """ok: 1/0 (or True/False) for a single output, or the share of segments that passed their checks."""
    with _LOCK:
        _AI.append((time.time(), role, model, seconds, tokens_per_s, float(ok)))


def _cached(key: str, ttl: float, fn):
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    try:
        value = fn()
    except Exception:  # noqa: BLE001 - telemetry must never break the API
        value = None
    _CACHE[key] = (time.time(), value)
    return value


# ---------------------------------------------------------------- host
class _FT(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]


class _MEM(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


_CPU_PREV: list[int] = []


def _cpu_percent() -> float | None:
    if os.name != "nt":
        return round(100 * os.getloadavg()[0] / (os.cpu_count() or 1), 1)
    idle, kernel, user = _FT(), _FT(), _FT()
    ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
    now = [(t.hi << 32) | t.lo for t in (idle, kernel, user)]
    prev = _CPU_PREV[:] or now
    _CPU_PREV[:] = now
    d_idle, d_total = now[0] - prev[0], (now[1] - prev[1]) + (now[2] - prev[2])
    return round(100 * (1 - d_idle / d_total), 1) if d_total > 0 else None


def _ram() -> dict | None:
    if os.name != "nt":
        return None
    m = _MEM()
    m.dwLength = ctypes.sizeof(m)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
    return {"percent": int(m.dwMemoryLoad), "used_gb": round((m.ullTotalPhys - m.ullAvailPhys) / 2**30, 1),
            "total_gb": round(m.ullTotalPhys / 2**30, 1)}


def _gpu() -> dict | None:
    out = subprocess.run(["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,"
                          "power.draw", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=3)
    name, util, used, total, temp, power = [x.strip() for x in out.stdout.strip().splitlines()[0].split(",")]
    return {"name": name, "util": float(util), "vram_used_gb": round(float(used) / 1024, 2),
            "vram_total_gb": round(float(total) / 1024, 2), "temp_c": float(temp), "power_w": float(power)}


def _ollama() -> list[dict]:
    import httpx
    ps = httpx.get(os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434") + "/api/ps", timeout=2).json()
    return [{"name": m["name"], "vram_gb": round(m.get("size_vram", 0) / 2**30, 2),
             "params": m.get("details", {}).get("parameter_size"), "context": m.get("context_length")}
            for m in ps.get("models", [])]


def host() -> dict:
    sample = {"ts": time.time(), "cpu": _cached("cpu", 2.0, _cpu_percent), "ram": _cached("ram", 2.0, _ram),
              "gpu": _cached("gpu", 3.0, _gpu), "models": _cached("ollama", 5.0, _ollama) or []}
    with _LOCK:
        if not _SERIES or sample["ts"] - _SERIES[-1]["ts"] >= 2.5:
            _SERIES.append({"ts": sample["ts"], "cpu": sample["cpu"], "ram": (sample["ram"] or {}).get("percent"),
                            "gpu": (sample["gpu"] or {}).get("util"),
                            "vram": (sample["gpu"] or {}).get("vram_used_gb")})
    return sample


# ---------------------------------------------------------------- summaries
def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, int(q * (len(s) - 1) + 0.5))], 1)


_ROLE = {"narrate": "Analyst brief", "brief": "Analyst brief", "extract": "Advisory mapping",
         "advisory": "Advisory analysis", "translate": "Translation"}


def _ai_row(role: str, model: str, calls: list[tuple[float, float, float]]) -> dict:
    """calls: (seconds, tokens/s or 0, share of the output that passed its checks: 1/0, or a fraction of segments)."""
    tps = [c[1] for c in calls if c[1]]
    return {"role": _ROLE.get(role, role), "model": model, "calls": len(calls), "p50_s": _pct([c[0] for c in calls], 0.5),
            "p95_s": _pct([c[0] for c in calls], 0.95), "tokens_per_s": round(statistics.mean(tps), 1) if tps else None,
            "ok_pct": round(100 * sum(float(c[2]) for c in calls) / len(calls), 1)}


def _on_record() -> list[dict]:
    """AI work measured when it was first generated; the content-addressed cache has served it since."""
    from . import cache
    groups: dict[tuple[str, str], list[tuple[float, float, float]]] = collections.defaultdict(list)
    for kind, body in cache._conn().execute("SELECT kind, body FROM ai_cache WHERE kind IN ('brief', 'translate', 'advisory')").fetchall():
        b = json.loads(body)
        if kind == "advisory":
            groups[(kind, "SecureBERT 2.0 NER + DeBERTa guard")].append(
                ((b.get("timings") or {}).get("total_ms", 0) / 1000, 0.0, 1.0))
        elif kind == "translate":
            groups[(kind, b.get("model", "?").split("/")[-1])].append(
                (b.get("seconds") or 0.0, 0.0, (b.get("validated") or 0) / (b.get("total") or 1)))
        elif b.get("seconds") is not None:
            groups[(kind, b.get("model", "?"))].append((b["seconds"], b.get("tokens_per_s") or 0.0,
                                                        float(b.get("status") == "validated")))
    rows = [_ai_row(k, m, v) for (k, m), v in groups.items()]
    return sorted(rows, key=lambda r: -r["calls"])


def snapshot(conn: sqlite3.Connection) -> dict:
    with _LOCK:
        api = {r: list(v) for r, v in _API.items()}
        ai = list(_AI)
        series = list(_SERIES)
    routes = []
    for route, rows in api.items():
        ms = [r[1] for r in rows]
        routes.append({"route": route, "calls": len(rows), "p50_ms": _pct(ms, 0.5), "p95_ms": _pct(ms, 0.95),
                       "errors": sum(1 for r in rows if r[2] >= 500), "last": max(r[0] for r in rows)})
    routes.sort(key=lambda r: -r["calls"])
    models: dict[tuple[str, str], list] = collections.defaultdict(list)
    for row in ai:
        models[(row[1], row[2])].append(row)
    ai_rows = [_ai_row(role, model, [(r[3], r[4], r[5]) for r in rows]) for (role, model), rows in models.items()]
    seq = conn.execute("SELECT COALESCE(MAX(seq), 0), COUNT(*) FROM ledger").fetchone()
    now = time.time()
    with _LOCK:
        if not _LEDGER_MARKS or now - _LEDGER_MARKS[-1][0] >= 5:
            _LEDGER_MARKS.append((now, seq[0]))
        first = _LEDGER_MARKS[0]
    rate = round(60 * (seq[0] - first[1]) / (now - first[0]), 2) if now - first[0] > 1 else 0.0
    by_prov = dict(conn.execute("SELECT provenance, COUNT(*) FROM ledger GROUP BY provenance").fetchall())
    meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    return {"uptime_s": round(now - _START), "host": host(), "series": series, "api": routes, "ai": ai_rows,
            "ai_record": _cached("ai_record", 30.0, _on_record) or [],
            "ledger": {"events": seq[1], "per_min": rate, "by_provenance": by_prov},
            "pipeline": {"built_at": meta.get("built_at"), "stages": json.loads(meta.get("build_stages", "[]"))}}


# ---------------------------------------------------------------- heatmaps
def _days(start: str, end: str) -> list[str]:
    d0, d1 = dt.date.fromisoformat(start), dt.date.fromisoformat(end)
    return [(d0 + dt.timedelta(days=i)).isoformat() for i in range((d1 - d0).days + 1)]


def heatmaps(conn: sqlite3.Connection, org_id: str | None = None) -> dict:
    from .engine.intel import dshield
    meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    go = json.loads(meta.get("sentinel", "{}")).get("go_live", "2026-08-01")
    end = meta.get("snapshot_date", "2026-10-31")
    days = _days(go, end)
    labels = {"auto.notify": "Notices", "auto.digest": "Daily digests", "auto.forecast": "Pre-emptive advisories",
              "auto.warn": "Early warnings", "auto.baseline": "Baselines", "auto.escalate": "Regulator reports",
              "auto.escalate_sla": "SLA escalations", "auto.hunt": "Threat hunts", "auto.report": "Report drafts",
              "auto.confirm": "Warnings confirmed", "auto.stand_down": "Stand-downs", "auto.advisory": "Advisory notices",
              "auto.case_opened": "Cases opened (live)"}
    where, args = ("AND json_extract(payload, '$.org_id') = ?", (org_id,)) if org_id else ("", ())
    rows = conn.execute(f"""SELECT kind, substr(ts, 1, 10), COUNT(*) FROM ledger
                            WHERE kind LIKE 'auto.%' AND kind NOT IN ('auto.proposed', 'auto.withdrawn') {where}
                            GROUP BY 1, 2""", args).fetchall()
    kinds = [k for k in labels if any(r[0] == k for r in rows)]
    grid = {(k, d): n for k, d, n in rows}
    autopilot = {"rows": [labels[k] for k in kinds], "cols": days,
                 "values": [[grid.get((k, d), 0) for d in days] for k in kinds]}

    exp = conn.execute("""SELECT s.label, o.sector, COUNT(DISTINCT a.org_id || a.cve_id) FROM assessments a
                          JOIN assets s ON s.id = a.asset_id JOIN orgs o ON o.id = a.org_id
                          WHERE a.R > 0 AND a.tier IN ('Critical', 'Compromise') GROUP BY 1, 2""").fetchall()
    techs = sorted({r[0] for r in exp}, key=lambda t: -sum(r[2] for r in exp if r[0] == t))[:14]
    sectors = ["Power & Energy", "BFSI", "Telecom", "Transport", "Government", "Strategic & Public Enterprises"]
    eg = {(t, s): n for t, s, n in exp}
    exposure = {"rows": techs, "cols": sectors, "values": [[eg.get((t, s), 0) for s in sectors] for t in techs]}

    from .engine.intel import PORT_NAMES
    hist = dshield()["history"]
    ports = [p for p in (443, 22, 80, 445, 3389, 25, 8443, 10443, 5432, 1521, 8090, 102, 502) if hist.get(p)]
    pdays = sorted({r["date"] for p in ports for r in hist[p]})
    pv = {(p, r["date"]): r["records"] for p in ports for r in hist[p]}
    attacks = {"rows": [f"{PORT_NAMES.get(p, p)} :{p}" for p in ports], "cols": pdays,
               "values": [[pv.get((p, d), 0) for d in pdays] for p in ports], "normalise": "row-range"}

    dec = conn.execute("SELECT tag, date, SUM(sessions) FROM decoy_daily GROUP BY 1, 2").fetchall()
    tags = sorted({r[0] for r in dec})
    ddays = sorted({r[1] for r in dec})
    dv = {(t, d): n for t, d, n in dec}
    surges = conn.execute("SELECT tag, first, last FROM decoy_surges").fetchall()
    marks = [[tags.index(t), ddays.index(d)] for t, f, l in surges for d in ddays if f <= d <= l and t in tags]
    from .sim.world import CATALOG
    names = {t: CATALOG[t][3] if t in CATALOG else t.replace("_", " ").title() for t in tags}
    decoy = {"rows": [names[t] for t in tags], "cols": ddays, "values": [[dv.get((t, d), 0) for d in ddays] for t in tags],
             "normalise": "row-range", "marks": marks}

    org_rows = conn.execute("""SELECT json_extract(payload, '$.org_id'), strftime('%Y-%W', ts), COUNT(*) FROM ledger
                               WHERE kind LIKE 'auto.%' AND kind NOT IN ('auto.proposed', 'auto.withdrawn')
                                 AND json_extract(payload, '$.org_id') IS NOT NULL AND ts >= ? GROUP BY 1, 2""",
                            (go,)).fetchall()
    orgs = [r[0] for r in conn.execute("SELECT id FROM orgs ORDER BY id").fetchall()]
    weeks = sorted({r[1] for r in org_rows})
    ov = {(o, w): n for o, w, n in org_rows}
    notices = {"rows": orgs, "cols": weeks, "values": [[ov.get((o, w), 0) for w in weeks] for o in orgs]}
    return {"autopilot": autopilot, "exposure": exposure, "attacks": attacks, "decoy": decoy, "notices": notices}
