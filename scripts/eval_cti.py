"""CTI evaluation suite for local models, graded against NVD ground truth (CTIBench-style tasks).

Tasks (2026 CVEs only, newer than every candidate model's training data, so no memorisation):
  RCM - root-cause mapping: description -> CWE id (top-1 exact match vs NVD primary CWE)
  VSP - vulnerability severity prediction: description -> CVSS v3.1 vector (per-metric accuracy,
        base-score mean absolute deviation vs NVD primary vector)

Usage: .venv/Scripts/python scripts/eval_cti.py [--n 40] [--models m1,m2]
Writes docs/eval_cti_results.json.
"""

import argparse
import gzip
import json
import math
import random
import re
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.ai.llm import available_models, chat  # noqa: E402

NVD_DIR = ROOT / "data" / "raw" / "nvd"
DEFAULT_MODELS = ["qwen3:4b", "qwen3:8b", "foundation-sec:8b-instruct"]
METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

RCM_SCHEMA = {"type": "object", "properties": {"cwe_id": {"type": "string"}}, "required": ["cwe_id"]}
RCM_SYSTEM = ("You are a vulnerability analyst. Map the vulnerability description to the single most specific "
              "MITRE CWE weakness. Answer with the CWE identifier in the form CWE-<number>.")

VSP_SCHEMA = {
    "type": "object",
    "properties": {
        "AV": {"type": "string", "enum": ["N", "A", "L", "P"]},
        "AC": {"type": "string", "enum": ["L", "H"]},
        "PR": {"type": "string", "enum": ["N", "L", "H"]},
        "UI": {"type": "string", "enum": ["N", "R"]},
        "S": {"type": "string", "enum": ["U", "C"]},
        "C": {"type": "string", "enum": ["H", "L", "N"]},
        "I": {"type": "string", "enum": ["H", "L", "N"]},
        "A": {"type": "string", "enum": ["H", "L", "N"]},
    },
    "required": METRICS,
}
VSP_SYSTEM = ("You are a vulnerability analyst. Assess the vulnerability description and assign each CVSS v3.1 "
              "base metric: AV (N/A/L/P), AC (L/H), PR (N/L/H), UI (N/R), S (U/C), C/I/A (H/L/N).")

# CVSS v3.1 specification weights
W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31_score(v: dict) -> float:
    changed = v["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[v["PR"]]
    iss = 1 - (1 - W["CIA"][v["C"]]) * (1 - W["CIA"][v["I"]]) * (1 - W["CIA"][v["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploit = 8.22 * W["AV"][v["AV"]] * W["AC"][v["AC"]] * pr * W["UI"][v["UI"]]
    if impact <= 0:
        return 0.0
    return roundup(min(1.08 * (impact + exploit), 10)) if changed else roundup(min(impact + exploit, 10))


def parse_vector(vector: str) -> dict:
    return dict(part.split(":") for part in vector.split("/")[1:])


def load_samples(n: int, seed: int = 7) -> list[dict]:
    feed = max(NVD_DIR.glob("nvdcve-2.0-20*.json.gz"))
    with gzip.open(feed, "rt", encoding="utf-8") as fh:
        vulns = json.load(fh)["vulnerabilities"]

    pool = []
    for item in vulns:
        cve = item["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        primary = [m for m in cve.get("metrics", {}).get("cvssMetricV31", []) if m.get("type") == "Primary"]
        cwes = [d["value"] for w in cve.get("weaknesses", []) if w.get("type") == "Primary"
                for d in w["description"] if re.fullmatch(r"CWE-\d+", d["value"])]
        if primary and len(cwes) == 1 and 120 <= len(desc) <= 900:
            vector = primary[0]["cvssData"]["vectorString"]
            pool.append({"id": cve["id"], "desc": desc, "cwe": cwes[0], "vector": vector,
                         "score": primary[0]["cvssData"]["baseScore"]})

    random.Random(seed).shuffle(pool)
    picked, per_cwe = [], {}
    for s in pool:  # cap 3 per CWE so XSS/SQLi do not dominate
        if per_cwe.get(s["cwe"], 0) < 3:
            picked.append(s)
            per_cwe[s["cwe"]] = per_cwe.get(s["cwe"], 0) + 1
        if len(picked) == n:
            break
    return picked


def run_model(model: str, samples: list[dict]) -> dict:
    chat([{"role": "user", "content": "ok"}], model=model, num_ctx=2048, max_tokens=8)
    rcm_hits, metric_hits, mads, seconds, failures = 0, {m: 0 for m in METRICS}, [], [], 0
    for s in samples:
        r = chat([{"role": "system", "content": RCM_SYSTEM}, {"role": "user", "content": s["desc"]}],
                 model=model, schema=RCM_SCHEMA, num_ctx=4096, max_tokens=60, timeout=90)
        found = re.search(r"CWE-\d+", (r.data or {}).get("cwe_id", "") if isinstance(r.data, dict) else "")
        rcm_ok = bool(found) and found.group(0) == s["cwe"]
        rcm_hits += rcm_ok

        v = chat([{"role": "system", "content": VSP_SYSTEM}, {"role": "user", "content": s["desc"]}],
                 model=model, schema=VSP_SCHEMA, num_ctx=4096, max_tokens=120, timeout=90)
        seconds += [r.seconds, v.seconds]
        pred = v.data if isinstance(v.data, dict) and all(k in v.data for k in METRICS) else None
        if pred is None:
            failures += 1
            mads.append(10.0)  # worst case for an unusable answer
        else:
            truth = parse_vector(s["vector"])
            for m in METRICS:
                metric_hits[m] += pred[m] == truth[m]
            mads.append(abs(cvss31_score(pred) - s["score"]))
        print(f"  {s['id']:<18} cwe={found.group(0) if found else '-':<9} truth={s['cwe']:<9} "
              f"{'OK ' if rcm_ok else '   '} vsp_mad={mads[-1]:.1f}", flush=True)

    n = len(samples)
    return {
        "model": model, "n": n,
        "rcm_acc_pct": round(100 * rcm_hits / n, 1),
        "vsp_mad": round(statistics.mean(mads), 2),
        "vsp_metric_acc_pct": {m: round(100 * h / n, 1) for m, h in metric_hits.items()},
        "vsp_invalid": failures,
        "median_s_per_call": round(statistics.median(seconds), 2),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--models", default=",".join(DEFAULT_MODELS))
    args = ap.parse_args()

    have = available_models()
    models = [m for m in args.models.split(",") if m in have or f"{m}:latest" in have]
    samples = load_samples(args.n)
    print(f"{len(samples)} 2026 CVEs with NVD primary CWE + CVSS v3.1 vector")
    print("baseline (always CWE-79):", round(100 * sum(s['cwe'] == 'CWE-79' for s in samples) / len(samples), 1), "%\n")

    results = []
    for model in models:
        print(f"== {model}")
        results.append(run_model(model, samples))
    (ROOT / "docs" / "eval_cti_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\n| Model | RCM (CWE top-1) | VSP MAD (lower=better) | AV | AC | PR | UI | S | C | I | A | s/call |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in results:
        acc = r["vsp_metric_acc_pct"]
        print(f"| {r['model']} | {r['rcm_acc_pct']}% | {r['vsp_mad']} | "
              + " | ".join(f"{acc[m]:.0f}" for m in METRICS) + f" | {r['median_s_per_call']} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
