"""Fresh, untuned extraction benchmark: every 2026 CVE in CISA KEV, graded against KEV's own
vendorProject/product (strict: compacted equality or token_sort_ratio >= 90). None of these CVEs were used
to design prompts, and all post-date every candidate model's training data.

Usage: .venv/Scripts/python scripts/eval_kev_extract.py [--models mist:8b,foundation-sec:8b-instruct] [--limit N]
Writes docs/eval_kev_extract.json.
"""

import argparse
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.ai.llm import chat  # noqa: E402
from backend.app.ingest.cve_records import load_cve5, load_kev, load_nvd  # noqa: E402
from scripts.bakeoff import EXTRACT_SCHEMA, extract_messages, matches, normalise  # noqa: E402


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return round(100 * (centre - half), 1), round(100 * (centre + half), 1)


def samples(limit: int | None) -> list[dict]:
    kev = load_kev()
    ids = sorted(c for c in kev if c.startswith("CVE-2026-"))
    nvd = load_nvd(set(ids))
    out = []
    for cid in ids:
        cna = (load_cve5(cid) or {}).get("containers", {}).get("cna", {})
        desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
        if not desc and cid in nvd:
            desc = next((d["value"] for d in nvd[cid].get("descriptions", []) if d["lang"] == "en"), "")
        if desc:
            out.append({"id": cid, "desc": desc, "vendor": kev[cid]["vendorProject"], "product": kev[cid]["product"]})
    return out[:limit] if limit else out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="mist:8b,foundation-sec:8b-instruct")
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()
    data = samples(args.limit)
    print(f"{len(data)} CISA KEV 2026 CVEs with descriptions")

    results = []
    for model in args.models.split(","):
        chat([{"role": "user", "content": "ok"}], model=model, num_ctx=2048, max_tokens=4)
        v_ok = p_ok = both = valid = 0
        secs, misses = [], []
        for s in data:
            r = chat(extract_messages(s["desc"], fewshot=True), model=model, schema=EXTRACT_SCHEMA,
                     num_ctx=4096, max_tokens=400, timeout=90)
            d = normalise(r.data) if isinstance(r.data, dict) else {}
            valid += bool(d)
            vo, po = matches(d.get("vendor", ""), s["vendor"]), matches(d.get("product", ""), s["product"])
            v_ok, p_ok, both = v_ok + vo, p_ok + po, both + (vo and po)
            secs.append(r.seconds)
            if not po:
                misses.append({"id": s["id"], "truth": f"{s['vendor']} / {s['product']}",
                               "pred": f"{d.get('vendor')} / {d.get('product')}"})
        n = len(data)
        res = {"model": model, "n": n, "json_valid_pct": round(100 * valid / n, 1),
               "vendor_pct": round(100 * v_ok / n, 1), "vendor_ci95": wilson(v_ok, n),
               "product_pct": round(100 * p_ok / n, 1), "product_ci95": wilson(p_ok, n),
               "both_pct": round(100 * both / n, 1), "median_s": round(statistics.median(secs), 2),
               "misses": misses}
        results.append(res)
        print(f"{model:<28} vendor {res['vendor_pct']}% {res['vendor_ci95']}  product {res['product_pct']}% "
              f"{res['product_ci95']}  both {res['both_pct']}%  {res['median_s']} s/item", flush=True)
    (ROOT / "docs" / "eval_kev_extract.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
