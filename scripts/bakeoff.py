"""Local-model bake-off on our real task: structured extraction from CVE text, scored against NVD CPE ground truth.

Usage: .venv/Scripts/python scripts/bakeoff.py [--n 30] [--models m1,m2,...]
Writes docs/bakeoff_results.json and docs/bakeoff_samples.md.
"""

import argparse
import gzip
import json
import random
import statistics
import sys
from pathlib import Path

from rapidfuzz import fuzz

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.ai.llm import available_models, chat  # noqa: E402

NVD_DIR = ROOT / "data" / "raw" / "nvd"
# foundation-sec:8b-instruct is a local alias of the HF GGUF with the official chat template applied
# (the raw import ships a bare "{{ .Prompt }}" template, which makes it behave like a base model).
DEFAULT_MODELS = ["qwen3:4b", "qwen3:8b", "foundation-sec:8b-instruct"]
STORY_SAMPLE = {
    "id": "CVE-2026-104935",
    "desc": "Authentication bypass by spoofing in Ivanti Connect Secure before version 25.1.3.0 allows a remote "
            "unauthenticated attacker to execute arbitrary commands. This does not impact ICS version 22.7R2.14 or "
            "prior.",
}

VULN_TYPES = ["rce", "auth_bypass", "privilege_escalation", "sqli", "xss", "path_traversal", "ssrf",
              "deserialization", "info_disclosure", "dos", "memory_corruption", "csrf", "other"]
EXTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "vendor": {"type": "string"},
        "product": {"type": "string"},
        "affected_versions": {"type": "string"},
        "fixed_version": {"type": "string"},
        "vuln_type": {"type": "string", "enum": VULN_TYPES},
        "attack_vector": {"type": "string", "enum": ["network", "adjacent", "local", "physical", "unknown"]},
        "requires_auth": {"type": "boolean"},
    },
    "required": ["vendor", "product", "affected_versions", "fixed_version", "vuln_type", "attack_vector",
                 "requires_auth"],
}
EXTRACT_SYSTEM = (
    "You are a cyber threat intelligence extraction engine. Read the vulnerability description and return "
    "only the JSON fields requested. Use the vendor and product names as written in the text. "
    "Use an empty string when a value is not stated."
)
FEWSHOT_SYSTEM = EXTRACT_SYSTEM + (
    " Rules: 'vendor' is the company or open-source project that ships the software. 'product' is the "
    "shipped product name only: never a component, feature, endpoint, command or version number."
)
# Pre-2025 CVEs only, so the few-shot examples cannot leak the 2026 test set.
FEWSHOT = [
    ("A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of "
     "Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may "
     "enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall. "
     "Fixed in PAN-OS 10.2.9-h1, 11.0.4-h1 and 11.1.2-h3.",
     {"vendor": "Palo Alto Networks", "product": "PAN-OS", "affected_versions": "10.2, 11.0, 11.1 before fixes",
      "fixed_version": "10.2.9-h1", "vuln_type": "rce", "attack_vector": "network", "requires_auth": False}),
    ("Cisco is aware of active exploitation of a previously unknown vulnerability in the web UI feature of Cisco "
     "IOS XE Software when exposed to the internet or to untrusted networks. This vulnerability allows a remote, "
     "unauthenticated attacker to create an account on an affected system with privilege level 15 access.",
     {"vendor": "Cisco", "product": "IOS XE", "affected_versions": "", "fixed_version": "",
      "vuln_type": "auth_bypass", "attack_vector": "network", "requires_auth": False}),
    ("Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI "
     "features used in configuration, log messages, and parameters do not protect against attacker controlled "
     "LDAP and other JNDI related endpoints. An attacker who can control log messages can execute arbitrary code.",
     {"vendor": "Apache", "product": "Log4j", "affected_versions": "2.0-beta9 through 2.15.0",
      "fixed_version": "2.16.0", "vuln_type": "rce", "attack_vector": "network", "requires_auth": False}),
    ("Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser "
     "that replaces an '@' character followed by a file path in an argument with the file's contents, allowing "
     "unauthenticated attackers to read arbitrary files on the Jenkins controller file system.",
     {"vendor": "Jenkins", "product": "Jenkins", "affected_versions": "2.441 and earlier, LTS 2.426.2 and earlier",
      "fixed_version": "2.442", "vuln_type": "path_traversal", "attack_vector": "network",
      "requires_auth": False}),
]


def normalise(pred: dict) -> dict:
    """Open-source projects ship under their own name (CPE vendor == product); fill whichever side is empty."""
    out = dict(pred)
    if not out.get("product"):
        out["product"] = out.get("vendor", "")
    if not out.get("vendor"):
        out["vendor"] = out.get("product", "")
    return out


def extract_messages(desc: str, fewshot: bool) -> list[dict]:
    if not fewshot:
        return [{"role": "system", "content": EXTRACT_SYSTEM}, {"role": "user", "content": desc}]
    msgs = [{"role": "system", "content": FEWSHOT_SYSTEM}]
    for text, answer in FEWSHOT:
        msgs += [{"role": "user", "content": text}, {"role": "assistant", "content": json.dumps(answer)}]
    return msgs + [{"role": "user", "content": desc}]


def load_samples(n: int, seed: int = 42) -> list[dict]:
    feed = max(NVD_DIR.glob("nvdcve-2.0-20*.json.gz"))  # current year: large pool, analysed CPEs
    with gzip.open(feed, "rt", encoding="utf-8") as fh:
        vulns = json.load(fh)["vulnerabilities"]

    pool = []
    for item in vulns:
        cve = item["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        cpes = {
            tuple(m["criteria"].split(":")[3:5])
            for cfg in cve.get("configurations", [])
            for node in cfg.get("nodes", [])
            for m in node.get("cpeMatch", [])
            if m.get("vulnerable")
        }
        if len(cpes) == 1 and 120 <= len(desc) <= 900:
            vendor, product = next(iter(cpes))
            pool.append({"id": cve["id"], "desc": desc, "vendor": vendor, "product": product})

    random.Random(seed).shuffle(pool)
    picked, seen_vendors = [], set()
    for s in pool:
        if s["vendor"] not in seen_vendors:
            picked.append(s)
            seen_vendors.add(s["vendor"])
        if len(picked) == n:
            break
    return picked


def norm(s: str) -> str:
    return s.lower().replace("_", " ").replace("-", " ").strip()


def matches(pred: str, truth: str) -> bool:
    """Strict: compacted equality or token_sort_ratio >= 90. (token_set_ratio and substring checks inflate
    scores, e.g. "Server" vs "Exchange Server" scores 100; the lenient version overstated accuracy by 20-30 pts.)"""
    p, t = norm(pred), norm(truth)
    if not p:
        return False
    return p.replace(" ", "") == t.replace(" ", "") or fuzz.token_sort_ratio(p, t) >= 90


def run_model(model: str, samples: list[dict], fewshot: bool = False) -> dict:
    chat([{"role": "user", "content": "ok"}], model=model, num_ctx=2048)  # warm-up / load into VRAM
    rows = []
    for s in samples:
        r = chat(
            extract_messages(s["desc"], fewshot),
            model=model, schema=EXTRACT_SCHEMA, num_ctx=4096, max_tokens=400, timeout=90,
        )
        d = normalise(r.data) if isinstance(r.data, dict) else {}
        rows.append({
            "id": s["id"], "valid": r.error is None and bool(d),
            "vendor_ok": matches(d.get("vendor", ""), s["vendor"]),
            "product_ok": matches(d.get("product", ""), s["product"]),
            "seconds": r.seconds, "tps": r.tokens_per_s, "pred": d,
        })
        print(f"  {s['id']:<18} valid={rows[-1]['valid']!s:<5} vendor={rows[-1]['vendor_ok']!s:<5} "
              f"product={rows[-1]['product_ok']!s:<5} {r.seconds:5.1f}s", flush=True)

    n = len(rows)
    return {
        "model": model + (" +fewshot" if fewshot else ""), "n": n,
        "json_valid_pct": round(100 * sum(r["valid"] for r in rows) / n, 1),
        "vendor_pct": round(100 * sum(r["vendor_ok"] for r in rows) / n, 1),
        "product_pct": round(100 * sum(r["product_ok"] for r in rows) / n, 1),
        "median_s": round(statistics.median(r["seconds"] for r in rows), 2),
        "median_tps": round(statistics.median(r["tps"] for r in rows if r["tps"]), 1),
        "rows": rows,
    }


def qualitative(model: str, sample: dict) -> str:
    n = chat(
        [{"role": "system", "content": "You are a national CERT analyst. Write a 3-sentence early warning for "
                                       "critical-infrastructure operators: what it is, why it matters, what to do."},
         {"role": "user", "content": f"{sample['id']}: {sample['desc']}"}],
        model=model, num_ctx=4096, temperature=0.2, max_tokens=500,
    )
    h = chat(
        [{"role": "system", "content": "Translate the security advisory into clear, formal Hindi. "
                                       "Keep CVE IDs, product names and version numbers unchanged."},
         {"role": "user", "content": n.content}],
        model=model, num_ctx=4096, max_tokens=900,
    )
    return (f"## {model}\n\n**Narrative ({sample['id']})** — {n.seconds:.1f}s {n.error or ''}\n\n{n.content}\n\n"
            f"**Hindi** — {h.seconds:.1f}s {h.error or ''}\n\n{h.content}\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--models", default=",".join(DEFAULT_MODELS))
    ap.add_argument("--fewshot", action="store_true", help="prepend 3 pre-2025 worked examples")
    ap.add_argument("--tag", default="", help="suffix for output files so runs do not overwrite each other")
    ap.add_argument("--no-qualitative", action="store_true")
    args = ap.parse_args()

    have = available_models()
    models = [m for m in args.models.split(",") if m in have or f"{m}:latest" in have]
    missing = sorted(set(args.models.split(",")) - set(models))
    if missing:
        print("skipping (not pulled yet):", ", ".join(missing))

    samples = load_samples(args.n)
    print(f"{len(samples)} CVEs with single-product CPE ground truth\n")

    results, md = [], ["# Bake-off qualitative samples\n"]
    for model in models:
        print(f"== {model}")
        results.append(run_model(model, samples, args.fewshot))
        if not args.no_qualitative:
            md.append(qualitative(model, STORY_SAMPLE))

    suffix = f"_{args.tag}" if args.tag else ""
    (ROOT / "docs" / f"bakeoff_results{suffix}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    if not args.no_qualitative:
        (ROOT / "docs" / f"bakeoff_samples{suffix}.md").write_text("\n".join(md), encoding="utf-8")

    print("\n| Model | JSON valid | Vendor | Product | Median s/item | Median tok/s |")
    print("|---|---|---|---|---|---|")
    for r in results:
        print(f"| {r['model']} | {r['json_valid_pct']}% | {r['vendor_pct']}% | {r['product_pct']}% "
              f"| {r['median_s']} | {r['median_tps']} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
