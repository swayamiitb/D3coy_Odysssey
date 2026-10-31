"""Pre-compute everything a demo touches, so nothing on stage waits for the GPU or the CPU translator. Safe to re-run
(the API caches every AI output by content).

  - AI briefs for the warnings on the "Now" feed, translated into each organisation's own language (plus --langs);
  - the advisory inbox (real CISA advisories + samples): analysis, and the approval-gated notification proposals;
  - one run of the test bench, so the Proof page shows fresh results.

Usage: .venv/Scripts/python scripts/warm_cache.py [--limit 10] [--langs hi]  (any of the 22 codes from /api/languages)
"""

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

API = "http://127.0.0.1:8000"
ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--langs", default="hi")
    args = ap.parse_args()
    state_lang = json.loads((ROOT / "config" / "scoring.json").read_text(encoding="utf-8"))["sentinel"]["state_language"]
    orgs = {o["id"]: o for o in httpx.get(f"{API}/api/orgs", timeout=60).json()}

    feed = httpx.get(f"{API}/api/feed", params={"limit": args.limit}, timeout=60).json()
    for card in feed["cards"]:
        path = f"{API}/api/alerts/{card['org_id']}/{card['cve_id']}"
        t = time.time()
        brief = httpx.get(f"{path}/brief", timeout=300).json()
        line = f"{card['org_id']}:{card['cve_id']} brief={brief['status']}"
        if brief["status"] == "validated":
            own = state_lang.get(orgs.get(card["org_id"], {}).get("state", ""), "hi")
            for lang in dict.fromkeys([own, *filter(None, args.langs.split(","))]):
                tr = httpx.get(f"{path}/brief/translate", params={"lang": lang}, timeout=600).json()
                line += f" {lang}={tr.get('validated')}/{tr.get('total')}"
        print(f"{line} ({time.time() - t:.0f}s)", flush=True)

    t = time.time()
    adv = httpx.get(f"{API}/api/advisories", timeout=900).json()
    print(f"advisories: {len(adv)} analysed ({time.time() - t:.0f}s); "
          f"{len(httpx.get(f'{API}/api/approvals', timeout=60).json())} proposals pending", flush=True)

    t = time.time()
    bench = httpx.post(f"{API}/api/tests/run", timeout=900).json()
    print(f"test bench: {bench['passed']}/{bench['total']} passed ({time.time() - t:.0f}s)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
