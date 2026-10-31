"""Pre-generate AI briefs and Indic-language translations for the warnings on the "Now" feed, so nothing on stage
waits for the GPU or the CPU translator. Safe to re-run (everything is cached by the API).

Usage: .venv/Scripts/python scripts/warm_cache.py [--limit 10] [--langs hi,bn,ta,te,mr]  (any of the 22 codes from /api/languages)
"""

import argparse
import sys
import time

import httpx

API = "http://127.0.0.1:8000"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--langs", default="hi,bn,ta,te,mr")
    args = ap.parse_args()
    feed = httpx.get(f"{API}/api/feed", params={"limit": args.limit}, timeout=60).json()
    for card in feed["cards"]:
        path = f"{API}/api/alerts/{card['org_id']}/{card['cve_id']}"
        t = time.time()
        brief = httpx.get(f"{path}/brief", timeout=300).json()
        line = f"{card['org_id']}:{card['cve_id']} brief={brief['status']}"
        if brief["status"] == "validated":
            for lang in filter(None, args.langs.split(",")):
                tr = httpx.get(f"{path}/brief/translate", params={"lang": lang}, timeout=600).json()
                line += f" {lang}={tr.get('validated')}/{tr.get('total')}"
        print(f"{line} ({time.time() - t:.0f}s)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
