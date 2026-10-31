"""Snapshot every public threat-intel source into data/raw so the demo runs fully offline.

Usage: python scripts/snapshot_feeds.py [--skip-nvd] [--vulnrichment-days 90]
"""

import argparse
import datetime as dt
import hashlib
import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
UA = {"User-Agent": "D3COY-EWS/0.1 (hackathon research; passive feed snapshot)"}

FEEDS = {
    "kev.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss_scores-current.csv.gz": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "feodo_ipblocklist.json": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "openphish.txt": "https://openphish.com/feed.txt",
    "enterprise-attack.json": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
}
NVD_YEARS = range(2021, dt.date.today().year + 1)
NVD_EXTRA = ["recent", "modified"]


def fetch(url: str, dest: Path, retries: int = 3, timeout: int = 180) -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
            dest.write_bytes(body)
            return {"file": str(dest.relative_to(RAW)), "url": url, "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(), "ok": True}
        except Exception as exc:  # noqa: BLE001 - report and retry any network failure
            if attempt == retries:
                return {"file": str(dest.relative_to(RAW)), "url": url, "ok": False, "error": repr(exc)}
            time.sleep(2 * attempt)


def vulnrichment_url(cve_id: str) -> str:
    _, year, num = cve_id.split("-")
    bucket = f"{int(num) // 1000}xxx"
    return f"https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{bucket}/{cve_id}.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-nvd", action="store_true")
    ap.add_argument("--vulnrichment-days", type=int, default=90)
    args = ap.parse_args()

    jobs = [(url, RAW / name) for name, url in FEEDS.items()]
    if not args.skip_nvd:
        for year in [*NVD_YEARS, *NVD_EXTRA]:
            name = f"nvdcve-2.0-{year}.json.gz"
            jobs.append((f"https://nvd.nist.gov/feeds/json/cve/2.0/{name}", RAW / "nvd" / name))

    started = time.time()
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda j: fetch(*j), jobs))
    for r in results:
        print(("OK  " if r["ok"] else "FAIL"), r["file"], r.get("bytes", r.get("error")), flush=True)

    # SSVC enrichment for recent KEV additions (the CVEs the demo stories draw from).
    kev_path = RAW / "kev.json"
    if kev_path.exists():
        kev = json.loads(kev_path.read_text(encoding="utf-8"))
        cutoff = (dt.date.today() - dt.timedelta(days=args.vulnrichment_days)).isoformat()
        cves = [v["cveID"] for v in kev["vulnerabilities"] if v["dateAdded"] >= cutoff]
        vr_jobs = [(vulnrichment_url(c), RAW / "vulnrichment" / f"{c}.json") for c in cves]
        with ThreadPoolExecutor(max_workers=8) as pool:
            vr = list(pool.map(lambda j: fetch(*j, retries=2, timeout=30), vr_jobs))
        ok = sum(r["ok"] for r in vr)
        print(f"OK   vulnrichment {ok}/{len(vr)} recent KEV CVEs (since {cutoff})", flush=True)
        results += vr

    manifest = {"snapshot_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                "seconds": round(time.time() - started, 1), "items": results}
    (RAW / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    failed = [r for r in results if not r["ok"]]
    print(f"done in {manifest['seconds']}s, {len(results) - len(failed)} ok, {len(failed)} failed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
