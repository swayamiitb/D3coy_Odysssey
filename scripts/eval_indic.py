"""End-to-end check of the Indic translation path in all 22 scheduled languages, through the running MT service
(the same protect -> translate -> transliterate -> validate path the dashboard uses). Writes docs/eval_indic22.json.

The sentences are real brief bullets: identifier lists, hostnames, IPs, CVE ids, dates and plain prose.
Run (service on :8010):  .venv\\Scripts\\python -X utf8 scripts\\eval_indic.py
"""

import json
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
MT = "http://127.0.0.1:8010"
PROTECT = ["Ivanti Connect Secure", "Vidyut Grid Western Corporation", "vpn-gw01.vgwc.example"]
SENTENCES = [
    "CVE-2026-104935: Ivanti Connect Secure authentication bypass under active exploitation, suspected compromise.",
    "This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the Ivanti Connect "
    "Secure VPN gateway (asset vpn-gw01.vgwc.example), which is internet-facing.",
    "Patch immediately: upgrade Ivanti Connect Secure to a fixed release (22.8R2.5, 25.1.3.0, or 25.1.3.1).",
    "Hunt for indicators: review authentication logs on vpn-gw01.vgwc.example since 2026-10-13 for connections to "
    "50[.]16[.]16[.]211.",
    "Restrict management and VPN interfaces to trusted networks if patching is delayed.",
    "Report the suspected compromise to CERT-In and preserve forensic evidence before rebuilding the device.",
]


def main() -> None:
    langs = httpx.get(f"{MT}/languages", timeout=10).json()
    record = {"model": None, "sentences": SENTENCES, "languages": {}, "validated": 0, "total": 0}
    started = time.time()
    for lang in langs:
        r = httpx.post(f"{MT}/translate", json={"texts": SENTENCES, "lang": lang["code"], "protect": PROTECT},
                       timeout=600).json()
        ok = sum(x["status"] == "validated" for x in r["results"])
        record["model"] = r["model"]
        record["languages"][lang["code"]] = {
            "name": lang["name"], "native": lang["native"], "script": lang["script"], "validated": ok, "total": len(SENTENCES),
            "seconds": r["seconds"],
            "withheld": [{"source": x["source"][:60], "problems": x["problems"]}
                         for x in r["results"] if x["status"] != "validated"]}
        record["validated"] += ok
        record["total"] += len(SENTENCES)
        print(f"{lang['code']:4s} {lang['name']:10s} {ok}/{len(SENTENCES)}  {r['seconds']:.0f}s  "
              + "; ".join(p for x in r["results"] for p in x["problems"])[:150])
    record["seconds"] = round(time.time() - started)
    print(f"TOTAL {record['validated']}/{record['total']} sentences validated across {len(langs)} languages "
          f"in {record['seconds']}s")
    (ROOT / "docs" / "eval_indic22.json").write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
