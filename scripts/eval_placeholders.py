"""Which placeholder format does IndicTrans2 copy through translation intact? (Evidence for backend/mt_service.py.)

Three identifier-heavy brief sentences x 8 languages = 80 identifiers per format; a hit is an exact, unsplit copy.
Run in the MT environment:  .venv-mt\\Scripts\\python -X utf8 scripts\\eval_placeholders.py
Measured 2026-10-31: <IDn> 0/80, [IDn] 0/80, IDn 27/80, #n 46/80, XQZn 60/80, raw (unprotected) 14/80.
"""

import re
import sys
import time
from pathlib import Path

import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend import mt_service as m  # noqa: E402

SENTENCES = [
    "Patch immediately: Upgrade {P} to a fixed release ({V1}, {V2}, or {V3}) to remediate the authentication bypass "
    "vulnerability ({C}).",
    "This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the {P} VPN gateway "
    "(asset {H}), which is internet-facing.",
    "Hunt for indicators: review logs on {H} since {D} for connections to {I}.",
]
VALUES = {"P": "Ivanti Connect Secure", "V1": "22.8R2.5", "V2": "25.1.3.0", "V3": "25.1.3.1", "C": "CVE-2026-104935",
          "H": "vpn-gw01.vgwc.example", "D": "2026-10-13", "I": "50[.]16[.]16[.]211"}
FORMATS = {"<IDn>": "<ID{}>", "[IDn]": "[ID{}]", "IDn": "ID{}", "#n": "#{}", "XQZn": "XQZ{}", "raw": None}
LANGS = ["hin_Deva", "tam_Taml", "ben_Beng", "urd_Arab", "tel_Telu", "mal_Mlym", "guj_Gujr", "pan_Guru"]


def main() -> None:
    tok, model = m._load()
    keys = list(VALUES)
    for name, fmt in FORMATS.items():
        ok = total = 0
        started = time.time()
        for tgt in LANGS:
            srcs, expects = [], []
            for s in SENTENCES:
                used = [k for k in keys if "{" + k + "}" in s]
                sub = VALUES if fmt is None else {k: fmt.format(keys.index(k) + 1) for k in keys}
                srcs.append(s.format(**sub))
                expects.append([sub[k] for k in used])
            enc = tok([f"eng_Latn {tgt} {x}" for x in srcs], truncation=True, padding="longest", return_tensors="pt")
            with torch.inference_mode():
                gen = model.generate(**enc, max_new_tokens=int(enc["input_ids"].shape[1] * 1.8) + 16, num_beams=4,
                                     no_repeat_ngram_size=4, use_cache=False)
            for out, exp in zip(tok.batch_decode(gen, skip_special_tokens=True), expects):
                for e in exp:
                    total += 1
                    ok += re.search(re.escape(e) + (r"(?!\d)" if fmt else ""), out) is not None
        print(f"{name:7s} {ok}/{total} identifiers survive ({time.time() - started:.0f}s)")


if __name__ == "__main__":
    main()
