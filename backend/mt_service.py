"""Indic translation microservice (IndicTrans2 en->indic distilled 200M, AI4Bharat, MIT). Offline, CPU.

Runs in its own Python 3.14 environment (.venv-mt) because sentencepiece has no Python 3.15 wheel yet.
Protected spans (CVE ids, versions, hostnames, IPs, product names) are replaced with <ID n> placeholders, the
format IndicTrans2's own preprocessor uses, and restored afterwards. Every output is validated: all placeholders
must survive exactly, and the text must be in the target script (no foreign-script leakage).

Run: .venv-mt\\Scripts\\python -m uvicorn backend.mt_service:app --host 127.0.0.1 --port 8010
"""

from __future__ import annotations

import os
import re
import time

os.environ.setdefault("HF_HOME", r"D:\hf-cache")
os.environ.setdefault("HF_HUB_OFFLINE", "1")  # never reach the network at run time

import torch  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer  # noqa: E402

MODEL_ID = "naklitechie/indictrans2-en-indic-dist-200M"  # byte-identical mirror of ai4bharat/indictrans2-en-indic-dist-200M
# All 22 scheduled languages of the Indian Constitution (Eighth Schedule), with their standard scripts.
# code -> (IndicTrans2 tag, English name, native name, script, right-to-left)
LANGUAGES = {
    "as": ("asm_Beng", "Assamese", "অসমীয়া", "Beng", False),
    "bn": ("ben_Beng", "Bengali", "বাংলা", "Beng", False),
    "brx": ("brx_Deva", "Bodo", "बड़ो", "Deva", False),
    "doi": ("doi_Deva", "Dogri", "डोगरी", "Deva", False),
    "gu": ("guj_Gujr", "Gujarati", "ગુજરાતી", "Gujr", False),
    "hi": ("hin_Deva", "Hindi", "हिन्दी", "Deva", False),
    "kn": ("kan_Knda", "Kannada", "ಕನ್ನಡ", "Knda", False),
    "ks": ("kas_Arab", "Kashmiri", "کٲشُر", "Arab", True),
    "kok": ("gom_Deva", "Konkani", "कोंकणी", "Deva", False),
    "mai": ("mai_Deva", "Maithili", "मैथिली", "Deva", False),
    "ml": ("mal_Mlym", "Malayalam", "മലയാളം", "Mlym", False),
    "mni": ("mni_Mtei", "Manipuri", "ꯃꯤꯇꯩꯂꯣꯟ", "Mtei", False),
    "mr": ("mar_Deva", "Marathi", "मराठी", "Deva", False),
    "ne": ("npi_Deva", "Nepali", "नेपाली", "Deva", False),
    "or": ("ory_Orya", "Odia", "ଓଡ଼ିଆ", "Orya", False),
    "pa": ("pan_Guru", "Punjabi", "ਪੰਜਾਬੀ", "Guru", False),
    "sa": ("san_Deva", "Sanskrit", "संस्कृतम्", "Deva", False),
    "sat": ("sat_Olck", "Santali", "ᱥᱟᱱᱛᱟᱲᱤ", "Olck", False),
    "sd": ("snd_Arab", "Sindhi", "سنڌي", "Arab", True),
    "ta": ("tam_Taml", "Tamil", "தமிழ்", "Taml", False),
    "te": ("tel_Telu", "Telugu", "తెలుగు", "Telu", False),
    "ur": ("urd_Arab", "Urdu", "اردو", "Arab", True),
}
LANGS = {code: v[0] for code, v in LANGUAGES.items()}
SCRIPT_RANGES = {
    "Deva": "ऀ-ॿ꣠-ꣿ", "Beng": "ঀ-৿", "Guru": "਀-੿", "Gujr": "઀-૿",
    "Orya": "଀-୿", "Taml": "஀-௿", "Telu": "ఀ-౿", "Knda": "ಀ-೿",
    "Mlym": "ഀ-ൿ", "Arab": "؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿",
    "Olck": "᱐-᱿", "Mtei": "ꯀ-꯿ꫠ-꫿",
}
_PROTECT = re.compile(
    r"CVE-\d{4}-\d{4,}"
    r"|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.(?:example|in|com|org|net|gov)\b"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\d{1,3}(?:\[\.\]\d{1,3}){3}\b"
    r"|\b\d+(?:\.\d+)+(?:[A-Za-z]+\d+(?:\.\d+)*)?(?:-[\d.]+)?\b"
    r"|\b\d{4}-\d{2}-\d{2}\b",
    re.I,
)
# IndicTrans2 is trained with script unification: Brahmic-script languages are generated in Devanagari and must be
# transliterated back. Brahmic Unicode blocks are ISCII-aligned, so this is an offset mapping (as in AI4Bharat's
# IndicNLP UnicodeIndicTransliterator), with fixes for letters a target script lacks.
BRAHMIC_BASE = {"Beng": 0x0980, "Guru": 0x0A00, "Gujr": 0x0A80, "Orya": 0x0B00, "Taml": 0x0B80, "Telu": 0x0C00,
                "Knda": 0x0C80, "Mlym": 0x0D00}
_TAMIL_FALLBACK = {0x16: 0x15, 0x17: 0x15, 0x18: 0x15, 0x1B: 0x1A, 0x1D: 0x1C, 0x20: 0x1F, 0x21: 0x1F, 0x22: 0x1F,
                   0x25: 0x24, 0x26: 0x24, 0x27: 0x24, 0x2B: 0x2A, 0x2C: 0x2A, 0x2D: 0x2A}
_SHARED = {0x64, 0x65}  # danda / double danda are used by all these scripts


_NO_NUKTA = {"Taml", "Mlym"}  # these scripts have no nukta (U+0D3C in Malayalam is a virama variant, not a nukta)


def _assigned(ch: str) -> bool:
    import unicodedata
    try:
        unicodedata.name(ch)
        return True
    except ValueError:
        return False


def _map_char(ch: str, script: str, lang: str) -> str:
    import unicodedata
    cp = ord(ch)
    if not 0x0900 <= cp <= 0x097F or (cp - 0x0900) in _SHARED:
        return ch
    off = cp - 0x0900
    if off == 0x3C and script in _NO_NUKTA:                    # nukta
        return ""
    if script == "Beng" and lang == "as" and off == 0x30:      # Assamese RA
        return "ৰ"
    if script == "Beng" and off == 0x35:                       # VA: Assamese WA, Bengali BA
        return "ৱ" if lang == "as" else "ব"
    if script == "Taml" and off in _TAMIL_FALLBACK:
        off = _TAMIL_FALLBACK[off]
    target = chr(BRAHMIC_BASE[script] + off)
    if _assigned(target):
        return target
    parts = unicodedata.normalize("NFD", ch)                   # e.g. ऩ -> न + ़ when the target lacks NNNA
    if len(parts) > 1:
        return "".join(_map_char(p, script, lang) for p in parts)
    return ch


def to_native(text: str, script: str, lang: str) -> str:
    import unicodedata
    if script not in BRAHMIC_BASE:
        return text
    out = []
    for ch in text:
        # Only the Devanagari nukta letters (क़ ख़ ग़ ज़ ड़ ढ़ फ़ य़) are pre-split; ऩ ऱ ऴ map directly (Tamil/Malayalam ன ற ழ).
        pieces = unicodedata.normalize("NFD", ch) if 0x0958 <= ord(ch) <= 0x095F else ch
        out.extend(_map_char(p, script, lang) for p in pieces)
    return unicodedata.normalize("NFC", "".join(out))


_FOREIGN = re.compile(r"[\u0400-\u04FF\u0E00-\u0E7F\u4E00-\u9FFF\uAC00-\uD7AF]")  # Cyrillic, Thai, CJK, Hangul

app = FastAPI(title="Odyssey Indic translation service")
_state: dict = {}


def _load():
    if "model" not in _state:
        torch.set_num_threads(max(4, (os.cpu_count() or 8) // 2))
        _state["tok"] = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True)
        _state["model"] = AutoModelForSeq2SeqLM.from_pretrained(MODEL_ID, trust_remote_code=True).eval()
    return _state["tok"], _state["model"]


def _protect(text: str, extra: list[str]) -> tuple[str, dict[str, str]]:
    mapping: dict[str, str] = {}

    def sub(value: str) -> str:
        key = next((k for k, v in mapping.items() if v == value), None)
        if key is None:
            key = f"<ID{len(mapping) + 1}>"
            mapping[key] = value
        return key

    for term in sorted({t for t in extra if t}, key=len, reverse=True):
        text = re.sub(re.escape(term), lambda m: sub(m.group(0)), text)
    text = _PROTECT.sub(lambda m: sub(m.group(0)), text)
    return text, mapping


def _validate(out: str, mapping: dict[str, str], script: str) -> list[str]:
    problems = [f"placeholder {k} lost or duplicated" for k in mapping if out.count(k) != 1]
    body = re.sub(r"<ID\d+>|[।॥]", "", out)  # danda / double danda are shared punctuation, not a leak
    letters = [c for c in body if c.isalpha() or "ऀ" <= c <= "꯿"]
    in_script = re.compile(f"[{SCRIPT_RANGES[script]}]")
    other = re.compile("[" + "".join(r for s, r in SCRIPT_RANGES.items() if s != script) + "]")
    if _FOREIGN.search(body) or other.search(body):
        problems.append("letters from another script leaked into the output")
    if letters and sum(bool(in_script.match(c)) for c in letters) / len(letters) < 0.6:
        problems.append(f"output is not mostly {script} script")
    return problems


class Request(BaseModel):
    texts: list[str]
    lang: str = "hi"
    protect: list[str] = []


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": MODEL_ID, "loaded": "model" in _state, "langs": list(LANGS)}


@app.get("/languages")
def languages() -> list[dict]:
    return [{"code": c, "tag": t, "name": n, "native": nat, "script": s, "rtl": rtl}
            for c, (t, n, nat, s, rtl) in LANGUAGES.items()]


@app.post("/translate")
def translate(req: Request) -> dict:
    if req.lang not in LANGUAGES:
        from fastapi import HTTPException
        raise HTTPException(400, f"unsupported language '{req.lang}'; see /languages")
    tok, model = _load()
    tgt, _, _, script, rtl = LANGUAGES[req.lang]
    started = time.perf_counter()
    prepared = [_protect(t, req.protect) for t in req.texts]
    batch = [f"eng_Latn {tgt} {p}" for p, _ in prepared]
    with torch.inference_mode():
        enc = tok(batch, truncation=True, padding="longest", return_tensors="pt")
        # Output length bounded by input length (no runaway loops); remote code predates the Cache API.
        gen = model.generate(**enc, max_new_tokens=int(enc["input_ids"].shape[1] * 1.8) + 16, num_beams=4,
                             no_repeat_ngram_size=4, num_return_sequences=1, use_cache=False)
    decoded = tok.batch_decode(gen, skip_special_tokens=True, clean_up_tokenization_spaces=True)
    results = []
    for (_, mapping), out, src in zip(prepared, decoded, req.texts):
        # '>' is not in the IndicTrans2 vocabulary, so the model emits "<ID1" (sometimes "<ID1′"); normalise.
        out = re.sub(r"['’]?<\s*ID\s*(\d+)\s*[>′'’]?", r" <ID\1> ", out)
        out = re.sub(r"(<ID\d+>)\s*[\]\[ʼ'’.]+(?=\s)", r"\1", out)  # stray marks the model attaches to identifiers
        out = re.sub(r"\s+", " ", out).replace(" ।", "।").replace("( ", "(").replace(" )", ")").strip()
        out = to_native(out, script, req.lang)
        problems = _validate(out, mapping, script)
        for key, value in mapping.items():
            out = out.replace(key, f"⁦{value}⁩" if rtl else value)  # isolate LTR ids inside RTL text
        results.append({"source": src, "text": out if not problems else None,
                        "status": "validated" if not problems else "withheld", "problems": problems})
    return {"lang": req.lang, "model": MODEL_ID, "script": script, "rtl": rtl,
            "seconds": round(time.perf_counter() - started, 2), "results": results}
