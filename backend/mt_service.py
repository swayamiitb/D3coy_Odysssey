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
LANGS = {"hi": "hin_Deva", "mr": "mar_Deva"}
_PROTECT = re.compile(
    r"CVE-\d{4}-\d{4,}"
    r"|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.(?:example|in|com|org|net|gov)\b"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\d{1,3}(?:\[\.\]\d{1,3}){3}\b"
    r"|\b\d+(?:\.\d+)+(?:[A-Za-z]+\d+(?:\.\d+)*)?(?:-[\d.]+)?\b"
    r"|\b\d{4}-\d{2}-\d{2}\b",
    re.I,
)
_DEVANAGARI = re.compile(r"[\u0900-\u097F]")
_FOREIGN = re.compile(r"[\u0400-\u04FF\u0600-\u06FF\u0E00-\u0E7F\u4E00-\u9FFF]")  # Cyrillic, Arabic, Thai, CJK

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


def _validate(out: str, mapping: dict[str, str]) -> list[str]:
    problems = [f"placeholder {k} lost or duplicated" for k in mapping if out.count(k) != 1]
    letters = [c for c in re.sub(r"<ID\d+>", "", out) if c.isalpha()]
    if _FOREIGN.search(out):
        problems.append("foreign-script characters")
    if letters and sum(bool(_DEVANAGARI.match(c)) for c in letters) / len(letters) < 0.6:
        problems.append("output is not mostly Devanagari")
    return problems


class Request(BaseModel):
    texts: list[str]
    lang: str = "hi"
    protect: list[str] = []


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": MODEL_ID, "loaded": "model" in _state, "langs": list(LANGS)}


@app.post("/translate")
def translate(req: Request) -> dict:
    tok, model = _load()
    tgt = LANGS[req.lang]
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
        out = re.sub(r"\s+", " ", out).replace(" ।", "।").replace("( ", "(").replace(" )", ")").strip()
        problems = _validate(out, mapping)
        for key, value in mapping.items():
            out = out.replace(key, value)
        results.append({"source": src, "text": out if not problems else None,
                        "status": "validated" if not problems else "withheld", "problems": problems})
    return {"lang": req.lang, "model": MODEL_ID, "seconds": round(time.perf_counter() - started, 2),
            "results": results}
