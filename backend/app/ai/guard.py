"""Prompt-injection guard for untrusted text (advisories, CVE descriptions, pasted input) before any LLM sees it.

Defence in depth:
  1. ProtectAI deberta-v3-base-prompt-injection-v2 (Apache-2.0, 184M, CPU) - threshold 0.90 (lower fires on
     benign words like "ignore" in admin guidance)
  2. deterministic rules for text that addresses an AI or tries to steer scoring - catches subtle injections the
     classifier misses
  3. architecture: the LLM never sets scores and only selects from closed sets, so even a missed injection cannot
     change a risk number
Verdict "blocked" keeps the text away from every LLM call; the deterministic pipeline still runs.
"""

from __future__ import annotations

import functools
import os
import re

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
THRESHOLD_BLOCK = 0.90
THRESHOLD_SUSPICIOUS = 0.50
_RULES = [
    ("ignore-instructions", re.compile(r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|all|earlier)\b.{0,20}"
                                       r"\b(instructions?|prompts?|rules?|context)\b", re.I)),
    ("addresses-the-ai", re.compile(r"\b(note|message|instruction)s?\s+(to|for)\s+(the\s+)?(ai|assistant|analyst model|"
                                    r"llm|language model|model)\b|\byou are (an? )?(ai|assistant|language model)\b", re.I)),
    ("steers-scoring", re.compile(r"\b(set|change|lower|reduce)\b.{0,20}\b(risk|score|severity|tier|priority)\b.{0,20}"
                                  r"\b(to|as)\b|\bdo not (mention|report|flag)\b", re.I)),
    ("role-markers", re.compile(r"<\|?(system|im_start|assistant|user)\|?>|\[\s*system\s*\]|###\s*(system|instruction)", re.I)),
]


@functools.lru_cache(maxsize=1)
def _clf():
    os.environ.setdefault("HF_HOME", r"D:\hf-cache")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    from transformers import pipeline
    return pipeline("text-classification", model=MODEL_ID, truncation=True, max_length=512, device=-1)


def screen(text: str) -> dict:
    text = text or ""
    chunks = [text[i:i + 1800] for i in range(0, max(len(text), 1), 1800)][:6]
    worst = max((r for r in (_clf()(c)[0] for c in chunks)),
                key=lambda r: r["score"] if r["label"] == "INJECTION" else 0)
    p_inj = worst["score"] if worst["label"] == "INJECTION" else 1 - worst["score"]
    rules = [name for name, rx in _RULES if rx.search(text)]
    verdict = ("blocked" if p_inj >= THRESHOLD_BLOCK or rules else
               "suspicious" if p_inj >= THRESHOLD_SUSPICIOUS else "clean")
    return {"verdict": verdict, "model": MODEL_ID, "p_injection": round(p_inj, 3), "rules": rules}
