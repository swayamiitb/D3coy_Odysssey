"""Security-domain embeddings (Cisco SecureBERT 2.0 bi-encoder, CPU) for related-threat retrieval.

The index (data/embeddings.npz) holds one L2-normalised vector per vulnerability description, so cosine
similarity is a dot product. Build: .venv/Scripts/python -m backend.app.ai.embed
"""

from __future__ import annotations

import functools
import os
import sqlite3
import time
from pathlib import Path

import numpy as np

MODEL_ID = "cisco-ai/SecureBERT2.0-biencoder"
ROOT = Path(__file__).resolve().parents[3]
INDEX = ROOT / "data" / "embeddings.npz"


@functools.lru_cache(maxsize=1)
def model():
    os.environ.setdefault("HF_HOME", r"D:\hf-cache")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(MODEL_ID, device="cpu")


def encode(texts: list[str]) -> np.ndarray:
    return model().encode(texts, batch_size=32, normalize_embeddings=True, show_progress_bar=False)


def build(db_path: Path = ROOT / "data" / "ews.db") -> int:
    rows = sqlite3.connect(db_path).execute("SELECT id, description FROM vulns WHERE description != ''").fetchall()
    started = time.time()
    matrix = encode([d[:1500] for _, d in rows]).astype(np.float32)
    np.savez_compressed(INDEX, ids=np.array([i for i, _ in rows]), matrix=matrix, model=MODEL_ID)
    print(f"embedded {len(rows)} descriptions with {MODEL_ID} in {time.time() - started:.0f}s -> {INDEX}")
    return len(rows)


@functools.lru_cache(maxsize=1)
def index() -> tuple[np.ndarray, np.ndarray] | None:
    if not INDEX.exists():
        return None
    data = np.load(INDEX)
    return data["ids"], data["matrix"]


def related(cve_id: str, k: int = 6) -> list[tuple[str, float]]:
    idx = index()
    if idx is None:
        return []
    ids, matrix = idx
    hit = np.where(ids == cve_id)[0]
    if not len(hit):
        return []
    sims = matrix @ matrix[hit[0]]
    order = np.argsort(-sims)
    return [(str(ids[i]), round(float(sims[i]), 3)) for i in order if ids[i] != cve_id][:k]


if __name__ == "__main__":
    build()
