"""Content-addressed cache for expensive AI outputs (briefs, translations), kept outside data/ews.db.

Keys are sha256 over the exact inputs (model, prompt version, facts / source text). Rebuilding the evidence
database therefore keeps every still-valid output, and an output can never be served for changed facts.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

PATH = Path(os.environ.get("ODYSSEY_CACHE") or Path(__file__).resolve().parents[2] / "data" / "cache.db")
_SCHEMA = """CREATE TABLE IF NOT EXISTS ai_cache (kind TEXT, key TEXT, created TEXT, body TEXT, PRIMARY KEY (kind, key));
CREATE TABLE IF NOT EXISTS ai_index (kind TEXT, subject TEXT, key TEXT, PRIMARY KEY (kind, subject));"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(PATH, check_same_thread=False)
    conn.executescript(_SCHEMA)
    return conn


def key_of(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def get(kind: str, key: str) -> dict | None:
    row = _conn().execute("SELECT body FROM ai_cache WHERE kind=? AND key=?", (kind, key)).fetchone()
    return json.loads(row[0]) if row else None


def put(kind: str, key: str, body: dict, created: str, subject: str | None = None) -> None:
    conn = _conn()
    conn.execute("INSERT OR REPLACE INTO ai_cache VALUES (?,?,?,?)",
                 (kind, key, created, json.dumps(body, ensure_ascii=False)))
    if subject:
        conn.execute("INSERT OR REPLACE INTO ai_index VALUES (?,?,?)", (kind, subject, key))
    conn.commit()


def latest(kind: str, subject: str) -> dict | None:
    """Most recent output for a subject (e.g. 'PWR-01:CVE-2026-104935'), regardless of key. Display only."""
    row = _conn().execute("""SELECT c.body FROM ai_index i JOIN ai_cache c ON c.kind = i.kind AND c.key = i.key
                             WHERE i.kind = ? AND i.subject = ?""", (kind, subject)).fetchone()
    return json.loads(row[0]) if row else None
