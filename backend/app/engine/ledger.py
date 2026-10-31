"""Append-only, hash-chained evidence ledger (tamper-evident audit trail).

Every input event (feed record, sensor hit, log sighting, analyst action, model output) is appended with
sha256(prev_hash + canonical payload). Scores and alerts are derived from the ledger, so any number can be
replayed; editing a past row breaks the chain, which `verify()` detects.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,          -- event time (observed/published), ISO-8601
    ingested   REAL NOT NULL,          -- wall-clock ingest time
    kind       TEXT NOT NULL,          -- vuln.published | kev.added | ssvc.updated | decoy.surge | ioc.sighting |
                                       -- analyst.approve | analyst.false_positive | model.output | ...
    subject    TEXT NOT NULL,          -- e.g. CVE id, asset id, alert id
    source     TEXT NOT NULL,          -- CISA_KEV, CNA, NVD, DECOY_GRID, SIM_LOGS, ANALYST, MODEL:<name>
    provenance TEXT NOT NULL,          -- REAL | SIM
    payload    TEXT NOT NULL,          -- canonical JSON
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS ledger_subject ON ledger(subject);
CREATE INDEX IF NOT EXISTS ledger_kind ON ledger(kind);
"""


def _canon(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Ledger:
    def __init__(self, path: Path | str | None = None, *, conn: sqlite3.Connection | None = None,
                 autocommit: bool = True):
        self.db = conn or sqlite3.connect(str(path), check_same_thread=False)
        self.autocommit = autocommit
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    def head(self) -> str:
        row = self.db.execute("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def append(self, *, ts: str, kind: str, subject: str, source: str, payload: dict,
               provenance: str = "REAL") -> str:
        # Reading the head and inserting must be one write transaction, or two writers (the live engine and an
        # analyst's click) can both chain from the same head and fork the chain. Inside a caller's write
        # transaction the reserved lock is already held.
        if not self.db.in_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        prev = self.head()
        body = _canon({"ts": ts, "kind": kind, "subject": subject, "source": source,
                       "provenance": provenance, "payload": payload})
        digest = hashlib.sha256((prev + body).encode()).hexdigest()
        self.db.execute(
            "INSERT INTO ledger (ts, ingested, kind, subject, source, provenance, payload, prev_hash, hash) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, time.time(), kind, subject, source, provenance, _canon(payload), prev, digest),
        )
        if self.autocommit:
            self.db.commit()
        return digest

    def events(self, subject: str | None = None, kind: str | None = None) -> list[dict]:
        q, args = "SELECT seq, ts, kind, subject, source, provenance, payload, hash FROM ledger WHERE 1=1", []
        if subject:
            q, args = q + " AND subject = ?", args + [subject]
        if kind:
            q, args = q + " AND kind = ?", args + [kind]
        rows = self.db.execute(q + " ORDER BY ts, seq", args).fetchall()
        return [{"seq": r[0], "ts": r[1], "kind": r[2], "subject": r[3], "source": r[4], "provenance": r[5],
                 "payload": json.loads(r[6]), "hash": r[7]} for r in rows]

    def verify(self) -> tuple[bool, int | None]:
        """Recompute the chain. Returns (ok, first_bad_seq)."""
        prev = GENESIS
        for seq, ts, kind, subject, source, prov, payload, prev_hash, digest in self.db.execute(
                "SELECT seq, ts, kind, subject, source, provenance, payload, prev_hash, hash FROM ledger ORDER BY seq"):
            body = _canon({"ts": ts, "kind": kind, "subject": subject, "source": source, "provenance": prov,
                           "payload": json.loads(payload)})
            if prev_hash != prev or hashlib.sha256((prev + body).encode()).hexdigest() != digest:
                return False, seq
            prev = digest
        return True, None
