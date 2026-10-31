"""After a rebuild the SOC's cases are seeded on first use. The first requests arrive together, so seeding must be
safe under concurrency: exactly one seed, no UNIQUE failures, and live case ids never collide."""

import sqlite3
import threading
from pathlib import Path

import pytest

from backend.app.engine import soc

DB = Path(__file__).resolve().parents[1] / "data" / "ews.db"


@pytest.fixture
def fresh_copy(tmp_path):
    if not DB.exists():
        pytest.skip("no built database")
    path = tmp_path / "ews.db"
    src, dst = sqlite3.connect(f"file:{DB}?mode=ro", uri=True), sqlite3.connect(path)
    src.backup(dst)
    src.close()
    dst.execute("DROP TABLE IF EXISTS soc_cases")
    dst.commit()
    dst.close()
    return path


def test_concurrent_first_requests_seed_the_cases_once(fresh_copy):
    errors: list[BaseException] = []

    def visitor() -> None:
        try:
            soc.ensure(sqlite3.connect(fresh_copy, timeout=30, check_same_thread=False))
        except BaseException as exc:  # noqa: BLE001 - any failure is the bug under test
            errors.append(exc)

    threads = [threading.Thread(target=visitor) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    conn = sqlite3.connect(fresh_copy)
    n = conn.execute("SELECT COUNT(*) FROM soc_cases").fetchone()[0]
    assert n > 0 and n == conn.execute("SELECT COUNT(DISTINCT id) FROM soc_cases").fetchone()[0]


def test_live_cases_opened_at_once_get_distinct_ids(fresh_copy):
    soc.ensure(sqlite3.connect(fresh_copy, timeout=30))
    ids: list[str] = []
    errors: list[BaseException] = []

    def opener(k: int) -> None:
        try:
            c = soc.open_case(sqlite3.connect(fresh_copy, timeout=30, check_same_thread=False), "incident",
                              f"Suspected compromise of host{k}", "PWR-01", "Compromise", "m.khan", 6, [], "x",
                              [f"host{k}"], "test")
            ids.append(c["id"])
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=opener, args=(k,)) for k in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(ids) == 5 and len(set(ids)) == 5
