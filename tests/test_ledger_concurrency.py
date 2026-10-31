"""The audit trail stays one chain when several writers append at once (the live engine, analysts' clicks)."""

import sqlite3
import threading

from backend.app.engine.ledger import Ledger


def test_concurrent_writers_never_fork_the_chain(tmp_path):
    path = tmp_path / "ledger.db"
    Ledger(path)

    def writer(name: str) -> None:
        led = Ledger(conn=sqlite3.connect(path, timeout=30, check_same_thread=False))
        for i in range(150):
            led.append(ts=f"2026-11-01T00:00:{i % 60:02d}Z", kind="test.event", subject=f"{name}-{i}", source="TEST",
                       payload={"i": i})

    threads = [threading.Thread(target=writer, args=(f"w{n}",)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    led = Ledger(path)
    assert led.db.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 600
    assert led.verify() == (True, None)
