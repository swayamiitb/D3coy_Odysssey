"""Test scratch lives beside the data, not in the system temp.

Most fixtures copy data/ews.db (hundreds of MB) once per test; a day of runs in %TEMP% filled the system drive and
failed the suite with "database or disk is full". Each pytest process gets its own directory under data/.pytest-tmp
(the repository's drive), removes it when the session ends, and clears what an earlier, interrupted run left behind.
An explicit --basetemp still wins."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

SCRATCH = Path(__file__).resolve().parents[1] / "data" / ".pytest-tmp"


def pytest_configure(config) -> None:
    if getattr(config.option, "basetemp", None):
        return
    SCRATCH.mkdir(parents=True, exist_ok=True)
    cutoff = time.time() - 900  # a run takes about a minute; Windows keeps a copy locked past session end now and then
    for d in SCRATCH.glob("run-*"):
        if d.stat().st_mtime < cutoff:
            shutil.rmtree(d, ignore_errors=True)
    config.option.basetemp = str(SCRATCH / f"run-{os.getpid()}")


def pytest_sessionfinish(session, exitstatus) -> None:
    base = getattr(session.config.option, "basetemp", None)
    if base and Path(base).resolve().is_relative_to(SCRATCH.resolve()):
        shutil.rmtree(base, ignore_errors=True)
