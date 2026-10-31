"""Vendor-agnostic version comparison.

Real advisories mix schemes that `packaging.version` cannot parse: Ivanti "22.8R2.4", Citrix "14.1-29.72",
OpenSSH "9.6p1", Exchange "2019_cu14", Log4j "2.0-beta9". Versions are tokenised into numeric and alphabetic
runs and compared element-wise:
  - numbers compare numerically;
  - a missing trailing element sorts below anything present (22.8R2 < 22.8R2.4, 9.6 < 9.6p1);
  - pre-release words (alpha, beta, rc, pre, dev, preview) sort below a missing element (2.0-beta9 < 2.0).
NVD splits some versions across the CPE version and update fields (22.8 + r2.4); `from_cpe` rejoins them.
"""

from __future__ import annotations

import functools
import re

_TOKEN = re.compile(r"\d+|[a-z]+")
_PRE = {"alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "snapshot", "milestone", "m"}

# Element ranks: pre-release < missing < alphabetic marker < number.
_PRE_RANK, _MISSING_RANK, _ALPHA_RANK, _NUM_RANK = 0, 1, 2, 3
_MISSING = (_MISSING_RANK, 0, "")


_ZERO = (_NUM_RANK, 0, "")


def _key(version: str) -> tuple:
    out = []
    for tok in _TOKEN.findall(version.lower()):
        if tok.isdigit():
            out.append((_NUM_RANK, int(tok), ""))
        elif tok in _PRE:
            out.append((_PRE_RANK, 0, tok))
        else:
            out.append((_ALPHA_RANK, 0, tok))
    return tuple(out)


def _pad(element: tuple, other: tuple) -> tuple:
    """A missing element behaves like 0 against a number (25.1.3 == 25.1.3.0), else as 'missing'."""
    return _ZERO if other[0] == _NUM_RANK else _MISSING


@functools.total_ordering
class Version:
    __slots__ = ("raw", "key")

    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.key = _key(self.raw)

    def _cmp(self, other: "Version") -> int:
        a, b = self.key, other.key
        for i in range(max(len(a), len(b))):
            x = a[i] if i < len(a) else _pad(_MISSING, b[i])
            y = b[i] if i < len(b) else _pad(_MISSING, a[i])
            if x != y:
                return -1 if x < y else 1
        return 0

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._cmp(other) == 0

    def __lt__(self, other: "Version") -> bool:
        return self._cmp(other) < 0

    def __hash__(self) -> int:
        key = list(self.key)
        while key and key[-1] == _ZERO:  # keep hash consistent with 25.1.3 == 25.1.3.0
            key.pop()
        return hash(tuple(key))

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"

    @property
    def parseable(self) -> bool:
        return bool(self.key) and self.key[0][0] == _NUM_RANK


def from_cpe(version_field: str, update_field: str = "*") -> str | None:
    """Rejoin NVD's split version/update fields: ('22.8', 'r2.4') -> '22.8r2.4'. None means wildcard."""
    if version_field in ("*", "-", ""):
        return None
    if update_field in ("*", "-", ""):
        return version_field
    return f"{version_field}{update_field}"


def in_range(v: Version, *, start_incl: str | None = None, start_excl: str | None = None,
             end_incl: str | None = None, end_excl: str | None = None) -> bool:
    if start_incl and v < Version(start_incl):
        return False
    if start_excl and v <= Version(start_excl):
        return False
    if end_incl and v > Version(end_incl):
        return False
    if end_excl and v >= Version(end_excl):
        return False
    return True
