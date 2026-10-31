"""Exposure matching: does a vulnerability affect a specific asset?

Three independent sources vote, each with provenance:
  NVD     - analysed CPE configurations (often absent for 2026 CVEs: NIST only analyses KEV/federal/critical)
  CNA     - the vendor's own CVE JSON 5 `affected[]` (explicit entries, ranges and defaultStatus)
  TEXT    - version constraints stated in the description ("before 25.1.3.0", "does not impact 22.7R2.14 or prior")

Reconciliation is explicit-evidence-first and safety-biased:
  explicit affected + explicit not-affected -> DISPUTED (treated as exposed, R=0.8, flagged for analyst)
  explicit affected                         -> AFFECTED (R=1.0)
  explicit not-affected                     -> CLEARED  (R=0.0, dissenting weak votes are kept and shown)
  only a CNA default of "affected"          -> PROBABLE (R=0.6)
  product match but no version evidence     -> UNKNOWN  (R=0.3)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .products import same_product
from .versions import Version, from_cpe, in_range

EXPLICIT, DEFAULT = "explicit", "default"
R_BY_STATUS = {"affected": 1.0, "disputed": 0.8, "probable": 0.6, "unknown": 0.3, "cleared": 0.0}


@dataclass
class Vote:
    source: str            # NVD | CNA | TEXT
    verdict: str           # affected | not_affected | unknown
    strength: str          # explicit | default
    reason: str
    span: str = ""


@dataclass
class Exposure:
    asset_id: str
    cve_id: str
    status: str
    relevance: float
    votes: list[Vote] = field(default_factory=list)

    @property
    def exposed(self) -> bool:
        return self.relevance >= 0.6


# ---------------------------------------------------------------- NVD

def nvd_vote(asset: dict, configurations: list[dict]) -> Vote | None:
    v = Version(asset["version"])
    seen_product = False
    for cfg in configurations or []:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m["criteria"].split(":")
                vendor, product, ver, upd = parts[3], parts[4], parts[5], parts[6]
                if not m.get("vulnerable") or not same_product(asset["vendor"], asset["product"], vendor, product):
                    continue
                seen_product = True
                exact = from_cpe(ver, upd)
                if exact is not None:
                    if Version(exact) == v:
                        return Vote("NVD", "affected", EXPLICIT, f"CPE {m['criteria']} matches {asset['version']}")
                    continue
                bounds = {k: m.get(k) for k in ("versionStartIncluding", "versionStartExcluding",
                                                 "versionEndIncluding", "versionEndExcluding")}
                if in_range(v, start_incl=bounds["versionStartIncluding"], start_excl=bounds["versionStartExcluding"],
                            end_incl=bounds["versionEndIncluding"], end_excl=bounds["versionEndExcluding"]):
                    shown = ", ".join(f"{k}={val}" for k, val in bounds.items() if val) or "all versions"
                    return Vote("NVD", "affected", EXPLICIT, f"{asset['version']} within NVD range ({shown})")
    if seen_product:
        return Vote("NVD", "not_affected", EXPLICIT, f"{asset['version']} not in any NVD vulnerable configuration")
    return None


# ---------------------------------------------------------------- CNA (CVE JSON 5)

def cna_vote(asset: dict, affected: list[dict]) -> Vote | None:
    v = Version(asset["version"])
    for entry in affected or []:
        if not same_product(asset["vendor"], asset["product"], entry.get("vendor", ""), entry.get("product", "")):
            continue
        for item in entry.get("versions", []):
            start, status = item.get("version", ""), item.get("status", "unknown")
            upper_excl, upper_incl = item.get("lessThan"), item.get("lessThanOrEqual")
            if upper_excl or upper_incl:
                start_incl = None if start in ("0", "*", "") else start
                hit = in_range(v, start_incl=start_incl, end_excl=upper_excl, end_incl=upper_incl)
                desc = f"{start or '0'} .. {'<' + upper_excl if upper_excl else '<=' + str(upper_incl)}"
            else:
                hit, desc = Version(start) == v, f"= {start}"
            if hit:
                verdict = "affected" if status == "affected" else "not_affected" if status == "unaffected" else "unknown"
                return Vote("CNA", verdict, EXPLICIT, f"{entry.get('vendor')} lists {desc} as {status}")
        default = entry.get("defaultStatus", "unknown")
        verdict = "affected" if default == "affected" else "not_affected" if default == "unaffected" else "unknown"
        return Vote("CNA", verdict, DEFAULT, f"not listed explicitly; CNA defaultStatus={default}")
    return None


# ---------------------------------------------------------------- description text

# Versions incl. vendor suffixes written with spaces: "8.0 Update 3", "2019 CU14", "7.5 SP2".
_V = r"(\d+(?:\.\d+)+(?:[A-Za-z]+\d+(?:\.\d+)*)?(?:-[\w.]+)?(?:\s+(?:Update|SP|Service Pack|CU|Cumulative Update|Patch|Build)\s*\d+)?)"
_NEGATION = re.compile(r"\b(does not|do not|doesn't|is not|are not|not)\s+(impact|affect|vulnerable)|unaffected", re.I)
_PATTERNS = [
    (re.compile(rf"\b(?:before|prior to|earlier than|below|lower than)\s+(?:version\s+)?{_V}", re.I), "lt"),
    (re.compile(rf"\b{_V}\s+(?:and|or)\s+(?:earlier|prior|below|lower|older)", re.I), "le"),
    (re.compile(rf"\b(?:through|up to and including|up to)\s+(?:version\s+)?{_V}", re.I), "le"),
]


# Ranges with a stated lower bound: "from 15.0 before 18.4.6", "18.5 before 18.5.4", "2.4.0 through 2.4.58",
# "versions 9.0 to 9.4". Each is [start, end) or [start, end] depending on the wording.
_RANGE = re.compile(
    rf"(?:\bfrom\s+(?:version\s+)?)?(?<![\w.-]){_V}\s+(?:(before|prior to|up to but not including)|"
    rf"(through|to|up to and including|until))\s+(?:version\s+)?{_V}", re.I)


def text_constraints(description: str) -> list[dict]:
    """Version bounds stated in prose, each with its sentence span and polarity. Bounded ranges are parsed first;
    a bare "before X" only counts where it is not the end of a range already captured."""
    out = []
    for sentence in re.split(r"(?<=[.;])\s+(?=[A-Z])", description):
        negated = bool(_NEGATION.search(sentence))
        polarity = "unaffected" if negated else "affected"
        taken: list[tuple[int, int]] = []
        for m in _RANGE.finditer(sentence):
            out.append({"op": "range", "start": m.group(1), "version": m.group(4),
                        "end_inclusive": m.group(3) is not None, "polarity": polarity, "span": sentence.strip()})
            taken.append(m.span())
        for rx, op in _PATTERNS:
            for m in rx.finditer(sentence):
                if any(a <= m.start() < b for a, b in taken):
                    continue
                out.append({"op": op, "version": m.group(1), "polarity": polarity, "span": sentence.strip()})
    return out


def _within(v: Version, c: dict) -> bool:
    if c["op"] == "range":
        end = Version(c["version"])
        return Version(c["start"]) <= v and (v <= end if c["end_inclusive"] else v < end)
    return v < Version(c["version"]) if c["op"] == "lt" else v <= Version(c["version"])


def _describe(c: dict) -> str:
    if c["op"] == "range":
        return f"{c['start']} {'through' if c['end_inclusive'] else 'before'} {c['version']}"
    return f"{'before' if c['op'] == 'lt' else 'up to'} {c['version']}"


def text_vote(asset: dict, description: str) -> Vote | None:
    v = Version(asset["version"])
    constraints = text_constraints(description)
    if not constraints:
        return None
    for c in (c for c in constraints if c["polarity"] == "unaffected"):
        if _within(v, c):
            return Vote("TEXT", "not_affected", EXPLICIT, f"text excludes {_describe(c)}", c["span"])
    affected = [c for c in constraints if c["polarity"] == "affected"]
    for c in affected:
        if _within(v, c):
            return Vote("TEXT", "affected", EXPLICIT, f"{asset['version']} is within {_describe(c)}", c["span"])
    if affected:
        return Vote("TEXT", "not_affected", EXPLICIT,
                    f"{asset['version']} is outside every stated range ({'; '.join(_describe(c) for c in affected)})",
                    affected[0]["span"])
    return None


# ---------------------------------------------------------------- reconciliation

def reconcile(asset: dict, cve: dict) -> Exposure:
    """`cve`: {"id", "description", "nvd_configurations", "cna_affected"}; `asset` has vendor/product/version."""
    votes = [vt for vt in (
        nvd_vote(asset, cve.get("nvd_configurations")),
        cna_vote(asset, cve.get("cna_affected")),
        text_vote(asset, cve.get("description", "")),
    ) if vt is not None]

    explicit_aff = any(x.verdict == "affected" and x.strength == EXPLICIT for x in votes)
    explicit_not = any(x.verdict == "not_affected" and x.strength == EXPLICIT for x in votes)
    if explicit_aff and explicit_not:
        status = "disputed"
    elif explicit_aff:
        status = "affected"
    elif explicit_not:
        status = "cleared"
    elif any(x.verdict == "affected" for x in votes):
        status = "probable"
    elif any(x.verdict == "not_affected" for x in votes):
        status = "cleared"
    else:
        status = "unknown"
    return Exposure(asset.get("id", ""), cve["id"], status, R_BY_STATUS[status], votes)
