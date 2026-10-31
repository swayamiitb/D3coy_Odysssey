"""Build normalised CVE records from the offline snapshot (CVE JSON 5 via Vulnrichment + NVD 2.0 feeds)."""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

RAW = Path(__file__).resolve().parents[3] / "data" / "raw"
NVD_FEEDS = ["nvdcve-2.0-modified.json.gz", "nvdcve-2.0-recent.json.gz", "nvdcve-2.0-2026.json.gz",
             "nvdcve-2.0-2025.json.gz", "nvdcve-2.0-2024.json.gz"]
_SSVC = re.compile(r'"(Exploitation|Automatable|Technical Impact)":\s*"([^"]+)"')


def load_nvd(ids: set[str]) -> dict[str, dict]:
    """NVD records for the given CVE ids, newest feed first (modified/recent win over yearly)."""
    found: dict[str, dict] = {}
    for name in NVD_FEEDS:
        path = RAW / "nvd" / name
        if not path.exists() or not ids - found.keys():
            continue
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for item in json.load(fh)["vulnerabilities"]:
                cid = item["cve"]["id"]
                if cid in ids and cid not in found:
                    found[cid] = item["cve"]
    return found


def load_cve5(cve_id: str) -> dict | None:
    path = RAW / "vulnrichment" / f"{cve_id}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def load_kev() -> dict[str, dict]:
    data = json.loads((RAW / "kev.json").read_text(encoding="utf-8"))
    return {v["cveID"]: v for v in data["vulnerabilities"]}


def load_epss() -> tuple[dict[str, float], str]:
    """EPSS scores keyed by CVE, plus the model/score-date header line."""
    scores, header = {}, ""
    with gzip.open(RAW / "epss_scores-current.csv.gz", "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#"):
                header = line.strip("#\n ")
                continue
            if line.startswith("cve,"):
                continue
            cve, epss, _ = line.rstrip("\n").split(",")
            scores[cve] = float(epss)
    return scores, header


def _cvss_vector(cve5: dict | None, nvd: dict | None) -> tuple[str | None, str | None]:
    """Prefer the CNA's own vector, then CISA ADP, then NVD primary."""
    containers = (cve5 or {}).get("containers", {})
    for source, blocks in (("CNA", [containers.get("cna", {})]), ("CISA_ADP", containers.get("adp", []))):
        for block in blocks:
            for metric in block.get("metrics", []):
                for key in ("cvssV3_1", "cvssV3_0"):
                    if key in metric and metric[key].get("vectorString"):
                        return metric[key]["vectorString"], source
    for metric in (nvd or {}).get("metrics", {}).get("cvssMetricV31", []):
        return metric["cvssData"]["vectorString"], "NVD" if metric.get("type") == "Primary" else "CNA"
    return None, None


def build_record(cve_id: str, nvd: dict | None = None, kev: dict | None = None,
                 epss: float | None = None) -> dict:
    cve5 = load_cve5(cve_id)
    cna = (cve5 or {}).get("containers", {}).get("cna", {})
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    if not desc and nvd:
        desc = next((d["value"] for d in nvd.get("descriptions", []) if d["lang"] == "en"), "")
    ssvc = dict(_SSVC.findall(json.dumps((cve5 or {}).get("containers", {}).get("adp", []))))
    vector, vector_source = _cvss_vector(cve5, nvd)
    return {
        "id": cve_id,
        "description": desc,
        "published": (cve5 or {}).get("cveMetadata", {}).get("datePublished") or (nvd or {}).get("published"),
        "cna_affected": cna.get("affected", []),
        "nvd_configurations": (nvd or {}).get("configurations", []),
        "nvd_status": (nvd or {}).get("vulnStatus"),
        "ssvc": ssvc,
        "kev": kev,
        "epss": epss,
        "cvss_vector": vector,
        "cvss_source": vector_source,
    }
