"""Advisory intelligence: turn free-text advisories (CERT-In style, vendor bulletins, emails) into exposures.

Deterministic first, encoders second, LLM last (closed set):
  1. regex IOCs / CVE ids (defang-aware) - authoritative
  2. SecureBERT 2.0 NER (CPU) - malware, systems, organisations, indicators (context chips)
  3. product identity: alias match against our inventory catalogue; if not unique, the security LLM picks
     ONE id from the catalogue (or "none") via JSON-schema enum, and must quote an evidence span from the text
  4. version ranges from the text (engine.exposure.text_constraints), reconciled per asset
  5. severity from the CNA-free text via the TF-IDF CVSS classifiers; exploitation claims from the text
  6. glass-box assessment per exposed asset (engine.scoring.assess)
"""

from __future__ import annotations

import functools
import os
import re
import time

from ..engine import cvss
from ..engine.exposure import Exposure, reconcile, text_constraints
from ..engine.products import mentions
from ..engine.scoring import assess
from .guard import screen
from .llm import chat

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_IP = re.compile(r"\b(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+(?:\.|\[\.\]))+(?:example|com|in|net|org|xyz|top|info|online|site)\b", re.I)
_URL = re.compile(r"\bhxxps?://\S+|\bhttps?://\S+", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_ITW = re.compile(r"exploited in the wild|active exploitation|actively exploited|limited exploitation|being exploited",
                  re.I)
_SECTOR_WORDS = {
    "Power & Energy": re.compile(r"\b(energy|power|grid|electricity|utilit(y|ies)|oil|gas)\b", re.I),
    "BFSI": re.compile(r"\b(bank|banks|banking|financial|insurance|payments?|net-banking|upi)\b", re.I),
    "Telecom": re.compile(r"\b(telecom|telecommunications?|isp|mobile operators?)\b", re.I),
    "Transport": re.compile(r"\b(transport|rail(way)?s?|metro|ports?|airports?|aviation|shipping)\b", re.I),
    "Government": re.compile(r"\b(government|ministr(y|ies)|e-governance|public sector)\b", re.I),
    "Strategic & Public Enterprises": re.compile(r"\b(defen[cs]e|space|strategic|psu)\b", re.I),
}
_NER_STOP = {"the", "a", "an", "organisations", "organizations", "attacker", "attackers", "victims", "banks",
             "appliance", "targeted appliance", "privileges", "vulnerability", "vulnerabilities", "remote", "bypass",
             "multiple vulnerabilities", "network", "operator station"}


def defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]") if "[.]" not in s else s


@functools.lru_cache(maxsize=1)
def _ner():
    os.environ.setdefault("HF_HOME", r"D:\hf-cache")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    from transformers import pipeline
    return pipeline("token-classification", model="cisco-ai/SecureBERT2.0-NER", aggregation_strategy="first",
                    device=-1)


@functools.lru_cache(maxsize=1)
def _cvss_model():
    import joblib
    from pathlib import Path
    path = Path(__file__).resolve().parents[3] / "data" / "models" / "text_clf.joblib"
    return joblib.load(path) if path.exists() else None


def predict_cvss(text: str) -> str | None:
    model = _cvss_model()
    if not model:
        return None
    x = model["vectorizer"].transform([text])
    parts = {m: model["cvss_heads"][m].predict(x)[0] for m in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]}
    return "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in parts.items())


def entities(text: str) -> list[dict]:
    out, seen = [], set()
    for e in _ner()(text[:4000]):
        word = e["word"].strip(" .,;:()")
        if len(word) < 3 or word.lower() in _NER_STOP or float(e["score"]) < 0.6:
            continue
        if e["entity_group"] == "Indicator" and not re.search(r"\d|\[\.\]|\.[a-z]{2,}", word):
            continue  # keep indicators that look like IOCs; phrases like "crafted HTTP" are noise
        key = (e["entity_group"], word.lower())
        if key not in seen:
            seen.add(key)
            out.append({"type": e["entity_group"], "text": word, "score": round(float(e["score"]), 2)})
    return out


# Hyphen counts as part of a word, so "kyc-update[.]example" is not mistaken for the word "update".
_VERSION_WORDS = re.compile(r"(?<![\w\-\[\]])(?:version|versions|prior to|before|through|update|updates|upgrade|"
                            r"release|releases|patch|fixed in)(?![\w\-\[\]])", re.I)


def _is_version_context(text: str, start: int) -> bool:
    """True when a dotted quad sits in a clause about versions ('updates 22.8R2.5 or 25.1.3.0'), not an IOC."""
    window = text[max(0, start - 60):start]
    clause = re.split(r"[.;:]\s", window)[-1]  # only the current clause; dotted versions inside it are fine
    return bool(_VERSION_WORDS.search(clause))


# Vendors, CERTs and standards bodies: links to them in an advisory are references to read, never things to block.
_REFERENCE_DOMAINS = {
    "cisa.gov", "nist.gov", "mitre.org", "cve.org", "first.org", "cert-in.org.in", "github.com", "siemens.com",
    "microsoft.com", "cisco.com", "fortinet.com", "fortiguard.com", "paloaltonetworks.com", "ivanti.com", "citrix.com",
    "cloud.com", "atlassian.com", "oracle.com", "sap.com", "vmware.com", "broadcom.com", "apache.org", "gitlab.com",
    "postgresql.org", "openssh.com", "php.net", "adobe.com", "beyondtrust.com", "schneider-electric.com", "se.com",
    "swift.com", "temenos.com", "f5.com", "nginx.org", "kernel.org", "hitachienergy.com", "mitsubishielectric.com",
    "nciipc.gov.in", "meity.gov.in",
}
_ATTACK_CONTEXT = re.compile(r"\b(c2|command[- ]and[- ]control|malicious|attackers?|threat actors?|callbacks?|"
                             r"beacon(?:s|ed|ing)?|hosted on|download(?:ed|s)? from|phishing|lookalike|look-alike|"
                             r"exfiltrat\w*|payloads?|indicators?|iocs?|block(?:ed|list)?)\b", re.I)


def _registrable(host: str) -> str:
    parts = host.lower().replace("[.]", ".").strip(".").split(".")
    return ".".join(parts[-3:]) if parts[-2:] in (["org", "in"], ["gov", "in"], ["co", "in"]) else ".".join(parts[-2:])


def _is_indicator(text: str, start: int, raw: str) -> bool:
    """A URL or domain is an indicator only if the advisory defanged it, or it sits in an attack context and is not a
    vendor / CERT / standards reference."""
    if "[.]" in raw or raw.lower().startswith("hxxp"):
        return True
    host = re.sub(r"^[a-z]+://", "", raw, flags=re.I).split("/")[0]
    if _registrable(host) in _REFERENCE_DOMAINS:
        return False
    clause = re.split(r"[.;]\s", text[max(0, start - 120):start])[-1]
    return bool(_ATTACK_CONTEXT.search(clause))


def iocs(text: str) -> dict:
    # Version ranges (CISA's machine-readable "vers:intdot/<8.0.0.11") and comparators ("< 8.0.0.11") are not IPs.
    vers_spans = [m.span() for m in re.finditer(r"vers:\S+", text)]
    ips = {m.group(0) for m in _IP.finditer(text)
           if not _is_version_context(text, m.start())
           and not any(a <= m.start() < b for a, b in vers_spans)
           and not re.search(r"[<>=]\s*v?$", text[max(0, m.start() - 3):m.start()], re.I)}
    urls, references = [], set()
    for m in _URL.finditer(text):
        u = m.group(0).rstrip(").,")
        if _is_indicator(text, m.start(), u):
            urls.append(defang(u))
        else:
            references.add(re.sub(r"^hxxp", "http", u, flags=re.I))
    url_hosts = {re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].lower() for u in references}
    domains = set()
    for m in _DOMAIN.finditer(text):
        d = m.group(0)
        if d.lower() in url_hosts:
            continue  # the host of a reference link is not a separate indicator
        if _is_indicator(text, m.start(), d):
            domains.add(defang(d))
        elif _registrable(d) not in _REFERENCE_DOMAINS:
            continue  # a plain mention outside an attack context: neither indicator nor reference
    return {
        "cves": sorted(set(_CVE.findall(text))),
        "ips": sorted({defang(x) for x in ips}),
        "domains": sorted(domains),
        "urls": urls,
        "sha256": sorted(set(_SHA256.findall(text))),
        "references": sorted(references),
    }


def identify_product(text: str, catalog: list[dict], allow_llm: bool = True) -> dict:
    """Closed-set product identity. Deterministic alias match first; the LLM only breaks ties or finds
    products named indirectly, and must choose from the catalogue or 'none'."""
    hits = [c for c in catalog if mentions(c["vendor"], c["product"], text)]
    if len(hits) == 1:
        return {"id": hits[0]["id"], "label": hits[0]["label"], "method": "alias match (deterministic)", "evidence": None}
    if not allow_llm:
        return {"id": None, "label": None, "evidence": None,
                "method": "LLM step skipped: text blocked by the prompt-injection guard"}
    options = hits or catalog
    ids = [c["id"] for c in options] + ["none"]
    schema = {"type": "object", "properties": {
        "product_id": {"type": "string", "enum": ids},
        "evidence": {"type": "string"}}, "required": ["product_id", "evidence"]}
    listing = "\n".join(f"- {c['id']}: {c['label']}" for c in options)
    r = chat([{"role": "system", "content": "You map security advisories to an organisation's software inventory. "
                                            "Pick exactly one product id from the list, or 'none' if the advisory "
                                            "does not concern any listed product. Quote the exact words from the "
                                            "advisory that name the product as 'evidence'."},
              {"role": "user", "content": f"Inventory products:\n{listing}\n\nAdvisory:\n{text[:3000]}"}],
             role="extract", schema=schema, max_tokens=120, timeout=120)
    pick = (r.data or {}) if isinstance(r.data, dict) else {}
    pid, evidence = pick.get("product_id", "none"), pick.get("evidence", "")
    grounded = bool(evidence) and evidence.lower() in text.lower()
    if pid == "none" or pid not in {c["id"] for c in options} or not grounded:
        return {"id": None, "label": None, "method": "security LLM (closed set)" + ("" if grounded or pid == "none"
                                                                                     else " - rejected: ungrounded"),
                "evidence": evidence or None}
    chosen = next(c for c in options if c["id"] == pid)
    return {"id": pid, "label": chosen["label"], "method": "security LLM (closed set, evidence-grounded)",
            "evidence": evidence}


def catalog_from(assets: list[dict]) -> list[dict]:
    seen = {}
    for a in assets:
        seen.setdefault(a["product_key"], {"id": a["product_key"], "vendor": a["vendor"], "product": a["product"],
                                           "label": a["label"]})
    return sorted(seen.values(), key=lambda c: c["id"])


def analyse(adv: dict, assets: list[dict], orgs: dict[str, dict]) -> dict:
    started = time.perf_counter()
    text = adv["text"]
    timings = {}
    t = time.perf_counter(); found = iocs(text); timings["regex_ms"] = round(1000 * (time.perf_counter() - t))
    t = time.perf_counter(); guard = screen(text); timings["guard_ms"] = round(1000 * (time.perf_counter() - t))
    t = time.perf_counter(); ents = entities(text); timings["ner_ms"] = round(1000 * (time.perf_counter() - t))
    t = time.perf_counter(); product = identify_product(text, catalog_from(assets), guard["verdict"] != "blocked")
    timings["product_ms"] = round(1000 * (time.perf_counter() - t))
    constraints = [{k: c[k] for k in ("op", "version", "polarity") if k in c} | ({"start": c["start"]} if "start" in c else {})
                   for c in text_constraints(text)]
    vector = predict_cvss(text)
    itw = _ITW.search(text)
    vuln = {"id": adv["id"], "description": text, "ssvc": {}, "kev": None, "epss": None,
            "cvss_vector": vector, "cvss_source": "ML (TF-IDF, from advisory text)",
            "nvd_configurations": [], "cna_affected": []}
    exposures = []
    if product["id"]:
        for a in (x for x in assets if x["product_key"] == product["id"]):
            exp = reconcile(a, vuln)
            if not exp.votes:  # product named but no version evidence in the text
                exp = Exposure(a["id"], adv["id"], "unknown", 0.3, [])
            res = assess(vuln, a, orgs[a["org_id"]], exp)
            exposures.append({"asset_id": a["id"], "org_id": a["org_id"], "org": orgs[a["org_id"]]["name"],
                              "sector": orgs[a["org_id"]]["sector"], "hostname": a["hostname"], "version": a["version"],
                              "zone": a["zone"], "status": exp.status, "tier": res.tier, "risk": res.risk,
                              "deadline_hours": res.deadline_hours, "decision": res.decision,
                              "reason": exp.votes[0].reason if exp.votes else "no version stated"})
    exposures.sort(key=lambda e: (-e["risk"], e["org_id"]))
    sectors_targeted = sorted(sector for sector, rx in _SECTOR_WORDS.items() if rx.search(text))
    return {
        "id": adv["id"], "title": adv.get("title"), "provenance": adv.get("provenance", "USER"),
        "guard": guard, "iocs": found, "entities": ents, "product": product, "constraints": constraints,
        "predicted_cvss": {"vector": vector, "score": cvss.base_score(cvss.parse(vector)) if vector else None},
        "exploitation_claim": itw.group(0) if itw else None,
        "exposed": [e for e in exposures if e["status"] in ("affected", "disputed", "probable")],
        "cleared": [e for e in exposures if e["status"] == "cleared"],
        "unknown": [e for e in exposures if e["status"] == "unknown"],
        "sectors_targeted": sectors_targeted,
        "timings": {**timings, "total_ms": round(1000 * (time.perf_counter() - started))},
    }
