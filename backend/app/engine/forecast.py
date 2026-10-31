"""Day-0 exploitation forecast: the moment a CVE is published, how likely is it to be exploited in the wild, and
how soon? This is what lets Odyssey warn *before* CISA confirms exploitation instead of after.

Only information available on the publication day is used, so the forecast can be backtested honestly:
  - the description text, the CNA's CVSS vector and CWE, and the vendor/product named;
  - the vendor's and product's exploitation history, counting only KEV listings dated *before* publication.
Never used (they arrive later and would leak the answer): KEV/cisa* fields, CISA SSVC, NVD reference tags, EPSS.

Model: TF-IDF + one-hot + history features -> logistic regression (standard ML, CPU, about a minute to train).
Trained by scripts/train_exploit_forecast.py on NVD 2021-2024, tuned on 2025, tested on Jan-Jul 2026.
"""

from __future__ import annotations

import bisect
import datetime as dt
import math
import re
from collections import Counter
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parents[3] / "data" / "models" / "exploit_forecast.joblib"
CVSS_KEYS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def norm(name: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def day0_fields(cve: dict) -> dict:
    """The publication-day view of an NVD 2.0 `cve` object."""
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    vendors = Counter()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    parts = m["criteria"].split(":")
                    vendors[(parts[3], parts[4])] += 1
    if not vendors:  # NVD has not analysed it yet: use the CNA's own affected[] block
        for block in cve.get("affected", []):
            for a in block.get("affectedData", []):
                if a.get("vendor") and a["vendor"].lower() != "n/a":
                    vendors[(a["vendor"], a.get("product", ""))] += 1
    vendor, product = vendors.most_common(1)[0][0] if vendors else ("", "")
    metrics = cve.get("metrics", {})
    rows = metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", [])
    rows = sorted(rows, key=lambda m: m.get("type") == "Primary")  # the CNA's score exists on day 0; NVD's later
    vector = rows[0]["cvssData"]["vectorString"] if rows else None
    cwes = [d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
            if re.fullmatch(r"CWE-\d+", d["value"])]
    return {"id": cve["id"], "published": cve.get("published", "")[:10], "description": desc,
            "vendor": norm(vendor), "product": norm(product), "vector": vector, "cwe": cwes[0] if cwes else "none"}


class History:
    """KEV listings per vendor and per product, as sorted dates, for 'known exploited before day X' features."""

    def __init__(self, kev: dict[str, dict], keys: dict[str, tuple[str, str]]):
        self.vendor: dict[str, list[str]] = {}
        self.product: dict[str, list[str]] = {}
        self.lag: dict[str, list[int]] = {}  # vendor -> days from publication to KEV listing
        self.listed = {cid: k["dateAdded"] for cid, k in kev.items()}
        for cid, k in kev.items():
            v, p = keys.get(cid) or (norm(k["vendorProject"]), norm(k["product"]))
            self.vendor.setdefault(v, []).append(k["dateAdded"])
            self.product.setdefault(f"{v}/{p}", []).append(k["dateAdded"])
        for d in (self.vendor, self.product):
            for v in d.values():
                v.sort()

    def set_lags(self, kev: dict[str, dict], published: dict[str, str], keys: dict[str, tuple[str, str]]) -> None:
        for cid, k in kev.items():
            if cid in published and cid in keys and published[cid]:
                lag = (dt.date.fromisoformat(k["dateAdded"]) - dt.date.fromisoformat(published[cid])).days
                if 0 <= lag <= 730:
                    self.lag.setdefault(keys[cid][0], []).append(lag)

    def counts(self, f: dict) -> dict:
        if not f["published"] or not f["vendor"]:
            return {"vendor_kev": 0, "vendor_kev_365": 0, "product_kev": 0, "vendor_recency": 0.0}
        day = f["published"]
        year_ago = (dt.date.fromisoformat(day) - dt.timedelta(days=365)).isoformat()
        vd = self.vendor.get(f["vendor"], [])
        pd = self.product.get(f"{f['vendor']}/{f['product']}", [])
        n_v, n_p = bisect.bisect_left(vd, day), bisect.bisect_left(pd, day)
        own = self.listed.get(f["id"])
        if own and own < day:  # never let a CVE's own (pre-publication) listing count as history
            n_v, n_p = max(n_v - (own in vd), 0), max(n_p - (own in pd), 0)
        last = (dt.date.fromisoformat(day) - dt.date.fromisoformat(vd[n_v - 1])).days if n_v else 3650
        return {"vendor_kev": n_v, "vendor_kev_365": n_v - min(bisect.bisect_left(vd, year_ago), n_v),
                "product_kev": n_p, "vendor_recency": math.exp(-last / 180)}


def featurise(f: dict, h: History) -> dict:
    """Categorical + numeric features as a dict (DictVectorizer input); text is vectorised separately."""
    x: dict = {}
    parts = dict(p.split(":", 1) for p in (f["vector"] or "").split("/")[1:] if ":" in p)
    for k in CVSS_KEYS:
        x[f"cvss_{k}={parts.get(k, 'missing')}"] = 1
    x[f"cwe={f['cwe']}"] = 1
    x[f"vendor={f['vendor'] or 'unknown'}"] = 1
    c = h.counts(f)
    x["log_vendor_kev"] = math.log1p(c["vendor_kev"])
    x["log_vendor_kev_365"] = math.log1p(c["vendor_kev_365"])
    x["log_product_kev"] = math.log1p(c["product_kev"])
    x["vendor_recency"] = c["vendor_recency"]
    x["vendor_ever_exploited"] = float(c["vendor_kev"] > 0)
    return x


_MODEL: dict = {}


def load() -> dict | None:
    if "m" not in _MODEL:
        import joblib
        _MODEL["m"] = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None
    return _MODEL["m"]


def predict(fields: list[dict]) -> list[dict]:
    """Forecast for publication-day fields: probability of exploitation, the flag at the operating threshold,
    the vendor's historical time-to-exploitation, and the strongest reasons (largest positive contributions)."""
    m = load()
    if m is None or not fields:
        return [{} for _ in fields]
    import scipy.sparse as sp
    h = m["history"]
    X = sp.hstack([m["tfidf"].transform([f["description"] for f in fields]),
                   m["dv"].transform([featurise(f, h) for f in fields])]).tocsr()
    p = m["clf"].predict_proba(X)[:, 1]
    coef = m["clf"].coef_[0]
    names = m["names"]
    out = []
    for i, f in enumerate(fields):
        row = X.getrow(i)
        contrib = sorted(((coef[j] * v, names[j]) for j, v in zip(row.indices, row.data) if coef[j] * v > 0),
                         reverse=True)[:4]
        lags = h.lag.get(f["vendor"], [])
        out.append({"p": round(float(p[i]), 4), "flag": bool(p[i] >= m["threshold"]), "threshold": m["threshold"],
                    "vendor_kev_before": h.counts(f)["vendor_kev"],
                    "median_days_to_exploit": sorted(lags)[len(lags) // 2] if lags else None,
                    "lag_n": len(lags), "reasons": [_explain(n) for _, n in contrib]})
    return out


def _explain(name: str) -> str:
    if name.startswith("log_vendor_kev_365"):
        return "vendor exploited in the last year"
    if name.startswith("log_vendor_kev") or name == "vendor_ever_exploited":
        return "vendor has a KEV history"
    if name == "log_product_kev":
        return "this product was exploited before"
    if name == "vendor_recency":
        return "vendor exploited recently"
    if name.startswith("cvss_"):
        k, v = name[5:].split("=")
        return {"AV=N": "network attack vector", "PR=N": "no privileges required", "UI=N": "no user interaction",
                "AC=L": "low attack complexity", "S=C": "scope change"}.get(f"{k}={v}", f"CVSS {k}:{v}")
    if name.startswith("cwe="):
        return name[4:]
    if name.startswith("vendor="):
        return f"vendor {name[7:]}"
    return f"text: \"{name}\""
