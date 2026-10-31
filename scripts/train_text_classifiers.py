"""Standard-ML text classifiers for vulnerability descriptions (CPU, minutes to train):
  - CVSS v3.1 base-metric prediction (8 heads) -> severity for CVEs that NVD has not analysed
  - CWE root-cause mapping (top-1 / top-3)

Trained on NVD 2021-2025 (NVD primary or CNA secondary labels), evaluated on the same held-out 2026 CVE set
as scripts/eval_cti.py, so results compare directly against the local LLMs.

Usage: .venv/Scripts/python scripts/train_text_classifiers.py
Writes data/models/text_clf.joblib and docs/eval_text_clf_results.json.
"""

import gzip
import json
import re
import statistics
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.eval_cti import METRICS, cvss31_score, load_samples, parse_vector  # noqa: E402

NVD_DIR = ROOT / "data" / "raw" / "nvd"
TRAIN_YEARS = range(2021, 2026)
MIN_CWE_SUPPORT = 20


def pick_vector(metrics: dict) -> str | None:
    rows = metrics.get("cvssMetricV31", [])
    rows = sorted(rows, key=lambda m: m.get("type") != "Primary")  # NVD primary first, then CNA
    return rows[0]["cvssData"]["vectorString"] if rows else None


def pick_cwe(weaknesses: list) -> str | None:
    for kind in ("Primary", "Secondary"):
        cwes = [d["value"] for w in weaknesses if w.get("type") == kind
                for d in w["description"] if re.fullmatch(r"CWE-\d+", d["value"])]
        if len(cwes) == 1:
            return cwes[0]
    return None


def load_training() -> tuple[list[str], list[dict], list[str], list[str]]:
    texts, vectors, cwe_texts, cwes = [], [], [], []
    for year in TRAIN_YEARS:
        with gzip.open(NVD_DIR / f"nvdcve-2.0-{year}.json.gz", "rt", encoding="utf-8") as fh:
            vulns = json.load(fh)["vulnerabilities"]
        for item in vulns:
            cve = item["cve"]
            if cve.get("vulnStatus") == "Rejected":
                continue
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            if len(desc) < 40:
                continue
            vec = pick_vector(cve.get("metrics", {}))
            if vec:
                texts.append(desc)
                vectors.append(parse_vector(vec))
            cwe = pick_cwe(cve.get("weaknesses", []))
            if cwe:
                cwe_texts.append(desc)
                cwes.append(cwe)
        del vulns
        print(f"  loaded {year}: {len(texts)} with CVSS, {len(cwes)} with CWE", flush=True)
    return texts, vectors, cwe_texts, cwes


def main() -> int:
    started = time.time()
    texts, vectors, cwe_texts, cwes = load_training()

    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=300_000, sublinear_tf=True)
    X = vec.fit_transform(texts + cwe_texts)
    X_cvss, X_cwe = X[: len(texts)], X[len(texts):]

    heads = {}
    for m in METRICS:
        y = [v[m] for v in vectors]
        heads[m] = LogisticRegression(max_iter=2000, C=4.0, n_jobs=-1).fit(X_cvss, y)
        print(f"  trained CVSS head {m}", flush=True)

    counts: dict[str, int] = {}
    for c in cwes:
        counts[c] = counts.get(c, 0) + 1
    keep = [i for i, c in enumerate(cwes) if counts[c] >= MIN_CWE_SUPPORT]
    cwe_clf = LinearSVC(C=0.5).fit(X_cwe[keep], [cwes[i] for i in keep])
    print(f"  trained CWE model on {len(keep)} CVEs, {len(cwe_clf.classes_)} classes", flush=True)

    # Evaluate on the exact held-out 2026 set used for the LLMs.
    samples = load_samples(40)
    Xs = vec.transform([s["desc"] for s in samples])
    pred_metrics = {m: heads[m].predict(Xs) for m in METRICS}
    metric_hits = {m: 0 for m in METRICS}
    mads, top1, top3 = [], 0, 0
    scores = cwe_clf.decision_function(Xs)
    for i, s in enumerate(samples):
        truth = parse_vector(s["vector"])
        pred = {m: pred_metrics[m][i] for m in METRICS}
        for m in METRICS:
            metric_hits[m] += pred[m] == truth[m]
        mads.append(abs(cvss31_score(pred) - s["score"]))
        ranked = cwe_clf.classes_[np.argsort(-scores[i])]
        top1 += ranked[0] == s["cwe"]
        top3 += s["cwe"] in ranked[:3]

    n = len(samples)
    result = {
        "model": "TF-IDF + LogisticRegression/LinearSVC (CPU)",
        "n": n,
        "train_cvss": len(texts), "train_cwe": len(keep), "cwe_classes": len(cwe_clf.classes_),
        "rcm_acc_pct": round(100 * top1 / n, 1), "rcm_top3_pct": round(100 * top3 / n, 1),
        "vsp_mad": round(statistics.mean(mads), 2),
        "vsp_metric_acc_pct": {m: round(100 * h / n, 1) for m, h in metric_hits.items()},
        "train_seconds": round(time.time() - started, 1),
    }
    (ROOT / "docs" / "eval_text_clf_results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (ROOT / "data" / "models").mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": vec, "cvss_heads": heads, "cwe": cwe_clf}, ROOT / "data" / "models" / "text_clf.joblib")

    acc = result["vsp_metric_acc_pct"]
    print("\n| Model | RCM top-1 | RCM top-3 | VSP MAD | " + " | ".join(METRICS) + " |")
    print(f"| {result['model']} | {result['rcm_acc_pct']}% | {result['rcm_top3_pct']}% | {result['vsp_mad']} | "
          + " | ".join(f"{acc[m]:.0f}" for m in METRICS) + " |")
    print(f"trained in {result['train_seconds']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
