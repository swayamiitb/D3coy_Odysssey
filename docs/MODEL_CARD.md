# Model card: local AI for the D3COY early-warning system

All measurements below were taken on Sat 31 Oct 2026 on the demo laptop: RTX 4070 Laptop 8 GB, Ollama 0.40.13, all models Q4_K_M.

The test sets are **2026 CVEs only**. Those are newer than every model's training data, so no model can have memorised the answers. Ground truth comes from NVD (CPE, CWE, CVSS v3.1 primary). With n = 40, every percentage has roughly ±15 points of uncertainty.

## Product extraction (description → vendor/product JSON)

- **Matching:** strict, meaning compacted equality or rapidfuzz `token_sort_ratio ≥ 90`. The earlier lenient matcher (`token_set_ratio`/substring) overstated accuracy by 20–30 points.
- **Prompting:** the security models get 4 examples from before 2025 plus vendor/product normalisation.

| Model | Type | Product | Vendor | JSON valid | Median s/item | tok/s |
|---|---|---|---|---|---|---|
| **mist:8b** (dreamgroup/MiST-8B, 19 Oct 2026, Apache-2.0) | security | **77.5%** | 62.5% | 100% | **1.69** | 41.5 |
| foundation-sec:8b-reasoning (Cisco, Jan 2026) | security | 72.5% | 62.5% | 100% | 1.86 | 39.3 |
| foundation-sec:8b-instruct (Cisco 1.1, Nov 2025), few-shot | security | 65.0% | 65.0% | 100% | 3.21 | 44.3 |
| foundation-sec:8b-instruct, zero-shot | security | 40.0% | 62.5% | 100% | 3.83 | 44.7 |
| qwen3:8b (baseline only) | general | 65.0% | 65.0% | 100% | 2.83 | 41.1 |
| qwen3:4b (baseline only) | general | 45.0% | 45.0% | 100% | 2.03 | 71.6 |

### Fresh check: all 2026 CVEs in CISA KEV, graded against KEV's own vendor/product names

None of these CVEs were used to design prompts. Matching is strict. 95% Wilson intervals are in brackets.

| Model | Vendor | Product | Both | s/item |
|---|---|---|---|---|
| mist:8b | 79.9% (73.7–84.9) | 37.6% (31.1–44.6) | 28.4% | 1.86 |
| foundation-sec:8b-instruct | 77.3% (70.9–82.6) | 40.7% (34.1–47.8) | 35.1% | 1.55 |

The two models are **statistically tied**. Most product misses are about naming granularity, not comprehension:

| Model output | KEV name |
|---|---|
| "Endpoint Manager Mobile" | "Endpoint Manager Mobile (EPMM)" |
| "SMA1000" | "SMA1000 Appliances" |
| "Chrome" | "Chromium V8" |

**Design consequence:** product identity is decided by *closed-set selection*. The LLM chooses from our inventory catalogue (or "none"), and deterministic matching does the rest. Free-text product names are never trusted on their own.

## CTI tasks (CTIBench-style)

- **RCM:** description → CWE, scored on the top-1 exact ID.
- **VSP:** description → CVSS v3.1 vector, scored by base-score mean absolute deviation (lower is better).

| Model | RCM top-1 | VSP MAD | Notes |
|---|---|---|---|
| **TF-IDF + LinearSVC / LogReg** (trained on NVD 2021–2025, 7 min on CPU) | **77.5%** (top-3 **87.5%**) | **0.86** | Per-metric accuracy 80–98% |
| mist:8b | **62.5%** | 2.31 | Best LLM on CWE |
| foundation-sec:8b-instruct | 40.0% | 1.81 | |
| qwen3:8b (baseline) | 27.5% | 1.85 | |
| qwen3:4b (baseline) | 2.5% | 1.27 | |
| foundation-sec:8b-reasoning | 7.5% | 9.81 (invalid) | Its thinking step can't be turned off, and it breaks JSON-schema tasks |

## Qualitative findings

- **Hallucinations, both models:**
  - Foundation-Sec misstated a fixed version ("up to and including 25.1.3.0").
  - MiST added a CVSS score of 9.8 that the source never stated.

  So a validator must check every number and version against the facts before any narrative is shown.
- **Indic languages:** Foundation-Sec produced Cyrillic garbage for Hindi. No security LLM handles Indian languages, so the validated English brief is translated by IndicTrans2 (see below).
- **Reasoning model:** Foundation-Sec-8B-Reasoning writes thorough analysis but takes about 112 s per narrative. Use it in batches for Critical alerts only.
- **Chat templates:** Hugging Face GGUF imports can arrive with a bare `{{ .Prompt }}` template. Always check with `ollama show`.

## Role assignment (config/models.json; one model per role, no fallbacks)

| Role | Model | Why |
|---|---|---|
| extract, classify, narrate | mist:8b | Best measured extraction and CWE among security models; fastest; Apache-2.0; Qwen3 template with tool support |
| reason (Critical-alert deep analysis) | foundation-sec:8b-reasoning | Security reasoning traces; free-text only |
| CWE / CVSS | TF-IDF classifiers; LLM adjudicates the top-3 CWE | Beat every LLM by a wide margin |
| translate (22 scheduled Indian languages) | IndicTrans2 en-indic dist-200M (AI4Bharat, MIT), CPU | The only open model covering all 22; runs beside the GPU LLM |

## Indic translation: all 22 scheduled languages

Only the *validated* English brief is translated, so the translator can't add facts. Each sentence is shown only if:
- every protected identifier (CVE id, version list, hostname, IP, date, product, organisation) survives exactly;
- every Latin word in the output appears in the English source;
- the text is in the target script, with no letters from another script.

Otherwise the English line is shown with a "translation withheld" badge.

- **Placeholder format, measured** (`scripts/eval_placeholders.py`; 80 identifiers, 8 languages):
  - IndicTrans2's own `<IDn>`: 0/80 survive, because `>` is not in its vocabulary.
  - `XQZn`: 60/80.
  - Unprotected text: 14/80.

  Lists such as "A, B, or C" travel as one placeholder.
- **Script unification:** Brahmic languages come out in Devanagari and are transliterated by Unicode offset, with fixes for letters a script lacks.
- **Colons:** the model writes `:` as a visarga, which is restored.
- **Beam reranking:** the validator reranks the beam search's 4-best list, at no extra decoding cost.
- **Result** (`scripts/eval_indic.py`, `docs/eval_indic22.json`): **127/132 sentences validated (96.2%)**.
  - Test set: 6 identifier-heavy brief sentences per language, through the running service.
  - 19 of 22 languages: 6/6.
  - Bengali and Manipuri: 5/6.
  - Santali: 3/6. The model mixes Devanagari and Urdu words into Ol Chiki. These are withheld, not shown.
  - Speed: about 20–50 s per language on the CPU. Results are cached.

## Day-0 exploitation forecast (standard ML, CPU)

- **Question:** the day a CVE is published, will it be exploited in the wild?
- **Inputs:** only what is known that day:
  - the description (TF-IDF, 1–2 grams);
  - the CNA's CVSS metrics and CWE;
  - the vendor;
  - the vendor's and product's CISA KEV history, counted strictly *before* publication.
- **Never used**, because each arrives later and would leak the answer: KEV/`cisa*` fields, SSVC, EPSS, NVD reference tags.
- **Model:** logistic regression, C chosen on 2025, threshold chosen to maximise F2 on 2025 (`scripts/train_exploit_forecast.py`, `docs/eval_exploit_forecast.json`).
- **Jan–Jul 2026 test** (model trained on 2021–2025):
  - flags 4.4% of CVEs and catches 49.2% of later-KEV ones;
  - CVSS ≥ 9 at the same budget catches 25.8%;
  - median lead 5 days, 46% a week or more ahead;
  - ROC AUC 0.913.
- **Aug–Oct 2026 live period** (model frozen 31 Jul, never tuned since):
  - flags 2.0% and catches 61.1% (44/72);
  - CVSS ≥ 9 at the same budget catches 16.7%;
  - ROC AUC 0.926.
- **Calibrated:** forecast 26.7% → observed 26.7%.
- **Low precision (5%):** exploitation is rare (base rate 0.16%), so forecasts become *proposals* for an analyst.
- **Use:** it feeds the Bayesian decision model as its prior, P(attack) = p·P(attack | exploited) + (1−p)·P(attack | not exploited).

## Live detectors (CPU, run every 5 s by the live engine)

The live engine (`backend/app/live.py`) reads the national decoy grid and enterprise firewall flows (both simulated
and labelled SIM, accelerated so one 5-second tick is one sensor-hour) and runs three detectors on them.

| Detector | Method | Fires when |
|---|---|---|
| Scanning surge | robust z-score (median / MAD over the last 72 ticks) on sessions **and** unique sources per product, plus breadth | z(sessions) ≥ 4, z(sources) ≥ 3, ≥ 3 sensors each above 3× their own median |
| C2 beacon | RITA-style periodicity on (source, destination, port) flows | ≥ 30 connections with interval coefficient of variation ≤ 0.2 |
| Flow anomaly | IsolationForest (200 trees) on per-host hourly features: connections, destinations, internal destinations, ports, bytes; trained on ten sensor-days of ordinary traffic | score below the training 0.1% quantile **and** fan-out, ports or bytes ≥ 6 robust z above baseline. IsolationForest scores saturate beyond the training range, so the z-gate both separates an internal sweep from a busy host and names the reason. |

Measured on this laptop (test bench, attack-drill layer, private copy of the data):
- **240 sensor-hours of ordinary traffic:** 0 detections. A separate 720-tick run also gave 0.
- **Mass scanning drill:** surge caught within 1 tick.
- **Implant drill:** beacon caught within 1 tick; an incident case opens and the regulator report is proposed.
- **Full intrusion drill:** scan, implant and lateral movement caught in that order, within 6 ticks.

Response follows the same graduated autonomy as the pipeline. Evidence of compromise acts at once: notice, CERT-In
draft, hunt and SOC case. Sensor-only early warnings and regulator escalations are proposals for an analyst.
