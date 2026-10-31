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
- **Hindi:** Foundation-Sec produced Cyrillic garbage. No security LLM supports Hindi or Marathi, so translation uses IndicTrans2.
- **Reasoning model:** Foundation-Sec-8B-Reasoning writes thorough analysis but takes about 112 s per narrative. Use it in batches for Critical alerts only.
- **Chat templates:** Hugging Face GGUF imports can arrive with a bare `{{ .Prompt }}` template. Always check with `ollama show`.

## Role assignment (config/models.json; one model per role, no fallbacks)

| Role | Model | Why |
|---|---|---|
| extract, classify, copilot, narrate | mist:8b | Best measured extraction and CWE among security models; fastest; Apache-2.0; Qwen3 template with tool support |
| reason (Critical-alert deep analysis) | foundation-sec:8b-reasoning | Security reasoning traces; free-text only |
| CWE / CVSS | TF-IDF classifiers; LLM adjudicates the top-3 CWE | Beat every LLM by a wide margin |
