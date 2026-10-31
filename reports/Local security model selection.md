# One GPU Seat Shapes a Twelve-Model Stack

The best fit for D3COY PS-01 on this laptop is **twelve models across nineteen roles**. The hardware, not preference, sets that number. Only one 8B model fits in 6.9 GiB, so **Foundation-Sec-1.1-8B-Instruct** holds the single resident GPU seat for extraction, narration and copilot planning. **Foundation-Sec-8B-Reasoning** gets a batch-only seat for closed-set CWE and ATT&CK adjudication, and keeps it only if it beats the classifiers in a paired test. Four security encoders run on the CPU: SecureModernBERT-NER, the SecureBERT 2.0 bi-encoder and cross-encoder, and CIRCL's expert-labelled ATT&CK classifier. Six standard ML components complete the set: our TF-IDF CWE classifier, our TF-IDF CVSS classifier, IndicTrans2, LightGBM, IsolationForest and HDBSCAN. Five deterministic engines need no weights at all. Of the 32 generative security repos of 8B or fewer that we catalogued, only three survive the filters for defensive, licensed, deployable models that work on CTI text. **MiST-8B** (19 Oct 2026, Apache-2.0) is the one credible challenger for the resident seat.

Local tests on 2026 CVEs force four changes to the case-study blueprint:

- **Extraction:** few-shot prompting lifted Foundation-Sec's product accuracy from 65% to **87.5% (95% CI 74–95)**, which provisionally clears the extraction gate.
- **CWE:** our 7-minute TF-IDF model beat every LLM (**77.5% vs 40%**, with non-overlapping intervals), so CWE moves to standard ML.
- **CVSS:** the same TF-IDF approach beat every LLM on CVSS vectors (mean absolute deviation **0.86 vs 1.27–1.85**), so CVSS estimation moves too.
- **ATT&CK:** CVE-LMTune's ATT&CK labels behaved like taxonomy echoes in a spot check, so CIRCL takes ATT&CK.

Inspecting the live Ollama imports also exposed template defects that would have invalidated the pending bake-off. **Ollama forces MiST into thinking mode on every turn.** That is the same defect that makes qwen3:4b leak its reasoning. Ollama also **drops the Reasoning model's `<think>` prefill, its default system prompt and its stop tokens**. This report gives corrected Modelfiles and a paired protocol, about three hours on 200 CVEs from July to October 2026, that settles every remaining seat.

## Three of 32 small security LLMs survive the filters

The census covers every security-specialised generative model of 8B or fewer that the Hugging Face API returned on 31 October 2026. That came from 40 keyword searches, 7 tag filters and more than 30 organisation listings, 3,948 unique repos in all ([HF API search](https://huggingface.co/api/models?search=cybersecurity&limit=200)). That produced 32 catalogued candidates, plus a long tail of about a dozen single-author fine-tunes with thin model cards and no recognised benchmarks. Each candidate then had to pass five filters. It must suit CTI text rather than source code or Kali command generation. It must be defensive, because the event disqualifies any hacking. It must carry a declared open licence. It must have a Q4_K_M GGUF of 5 GB or less with a known chat template. And its publisher must have evaluated it at least once. Almost every published number is self-reported, and independent re-runs disagree by up to 15 points. Cisco reports CTI-MCQ 0.644 for Foundation-Sec-8B-Instruct; a third party measured 0.4996 ([CyberSecQwen-4B card](https://huggingface.co/athena129/CyberSecQwen-4B)). The ranking therefore weights local measurements first, then third-party numbers, then self-reports.

| Rank | Model (≤8B) | Verdict for D3COY | Decisive evidence |
|---|---|---|---|
| 1 | [Foundation-Sec-1.1-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct) | **Resident seat** (extract, narrate, copilot) | Local: 87.5% product match with 4-shot prompting, 100% valid JSON, 44 tok/s. Official Q4_K_M GGUF. Context raised from 4k to 64k. IFEval 0.815, HarmBench 94.74% (self-reported) |
| 2 | [MiST-8B](https://huggingface.co/dreamgroup/MiST-8B) | **Challenger** for the resident seat | Best ≤8B result in the only single-protocol table: mean 61.7, against 53.5 for Foundation-Sec-8B (run by MiST's own authors). IFEval 88.5. Apache-2.0. Community GGUF only; 12 days old |
| 3 | [Foundation-Sec-8B-Reasoning](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning) | **Batch seat** (adjudicate), conditional | Self-reported CTI-RCM 0.753 and VSP 0.856. SFT plus RLVR. Official Q4_K_M GGUF. Long reasoning traces |
| 4 | [RedSage-Qwen3-8B-DPO / Ins](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins) | Excluded | No licence declared; offensive and Kali skill set. The DPO model self-reports CTI-MCQ 70.84; MiST's re-run gave 62.0 |
| 5 | [Llama-Primus-Merged](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged) | Excluded | Feb 2025. Its only distinguishing score is function calling (BFCL 74.77), and the copilot does not use tools. Third-party CTI-MCQ 54.7 |
| 6 | [Llama-Primus-Reasoning](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning) | Excluded | Feb 2025; community GGUF only; CISSP-style chain-of-thought score only |
| 7 | [exploitintel/cve-cwe-qwen3-8b](https://huggingface.co/exploitintel/cve-cwe-qwen3-8b) | Excluded | A CWE-only LLM that would take the GPU seat for a task the CPU classifier already does better. EM 0.676 on its own split |
| 8 | [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) (1.0) | Superseded by 1.1 | No official Q4_K_M; Q8_0 is 8.54 GB, which does not fit |
| 9 | [Gemma4Defense-2B](https://huggingface.co/athena129/Gemma4Defense-2B) / [CyberSecQwen-4B](https://huggingface.co/athena129/CyberSecQwen-4B) | Excluded | Hackathon entries trained at 4,096 tokens; the 4B template rewrites the system role as user |
| 10 | [Cyber-Prime-1.2](https://huggingface.co/Akahsizrr/Cyber-Prime-1.2) (2.6B) | Excluded | Single author; self-reported CyNER F1 0.687; LFM2 support in Ollama unverified |
| 11 | [cyber-analyst-4B](https://huggingface.co/BrainboxAI/cyber-analyst-4B) | Excluded | About 45% Hebrew training data; no benchmarks |
| 12 | [Tini-Cybersec-8B-A1B](https://huggingface.co/iselabvn/Tini-Cybersec-8B-A1B) | Excluded | 8.47B total parameters, over the 8B line; training mix distilled from proprietary models |
| 13 | [SecGPT-7B](https://huggingface.co/clouditera/SecGPT-7B) | Excluded | Chinese-language model |
| 14 | [Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) (base) | Excluded | No chat template; few-shot completion only |

The other 18 catalogued repos fail on orientation, domain or age, and naming them matters for judges. Several are offensive or dual-use by their own cards. DeepHat and WhiteRabbitNeo say they serve "offensive and defensive cybersecurity", and WhiteRabbitNeo tells users how to seed a reply to get past refusals. BaronLLM is "fine-tuned for offensive cybersecurity research". alias3-micro ships a "refusal-direction projection for authorised de-refusal" ([WhiteRabbitNeo card](https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B); [BaronLLM card](https://huggingface.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF); [alias3-micro card](https://huggingface.co/aliasrobotics/alias3-micro-1026)). Every abliterated, "heretic" or "uncensored" variant is excluded on the same grounds. That includes two Foundation-Sec derivatives. VulnLLM-R, Antares and djini work on source code, not advisories. Antares is also gated and says it "does not explain vulnerabilities" ([antares-1b card](https://huggingface.co/fdtn-ai/antares-1b)). Lily and ZySec are January 2024 Mistral-era models; Lily scored a third-party CTI-MCQ of 42.1 ([MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B)). CyberPal 2.0 describes a 4B–20B family, but only the 20B model is public ([cyber-pal-security org](https://huggingface.co/cyber-pal-security)). None of the 32 claims Hindi or Marathi support.

### About 75 encoder and classifier repos yield four seats and four challengers

The census of small models found about 75 encoder, classifier and time-series repos. For each role the strongest candidate is the one with the most honest evaluation, not the highest number, because every headline F1 is self-reported on the publisher's own split.

| Role | Seated | Runner-up (tested in bake-off) | Rejected, and why |
|---|---|---|---|
| NER | [attack-vector/SecureModernBERT-NER](https://huggingface.co/attack-vector/SecureModernBERT-NER): 22 entity types, MIT, 396M; zero false positives in the local spot check | [cisco-ai/SecureBERT2.0-NER](https://huggingface.co/cisco-ai/SecureBERT2.0-NER): 5 coarse types, Apache-2.0, 150M; about three false positives, missed APT29, no actor class | [CyNER-2.0](https://huggingface.co/PranavaKailash/CyNER-2.0-DeBERTa-v3-base) (third place); CyberPeace and pzryathzsdhc NER (inherit OpenRAIL-M restrictions); AI4Sec CyNER (pickle weights, empty README) |
| Embedding | [cisco-ai/SecureBERT2.0-biencoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder): mAP 0.951, against 0.912 for MiniLM | none | ATTACK-BERT (pickle, short sentences only); CIRCL bi-encoder (GPL-3.0); general embedders fail rule (a) |
| Rerank | [cisco-ai/SecureBERT2.0-cross_encoder](https://huggingface.co/cisco-ai/SecureBERT2.0-cross_encoder): the only security reranker | none | — |
| ATT&CK | [CIRCL/vulnerability-attack-technique-classification-roberta-base](https://huggingface.co/CIRCL/vulnerability-attack-technique-classification-roberta-base): expert CTID labels, recall@5 0.644, CC-BY-4.0 | [Sana9/securebert-vuln2attack-flat](https://huggingface.co/Sana9/securebert-vuln2attack-flat) (CVE-LMTune): micro-F1 0.8168, but on labels that appear derived from the taxonomy | TTPXHunter (no label map); MITRE TRAM (no hosted weights found) |
| CWE | Our TF-IDF + LinearSVC: **77.5% top-1 locally** | [xamxte/cwe-classifier-roberta-base](https://huggingface.co/xamxte/cwe-classifier-roberta-base): 75.6% top-1 on CTI-Bench, an external test | Sana9 vuln2cwe (macro-F1 0.0992); CIRCL cwe-parent (accuracy 0.568) |
| CVSS vector | Our TF-IDF + 8 logistic-regression heads: **MAD 0.86 locally** | [AXONVERTEX cve-cvss-vector-modernbert-base](https://huggingface.co/AXONVERTEX-AI-RESEARCH/cve-cvss-vector-modernbert-base): 31.3% exact vector, MAE 1.02 on 2026 CVEs; needs custom code | [CIRCL VLAI](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base): 4-band severity only, so it cannot supply the C/I/A metrics the formula needs |
| Not seated | — | — | Covered under "Exactly twelve" below: urlbert-tiny phishing, Reynier DGA, sumitp76 exploitability, Chronos-2, Cisco TSM, TimesFM 3.0, C2Sentinel |

## Local 2026 tests move four seats and narrow a fifth

The case study assumed Foundation-Sec would extract at 65% and that CVE-LMTune encoders would handle CWE and ATT&CK. The new measurements on 40 CVEs from 2026, newer than every model's training data, revise both assumptions. The intervals below are 95% Wilson intervals at n = 40.

| Task (n = 40) | Best LLM (rule-a eligible) | Best non-LLM | Reading |
|---|---|---|---|
| Product match vs NVD CPE | Foundation-Sec-1.1, 4-shot + normalisation: **87.5% (74–95)** | — (qwen3:8b reference: 95%, 84–99) | The gap to qwen3:8b is no longer significant; the intervals overlap |
| Vendor match | Foundation-Sec-1.1: 77.5% (62–88) | — | Unchanged from zero-shot |
| CWE top-1 | Foundation-Sec: 40% (26–55) | TF-IDF + LinearSVC: **77.5% (62–88)**; top-3 87.5% | A real gap; the intervals do not overlap |
| CVSS base-score MAD | 1.27–1.85 (all LLMs) | TF-IDF: **0.86** | The classifier is about twice as accurate |
| CVSS Integrity / Privileges Required accuracy | Foundation-Sec: 12.5% / 32.5% | TF-IDF: 80% / 85% | LLM per-metric accuracy is unusable |

Sources: [local few-shot bake-off](../docs/bakeoff_results_fewshot4.json); [local classifier eval](../docs/eval_text_clf_results.json); [local LLM CTI eval](../docs/eval_cti_results_round1.json).

**Few-shot prompting closes most of the extraction gap, so the extract seat passes its gate provisionally.** The case study's gate requires the extraction interval to clear 65%. The lower bound is now **73.9%**. The four worked examples are pre-2025 CVEs, so they cannot leak the 2026 test set ([bakeoff.py](../scripts/bakeoff.py)). The prompt was refined against the same 40 CVEs across two runs, though, so 87.5% is an optimistic estimate. The gate must be re-run on the fresh 200-CVE set before it counts. The case study's other extraction mode, closed-set selection among CPE candidates, is still untested. It could add more on top.

**Classifiers beat every LLM on CWE and CVSS, so both tasks move to standard ML under rule (c).** Our TF-IDF model trained on 136,834 NVD CVEs from 2021–2025 in 415 seconds and covers 231 CWE classes ([local classifier eval](../docs/eval_text_clf_results.json)). It is also the only CWE model whose accuracy has been measured on post-training 2026 CVEs. Its rivals give less reason for confidence. CVE-LMTune's CWE model reports a macro-F1 of just **0.0992** ([Sana9 vuln2cwe](https://huggingface.co/Sana9/securebert-vuln2cwe-flat)). xamxte's 75.6% on CTI-Bench is the best external number among the encoders ([xamxte card](https://huggingface.co/xamxte/cwe-classifier-roberta-base)), so it is the challenger. Rule (d) favours the TF-IDF model for a second reason: it **retrains in seven minutes** on that day's NVD and CNA labels, which no frozen encoder can do. CVSS follows the same logic. The scoring formula's impact term needs the C, I and A metrics, and TF-IDF predicts them at 82.5%, 80% and 90%. Foundation-Sec manages 47.5%, 12.5% and 25%. The case study's rules stay in force: a CNA or ADP vector always wins, and the estimate is shown as "AI estimate, pending NVD".

**CIRCL's expert labels beat CVE-LMTune's taxonomy echoes for ATT&CK.** We gave CVE-LMTune's ATT&CK model a generic buffer-overflow RCE description, the example from its own card. Its top five were Steal Web Session Cookie and four Access Token Manipulation variants, all scored 0.83–0.89. It returned no exploitation technique at all. That pattern fits labels inherited mechanically through a CWE→CAPEC→ATT&CK chain built from CVE2CAPEC and NVD data ([CVE-LMTune repo](https://github.com/terranovafr/CVE-LMTune)). CIRCL's classifier scores lower, with recall@5 of 0.644 over 53 parent techniques. But it learns from the CTID's expert CVE-to-ATT&CK mappings and publishes honest metrics ([CIRCL metrics.json](https://huggingface.co/CIRCL/vulnerability-attack-technique-classification-roberta-base/raw/main/metrics.json)). The CTID lookup still runs first for KEV CVEs, as the case study specified.

**SecureModernBERT-NER's richer schema outweighs Cisco's provenance.** SecureModernBERT-NER emits THREAT-ACTOR, CAMPAIGN, SECTOR, PRODUCT and TOOL directly, among 22 types ([card](https://huggingface.co/attack-vector/SecureModernBERT-NER)). Those are exactly the fields the correlation graph and campaign clustering consume. SecureBERT 2.0's NER has five coarse classes and no actor class. In the local spot check it tagged "exploited" and "European" as indicators and missed APT29. SecureModernBERT missed the CVE ID and the IPv4 address, but the case study's regex layer extracts those deterministically anyway. The price is speed: about 2.5 times slower, roughly 2.4 s of CPU time for a 2,000-token advisory.

**The reasoning seat narrows to closed-set adjudication.** With TF-IDF top-3 at 87.5% and top-1 at 77.5%, choosing among the top three candidates can add at most **ten points** of CWE accuracy. That ceiling is small enough that the seat must earn its 5 GB download and its GPU swaps in a paired test. The case study also gave this seat SSVC drafts. Those are dropped. The SSVC tree already takes deterministic proxies for Automatable and Technical Impact, and LLMs asked for SSVC decision points "over-predict risk" and reach at best fair agreement ([arXiv 2510.18508](https://arxiv.org/abs/2510.18508)).

| Case-study assignment | This report | Why |
|---|---|---|
| `ner`: SecureBERT 2.0 NER | **SecureModernBERT-NER** | 22 vs 5 types; actor/campaign/sector classes; fewer false positives |
| `map_attack`: CVE-LMTune vuln2attack + PKEV | **CIRCL ATT&CK classifier** + PKEV | Expert labels; CVE-LMTune's top five were implausible for RCE |
| `map_cwe`: CVE-LMTune vuln2cwe | **TF-IDF + LinearSVC** (standard ML); CNA CWE first | 77.5% vs 40% locally; CVE-LMTune macro-F1 0.099 |
| CVSS for vector-less CVEs: optional CIRCL VLAI | **`estimate_cvss`: TF-IDF, 8 heads** | MAD 0.86; the formula needs C/I/A, which VLAI cannot give |
| `reason`: CWE adjudication + SSVC drafts | **`adjudicate`**: closed-set CWE/ATT&CK only; conditional seat | 10-point ceiling; LLM SSVC over-prediction |
| `extract` gate open | **Provisionally passed** | Lower bound 73.9% > 65% at n = 40 |
| `classify` role and `qwen3-embedding` in [config/models.json](../config/models.json) | **Removed** | Vulnerability type derives from the CWE group; rule (a) |
| extract / narrate / copilot on Foundation-Sec-1.1; SecureBERT 2.0 embed and rerank; IndicTrans2; LightGBM; deterministic engines | **Unchanged** | Consistent with the evidence |

## Twelve models fill nineteen roles around one GPU seat

Each role gets exactly one component (rule b). Generative and encoder seats meet rule (a). Standard ML seats are separate pipeline components under rule (c). The three GGUF files were checked against the hashes Hugging Face publishes. Each local Ollama blob's SHA-256 matches the LFS object id in its repo tree, so the files on disk are byte-identical to the vendor releases ([FS-1.1 tree](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF/tree/main); [Reasoning tree](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF/tree/main); [MiST GGUF tree](https://huggingface.co/mradermacher/MiST-8B-GGUF/tree/main)).

| # | Role(s) | Component | HF repo id → file | Licence | Size | Placement |
|---|---|---|---|---|---|---|
| 1 | `extract`, `narrate`, `copilot` | Foundation-Sec-1.1-8B-Instruct Q4_K_M | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` → `foundation-sec-1.1-8b-instruct-q4_k_m.gguf` (sha256 `5813d725b38f0da1…`) | "other": Llama 3.1 Community Licence + Apache-2.0 for Cisco's changes ([NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/main/NOTICE.md)) | 4,920,780,160 B; 8.03B params | GPU, resident, `keep_alive -1` |
| 2 | `adjudicate` (conditional) | Foundation-Sec-8B-Reasoning Q4_K_M | `fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF` → `foundation-sec-8b-reasoning-q4_k_m.gguf` (sha256 `7a61e41b1ca1b339…`) | "other" (same structure) | 4,920,851,232 B; 8.03B | GPU, batch window only, `keep_alive 0` |
| 3 | `ner` | SecureModernBERT-NER | `attack-vector/SecureModernBERT-NER` → `model.safetensors` | MIT | 395.9M; 1.58 GB fp32 | CPU |
| 4 | `embed` | SecureBERT 2.0 bi-encoder | `cisco-ai/SecureBERT2.0-biencoder` | Apache-2.0 | 149.0M; 768-d; 1,024 tokens | CPU |
| 5 | `rerank` | SecureBERT 2.0 cross-encoder | `cisco-ai/SecureBERT2.0-cross_encoder` (underscore; the card's hyphenated id is wrong) | Apache-2.0 | 149.6M | CPU |
| 6 | `map_attack` | CIRCL ATT&CK classifier, after the CTID PKEV lookup | `CIRCL/vulnerability-attack-technique-classification-roberta-base` | CC-BY-4.0 | 124.7M; 53 labels | CPU |
| 7 | `map_cwe` | TF-IDF (1–2-grams, 300k features) + LinearSVC, after CNA CWE | local, [train_text_classifiers.py](../scripts/train_text_classifiers.py) | own code (scikit-learn BSD-3) | 231 classes; ≈0.6 GB RAM (231 × 300k float64, my arithmetic) | CPU |
| 8 | `estimate_cvss` | TF-IDF + 8 logistic-regression heads, only when no CNA/ADP vector exists | local, same script | own code | ≈50 MB | CPU |
| 9 | `translate` | IndicTrans2 en→Indic, distilled | `ai4bharat/indictrans2-en-indic-dist-200M` → `model.safetensors` | MIT; gated (auto-approve); custom modelling code ([HF API](https://huggingface.co/api/models/ai4bharat/indictrans2-en-indic-dist-200M)) | 274.6M F32; ≈1.1 GB | CPU |
| 10 | `predict_exploit` | LightGBM + isotonic calibration + TreeSHAP | local | MIT (LightGBM) | small | CPU |
| 11 | `detect_anomaly` | IsolationForest per host-hour | local (scikit-learn) | BSD-3 | small | CPU |
| 12 | `cluster_campaign` | HDBSCAN over SecureBERT vectors + IDF-weighted IOC Jaccard | local (scikit-learn) | BSD-3 | small | CPU |
| — | `extract_ioc`, `match_exposure`, `detect_surge`, `detect_beacon`, `decide`/`score` | Regex IOC extraction; version-range reconciler; robust z-score; RITA-style beacon scoring; SSVC tree + E·I·R·K formula | none | own code | none | CPU |

### Exactly twelve, because VRAM and evidence leave no other number

The count follows from three constraints, not from a target.

**First, the GPU has exactly one 8B seat.** Two Q4_K_M 8B models need about 9.8 GiB against 6.9 GiB free, so they cannot co-reside. Ollama's rule is that "new models must be able to completely fit in VRAM to allow concurrent model loads" ([Ollama FAQ](https://docs.ollama.com/faq)). The demo's core story, a new advisory arriving and becoming an alert, runs extraction live and then streams the narrative. So extraction, narration and copilot planning must share one model, or the judges watch a 2–6 s model swap on stage.

**Second, a batch-only second LLM is worth its cost only where it measurably beats the CPU components.** That is why `adjudicate` is the one conditional seat.

**Third, every structured task gets its own CPU component**, because the local tests show LLMs losing badly to classifiers on structured outputs. The remaining roles have no credible pretrained model. The census found no evaluated small model for logs, network traffic or C2, so those engines are deterministic.

The bake-off can only **lower** the count, never raise it. Every gate either confirms a seat or deletes its role, and rule (b) forbids substitutes. If Reasoning fails its gate, the role is deleted, or it moves to the resident model if that model does the job. Either way the count falls to eleven. If the cross-encoder adds less than three points of candidate recall, it goes too, leaving ten. If MiST wins the resident seat, or xamxte or AXONVERTEX wins a classifier seat, the count stays at twelve with different members.

The models left out were left out for specific reasons. urlbert-tiny-v4 and the DGA detector report about 99% accuracy, but on random splits of old public lists. Nothing in the scoring path consumes them. Lookalike `gov.in` domains are better caught deterministically ([urlbert card](https://huggingface.co/CrabInHoney/urlbert-tiny-v4-phishing-classifier)). sumitp76's exploitability model runs downloaded code and samples negatives from random NVD CVEs, which flatters its ROC-AUC. The forecasting models have no consumer yet. Among them, TimesFM 3.0 carries a non-commercial licence, and Cisco's TSM requires Python 3.11 ([TimesFM 3.0](https://huggingface.co/google/timesfm-3.0-pytorch); [cisco-tsm on PyPI](https://pypi.org/pypi/cisco-tsm/json)). CIRCL's severity model is excluded because the formula needs C/I/A metrics, and a severity band cannot supply them.

### The VRAM and CPU budgets leave about 1.5 GiB of GPU headroom

One figure here is measured; the rest are projected. With MiST loaded at Ollama's default 4,096-token context, `/api/ps` reported **4.76 GiB in VRAM, 100% on GPU**. nvidia-smi showed **5,851 MiB used and 2,098 MiB free** of 8,188 MiB (local reading, 31 Oct 2026). The other rows are my projections from the published GGUF sizes and the KV-cache arithmetic for each model's layer and attention-head counts. q8_0 KV halves the cache with "a very small loss in precision" ([Ollama FAQ](https://docs.ollama.com/faq)).

| Item | Foundation-Sec (Llama-3.1 arch: 32 layers, 8 KV heads) | MiST-8B (Qwen3 arch: 36 layers, 8 KV heads) |
|---|---|---|
| Free before load | 6.9 GiB | 6.9 GiB |
| Weights (GGUF file) | 4.58 GiB | 4.68 GiB |
| KV cache at 8K, f16 / q8_0 | 1.00 / 0.53 GiB | 1.13 / 0.60 GiB |
| Measured total at 4K | — | 4.76 GiB (`size_vram`) |
| Projected total at 8K, q8_0 | ≈5.0–5.3 GiB | ≈5.1–5.4 GiB |
| Headroom at 8K | ≈1.6–1.9 GiB | ≈1.5–1.8 GiB |
| Second 8B model co-resident | No (≈9.8 GiB needed) | No |

Q5_K_M would fit at 8K with almost no margin. Cisco publishes only Q4_K_M and Q8_0, though, and the official file's provenance is worth more than the roughly 3% perplexity that Q4_K_M costs on Llama-3.1-8B ([fedric95 PPL table](https://huggingface.co/fedric95/Meta-Llama-3.1-8B-GGUF)). Everything else runs on the CPU, so no encoder competes for the GPU seat.

| CPU component | RAM | Latency on this i9-14900HX (measured unless marked) |
|---|---|---|
| SecureModernBERT-NER | 1.58 GB | 105 ms per sentence; 607 ms per ~500 tokens; ≈2.4 s per 2,000-token advisory |
| SecureBERT 2.0 bi-encoder | ≈0.6 GB | 132 ms short; 326 ms per ~600-token document; 53 ms each in a batch of 16 |
| SecureBERT 2.0 cross-encoder | ≈0.6 GB | ≈25–50 ms per pair (estimate) |
| CIRCL ATT&CK (RoBERTa-base) | ≈0.5 GB | 16–23 ms short; 147–182 ms at 450–512 tokens (measured on same-architecture models) |
| TF-IDF CWE + CVSS | ≈0.65 GB | under 10 ms (estimate) |
| IndicTrans2 | ≈1.1 GB | unmeasured |
| LightGBM, IsolationForest, HDBSCAN | under 0.2 GB | milliseconds |
| Torch runtime + Ollama host-side mapping | ≈1 GB + up to ≈5 GB page cache | — |
| **Total** | **≈11 GB of 32 GB** | ≈1–1.5 s of CPU per CVE, against 3.2 s of GPU |

The pipeline is GPU-bound. About 560 CVEs a day cost roughly 30 GPU-minutes at the measured 3.2 s per item. The CPU passes overlap with that work. The vendor prefilter against the inventory cuts it to minutes.

### The registry makes every seat a config change

Rule (d) is met by making the registry the only place a model is named. Each role entry stores the runtime reference, the weight digest, the template digest, the per-role options, the contract schema and the gate file. Swapping a seat is then a config edit followed by a gate re-run. Every output is stamped with the entry's digests, so any alert can be replayed exactly. Below is a minimal shape for the next version of [config/models.json](../config/models.json). It merges today's separate `roles` and `ml_components` blocks.

```json
{
  "registry_version": "2026-10-31.2",
  "runtime": {"ollama": "0.40.13", "models_dir": "D:\\ollama\\models"},
  "roles": {
    "extract":  {"kind": "llm", "ref": "fsec-1.1-instruct:8b-q4km", "gguf_sha256": "5813d725b38f0da1...",
                 "placement": "gpu-resident", "options": {"temperature": 0, "seed": 42, "repeat_penalty": 1.0, "num_predict": 512},
                 "format": "schemas/extract.v2.json", "gate": "gates/extract.yaml"},
    "narrate":  {"kind": "llm", "ref": "fsec-1.1-instruct:8b-q4km", "options": {"temperature": 0.3, "repeat_penalty": 1.05, "num_predict": 400},
                 "stream": true, "validator": "validators/narrative_facts.py", "gate": "gates/narrate.yaml"},
    "adjudicate": {"kind": "llm", "ref": "fsec-reasoning:8b-q4km", "gguf_sha256": "7a61e41b1ca1b339...",
                 "placement": "gpu-batch", "keep_alive": 0, "parse": "after_think_close", "gate": "gates/adjudicate.yaml"},
    "map_cwe":  {"kind": "sklearn", "ref": "artifacts/tfidf_cwe_2021-2026H1.joblib", "sha256": "...",
                 "precedence": ["cna_cwe", "nvd_cwe", "model"], "retrain": "nightly", "gate": "gates/map_cwe.yaml"},
    "map_attack": {"kind": "hf-encoder", "ref": "CIRCL/vulnerability-attack-technique-classification-roberta-base",
                 "revision": "<pinned sha>", "precedence": ["ctid_pkev", "model"], "top_k": 5, "gate": "gates/map_attack.yaml"}
  }
}
```

Rename the current alias `foundation-sec:8b-instruct` while you do this. It actually points to the 1.1 weights, and the name invites a 1.0/1.1 mix-up in the audit trail.

## The live imports carry three template defects

Running `ollama show` and `/api/show` on the imported models turned up problems that the bake-off would otherwise have measured as model quality.

**MiST was mapped to the wrong Qwen3 template.** Ollama 0.40.13 matched MiST's GGUF to a Go template whose generation prompt always ends `<|im_start|>assistant\n<think>\n`, whatever the `think` setting. That is byte-for-byte the tail of the local `qwen3:4b` template. It explains why qwen3:4b leaks reasoning with `think=false`. The `qwen3:8b` template, by contrast, emits an empty `<think>\n\n</think>` block when thinking is off. MiST's own Jinja template is the hybrid one: it adds `<think>\n\n</think>\n\n` only when `enable_thinking` is false ([MiST chat_template.jinja](https://huggingface.co/dreamgroup/MiST-8B/blob/main/chat_template.jinja)). Tested as imported, MiST would think before every JSON answer. It would also hit the bug class where Ollama waits for `</think>` before it applies the JSON grammar ([ollama #14645](https://github.com/ollama/ollama/issues/14645)). Ollama also gave it Qwen3's thinking-mode sampling defaults (temperature 0.6, top-k 20, top-p 0.95). MiST's own generation_config sets no sampling at all, only EOS ids [151645, 151643] and 2,048 maximum new tokens ([MiST generation_config](https://huggingface.co/dreamgroup/MiST-8B/blob/main/generation_config.json)).

**The Reasoning import loses three things its official template provides.** Ollama rendered the template from the GGUF (`template_source: gguf_chat_template`) as a generic `<|role|>` loop. That loop has no stop tokens, no default system prompt, and a generation prompt of plain `<|assistant|>\n`. The official template differs on all three. It injects a long "Metis" system prompt when the caller gives none. It closes each past assistant turn with `\n<|end_of_text|>`. And it opens generation with `\n<|assistant|>\n<think>` ([Reasoning tokenizer_config](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/tokenizer_config.json)). Its generation_config sets EOS ids [128001, 128009], temperature 0.6, top-p 0.95 and repetition penalty 1.1 ([generation_config](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/generation_config.json)).

**The Foundation-Sec-1.1 alias is correct as built.** Its Go template reproduces the official Jinja exactly. A system turn is `<|system|>\n…\n` and a user turn is `<|user|>\n…\n`. A past assistant turn is `<|assistant|>\n…<|end_of_text|>\n`, and generation opens with `<|assistant|>\n` ([FS-1.1 chat_template.jinja](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct/blob/main/chat_template.jinja)). All three GGUFs set the BOS flag as the official tokenizers expect: Llama-architecture files add BOS automatically, MiST adds none. So no template below writes a BOS token itself.

The imports also landed on different runners. Ollama reports `runner: ggml` for the Reasoning import and `runner: llamacpp` for MiST. Since grammar behaviour has differed between Ollama's paths and llama.cpp ([ollama #15502](https://github.com/ollama/ollama/issues/15502)), the registry should record each seat's runner, and the JSON tests must run on that runner.

Server environment (set once as user variables, then restart Ollama). `MAX_LOADED_MODELS=1` is right now that embeddings run on the CPU: Ollama hosts only LLMs, and only one fits.

```powershell
[Environment]::SetEnvironmentVariable("OLLAMA_FLASH_ATTENTION", "1",    "User")
[Environment]::SetEnvironmentVariable("OLLAMA_KV_CACHE_TYPE",   "q8_0", "User")   # global; needs flash attention
[Environment]::SetEnvironmentVariable("OLLAMA_CONTEXT_LENGTH",  "8192", "User")   # default is 4096 on <24 GiB GPUs
[Environment]::SetEnvironmentVariable("OLLAMA_MAX_LOADED_MODELS","1",   "User")
[Environment]::SetEnvironmentVariable("OLLAMA_NUM_PARALLEL",    "1",    "User")
[Environment]::SetEnvironmentVariable("OLLAMA_KEEP_ALIVE",      "30m",  "User")
[Environment]::SetEnvironmentVariable("OLLAMA_MODELS",          "D:\ollama\models", "User")
```

### Foundation-Sec-1.1-8B-Instruct (resident seat)

```
# fsec-1.1-instruct.Modelfile  ->  ollama create fsec-1.1-instruct:8b-q4km -f fsec-1.1-instruct.Modelfile
FROM hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:latest
TEMPLATE """{{- range .Messages }}{{- if eq .Role "system" }}<|system|>
{{ .Content }}
{{ else if eq .Role "user" }}<|user|>
{{ .Content }}
{{ else if eq .Role "assistant" }}<|assistant|>
{{ .Content }}<|end_of_text|>
{{ end }}{{- end }}<|assistant|>
"""
PARAMETER stop "<|end_of_text|>"
PARAMETER stop "<|user|>"
PARAMETER stop "<|system|>"
PARAMETER num_ctx 8192
PARAMETER temperature 0
PARAMETER seed 42
PARAMETER repeat_penalty 1.0
PARAMETER num_predict 512
```

These defaults suit extraction. Ollama's built-in Modelfile default is temperature 0.8 ([Modelfile doc](https://docs.ollama.com/modelfile)), so the explicit zero matters. Narration overrides per request: temperature 0.3, repeat_penalty 1.05, num_predict 400, streamed, no `format`. Extraction and copilot plans pass the JSON schema in `format` and also paste it into the prompt, as the Ollama docs recommend ([structured outputs](https://docs.ollama.com/capabilities/structured-outputs)). The template has no `.Tools` and no thinking block, so Ollama lists the model as `completion` only. That is why the JSON grammar engages from the first token, consistent with the measured 100% JSON validity.

### Foundation-Sec-8B-Reasoning (batch seat)

```
# fsec-reasoning.Modelfile  ->  ollama create fsec-reasoning:8b-q4km -f fsec-reasoning.Modelfile
FROM hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:latest
SYSTEM """You are Metis, a cybersecurity reasoning model from the Minerva family developed by Foundation AI at Cisco. You specialize in security analysis, threat intelligence, and strategic reasoning in cybersecurity contexts. You were released in November 2025.

The user is a cybersecurity professional trying to accomplish some cybersecurity task. You must help them accomplish their tasks in the most efficient and safe manner possible. You must respond in a fashion that is direct, accurate, relevant, and helpful.

You have professional knowledge and experience of a senior-level cybersecurity specialist. For tasks relating to cyber threat intelligence (CTI), make sure that the identifiers are absolutely correct. The validity of the identifiers for common vulnerability enumerations (CVEs), common weakness enumerations (CWEs), other techniques, tactics, and procedures identifiers (TTPs), and advanced persistent threat classifications (APT) is of paramount importance.

For tasks relating to cloud security, it's important to be precise in the response as well. These questions will often ask you to consider, verify, or produce cloud configuration settings in various formats (such as JSON, Terraform, XML, etc.). Make sure these are absolutely correct before providing them to the user. Cite sources, especially from relevant cloud providers' documentation, and explain your logic thoroughly.

In the rare case when the user asks a harmful or unsafe question, especially pertaining to generating malware or ransomware, make sure to politely but firmly refuse. If the user asks questions not directly related to cybersecurity, you must also politely refuse the query and explain that you are only knowledgeable in cybersecurity."""
TEMPLATE """{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 }}
{{- if eq .Role "system" }}
<|system|>
{{ .Content }}
{{- else if eq .Role "user" }}
<|user|>
{{ .Content }}
{{- else if eq .Role "assistant" }}
<|assistant|>
{{ .Content }}
<|end_of_text|>
{{- end }}
{{- if and $last (ne .Role "assistant") }}
<|assistant|>
<think>
{{- end }}
{{- end }}"""
PARAMETER stop "<|end_of_text|>"
PARAMETER stop "<|eot_id|>"
PARAMETER stop "<|user|>"
PARAMETER stop "<|system|>"
PARAMETER temperature 0.6
PARAMETER top_p 0.95
PARAMETER repeat_penalty 1.1
PARAMETER num_ctx 8192
PARAMETER num_predict 2048
```

The leading newlines are deliberate. The official template renders `BOS` + `\n<|system|>\n…` + `\n<|user|>\n…` + `\n<|assistant|>\n<think>`, and the Go whitespace trims above reproduce that sequence. Put the adjudication task in the **user** turn and leave the Metis system prompt in place, since the model was presumably RL-trained under it (an inference; Cisco does not say). Do not pass `format` to this model, because a grammar would constrain the reasoning trace too. Instead, ask for a final line `ANSWER: <candidate id>`, split the output on `</think>`, parse that line with a regex, and reject any answer that is not among the candidates. Because the template never references `.Thinking`, Ollama should list the alias as `completion` only and return the trace inside `content`. Confirm this with `/api/show` after creating the alias; if `thinking` still appears, call it with `think: true` and read `message.thinking`.

### MiST-8B (challenger; two aliases, one model)

```
# mist-nothink.Modelfile  ->  ollama create mist:8b-q4km-nothink -f mist-nothink.Modelfile
FROM hf.co/mradermacher/MiST-8B-GGUF:Q4_K_M
TEMPLATE """{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 }}
{{- if eq .Role "system" }}<|im_start|>system
{{ .Content }}<|im_end|>
{{ else if eq .Role "user" }}<|im_start|>user
{{ .Content }}<|im_end|>
{{ else if eq .Role "assistant" }}<|im_start|>assistant
{{ .Content }}<|im_end|>
{{ end }}
{{- if and $last (ne .Role "assistant") }}<|im_start|>assistant
<think>

</think>

{{ end }}
{{- end }}"""
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
PARAMETER stop "<|im_start|>"
PARAMETER num_ctx 8192
PARAMETER temperature 0
PARAMETER seed 42
PARAMETER repeat_penalty 1.0
PARAMETER num_predict 512
```

```
# mist-think.Modelfile  ->  ollama create mist:8b-q4km-think -f mist-think.Modelfile   (adjudicate test only)
FROM hf.co/mradermacher/MiST-8B-GGUF:Q4_K_M
TEMPLATE """{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 }}
{{- if eq .Role "system" }}<|im_start|>system
{{ .Content }}<|im_end|>
{{ else if eq .Role "user" }}<|im_start|>user
{{ .Content }}<|im_end|>
{{ else if eq .Role "assistant" }}<|im_start|>assistant
{{ .Content }}<|im_end|>
{{ end }}
{{- if and $last (ne .Role "assistant") }}<|im_start|>assistant
{{ end }}
{{- end }}"""
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
PARAMETER stop "<|im_start|>"
PARAMETER num_ctx 8192
PARAMETER temperature 0.6
PARAMETER top_p 0.95
PARAMETER top_k 20
PARAMETER repeat_penalty 1.0
PARAMETER num_predict 2048
```

Parameters not restated are inherited from the parent import, which for MiST means top_k 20 and top_p 0.95. Run `ollama show --modelfile` after each `create` to confirm that the stop list and parameters are what you expect. The non-thinking alias reproduces MiST's Jinja with `enable_thinking=false`. The thinking alias reproduces it with `enable_thinking` undefined, which leaves the model free to open its own `<think>` block. Its sampling values are the Qwen3 defaults Ollama applied, because MiST publishes none. Both aliases share one GGUF digest, so they count as one model under rule (b). Neither declares tools, because MiST's card says tool use "has not been specifically trained or evaluated" ([MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B)).

One test proves each template right before any bake-off number is trusted. Render the same two-turn conversation with the official Jinja template, using `apply_chat_template(..., add_generation_prompt=True)` and stripping the leading BOS for the Llama files. Send that string through `/api/generate` with `raw: true`. Then send the same messages through `/api/chat`. At temperature 0 and seed 42, the outputs must be byte-identical on three prompts. Any difference means the Go template has drifted from the official one.

## A three-hour paired bake-off settles every open seat

The protocol runs every candidate on the same items, so each comparison is paired and small differences can be tested. Every set below avoids the training windows of the models under test. The cut-offs are CVE-LMTune's data update on 17 June 2026, xamxte's release on 15 March 2026, AXONVERTEX's pre-July-2025 training CVEs, and Foundation-Sec's stated data cut-off of 10 April 2025 ([Reasoning card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning)). MiST's cut-off is unpublished. Its paper was submitted on 16 September 2026, so October 2026 CVEs are reported as a separate slice ([arXiv 2609.18496](https://arxiv.org/abs/2609.18496)).

| Set | Content | Size | Ground truth |
|---|---|---|---|
| T-CVE | CVEs published 1 Jul–31 Oct 2026, stratified by vendor frequency (top 50 vs long tail), CNA and description length. Disjoint from the 40-CVE development set and the few-shot examples | 200 | CNA `affected[]`, plus NVD CPE where the CVE is Analyzed; CNA/NVD CWE; CNA/ADP/NVD CVSS 3.1 |
| T-NAR | Facts JSON from the pipeline, including the three Ivanti CVEs | 30 × 2 runs | The facts JSON itself |
| T-COP | Analyst questions with gold query plans, plus planted prompt injections | 30 + 5 | Gold plans |
| T-ADJ | T-CVE items with the classifier's top-3 CWE candidates | 100 | CWE truth |
| T-ATT | CTID-mapped CVEs held out from CIRCL's training (its 118-item test split, if the IDs are published) | ≈118 | CTID mappings |
| T-NER | Advisories hand-labelled for actor, malware, tool, product, organisation, sector and campaign | 12 | Manual labels |
| T-REF | Advisories that describe exploit mechanics in detail | 20 | Should never be refused |

| LLM role | Candidates (alias) | Primary metric | Hard gate (failing any one makes the model ineligible) |
|---|---|---|---|
| `extract` | fsec-1.1 and mist-nothink, each in mode A (4-shot + normalisation) and mode B (closed-set CPE candidates); fsec-reasoning in mode B on 30 items | Product exact match (paired) | JSON valid ≥ 99%; Wilson lower bound > 65%; zero IDs outside the candidate set after validation; p50 latency ≤ 5 s; at most 1 of 20 T-REF refusals |
| `narrate` | fsec-1.1, mist-nothink; fsec-reasoning on 10 items | Validator pass rate (share not withheld) | Zero unsupported CVEs, versions or numbers in any shown text (the validator enforces this); English only; time to first token ≤ 2 s streamed |
| `copilot` | fsec-1.1, mist-nothink | Intent exact match and slot F1 | Plan schema valid ≥ 95%; all 5 injections leave the plan unchanged |
| `adjudicate` | fsec-reasoning, mist-think (50 items), and the resident-seat winner | Adjudicated CWE top-1 against the classifier's own top-1 (McNemar) | Answer ∈ candidates for 100% of parsed outputs; p95 ≤ 60 s |

Every LLM run also records tokens per second, Ollama's `load_duration`, peak VRAM from nvidia-smi, the runner, and the rate of hallucinated IDs, as the case study requires.

**Rule D1: the resident seat.** A candidate is eligible only if it passes every hard gate for `extract`, `narrate` and `copilot`. Among eligible models, the one with higher product accuracy wins if McNemar's p < 0.05. Otherwise the seat is decided in this order: narrative pass rate, then extraction p95 latency, then official vendor GGUF over community GGUF, then Apache-2.0 over the Llama-derived "other" licence. The live roles are never split across two models, for the swap reason given above. One hypothesis is worth stating before the run. MiST shares its base model with qwen3:8b, which scored 95% on extraction. If MiST's security mid-training preserved that strength, MiST takes the seat, and with it a cleaner licence.

**Rule D2: the adjudicate seat.** Foundation-Sec-8B-Reasoning keeps the seat only if it does both of two things at McNemar p < 0.05. It must beat the classifier's own top-1, and it must beat the resident model doing the same adjudication. If only the resident model beats the classifier, the role moves to the resident model and the second LLM is dropped. If no model beats the classifier, the role is deleted.

**Rule D3: classifier seats.** The challenger takes a seat only if its primary metric beats the incumbent's at p < 0.05 after Holm correction. Otherwise the incumbent holds: TF-IDF for CWE and CVSS, CIRCL for ATT&CK and SecureModernBERT for NER. For the TF-IDF models, being retrainable and transparent is the deciding advantage when the metrics are close.

**Rule D4: the rerank seat.** The cross-encoder stays only if reranking raises mode-B CPE candidate recall@5 by at least three points over bi-encoder ranking alone.

| Task | Candidates | Primary metric | Secondary metrics and controls |
|---|---|---|---|
| CWE | TF-IDF + LinearSVC retrained on 2021 → 30 Jun 2026; xamxte (load `cwe_label_map.json`); Sana9 vuln2cwe; CIRCL cwe-parent | Exact top-1 | Top-3; parent-level top-1 via CWE ChildOf, so CIRCL's 303 parent classes compare fairly; label-space coverage; wrap LinearSVC in `CalibratedClassifierCV` for displayable confidence |
| CVSS | TF-IDF, 8 heads (retrained); AXONVERTEX (pinned revision, `cvss_predictor.py` read before running, run with `python -I` from its own folder); CIRCL VLAI (band only) | Base-score MAD (paired bootstrap) | Error in the impact subscore, which is the input I that the formula uses; per-metric accuracy; exact vector; band accuracy; per-metric Brier score |
| ATT&CK | CIRCL classifier; Sana9 vuln2attack collapsed to parent techniques; TF-IDF one-vs-rest LR trained on CIRCL's training split | Parent-level recall@5 | Micro-F1 at 0.5. Plausibility probe on 20 RCE and injection CVEs: share of the top five that fall in Initial Access, Execution or Privilege Escalation. Sana9's training covers almost every CVE, so its T-ATT score is flagged as leaked |
| NER | SecureModernBERT (`first` aggregation); SecureBERT2.0-NER (`first`); CyNER-2.0 (`simple`) | Strict span F1 for actor, malware, tool, product and organisation | Per-type F1; CPU time per 2,000-token advisory; regex merge applied to all three |

Each system is reported with a Wilson interval. Binary per-item outcomes use McNemar's exact test, and deviation metrics use 10,000 paired bootstrap resamples. At n = 200, an accuracy near 87.5% carries an interval of about **±4.6 points**. A paired difference smaller than about 6–8 points will not separate at 80% power. Any smaller gap counts as a tie and goes to the tie-breaks.

| Phase | Hardware | Work | Estimated time |
|---|---|---|---|
| 0 | GPU | Create the four aliases; run template-equivalence and `/api/show` capability checks | 15 min |
| 1 | CPU, in parallel with phases 2–4 | Retrain TF-IDF to 30 Jun 2026; run 4 CWE, 3 CVSS, 3 ATT&CK and 3 NER candidates | 40 min |
| 2 | GPU: fsec-1.1 | `extract` A+B (400 calls at 3.2 s), `narrate` 60, `copilot` 35, `adjudicate` 100 | ≈36 min |
| 3 | GPU: mist-nothink, then mist-think | The same set, plus `adjudicate` on 50 items with thinking | ≈55 min |
| 4 | GPU: fsec-reasoning | `adjudicate` 100, `extract` B 30, `narrate` 10 (assumes traces of ~1,100 tokens) | ≈60 min |
| 5 | CPU | Statistics, decision rules D1–D4, registry update, gate files | 15 min |

The GPU phases total about three hours and run unattended in model-grouped order, with `keep_alive: 0` between models. If time runs short before the 1 PM deadline, a one-and-a-half-hour fast lane is available: drop T-CVE to 100 items and skip mist-think. It loses some statistical power but no decision rule.

## Risks and claims we could not verify

**The largest risk is that the good extraction number is partly an artefact.** The 87.5% came from a prompt tuned over two rounds on the same 40 CVEs, and its interval runs from 74% to 95%. On fresh data it could land near the 65% gate. If it fails, the case study's fallback-free answer applies: the deterministic matcher carries products alone, and the LLM narrates. **Self-reported benchmarks are unreliable for choosing.** Cisco reports CTI-RCM 0.694 for Foundation-Sec-1.1 ([card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct)), against 40% CWE accuracy locally. MiST's 61.7 mean comes from its authors running every rival themselves. **MiST carries specific uncertainties.** It is twelve days old. Its card claims an EMNLP paper that the arXiv page does not list. "Dream" is not identified as an organisation. Its GGUF is a community conversion, and its training-data cut-off is unknown.

**The environment holds two traps.** The project venv runs **Python 3.15.2**, and scikit-learn already works there, since the TF-IDF models trained in it. But the encoder timings were measured on Python 3.12.7 with torch 2.11.0+cpu, and torch, LightGBM and IndicTrans2's custom code were not verified on 3.15. If any of them lacks a wheel, run the CPU encoder service from a uv-managed 3.12 venv behind localhost. That keeps the pipeline unchanged. **IndicTrans2** is gated, ships its own modelling and tokenizer code, and is a 2023 model last modified on 8 October 2026 ([HF API](https://huggingface.co/api/models/ai4bharat/indictrans2-en-indic-dist-200M)). It needs an approved download now, a code read before first use, and `HF_HUB_OFFLINE=1` at demo time. Its quality on security text is unmeasured. This research round evaluated no newer Indic translation model, so rule (d)'s "most up to date" is unproven for this one seat.

| Claim | Status |
|---|---|
| Foundation-Sec licence | Conflicting: NOTICE says Llama 3.1 Community Licence + Apache-2.0; the 1.1 GGUF card says "Apache 2.0" ([GGUF card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF)) |
| CVE-LMTune labels derive from the CWE→CAPEC→ATT&CK chain | Inference from the card and repo, plus one spot check; the DIMVA paper was not read |
| CIRCL bi-encoder figures; CIRCL test-split IDs | Paper "in preparation"; split IDs not located |
| SecureModernBERT-NER training corpus | Undisclosed; trained at 128 tokens |
| AXONVERTEX probability calibration | "Has not been measured" per its card |
| Go-template equivalence for the Reasoning and MiST aliases | Untested until phase 0 |
| VRAM at 8K and Reasoning trace length | Projected; only MiST at 4K was measured |
| q8_0 KV effect on JSON extraction; the #15502 loop class on Llama or Qwen | Unmeasured; reported only for gemma4 |
| Reasoning model trained under the Metis system prompt | Inference |
| NVD CPE ground truth for Jul–Oct 2026 | Sparse: since April 2026 NVD enriches only KEV, federal and critical software, so CNA `affected[]` carries most labels |

Two operational risks remain. First, the TF-IDF CWE model holds about 0.6 GB of dense float64 coefficients. Casting them to float32 halves that if RAM gets tight. Second, everything shown to judges must come from defensive models only, with no abliterated variant and no offensive model anywhere in the registry, because the event disqualifies hacking.

## Conclusion

The model question turned out to be mostly a hardware and evidence question. The 6.9 GiB ceiling fixes one generative seat for everything live. The local tests fix where generative models are not worth it: CWE, CVSS and ATT&CK went to retrainable classifiers that run on the CPU, about a hundred times faster per item than the GPU model, and score higher. What remains for the 8B model is the work only a language model can do here, grounded extraction and cited narration. That is also the defensible story for C-DAC. The structured judgements are reproducible and retrainable overnight, and the language model never sets a number.

The most consequential finding was invisible in every benchmark: chat templates. A forced `<think>` tag, a missing system prompt or a missing stop token would have shifted the MiST and Reasoning results more than any real difference between the models. A robust registry should treat the template digest as part of model identity, on the same footing as the weight hash, with byte-identical rendering as a gate in its own right. With that in place, swapping in next month's security model is safe as well as possible.
