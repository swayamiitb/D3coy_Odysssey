# Small CPU-runnable cybersecurity models (encoders, classifiers, embedders, time-series FMs) for the D3COY threat early-warning pipeline: a verified census as of 31 Oct 2026

How this was checked:
- Every repo listed was confirmed to exist through the Hugging Face API on 2026-10-31 (`https://huggingface.co/api/models/<id>`). Creation date, license tag, gated flag, safetensors parameter count and label set (from `config.json`) come from that API unless noted.
- Metrics marked **SR** are self-reported by the publisher, in the model card or the publisher's own paper. Nothing marked SR was independently reproduced.
- Numbers marked **MEASURED** come from a local run on this machine on 2026-10-31:
  - Hardware and stack: Intel Raptor Lake laptop CPU (CPUID family 6, model 183; torch used 24 threads), torch 2.11.0+cpu, transformers 5.22.1, sentence-transformers 6.2.0.
  - Method: fp32, no ONNX or quantisation, median of 10 forward passes after 2 warm-ups.
  - Inputs: a 1-sentence CTI text of about 30–50 tokens, a 512-token text, and a batch of 16 short texts.
  - These are first-party measurements. There is no URL for them, and the scripts and logs were in the session scratchpad.

## Role 1: Which small models should do cyber NER and IOC/entity extraction from advisories and reports?

### Takeaway
No model beats regexes for IPs, hashes, URLs and CVE IDs, so use a deterministic IOC extractor as the primary layer. Add one NER model for the context entities (malware, actor, product, organisation, sector):
1. **attack-vector/SecureModernBERT-NER**: 22 fine-grained types, 503k training spans, MIT, but 396M params.
2. **cisco-ai/SecureBERT2.0-NER**: Apache-2.0, 150M, fast, but only 5 coarse types, and its spans fragmented in my test.
3. **PranavaKailash/CyNER-2.0-DeBERTa-v3-base**: 8 types including Threat_group.

All headline F1s are self-reported on the publishers' own splits.

In a local two-sentence spot check (MEASURED), SecureModernBERT gave correctly typed entities with no false positives, at about 105 ms per sentence on CPU. SecureBERT2.0-NER (about 40 ms) and CyNER-2.0 (about 63 ms) each produced about three false positives. All ModernBERT NER models need `aggregation_strategy="first"`.

### Cited Findings
**Census (all verified on HF, none gated)**

| Repo id | Publisher | Created | Arch / params | License | Labels | Training data | Published metric (SR) |
|---|---|---|---|---|---|---|---|
| [cisco-ai/SecureBERT2.0-NER](https://huggingface.co/cisco-ai/SecureBERT2.0-NER) | Cisco AI | 2025-10-06 | ModernBertForTokenClassification, 149.6M | Apache-2.0 | 11 BIO tags = Indicator, Malware, Organization, System, Vulnerability | 3.4k train + 717 test samples, "fully hand-labeled by domain experts"; the paper identifies it as the CyNER test set ([paper Table 9](https://arxiv.org/html/2510.00240)) | F1 0.945 / R 0.965 / P 0.927, vs SecureBERT 0.734 and CyBERT 0.351 ([card](https://huggingface.co/cisco-ai/SecureBERT2.0-NER)) |
| [attack-vector/SecureModernBERT-NER](https://huggingface.co/attack-vector/SecureModernBERT-NER) | attack-vector (individual; HF training-run path shows "juanmcristobal") | 2025-10-24 (modified 2025-12-30) | ModernBertForTokenClassification on ModernBERT-large, 395.9M | MIT | 42 BIO tags / 22 types: URL, ORG, SERVICE, SECTOR, FILEPATH, DOMAIN, PLATFORM, THREAT-ACTOR, PRODUCT, MALWARE, LOC, CVE, TOOL, IPV4, IPV6, MITRE-TACTIC, MD5, SHA1, SHA256, EMAIL, CAMPAIGN, REGISTRY-KEYS | 502,726 labelled spans "sourced from real-world threat reports, vulnerability advisories, and incident analyses"; source corpus not named; max sequence length 128 tokens during training | AutoTrain validation micro P 0.8468 / R 0.8484 / F1 0.8476, accuracy 0.9589. Per-label "accuracy" from an independent re-evaluation: CVE 0.9995, IPV4 0.9631, MALWARE 0.9087, DOMAIN 0.8878, MITRE-TACTIC 0.7093, IPV6 0.7425 ([card](https://huggingface.co/attack-vector/SecureModernBERT-NER)) |
| [PranavaKailash/CyNER-2.0-DeBERTa-v3-base](https://huggingface.co/PranavaKailash/CyNER-2.0-DeBERTa-v3-base) | Pranava Kailash (individual) | 2024-08-23 | DebertaV2ForTokenClassification, 183.8M | MIT | 17 BIO tags: Date, Indicator, Location, Malware, Organization, System, Threat_group, Vulnerability | Original CyNER plus a "PranavaKailash/CyNER2.0_augmented_dataset"; 3 epochs | P 91.06 / R 92.72 / F1 91.88 on the augmented dataset; paper citation is "yet_to_update" ([card](https://huggingface.co/PranavaKailash/CyNER-2.0-DeBERTa-v3-base)) |
| [CyberPeace-Institute/SecureBERT-NER](https://huggingface.co/CyberPeace-Institute/SecureBERT-NER) | CyberPeace Institute | 2023-06-23 | RobertaForTokenClassification (SecureBERT v1), 124.1M | MIT (base SecureBERT is bigscience-openrail-m) | 40 BIO tags (APTNER schema): TIME, LOC, SECTEAM, TOOL, IDTY, MAL, APT, VULNAME, VULID, ENCR, FILE, SHA2, SHA1, MD5, URL, IP, DOM, OS, PROT, ACT, EMAIL | APTNER dataset | **No metrics on card** ([card](https://huggingface.co/CyberPeace-Institute/SecureBERT-NER)). The same base fine-tuned on APTNER by Cyber-ThreaD reports F1 0.562 (eval) / 0.636 (prediction set) ([Cyber-ThreaD/SecureBERT-APTNER](https://huggingface.co/Cyber-ThreaD/SecureBERT-APTNER)) |
| [AI4Sec/cyner-xlm-roberta-base](https://huggingface.co/AI4Sec/cyner-xlm-roberta-base) (original IBM CyNER) | AI4Sec | 2022-03-02 | XLMRobertaForTokenClassification | MIT | Same 11 tags as Cisco (Indicator/Malware/Organization/System/Vulnerability) | CyNER | README is empty; weights only as `pytorch_model.bin` (pickle). The **-large** sibling has no weight file, only config.json and parameter.json ([large repo](https://huggingface.co/AI4Sec/cyner-xlm-roberta-large)) |
| [pzryathzsdhc/cti-ner-securebert](https://huggingface.co/pzryathzsdhc/cti-ner-securebert) | individual (capstone, [github dandye/nlp_capstone](https://github.com/dandye/nlp_capstone)) | 2026-07-20 | RoBERTa (SecureBERT v1), 124.1M | MIT | 33 tags / 16 types incl. attack technique id/name, CVE, CWE, file hash/name/path, IP, email, malware family, threat actor group, hacking tool, tactic, TLP, YARA rule name, affected product | **66 CISA advisories** (2,799 chunks) with LLM-proposed (Claude Sonnet) gold labels; human-curated 8-advisory test split | Strict micro F1 0.71, macro 0.74. Per label: technique id 0.99, CWE 1.00, CVE 0.95, IP 0.91, threat actor 0.32, hacking tool 0.48 ([card](https://huggingface.co/pzryathzsdhc/cti-ner-securebert)) |
| [pzryathzsdhc/cti-ner-gliner](https://huggingface.co/pzryathzsdhc/cti-ner-gliner) | same | 2026-07-21 | GLiNER (gliner_medium-v2.1) | Apache-2.0 | 16 zero-shot label strings, as above | same 66 advisories | Strict micro F1 0.56; IP-address F1 collapses to 0.03; input truncated at 384 tokens ([card](https://huggingface.co/pzryathzsdhc/cti-ner-gliner)) |

**Related base encoders, for fine-tuning only (no task head)**
- **[cisco-ai/SecureBERT2.0-base](https://huggingface.co/cisco-ai/SecureBERT2.0-base)**: ModernBERT, 149.7M, Apache-2.0. Pretrained on 13.62B text tokens plus 53.4M code tokens; about 12.2B of the text tokens are "large-scale web text". The paper gives no data cut-off date ([paper Table 1](https://arxiv.org/html/2510.00240)). Paper v1 was submitted 2025-09-30 and v2 revised 2025-10-10 ([arXiv](https://arxiv.org/abs/2510.00240)).
- **[ehsanaghaei/SecureBERT](https://huggingface.co/ehsanaghaei/SecureBERT)**: RoBERTa, license **bigscience-openrail-m**.
- **[ehsanaghaei/SecureBERT_Plus](https://huggingface.co/ehsanaghaei/SecureBERT_Plus)**: license **CC-BY-NC-4.0**, which is non-commercial.
- **[jackaduma/SecBERT](https://huggingface.co/jackaduma/SecBERT)**: Apache-2.0, 84M, trained on APTnotes, Stucco-Data and CASIE.
- **[markusbayer/CySecBERT](https://huggingface.co/markusbayer/CySecBERT)**: Apache-2.0, 110M.
- **[ibm-research/CTI-BERT](https://huggingface.co/ibm-research/CTI-BERT)**: BERT trained from scratch on about 1.2B security tokens, 256-token sequence length. It has no license tag in the HF metadata, though a LICENSE file ships in the repo.

**MEASURED on this machine**
- **cisco-ai/SecureBERT2.0-NER**
  - Speed: loaded and ran with plain `AutoModelForTokenClassification` (sdpa attention). 45.1 ms for a 50-token sentence; 233.6 ms for 512 tokens; 322.9 ms for a batch of 16 short sentences (about 20 ms per sentence).
  - Quality with `aggregation_strategy="simple"`: the test sentence was "the LockBit affiliate exploited CVE-2025-12345 in Fortinet FortiOS to deploy Cobalt Strike beacons calling back to 185.222.202.55 and update-check[.]com". Spans came out fragmented, for example `Malware:"Lock"` + `Malware:"Bit"` and `Indicator:"185"`, `"."`, `"222"`. The CVE ID was split across Indicator and Vulnerability tags, and the verb "exploited" was tagged Indicator.
  - Re-test with `aggregation_strategy="first"` (identical output with "max" and "average"):
    - Spans now merge correctly: `Malware:LockBit`, `Indicator:CVE-2025-12345`, `System:Fortinet FortiOS`, `Malware:Cobalt Strike beacons`, `Indicator:185.222.202.55`, `Indicator:update-check[.]com.` (trailing period included).
    - "exploited" is still tagged Indicator, and the CVE ID is typed Indicator rather than Vulnerability.
    - On a second sentence ("APT29 used spear-phishing emails from attacker@evil-mail.ru to deliver WINELOADER …; the dropper hash is d41d8…"), it found `Indicator:attacker@evil-mail.ru`, `Malware:WINELOADER` and `Indicator:<md5>.`.
    - False positives on the second sentence: `Indicator:"spear-phishing emails"`, `Indicator:"European"`, `Indicator:"dropper hash"`. It **missed APT29** entirely.
    - Timings in this run: 38.4 ms short, 244 ms at 512 tokens, 313 ms for a batch of 16.
    - transformers warned "Tokenizer does not support real words, using fallback heuristic" for word-level aggregation with this BPE tokenizer.
- **CyberPeace-Institute/SecureBERT-NER**
  - Speed: 25.1 ms for 44 tokens; 171.6 ms for 512 tokens; 204.1 ms for a batch of 16 (about 13 ms per sentence).
  - Quality ("simple" aggregation): correct `TIME:"March 2026"`, `IDTY:"Fortinet"`, `MAL:"Cobalt Strike beacons"`. The CVE ID and IP were again split into sub-pieces. It missed LockBit and the defanged domain.
  - Tokenizer warns above 512 tokens (566 > 512).
- **attack-vector/SecureModernBERT-NER**
  - Loaded with plain `AutoModelForTokenClassification`; the 1.58 GB safetensors downloaded in about 54 s.
  - With "first" aggregation on the same two sentences: `THREAT-ACTOR:LockBit`, `ORG:Fortinet`, `PRODUCT:FortiOS`, `TOOL:Cobalt` + `TOOL:Strike` (split into two spans), `DOMAIN:update-check[.]com.`; then `THREAT-ACTOR:APT29`, `EMAIL:attacker@evil-mail.ru`, `MALWARE:WINELOADER`, `MD5:<hash>.`.
  - **Zero false positives** on these two sentences, and indicator types came out correctly typed. It **missed** CVE-2025-12345, the IPv4 185.222.202.55 and "European diplomats" (SECTOR/LOC) in these tests.
  - With "simple" aggregation, output fragments badly; the MD5 split into about 25 pieces.
  - Speed: 104.6 ms for 50 tokens; 607 ms for 492 tokens; 870 ms for a batch of 16 (about 54 ms each).
- **PranavaKailash/CyNER-2.0-DeBERTa-v3-base**
  - Loaded with plain Auto classes (DebertaV2Tokenizer).
  - With "simple" aggregation (clean spans for this SentencePiece model):
    - Correct: `Date:March 2026`, `Threat_group:the LockBit affiliate`, `Organization:Fortinet`, `System:FortiOS`, `Malware:Cobalt Strike`, `Indicator:185.222.202.55`, `Indicator:update-check[.]com`; then `Threat_group:APT29`, `Indicator:attacker@evil-mail.ru`, `Malware:WINELOADER`, `Organization:European diplomats`, `Indicator:<md5>`.
    - Errors: `Vulnerability:"exploited"`, `Indicator:CVE-2025-12345` (wrong type), `Indicator:"beacons"`, `Indicator:"spear-phishing emails"`, `Malware:"dropper"`, `Indicator:"hash"`.
  - With "first" aggregation, transformers 5.22.1 **glued words together** ("March2026,", "theLockBitaffiliate"). So use "simple" for this model, the opposite of the ModernBERT models.
  - Speed: 63.1 ms for 45 tokens; 238 ms for 477 tokens; 275 ms for a batch of 16 (about 17 ms each).

**Other observations**
- The SecureModernBERT-NER card states its limits: the model "does not normalise entities (e.g., deobfuscating `hxxp`) nor validate indicator authenticity", and it recommends downstream validation ([card](https://huggingface.co/attack-vector/SecureModernBERT-NER)).
- The cti-ner-securebert card warns that "a naive single-pass tokenizer call truncates long, hash-heavy advisory text". Inference needs the repo's sliding-window code ([card](https://huggingface.co/pzryathzsdhc/cti-ner-securebert)).

### Inferences
- **Ranking for our pipeline:**
  1. SecureModernBERT-NER, for the richest schema. Its IPV4/DOMAIN/URL/hash/CVE/THREAT-ACTOR/SECTOR/CAMPAIGN types map directly onto alert fields and the asset-correlation demo.
  2. SecureBERT2.0-NER, for speed, the clean Apache-2.0 license and Cisco provenance. Its "Indicator" class lumps together every IOC type, so a regex pass is needed to type them anyway.
  3. CyNER-2.0, a middle ground with Threat_group/Date/Location.
  4. CyberPeace SecureBERT-NER, fast but with no published metrics.
- **CPU cost:** MEASURED, SecureModernBERT-NER is about 2.5–2.8× slower than SecureBERT2.0-NER (105 vs 38–45 ms short; 607 vs 244 ms per ~500-token chunk).
  - A typical 2,000-token advisory therefore costs about 2.4 s with SecureModernBERT, versus about 1 s with SecureBERT2.0-NER, at batch size 1.
  - The model was trained at 128 tokens, so feeding 128–256-token windows is advisable anyway.
- **What the two-sentence spot check suggests** (it is anecdotal, not an evaluation):
  - SecureModernBERT is high-precision for context entities (actor, product, tool, malware) and the typed IOCs it does find.
  - It can miss IPs and CVE IDs, so regex must cover those.
  - SecureBERT2.0-NER is higher-recall for IOC-like strings but noisy (tagging "exploited", "European", "dropper hash"), and it has no actor class.
  - Combined recipe: regex IOCs, plus SecureModernBERT for THREAT-ACTOR / MALWARE / TOOL / PRODUCT / ORG / SECTOR / CAMPAIGN.
- **DeBERTa estimate:** DeBERTa-v3-base is typically 1.3–1.6× a RoBERTa-base forward pass, so about 35–45 ms per sentence (estimate).
- **Aggregation is mandatory:** both ModernBERT NER models fragment spans under the default-style "simple" aggregation, because B- tags land on BPE sub-tokens. Use `aggregation_strategy="first"` (as the SecureModernBERT card does), strip trailing punctuation, and re-validate IOC spans with regex.
- **Self-reported F1s are not comparable.** SecureBERT2.0 reports 0.945 on 717 CyNER rows, SecureModernBERT 0.848 on its own split, CyNER-2.0 0.919 on its augmented set, and cti-ner-securebert 0.71 strict on 8 CISA advisories. The schemas, splits and scoring all differ. The cti-ner-securebert number is the most "honest" (document-level, strict spans), and it shows how hard real advisories are.
- **License risk:** models fine-tuned from SecureBERT v1 inherit bigscience-openrail-m use restrictions, even when the derivative is tagged MIT (CyberPeace, pzryathzsdhc). For a government-facing deliverable, prefer the Apache-2.0 or MIT ModernBERT-based models.

### Gaps
- No independent, shared-benchmark comparison of these NER models on CERT-In/CISA-style advisories was found.
- The SecureModernBERT-NER training corpus (sources, licenses, date range) is undisclosed.
- No training-data cut-off date is stated for any NER model.
- CyNER-2.0's augmented dataset composition and size were not checked.

## Role 2: Which security-domain embedding and reranker models suit deduplication, campaign clustering and retrieval, and how do they compare with general embedders?

### Takeaway
1. **cisco-ai/SecureBERT2.0-biencoder** (Apache-2.0, 149M, 768-d, 1024 tokens) as the security-domain embedder.
2. **cisco-ai/SecureBERT2.0-cross_encoder** as a reranker or dedup confirmer.

The only security-retrieval evidence is Cisco's own in-house set, and it was compared only against weak baselines (MiniLM, ATTACK-BERT, ms-marco cross-encoders). No benchmark compares security embedders with bge-m3, Qwen3-Embedding-0.6B, EmbeddingGemma or nomic. Keep a general embedder as a fallback; bge-m3 suits multilingual Indian-language advisories. Benchmark both on a small labelled sample before committing.

### Cited Findings
**Census**

| Repo id | Publisher | Created | Arch / params | License / gating | Notes |
|---|---|---|---|---|---|
| [cisco-ai/SecureBERT2.0-biencoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder) | Cisco AI | 2025-10-06 (mod. 2026-05-21) | ModernBERT (sentence-transformers), 149.0M, 768-d, max 1024 tokens | Apache-2.0, not gated | Fine-tuned on a 43k cybersecurity QA corpus, 60k security-governance QA and 25k instruction pairs; 5k "rules corpus" for evaluation ([card](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder)) |
| [cisco-ai/SecureBERT2.0-cross_encoder](https://huggingface.co/cisco-ai/SecureBERT2.0-cross_encoder) | Cisco AI | 2025-10-06 | ModernBertForSequenceClassification, 149.6M, 1 output | Apache-2.0 | 35,705 training pairs ([card](https://huggingface.co/cisco-ai/SecureBERT2.0-cross_encoder)) |
| [basel/ATTACK-BERT](https://huggingface.co/basel/ATTACK-BERT) | Basel Abdeen | 2023-04-14 | MPNet sentence-transformer (about 110M) | No license tag in metadata; card text says "License: apache-2.0" | Maps attack-action sentences to embeddings; used by the SMET tool for ATT&CK mapping ([card](https://huggingface.co/basel/ATTACK-BERT)). Weights only as `pytorch_model.bin` |
| [CIRCL/vulnerability-attack-technique-biencoder](https://huggingface.co/CIRCL/vulnerability-attack-technique-biencoder) | CIRCL (Luxembourg CERT) | 2026-08-12 | RoBERTa-base, 124.6M | **GPL-3.0** | CVE↔ATT&CK technique-description bi-encoder; see Role 3 |
| [Qwen/Qwen3-Embedding-0.6B](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B) | Alibaba Qwen | 2025-06-03 | Qwen3 decoder, 595.8M | Apache-2.0, not gated | config `transformers_version` 4.51.3 |
| [google/embeddinggemma-300m](https://huggingface.co/google/embeddinggemma-300m) | Google | 2025-07-17 | 302.9M | Gemma license, **gated (manual approval)** | README and config return 401 without an accepted licence and token |
| [BAAI/bge-m3](https://huggingface.co/BAAI/bge-m3) | BAAI | 2024-01-27 | XLM-RoBERTa | MIT | Ships an ONNX export in the repo |
| [nomic-ai/nomic-embed-text-v1.5](https://huggingface.co/nomic-ai/nomic-embed-text-v1.5) / [v2-moe](https://huggingface.co/nomic-ai/nomic-embed-text-v2-moe) | Nomic | 2024-02 / 2025-02 | NomicBert 136.7M / 475.3M | Apache-2.0 | `auto_map` points at remote code in `nomic-ai/nomic-bert-2048`, so it **needs `trust_remote_code=True`** |

**Published metrics (SR, Cisco paper)**
- **Bi-encoder (paper Table 8; the paper does not clearly name the dataset):** SecureBERT 2.0 scores mAP 0.951 / R@1 0.984 / MRR@10 0.989. Baselines:

  | Baseline | mAP | R@1 | MRR@10 |
  |---|---|---|---|
  | all-MiniLM-L12-v2 | 0.912 | 0.924 | 0.945 |
  | basel/ATTACK-BERT | 0.906 | 0.918 | 0.944 |
  | all-MiniLM-L6-v2 | 0.898 | 0.917 | 0.940 |

  Source: [arXiv 2510.00240 HTML](https://arxiv.org/html/2510.00240).
- **Cross-encoder (paper Table 7):** SecureBERT 2.0 scores mAP 0.955 / R@1 0.948 / NDCG@10 0.986 / MRR@10 0.983. Baselines:

  | Baseline | mAP | R@1 |
  |---|---|---|
  | ms-marco-TinyBERT-L2-v2 | 0.920 | 0.849 |
  | ms-marco-MiniLM-L4-v2 | 0.904 | 0.863 |
  | bge-reranker-large | 0.741 | 0.741 |

  Source: [arXiv 2510.00240 HTML](https://arxiv.org/html/2510.00240); also on the [card](https://huggingface.co/cisco-ai/SecureBERT2.0-cross_encoder).

**Independent comparisons**
- A web search found no security-specific MTEB-style leaderboard for embedders. The comparisons that do exist are small studies inside CTI-RAG papers:
  - A RAG-for-emerging-cybersecurity paper compared five general embedders and found small differences, with mxbai-embed-large-v1 best ([arXiv 2510.27080](https://arxiv.org/pdf/2510.27080)).
  - AttackSeqBench reported only marginal differences between embedding models, including ATT&CK BERT ([arXiv 2503.03170](https://arxiv.org/pdf/2503.03170)).
  - Both of these come from a search summary; I did not verify them in the full text.
  - CTI retrieval benchmarks such as CTIConnect (KDD '26) evaluate LLMs end to end, not embedders ([arXiv 2510.11974](https://arxiv.org/pdf/2510.11974)).

**MEASURED on this machine**
- cisco-ai/SecureBERT2.0-biencoder loaded with `SentenceTransformer(...)` in sentence-transformers 6.2.0.
- Speed: 132 ms to encode one ~50-token sentence; 854 ms for a batch of 16 (about 53 ms each); 326 ms for one ~600-token document.
- Sanity check on cosine similarity: "Cobalt Strike beacon calling back to a C2 server over HTTPS" vs "The implant periodically beacons to attacker-controlled infrastructure" scored 0.482. The same query vs "Patch Tuesday fixes a print spooler privilege escalation" scored −0.021.

### Inferences
- **Ranking for dedup and campaign clustering:**
  1. SecureBERT2.0-biencoder for candidate generation (ANN/HNSW or a simple cosine threshold).
  2. SecureBERT2.0-cross_encoder to confirm near-duplicates in the top-k. Expect cross-encoder cost per pair to be similar to one 150M forward pass, about 25–50 ms on this CPU (estimate from the NER timings).
  3. bge-m3 as the general and multilingual fallback.
  4. Qwen3-Embedding-0.6B: about 4× the parameters, so expect roughly 3–4× the latency. Estimate.
  5. ATTACK-BERT only for short "attacker does X" sentences mapped to ATT&CK.
- **Licensing and offline setup:** EmbeddingGemma's manual gating makes it a poor choice for a 24-hour offline build unless it is downloaded in advance with an approved token. The nomic models need remote code.
- **Cisco's evaluation is weak:** the comparison omits all strong 2024–2026 general embedders, so it does not prove the domain model beats bge-m3 or Qwen3 on advisories. A 50–100-pair labelled dedup set built from cached advisories would settle it quickly.

### Gaps
- No public benchmark of SecureBERT2.0-biencoder vs bge-m3 / Qwen3-Embedding / EmbeddingGemma / nomic on security retrieval or dedup was found.
- The Cisco bi-encoder evaluation dataset is not clearly identified in the paper.
- The ollama-packaged variants named in the brief (`qwen3-embedding:0.6b`, `embeddinggemma`) were not checked; only the HF repos were verified.

## Role 3: Which models map CVE or advisory text to ATT&CK techniques, CWE and CAPEC?

### Takeaway
- **ATT&CK:** use **CIRCL/vulnerability-attack-technique-classification-roberta-base**. It is trained on expert CTID mappings over 53 parent techniques, with honest recall@5 ≈ 0.64 (CC-BY-4.0). Optionally add the CIRCL bi-encoder for open-vocabulary ranking.
- **CWE:** use **xamxte/cwe-classifier-roberta-base**. It is the only model with an external benchmark: CTI-Bench cti-rcm strict top-1 75.6% (CC-BY-4.0).
- **CAPEC:** **Sana9/securebert-vuln2capec-flat** is the only credible option.

The Sana9 CVE-LMTune suite (DIMVA '26) covers all three taxonomies with high micro-F1. Its labels appear to be derived through CWE-based taxonomy chaining rather than expert mapping, and its macro-F1 is low.

### Cited Findings
**Sana9 CVE-LMTune suite**

Publisher: Sana Rekbi and Franco Terranova (with Lahmadi and Chrisment, LORIA/Inria per the paper). The paper is "Multi-Taxonomy Vulnerability Classification with Hierarchically Finetuned Language Models", DIMVA '26, Chania, July 2026 ([HAL hal-05500820](https://hal.science/hal-05500820)). The code is at [terranovafr/CVE-LMTune](https://github.com/terranovafr/CVE-LMTune); that repo's license is stated inconsistently as GPL-3.0 and AGPL-3.0. The data is on [Zenodo 10.5281/zenodo.16936476](https://doi.org/10.5281/zenodo.16936476).

| Repo id | Created | Arch / params | License | Labels | Data | SR metrics (held-out 20% test, threshold 0.5) |
|---|---|---|---|---|---|---|
| [Sana9/securebert-vuln2attack-flat](https://huggingface.co/Sana9/securebert-vuln2attack-flat) | 2026-04-28 (mod. 2026-10-28) | RoBERTa (SecureBERT v1), 124.8M | bigscience-openrail-m | 175 ATT&CK Enterprise (sub)techniques, multi-label | 231,009 CVEs, latest CVE update 17/06/2026, 60/20/20 split | Micro-F1 0.8168, macro-F1 0.4286, weighted-F1 0.8093, P@1 0.9321, MRR 0.946, subset accuracy 0.6874 |
| [Sana9/securebert-vuln2cwe-flat](https://huggingface.co/Sana9/securebert-vuln2cwe-flat) | 2026-04-28 | 125.2M | openrail-m | 713 CWEs | 259,549 CVEs, to 17/06/2026 | Micro-F1 0.7886, **macro-F1 0.0992**, P@1 0.8172, R@5 0.845 |
| [Sana9/securebert-vuln2capec-flat](https://huggingface.co/Sana9/securebert-vuln2capec-flat) | 2026-06-24 | 125.0M | openrail-m | 444 in config.json vs 445 stated on card | 239,931 CVEs, to 17/06/2026 | Micro-F1 0.8274, macro-F1 0.3984, P@1 0.8805 |
| [Sana9/securebert-vuln2atlas-flat](https://huggingface.co/Sana9/securebert-vuln2atlas-flat) | 2026-10-15 | 124.7M | openrail-m | 10 MITRE ATLAS techniques | non-AI CVEs plus 228 annotated AI CVEs | Micro-F1 0.823 ± 0.006 (non-AI test); 0.755 ± 0.013 on AI CVEs |
| bert- and distilbert- variants, e.g. [Sana9/distilbert-vuln2attack-flat](https://huggingface.co/Sana9/distilbert-vuln2attack-flat), [bert-vuln2cwe-flat](https://huggingface.co/Sana9/bert-vuln2cwe-flat) | 2026-04/06 | BERT-base 110M / DistilBERT 67M | MIT | same label sets | same data | not extracted; see Gaps |

- **Label provenance:** the cards' disclaimers say the project "is a result of the use of the NVD API … the CVE2CAPEC project" ([card](https://huggingface.co/Sana9/securebert-vuln2attack-flat)). The repo says data is downloaded "from CVE2CAPEC, NVD, and MITRE" and does not describe expert mapping ([GitHub](https://github.com/terranovafr/CVE-LMTune)).
- **Loading:** all variants load with standard `AutoModelForSequenceClassification`, with `problem_type: multi_label_classification` (sigmoid). The card quick-start uses `use_fast=False`. Repos also ship an extra `classification_head.pth` that the quick-start never references (config.json on HF).

**CIRCL / Vulnerability-Lookup models**
- [CIRCL/vulnerability-attack-technique-classification-roberta-base](https://huggingface.co/CIRCL/vulnerability-attack-technique-classification-roberta-base)
  - Basics: created 2026-07-13, RoBERTa-base 124.7M, CC-BY-4.0, 53 parent ATT&CK techniques.
  - Labels and splits: labels come from the CTID "Mapping ATT&CK to CVE for Impact" expert mappings plus the CTID KEV mappings (ATT&CK 16.1). Splits are 972 train / 106 validation / 118 test, and the test split was touched once.
  - Metrics (metrics.json): recall@5 0.644, recall@3 0.518, micro-F1 0.390, macro-F1 0.191 ([metrics.json](https://huggingface.co/CIRCL/vulnerability-attack-technique-classification-roberta-base/raw/main/metrics.json)). Across five seeds, recall@5 is 0.667 ± 0.015 ([bi-encoder card](https://huggingface.co/CIRCL/vulnerability-attack-technique-biencoder)).
  - The card says "Scores are not calibrated probabilities" and the outputs are "not verified mappings".
  - Paper: [arXiv 2607.25572](https://arxiv.org/abs/2607.25572).
  - Companion: an LLM-expanded variant ([…-llm-expanded](https://huggingface.co/CIRCL/vulnerability-attack-technique-classification-roberta-base-llm-expanded), 62 labels). It was published as a negative result: LLM labels at ≈0.39 agreement gave no reliable gain.
- [CIRCL/vulnerability-attack-technique-biencoder](https://huggingface.co/CIRCL/vulnerability-attack-technique-biencoder)
  - Basics: created 2026-08-12, GPL-3.0. It scores CVE text against the official ATT&CK technique descriptions.
  - Metrics: recall@5 0.643 ± 0.019 on the 53-technique vocabulary; macro-F1 0.212 vs 0.176 for the classifier; open-vocabulary recall@5 0.515 over 222 parent techniques, which the card describes as "2.3×" a generic zero-shot embedder.
  - Caveat from the card: held-out techniques rank no better than with a generic MiniLM.
  - Usage needs `technique_texts.json` plus `config.biencoder` scoring code from the card.
  - Numbers come from a follow-up paper still "in preparation".
- [CIRCL/cwe-parent-vulnerability-classification-roberta-base](https://huggingface.co/CIRCL/cwe-parent-vulnerability-classification-roberta-base): MIT, 303 CWE classes, eval accuracy 0.568 and macro-F1 0.210 ([metrics.json](https://huggingface.co/CIRCL/cwe-parent-vulnerability-classification-roberta-base/raw/main/metrics.json)). The card says "More information needed".

**Other CWE / ATT&CK models**
- [xamxte/cwe-classifier-roberta-base](https://huggingface.co/xamxte/cwe-classifier-roberta-base)
  - Basics: created 2026-03-15, RoBERTa-base 124.8M, CC-BY-4.0, 205 CWE classes, single-label.
  - Training data: 234,770 samples with Claude-Sonnet-4.6-refined labels ([dataset xamxte/cve-to-cwe](https://huggingface.co/datasets/xamxte/cve-to-cwe)).
  - Internal test: top-1 87.4% and macro-F1 0.607. This test set is agreement-filtered, and the card says this "biases evaluation toward unambiguous cases".
  - **External, CTI-Bench cti-rcm strict top-1:** 75.6% on 2023–24 CVEs and 71.8% on cti-rcm-2021. The card compares Foundation-Sec-8B at 72.0% and GPT-4 at 72.0%.
  - Paper: [arXiv 2603.14911](https://arxiv.org/abs/2603.14911).
  - Gotcha: config `id2label` is `LABEL_n`, so you must load `cwe_label_map.json`.
- [mulliken/cwe-predictor](https://huggingface.co/mulliken/cwe-predictor): DistilBERT 67M, Apache-2.0, 232 CWEs. Trained on 111,640 NVD CVE→CWE pairs; validation accuracy 0.727 and macro-F1 0.251 (SR).
- [nanda-rani/TTPXHunter](https://huggingface.co/nanda-rani/TTPXHunter): RoBERTa 124.8M, MIT, 193 labels. The labels are only `LABEL_0…LABEL_192` with no mapping, and every card evaluation field reads "[More Information Needed]".
- **MITRE TRAM:** README says it uses "SciBERT-based single-label and multi-label models" and identifies "up to 50 common ATT&CK techniques". Apache-2.0. The README does not say where trained weights are hosted ([GitHub](https://github.com/center-for-threat-informed-defense/tram)). An HF author search for `mitre` and `center-for-threat-informed-defense` returned **0 models** (HF API, 2026-10-31).
- [alirezaaminzadeh/attack-technique-classifier](https://huggingface.co/alirezaaminzadeh/attack-technique-classifier): TF-IDF plus one-vs-rest logistic regression, shipped as joblib (pickle) files, 0 downloads.

**MEASURED on this machine**
- **Sana9/securebert-vuln2attack-flat**
  - Loaded with plain `AutoModelForSequenceClassification` (problem_type multi_label_classification); no use of `classification_head.pth` was needed.
  - In transformers 5.22.1, `use_fast=False` and `use_fast=True` both return `RobertaTokenizer` and give identical outputs, so the card's `use_fast=False` is moot on v5.
  - Speed: 16.0 ms for a 15-token CVE sentence; 147 ms for 452 tokens; 77 ms for a batch of 16 (about 5 ms each).
  - **Output sanity check:** for the card's own example ("Buffer overflow vulnerability in OpenSSL allows remote attackers to execute arbitrary code."), top-5 sigmoid scores were T1539 (Steal Web Session Cookie) 0.886, T1134 (Access Token Manipulation) 0.839, T1134.002 0.836, T1134.001 0.832, T1134.003 0.830. All five clear the 0.5 threshold, and none is an exploitation technique such as T1190 or T1203.
- **xamxte/cwe-classifier-roberta-base:** for an SQL-injection description, the raw config label was `LABEL_189`. Mapped through `cwe_label_map.json`, it is **CWE-89 at 0.924**, which is correct. This confirms the label-map gotcha.
- **CIRCL severity** (Role 4) is the roberta-base reference: 22.7 ms per short CVE.

### Inferences
- **Reading the Sana9 numbers:** CVE2CAPEC is a public project that links CVE→CWE→CAPEC→ATT&CK through MITRE's taxonomy relationships ([CVE2CAPEC](https://github.com/Galeax/CVE2CAPEC); I did not open its README this session). Sana9's ATT&CK and CAPEC labels are therefore most likely mechanically implied by each CVE's NVD CWE. Their high micro-F1 then largely measures CWE recovery plus a deterministic lookup, which explains macro-F1 of 0.43 for ATT&CK and 0.10 for CWE. They are useful for the top-k "likely techniques" a dashboard shows, but they are not evidence of exploitation-relevant technique mapping. CIRCL's expert-label model is lower-scoring but more faithful.
- **Recommended stack:** CWE from xamxte, with Sana9 CWE as a second opinion. CAPEC from Sana9. ATT&CK from CIRCL top-5, with Sana9 top-5 shown as "taxonomy-implied".
  - Cost: each model is a roberta-base-class forward pass, MEASURED at 15–25 ms per CVE description on this CPU. All three cost under 100 ms per CVE, which is fully deterministic at fixed weights and threshold.
- **Sana9 ATT&CK spot check:** for a generic buffer-overflow RCE description, the model returned five token-manipulation and cookie-theft techniques at about 0.83–0.89. This is consistent with labels inherited mechanically through the CWE→CAPEC→ATT&CK chain. Do not show Sana9 ATT&CK output as "the technique being used" without CIRCL corroboration, or without a top-k display that is clearly labelled as such.
- **License:** Sana9 SecureBERT variants carry OpenRAIL-M. The bert- and distilbert- variants are MIT, if a cleaner license matters.

### Gaps
- Metrics for the Sana9 bert- and distilbert- variants were not extracted, so the speed/accuracy trade-off of the 67M DistilBERT variants is unknown.
- The DIMVA paper's full text (hierarchical vs flat comparison, label-derivation method) was not read. The derivation claim above is an inference.
- Where TRAM's trained SciBERT weights are hosted could not be determined.
- No model maps free-text *reports* (not CVEs) to ATT&CK with a published, recent evaluation, apart from TRAM (~50 techniques) and TTPXHunter (card has no evaluation).

## Role 4: Which models predict CVSS vectors or severity from text, for CVEs NVD hasn't analysed yet?

### Takeaway
1. **AXONVERTEX-AI-RESEARCH/cve-cvss-vector-modernbert-base** is the only small model that predicts the full CVSS v3.1 base vector. It has a rigorous temporal evaluation on 57,611 CVEs from 2026: exact vector 31.3%, base-score MAE 1.02, severity accuracy 63.2%. But it is brand new (2026-10-05, 17 downloads) and needs its own predictor script.
2. **CIRCL/vulnerability-severity-classification-roberta-base** is the mature 4-class severity classifier: leakage-free accuracy 74.2%, CC-BY-4.0, and MEASURED at 22.7 ms per CVE.

Show both as "AI estimate, pending NVD".

### Cited Findings
- **[AXONVERTEX-AI-RESEARCH/cve-cvss-vector-modernbert-base](https://huggingface.co/AXONVERTEX-AI-RESEARCH/cve-cvss-vector-modernbert-base)**
  - Basics: created 2026-10-05, Apache-2.0, ModernBERT-base (~150M; safetensors total 149.0M for the encoder) with eight per-metric heads (AV, AC, PR, UI, S, C, I, A).
  - Output: always a valid v3.1 vector via joint decoding over 2,592 valid vectors, plus probabilities, `expected_score` and `uncertain_metrics`. Uncertain metrics are those whose top probability is below 0.7.
  - Training data: about 107,000 CVE records from cvelistV5, published before 2025-07-01. Labels are the CNA vector, with the ADP (mainly CISA vulnrichment) vector as fallback; "NVD's own scores are not in the CVE List and were not used". CVSS strings are stripped from descriptions to remove leakage.
  - Evaluation: temporal test on CVEs published 2026-01-01 to early October 2026 (n=57,611). Headline numbers exclude Oracle, whose descriptions are generated from the vector (99% exact match otherwise), leaving n=55,131.

    | Metric | This model | TF-IDF + logistic regression | Assigner-only prior |
    |---|---|---|---|
    | Exact vector | 31.3% [30.9, 31.7] | 29.9% | 14.3% |
    | Score MAE (expected score) | 1.02 | — | — |
    | Within ±1.0 | 59.0% | — | — |
    | Severity accuracy (most likely severity) | 63.2% | 59.6% | — |
    | Mean per-metric accuracy | 82.6% | — | — |
    | Severity macro-F1 | 0.525 | 0.489 | — |

  - The card says calibration "has not been measured".
  - Loading: requires `hf_hub_download(REPO, "cvss_predictor.py")` plus `heads.safetensors`, i.e. custom code. It also ships `serve.py`, a FastAPI service.
- **[CIRCL/vulnerability-severity-classification-roberta-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base)** ("VLAI")
  - Basics: created 2025-02-27, modified 2026-10-29, CC-BY-4.0, RoBERTa-base 124.6M. 6,122 downloads, the most-used model in this census.
  - Labels: Low (<4.0), Medium, High, Critical (≥9.0), taken from the first available of CVSS v4.0, v3.1, v3.0, v2.0.
  - Training data: [CIRCL/vulnerability-scores](https://huggingface.co/datasets/CIRCL/vulnerability-scores) revision 55a886a, built from CVE, GitHub, PySec and CSAF (Red Hat, Cisco, CISA) advisories. Split: 670,283 train rows (567,964 labelled), 83,550 validation, 83,376 test. The split is group-aware, so no vulnerability appears in both train and test.
  - Results (SR, leakage-free test, 70,472 rows): accuracy **0.7415** (95% CI 0.7383–0.7447), macro-F1 0.646. Per-class F1: Low 0.428 (recall 0.328), Medium 0.800, High 0.728, Critical 0.628.
  - The card's October 2026 note says the earlier ">82%" accuracy in the [VLAI paper (arXiv 2507.03607)](https://arxiv.org/abs/2507.03607) "was measured on a split where many test descriptions also appeared in training" ([technical report](https://doi.org/10.5281/zenodo.23760802)).
- **Not suitable:**
  - [NilHRH/vulnerability-severity-clf](https://huggingface.co/NilHRH/vulnerability-severity-clf) (2026-10-27, MIT, Ettin-150M): 99.53% accuracy, but its labels are "deterministic policy labels" over CVE + EPSS + KEV + OSV fields. It re-derives a scoring policy and does not estimate CVSS from text.
  - [bziemba/SecureBERT-MultiTask-CVSS-CWE](https://huggingface.co/bziemba/SecureBERT-MultiTask-CVSS-CWE): custom class, pickle weights, no license, no evaluation.
  - [iashour/CANDLE_cvss_vector](https://huggingface.co/iashour/CANDLE_cvss_vector) and siblings: MPNet 109M per metric, MIT, empty README.
  - [drorrabin/cvss_score_pred](https://huggingface.co/drorrabin/cvss_score_pred): LoRA on Llama-3.1-8B, not small.
- **MEASURED (CIRCL severity):** loaded with plain `AutoModelForSequenceClassification`.
  - Speed: 22.7 ms for a 29-token description; 182 ms at 512 tokens; 160 ms for a batch of 16 (10 ms each).
  - Sanity check: "heap-based buffer overflow … remote unauthenticated attacker to execute arbitrary code" → Critical 0.964.

### Inferences
- **Ranking:**
  1. CIRCL severity for the risk-level label, because it is mature, fast and has an honest evaluation.
  2. The AXONVERTEX vector predictor for a full vector and score with uncertainty flags. Its `uncertain_metrics` output is ideal for handing off to the single generative LLM on the GPU.
- **Speed:** AXONVERTEX is ModernBERT-base, so it should run at about the speed of SecureBERT2.0-NER: roughly 45 ms short, 230 ms at 512 tokens on this CPU (estimate from the measured ModernBERT-base forward).
- **Ceiling of text-only prediction:** both evaluations show that a strong TF-IDF baseline gets within 1–2 points. A TF-IDF plus logistic-regression fallback trained on the cached CIRCL dataset would be a credible deterministic backup.
- **Code risk:** AXONVERTEX requires executing downloaded Python (`cvss_predictor.py`). Read the file before running it, and pin the revision.

### Gaps
- No independent replication of either model.
- Calibration of the AXONVERTEX probabilities is explicitly unmeasured.
- No small model predicts CVSS v4.0 vectors; CIRCL only reads v4.0 base scores as labels.

## Role 5: Which models classify phishing URLs, domains, DGA and lookalike domains?

### Takeaway
1. **CrabInHoney/urlbert-tiny-v4-phishing-classifier**: 3.7M params, Apache-2.0, sub-millisecond-class on CPU.
2. Its 4-class sibling, **urlbert-tiny-v4-malicious-url-classifier** (benign/defacement/malware/phishing).
3. **pirocheto/phishing-url-detection** (LinearSVM, ONNX, ROC-AUC 0.987) as a deterministic backup.
4. **Reynier/modernbert-dga-detector** for DGA.

All metrics are self-reported random-split results on public Kaggle/HF datasets and will overstate real-world accuracy. For lookalike or typosquat detection no usable open model exists: the Anvilogic models are gated and unused. Use deterministic permutation and edit-distance logic.

### Cited Findings

| Repo id | Created | Arch / params | License | Labels | Data | SR metrics |
|---|---|---|---|---|---|---|
| [CrabInHoney/urlbert-tiny-v4-phishing-classifier](https://huggingface.co/CrabInHoney/urlbert-tiny-v4-phishing-classifier) | 2025-03-30 | BERT-tiny, 3.69M | Apache-2.0 | LABEL_0=good, LABEL_1=phishing (mapping only in the card's example) | [ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset) urls.json | Accuracy 0.9907, P 0.9945, R 0.9855, F1 0.9900 |
| [CrabInHoney/urlbert-tiny-v4-malicious-url-classifier](https://huggingface.co/CrabInHoney/urlbert-tiny-v4-malicious-url-classifier) | 2025-03-30 | 3.69M (14.8 MB) | Apache-2.0 | 4 classes (benign, defacement, malware, phishing) as LABEL_0..3 | [Kaggle Malicious URLs dataset (sid321axn)](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) | Accuracy 0.9922; phishing F1 0.9734, malware F1 0.9845 |
| [pirocheto/phishing-url-detection](https://huggingface.co/pirocheto/phishing-url-detection) | 2023-11-17 | LinearSVM (sklearn), ships `model.onnx` | MIT | phishing probability | pirocheto/phishing-url | ROC-AUC 0.9868, accuracy 0.9486, F1 0.9486. The card recommends ONNX over pickle |
| [ealvaradob/bert-finetuned-phishing](https://huggingface.co/ealvaradob/bert-finetuned-phishing) | 2023-12-20 | bert-large-uncased, 336M | Apache-2.0 | benign / phishing | URLs, emails, SMS and HTML from ealvaradob/phishing-dataset | Accuracy 0.9717, P 0.9658, R 0.9670, FPR 0.0249 |
| [kmack/malicious-url-detection](https://huggingface.co/kmack/malicious-url-detection) | 2024-04-23 | DistilBERT, 67.0M | Apache-2.0 | BENIGN / MALWARE | kmack/Phishing_urls | **No metrics** |
| [protectai/codebert-base-Malicious_URLs-onnx](https://huggingface.co/protectai/codebert-base-Malicious_URLs-onnx) | 2023-11-12 | CodeBERT, ONNX | no license tag | phishing / benign / defacement / malware | Kaggle sid321axn | Card states "THIS PROJECT HAS BEEN ARCHIVED" (llm-guard) |
| [r3ddkahili/final-complete-malicious-url-model](https://huggingface.co/r3ddkahili/final-complete-malicious-url-model) | 2025-01-21 | BERT-base, 109.5M (LoRA) | Apache-2.0 | 4 classes as LABEL_0..3 | Kaggle, ~651k URLs | 98% validation accuracy, F1 0.965. The card's code uses a placeholder model name |
| [Reynier/modernbert-dga-detector](https://huggingface.co/Reynier/modernbert-dga-detector) | 2025-08-19 | ModernBERT-base, 149.6M | Apache-2.0 | 0=legit, 1=DGA (no id2label in config) | "Domain names dataset" (unspecified) | Accuracy 0.9658 ± 0.0153, F1 0.9579, FPR 0.0267. "Query Time 0.1226 ± 0.0253 in CPU" (units unstated) |
| [Anvilogic/CE-Typosquat-Detect](https://huggingface.co/Anvilogic/CE-Typosquat-Detect), [Anvilogic/Embedder-Typosquat-Detect](https://huggingface.co/Anvilogic/Embedder-Typosquat-Detect) | 2024-11-08 | CANINE-c, 132M | MIT | typosquat pair scoring | Anvilogic typosquat training sets | **Gated (manual)**; 2 and 0 downloads |

- **Email models (out of scope for URLs):** [cybersectony/phishing-email-detection-distilbert_v2.4.1](https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1) (DistilBERT 67M, Apache-2.0, 304k downloads) and [ptouch/phishing-distilbert-cyber207](https://huggingface.co/ptouch/phishing-distilbert-cyber207) (no license, no labels in config) are the most-downloaded phishing models.
- **Homoglyph / lookalike search:** an HF search for "homoglyph" found one LLM repo; "dnstwist" found nothing (HF API search, 2026-10-31).
- **urlbert-tiny-v4 limits:** `max_position_embeddings` is **64**, `model_max_length` is 64, `vocab_size` is 400, there are 8 layers with hidden size 192, and `id2label` is absent ([config.json](https://huggingface.co/CrabInHoney/urlbert-tiny-v4-phishing-classifier/raw/main/config.json)).
  - MEASURED: passing `max_length=512` crashed with "The size of tensor a (512) must match the size of tensor b (64)". Inputs must be truncated to 64 tokens, so long URLs are judged on their first ~64 tokens only.
  - Latency was not measured because of this crash; the estimate is under 2 ms per URL given the 3.7M-param, 8×192 architecture.

### Inferences
- **Speed:** urlbert-tiny-v4 is about 40× smaller than BERT-base, so expect well under 5 ms per URL on this CPU (estimate, unless measured below). It is the only model here cheap enough to score every URL and domain in a feed.
- **Dataset artefacts:** the two common training sets (ealvaradob, Kaggle sid321axn) are aggregations of older public lists with random splits. Accuracy of about 99% will not hold on fresh Indian-government-themed phishing. Use the score as one feature in risk scoring, not as a verdict.
- **Lookalikes:** implement deterministic checks against a protected-domain list (for example gov.in / nic.in brand terms): Damerau-Levenshtein distance, a homoglyph/IDN confusables table, and dnstwist-style permutations. Optionally add urlbert scores. This is faster, explainable and needs no gated model. (The tool suggestion is an inference; dnstwist was not verified this session.)
- **DGA:** the Reynier model's training data is unspecified. Treat it as experimental, or use a character n-gram entropy heuristic.

### Gaps
- No small URL or lookalike model with an evaluation on a temporal or out-of-distribution split was found.
- The Reynier DGA dataset and latency units are unknown.
- The Anvilogic typosquat models' metrics could not be read, because the cards are gated.

## Role 6: Which models handle log/network anomaly and C2 beacon detection, and which time-series foundation models can forecast signal volumes on Windows CPU?

### Takeaway
- **Logs, network and C2:** no credible, evaluated, pretrained small model exists on HF. Every candidate is a hackathon or student model or an unevaluated single-author release (for example C2Sentinel). Build these with classical, deterministic methods: periodicity/jitter scoring for beacons and IsolationForest over parsed log templates.
- **Forecasting:**
  1. **amazon/chronos-2** (120M, Apache-2.0, `pip install chronos-forecasting`, CPU-supported). The easiest and strongest option on Windows with Python 3.12.
  2. **Chronos-Bolt tiny/small** or **chronos-2-small** (8.7–48M) for very fast CPU runs.
  3. **cisco-ai/cisco-time-series-model-1.0** (255M, Apache-2.0). It is best on observability data (SR), but its PyPI package **requires Python ≥3.11,<3.12** with hard pins, so it needs a separate Python 3.11 venv.

  TimesFM 3.0 and Moirai 2.0 carry non-commercial licenses.

### Cited Findings
**Time-series foundation models (all verified on HF, none gated)**

| Repo id | Publisher | Created | Params | License | Install / CPU notes |
|---|---|---|---|---|---|
| [cisco-ai/cisco-time-series-model-1.0](https://huggingface.co/cisco-ai/cisco-time-series-model-1.0) | Cisco AI / Splunk | 2026-03-03 (mod. 2026-04-24) | 254.75M | Apache-2.0 | See the bullets below this table |
| [cisco-ai/cisco-time-series-model-1.0-preview](https://huggingface.co/cisco-ai/cisco-time-series-model-1.0-preview) | Cisco | 2025-11-19 | 498.8M | Apache-2.0 | Older, continued pretraining from TimesFM. Tech report: [arXiv 2511.19841](https://arxiv.org/abs/2511.19841) |
| [amazon/chronos-2](https://huggingface.co/amazon/chronos-2) | Amazon | 2025-10-30 (mod. 2026-06-05) | 119.5M | Apache-2.0 | Encoder-only, quantile forecasts, covariates. `pip install "chronos-forecasting>=2.0"`; card says it supports "both GPU and CPU inference" and gives ">300 time series forecasts per second on a single A10G" ([card](https://huggingface.co/amazon/chronos-2)). PyPI latest is 2.3.2 (`pip index`, 2026-10-31) |
| [autogluon/chronos-2-small](https://huggingface.co/autogluon/chronos-2-small) | AutoGluon | 2025-12-03 | 27.9M | Apache-2.0 | chronos-forecasting |
| [amazon/chronos-bolt-small](https://huggingface.co/amazon/chronos-bolt-small) / [-tiny](https://huggingface.co/amazon/chronos-bolt-tiny) / [-base](https://huggingface.co/amazon/chronos-bolt-base) | Amazon | 2024-11-25 | 47.7M / 8.65M / 205.3M | Apache-2.0 | T5 encoder-decoder trained on "nearly 100 billion time series observations"; deployable to "both CPU and GPU" ([card](https://huggingface.co/amazon/chronos-bolt-small)) |
| [google/timesfm-2.5-200m-pytorch](https://huggingface.co/google/timesfm-2.5-200m-pytorch) and [google/timesfm-2.5-200m-transformers](https://huggingface.co/google/timesfm-2.5-200m-transformers) | Google | 2025-09-02 / 2026-02-19 | 231.3M | Apache-2.0 | Native `timesfm` package (PyPI latest 3.0.2, requires Python ≥3.10, `[torch]` extra; [PyPI JSON](https://pypi.org/pypi/timesfm/json)). A Transformers port exists (library_name transformers) |
| [google/timesfm-3.0-pytorch](https://huggingface.co/google/timesfm-3.0-pytorch) | Google | 2026-08-24 | 330.7M | **TimesFM Non-Commercial License v1.0** | 20 layers, d=1280. Pretraining includes GiftEvalPretrain, Wikipedia pageviews (cutoff Nov 2023) and Google Trends (EoY 2022). GitHub news: "TimesFM 3.0 is out!" (Aug 2026), with commercial use via BigQuery ML ([GitHub](https://github.com/google-research/timesfm)) |
| [Salesforce/moirai-2.0-R-small](https://huggingface.co/Salesforce/moirai-2.0-R-small) | Salesforce | 2025-08-06 | 11.4M | **CC-BY-NC-4.0** | Install from source (uni2ts, `pip install -e`) |
| [ibm-granite/granite-timeseries-ttm-r2](https://huggingface.co/ibm-granite/granite-timeseries-ttm-r2) | IBM | 2024-10-08 | 0.81M | Apache-2.0 | `granite-tsfm`. Supports minutely and hourly resolutions and needs context 512/1024 (r2.1 relaxes this) ([card](https://huggingface.co/ibm-granite/granite-timeseries-ttm-r2)). [ibm-research/ttm-r3](https://huggingface.co/ibm-research/ttm-r3) is **CC-BY-NC-SA-4.0** |
| [Datadog/Toto-Open-Base-1.0](https://huggingface.co/Datadog/Toto-Open-Base-1.0) | Datadog | 2025-04-30 | 151.3M | Apache-2.0 | Observability-focused; appears in Cisco's comparison |
| [NX-AI/TiRex-2](https://huggingface.co/NX-AI/TiRex-2) | NX-AI | 2026-06-16 | 82.5M | Apache-2.0 | `tirex-2` library; not evaluated here. The original [NX-AI/TiRex](https://huggingface.co/NX-AI/TiRex) has license "other" |

**Cisco Time Series Model 1.0 in detail**
- **Architecture:** decoder-only, multiresolution input. The coarse context is 60× the fine resolution, each context is ≤512 points, the forecast is 128 points with 15 quantiles, and it uses RoPE.
- **Training mix:** internal Splunk Observability metrics 68% (46.2% at 1-hour/1-minute, 21.8% at 5-hour/5-minute), GIFT-Eval pretrain 19.5%, Chronos datasets 3%, synthetic 9.5% ([card](https://huggingface.co/cisco-ai/cisco-time-series-model-1.0)).
- **Install:** `uv venv --python 3.11` then `uv pip install cisco-tsm`. The example selects "cpu" when CUDA is absent, there are no Windows notes, and the commands are Unix-style ([GitHub splunk/cisco-time-series-model](https://github.com/splunk/cisco-time-series-model)).
- **PyPI constraints:** `cisco-tsm` 1.0.2 has `requires_python <3.12,>=3.11` and pins `timesfm[torch]==1.3.0`, `pandas==2.3.1`, `numpy==2.3.1` ([PyPI JSON](https://pypi.org/pypi/cisco-tsm/json)).
- **Not loadable via Transformers:** the HF card declares `library_name: transformers`, but `config.json` model_type is the custom `cisco-time-series-model-1.0`, so `AutoModel` cannot load it.

**Published forecasting metrics (SR, Cisco card; lower MASE is better)**
- **Observability, 1-minute resolution (context 1024, horizon 128):**

  | Model | MASE |
  |---|---|
  | CTSM-1.0 | 0.562 |
  | Toto-Open-Base-1.0 | 0.670 |
  | TimesFM-2.5 | 0.671 |
  | Chronos-2 | 0.674 |
  | TimesFM-2.0 | 0.762 |
  | Chronos-bolt-base | 0.810 |

- **Observability, 5-minute resolution:** CTSM 0.543, Chronos-2 0.620, TimesFM-2.5 0.621.
- **Full GIFT-Eval benchmark:** Cisco's own table lists **Chronos-2 first** (MASE 0.692), ahead of TimesFM-2.5 and CTSM ([card](https://huggingface.co/cisco-ai/cisco-time-series-model-1.0)).

**Log, network and C2 candidates (all weak)**
- [danielostrow/c2sentinel](https://huggingface.co/danielostrow/c2sentinel)
  - Basics: 2026-01-18, MIT, single author. "Built on a fine-tuned LogBERT transformer architecture". Input is connection records (timestamp, dst_ip, dst_port, bytes_sent, bytes_recv, …).
  - Detection: a hybrid of signature, ML, context and whitelist methods.
  - Custom loader: `c2sentinel.py`.
  - Red flags: **0 downloads, 0 likes**, and the README has no accuracy, precision, recall or dataset statement (grep of the README, 2026-10-31).
- [rdpahalavan/bert-network-packet-flow-header-payload](https://huggingface.co/rdpahalavan/bert-network-packet-flow-header-payload): 2023, Apache-2.0, DistilBERT, 24 attack classes (DoS Hulk, PortScan, Heartbleed, …; CIC-IDS/UNSW-style). The README has no metrics.
- [gates04/DistilBERT-Network-Intrusion-Detection](https://huggingface.co/gates04/DistilBERT-Network-Intrusion-Detection): 24 `LABEL_n` classes, no license, no README content checked.
- [Dumi2025/log-anomaly-detection-model-new](https://huggingface.co/Dumi2025/log-anomaly-detection-model-new): RoBERTa 124.6M with an empty template card and no license, despite 1,867 downloads.
- [AungMoonLord/bert-log-anomaly-detection](https://huggingface.co/AungMoonLord/bert-log-anomaly-detection): a Samsung × KBTG hackathon prototype for SQL transaction logs.
- An HF search for "logbert" returned only repos with ≤8 downloads (HF API, 2026-10-31).
- **BeaconClassifier** (GitHub) is a training pipeline over Zeek conn.log, not a shipped model ([GitHub](https://github.com/wspencerhurst/BeaconClassifier), via search snippet only).

### Inferences
- **Forecasting choice:** volumes such as "advisories per day per sector" or "IOC sightings per hour" are short, sparse and daily or hourly. Chronos-2 (or chronos-2-small and chronos-bolt-tiny) is the pragmatic choice:
  - It is pure PyTorch on PyPI, so it should be Python 3.12-compatible; the PyPI requires_python was not checked.
  - It carries no license risk.
  - It handles short contexts and is top-ranked on GIFT-Eval even in Cisco's table.
  - On CPU, a single series at context ≤512 should take roughly tens of milliseconds for the small variants and around 0.1–0.5 s for 120M models (estimate; not measured).
- **Where CTSM wins:** only minute-level observability-style telemetry. It costs a separate Python 3.11 venv, which `uv` can create on Windows, and old pinned timesfm 1.3.0 / numpy 2.3.1. For a 24-hour hackathon it is a "nice-to-have" demo of national-telemetry-grade forecasting, not core.
- **TTM-r2:** tiny and CPU-trivial, but it needs ≥512 historical points at minute or hourly resolution. Daily CVE counts over two years (~730 points) would only just qualify.
- **Beacons:** a deterministic scorer gives explainable output and needs no model weights. Group connections by (src, dst, port), compute inter-arrival mean, coefficient of variation and byte-size regularity, and alert on low jitter with a long duration (the RITA-style approach). Prefer it to the unevaluated C2Sentinel. For logs, use template mining (Drain-style) plus IsolationForest or rare-template counts. Both techniques are inferences from common practice; this session found no evaluated pretrained alternative.
- **Hackathon rules:** they forbid real-network probing, so these components should run on simulated Zeek-like data.

### Gaps
- No CPU latency figures were found for any TSFM on consumer CPUs, and none were measured here.
- Windows-specific issues for chronos-forecasting, timesfm and uni2ts were not tested.
- No HF log-anomaly model with a model card stating its dataset (HDFS/BGL) and metrics was found.

## Role 7: Are there exploit-prediction models with public weights (besides EPSS, which publishes scores only)?

### Takeaway
Effectively no. EPSS's pipeline and training data are not published. The only HF candidate with stated metrics is **sumitp76/cve-exploitability**: TextCNN plus CVSS/CWE MLP, labelled by CISA KEV, ROC-AUC 0.934 (SR). It is a 9-download, single-author model that needs custom loader code. For the demo, use a cached EPSS CSV snapshot plus CISA KEV membership as deterministic features, and optionally that model as a "text-based exploitability prior".

### Cited Findings
- **EPSS FAQ:** "The operational pipeline (data collection, feature generation, model training, scoring infrastructure) is not published". Data partners' telemetry is under agreements "that prohibit redistribution, so the training data cannot be released". "Scores are published freely via CSV download and API with no registration required", and "New scores are published each day" ([FIRST EPSS FAQ](https://www.first.org/epss/faq)).
- **[sumitp76/cve-exploitability](https://huggingface.co/sumitp76/cve-exploitability)**
  - Basics: 2026-06-14, MIT, library "pytorch". Predicts P(exploited in the wild); positive label = CISA KEV, negatives sampled from NVD.
  - Results (SR, held-out):

    | Model | ROC-AUC | PR-AUC |
    |---|---|---|
    | TextCNN + CVSS fusion (this model) | 0.934 | 0.763 |
    | CVSS score only | 0.746 | 0.316 |
    | Structured logistic regression | 0.819 | 0.440 |

  - Card limitations: "KEV is a weak/incomplete label; the training class prevalence is inflated versus the real-world (<1%)".
  - Loading executes the downloaded `hf_model.py`.
- **Other HF candidates with no usable documentation:**
  - [iashour/CANDLE_epss](https://huggingface.co/iashour/CANDLE_epss): MPNet-based custom `EPSSPredictor`, 109.6M, MIT, empty README.
  - [TNIZZELL/exploit_classifier_model](https://huggingface.co/TNIZZELL/exploit_classifier_model): BERT, 5 `LABEL_n` classes, no README.
  - [conff/qwen_finetune_epss_score](https://huggingface.co/conff/qwen_finetune_epss_score): Qwen fine-tune, not small or encoder (HF search, 2026-10-31).
- **Research found without weights:**
  - ICSE 2025 journal-first paper on early exploitability prediction from just-disclosed CVE records ([conf page](https://conf.researchr.org/details/icse-2025/icse-2025-journal-first-papers/24/Early-and-Realistic-Exploitability-Prediction-of-Just-Disclosed-Software-Vulnerabilit)).
  - "Rewiring transformers for exploit likelihood prediction" (2026, AIP Conf. Proc., not open access) ([listing](https://zuscholars.zu.ac.ae/works/8126)).
  - Both via search snippets; no code or weights located.
- **Forecasting CVE volume, not exploitation:** FIRST Vuln4Cast and Jerry Gamblin's CVEForecast forecast CVE *volume* rather than per-CVE exploitation (search summary; not opened).

### Inferences
- **Recommended exploitability feature:** a deterministic composite, for example `max(EPSS percentile, KEV flag)` with CVSS from Role 4 for un-analysed CVEs. It is explainable to judges and needs no weights.
- **Using sumitp76:** it is only appropriate as an experimental prior. Its KEV-vs-random-NVD negatives make the ROC-AUC optimistic, and its training CVEs "score optimistically" by its own admission.

### Gaps
- No evaluated, open-weight exploit-prediction encoder was found.
- The ICSE 2025 paper's artefacts (code/weights) were not checked.
- The EPSS model version in current CSVs (the "#" header line) was not inspected.

## Do these models load with 2026 `transformers`/`sentence-transformers`, and what gotchas apply (especially on this Windows machine)?

### Takeaway
On transformers 5.22.1 and sentence-transformers 6.2.0, the plain-HF models (ModernBERT, RoBERTa, DeBERTa, BERT) load with standard Auto classes on CPU. MEASURED loading OK: SecureBERT2.0-NER, SecureModernBERT-NER, CyNER-2.0, CyberPeace NER, Sana9 vuln2attack, xamxte CWE, CIRCL severity, SecureBERT2.0-biencoder.

The real blockers on *this* PC are environmental:
- user-site **transformers 4.45.0**, too old for ModernBERT;
- a broken TensorFlow install that crashes `sentence_transformers` import;
- a stale **torchaudio 2.5.1** that crashes `transformers` v5 import alongside torch 2.11;
- a stale **Brotli 1.1.0** that breaks Hub downloads of many repos;
- a nearly full **C: drive** (8.9–22 GB free and fluctuating), where the HF cache lives by default.

Use a dedicated venv and set `HF_HOME` to D:.

### Cited Findings
- **Library versions (PyPI, via `pip index versions` on 2026-10-31):** transformers 5.22.1 (latest), sentence-transformers 6.2.0, timesfm 3.0.2, chronos-forecasting 2.3.2, gliner 0.2.29.
- **Transformers v5:** dropped TensorFlow and Flax, PyTorch only. The v5 release candidate was announced 2025-12-01 ([HF blog](https://huggingface.co/blog/transformers-v5)). Third-party summaries also mention the removal of the slow/fast tokenizer split and of some pipelines ([DEV Community](https://dev.to/prabhakar_chaudhary_7afe4/transformers-v5-what-actually-changed-in-hugging-faces-biggest-library-overhaul-in-five-years-52i); [AssemblyAI](https://www.assemblyai.com/blog/hugging-face-transformers-tutorial)).
- **Card example code that breaks on v5:**
  - The SecureBERT2.0-NER card's example uses `TFAutoModelForTokenClassification` and says "Framework: TensorFlow" ([card](https://huggingface.co/cisco-ai/SecureBERT2.0-NER)). The repo ships `model.safetensors`, and MEASURED it loads fine with the PyTorch `AutoModelForTokenClassification`. Use that, not the card snippet.
  - The SecureBERT2.0-cross_encoder card's code loads `"cisco-ai/SecureBERT2.0-cross-encoder"` with a hyphen ([card](https://huggingface.co/cisco-ai/SecureBERT2.0-cross_encoder)). The real repo id uses an **underscore**: `cisco-ai/SecureBERT2.0-cross_encoder` (HF API).
- **ModernBERT version floor:** ModernBERT models (all SecureBERT2.0-*, SecureModernBERT-NER, AXONVERTEX CVSS, the Reynier DGA model, NilHRH) need transformers ≥4.48, the first release with ModernBERT ([HF ModernBERT blog](https://huggingface.co/blog/modernbert)). Qwen3-Embedding's config was saved with transformers 4.51.3 (config.json).
- **This machine (MEASURED, 2026-10-31):**
  - **Python and torch:** system Python 3.12.7 with torch 2.11.0+cpu and **transformers 4.45.0** in user site-packages (`C:\Users\sayan\AppData\Roaming\Python\Python312`).
  - **Stale transformers remnant:** pip reports an "invalid distribution ~ransformers" left over from an interrupted install.
  - **Broken TensorFlow:** `import sentence_transformers` fails with "module 'tensorflow' has no attribute 'data'".
  - **Stale torchaudio:** in a fresh venv with transformers 5.22.1, `import transformers`' audio utilities import the user-site torchaudio 2.5.1. It fails with `OSError: [WinError 127] … libtorchaudio.pyd`. Installing `torchaudio==2.11.0` from the PyTorch CPU index fixed it.
  - **Disk:** C: is 952 GB with only **8.9 GB free** at first check. During one 1.58 GB model download it dropped to **335 MB free** (hf_xet "There is not enough space on the disk (os error 112)"), presumably from other processes sharing the drive; later it was 17–22 GB. D: has 830 GB free.
  - **Brotli download failure:** downloads of several repos (Sana9, CrabInHoney urlbert, PranavaKailash CyNER-2.0, xamxte) failed repeatably with `TypeError: process() takes no keyword arguments`, even with 19 GB free.
    - The innermost frame is `httpx2/_decoders.py:191 decode → self._decompress(data, output_buffer_limit=...)`, called from huggingface_hub 2.4.0 `http_get`.
    - Cause: the user-site **Brotli 1.1.0** (`AppData\Roaming\Python\Python312\site-packages\brotli.py`) does not accept the `output_buffer_limit` keyword.
    - `HF_HUB_DISABLE_XET=1` did **not** help. **`pip install -U Brotli` (→ 1.2.1) fixed it.**
    - Repos that happened to download without brotli-encoded responses (Cisco, CyberPeace, CIRCL, attack-vector) worked even before the fix.
- **Gated repos in this census:**
  - `google/embeddinggemma-300m` (manual), the Anvilogic typosquat models (manual).
  - Cisco Foundation AI's small LLMs [fdtn-ai/antares-350m](https://huggingface.co/fdtn-ai/antares-350m) (352M) and [fdtn-ai/antares-1b](https://huggingface.co/fdtn-ai/antares-1b) (1.84B), gated "auto". These are generative, so out of scope, but they are Cisco's newest small security models (2026-07-21).
  - Everything else listed is ungated (HF API `gated` field).
- **Custom or remote code required:**
  - nomic-embed (`trust_remote_code`)
  - AXONVERTEX CVSS (`cvss_predictor.py`)
  - sumitp76 exploitability (`hf_model.py`)
  - C2Sentinel (`c2sentinel.py`)
  - bziemba CVSS-CWE (`model_class.py`)
  - Cisco TSM (`cisco-tsm` package)
  - CIRCL bi-encoder (custom scoring, standard `AutoModel`)
  - CyberPeace Cybersecurity-Knowledge-Graph (custom `model.py` / `.pt` files) ([repo](https://huggingface.co/CyberPeace-Institute/Cybersecurity-Knowledge-Graph))
  - (HF file listings)
- **Pickle-only weights (`pytorch_model.bin`, `.joblib`, `.pkl`):** basel/ATTACK-BERT, AI4Sec/cyner-xlm-roberta-base, ealvaradob/bert-finetuned-phishing, ehsanaghaei/SecureBERT, ibm-research/CTI-BERT, alirezaaminzadeh (joblib), pirocheto (pickle, with ONNX alternative) (HF file listings). The pirocheto card itself warns that pickle allows code injection ([card](https://huggingface.co/pirocheto/phishing-url-detection)).
- **Missing label maps:** models whose config ships only `LABEL_n` names, so you must hardcode the mapping from the card:
  - urlbert-tiny-v4 (both variants)
  - xamxte CWE (`cwe_label_map.json`)
  - TTPXHunter (no mapping published)
  - r3ddkahili, cybersectony
  - Reynier DGA (config has no labels)
  - (config.json via HF)

**Latency summary (MEASURED; fp32, 24 threads)**

| Model | Arch | ~short text bs1 | 512 tok bs1 | batch 16 short |
|---|---|---|---|---|
| CIRCL severity | RoBERTa-base | 22.7 ms | 182 ms | 160 ms |
| CyberPeace SecureBERT-NER | RoBERTa-base | 25.1 ms | 172 ms | 204 ms |
| SecureBERT2.0-NER | ModernBERT-base | 45.1 ms | 234 ms | 323 ms |
| SecureBERT2.0-biencoder (ST `encode`) | ModernBERT-base | 132 ms | 326 ms (~600 tok) | 854 ms |

| Model | Arch | ~short text bs1 | ~500 tok bs1 | batch 16 short |
|---|---|---|---|---|
| Sana9 securebert-vuln2attack-flat | RoBERTa-base | 16.0 ms (15 tok) | 147 ms (452 tok) | 77 ms |
| SecureBERT2.0-NER (2nd run) | ModernBERT-base | 38.4 ms | 244 ms (512 tok) | 313 ms |
| CyNER-2.0 | DeBERTa-v3-base | 63.1 ms | 238 ms (477 tok) | 275 ms |
| SecureModernBERT-NER | ModernBERT-large, 396M | 104.6 ms | 607 ms (492 tok) | 870 ms |

First-load times including download on this connection: 1.7–54 s per model (the 1.58 GB SecureModernBERT took about 54 s).

**Card-vs-reality loading notes (MEASURED):**
- **Aggregation:** ModernBERT NER needs `aggregation_strategy="first"`, and DeBERTa CyNER-2.0 needs `"simple"`.
- **Sana9:** `use_fast` is moot on v5.
- **Label maps:** xamxte needs `cwe_label_map.json`.
- **Sequence limits:** urlbert-tiny is limited to 64 tokens.
- **ModernBERT runtime:** the attention implementation used on CPU was `sdpa`.

### Inferences
- **Setup recipe for the hackathon box:**
  1. `py -3.12 -m venv D:\DECOY\.venv`.
  2. Install `torch` (CPU wheel, or the CUDA wheel if the LLM shares the env), `transformers>=5`, `sentence-transformers>=6`, `chronos-forecasting`, `onnxruntime`.
  3. Run `pip install -U Brotli` (or `pip uninstall tensorflow torchaudio` from user site), so the user-site Brotli, TensorFlow and torchaudio stop interfering. Then set `HF_HOME=D:\hf_cache` and `USE_TF=0`.
  4. Pre-download all chosen repos while online and pin revisions.
  5. At demo time, set `HF_HUB_OFFLINE=1` so runs are offline and deterministic.
  6. Keep Cisco TSM (if used) in a separate `uv`-made Python 3.11 venv.
- **Throughput:** a full per-advisory pass costs roughly 0.5–1.5 s of CPU per advisory, which is adequate for a demo processing hundreds of cached advisories. That pass covers NER on about four 512-token chunks, embedding, three taxonomy classifiers and two CVSS/severity models (inference from the measured per-forward costs). Batching gives a 2–4× throughput gain, per the bs16 vs bs1 timings above.
- **ModernBERT runtime:** on CPU with sdpa attention, ModernBERT does not need flash-attn on Windows (MEASURED; the attention implementation reported "sdpa").

### Gaps
- ONNX or int8-quantised CPU speeds were not measured. They would likely give a 2–3× speedup, but that is unverified.
- Qwen3-Embedding-0.6B, bge-m3, the cross-encoder, AXONVERTEX CVSS and urlbert-tiny latency were not measured: the first was skipped for disk space, and urlbert crashed at 512 tokens (see above). Those figures are estimates.
- The entity spot checks used only two sentences. They are anecdotal, not an evaluation.
- GLiNER, chronos-forecasting, timesfm and cisco-tsm were not installed or tested on this machine.
