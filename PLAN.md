# D3COY 1.0 · PS 01: Build Plan

> **Decision record v2 (Sat 31 Oct, 16:10).** This record overrides the rest of this file where they conflict.
> It reconciles three inputs:
> - our case-study report (`reports/National cyber early warning case study.md`)
> - the model research and local tests
> - the teammate brief (`research-summary.md`)
>
> | Topic | Decision | Why |
> |---|---|---|
> | Judging | Optimise for the published criteria: quality and originality · technical understanding of the problem statement · feasibility and impact · USP and future scope | Unstop page (teammate brief) |
> | Exploit predictor (custom LightGBM) | **Deferred to P3.** The scorecard instead shows a *signal-fusion backtest*: our evidence rules vs EPSS alone vs CVSS alone, on 2026 KEV entries | The flagship CVE was in KEV on day 0, so a predictor shows no lead there. It also costs 2.5 h and carries leakage risk. EPSS was 0.003 on KEV-listed CVE-2026-111357 |
> | Tier | Comes from an SSVC-style decision tree, mapped to the CERT-In Blueprint deadlines (12 h / 1 d / 3 d / 5 d) and BOD 26-04 | Both research streams agree; it's auditable |
> | Score (ranking) | `Risk = 100 · R · K · (0.55·L + 0.30·S + 0.15·V)`. L has evidence floors (KEV, active exploitation). Confidence is computed separately | R gates cleared assets to 0, which a purely additive score cannot do. The inner sum keeps the waterfall readable |
> | Exposure | Reconcile three sources (NVD, the vendor's CVE record, description text) with vendor-aware version comparison. **Built and tested: 21 tests, real Ivanti data** | Only 21% of Oct-2026 CVEs have NVD product data (measured) |
> | Core LLM | Foundation-Sec-1.1-8B-Instruct (stays loaded). Challenger: MiST-8B (19 Oct 2026), under test now. Foundation-Sec-8B-Reasoning runs in batches, for Critical alerts only | Strict metric: Foundation-Sec few-shot ties qwen3:8b at 65%. Security-tuned with no loss |
> | Classifiers | CVSS and CWE from TF-IDF classifiers (CWE top-1 77.5%, CVSS mean error 0.86), used only when the vendor's CVE record has no vector | These beat every LLM in our local tests |
> | Embeddings | SecureBERT 2.0 bi-encoder | User rule: core models must be security-specialised. torch is already installed |
> | Data sources | Add CIRCL Vulnerability-Lookup sightings, the Exploit-DB CSV and Nuclei template index (metadata only), the CISA advisories RSS and CTID's KEV→ATT&CK mappings. CERT-In advisories are simulated and labelled SIM because the site is unreachable from the venue | Teammate brief plus our reachability tests |
> | Trust layer | Hash-chained evidence ledger, human approve/override, a false-positive button, "AI-generated" labels | ISACA digital-trust theme; matches the H3lium competitor's polish |
> | Actions | A closed catalogue mapped to ATT&CK mitigations, D3FEND, NIST CSF 2.0 and CIS v8.1, plus KEV's `requiredAction` quoted word for word | The LLM can't invent control IDs |
> | Story | Pitch opens with C-Edge 2024 (about 300 banks hit through a Jenkins CVE, CVE-2024-23897). Live demo is the real Oct-2026 Ivanti three-CVE chain, each event badged REAL or SIM | Indian impact plus fresh, real data |
> | Decoy grid | Kept at P1, after the main flow works. Simulated, calibrated to GreyNoise data, with a chance baseline | Event theme; strongest early signal |
> | UI | React + Vite + Tailwind + shadcn/ui + Recharts on Node 26 LTS | Fastest route to a polished dashboard |
> | Accuracy metric | Strict `token_sort_ratio ≥ 90`. The final number comes from **282 KEV 2026 records** against KEV's vendorProject/product fields | The lenient metric overstated accuracy by 20–30 points |

AI-based national cyber threat early warning system. Plan written at 14:30 on Sat 31 Oct. Hacking ends at **13:00 on Sun 1 Nov**, and the elimination round starts at the same time.

Every source, model and tool listed as working below was checked live on this laptop and this network at about 14:30 today.

---

## 0. The pitch

**Most teams will build:** a dashboard over NVD, with a cloud chatbot summarising CVEs and a risk score that is just CVSS.

**We build:** a national early warning system that **predicts** which vulnerabilities will be exploited, **listens** for attackers on a grid of decoy sensors, **links** weak signals across feeds, logs and assets into one high-confidence warning, and **explains** every score. It runs fully offline on one laptop GPU, so no national threat data leaves the machine.

**One sentence for the judges:**
> "Reactive tools tell you that you were hit. Ours tells you, days earlier, *who* is about to be hit, *why*, and *what to do*. Every number is explained and it runs entirely on-premise."

### Design principles (every component is checked against these)

| Principle | What it means in the build |
|---|---|
| **State of the art, proven by measurement** | Use only the latest *verified* 2025–2026 models and methods. Each one is chosen by research plus a local benchmark against NVD ground truth. Every "breakthrough" claim on a slide has a measured number behind it. |
| **Model-agnostic** | A role-based model registry (`extract`, `narrate`, `reason`, `copilot`, `translate`, `embed`, `ner`, `classify`) is configured by name. Any Ollama model, GGUF file or encoder can be swapped in without code changes. The bake-off picks what fills each role. |
| **Source-agnostic** | Every feed is a connector plugin that maps into one standards-based model: STIX 2.1 objects, ATT&CK, CVSS/SSVC, CPE 2.3. Adding a source (CERT-In, MISP, TAXII, honeypot) means writing one connector, not changing the core. |
| **Dynamic** | Scoring weights, thresholds, sector definitions, source-reliability ratings and stories live in config. Risk is recalculated live whenever a new signal arrives, which is what drives the early-warning timeline. |
| **Robust** | Offline-first snapshots. JSON-schema-constrained output with validation, retries and template fallbacks. Deterministic replay. Graceful degradation: no GPU → encoders and templates; model missing → next model in that role. |
| **Deployment-agnostic** | The same code runs on one laptop (demo) or as services: a FastAPI backend, any OpenAI-compatible or Ollama endpoint, and SQLite that can move to Postgres. |

### What sets us apart

| # | Feature | Why it wins | What others will have |
|---|---|---|---|
| 1 | **Exploit predictor, tested on past data** | We can quantify "early": "Our model would have flagged X% of CISA KEV entries on the day they were published, a median of N days before CISA listed them." | Nothing predictive. CVSS only |
| 2 | **Decoy sensor grid** (simulated honeypots) | Fits the event name. Attackers scan decoys *before* they hit real organisations, which is literally early warning | – |
| 3 | **Correlation that escalates** | Three weak signals (an advisory, an IOC feed, a beacon in our logs) become one Critical alert, shown live | Separate lists that are never linked |
| 4 | **Early-warning timeline** for each threat | Plots risk over time with the signal that raised it at each step, so "early" is something you can see | – |
| 5 | **Fully explained score** | A waterfall of the 4 factors the brief names, plus confidence from source-reliability ratings. The language model explains the score but never sets it | A black-box number |
| 6 | **Runs fully offline (sovereign AI)** | Local models on an RTX 4070 laptop. Zero bytes sent to any cloud. Resonates with C-DAC and with national security | Calls to cloud model APIs |
| 7 | **Built for India** | The 6 NCIIPC critical-infrastructure sectors, a CERT-In 6-hour incident report draft, STIX 2.1 export, Hindi and Marathi alerts | Generic |
| 8 | **Analyst assistant that cites its sources** | Its database queries are visible on screen and every claim links to a record | A chatbot that can make things up |

---

## 1. The demo (what the judges see)

**Elimination round (~3 min):**
1. **(0:00) Problem, using a real number:** NVD published **17,369 CVEs in October 2026** alone, about 560 a day (checked live). No team can triage that.
2. **(0:20) Situation room:**
   - a live feed of incoming threat signals;
   - the national threat level;
   - a sector × severity heatmap;
   - "17,369 CVEs → 41 relevant to our 15 organisations → 6 warnings".
3. **(0:50) The main story, "Silent Gateway", run with the replay control:**
   - The decoy grid sees scanning for a VPN-appliance flaw. Status: *Watch*.
   - The CVE is published. The predictor scores it at 0.83 and two power-sector organisations run the affected version. Status: **High**.
   - A command-and-control (C2) IP appears in the Feodo feed. The same IP is beaconing every 60 seconds from one of those appliances. Status: **CRITICAL – likely compromise**.
4. **(1:50) Open the alert:**
   - the AI summary;
   - the score waterfall: why it scored 91;
   - the evidence list, every item citing a source;
   - the early-warning timeline;
   - recommended actions (patch, block, investigate);
   - **CERT-In report draft** and **STIX export** buttons;
   - a one-click Hindi version.
5. **(2:30) Proof:** the backtest chart (lead time over CISA) and "100% local AI, 0 cloud calls".

**Final judging (~5–7 min):** the same flow, then:
- the threat graph explorer, showing how far the compromise could spread;
- an assistant question: *"Which BFSI orgs are exposed to the phishing campaign and what should they block?"*;
- the "How it works" page with model metrics.

The demo is **deterministic**. Every event in a story is timestamped and played back by a replay engine at 60× speed, so it looks the same every time.

---

## 2. Architecture

```
 ┌──────────────── SOURCES (saved to data/raw so the demo runs offline) ───────┐
 │ CISA KEV · NVD 2.0 (yearly + recent) · EPSS · CISA Vulnrichment (SSVC)      │
 │ Feodo Tracker (C2 IPs) · OpenPhish · MITRE ATT&CK (STIX)                    │
 │ SIMULATED: CERT-In-style advisories · asset inventory (15 orgs, 6 sectors)  │
 │            firewall/DNS/auth logs · decoy sensor grid hits                  │
 └───────────────┬─────────────────────────────────────────────────────────────┘
                 ▼
  INGEST + NORMALISE ─► one common record shape (Signal / Vuln / IOC / Event)
                 ▼
  ┌──────────────── AI ANALYSIS (all local) ──────────────────────────────┐
  │ A. Extraction: regex (IOC/CVE) + LLM JSON-schema → vendor/product/    │
  │    version/attack type/actor                                          │
  │ B. Asset matching: CPE + version-range → exposure                     │
  │ C. Exploit predictor (LightGBM, publish-time features) + SHAP          │
  │ D. Emerging-trend detector (burst z-score per vendor/CWE/technique)   │
  │ E. Campaign clustering (embeddings + shared IOCs → HDBSCAN)            │
  │ F. ATT&CK mapping (embedding retrieval + LLM re-rank) → mitigations    │
  │ G. Log analytics: IOC sightings · beacon detector · IsolationForest    │
  │ H. Decoy grid: scan bursts per CVE/port → pre-exploitation signal      │
  └───────────────┬───────────────────────────────────────────────────────┘
                 ▼
  CORRELATION GRAPH (networkx): CVE–product–asset–org–sector–IOC–campaign–technique
                 ▼
  SCORING ENGINE (fixed formula, explainable) ─► tier, SLA, confidence
                 ▼
  LLM NARRATOR (grounded, every claim cited) ─► summary · why · actions · Hindi/Marathi
                 ▼
  FastAPI + SSE ─► React "Situation Room" ─► workflow · CERT-In draft · STIX export
```

**Stack** (everything listed is already installed):
- **Backend:** Python 3.12, FastAPI and uvicorn, SQLite, pandas, scikit-learn, LightGBM, networkx, httpx.
- **Frontend:** React, Vite, TypeScript, Tailwind, ECharts for charts, react-force-graph for the graph. Node 22 and pnpm are installed.
- **Environment:** a uv virtual environment on the D: drive.
- **Models:** Ollama 0.20.0, called through its REST API. JSON-schema structured output uses `format`, and the assistant uses tool calling.

---

## 3. Data sources (checked live at 14:30)

| Source | Status | Used for |
|---|---|---|
| CISA KEV JSON | ✅ 1,766 entries, updated 2026-10-30 | Exploited-in-the-wild label, `dateAdded` for the backtest, `knownRansomwareCampaignUse` |
| NVD yearly JSON feeds (`nvdcve-2.0-YYYY.json.gz`, 2025 is 25.7 MB) | ✅ | Training data for the predictor: CVSS, CWE, CPE, references |
| NVD API 2.0 | ✅ 17,369 CVEs in Oct 2026 | Recent CVEs and the live headline number |
| EPSS bulk CSV (`epss.empiricalsecurity.com/epss_scores-current.csv.gz`) | ✅ 2.8 MB | Current exploitation probability |
| CISA Vulnrichment (raw GitHub per CVE) | ✅ e.g. CVE-2024-3400 → active / yes / total | SSVC fields: Exploitation, Automatable, Technical Impact |
| Feodo Tracker C2 IP blocklist | ✅ | Real IOCs for the beaconing story |
| OpenPhish feed | ✅ | Real phishing URLs for the BFSI lookalike-domain story. **Shown defanged** |
| MITRE ATT&CK enterprise STIX | ✅ | Techniques, mitigations, mapping |
| ThreatFox / URLhaus exports | ❌ 410 without a key | Optional: get a free abuse.ch Auth-Key (P2) |
| CERT-In website | ❌ timed out twice from the venue | **Simulated** advisories in CERT-In's CIVN-2026-xxxx style, clearly labelled as simulated |

**The first job is to save a snapshot of everything above** to `data/raw/` (`scripts/snapshot_feeds.py`). The demo then runs fully offline from that snapshot, and a live refresh is just a bonus.

---

## 4. Local AI stack

**Hardware:**
- CPU: i9-14900HX, 24 cores / 32 threads.
- RAM: 32 GB, with about 8 GB free.
- GPU: **RTX 4070 Laptop with 8 GB VRAM**, about 0.9 GB of which is already in use by the display.
- CUDA: 13.1.
- **C: has only 23.8 GB free**, so all models must go on the D: drive.
- `torch` is the CPU-only build, so all GPU inference goes through Ollama.

> **Status at 14:45:** the installed Ollama is **0.20.0**, and it refuses `qwen3.5` with HTTP 412, "requires newer Ollama".
> - The official portable **v0.40.13** is downloaded and checksum-verified at `D:\ollama\v0.40.13\`. It is not running yet because it needs your approval.
> - Until then we use **`qwen3:4b` / `qwen3:8b`**, which are already pulled and work on 0.20.0.
> - Already pulled: `qwen3:4b` (2.5 GB), `qwen3:8b` (5.2 GB), `Foundation-Sec-1.1-8B` (4.9 GB), `qwen3-embedding:0.6b` (0.6 GB).

**Models (all tags checked on ollama.com and Hugging Face):**

| Role | Primary choice | Size | Notes |
|---|---|---|---|
| Main model for bulk extraction and classification | `qwen3.5:4b` (q4_K_M) | 3.3 GB | Stays loaded with the embedding model. Supports vision, tools, thinking and 256K context |
| Narratives, assistant, deep analysis | `qwen3.5:9b` (q4_K_M) | 6.6 GB | Tight in 7.2 GB of free VRAM. Use `num_ctx` 8192 with a q8 KV cache. Loaded on demand |
| Security specialist (bake-off contender) | `hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` | ~4.9 GB | Official Cisco Foundation AI security model, based on Llama 3.1. Use it if it wins on ATT&CK mapping and extraction, since it makes a strong pitch point |
| Embeddings | `qwen3-embedding:0.6b` | 0.64 GB | Multilingual. Used for clustering, ATT&CK retrieval and the assistant's retrieval |
| Fallback | `granite4.2` | 5.3 GB | Strong tool calling |

**Ollama setup** (do this **before** pulling any model):
```
setx OLLAMA_MODELS D:\ollama\models
setx OLLAMA_FLASH_ATTENTION 1
setx OLLAMA_KV_CACHE_TYPE q8_0
setx OLLAMA_KEEP_ALIVE 30m
```
Restart Ollama after setting these.

The existing `sarvam-1` and `navarasa-2b` models stay on C:. Copy them across only if the Indic bake-off needs them; sarvam-1 is a base model, not instruction-tuned.

**Free up VRAM:**
- Windows Settings → Display → Graphics: set VS Code and the browser to "Power saving", which uses the Intel integrated GPU.
- Keep the laptop plugged in, on the High-performance power plan.

**Bake-off (45 min, on our real task):**
- **Test set:** 30 NVD CVE descriptions, using their CPE vendor/product as ground truth.
- **Contenders:** qwen3.5:4b, qwen3.5:9b, Foundation-Sec-1.1-8B and granite4.2.
- **Measures:**
  - JSON-schema validity, as a %;
  - vendor and product exact match, as a %;
  - tokens per second and seconds per item;
  - quality of 3 alert narratives, judged by eye;
  - Hindi and Marathi translation of one alert, judged by eye.
- **Result:** pick a winner for each role and record the numbers in `docs/MODEL_CARD.md`. They become slide content.

**Rules for using the language models:**
1. **The model never sets the score.** Scoring is a fixed formula, and the model only explains it.
2. **Every model output is constrained to a JSON schema**, with temperature 0.
3. **Every claim must cite a fact ID** taken from the input facts. A validator rejects any output that cites an unknown ID, and the code then falls back to a template.
4. **Precompute** all alert narratives in a batch, so the dashboard is instant. Live inference is used only for the injected event in the story and for the assistant, both streamed.

---

## 5. AI / ML components

### A. Extraction from text (NLP)
- **Regex:** CVE IDs, IPv4 and IPv6 addresses, domains, URLs, MD5/SHA1/SHA256 hashes. Defang and re-fang each value.
- **LLM with a JSON schema:** `{vendor, product, versions_affected[], fixed_version, vuln_type, attack_vector, threat_actor?, malware?, sectors_targeted[], exploited_in_wild: bool}`.
- **Measure accuracy** against NVD CPE data automatically. That gives a real accuracy figure to quote.

### B. Asset matching (exposure)
- Each simulated asset carries a CPE 2.3 string and a version.
- Match the vulnerability's CPE configurations and version ranges (using `packaging.version`).
- Fall back to fuzzy vendor/product matching with an embedding similarity of at least 0.85, flagged as "probable match".

### C. Exploit predictor: the "early" proof
- **Label:** the CVE appears in KEV within 365 days of publication.
- **Features (only what was known at publication, so no leakage):**
  - each part of the CVSS vector;
  - the CWE;
  - the vendor's earlier KEV count, counting only entries before the publish date;
  - whether the product is "edge" (VPN, firewall, gateway, mail);
  - how many references and which tags (Exploit, Patch);
  - key phrases in the description (RCE, auth bypass, unauthenticated) and a TF-IDF-SVD of the text.
- **Data:** NVD feeds for 2021–2026, about 1k positives. Split by time: train on CVEs published up to the end of 2024, test on Jan 2025 – Apr 2026.
- **Model:** LightGBM, with class weights. `pred_contrib=True` gives per-feature SHAP values for each CVE, which feed the "why" for the predictor.
- **Metrics for the slide:**
  - PR-AUC against two baselines: CVSS ≥ 9, and CVSS score alone;
  - recall@top-2% ("watching 2% of new CVEs catches X% of later-KEV CVEs");
  - **median lead time** between publication and the KEV `dateAdded` date, for the CVEs we caught.
- **Report honestly that some KEV entries are added on day 0**, and show the distribution.
- **Time:** about 2.5 h. It runs on the CPU with a scripted pipeline (`scripts/train_predictor.py`).

### D. Emerging-trend detector
- **Method:** compare weekly counts for each vendor, CWE and ATT&CK technique across KEV additions, NVD and feeds against an 8-week baseline. Flag when z ≥ 3 or the Poisson tail probability is below 0.01.
- **Output:** "Emerging: <vendor> — 4 KEV additions in 14 days vs a baseline of 0.3."
- These are **real data** signals.

### E. Campaign clustering
- **Method:** embed each signal (advisory, IOC context or phishing URL), plus Jaccard overlap of shared IOCs and products, then HDBSCAN (`sklearn.cluster.HDBSCAN`).
- The LLM names each cluster and writes a one-line description of it.
- Phishing gets its own pass: detect lookalike domains of our simulated organisations' domains in OpenPhish using edit distance, homoglyphs and brand tokens.

### F. ATT&CK mapping and grounded recommendations
1. Embed the 600+ ATT&CK technique descriptions once.
2. Retrieve the top 8 techniques for each threat by cosine similarity.
3. The LLM re-ranks them down to the top 3, using a JSON schema.
4. Follow the ATT&CK `mitigates` relationships to get the mitigations.

Recommendations are therefore **taken from ATT&CK, not invented by the LLM.** They are combined with the KEV `requiredAction` and the vendor's fixed version.

### G. Log analytics (on simulated telemetry)
- **IOC sightings:** join firewall and DNS logs against Feodo and OpenPhish indicators.
- **Beacon detector:** for each (source, destination) pair, flag a low coefficient of variation of the time between connections combined with many connections, i.e. regular C2 check-ins. The calculation is cheap and looks impressive.
- **IsolationForest** on per-host-hour features: failed logins, bytes out, distinct destinations, after-hours activity.

### H. Decoy sensor grid (the theme)
- **Setup:** 24 simulated honeypot sensors across regions and sectors.
- **Events:** each hit has a timestamp, source IP, port, path/payload signature and the CVE it targets.
- **Signal:** a burst of scanning for a CVE across at least 3 sensors in 6 h → a pre-exploitation warning to every organisation running that product.
- **Simulated only.** We do not run a real honeypot on the venue network (see the rules).

### I. LLM narrator
- **Input:** a facts JSON containing IDs, score contributions, assets, evidence and mitigations.
- **Output:** `{headline, situation, why_it_matters[], affected[], actions[{type: patch|block|investigate, step, owner, sla}], citations[]}`.
- Translation to Hindi and Marathi is a second pass over the finished English output.

### J. Analyst assistant
- **Model:** qwen3.5 with tool calling.
- **Tools:**
  - `search_threats`
  - `get_alert`
  - `assets_exposed_to(cve|campaign)`
  - `org_risk(org|sector)`
  - `iocs_for(campaign)`
  - `explain_score(alert)`
- **UI:** tool calls are shown on screen and answers cite records.

---

## 6. Scoring model (deliverable 4: "threat scoring approach")

Each factor is a number from 0 to 1, made by combining its sub-signals with a **noisy-OR**: `1 − Π(1 − sᵢ)`. Noisy-OR is easy to explain: each extra signal can only raise the factor, with diminishing returns.

| Factor (from the brief) | Weight | Sub-signals |
|---|---|---|
| **Exploitability (E)** | 0.30 | KEV listed (0.95) · SSVC Exploitation active/PoC (0.9 / 0.6) · EPSS probability · predictor p × 0.8 · decoy scanning seen (0.6) · Automatable = yes (0.3) |
| **Asset criticality (A)** | 0.25 | max over affected assets of tier (crown-jewel 1.0 / high 0.75 / medium 0.5 / low 0.25) × exposure (internet 1.0 / DMZ 0.8 / internal 0.6) × sector (critical-infrastructure 1.0 / other 0.7) |
| **Potential impact (I)** | 0.25 | SSVC Technical Impact (total 1.0 / partial 0.5) or the CVSS C/I/A impact · blast radius (critical assets reachable from the exposed asset) · KEV ransomware use = Known (0.4) |
| **Available evidence (V)** | 0.20 | noisy-OR over independent sources, each weighted by **Admiralty reliability** (A 0.9 … F 0.3) · sighting in our own logs (0.9) |

**Formulas:**
- `Risk = 100 × (0.30E + 0.25A + 0.25I + 0.20V)`
- **Confidence** = V, shown separately.
- **Relevance** = exposure match quality (exact CPE 1.0, probable 0.6, sector-only 0.3).
- **Severity** = the average of E and I.

The three alert criteria in the brief map one-to-one onto these.

**Override rules** (in the spirit of SSVC, and shown in the UI as "rule fired"):
- Active exploitation or KEV, **and** an internet-facing asset with a matching version → score floor 85.
- An IOC sighting on an asset that also has a matching vulnerability → **CRITICAL – likely compromise**, which starts the CERT-In 6-hour clock.

**Tiers and SLAs:**

| Tier | Score | SLA |
|---|---|---|
| Critical | ≥ 80 | Mitigate within 24 h. If there is incident evidence, file the CERT-In report within 6 h |
| High | 60–79 | 72 h |
| Medium | 40–59 | 14 days |
| Watch | < 40, or no asset match yet | Monitoring only. Typical for decoy-grid and emerging-trend warnings |

**Worked example:** the "Silent Gateway" story at its final stage.
- **Inputs:**
  - E = 1 − (1−0.95)(1−0.6)(1−0.66) ≈ 0.99
  - A = 1.0 × 1.0 × 1.0 = 1.0 (power-sector VPN, internet-facing, crown jewel)
  - I = 0.95
  - V = 0.97
- **Result:** Risk ≈ 98, then the override applies → **CRITICAL**.
- **Score history:** the same alert scored 34 when only the decoy grid had seen activity, and 71 once the CVE matched an asset. Those three points make up its early-warning timeline.

---

## 7. Simulated world (`backend/app/sim/`)

Everything is generated from a fixed seed, so it is reproducible.

- **15 fictional organisations** across the 6 NCIIPC critical-infrastructure sectors: Power & Energy, BFSI, Telecom, Transport, Government, Strategic & Public Enterprises. Each has a name, a state, a sector, a domain and a contact. **No real company names.**
- **About 600 assets:**
  - **Fields:** hostname, IP (RFC 1918 / documentation ranges), CPE 2.3 and version, network zone (internet/DMZ/internal), criticality tier, owner, and network edges for the blast-radius calculation.
  - **Products:** a deliberate mix. Edge appliances (VPN, firewall, mail gateway), web servers, CMSs, databases, OT/SCADA HMIs (Power), core banking (BFSI).
- **Logs** (about 50k lines over 7 days): firewall, DNS and authentication, mostly normal background traffic.
- **Decoy grid:** 24 sensors and about 5k hits of background noise.
- **Stories planted on top:**
  1. **Silent Gateway**, the main story: decoy scanning, then a real recent KEV CVE on a VPN or edge appliance, then two power-sector organisations exposed, then a Feodo C2 IP beaconing from one of them.
     **Pick the CVE from real KEV additions in the last 30 days** during setup, so it is fresh and real.
  2. **Lookalike Harvest:** real OpenPhish URLs plus planted lookalike domains of our fictional banks. DNS logs show 3 BFSI workstations resolving them. The warning is "credential-phishing campaign targeting BFSI".
  3. **Emerging vendor surge:** taken from the **real** KEV burst data for the last 60 days, applied to whichever organisations run that vendor's products.

---

## 8. Dashboard screens (dark "situation room" theme)

1. **Situation Room (home):**
   - national threat level from 1 to 5;
   - KPI tiles: signals in 24 h, new CVEs, relevant CVEs, alerts by tier, organisations exposed;
   - the funnel "17,369 → 41 → 6";
   - a live signal ticker over SSE;
   - a **sector × severity heatmap** (no India map; see the risks section);
   - top warnings;
   - a list of emerging trends.
2. **Alert detail ("Why this matters"):**
   - the AI summary;
   - the **score waterfall**;
   - a confidence gauge and the evidence list with citations;
   - the **early-warning timeline** (risk over time, with signal markers);
   - affected organisations and assets;
   - ATT&CK techniques;
   - an action checklist that drives the workflow;
   - **CERT-In draft**, **STIX 2.1 export** and **blocklist export** buttons;
   - an EN / हिन्दी / मराठी toggle.
3. **Threat graph:** a force graph of CVE ↔ product ↔ asset ↔ org ↔ IOC ↔ campaign ↔ technique, with blast-radius highlighting.
4. **Decoy grid:** sensors, a timeline of hits, the most-scanned CVEs, and pre-exploitation warnings.
5. **Exposure:** each organisation's inventory and which assets are exposed, with filters.
6. **Analyst assistant:** chat with tool calls shown on screen.
7. **How it works:** a model card, metrics, the backtest chart and the scoring formula. This page is deliverable 4, live.

**Replay control panel** (`Ctrl+Shift+D`): load a story, play or pause it at 60× speed, reset. The demo runs on this.

---

## 9. Mitigation workflow (deliverable 4)

1. **Alert lifecycle:** `New → Triaged → Assigned → Mitigating → Verified → Closed`, with an SLA timer for each tier and an owner taken from the asset inventory.
2. **The three action types from the brief:**
   - **Patch:** the vendor's fixed version, the KEV `requiredAction`, and the due date.
   - **Block:** IOC export as CSV, a firewall rule snippet, or a STIX 2.1 bundle.
   - **Investigate:** a hunting checklist mapped to the ATT&CK techniques, plus the log lines that triggered the alert.
3. **Escalation:** a Critical alert with incident evidence → a draft **CERT-In incident report**, pre-filled with the fields of the 2022 Directions and the 6-hour deadline.
4. **Feedback loop:** when an analyst marks an alert as a false positive, the source-reliability weight for that source goes down. This is the "learns from analysts" point.

---

## 10. Repository layout

```
D:\DECOY\
  PLAN.md
  docs/MODEL_CARD.md            (bake-off and predictor metrics, scoring explanation)
  backend/
    app/main.py                 (FastAPI, SSE)
    app/db.py, app/schemas.py
    app/ingest/                 (kev, nvd, epss, vulnrichment, feodo, openphish, mitre, certin_sim)
    app/ai/                     (llm.py [Ollama REST], extract, embed, attack_map, cluster,
                                 predictor, anomaly, narrate, copilot)
    app/engine/                 (correlate, score, emerging, decoy, workflow, replay)
    app/sim/                    (world, logs, decoys, stories)
  scripts/                      (snapshot_feeds.py, bakeoff.py, train_predictor.py, precompute.py)
  data/raw/  data/sim/  data/models/   (saved snapshots, fully offline)
  frontend/                     (React + Vite + TS + Tailwind)
  pitch/                        (slides and backup demo video)
```

---

## 11. Timeline (each gate needs a yes or no)

| Time | Phase | Done when |
|---|---|---|
| **14:30–15:15** | **P0 setup.** Ollama environment variables. Start the model pulls in the background (about 15 GB). Create the uv virtual environment. Scaffold the repo. **Save the feed snapshots.** `git init` | Snapshots exist on disk |
| 15:15–16:00 | **Bake-off** (once the models have downloaded). Meanwhile, write the simulated world generator | Model chosen for each role |
| 16:00–17:45 | **P0 main flow:** ingest and normalise, CPE matching, scoring v1, alerts, API, basic UI with the alert list and detail page | **Gate 17:45:** advisory → asset → scored alert works end to end |
| 18:00 | **Mentor round 1:** show the main flow. Ask the questions in §14 | |
| 18:00–21:00 | **P1 AI depth:** LLM extraction, narrator with validator, ATT&CK mapping, IOC sightings and beacon detector, decoy grid, correlation escalation. **Predictor training runs in parallel.** Eat dinner in 30 minutes | Silent Gateway escalates from Watch to High to Critical |
| 21:00–01:00 | **P1 dashboard:** Situation Room, alert detail (waterfall and timeline), replay engine, SSE live updates, decoy grid page | All 3 stories play through the UI |
| 01:00–03:00 | **P1/P2:** emerging-trend detector, campaign clustering, threat graph, exposure page | |
| **03:00–05:00** | **Sleep.** Not optional: a tired presenter loses the room | |
| 05:00–08:00 | **P2 extras:** assistant with tools, CERT-In draft, STIX and blocklist export, Hindi and Marathi, How-it-works page. Precompute all narratives | |
| **08:00** | **Mentor round 2: full demo run-through.** Note every point where the mentor hesitates | |
| 08:30–11:00 | Fix what mentor 2 found. Write the **slides** and `MODEL_CARD.md`. Final visual polish. **Record the backup video at 10:30** | |
| **11:00** | **Feature freeze** | |
| 11:00–12:30 | **Code freeze at 12:00.** Rehearse 3 times, timed (3-minute and 6-minute versions). **Test with Wi-Fi off.** Load the models before going on stage | |
| 12:30–13:00 | Buffer. Charger, presentation mode, notifications off, Windows Update paused | |

**What to cut if behind** (cut from the bottom of P2 upwards):
- **P0 (must have):** main flow, scoring with waterfall, dashboard home and alert detail, offline snapshots.
- **P1 (core differentiators):** LLM narrator, correlation escalation, decoy grid, beacon detector, replay engine, predictor.
- **P2 (nice to have):** assistant, campaign clustering, graph view, Indic languages, STIX/CERT-In export, emerging trends.

**If the 17:45 gate fails,** drop the assistant and the Indic languages immediately.

---

## 12. Slides (deliverable 4), 8 slides

1. **The problem in one number:** 17,369 CVEs a month, plus the brief's pain points.
2. **Reactive → proactive → predictive:** where we sit.
3. **Architecture** (the diagram in §2), and "100% local AI".
4. **The AI models:** extraction, predictor, clustering, ATT&CK mapping, anomaly and beacon detection, narrator with citations. Include the bake-off table.
5. **Scoring:** the 4 factors from the brief, noisy-OR, Admiralty ratings, SSVC overrides, and the worked example.
6. **Proof:** backtest PR-AUC and recall@2% against the CVSS baseline, the lead-time distribution, extraction accuracy, and the noise reduction (17,369 → 6).
7. **Mitigation workflow:** lifecycle, SLAs, CERT-In 6-hour report, STIX sharing, feedback loop.
8. **Built for India and next steps:** NCIIPC sectors, Indic-language alerts, a decoy grid that could become a national honeynet, real CERT-In and NCIIPC feeds.

---

## 13. Risks and fallbacks

| Risk | Mitigation |
|---|---|
| Venue Wi-Fi drops or a feed goes down | Everything is saved to `data/raw` by 15:15. **Test the demo with Wi-Fi off** |
| 8 GB of VRAM overflows or the LLM is slow | 4b model stays loaded, 9b loads on demand. Narratives precomputed. Streaming shows progress. Template fallback |
| LLM makes things up | JSON schema, citation validator, template fallback. The score never comes from the LLM |
| Demo goes off-script | Deterministic replay. Reset button. Backup video |
| C: drive fills up and Windows becomes unstable | Models, virtual environment and data all on D: |
| Laptop crash or file loss | `git commit` every milestone. Copy to a USB stick at 08:00 and 11:00 |
| **An India map with disputed borders** offends government judges | **No India map.** Use the sector heatmap and a state list instead |
| Windows Update, sleep or notifications during the demo | Pause updates, use the High-performance plan, turn on Focus Assist |
| Judges ask "is this just ChatGPT?" | The predictor's metrics, the classic ML (LightGBM, IsolationForest, HDBSCAN), the explained score and the local models |

---

## 14. Rules check and questions for mentors

**Rules check:**
- ✅ No active scanning, probing or exploiting. Feeds are only read, and assets come only from the simulated inventory.
- ✅ No malware samples are downloaded, only metadata. Every IOC is **defanged** on screen (`hxxp://`, `[.]`).
- ✅ No Tor, dark web or leak sites. Only official public feeds.
- ✅ Decoys are simulated, not real honeypots on the venue network.
- ✅ All code is written during the event. Simulated organisations are fictional.
- ⚠️ **Confirm with the organisers that AI coding tools are allowed.** The rules ban "unauthorized assistance".

**Questions for mentor round 1:**
1. What are the judging criteria and their weights?
2. How long is the elimination demo, and how long is the final?
3. Are AI coding assistants allowed?
4. What do we submit: repository, slides, video?
5. Do they prefer a national-CERT view, or a single-organisation SOC view?
6. Would C-DAC value Indic-language support or offline operation? Ask this to confirm the pitch angle.
