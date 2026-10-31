# D3COY 1.0 · PS 01 — Research Brief for the Team Lead

> **Prepared:** Sat 31 Oct 2026, 15:30 IST, by a team member with Claude Code (4 parallel research agents; key claims re-checked against primary sources).
> **Status:** research only. Nothing has been built yet; the repo holds only the team rulebook (`CLAUDE.md`).
> **Reading time:** ~10 minutes. Start with sections 0 and 1.

---

## 0. Summary

- **Local AI model:** use **Cisco Foundation-Sec-1.1-8B-Instruct** (Nov 2025, security-trained, 64K context, no "thinking" step). If our size rule is strictly *under* 8B, use **Qwen3-4B-Instruct-2507** instead. Make the final pick with a 30-minute test on real data (section 4.4), not on published scores.
- **Judging:** D3COY's published criteria are quality & originality, technical understanding of the problem statement, feasibility & impact, and USP & future scope. The event theme is "security, privacy and digital trust", which is ISACA's own concept.
- **How we win:**
  - be the team that **measures its AI** (accuracy on real 2026 data)
  - align our scoring with **CERT-In's Blueprint (May 2026)** and **CISA's BOD 26-04 (June 2026)**
  - show an **auditable mitigation workflow**
  - open the pitch with a **real Indian incident**: the July 2024 ransomware that took down ~300 banks
- **Bar set by the competition:** at least one other D3COY team has a polished demo with an audit log, a false-positive workflow and a benchmark scorecard. We need the same level of polish plus real data.

## 1. Decisions needed from you

| # | Decision | Recommendation |
|---|---|---|
| 1 | Is "under 8B parameters" an organiser rule or our own limit (8 GB GPU)? Neither the problem statement nor the Unstop page mentions model size. | If it's our own limit, Foundation-Sec (8.03B) is fine |
| 2 | Approve the 30-minute model test (section 4.4) | Yes. It picks the model and gives us a pitch metric |
| 3 | Adopt the build recommendations in section 5 | Yes. Each is costed in hours |
| 4 | Assign owners for the three parts: data + backend / AI engine / dashboard + PPT | Needed before coding starts (contracts first) |
| 5 | Ask the organisers about the 24-hour round: judging criteria, and pitch + demo length | Unstop lists criteria for Round 0 only |

## 2. How D3COY is judged

Source: D3COY's Unstop page (checked directly).

- **Round 0 criteria (exact wording):**
  1. "Quality and originality of the proposed solution"
  2. "Technical understanding of the problem statement"
  3. "Feasibility and potential impact of the proposed approach"
  4. "Unique Selling Proposition (USP) and Future Scope"
- **24-hour round:** no formal criteria published. It only says it tests "technical skills, problem-solving abilities, and creativity", so plan for the four above.
- **Format and prizes:** top 36 teams in the offline round. Prizes are overall ranks: ₹75k / ₹60k / ₹50k, so we compete against teams on every problem statement. Tagline: "Outsmart the Obvious!"
- **No published rules** on pre-built code, AI tools, or pitch length.
- **Local context:**
  - DJS ISACA co-ran SYN3RGY (Feb 2024), with a mixed faculty and industry jury.
  - A DJSCE team won an NTRO problem statement at SIH 2024, so the local judges know national-security style briefs.

| Criterion | What we should show |
|---|---|
| Quality & originality | Warnings built from several signals (not severity alone); a replay of real history; the AI's measured accuracy |
| Technical understanding | The problem statement's own example (advisory → matched asset → risk → alert) is our first working slice; scoring follows CERT-In and CISA guidance; every objective and deliverable covered |
| Feasibility & impact | Runs fully offline on one laptop; free data; no API cost; national view by sector |
| USP & future scope | AI that stays in India, plus auditability. Roadmap: import from OpenCTI/MISP, sharing with sector security teams, auto-drafted CERT-In reports |

## 3. Positioning and pitch

### 3.1 Speak the ISACA judges' language
ISACA defines digital trust as "confidence in the integrity of relations, interactions and transactions". Lines to use:
1. "Every warning is a risk-register entry, with an owner, a score, a treatment and a due date."
2. "Scores come from a fixed formula, so an auditor can recompute any score from the logged inputs."
3. "The AI advises and a human decides, and both are recorded in a tamper-evident audit log." CERT-In's Blueprint itself recommends human validation of AI output.
4. "Evidence and confidence on every output: that is digital trust."

Possible key risk indicators to show:
- share of exploited (KEV) CVEs on critical assets that are past their due date
- median early-warning lead time
- share of issues fixed within the Blueprint's timelines

### 3.2 The competition
- **H3lium** ([repo](https://github.com/RiseMantis/H3lium)) is publicly labelled "Demo for D3coy hackathon". It targets a different problem statement (security of AI agents), but competes for the same overall prizes. It has:
  - a polished dashboard
  - a tamper-evident audit log
  - a factor-by-factor risk explanation
  - a "mark false positive" workflow
  - a benchmark scorecard
  - a guided walkthrough

  It runs on simulated data only.
- **Vajra-Sec** ([repo](https://github.com/Axikop/Vajra-Sec)) is an internship project and the closest to our idea: NVD and CERT-In feeds, matching CVEs to assets, a local 3B model, a React dashboard. Its README admits **no risk model, no false-positive measurement and no audit log**. Our advantages are exactly those gaps.
- **Typical rival builds:** IP-reputation lookups (VirusTotal/AbuseIPDB), intrusion models trained on old public datasets (CICIDS), world attack maps, severity from CVSS alone.

### 3.3 Opening story (verified)

| Date | Event |
|---|---|
| 24–26 Jan 2024 | Jenkins advisory for CVE-2024-23897; public exploits appear |
| 10 Feb 2024 | EPSS gives a 61.5% chance of exploitation within 30 days |
| 31 Jul 2024 | Ransomware enters through a Jenkins server at Brontoo, a partner of C-Edge Technologies. ~300 small Indian banks lose UPI/ATM services; NPCI isolates C-Edge |
| 19 Aug 2024 | CISA adds the CVE to its Known Exploited Vulnerabilities (KEV) list |

**Line:** "Any organisation running Jenkins would have had a Critical warning from us in February." Present it as a clearly labelled replay of history.

**For Q&A:** with CitrixBleed 2 (CVE-2025-5777), EPSS was still only 4.2% the day before CISA listed it, but the vendor bulletin and attack sightings had already caught it. That is why we combine signals instead of relying on EPSS.

### 3.4 Pitch shape (5–7 min, 8–10 slides)

| Section | Time |
|---|---|
| Opening story | 0:30 |
| Problem | 0:30 |
| Solution | 0:30 |
| **Live demo** | **3:00** |
| The AI: model, why local, measured accuracy | 1:00 |
| Governance & regulation | 1:00 |
| Roadmap | 0:30 |

Record the backup demo video twice at code freeze.

### 3.5 Q&A answers

| Question | Answer |
|---|---|
| What if the AI makes things up? | The AI never sets the score. It fills a fixed format, anything without evidence goes to "needs review", and a human approves |
| False positives? | Exact asset matches are kept separate from "possible" ones; a false-positive button is logged; precision is measured |
| Why a local model? | Data stays in India; critical infrastructure is often air-gapped; security logs count as personal data under the DPDP Act; it works offline; there's no per-request cost |
| How did you test the AI? | 282 real 2026 KEV records the model had never seen, plus the time-to-warning replay |
| Why not OpenCTI/MISP? | They are threat-intel databases and sharing platforms, and OpenCTI even has KEV and EPSS connectors. We are the asset-aware decision layer on top and can import their data. **Don't claim they lack KEV/EPSS** |
| Does it scale? | The score is a pure function; the AI runs only on new advisories; results are cached |

### 3.6 Regulatory facts

Safe to put on slides:
- **CERT-In Directions** (28 Apr 2022): report listed incidents within **6 hours**; keep logs **180 days** in India.
- **CERT-In Blueprint** (25 May 2026): it calls these deadlines "indicative" (guidance, not a mandate).
  - KEV on internet-facing or crown-jewel systems: **12 h**
  - Critical, externally exposed: **1 day**
  - KEV, internal: **1 day**
  - Critical internal, high-value systems: **3 days**
  - High severity: **5 days**

  It prioritises by KEV, EPSS, exploitability and business criticality, and recommends human validation of AI outputs.
- **CISA BOD 26-04** (10 Jun 2026): replaces BOD 22-01 and BOD 19-02. Deadlines are set by asset exposure, KEV status, exploit automation and technical impact. Its table is "informed by the SSVC system"; the top tier is 3 days plus forensic triage.
- **DPDP Rules** (notified Nov 2025): security safeguards, including keeping logs for 1 year, phase in around May 2027.

**Don't claim:**
- that the Blueprint mentions SSVC (it doesn't), or that it is mandatory
- that India has adopted a National Cyber Security Strategy (not verified)
- that NVD lacks product data (it restored "affected" data in June 2026)

## 4. Local AI model

### 4.1 Recommendation

| Role | Model | Size | Why |
|---|---|---|---|
| **Main**: product extraction, summaries, mitigation steps | **Foundation-Sec-1.1-8B-Instruct**, Q4_K_M | 8.03B, ~4.9 GB | Security-trained (CTI-RCM 0.694 vs 0.558 for Llama 3.1 8B); no thinking step, so the JSON format applies from the first token; 64K context; training data to Apr 2025 |
| Challenger in the test | Foundation-Sec-8B-Instruct (v1) | ~4.9 GB | CTI-RCM 0.704, IFEval 0.861 in Cisco's Jan 2026 paper; 4K context is enough for one CVE per request |
| Fallback (strict "under 8B") | **Qwen3-4B-Instruct-2507** | 4.02B, 2.5 GB | Official Ollama tag `qwen3:4b-instruct-2507-q4_K_M`; no thinking step; IFEval 83.4; ~2× faster |
| Flagship explanation (pre-generated only) | Foundation-Sec-8B-Reasoning | ~4.9 GB | Highest score (CTI-RCM 0.753), but thinking can't be turned off. Run it without JSON mode and keep only the text after `</think>` |
| Embeddings (campaign grouping, ATT&CK lookup) | `qwen3-embedding:0.6b` (Ollama) | 0.6 GB | No PyTorch needed. Security encoders (SecureBERT 2.0, ATTACK-BERT) need PyTorch and haven't clearly beaten general models |

### 4.2 Models considered and rejected

| Model | Why not |
|---|---|
| Llama-Primus (Trend Micro) | Scores below Foundation-Sec; reasoning format undocumented |
| VulnLLM-R-7B, WhiteRabbitNeo | Built for source-code bug hunting or offensive work, not our tasks |
| DeepHat-V1-7B | CTI-RCM 0.434; Cisco's paper says it ignores answer-format instructions |
| BaronLLM, Dolphin3-Cyber, notmythos, FS-Red-Team | Offensive or "uncensored" focus; no benchmarks; unclear licences. Risky to show to ISACA judges |
| Llama-Guard-3 | A safety classifier, not a text generator |
| RedSage-Qwen3-8B (Jan 2026) | Good scores, but **no licence declared**, so no right to use it |

### 4.3 How to run it well (Ollama, 8 GB GPU)
- **JSON validity isn't the risk; accuracy is.** Ollama's `format` option enforces the JSON schema with grammar-constrained decoding, so the risk is wrong *content*, not broken JSON.
- **Trap 1: missing chat template.** Cisco's GGUF files ship without a chat template. Write an Ollama Modelfile with the template and stop token, then verify it with `ollama show --modelfile`. Allow about 20 minutes.
- **Trap 2: thinking models.** They can skip the JSON schema. Use only non-thinking models for extraction, and validate every reply with Pydantic.
- **Video memory budget.** An 8B Q4_K_M model needs ~5.6 GB at 4K context and ~6.2 GB at 8K (~5.7 GB with a q8_0 KV cache). On our laptop, desktop apps already used 1.87 GB of the 8 GB. Close GPU-heavy apps and check that `ollama ps` shows **100% GPU**.
- **Settings:**
  - set `num_ctx` explicitly (Ollama quietly defaults to 4096)
  - `OLLAMA_KV_CACHE_TYPE=q8_0`
  - `OLLAMA_NUM_PARALLEL=2` for bulk pre-generation (~1.6× throughput)
  - temperature 0 with a fixed seed
  - `keep_alive=-1` during the demo
- **Speed:** about 38–45 tokens/sec for 8B on 8 GB laptop GPUs; 4B models run about twice as fast. 300 CVEs × ~250 output tokens takes roughly 20–30 minutes in total.

### 4.4 The 30-minute model test (also produces a pitch metric)
1. **Test set:** CVEs CISA added to KEV in **2026**. That's after the models' training cutoff, so they can't have memorised them. Use 50 for the comparison and all **282** for the final number.
2. **Input:** the official CVE description only. **Output JSON:** vendor, product, version range, attack type, impact.
3. **Scoring:** compare against KEV's `vendorProject` / `product` fields.
   - Count a normalised exact match, and a fuzzy match with rapidfuzz `token_sort_ratio` ≥ 90.
   - **Not** `token_set_ratio`: it rates "Server" vs "Exchange Server" as 100.
   - Also record the share passing schema validation, tokens/sec, and whether it ran 100% on the GPU.
4. **Decision:** the most accurate model wins if it reaches at least 30 tokens/sec; a faster model wins if it's within 3 accuracy points.
5. **Pitch slide:** "X% accuracy (±4%) on 282 real 2026 KEV records the model had never seen."

## 5. Recommended build elements

| # | Element | Why | Est. effort |
|---|---|---|---|
| 1 | **Data sources (no keys needed):** CISA KEV · FIRST EPSS · CVE.org records ([cvelistV5](https://github.com/CVEProject/cvelistV5), which carry CISA's SSVC values on ~93% of 2026 CVEs) · [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) (exploited/PoC sightings and timelines) · CERT-In notes (scrape) · CISA advisories RSS · Exploit-DB + Nuclei (exploit available) · CTID KEV→ATT&CK mappings | Real, current, free; SSVC comes ready-made | ~4 h total |
| 2 | **Honest AI role:** read unstructured advisories (CERT-In notes often lack CVE IDs); repair blank or free-text product fields; match product names to our assets; write grounded explanations and playbooks | NVD restored product data in June 2026, so "AI fills the NVD gap" is no longer true | — |
| 3 | **Fixed risk formula (0–100):** 30 likelihood (KEV / PoC / EPSS) + 20 severity + 20 asset criticality + 15 exposure + 10 log evidence + 5 recency. Shown with a confidence % and an SSVC decision (Track / Attend / Act); due dates from the CERT-In Blueprint tiers | Explainable and recomputable; never multiplies EPSS by CVSS (EPSS's guidance says not to) | ~2.5 h |
| 4 | **AI scorecard page:** measured extraction accuracy; median early-warning lead time from the replay; our ranking compared with CVSS-only and with [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer) | Judges trust measured numbers | ~2 h |
| 5 | **Mitigation workflow** (a required deliverable): New → Triaged → Mitigating → Verifying → Closed (resolved / risk accepted / not applicable), or Reopened. Each alert has an owner, a due date from its CERT-In tier and an SLA state; it maps to NIST SP 800-61r3 | Directly answers the problem statement's deliverable | ~2 h |
| 6 | **Action catalogue with control IDs:** each action carries ATT&CK mitigation, D3FEND, NIST CSF 2.0 and CIS v8.1 IDs, plus KEV's `requiredAction` text word for word. The AI picks only from the catalogue, so it can't invent IDs | Authoritative recommendations that speak ISACA's language | ~1 h |
| 7 | **Trust layer:** tamper-evident (hash-chained) audit log; "AI-generated" labels; human approve/override; false-positive button | Matches the competition's polish; digital-trust theme | ~1.5 h |
| 8 | **National view without a map outline:** a sector heatmap (power, banking, telecom, healthcare, government) of fictional organisations, or a grid of state tiles | Maps with incorrect India borders carry legal risk (Criminal Law Amendment Act 1961; DST map guidelines) | — |
| 9 | **Realistic simulated logs:** a seeded generator using real attack request patterns from Nuclei templates, plus an answer-key file to measure detection | Credible evidence signal, and measurable | ~2 h |
| 10 | **Dashboard tools:** Vite + React + Tailwind + shadcn/ui (ready dashboard layout) + Recharts; heatmap with a CSS grid. Skip Tremor (no longer maintained) | Fastest path to a polished UI | saves hours |
| 11 | **Keep the machine learning modest:** embedding clustering into campaigns, plus anomaly detection (Isolation Forest) on logs. Don't train our own "will it be exploited" model: it adds little beyond EPSS and is easily inflated by data leakage. Show "EPSS alone vs our combined signals" instead | Real ML without wasting hours | saves ~3 h |

**Lower priority** (only if ahead of schedule): relationship graph, ATT&CK heatmap, PDF export, chat assistant, weight sliders.

## 6. Sources

✔ = checked directly against the source. The rest come from the research agents' cited sources.

**D3COY and competition**
- [D3COY on Unstop ✔](https://unstop.com/hackathons/d3coy-shri-vile-parle-kelavani-mandals-dwarkadas-j-sanghvi-college-of-engineering-djsce-mumbai-1767673/amp)
- [H3lium ✔](https://github.com/RiseMantis/H3lium)
- [Vajra-Sec ✔](https://github.com/Axikop/Vajra-Sec)
- [SYN3RGY report](https://www.djsce.ac.in/docs/Syn3rgy%20Report.pdf)
- [ISACA on digital trust](https://www.isaca.org/resources/news-and-trends/isaca-now-blog/2022/understanding-the-full-digital-trust-ecosystem)

**Models**
- [Foundation-Sec-1.1-8B-Instruct ✔](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct)
- [Foundation-Sec-8B-Reasoning paper ✔](https://arxiv.org/html/2601.21051v1)
- [Qwen3-4B-Instruct-2507](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507)
- [RedSage-Qwen3-8B](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins)
- [Ollama FAQ](https://docs.ollama.com/faq)
- [RTX 4060 Laptop benchmark](https://www.nidhiyashwanth.com/blog/local-ai-benchmark)

**Regulation and guidance**
- [CISA BOD 26-04 ✔](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
- [NVD changes 2026 ✔](https://www.nist.gov/itl/nvd)
- [CERT-In Blueprint (May 2026)](https://www.cert-in.org.in/PDF/Blueprint_for_Defending_against_AI_Assisted_Exploitation.pdf)
- [CERT-In Directions 2022](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf)
- [DPDP Rules (PIB)](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf)

**C-Edge incident**
- [CloudSEK ✔](https://www.cloudsek.com/blog/major-payment-disruption-ransomware-strikes-indian-banking-infrastructure)
- [CSO Online ✔](https://www.csoonline.com/article/3480250/over-300-indian-banks-suffer-payment-disruption-from-ransomware-attack.html)
- [The Week ✔](https://www.theweek.in/news/biz-tech/2024/08/01/ransomware-attack-targets-300-banks-across-india-upi-atm-services-disrupted.html)

**Data and tools**
- [CISA Vulnrichment](https://github.com/cisagov/vulnrichment)
- [CVE.org records (cvelistV5)](https://github.com/CVEProject/cvelistV5)
- [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu)
- [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer)
- [D3FEND mappings](https://d3fend.mitre.org/mappings/attack-mitigations/)
- [NIST CSF 2.0 informative references](https://www.nist.gov/cyberframework/csf-20-informative-references)
