# Open-weight, cybersecurity-specialised generative LLMs of 8B parameters or fewer (as of 31 Oct 2026): census and fit for the D3COY early-warning system

Method: I queried the Hugging Face API on 31 Oct 2026 with 40 keyword searches, 7 tag filters and 30+ org listings (3,948 unique repos), e.g. [HF API search](https://huggingface.co/api/models?search=cybersecurity&limit=200), [tag filter](https://huggingface.co/api/models?filter=cybersecurity&limit=300). I then pulled per-repo metadata (`/api/models/{id}`: creation date, safetensors parameter count, license, gating, downloads), README.md, config.json, tokenizer_config.json (chat templates) and file trees (GGUF sizes). Unless noted, "release" is the date stated on the model card, and "repo created" is the HF `createdAt` value. Download counts are the HF API's rolling ~30-day counts on 31 Oct 2026. **Every benchmark number in this file is self-reported by the model's publisher unless it is marked "third-party".**

---

## Q1. Which security-specialised generative models of 8B or fewer exist on Hugging Face, and what are their basic facts?

### Takeaway
About 30 relevant ≤8B generative repos exist. Only four lineages have a vendor or academic publisher plus a real evaluation: Cisco Foundation AI (Foundation-Sec, Antares), Trend Micro (Llama-Primus), Khalifa University RISys-Lab (RedSage) and Dream (MiST-8B, released 19 Oct 2026). Everything else is single-author or hackathon fine-tunes, or offensive/uncensored models. The newest strong entrant, MiST-8B, is not in the user's candidate list. CyberPal 2.0 only has its 20B model public.

### Cited Findings

**Table A: identity facts (≤8B, generative, security-specialised)**

| # | Repo id | Publisher (type) | Release | Base model | Params (safetensors) | License | Context (config / card) | DL 30d |
|---|---|---|---|---|---|---|---|---|
| 1 | [fdtn-ai/Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) | Cisco Foundation AI (vendor) | 28 Apr 2025 (card) | Llama-3.1-8B, continued pretraining on ~5.1B security tokens | 8,031,309,824 | Apache-2.0 | 131,072 (config) | 8,082 |
| 2 | [fdtn-ai/Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) | Cisco (vendor) | 1 Aug 2025 (card); tech report [arXiv 2508.01059](https://arxiv.org/abs/2508.01059) | Foundation-Sec-8B | 8,031,309,824 | "other": Llama 3.1 Community License, with Cisco changes under Apache-2.0 ([NOTICE.md](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/main/NOTICE.md)) | config says 131,072, but the 1.1 card says Instruct was **4k** | 14,912 |
| 3 | [fdtn-ai/Foundation-Sec-1.1-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct) | Cisco (vendor) | 20 Nov 2025 (card) | Foundation-Sec-1.1-8B base | 8,030,326,784 | "other" ([API](https://huggingface.co/api/models/fdtn-ai/Foundation-Sec-1.1-8B-Instruct)) | 65,536 ("extended from 4k to 64k") | 1,886 |
| 4 | [fdtn-ai/Foundation-Sec-8B-Reasoning](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning) | Cisco (vendor) | 28 Jan 2026 (card); repo created 6 Nov 2025; [arXiv 2601.21051](https://arxiv.org/abs/2601.21051) | Foundation-Sec-8B, then SFT + RLVR | 8,030,425,088 | "other": Llama 3.1 + Apache-2.0 ([NOTICE.md](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/NOTICE.md)) | config 131,072; trained at 32,768 sequence length | 2,496 |
| 5 | [fdtn-ai/antares-1b](https://huggingface.co/fdtn-ai/antares-1b) | Cisco (vendor) | repo created 21 Jul 2026 (card says "2026") | ibm-granite/granite-4.0-1b | card says "1B", safetensors says 1,837,271,040 | Apache-2.0, **gated with manual review** | 128K (card) | 1,306 |
| 6 | [fdtn-ai/antares-350m](https://huggingface.co/fdtn-ai/antares-350m) | Cisco (vendor) | 21 Jul 2026 | granite-4.0-350m | 352,379,904 | Apache-2.0, gated (manual) | 32K (card) | 142 |
| 7 | [trendmicro-ailab/Llama-Primus-Base](https://huggingface.co/trendmicro-ailab/Llama-Primus-Base) | Trend Micro (vendor) | repo created 19 Feb 2025; [arXiv 2502.11191](https://arxiv.org/abs/2502.11191) | Llama-3.1-8B-Instruct + continued pretraining | 8,030,261,248 | MIT, and must also comply with the Llama 3.1 Community License | 131,072 | 46 |
| 8 | [trendmicro-ailab/Llama-Primus-Merged](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged) | Trend Micro (vendor) | 16 Feb 2025 | Primus-Base (merged) | 8,030,261,248 | MIT + Llama 3.1 | 131,072 | 529 |
| 9 | [trendmicro-ailab/Llama-Primus-Reasoning](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning) | Trend Micro (vendor) | 20 Feb 2025 | Primus-Merged + reasoning distilled from o1/R1 | 8,030,261,248 | MIT + Llama 3.1 | 131,072 | 259 |
| 10 | [RISys-Lab/RedSage-Qwen3-8B-Ins](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins) | Khalifa University RISys-Lab (academic) | repo created 16 Oct 2025; ICLR 2026, [arXiv 2601.22159](https://arxiv.org/abs/2601.22159) | RedSage-Qwen3-8B-Base (Qwen3-8B-Base + 11.8B-token CPT) | 8,190,735,360 | **not declared on card** | 32,768 | 574 |
| 11 | [RISys-Lab/RedSage-Qwen3-8B-DPO](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-DPO) | RISys-Lab (academic) | 15 Oct 2025 | RedSage-Ins + DPO | 8,190,735,360 | not declared | 32,768 | 572 |
| 12 | [RISys-Lab/RedSage-K-SFT-GRPO](https://huggingface.co/RISys-Lab/RedSage-K-SFT-GRPO) (also K-SFT, K-GRPO) | RISys-Lab (academic) | 30 Sep 2026; KaliBench [arXiv 2610.02206](https://arxiv.org/abs/2610.02206) | RedSage-Ins | 8,190,735,360 | not declared | 32,768 | ~575 each |
| 13 | [dreamgroup/MiST-8B](https://huggingface.co/dreamgroup/MiST-8B) | "Dream" (company per card) | repo created 19 Oct 2026; [arXiv 2609.18496](https://arxiv.org/abs/2609.18496) submitted 16 Sep 2026 | Qwen3-8B-Base, then mid-training (~976M tokens), SFT, DPO | 8,190,735,360 | Apache-2.0 | 32,768 | 113 |
| 14 | [DeepHat/DeepHat-V1-7B](https://huggingface.co/DeepHat/DeepHat-V1-7B) | DeepHat/Kindo (WhiteRabbitNeo lineage; shares the WRN Discord link) | repo created 25 Apr 2025 | Qwen2.5-Coder-7B | 7,615,616,512 | Apache-2.0 | 32,768 config; 131,072 with YaRN per card | 4,788 |
| 15 | [WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B](https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B) | WhiteRabbitNeo (community/vendor) | 28 Sep 2024 | Qwen2.5-Coder-7B | 7,615,616,512 | Apache-2.0 plus WRN usage restrictions (e.g. no military use) | 32,768 | 1,748 |
| 16 | [WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B](https://huggingface.co/WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B) | WhiteRabbitNeo | 19 Aug 2024 | Llama-3.1-8B | 8,030,261,248 | llama3.1 | 131,072 | 200 |
| 17 | [WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0](https://huggingface.co/WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0) | WhiteRabbitNeo | 15 May 2024 | Llama-3-8B | 8,030,261,248 | llama3 | 8,192 | 196 |
| 18 | [Virtue-AI-HUB/VulnLLM-R-7B](https://huggingface.co/Virtue-AI-HUB/VulnLLM-R-7B) | Virtue AI (vendor) | 5 Jun 2025; [arXiv 2512.07533](https://arxiv.org/abs/2512.07533) | Qwen2.5-7B-Instruct | 7,615,616,512 | Apache-2.0 | 32,768 | 1,686 |
| 19 | [athena129/CyberSecQwen-4B](https://huggingface.co/athena129/CyberSecQwen-4B) (mirror: [lablab-ai-amd-developer-hackathon/CyberSecQwen-4B](https://huggingface.co/lablab-ai-amd-developer-hackathon/CyberSecQwen-4B)) | individual, AMD hackathon entry (community) | 7 May 2026 | Qwen3-4B-Instruct-2507 (LoRA r=64) | 4,022,468,096 | Apache-2.0 | config 262,144; card says 32,768 native; **trained at 4,096** | 188 |
| 20 | [athena129/Gemma4Defense-2B](https://huggingface.co/athena129/Gemma4Defense-2B) | same author (community) | 7 May 2026 | gemma-4-E2B-it | 4,650,988,835 total (2.3B effective) | Apache-2.0 | 131,072; trained at 4,096 | 30 |
| 21 | [iselabvn/Tini-Cybersec-8B-A1B](https://huggingface.co/iselabvn/Tini-Cybersec-8B-A1B) | iselabvn (lab affiliation unverified) | 30 Jun 2026 | LiquidAI/LFM2.5-8B-A1B (MoE) | **8,467,856,832 total**, ~1B active | Apache-2.0 (card) | 128,000; trained at 8,192 | 326 |
| 22 | [aliasrobotics/alias3-micro-1026](https://huggingface.co/aliasrobotics/alias3-micro-1026) | Alias Robotics (vendor) | 19 Oct 2026 | Qwen/Qwen3.5-4B | 4,205,751,296 | Apache-2.0 | 262,144 | 434 |
| 23 | [Akahsizrr/Cyber-Prime-1.2](https://huggingface.co/Akahsizrr/Cyber-Prime-1.2) (also [1.1-2.6B](https://huggingface.co/Akahsizrr/Cyber-Prime-1.1-2.6B)) | individual (community) | 29 Sep 2026 (1.1: 23 Sep 2026) | LiquidAI/LFM2-2.6B | 2,697,198,592 | other (lfm1.0) | 131,072 | 120 / 430 |
| 24 | [BrainboxAI/cyber-analyst-4B](https://huggingface.co/BrainboxAI/cyber-analyst-4B) | BrainboxAI (small vendor) | 12 Apr 2026 | unsloth/gemma-4-E4B-it (QLoRA) | not exposed by API (Gemma-4-E4B) | Apache-2.0 | 131,072 | 470 |
| 25 | [ZySec-AI/SecurityLLM](https://huggingface.co/ZySec-AI/SecurityLLM) (ZySec-7B) | ZySec AI (small vendor) | 28 Jan 2024 | Mistral-7B architecture (base not declared) | 7,241,732,096 | Apache-2.0 | 32,768 | 1,140 |
| 26 | [segolilylabs/Lily-Cybersecurity-7B-v0.2](https://huggingface.co/segolilylabs/Lily-Cybersecurity-7B-v0.2) | Sego Lily Labs (community) | 11 Jan 2024 | Mistral-7B-Instruct-v0.2 | 7,241,732,096 | Apache-2.0 | 32,768 | 523 |
| 27 | [clouditera/SecGPT-7B](https://huggingface.co/clouditera/SecGPT-7B) (also [SecGPT-1.5B](https://huggingface.co/clouditera/SecGPT-1.5B)) | Clouditera (Chinese vendor) | 14 Apr 2025 | Qwen2 architecture (card compares against Qwen2.5) | 7,615,616,512 / 1,543,714,304 | Apache-2.0 | 32,768 | 74 / 106 |
| 28 | [AlicanKiraz0/Seneca-Cybersecurity-LLM_x_Qwen2.5-7B-CyberSecurity](https://huggingface.co/AlicanKiraz0/Seneca-Cybersecurity-LLM_x_Qwen2.5-7B-CyberSecurity) | individual | 30 Dec 2024 | Qwen2.5-Coder-7B-Instruct | 7,615,616,512 | MIT | 32,768 | 84 |
| 29 | [AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF](https://huggingface.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF) (BaronLLM v1) | individual | 21 Jan 2025 | Llama-3.1-8B-Instruct | 8.03B (GGUF only) | MIT | 131,072 | 978 (380 likes) |
| 30 | [DexopT/Qwen3-4B-Cybersecurity](https://huggingface.co/DexopT/Qwen3-4B-Cybersecurity) (+ [Heretic abliterated](https://huggingface.co/DexopT/Qwen3-4B-Cybersecurity-Heretic-16bit)) | individual | 21 Mar 2026 | Qwen3-4B-Instruct-2507 | 4,022,468,096 | Apache-2.0 | 262,144 | 472 |
| 31 | [exploitintel/cve-cwe-qwen3-8b](https://huggingface.co/exploitintel/cve-cwe-qwen3-8b) | ExploitIntel (community) | 30 May 2026 | Qwen3-8B (QLoRA, merged) | 8,190,735,360 | Apache-2.0 | 40,960 | 642 |
| 32 | [djini-ai/djini-4b-security-agent](https://huggingface.co/djini-ai/djini-4b-security-agent) / [djini-7b-cve-hunter](https://huggingface.co/djini-ai/djini-7b-cve-hunter) | djini-ai (community) | 26 Oct 2026 | Qwen3.5-4B / Qwen2.5-Coder-7B-Instruct | 4,205,751,296 / 7,615,616,512 | Apache-2.0 | 262,144 / 32,768 | 443 / 358 |

Sources for the table: each repo link above plus `https://huggingface.co/api/models/<repo>` (e.g. [Foundation-Sec-8B API](https://huggingface.co/api/models/fdtn-ai/Foundation-Sec-8B), [MiST-8B API](https://huggingface.co/api/models/dreamgroup/MiST-8B), [RedSage-Ins API](https://huggingface.co/api/models/RISys-Lab/RedSage-Qwen3-8B-Ins)).

**Other facts**
- The Trend Micro models are also mirrored under trend-cybertron (Llama-Primus-Base/Merged/Reasoning, 0 downloads) — [trend-cybertron org](https://huggingface.co/trend-cybertron).
- The Foundation-Sec-1.1 card says the context window was "Increased from 4k to 64k tokens" — [Foundation-Sec-1.1-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct).
- Antares is a family of 350M, 1B and 3B models. Only 350M and 1B are on HF; the fdtn-ai org lists no antares-3b — [antares-350m card](https://huggingface.co/fdtn-ai/antares-350m); [fdtn-ai org](https://huggingface.co/fdtn-ai).
- Antares does agentic vulnerability localisation in code repositories using a terminal tool. It "does not explain vulnerabilities," and the card lists "general chat or instruction following" as out of scope. Tech report: [Antares technical report](https://cisco-foundation-ai.github.io/antares/technical-report.pdf) — [antares-1b card](https://huggingface.co/fdtn-ai/antares-1b).
- The CyberPal 2.0 paper describes a family "ranging from 4B-20B parameters" — [arXiv 2510.14113](https://arxiv.org/abs/2510.14113). The cyber-pal-security org holds only CyberPal2.0-20B (20,914,757,184 params, gpt-oss-20b base), so **no ≤8B CyberPal is public** — [cyber-pal-security org](https://huggingface.co/cyber-pal-security); [CyberPal2.0-20B](https://huggingface.co/cyber-pal-security/CyberPal2.0-20B). The MiST card calls it "IBM Research's CyberPal 2.0-20B" — [MiST-8B](https://huggingface.co/dreamgroup/MiST-8B).
- The RedSage K-series turns natural-language requests into Kali/Linux commands, with output format `<think>…</think><output>command</output>` — [RedSage-K-SFT-GRPO](https://huggingface.co/RISys-Lab/RedSage-K-SFT-GRPO).
- VulnLLM-R-7B reasons over source code for vulnerability detection, not CTI text — [VulnLLM-R-7B](https://huggingface.co/Virtue-AI-HUB/VulnLLM-R-7B).
- djini-4b-security-agent is a code vulnerability-hunting agent (it recovered "a dlsym-dispatch chain, CWE-94") — [djini-4b-security-agent](https://huggingface.co/djini-ai/djini-4b-security-agent).
- ibm-granite/granite-3.3-8b-security-lib is not a CTI model. It is a set of LoRA "intrinsics" for LLM safety, e.g. adversarial scoping and a "Function Calling Scanner" — [granite-3.3-8b-security-lib](https://huggingface.co/ibm-granite/granite-3.3-8b-security-lib).
- Cisco's other HF releases are encoders, not generative: SecureBERT2.0 base/NER/bi-encoder/cross-encoder/code-vuln — [cisco-ai org](https://huggingface.co/cisco-ai).
- Long tail of single-author ≤8B fine-tunes with thin cards and no recognised benchmarks:
  - [Mohamedabul/Qwen2.5-3B-CyberSecurity-Instruct](https://huggingface.co/Mohamedabul/Qwen2.5-3B-CyberSecurity-Instruct) (3,287 DL)
  - [nyxspecter4/kin-cybersecurity-3b](https://huggingface.co/nyxspecter4/kin-cybersecurity-3b) (license qwen-research)
  - [AYI-NEDJIMI/CyberSec-Assistant-3B](https://huggingface.co/AYI-NEDJIMI/CyberSec-Assistant-3B) (fr/en)
  - [reaperdoesntknow/Qwen3.5-2B-CyberSec](https://huggingface.co/reaperdoesntknow/Qwen3.5-2B-CyberSec)
  - [Nguuma/security-slm-unsloth-1.5b](https://huggingface.co/Nguuma/security-slm-unsloth-1.5b)
  - [ApolloRaines/Llama-3.1-8B-Instruct-Security-Analyst](https://huggingface.co/ApolloRaines/Llama-3.1-8B-Instruct-Security-Analyst)
  - [pki/nova-8b-cybersec](https://huggingface.co/pki/nova-8b-cybersec) (Dolphin3 base)
  - [opena2a/nanomind-security-analyst](https://huggingface.co/opena2a/nanomind-security-analyst) (gated, Qwen3-1.7B)
  - [OpenPathAI/Orbit-3-8B-Llama-thinking](https://huggingface.co/OpenPathAI/Orbit-3-8B-Llama-thinking) (8K ctx)
  - [YoSaNoo/Forge-1-Gemma-4-E2B](https://huggingface.co/YoSaNoo/Forge-1-Gemma-4-E2B)
  - [kiel2/Kiel-3-Cyber](https://huggingface.co/kiel2/Kiel-3-Cyber)
  - [emulsazib/Qwen3-4B-Instruct-2507-AETHER](https://huggingface.co/emulsazib/Qwen3-4B-Instruct-2507-AETHER) (GGUF named "aether-qwen3-4b-attack")
- "Dolphin3-Cyber-8B" is [RavichandranJ/Dolphin3-Cyber-8B-LoRA](https://huggingface.co/RavichandranJ/Dolphin3-Cyber-8B-LoRA): an adapter only, on base `huihui-ai/Dolphin3.0-Llama3.1-8B-abliterated`, with 0 downloads. The related [GT-Edge-AI/Dolphin3.0-Llama3.1-8B-Cyber-LoRA-Test-v0.2](https://huggingface.co/GT-Edge-AI/Dolphin3.0-Llama3.1-8B-Cyber-LoRA-Test-v0.2) ships a GGUF named `Dolphin3.0-Llama3.1-8B-abliterated.Q4_K_M.gguf` — [API](https://huggingface.co/api/models/GT-Edge-AI/Dolphin3.0-Llama3.1-8B-Cyber-LoRA-Test-v0.2).
- **Out of scope (>8B), noted only:**
  - CyberPal2.0-20B
  - [trend-cybertron/Llama-Primus-Nemotron-70B-Instruct](https://huggingface.co/trend-cybertron/Llama-Primus-Nemotron-70B-Instruct)
  - Trend Micro [sovereign-v2](https://huggingface.co/trendmicro-ailab/sovereign-v2) (31,577,937,344 params, gated manual, created 8 Oct 2026)
  - [Trendyol-Cybersecurity-LLM-Qwen3-32B-Q8_0-GGUF](https://huggingface.co/Trendyol/Trendyol-Cybersecurity-LLM-Qwen3-32B-Q8_0-GGUF) and [v2-70B](https://huggingface.co/Trendyol/Trendyol-Cybersecurity-LLM-v2-70B-Q4_K_M)
  - BaronLLM-v2 (Qwen3-14B)
  - Titus-CybersecurityLLM-v1.0 (GGUF reports 34.66B params)
  - SecGPT-14B
  - [dreamgroup/MiST-30B-A3B](https://huggingface.co/dreamgroup/MiST-30B-A3B)
  - exploitintel 32B / Gemma4-12B
  - [orcarouter/OrcaCyber-Nano-1.0](https://huggingface.co/orcarouter/OrcaCyber-Nano-1.0): "Nano" in name only, base is Qwen3.8-27B, gated
  - Blackfrost-AI CYBER-FROST-3.8 (~180B)
  - WhiteRabbitNeo 13B/33B/70B
  - CyberBuddyAI/CyberOps-Qwen3.5-9B, empero-ai/Qwythos-9B, DuoNeural/Cyber-Ornith-1.5-9B-OBLITERATED, LuisPPB16/Qwen3.5-9B-Red_Team

  Sources: [HF API](https://huggingface.co/api/models?search=cybersecurity&limit=200) and each repo's API record.

### Inferences
- The 8B "Qwen3" models (RedSage, MiST, exploitintel) are 8.19B, the same size as stock Qwen3-8B (the user's `qwen3:8b`). Tini-Cybersec is 8.47B total, so strictly above the 8B line, but only ~1B is active. I kept it as a borderline entry.
- Repo traction (downloads) is concentrated in Foundation-Sec-8B-Instruct (14.9K), Foundation-Sec-8B (8.1K) and DeepHat (4.8K). MiST-8B is 12 days old and has no independent replication yet.

### Gaps
- Dream's corporate identity: the card says only "developed by Dream", and the arXiv abstract page lists no affiliations.
- The iselabvn affiliation is unverified.
- The RedSage license is not declared in card metadata. The arXiv abstract says "all models, datasets, and code are public" but names no license.
- The Antares-3B release status beyond "not on HF" is unknown.

---

## Q2. Can each run on our laptop (8 GB VRAM, about 6.9 GiB free, Ollama 0.20.0 / portable 0.40.13)? GGUF, Q4_K_M size, chat template quirks, tool calling/JSON

### Takeaway
Every 7–8B candidate has a Q4_K_M GGUF of 4.37–5.34 GB, which fits in 6.9 GiB with modest KV cache. Only one such model fits on the GPU at a time.

Official vendor Q4_K_M GGUFs exist only for:
- Foundation-Sec-8B (base)
- Foundation-Sec-1.1-8B-Instruct
- Foundation-Sec-8B-Reasoning (all 4.92 GB)
- Lily (4.37 GB)
- cyber-analyst-4B (5.34 GB)

**Foundation-Sec-8B-Instruct has no official Q4_K_M** (only Q8_0, 8.54 GB, which does not fit).

The Foundation-Sec models use a non-standard `<|system|>/<|user|>/<|assistant|>` format with no tool support in the template. Qwen-derived security models (RedSage, MiST, DeepHat) keep ChatML and tool blocks. Qwen3.5-based models (alias3-micro, djini-4b) need the newer Ollama.

### Cited Findings

**Table B: deployability**

| Model | Best Q4_K_M GGUF (size) | Chat template / stop-token quirks | Tool calling / JSON evidence |
|---|---|---|---|
| Foundation-Sec-8B (base) | **official** [fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF/tree/main) 4.92 GB | Base model, no chat template; few-shot completion only ([card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B)) | None |
| Foundation-Sec-8B-Instruct | No official Q4_K_M; official Q8_0 is [8.54 GB](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF/tree/main). Community: [mradermacher/Foundation-Sec-8B-Instruct-GGUF](https://huggingface.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF/tree/main) 4.92 GB | `{{bos}}<|system|>\n…\n<|user|>\n…\n<|assistant|>\n`. **Injects a long default system prompt** ("You are a helpful cybersecurity assistant…") when none is given. EOS `<|end_of_text|>` (id 128001) ([tokenizer_config](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/main/tokenizer_config.json), [generation_config](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/main/generation_config.json)) | No `tools` in template. IFEval 0.811 (self-reported) |
| Foundation-Sec-1.1-8B-Instruct | **official** [Q4_K_M 4.92 GB](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF/tree/main) (GGUF metadata context 65,536) | Same role tags, no default system prompt. Every assistant turn ends with `eos_token`. EOS `<|end_of_text|>` (128001) ([tokenizer_config](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct/blob/main/tokenizer_config.json)) | No `tools` in template. IFEval 0.815 (self-reported) |
| Foundation-Sec-8B-Reasoning | **official** [Q4_K_M 4.92 GB](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF/tree/main) (+ [Q8_0](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF)) | Same role tags. Default system prompt "You are Metis, a cybersecurity reasoning model from the Minerva family developed by Foundation AI at Cisco… released in November 2025". generation_config: eos [128001, 128009], temperature 0.6, top_p 0.95, repetition_penalty 1.1 ([tokenizer_config](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/tokenizer_config.json)) | No `tools` in template |
| antares-1b / 350m | Community [HolkViking/antares-1b-Q4_K_M-GGUF](https://huggingface.co/HolkViking/antares-1b-Q4_K_M-GGUF/tree/main) 1.14 GB | `<think>`, `<tool_call>{"name":"terminal",…}</tool_call>`, `<tool_response>`; ends with `submit_vulnerable_files` ([card](https://huggingface.co/fdtn-ai/antares-1b)) | Native, but only a terminal tool for code search |
| Llama-Primus-Merged | Community [mradermacher/Llama-Primus-Merged-GGUF](https://huggingface.co/mradermacher/Llama-Primus-Merged-GGUF/tree/main) 4.92 GB | Standard Llama 3.1 template incl. tools; eos `<|eot_id|>`; gen eos [128001, 128008, 128009] ([tokenizer_config](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged/blob/main/tokenizer_config.json)) | **BFCL v2 74.77 (prompt)** vs Llama-3.1-8B-Instruct 73.02 (self-reported, [card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged)) |
| Llama-Primus-Reasoning | Community [DevQuasar-6/trendmicro-ailab.Llama-Primus-Reasoning-GGUF](https://huggingface.co/DevQuasar-6/trendmicro-ailab.Llama-Primus-Reasoning-GGUF/tree/main) 4.92 GB | Llama-3 headers, default "You are a helpful assistant.", no tools ([tokenizer_config](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning/blob/main/tokenizer_config.json)) | None |
| RedSage-Qwen3-8B-Ins / DPO | Community [mradermacher/RedSage-Qwen3-8B-Ins-GGUF](https://huggingface.co/mradermacher/RedSage-Qwen3-8B-Ins-GGUF/tree/main) and [-DPO-GGUF](https://huggingface.co/mradermacher/RedSage-Qwen3-8B-DPO-GGUF/tree/main), 5.03 GB each | ChatML with Qwen tools block. Default system "You are REDSAGE, cybersecurity-tuned model developed by Khalifa University". Tokenizer eos `<|im_end|>` but generation_config eos_token_id 151643 (`<|endoftext|>`) ([tokenizer_config](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins/blob/main/tokenizer_config.json)) | Template supports `<tool_call>`. The card's "tool use" means "Generating and explaining commands for tools like nmap, sqlmap, and metasploit", not function calling ([card](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins)). IFEval 79.97 vs Qwen3-8B 85.21 (self-reported) |
| MiST-8B | Community [mradermacher/MiST-8B-GGUF](https://huggingface.co/mradermacher/MiST-8B-GGUF/tree/main) 5.03 GB | Qwen3 template with tools; eos [151645, 151643]. The card says "MiST-8B uses the same inference setup as Qwen3-8B" ([card](https://huggingface.co/dreamgroup/MiST-8B)) | The card puts "Autonomous agent deployment" out of scope: "Agentic and tool-use capabilities have not been specifically trained or evaluated". IFEval 88.5 vs Qwen3-8B 90.0 (self-reported) |
| DeepHat-V1-7B | Community [mradermacher/DeepHat-V1-7B-GGUF](https://huggingface.co/mradermacher/DeepHat-V1-7B-GGUF/tree/main) 4.68 GB; Ollama listing `DeepHat/DeepHat-V1-7B` ([ollama search](https://ollama.com/search?q=deephat)) | ChatML "w/specific formatting for XLAM Qwen tool calling format"; default system "You are DeepHat…" ([tokenizer_config](https://huggingface.co/DeepHat/DeepHat-V1-7B/blob/main/tokenizer_config.json)) | Tools in template; no published tool score |
| WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B | [bartowski Q4_K_M](https://huggingface.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF/tree/main) 4.68 GB | Plain ChatML, no tools. The card tells users to seed "Sure! Let me provide…" to get past refusals ([card](https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B)) | None |
| Llama-3.1-WhiteRabbitNeo-2-8B | [bartowski Q4_K_M](https://huggingface.co/bartowski/Llama-3.1-WhiteRabbitNeo-2-8B-GGUF/tree/main) 4.92 GB | Template ends turns with `<|eot_id|>`, but generation_config eos is only 128001 (`<|end_of_text|>`), a possible run-on risk ([generation_config](https://huggingface.co/WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B/blob/main/generation_config.json)) | None |
| VulnLLM-R-7B | [mradermacher Q4_K_M](https://huggingface.co/mradermacher/VulnLLM-R-7B-GGUF/tree/main) 4.68 GB | Stock Qwen2.5 template with tools | n/a (code) |
| CyberSecQwen-4B | [mradermacher Q4_K_M](https://huggingface.co/mradermacher/CyberSecQwen-4B-GGUF/tree/main) 2.50 GB | **Template rewrites the `system` role as `user`**; no tools ([tokenizer_config](https://huggingface.co/athena129/CyberSecQwen-4B/blob/main/tokenizer_config.json)). Trained at max sequence length 4,096 | None |
| Gemma4Defense-2B | [mradermacher Q4_K_M](https://huggingface.co/mradermacher/Gemma4Defense-2B-GGUF/tree/main) 3.43 GB | Gemma 4 template with tools | None published |
| Tini-Cybersec-8B-A1B | [bartowski Q4_K_M](https://huggingface.co/bartowski/iselabvn_Tini-Cybersec-8B-A1B-GGUF/tree/main) 5.17 GB | LFM2.5 template with tools; gen temp 0.2, top_k 80, rep 1.05 ([generation_config](https://huggingface.co/iselabvn/Tini-Cybersec-8B-A1B/blob/main/generation_config.json)) | Tools in template; no score |
| alias3-micro-1026 | **No GGUF found**; only ONNX/MLC/LiteRT conversions by eduardoworrel ([HF search](https://huggingface.co/api/models?search=alias3&limit=30)) | Qwen3.5 template; served with `--tool-call-parser qwen3_coder --reasoning-parser qwen3` ([card](https://huggingface.co/aliasrobotics/alias3-micro-1026)) | "native tool calls, shell, multi-step reasoning". Typed-fact extraction 48.3% exact match (self-reported) |
| Cyber-Prime-1.2 | [mradermacher Q4_K_M](https://huggingface.co/mradermacher/Cyber-Prime-1.2-GGUF/tree/main) 1.67 GB | LFM2 template with tools; gen temp 0.1. The card advises: "For NER, request a JSON object" ([card](https://huggingface.co/Akahsizrr/Cyber-Prime-1.1-2.6B)) | CyNER F1 0.687 (self-reported, Q3) |
| cyber-analyst-4B | **official** `gemma-4-E4B-it.Q4_K_M.gguf` 5.34 GB + mmproj 0.99 GB ([tree](https://huggingface.co/BrainboxAI/cyber-analyst-4B/tree/main)) | Gemma 4; the card gives a recommended system prompt (temp 0.2, rep 1.05) ([card](https://huggingface.co/BrainboxAI/cyber-analyst-4B)) | Card: "Need JSON for a SIEM? Replace OUTPUT_FORMAT with your schema" (prompt-level only) |
| ZySec-7B (SecurityLLM) | Official GGUF only [Q8_0 7.7 GB](https://huggingface.co/ZySec-AI/ZySec-7B-GGUF/tree/main) (does not fit); [QuantFactory/SecurityLLM-GGUF](https://huggingface.co/QuantFactory/SecurityLLM-GGUF/tree/main) Q4_K_M 4.37 GB | Zephyr-style `<|system|>/<|user|>/<|assistant|>` with `</s>` after every turn | None |
| Lily-Cybersecurity-7B-v0.2 | **official** [Q4_K_M 4.37 GB](https://huggingface.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF/tree/main) | Mistral `[INST]`; **raises an exception on a system role** | None |
| SecGPT-7B | Official only [F16 15.24 GB](https://huggingface.co/clouditera/SecGPT-7B-GGUF/tree/main); [mradermacher Q4_K_M](https://huggingface.co/mradermacher/SecGPT-7B-GGUF/tree/main) 4.68 GB | Stock Qwen2.5 template ("You are Qwen…") | Tools in template |
| Seneca (Qwen2.5-7B) | [mradermacher Q4_K_M](https://huggingface.co/mradermacher/SenecaLLM_x_Qwen2.5-7B-CyberSecurity-GGUF/tree/main) 4.68 GB | Stock Qwen2.5 | Tools in template |
| BaronLLM v1 | Official [Q6_K 6.60 GB](https://huggingface.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF/tree/main) only | Llama 3.1 | — |
| exploitintel/cve-cwe-qwen3-8b | In-repo `qwen3-8b.Q4_K_M.gguf` [5.03 GB](https://huggingface.co/exploitintel/cve-cwe-qwen3-8b/tree/main) | Qwen3 template | Outputs CWE IDs |

- Ollama library: no official fdtn-ai, Trend Micro, RISys-Lab or Dream namespace was found.
  - Foundation-Sec appears only as community uploads (FenkoHQ/Foundation-Sec-8B, bogdancsn/Foundation-Sec-8B, dr-ry/foundation-sec-8b-instruct-chat-GGUF, axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF) plus an abliterated `Jarcgon/foundation-sec-abliterated` — [ollama search foundation-sec](https://ollama.com/search?q=foundation-sec).
  - A WhiteRabbitNeo namespace exists, including `WhiteRabbitNeo/WhiteRabbitNeo-V3-7B`, which is not on HF — [ollama search whiterabbitneo](https://ollama.com/search?q=whiterabbitneo).
  - The most-pulled security model on Ollama is the community `CyberCrew/notmythos-8b` (348.2K pulls, base undisclosed) — [ollama search security](https://ollama.com/search?q=security).

### Inferences
- **Foundation-Sec fix for Ollama.** The user's earlier `{{ .Prompt }}` template is consistent with Ollama failing to map Cisco's non-standard Jinja template. A Modelfile that mirrors the HF template should be:

  ```
  TEMPLATE """{{ if .System }}<|system|>
  {{ .System }}
  {{ end }}<|user|>
  {{ .Prompt }}
  <|assistant|>
  """
  PARAMETER stop "<|end_of_text|>"
  PARAMETER stop "<|user|>"
  ```

  For Reasoning, also add `PARAMETER stop "<|eot_id|>"` and use temp 0.6 / top_p 0.95 / repeat_penalty 1.1, per its generation_config. For multi-turn Instruct, append `<|end_of_text|>` after each prior assistant turn. This is derived from the tokenizer_config templates cited above; the exact generation-prompt string was truncated in my extract, and `<|assistant|>\n` is the pattern used for the other roles.
- **Memory.** A 5.0 GB Q4_K_M plus the CUDA context leaves roughly 1–1.5 GiB for KV cache. Use 8–16K context for 8B Llama/Qwen models and avoid running two 8B models at once. A 1.67 GB Cyber-Prime or 2.5 GB CyberSecQwen could sit next to one 8B model, but it would be tight.
- **Architecture risk for Ollama 0.20.0.**
  - Llama 3.x, Qwen2/2.5, Qwen3 and Mistral GGUFs are mainstream and should load.
  - Qwen3.5 models (alias3-micro, djini-4b, Qwen3.5-2B-CyberSec) will not load on 0.20.0, per the user's own finding.
  - Gemma 4, LFM2 and LFM2.5-MoE are unverified.
- **Thinking mode.** RedSage and MiST both start from Qwen3-8B-*Base*, not hybrid-thinking Qwen3-8B, so Qwen3's `/think` and `/no_think` switches should not be assumed to work. This is inferred from base_model metadata, not tested.

### Gaps
- Not verified: Ollama 0.20.0 or 0.40.13 support for Gemma-4 (cyber-analyst-4B, Gemma4Defense), LFM2 (Cyber-Prime), LFM2.5-MoE (Tini) and Granite-4.0 (Antares) GGUFs.
- No security model publishes a JSON-schema adherence benchmark. Primus-Merged's BFCL v2 is the only published function-calling score among ≤8B security models.
- Antares quant variants: the card links "16 quantizations" without naming an official GGUF.

---

## Q3. What published cyber benchmark scores exist, and which are self-reported?

### Takeaway
Nearly all scores are self-reported, protocols differ, and independent re-runs disagree by up to ~15 points. For example, Foundation-Sec-8B-Instruct scores CTI-MCQ 0.644 per Cisco but 0.4996 per a third party.

The best self-reported ≤8B results:
- **CTI-RCM (CVE→CWE):** RedSage-8B-Ins 76.7, Foundation-Sec-8B-Reasoning 0.753, MiST-8B 73.9
- **CTI-MCQ:** MiST-8B 79.3
- **CTI-ATE (ATT&CK technique extraction):** MiST-8B 57.3 (Athena-ATE)
- **CVSS (VSP):** Foundation-Sec-1.1 0.865 (Cisco's metric)

### Cited Findings

**Table C: benchmarks (S = self-reported, T = third-party)**

| Model | Scores | Source |
|---|---|---|
| Foundation-Sec-8B (base) | **S:** CTI-MCQA 67.39, CTI-RCM 75.26 (Llama 3.1 8B: 64.14 / 66.43; Llama 3.1 70B: 68.23 / 72.66) | [card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B); [arXiv 2504.21039](https://arxiv.org/abs/2504.21039) |
| | **T (athena129, 5-shot):** RCM 0.745, MCQ 0.655 | [CyberSecQwen-4B card](https://huggingface.co/athena129/CyberSecQwen-4B) |
| | **T (MiST authors, variant unspecified):** CTI-MCQ 58.2, RCM 67.9, SECURE-MAET 84.7, CWET 83.3, KCV 80.1, Athena-CKT 76.9, Athena-ATE 37.3, RMS 18.7, Athena-TAA 26.4, MMLU-Cyber 78.6, SecEval 65.0, mean 53.5 | [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B) |
| Foundation-Sec-8B-Instruct | **S:** CTI-MCQA 0.644, CTI-RCM 0.692, CTI-VSP 0.802, IF-Eval 0.811, AlpacaEval2 35.453; HarmBench 91.98% (0-shot, temp 0.3) | [card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) |
| | **T (athena129, 0-shot, strict acc):** MCQ 0.4996, RCM 0.6850 | [CyberSecQwen-4B card](https://huggingface.co/athena129/CyberSecQwen-4B) |
| Foundation-Sec-1.1-8B-Instruct | **S:** CTI-MCQA 0.644, RCM 0.694, VSP 0.865, IF-Eval 0.815, AlpacaEval2 32.643; HarmBench 94.74% | [card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct) |
| Foundation-Sec-8B-Reasoning | **S:** CTI-MCQA 0.691, RCM 0.753, VSP 0.856, CTI-Reasoning (internal, "second-degree connections between MITRE ATT&CK entities") 0.411; vs GPT-5-Nano 0.688 / 0.672 / 0.822 / 0.431; HarmBench 93.00% | [card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning); [arXiv 2601.21051](https://arxiv.org/abs/2601.21051) (10 cyber + 10 general benchmarks; numbers not in abstract) |
| Llama-Primus-Base | **S (5-shot, no CoT):** CISSP 0.7230, CTI-MCQ 0.6676, CTI-RCM 0.6780, CTI-VSP MAD 1.0912 (lower is better), CTI-ATE 0.3140, CyberMetric-500 0.8660, SecEval 0.5007 | [card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Base) |
| Llama-Primus-Merged | **S:** CTI-MCQ 0.6656, RCM 0.6620, VSP 1.1233, ATE 0.3387, CyberMetric 0.8660, SecEval 0.5062, CISSP 0.7191; MMLU 67.36; MT-Bench 8.29; LongBench 8K+ 50.66; BFCL v2 74.77 | [card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged) |
| | **T (MiST, "Primus-8B"):** CTI-MCQ 54.7, RCM 67.2, ATE 30.6, TAA 21.4, SecEval 60.9 | [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B) |
| Llama-Primus-Reasoning | **S:** CISSP 0.8193 (CoT, distilled o1+R1) vs Llama-3.1-8B-Instruct 0.7288 (CoT) | [card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning) |
| RedSage-Qwen3-8B-Ins | **S:** CTI-MCQ 70.56, CTI-RCM 76.70, CyberMetric-500 89.80, MMLU-Security 78.00, SecBench-En 79.91, SecEval 72.48, SECURE CWET 91.45 / KCV 81.34 / MEAT 91.47; IFEval 79.97 | [card](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins) |
| RedSage-Qwen3-8B-DPO | **S:** CTI-MCQ 70.84, RCM 70.60, CyberMetric 90.00, MMLU-Sec 79.00, SecBench-En 80.06, SecEval 74.22; IFEval 83.44 | [card](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-DPO) |
| | **T (MiST):** CTI-MCQ 62.0, RCM 73.2, ATE 51.6, TAA 22.8, SecEval 67.4, mean 56.5 | [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B) |
| RedSage-K-SFT-GRPO | **S (KaliBench):** Unrestricted exact match 32.2, total score 70.3 | [card](https://huggingface.co/RISys-Lab/RedSage-K-SFT-GRPO) |
| MiST-8B | **S:** CTI-MCQ 79.3, CTI-RCM 73.9, SECURE-MAET 94.3, CWET 93.7, KCV 87.3, Athena-CKT 86.0, Athena-ATE 57.3, Athena-RMS 25.7, Athena-TAA 24.6, PrimeVul 10.0, MMLU-Cyber 83.4, SecEval 71.5, mean 61.7 (vs Qwen3-8B 48.6); general: ARC-C 89.8, GSM8K 90.0, MMLU 74.9, IFEval 88.5 | [card](https://huggingface.co/dreamgroup/MiST-8B); [arXiv 2609.18496](https://arxiv.org/abs/2609.18496) |
| DeepHat-V1-7B | No self-reported scores. **T (MiST):** CTI-MCQ 54.7, RCM 67.2, ATE 9.8, TAA 14.8, SecEval 62.4, mean 48.4 | [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B) |
| Lily-Cybersecurity-7B | No self-reported scores. **T (MiST):** CTI-MCQ 42.1, RCM 42.9, mean 34.4 | [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B) |
| CyberSecQwen-4B | **S:** CTI-MCQ 0.5868 ± 0.0029, CTI-RCM 0.6664 ± 0.0023 (Foundation-Sec protocol, 5 trials) | [card](https://huggingface.co/athena129/CyberSecQwen-4B) |
| Gemma4Defense-2B | **S:** CTI-MCQ 0.6042 ± 0.0090, RCM 0.6754 ± 0.0035 | [card](https://huggingface.co/athena129/Gemma4Defense-2B) |
| Tini-Cybersec-8B-A1B | **S:** CS-Eval comprehensive 76.65% (leaderboard "under submission") | [card](https://huggingface.co/iselabvn/Tini-Cybersec-8B-A1B) |
| SecGPT-7B / 1.5B | **S:** CISSP 77.86 / 72.61, CS-Eval 88.24 / 84.32 (vs Qwen2.5-7B 66.30 / 84.66) | [SecGPT-7B card](https://huggingface.co/clouditera/SecGPT-7B) |
| Cyber-Prime-1.2 | **S (CyberBench subset, 2-shot):** CyNER F1 0.687, APTNER 0.507, CyNews ROUGE-1 0.461, SecMMLU 0.700, CyQuiz 0.750, phishing F1 0.979, HTTP-log F1 0.890, avg 0.711 | [card](https://huggingface.co/Akahsizrr/Cyber-Prime-1.2) |
| alias3-micro-1026 | **S:** Cybench-Subtask 21.1% (Qwen3.5-4B base 7.6%, Gemma-4 E4B 12.7%); typed-fact extraction 48.3% EM; phishing triage 92.5% bal-acc (decision head) | [card](https://huggingface.co/aliasrobotics/alias3-micro-1026) |
| exploitintel/cve-cwe-qwen3-8b | **S:** exact-match 0.676, micro-F1 0.702, macro-F1 0.511 on its own 6,802-row held-out split (easy 0.841 / hard 0.605 EM) | [card](https://huggingface.co/exploitintel/cve-cwe-qwen3-8b) |
| antares-1b / 350m | **S:** VLoc Bench File F1 0.209 (1B GRPO) / 0.135 (350M GRPO); no CTIBench | [antares-1b card](https://huggingface.co/fdtn-ai/antares-1b) |
| ZySec-7B, WRN (all), Seneca, BaronLLM, DexopT, cyber-analyst-4B, VulnLLM-R (card refers to paper) | No CTIBench/CyberMetric/SecEval numbers found on cards | respective cards above |
| Out of scope: CyberPal2.0-20B | Paper 0.874 / 0.757 (as cited by athena129, "Figure 11 of arXiv:2510.14113"); **T (athena129):** MCQ 0.738, RCM 0.728; **T (MiST):** 73.8 / 72.8 | [CyberSecQwen-4B card](https://huggingface.co/athena129/CyberSecQwen-4B); [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B) |

**Conflicts and protocol notes**
- **Foundation-Sec-8B-Instruct CTI-MCQ** differs by source: Cisco 0.644 vs athena129 0.4996 (0-shot strict accuracy). athena129 attributes this to an "instruction-tuning-collapses-MCQ effect" (−15.6 pp vs the Foundation-Sec base). Sources: [Cisco card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct); [CyberSecQwen-4B card](https://huggingface.co/athena129/CyberSecQwen-4B).
- **RedSage-8B-DPO** CTI-MCQ / RCM: self 70.84 / 70.60 vs MiST's run 62.0 / 73.2 — [RedSage-DPO card](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-DPO); [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B).
- **Primus** CTI-MCQ: Trend 0.6656 (Merged, 5-shot) vs MiST's "Primus-8B" 54.7 — [Primus-Merged card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged); [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B).
- **Cisco's Llama 3.1 8B baseline** is not stable across Cisco's own cards: CTI-MCQA 0.617 (Instruct and 1.1 cards) vs 0.607 (Reasoning card); RCM 0.558 vs 0.531 — [1.1 card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct); [Reasoning card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning).
- **CTI-VSP metric:** Cisco describes VSP as "average absolute difference from the true scores" yet reports rising values as improvements (0.802 → 0.865), so a transformed score is implied but not explained. Trend Micro reports raw MAD (lower is better, 1.09). The two cannot be compared — [Foundation-Sec-1.1 card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct); [Primus-Base card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Base).
- **Cyber-Prime 1.1 averages** disagree between cards: the 1.1 card gives avg 0.592 (CyNER 0.499), the 1.2 card lists 1.1 at avg 0.570 (CyNER 0.442) — [1.1 card](https://huggingface.co/Akahsizrr/Cyber-Prime-1.1-2.6B); [1.2 card](https://huggingface.co/Akahsizrr/Cyber-Prime-1.2).
- **CyberSecQwen contamination.** Its card reports that an earlier internal version had "roughly 72% test-set overlap when trained on undeduplicated CTI corpora", which is why the released model was decontaminated — [CyberSecQwen-4B card](https://huggingface.co/athena129/CyberSecQwen-4B).
- Benchmark references: CTIBench [arXiv 2406.07599](https://arxiv.org/abs/2406.07599) and CyberMetric [arXiv 2402.07688](https://arxiv.org/abs/2402.07688), as cited in the [Primus-Base card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Base).

### Inferences
- MiST's table is the only one that runs most ≤8B security models under a single protocol. It ranks them MiST-8B 61.7 > RedSage-8B-DPO 56.5 > Foundation-Sec-8B 53.5 > Qwen3-8B-Primus 53.2 > Primus-8B 50.6 > Qwen3-8B 48.6 > DeepHat 48.4 > Lily 34.4. MiST's authors ran it themselves, so it favours MiST. It is the best cross-model view available, but it needs local confirmation.
- On CTIBench TAA (threat-actor attribution), only MiST's "Athena-TAA" column exists for small models: 14.8–26.4. Foundation-Sec-8B (26.4) beats MiST (24.6). All are low.

### Gaps
- Not reported for any ≤8B model: official CTIBench TAA in the original CTIBench format, SecBench in Chinese, or CISSP for Foundation-Sec, RedSage or MiST.
- I did not read the full PDFs of arXiv 2601.21051 (Foundation-Sec-Reasoning), 2601.22159 (RedSage), 2609.18496 (MiST) or 2508.01059 (Foundation-Sec-Instruct); the abstract pages carry no tables. Per-benchmark details for the "10 cyber benchmarks" in the Reasoning report are therefore missing.
- arXiv 2602.00513 is "Minerva: Reinforcement Learning with Verifiable Rewards for CTI LLMs" (Alam, Piplai, Cardei, Rastogi, Worth; v1 31 Jan 2026). It reports +15.8 pp over base models across 12 CTI benchmarks, but the abstract names no released models — [arXiv 2602.00513](https://arxiv.org/abs/2602.00513). Its relation, if any, to the "Minerva family" named in the Foundation-Sec-Reasoning system prompt is unverified.

---

## Q4. Do general small models beat the specialised ones on published cyber benchmarks?

### Takeaway
Not on vulnerability-to-CWE mapping. Published third-party numbers put stock Qwen3-8B at CTI-RCM ~54, against 70–77 for the security 8B models. On knowledge MCQ, general models come close: third-party Gemma-4-E4B-it CTI-MCQ 0.666 vs Foundation-Sec-Instruct 0.500 at the same protocol. No published CTIBench numbers were found for Qwen3.5 4B/9B, Granite 4.x, Ministral 3 8B or Phi-4-mini.

### Cited Findings
- Qwen3-8B (non-reasoning), measured by RedSage authors: CTI-MCQ 62.76, CTI-RCM 54.00, CyberMetric 88.60, MMLU-Security 76.00, SecBench-En 73.26, SecEval 65.46, IFEval 85.21 — [RedSage-Ins card](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins).
- Qwen3-8B, measured by MiST authors: CTI-MCQ 58.2, RCM 53.5, Athena-ATE 9.4, TAA 15.0, SecEval 66.7, IFEval 90.0 — [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B).
- Measured by athena129 under the Foundation-Sec protocol — [CyberSecQwen-4B card](https://huggingface.co/athena129/CyberSecQwen-4B):

  | Model | Shots | CTI-MCQ | CTI-RCM |
  |---|---|---|---|
  | Qwen3-4B-Instruct-2507 | 0 | 0.473 | 0.519 |
  | Qwen3-4B-Base | 5 | 0.667 | 0.517 |
  | Gemma-4-E4B-it | 0 | 0.666 | 0.618 |
  | Gemma-4-E4B-base | 5 | 0.666 | 0.588 |

  Gemma-4-E2B-it scored 0.578 / 0.580 in the same harness — [Gemma4Defense-2B card](https://huggingface.co/athena129/Gemma4Defense-2B).
- Llama-3.1-8B-Instruct, measured by Trend Micro: CTI-MCQ 0.6420, RCM 0.5910, ATE 0.2721, CyberMetric 0.8560, SecEval 0.4966, CISSP 0.7073 — [Primus-Base card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Base). Measured by Cisco: 0.617 / 0.558 / VSP 0.815 — [Foundation-Sec-8B-Instruct card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct).
- Agentic CTF: Qwen3.5-4B 7.6% and Gemma-4 E4B 12.7% on Cybench-Subtask vs alias3-micro 21.1% (self-reported by Alias Robotics) — [alias3-micro card](https://huggingface.co/aliasrobotics/alias3-micro-1026).
- Small proprietary references: GPT-4o-mini CTI-MCQA 0.672 / RCM 0.655 / VSP 0.792 — [Foundation-Sec-1.1 card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct). GPT-5-Nano 0.688 / 0.672 / 0.822 — [Foundation-Sec-Reasoning card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning).
- A web search found no independent head-to-head of Qwen3.5 or Gemma 4 on CTIBench beyond these cards ([search result: athena129 space](https://athena129-cybersecqwen-chat.static.hf.space/index.html)).

### Inferences
- For CWE/CVSS/ATT&CK mapping (role 6), a security-tuned 8B should beat `qwen3:8b` by roughly 15–20 RCM points, if the self-reports hold.
- For product/vendor/version extraction (role 1), CTIBench says little. The user's own 17-CVE test (qwen3:8b 88% vs Foundation-Sec-1.1 65% with a broken template) is more relevant than any published number.

### Gaps
- No CTIBench, CyberMetric or SecEval numbers were found for Qwen3.5-4B/9B, Gemma-4-E4B (beyond athena129's MCQ/RCM), Granite 4.x, Ministral 3 8B, Phi-4-mini or Llama 3.2.

---

## Q5. Which models support Hindi/Marathi or other Indic languages?

### Takeaway
None of the security-specialised models claims Hindi, Marathi or any Indic language. Every card lists English, with exceptions: SecGPT (Chinese), cyber-analyst-4B (Hebrew + English), Primus-Merged (Japanese MMLU reported) and CyberSec-Assistant-3B (French). Translation (role 5) must use a general multilingual model.

### Cited Findings
- Language declarations:
  - Foundation-Sec cards: "Supported Language(s): English" — [Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B).
  - MiST: "Language: English" — [MiST-8B](https://huggingface.co/dreamgroup/MiST-8B).
  - CyberSecQwen-4B: "Languages: English" — [CyberSecQwen-4B](https://huggingface.co/athena129/CyberSecQwen-4B).
- Primus-Merged reports MMLU (Japanese) 47.85%, French 58.14% and German 56.68%; its metadata lists en and ja — [Primus-Merged](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged).
- SecGPT-7B's language tag is zh, and its card is in Chinese — [SecGPT-7B](https://huggingface.co/clouditera/SecGPT-7B).
- cyber-analyst-4B: "Roughly 45% Hebrew, roughly 55% English" — [cyber-analyst-4B](https://huggingface.co/BrainboxAI/cyber-analyst-4B).
- HF searches for Hindi or Indic security LLMs returned none (`search=hindi cyber`, `search=indic security`, `filter=hi&search=security` all empty; `filter=hi&search=cyber` returned only multilingual GLM/Nemotron re-uploads >8B and a MuRIL cyberbullying classifier) — [HF API](https://huggingface.co/api/models?filter=hi&search=cyber&limit=30).
- General models: Qwen3-8B claims "Support of 100+ languages and dialects… multilingual instruction following and translation" — [Qwen3-8B](https://huggingface.co/Qwen/Qwen3-8B). Gemma 4 claims "Out-of-the-box support for 35+ languages, pre-trained on 140+ languages" — [gemma-4-E4B-it](https://huggingface.co/google/gemma-4-E4B-it).

### Inferences
- Security fine-tunes trained on English-only security SFT (Foundation-Sec, RedSage, MiST) are likely to have lost multilingual quality. Translation should run on `qwen3:8b`, which is already loaded for other roles. Keep CVE IDs, ATT&CK IDs, product names and CVSS vectors as untranslated placeholders.

### Gaps
- There is no published Hindi or Marathi quality data for Qwen3-8B or Gemma-4-E4B on security text. Dedicated Indic MT models were not researched here (out of scope).

---

## Q6. Defensive vs offensive orientation, uncensored/abliterated variants, and other red flags

### Takeaway
For a C-DAC-judged hackathon whose rules ban hacking, use the defensive vendor and academic models: Foundation-Sec family, MiST, Primus, CyberSecQwen, Cyber-Prime, cyber-analyst. Avoid WhiteRabbitNeo, DeepHat, BaronLLM, DexopT, alias3-micro (offensive or dual-use, with de-refusal tooling) and every abliterated, heretic or obliterated variant.

### Cited Findings

**Defensive or safety-aligned**
- Foundation-Sec-Instruct/1.1/Reasoning report HarmBench 91.98% / 94.74% / 93.00% vs Llama-3.1-8B-Instruct 72.43% (62.75% on the Reasoning card). Out-of-scope uses include "Generate malware or other malicious code" — [Instruct card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct); [Reasoning card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning).
- MiST excludes "malware development" and "Autonomous agent deployment", and includes "safety and refusal data in the training mixture" — [MiST-8B](https://huggingface.co/dreamgroup/MiST-8B).
- CyberSecQwen-4B and Gemma4Defense-2B: "must not be used to produce exploit code" — [CyberSecQwen-4B](https://huggingface.co/athena129/CyberSecQwen-4B).
- cyber-analyst-4B: "It is not an offensive tool" — [card](https://huggingface.co/BrainboxAI/cyber-analyst-4B).
- Cyber-Prime: "intended for defensive security analysis" — [card](https://huggingface.co/Akahsizrr/Cyber-Prime-1.1-2.6B).
- Antares has "No standalone safety alignment (no RLHF or HarmBench evaluation)" — [antares-1b](https://huggingface.co/fdtn-ai/antares-1b).

**Offensive or dual-use**
- DeepHat "can be used for offensive and defensive cybersecurity" — [DeepHat-V1-7B](https://huggingface.co/DeepHat/DeepHat-V1-7B).
- WhiteRabbitNeo says the same, and its card tells users to seed responses to bypass refusals — [WRN 2.5](https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B).
- BaronLLM is "fine-tuned for *offensive cybersecurity research & adversarial simulation*" — [BaronLLM](https://huggingface.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF).
- DexopT is tagged offensive-security ("SQL injection, XSS, buffer overflows, reverse shells") — [DexopT](https://huggingface.co/DexopT/Qwen3-4B-Cybersecurity).
- RedSage covers "Skill (Offensive)" and "Tools (Kali)" and is "Generating and explaining commands for tools like nmap, sqlmap, and metasploit" — [RedSage-Ins](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins).
- alias3-micro: "No policy layer between operator and target". It also has optional steering overlays, including "a runtime refusal-direction projection for authorised de-refusal" — [alias3-micro](https://huggingface.co/aliasrobotics/alias3-micro-1026).

**Abliterated, uncensored or derived-unsafe variants**
- [DexopT/Qwen3-4B-Cybersecurity-Heretic-16bit](https://huggingface.co/DexopT/Qwen3-4B-Cybersecurity-Heretic-16bit)
- [e12ex2/Foundation-Sec-8B-Instruct-heretic](https://huggingface.co/e12ex2/Foundation-Sec-8B-Instruct-heretic) (834 DL)
- [Ironcybersec/foundation-sec-8b-red-team](https://huggingface.co/Ironcybersec/foundation-sec-8b-red-team)
- Ollama `Jarcgon/foundation-sec-abliterated` ([search](https://ollama.com/search?q=foundation-sec))
- mradermacher DeepHat-V1-7B-Heretic-Abliterated and WhiteRabbitNeo-2.5-…-OBLITERATED GGUFs ([HF search](https://huggingface.co/api/models?search=DeepHat&filter=gguf))
- NiroshanDb23/Lily-Cybersecurity-7B-Uncensored-GGUF ([HF search](https://huggingface.co/api/models?search=Lily-Cybersecurity&filter=gguf))
- [sds-ai/Foundation-Sec-8B-Chinese-Chat](https://huggingface.co/sds-ai/Foundation-Sec-8B-Chinese-Chat): a merge that includes `DavidAU/L3.1-Evil-Reasoning-Dark-Planet-Hermes-R1-Uncensored-8B`
- Dolphin3-Cyber LoRA (abliterated base)
- [xtools-at/Qwen3.5-4B-Qwensploit-CyberSecurity](https://huggingface.co/xtools-at/Qwen3.5-4B-Qwensploit-CyberSecurity) (base "…UNCENSORED-heretic")
- [RedTeamLab/Qwen3.5-4B-redteam-v4.1](https://huggingface.co/RedTeamLab/Qwen3.5-4B-redteam-v4.1)

**Other red flags**
- **Foundation-Sec-8B-Instruct:** the config says 131,072 context, but the 1.1 card says the earlier Instruct was 4k — [1.1 card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct).
- **Foundation-Sec licensing:** "other" = Llama 3.1 Community License plus Apache-2.0 for Cisco's changes ([NOTICE.md](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/main/NOTICE.md)). The 1.1 GGUF card nevertheless says it was "originally released on November 18, 2025 under Apache 2.0" — [GGUF card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF).
- **Foundation-Sec-8B-Reasoning dates:** the card says release 28 Jan 2026, the repo was created 6 Nov 2025, and the default system prompt says "released in November 2025" — [card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning); [API](https://huggingface.co/api/models/fdtn-ai/Foundation-Sec-8B-Reasoning).
- **Knowledge cutoff:** all Cisco post-trained models state a data cutoff of 10 Apr 2025, which matters for 2026 CVEs — [Reasoning card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning); [antares-1b](https://huggingface.co/fdtn-ai/antares-1b).
- **Antares:** "1B" on the card vs 1.84B in safetensors; self-built benchmark; proprietary data; manual gating — [antares-1b](https://huggingface.co/fdtn-ai/antares-1b).
- **MiST-8B:** the card calls it an "EMNLP paper", but the arXiv abstract page lists no venue; released 12 days ago; numbers for other models were run by MiST's authors — [MiST-8B](https://huggingface.co/dreamgroup/MiST-8B); [arXiv 2609.18496](https://arxiv.org/abs/2609.18496).
- **RedSage:** no license declared; IFEval drops to 79.97 from Qwen3-8B's 85.21 — [RedSage-Ins](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins).
- **Tini-Cybersec:** 8.47B total. Its training mix includes `nohurry/Opus-4.6-Reasoning-3000x-filtered` and `Jackrong/DeepSeek-V4-Distill-8000x` (distilled from proprietary models) and AlicanKiraz0's "offensive/defensive" Fenrir/Heimdall sets — [Tini card](https://huggingface.co/iselabvn/Tini-Cybersec-8B-A1B).
- **Cyber-Prime-1.9:** a GGUF exists ([mradermacher/Cyber-Prime-1.9-2.6B-GGUF](https://huggingface.co/mradermacher/Cyber-Prime-1.9-2.6B-GGUF)), but the source repo `Akahsizrr/Cyber-Prime-1.9-2.6B` returned HTTP 401 (private or removed).
- **amine47agent/DeepSeek-CyberSec-8B:** its only GGUF is named `DeepSeek-R1-Distill-Llama-8B.Q4_K_M.gguf` and the card has no license or base model, suggesting a re-upload — [API](https://huggingface.co/api/models/amine47agent/DeepSeek-CyberSec-8B).
- **Lily and ZySec:** January 2024 Mistral-7B era. Lily's third-party CTI-MCQ is 42.1 — [MiST-8B card](https://huggingface.co/dreamgroup/MiST-8B).
- **CyberSecQwen-4B:** a hackathon artifact. Its system→user template rewrite and 4k training length limit its use for long advisories — [card](https://huggingface.co/athena129/CyberSecQwen-4B).

### Inferences
- For the demo, show only defensive vendor or academic models. Even defensive models like Foundation-Sec are dual-use, and Cisco's own cards say so.
- RedSage is academically strong, but its offensive and Kali skill set is a poor optics fit for a "no hacking" event.

### Gaps
- No XSTest or over-refusal numbers for Foundation-Sec or MiST. Over-refusing on threat text (e.g. exploit descriptions inside advisories) is untested. Primus-Merged reports XSTest 83.20% vs Llama 93.20% — [Primus-Merged](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged).

---

## Q7. Which 1–3 generative models fit each role in our system?

### Takeaway
Run **two resident-on-demand models**:
- **`qwen3:8b`** for JSON extraction, narratives, copilot tool calling and Hindi/Marathi.
- **`Foundation-Sec-8B-Reasoning` (official Q4_K_M, 4.92 GB)** for Critical-alert reasoning and ATT&CK/CWE/CVSS mapping.

**MiST-8B** (community Q4_K_M, 5.03 GB) is the one challenger worth a quick A/B test on extraction and mapping. **Foundation-Sec-1.1-8B-Instruct** stays as an extraction/narrative fallback once its retest with the fixed template is done.

### Cited Findings
- Hardware fit: Foundation-Sec-8B-Reasoning Q4_K_M is 4.92 GB ([tree](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF/tree/main)); MiST-8B Q4_K_M is 5.03 GB ([tree](https://huggingface.co/mradermacher/MiST-8B-GGUF/tree/main)); Foundation-Sec-1.1 Q4_K_M is 4.92 GB ([tree](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF/tree/main)).
- The ranking evidence for each role is the Q2/Q3/Q4/Q6 findings above, each with its source.

**Role 1: structured JSON extraction (vendor, product, versions, vuln type)**
1. **qwen3:8b**: measured 88% locally. Native Ollama support, so it can use Ollama's JSON-schema `format`. Qwen3-8B IFEval is 85.21–90.0 (third-party, [RedSage card](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-Ins), [MiST card](https://huggingface.co/dreamgroup/MiST-8B)).
2. **MiST-8B**: same Qwen3-8B lineage and ChatML template. IFEval 88.5 (self-reported), and the best self-reported cyber suite mean among ≤8B models. Worth re-running the 17-CVE test ([card](https://huggingface.co/dreamgroup/MiST-8B)).
3. **Foundation-Sec-1.1-8B-Instruct** (with the fixed template): official GGUF, 64k context for long advisories, IFEval 0.815 (self-reported) ([card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct)). Its 65% score was obtained with a broken template and is not valid.
   - Not recommended: CyberSecQwen-4B (MCQ/RCM-format tuning, 4k training, system→user rewrite).

**Role 2: grounded alert narratives citing fact IDs**
1. **qwen3:8b** (non-thinking). Strongest measured instruction-following, and no model swap needed.
2. **Foundation-Sec-1.1-8B-Instruct**: defensive security voice, HarmBench 94.74%, 64k context ([card](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct)).
3. **MiST-8B**.
   - No security model publishes a grounding or citation benchmark. Enforce citations with a schema such as `{claim, fact_ids[]}` and reject any ID not in the input.

**Role 3: deep reasoning for the few Critical alerts**
1. **Foundation-Sec-8B-Reasoning**: official Q4_K_M; SFT + RLVR; CTI-RCM 0.753, VSP 0.856, CTI-Reasoning 0.411 vs GPT-5-Nano 0.431 (self-reported); HarmBench 93% ([card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning)). Use temp 0.6 / top_p 0.95 / rep 1.1 and run it asynchronously, since traces are long.
2. **qwen3:8b in thinking mode**: no swap needed.
3. **Llama-Primus-Reasoning**: CISSP 0.8193 with CoT (self-reported). Feb 2025 model, community GGUF only ([card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning)).

**Role 4: analyst copilot with tool calling over our database**
1. **qwen3:8b**: native Ollama tools.
2. **Llama-Primus-Merged**: the only ≤8B security model with a published function-calling score, BFCL v2 74.77 (self-reported). Standard Llama 3.1 tool template, 128K context ([card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged)).
3. **RedSage-Qwen3-8B-DPO**: has a Qwen tool template. But its "tool use" means CLI commands, its license is undeclared, and it has offensive skills, so low priority ([card](https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-DPO)).
   - Avoid for this role:
     - Foundation-Sec family: no `tools` in its templates.
     - MiST: tool use "not specifically trained or evaluated".
     - alias3-micro: Qwen3.5 base (Ollama 0.20.0 can't run it), dual-use, de-refusal overlay.

**Role 5: Hindi/Marathi translation of alerts**
1. **qwen3:8b**: "100+ languages and dialects… translation" ([Qwen3-8B](https://huggingface.co/Qwen/Qwen3-8B)).
2. **Gemma-4-E4B-it**: "35+ languages out of the box, 140+ pre-trained" ([gemma-4-E4B-it](https://huggingface.co/google/gemma-4-E4B-it)), if the Ollama build supports Gemma 4.
   - No security-specialised model qualifies (Q5).

**Role 6: mapping text to ATT&CK techniques, CWE and CVSS vectors**
1. **Foundation-Sec-8B-Reasoning**: RCM 0.753, VSP 0.856 (self-reported). It is the same model as role 3, so this costs only one swap.
2. **MiST-8B**: CTI-RCM 73.9, Athena-ATE 57.3 (best ≤8B ATT&CK technique extraction in MiST's table), SECURE-CWET 93.7 (self-reported).
3. **exploitintel/cve-cwe-qwen3-8b**, for CWE only: exact-match 0.676 on its own NVD/CNA-consensus split, with an in-repo Q4_K_M of 5.03 GB ([card](https://huggingface.co/exploitintel/cve-cwe-qwen3-8b)).
   - Alternative if Reasoning traces are too slow: Foundation-Sec-1.1-8B-Instruct (RCM 0.694, VSP 0.865, self-reported).

### Inferences
- **Minimise swaps.** Under 6.9 GiB only one ~5 GB model can be resident. Keep `qwen3:8b` hot and batch the Critical-alert and mapping work for Foundation-Sec-8B-Reasoning.
- **Trust our own data first.** Self-reported CTIBench numbers are not reliable enough to choose on. A 30-minute local check (17 CVEs for extraction; 20–30 CVEs with known NVD CWE/CVSS for mapping) between qwen3:8b, Foundation-Sec-8B-Reasoning, Foundation-Sec-1.1 (fixed template) and MiST-8B should decide the final set.
- **Don't trust models alone for CVSS and ATT&CK.** Prefer authoritative NVD/CNA vectors when present, and use the LLM only to fill gaps, with regex validation of `CVSS:3.1/AV:…` strings. Constrain ATT&CK output to IDs from a retrieved candidate list. This is a design inference, not sourced.
- **Judging narrative.** "Cisco Foundation-Sec (security-specialised, defensive, HarmBench-aligned) for analysis and mapping, plus a general multilingual model for extraction, copilot and Hindi/Marathi" fits the C-DAC "national, defensive" framing.

### Gaps
- No published evidence covers fact-ID-grounded narrative quality, JSON-schema adherence under Ollama `format`, or Marathi translation quality for any candidate. These need local testing.
- MiST-8B's behaviour in Ollama (template recognition from the mradermacher GGUF) is untested.
