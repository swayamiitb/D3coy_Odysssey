# Serving local LLMs on an 8 GB laptop GPU (RTX 4070 Laptop, Windows 11) for a real-time security analytics app — as of 31 Oct 2026

Target box: RTX 4070 Laptop (8 GB GDDR6, Ada, CC 8.9, about 0.9 GB already used by the Windows desktop), i9-14900HX, 32 GB RAM, NVMe, CUDA 13.1. Ollama 0.20.0 installed; Ollama 0.40.13 portable available. Workload: batch JSON extraction and narratives, live streamed narratives, a tool-calling copilot, an embedding model, and possibly two 8B models that swap.

Notation: "(2024)" or "(2025)" marks findings older than 2026. Every number under "Cited Findings" comes from the linked source. Anything I worked out myself (budget arithmetic, scaling estimates) is under "Inferences".

---

## 1. Quantisation quality vs speed for 8B models (Q4_K_M / Q5_K_M / Q6_K / Q8_0 / IQ4_XS); does Q4_K_M hurt Llama-3.1-8B-based security models?

### Takeaway
On Llama-3.1-8B, Q4_K_M raises wikitext perplexity about 2.9% over BF16, Q5_K_M about 1.0%, Q6_K about 0.35% and Q8_0 about 0.1%. Downstream benchmark scores stay within error bars. The one task-level measurement found (tool-calling F1) shows a small but real drop for Llama-3.1-8B at Q4_K_M: 0.835 → 0.793. On this card, Q8_0 (about 8 GiB of weights) cannot fit, and Q6_K leaves almost no headroom. The realistic choices are **Q4_K_M** (default) or **Q5_K_M** (if one 8B model stays resident at a modest context). IQ4_XS is a valid squeeze option.

### Cited Findings
**Size and speed (llama.cpp's own Llama-3.1-8B table; hardware not stated):**
- Q4_K_M: 4.8944 bpw, 4.58 GiB, pp512 821.81 t/s, tg128 71.93 t/s — [llama.cpp quantize README](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
- Q5_K_M: 5.7036 bpw, 5.33 GiB, pp512 758.69, tg128 67.23 — [same](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
- Q6_K: 6.5633 bpw, 6.14 GiB, pp512 812.01, tg128 58.67 — [same](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
- Q8_0: 8.5008 bpw, 7.95 GiB, pp512 865.09, tg128 50.93 — [same](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
- IQ4_XS: 4.4597 bpw, 4.17 GiB, pp512 771.80, tg128 77.51 — [same](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
- Q4_K_S: 4.6672 bpw, 4.36 GiB, tg128 76.71 — [same](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
- F16: 14.96 GiB, tg128 29.17 — [same](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
- The README does **not** include PPL or KLD for these rows — [same](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)

**Perplexity, Llama-3.1-8B (wikitext-2-raw-v1, llama.cpp b3472; 2024):**

| Quant | File size | PPL |
|---|---|---|
| BF16 | 16.10 GB | 6.4006 |
| Q8_0 | 8.54 GB | 6.4070 |
| Q6_K | 6.60 GB | 6.4231 |
| Q5_K_M | 5.73 GB | 6.4623 |
| Q5_K_S | 5.60 GB | 6.5161 |
| Q4_K_M | 4.92 GB | 6.5837 |
| Q4_K_S | 4.69 GB | 6.6751 |
| Q3_K_M | 4.02 GB | 7.0488 |
| Q2_K | 3.18 GB | 9.7262 |

Source: [fedric95/Meta-Llama-3.1-8B-GGUF](https://huggingface.co/fedric95/Meta-Llama-3.1-8B-GGUF)

- Same repo, downstream scores, Q8_0 vs Q4_K_M — [fedric95](https://huggingface.co/fedric95/Meta-Llama-3.1-8B-GGUF):
  - WinoGrande 74.11 ±1.23 vs 73.17 ±1.25
  - HellaSwag 79.42 vs 79.06
  - MMLU 39.47 ±1.24 vs 39.53 ±1.24
  - The differences are within the error bars.

**KL divergence, Llama-Guard-3-8B vs F16 (a Llama-3.1-8B fine-tune for safety classification, so the closest "security-classifier" proxy found):**

| Quant | Mean KLD | RMS Δp | PPL correlation |
|---|---|---|---|
| Q8_0 | 0.0048 | 2.07% | 99.89% |
| Q6_K | 0.0073 | 2.53% | 99.83% |
| Q5_K_M | 0.0173 | 3.87% | 99.62% |
| Q4_K_M (naive) | 0.0308 | 5.26% | 99.34% |

- The author's experimental layer-wise "smaller" Q4_K_M (4.41 GB) was worse: KLD 0.0558, RMS Δp 7.0%. — [eaddario/Llama-Guard-3-8B-GGUF](https://huggingface.co/eaddario/Llama-Guard-3-8B-GGUF)
- Mistral-7B, median KLD (Artefact2 gist; 2024): Q4_K_M 0.0075 (4.83 bpw), IQ4_XS 0.0088 (4.32 bpw), Q5_K_M 0.0043, Q6_K 0.0032. — [Artefact2 gist](https://gist.github.com/Artefact2/b5f810600771265fc1e39442288e8ec9). Note: this is a median on another model, so it is not directly comparable with eaddario's means.
- Llama 3 under low-bit quantisation (2024 paper): "still suffers non-negligible degradation… especially in ultra-low bit-width". Secondary summaries say 4-bit remains viable and 2–3-bit is where losses become large. — [Huang et al., arXiv 2404.14047](https://arxiv.org/abs/2404.14047v1). I did not verify the 4-bit figures against the paper's tables.

**Task-level evidence (tool calling, Docker eval, June 2025, M4 Max):**
- Llama 3.1 8B: F16 F1 0.835 vs Q4_K_M 0.793 — [Docker blog](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/)
- Qwen3 8B: F16 0.933 vs Q4_K_M 0.919 — [same](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/)
- The authors say they saw "no significant difference" between quantised and non-quantised variants — [same](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/)

**Security-specific models:**
- Cisco's Foundation-Sec-8B is continued-pretrained from Llama-3.1-8B. Its official Q4_K_M GGUF is about 4.92 GB and published **without** any Q4-vs-full-precision benchmark. Ollama pull: `ollama run hf.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF:Q4_K_M`. Base model released 28 Apr 2025. — [fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF)
- Instruct GGUFs exist from community quantisers (e.g., mradermacher, with imatrix quants in a separate repo) — [mradermacher/Foundation-Sec-8B-Instruct-GGUF](https://huggingface.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF)
- Anecdotal (blog): coding showed more errors at Q4_K_M than Q5_K_M, while chat felt similar — via search summary of [eastondev GGUF guide](https://eastondev.com/blog/en/posts/ai/20260422-ollama-gguf-quantization/). Opinion, not a measurement.

### Inferences
- Relative to BF16 perplexity (my arithmetic on fedric95's table): Q8_0 +0.10%, Q6_K +0.35%, Q5_K_M +0.96%, Q4_K_M +2.86%, Q4_K_S +4.29%. The Q4_K_M → Q5_K_M step buys the largest quality gain per extra GB.
- **Fit on this card** (about 7.1 GB usable after the desktop):
  - Q8_0 (7.95 GiB weights) cannot run fully on GPU.
  - Q6_K (6.14 GiB) leaves under 1 GB for KV cache, compute buffers and CUDA context. That works only at very small context, with no embedding model resident.
  - Q5_K_M (5.33 GiB) fits with about 8K context and q8_0 KV, but not alongside a second model.
  - Q4_K_M (4.58 GiB) is the only 8B quant that comfortably leaves room for an embedding model and 8K+ context.
- Q4_K_M on a Llama-3.1-8B security model should be fine for JSON extraction where the answer is grounded in the prompt (copying fields, picking enum values), because the top-token agreement loss is small (RMS Δp of about 5%).
- Q4_K_M is more likely to hurt on knowledge recall (e.g., "which ATT&CK technique ID is this?") and on multi-step reasoning. The Llama 3.1 tool-call F1 drop of about 0.04 is the best task-level signal: modest but real.
- If one model is resident and the context is ≤8K, Q5_K_M is a cheap upgrade. It costs about 7% decode speed versus Q4_K_M in llama.cpp's table.
- Prefer imatrix ("i1"/bartowski-style) Q4_K_M files when importing from HF. That is a general community practice I did not measure here.

### Gaps
- No public KLD or PPL table exists for Foundation-Sec-8B(-Instruct) or Llama-Primus at each quant. No security-benchmark (CTIBench/CyberMetric) comparison of Q4_K_M vs BF16 was found.
- No JSON-extraction-specific quant comparison was found for any 8B model.
- No measured IQ4_XS perplexity for Llama-3.1-8B was found.
- The llama.cpp README speed table does not state its hardware, so only the ratios between quants are usable.

---

## 2. KV-cache quantisation (q8_0, q4_0) and flash attention in Ollama/llama.cpp: VRAM saved, quality impact, version support

### Takeaway
Set `OLLAMA_FLASH_ATTENTION=1` and `OLLAMA_KV_CACHE_TYPE=q8_0`. q8_0 halves KV memory with near-zero measured perplexity change. q4_0 quarters it but shows measurable loss, which grows with context and is reported to hurt tool calls.

The feature has been in Ollama since Dec 2024 (PR #6279), so both 0.20.0 and 0.40.13 support it. The setting is **global** (server-wide, not per model). Flash attention is now auto-enabled for some architectures (qwen3, gemma3, etc.) on Ampere and newer GPUs, but forcing it on is the safe choice for Llama-arch models.

### Cited Findings
**Official Ollama FAQ:**
- `OLLAMA_KV_CACHE_TYPE` defaults to `f16`.
- `q8_0` uses about half the memory of f16 with "a very small loss in precision".
- `q4_0` uses about a quarter of f16, with "small-medium loss… more noticeable at higher context sizes".
- Quantisation applies only when flash attention is enabled.
- It is a global setting.
- Models with a high GQA count (e.g., Qwen2) may lose more.
- Source: [Ollama FAQ](https://docs.ollama.com/faq)
- The FAQ says Ollama uses flash attention "automatically when the selected backend and devices support it". `OLLAMA_FLASH_ATTENTION=1` forces it on and `=0` turns it off — [Ollama FAQ](https://docs.ollama.com/faq)

**Original implementation post (Dec 2024):**
- Merged via PR #6279 — [smcleod.net](https://smcleod.net/2024/12/bringing-k/v-context-quantisation-to-ollama/)
- q8_0 saves about 50% and q4_0 about 66% of KV VRAM. Example for an 8B model at 32K context: F16 ~6 GB, Q8_0 ~3 GB, Q4_0 ~2 GB — [same](https://smcleod.net/2024/12/bringing-k/v-context-quantisation-to-ollama/)
- Quality: Qwen2.5-Coder-7B Q6_K PPL was 8.3891 (f16 KV) vs 8.3934 (q8_0 KV). Early tests showed q4_0 adding about +0.21–0.25 PPL ("some noticeable quality reduction") — [same](https://smcleod.net/2024/12/bringing-k/v-context-quantisation-to-ollama/)
- Without flash attention, Ollama falls back to F16 and logs a warning — [same](https://smcleod.net/2024/12/bringing-k/v-context-quantisation-to-ollama/)
- The setting cannot be made per Modelfile, per API call or per CLI command. K and V cannot use different types in Ollama — [same](https://smcleod.net/2024/12/bringing-k/v-context-quantisation-to-ollama/)
- Embedding models are auto-detected and their KV quantisation is disabled, with a warning in the log — [same](https://smcleod.net/2024/12/bringing-k/v-context-quantisation-to-ollama/)
- Supported on CUDA GPUs from Pascal onward — [same](https://smcleod.net/2024/12/bringing-k/v-context-quantisation-to-ollama/)

**Conflicting fallback reports:** another source says Ollama panics on load instead of falling back when FA is unsupported — via [llmhardware.io guide](https://llmhardware.io/guides/kv-cache-quantization-ollama-llama-cpp). Behaviour varies by version.

**Community measurements (2026):**
- Qwen3.6-27B PPL: F16 6.9233, q8_0 6.9193, q4_0 6.9381 — [r/LocalLLaMA snapshot](https://reddit.sentinel-team.org/posts/1suur3s/snapshots/2026-05-02T03%3A06%3A21.60641Z). This is a single user's test.
- A single-model output-similarity test (Qwen2.5-Coder-7B) found q8_0 close to f16 and q4_0 "a cliff" — [InventiveHQ](https://inventivehq.com/blog/kv-cache-quantization-quality-benchmark). The metric is non-standard.
- Claimed asymmetric costs: K at q8 under 0.1% PPL, K at q4 about 0.4%, V at q4 about 1.4% — [techplained](https://www.techplained.com/kv-cache-quantization). Unverified methodology.
- Claim that q4 KV degrades tool-call accuracy, so use q8 or higher — [InsiderLLM function-calling guide, upd. 16 Oct 2026](https://insiderllm.com/guides/function-calling-local-llms/)

**llama.cpp flags:** `-ctk/-ctv` (`--cache-type-k/--cache-type-v`). V-cache quantisation needs flash attention — [llmhardware.io](https://llmhardware.io/guides/kv-cache-quantization-ollama-llama-cpp)

**Flash-attention defaults:**
- In 2024, PR #4120 auto-enabled FA only when a supported CUDA version or Metal was detected — [ollama PR #4120](https://github.com/ollama/ollama/pull/4120)
- Ollama 0.30.0 (13 May 2026) reportedly turns FA on automatically for `qwen3, qwen3moe, qwen3vl, qwen3vlmoe, gemma3, gpt-oss, mistral3` on NVIDIA Ampere and newer. `OLLAMA_FLASH_ATTENTION` still defaults to false and acts as an override — [InsiderLLM 0.30 guide](https://insiderllm.com/guides/ollama-0-30-0-whats-new/). This is a secondary source; the official 0.30.0 notes do not list it ([v0.30.0](https://github.com/ollama/ollama/releases/tag/v0.30.0)).
- Ollama 0.17.0 (21 Feb 2026) "supports 8-bit KV cache quantization" as part of the new-engine release — [InsiderLLM 0.17 guide](https://insiderllm.com/guides/ollama-0-17-new-features/). The feature predates 0.17; this likely refers to the new engine path.

### Inferences
- **KV size per token, worked out by me** (not fetched this session). Llama-3.1-8B uses GQA with 32 layers, 8 KV heads and head dim 128 (from its public config.json):
  - f16: 2 × 32 × 8 × 128 × 2 bytes = 128 KiB/token, so 8K context ≈ 1.0 GiB and 32K ≈ 4 GiB.
  - q8_0 (≈1.06 bytes/value): 8K ≈ 0.53 GiB, 32K ≈ 2.1 GiB.
  - q4_0 (≈0.56 bytes/value): 8K ≈ 0.28 GiB.
  - smcleod's "8B @32K F16 ≈ 6 GB" is higher than this; it probably includes compute buffers or a different model.
  - Qwen3-8B/4B (36 layers, 8 KV heads, dim 128) ≈ 144 KiB/token at f16.
- At the context lengths this app needs (4–8K), q8_0 saves only about 0.5 GB on an 8B Llama. That is still worth it on 8 GB, because it is roughly the space an embedding model needs. q4_0 is not worth the quality risk at these lengths.
- Because the KV type is global, q8_0 also applies to the copilot. The evidence says q8_0 is safe for tool calling; q4_0 is the risky one.
- Ada (CC 8.9) is well within FA support. Forcing `OLLAMA_FLASH_ATTENTION=1` guarantees KV quantisation engages for the Llama arch, which is not on the reported auto-FA list.
- Verify in the server log (look for a KV/flash-attention line) or by checking that `ollama ps` size drops after the change.

### Gaps
- No official Ollama release note found that states the exact per-architecture FA default list (only the secondary InsiderLLM claim).
- The Ollama version that first shipped PR #6279 is not stated in the sources found. It was merged around Dec 2024, so it predates both installed versions.
- No KV-quant quality measurement on Llama-3.1-8B specifically, nor on JSON extraction.

---

## 3. Expected tokens/s for 4B and 8B Q4 models on an RTX 4070 Laptop; prompt-processing speed

### Takeaway
Expect roughly **35–45 tok/s decode for an 8B Q4_K_M** and roughly **60–75 tok/s for a 4B Q4_K_M** on this laptop GPU, if it is fully on GPU and not power-throttled. The only measured 4070-Laptop figure found is 39.7 tok/s for a 7B Q4_K_M (2024).

Prompt processing should run in the low thousands of tok/s for 8B, so a 2–3K-token alert context should prefill in about 1 s. Decode is memory-bandwidth-bound: the laptop chip has about 256 GB/s, roughly half the desktop 4070's ~504 GB/s.

### Cited Findings
**Laptop GPU spec:**
- RTX 4070 Laptop: 4608 CUDA cores, 128-bit bus at 16 Gbps effective, boost 1605–2175 MHz — [Notebookcheck](https://www.notebookcheck.net/NVIDIA-GeForce-RTX-4070-Laptop-GPU-Benchmarks-and-Specs.675690.0.html)
- Bandwidth listed as 256 GB/s for the 140 W variant (259 GB/s on some variants) — [LaptopMedia 140W](https://laptopmedia.com/tr/video-card/nvidia-geforce-rtx-4070-laptop-140w/)
- TGP varies by laptop: 115 W is a common reference, and Notebookcheck lists models from about 65 W to 140 W — [GPUPrix](https://gpuprix.com/ireland/gpus/geforce-rtx-4070-laptop); [Notebookcheck](https://www.notebookcheck.net/NVIDIA-GeForce-RTX-4070-Laptop-GPU-Benchmarks-and-Specs.675690.0.html)
- Laptop vs desktop 4070: 4608 vs 5888 shaders, 8 vs 12 GB, 115 W vs 200 W — [GPUPrix](https://gpuprix.com/ireland/gpus/geforce-rtx-4070-laptop)
- Desktop 4070 bandwidth is about 504 GB/s, per a search-result summary of [kunalganglani.com](https://www.kunalganglani.com/blog/rtx-4060-vs-rtx-4070-for-ai)

**Measured on the 4070 Laptop (2024, Jan.ai):**
- Mistral-7B-v0.2 Q4_K_M with llama.cpp on GPU: **39.70 tok/s**; CPU-only: 11.57 tok/s — [Jan.ai TensorRT-LLM benchmark](https://www.jan.ai/post/benchmarking-nvidia-tensorrt-llm)
- TensorRT-LLM AWQ INT4: 51.57 tok/s (+29.9%) — [same](https://www.jan.ai/post/benchmarking-nvidia-tensorrt-llm)
- Caveat: Jan's spec table lists 272 GB/s, 192-bit and 7,680 cores for this GPU, which contradicts Notebookcheck. Treat Jan's spec table as wrong, but the measured tok/s as valid.

**Calculator estimate (not measured):** Llama-3.1-8B Q4_K_M on 4070 Laptop 8GB ≈ 39.9 tok/s decode; one related page lists TTFT ≈ 4.9 s — [willitrunai](https://willitrunai.com/can-run/hf-bartowski--meta-llama-3-1-8b-instruct-gguf-on-rtx-4070-laptop-8gb)

**Measured upper reference (desktop RTX 4070 Ti 12 GB, llama-bench b10566, CUDA 13.3, FA off, f16 KV, Q4_K_M, Aug 2026):**

| Model | pp512 | tg128 | VRAM |
|---|---|---|---|
| Qwen3-4B | 9932.6 t/s | 148.9 t/s | 3819 MiB |
| Qwen3-8B | 5881.7 t/s | 89.5 t/s | 6128 MiB |

- Power: about 206–215 W during generation — [uepon blog](https://uepon.hatenadiary.com/entry/2026/08/26/002643)
- CPU-only on that desktop: 8B 8.8 tok/s, 4B 15.8 tok/s — [same](https://uepon.hatenadiary.com/entry/2026/08/26/002643)
- Qwen3-14B decode falls from 51.1 to 38.0 tok/s as KV depth grows from 0 to 16K, and collapses to 2.3 tok/s at 32K once VRAM overflows — [same](https://uepon.hatenadiary.com/entry/2026/08/26/002643)
- llama.cpp's CUDA scoreboard (Llama-2-7B Q4_0) has **no** 4070 Laptop entry. On a 4070 Ti SUPER, FA on vs off changes pp512 from 6924 to 7612 and leaves tg128 flat at ~132 — [llama.cpp discussion #15013](https://github.com/ggml-org/llama.cpp/discussions/15013)
- Relative decode cost by quant (Llama-3.1-8B): IQ4_XS 77.5 > Q4_K_S 76.7 > Q4_K_M 71.9 > Q5_K_M 67.2 > Q6_K 58.7 > Q8_0 50.9 tok/s — [llama.cpp quantize README](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)

### Inferences
- **Decode:** scaling the 4070 Ti numbers by the bandwidth ratio (256/~504 ≈ 0.51; the 4070 Ti figure is my unsourced knowledge) gives about 45 tok/s for 8B Q4_K_M and about 75 tok/s for 4B Q4_K_M. Real-world efficiency is usually 80–90% of this, and the Jan.ai 7B measurement of 39.7 tok/s is consistent. So budget **~40 tok/s (8B)** and **~65 tok/s (4B)**.
- **Prefill:** scaling by cores and clocks (about 0.5–0.6× the 4070 Ti) gives roughly 2,500–3,500 tok/s for 8B and 5,000+ for 4B at short contexts. A 2K-token prompt then prefills in under 1 s on GPU. The willitrunai TTFT of about 4.9 s looks pessimistic.
- **Batch budget:** 300 extractions × ~300 output tokens at ~40 tok/s ≈ 7.5 s each ≈ **~40 min sequential**. Start the precompute early.
- **Live demo:** ~40 tok/s is well above reading speed, which is fine for streamed narratives.
- **Throttling:** sustained batch runs on a laptop can lose speed. Plug in AC power, use the vendor's "performance" mode, and watch `nvidia-smi` clocks and power.
- **Partial offload:** any spill to system RAM (shown in `ollama ps` as a CPU/GPU split) drops decode toward CPU speeds of about 9–16 tok/s. That is the main performance risk on 8 GB.

### Gaps
- I found no published llama-bench or Ollama measurement for an 8B or 4B model on an RTX 4070 *Laptop* in 2025–2026. Run `llama-bench -m model.gguf -ngl 99 -fa 1` or read `eval_count/eval_duration` from Ollama's responses to get real numbers.
- No measured prompt-processing figure for this exact GPU was found.

---

## 4. VRAM budgeting, model swap/load latency, OLLAMA_MAX_LOADED_MODELS, keep_alive; can a 0.6B embedding model co-reside with an 8B model?

### Takeaway
Yes: an 8B Q4_K_M at 4–8K context with q8_0 KV, plus `qwen3-embedding:0.6b` (639 MB), should fit in the ~7.1 GB left after the desktop. **Two 8B models cannot co-reside** (≈9.2 GiB of weights alone), so they must swap.

Ollama only runs models concurrently when each new model fits entirely in VRAM. Otherwise it unloads idle models and queues the request. Expect a swap to cost a few seconds from NVMe, so batch jobs by model and pin the live-demo model with `keep_alive: -1`.

### Cited Findings
**Ollama FAQ defaults and rules:**
- `OLLAMA_MAX_LOADED_MODELS` defaults to 3 × the number of GPUs.
- `OLLAMA_NUM_PARALLEL` defaults to 1, and "Required RAM will scale by `OLLAMA_NUM_PARALLEL` * `OLLAMA_CONTEXT_LENGTH`".
- `OLLAMA_MAX_QUEUE` defaults to 512; extra requests get a 503.
- `keep_alive` defaults to 5 min. It accepts a duration, seconds, a negative value (keep loaded forever) or `0` (unload immediately). The API value overrides `OLLAMA_KEEP_ALIVE`.
- Preload by sending an empty request to `/api/generate` or `/api/chat`, or `ollama run model ""`. Unload with `ollama stop model`.
- "When using GPU inference new models must be able to completely fit in VRAM to allow concurrent model loads". Otherwise requests queue while idle models are unloaded.
- Source: [Ollama FAQ](https://docs.ollama.com/faq)

**Context default:**
- The default context depends on VRAM: under 24 GiB gets **4k**, 24–48 GiB gets 32k, 48 GiB and up gets 256k. Override with `OLLAMA_CONTEXT_LENGTH`.
- `ollama ps` shows the allocated `CONTEXT` and the GPU/CPU split in `PROCESSOR`.
- Source: [Ollama context-length doc](https://docs.ollama.com/context-length)
- Conflicting doc: the Modelfile reference still lists `num_ctx` default 2048 — [Ollama Modelfile doc](https://docs.ollama.com/modelfile)

**Scheduler:** since 0.17.0 (Feb 2026), the scheduler "measures exact memory needs" instead of estimating, and `nvidia-smi` should match `ollama ps` — [InsiderLLM 0.17 guide](https://insiderllm.com/guides/ollama-0-17-new-features/)

**Recent fixes:**
- v0.40.4 (12 Oct 2026): "reuses verified manifests and already loaded models" — [Ollama releases](https://github.com/ollama/ollama/releases)
- v0.40.6 (16 Oct 2026): "win: prevent orphaned runners" — [Ollama releases](https://github.com/ollama/ollama/releases)

**Sizes:**
- `qwen3-embedding:0.6b` = 639 MB (32K context); `4b` = 2.5 GB; `8b` = 4.7 GB — [ollama.com/library/qwen3-embedding](https://ollama.com/library/qwen3-embedding)
- Llama-3.1-8B Q4_K_M = 4.58 GiB of weights — [llama.cpp README](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
- Foundation-Sec-8B Q4_K_M is about 4.94 GB of RAM at runtime on CPU — [fdtn-ai GGUF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF)
- Qwen3-8B Q4_K_M used 6128 MiB of VRAM in llama-bench on a 12 GB card — [uepon](https://uepon.hatenadiary.com/entry/2026/08/26/002643)

**Load latency (blog estimates, not tied to this hardware):**
- 7B cold start ≈ 3–10 s; 70B ≈ 18 s from NVMe vs ≈ 74 s from SATA — [DEV Community](https://dev.to/jovan_chan_9500711396d4e6/ollama-keeps-reloading-the-model-fix-vram-unloading-cold-starts-and-model-swapping-2026-25b7)
- 7B ≈ 10–15 s; 14B ≈ 20–30 s — [eastondev](https://eastondev.com/blog/en/posts/ai/20260406-ollama-multi-model-deployment/)
- Advice for 8 GB cards: keep one model preloaded, because two 7B models resident risk OOM. Ollama evicts the longest-idle model, and a `size_vram` lower than the model size in `/api/ps` means it has partly spilled to RAM — [mljourney](https://mljourney.com/ollama-keep-alive-and-model-preloading-eliminate-cold-start-latency/)

### Inferences
**VRAM budget for this laptop** (approximate, my arithmetic):

| Item | Size |
|---|---|
| Total VRAM | 8.0 GB |
| Used by the Windows desktop | 0.9 GB |
| CUDA context and runner overhead (assumed) | ~0.3–0.5 GB |
| **Usable** | **~6.6–6.8 GB** |

**Option A — one 8B for all roles, plus the embedding model:**

| Item | Size |
|---|---|
| 8B Q4_K_M weights | 4.6 GB |
| 8K q8_0 KV | 0.55 GB |
| Compute buffers (assumed) | ~0.4–0.6 GB |
| qwen3-embedding:0.6b, weights and buffers | ~0.8 GB |
| **Total** | **~6.4–6.6 GB** |

This fits, but with little margin. Drop context to 4K or move embeddings off the GPU if `ollama ps` shows a CPU split.

**Option B — 8B plus a 4B:** 4.6 + ~2.5 GB of weights alone exceeds the usable VRAM. This does not fit without spill.

**Option C — two 8B models:** these must swap. Rough cost: reading ~4.9 GB from NVMe (warm Windows file cache in 32 GB RAM makes repeats faster) plus GPU upload and warm-up is probably about 2–6 s per swap. Measure it via the `load_duration` field in Ollama responses.

**Practical policy:**
1. Prefer **one 8B model for all LLM roles**, with role-specific system prompts and schemas. This removes swapping entirely.
2. If two 8B roles are unavoidable, run the batch precompute grouped by model: all jobs for model A, then all for model B. Never interleave them.
3. During the live demo, keep only the demo-path model resident with `keep_alive: -1`, and preload it before going on stage.
4. Precompute the embeddings in batch. At demo time only a handful of query embeddings are needed, and the 0.6B model can co-reside.
5. Set `OLLAMA_MAX_LOADED_MODELS=2` (one LLM plus the embedder) to stop a third model from thrashing.
6. Keep `OLLAMA_NUM_PARALLEL=1` for the live demo (lowest latency, smallest KV). For batch, `NUM_PARALLEL=2–4` raises throughput, but the KV is multiplied: 4 × 4K q8_0 ≈ 1.06 GiB on Llama-8B. Use it only when the embedder is unloaded.
7. Freeing desktop VRAM may be possible by running the display on the iGPU (hybrid/Optimus mode instead of a dGPU-only MUX setting) and by closing hardware-accelerated apps such as browsers and Electron apps. This is unverified for this specific laptop.

### Gaps
- No measured Ollama swap or load times for an 8B model on an RTX 4070 Laptop with NVMe. Measure `load_duration`.
- No official figure for Ollama's per-model compute-buffer overhead at 8K context on CUDA.
- Whether `num_gpu: 0` (forcing an embedding model onto CPU) is still honoured by the 0.30+ llama.cpp engine was not verified.

---

## 5. Structured outputs in Ollama (JSON-schema `format`): reliability, failure modes, mitigations

### Takeaway
`format` with a JSON schema guarantees *syntax*, not sensible content. In 2026 it has had serious, version-specific bugs:
- **The schema was silently ignored when `think=false`** for gemma4 (fixed in 0.21.1) and qwen3.5/3.6 (fixed in 0.31.2, July 2026). **Installed 0.20.0 has both bugs.**
- **Degenerate repetition loops inside free-text string fields** that burn the whole `num_predict` budget and leave JSON unterminated. Reported on gemma4; still open as of Aug 2026. The same GGUF was clean on llama.cpp-server.

Mitigations: upgrade, put the schema in the prompt, cap `num_predict`, use `temperature 0` and `repeat_penalty 1.0`, keep free-text fields short, validate with Pydantic and retry.

### Cited Findings
**Official docs:**
- Pass a JSON schema (e.g., Pydantic `model_json_schema()`) as `format`; `format: "json"` gives schema-less JSON.
- "ideal to also pass the JSON schema as a string in the prompt".
- Use temperature 0.
- OpenAI-compatible `response_format` also works.
- Ollama cloud does not support structured outputs.
- Source: [Ollama structured outputs doc](https://docs.ollama.com/capabilities/structured-outputs)

**#15260 (gemma4):**
- With `think:false` plus `format`, Ollama returned plain text with no warning, on 0.20.0, 0.20.5 and 0.21.0, streaming or not.
- Leaving `think` unset gave valid JSON but added about 3–4 s of thinking.
- Fixed in **v0.21.1** (PR #15678, closed 21 Apr 2026), for gemma4 only.
- Users then reported qwen3.6 also affected, and hybrid Qwen3 tags (`8b`, `latest`) still affected.
- Source: [ollama #15260](https://github.com/ollama/ollama/issues/15260)

**#14645 (qwen3.5/3.6):**
- "format is ignored when think is disabled for qwen3.5 series", opened 5 Mar 2026 on 0.17.6.
- Still broken in 0.18.2 through 0.21.0, and on `/api/chat` in 0.30.7.
- A user reported Qwen3 also affected starting in 0.30.0.
- Closed by PR #15901 on 7 Jul 2026; the fix was confirmed in **v0.31.2**.
- Reporter's analysis: Ollama waits for a `</think>` token before applying the grammar, but the template injects a closed empty think block, so the grammar never engages.
- Workarounds: use `/api/generate` instead of `/api/chat`, a custom model without the thinking capability, or llama.cpp.
- Also on 0.20.2/0.20.5: format was ignored even with `think=True`, and tool calls sometimes appeared as raw tags.
- Source: [ollama #14645](https://github.com/ollama/ollama/issues/14645)

**#15502 (gemma4:31b and 26b, Ollama 0.20.5, opened 11 Apr 2026):**
- Free-text string fields under `format` degenerate ("a a", then "own own own…") until `num_predict` is exhausted, leaving JSON unterminated.
- Rates: 10/10 on long outputs, 7/8 on a nested schema, 4–5/10 on the 26B MoE.
- Schemas with only arrays and enums were clean. gemma3:27b was clean.
- `repeat_penalty` of 1.0, 1.15 and 1.5 had no effect.
- Putting the schema in the prompt fixed short outputs (0/5 failures) but not long ones (3–10/10).
- The same GGUF on **llama.cpp-server: 0/10 repetition, 10/10 valid JSON**. vLLM with `disable_any_whitespace` gave 9/10 valid.
- The reporter attributes the fault to Ollama's grammar path. An XGrammar integration draft exists but is unmerged.
- **Still open** at last activity (2 Aug 2026).
- Source: [ollama #15502](https://github.com/ollama/ollama/issues/15502)

**Other failure modes:**
- Structured output not enforced for gpt-oss:20b when streaming plus thinking — [ollama #14440](https://github.com/ollama/ollama/issues/14440)
- Older reports (2024–25): `enum`/`const` not honoured and property order lost through the OpenAI endpoint — [#8063](https://github.com/ollama/ollama/issues/8063), [#7978](https://github.com/ollama/ollama/issues/7978)
- Schema not injected into the prompt, so the model "can't see" enum options — [#8162](https://github.com/ollama/ollama/issues/8162)
- llama3.1/3.2 output not matching the requested shape — [#8543](https://github.com/ollama/ollama/issues/8543)
- Infinite whitespace (2024): the old `format=json` grammar allowed unbounded whitespace, so models could emit whitespace forever. The fix removed whitespace generation, and commenters noted that hurt some models — [ollama PR #3785](https://github.com/ollama/ollama/pull/3785)
- Community guide recommends `repeat_penalty 1.0` for JSON, because penalties discourage the repeated structural tokens JSON needs — [sudormrf-dev guide](https://github.com/sudormrf-dev/ollama-structured-outputs-guide) (community opinion)
- `format` guarantees structure, not sensible values, so bounds-check them — [InsiderLLM](https://insiderllm.com/guides/function-calling-local-llms/)

### Inferences
**Recommended pattern for the batch JSON extraction:**
1. Run Ollama **≥0.31.2**. 0.40.13 is the obvious choice.
2. Use a non-thinking model (Llama-3.1-8B/Foundation-Sec-Instruct has no thinking mode, which sidesteps the whole think/format bug class). If a Qwen3-family model is used, test `think:false` + `format` on the exact version before relying on it.
3. Use a flat schema. Put categorical fields as `enum`s, which were clean in #15502. Keep free-text fields few and short, and ask for "≤2 sentences" in the prompt.
4. Paste the schema into the prompt as well as passing it in `format`.
5. Set options `temperature: 0`, `repeat_penalty: 1.0`, a fixed `seed`, and **`num_predict` capped** at about 1.5–2× the expected output (e.g., 512 for an extraction). A loop then costs ~10 s instead of minutes.
6. Validate with Pydantic. On failure, retry once with a shorter or simpler schema, then fall back to `format:"json"` plus repair, and flag the record.
7. Generate the long alert narratives **without** `format`, as plain streamed text. Keep JSON for short, structured fields only. This avoids the #15502 failure class during the live demo.
8. If Ollama's grammar path still misbehaves on the chosen model, llama.cpp `llama-server` with the same GGUF was the robust alternative in #15502.

### Gaps
- Whether Ollama's grammar honours JSON-schema `maxLength`/`maxItems` (which would hard-bound string fields) was not confirmed in the sources found.
- No published structured-output failure rates for Llama-3.1-8B or Foundation-Sec on Ollama 0.40.x.
- Whether #15502-style loops affect Llama-arch models, or only gemma4, is unknown.

---

## 6. Tool-calling reliability by model family (Qwen3, Llama 3.1, Granite, Gemma) in Ollama

### Takeaway
In the only rigorous same-harness comparison found (Docker, June 2025, 21 models, 3,570 cases), Qwen3-8B clearly beats Llama-3.1-8B on tool-selection F1:

| Model | F16 F1 | Q4_K_M F1 |
|---|---|---|
| Qwen3-8B | 0.933 | 0.919 |
| Llama-3.1-8B | 0.835 | 0.793 |

Gemma3-4B scored 0.733. Granite was not tested. In 2026 Ollama, tool-calling correctness also depends on per-model parsers and thinking handling (raw tags leaking, tool calls landing in reasoning), so pin a version and test.

### Cited Findings
**Docker eval** (June 2025, MacBook M4 Max, up to 5 rounds per case, non-strict matching) — [Docker blog](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/):

| Model | Tool-selection F1 |
|---|---|
| qwen3:14B-Q4_K_M | 0.971 |
| qwen3:8B-F16 | 0.933 |
| qwen3:8B-Q4_K_M | 0.919 |
| llama3.1:8B-F16 | 0.835 |
| qwen2.5:14B-Q4_K_M | 0.812 |
| llama3.1:8B-Q4_K_M | 0.793 |
| qwen2.5:7B | 0.753 |
| gemma3:4B | 0.733 |
| llama3.2:3B | 0.727 |
| llama-xlam:8B | 0.570 |
| watt-tool:8B | 0.484 |

- Recurring failure: "eager" tool calling, e.g., calling tools on "Hi there!" — [same](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/)
- Latency on the M4 Max: Qwen3-8B about 84 s per multi-round interaction (thinking), 14B about 142 s — [same](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/)

**InsiderLLM** (published Feb 2026, updated 16 Oct 2026; mostly unmeasured ratings):
- Qwen 3.5 9B (~6 GB at Q4) is its recommended 8 GB pick, with Llama 3.1 8B the runner-up.
- Gemma 4 26B-A4B forces a reasoning trace, so tool output lands in `reasoning_content`. Fix: disable thinking via chat-template kwargs.
- Qwen 3.6 silently ignores `chat-template-kwargs` when written with a space after the colon.
- Keep about 5–10 tools for 7B-class models; each definition costs about 50–150 tokens.
- Ollama does not support `tool_choice`.
- An oversized `num_ctx` causing CPU fallback degrades tool-call formatting.
- Q4 KV cache reportedly degrades tool-call accuracy.
- Source: [InsiderLLM](https://insiderllm.com/guides/function-calling-local-llms/)

**Ollama-specific parser issues:**
- Tool calls sometimes appeared as raw tags in output on qwen3.5 with 0.20.2/0.20.5 — [ollama #14645](https://github.com/ollama/ollama/issues/14645)
- v0.40.11: "qwen3coder keeps literal function closing tags in parameters" — [releases.sh](https://releases.sh/ollama/ollama)
- v0.40.7 fixed streaming Responses where tool calls could be emitted before reasoning items — [Ollama releases](https://github.com/ollama/ollama/releases)
- v0.40.12 fixed tool-only assistant turns from Kimi CLI — [Ollama releases](https://github.com/ollama/ollama/releases)

**New small candidates in Ollama (Oct 2026):**
- NVIDIA Nemotron 3.5 Bolt E4B (Gemma-4-based, 128K context, "fast conversations, image understanding, and tool use"), v0.40.10, 23 Oct — [Ollama releases](https://github.com/ollama/ollama/releases)
- Gemma 4 E2B/E4B/26B-A4B/31B since v0.20.0 (2 Apr 2026) — [v0.20.0](https://github.com/ollama/ollama/releases/tag/v0.20.0)

### Inferences
- For the copilot, a Qwen3-family 8B (or Qwen3.5-9B if it fits) is the evidence-backed choice over Llama-3.1-8B-based security models. Llama-3.1-8B Q4_K_M loses about 0.14 F1 to Qwen3-8B Q4_K_M in the same harness.
- If Foundation-Sec (Llama-3.1-based) is used for domain narratives and Qwen3 for tool calls, that is exactly the two-8B swap scenario in Q4. Prefer one model, or put the copilot on a 4B (Qwen3-4B / Gemma-4-E4B / Nemotron-Bolt-E4B) that co-resides with the embedder.
- Keep the copilot's toolset small (≤6 tools) with tight parameter schemas. Validate arguments in code, and add a system rule like "only call tools when the user asks for data" to curb eager calling.
- With Qwen3 hybrid-thinking models, decide explicitly on `think: true/false` and test tool calls on the exact Ollama version, given the parser and thinking-gate bugs above. Thinking adds large latency, which matters for a live demo.

### Gaps
- No same-harness tool-calling benchmark for Granite (3.x/4.x) or Gemma 4 small models in Ollama was found.
- One vendor-sourced figure surfaced (Granite 4.2 8B, BFCL v4 52.39), but I could not tie it to a verifiable source page, so it is excluded.
- The Docker results are from June 2025 on Apple Silicon. No 2026 re-run on CUDA or Ollama 0.40.x was found.
- No measured tool-calling data for Foundation-Sec-8B-Instruct.

---

## 7. What changed between Ollama 0.20 and 0.40 that matters

### Takeaway
Upgrade to **0.40.13**. Between 0.20.0 (2 Apr 2026) and 0.40.13 (28 Oct 2026), Ollama:
- moved to a **llama.cpp-based engine** (0.30.0, May 2026), with better HF GGUF compatibility and "faster NVIDIA performance";
- fixed the `format` + `think:false` bugs (0.21.1 for gemma4, 0.31.2 for qwen3.5);
- made MLX the default on Apple Silicon only (0.40.0), which is irrelevant on this Windows box;
- added Windows runner and template-diagnostics fixes (0.40.6, 0.40.7).

The one migration risk: 0.30.0 performs a one-time model-store migration.

### Cited Findings
**Before 0.20 (context):**
- 0.17.0 (21 Feb 2026): new engine and scheduler that "measures exact memory needs"; claims up to 40% faster prompt processing and 18% faster generation on NVIDIA; desktop apps set default context by memory — [InsiderLLM 0.17](https://insiderllm.com/guides/ollama-0-17-new-features/)
- 0.19: NVFP4 support (NVIDIA 4-bit format; preview on specific models) — [ToolRadar](https://toolradar.com/tools/ollama-v0-19) (secondary; exact NVFP4 tag names not found)

**0.20.0 (2 Apr 2026):**
- Gemma 4 (`gemma4:e2b`, `e4b`, `26b` MoE with 4B active, `31b` dense)
- MLX `add_bos_token` fix
- SentencePiece-style BPE tokenizer support
- Source: [v0.20.0](https://github.com/ollama/ollama/releases/tag/v0.20.0)

**0.21.1 (~21–23 Apr 2026):** gemma4 `format` honoured with `think:false` — [#15260](https://github.com/ollama/ollama/issues/15260)

**0.30.0 (13 May 2026):**
- "improved compatibility and performance using llama.cpp"
- llama.cpp engine extends the MLX engine on Apple Silicon
- "wider range of models, including GGUF-based models from Hugging Face" and custom fine-tunes
- "faster performance on NVIDIA"
- Known issues: `llama3.2-vision` unsupported; `laguna-xs.2` unsupported on Windows/Linux; `nomic-embed-text` now lowercases inputs
- Source: [v0.30.0](https://github.com/ollama/ollama/releases/tag/v0.30.0)
- Also reported (secondary): a one-time storage migration to a content-addressable format on first run, which took a few minutes with no re-download; auto-FA for qwen3, gemma3, gpt-oss and mistral3 on Ampere+; RAG pipelines on nomic should re-index — [InsiderLLM 0.30](https://insiderllm.com/guides/ollama-0-30-0-whats-new/)

**0.31.2 (~6–9 Jul 2026):**
- qwen3.5/3.6 `format` + `think:false` fix confirmed — [#14645](https://github.com/ollama/ollama/issues/14645)
- "Updated the MLX and llama.cpp engines" — [libhunt changelog](https://go.libhunt.com/ollama-changelog/0.31.2)

**0.40.0 (25 Sep 2026):**
- On Apple Silicon, MLX-supported architectures run on MLX by default. Examples: `qwen3.8`, `gemma4`, `qwen3.6`, `qwen3.5`; decision models; `embeddinggemma-2` on MLX.
- Source: [v0.40.0](https://github.com/ollama/ollama/releases/tag/v0.40.0)

**0.40.4 (12 Oct 2026):**
- Multimodal embeddings "through llama-server"
- "Gemma 4 prefill is faster on NVIDIA GPUs with the MLX runner"
- Reuses verified manifests and already-loaded models
- Source: [Ollama releases](https://github.com/ollama/ollama/releases)

**0.40.5 (14 Oct 2026):**
- rc0: "MLX Metal kernels ported to CUDA" — [releases.sh](https://releases.sh/ollama/ollama)
- Nemotron 3.5 Super and Bolt — [Ollama releases](https://github.com/ollama/ollama/releases)

**0.40.6 (16 Oct 2026):** "win: prevent orphaned runners"; GGUF q2_0 type — [Ollama releases](https://github.com/ollama/ollama/releases)

**0.40.7 (18 Oct 2026):**
- `ollama show` reports renderer, parser and template source; the API gains `renderer`, `parser` and `template_source` fields
- More draft models for speculative decoding; llama-server infers the draft type
- Responses tool-call ordering fixes
- Source: [Ollama releases](https://github.com/ollama/ollama/releases)

**0.40.9–0.40.13 (22–28 Oct 2026):**
- Streaming OpenAI Responses and Anthropic Messages now report generation failures instead of ending silently
- Flint on Windows/Linux
- d3 decision models (2B/4B/9B/27B) that "classify text, answer yes/no, or score options with probabilities". GitHub lists them under v0.40.11; releases.sh under v0.40.9.
- Nemotron 3.5 Bolt E4B (v0.40.10)
- LFM3 family; LFM3 on Windows/Linux in 0.40.13
- Sources: [Ollama releases](https://github.com/ollama/ollama/releases); [releases.sh](https://releases.sh/ollama/ollama)

**Latest stable:** 0.40.13 (28 Oct 2026) — [Wikipedia](https://en.wikipedia.org/wiki/Ollama); [Ollama releases](https://github.com/ollama/ollama/releases)

### Inferences
- For this Windows/CUDA build, the changes that matter are:
  1. the llama.cpp engine in 0.30+, with better HF-GGUF compatibility (relevant for Foundation-Sec or other security fine-tunes) and claimed NVIDIA speedups;
  2. the structured-output fixes in 0.21.1 and 0.31.2;
  3. the Windows orphaned-runner fix in 0.40.6, which helps avoid ghost VRAM use after crashes;
  4. the `template_source` diagnostics in 0.40.7, useful for HF imports (see Q9).
- The MLX-default change (0.40.0) applies only to Apple Silicon. The "MLX runner on NVIDIA" mentions (0.40.4, 0.40.5-rc0) suggest an experimental MLX-on-CUDA path, but it was only cited for Gemma 4 prefill. Don't depend on it.
- **Upgrade safety:**
  1. Run the 0.40.13 portable with a separate `OLLAMA_MODELS` directory, or back up the existing store first. 0.30's store migration may not be readable by 0.20.0 if a rollback is needed (unverified).
  2. Re-pull or re-create models under 0.40.13.
  3. Fully quit the tray app of the installed 0.20.0 so two servers don't fight over port 11434 and VRAM.
  4. Set the env vars in the shell that launches the portable `ollama serve`.
- For a 24-hour build, don't chase new models (Flint, LFM3, d3) unless one clearly fits a role. The d3 "decision" models are interesting for risk scoring, but they are days old.

### Gaps
- The full release notes for 0.21–0.29 and 0.31–0.35 were not retrieved; releases.sh only covers 0.40.5 and later. Other API changes in that range (e.g., to `/api/embed`, `keep_alive` semantics or tool-call streaming) may exist.
- Exact NVFP4 tag names and whether NVFP4 runs on Ada (it is a Blackwell-native format) are not confirmed.
- No measured Windows/CUDA speedup from 0.20 to 0.40 was found.
- Whether a qwen3 (hybrid) format fix landed after the 0.30.0 regression report is not confirmed.

---

## 8. Alternatives on Windows: llama.cpp server, LM Studio, vLLM (WSL). Is switching worth it for a 24-hour build?

### Takeaway
Not worth a full switch. Ollama 0.40.13 already runs a llama.cpp-based engine. Reported overhead is roughly ≤10% versus raw llama.cpp, and the team already has it installed.

Keep **llama.cpp `llama-server`** (Windows CUDA binaries) as a **fallback for structured-output robustness**: it handled the same GGUF cleanly where Ollama's grammar path looped. LM Studio is GUI-centric with about the same speed. **vLLM on WSL2 is a poor fit for 8 GB**: a 4070-Laptop user could only run ~1B models.

### Cited Findings
- Single-run benchmark (hardware and OS unstated): LM Studio ~0.3% slower and Ollama ~10% slower than raw llama.cpp — [InventiveHQ](https://inventivehq.com/blog/ollama-vs-llama-cpp-vs-lm-studio-benchmark)
- Other 2026 comparisons conflict (identical speeds vs 20–30% gaps); raw llama.cpp reportedly leads by 3–5% on NVIDIA — via search summary of [bestllmfor](https://bestllmfor.com/guides/ollama-vs-lm-studio-vs-llama-cpp-2026/) and [InsiderLLM](https://insiderllm.com/guides/ollama-vs-lm-studio/). Low confidence.
- llama.cpp-server with the same gemma4 GGUF: 0/10 repetition and 10/10 valid JSON where Ollama failed; vLLM with `disable_any_whitespace`: 9/10 valid — [ollama #15502](https://github.com/ollama/ollama/issues/15502)
- A qwen3.5 `format` reporter moved to llama.cpp after months of the Ollama bug — [ollama #14645](https://github.com/ollama/ollama/issues/14645)
- vLLM in WSL2 on a Windows 11 laptop with an 8 GB RTX 4070: only ~1B models ran. A 7B failed because free memory (6.89 of 8.0 GiB) was below the required 0.9 × 8 GiB = 7.2 GiB, and changing `--gpu-memory-utilization` didn't help that user — [r/LocalLLaMA thread](https://redlib.ssps.io/r/LocalLLaMA/comments/1l8t8n8/huge_vram_usage_with_vllm)
- vLLM's `gpu_memory_utilization` (default 0.9) covers weights, activations and KV, and vLLM pre-allocates the KV — [vLLM forum](https://discuss.vllm.ai/t/what-does-gpu-memory-utilisation-include/1651)
- WSL2 vLLM example on a 6 GB laptop GPU: TinyLlama 1.1B at 0.7 utilisation; 7B described as too much — [DEV Community](https://dev.to/lugerlogic/running-tiny-llms-on-your-local-machine-with-vllm-wsl2-no-cloud-needed-5c44)
- TensorRT-LLM was +29.9% vs llama.cpp on the 4070 Laptop (2024), but needs model-specific engine builds — [Jan.ai](https://www.jan.ai/post/benchmarking-nvidia-tensorrt-llm)
- Both Ollama and LM Studio use llama.cpp underneath; differences come mainly from defaults and packaging — via search summary of [deploybase](https://deploybase.ai/articles/lm-studio-vs-ollama)

### Inferences
- On Windows, the desktop's ~0.9 GB already pushes vLLM below its default 0.9 utilisation threshold. With vLLM's eager KV pre-allocation and the WSL2 overhead, 7–8B models are impractical on this card. Skip it.
- The ~10% Ollama overhead (if real) is about 4 tok/s at 40 tok/s, which is irrelevant for the demo.
- What matters more is correctness (the grammar path) and operational simplicity (model management, `keep_alive`, the OpenAI-compatible API).
- **Contingency plan** (about 30 min of work, if needed): download the llama.cpp Windows CUDA release and run `llama-server -m model.gguf -ngl 99 -fa on -ctk q8_0 -ctv q8_0 -c 8192`. Point the app's OpenAI-compatible client at it for the extraction path only. The same GGUF files work, and Ollama stores blobs as GGUF under its models directory.
- LM Studio adds nothing over Ollama for a headless backend. Its one advantage is GUI inspection of templates and settings.

### Gaps
- No Windows/CUDA head-to-head (same GGUF, same GPU) of Ollama 0.40.x vs llama-server vs LM Studio from 2026 was found.
- Whether llama-server's `--jinja` / JSON-schema path avoids loops for Llama-arch models specifically is untested in the sources.

---

## 9. Running HF GGUF imports in Ollama: chat-template pitfalls and how to set TEMPLATE / PARAMETER stop

### Takeaway
An imported GGUF without a recognised `tokenizer.chat_template` gets a generic wrapper (effectively a bare `{{ .Prompt }}`). The model then rambles, role-plays both sides, or never emits its stop token.

Always run `ollama show --template` / `--modelfile` after importing. On 0.40.7+, the new `template_source` field shows where the template came from. For a Llama-3.1-based security model, copy the template and stops from the official `llama3.1` library model. Also make sure you are importing the **Instruct** variant: the official Foundation-Sec Q4_K_M GGUF is the *base* model.

### Cited Findings
- Modelfile `FROM` accepts a GGUF path (absolute or relative); split GGUFs use a wildcard (`FROM ./model-*.gguf`). `TEMPLATE` uses Go template syntax with `{{ .System }}`, `{{ .Prompt }}`, `{{ .Response }}`. Multiple stop strings are set with repeated `PARAMETER stop "..."` lines — [Ollama Modelfile doc](https://docs.ollama.com/modelfile)
- Modelfile defaults: `temperature 0.8`, `top_k 40`, `top_p 0.9`, `repeat_penalty 1.0`, `repeat_last_n 64`, `num_predict -1` (unlimited) — [Ollama Modelfile doc](https://docs.ollama.com/modelfile)
- "Ollama does not quantize GGUF models during import" — quantise beforehand with `llama-quantize` — [Ollama import doc](https://docs.ollama.com/import)
- Ollama picks a template from a fixed list by matching the GGUF's `tokenizer.chat_template` metadata. If it is missing or unmatched, the model gets a generic wrapper and may never emit its stop token. Diagnose with `ollama show --template <model>` and `ollama show --modelfile <model>` — [SSD Nodes guide](https://www.ssdnodes.com/learn/ollama-import-gguf-model)
- Fix by writing a Go-syntax `TEMPLATE` that matches the model's own format, plus the matching `PARAMETER stop`. ChatML example: `<|im_end|>`. Llama 3 needs a different template — [InsiderLLM GGUF fix guide](https://insiderllm.com/guides/gguf-file-wont-load-fix/)
- The Ollama registry sometimes ships a simplified template that differs from the GGUF-embedded one, and converting Jinja to Go templates is fragile — [HF forum](https://discuss.huggingface.co/t/ollama-model-registry-provides-wrong-chat-template/176139)
- v0.40.7: `ollama show` reports the renderer, parser and template source (API fields `renderer`, `parser`, `template_source`) — [Ollama releases](https://github.com/ollama/ollama/releases)
- 0.30.0 widened support for "GGUF-based models from Hugging Face" and custom fine-tunes — [v0.30.0](https://github.com/ollama/ollama/releases/tag/v0.30.0)
- Foundation-Sec-8B Q4_K_M (fdtn-ai) is derived from the base Foundation-Sec-8B, gives no chat-template notes, and can be pulled with `ollama run hf.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF:Q4_K_M` — [fdtn-ai GGUF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF)
- An Instruct GGUF exists at [mradermacher/Foundation-Sec-8B-Instruct-GGUF](https://huggingface.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF)
- The structured-output docs recommend temperature 0, and the Modelfile default is 0.8, so set it explicitly per request for extraction — [structured outputs doc](https://docs.ollama.com/capabilities/structured-outputs); [Modelfile doc](https://docs.ollama.com/modelfile)

### Inferences
**Safest recipe for a Llama-3.1-based HF GGUF** (e.g., Foundation-Sec-8B-Instruct):
1. `ollama pull llama3.1:8b`, then `ollama show --modelfile llama3.1:8b > base.Modelfile` to get Ollama's maintained Go template, which handles `.Messages` and `.Tools`.
2. Write a new Modelfile: `FROM ./Foundation-Sec-8B-Instruct.Q4_K_M.gguf`, then paste the `TEMPLATE """..."""` block from step 1, then the stops:

   ```
   PARAMETER stop "<|eot_id|>"
   PARAMETER stop "<|start_header_id|>"
   PARAMETER stop "<|end_header_id|>"
   ```

   Add `PARAMETER stop "<|eom_id|>"` if you rely on the Llama-3.1 built-in tool format. These are the standard Llama-3 special tokens; check them against the model's `tokenizer_config.json`.
3. Add `PARAMETER num_ctx 8192` and `PARAMETER temperature 0.2`. Per-request options override these.
4. `ollama create foundation-sec-instruct -f Modelfile`, then `ollama show --template foundation-sec-instruct` and run a 2-turn smoke test. Pass if it stops cleanly and does not invent a "user:" turn.

**Symptoms of a bad template:**
- Endless generation that hits `num_predict`.
- Output that contains `<|start_header_id|>` or "assistant" text.
- Ignoring the system prompt.
- Tool calls returned as plain text instead of `tool_calls`.

**Model-variant pitfalls:**
- A **base** (non-instruct) model will follow no chat template well, so don't use the fdtn-ai base Q4_K_M as a chat or JSON model.
- If a security fine-tune changed the template (e.g., ChatML on a Llama base), use *its* `tokenizer_config.json` template, not llama3.1's.

### Gaps
- Whether Ollama 0.30+ (llama.cpp engine) now renders the GGUF's embedded Jinja template directly, which would reduce the pitfall, versus mapping it to a Go template was not confirmed. `template_source` in 0.40.7 hints that both paths exist.
- Foundation-Sec-8B-Instruct's exact chat template and stop tokens were not retrieved in this session. Verify them from its HF `tokenizer_config.json`.

---

## 10. Concrete recommended settings for this laptop and workload (synthesis)

### Takeaway
Run **Ollama 0.40.13 portable** with FA on, q8_0 KV, an 8K context, at most 2 loaded models and one pinned demo model. Use **one 8B Q4_K_M LLM for all roles where possible**, plus `qwen3-embedding:0.6b`. Use schema-constrained JSON only for short structured fields, with capped `num_predict` and validation and retry. Stream narratives as plain text.

### Cited Findings
- Env vars and semantics (`OLLAMA_FLASH_ATTENTION`, `OLLAMA_KV_CACHE_TYPE`, `OLLAMA_MAX_LOADED_MODELS`, `OLLAMA_NUM_PARALLEL`, `OLLAMA_KEEP_ALIVE`, `keep_alive` -1/0, preload by empty request). On Windows, set them as user environment variables and restart Ollama, which inherits user and system variables — [Ollama FAQ](https://docs.ollama.com/faq)
- `OLLAMA_CONTEXT_LENGTH`; the default is 4k on GPUs under 24 GiB; check with `ollama ps` — [context-length doc](https://docs.ollama.com/context-length)
- q8_0 KV ≈ ½ memory with a very small loss; q4_0 ≈ ¼ with a noticeable loss at long context — [Ollama FAQ](https://docs.ollama.com/faq)
- Schema in the prompt plus temperature 0 — [structured outputs doc](https://docs.ollama.com/capabilities/structured-outputs)
- `format`+`think:false` fixed in 0.21.1 (gemma4) and 0.31.2 (qwen3.5) — [#15260](https://github.com/ollama/ollama/issues/15260); [#14645](https://github.com/ollama/ollama/issues/14645)
- Free-text loop bug exhausts `num_predict` (open as of Aug 2026) — [#15502](https://github.com/ollama/ollama/issues/15502)
- Qwen3-8B > Llama-3.1-8B on tool-call F1 — [Docker](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/)

### Inferences
**Server environment** (PowerShell, before launching the portable `ollama serve`; or as user environment variables for the tray app):

```powershell
$env:OLLAMA_FLASH_ATTENTION   = "1"
$env:OLLAMA_KV_CACHE_TYPE     = "q8_0"
$env:OLLAMA_CONTEXT_LENGTH    = "8192"   # drop to 4096 if `ollama ps` shows any CPU split
$env:OLLAMA_MAX_LOADED_MODELS = "2"      # 1 LLM + 1 embedder
$env:OLLAMA_NUM_PARALLEL      = "1"      # live demo; try 2-4 for batch only with the embedder unloaded
$env:OLLAMA_KEEP_ALIVE        = "30m"    # per-request keep_alive:-1 for the demo model
$env:OLLAMA_MODELS            = "D:\ollama-models-040"  # separate store for the 0.40.13 portable
.\ollama.exe serve
```

**Model choices:**
- **8B LLM:** Q4_K_M (imatrix if from HF). Use Q5_K_M only if it is the sole resident model and `ollama ps` shows 100% GPU at 8K.
- **Copilot:** Qwen3-family 8B for tool calling, or the same 8B if it is a Llama-based security model and its tool calls pass your smoke tests. A 4B option (Qwen3-4B, Gemma-4-E4B, Nemotron-Bolt-E4B) would co-reside more easily and decode about 1.6× faster.
- **Embeddings:** `qwen3-embedding:0.6b` (639 MB). Precompute all document embeddings in batch.

**Per-request options:**

| Path | Settings |
|---|---|
| JSON extraction (batch) | `format: <schema>`; schema text in the prompt; `temperature: 0`; `seed: 42`; `repeat_penalty: 1.0`; `num_predict: 512` (≈1.5–2× the expected output); `num_ctx: 8192`; `think: false` only on models without thinking or after verifying the fix on 0.40.13 |
| Narratives (batch and live) | no `format`; `stream: true`; `temperature: 0.3–0.5`; `num_predict: 350–500`; `repeat_penalty: 1.05–1.1`; `keep_alive: -1` on the live model |
| Copilot | ≤6 tools; `temperature: 0–0.2`; `num_predict: 512`; argument validation in code; thinking off for latency unless accuracy needs it |

JSON extraction also needs **validate → 1 retry with a simplified schema → fall back to `format:"json"` + repair → flag**.

**Two-model swap, if unavoidable:**
1. Group the batch by model.
2. Call `keep_alive: 0` on the outgoing model before the first call to the incoming model, to force a clean unload.
3. Log `load_duration` to measure the swap cost.
4. Keep only the demo model pinned during judging.

**Pre-demo checklist:**
1. `ollama ps` shows `100% GPU` and the expected `CONTEXT`.
2. Fire a warm-up request.
3. Close GPU-hungry apps (browser hardware acceleration).
4. Plug in AC power and set the laptop to its performance power mode.
5. Have the cached precomputed outputs as the offline fallback, per the hackathon's offline-demo rule.

**Fallback runtime:** keep llama.cpp `llama-server` (Windows CUDA build) with the same GGUF ready for the extraction path if Ollama's grammar path misbehaves on the chosen model.

### Gaps
- All the throughput and VRAM numbers above are estimates for this exact laptop and need a 10-minute on-device check:
  1. `ollama run <model> --verbose` for eval rate.
  2. `ollama ps` and `nvidia-smi` for VRAM.
  3. Timing a forced swap.
  4. 50 sample extractions to measure the schema-failure rate.
- The batch speedup from `OLLAMA_NUM_PARALLEL` > 1 on this GPU is not measured in any source found.
