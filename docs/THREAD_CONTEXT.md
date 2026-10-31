# Odyssey: full context of the main build thread

A handover of everything this thread established. It covers the brief and the rules we work under, what was built and
why, how it is verified, how it covers the problem statement, the mentors' feedback and our prior-art research, what is
still open, and how to run and demo it.

As of 1 Nov 2026, about 02:30 IST, commits up to `472d47f`. Hacking ends and the elimination round starts at 13:00 IST
today; mentoring round 2 is at 08:00.

---

## 1. The brief

- **Event:** D3COY 1.0, organised by DJS ISACA and C-DAC.
- **Problem statement PS-01:** AI-Based National Cyber Threat Early Warning System.
- **PS-01 key objectives:**
  1. aggregate threat intelligence from multiple sources (advisories, security bulletins, vulnerability databases, threat feeds);
  2. AI-based threat analysis;
  3. early warning generation for emerging threats;
  4. risk prioritisation;
  5. actionable recommendations;
  6. a dashboard of active threats and affected technologies.
- **PS-01 example use case:** a new advisory arrives, the system matches it to the organisation inventory, assigns risk, recommends mitigation and alerts whoever is exposed.
- **PS-01 deliverables:**
  - a functional prototype;
  - a dashboard of detected threats, risk levels and alerts;
  - a demonstration on public threat intelligence plus a controlled simulated dataset;
  - an explanation of the AI model, threat scoring and mitigation workflow.
- **Judging** (published round-0 criteria): quality and originality, technical understanding of the PS, feasibility and impact, USP and future scope. Event theme: security, privacy and digital trust.
- **Mentor feedback, round 1:** one item came from the judges, nine from the mentors.
  - Judges: make the whole system **proactive**.
  - Mentors:
    1. threat-intelligence aggregation;
    2. dashboard;
    3. **SOC**;
    4. **show real tests and attacks**;
    5. AI-based threat analysis;
    6. early warning and **organisation-based OSINT**;
    7. risk minimisation and mitigation, framed as **risk management**;
    8. actionable intelligence and recommendations;
    9. **human in the loop**.

## 2. Standing rules from the team lead

These held for the whole thread.

- **Win, and be class-apart:** state of the art as of Oct 2026, and dynamic and agnostic, meaning pluggable models, sources and config. Every claim must be measured, never assumed.
- **Core AI:**
  - security-specialised models of about 8B or smaller only, with no fallback models;
  - general models are allowed only as evaluation baselines;
  - one impactful decision model;
  - ask before downloading any LLM.
- **Fully local:** RTX 4070 Laptop (8 GB VRAM), i9-14900HX, 32 GB RAM, 0 cloud calls. Services bind to 127.0.0.1. Ollama stays on 0.0.0.0, as the team lead decided.
- **End-to-end product:** every capability ships with its interface, a demoable use case and a working backend, and every button must really act. Neither UI-only nor backend-only work counts.
- **Uber "Oreo" interface:**
  - black nav, page header band and footer around a white body, with Base greys between;
  - no dark mode;
  - one question per page and about four figures per band;
  - details live in sheets that slide in from the right.
- **No chat assistant.** It was built, judged broken and unwanted, and removed.
- **Safety:**
  - passive public feeds only: no scanning or exploiting of real networks;
  - indicators are always defanged;
  - simulated data is labelled SIM everywhere.
- **Git:**
  - Commit locally; the team's auto-sync hook commits and pushes at the end of every Claude turn.
  - Teammates only pull.
  - A second Claude thread works in the same folder (section 15).

## 3. What Odyssey is

A national CERT's early-warning system for India's critical-infrastructure operators.

- **The base build** reads 13 sources. It works out which CVEs and advisories hit the installed versions of 15 simulated operators across 6 NCIIPC sectors. It scores and tiers each exposure, and plans the fewest fixes that remove the most risk.
- **On a schedule:** it warns each operator in its own language, among 22 Indian languages. It acts on its own where the evidence is solid, and proposes to an analyst where it is not.
- **While running:** it watches its own sensors and the small real feeds every few seconds. It detects attacks (surge, C2 beacon, flow anomaly), opens SOC cases and logs every step in a hash-chained audit trail.

```
public feeds (REAL) ─┐                      ┌─ Now      what needs you
SIM sensors / logs ──┼─► pipeline (build) ──┤   Live     the system running, attack drills
inventory (SIM) ─────┘    data/ews.db       ├─ SOC      cases, decisions, log, system telemetry
                              ▲             ├─ Intel    threats, exposure heatmaps, risk plan, advisories
   live engine (every 5 s) ───┤             ├─ Orgs     each operator: exposure, fixes, OSINT, inbox
   HTTP shield (other thread) ┘             └─ Proof    every claim with evidence, test bench, how it works
        all write one hash-chained ledger ─► SSE stream ─► every open screen refreshes
```

## 4. The build pipeline (`backend/app/pipeline.py`, about 90 s)

| Stage | What it does |
|---|---|
| Feeds and candidate selection | Offline snapshot in `data/raw` (NVD 2021–26, KEV, EPSS, Vulnrichment/SSVC, CISA advisories, DShield, Feodo, OpenPhish, ATT&CK). Picks the CVEs that name a constituency product. |
| NVD records | Version configurations, CNA records, CVSS/CWE (TF-IDF classifiers fill gaps). |
| Day-0 forecast | Leak-free logistic regression, frozen on 31 Jul. Flags new CVEs likely to be exploited; this becomes the Bayesian prior. |
| Telemetry detectors | Daily decoy-grid surges (robust z on sessions and unique sources, breadth ≥ 3 sensors, 28-day baseline), decoy exploit tags, C2 beacons in firewall logs. |
| Exposure and scoring | Three-source version reconciliation (NVD, CNA, advisory text, vendor-aware versions). `Risk = 100·R·K·(0.55·L + 0.30·S + 0.15·V)`. An SSVC decision path sets the tier and the CERT-In deadline; a Bayesian P(compromise) sets the 6 h clock. |
| Sentinel autopilot | Graduated autonomy over every warning's time line: notices, digests, baselines, hunts, reports, confirms and stand-downs run on their own. Forecasts, sensor-only warnings and escalations are proposals. Lead times over KEV are attributed REAL or SIM. |

## 5. The live system (`backend/app/live.py`, started with the API)

- **Every 5 s:**
  - reads the SIM decoy grid (24 sensors, 8 products) and firewall flows, accelerated so one tick is one sensor-hour;
  - runs the surge detector, the C2 beacon detector (≥ 30 connections, interval coefficient of variation ≤ 0.2) and the flow-anomaly detector;
  - acts through the same Autopilot policy: compromise evidence triggers a notice, a CERT-In draft, a hunt and a SOC incident case at once, and the regulator escalation is proposed. Surge warnings are proposed.
- **Flow-anomaly detector:** an IsolationForest trained on ten sensor-days. It alerts only below its 0.1% score quantile **and** when fan-out, ports or bytes are ≥ 6 robust z out of range, because its scores saturate beyond the training range.
- **Every 15 min** it re-reads CISA KEV, Feodo Tracker and OpenPhish. New KEV entries that touch the inventory become proposals; Feodo C2s are matched to flows; OpenPhish hosts to look-alike domains. Each feed reports its freshness, and offline means the snapshot keeps serving.
- **Attack drills** (scan, implant, full intrusion), started from the Live page or `POST /api/live/drill/{scan|beacon|chain}`. Traffic is labelled DRILL, and time to detect is measured.
  - Full intrusion, measured: caught in order in about 26 s, with the incident case opened automatically.
  - 720 quiet ticks give 0 detections.
- **`GET /api/live`** returns the stream state plus what each pipeline stage did in the last hour. That counts only since the engine started, so a rebuild does not inflate it.

## 6. AI models (`config/models.json`, `docs/MODEL_CARD.md`)

| Job | Model | Runs on | Measured |
|---|---|---|---|
| Explain each warning, read advisories | MiST 8B (security-tuned) via Ollama | GPU | briefs 22/23 pass the fact validator (19 first try); vendor extraction 79.9% |
| Deep reasoning, batch only | Foundation-Sec-8B-Reasoning | GPU | free text, never on the critical path |
| Entities in advisories | SecureBERT 2.0 NER + IOC rules (defanged; versions and vendor links are never indicators) | CPU | |
| Related threats | SecureBERT 2.0 bi-encoder | CPU | |
| CWE and CVSS when missing | TF-IDF + linear models | CPU | CWE top-1 77.5%, CVSS error 0.85 |
| Exploitation on day 0 | TF-IDF + leak-free KEV history → logistic regression | CPU | 61.1% of later-exploited CVEs caught while flagging 2% (CVSS ≥ 9: 16.7%) |
| Compromise decision | Bayesian model; the forecast is its prior | CPU | every factor shown as a likelihood ratio |
| Surge, beacon, flow anomaly | robust z · periodicity · IsolationForest + z-gate | CPU | test bench drills and negative controls |
| Prompt-injection guard | DeBERTa-v3 classifier + rules | CPU | 5/5 hostile caught, 0/5 benign blocked |
| 22 Indian languages | IndicTrans2 distilled 200M + validator (placeholders, Latin words, script) | CPU (:8010) | 127/132 sentences validated |

Every sentence an LLM writes is checked against numbered facts, and unverifiable text is withheld. Outputs are cached
by content hash (`data/cache.db`); a rebuild keeps still-valid outputs.

## 7. The interface (React + Vite + Tailwind on :5173)

- **Now:**
  - the incident card ("A suspected compromise needs you now", CERT-In countdown, journey bar, one action);
  - a live status line;
  - the India tile map (no contested borders);
  - "Up next";
  - a black "Odyssey at work" band;
  - the decisions waiting.
- **Live:** what each pipeline stage did, attack drills with step-by-step progress and time to detect, sensor streams with z-scores, detections and real-feed freshness.
- **SOC:**
  - **Overview:** the decision queue, team on shift, the autopilot heatmap, and replay, handover and warnings as cards.
  - **Cases:** opened automatically, with owners by rule, SLA clocks, playbooks, notes and audited MTTA, MTTR and SLA.
  - **Warnings:** every warning ranked by risk, with tier and sector filters.
  - **Log:** everything Odyssey did, plus every human decision.
  - **System:** CPU, GPU, VRAM and memory, resident models, every AI job timed and checked, API latency, audit trail and build stages.
- **Intel:**
  - **Overview:** what is under attack, the critical-exposure heatmap (technology × sector) and the likely-next forecast.
  - **Threats:** real DShield attacks heatmap (port × day), plus the decoy grid, campaigns, CISA advisories and sources as sheets.
  - **Risk plan:** 93 changes remove 50% of national risk, 205 remove 80%, out of 344 tickets.
  - **Advisories:** inbox plus paste-any-advisory; who must act, what to block, how it was read.
- **Organisations:** 15 operators. Each has an overview, risk plan, "What outsiders see" (OSINT: exposed services, C2 in traffic, look-alike domains, DShield on its ports, advisories naming its products) and an inbox in its own language.
- **Proof:**
  - 8 claim cards, each opening its evidence: test bench, lead over KEV, day-0 forecast, EPSS comparison, 22 languages, exposure precision, briefs, model comparison.
  - "How it works" covers the 6-step pipeline, the model table, the open scoring formula with a live worked example, and who does what.
- **"Why this warning?" sheet:** three figures (time to act, SSVC decision, chance of compromise), then four tabs:
  - **What to do:** brief in 22 languages, actions, CERT-In report draft, STIX 2.1 export with TLP.
  - **Why this score:** Bayesian model, factor breakdown, evidence rules, three-source exposure votes.
  - **How it unfolded:** replay, ledger timeline.
  - **Related:** ATT&CK, related threats, source text.
- **Design system:** `frontend/src/index.css` holds the tokens; `frontend/src/ui.tsx` holds Hero, Figures, Band, Section, Tile, Sheet, Pill, Row, Stat, Tabs, TierPill, Prov and toasts. Heatmaps use blue for activity and red for risk.

## 8. Data and honesty

| Data | Status | Details |
|---|---|---|
| Public sources | REAL | NVD, CISA KEV, Vulnrichment (SSVC), FIRST EPSS, CISA advisories, SANS ISC DShield, abuse.ch Feodo Tracker, OpenPhish, MITRE ATT&CK |
| Organisations, inventory, decoy grid, firewall logs, CERT-In-style advisories | SIM, labelled on screen | The CERT-In site is unreachable from the venue. |
| Live sensors | SIM, accelerated | |
| Three small feeds (KEV, Feodo, OpenPhish) | REAL, live | Re-read every 15 min. |
| Snapshot | Fetched 31 Oct 2026 | Refreshes with each rebuild. |

Lead time over KEV is reported separately for REAL signals only (4 CVEs, median 20.5 d, up to 42.4 d). Exposures that
were already known when monitoring began are reported apart and not counted as lead.

## 9. Verification (all green at `472d47f`)

| Check | How | Result |
|---|---|---|
| Engine tests | `.venv\Scripts\python -m pytest -q` | 91/91: 60 core plus 31 from the shield thread. Includes a regression test proving concurrent writers no longer fork the audit chain, and tests for decay, the clocks, supplier fan-out and the hostile advisory. |
| Test bench | Proof → *Run them now* (`POST /api/tests/run`) | 66/66: 4 attack drills on a data copy, 5 detection checks with negative controls, the audit-trail chain, and the engine tests. |
| Product flows | `.venv\Scripts\python scripts\e2e_check.py` | 15/15 on a private DB copy: every screen loads; approve and reject; a warning from issued to closed; a SOC case from new to closed; advisory analysis; compliance clocks, supplier fan-out and the hostile advisory; three live drills with live re-scoring; the audit trail. |
| Interface | `python scripts\ui_audit.py` (Playwright drives the installed Edge) | 17/17 click-through steps on a copy API at :8001, with 0 page or console errors and 0 HTTP 5xx. |
| Production build | `cd frontend && npm run build` | OK (one large-chunk warning only). |

Headline measurements, also recomputed on the Proof page:

| Measurement | Value |
|---|---|
| Noise reduction | 47×: 16,730 CVEs this month → 356 warnings needing action |
| CVEs triaged in 2026 | 82,104 2026 CVEs → 2,277 name a constituency product → 354 Critical |
| EPSS alone misses | 49.1% of KEV-confirmed exploited CVEs (CVSS ≥ 9 alone: 52.7%) |
| Exposure precision | 4,515 asset × CVE pairs cleared by version evidence; 0 false "affected" on the real Ivanti case |

## 10. Coverage of the PS, the mentors and our prior-art research

### PS-01: covered in full

| Objective / deliverable | Where |
|---|---|
| Aggregation (13 sources) | Intel → Threats → Intelligence sources |
| AI analysis | Briefs, advisory reading, forecast, Bayesian model, live detectors (no chatbot) |
| Early warning | Day-0 forecast, pre-disclosure surge warnings, autopilot notices, live detection |
| Risk prioritisation | Open formula, SSVC tier, CERT-In deadline, Bayesian clock |
| Actionable recommendations | Named fixed release, owner and deadline; block, hunt, STIX; national and per-org risk plan |
| Dashboard of threats and affected technologies | Intel Overview and Threats; SOC; Now |
| Example use case | Intel → Advisories → real CISA "Siemens WinCC": 13 assets at 7 operators, version ranges parsed, proposal to notify, analyst approves |
| Functional prototype, public plus simulated demo, explanation of model, scoring and workflow | The whole app; Proof → How it works; `docs/MODEL_CARD.md`; `docs/PS_COVERAGE.md` |

### Mentors and judges: covered in full

| Feedback | Response |
|---|---|
| Proactive | Live engine (5 s), autopilot, feed watch |
| Aggregation and dashboard | As above |
| SOC | SOC destination: cases, playbooks, SLAs, metrics, handover, system telemetry |
| Real tests and attacks | Test bench, attack drills, real KEV, DShield and advisories; the shield thread adds a protected real web app and a red team |
| AI analysis | As above |
| Early warning and org OSINT | Organisations → What outsiders see |
| Risk management | Risk plan |
| Actionable intelligence | Per-warning actions and the plan |
| Human in the loop | Graduated autonomy with approve/reject, reasons kept for calibration |

### Prior art: the 16 "class-apart" decisions

Source: `reports/National cyber early warning case study.md`. All 16 are done; the last five were closed in the
completion pass (marked ★).

| # | Decision | Status |
|---|---|---|
| 1 | Three-source exposure reconciliation | Done |
| 2 | Evidence floors; decoy exploit tags count | Done |
| 3 | Severity, relevance, confidence, decision kept separate; multiplicative risk | Done |
| 4 | Named-rule ledger, Admiralty, decay and age-off | Done ★: transient sensor evidence (decoy surges, decoy exploit tags, C2 sightings) loses weight in V with a half-life (14 / 21 / 10 days) and stops counting after its age-off (45 / 60 / 30 days), as a rule and for the Bayesian model; catalogue facts never decay; each rule shows its age and weight (`config/scoring.json` evidence_decay). |
| 5 | SSVC → CERT-In deadlines + KEV due + 6 h / DAKSH / DPDP clocks | Done ★: each warning carries the clocks that apply (`engine/obligations.py`): CERT-In 6 h, RBI DAKSH 6 h (banks), SEBI CSCRF 6 h (market entities), DPDP Board 72 h (systems holding personal data), NCIIPC for notified CII, the sector CSIRT, or the patch deadline; shown first in "Why this warning?". |
| 6 | Chain-aware grouping, blast radius | Done |
| 7 | Closed-set, span-grounded LLM with numeric validation | Done |
| 8 | Security encoders for structured tasks | Done |
| 9 | Pre-disclosure surge detector with a chance baseline | Done (with a negative control) |
| 10 | Leakage-safe, calibrated, budget-judged predictor | Done |
| 11 | Live prompt-injection red-team in the demo | Done ★: a hostile SIM advisory in the inbox (CIVN-SIM-2026-0431) hides instructions for AI systems; the guard blocks it, a banner says the model never read it, and the deterministic layer still finds the product, exposure and indicators. |
| 12 | Honest KPIs: time to alert, lead over KEV | Done (plus drill time to detect) |
| 13 | Routing by NCIIPC sector, sector CSIRT, supplier fan-out | Done ★: a SIM supplier graph (`config/suppliers.json`: shared core banking, OT integrator, managed security) fans every advisory and warning on a product a supplier runs out to its dependents, including those who do not run it; shown on advisories, warnings and each organisation, and added to advisory notification proposals. |
| 14 | Indic languages with protected spans and script checks | Done (22 languages, beyond the planned 2) |
| 15 | Standards-native, sovereign output | Done: STIX 2.1, TLP, Admiralty, offline |
| 16 | Event-sourced live re-scoring with deterministic replay | Done ★: a live C2 beacon re-decides every warning on that host through the Bayesian model; those crossing 50% become suspected compromises at once, with their own 6-hour clock from detection, and the change is in the ledger (`live.rescore`). |

Deliberate deviation: the research suggested no India map. We use a tile cartogram with no borders, which avoids contested boundaries.

## 11. Known gaps and limits

- Live sensors and the organisations are simulated. Dark-web sources are not covered.
- **Deadlines run in real time from the build.** The incident's 6 h CERT-In clock starts at build time, so run `scripts\demo_reset.ps1` shortly before every demo.
- Each attack drill adds proposals and cases to the live database. So does each shield attack, which is why there were 52 pending decisions at 02:00. A demo reset clears them.
- The frontend bundle is 832 KB, which is fine for local use.

## 12. Running it

| What | Command / URL |
|---|---|
| Start everything (Ollama, API :8000, translation :8010, UI :5173) | `powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1` |
| **Fresh demo state (about 5 min)** | `powershell -ExecutionPolicy Bypass -File scripts\demo_reset.ps1` |
| Rebuild only (stops and starts the API) | `scripts\rebuild.ps1` |
| Pre-compute briefs, translations, advisories; run the test bench | `.venv\Scripts\python scripts\warm_cache.py` |
| Run against a copy of the data | Set `ODYSSEY_DB`, `ODYSSEY_CACHE` and `ODYSSEY_LIVE=0`; the audit scripts already do this |
| The UI | http://127.0.0.1:5173 (`?view=now|live|soc|intel|orgs|proof&tab=…`, `&nolive` for screenshots) |

**Nine-step walk-through** (also in `docs/PS_COVERAGE.md`):
1. Now: the compromise, *Why this warning?*
2. Approve a decision.
3. SOC → Cases: CASE-0001.
4. SOC → Overview and System.
5. Intel → Overview, then Risk plan.
6. Intel → Advisories: WinCC.
7. Organisations → Vidyut Grid West Corp.
8. Live: run the *Full intrusion* drill.
9. Proof: *Run them now*.

## 13. Repository map (main thread)

| Area | Files |
|---|---|
| Build | `backend/app/pipeline.py`, `backend/app/sim/` (world, telemetry), `scripts/snapshot_feeds.py` |
| Engines (`backend/app/engine/`) | `exposure`, `versions`, `products`, `scoring`, `bayes`, `forecast`, `detectors`, `campaigns`, `sentinel` (autopilot), `riskplan`, `intel`, `soc`, `workflow`, `replay`, `reports` (CERT-In, STIX), `attack` (ATT&CK), `scorecard`, `testbench`, `ledger` |
| AI (`backend/app/ai/`) | `llm` (role registry), `narrate` (grounded briefs), `advisory` (IOCs, NER, mapping), `guard`, `embed`; `backend/mt_service.py` (IndicTrans2) |
| Runtime | `backend/app/main.py` (API, SSE, startup warm-up), `backend/app/live.py`, `backend/app/telemetry.py`, `backend/app/cache.py` |
| UI (`frontend/src/`) | `App`, `Shell` (nav, footer, hero figures), `ui` (design system), `Now`, `Live`, `SocOps`, `SystemView`, `Soc` (Intel), `Advisories`, `Orgs`, `Proof`, `ProofProactive`, `HowItWorks`, `AlertDetail` and its panels, `Heatmap`, `IndiaMap`, `Rewind`, `proactive` |
| Checks | `tests/`, `scripts/e2e_check.py`, `scripts/ui_audit.py` |
| Docs | `README.md`, `docs/PS_COVERAGE.md`, `docs/MODEL_CARD.md`, `PLAN.md`, `reports/`, `research_notes/` |

## 14. How this thread got here

1. All 22 IndicTrans2 languages, with a validated translation path.
2. Made proactive: day-0 forecast, sentinel autopilot with graduated autonomy, lead-time attribution, superseding, incident merge.
3. Mentor round: intel aggregation, real DShield and CISA advisories, VERS parsing, org OSINT, look-alikes, risk plan, approvals, test bench, a copilot (later removed), real-vs-SIM proof.
4. Uber UI, in three passes: map-first light theme, then the "Oreo" layering (black bands around white), then progressive disclosure (tiles, sheets, sections) because pages were still too complex.
5. Telemetry and SOC: API, AI and host telemetry, heatmaps across views, and the full SOC (cases, playbooks, SLAs, metrics, handover).
6. System-wide audit:
   - **Built:** live engine, attack drills, Live page, real-feed watch.
   - **Removed:** the chat assistant.
   - **Fixed:**
     - the ledger fork race;
     - Proof and brief cold starts;
     - inflated live counters;
     - inconsistent headline counts;
     - the 50-item decision cap;
     - startup robustness;
     - overstated model registry;
     - advisory IOC plurals.
   - **Added:** the simplified warning sheet, README, `demo_reset`, `e2e_check`, `ui_audit`.

## 15. Parallel work in this folder: the HTTP Shield thread

A second Claude Code thread, opened 01:18 tonight in the same `d:\DECOY` folder, is building "Odyssey in action". It
connects Odyssey to a real web app and red-teams it:

- `agent/` — drop-in middleware for ASGI, WSGI and Express, plus a log tailer;
- `backend/app/shield.py` and `backend/app/engine/webattack.py` — a WAF/IDS: signatures, brute-force and sweep detection, blocklist policy;
- `backend/app/engine/redteam.py`;
- a demo target app `target/portal.py` on :8080;
- `frontend/src/Shield.tsx` and Shield endpoints in `main.py`;
- `tests/test_shield.py`.

It shares the ledger, the autopilot and the database with the main thread, so its attacks create real proposals and cases.
Both threads' turns trigger the auto-sync, so its in-progress files reach GitHub. Coordinate before running
`demo_reset.ps1`: it wipes the shield's test data along with everything else.

## 16. Suggested next steps

1. Run `scripts\demo_reset.ps1` about 10 minutes before each judging slot, then re-run the shield demo if it is part of the pitch.
2. Close the cheapest prior-art gaps if time allows:
   - surface the DPDP 72 h and SEBI CSCRF routes on warnings for affected sectors;
   - script a prompt-injection demo advisory in the inbox.
3. Merge the shield thread's work once its tests and the UI audit pass with it, then extend `ui_audit.py` to cover its screen.
