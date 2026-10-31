# Odyssey: full context of the main build thread

Everything this thread established, for teammates, judges' Q&A preparation and any new Claude session that picks the
work up: the brief and the rules we work under, what was built and why, how it is verified, how it covers the problem
statement, the mentors' feedback and our prior-art research, how to run and demo it, and what is left.

As of 1 Nov 2026, 04:00 IST, commits up to `1f4dba4`, all on GitHub. Mentoring round 2 is at 08:00; hacking ends and
the elimination round starts at 13:00.

---

## 1. The brief

- **Event:** D3COY 1.0, organised by DJS ISACA and C-DAC. Theme: security, privacy and digital trust.
- **Problem statement PS-01:** AI-Based National Cyber Threat Early Warning System.
- **PS-01 key objectives:**
  1. aggregate threat intelligence from many sources (advisories, bulletins, vulnerability databases, threat feeds);
  2. AI-based threat analysis;
  3. early warning generation for emerging threats;
  4. risk prioritisation;
  5. actionable recommendations;
  6. a dashboard of active threats and affected technologies.
- **PS-01 example use case:** a new advisory arrives; the system matches it to the organisation inventory, assigns risk, recommends mitigation and alerts whoever is exposed.
- **PS-01 deliverables:** a functional prototype; a dashboard of detected threats, risk levels and alerts; a demonstration on public threat intelligence plus a controlled simulated dataset; an explanation of the AI model, the threat scoring and the mitigation workflow.
- **Judging** (published round-0 criteria): quality and originality; technical understanding of the PS; feasibility and impact; USP and future scope.
- **Round-1 feedback:**
  - Judges: make the whole system **proactive**.
  - Mentors: threat-intelligence aggregation; dashboard; **SOC**; **show real tests and attacks**; AI-based threat analysis; early warning and **organisation-based OSINT**; risk minimisation and mitigation as **risk management**; actionable intelligence and recommendations; **human in the loop**.
- **Later asks from the team lead (all built):** adaptive telemetry; a stronger SOC; an **organisation-based threat map** with end-to-end OSINT visualisation, as a subset of the national picture; visuals that are clear and free of anything invented; "it has to be truly innovative" and "the ultimate product".

## 2. Standing rules from the team lead

- **Win, and be class-apart:** state of the art as of Oct 2026; dynamic and agnostic (pluggable models, sources, config); every claim measured, never assumed.
- **Core AI:** security-specialised models of about 8B or smaller only, no fallback models; general models only as evaluation baselines; one impactful decision model; ask before downloading any LLM.
- **Fully local:** RTX 4070 Laptop (8 GB VRAM), i9-14900HX, 32 GB RAM, 0 cloud calls. Services bind to 127.0.0.1. Ollama stays reachable on the network, by the team lead's decision.
- **End-to-end product:** every capability ships with its interface, a demoable use case and a working backend; every button must really act. Neither UI-only nor backend-only work counts.
- **Uber "Oreo" interface:** black nav, page header band and footer around a white body with Base greys; no dark mode; one question per page, about four figures per band; details in sheets that slide in from the right; black is structure, never a data fill; colour only for meaning.
- **No chat assistant.** Built, measured, judged unreliable and removed.
- **Safety:** passive public feeds only, no scanning or exploiting of real networks; indicators always defanged; simulated data labelled SIM everywhere.
- **Git:** commit locally; the team's auto-sync hook commits and pushes at the end of every Claude turn; teammates only pull. A second Claude thread works in the same folder (section 16).

## 3. What Odyssey is

A national CERT's early-warning system for India's critical-infrastructure operators, running on one laptop.

- **The build** reads 13 sources, works out which CVEs and advisories hit the installed versions of 15 simulated operators across 6 NCIIPC sectors, scores and tiers every exposure, and plans the fewest fixes that remove the most risk.
- **The autopilot** warns each operator in its own language (22 Indian languages), acts on its own where the evidence is solid, and proposes to an analyst where it is not.
- **The live engine** watches its own sensors every 5 seconds and four real feeds every 15 minutes (5 while something is happening), takes new real CVEs in from NVD, detects attacks (surge, C2 beacon, flow anomaly), re-scores warnings on live evidence, opens SOC cases, and tunes its own thresholds from analysts' decisions. Every step lands in a hash-chained audit trail and reaches every open screen.

```
public feeds (REAL) ─┐                       ┌─ Now       what needs you
SIM sensors / logs ──┼─► pipeline (build) ───┤   Live      the running system, drills, new CVEs
inventory (SIM) ─────┘    data/ews.db        ├─ SOC       cases, decisions, log, adaptive detectors, system
                              ▲              ├─ Intel     threats, exposure heatmaps, risk plan, advisories, situation report
   live engine (5 s) ─────────┤              ├─ Orgs      each operator: threat map, exposure, fixes, OSINT, inbox
   feed watch + NVD intake ───┤              └─ Proof     every claim with evidence, test bench, how it works
   HTTP shield (other thread) ┘
        all write one hash-chained ledger ─► SSE stream ─► every open screen refreshes
```

## 4. The build pipeline (`backend/app/pipeline.py`, about 95 s)

| Stage | What it does |
|---|---|
| Feeds and candidate selection | Offline snapshot in `data/raw` (NVD 2021–26, KEV, EPSS, Vulnrichment/SSVC, CISA advisories, DShield, Feodo, OpenPhish, ATT&CK). Picks the CVEs naming a constituency product. |
| NVD records | Version configurations, CNA records, CVSS/CWE (TF-IDF classifiers fill gaps). |
| Day-0 forecast | Leak-free logistic regression frozen on 31 Jul 2026; flags new CVEs likely to be exploited; feeds the Bayesian prior. |
| Telemetry detectors | Daily decoy-grid surges (robust z on sessions and unique sources, breadth ≥ 3 sensors, 28-day baseline), decoy exploit tags, C2 beacons in firewall logs. Each carries its age for evidence decay. |
| Exposure and scoring | Three-source version reconciliation (NVD, CNA, advisory text; vendor-aware versions). `Risk = 100·R·K·(0.55·L + 0.30·S + 0.15·V)`, with evidence decay and age-off on sensor evidence. An SSVC decision path sets the tier and the CERT-In deadline; a Bayesian P(compromise) sets the 6-hour clock. |
| Sentinel autopilot | Graduated autonomy over every warning's time line: notices, digests, baselines, hunts, reports, confirms and stand-downs run on their own; forecasts, sensor-only warnings and escalations are proposals. Lead times over KEV attributed REAL or SIM. |

## 5. The live system (`backend/app/live.py`, started with the API)

- **Every 5 s:** reads the SIM decoy grid (24 sensors, 8 products) and firewall flows (one tick is one sensor-hour); runs the surge detector, the C2 beacon detector (periodicity, ≥ 30 connections, interval cv ≤ 0.2) and the flow-anomaly detector (IsolationForest trained on ten sensor-days, gated by a robust z ≥ 6 on fan-out, ports or bytes so the alert has a reason); acts through the Autopilot policy: compromise evidence triggers a notice, a CERT-In draft, a hunt and a SOC incident case at once, the regulator escalation is proposed; surge warnings are proposed.
- **Live re-scoring:** a confirmed beacon re-decides every warning on that host through the Bayesian model; those crossing 50% become suspected compromises with their own 6-hour clock from detection (`live.rescore` ledger event).
- **Feed watch, every 15 min on its own thread:** NVD (CVEs published or changed since the last check), CISA KEV, Feodo Tracker, OpenPhish. Offline means the snapshot keeps serving and the screen says so.
- **Live CVE intake** (`engine/intake.py`): a new CVE naming a product we run is built into a record, version-reconciled, scored, forecast on day 0 and acted on (Critical: notified at once; forecast-flagged: pre-emptive advisory proposed; else the digest). The PS use case, live, on real data; each intake is a `live.intake` ledger event with minutes since publication.
- **Adaptive telemetry** (`engine/adaptive.py`, `GET /api/adaptive`): thresholds re-derived every minute from the record, within bounds: surge z per product (4.0; +0.5 per false alarm, −0.25 per confirmed surge in 45 days; 3.5–7.0), anomaly gate per organisation (6.0; +1.0 per false positive it closed in 30 days; up to 10), beacon evidence (30 connections; 20 where a suspected compromise is open), feed cadence (15 min; 5 min for an hour after a Critical intake, a live compromise or a drill). Every change is a `live.adapt` ledger event with its reason.
- **Attack drills** from the Live page or `POST /api/live/drill/{scan|beacon|chain|cve}`: mass scanning, an implant calling a real Feodo C2, a full intrusion (scan → implant → lateral movement), and a new critical FortiOS CVE in exact NVD format. Traffic is labelled DRILL; time to detect is measured (full intrusion caught in order in about 26 s; the CVE drill matched, scored and 11 operators notified within a second; 720 quiet ticks give 0 detections).
- **`GET /api/live`** returns the stream state, intakes, adaptive settings and what each pipeline stage did since the engine started.

## 6. AI models (`config/models.json`, `docs/MODEL_CARD.md`)

| Job | Model | Runs on | Measured |
|---|---|---|---|
| Explain each warning, read advisories | MiST 8B (security-tuned) via Ollama | GPU | briefs 22/23 pass the fact validator (19 first try); vendor extraction 79.9% |
| Deep reasoning, batch only | Foundation-Sec-8B-Reasoning | GPU | free text, never on the critical path |
| Entities in advisories | SecureBERT 2.0 NER + IOC rules (defanged; versions and vendor links never indicators; plurals read) | CPU | |
| Related threats | SecureBERT 2.0 bi-encoder | CPU | |
| CWE and CVSS when missing | TF-IDF + linear models | CPU | CWE top-1 77.5%, CVSS error 0.85 |
| Exploitation on day 0 | TF-IDF + leak-free KEV history → logistic regression | CPU | 61.1% of later-exploited CVEs caught while flagging 2% (CVSS ≥ 9: 16.7%) |
| Compromise decision | Bayesian model; the forecast is its prior | CPU | every factor a likelihood ratio |
| Surge, beacon, flow anomaly | robust z · periodicity · IsolationForest + z-gate, adaptive thresholds | CPU | bench drills and negative controls |
| Prompt-injection guard | DeBERTa-v3 classifier + rules | CPU | 5/5 hostile caught, 0/5 benign blocked; hostile inbox advisory blocked |
| 22 Indian languages | IndicTrans2 distilled 200M + validator | CPU (:8010) | 127/132 sentences validated |

Language models only explain; the deterministic engine decides scores, tiers and deadlines. Every sentence an LLM writes
is checked against numbered facts; unverifiable text is withheld. Outputs are cached by content hash (`data/cache.db`).

## 7. The interface (React + Vite + Tailwind on :5173)

- **Now:** one headline ("A suspected compromise needs you now"), the incident card with its CERT-In countdown, journey bar and one action; a live status line; the India tile map (no contested borders); "Up next"; the black "Odyssey at work" band; the decisions waiting.
- **Live:** the pipeline stage by stage; attack drills with step-by-step progress and time to detect; new CVEs taken in from NVD; sensor streams with z-scores; detections; real-feed freshness.
- **SOC:** Overview (decision queue, team on shift, autopilot heatmap, **detectors adapting to your decisions**, replay/handover/warnings cards); Cases (opened automatically, owners by rule, SLA clocks, playbooks, notes, audited MTTA/MTTR/SLA); Warnings (ranked, tier and sector filters); Log; System (CPU, GPU, VRAM, memory, resident models, every AI job timed and checked, API latency, audit trail, build stages).
- **Intel:** Overview (what is under attack, the exposure heatmap technology × sector, the likely-next forecast, the **national situation report**); Threats (real DShield heatmap port × day; decoy grid, campaigns, CISA advisories, sources as sheets); Risk plan (93 changes remove 50% of national risk, 205 remove 80%, of 344 tickets); Advisories (inbox, paste-any-advisory, who must act, through suppliers, ready to block, how it was read; the hostile advisory shows the guard's block).
- **Organisations:** each operator opens on its **threat map** (`engine/threatmap.py`): assets laid out by zone (internet-facing, DMZ, internal, crown jewels; the worst ~10 per column drawn, the rest folded into one circle with its counts); threats on the left with their record (attack pressure per listening port with the DShield 28-day trend, decoy-grid scanning, exploited CVEs, phishing look-alikes, suppliers); implants calling out to C2 on the right; blast-radius lines to the crown jewels; REAL/SIM provenance on every node and line; hover shows the record, click opens the warning; refreshes every 10 s. Then open warnings, fix first, risk plan, "What outsiders see" (OSINT: exposed services, C2 in traffic, look-alike domains, DShield on its ports, advisories naming its products, its suppliers) and its inbox in its own language.
- **Proof:** eight claim cards each opening its evidence (test bench, lead over KEV, day-0 forecast, EPSS comparison, 22 languages, exposure precision, briefs, model comparison); "How it works": six steps, the model table, the open formula with a live worked example, who does what.
- **"Why this warning?" sheet:** three figures (time to act, SSVC decision, chance of compromise), then four tabs: What to do (the clocks that apply, the brief in 22 languages, actions, CERT-In draft, STIX 2.1 export), Why this score (Bayesian model, factor breakdown, evidence rules with age and weight, three-source exposure votes), How it unfolded (replay, ledger timeline), Related (through suppliers, ATT&CK, related threats, source text).
- **Design system:** `frontend/src/index.css` tokens; `frontend/src/ui.tsx`: Hero, Figures, Band, Section, Tile, Sheet, Pill, Row, Stat, Tabs, TierPill, Prov, toasts. Heatmaps use blue for activity and red for risk.

## 8. India's obligations and the supply chain

- **Clocks on every warning** (`engine/obligations.py`): CERT-In 6 h incident report, RBI DAKSH 6 h (banks), SEBI CSCRF 6 h (market entities), DPDP Board 72 h (systems holding personal data), NCIIPC for notified CII, the sector CSIRT, or the CERT-In Blueprint patch deadline; KEV due dates shown for reference.
- **Supplier fan-out** (`config/suppliers.json`, `engine/suppliers.py`, SIM): shared core banking, an OT integrator, a managed security provider. An advisory on a product a supplier runs reaches its dependents even where they do not run it (the C-Edge lesson); shown on advisories, warnings, organisations and the threat map, and added to notification proposals.

## 9. Data and honesty

| Data | Status |
|---|---|
| NVD, CISA KEV, Vulnrichment (SSVC), FIRST EPSS, CISA advisories, SANS ISC DShield, abuse.ch Feodo Tracker, OpenPhish, MITRE ATT&CK | REAL (snapshot 31 Oct 2026; NVD, KEV, Feodo and OpenPhish also read live) |
| Organisations, inventory, decoy grid, firewall logs, supplier graph, CERT-In-style advisories (the CERT-In site is unreachable from the venue) | SIM, labelled on screen |
| Live sensors | SIM, accelerated (one 5-second tick is one sensor-hour) |
| Lead over KEV | Reported separately on REAL signals only: 4 CVEs, median 20.5 d, up to 42.4 d; exposures known at go-live reported apart |

## 10. Verification (all green at `1f4dba4`)

| Check | How | Result |
|---|---|---|
| Engine tests | `.venv\Scripts\python -m pytest -q` | 98/98: 67 core plus 31 from the shield thread. Include: concurrent writers never fork the audit chain; SOC seeding and live case ids safe under concurrent requests; evidence decay; the clocks; supplier fan-out; the hostile advisory; live intake (matched, scored, acted on; patched versions cleared); the threat map a consistent subset of the record with provenance on every edge; adaptive thresholds follow recorded decisions within bounds. |
| Test bench | Proof → *Run them now* (`POST /api/tests/run`) | 109/109: 5 attack drills on a data copy, 5 detection checks with negative controls, the audit-trail chain, the engine tests. |
| Product flows | `.venv\Scripts\python scripts\e2e_check.py` | 16/16 on a private DB copy: every screen; approve and reject; a warning from issued to closed; a SOC case from new to closed; advisory analysis; compliance clocks, supplier fan-out and the hostile advisory; the organisation threat map; three drills plus a live CVE intake with live re-scoring and the adaptive layer focusing; the audit trail. |
| Interface | `python scripts\ui_audit.py` (Playwright drives the installed Edge against a copy API on :8001) | 18/18: every screen, sheet and button including the report, the threat map drawn and hovered, the adaptive section, the CVE and implant drills; 0 page or console errors, 0 HTTP 5xx. |
| Production build | `cd frontend && npm run build` | OK |

Headline measurements, recomputed live on the Proof page: 47× noise reduction (16,730 CVEs this month → 356 warnings
needing action); 82,104 2026 CVEs → 2,277 name a constituency product → 354 Critical; EPSS alone misses 49.1% of
KEV-confirmed exploited CVEs (CVSS ≥ 9 alone 52.7%); 4,515 asset × CVE pairs cleared by version evidence; 0 false
"affected" on the real Ivanti case.

## 11. Coverage of the PS, the mentors and the prior-art research

**PS-01:** all six objectives, the example use case (the real CISA Siemens WinCC advisory: 13 assets at 7 operators,
version ranges parsed, proposal to notify, analyst approves; and live intake for new CVEs) and all four deliverables.

**Judges and mentors:** all ten points: proactive (live engine, autopilot, feed watch, intake, adaptive); aggregation;
dashboard; SOC (cases, playbooks, SLAs, metrics, handover, adaptive detectors, system telemetry); real tests and attacks
(test bench, drills, real KEV/DShield/advisories; the shield thread adds a protected real web app); AI analysis; early
warning and organisation OSINT (threat map, OSINT tab); risk management (risk plan); actionable intelligence; human in
the loop (graduated autonomy, approve/reject with reasons feeding calibration).

**Prior-art research** (`reports/National cyber early warning case study.md`): all 16 "class-apart" decisions built:
three-source exposure; evidence floors with decoy exploit tags; separated severity/relevance/confidence/decision;
named-rule ledger with Admiralty weighting, decay and age-off; SSVC → CERT-In deadlines with the 6 h / DAKSH / SEBI /
DPDP clocks; chain-aware grouping and blast radius; closed-set span-grounded LLM with numeric validation; security
encoders for structured tasks; the surge detector with a chance baseline; the leakage-safe budget-judged predictor; a
live prompt-injection red-team (the hostile inbox advisory); honest KPIs (time to alert, lead over KEV, time to detect);
routing by sector, CSIRT and supplier fan-out; Indic languages with protected spans; standards-native sovereign output
(STIX 2.1, TLP, offline); event-sourced live re-scoring with deterministic replay. Deliberate deviation: the research
advised no India map; a borderless tile map avoids contested boundaries.

## 12. Bugs found by the audits and fixed

Concurrent ledger appends could fork the hash chain (now one write transaction); SOC case seeding raced under the first
concurrent requests (HTTP 500 on Live) and live case ids could collide; the Proof page and the first brief took 15–20 s
after a restart (warmed at startup); live counters counted a rebuild's events as an hour of activity; autopilot totals
double-counted the build's own actions; headline counts disagreed (now one definition: warnings needing action = Critical
+ suspected compromise, excluding closed); the decisions list silently capped at 50; the API would not start if an
optional engine failed; the model registry claimed components that were not built; an advisory's attacker domain was
missed because the attack context read only singular words; the CVE drill reused an id and silently did nothing on a
copy; the CERT-In report modal sat under the nav.

## 13. Running it

| What | Command / URL |
|---|---|
| Start everything (Ollama, API :8000, translation :8010, UI :5173) | `powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1` |
| **Fresh demo state (about 5 min)** | `powershell -ExecutionPolicy Bypass -File scripts\demo_reset.ps1` |
| Rebuild only (stops and starts the API) | `scripts\rebuild.ps1` |
| Pre-compute briefs, translations, advisories; run the test bench | `.venv\Scripts\python scripts\warm_cache.py` |
| Run against a copy of the data | `ODYSSEY_DB`, `ODYSSEY_CACHE`, `ODYSSEY_LIVE=0`; the audit scripts do this |
| The UI | http://127.0.0.1:5173 (`?view=now|live|soc|intel|orgs|proof&tab=…&org=…`, `&nolive` for screenshots) |

**Demo** (`docs/PITCH.md` has the full script and the judges' Q&A): Now and *Why this warning?* → approve a decision →
Live: the new-CVE drill, then the full intrusion → SOC → Cases → SOC overview (adaptive detectors) → Intel overview,
risk plan, the situation report, the WinCC and hostile advisories → Organisations: Vidyut Grid West Corp's threat map,
OSINT, suppliers, Marathi inbox → Proof: *Run them now*.

The incident's CERT-In 6-hour clock starts at build time: run `demo_reset.ps1` about ten minutes before each slot, and
tell the shield thread first, because it clears that thread's test data too.

## 14. Repository map (main thread)

| Area | Files |
|---|---|
| Build | `backend/app/pipeline.py`, `backend/app/sim/` (world, telemetry), `scripts/snapshot_feeds.py` |
| Engines (`backend/app/engine/`) | `exposure`, `versions`, `products`, `scoring`, `bayes`, `forecast`, `detectors`, `campaigns`, `sentinel` (autopilot), `riskplan`, `intel`, `soc`, `workflow`, `replay`, `reports` (CERT-In, STIX), `attack` (ATT&CK), `scorecard`, `testbench`, `ledger`, `obligations`, `suppliers`, `intake`, `adaptive`, `threatmap`, `sitrep` |
| AI (`backend/app/ai/`) | `llm` (role registry), `narrate` (grounded briefs), `advisory` (IOCs, NER, mapping), `guard`, `embed`; `backend/mt_service.py` (IndicTrans2) |
| Runtime | `backend/app/main.py` (API, SSE, startup warm-up), `backend/app/live.py`, `backend/app/telemetry.py`, `backend/app/cache.py` |
| UI (`frontend/src/`) | `App`, `Shell`, `ui`, `Now`, `Live`, `Adaptive`, `SocOps`, `SystemView`, `Soc` (Intel), `Advisories`, `Orgs`, `OrgThreatMap`, `Proof`, `ProofProactive`, `HowItWorks`, `AlertDetail` and its panels, `Heatmap`, `IndiaMap`, `Rewind`, `proactive` |
| Config | `config/scoring.json` (rules, deadlines, clocks, regulators, decay, sentinel policy), `config/models.json`, `config/suppliers.json` |
| Checks | `tests/`, `scripts/e2e_check.py`, `scripts/ui_audit.py`, `scripts/demo_reset.ps1` |
| Docs | `README.md`, `docs/PS_COVERAGE.md`, `docs/MODEL_CARD.md`, `docs/PITCH.md`, this file, `PLAN.md`, `reports/`, `research_notes/` |

## 15. How this thread got here

1. All 22 IndicTrans2 languages with a validated translation path.
2. Made proactive: day-0 forecast, sentinel autopilot with graduated autonomy, lead-time attribution, superseding, incident merge.
3. Mentor round: aggregation, real DShield and CISA advisories, VERS parsing, org OSINT, look-alikes, risk plan, approvals, test bench, a copilot (later removed), real-vs-SIM proof.
4. Uber UI in three passes: map-first light theme; the "Oreo" layering; progressive disclosure (tiles, sheets, sections).
5. Telemetry and SOC: API, AI and host telemetry; heatmaps; the full SOC.
6. System-wide audit: live engine and drills, chat assistant removed, races and cold starts fixed, honest counters, README, `demo_reset`, `e2e_check`, `ui_audit`.
7. Completion pass: the five open prior-art items (decay, clocks, supplier fan-out, injection demo, live re-scoring).
8. "Ultimate" pass: live CVE intake from NVD, the new-CVE drill, the national situation report, coherent counts, the pitch.
9. Team lead's last asks: the organisation threat map, adaptive telemetry, the SOC adaptive view.

## 16. Parallel work in this folder: the HTTP Shield thread

A second Claude Code thread works in the same `d:\DECOY` folder on "Odyssey in action": it connects Odyssey to a real
web app and red-teams it (`agent/` middleware for ASGI/WSGI/Express, `backend/app/shield.py`,
`backend/app/engine/webattack.py`, `backend/app/engine/redteam.py`, `target/portal.py` on :8080, `frontend/src/Shield.tsx`,
`tests/test_shield.py`, its own entry in `README.md`). It shares the ledger, the autopilot and the database, so its attacks
create real proposals and cases; its 31 tests run in the same suite. Both threads' turns trigger the auto-sync. The main
thread's commits list their files explicitly so as not to sweep the shield's in-progress work in.

## 17. Known limits

- Organisations, inventory, sensors and the supplier graph are simulated and labelled SIM; the live sensors are accelerated.
- CERT-In advisories are simulated because the site is unreachable from the venue; dark-web sources are not covered.
- Forecast precision is 5% because exploitation is rare (0.16% base rate), which is why forecasts are proposals.
- Each drill and each shield attack adds proposals and cases to the live database; `demo_reset.ps1` clears them.
- The deadlines run in real time from the build (see section 13).
- A background task started from Claude Code may show as still running after `demo_reset.ps1` finishes, because the API it launched inherits the task's output handles; it is harmless.

## 18. Suggested next steps

1. Rehearse the nine-step demo once with `docs/PITCH.md` open; run `demo_reset.ps1` ten minutes before each slot.
2. If the shield demo is in the pitch, make sure it works on the reset data; otherwise leave it out.
3. After the hackathon: real operator onboarding (inventory connectors), the national supplier graph from procurement data, sector-specific OT telemetry.
