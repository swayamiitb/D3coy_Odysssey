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
- **Intel:** Overview (what is under attack, the exposure heatmap technology × sector, the likely-next forecast, the **national situation report**, **risk lists and STIX** export); **Graph** (the intelligence graph, section 19); Threats (real DShield heatmap port × day; decoy grid, campaigns, CISA advisories, sources as sheets); Risk plan (93 changes remove 50% of national risk, 205 remove 80%, of 344 tickets); Advisories (inbox, paste-any-advisory, who must act, through suppliers, ready to block, how it was read; the hostile advisory shows the guard's block).
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
| Engine tests | `.venv\Scripts\python -m pytest -q` | 124/124 at the graph commit (section 19): 75 core plus 49 from the shield thread. Earlier, 98/98: 67 core plus 31 from the shield thread. Include: concurrent writers never fork the audit chain; SOC seeding and live case ids safe under concurrent requests; evidence decay; the clocks; supplier fan-out; the hostile advisory; live intake (matched, scored, acted on; patched versions cleared); the threat map a consistent subset of the record with provenance on every edge; adaptive thresholds follow recorded decisions within bounds. |
| Test bench | Proof → *Run them now* (`POST /api/tests/run`) | 109/109: 5 attack drills on a data copy, 5 detection checks with negative controls, the audit-trail chain, the engine tests. |
| Product flows | `.venv\Scripts\python scripts\e2e_check.py` | 19/19 at the graph commit (the shield thread added two, section 19 added the graph flow). Earlier, 16/16 on a private DB copy: every screen; approve and reject; a warning from issued to closed; a SOC case from new to closed; advisory analysis; compliance clocks, supplier fan-out and the hostile advisory; the organisation threat map; three drills plus a live CVE intake with live re-scoring and the adaptive layer focusing; the audit trail. |
| Interface | `python scripts\ui_audit.py` (Playwright drives the installed Edge against a copy API on :8001) | 21/21 at the graph commit. Earlier, 18/18: every screen, sheet and button including the report, the threat map drawn and hovered, the adaptive section, the CVE and implant drills; 0 page or console errors, 0 HTTP 5xx. |
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
| Engines (`backend/app/engine/`) | `exposure`, `versions`, `products`, `scoring`, `bayes`, `forecast`, `detectors`, `campaigns`, `sentinel` (autopilot), `riskplan`, `intel`, `soc`, `workflow`, `replay`, `reports` (CERT-In, STIX), `attack` (ATT&CK), `scorecard`, `testbench`, `ledger`, `obligations`, `suppliers`, `intake`, `adaptive`, `threatmap`, `sitrep`, `graph` (intelligence graph, replay), `export` (risk lists, STIX bundle), `watch` (watchlists), `iocs` (indicator import), `brand` (brand and social watch), `surface` (consented attack surface) (CAP red-team against our own ingest) |
| AI (`backend/app/ai/`) | `llm` (role registry), `narrate` (grounded briefs), `advisory` (IOCs, NER, mapping), `guard`, `embed`; `backend/mt_service.py` (IndicTrans2) |
| Runtime | `backend/app/main.py` (API, SSE, startup warm-up), `backend/app/live.py`, `backend/app/telemetry.py`, `backend/app/cache.py`, `backend/app/taxii.py` (TAXII 2.1 router), `backend/app/osint_api.py` (brand and surface routes), `backend/app/sachet.py` (SACHET reader, CAP writer, CAP ingest guard) |
| UI (`frontend/src/`) | `App`, `Shell`, `ui`, `Now`, `Live`, `Adaptive`, `SocOps`, `SystemView`, `Soc` (Intel), `Advisories`, `Orgs`, `OrgThreatMap`, `Proof`, `ProofProactive`, `HowItWorks`, `AlertDetail` and its panels, `Heatmap`, `IndiaMap`, `Rewind`, `proactive` |
| Config | `config/scoring.json` (rules, deadlines, clocks, regulators, decay, sentinel policy), `config/models.json`, `config/suppliers.json` |
| Checks | `tests/`, `scripts/e2e_check.py`, `scripts/ui_audit.py`, `scripts/demo_reset.ps1` |
| Docs | `README.md`, `docs/PS_COVERAGE.md`, `docs/MODEL_CARD.md`, `docs/PITCH.md`, `docs/TIP_GAP_AUDIT.md`, `docs/SACHET_BHASHINI_PLAN.md` (the shield thread's plan; Connector A built, section 21), this file, `PLAN.md`, `reports/`, `research_notes/` |

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
create real proposals and cases; its tests run in the same suite (49 of the 124). Both threads' turns trigger the auto-sync.
The main thread's commits list their files explicitly so as not to sweep the shield's in-progress work in.

Since the first version of this document the shield thread also delivered, all committed and verified: **Channels**
(`backend/app/notify.py`, `config/notify.json`, secrets in the git-ignored `config/notify.local.json` or the environment):
a tap on the ledger, cursor at the head on API start, one card per routable event to Slack, Discord, Teams, e-mail or any
webhook, severity floor High, one per (kind, subject) per 10 min, cap 20/min, back-off 60 s per failing destination; new
ledger kinds `notify.sent` / `notify.failed` (destination host only, never the URL); endpoints `GET /api/notify`,
`POST /api/notify/test/{name}`, `POST /api/notify/channels/{name}/enabled?on=`, `POST /api/notify/reload`; starts only
when `ODYSSEY_LIVE != 0` and `ODYSSEY_NOTIFY != 0`; `auto.notify` is deliberately not routed (one CVE intake would be
eleven org notices), `live.intake`, `live.detect.*`, `live.rescore`, `live.drill.end`, `auto.case_opened`,
`auto.escalate`, `auto.proposed` and `shield.*` are. The **Ops Console** (`target/console.py`, :8090) is a webhook receiver
with a live card page. `agent/odyssey_proxy.py` is a reverse-proxy agent for any stack (drops with 403 before the upstream).
The Live page gained "A real app, protected" and "Alerts delivered to your apps" above the pipeline section.
`scripts/demo_reset.ps1` also launches the console if it is down and, as its last step, clears it, so the proposals that
`warm_cache.py` creates leave no cards before a demo; after an API restart the shield registry is empty for up to 10 s
until the portal's heartbeat re-announces it. The shield thread also moved all test scratch off the full C: drive (see
`machine-c-drive-nearly-full` in the team lead's memory notes and `tests/conftest.py`).

## 17. Known limits

- Organisations, inventory, sensors and the supplier graph are simulated and labelled SIM; the live sensors are accelerated.
- CERT-In advisories are simulated because the site is unreachable from the venue; dark-web sources are not covered.
- Forecast precision is 5% because exploitation is rare (0.16% base rate), which is why forecasts are proposals.
- Each drill and each shield attack adds proposals and cases to the live database; `demo_reset.ps1` clears them.
- The deadlines run in real time from the build (see section 13).
- A background task started from Claude Code may show as still running after `demo_reset.ps1` finishes, because the API it launched inherits the task's output handles; it is harmless.
- The brand and social watch reads public sources over the network: crt.sh rate-limits for a minute at a time and is then shown offline, a live scan takes 10 to 25 s, and a hit is a scored match of a term, not a finding of abuse. The attack-surface scan covers only systems the operator owns (section 20); a public target is refused by rule.
- SACHET is read-only public input and Odyssey's CAP is SACHET-compatible, not connected to SACHET (section 21). Most
  SACHET alerts are district-level, so the state inferred for an alert is explainable but not perfect; the basis and
  confidence are on every row. Titles arrive in the regional language and are shown as published. Bhashini is not built.

## 18. Suggested next steps

1. Rehearse the nine-step demo once with `docs/PITCH.md` open; run `demo_reset.ps1` ten minutes before each slot.
2. If the shield demo is in the pitch, make sure it works on the reset data; otherwise leave it out.
3. After the hackathon: real operator onboarding (inventory connectors), the national supplier graph from procurement data, sector-specific OT telemetry.

## 19. The intelligence graph, risk lists and STIX, the TIP gap audit (1 Nov 2026, 05:45 to 07:00 IST)

The team lead asked for a deep audit against the platforms CloudSEK's knowledge-base ranking lists (CloudSEK and
Recorded Future first), inside our scope, and named one example gap: a well-defined adaptive, breathing intelligence
graph. `docs/TIP_GAP_AUDIT.md` is the audit. Built to close the gap:

- `backend/app/engine/graph.py`: `intel_graph(conn, focus, live)` builds the graph from the database, the ledger, the
  live engine and the local ATT&CK and Feodo snapshots. Eleven node kinds (org, asset in org focus, product, cve,
  campaign, technique, malware, actor, indicator, supplier, signal); edges with kind, label, provenance (REAL, SIM,
  REAL · SIM), weight and last_seen; every node has `last_seen`, `age_h`, `pulse = exp(-age_h/48)`, `phase`
  (fresh < 1 h, today, week, fading < 30 d, aged), `risk`, `tier`, `facts`, and a deterministic layout (`ring`,
  `angle`, `r`): rings by kind, angles from the circular mean of inner neighbours with a minimum gap, evenly spaced when
  the ring is full. Threat groups: ATT&CK intrusion-sets ranked malware-link first (Feodo family → ATT&CK software →
  groups using it), then technique overlap (≥ 3 and ≥ 60% of observed), at most 8, every one labelled "overlap, not
  attribution". Cached 4 s per focus. `node_card()` gives neighbours, the ledger evidence and how the kind is derived.
- `backend/app/engine/export.py`: `risk_list()` for cves | ips | domains | products (scored, provenance, evidence;
  C2 refanged with the defanged form beside it), `to_csv()`, `graph_stix()` (STIX 2.1 identities, infrastructure,
  software, vulnerabilities, campaigns, attack-patterns, malware, intrusion-sets, indicators, sightings for beacons,
  notes for live signals, relationships; no dangling references).
- API: `GET /api/graph?focus=`, `GET /api/graph/node?id=&focus=`, `GET /api/graph/stix?focus=&tlp=`,
  `GET /api/risklists`, `GET /api/risklists/{kind}?format=json|csv`.
- UI: `frontend/src/IntelGraph.tsx` (Intel → Graph tab; focus pills; breath strip; SVG with ring captions, breathing
  halos, one-shot ping for new nodes, collision-avoiding labels, hover panel, kind-chip filter, click → card sheet with
  neighbours you can follow and the evidence list); `Orgs.tsx` gets "Open in the intelligence graph"; `Soc.tsx`
  Intel overview gets the "Risk lists and STIX" tile and sheet; `App.tsx` handles `go('intel','graph:ORG')` and
  `?focus=`; `index.css` has the `odyssey-breath` and `odyssey-ping` keyframes.
- Verification: `tests/test_graph.py` (8 tests), the graph flow in `scripts/e2e_check.py`, the graph step in
  `scripts/ui_audit.py`. The API was restarted so the running system serves the new code.
- Still missing in scope at that point (audit section 6): user-authored watchlists and alert rules on graph entities,
  bulk IOC import, a TAXII server, graph history. All four, plus passive brand and social monitoring and a consented
  attack-surface scan of owned systems, were built in the next hour (section 20). Out of scope by rule: dark web,
  scanning of networks we do not own, takedowns, sandboxing (each with a plug-in point in the audit).
- Lesson for the next thread: never run pytest, the e2e check and the UI audit at the same time on this laptop; the
  advisory-analysis paths load models in each process and the machine runs out of memory (one MemoryError and one
  guard-model failure in a concurrent run, both green when run alone).

## 20. Watchlists, indicator import, TAXII, replay, brand and social watch, consented attack surface (1 Nov 2026, 07:15 to 08:15 IST)

The four items the audit's section 6 listed as still worth building, and two its section 5 had placed out of scope,
built within the rules the team lead set (passive public sources for anyone else's systems; active checks only on
systems we own and prove we own). All six are deterministic services with no model call. Built and tested on the
backend first, by parallel sub-threads; the interface landed right after. The API serves the new routes after the
next restart; the sub-threads never restart :8000 while a demo may be running, so the main thread does it.

**Files.** `backend/app/engine/watch.py` (watchlists), `backend/app/engine/iocs.py` (indicator import and matching),
`backend/app/taxii.py` (TAXII 2.1 router, mounted by `main.py`), `backend/app/engine/brand.py` (brand and social
watch), `backend/app/engine/surface.py` (consented attack surface), `backend/app/osint_api.py` (the brand and surface
routes), `backend/app/engine/graph.py` (`as_of` on the builder, `replay_steps()`, and the new node sources: matched
imports, brand hits of weight, surface scans, watch firings), `backend/app/live.py` (watch evaluation every third tick,
the imported address sets and `iocs.mark_live_match` on every tick), `backend/app/main.py` (graph replay, watch and
indicator routes), `tests/test_brand_surface.py`. UI: `frontend/src/IntelGraph.tsx` gains the replay slider, a Watch
button on every card and the Watchlist section; Intel gets a new Indicators tab (import, what is held, CSV, STIX and
TAXII); Intel → Threats gets "Brand and social watch" and "Attack surface, with consent"; Organisations → OSINT gets
the brand watch for that organisation. The UI files are new files under `frontend/src/` wired in by the main thread.

**Endpoints.**

- Graph: `GET /api/graph?focus=&as_of=` (the record as it stood at `as_of`; later evidence left out, pulses aged to
  it), `GET /api/graph/replay` (nine instants: snapshot date, 30, 14, 7, 3 and 1 days ago, 6 h and 1 h ago, now),
  `GET /api/graph/node?id=&focus=`.
- Watchlists: `GET /api/watches` (watches, events, suggestions, rule texts, the default rule), `POST /api/watches`
  `{target, rule?, owner?, label?, note?}` (404 when the target is not in the graph, 400 on a bad rule),
  `POST /api/watches/{id}/pause|resume|delete`, `POST /api/watches/evaluate`.
- Indicators: `POST /api/iocs/import {text, source?, tlp?, tags?}` (400 when empty), `GET /api/iocs?matched_only=&limit=`,
  `GET /api/iocs/export?format=csv|stix&matched_only=`.
- TAXII 2.1 (read-only, media type `application/taxii+json;version=2.1`, bearer token when `ODYSSEY_TAXII_TOKEN` is
  set): `GET /taxii2/`, `/taxii2/odyssey/`, `/taxii2/odyssey/collections/`, `.../collections/{id or alias}/`,
  `.../objects/?limit=&next=&added_after=&match[type]=&match[id]=`, `.../manifest/`, `.../objects/{object_id}/`,
  `.../objects/{object_id}/versions/`. Collections: `graph`, `indicators`, `vulnerabilities`, fixed UUIDs.
- Brand: `GET /api/brand?org_id=`, `POST /api/brand/scan {term | org_id}` (10 to 25 s), `GET /api/brand/hits?term=&org_id=&limit=`.
- Surface: `POST /api/surface/scan {url, consent: true, org_id?}` (400 with the reason when refused),
  `GET /api/surface?org_id=`, `GET /api/surface/can-scan?url=`, `GET /api/surface/{scan_id}`.
- Live: `GET /api/live` detections gain kinds `ioc` and `watch`.

**Ledger kinds.** `watch.added`, `watch.paused`, `watch.active`, `watch.deleted`, `watch.fired` (source WATCHLIST,
provenance AUTO; the channels route it); `ioc.import`, `ioc.match`; `brand.hit` (score 70 or above, provenance REAL);
`surface.scan`, `surface.finding`.

**Tables** (all created on first use by each engine's `ensure()`):

- `watches` (id, created_at, owner, target, label, kind, rule JSON, note, status active|paused, last_state JSON,
  last_eval, fired, last_fired); `watch_events` (id, ts, watch_id, target, label, reason, severity, payload JSON).
- `iocs` (id, value, type, defanged, source, tlp, tags, note, added_at, first_seen, last_seen, matched, matches JSON,
  enrich JSON, severity; unique on value and type); `ioc_imports` (id, ts, source, tlp, format text|csv|stix, found,
  new, matched, by_type JSON, seconds).
- `brand_hits` (id, ts, term, org_id, source, kind, channel, value defanged, url, title, snippet, score, provenance,
  evidence, raw, first_seen, last_seen; unique on term, source, kind, value); `brand_scans` (id, ts, term, org_id,
  sources JSON with status and ms per source, hits, new_hits, seconds).
- `surface_scans` (id, ts, target, host, org_id, app_id, consent, score, grade, findings, seconds, requests, status
  done|refused|unreachable, reason); `surface_findings` (id, scan_id, check_name, severity, title, detail, evidence,
  cwe, fix, path, provenance).

**Rules.**

- Watch rules: `any` (fresh evidence, a worsening tier or a new connection), `fresh` (pulse rises above the threshold,
  or new evidence is recorded), `tier` (the worst open tier reaches the threshold or worse), `connect` (a new edge).
  Default `{kind: any, pulse: 0.5, tier: Critical}`. Edge-triggered against `last_state`: a watch fires on the change,
  never on every evaluation while the condition holds. Evaluated by the live engine every third tick (15 s) and on
  `POST /api/watches/evaluate`; an exception in a watch is logged and never stops detection. Event severity follows the
  entity's tier: Compromise to Critical, Critical to High, High to Medium, Medium and Watch to Low. Assets are watched
  in their organisation's focus graph (the asset id starts with the organisation id).
- Indicators: types `ipv4-addr`, `domain-name`, `url`, `file:sha256`, `file:sha1`, `file:md5`, `vulnerability`;
  refanged on the way in (`[.]`, `hxxp`, `[:]`), stored once per (value, type), defanged for display. Matched against
  the live flows and C2 sightings (SIM), the shield's attackers (`shield.detect.*`), our own addresses and domains and
  their look-alikes, and the exposure record (CVEs); enriched from Feodo Tracker, DShield, OpenPhish and CISA KEV
  (REAL). Imported addresses and domains join the live engine's flow matching on every tick (`live flows` match,
  severity High). Export as CSV or a STIX 2.1 bundle.
- Replay: nothing recorded after the instant is drawn, a CVE not yet published at that date is not in anyone's
  picture, every pulse is aged to the instant, and the layout rules are unchanged so stepping through does not jitter.
- Brand: six passive public sources (crt.sh, URLhaus, OpenPhish, Google News RSS, Hacker News, Reddit RSS), 20 s
  timeout each, run in parallel; a source that does not answer is reported offline, never raised. For an organisation
  the terms are its name's words of five letters or more minus generic words, its domain and that domain's look-alike
  permutations. Hit kinds `lookalike_cert`, `malicious_url`, `phishing_url`, `mention`; score 0 to 100 by explicit
  rules; `LEDGER_FLOOR = 70` for `brand.hit`; the graph draws hits at 70 or above that belong to an organisation.
- Surface: two gates in code, both required: `consent: true` and a host that is loopback, RFC 1918, link-local or
  carrier-grade NAT, or an app the HTTP-shield agent has registered; otherwise refused with the reason (HTTP 400).
  GET and HEAD only, no payloads, `MAX_REQUESTS = 40`, `COOLDOWN_S = 60` per target. Checks: `transport`, `tls`,
  `headers`, `cookies`, `disclosure`, `exposure` (files and admin paths), `ports` (a TCP connect to 21, 22, 23, 80,
  443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017 on the target host; the sensitive ones are
  High findings). Framework fingerprints map to product keys so the scan links to known CVEs in the constituency.
  Grade A at 90 or more, B 80, C 70, D 55, E 40, else F.
- Honesty: a brand hit is a scored match of a term in a public source, not a finding of abuse; a surface grade describes
  an owned system as it answered, and nothing else was touched; an imported indicator keeps its source and TLP and a
  match says where in our own record it was seen; every new node and edge carries REAL, SIM or REAL · SIM.

**Measured so far.** A live brand run for "irctc" returned 79 real hits, with crt.sh rate-limited that minute and shown
offline. The CityPower portal (:8080, registered to PWR-01) scores 29, grade F: plain HTTP, open SSH and SMB ports, no
CSP, an exposed `/openapi.json`, a FastAPI fingerprint. `tests/test_brand_surface.py` has 8 tests (scan scores, stores
and audits; no duplicates on a second scan; offline sources do not fail a scan; generic words dropped from an
organisation's terms; the ownership gate refuses what is not ours; a scan finds and audits; the cooldown; the real
portal when it is up).

**Verification plan (targets until the main thread runs them, one check at a time, never concurrently).**

- Engine tests: about 140 (124 at the graph commit, plus 8 brand and surface, plus the watchlist, indicator and TAXII
  tests in a file of their own). `tests/test_watch_iocs_taxii.py` did not exist when this section was written.
- Product flows (`scripts/e2e_check.py`): 25 (19 plus six: a watch added, fired by the scanning drill and paused;
  an import that matches a C2 sighting and one of our own assets, exported as CSV and STIX; TAXII discovery,
  collections and a paged objects read; the graph at an earlier instant; a brand scan; a consented scan of the portal
  and a refused public target).
- Interface (`scripts/ui_audit.py`): 24 steps (21 plus three: the Indicators tab with an import; a watch set from a
  graph card and the replay slider moved; the brand and attack-surface sections opened).
- Production build: `cd frontend && npm run build`.
- Documents updated in this pass: `README.md`, `docs/TIP_GAP_AUDIT.md` (sections 1, 2, 3, 5, 6 and 7),
  `docs/PS_COVERAGE.md`, `docs/PITCH.md`, `docs/MODEL_CARD.md`, this file.

## 21. The SACHET connector: national disaster alerts in, SACHET-compatible CAP out, a hardened CAP ingest (1 Nov 2026, 08:20 to 09:00 IST)

The shield thread wrote `docs/SACHET_BHASHINI_PLAN.md`, two independent connectors: A for SACHET and B for Bhashini.
The team lead's decision: leave Bhashini for now, build SACHET and solidify it. This section is Connector A as the
main thread built it, in the plan's shape (reader, writer, guard, red-team, tests). Connector B is deliberately not
built: Bhashini is a cloud API that would break the 0-cloud-calls promise, and the local IndicTrans2 stays the
translator. Why SACHET at all, for a cyber early-warning system: when an operator goes dark, the first question is
whether it is the weather or an attack. A disaster alert on the operator's state is context for its warnings, and an
attack landing during a disaster is worse. The security angle: an early-warning system must defend its own inputs, so
every inbound CAP message is treated as hostile until proven otherwise. No model is called anywhere in this connector.

**Files.** `backend/app/sachet.py` (reader, writer, guard; standard-library XML and httpx, no new dependency;
defusedxml is not installed and is not needed, because any DTD is refused before parsing), (ten hostile cases against our own loopback ingest), `backend/app/main.py` (the five routes below; the guard starts at
API startup unless `ODYSSEY_SACHET=0` and reads the feed once in a background thread), `backend/app/engine/graph.py`
(`_disasters()`: matched SACHET alerts and accepted inbound CAP as `signal` nodes), `tests/test_sachet.py`, the SACHET
flow in `scripts/e2e_check.py`, the SACHET step in `scripts/ui_audit.py`. UI: "Disaster alerts (SACHET)" under
Intel → Threats (a new file under `frontend/src/`, wired in by the main thread) and a tile on Now. Snapshots, both
public domain, for offline runs and tests: `data/raw/sachet_rss.xml` (100 real items, 1 Nov 2026) and
`data/raw/sachet_cap_sample.xml` (one real CAP 1.2 message).

**The reader.** `CapGuard.read_feed(live)` reads `https://sachet.ndma.gov.in/cap_public_website/rss/rss_india.xml`
every 900 s (`FEED_INTERVAL_S`), read-only, with the same `fresh | snapshot | offline` states as the other feeds and
the snapshot served when the network is down; provenance REAL, source "NDMA SACHET public CAP feed (public domain)".
`infer_states(title, author, areas, sender)` gives each alert the states it concerns, each with its basis and a
confidence: a state named in the text (0.95), an SDMA sender naming its state (0.9), a sender office such as IMD
Chennai or IMD Amaravati mapped to its state (0.85), a district named (0.75), and only when nothing else matched, the
script of the text (Telugu, Bengali, Tamil, Kannada and so on; 0.4). `match_orgs()` joins those states to the
operators' states. `fetch_cap(url)` returns one alert's full CAP message and fetches only from `sachet.ndma.gov.in`
(loopback allowed for tests); the same DTD refusal and size cap apply.

**The writer.** `write_cap(alert, infos, status="Exercise")` renders an Odyssey warning as CAP 1.2 in the
`urn:oasis:names:tc:emergency:cap:1.2` namespace: identifier, sender `odyssey@ncew.local`, sent in IST, status,
`msgType` Alert, source "Odyssey National Cyber Early Warning (prototype)", scope Restricted with a restriction line, a
note that says it is SACHET-compatible and not an NDMA/SACHET message, then one `<info>` per language with category
Security, the event, urgency and severity from the tier (Compromise to Extreme and Immediate, Critical to Severe and
Immediate, High to Moderate and Expected, Medium and Watch to Minor and Future), certainty, expiry, `senderName`
"Odyssey (SACHET-compatible prototype, not NDMA)", headline, description, instruction, parameters (`odyssey:risk`,
`odyssey:tier`, `odyssey:deadline_hours`, `cve`, `kev`) and the area. Every text node is escaped.
`GET /api/warnings/{org_id}/{cve_id}/cap?langs=hi,mr&status=Exercise` assembles it from the warning's detail and brief:
English always, plus one `<info>` per requested language when the local translator validated the headline and at
least one sentence (withheld sentences are dropped and noted in the message, never guessed); the response header
`X-Odyssey-Languages` lists the languages included; `application/cap+xml`, served as a download. `status` may be
Exercise, Actual, Test or Draft; drills and red-team runs are always Exercise. Example:
`/api/warnings/PWR-01/CVE-2026-104935/cap?langs=hi`.

**The guard.** `POST /api/sensor/cap` takes a raw CAP 1.2 body (`content-type: application/xml`; the optional
`x-odyssey-redteam` header labels an exercise). `CapGuard.ingest()` walks the ladder in this order and stops at the
first refusal:

1. `rate_limited`: more than 30 messages in 60 s from one source (`RATE_MAX`, `RATE_WINDOW_S`);
2. `oversize`: more than 2 MB (`MAX_XML_BYTES`);
3. `xxe`: any `<!DOCTYPE` or `<!ENTITY` anywhere in the body, refused before the parser sees it (`safe_parse`; CAP
   never carries a DTD, so nothing legitimate is lost; this covers external entities and billion laughs);
4. `malformed`: not well-formed, not a CAP `<alert>`, or an unexpected namespace;
5. `missing_fields`: identifier, sender and sent are required;
6. `untrusted_sender`: not on the allow-list (domains `ndma.gov.in`, `imd.gov.in`, `mausam.imd.gov.in`, `cwc.gov.in`,
   `incois.gov.in`, `cert-in.org.in`; prefixes `IMD-`, `CWC-`, `INCOIS-`, `SDMA-`, `NDMA`; our own `odyssey@ncew.local`);
   the real `IMD-Chennai` and `controlroom@ndma.gov.in` pass, `EVIL-Agency` does not;
7. `replay`: an identifier already accepted (the set is loaded from `cap_ingest` when the guard starts);
8. `stale`: `<expires>` in the past.

Then accepted. Every outcome is a row in `cap_ingest` (ts, accepted, reason, detail, identifier, sender, status,
msg_type, event, severity, areas, states, orgs, source_ip, redteam, bytes, and the first 4,000 characters of raw for
accepted rows only) and a ledger event `cap.ingest.accepted` or `cap.ingest.refused` (source CAP_INGEST, provenance
SIM when the red-team header is set, else REAL). An accepted alert gets its states and operators inferred the same way
as the feed. The response is `{accepted, reason, detail, identifier, sender, event, severity, states, orgs, redteam}`.

**Red-teaming the guard.** Done by a separate session, by the team lead's decision; nothing in the product fires hostile CAP. The guard is exercised by a separate red-team session against `POST /api/sensor/cap` (an `x-odyssey-redteam` header labels the exercise); the panel shows every decision as it happens. The in-session runner built at 08:30 was removed at 08:50.

**Endpoints.**

- `GET /api/sachet?live=true&limit=40`: `feed` (status, fetched_at, last_try, detail, ms, source, provenance, url,
  count, matched, by_state), `alerts`, `matched_alerts`, `inbound` (accepted rows), `decisions` (the last 30),
  `ingest` (accepted, refused by reason, total), `trusted`, `limits`, `how`, `endpoint`, `provenance`.
- `GET /api/sachet/alert?url=`: the full CAP of one SACHET alert (identifier, sender, sent, status, msgType, scope,
  references, expires, namespace, infos with areas, inferred states); 400 unless the host is `sachet.ndma.gov.in`.
- `POST /api/sensor/cap`: the guard.
- `GET /api/warnings/{org_id}/{cve_id}/cap?langs=&status=`: the writer.
- `GET /api/graph`: up to eight matched SACHET alerts as REAL `signal` nodes (`facts.signal = 'disaster'`, risk 35,
  tier Medium, an "on" edge to each operator in that state labelled "context, not a cyber signal") and up to ten
  accepted inbound CAP messages as `signal` nodes (`facts.signal = 'cap_inbound'`; SIM when the `x-odyssey-redteam` header marked an
  exercise). Replay (`as_of`) leaves out alerts published after the instant.

**Ledger kinds.** `cap.ingest.accepted`, `cap.ingest.refused`. **Table.** `cap_ingest`, created on
first use by `CapGuard.ensure()`.

**Measured on the live run (1 Nov 2026, about 08:50 IST).** The feed read fresh: 100 items, 99 with an inferred
state, 80 matched to operators; Andhra Pradesh SDMA dominated the hour. The red-team: 10 of 10 cases in 0.36 s against
the loopback endpoint, `planted_secret_leaked: false`.

**The demo arc** (`docs/PITCH.md`, 40 s after the brand and surface moment). Intel → Threats → *Disaster alerts
(SACHET)*: real alerts on our operators' states, REAL, each with the basis of its state; "weather or attack?"; the graph
draws the alert on the operator. The guard's live decisions sit beside it for the separate red-team session to drive. The Q&A line, when asked whether this is connected to SACHET: no; read-only public input in,
SACHET-compatible CAP out, routing through an authorised agency is theirs to decide.

**Honest limits.** SACHET is read-only, public-domain input; Odyssey's CAP is SACHET-compatible and not connected to
SACHET; no hostile traffic ever goes to NDMA or any third party; most SACHET alerts are district-level, so state
inference is explainable but not perfect and the basis and confidence are on every row; the feed's titles are often in
a regional language (Telugu, Bengali, Tamil) and are shown as published; the writer carries only sentences the local
translator validated; no language model is involved; Bhashini is deliberately left out (the plan's Connector B stays a
plan; local IndicTrans2 stays the translator).

**Verification (targets until the main thread runs them, one check at a time, never concurrently).**
`tests/test_sachet.py`: parse the RSS snapshot and match a state; parse the CAP sample; org match by state; XXE and
billion laughs refused without expanding the planted secret; oversize, forged sender, replay, stale and malformed
refused and the flood capped at the window maximum; `write_cap` round-trips through `safe_parse` with two languages,
severity mapped, namespace present; a script tag escaped, never emitted raw; every decision audited with the chain
intact (a temporary copy of the database, deltas not absolute counts). One flow in `scripts/e2e_check.py` (26 flows:
the feed read from the snapshot and matched, a legitimate CAP accepted and a forged one refused, a warning downloaded as CAP), one step in `scripts/ui_audit.py` (25 steps: the Disaster alerts (SACHET)
section opened and the guard panel read). Documents updated in this pass: `README.md`, `docs/PS_COVERAGE.md`,
`docs/PITCH.md`, `docs/TIP_GAP_AUDIT.md`, this file.
