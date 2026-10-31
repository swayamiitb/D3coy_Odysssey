# Odyssey against PS-01: what to look at, and the evidence

Every number below is measured on this laptop from public 2026 data or local test runs. SIM marks simulated
telemetry, which the UI labels everywhere. The **Proof** page recomputes these numbers live, and its test bench
re-runs the checks on demand. `scripts/e2e_check.py` drives every screen and every button through the API on a
private copy of the database (14 flows: approve and reject, a warning from issued to closed, a SOC case from new to
closed, a pasted advisory, three live attack drills, the audit trail); `scripts/ui_audit.py` clicks through the
whole interface in a real browser on another copy, so the product is checked end to end, not just the engine.

## Key objectives

| PS-01 objective | What Odyssey does | Where to see it | Evidence |
|---|---|---|---|
| **Threat intelligence aggregation** | 13 sources (10 REAL, 3 SIM):<br>• vulnerability databases: NVD 2021–26, CISA KEV, FIRST EPSS, CISA SSVC<br>• public advisories: CISA ICS and alerts, CERT-In-style samples<br>• attack telemetry: SANS ISC DShield honeypots, national decoy grid (SIM)<br>• indicators: Feodo C2, OpenPhish<br>• security logs: firewall flows (SIM)<br>• MITRE ATT&CK | Intel → *Threats* → *Intelligence sources* (each source shows its funnel) | 82,104 CVEs in 2026 → 2,277 name a constituency product → 354 Critical warnings. 30 latest CISA advisories → 8 touch the constituency. |
| **AI-based threat analysis** | • a security-tuned LLM (MiST 8B) explains every warning and reads advisories<br>• SecureBERT 2.0 extracts entities and relates threats<br>• classic ML predicts CWE and CVSS<br>• a day-0 exploitation forecast<br>• a Bayesian compromise model<br>• detectors for scanning surges and C2 beacons<br>• a prompt-injection guard | Proof → *How it works* · Intel → *Advisories* · **Live** (detectors at work) | • briefs: 22/23 pass the fact validator (19 on the first attempt)<br>• CWE top-1: 77.5%<br>• injection guard: 5/5 hostile caught, 0/5 benign blocked<br>• beacon detector: 60 s implant found, 0 alerts on clean traffic |
| **Early warning generation** | • **Day-0 forecast:** before anyone exploits a new CVE, flags it as likely to be.<br>• **Pre-disclosure warnings:** from decoy-grid scanning surges.<br>• **Sentinel autopilot:** sends notices by severity, confidence and relevance. | Now → *Ahead of the threat* · Intel → *Overview* and *Threats* · Proof | • **Forecast** (frozen 31 Jul; Aug–Oct out-of-time): flags 2.0% of new CVEs and catches **61.1%** of those CISA later lists. CVSS ≥ 9 at the same budget catches 16.7%.<br>• **Lead over CISA KEV**, on real signals alone: **4 CVEs, median 20.5 days, up to 42.4 days**. |
| **Risk prioritisation** | Risk = 100·R·K·(0.55·L + 0.30·S + 0.15·V):<br>• L = exploitability<br>• S = potential impact<br>• V = evidence (Admiralty-weighted)<br>• K = asset criticality, exposure and blast radius<br>• R = relevance (the installed version is checked against NVD, CNA and advisory text)<br>The tier comes from an SSVC decision path, deadlines from the CERT-In Blueprint, and the 6-hour clock from a Bayesian P(compromise). | Any warning → *Why this warning?* · Proof → *How it works* (live worked example) | KEV backtest: EPSS alone misses 49.1% of exploited CVEs and CVSS ≥ 9 alone misses 52.7%. Exposure check: 0 false "affected" on the real Ivanti case. |
| **Actionable recommendations** | Each warning gets:<br>• patch to a *named* fixed release (never a downgrade)<br>• block indicators (STIX 2.1 export)<br>• restrict interfaces<br>• hunt playbook; ATT&CK mitigations<br>Per organisation and nationally, a **risk plan**: the fewest changes that remove the most risk. | Intel → *Risk plan* (national) · Organisations → *Risk plan* · warning drawer · CERT-In report draft | 93 changes remove 50% of national risk and 205 remove 80% (344 tickets). 233 tickets carry a vendor fix target. |
| **Threat intelligence dashboard** | • active threats by technology<br>• heatmaps: critical exposure by technology × sector, real attacks by port × day, decoy sessions by product × day, autopilot actions by type × day, notices per organisation<br>• warning pressure over time, with replay<br>• correlated campaigns<br>• the analyst decision queue and the autopilot log | **Intel → Overview** and *Threats* · **SOC → Overview** | Technology rows: exposure, Critical warnings, exploited CVEs, forecast CVEs, campaign status. Each page shows four live figures in its header. |

**Example use case (from the PS).** On Intel → Advisories, open the **real CISA ICS advisory "Siemens WinCC"**:
1. Odyssey identifies the product and parses the advisory's machine-readable version ranges (`vers:intdot/<8.0.0.11`, `vers:all/*`).
2. It matches 13 WinCC assets at 7 power and other operators.
3. It assigns risk and recommends patching, or mitigation where no fix exists.
4. It **proposes** notices to each organisation in its own language.
5. An analyst approves them.

## Expected deliverables

- **Functional prototype:** runs fully offline on an RTX 4070 laptop, with 0 cloud calls.
- **Dashboard of detected threats, risk levels and alerts:** Now, SOC (Overview, Cases, Warnings, Log, System), Intel (Overview, Threats, Risk plan, Advisories) and Organisations.
- **Demonstration on public threat intelligence plus a controlled simulated dataset:**
  - REAL: CVEs, KEV, SSVC, EPSS, advisories, DShield, Feodo and phishing.
  - SIM: decoy grid, firewall logs and organisations.
  - Every item is labelled.
- **Explanation of the AI model, threat scoring and mitigation workflow:** **Proof → How it works** (pipeline, model roster with measured results, scoring with a live example, three-lane workflow), `docs/MODEL_CARD.md`, and this file.

## Mentor feedback, round 1 → what changed

| Feedback | Response |
|---|---|
| Make the system **proactive** (judge) | Odyssey runs continuously (**Live**): sensors, detectors and the autopilot every 5 s, real feeds (CISA KEV, Feodo, OpenPhish) re-checked every 15 min. It acts without being asked:<br>• day-0 exploitation forecast<br>• pre-disclosure surge warnings, with confirmation or stand-down<br>• autopilot notices in the organisation's language and daily digests<br>• SLA watch<br>• peer hunt on compromise<br>• CERT-In report pre-drafted<br>286 automatic actions since go-live (227 more proposed for a human); every one is in the hash-chained audit trail. |
| TI aggregation, dashboard, **SOC**, **real tests and attacks** | • **SOC destination:** cases opened automatically (one incident per compromised asset, one remediation case per organisation × product × version for known-exploited Critical exposure), owners by rule, SLA clocks from CERT-In timelines, playbook checklists, notes, MTTA / MTTR / SLA measured from analysts' recorded actions, one-click shift handover<br>• **System telemetry**, live every 3 s: CPU, GPU, VRAM, memory, the models resident on the GPU, every AI job timed and checked, API latency per route, audit-trail growth, build stages<br>• Intel view and aggregation, real global attack telemetry (DShield) next to the SIM decoy grid<br>• a **test bench** that runs on demand: 66 checks (56 engine tests, 4 attack drills on a copy of the data, 5 detection checks with negative controls, 1 audit-trail check)<br>• **attack drills** on the Live page (mass scanning, implant beacon, full intrusion) that anyone can start; the test bench runs the same drills on a copy of the data<br>• `scripts/e2e_check.py` (14 product flows through the API) and `scripts/ui_audit.py` (17 click-through steps in a real browser) |
| AI-based threat analysis | Built into every screen rather than a chat box: a validated AI brief on every warning (in the organisation's language), advisory analysis against the inventory, the day-0 exploitation forecast, the Bayesian compromise model, and three live detectors (surge, C2 beacon, IsolationForest flow anomaly) running every 5 seconds. |
| Early warning and **organisation-based OSINT** | Organisations → OSINT and Inbox tabs, per organisation:<br>• internet-facing services<br>• global attack activity on its ports<br>• C2 indicators in its traffic<br>• look-alike domains in live phishing feeds<br>• real advisories naming its products<br>• everything Odyssey sent it |
| **Risk minimisation and mitigation → risk management** | Risk plan:<br>• change tickets per (organisation, product, version)<br>• ordered by urgency, then by risk removed per unit of effort<br>• burn-down curve<br>• named fix targets and owners |
| Actionable intelligence and recommendations | Named fixed release, owner and deadline per ticket; block and hunt steps; STIX export; CERT-In report draft. |
| **Human in the loop** | Graduated autonomy:<br>• **Run on their own:** evidence-based notices, digests and hunts.<br>• **Proposed for an analyst:** predictions, sensor-only warnings, regulator escalations and new-advisory notices.<br>• **Approve:** sends.<br>• **Reject:** records the reason for calibration.<br>• **History:** approvals before the live window come from a *simulated* duty officer, labelled SIM. |

## Honest limitations

- **Forecast precision is low (5%)**, because exploitation is rare (base rate 0.16%). That is why forecasts are proposals for a human, never automatic notices.
- **Lead time comes from two sources:**
  - REAL signals: CISA SSVC, vendor "exploited" text, and the forecast.
  - SIM decoy telemetry: the decoy grid.

  The Proof page attributes each lead to one of them. Leads that exist only because monitoring started on 1 Aug are reported apart.
- **Translation:** 127/132 sentences validated across 22 languages. Santali (3/6) is weakest; withheld lines fall back to English.
- **DShield trends:** they show no elevated attack activity on our service ports this week. We report that as measured.
- **Deadlines run in real time from the build:** the incident's CERT-In 6-hour clock starts when the database is built, so `scripts\demo_reset.ps1` is run shortly before each demo.
- **Live sensors are simulated:** the decoy grid and firewall flows in the Live view are SIM (labelled, accelerated: one 5-second tick is one sensor-hour); the three real feeds it re-checks (CISA KEV, Feodo, OpenPhish) are live and public.

## Five-minute walk-through

1. **Now.** "A suspected compromise needs you now": the Ivanti compromise at Vidyut Grid, with its 6-hour CERT-In clock on the trip card. *Why this warning?* opens the decision model, the replay (warned 12 days before disclosure), the brief in Marathi and the CERT-In draft.
2. **Now → Needs your decision.** Approve one proposal; the notices go out in each organisation's language. The black *Odyssey at work* band shows what it did on its own.
3. **SOC → Cases.** CASE-0001, the incident: *Start response*, tick the first playbook steps, add a note. The header figures (open cases, SLA, decisions, MTTA) update from what you did.
4. **SOC → Overview.** The autopilot heatmap; *Replay the last 90 days*; *Write the shift handover*. **SOC → System** shows the laptop's live vital signs and every AI job timed.
5. **Intel → Overview.** What is under attack, where the critical exposure is (heatmap), and what is likely to be exploited next. **Intel → Risk plan:** the fewest changes that remove the most national risk.
6. **Intel → Advisories.** The real CISA WinCC advisory, analysed live: 13 assets at 7 organisations, version ranges parsed, indicators separated from vendor links, and a notification proposal.
7. **Organisations → Vidyut Grid West Corp.** Overview, Risk plan, What outsiders see (OSINT), and its Marathi inbox.
8. **Live → Run an attack drill → Full intrusion.** Watch scanning, the implant and lateral movement get caught in order (about 30 s), the incident case open in SOC, and the regulator report wait in *Needs your decision*.
9. **Proof.** Each card is one claim with its evidence a click away; *Run them now* re-runs the test bench.

The interface follows Uber's website: black bands (navigation, page header, footer) around a white body, one question
per page, and details in sheets that slide in from the right.
