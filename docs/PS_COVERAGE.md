# Odyssey against PS-01: what to look at, and the evidence

Every number below is measured on this laptop from public 2026 data or local test runs. SIM marks simulated
telemetry, which the UI labels everywhere. The **Proof** page recomputes these numbers live, and its test bench
re-runs the checks on demand.

## Key objectives

| PS-01 objective | What Odyssey does | Where to see it | Evidence |
|---|---|---|---|
| **Threat intelligence aggregation** | 13 sources (10 REAL, 3 SIM):<br>• vulnerability databases: NVD 2021–26, CISA KEV, FIRST EPSS, CISA SSVC<br>• public advisories: CISA ICS and alerts, CERT-In-style samples<br>• attack telemetry: SANS ISC DShield honeypots, national decoy grid (SIM)<br>• indicators: Feodo C2, OpenPhish<br>• security logs: firewall flows (SIM)<br>• MITRE ATT&CK | Intel → *Threats & sources* (each source shows its funnel) | 82,104 CVEs in 2026 → 2,277 name a constituency product → 354 Critical warnings. 30 latest CISA advisories → 8 touch the constituency. |
| **AI-based threat analysis** | • a security-tuned LLM (MiST 8B) explains warnings, reads advisories and answers analysts<br>• SecureBERT 2.0 extracts entities and relates threats<br>• classic ML predicts CWE and CVSS<br>• a day-0 exploitation forecast<br>• a Bayesian compromise model<br>• detectors for scanning surges and C2 beacons<br>• a prompt-injection guard | Proof → *How it works* · Intel → *Advisories* · **Ask Odyssey** (copilot) | • briefs: 22/23 pass the fact validator (19 on the first attempt); copilot answers are checked number by number<br>• CWE top-1: 77.5%<br>• injection guard: 5/5 hostile caught, 0/5 benign blocked<br>• beacon detector: 60 s implant found, 0 alerts on clean traffic |
| **Early warning generation** | • **Day-0 forecast:** before anyone exploits a new CVE, flags it as likely to be.<br>• **Pre-disclosure warnings:** from decoy-grid scanning surges.<br>• **Sentinel autopilot:** sends notices by severity, confidence and relevance. | Now → *Ahead of the threat* · Intel → *Threats & sources* · Proof | • **Forecast** (frozen 31 Jul; Aug–Oct out-of-time): flags 2.0% of new CVEs and catches **61.1%** of those CISA later lists. CVSS ≥ 9 at the same budget catches 16.7%.<br>• **Lead over CISA KEV**, on real signals alone: **4 CVEs, median 20.5 days, up to 42.4 days**. |
| **Risk prioritisation** | Risk = 100·R·K·(0.55·L + 0.30·S + 0.15·V):<br>• L = exploitability<br>• S = potential impact<br>• V = evidence (Admiralty-weighted)<br>• K = asset criticality, exposure and blast radius<br>• R = relevance (the installed version is checked against NVD, CNA and advisory text)<br>The tier comes from an SSVC decision path, deadlines from the CERT-In Blueprint, and the 6-hour clock from a Bayesian P(compromise). | Any warning → *Why this warning?* · Proof → *How it works* (live worked example) | KEV backtest: EPSS alone misses 49.1% of exploited CVEs and CVSS ≥ 9 alone misses 52.7%. Exposure check: 0 false "affected" on the real Ivanti case. |
| **Actionable recommendations** | Each warning gets:<br>• patch to a *named* fixed release (never a downgrade)<br>• block indicators (STIX 2.1 export)<br>• restrict interfaces<br>• hunt playbook; ATT&CK mitigations<br>Per organisation and nationally, a **risk plan**: the fewest changes that remove the most risk. | Intel → *Risk plan* (national) · Organisations → *Risk plan* · warning drawer · CERT-In report draft | 93 changes remove 50% of national risk and 205 remove 80% (344 tickets). 233 tickets carry a vendor fix target. |
| **Threat intelligence dashboard** | • active threats by technology<br>• warning pressure over time<br>• correlated campaigns<br>• real attack telemetry<br>• the analyst decision queue<br>• the autopilot log | **Intel → Overview** | Technology table: exposure, Critical/High warnings, exploited CVEs, forecast CVEs, campaign status and global attack trend per product. |

**Example use case (from the PS).** On Intel → Advisories, open the **real CISA ICS advisory "Siemens WinCC"**:
1. Odyssey identifies the product and parses the advisory's machine-readable version ranges (`vers:intdot/<8.0.0.11`, `vers:all/*`).
2. It matches 13 WinCC assets at 7 power and other operators.
3. It assigns risk and recommends patching, or mitigation where no fix exists.
4. It **proposes** notices to each organisation in its own language.
5. An analyst approves them.

## Expected deliverables

- **Functional prototype:** runs fully offline on an RTX 4070 laptop, with 0 cloud calls.
- **Dashboard of detected threats, risk levels and alerts:** Now, Intel (Overview, Threats & sources, Risk plan, All warnings) and Organisations.
- **Demonstration on public threat intelligence plus a controlled simulated dataset:**
  - REAL: CVEs, KEV, SSVC, EPSS, advisories, DShield, Feodo and phishing.
  - SIM: decoy grid, firewall logs and organisations.
  - Every item is labelled.
- **Explanation of the AI model, threat scoring and mitigation workflow:** **Proof → How it works** (pipeline, model roster with measured results, scoring with a live example, three-lane workflow), `docs/MODEL_CARD.md`, and this file.

## Mentor feedback, round 1 → what changed

| Feedback | Response |
|---|---|
| Make the system **proactive** (judge) | Odyssey now acts without being asked:<br>• day-0 exploitation forecast<br>• pre-disclosure surge warnings, with confirmation or stand-down<br>• autopilot notices in the organisation's language and daily digests<br>• SLA watch<br>• peer hunt on compromise<br>• CERT-In report pre-drafted<br>286 automatic actions since go-live (227 more proposed for a human); every one is in the hash-chained audit trail. |
| TI aggregation, dashboard, SOC, **real tests and attacks** | • Intel view and aggregation table<br>• real global attack telemetry (DShield) next to the SIM decoy grid<br>• a **test bench** that runs on demand: 57 checks (51 engine tests, 5 detection checks with negative controls, 1 audit-trail check)<br>• real exploited CVEs and real CISA advisories end to end |
| AI-based threat analysis | Analyst copilot. The model picks one read-only query; entities are resolved deterministically; every answer cites facts and is withheld if unverifiable. Answers can be delivered in 22 languages. |
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
- **Copilot routing:** the tool choice is made by an 8B model. Entity resolution is deterministic; unusual phrasings can still pick a broader tool.

## Five-minute walk-through

1. **Now.** The Ivanti compromise at Vidyut Grid has a 6-hour CERT-In clock. Click *Why this warning?* to see the decision model, the replay (warned 12 days before disclosure), the brief in Marathi, and the CERT-In draft.
2. **Now → Needs your decision.** Approve one proposal; the notices go out in each organisation's language. *Ahead of the threat* shows CVEs flagged on day 0 that CISA confirmed days later.
3. **Intel → Overview.** Press *Replay since go-live* to watch three months of Odyssey acting on its own, then see threats by technology.
4. **Intel → Risk plan.** The fewest changes that remove the most national risk.
5. **Organisations → Vidyut Grid West Corp.** Overview, Risk plan, OSINT, and its Marathi inbox.
6. **Intel → Advisories.** The real CISA WinCC advisory, analysed live: 13 assets at 7 organisations, version ranges parsed, indicators separated from vendor links, and a notification proposal.
7. **Ask Odyssey** (search bar). "Which power-sector organisations face known-exploited issues?"
8. **Proof.** Run the test bench, read the forecast backtest and lead over KEV, then *How it works*.

The interface is light (Uber-style) by default; the moon icon switches to dark.
