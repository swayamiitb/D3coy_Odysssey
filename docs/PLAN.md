# Master Plan — D3COY 1.0 · PS 01

> **Status:** skeleton. This gets filled in after research, through the master-plan brief, and the team lead's task split.

## Timeline (deadline Sun 1 Nov 12:00 IST)

| Clock | Phase |
|---|---|
| Sat 14:30 – 16:30 | Research → master plan → contracts → task split (team lead) |
| Sat 16:30 – 21:00 | Each part builds its thin slice against mock contracts |
| **Sat 21:00** | **Merge window 1:** thin slice running end to end |
| Sat 21:00 – Sun 02:00 | Core features |
| **Sun 02:00** | **Merge window 2** |
| Sun 02:00 – 06:00 | Features + integration |
| **Sun 06:00** | **Merge window 3**; PPT starts (one person) |
| Sun 06:00 – 09:00 | Polish, demo mode, rehearsal #1 |
| **Sun 09:00** | **Feature freeze:** fixes, polish, rehearsals #2–#3 only |
| **Sun 11:00** | **Code freeze:** tag `demo-final` |
| **Sun 12:00** | **Submit** |

## Parts & owners (team lead assigns)

| Part | Folder | Owner |
|---|---|---|
| Data collection + backend API | `ingestion/` | TBD |
| AI analysis + risk scoring | `ai_engine/` | TBD |
| Frontend dashboard | `dashboard/` | TBD |
| Shared contracts | `shared/contracts/` | Team lead |

## Thin slice (MVP)

One CVE → matched to a simulated asset → risk score with breakdown → AI explanation + mitigation → shown on the dashboard.

## Task board

| ID | Task | Part | Owner | Timebox | Status |
|---|---|---|---|---|---|

## PS objective traceability (rule 16)

Every page and tab names the objective it serves in its header (a numbered pill, `frontend/src/ui.tsx` OBJECTIVES,
`App.tsx` OBJ); the footer lists the seven and jumps to each. Checked Sun 1 Nov 2026 11:20 IST.

| PS objective / deliverable | Feature(s) | Status |
|---|---|---|
| 1 Threat intelligence aggregation | Intel › Overview (the aggregation table: 13 sources, 10 REAL; real-feed strips: blocklist.de, Exploit-DB, ransomware.live, HIBP, CISA ICS, GitHub advisories, Tor, Spamhaus DROP, Emerging Threats), Live › Real feeds (NVD, CISA KEV, Feodo, OpenPhish, SANS ISC DShield, CISA advisories, NDMA SACHET re-read live and written through to the snapshot), Intel › Indicators (import, TAXII) | Built |
| 2 AI-based threat analysis | The AI brief on every warning (What to do), Intel › Advisories (advisory analysis with SecureBERT NER and the injection guard), Intel › Graph (relationships between threats), Intel › Threats (campaigns, ATT&CK), day-0 exploitation forecast, Bayesian compromise model, live detectors | Built |
| 3 Early warning generation | Now (the duty desk), Live (NVD intake, detections, drills, the satellite threat map), SOC › Warnings, SOC › Log (the autopilot's actions), warning sheet › How it unfolded | Built |
| 4 Risk prioritisation | Warning sheet › Why this score (Risk = 100·R·K·(0.55L+0.30S+0.15V), SSVC, evidence), SOC › Warnings (ranked), Intel › Risk plan, Organisations | Built |
| 5 Actionable recommendations | Warning sheet › What to do (named fixed release, block, hunt, CERT-In draft), SOC › Cases (playbooks), Intel › Risk plan (change tickets), Organisations (fixes, notices in the operator's language) | Built |
| 6 Threat intelligence dashboard | Now, SOC › Overview, Intel › Overview, Organisations, Live | Built |
| D Explanation of AI model, scoring, mitigation workflow | Proof › How it works, Proof › Evidence (scorecard, test bench), `docs/MODEL_CARD.md`, `docs/PS_COVERAGE.md` | Built |

## Demo story

TBD.
