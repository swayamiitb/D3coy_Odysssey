# Odyssey: national cyber threat early warning, on one laptop

Odyssey answers PS-01 of D3COY 1.0, the AI-Based National Cyber Threat Early Warning System. It watches public
threat intelligence and its own sensors, finds what threatens India's critical-infrastructure operators, and warns
each of them in its own language. It does the routine work on its own and asks a person before anything
consequential.

Everything runs locally on an RTX 4070 Laptop (8 GB VRAM), with **0 cloud calls**.

## What it does

| PS-01 objective | In Odyssey |
|---|---|
| Aggregate threat intelligence | 13 sources: NVD, CISA KEV, SSVC, EPSS, CISA advisories, SANS ISC DShield, Feodo Tracker, OpenPhish and MITRE ATT&CK (real), plus a national decoy grid, firewall logs and CERT-In-style advisories (simulated, labelled SIM). |
| AI-based threat analysis | A security-tuned LLM (MiST 8B) writes a fact-checked brief for every warning. It reads advisories with SecureBERT 2.0 and a prompt-injection guard, forecasts exploitation on day 0, and runs a Bayesian compromise model and three live detectors (surge, C2 beacon, IsolationForest flow anomaly). |
| Early warnings | Pre-disclosure surge warnings, day-0 forecasts, and immediate notices in 22 Indian languages. The autopilot acts every 5 seconds. |
| Risk prioritisation | `Risk = 100·R·K·(0.55·L + 0.30·S + 0.15·V)`, with version-verified exposure. An SSVC decision sets the tier and the CERT-In deadline. |
| Actionable recommendations | A named fixed release, owner and deadline per change ticket, and a national and per-organisation risk plan (the fewest changes that remove the most risk). Also: indicators to block, STIX export, and a pre-filled CERT-In report. |
| Dashboard | Six destinations, below. |

## The interface

- **Now:** what needs you right now. The incident card with its CERT-In clock, the map of India, what's next, and the decisions waiting for you.
- **Live:** the system running. The pipeline stage by stage, sensor streams with z-scores, detections and real-feed freshness. **Attack drills** let anyone inject a scan, an implant or a full intrusion and watch Odyssey catch it, with the time to detect.
- **SOC:** cases with owners, SLAs and playbooks; every warning; everything the autopilot did; and the laptop's live vital signs.
- **Intel:** what is under attack, where the exposure is (heatmaps), what will be exploited next, the risk plan, and advisories.
- **Organisations:** each operator's exposure, fixes, what outsiders see (OSINT), and its inbox in its own language.
- **Proof:** every claim measured on this laptop, each with its evidence, and a test bench you can re-run.

## Run it

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1   # Ollama, API :8000, translation :8010, dashboard :5173
```

Open http://127.0.0.1:5173. To rebuild the database from the offline feed snapshot, run `scripts\rebuild.ps1` (about 4 minutes). Then pre-compute the AI outputs a demo touches with `.venv\Scripts\python scripts\warm_cache.py`.

## Check it

| Check | Command | What it proves |
|---|---|---|
| Engine tests | `.venv\Scripts\python -m pytest -q` | 56 tests: exposure, scoring, the proactive layer, SOC, advisories, and the audit trail under concurrent writers. |
| Test bench | Proof → *Run them now* | 66 checks: 4 attack drills on a copy of the data, detectors with negative controls, the audit-trail chain, and the engine tests. |
| Product flows | `.venv\Scripts\python scripts\e2e_check.py` | 14 flows through the API on a private copy: approve and reject, a warning from issued to closed, a SOC case from new to closed, advisory analysis, three live drills, and the audit trail. |
| Interface | `python scripts\ui_audit.py` | A real browser clicks through every screen, sheet and button on another copy, and reports any page error, console error or failed request. |

## Honesty

- **Labels:** every fact is labelled REAL (public data) or SIM (simulated sensors, organisations and logs).
- **Live sensors:** the live decoy grid and firewall flows are SIM, accelerated so one 5-second tick is one sensor-hour.
- **Live feeds:** CISA KEV, Feodo Tracker and OpenPhish are re-read every 15 minutes when the network is up.
- **Audit trail:** every action is in a hash-chained trail; editing any past entry breaks the chain.

More detail:
- `docs/PS_COVERAGE.md`: objectives, mentor feedback, measured results and a five-minute walk-through.
- `docs/MODEL_CARD.md`: models, evaluations and the live detectors.
