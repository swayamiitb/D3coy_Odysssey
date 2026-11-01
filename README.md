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
| Protect & red-team a real app | An **HTTP shield** (inline WAF/IDS) protects a *real* connected web application through a drop-in agent (ASGI/WSGI/Express, or an access-log tailer). It detects SQLi, XSS, path traversal, command injection, SSTI/SSRF/Log4Shell, scanning and brute force, blocks them inline in block mode, and can be proved by a built-in **red-team** that fires real attacks at the app over the wire (loopback/private only) and measures detection rate, block rate, precision and time-to-detect. |
| Early warnings | Pre-disclosure surge warnings, day-0 forecasts, and immediate notices in 22 Indian languages. The autopilot acts every 5 seconds. |
| Risk prioritisation | `Risk = 100·R·K·(0.55·L + 0.30·S + 0.15·V)`, with version-verified exposure. An SSVC decision sets the tier and the CERT-In deadline. |
| Actionable recommendations | A named fixed release, owner and deadline per change ticket, and a national and per-organisation risk plan (the fewest changes that remove the most risk). Also: indicators to block, STIX export, and a pre-filled CERT-In report. |
| Dashboard | Six destinations, below. |

## The interface

- **Now:** what needs you right now. The incident card with its CERT-In clock, the map of India, what's next, and the decisions waiting for you.
- **Live:** the system running. The pipeline stage by stage, sensor streams with z-scores, detections, real-feed freshness, and **real CVEs taken in from NVD** as they appear (matched to installed versions, forecast and acted on within seconds). **Attack drills** let anyone inject a scan, an implant, a full intrusion or a newly published CVE and watch Odyssey respond, with the time to detect.
- **SOC:** cases with owners, SLAs and playbooks; the decision queue; every warning; everything the autopilot did; **adaptive detectors** (thresholds re-derived every minute from analysts' decisions, shown with their reasons); and the laptop's live vital signs.
- **Intel:** what is under attack, where the exposure is (heatmaps), what will be exploited next, the risk plan, advisories, and a one-click **national situation report** (Markdown, for CERT-In, NCIIPC and the sector CSIRTs).
- **Organisations:** each operator's **threat map** (the national picture cut down to one organisation: attack pressure on its ports, decoy-grid scanning of its products, exploited CVEs, implants calling out, phishing look-alikes, suppliers and blast radius, laid out from the internet-facing perimeter to the crown jewels, with provenance on every line), its exposure, fixes, what outsiders see (OSINT), and its inbox in its own language.
- **Proof:** every claim measured on this laptop, each with its evidence, and a test bench you can re-run.

## Run it

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1   # Ollama, API :8000, translation :8010, dashboard :5173
```

Open http://127.0.0.1:5173. `start_all.ps1` also launches the protected demo app (CityPower portal, :8080) behind the HTTP shield; set `ODYSSEY_TARGET=0` to skip it. To protect your own app instead, drop in an agent from `agent/` (see `agent/README.md`).

**Before a demo, run `scripts\demo_reset.ps1` (about 5 minutes).** It rebuilds the database from the offline feed snapshot, restarts the API and pre-computes what the demo touches. The CERT-In 6-hour clock on the incident starts at build time, so a build from the night before shows that deadline as overdue.

## Check it

| Check | Command | What it proves |
|---|---|---|
| Engine tests | `.venv\Scripts\python -m pytest -q` | 98 tests: exposure, scoring, the proactive layer, SOC, advisories, the audit trail under concurrent writers, and the HTTP shield (signature engine on encoded/evaded payloads, block list, red-team safety). |
| HTTP shield red-team | Live → *Red-team the shield* → *Run all attacks* (or `POST /api/redteam/run`) | Fires real SQLi/XSS/traversal/cmdi/SSTI/SSRF/Log4Shell/scanning/brute-force requests at the protected app over the wire and measures detection rate, block rate, precision and time-to-detect. Loopback/private targets only. |
| Test bench | Proof → *Run them now* | 109 checks: 5 attack drills on a copy of the data, detectors with negative controls, the audit-trail chain, and the engine tests. |
| Product flows | `.venv\Scripts\python scripts\e2e_check.py` | 16 flows through the API on a private copy: approve and reject, a warning from issued to closed, a SOC case from new to closed, advisory analysis, three live drills, and the audit trail. |
| Interface | `python scripts\ui_audit.py` | A real browser clicks through every screen, sheet and button on another copy, and reports any page error, console error or failed request. |

## Honesty

- **Labels:** every fact is labelled REAL (public data) or SIM (simulated sensors, organisations and logs).
- **Live sensors:** the live decoy grid and firewall flows are SIM, accelerated so one 5-second tick is one sensor-hour.
- **Live feeds:** NVD (new CVEs), CISA KEV, Feodo Tracker and OpenPhish are re-read every 15 minutes when the network is up; new CVEs that name a product we run are taken in at once.
- **HTTP shield:** it inspects real HTTP requests from the connected app; the bundled target and the red-team are a local lab (the runner only ever attacks loopback/private addresses), and every red-team request is labelled as an exercise in the audit trail.
- **Audit trail:** every action is in a hash-chained trail; editing any past entry breaks the chain.

More detail:
- `docs/PS_COVERAGE.md`: objectives, mentor feedback, measured results and a five-minute walk-through.
- `docs/MODEL_CARD.md`: models, evaluations and the live detectors.
- `docs/PITCH.md`: the demo script and the judges' questions with honest answers.

## Landing page and team notes

The site opens on our scroll-story landing (`frontend/src/landing/`): real botnet command servers on a 3D globe, a dive
into India's operators, the evidence arc, then the globe unrolls into a flat world where real attack origins fly in.
"Open the console" goes to the Odyssey console above (`/?view=now`). Team rulebook: [CLAUDE.md](CLAUDE.md); decisions:
[docs/DECISIONS.md](docs/DECISIONS.md); plan: [docs/PLAN.md](docs/PLAN.md).

The console wears an Uber black-and-white theme with SOC accents (`frontend/src/index.css`, `html.soc`): a white body
with black bands, red only for threat. The moon button in the top bar switches the whole console to the night-shift
(all black) look, remembered per browser. `Ctrl`/`⌘ K` opens a search over pages, operators, open warnings and
technologies. The left rail on wide screens expands to the sections of each destination. On Now, "Threat activity" is
a real 2D map (world-atlas + d3-geo; India drawn from @svg-maps/india so no contested border is drawn): hover an origin
in the list to see its attack arcs; click an Indian state to open a 3D site view of its government agencies, with
labelled buildings and the attacks coming in. The operators, buildings and arc landing points are simulated (SIM); the
attack origins (SANS ISC DShield, abuse.ch Feodo Tracker), CVEs, KEV and EPSS are real. More real, open feeds are bundled by
`frontend/scripts/landing-attackers.mjs`, `real-feeds.mjs` and `real-feeds-2.mjs` (run them with the network up to refresh):
DShield's top 2,000 attacking IPs located by RIPEstat, blocklist.de attacks by service, the Exploit-DB index, ransomware.live
victims in India, Have I Been Pwned breaches, CISA ICS advisories, GitHub critical advisories, Tor exits, Spamhaus DROP and
Emerging Threats compromised hosts. They appear on Intel (Real-world threat intelligence, Attacks by service) and as the
"exploit public" mark on warnings.
