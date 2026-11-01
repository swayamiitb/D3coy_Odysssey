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
| Protect & red-team a real app | An **HTTP shield** (inline WAF/IDS) protects a *real* connected web application through a drop-in agent (ASGI/WSGI/Express), a reverse proxy for any stack you cannot modify, or an access-log tailer. It detects SQLi, XSS, path traversal, command injection, SSTI/SSRF/Log4Shell, scanning and brute force, blocks them inline in block mode, and can be proved by a built-in **red-team** that fires real attacks at the app over the wire (loopback/private only) and measures detection rate, block rate, precision and time-to-detect. |
| Deliver alerts to your apps | What Odyssey decides reaches the apps a team already uses, as one card per alert: **Slack, Discord, Microsoft Teams, e-mail (SMTP) or any webhook** (your own dashboard, a Jira/Trello automation), fed by a tap on the audit trail with a severity floor, de-duplication and a per-minute cap. The lab ships an **Ops Console** destination (:8090) so the whole loop runs with no external account; the same card reaches a real channel the moment its URL is configured. Every delivery is audited. |
| One connected picture, for exchange | An **intelligence graph** of every entity Odyssey knows about (organisations, assets, technologies, CVEs, campaigns, ATT&CK techniques, malware families, threat groups, indicators, suppliers, live signals) and how they connect, read from the record every 5 seconds with provenance on every edge; nodes **breathe** with fresh evidence and lie still as it ages; threat groups are overlap with the ATT&CK record, never attribution; an evidence card per entity. **Risk lists** (CSV / JSON: vulnerabilities, addresses, domains, technologies, each row scored and sourced) for a SIEM, firewall or EDR, and the whole graph as a **STIX 2.1 bundle**. |
| Watch what matters | **Watchlists and alert rules** on any graph entity (a technology, a CVE, a C2 address, a threat group, an organisation, an asset): fresh evidence, a worsening tier, a new connection, or any of those. Rules are edge-triggered and evaluated by the live engine every 15 s; a firing is a `watch.fired` event in the audit trail, a detection on Live, a node in the graph and a card through the channels. |
| Take indicators in, give them back | **Bulk indicator import**: paste any text, CSV or STIX 2.1 bundle; IPv4 addresses, domains, URLs, hashes and CVE ids are matched in seconds against the firewall flows, C2 sightings, the shield's attackers, the constituency's own addresses, domains and their look-alikes, and the exposure record, and enriched from Feodo Tracker, DShield, OpenPhish and CISA KEV. From then on the live engine matches new flows against the imported addresses on every tick. Out again as CSV, STIX, or a read-only **TAXII 2.1** server (collections `graph`, `indicators`, `vulnerabilities`) for platforms that pull. |
| Brand and social watch | Passive monitoring of public sources for a brand term or an organisation: crt.sh certificate transparency (look-alike certificates), URLhaus and OpenPhish (malicious and phishing URLs naming the brand), Google News, Hacker News and Reddit (mentions). Each hit is scored 0 to 100 by explicit rules; a hit at 70 or above is a `brand.hit` event and a node in the graph. Nothing touches the organisation or the sites found. |
| Attack surface, with consent | A posture check of a system the operator **owns**: loopback or private addresses, or an app the Odyssey agent has announced; anything else is refused with the reason. GET and HEAD only, at most 40 requests: transport, security headers, cookies, exposed files and admin paths, a framework fingerprint (mapped to product keys and so to known CVEs), reachable service ports. A score and a grade A to F; each finding with a CWE, the evidence and a fix. The demo portal scores 29, grade F. |
| Paired with India's SACHET | Odyssey reads NDMA's public-domain **SACHET** CAP 1.2 feed (disaster alerts from IMD, the SDMAs, CWC and INCOIS) every 15 minutes, read-only and snapshot-backed, infers the state each alert concerns with a stated basis (sender office, state name, district name, script of the text) and a confidence, and matches it to the operators in that state: "is this outage the weather, or an attack?" Its own warnings leave as **SACHET-compatible CAP 1.2** (one `<info>` per validated language, status Exercise), never as SACHET messages. Inbound CAP at `POST /api/sensor/cap` is hostile until proven otherwise: an eight-step guard (flood, size, any DTD or entity refused before parsing, well-formed, required fields, authorised sender, replay, expiry), every decision in the audit trail. The guard is exercised by a separate red-team session against `POST /api/sensor/cap` (an `x-odyssey-redteam` header labels the exercise); the panel shows every decision as it happens. |
| Early warnings | Pre-disclosure surge warnings, day-0 forecasts, and immediate notices in 22 Indian languages. The autopilot acts every 5 seconds. |
| Risk prioritisation | `Risk = 100·R·K·(0.55·L + 0.30·S + 0.15·V)`, with version-verified exposure. An SSVC decision sets the tier and the CERT-In deadline. |
| Actionable recommendations | A named fixed release, owner and deadline per change ticket, and a national and per-organisation risk plan (the fewest changes that remove the most risk). Also: indicators to block, STIX export, and a pre-filled CERT-In report. |
| Dashboard | Six destinations, below. |

## The interface

- **Now:** what needs you right now. The incident card with its CERT-In clock, the map of India, what's next, and the decisions waiting for you.
- **Live:** the system running. The pipeline stage by stage, sensor streams with z-scores, detections, real-feed freshness, and **real CVEs taken in from NVD** as they appear (matched to installed versions, forecast and acted on within seconds). **Attack drills** let anyone inject a scan, an implant, a full intrusion or a newly published CVE and watch Odyssey respond, with the time to detect.
- **SOC:** cases with owners, SLAs and playbooks; the decision queue; every warning; everything the autopilot did; **adaptive detectors** (thresholds re-derived every minute from analysts' decisions, shown with their reasons); and the laptop's live vital signs.
- **Intel:** what is under attack, where the exposure is (heatmaps), what will be exploited next, the risk plan, advisories, a one-click **national situation report** (Markdown, for CERT-In, NCIIPC and the sector CSIRTs), **risk lists and STIX** to export, and the **intelligence graph**: every entity and how they connect, breathing with fresh evidence, national or one organisation in focus, hover for the record, click for the evidence card, **Watch** on every card and a **Watchlist** of the rules you set, and a **replay** slider that shows the record as it stood at nine earlier instants. **Indicators**: paste a partner's list (text, CSV or STIX), see what matched and where, what is held, and the CSV, STIX and TAXII ways out. Under *Threats*, **Brand and social watch** (passive public sources, scored), **Attack surface, with consent** (a posture check of a system you own, graded A to F) and **Disaster alerts (SACHET)**: NDMA's public CAP feed on the operators' states, labelled REAL, each row with the basis and confidence of its state inference, the inbound CAP decisions and their refusal reasons, *Run the CAP red-team*, and a warning downloadable as SACHET-compatible CAP; a tile on Now points to it.
- **Organisations:** each operator's **threat map** (the national picture cut down to one organisation: attack pressure on its ports, decoy-grid scanning of its products, exploited CVEs, implants calling out, phishing look-alikes, suppliers and blast radius, laid out from the internet-facing perimeter to the crown jewels, with provenance on every line), its exposure, fixes, what outsiders see (OSINT, with the brand and social watch for that organisation), and its inbox in its own language.
- **Proof:** every claim measured on this laptop, each with its evidence, and a test bench you can re-run.

## Run it

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1   # Ollama, API :8000, translation :8010, dashboard :5173
```

Open http://127.0.0.1:5173. `start_all.ps1` also launches the protected demo app (CityPower portal, :8080) behind the HTTP shield, and the Ops Console (:8090) where the alerts land; set `ODYSSEY_TARGET=0` / `ODYSSEY_CONSOLE=0` to skip them. To protect your own app, drop in an agent from `agent/`; to route alerts to your Slack, Discord, Teams or e-mail, see `agent/README.md`.

**Before a demo, run `scripts\demo_reset.ps1` (about 5 minutes).** It rebuilds the database from the offline feed snapshot, restarts the API and pre-computes what the demo touches. The CERT-In 6-hour clock on the incident starts at build time, so a build from the night before shows that deadline as overdue.

## Check it

| Check | Command | What it proves |
|---|---|---|
| Engine tests | `.venv\Scripts\python -m pytest -q` | About 140 tests (the target; 124 verified at the graph commit, plus 8 for brand monitoring and the attack-surface gate, plus the watchlist, indicator and TAXII tests, plus the SACHET tests; the main thread verifies the count): exposure, scoring, the proactive layer, SOC, advisories, the intelligence graph (a consistent subset of the record, pulse as evidence age, deterministic layout, one organisation in focus, entity cards, risk lists, a STIX bundle with no dangling reference), watchlists (edge-triggered rules that fire once per change and land in the ledger), indicator import (text, CSV and STIX in; matches against our own record; CSV and STIX out), the TAXII server, brand monitoring (scoring, no duplicates on a second scan, offline sources do not fail a scan), the attack-surface gate (refuses what is not ours) and scan, the SACHET connector (the real feed snapshot parsed and matched to operators by state, XXE and billion laughs refused without expanding a planted secret, forged sender, replay, stale, oversize, malformed and flood refused, the CAP writer round-tripping through the parser with two languages, a script tag escaped, every decision audited), the audit trail under concurrent writers, the HTTP shield (signature engine on encoded/evaded payloads, block list, a registration that survives an API restart, the reverse-proxy agent, red-team safety) and the channels (one card per event in five shapes, the severity floor, de-duplication, the per-minute cap, back-off, audited deliveries). |
| HTTP shield red-team | Live → *Red-team the shield* → *Run all attacks* (or `POST /api/redteam/run`) | Fires real SQLi/XSS/traversal/cmdi/SSTI/SSRF/Log4Shell/scanning/brute-force requests at the protected app over the wire and measures detection rate, block rate, precision and time-to-detect. Loopback/private targets only. |
| Test bench | Proof → *Run them now* | 135 checks: 5 attack drills on a copy of the data, detectors with negative controls, the audit-trail chain, and the engine tests. |
| Product flows | `.venv\Scripts\python scripts\e2e_check.py` | 26 flows through the API on a private copy (the target; 19 verified at the graph commit, six added for today's services and one for the SACHET connector; the main thread verifies them): approve and reject, a warning from issued to closed, a SOC case from new to closed, advisory analysis, the intelligence graph (national, one organisation, an entity card, risk lists, STIX, replay at an earlier instant), a watch added, fired by a drill and paused, an indicator import that matches a C2 and one of our own assets and comes back as CSV, STIX and by TAXII, a brand scan, a consented scan of the portal and a refused public target, three live drills, the HTTP shield (an agent announces an app, an attack is detected and opens a case, block mode drops the next one, a public red-team target is refused), the channels (a test alert and an attack's card reach a real webhook; an unconfigured channel refuses), the SACHET connector (the feed read from the snapshot and matched to operators, a legitimate CAP accepted and a forged one refused, the CAP red-team 10 of 10 with no leak, a warning downloaded as CAP), and the audit trail. |
| Interface | `python scripts\ui_audit.py` | A real browser clicks through every screen, sheet and button on another copy (25 steps, the target; 21 verified at the graph commit, four added: the Indicators tab with an import, a watch set from a graph card and the replay slider, the brand and attack-surface sections, the Disaster alerts (SACHET) section with the CAP red-team run; the main thread verifies them), including the intelligence graph with an entity card and an organisation in focus, the shield card and a test alert delivered to a webhook, and reports any page error, console error or failed request. |

## Honesty

- **Labels:** every fact is labelled REAL (public data) or SIM (simulated sensors, organisations and logs).
- **Live sensors:** the live decoy grid and firewall flows are SIM, accelerated so one 5-second tick is one sensor-hour.
- **Live feeds:** NVD (new CVEs), CISA KEV, Feodo Tracker and OpenPhish are re-read every 15 minutes when the network is up; new CVEs that name a product we run are taken in at once.
- **HTTP shield:** it inspects real HTTP requests from the connected app; the bundled target and the red-team are a local lab (the runner only ever attacks loopback/private addresses), and every red-team request is labelled as an exercise in the audit trail.
- **Channels:** nothing leaves the laptop until you configure a destination; the bundled Ops Console is a local webhook receiver. Only the alert cards you route go out, to the URLs you set, and every delivery is in the audit trail with the destination host, never the secret. The analysis itself never leaves.
- **Brand and social watch:** every request is a read of a public feed or a public search (crt.sh, URLhaus, OpenPhish, Google News, Hacker News, Reddit); nothing touches the organisation or the sites found. A hit is a match of a term with a score for how strong the match is, not a finding of abuse. A source that does not answer is shown as offline, never hidden.
- **Attack surface:** the scan runs only against a system you own and prove you own (a loopback or private address, or an app the Odyssey agent has announced); a public address is refused with the reason. GET and HEAD only, at most 40 requests, a 60 s cooldown per target. The grade describes that system as it answered; nothing else was touched.
- **SACHET:** NDMA's SACHET feed is read-only, public-domain input, read the way NVD or KEV is read; nothing is ever sent to NDMA. Odyssey's CAP output is SACHET-compatible (the same CAP 1.2 format, status Exercise, a note saying it is not an NDMA message) and is not connected to SACHET. The CAP red-team fires only at Odyssey's own loopback endpoint, never at NDMA or any third party. Most SACHET alerts are district-level, so the state inferred for an alert is explainable but not perfect; the basis and confidence are on every row. No language model is used anywhere in this connector. Bhashini is deliberately left out; the local IndicTrans2 stays the translator.
- **Audit trail:** every action is in a hash-chained trail; editing any past entry breaks the chain.

More detail:
- `docs/PS_COVERAGE.md`: objectives, mentor feedback, measured results and a five-minute walk-through.
- `docs/MODEL_CARD.md`: models, evaluations and the live detectors.
- `docs/PITCH.md`: the demo script and the judges' questions with honest answers.
- `docs/TIP_GAP_AUDIT.md`: Odyssey against the leading threat-intelligence platforms (CloudSEK, Recorded Future and the rest of the field): what matches, what was built to close the gap and after the audit, what stays out of scope and where it would plug in.

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
