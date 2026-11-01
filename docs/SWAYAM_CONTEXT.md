# Odyssey - full context download (session of 1 Nov 2026)

Written for the Odyssey team and any future Claude session picking this up. It is a complete handover of what this
thread did, why, the decisions and boundaries held, every file and endpoint added, how it was verified, and how to run
it. It complements `docs/THREAD_CONTEXT.md` (the earlier, shared handover) and does not replace it.

---

## 1. Where this thread started and where it ended

This session continued an earlier one (PS-01, "AI-Based National Cyber Threat Early Warning System", fully local on an
RTX 4070 laptop). At the start, Odyssey already had: the build pipeline, the live engine with detectors, the
per-organisation threat map, adaptive telemetry, SOC cases, advisories, the HTTP shield (from a parallel "shield
thread"), channels, and a passing verification suite.

The team lead's request that opened this thread: **audit Odyssey against the leading threat-intelligence and
aggregator platforms** (the CloudSEK knowledge-base ranking, most weight on CloudSEK and Recorded Future), within our
scope (one laptop, on-premise, Indian context), and **build whatever is missing** so it does not fall short "other
than scale" - the example given was "a well-defined adaptive breathing intelligence graph."

By the end, the thread had built the intelligence graph and the other TIP-grade pieces, paired Odyssey with India's
SACHET feed, and stood up a realistic owned lab target with an autonomous red-team agent so the detect-and-report loop
runs against real traffic. Everything is committed and pushed; `main` is in sync with GitHub (head `eb6021d`).

---

## 2. The audit that drove the work

`docs/TIP_GAP_AUDIT.md` is the written audit against CloudSEK, Recorded Future and the rest of the field. The verdict:
Odyssey already had the parts that *decide* (exposure, scoring, SSVC tiers, Indian obligations, autopilot, live
detectors, the threat map). What it lacked were the parts a platform is *recognised by*. Those were built this thread:

1. **The intelligence graph** - one connected, breathing picture of every entity and how they relate.
2. **Entity intelligence cards** - a page per entity with its neighbours and the evidence behind it.
3. **Threat-group and malware context** from ATT&CK, stated as overlap, never attribution.
4. **Risk lists and a STIX 2.1 bundle**, plus a **TAXII 2.1 server**, for the tools a SOC already runs.
5. **Watchlists and alert rules**, **bulk indicator import and matching**, **graph replay**, **brand and social
   monitoring**, and a **consented attack-surface scan**.

Out of scope by rule (each with a plug-in point noted in the audit): dark-web collection, active scanning of real
third parties, brand/social at commercial scale, takedowns, sandboxing.

---

## 3. What was built, feature by feature

### 3.1 The intelligence graph (`backend/app/engine/graph.py`, `frontend/src/IntelGraph.tsx`)
- `intel_graph(conn, focus, live, as_of=None)` builds a graph from the database, the hash-chained ledger, the live
  engine and the local ATT&CK and Feodo snapshots. Eleven node kinds: organisations, assets (when one org is in
  focus), technologies, CVEs, campaigns, ATT&CK techniques, malware families, threat groups, indicators, suppliers and
  live signals.
- Every node carries its latest-evidence time and a **pulse = exp(-age_hours / 48)**, so the picture **breathes**:
  fresh live evidence pulses fast, old evidence lies still. Phases: fresh (<1 h), today, week, fading (<30 d), aged.
- Deterministic layout (rings by kind; angles from the circular mean of each node's inner neighbours), so it does not
  jitter between polls.
- Threat groups are ATT&CK intrusion-sets ranked by malware link (a C2's Feodo family matched to ATT&CK software, then
  the groups recorded using it), then technique overlap with what is observed. **Every group node says "overlap, not
  attribution"** and links to the ATT&CK page.
- `node_card()` returns one entity's neighbours, the ledger events behind it, and how that kind of node is derived.
- **Replay:** `as_of` rebuilds the graph as it stood at a past instant (later evidence removed, pulses aged to then).
  `replay_steps()` offers nine instants from the snapshot to now.
- UI: Intel -> Graph tab. Focus pills (national or one operator), a breath strip, an SVG with ring captions, breathing
  halos, a one-shot "ping" for new nodes, collision-avoiding labels, a hover panel, a kind filter, a replay slider, a
  "Watch" button on every card, and a card sheet you can follow neighbour to neighbour.
- Endpoints: `GET /api/graph?focus=&as_of=`, `GET /api/graph/node?id=&focus=`, `GET /api/graph/replay`.

### 3.2 Risk lists, STIX and TAXII (`backend/app/engine/export.py`, `backend/app/taxii.py`)
- Risk lists: four scored, sourced lists (vulnerabilities, addresses, domains, technologies) as CSV or JSON for a
  SIEM, firewall or EDR; C2 addresses refanged for a block list with the defanged form beside them.
  `GET /api/risklists`, `GET /api/risklists/{kind}?format=json|csv`.
- `graph_stix()` emits the whole graph as a STIX 2.1 bundle (identities, infrastructure, software, vulnerabilities,
  campaigns, attack-patterns, malware, intrusion-sets, indicators, sightings, relationships) with no dangling
  reference. `GET /api/graph/stix`.
- **TAXII 2.1 server:** discovery, one API root, three read-only collections (graph, indicators, vulnerabilities),
  paging, `match[type]`/`match[id]`/`added_after` filters, manifest, versions, optional bearer token
  (`ODYSSEY_TAXII_TOKEN`). `GET /taxii2/...`. Any TAXII client (OpenCTI, MISP, a SIEM) can pull.
- UI: Intel -> Indicators tab shows the exports and a live "Test it" against the TAXII collections.

### 3.3 Watchlists and alert rules (`backend/app/engine/watch.py`)
- Watch any graph entity with a rule (fresh evidence, a worsening tier, a new connection, or any). Rules are
  edge-triggered (fire on the change, not every evaluation). The live engine evaluates every active watch every ~15 s.
  A firing is a `watch.fired` ledger event, routed through the channels, and shown as a live detection.
- Endpoints: `GET/POST /api/watches`, `POST /api/watches/{id}/pause|resume|delete`, `POST /api/watches/evaluate`.
  UI: the Watchlist section under the graph, and a Watch button on each card.

### 3.4 Bulk indicator import and matching (`backend/app/engine/iocs.py`)
- Paste or upload anything (CSV, a list, an advisory, a STIX bundle). It extracts IPv4, domains, URLs, hashes and CVE
  ids, refangs and de-dupes them, and matches each against the record: live flows, C2 sightings, the shield's
  attackers, our own assets and domains and their look-alikes, and the exposure record; enriched from Feodo, DShield,
  OpenPhish and KEV. The live engine also matches imported addresses against flows on every tick (`ioc` detections).
- Ledger: `ioc.import`, `ioc.match`. CSV and STIX export. Endpoints: `POST /api/iocs/import`, `GET /api/iocs`,
  `GET /api/iocs/export?format=csv|stix`. UI: Intel -> Indicators.

### 3.5 Brand and social monitoring (`backend/app/engine/brand.py`, `backend/app/osint_api.py`)
- Passive reads of public sources - certificate transparency (crt.sh), URLhaus, OpenPhish, Google News, Hacker News,
  Reddit - for impersonation and risk mentions of a brand or an operator, scored, with a `brand.hit` ledger event at
  score >= 70. Endpoints: `GET /api/brand`, `POST /api/brand/scan`, `GET /api/brand/hits`. UI: Intel -> Threats and
  Organisations -> What outsiders see.

### 3.6 Consented attack-surface scan (`backend/app/engine/surface.py`, `backend/app/osint_api.py`)
- A BeVigil-style discovery, but **only for systems the operator owns**: the target must resolve to loopback /
  RFC-1918 private / an app registered by the shield agent, and carry consent, or it is refused. GET/HEAD only, <= 40
  requests. Checks transport, security headers, cookies, exposed files and admin paths, a framework fingerprint mapped
  to product keys, and open service ports; scores and grades. Ledger `surface.scan`, `surface.finding`. Endpoints:
  `POST /api/surface/scan`, `GET /api/surface`, `GET /api/surface/can-scan`, `GET /api/surface/{id}`.

### 3.7 The SACHET connector (`backend/app/sachet.py`)
Odyssey paired with India's SACHET alert feed. Three independent parts:
- **Reader:** NDMA's public-domain SACHET CAP 1.2 RSS feed, read-only every 15 min (snapshot-backed), with the state
  each alert concerns inferred with a stated basis (sender office, state name, district name, script) and matched to
  the operators there ("is this outage the weather, or an attack?").
- **Writer:** Odyssey's own warnings as **SACHET-compatible** CAP 1.2 (one `<info>` per validated language, status
  Exercise), never presented as SACHET messages. `GET /api/warnings/{org}/{cve}/cap`. The warning sheet has a CAP
  download button.
- **Guard:** `POST /api/sensor/cap` treats every inbound CAP as hostile until validated - an eight-step ladder (flood,
  size, any DTD/entity refused before parsing, well-formed, required fields, an authorised-sender allow-list, replay,
  expiry). Each decision is a `cap.ingest.accepted` / `cap.ingest.refused` ledger event. Table `cap_ingest`.
  Encoding-aware DTD refusal (a reviewer hardened `safe_parse` so a UTF-16/UTF-32/declared-encoding body cannot hide a
  DOCTYPE). No dependency beyond the standard library and httpx (defusedxml is not installed and not needed).
- Other endpoints: `GET /api/sachet`, `GET /api/sachet/alert`. The graph draws matched SACHET alerts as REAL signals
  on the operators and accepted inbound CAP as signals. UI: Intel -> Threats "Disaster alerts (SACHET)" and a Now
  tile. `docs/SACHET_BHASHINI_PLAN.md` (shield thread) is the plan; this implements Connector A only.
- An **in-session CAP red-team runner was built then removed** on the team lead's instruction: red-teaming is done by
  a separate session against `POST /api/sensor/cap` with an `x-odyssey-redteam` header; the guard and its live
  decisions panel stay.
- **Bhashini (MeitY cloud translation) is deliberately not wired.** Local IndicTrans2 stays the translator, so the "0
  cloud calls" claim holds. It would plug in behind the existing translate seam, off unless a key is supplied.

### 3.8 Real-world testing: the lab target, OAuth, and the red-team agent
Documented in full in `docs/REAL_WORLD_TESTING.md`.
- **`target/gov_portal.py`** - the **Lokseva Digital Services Directorate**, a FICTIONAL government citizen-services
  portal (org `GOV-01`), a second HTTP-shield lab target modelled on `target/portal.py`. It is built to look realistic
  (masthead with emblem, navigation, a hero with search, a stats strip, an online-services grid, active alerts,
  notices, emergency helplines, a footer, and `/services` `/about` `/contact` `/notices` pages) while carrying a visible
  **SIMULATION banner** on every page and a footer saying it is a fictional lab target holding no real data. It binds
  to the shield via `agent/odyssey_asgi` on `:8081`, reflects input and exposes the probed endpoints, and forwards a
  submitted CAP to the ingest guard. It runs a **self-contained mock OAuth 2.0 flow** (login, authorize, token, a
  protected dashboard) - demo account `officer` / `demo123` printed on the page, no real identity provider, no real
  credential collected - so the shield has a realistic auth surface (open redirect, missing state/CSRF, SQLi, forged
  token, brute force). Body parsing is done without python-multipart (not installed).
- **`scripts/redteam_agent.py`** - a standalone red-team entity (a separate process from Odyssey) that runs the
  web-attack families (via Odyssey's own loopback-guarded runner) plus OAuth/auth cases at the lab target, in a number
  of waves you choose, labelled as an exercise. **Hard rule, enforced in code:** it resolves the target host and
  refuses anything that is not loopback / RFC-1918 before sending a byte, so it can never reach a real or third-party
  service. It is person-run, not an unattended endless loop.
- **`scripts/start_gov_target.ps1`** - brings the lab target up on `:8081`.

---

## 4. Boundaries and decisions held this thread

These came up repeatedly and are load-bearing:
- **Never attack a real SACHET site, a real government service, or any third party** - autonomous or manual. Odyssey
  only *reads* SACHET's public feed; it has no sensor inside NDMA and cannot detect an attack there. The
  attack-to-report loop is demonstrated only against **lab targets we own**, on loopback.
- **Never impersonate a real agency.** The lab target is a clearly fictional operator with a SIMULATION banner.
- **Red-teaming is person-triggered**, loopback/private-guarded. No unattended attack loop in the product.
- **Threat groups are overlap with the ATT&CK record, not attribution** - on the node, in the card, in the STIX.
- **SIM/REAL labels everywhere; indicators defanged; hash-chained audit trail; 0 cloud calls** (Bhashini stays off).
- Verification runs **sequentially** (pytest, then e2e, then ui_audit) - running them together exhausts the laptop's
  RAM. `ui_audit.py` needs the system Python (Playwright), the others use `.venv`.
- Commit **only own files**; the shield thread owns `target/portal.py`, `target/console.py`, `agent/`, `shield.py`,
  `redteam.py`, `notify.py`, `config/notify.json`, `start_all.ps1`. Push via `bash scripts/autosync.sh`.

---

## 5. Files, endpoints, ledger kinds, tables

**New backend modules:** `engine/graph.py`, `engine/export.py`, `engine/watch.py`, `engine/iocs.py`,
`engine/brand.py`, `engine/surface.py`, `sachet.py`, `taxii.py`, `osint_api.py`.
**New frontend:** `IntelGraph.tsx`, `Watchlist.tsx`, `IocImport.tsx`, `BrandWatch.tsx`, `SurfaceScan.tsx`,
`Sachet.tsx` (plus edits to App, Soc, Orgs, Now, ExportPanel, proactive, api, index.css).
**New tests:** `test_graph.py`, `test_watch_iocs_taxii.py`, `test_brand_surface.py`, `test_sachet.py`.
**Lab target and scripts:** `target/gov_portal.py`, `scripts/redteam_agent.py`, `scripts/start_gov_target.ps1`.
**Docs:** `TIP_GAP_AUDIT.md`, `REAL_WORLD_TESTING.md`, this file; updates to README, PS_COVERAGE, PITCH, MODEL_CARD,
THREAD_CONTEXT.

**New API endpoints:** `/api/graph`, `/api/graph/node`, `/api/graph/replay`, `/api/graph/stix`, `/api/risklists`,
`/api/risklists/{kind}`, `/api/watches` (+ actions + evaluate), `/api/iocs/import`, `/api/iocs`, `/api/iocs/export`,
`/api/brand`, `/api/brand/scan`, `/api/brand/hits`, `/api/surface/scan`, `/api/surface`, `/api/surface/can-scan`,
`/api/surface/{id}`, `/api/sachet`, `/api/sachet/alert`, `/api/sensor/cap`, `/api/warnings/{org}/{cve}/cap`,
`/taxii2/...`.

**New ledger kinds:** `watch.added|paused|active|deleted|fired`, `ioc.import`, `ioc.match`, `brand.hit`,
`surface.scan`, `surface.finding`, `cap.ingest.accepted`, `cap.ingest.refused`.
**New tables:** `watches`, `watch_events`, `iocs`, `ioc_imports`, `brand_hits`, `brand_scans`, `surface_scans`,
`surface_findings`, `cap_ingest`.

---

## 6. Verification (all green)

- Engine tests: **221 passed** (`.venv\Scripts\python -m pytest -q`), including the new graph, watch/ioc/taxii,
  brand/surface and SACHET suites, with adversarial-reviewer regression tests.
- Product flows: **26/26** (`scripts\e2e_check.py`).
- Browser audit: **25/26 steps** (`python scripts\ui_audit.py`); the one flag was a transient asset 404, not a
  regression (a clean reload of the new pages shows none).
- `npm run build` and `npx oxlint` clean.
- Lab-target loop: red-team agent 3 waves -> 459 attacks detected on the Lokseva portal, 242 blocked in block mode,
  11 attack families including the OAuth ones (SSRF, SQLi, XSS), a Compromise case opened, 29 alerts delivered to the
  channels. The agent refuses a public target outright.

---

## 7. How to run

**The system:**
```
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1      # Ollama, API :8000, translation :8010, dashboard :5173, shield targets, Ops Console :8090
powershell -ExecutionPolicy Bypass -File scripts\start_gov_target.ps1   # the Lokseva lab target on :8081
```
Open `http://127.0.0.1:5173`. Before a demo, `scripts\demo_reset.ps1` (rebuilds the DB; the CERT-In 6-hour clock
starts at build, so reset ~10 min before each slot).

**The attack-to-report loop (what you watch manually):**
1. Open the Live page (`http://127.0.0.1:5173/?view=live`) and the target (`http://127.0.0.1:8081/`, sign in
   `officer` / `demo123`), and optionally the Ops Console (`http://127.0.0.1:8090/`).
2. Optional: set the target to block mode (the "Block inline" toggle, or
   `POST /api/shield/apps/lokseva-alert-portal/mode?mode=block`).
3. Run `.venv\Scripts\python scripts\redteam_agent.py --waves 5 --delay 20`.
4. Watch Odyssey detect, block, open a Compromise case, and deliver alerts to the channels.
5. Reset for browsing: `POST /api/shield/unblock/127.0.0.1` and set the app back to `mode=monitor`.

**The SACHET guard:** a separate session sends CAP to `POST /api/sensor/cap` with header `x-odyssey-redteam: <id>`;
the decisions appear live on Intel -> Threats -> Disaster alerts (SACHET).

---

## 8. Coordination with the parallel shield thread

A second Claude session ("shield thread", session `decoy-a0`) works the same repo on the HTTP shield, channels, the
Ops Console, the reverse-proxy agent, and `docs/SACHET_BHASHINI_PLAN.md`. This thread routed four new ledger kinds
through their channels (they own `config/notify.json`), added a second lab target without touching their files, and
kept off `scripts/ui_audit.py`, `scripts/e2e_check.py` and `docs/THREAD_CONTEXT.md` while they worked. The auto-sync
hook commits on each turn, so most of this thread's work landed as "Auto-sync" commits; the descriptive commits are
`4e6b9a2`, `d025dcb`, `bd81eb2`, `eb6021d`.

---

## 9. Open items and next steps

- In-scope, not yet built: user-authored watchlist rules UI depth, bulk IOC scheduled pulls, graph-history UI on the
  replay slider beyond the current instants, and a TAXII push/collection write (currently read-only).
- Out of scope by rule (plug-in points in `docs/TIP_GAP_AUDIT.md`): dark-web collection, scanning real third parties,
  brand/social at scale, takedowns, sandboxing.
- Bhashini: wire behind the translate seam only if the team lead supplies ULCA credentials and accepts the on-screen
  "cloud translation on" caveat; otherwise it ships as "supported, off".
- Before judging: `demo_reset.ps1` ~10 min before each slot; rehearse the Live attack-to-report loop once.
