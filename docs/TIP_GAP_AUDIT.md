# Odyssey against the leading threat-intelligence platforms: a gap audit

Written for the Odyssey team and the D3COY mentors. Audited on 1 November 2026 against the platforms CloudSEK's
knowledge-base article "Best cyber threat intelligence platforms" ranks, with the most weight on its top two,
CloudSEK and Recorded Future. The question was narrow: *apart from scale, where would Odyssey fall short of an
industry-grade intelligence platform, within our scope* (one laptop with an 8 GB GPU, fully on-premise, PS-01's
national early-warning mandate, India's regulators and languages)?

Vendor capabilities below are taken from the vendors' public product descriptions as of the audit date and are
paraphrased; no vendor was tested. Odyssey's side is what runs in this repository, with the screen or endpoint that
proves it.

## 1. Verdict in one paragraph

Before this audit Odyssey already had the parts that *decide*: exposure, scoring, SSVC tiers, Indian obligations,
autopilot with approvals, live detectors, a per-organisation threat map, advisories, risk plans, channels, a shield.
What it lacked were the parts an intelligence platform is *recognised by*: one connected picture of every entity
(the "intelligence graph"), an evidence card per entity, threat-group context, and machine-readable outputs for the
tools a SOC already runs (risk lists, a STIX bundle). Those four are now built and tested (section 4). The four items
this audit first listed as still worth building, and two it had placed out of scope, were built the same morning
(section 6): watchlists and alert rules, bulk indicator import with matching, a TAXII 2.1 server, graph replay, passive
brand and social monitoring, and attack-surface discovery for systems the operator owns. What remains missing is
outside the scope by design (dark-web collection, scanning of networks we do not own, takedowns, sandboxing,
section 5), and each has a defined place to plug in.

## 2. The criteria the article uses, and how Odyssey meets them

| Criterion (article) | What the leaders offer | Odyssey today | Where |
|---|---|---|---|
| Intelligence coverage | Hundreds of open, commercial, dark-web and technical sources | 13 sources, 9 real public feeds (NVD, CISA KEV, SSVC, EPSS, CISA advisories, DShield, Feodo Tracker, OpenPhish, MITRE ATT&CK) plus simulated sensors, every fact labelled REAL or SIM; since the audit, five more passive public sources read by the brand and social watch (crt.sh certificate transparency, URLhaus, Google News, Hacker News, Reddit), and any partner's indicators by bulk import (text, CSV, STIX), matched against our own record | Intel → Threats → Intelligence sources; Intel → Threats → Brand and social watch; Intel → Indicators |
| Enrichment and correlation | Entities linked across vulnerabilities, actors, malware, indicators, victims | The intelligence graph: 11 entity kinds, every edge from the record with provenance; campaigns correlated from KEV, decoy surges and exposure; ATT&CK techniques by explicit rules; threat groups by overlap with the ATT&CK record | Intel → Graph, `/api/graph` |
| Practical automation | Playbooks, automated scoring, alert routing | Graduated autonomy (act, propose, digest) with an approvals queue; SOC cases open themselves with playbooks and SLAs; thresholds re-derive themselves from decisions | Now, SOC, Live |
| Integration readiness | SIEM, SOAR, EDR, ticketing, TIP exchange | Webhooks to Slack, Discord, Teams, e-mail or any URL; risk lists (CSV / JSON) for SIEM, firewall and EDR; STIX 2.1 per alert and for the whole graph; CERT-In report; a REST API; since the audit, indicators in (text, CSV or STIX, matched against our own record), indicators out as CSV, STIX or a read-only TAXII 2.1 server for platforms that pull, and watchlist firings routed through the same channels | Intel → Overview → Risk lists and STIX, Intel → Indicators, `/api/risklists`, `/api/graph/stix`, `/api/iocs`, `/taxii2/`, `agent/README.md` |
| Dark-web visibility | Forums, markets, leak sites, Telegram | None, by design: Odyssey collects only passive public feeds. Since the audit the brand and social watch reads the open web (certificate transparency, URL lists, news, Hacker News, Reddit); forums, markets, leak sites and Telegram stay out. The graph's indicator kind, the brand source adapters and the indicator import are the plug-in points (section 5) | Intel → Threats → Brand and social watch (open web only) |
| Scalability and deployment fit | Cloud SaaS, enterprise tiers | One laptop, 0 cloud calls, 44,000 asset × CVE assessments rebuilt in about 95 s; event-sourced, so a server adds workers not architecture | Proof → How it works |
| Pricing | Subscription | Open source in this repository | — |

## 3. The top two, feature by feature

### 3.1 Recorded Future

| Recorded Future (public description) | Odyssey | Status |
|---|---|---|
| Intelligence Graph: entities and relationships from all sources, updated continuously | Intelligence graph over organisations, assets, technologies, CVEs, campaigns, ATT&CK techniques, malware families, threat groups, indicators, suppliers and live signals; re-read from the record every 5 s; nodes carry the time of their latest evidence and a pulse that decays with it (48-hour e-folding), so the picture breathes with live detections and intake and lies still as evidence ages | **Built in this audit** |
| Intelligence Cards: one page per entity with risk score, evidence, related entities | Entity card per node: what it is, facts, connected entities, the ledger events behind it, the live detection when there is one | **Built** |
| Risk scores with transparent risk rules and evidence | `Risk = 100·R·K·(0.55·L + 0.30·S + 0.15·V)` with named evidence, decay and age-off; SSVC decision path; Bayesian P(compromise) | Already had |
| Risk lists for SIEM / firewall / EDR ingestion | Four scored lists (vulnerabilities, addresses, domains, technologies) as CSV or JSON, each row with score, provenance and evidence | **Built** |
| Alerting rules and watchlists, playbook alerts | Autopilot policy (what is acted on, proposed or digested), approvals queue, channels with severity floor, de-duplication and rate cap; adaptive focus on products and organisations under attack; analyst-authored watchlists on any graph entity with four rule kinds, edge-triggered, evaluated every 15 s, delivered through the channels | Already had (policy); **Built after the audit** (user-authored rules, section 6) |
| Threat-actor, malware and vulnerability intelligence modules | Threat groups from the ATT&CK record ranked by overlap with the techniques and malware actually observed, labelled "overlap, not attribution"; malware family of every C2 seen (Feodo Tracker to ATT&CK software); vulnerability record with KEV, SSVC, EPSS, forecast | **Built** (groups, malware); already had (vulnerabilities) |
| Third-party / supply-chain intelligence | Supplier graph with blast radius and fan-out proposals | Already had (SIM graph) |
| Attack Surface Intelligence | Per-organisation OSINT from passive sources (ports under attack, look-alike domains, exposed services); a consented attack-surface scan of systems the operator owns, graded A to F, its framework fingerprint linked to the exposure record | **Built after the audit** for owned systems only (section 6); passive for everything else |
| AI summaries (research notes) | Fact-checked briefs from a local 8B model, every sentence validated or withheld; a national situation report | Already had |
| Integrations marketplace, browser extension | Webhooks, STIX, CSV, REST | Partial (no marketplace, no extension) |

### 3.2 CloudSEK (XVigil, BeVigil, SVigil as publicly described)

| CloudSEK | Odyssey | Status |
|---|---|---|
| AI-based risk prediction | Day-0 exploitation forecast, tested out-of-time; Bayesian compromise model | Already had, measured |
| Digital asset monitoring (brand, domains, apps, code leaks) | Look-alike domains in live phishing feeds per organisation; a brand and social watch over certificate transparency, URLhaus, OpenPhish, news and public social feeds, scored and audited; exposed services; nothing active | **Built after the audit** (domains, certificates, URLs, mentions; section 6); no app-store or code-leak monitoring |
| Dark-web and underground monitoring | None by design | Out of scope (section 5) |
| Automated threat scoring and real-time alerts | Live detectors every 5 s, scoring with decay, alerts to channels within seconds | Already had |
| Attack-surface discovery (BeVigil) | A consented posture check of the operator's own systems only (loopback or private, or an app the Odyssey agent announced), GET and HEAD, at most 40 requests; a public target is refused with the reason | **Built after the audit**, owned systems only (section 6); scanning of others' networks stays out by rule |
| Supply-chain / vendor risk (SVigil) | Supplier graph, fan-out, obligations | Already had (SIM) |
| Takedown services | None | Out of scope |
| Indian context | CERT-In 6-hour clock and Blueprint deadlines, RBI, SEBI CSCRF, DPDP, NCIIPC and sector CSIRT routing, 22 Indian languages, Indian operators and suppliers in the constituency | Beyond the vendors' public descriptions |

### 3.3 The rest of the list, in one line each

CrowdStrike Falcon X: malware auto-analysis and actor linkage (Odyssey: no sandbox; actor linkage via ATT&CK overlap).
ThreatConnect: playbooks, case management, ATT&CK (Odyssey: cases with playbooks, approvals, ATT&CK mapping with real
mitigations). Anomali ThreatStream: IOC enrichment and matching, feed management (Odyssey: indicators matched against
telemetry, feeds with freshness and adaptive cadence; bulk IOC import in text, CSV and STIX built after the audit,
section 6). Mandiant: actor tracking (ATT&CK
overlap only). Cybersixgill: deep and dark web (out of scope). Palo Alto AutoFocus: sample-centric intelligence (no
samples).

## 4. Built in this audit

1. **The intelligence graph** (`backend/app/engine/graph.py`, `frontend/src/IntelGraph.tsx`, `/api/graph`). Rings by
   entity kind from the organisations outward; angles from the circular mean of each node's inner neighbours, so the
   layout is deterministic and does not jitter. Nodes are sized by risk and filled by worst tier; diamonds are threat
   groups, triangles live signals; a halo breathes with the evidence pulse, fast for the last hour, still after a week.
   One organisation in focus puts it at the centre with its assets. Hover for the record, click for the card.
2. **Entity cards** (`/api/graph/node`): neighbours, the ledger events behind the node, the live detection when there
   is one, and a one-line statement of how that kind of node is derived.
3. **Threat-group and malware context, without attribution.** The malware family of each C2 seen comes from Feodo
   Tracker and is matched to ATT&CK software; groups ATT&CK records using that malware come first, then groups whose
   documented techniques overlap most with the techniques observed here. Every such node says "overlap, not
   attribution" and links to the ATT&CK page.
4. **Risk lists and a STIX bundle** (`backend/app/engine/export.py`, `/api/risklists/{cves|ips|domains|products}`,
   `/api/graph/stix`). Scored rows with provenance and evidence; C2 addresses refanged for a block list with the
   defanged form beside them; the graph as STIX 2.1 identities, vulnerabilities, software, campaigns, attack patterns,
   malware, intrusion sets, indicators, sightings and relationships, with no dangling reference.
5. **Verification.** Eight new engine tests (`tests/test_graph.py`): the graph is a consistent subset of the record,
   provenance on every element, pulse is evidence age and a live detection breathes, the layout is deterministic and
   keeps nodes apart, one organisation in focus shows only that organisation, cards carry neighbours and evidence,
   risk lists are scored and sourced, the STIX bundle has no dangling reference. One new product flow in
   `scripts/e2e_check.py`, one new browser step in `scripts/ui_audit.py`.

## 5. Out of scope by design, with the plug-in point

| Capability | Why not here | Where it would plug in |
|---|---|---|
| Dark-web, forum, Telegram and leak-site collection | Needs commercial access and collection infrastructure; not passive public data; not on one laptop | A feed adapter in `live.py` (`FEEDS`) or a source adapter in `engine/brand.py` (`SOURCES`), or a partner's export through `POST /api/iocs/import`, producing `indicator` and `signal` nodes with provenance "REAL · vendor"; the graph, cards, risk lists, STIX and TAXII need no change |
| Active scanning of networks the operator does not own | Still refused by rule, in code: `engine/surface.py` scans only a loopback or private address or an app the Odyssey agent has announced, and answers a public target with the refusal and its reason. What is built (section 6) is the consented posture check of the operator's own systems, GET and HEAD only, at most 40 requests | A stronger proof of ownership (a DNS or well-known-file token) in the same gate, if a deployment ever needs to check its own public address; the running agent remains the proof today |
| Brand, social-media and mobile-app monitoring | Built after the audit as passive monitoring of public sources (section 6): certificate transparency, URLhaus, OpenPhish, news and public social feeds, scored and audited. Mobile-app stores, code-leak monitoring and paid social platforms stay out: they need platform APIs and collection at scale | A source adapter in `engine/brand.py` (`SOURCES`) returning normalised hits; scoring, storage, the ledger, the graph and the screen need no change |
| Takedowns and vendor notifications | A service, not software | Channels already deliver the alert card to any webhook, so a takedown desk can be a destination |
| Sandboxing and malware analysis | No samples in a passive design | A `malware` node with analysis facts; ATT&CK software links already exist |
| Hundreds of operators and millions of assets | One laptop; scale was excluded from this audit by the brief | Event-sourced design; SQLite to a server database, workers for the pipeline |

## 6. Built after the audit (1 Nov 2026, 07:15 to 08:15 IST)

The first version of this section listed four items still worth building in scope (watchlists and rules, bulk
indicator import, a TAXII server, graph history). All four were built that morning, and two items section 5 had placed
out of scope were built within the boundary the rules allow (passive brand and social monitoring; attack-surface
discovery for systems the operator owns). All six are deterministic services with no model call. They were built and
tested on the backend first; the interface landed right after: Intel → Graph gets a replay slider, a Watch button on
every card and a Watchlist section; Intel gets a new Indicators tab (import, what is held, CSV, STIX and TAXII);
Intel → Threats gets "Brand and social watch" and "Attack surface, with consent"; Organisations → OSINT gets the brand
watch for that organisation.

1. **Watchlists and alert rules** (`backend/app/engine/watch.py`; `GET` and `POST /api/watches`,
   `POST /api/watches/{id}/pause|resume|delete`, `POST /api/watches/evaluate`). An analyst watches any graph node with
   a rule: `any` (fresh evidence, a worsening tier or a new connection), `fresh` (pulse rises above a threshold, or new
   evidence is recorded), `tier` (the worst open tier reaches the threshold or worse), `connect` (a new edge appears).
   Rules are edge-triggered: a watch fires on the change, not on every evaluation while the condition holds. The live
   engine evaluates every active watch against the current graph every 15 s; a firing is a `watch.fired` ledger event,
   a detection of kind `watch` on Live, a signal node in the graph and a card through the channels. Adding, pausing,
   resuming and deleting are audited (`watch.added`, `watch.paused`, `watch.active`, `watch.deleted`).
2. **Bulk indicator import and matching** (`backend/app/engine/iocs.py`; `POST /api/iocs/import`, `GET /api/iocs`,
   `GET /api/iocs/export?format=csv|stix`). Any text, CSV or STIX 2.1 bundle in; IPv4 addresses, domains, URLs,
   SHA-256, SHA-1 and MD5 hashes and CVE ids out, refanged for matching and defanged for display. Each is matched
   against what Odyssey actually holds: the live firewall flows and C2 sightings (SIM), the HTTP shield's attackers,
   the constituency's own addresses and domains and their look-alikes, and the exposure record for CVEs; and enriched
   from Feodo Tracker, DShield, OpenPhish and CISA KEV (REAL). An import is `ioc.import`, a match `ioc.match`; from then
   on the live engine matches new flows against the imported addresses on every tick. This is the ThreatStream pattern
   from section 3.3.
3. **TAXII 2.1 server** (`backend/app/taxii.py`; `GET /taxii2/` discovery, `/taxii2/odyssey/` root,
   `/taxii2/odyssey/collections/`, `.../collections/{id or alias}/objects/`, `/manifest/`, `/objects/{id}/`,
   `/objects/{id}/versions/`). Read-only, one API root, three collections (`graph`, `indicators`, `vulnerabilities`)
   built from the same STIX generator as the bundle export, so a platform that pulls gets the same objects; paging
   (`limit`, `next`), `added_after`, `match[type]` and `match[id]`; media type `application/taxii+json;version=2.1`; a
   bearer token when `ODYSSEY_TAXII_TOKEN` is set.
4. **Graph replay** (`as_of=` on `/api/graph`, `GET /api/graph/replay`). The record as it stood at nine instants: the
   snapshot date, 30, 14, 7, 3 and 1 days ago, 6 hours and 1 hour ago, and now. Later evidence is left out and every
   pulse is aged to that instant; the layout rules are unchanged, so the picture can be stepped through without jitter.
5. **Brand and social monitoring** (`backend/app/engine/brand.py`; `GET /api/brand?org_id=`,
   `POST /api/brand/scan {term | org_id}`, `GET /api/brand/hits`). Passive and public only: crt.sh certificate
   transparency (look-alike certificates), abuse.ch URLhaus and OpenPhish (malicious and phishing URLs naming the
   term), Google News RSS, Hacker News and Reddit RSS (mentions). For an organisation the terms are its name's
   distinctive words, its domain and that domain's look-alike permutations. Hits are scored 0 to 100 by explicit rules,
   stored once per (term, source, kind, value), and a new hit at 70 or above is a `brand.hit` ledger event and a node
   in the graph. Nothing touches the organisation or the sites found; a source that does not answer is reported offline,
   never raised. A live run for the term "irctc" returned 79 real hits, with crt.sh rate-limited that minute and shown
   as such.
6. **Attack-surface discovery, with consent** (`backend/app/engine/surface.py`;
   `POST /api/surface/scan {url, consent: true, org_id?}`, `GET /api/surface`, `GET /api/surface/can-scan?url=`,
   `GET /api/surface/{scan_id}`). Two conditions are enforced in code and both must hold: `consent: true`, and a target
   that is provably the operator's own (a loopback, RFC 1918, link-local or carrier-grade NAT address, or an application
   the HTTP-shield agent has registered). A public address with no registered agent is refused with the reason
   (HTTP 400). GET and HEAD only, no payloads, at most 40 requests, a 60 s cooldown per target. Checks: transport and
   TLS, security headers, cookie flags, exposed files and admin paths, a framework fingerprint mapped to product keys
   (and so to known CVEs in the constituency), and locally reachable service ports. Each finding carries a CWE, the
   evidence and a fix; a score and a grade A to F; `surface.scan` and `surface.finding` in the ledger. The demo portal
   (CityPower, :8080, registered to PWR-01) scores 29, grade F: plain HTTP, open SSH and SMB ports, no CSP, an exposed
   `/openapi.json`, a FastAPI fingerprint.
7. **The graph draws them.** Imported indicators that matched, brand hits of weight, surface scans and watch firings
   are nodes with their provenance, so the one connected picture includes what the operator brought in and what it set
   a rule on.

Verification: `tests/test_brand_surface.py` (8 tests: a scan scores, stores and audits; a second scan makes no
duplicates; offline sources do not fail a scan; generic words are dropped from an organisation's terms; the ownership
gate refuses what is not ours; a scan finds and audits; the cooldown blocks a quick rescan; the real portal when it is
up). The watchlist, indicator and TAXII tests, six new product flows in `scripts/e2e_check.py` and three new browser
steps in `scripts/ui_audit.py` are targets the main thread verifies: about 140 engine tests, 25 flows, 24 steps.

## 7. What we do not claim

Odyssey does not attribute activity to threat groups; the group nodes are overlap with the public ATT&CK record and say
so on the node, in the card and in the STIX description. The organisations, assets, decoy grid, firewall sightings and
supplier graph are simulated and labelled SIM everywhere, including in the exports. Pulse is evidence age, not severity.
A brand hit is a match of a term in a public source with a score for how strong the match is, not a finding of abuse.
A surface grade describes an owned system as it answered a few dozen GET and HEAD requests; nothing else was touched.
An imported indicator keeps the importer's source and TLP, and a match says where in our own record it was seen, not
what the indicator is.
