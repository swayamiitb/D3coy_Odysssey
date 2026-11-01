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
tools a SOC already runs (risk lists, a STIX bundle). Those four are now built and tested (section 4). What remains
missing is outside the scope by design (dark-web collection, external scanning of real organisations, takedowns,
brand and social monitoring at scale, section 5), and each has a defined place to plug in.

## 2. The criteria the article uses, and how Odyssey meets them

| Criterion (article) | What the leaders offer | Odyssey today | Where |
|---|---|---|---|
| Intelligence coverage | Hundreds of open, commercial, dark-web and technical sources | 13 sources, 9 real public feeds (NVD, CISA KEV, SSVC, EPSS, CISA advisories, DShield, Feodo Tracker, OpenPhish, MITRE ATT&CK) plus simulated sensors, every fact labelled REAL or SIM | Intel → Threats → Intelligence sources |
| Enrichment and correlation | Entities linked across vulnerabilities, actors, malware, indicators, victims | The intelligence graph: 11 entity kinds, every edge from the record with provenance; campaigns correlated from KEV, decoy surges and exposure; ATT&CK techniques by explicit rules; threat groups by overlap with the ATT&CK record | Intel → Graph, `/api/graph` |
| Practical automation | Playbooks, automated scoring, alert routing | Graduated autonomy (act, propose, digest) with an approvals queue; SOC cases open themselves with playbooks and SLAs; thresholds re-derive themselves from decisions | Now, SOC, Live |
| Integration readiness | SIEM, SOAR, EDR, ticketing, TIP exchange | Webhooks to Slack, Discord, Teams, e-mail or any URL; risk lists (CSV / JSON) for SIEM, firewall and EDR; STIX 2.1 per alert and for the whole graph; CERT-In report; a REST API | Intel → Overview → Risk lists and STIX, `/api/risklists`, `/api/graph/stix`, `agent/README.md` |
| Dark-web visibility | Forums, markets, leak sites, Telegram | None, by design: Odyssey collects only passive public feeds. The graph's indicator kind and the feed watcher are the plug-in point (section 5) | — |
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
| Alerting rules and watchlists, playbook alerts | Autopilot policy (what is acted on, proposed or digested), approvals queue, channels with severity floor, de-duplication and rate cap; adaptive focus on products and organisations under attack | Already had (policy-driven rather than user-authored rules; see section 6) |
| Threat-actor, malware and vulnerability intelligence modules | Threat groups from the ATT&CK record ranked by overlap with the techniques and malware actually observed, labelled "overlap, not attribution"; malware family of every C2 seen (Feodo Tracker to ATT&CK software); vulnerability record with KEV, SSVC, EPSS, forecast | **Built** (groups, malware); already had (vulnerabilities) |
| Third-party / supply-chain intelligence | Supplier graph with blast radius and fan-out proposals | Already had (SIM graph) |
| Attack Surface Intelligence | Per-organisation OSINT from passive sources only (ports under attack, look-alike domains, exposed services) | Partial, passive by design |
| AI summaries (research notes) | Fact-checked briefs from a local 8B model, every sentence validated or withheld; a national situation report | Already had |
| Integrations marketplace, browser extension | Webhooks, STIX, CSV, REST | Partial (no marketplace, no extension) |

### 3.2 CloudSEK (XVigil, BeVigil, SVigil as publicly described)

| CloudSEK | Odyssey | Status |
|---|---|---|
| AI-based risk prediction | Day-0 exploitation forecast, tested out-of-time; Bayesian compromise model | Already had, measured |
| Digital asset monitoring (brand, domains, apps, code leaks) | Look-alike domains in live phishing feeds per organisation; exposed services; nothing active | Partial: domains only |
| Dark-web and underground monitoring | None by design | Out of scope (section 5) |
| Automated threat scoring and real-time alerts | Live detectors every 5 s, scoring with decay, alerts to channels within seconds | Already had |
| Attack-surface discovery (BeVigil) | Passive only; no scanning of real networks | Out of scope by rule |
| Supply-chain / vendor risk (SVigil) | Supplier graph, fan-out, obligations | Already had (SIM) |
| Takedown services | None | Out of scope |
| Indian context | CERT-In 6-hour clock and Blueprint deadlines, RBI, SEBI CSCRF, DPDP, NCIIPC and sector CSIRT routing, 22 Indian languages, Indian operators and suppliers in the constituency | Beyond the vendors' public descriptions |

### 3.3 The rest of the list, in one line each

CrowdStrike Falcon X: malware auto-analysis and actor linkage (Odyssey: no sandbox; actor linkage via ATT&CK overlap).
ThreatConnect: playbooks, case management, ATT&CK (Odyssey: cases with playbooks, approvals, ATT&CK mapping with real
mitigations). Anomali ThreatStream: IOC enrichment and matching, feed management (Odyssey: indicators matched against
telemetry, feeds with freshness and adaptive cadence; no bulk IOC import, section 6). Mandiant: actor tracking (ATT&CK
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
| Dark-web, forum, Telegram and leak-site collection | Needs commercial access and collection infrastructure; not passive public data; not on one laptop | A feed adapter in `live.py` (`FEEDS`) producing `indicator` and `signal` nodes with provenance "REAL · vendor"; the graph, cards, risk lists and STIX need no change |
| Active attack-surface scanning of real organisations | The rules forbid touching any real network; the shield protects a real app that *opts in* instead | The agent and reverse proxy in `agent/`; BeVigil-style discovery would be a consented scanner feeding `asset` nodes |
| Brand, social-media and mobile-app monitoring | Needs platform APIs and collection at scale | Same adapter path as the dark web, into `indicator` nodes of type `domain-name` / `url` |
| Takedowns and vendor notifications | A service, not software | Channels already deliver the alert card to any webhook, so a takedown desk can be a destination |
| Sandboxing and malware analysis | No samples in a passive design | A `malware` node with analysis facts; ATT&CK software links already exist |
| Hundreds of operators and millions of assets | One laptop; scale was excluded from this audit by the brief | Event-sourced design; SQLite to a server database, workers for the pipeline |

## 6. Still worth building, in scope

- **User-authored watchlists and alert rules** on graph entities (an operator watches a technology, a CVE, a C2 and
  gets a card when its pulse rises). The policy engine and the channels exist; a rules table and a tap are missing.
- **Bulk indicator import** (CSV / STIX in) matched against telemetry, the ThreatStream pattern.
- **TAXII 2.1 server** over the existing STIX bundles for platforms that pull rather than fetch.
- **Graph history**: replay the graph at a past time from the ledger (the per-alert replay exists).

## 7. What we do not claim

Odyssey does not attribute activity to threat groups; the group nodes are overlap with the public ATT&CK record and say
so on the node, in the card and in the STIX description. The organisations, assets, decoy grid, firewall sightings and
supplier graph are simulated and labelled SIM everywhere, including in the exports. Pulse is evidence age, not severity.
