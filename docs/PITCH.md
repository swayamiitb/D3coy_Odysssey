# Odyssey: pitch, demo script and judge Q&A

Written for the team presenting at D3COY 1.0 (PS-01). About nine minutes of demo, then questions.

## The one-line claim

Odyssey is a national cyber threat early-warning system that runs on one laptop: it reads real threat intelligence,
finds which Indian critical-infrastructure operators are exposed, warns each of them in its own language, acts on its
own where the evidence is solid, and asks a person before anything consequential. Every number on screen is measured
and reproducible, and it has been ahead of CISA on real CVEs.

## Opening (30 s)

"In July 2024 one supplier's unpatched Jenkins server took about 300 Indian banks offline for days. The CVE was
public. Nobody connected it to who was exposed in time. Odyssey closes that gap."

## Demo script (about nine minutes)

Before you start: run `scripts\demo_reset.ps1` ten minutes earlier, open http://127.0.0.1:5173, hard-refresh. Run the
brand scan for the term IRCTC once (Intel → Threats → *Brand and social watch*, 10 to 25 s on the network) so its hits
are on screen, and run the consented scan of the portal once (Intel → Threats → *Attack surface, with consent*) so the
grade is there; both are stored and shown again without a rescan.

1. **Now (60 s).** "A suspected compromise needs you now." Point at the 6-hour CERT-In countdown, the one black
   action, the map of India. Click *Why this warning?*: the clocks that apply, the AI brief, then *Why this score*
   (Bayesian 98.7%, the three-source version check) and *How it unfolded* (warned 12 days before disclosure). Close.
2. **Needs your decision (30 s).** Approve one proposal: notices go out in Marathi, Gujarati, Hindi. "Odyssey proposes;
   a person approves anything consequential."
3. **Live (3 min).** The pipeline stage by stage. Start the *Full intrusion* drill and keep talking: scanning surge,
   implant beacon, lateral movement caught in order in about 30 seconds; an incident case opens on its own; the
   host's warnings are re-scored to suspected compromise with a fresh clock; the regulator report waits for you.
   Show the real feeds fresh and the new CVEs taken in from NVD since the last check.
   Then *Odyssey in action on a real app*: scroll up to *A real app, protected*. The CityPower portal is a real web
   application behind the Odyssey agent; keep the Ops Console (http://127.0.0.1:8090) open beside it (your Slack or
   Discord, once its URL is in). Flip *Block inline*, press *Run all attacks*: real SQLi, XSS, traversal,
   command-injection, scanning and brute-force requests over HTTP; 45/45 caught, 45/45 dropped with 403, 0 false
   positives, about 15 ms each, while the legitimate customer keeps browsing. The block proposal and the incident case
   appear, and every alert lands in the console as a card as it happens. "The same engine, on your traffic, telling
   your team."
4. **SOC → Cases (45 s).** CASE-0001: *Start response*, tick two playbook steps, add a note. The header figures move.
5. **Intel (60 s).** What is under attack and the exposure heatmap; *Risk plan*: 93 changes remove half of the
   national risk, 205 remove 80%; *Advisories*: the real CISA Siemens WinCC advisory, 13 assets at 7 operators,
   version ranges parsed; then the hostile advisory, blocked by the guard with the deterministic layer still working.
   Then *Graph* (40 s): the intelligence graph, every entity and how they connect, breathing. Hover the QakBot C2
   (a real Feodo indicator) and the groups ATT&CK records using that family light up, labelled "overlap, not
   attribution"; click Ivanti Connect Secure for its evidence card; press *Vidyut Grid West Corp* to put one operator
   at the centre. Back on *Overview*, *Risk lists and STIX*: the same intelligence as CSV for a firewall or SIEM and
   as a STIX 2.1 bundle. "This is what a TIP is recognised by, drawn from our own record, with its source on every line."
   Then, 30 s, what a partner brings in and what you set a rule on. *Indicators*: paste the partner indicator list
   (the demo text: a QakBot C2 address, our own VPN gateway, a look-alike domain, a CVE id) and press *Import*. In a
   second or two it says what matched and where: the QakBot C2 against the C2 sightings and the live flows, our own
   VPN gateway against the constituency's assets, each with its enrichment from Feodo, DShield and KEV. "Your
   indicators, matched against our own record in seconds, and pulled back by TAXII." Back on *Graph*, press *Watch*
   on the FortiOS card (the FortiGate firmware) and start the *Mass scanning* drill from Live: within 15 s the watch
   fires on the fresh evidence, shows as a detection, and lands in the console as a card. Under *Threats*, *Brand and
   social watch*: the term IRCTC, with real look-alike certificates, URLs and mentions from public sources, each
   scored and its source named (if crt.sh says rate-limited, say so; the row shows it). Then *Attack surface, with
   consent*: the CityPower portal, our own, scores 29, grade F: plain HTTP, open SSH and SMB ports, no CSP, an exposed
   OpenAPI document, a FastAPI fingerprint, each with a fix. "It scans only what you own and prove you own; anything
   else it refuses, and says why."
   Then, 40 s, *Disaster alerts (SACHET)*: NDMA's national alert feed, public domain, read live and labelled REAL,
   with the real alerts of the last hours on our operators' states (this morning: 100 alerts, 99 with a state, 80 on
   our operators, most of them from Andhra Pradesh SDMA), each row with the basis of its state inference ("sender
   office: IMD Amaravati", "district named: Krishna") and its confidence. "When an operator goes dark, the first
   question is: weather or attack? Now the disaster alert sits next to the cyber warnings, and the graph draws it on
   the operator." Press *Run the CAP red-team*: ten hostile CAP messages at Odyssey's own ingest on loopback, an XXE
   pointed at a planted secret, billion laughs, a forged sender, a replay, a stale alert, a malformed body, 3 MB, a
   stored script, a flood of 40; 10 of 10 handled in well under a second, the planted secret never leaks, and the one
   legitimate alert is accepted. "An early-warning system has to defend its own inputs. Nothing was sent to NDMA; what
   goes out is SACHET-compatible CAP, not a SACHET message."
6. **Organisations (45 s).** Vidyut Grid West Corp opens on its threat map: hover the VPN gateway (compromised, calling a real QakBot C2), the HTTPS port under real attack pressure, the Ivanti scanning surge; then what outsiders see, its suppliers, its Marathi inbox. "Country threat maps draw arcs between nations; this is the same idea per operator, every line with its source."
7. **Proof (60 s).** Eight claims, each with its evidence; press *Run them now* (135 checks, about two minutes,
   let it run while you take questions); *How it works*: six steps, the model table, the open formula.
8. **Close (20 s).** "Real data, measured claims, a human in the loop, zero cloud calls, and it runs on this laptop."

## What makes it class-apart (say these, in this order)

1. **Evidence decides, models explain.** Version-verified exposure from three sources; a scoring formula you can
   read; an SSVC decision path; AI only writes briefs, and every sentence is fact-checked or withheld.
2. **Ahead of the threat, measured honestly.** Day-0 forecast tested out-of-time (61% of later-exploited CVEs caught
   while flagging 2%); lead over CISA KEV reported on real signals only (median 20.5 days, up to 42).
3. **It runs, and it adapts.** Detectors every 5 seconds, real feeds every 15 minutes (5 when something is happening), new
   CVEs taken in live, attack drills anyone can start, live re-scoring, cases that open themselves, and thresholds that
   re-derive themselves from analysts' decisions, within bounds, with every change audited.
4. **Built for India.** CERT-In Blueprint deadlines, the 6-hour incident clock, RBI DAKSH, SEBI CSCRF, DPDP, NCIIPC
   and sector CSIRT routing, supplier fan-out, 22 Indian languages with validated translation, and India's SACHET
   disaster alerts read alongside the cyber record (weather or attack?), with warnings out in SACHET-compatible CAP.
5. **Trust by construction.** Hash-chained audit trail, REAL/SIM labels everywhere, a test bench you can re-run on
   stage, 0 cloud calls.
6. **One connected, breathing picture.** The intelligence graph links every entity in the record and decays with
   evidence age; threat groups are ATT&CK overlap, never attribution; the same picture leaves as risk lists, STIX and
   TAXII, can be replayed as it stood at nine earlier instants, takes a partner's indicators in and matches them against
   our own record, and fires the rules an analyst sets on any entity in it.

## Judge questions and the honest answers

- **"The organisations and sensors are simulated."** Yes, labelled SIM on every screen. The CVEs, advisories, attack
  telemetry (DShield), C2 lists and feeds are real; the lead over KEV is reported on real signals only.
- **"Forecast precision is 5%."** Exploitation is rare (0.16% of CVEs). That is why forecasts are proposals for a
  person, never automatic notices, and why we report recall at a fixed alert budget against CVSS and EPSS.
- **"8B models hallucinate."** They never decide. The engine decides scores, tiers and deadlines; the model writes
  the brief, and 22 of 23 briefs passed the fact validator; the failure is withheld, not shown.
- **"Why no chat assistant?"** We built one, measured it, and removed it: not reliable enough to put in front of a
  national CERT. Everything it could answer is on a screen with its evidence.
- **"How is this different from a TIP or a vulnerability scanner?"** A scanner finds flaws; a TIP stores indicators.
  Odyssey connects real threat intelligence to who is exposed in the country, decides urgency against Indian
  obligations, warns in the operator's language, and proves its lead time. It also has what a TIP is recognised by:
  an intelligence graph with an evidence card per entity and replay, watchlists and rules on it, threat-group context
  from ATT&CK without attribution, a partner's indicators in and matched, and risk lists, STIX and TAXII for the tools
  you already run. `docs/TIP_GAP_AUDIT.md` sets it against CloudSEK, Recorded Future and the rest of the field, and
  says what stays out of scope (dark web, scanning of networks we do not own, takedowns) and why.
- **"Can it take our indicators?"** Yes. Paste them as text, CSV or a STIX 2.1 bundle on Intel → Indicators; IPv4
  addresses, domains, URLs, hashes and CVE ids are matched in seconds against our own flows, C2 sightings, the shield's
  attackers, our assets and domains and their look-alikes, and the exposure record, enriched from Feodo, DShield,
  OpenPhish and KEV, and from then on matched live on every tick. They come back as CSV, STIX, or by TAXII 2.1 pull
  from `/taxii2/` (three collections: graph, indicators, vulnerabilities; a bearer token if you set one).
- **"Do you scan real companies?"** No. The attack-surface check is consent-gated in code to systems the operator
  owns: a loopback or private address, or an app the Odyssey agent has announced; a public address is refused with the
  reason. GET and HEAD only, at most 40 requests, a cooldown per target. Everything about other organisations comes
  from passive public sources: the feeds, certificate transparency, URL lists, news and public social feeds. Nothing
  touches them, and a brand hit is a scored match of a term, not a finding of abuse.
- **"Is this connected to SACHET?"** No, and we do not say it is. Odyssey reads SACHET's public-domain CAP feed,
  read-only, the way it reads NVD or KEV; nothing is sent to NDMA. Its own warnings are written in the same CAP 1.2
  format SACHET publishes, status Exercise, labelled "SACHET-compatible" in the message itself, so an authorised agency
  such as CERT-In could route them with configuration rather than redevelopment; that routing is theirs to decide, not
  ours. The CAP red-team fires only at Odyssey's own loopback endpoint. Most SACHET alerts are district-level, so the
  state we infer carries its basis and a confidence on the row and is not always right. Bhashini is not used; the
  translator stays local.
- **"Is anything here connected to something real?"** Yes. A real web application runs behind the Odyssey agent and
  is attacked by a real HTTP client over the wire, and the alerts leave the laptop by real webhooks: Slack, Discord,
  Teams, e-mail or your own app (the Ops Console in the demo). The organisations and sensors stay simulated and
  labelled.
- **"Can it scale to thousands of operators?"** The engine is SQLite and vectorised scoring; a rebuild of 44,000
  asset × CVE assessments takes 90 seconds on a laptop. The design is event-sourced, so a server deployment adds
  workers, not architecture.
- **"What would you build next?"** Real operator onboarding (inventory connectors), the national supplier graph from
  procurement data, and sector-specific OT telemetry.

## If something goes wrong on stage

- API not responding: `powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1` (about a minute).
- A brief shows "writing…" for long: the model is cold; move on, it will appear. Pre-computed briefs cover the
  walk-through.
- Network down: the feeds show "offline, serving the snapshot"; everything else works. Say so; it is a feature.
- Portal or Ops Console down: `start_all.ps1` brings them back; the shield card says "agent silent" until the portal
  is up, and the channels row says "failing" until the console is.
- Brand watch slow or a source offline: the sources row names which one (crt.sh rate-limits for a minute at a time);
  the stored hits still show. Say so; the row is the honest state of a public source.
- Consented scan refused: the portal is down, or the agent has not re-announced it since the restart (up to 10 s), or
  the 60 s cooldown is running. Wait, or show the stored scan; the refusal reason on screen is the gate working.
- SACHET feed offline: the panel says "offline, serving the snapshot" and shows the 100 real alerts saved on 1 Nov;
  the state inference, the operator match, the CAP download and the red-team work without the network. Say so; it is
  the same honesty as the other feeds.
