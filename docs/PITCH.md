# Odyssey: pitch, demo script and judge Q&A

Written for the team presenting at D3COY 1.0 (PS-01). Eight minutes of demo, then questions.

## The one-line claim

Odyssey is a national cyber threat early-warning system that runs on one laptop: it reads real threat intelligence,
finds which Indian critical-infrastructure operators are exposed, warns each of them in its own language, acts on its
own where the evidence is solid, and asks a person before anything consequential. Every number on screen is measured
and reproducible, and it has been ahead of CISA on real CVEs.

## Opening (30 s)

"In July 2024 one supplier's unpatched Jenkins server took about 300 Indian banks offline for days. The CVE was
public. Nobody connected it to who was exposed in time. Odyssey closes that gap."

## Demo script (about 8 minutes)

Before you start: run `scripts\demo_reset.ps1` ten minutes earlier, open http://127.0.0.1:5173, hard-refresh.

1. **Now (60 s).** "A suspected compromise needs you now." Point at the 6-hour CERT-In countdown, the one black
   action, the map of India. Click *Why this warning?*: the clocks that apply, the AI brief, then *Why this score*
   (Bayesian 98.7%, the three-source version check) and *How it unfolded* (warned 12 days before disclosure). Close.
2. **Needs your decision (30 s).** Approve one proposal: notices go out in Marathi, Gujarati, Hindi. "Odyssey proposes;
   a person approves anything consequential."
3. **Live (2 min).** The pipeline stage by stage. Start the *Full intrusion* drill and keep talking: scanning surge,
   implant beacon, lateral movement caught in order in about 30 seconds; an incident case opens on its own; the
   host's warnings are re-scored to suspected compromise with a fresh clock; the regulator report waits for you.
   Show the real feeds fresh and the new CVEs taken in from NVD since the last check.
4. **SOC → Cases (45 s).** CASE-0001: *Start response*, tick two playbook steps, add a note. The header figures move.
5. **Intel (60 s).** What is under attack and the exposure heatmap; *Risk plan*: 93 changes remove half of the
   national risk, 205 remove 80%; *Advisories*: the real CISA Siemens WinCC advisory, 13 assets at 7 operators,
   version ranges parsed; then the hostile advisory, blocked by the guard with the deterministic layer still working.
6. **Organisations (45 s).** Vidyut Grid West Corp opens on its threat map: hover the VPN gateway (compromised, calling a real QakBot C2), the HTTPS port under real attack pressure, the Ivanti scanning surge; then what outsiders see, its suppliers, its Marathi inbox. "Country threat maps draw arcs between nations; this is the same idea per operator, every line with its source."
7. **Proof (60 s).** Eight claims, each with its evidence; press *Run them now* (103 checks, about two minutes,
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
   and sector CSIRT routing, supplier fan-out, 22 Indian languages with validated translation.
5. **Trust by construction.** Hash-chained audit trail, REAL/SIM labels everywhere, a test bench you can re-run on
   stage, 0 cloud calls.

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
  obligations, warns in the operator's language, and proves its lead time.
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
