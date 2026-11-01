# Odyssey: 50 judge questions and the answers

Prep sheet for the team presenting at D3COY 1.0 (PS-01). Medium (M) to hard (H) questions a judge is likely to ask,
with answers short enough to say aloud in 20 to 40 seconds. Every number is from `docs/MODEL_CARD.md`,
`docs/PS_COVERAGE.md`, `docs/PITCH.md` or the scoring config; none is rounded up.

**Three rules when answering.** Lead with the plain answer, then one number. Say SIM before they find it. When a
question lands on a real limit, name the limit and the next step; do not defend it.

---

## The idea

**1. (M) CERT-In already publishes advisories. What is new here?**
CERT-In tells everyone about a flaw. Odyssey tells each operator whether the flaw touches the exact version it runs,
how urgent it is against Indian deadlines, and drafts the notice in its own language for a person to approve. The gap
is connecting intelligence to exposure, which is where C-Edge failed: the Jenkins CVE was public for six months.

**2. (M) How is this different from a scanner like Tenable or Qualys?**
A scanner looks inside one network for flaws. Odyssey works nationally, from threat intelligence inward: which
operators run what is being exploited, ranked by evidence and Indian obligations, with lead time measured. A
scanner's inventory export is a good input to Odyssey, not a competitor.

**3. (H) And from a threat-intelligence platform like CloudSEK, Recorded Future or OpenCTI?**
A TIP stores and enriches indicators; Odyssey adds exposure, a score, a deadline and an action per operator. It also
has what a TIP is known for: the intelligence graph, entity cards, STIX 2.1 and TAXII 2.1, indicator import and
watchlists. Our gap audit against CloudSEK and Recorded Future is in `docs/TIP_GAP_AUDIT.md`, with dark web,
takedowns and scanning of others' networks out of scope by rule.

**4. (M) Who is the user?**
A national or sector CERT duty officer: CERT-In, a sector CSIRT, NCIIPC. The Now screen answers their one question,
what needs me. Downstream, each operator's security team receives the notice, in its language, with the fix and the
clock.

**5. (H) You call it early warning, but KEV only lists a flaw after it is exploited.**
KEV is one input, not the warning. The early signals are the day-0 forecast, a vendor saying "exploited in the wild",
and scanning surges on the decoy grid. Measured on real signals only, Odyssey acted a median 20.5 days before CISA
listed the flaw, up to 42.4.

## Data

**6. (H) Your operators are simulated. Isn't the demo fake?**
The 15 operators, their inventory, the decoy grid and the firewall flows are simulated, and every screen says SIM.
Everything public is real: 82,104 CVEs of 2026, KEV, SSVC, EPSS, CISA advisories, DShield, Feodo, OpenPhish and
SACHET. No real operator hands its inventory to a hackathon; the inventory is the one input a deployment plugs in.

**7. (M) How would you get a real operator's inventory?**
Through connectors: an asset-register or CMDB export, SBOMs in CycloneDX or SPDX, or the operator's own scanner
output. Odyssey needs four fields per system: product, version, exposure (internet, DMZ, internal) and a criticality
tier. That is the first thing we would build next.

**8. (H) NVD now labels only 21% of new CVEs with product and version. How do you match at all?**
Three sources vote: NVD's CPE data, the vendor's own affected and unaffected versions, and the advisory text, where
the model extracts the product and the version ranges are parsed. Versions are compared vendor-aware. When the
sources disagree the warning is marked disputed; on the real Ivanti case there were 0 false "affected".

**9. (M) What happens if a feed is down, on stage or in production?**
Every feed is snapshot-backed and shows its state: fresh, snapshot or offline. Feeds are re-read every 15 minutes,
every 5 when something is happening. The whole demo runs with the network unplugged.

**10. (H) Can someone poison a feed to trigger false alarms?**
Each source has an Admiralty reliability grade, A to F, and confidence rises only when independent origins agree.
Only strong evidence sets a likelihood floor: KEV, an SSVC "active" verdict, exploits on two or more decoys, or the
vendor's own statement. Advisory text passes a prompt-injection guard, inbound CAP passes an eight-step guard, and
every line carries its provenance in a hash-chained trail.

**11. (M) Why only 13 sources?**
They were chosen for decision value: vulnerability databases, advisories, attack telemetry and indicators. The
console also bundles Exploit-DB, ransomware.live, Have I Been Pwned, GitHub advisories, Tor exits, Spamhaus DROP
and Emerging Threats. A new source is a connector plus an Admiralty grade; the scoring does not change.

**12. (H) Do you use dark-web data?**
Indirectly, from public aggregators: ransomware.live reads the leak sites (565 Indian victims bundled) and Have I
Been Pwned covers breach dumps. Direct forum collection needs legal cover and an authorised agency, so it is a named
plug-in point, not something a student laptop should do.

## Scoring

**13. (M) Walk us through the score.**
Risk = 100 × Relevance × Importance × (0.55 Likelihood + 0.30 Severity + 0.15 Evidence), capped at 100. Relevance
asks whether this exact version is affected; Importance is criticality, exposure and blast radius; Likelihood comes
from evidence in rank order; Severity from SSVC technical impact; Evidence from source grades. The Ivanti receipt on
slide 7 adds up by hand to 83.3.

**14. (H) Why 55, 30 and 15? Aren't those arbitrary?**
They are a stated policy, in a config file, not hidden in code, and the file's hash is stored in every alert so any
change is auditable and replayable. Likelihood dominates because exploitation evidence is what predicts harm: on 110
real exploited CVEs, EPSS alone missed 49% and CVSS 9+ alone missed 53%. We have not calibrated the weights on Indian
incident data; with CERT-In's history that is the first thing we would tune.

**15. (M) What is the difference between risk and confidence?**
Risk is how bad and how soon; confidence is how sure we are of the facts behind it. Confidence comes from Admiralty
source grades and agreement between independent sources. A high-risk, low-confidence warning goes to an analyst as a
proposal, not straight to the operator.

**16. (M) Why SSVC instead of CVSS?**
CVSS measures how bad a flaw could be in general; SSVC, CISA's decision method, asks what to do: Act, Attend or
Track, from exploitation, automatability, impact, exposure and mission. CVSS is kept only as corroboration, because
alone it misses about half of what gets exploited.

**17. (M) Where do the deadlines come from?**
From the CERT-In Blueprint's indicative timelines: 12 hours for a known-exploited flaw on an internet-facing or
crown-jewel system, then 24, 72, 120 and 336 hours by tier. A suspected compromise gets the 6-hour CERT-In reporting
clock from the April 2022 Directions. RBI, SEBI, DPDP and NCIIPC clocks are shown where they apply.

**18. (M) What makes Relevance zero?**
The installed version is outside the affected ranges, or the vendor lists it as fixed. Then the risk is zero and the
host is shown as safe, which matters as much as the alarms: patched hosts never reach the queue.

**19. (H) Two warnings both score 100. Which goes first?**
The score is capped, so ordering at the top comes from the decision, not the number: a suspected compromise outranks
a Critical, and within a tier the earlier deadline goes first. That is why the Now screen leads with one warning and
its countdown, not a list of hundreds.

**20. (M) Does old evidence keep counting?**
No. Sensor evidence, decoy surges and C2 sightings lose weight with age and stop counting after their window.
Catalogue facts like a KEV listing or a vendor statement never decay, because they stay true.

**21. (H) Can an analyst change a score?**
Not the number; it is reproducible from the evidence and the config hash. The analyst acts on the warning:
acknowledge, mark false positive, reject with a reason. Those decisions re-derive the detector thresholds within
fixed bounds, and every change is in the audit trail.

**22. (M) What is the Bayesian model for?**
It estimates the chance a host is already compromised, from exposure, exploitation, reachability and live telemetry,
with the day-0 forecast as its prior. When a C2 beacon is confirmed on a host, every warning on it is re-decided at
once and the 6-hour CERT-In clock starts.

## AI

**23. (M) If rules decide, where is the AI?**
Reading and explaining: a security LLM reads advisories and writes every brief; SecureBERT extracts entities and
relates threats; classic ML predicts root cause and the day-0 forecast; detectors find surges, beacons and anomalies;
IndicTrans2 translates into 22 languages. Nine models, one job each, none of them sets a score, a tier or a deadline.

**24. (H) Small LLMs hallucinate. Why trust the briefs?**
Because nothing unchecked is shown. Every number, version, deadline and authority in a brief is checked against the
facts; a failing sentence is withheld, never displayed. 22 of 23 briefs passed, 19 on the first attempt, and the one
that failed was withheld.

**25. (M) Why MiST 8B and not Llama or GPT-4?**
We measured: MiST 8B had the best product extraction among the security models we tested (77.5%), was the fastest at
about 1.7 seconds per item, and is Apache-2.0. A cloud model was ruled out by design, see the next question.

**26. (H) Why local and under 8 billion parameters?**
A national early-warning record is a map of every operator's weaknesses; it should not leave the building. Everything
runs on one RTX 4070 laptop with 0 cloud calls, which also means no per-call cost and no dependency on a foreign API
during an incident. Small models are enough because the model explains and the engine decides.

**27. (M) What if the GPU or the model fails?**
Scoring, tiers, deadlines, detectors and translation run on the CPU and do not need the LLM. Only the brief waits; the
warning, its score and its actions still go out. Briefs for the demo are pre-generated and cached.

**28. (H) How is the day-0 forecast built, and how do you avoid leakage?**
A logistic regression on what is known the day a CVE is published: the description, the CNA's CVSS and CWE, the
vendor, and that vendor's KEV history strictly before publication. KEV, SSVC, EPSS and NVD reference tags are never
used because they arrive later. Trained on 2021 to 2025, frozen on 31 July, scored on August to October.

**29. (H) Its precision is 5%. Isn't that useless?**
Exploitation is rare: 0.16% of CVEs. At a 2% alert budget it caught 61.1% of the CVEs CISA later listed, where CVSS
9+ at the same budget caught 16.7%, and it is calibrated (26.7% forecast, 26.7% observed). That is why forecasts are
proposals for a person, never automatic notices.

**30. (H) How do you know a Marathi or Santali translation is correct?**
Only the already-validated English brief is translated, so the translator cannot add facts. A sentence ships only if
every CVE id, version, hostname, date and name survives exactly, no stray English appears, and the script is clean.
127 of 132 test sentences passed across 22 languages; Santali is weakest at 3 of 6, and failing lines fall back to
English with a "translation withheld" badge.

**31. (H) An attacker hides instructions inside an advisory. What happens?**
A DeBERTa-v3 classifier plus rules screens advisory text first: 5 of 5 hostile advisories caught, 0 of 5 benign ones
blocked. Even if one got through, the model cannot change a score, a tier or a deadline, so the deterministic layer
keeps working. We show this live on stage.

**32. (M) Why is there no chat assistant?**
We built one, measured it and removed it: it was not reliable enough to put in front of a national CERT. Everything it
could answer is on a screen, with its evidence one click away.

## Evidence

**33. (H) Your rules flag 110 of 110 exploited CVEs. Isn't that circular?**
Yes, partly, and we say so on the slide: KEV is one of our inputs. The comparison shows that a single public score,
EPSS or CVSS, misses about half. The honest test is the out-of-time forecast: frozen in July, 61.1% of later-exploited
CVEs caught while flagging 2%.

**34. (H) A 20.5-day median lead from four CVEs is not statistically meaningful.**
Agreed, four is small, and we report it as measured, not as a rate. It counts real signals only, and leads that exist
only because monitoring started on 1 August are reported apart. The stronger evidence is the forecast: 44 of 72
later-listed CVEs, ROC AUC 0.926 out of time.

**35. (H) The shield caught 45 of 45 attacks from your own red team. Of course it did.**
Fair: it is a regression test of the attack families, with real evasion (URL, double-URL, entity and base64 encoding,
SQL comments), sent over the wire to a real app, plus 0 false positives on benign traffic. It is a signature engine
in the class of ModSecurity CRS, not a claim against a skilled adversary. The next step is the OWASP CRS test corpora
and an external pen test.

**36. (M) Has it been tested on a real incident?**
The real CISA WinCC advisory runs end to end: 13 assets at 7 operators found, scored and notified. On real CVEs,
Odyssey acted before CISA's KEV listing on four. The 12-day pre-disclosure warning in the demo comes from the
simulated decoy grid and is labelled so.

**37. (M) What does "measured" mean for your numbers?**
Each number is recomputed from the record on the Proof page, and the test bench re-runs on stage: 221 engine tests,
26 of 26 product flows through the API, 25 of 26 browser steps. Models were chosen by measurement on 2026 CVEs, newer
than any model's training data.

**38. (M) How fast is it?**
Detectors run every 5 seconds; a scanning surge or an implant beacon is caught in one tick. A new NVD CVE naming a
constituency product is matched, scored and forecast within seconds. A full rebuild of 44,000 asset × CVE
assessments takes about 90 seconds on the laptop. The shield decides inline in about 15 ms.

## Security, law and privacy

**39. (H) Odyssey holds every operator's weaknesses. Isn't it the perfect target?**
Yes, which is why it is on-premise with 0 cloud calls, evidence is defanged, the TAXII server is read-only with a
bearer token, every inbound channel is guarded, and the audit trail is hash-chained. A production deployment adds
role-based access, encryption at rest and network segmentation; we have not built those for the prototype.

**40. (M) Why a hash-chained audit trail?**
So nobody, including an insider, can quietly change what was known, decided or sent, and when. Every score can be
recomputed from the ledger and the config hash, which matters when a regulator asks why a notice went out late.

**41. (H) Do you scan real companies? Is that legal?**
No. The attack-surface check is consent-gated in code: it runs only against loopback, private addresses or an app the
Odyssey agent has announced, with GET and HEAD only and at most 40 requests. Everything about other organisations
comes from passive public sources. The red-team agent refuses any public target before sending a byte.

**42. (M) What about personal data and the DPDP Act?**
The record is about systems, not people: products, versions, exposure, indicators. The breach feed carries breach
metadata (service, date, account count), not personal records. DPDP's 72-hour breach clock is one of the obligations
Odyssey tracks for operators.

**43. (H) Do you attribute attacks to countries or groups?**
No. Threat groups come from the MITRE ATT&CK record as overlap of malware and techniques, and every node, card and
STIX object says "overlap, not attribution". Attribution is a political act for an authorised agency, not a scoring
input.

**44. (M) Are you connected to SACHET?**
No, and we do not say we are. Odyssey reads SACHET's public CAP feed read-only, to ask "weather or attack?" when an
operator goes dark, and writes its own warnings as SACHET-compatible CAP 1.2 marked Exercise. Routing them through an
authorised agency would be configuration, not redevelopment.

## Deployment and the future

**45. (H) Will it scale to thousands of operators?**
The engine is SQLite with vectorised scoring, and 44,000 assessments rebuild in about 90 seconds on a laptop. The
design is event-sourced, so a server deployment adds workers and a server database, not new architecture. We have
not load-tested at national scale yet.

**46. (H) How would CERT-In actually deploy this?**
On-premise at the CERT, with operators onboarded through inventory connectors, the same public feeds, and the
alerts leaving by the channels a SOC already uses: STIX, TAXII, webhooks to Slack, Teams or e-mail, and CAP. The
duty officer approves; operators receive notices in their language.

**47. (M) What does it cost to run?**
The models are open-weight (Apache-2.0 and MIT), the data is public, and it runs on one RTX 4070 laptop with no
per-call API fees. A server deployment needs commodity GPU hardware; we have not priced a national rollout.

**48. (M) Why does the intelligence graph matter?**
It shows relationships a list hides: which operators share a vulnerable product, which C2 a compromised host calls,
which techniques a campaign uses. Watchlists fire on changes in it, and the same graph leaves as a STIX bundle for
other tools.

**49. (M) What would you build next?**
Inventory connectors for real operators, a supplier graph from procurement data (the C-Edge lesson), sector OT
telemetry for power, water and transport, live CERT-In and NCIIPC feeds, and calibrating the weights on Indian
incident history.

**50. (H) What is the biggest weakness of Odyssey today?**
The constituency is simulated, so the operator-side numbers are demonstrations, not field results. The lead-time
sample is small, the shield is a signature engine, and the weights are policy, not calibrated. Each of these is
stated on our slides, and each has a named next step.
