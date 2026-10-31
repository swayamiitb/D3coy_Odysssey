# Commercial AI Threat-Intelligence Platforms: How They Turn Raw Threat Data into Prioritised, Explained, Actionable Intelligence (as of 31 Oct 2026)

Labels used throughout:
- **[Docs]** is vendor technical documentation describing how a mechanism works. It is generally reliable about mechanics.
- **[Vendor claim]** is a marketing or press-release outcome claim that has not been independently verified.
- **[Independent]** is an analyst firm, survey, academic paper or independent press.
- **[Secondary]** is a third-party integration doc, a reseller page or a search-snippet-only source. Treat it with more caution.

Dates are given wherever a fact may be stale.

---

## 1. Recorded Future: Intelligence Graph, risk rules with evidence strings, criticality, Recorded Future AI, and how scores are explained

### Takeaway
Recorded Future's score is the clearest emulable pattern in the market. Each entity type has its own set of named **risk rules**. Each triggered rule carries a **criticality** (0–4) and an **evidence string**. The 0–99 score's **base** is set by the most critical rule that fired, so the explanation is simply the list of rules that fired, with their evidence. Its 2025–2026 AI layer (AI Sessions, agentic "Autonomous Threat Operations") sits on top of the graph and does not replace this rule-based score.

### Cited Findings
**Score mechanics [Docs/Secondary]**
- The overall risk score is "a number between 0 and 99, determined by which rules are currently triggered." "The highest severity level associated with an indicator determines the base score": Very malicious = 90, Malicious = 65, Suspicious = 25, Unusual = 5. Risk rules "are assigned a level of severity, which factors into the overall risk score." — [Recorded Future browser extension page](https://www.recordedfuture.com/products/browser-extension/)
- The page does **not** say how additional rules push the score above the base. Third-party descriptions don't settle it either. — [Recorded Future browser extension page](https://www.recordedfuture.com/products/browser-extension/)
- Criticality table, as reproduced in the LogPoint integration docs. The page now redirects (403 on fetch), so this was read from a search snippet:

  | Label | Criticality | Score | Colour |
  |---|---|---|---|
  | Very Malicious | 4 | 90–99 | Red |
  | Malicious | 3 | 65–89 | Red |
  | Suspicious | 2 | 25–64 | Bright Yellow |
  | Unusual | 1 | 5–24 | Light Gray |
  | No current evidence of risk | 0 | — | — |

  — [LogPoint Recorded Future Intelligence Card docs](https://docs.logpoint.com/docs/recordedfuture/en/latest/intelligencecard.html) [Secondary]
- Each indicator type has its own distinct set of risk rules. — [Elastic Recorded Future integration](https://www.elastic.co/docs/reference/integrations/ti_recordedfuture) [Secondary]
- Criticality runs 0–4 for most entities and 0–5 for some rule-based nodes. — [Synapse Recorded Future power-up user guide](https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/storm-packages/synapse-recordedfuture/userguide.html) [Secondary]
- **Evidence strings:** each triggered rule carries a human-readable summary of the sightings that support it. The Elastic integration example records one sighting on one source, "ThreatFox Infrastructure Analysis", which identified a domain as possible C2 for CryptBot. A second example records a Bitdefender endpoint-telemetry detection. — [Elastic Recorded Future integration](https://www.elastic.co/docs/reference/integrations/ti_recordedfuture) [Secondary]
- Integrations expose a compact **RiskString** such as "4/52", meaning 4 of 52 possible rules triggered. — [Google SecOps SOAR Recorded Future integration](https://docs.cloud.google.com/chronicle/docs/soar/marketplace-integrations/recorded-future) [Secondary]
- Integrators tune thresholds. The Cortex XSOAR integration notes say the default "Suspicious" range changed from 5–64 to 25–64, which de-noises the "Unusual" band. Google SecOps SOAR also defaults its suspicious threshold to 25. — [Cortex XSOAR Recorded Future v2 integration](https://demisto.pan.dev/docs/reference/integrations/recorded-future-v2) and [Google SecOps SOAR integration](https://docs.cloud.google.com/chronicle/docs/soar/marketplace-integrations/recorded-future) [Secondary; I did not confirm which XSOAR page holds the exact note]
- **Free tier vs paid tier:** free "Express" users see the dynamic risk score and only the **top risk rule**. Paid users get "detailed context and evidence about each of the indicators." The extension scans pages, PDFs, and SIEM or vulnerability-scanner UIs for IPs, domains, URLs, hashes and CVEs. It ranks them by risk or overlays scores in place. — [Recorded Future browser extension page](https://www.recordedfuture.com/products/browser-extension/)
- **Intelligence Cards** summarise about 300 million threat-related entities. — [Recorded Future browser extension page](https://www.recordedfuture.com/products/browser-extension/) [Vendor claim]

**Intelligence Graph and data breadth**
- The Intelligence Graph "correlates signals across technical sources, dark web, open web, and adversary infrastructure", with Insikt Group adding human analysis. The current page does not list entity or relationship types. — [Recorded Future Intelligence Graph page](https://recordedfuture.com/platform/intelligence-graph) [Vendor claim]
- A search snippet attributed ">200 billion nodes" and ">1 million global sources" to Recorded Future pages. These figures did **not** appear on the page when fetched on 2026-10-31, so treat them as unverified. — [Recorded Future Intelligence Graph page](https://recordedfuture.com/platform/intelligence-graph)

**AI layer (2024–2026)**
- "AI Insights" (about 2024) generated quick summaries from large amounts of text and data. — [Recorded Future RSA blog](https://recordedfuture.com/blog/platform-innovations-to-drive-future-of-threat-intelligence) [Vendor claim]
- A March 2026 datasheet positions "Recorded Future AI" as extending the Intelligence Graph. **AI Sessions** lets analysts use natural language to query the graph and automate analysis and production. The vendor says it is not designed to answer queries unrelated to the Intelligence Graph, which means it is grounded and scope-limited by design. — [Recorded Future AI datasheet, March 2026](https://assets.recordedfuture.com/Datasheets/2026_0313%20-%20Recorded%20Future%20AI.pdf); [Recorded Future AI page](https://recordedfuture.com/platform/recorded-future-ai)
- The current Recorded Future AI page markets three things:
  - "Autonomous Threat Operations", which deploys intelligence across the stack "continuously, without manual steps"
  - "agentic processing", which turns new threat disclosures into detection signatures "in as little as 31 minutes" (attributed to Recorded Future R&D)
  - "100+ native integrations"

  It gives no false-positive or time-saved figures and states no limitations. — [Recorded Future AI page](https://recordedfuture.com/platform/recorded-future-ai) [Vendor claim]
- In its 2026 Forrester announcement, Recorded Future says it is building autonomous and agentic workflows "while preserving human control over consequential decisions." — [Recorded Future press release, Sep 2026](https://www.recordedfuture.com/newsroom/press-releases/recorded-future-leader-external-threat-intelligence-2026) [Vendor claim]

**Results and independent signal**
- Recorded Future was named a Leader in the Forrester Wave: External Threat Intelligence Service Providers, Q3 2026. It says it earned the top possible score on twelve criteria. — [Recorded Future press release, 17 Sep 2026](https://www.recordedfuture.com/newsroom/press-releases/recorded-future-leader-external-threat-intelligence-2026) [Vendor claim about an independent report]
- Recorded Future's own *2025 State of Threat Intelligence* survey (August 2025; 615 practitioners at firms with more than 1,000 employees) found these top complaints about TI:
  - 50%: difficulty judging whether reports are accurate and credible
  - 48%: poor integration
  - 46%: information overload
  - 46%: lack of context for their own environment
  - The top requested improvement was faster delivery (33%).

  — [Cybersecurity Dive, 12 Nov 2025](https://www.cybersecuritydive.com/news/threat-intelligence-customer-complaints-recorded-future/805300/) [Independent press reporting a vendor survey]
- Practitioner reviews on comparison sites mention false positives as a recurring complaint. These are anecdotal. — [PeerSpot comparison](https://www.peerspot.com/products/comparisons/ibm-x-force-exchange_vs_recorded-future_vs_usm-anywhere) [Secondary]

### Inferences
- The explanation **is** the score. Because the base equals the floor of the highest-criticality band, an analyst can always answer "why 72?": a criticality-3 rule fired, plus extra rules, and here is each rule's evidence string. This is easy to replicate with a few dozen hand-written rules over open feeds.
- Showing a ratio like "4/52" tells the analyst both how much evidence exists and how much was possible. That is a cheap but useful confidence cue.
- Re-tuning the Suspicious floor from 5 to 25 suggests the lowest band was producing noise. A prototype should keep "Unusual" non-alerting.

### Gaps
- I could not fetch Recorded Future's official support-portal article (login required) on how additional rules add points above the base, or on rule-level decay.
- I found no public, current list of Intelligence Graph entity and relationship types.
- I found no independent measurement of score precision.

---

## 2. Google Threat Intelligence (GTI) / Mandiant: Gemini, actor and campaign tracking, Threat Profiles, how relevance is surfaced

### Takeaway
Google separates the questions most cleanly:
- **Verdict:** is it bad?
- **Severity:** should I care?
- **Threat Score:** a 0–100 value derived from the two.
- **Relevance:** does it overlap my profile?
- **Priority:** relevance combined with severity.

It explains scores through a **Threat Score Explainer** ("open ledger of evidence") and a Gemini "**Tell me why?**" natural-language explanation. Relevance comes from a configurable **Threat Profile** (industries, regions, motivations). Since 2026, it also comes from a Gemini-built **Organization Profile** with citations, used in dark-web alerting.

### Cited Findings
**Indicator scoring and explanation [Docs]**
- **Verdict:** Malicious / Suspicious / Undetected / Benign / Unknown. Unknown is the default ("Data unavailable").
- **Severity:** High / Medium / Low / None. It answers "should you care about this indicator?"
- **Threat score:** 0 (completely benign) to 100 (highly malicious and severe).

  Mapping from verdict and severity to score:

  | Verdict + Severity | Threat score |
  |---|---|
  | Benign + None | 0 |
  | Undetected + None | 1 |
  | Suspicious + Low | 21 |
  | Suspicious + Medium | 25 |
  | Suspicious + High | 29 |
  | Malicious + Low | 30–59 |
  | Malicious + Medium | 60–79 |
  | Malicious + High | 80–100 |

  — [GTI Indicator Score docs](https://gtidocs.virustotal.com/docs/google-threat-intelligence-indicator-score)
- The Threat Score draws on the verdict, severity, Mandiant analyst intelligence, sandbox detonations and a separate **GTI Confidence Score**. — [GTI Indicator Score docs](https://gtidocs.virustotal.com/docs/google-threat-intelligence-indicator-score)
- Ten "explainability card" categories:
  1. Highest Impact Factor
  2. Human Verified Ground Truth
  3. Mitigating Factors
  4. Threat Intelligence
  5. Technical Evidence
  6. Tool Abuse
  7. Propagated Factors
  8. Collective Detections
  9. Machine Learning Models
  10. Historical Context

  — [GTI Indicator Score docs](https://gtidocs.virustotal.com/docs/google-threat-intelligence-indicator-score)
- The **Threat Score Explainer** card is described as an "open ledger of evidence." Analyst overrides are highlighted on the card. — [GTI Indicator Score docs](https://gtidocs.virustotal.com/docs/google-threat-intelligence-indicator-score)
- **Decay:** each signal has an expiration timestamp. Expired signals "age off" and are kept only in history. If the primary signal ages off, the score is recalculated and can drop to Suspicious or Undetected. — [GTI Indicator Score docs](https://gtidocs.virustotal.com/docs/google-threat-intelligence-indicator-score)
- The object API exposes `gti_assessment` with `verdict`, `severity`, `threat_score` and `contributing_factors`. — [GTI file object reference](https://gtidocs.virustotal.com/docs/file-object); [migration guide](https://gtidocs.virustotal.com/docs/migrate-from-virustotal)

**Relevance to the customer's environment in SecOps (Applied Threat Intelligence) [Docs]**
- ATI priority models:
  - **Active Breach:** IoCs Mandiant observed in active or past compromises, with Malicious verdict and High severity.
  - **High:** IoCs tied to GTI-identified actors or malware but not seen in Mandiant IR. Network IoCs match outbound traffic only.
  - **Medium:** IoCs with Malicious verdict and High severity, without IR sightings.
  - **Inbound IP authentication:** IPs authenticating inbound to local infrastructure.
- Model features: "GTI Verdict, GTI Severity, Active IR, Prevalence, Attribution, Blocked, Network Direction."
- Google **recommends keeping Medium rule packs in non-alerting mode** because of potential alert volume.

  — [Google SecOps ATI prioritization overview](https://docs.cloud.google.com/chronicle/docs/detection/ati-prioritization)

**Threat Profiles [Docs]**
- Profiles are configured by target industries and target regions. Advanced options add source regions, malware roles and actor motivations. A time window of "a minimum of 90 days is required" for the best recommendations. — [GTI Manage Threat Profiles](https://gtidocs.virustotal.com/docs/manage-threat-profiles)
- The system recommends Threat Actors, Campaigns, Malware & Tools, IoC Collections, Vulnerabilities and Reports. It matches on how many configured categories an object hits, with a cap per object type. — [GTI Manage Threat Profiles](https://gtidocs.virustotal.com/docs/manage-threat-profiles)
- The **Threat Map** plots **Relevance** on the X-axis (a "configuration dependent metric" comparing the threat with the profile dimensions) against **Global Frequency** on the Y-axis (submission and lookup prevalence). — [GTI Manage Threat Profiles](https://gtidocs.virustotal.com/docs/manage-threat-profiles)
- A "**Tell me why?**" button "generates a natural language explanation of why the object was linked to the Threat Profile." Users can rate the explanation, ask follow-ups, or move to the agentic tool. — [GTI Manage Threat Profiles](https://gtidocs.virustotal.com/docs/manage-threat-profiles)
- Alerting comes in two forms:
  - Daily or weekly email **digests**, sent at 09:00 UTC
  - A real-time **IoC Stream** of new indicators linked to profile objects

  An Activity Timeline logs changes such as new detection rules. Deleted recommendations regenerate the next day if they still match; adding them to the profile confirms them. — [GTI Manage Threat Profiles](https://gtidocs.virustotal.com/docs/manage-threat-profiles)
- Threat Profiles added "further relevance" in an October 2024 changelog entry. — [GTI changelog, 7 Oct 2024](https://gtidocs.virustotal.com/changelog/07-october-2024)
- Search snippets describe a separate **Relevance Score** (overlap with industry, geography and software) and a **Priority** that combines Relevance with Severity. I could not fetch the page body to confirm. — [GTI Threat Landscape AI recommendations](https://gtidocs.virustotal.com/docs/threat-landscape-ai-recommendations) [Secondary/snippet]
- A community post (17 Jul 2026) announces quarterly-updated **Country & Industry Profiles**. — [Google Cloud Community post](https://security.googlecloudcommunity.com/googletimondays-92/google-threat-intelligence-introduces-country-industry-profiles-7929) [Secondary]

**Gemini Organization Profile and dark-web Relevance System (2026)**
- The **Relevance System** is described as "an advanced AI-driven engine" that turns dark-web noise into "high-fidelity signal" using frontline intelligence plus knowledge of your organization.
  - It is in **Beta** ("My Landscape").
  - Google advises running DTM and ASM in parallel.
  - The Organization Profile has citations, versioning and editing.
  - It includes "Threat Scenarios" (system-inherited plus custom).
  - Roles are split between alert admins (profile and thresholds) and users (triage plus feedback).

  — [GTI Dark Web Intel docs](https://gtidocs.virustotal.com/docs/dark-web-intel) [Docs]
- How it works, per The Register (23 Mar 2026; launched in public preview around RSAC 2026):
  - The customer confirms its identity and Gemini builds an org profile "within a couple of minutes." The profile covers environment, business operations, VIPs, brands and technology, drawn from open sources **with citations**.
  - Agents tag dark-web data and run a **vector comparison** against the profile.
  - Alerts cover the previous 7 days and are ranked by relevance, i.e. whether an actor is discussing the organisation's own elements.

  — [The Register, 23 Mar 2026](https://theregister.com/2026/03/23/google_dark_web_ai) [Independent press]
- The Register also reports these Google claims:
  - 98% accuracy in internal tests across 8–10 million events per day
  - Keyword and regex monitoring yields 80–90% false positives (a Google product manager's characterisation)
  - GTIG tracks 627 threat groups
  - SecOps agents that investigate alerts and give verdicts with explanations are in preview; remote MCP server support is GA

  The article flags that agents with broad access could become a new attack vector, and that trust in AI recommendations is not yet established. — [The Register, 23 Mar 2026](https://theregister.com/2026/03/23/google_dark_web_ai) [Vendor claims reported by independent press]
- Google's product page says GTI offers tailored risk profiles covering actors, campaigns and malware families. It says "Gemini in Threat Intelligence" surfaces the threats most relevant to your risk profile. — [Google Cloud Threat Intelligence product page](https://cloud.google.com/security/products/threat-intelligence) [Vendor claim]
- Google was among 10 vendors evaluated in the Forrester External TI Wave Q3 2026. The blog post does not give per-vendor placement. — [Forrester blog, 22 Sep 2026](https://www.forrester.com/blogs/announcing-the-forrester-wave-external-threat-intelligence-service-providers-q3-2026/) [Independent]

### Inferences
- Google's design maps directly onto the brief's "severity + confidence + relevance + evidence" requirement:
  - verdict × severity gives the threat score
  - a separate confidence score
  - relevance comes from a profile
  - priority = relevance × severity
  - an evidence-ledger card plus an LLM "why" explanation sit on top
- A prototype can copy the profile-driven Threat Map (relevance vs global frequency) as a 2D dashboard chart.
- Signal expiry ("age off") is a simple, defensible decay model: each evidence item gets a TTL rather than a continuous decay curve.
- Defaulting the Medium tier to non-alerting is an explicit vendor admission that IoC matching at volume causes alert fatigue.

### Gaps
- I found no public formula for the GTI Relevance Score or the Confidence Score.
- I found no independent accuracy test of the dark-web Relevance System. The 98% figure is internal.
- I did not verify the Gemini agent features in GTI (e.g., malware-analysis agents) beyond press coverage.

---

## 3. Microsoft: Defender Threat Intelligence (MDTI), Security Copilot, and the Threat Intelligence Briefing Agent

### Takeaway
Microsoft's distinctive move is to **pull the organisation's own exposure data** into the TI product: Defender Vulnerability Management, Defender EASM and Defender for Endpoint. Its **Threat Intelligence Briefing Agent** researches active threats against *your* vulnerabilities, filtered by region and industry, writes a tiered briefing, and shows its reasoning steps. Its IoC reputation is a simple, explainable **count-of-ML-rules** banding (0–100). In August 2026, MDTI content was folded into the Defender portal at no extra cost.

### Cited Findings
**Reputation scoring [Docs]**
- The 0–100 reputation score is derived from "proprietary data and machine learning rules", each rated High, Medium or Low severity. The rules assess factors such as TLD, hosting provider, name server, registrar and TLS-certificate traits. "The combination of indicators, rather than any single one, predicts whether an entity is likely malicious." — [Microsoft Learn: TI on entity pages, updated Aug 2026](https://learn.microsoft.com/en-us/defender-xdr/entity-page-threat-intelligence)
- Score bands:

  | Score | Category | Basis |
  |---|---|---|
  | 75–100 | Malicious | Confirmed associations to known malicious infrastructure on Microsoft's blocklist, plus ML-rule matches |
  | 50–74 | Suspicious | Three or more ML-rule matches |
  | 25–49 | Neutral | At least two rule matches |
  | 0–24 | Unknown | Zero or one rule match |

  — [Microsoft Learn: TI on entity pages](https://learn.microsoft.com/en-us/defender-xdr/entity-page-threat-intelligence)
- Entity enrichments are free for all Defender XDR customers:
  - **IP and domain:** reputation, attributed threat reports, PDNS, WHOIS, host pairs, subdomains, TLS certs, services, components, trackers, cookies
  - **URL and file:** reputation, attributed threat reports, sandbox analysis

  Data is collected via passive DNS, port scans and web crawling. — [Microsoft Learn: TI on entity pages](https://learn.microsoft.com/en-us/defender-xdr/entity-page-threat-intelligence)
- Microsoft does not publish the full list of its machine-learning reputation rules. — [Microsoft Learn reputation scoring (search snippet)](https://learn.microsoft.com/defender/threat-intelligence/reputation-scoring) [Docs]

**MDTI convergence (2026)**
- The final phase of MDTI convergence went GA in the Defender portal on **1 Aug 2026**, giving Microsoft TI "at no additional cost." Some formerly premium MDTI connectors and APIs are now free to eligible Sentinel and Defender XDR customers.
- The standalone Intel Profiles, Intel Explorer and Intel Projects pages retired in August 2026. Their capabilities move into the Defender "Threat Intelligence" section: Threat Analytics, actor profiles, embedded IoCs and ATT&CK mappings, correlation with incidents, and linking intel to cases.

  — [Petri, 5 Aug 2026](https://petri.com/microsoft-threat-intelligence-defender-xdr-sentinel/) [Independent press]

**Threat Intelligence Briefing Agent [Docs, page dated May 2026, updated 9 Oct 2026]**
- **Purpose:** generates briefings "based on the latest threat actor activity and both internal and external vulnerability information—in a matter of minutes." It "dynamically chooses the next step based on the outcome of the previous step," deciding "what threat intelligence to include and prioritize." It then translates this into a report "consumed by various audiences" (CISOs, managers, analysts).
- **Requirements:**
  - Required plugin: Microsoft Threat Intelligence
  - Optional plugin: Defender EASM
  - Needs read access to Defender Vulnerability Management, and optionally Exposure Management
  - Best suited to customers running Defender EASM and Defender for Endpoint
  - Requires Security Copilot
- **Input parameters:**
  - "Insights to research" (number of vulnerabilities to research for active threats)
  - "Look back days"
  - Email recipient
  - **Region**
  - **Industry**

  It runs on a schedule ("on the trigger") or one-off.
- **Output:** "a relevant summary of threat information and detailed technical analysis, including any actively exploited vulnerability and its possible organizational impact."
- **Transparency:** "View activity" shows an activity map of the steps the agent took. Thumbs up/down plus free-text feedback is collected.

  — [Microsoft Learn: Threat Intelligence Briefing Agent](https://learn.microsoft.com/en-us/copilot/security/threat-intel-briefing-agent)
- An embedded variant runs in the Defender portal, set up from a banner on Threat Analytics. A mirror of that page lists a default trigger of every 7 days. A Bitsight press release (12 Jun 2025) says it can run every 24 hours and that Bitsight supplies dark- and deep-web intelligence to it. These sources conflict on cadence. — [Microsoft Learn: Briefing Agent in Defender](https://learn.microsoft.com/en-us/defender-xdr/threat-intel-briefing-agent-defender); [Bitsight press release, Jun 2025](https://www.bitsight.com/press-releases/bitsight-provides-dark-web-threat-intelligence-microsoft-security-copilot) [Vendor claim]
- Security Copilot agents, including TI-related ones, were first announced 24 Mar 2025. — [SiliconANGLE, 24 Mar 2025](https://siliconangle.com/2025/03/24/microsoft-introduces-ai-agents-security-copilot/) [Independent press]
- Microsoft was **not** among the vendors in Forrester's 2026 External TI Wave, though it was in the 2023 evaluation. — [Forrester blog, Sep 2026](https://www.forrester.com/blogs/announcing-the-forrester-wave-external-threat-intelligence-service-providers-q3-2026/) [Independent]

### Inferences
- The Briefing Agent is the closest commercial analogue to the hackathon's required demo flow: new advisory → correlate with asset inventory → exposure → risk level → alert.
  - Its parameter set (top-N vulnerabilities, look-back window, region, industry, recipient) is a ready-made config schema for a prototype.
  - So are its two-tier output (executive summary plus technical detail) and its visible step trace.
- Microsoft's banding by *number of rule matches* is the most transparent scoring scheme found, and the easiest to reproduce: "3+ rules → Suspicious".
- Agentic "choose next step" behaviour is less important for a 24-hour build than a fixed, auditable pipeline. The visible activity trace is the part worth copying.

### Gaps
- I found no published accuracy, time-saved figures or independent evaluation of the Briefing Agent.
- The default cadence is unresolved (7 days vs 24 hours).
- I did not find Microsoft's list of ML reputation rules, by design.

---

## 4. CrowdStrike (Falcon Adversary Intelligence + Charlotte AI), Palo Alto (Unit 42 / Cortex XSIAM / Xpanse), SentinelOne (Purple AI)

### Takeaway
These XDR-centric vendors frame TI as fuel for **agentic SOC workflows**: hunt, malware analysis and auto-investigation, rather than as standalone scored intelligence. Their public material is heavy on agent rosters and light on scoring transparency or measured accuracy. The most emulable, documented mechanism among them is Palo Alto's **Admiralty-scale source-reliability rule** for resolving conflicting verdicts.

### Cited Findings
**CrowdStrike**
- **Threat AI (Fal.Con, Sep 2025)** is marketed as "the industry's first agentic threat intelligence system of autonomous agents that reason across data, hunt for threats, and take action." Its first two agents:
  - **Malware Analysis Agent** "automatically analyzes suspicious files, connects them to known threats" and retroactively hunts past data.
  - **Hunt Agent** "continuously searches the environment for hidden threats identified by CrowdStrike's threat intelligence."

  — [CrowdStrike Fall 2025 release blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-fall-2025-release-defines-agentic-soc-secures-ai-era) [Vendor claim]
- CrowdStrike lists seven "mission-ready" agents, "trained on millions of expert decisions from Falcon Complete Next-Gen MDR," drawing on "trillions of telemetry events" and "over a decade of annotated threats." Agents operate "always under analyst command." The only speed claim is qualitative ("hours of research into seconds"). **No accuracy percentages are given.** — [CrowdStrike Fall 2025 release blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-fall-2025-release-defines-agentic-soc-secures-ai-era) [Vendor claim]
- Other launches: **Charlotte AI AgentWorks** (no-code agent builder), "agentic response collaboration" with analysts and third-party agents, and a TI browser extension. — [CrowdStrike Fall 2025 release blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-fall-2025-release-defines-agentic-soc-secures-ai-era) [Vendor claim]
- Futurum's analyst commentary frames this as a "human-led agentic SOC" and is cautiously positive. — [Futurum Group](https://futurumgroup.com/insights/crowdstrike-fal-con-2025-a-vision-and-a-path-to-the-human-led-agentic-soc/) [Independent analyst]
- CrowdStrike was named a Leader in the Forrester External TI Service Providers Wave, Q3 2026. It says it received the top scores in both Current Offering and Strategy. — [CrowdStrike blog, Sep 2026](https://www.crowdstrike.com/en-us/blog/crowdstrike-named-leader-forrester-wave-external-threat-intelligence-q3-2026/) [Vendor claim about an independent report]

**Palo Alto Networks**
- Cortex XSIAM **Threat Intel Management (TIM)** unifies "threat intel aggregation, scoring, and sharing." It requires the Premium licence or the TIM add-on. — [Cortex XSIAM docs: What is TIM](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/detect-investigate-and-respond-to-threats/threat-management/threat-intel-management/get-started-with-threat-intel-management/what-is-threat-intel-management) [Docs]
- **Verdict logic** (XSOAR/XSIAM TIM):
  - Verdicts are Unknown (0), Benign (1), Suspicious (2), Malicious (3).
  - "An indicator's verdict is assigned according to the verdict returned by the source with the highest reliability." Reliability uses the **Admiralty** source-reliability matrix.
  - Reliability tiers: Manual = A+++, reputation script = A++, third-party enrichment = A+, feeds = A ("Completely reliable") through F ("can't be judged"), set per integration.
  - On a reliability tie, "the worse verdict is used."
  - Setting a verdict to Unknown and re-enriching triggers recomputation.

  — [Cortex XSOAR 8 indicator verdict docs](https://cortex-docs.paloaltonetworks.com/cortex-xsoar-8-saas/investigate-and-respond-to-threats/threat-intel-management/indicator-investigation/indicator-verdict) [Docs]
- **Unit 42 Intel** draws on WildFire sandbox, the PAN-DB URL database, the Unit 42 research team and third-party feeds. It supports an "Update & Enrich" action. — [XSOAR Unit 42 Intelligence integration](https://xsoar.pan.dev/docs/reference/integrations/unit-42-intelligence) [Docs]
- **Cortex AgentiX** is described as AI agents that investigate and remediate under human-set guardrails, with audit trails. XSIAM is described as including attack-surface management. — [TheNetworkDNA, Oct 2026](https://www.thenetworkdna.com/2026/10/palo-alto-networks-ai-security-agentic-security.html) [Secondary]

**SentinelOne**
- **Purple AI Agentic Investigation** was opened to all customers (BusinessWire release dated 17 Jun 2026).
  - It auto-starts investigations once a threat crosses a **customer-defined threshold**, reaches a verdict and acts, while analysts can watch and intervene.
  - It uses endpoint, identity, cloud and third-party telemetry.
  - It is metered in "Singularity Credits."

  — [SentinelOne press release](https://www.sentinelone.com/press/sentinelone-opens-purple-ai-agentic-investigation-to-all-customers-bringing-frontier-ai-directly-into-the-soc/); [BusinessWire](https://secure.businesswire.com/news/home/20260617370648/en/SentinelOne-Opens-Purple-AI-Agentic-Investigation-to-All-Customers-Bringing-Frontier-AI-Directly-Into-the-SOC) [Vendor claim]
- SentinelOne's earlier releases:
  - "Athena" release (29 Apr 2025): "deep security reasoning", agentic detection and response, and hyperautomation for any SIEM. — [BusinessWire, Apr 2025](https://www.businesswire.com/news/home/20250429490914/en/SentinelOne-Brings-Deep-Security-Reasoning-Agentic-Detection-and-Response-and-Hyperautomation-Workflows-to-Any-SIEM-or-Data-Source-with-Purple-AI-Athena-Release) [Vendor claim]
  - Auto Investigation GA was announced at RSAC 2026. — [Security Boulevard, Mar 2026](https://securityboulevard.com/2026/03/sentinelone-announces-ai-agent-security-red-teaming-and-auto-investigation-ga-at-rsac-2026/) [Secondary]
- Claim: auto-investigation shrinks "hours and days into minutes and seconds." It has no independent benchmark. G2 shows 4.8/5 from only 2 reviews, which is too thin to draw conclusions from. — [SentinelOne press release](https://www.sentinelone.com/press/sentinelone-opens-purple-ai-agentic-investigation-to-all-customers-bringing-frontier-ai-directly-into-the-soc/); [G2](https://www.g2.com/products/sentinelone-purple-ai/reviews)

### Inferences
- For a prototype, the XSOAR rule "highest-reliability source wins; on a tie, take the worse verdict; manual overrides everything" is a deterministic, explainable way to merge open feeds that disagree. For example, a CERT advisory should beat a crowdsourced feed.
- Agentic claims across these three vendors are almost entirely unbenchmarked. The defensible, copyable pieces are "auto-investigate above a threshold" (SentinelOne) and "always under analyst command" plus an audit trail.

### Gaps
- I found no public scoring formula for CrowdStrike indicator or actor confidence.
- I found no documentation on how Cortex Xpanse exposure data feeds TIM scoring.
- I found no independent accuracy data for Charlotte AI, Threat AI or Purple AI.

---

## 5. TIPs and intel-centric vendors: ThreatConnect, Anomali, EclecticIQ, Cyware, Silobreaker, Flashpoint, Group-IB, Feedly

### Takeaway
Two layers separate the TIPs:
- **Transparent, weighted, multi-signal scoring with guardrails.** ThreatConnect CAL/ThreatAssess and the Cyware CTIX Confidence Engine are the most documented. Anomali blends ML scores with per-source weights.
- **LLM features for summarisation, NL query and extraction.** These include EclecticIQ's bring-your-own and self-hosted LLM via Ollama, Feedly's entity-extraction models plus CVE prediction, and Flashpoint's reference-backed summaries.

None publishes precision or recall figures.

### Cited Findings
**ThreatConnect**
- **CAL Global Threat Score** is a 0–1000 "baseline reputation score" with these bands: Low 0–200, Medium 201–500, High 501–800, Critical 801–1000.
  - "A Critical score does not mean that an Indicator is confirmed to be malicious," and Low does not mean benign.
  - **Signals:** OSINT feed reporting, observed activity across customers, prevalence and rarity, structural and behavioural traits, reputation and enrichment context, and community false-positive feedback.
  - It is type-aware across 10 indicator types.
  - It counts **risk-reducing** signals too (known-good infrastructure). "No single signal is sufficient on its own."

  — [ThreatConnect KB: CAL Global Threat Score](https://knowledge.threatconnect.com/docs/cal-global-threat-score) [Docs]
- **CAL guardrails:**
  - **Bounded signal influence**
  - **Diminishing returns** for repeated observations
  - **Temporal smoothing:** "Scores may increase rapidly in response to strong new risk signals, while risk decays more gradually"
  - **Capped activity amplification:** high activity "cannot overwhelm other contexts"
  - More weight on recent intelligence

  Changes reflect "the current intelligence landscape, not a retroactive reassessment." — [ThreatConnect KB: CAL Global Threat Score](https://knowledge.threatconnect.com/docs/cal-global-threat-score) [Docs]
- **CAL explanation:** "Impact Factors" show the key contributing signals and recent changes. They provide transparency "not to expose internal scoring logic." The score (continuous) is kept separate from Indicator Status (an actionable recommendation). ThreatConnect warns that a global baseline alone can amplify early or incomplete signals in automation, and recommends personalised layers. — [ThreatConnect KB: CAL Global Threat Score](https://knowledge.threatconnect.com/docs/cal-global-threat-score) [Docs]
- **ThreatAssess** is a 0–1000 org-specific score.
  - Inputs: Threat Rating (the analyst-set 0–5 "skull" evilness scale, weighted-average across owners), Confidence Rating (0–100, weighted-average across owners), recent false-positive reports, recent observations, and the CAL score (weightable).
  - ThreatConnect describes it as building on CAL with customer feeds, local context and analyst input to produce "a more refined, customer-specific score."

  — [ThreatConnect KB: ThreatAssess and CAL](https://knowledge.threatconnect.com/docs/threatassess-and-cal); [Threat and Confidence Ratings](https://knowledge.threatconnect.com/docs/threat-and-confidence-ratings.md); [CAL Global Threat Score](https://knowledge.threatconnect.com/docs/cal-global-threat-score) [Docs]

**Anomali**
- ThreatStream assigns ML **confidence** to Domain, IP and URL observables.
  - For imported or user streams, the score comes entirely from Anomali's algorithms unless overridden.
  - For premium and OSINT feeds, the final score **blends the ML score with the source's own reported confidence**, using a per-source weight set by Anomali.

  — [Anomali docs: Observable Confidence](https://docs.anomali.com/Content/Features/threat_model/Observables/Observable_Confidence.htm) [Docs]
- The ML scoring algorithm is named "MACULA". — [eSecurityPlanet](https://www.esecurityplanet.com/products/anomali-threatstream.html) [Secondary]
- **Anomali Copilot** translates natural-language questions into Anomali Query Language (AQL) to build dashboards and alerts. Anomali says it is grounded in TI data and limits hallucinations. It also ships as a browser extension and an Excel add-in. — [Anomali Copilot docs](https://docs.anomali.com/Content/Features/Anomali_Copilot/Anomali_Copilot_Overview.htm); [Anomali blog](https://www.anomali.com/blog/announcing-expanded-capabilities-for-copilot) [Docs / Vendor claim]

**Cyware**
- The **CTIX Confidence Score** is a 0–100 likelihood that an indicator is malicious. It is a **weighted average of four sub-scores**: relations score, enrichment policy score, source confidence score and source sightings score. Weights are customisable, and enrichment scores may lag because they depend on external tools.
- A snippet also mentions that feeds older than 12 months lose 50 points. This is unverified, because the page body failed to load.

  — [Cyware techdocs: CTIX Confidence Score Engine](https://techdocs.cyware.com/ctix/en/ctix-confidence-score-engine.html) [Docs, via search snippet]
- **Quarterback AI** launched as a copilot chat assistant in March 2024. Agentic workflows (e.g., a Playbook Builder Agent) were added in November 2025. — [BusinessWire, 12 Nov 2025](https://businesswire.com/news/home/20251112076683/en/Cyware-Introduces-Agentic-AI-Workflows-to-Strengthen-its-Cyware-Quarterback-AI) [Vendor claim]

**EclecticIQ**
- Intelligence Center 3.5 (April 2025) added **bring-your-own-LLM per AI feature**, including **on-prem self-hosted models via Ollama for air-gapped environments**, plus an AI Assistant for investigations. 3.4 (August 2024) introduced AI provider configuration. — [EclecticIQ docs: 3.5 release](https://docs.eclecticiq.com/ic/3.7.2/release/3.5/); [EclecticIQ blog 3.5](https://blog.eclecticiq.com/eclecticiq-intelligence-center-3.5-smarter-and-faster-decisions); [EclecticIQ blog 3.4](https://blog.eclecticiq.com/eclecticiq-intelligence-center-3-4?hsLang=en) [Docs]

**Silobreaker**
- Silobreaker AI (November 2023) summarises Silobreaker's own analyst content and generates threat reports. — [Help Net Security, Nov 2023](https://www.helpnetsecurity.com/2023/11/06/silobreaker-ai/) [Vendor claim]
- Later additions: "AI Summarise" (key topics from one or many documents), "AI Context" and AI-enhanced geofencing. — [BusinessWire, Aug 2024](https://www.businesswire.com/news/home/20240806631166/en/Silobreaker-Unveils-More-AI-Powered-Features-to-Streamline-Threat-Intelligence-Operations) [Vendor claim]

**Flashpoint**
- Flashpoint launched AI Summarization for Search and AI Summarization for Investigations at Black Hat USA 2025 (August 2025). These produce "concise, **reference-backed** summaries" of findings saved in an investigation, which can be regenerated as items are added. — [Flashpoint news, Aug 2025](https://flashpoint.io/news/flashpoint-unveils-ai-summarization-for-search-and-investigations-at-black-hat-usa-2025/) [Vendor claim]
- An earlier Ignite AI chatbot answers natural-language questions over finished intelligence. — [Flashpoint blog: Announcing Ignite AI](https://flashpoint.io/blog/announcing-ignite-ai) [Vendor claim]
- Flashpoint was among the 10 vendors in Forrester's Q3 2026 External TI Wave. — [Forrester blog](https://www.forrester.com/blogs/announcing-the-forrester-wave-external-threat-intelligence-service-providers-q3-2026/) [Independent]

**Group-IB**
- The only item found: Group-IB threat-actor profiling can be auto-correlated in EclecticIQ via an integration. — [EclecticIQ solution brief](https://www.eclecticiq.com/library/group-ib-and-eclecticiq-intelligence-center) [Vendor]

**Feedly AI for Threat Intelligence**
- Pre-trained "AI Models" tag threat actors, malware families, CVEs, ATT&CK TTPs (techniques, sub-techniques "and their relationships", ATT&CK v10), IoCs (URLs, IPs, emails, domains, hashes), companies, vendors and industries. Some models use **disambiguation** to remove false positives.
- Feedly says it reads "millions of articles, reports, and social media posts every day," with a "50,000+" source bundle curated by "200,000 cyber professionals."

  — [Feedly: Track Emerging Threats with Feedly AI](https://feedly.com/new-features/posts/track-emerging-threats-with-feedly-ai) [Vendor claim]
- The "**High Vulnerability**" model flags CVSS > 8, **or > 5 with a known exploit**. When no CVSS exists yet, "a machine learning model is used to forecast the CVSS score based on the descriptions of the vulnerability." Vulnerability data is aggregated from NVD plus 20+ vendor advisory sites, with near-real-time exploit monitoring. The CVE insights card gives a "360 degree view" to support the decision to open a ticket. **No accuracy metrics are given.** — [Feedly: Track Emerging Threats with Feedly AI](https://feedly.com/new-features/posts/track-emerging-threats-with-feedly-ai) [Docs/Vendor claim]
- CVE Insights Cards show a timeline, severity (CVSS, **EPSS** or AI-predicted) and proof-of-exploit. "Ask AI" summarises up to 25 reports, multilingual, and extracts IoCs and TTPs. A TTP agent pairs with ATT&CK Navigator. Export formats are STIX, MISP and JSON. — [Feedly Ask AI](https://feedly.com/new-features/posts/new-feedly-ask-ai-synthesize-threat-reports-and-articles-in-minutes-with-high-accuracy); [Feedly TTP AI Agent docs](https://docs.feedly.com/category/824-ttp-ai-agent) [Vendor claim]

### Inferences
- ThreatConnect's four guardrails are a ready-made spec for a robust prototype score: bounded per-signal weight, diminishing returns for repeat sightings, fast-rise/slow-decay, and capped volume amplification. FP feedback as a negative signal is the fifth.
- Cyware's four-component weighted average (relations, enrichment, source confidence, sightings) is a simple, configurable confidence formula that maps well onto open feeds.
- Feedly's "CVSS > 8, or > 5 with known exploit" rule plus ML-predicted CVSS for fresh CVEs suits national early warning, where advisories land before NVD scoring. A local LLM or regressor could forecast severity from description text.
- EclecticIQ's Ollama precedent legitimises a fully local LLM stack for a government or air-gapped context. This is a useful "national" framing for C-DAC judges.
- Flashpoint's "reference-backed" summaries and Google's citations show the industry norm: LLM output must cite the underlying evidence items.

### Gaps
- I could not research ThreatConnect "Threat Graph" specifics.
- I found no current material on Group-IB's own AI or LLM features.
- A Flashpoint "Custom Summary Builder" (reported for Black Hat 2026) and planned 2026 agentic AI surfaced only in search summaries, not confirmed on a primary page.
- I could not verify the Cyware decay rule.
- No vendor in this group publishes extraction precision or recall.

---

## 6. What independent analysts, surveys and reviewers say works, and what they complain about

### Takeaway
Independent sources agree on four points:
- **Relevance and decision-linkage are the bottleneck, not data volume.** SANS 2026 found 91% of CISOs value CTI but only 26% say it significantly influences their decisions.
- **Noise and false positives come from poorly targeted IoC matching.**
- **Analysts distrust black-box AI.** Forrester 2026 tells buyers to "demand transparency instead of accepting AI as a black box."
- **Open-source LLMs remain weak at fine-grained CTI tasks** such as ATT&CK technique classification on full reports (best micro-F1 0.22).

### Cited Findings
**SANS surveys**
- **SANS 2026 CTI Survey** (fieldwork November 2025–January 2026; 401 practitioners plus a first-ever executive module of 67 CISOs/CSOs):
  - 91% of CISOs rate CTI valuable or extremely valuable, but only 26% say it significantly influences their decisions.
  - SANS frames this as "a translation problem, not a credibility one."
  - 44% cite lack of time or funding as the top barrier.
  - SANS recommends identifying the CTI products that inform recurring stakeholder decisions, rather than producing more reports.

  — [Flare summary of SANS 2026 CTI Survey](https://flare.io/learn/resources/blog/sans-cti-survey-2026); [SANS announcement](https://www.sans.org/press/announcements/2026-cyber-threat-intelligence-survey-insights-report); [Intel 471 whitepaper page](https://www.intel471.com/resources/whitepapers/the-2026-sans-cyber-threat-intelligence-survey-what-cisos-want-intelligence-driven-decisions) [Independent, via sponsor summaries]
- **SANS 2025 CTI Survey** (Rebekah Brown and Andreas Sfakianakis):
  - 70.2% say an "increasingly complex digital landscape" drives CTI process change.
  - The most-cited process change was the shift from manual collection toward automation.
  - Sponsor summaries list budget, tool fragmentation and proving ROI as top challenges.

  — [SANS 2025 CTI Survey page](https://www.sans.org/white-papers/2025-cti-survey-webcast-forum-navigating-uncertainty-todays-threat-landscape); [SANS 2025 PDF hosted by SOCRadar](https://socradar.io/wp-content/uploads/2025/05/SANS-2025-CTI-Cyber_Threat_Intelligence_Survey-SOCRadar.pdf); [Dataminr summary](https://resources.dataminr.com/resources/sans-2025-cti-survey) [Independent; percentages beyond these were not verified]

**Forrester Wave: External Threat Intelligence Service Providers, Q3 2026** (analyst Jitin Shabadu, blog dated 22 Sep 2026)
- Vendors evaluated: CrowdStrike, Doppel, Flashpoint, Fortinet, Google, Netcraft, Recorded Future, ReliaQuest, TrendAI and ZeroFox. The evaluation used 17 current-offering criteria and 6 strategy criteria.
- Trends:
  - PIRs moved "from onboarding to adoption", meaning how well priority intelligence requirements are "embedded within the platform."
  - Digital risk protection was split out.
  - AI is "a product battleground", and the evaluation "scrutinizes how vendors measure the effectiveness of their AI-driven capabilities."
- Advice to buyers:
  - "Use-case excellence wins out over platform breadth." "No vendor leads every category."
  - "A balanced roadmap beats an AI-only roadmap."
  - "demand transparency instead of accepting AI as a black box."
  - AI on weak intelligence is "advanced weaponry loaded with rusted ammunition."

  — [Forrester blog, 22 Sep 2026](https://www.forrester.com/blogs/announcing-the-forrester-wave-external-threat-intelligence-service-providers-q3-2026/) [Independent]

**Gartner and peer reviews**
- Gartner (July 2024): "Using TI improperly will result in more noise and false positives. Proper planning for TI usage is critical." Modern tools ingest TI but "often don't include guidance on the best way to utilize it." — [Gartner abstract](https://www.gartner.com/en/documents/5571127) [Independent]
- Gartner Peer Insights reviews include complaints such as "Way too many False Positives, no vetting or validation process behind the IOCs" (September 2025, one vendor), alongside praise for tools that "reduce false positives and reduce notification floods." — [Gartner Peer Insights: Cyberthint](https://www.gartner.com/reviews/product/cyberthint-unified-cyber-threat-intelligence-platform); [Gartner Peer Insights: TIP category](https://www.gartner.com/reviews/product/threat-intelligence-platform) [Independent, anecdotal]
- Practitioner survey (Recorded Future, 2025): 50% struggle to judge report accuracy and credibility; 46% report information overload; 46% lack environment-specific context. — [Cybersecurity Dive, Nov 2025](https://www.cybersecuritydive.com/news/threat-intelligence-customer-complaints-recorded-future/805300/) [Independent press, vendor survey]
- ReliaQuest notes that noise remains a problem despite TIPs' original role as IoC "clearinghouses." — [ReliaQuest blog](https://www.reliaquest.com/blog/no-time-for-threat-intel-noise/) [Vendor commentary]
- Google's own product manager estimates 80–90% false positives for keyword and regex dark-web monitoring. This is a vendor framing used to sell its LLM relevance system. — [The Register, Mar 2026](https://theregister.com/2026/03/23/google_dark_web_ai)

**Academic evidence on LLMs for CTI** (relevant to local models)
- **CTIBench** (2024) tests four analyst tasks: CTI knowledge, ATT&CK mapping (CTI-ATE), CVSS severity prediction, and threat-actor attribution. Proprietary models outperformed open-source ones. Summaries report that Llama3-8B performed poorly on mapping and reasoning. — [CTIBench, arXiv 2406.07599](https://arxiv.org/pdf/2406.07599v3) [Independent; per-model numbers not verified here]
- A 2026 study tested 7 open-source LLMs (8B–236B) on multi-label ATT&CK technique classification over full CTI reports. The best reached micro-F1 0.22, and the authors conclude that current open-source LLMs "are insufficient for production-grade ATT&CK classification." — [arXiv 2606.18166](https://arxiv.org/pdf/2606.18166) [Independent]
- AthenaBench: GPT-5 scored highest, then Gemini-2.5 Pro; open-source models lag on CTI tasks. — [AthenaBench, arXiv 2511.01144](https://arxiv.org/pdf/2511.01144v2) [Independent]

### Inferences
- The judging-relevant pain points are credibility, noise and lack of org context, and the 26% decision-influence gap. A prototype wins by visibly addressing them:
  - show evidence and sources for every score
  - alert only on asset-matched items
  - phrase alerts as decisions (patch / block / monitor) with owners and deadlines
- Given the benchmark results, a laptop-scale LLM should be used for **summarising and explaining from supplied evidence**, not for authoritative ATT&CK mapping or scoring. Deterministic rules plus regex and dictionary extraction should drive the score.

### Gaps
- I found no 2025–2026 Gartner Market Guide for TI content in open sources.
- I did not obtain Forrester's per-vendor placements beyond vendor self-reports.
- I did not obtain the full SANS 2026 report tables (registration required).

---

## 7. Lessons and design patterns for a 24-hour AI early-warning prototype

### Takeaway
Copy the **mechanics** that the leaders document, not the agentic marketing:
- named risk rules with evidence strings and criticality-based score floors (Recorded Future)
- separate verdict, severity, confidence and relevance, combined into a priority (Google)
- source-reliability conflict resolution (Palo Alto, Admiralty scale)
- score guardrails and decay (ThreatConnect, Google)
- an org/asset profile driving relevance (Google, Microsoft)
- an LLM used only to explain and summarise from cited evidence (Google "Tell me why?", Flashpoint, Microsoft Briefing Agent)

All of this runs on open data and a local model.

### Cited Findings
These are the specific vendor mechanisms that ground each pattern. Full citations are in sections 1–6.

**Scoring and evidence**
- **Rules → criticality → base-score floor (90/65/25/5) → evidence string per rule; free tier shows only the top rule.** — [Recorded Future browser extension](https://www.recordedfuture.com/products/browser-extension/); [Elastic Recorded Future integration](https://www.elastic.co/docs/reference/integrations/ti_recordedfuture)
- **Verdict × severity → 0–100 score bands; a separate confidence score; an explainer card as an "open ledger of evidence"; signals expire and "age off".** — [GTI Indicator Score](https://gtidocs.virustotal.com/docs/google-threat-intelligence-indicator-score)
- **Bands defined by number of rule matches (≥3 → Suspicious).** — [Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/entity-page-threat-intelligence)
- **Highest-reliability source wins; tie → worse verdict; manual = A+++.** — [Cortex XSOAR verdict docs](https://cortex-docs.paloaltonetworks.com/cortex-xsoar-8-saas/investigate-and-respond-to-threats/threat-intel-management/indicator-investigation/indicator-verdict)
- **Guardrails:** bounded signals, diminishing returns, fast-rise/slow-decay, capped activity, FP feedback as a negative signal, and an "Impact Factors" explanation. — [ThreatConnect CAL](https://knowledge.threatconnect.com/docs/cal-global-threat-score)
- **Weighted average of relations, enrichment, source-confidence and sightings sub-scores.** — [Cyware CTIX](https://techdocs.cyware.com/ctix/en/ctix-confidence-score-engine.html)
- **High-vulnerability rule (CVSS > 8, or > 5 with exploit) and ML-forecast CVSS from description text.** — [Feedly](https://feedly.com/new-features/posts/track-emerging-threats-with-feedly-ai)

**Relevance**
- **Threat Profile (industry, region, motivation); relevance vs global-frequency map; "Tell me why?" LLM explanation; daily digest plus real-time IoC stream.** — [GTI Threat Profiles](https://gtidocs.virustotal.com/docs/manage-threat-profiles)
- **Medium tier non-alerting by default to control volume; features include Prevalence, Attribution, Active IR, Network Direction.** — [Google SecOps ATI](https://docs.cloud.google.com/chronicle/docs/detection/ati-prioritization)
- **Org profile with citations and versioning; vector matching of dark-web chatter against the profile; 7-day alert window.** — [GTI Dark Web Intel](https://gtidocs.virustotal.com/docs/dark-web-intel); [The Register](https://theregister.com/2026/03/23/google_dark_web_ai)

**Briefing and analyst support**
- **Briefing agent parameters (top-N vulnerabilities, look-back days, region, industry, recipient); exec plus technical output; visible activity trace; thumbs feedback.** — [Microsoft Learn Briefing Agent](https://learn.microsoft.com/en-us/copilot/security/threat-intel-briefing-agent)
- **Self-hosted LLM via Ollama for air-gapped use.** — [EclecticIQ 3.5 docs](https://docs.eclecticiq.com/ic/3.7.2/release/3.5/)
- **Reference-backed AI summaries.** — [Flashpoint, Aug 2025](https://flashpoint.io/news/flashpoint-unveils-ai-summarization-for-search-and-investigations-at-black-hat-usa-2025/)

**Independent constraints**
- **Demand transparency, not black-box AI; PIRs embedded in the platform.** — [Forrester 2026](https://www.forrester.com/blogs/announcing-the-forrester-wave-external-threat-intelligence-service-providers-q3-2026/)
- **Make CTI drive decisions (91% value vs 26% influence).** — [Flare / SANS 2026](https://flare.io/learn/resources/blog/sans-cti-survey-2026)
- **Open LLMs are weak at ATT&CK classification (micro-F1 0.22).** — [arXiv 2606.18166](https://arxiv.org/pdf/2606.18166)

### Inferences
These are concrete features to emulate in the prototype. They are recommendations synthesised from the findings above, not vendor facts.

**Feature list**
1. **Risk-rule engine with evidence strings (Recorded Future pattern).** Define about 15–30 named rules per entity type (CVE, IoC, actor or campaign, advisory). Each rule has a criticality of 1–4 and emits a templated evidence string that cites its source and date.
   - Example CVE rules:
     - "Listed in CISA KEV" (crit 4)
     - "Public exploit / PoC reported" (crit 3)
     - "EPSS ≥ 0.5" (crit 3)
     - "CVSS ≥ 9" (crit 3)
     - "Vendor advisory published" (crit 2)
     - "Mentioned in national CERT advisory" (crit 2)
     - "Discussed in ≥ N sources in 48 h" (crit 1)
   - Score = band floor of the highest criticality (90/65/25/5) plus a small bounded increment per additional rule, capped at the band ceiling. Show "k/N rules triggered."
2. **Four separate axes, then priority (Google pattern).**
   - **Threat score** (from the rules)
   - **Confidence** (Cyware-style weighted average of source reliability, corroborating-source count, sightings and enrichment agreement)
   - **Relevance** (overlap with the asset inventory and the org/sector profile)
   - **Priority** = f(threat, relevance), gated by confidence. Example: P1 needs threat ≥ 65, relevance = direct asset match and confidence ≥ medium.
3. **Admiralty source reliability (Palo Alto pattern).** Tag every feed A–F, with the analyst as A+++. Merge conflicting verdicts by "most reliable wins; tie → worse verdict." Show the reliability letter on the card.
4. **Guardrails and decay (ThreatConnect and Google patterns).**
   - Per-source contribution caps
   - Diminishing returns for repeated sightings, e.g. log-scaled
   - Fast rise, slow decay
   - A TTL on each evidence item, after which it "ages off" into history
   - Analyst "false positive" clicks as a risk-reducing signal
5. **Intelligence card / explainer (Recorded Future, Google and Microsoft patterns).** One card per entity shows:
   - score badge and band colour
   - the list of triggered rules with evidence strings and source links
   - matched assets
   - confidence breakdown
   - a timeline (first seen, last seen)
   - a "Tell me why" button that has the local LLM paraphrase **only** the listed evidence, with citations, and refuse otherwise (the Recorded Future AI scope-limiting pattern)
6. **Org and asset profile driving relevance (Google Threat Profile and Microsoft Briefing Agent patterns).** Use a simulated asset inventory (vendor, product, version, CPE, exposure such as internet-facing or internal, criticality, owner) plus a profile of sector, region and critical services. Relevance tiers:
   - **Direct:** CPE or version match on an internet-facing asset
   - **Indirect:** vendor or product match
   - **Contextual:** sector or region targeted by the actor

   Plot a **relevance vs global-frequency** scatter on the dashboard.
7. **Scheduled briefing agent (Microsoft pattern).**
   - Config: top-N vulnerabilities, look-back days, region, industry, recipient.
   - Output: a one-paragraph executive summary for a CISO or ministry official, a technical section, and recommended mitigation steps per asset.
   - Show a step-by-step "activity trace" of the pipeline: fetched → extracted → matched → scored → summarised.
   - Collect thumbs up/down feedback.
8. **Tiered alerting to fight fatigue (Google ATI pattern).**
   - Only P1 and P2 generate pushed alerts.
   - "Medium" goes to the daily digest and is non-alerting.
   - "Unusual" is dashboard-only.
   - Include a 7-day look-back window and a real-time stream for P1 IoCs or CVEs.
9. **Extraction pipeline sized for a laptop (Feedly pattern, sized by the benchmark limits).**
   - Regex for IoCs, CVE IDs and hashes, with defanging on display.
   - Dictionary or gazetteer matching for actor and malware names from MITRE ATT&CK groups and software lists.
   - The local LLM only for summarisation, entity disambiguation hints and severity forecasting for un-scored CVEs (the Feedly "AI-predicted CVSS" idea).
   - Mark any LLM-proposed ATT&CK technique as "low confidence / needs analyst review", given micro-F1 0.22 for open models.
10. **Decision-oriented output (SANS 2026 and Forrester PIR patterns).**
    - Encode 3–5 **Priority Intelligence Requirements** as saved queries, e.g. "exploited vulnerabilities in our internet-facing VPNs" or "ransomware targeting government or healthcare in India."
    - Tie every alert to a PIR, an asset owner, a recommended action (patch, mitigate, block or monitor) and an SLA.
    - This directly answers the "translation problem."
11. **Local or air-gapped AI (EclecticIQ pattern).** Run a local model (e.g., via Ollama). This can be framed as sovereign and suitable for national CERT deployment.

**Suggested open data to drive the rules** (my suggestion; not researched in this note):
- CISA KEV
- NVD / CVE JSON
- FIRST EPSS
- MITRE ATT&CK groups and software
- CERT-In advisories
- vendor PSIRT RSS feeds
- abuse.ch ThreatFox / URLhaus / Feodo
- the Recorded Future evidence-string example shows that ThreatFox is a source commercial vendors already cite

**Compact comparison of scoring and explanation mechanisms** (synthesised from sections 1–5)

| Platform | Score scale | How the score is built | How it is explained | Relevance mechanism | AI and copilot layer |
|---|---|---|---|---|---|
| Recorded Future | 0–99, 5 bands | Triggered risk rules; highest criticality sets the base | Rule list plus evidence strings; "k/N" | Not documented publicly (gap) | AI Sessions on the graph; agentic signature generation (vendor) |
| Google GTI | 0–100 threat score; verdict plus severity | Verdict × severity plus Mandiant intelligence, sandbox, confidence; signals age off | Threat Score Explainer ledger; 10 factor categories; "Tell me why?" | Threat Profile relevance; Gemini org profile; ATI priority on log matches | Gemini explanations; dark-web relevance (Beta); SecOps agents (preview) |
| Microsoft | 0–100 reputation, 4 bands | Count of severity-rated ML rules plus blocklist | Rules impacting the score listed; entity pages | DVM, EASM, MDE exposure data plus region and industry parameters | TI Briefing Agent with activity trace |
| ThreatConnect | 0–1000 CAL; 0–1000 ThreatAssess | Multi-signal with guardrails; ThreatAssess adds analyst ratings, FP reports, observations | "Impact Factors" | ThreatAssess is customer-specific | (not researched in depth) |
| Cyware CTIX | 0–100 confidence | Weighted average of relations, enrichment, source confidence, sightings | Sub-score breakdown (configurable weights) | (not documented here) | Quarterback AI copilot and agents |
| Anomali | ML confidence | ML score blended with source-reported confidence by per-source weight | (not documented here) | (not documented here) | Copilot NL → AQL |
| Palo Alto TIM | Verdict 0–3 | Highest-reliability source (Admiralty A–F); tie → worse | Source and reliability shown | (Xpanse link not documented) | AgentiX (secondary source) |
| Feedly | CVSS / EPSS / AI-predicted | Rule "CVSS > 8, or > 5 plus exploit"; ML CVSS forecast | CVE insights card | Keyword and entity AI Feeds | Ask AI (25-report synthesis), TTP agent |

**What to avoid** (from complaints):
- black-box scores without evidence (Forrester)
- alerting on every IoC match (Gartner; Google's own Medium-tier advice)
- reports that don't tie to decisions (SANS 2026)
- unverifiable LLM claims without citations (50% credibility complaint)

### Gaps
- No vendor publishes exact weights or formulas end-to-end. Google comes closest (the verdict × severity table) and Recorded Future gives base floors, so any prototype formula is an informed design choice rather than a replication.
- No independent precision or recall data exists for any commercial AI CTI feature found. All "accuracy" and "time saved" figures (Google 98%, Recorded Future 31 minutes, SentinelOne "minutes and seconds") are vendor-internal.
- I did not research open-data feed licensing or terms (e.g., abuse.ch, CERT-In reuse).
