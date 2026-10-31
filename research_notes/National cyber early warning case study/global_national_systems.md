# National cyber early-warning and threat-intelligence-sharing systems outside India: case studies (state as of October 2026)

Scope note: this covers US (CISA), UK (NCSC), EU (ENISA, CERT-EU, Cyber Solidarity Act alert system, EUVD), Israel (INCD), Singapore (CSA), Japan (NICT NICTER/DAEDALUS), South Korea (KISA), Australia (ASD/ACSC) and Germany (BSI). India is excluded. Facts older than 2025 carry their year. "[24h]" marks ideas that one laptop running local AI could copy in a 24-hour hackathon. "[stretch]" means possible but risky in 24 hours. "[no]" means it needs national-scale data or authority.

---

## 1. United States: CISA (AIS, KEV/BOD 26-04, Vulnrichment/SSVC, CyberSentry, EINSTEIN to CADS, JCDC, pre-ransomware notifications)

### Takeaway
CISA runs the world's most documented national early-warning stack. It has four layers: a machine-to-machine indicator feed (AIS), an authoritative "exploited now" vulnerability list (KEV) with a decision-tree enrichment of CVEs (Vulnrichment/SSVC), sensors on federal and critical-infrastructure networks (EINSTEIN, now CADS, plus CyberSentry), and a human tip-to-victim phone-tree for ransomware (PRNI under JCDC). The parts that work best are narrow, criteria-driven and fast to act on (KEV, PRNI). The broad indicator-sharing pipe (AIS) has declined badly and its legal basis is uncertain.

### Cited Findings

**Automated Indicator Sharing (AIS): what it is and its decline**
- DHS OIG report OIG-24-60 (Sept 2024): AIS use fell to its lowest level since 2017. Indicator sharing dropped 93% from 2020 to 2022. Federal indicator collection fell from 9,484,158 (2021) to 413,834 (2022), a drop of about 96%. CISA partly blamed an "incoming federal partner" that stopped sharing over "unspecified security concerns." — [FedScoop on OIG-24-60](https://fedscoop.com/cisa-threat-information-sharing-dhs-oig-report/); [OIG-24-60 PDF](https://oig.dhs.gov/sites/default/files/assets/2024-09/OIG-24-60-Sep24.pdf)
- AIS participants fell from 304 (CY2020) to 135 (CY2022). — [The Record](https://therecord.media/cisa-pledges-to-resolve-threat-sharing-program-issues-oig-report); [Federal News Network](https://federalnewsnetwork.com/?p=5175814)
- CISA "paused outreach efforts for promoting AIS in May 2022" without explanation. At least one major stakeholder was unaware AIS existed. A planned Quality Service Management Office never launched. The OIG "could not identify detailed FY 2021 and FY 2022 funding expenditures for the AIS capability." — [FedScoop](https://fedscoop.com/cisa-threat-information-sharing-dhs-oig-report/)
- AIS 2.0 was finished in March 2022. It added a single submission portal, submission status tracking, filtering and anonymous submissions. — [FedScoop](https://fedscoop.com/cisa-threat-information-sharing-dhs-oig-report/)
- Press coverage of OIG-24-60 also reports that the OIG found indicator quality was not adequate for participants to act on. I saw this only in search-result summaries, not in the PDF text. — [OIG-24-60 PDF](https://oig.dhs.gov/sites/default/files/assets/2024-09/OIG-24-60-Sep24.pdf); [GovInfoSecurity, "death spiral"](https://www.govinfosecurity.com/experts-warn-cisas-threat-sharing-in-death-spiral-a-26426)
- OIG-25-46 (Sept 2025), "CISA Has Not Finalized Plans for Automated Cyber Threat Information Sharing Beyond Cybersecurity Act of 2015 Expiration": 2024 had 18 federal and 87 non-federal participants. Some non-federal participants are ISACs/ISAOs that each represent hundreds of organisations. The acting director said there were no near-term plans to discontinue AIS. — [Inside Cybersecurity copy of OIG-25-46](https://insidecybersecurity.com/sites/insidecybersecurity.com/files/documents/2025/sep/cs2025_0171.pdf); [CyberScoop](https://cyberscoop.com/watchdog-cyber-threat-information-sharing-programs-future-uncertain-with-expected-expiration-of-2015-law/)
- CISA concurred with the OIG recommendations: a recruitment and retention strategy with metrics, and documented AIS costs. It commissioned an independent AIS evaluation, "including alternative information-sharing systems", with recommendations due by July 31, 2025. — [FedScoop](https://fedscoop.com/cisa-threat-information-sharing-dhs-oig-report/)
- Legal basis: the liability, antitrust and disclosure protections of the Cybersecurity Information Sharing Act of 2015 lapsed on Sept 30, 2025. A November 2025 funding law reauthorised them to Jan 30, 2026, and a February 2026 law extended them to Sept 30, 2026. A Sept 3, 2026 CRS update still treated expiry as hypothetical. A single vendor source says the Senate passed an extension to Dec 11, 2026 on Aug 8, 2026, and that the House backed a long renewal in the FY2027 NDAA. — [Davis Wright Tremaine (Oct 2025)](https://dwt.com/blogs/privacy--security-law-blog/2025/10/cybersecurity-information-sharing-act-expires); [Data Protection Report (Nov 2025)](https://www.dataprotectionreport.com/2025/11/update-cisa-2015-is-reauthorized-until-january-2026/); [Hunton (extension to Sept 2026)](https://hunton.com/privacy-and-cybersecurity-law-blog/congress-extends-cybersecurity-information-sharing-act-of-2015-through-september-2026); [CRS IF12959 (Sept 3, 2026)](https://www.everycrsreport.com/files/2026-09-03_IF12959_e88b818ccb3aca205dcf1ba233b57cd55207205b.html); [Bright Defense](https://www.brightdefense.com/news/cisa-2015-faces-september-30-expiration/); [Nextgov (May 2026)](https://www.nextgov.com/cybersecurity/2026/05/trump-admin-will-push-long-term-reauthorization-key-cyber-data-sharing-law/413395/)
- AI inside AIS, from CISA's own AI use-case inventory:
  - DHS-4 "Automated Detection of PII in Cybersecurity Data" uses keyword and information extraction to flag personal data in submissions for analyst review. Status: operation and maintenance.
  - DHS-5 "Confidence Scoring for Cybersecurity Threat Indicators" uses "a decision-tree model" to give each submission a reliability score so analysts can prioritise review. Status: operation and maintenance.
  - Source: [CISA AI Use Cases](https://cisa.gov/ai/cisa-use-cases)
- ACT-IAC describes the PII detector as NLP, including named-entity recognition, combined with privacy-guidance thresholds. — [ACT-IAC](https://www.actiac.org/et-use-case/automated-pii-detection)

**Known Exploited Vulnerabilities (KEV) catalog and the BOD 26-04 risk model**
- A CVE enters KEV only if it meets three criteria: (1) it has a CVE ID; (2) there is "reliable evidence that the vulnerability has been actively exploited in the wild"; (3) "there is a clear remediation action ... such as a vendor-provided update." — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities)
- Active exploitation means "reliable evidence that execution of malicious code was performed by an actor" without the owner's permission. Failed attempts count, including against honeypots. Scanning, security research and proof-of-concept code do not count, and a public PoC is not required. — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities)
- CISA calls KEV the "authoritative repository" for the exploitation-status input to SSVC-style frameworks. — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities)
- BOD 26-04, "Prioritizing Security Updates Based on Risk" (June 10, 2026), replaces one-deadline-fits-all KEV patching with risk-based urgency. Per Qualys, the factors are asset exposure, KEV status, exploit automation and technical impact. It covers on-premises, third-party-hosted and FedRAMP and non-FedRAMP cloud systems. — [SecurityWeek](https://www.securityweek.com/cisa-directs-federal-agencies-to-prioritize-security-patches-based-on-risk/); [Qualys BOD 26-04 docs](https://docs.qualys.com/en/etm/latest/cisa_bod/bod_overview.htm); [Covington Inside Privacy](https://www.insideprivacy.com/cybersecurity-2/cisa-releases-binding-operational-directive-on-prioritizing-security-updates-based-on-risk/)
- Sources disagree on what BOD 26-04 replaces. BleepingComputer says it "supersedes and revokes" BOD 19-02 and BOD 22-01; its headline reports a 3-day deadline for critical exploited flaws. CISA's KEV page says it "carries forward the KEV catalog criteria from BOD 22-01." — [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-tells-govt-agencies-to-patch-critical-exploited-flaws-in-3-days/amp); [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities)
- A third-party compliance blog gives milestones of Aug 7, 2026 (policy updates) and Dec 7, 2026 (remediation under the new timelines). These are unverified against the directive text. — [compliancehub.wiki](https://compliancehub.wiki/bod-26-04-august-7-deadline-fortinet-arista-kev-risk-based-patching/); [runZero](https://www.runzero.com/blog/bod-26-04/)
- KEV dissemination: each addition goes out as a GovDelivery bulletin ("CISA Adds N Known Exploited Vulnerabilities to Catalog"). — [example bulletin](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/41ffb74)

**Vulnrichment / SSVC: decision-tree scoring CISA publishes into CVE records**
- CISA writes into its ADP (Authorized Data Publisher) container in each CVE record: "CISA is assessing new and recent CVEs and adding key SSVC decision points." Every analysed CVE gets three decision points:
  - **Exploitation**: none, poc ("a public proof-of-concept available at the time of analysis") or active.
  - **Automatable**: yes or no.
  - **Technical Impact**: partial or total ("total control over the impacted software").
  - CISA uses SSVC 2.0 with the "CISA Coordinator tree" version 3. — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)
- Other ADP fields: a KEV block (`"type": "kev"`, `dateAdded`, `reference`), a CWE when the CNA gave none, and CVSS 3.1 for some higher-risk CVEs. CISA stopped adding CPE strings on Dec 10, 2024. CISA never overwrites the CNA's own data; if the CNA later adds CWE/CVSS/CPE, CISA drops its own. — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)
- Vulnrichment data can be read through the GitHub repo or the CVE Services API, organised by year and CVE ID range. Anyone already consuming live CVE data gets it automatically. — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)
- CISA describes SSVC as weighing "exploitation status, impacts to safety, and prevalence of the affected product." — [SecurityWeek on Vulnrichment launch (2024)](https://www.securityweek.com/cisa-announces-cve-enrichment-project-vulnrichment/amp/)

**CyberSentry: sensors inside critical-infrastructure networks**
- CyberSentry is a voluntary, CISA-managed capability under agreements with critical-infrastructure partners that run systems supporting National Critical Functions. It watches IT and OT networks for "known and unknown malicious activity." CISA places hardware and software at partner sites at no cost to the partner. — [CISA CyberSentry](https://www.cisa.gov/cybersentry); [CyberSentry factsheet (2023)](https://www.cisa.gov/sites/default/files/2023-06/CyberSentry_Factsheet_508c.pdf)
- CISA's case studies include infected OT equipment, unintentional exposure, the SolarWinds response and malware discovery. — [CISA CyberSentry](https://www.cisa.gov/cybersentry)
- Weakness: on July 20, 2025, the agreement under which Lawrence Livermore National Laboratory analysed CyberSentry data expired. Sensors kept collecting, but LLNL said the data was not being reviewed. CISA said the program "remains fully operational." — [CyberScoop](https://cyberscoop.com/contract-lapse-leaves-critical-infrastructure-cybersecurity-sensor-data-unanalyzed-at-national-lab/); [The Register](https://www.theregister.com/2025/07/22/lapsed_cisa_funding_cybersentry/); [Federal News Network](https://federalnewsnetwork.com/cybersecurity/2025/07/agreement-for-critical-cisa-cyber-threat-analysis-work-expires/)
- AI: DHS-106 "Critical Infrastructure Network Anomaly Detection" applies unsupervised ML (anomaly detection, continuous estimation, generative AI) to CI networks. Status: initiation. — [CISA AI Use Cases](https://cisa.gov/ai/cisa-use-cases)

**EINSTEIN / NCPS to CADS (Cyber Analytics and Data System) / JCE**
- In the FY2024 budget (2023), CISA asked for about $425M for CADS to restructure NCPS. NCPS's analytics, information-sharing and core-infrastructure parts move to CADS; the EINSTEIN intrusion detection and prevention suite does not. — [Federal News Network (Mar 2023)](https://federalnewsnetwork.com/cybersecurity/2023/03/cisa-lays-out-post-einstein-future-with-shift-to-cyber-analytics-and-data-system/); [ExecutiveGov](https://executivegov.com/2023/03/cisa-seeks-425m-in-fy24-budget-for-cyber-analytics-and-data-system/)
- House Homeland Democrats (2023) said legacy EINSTEIN capabilities and CADS will become the "Joint Collaboration Environment" (JCE). — [House Homeland Democrats statement](https://democrats-homeland.house.gov/download/menendez-opening-statement-cip-091923&download=1)
- The FY2025 budget lists $394.1M for JCE efforts and describes CADS as "modern, scalable, unclassified analytic infrastructure for CISA's cyber operators." — [GovConWire](https://www.govconwire.com/articles/cisa-3b-fy-2025-budget)
- Reporting described EINSTEIN as having "limited effectiveness against novel threats." It was signature-based. — [FedScoop](https://fedscoop.com/cisa-considers-the-future-state-of-einstein-as-agencies-modernize/)
- AI: DHS-2403 "SOC Network Anomaly Detection" runs unsupervised learning over "terabytes of daily sensor log data" (EINSTEIN/CADS sensors) to help analysts narrow and prioritise investigations. Status: operation and maintenance. — [CISA AI Use Cases](https://cisa.gov/ai/cisa-use-cases)

**JCDC and the pre-ransomware notification initiative (PRNI): the clearest "warn before damage" metric**
- JCDC is a public-private collaborative set up under 2021 NDAA authorities. — [CISA JCDC](https://cisa.gov/jcdc)
- How PRNI works (CISA, March 23, 2023): ransomware actors often wait "hours to days" between initial access and encryption. JCDC receives tips from "the cybersecurity research community, infrastructure providers, and cyber threat intelligence companies." CISA field staff then contact the victim with specific mitigation guidance, and international CERTs are used for non-US victims. CISA stressed "Without these tips, there are no notifications!" — [CISA blog](https://www.cisa.gov/news-events/news/getting-ahead-ransomware-epidemic-cisas-pre-ransomware-notifications-help-organizations-stop-attacks)
- Scale over time:
  - Early 2023: 60+ entities notified. — [CISA blog](https://www.cisa.gov/news-events/news/getting-ahead-ransomware-epidemic-cisas-pre-ransomware-notifications-help-organizations-stop-attacks)
  - 2023: more than 1,200 notifications. — [Cybersecurity Dive](https://www.cybersecuritydive.com/news/cisa-pre-ransomware-alerts/705046)
  - 2023: 154 of those went to healthcare organisations. — [HIPAA Journal (Feb 2024)](https://www.hipaajournal.com/cisa-pre-ransomware-alerts-helped-154-healthcare-organizations-save-millions-in-costs/)
  - 2024: 2,131 notifications as of November, for 3,368 in total since inception. — [Cybersecurity Dive](https://cybersecuritydive.com/news/cisa-pre-ransomware-alerts-double/735785); [Risky Bulletin](https://www.risky.biz/risky-bulletin-cisa-sent-2-100-pre-ransomware-alerts-this-year)
  - Late 2022 to Oct 2025: more than 4,300 notifications, "potentially preventing an estimated $9 billion in economic damage" (no method given). — [SANS (Oct 14, 2025)](https://www.sans.org/blog/cisas-pre-ransomware-notification-and-you)
- Lead time: CISA can notify a potential victim "in less than an hour," and most notifications go out the same day the intelligence arrives. This compares with ransomware operators reaching domain admin in as little as 8–9 minutes after initial access. Some recipients assume the call is a scam. — [SANS](https://www.sans.org/blog/cisas-pre-ransomware-notification-and-you)
- Single anecdotes: one notification "prevented an estimated $350 million attack" on a mass-transit partner (no method given). — [HIPAA Journal](https://www.hipaajournal.com/cisa-pre-ransomware-alerts-helped-154-healthcare-organizations-save-millions-in-costs/)
- Ransomware Vulnerability Warning Pilot (RVWP, started Jan 2023): CISA scans for internet-facing devices with vulnerabilities that ransomware gangs use and warns the owners. It sent 1,754 notifications in CY2023, and 852 led to patching, a compensating control or the device going offline (about 49% action rate). — [ExecutiveGov](https://www.executivegov.com/articles/cisa-offers-update-on-ransomware-vulnerability-warning-pilot-program)
- JCDC published an AI Cybersecurity Collaboration Playbook on Jan 14, 2025, based on two 2024 AI tabletop exercises. — [CISA press release](https://cisa.gov/news-events/news/cisa-jcdc-government-and-industry-partners-publish-ai-cybersecurity-collaboration-playbook); [JCDC AI Playbook PDF](https://cisa.gov/sites/default/files/2025-01/JCDC%20AI%20Playbook.pdf)

### Inferences
- CISA's strongest early-warning products pair one external signal with a known owner and a concrete action: a PRNI tip plus a victim plus "evict now", or a KEV entry plus an asset plus "patch by date". AIS shared high-volume indicators with no owner context and low confidence, and participation fell. For a prototype this argues for an **asset-correlated alert** over a raw IOC feed.
- BOD 26-04's four factors (exposure, KEV status, automation, technical impact) map almost one-to-one onto SSVC decision points and onto the hackathon brief's flow (advisory, then asset inventory, then exposure, then risk). It is a defensible "government-grade" scoring basis to cite.
- PRNI's time-to-notify (under 1 hour, same day) is one of the few published lead-time KPIs anywhere. A prototype can display "time from advisory ingest to alert" as its headline metric.

### Gaps
- No 2025 or 2026 calendar-year PRNI or RVWP counts found. The latest is ">4,300 cumulative" (Oct 2025).
- The CISA 2015 reauthorisation outcome after Sept 30, 2026 is unconfirmed.
- AIS's STIX 2.1/TAXII 2.1 transport is widely documented, but I did not re-fetch the CISA AIS page this session. Verify at cisa.gov/ais before citing.
- Current CADS/JCE deployment status and FY2026/27 funding not found.
- Whether the CyberSentry LLNL analysis agreement was renewed after July 2025 is unknown.
- I found no official CISA statement of average KEV inclusion lag.

---

## 2. United Kingdom: NCSC (Early Warning, Active Cyber Defence, CiSP, AI)

### Takeaway
The UK model is "Active Cyber Defence" (ACD): free, automated, at-scale services that match NCSC-held or privileged threat data against assets that organisations register (IPs and domains). Early Warning reaches 13,178 organisations, and takedowns are measured in hours. The legacy community-sharing platform CiSP was shut down on 28 Nov 2025. NCSC's public AI material is mostly threat assessment rather than published defensive AI use.

### Cited Findings

**Early Warning: how it works**
- Free service designed to "inform your organisation as soon as possible" of potential attacks. It draws on NCSC feeds plus trusted public, commercial and closed sources, including "several privileged feeds not available elsewhere." It filters the millions of events NCSC receives every day and correlates them against the IP addresses and domains each organisation registers. "Early Warning does not conduct any active scanning of your networks itself", although some commercial feeds may be scan-derived. — [MyNCSC Early Warning service description](https://www.ncsc.gov.uk/collection/myncsc-help-centre/service-descriptions/early-warning); [NCSC Early Warning](https://www.ncsc.gov.uk/section/active-cyber-defence/early-warning)
- Three alert types:
  - **Incident Notifications**: likely active compromise, e.g. a host infected with malware. Shown as "Suspected compromise".
  - **Network Abuse Events**: assets linked to malicious or unwanted activity, e.g. a client scanning the internet. Also shown as "Suspected compromise".
  - **Vulnerability and Open Port Alerts**: exposed vulnerable services, e.g. an exposed Elasticsearch. Shown as "Known vulnerability".
  - Source: [MyNCSC](https://www.ncsc.gov.uk/collection/myncsc-help-centre/service-descriptions/early-warning)
- Delivery cadence: findings appear in the MyNCSC portal immediately. Emails for compromise and abuse go out daily and vulnerability/open-port emails weekly, usually between 08:00 and 10:00, with out-of-hours contact for critical or one-off alerts. Owners can set a finding to "Marked as fixed" or "Risk accepted" in MyNCSC. — [MyNCSC](https://www.ncsc.gov.uk/collection/myncsc-help-centre/service-descriptions/early-warning)
- Stated limitation: NCSC says Early Warning should not be the only layer of defence for a network. — [NCSC Early Warning](https://ncsc.gov.uk/earlywarning)
- Scale, Annual Review 2025 (1 Sept 2024 to 31 Aug 2025):
  - 13,178 organisations signed up.
  - 316,343 customer IPs alerted.
  - 131,000 IPs suspected of compromise, reported to 1,350 organisations.
  - Vulnerability reports covering 187,000 IPs, sent to 4,030 organisations.
  - Source: [NCSC Annual Review 2025, ACD chapter](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)

**Other ACD services and measured outcomes (Annual Review 2025)**
- **Takedown**: 1.2 million commodity campaigns removed. More than 26,000 phishing campaigns against HMG departments disrupted. 79% of confirmed HMG-targeted phishing resolved within 24 hours of detection. 50% taken down in under 1 hour, against about 4 hours the year before. — [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)
- **Share and Defend** (since March 2025): shares takedown-derived malicious-domain feeds with ISPs such as BT for blocking. NCSC says it has blocked "millions" of attempts but gives no number. — [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)
- **Protective DNS (PDNS)**: more than 13,000 schools protected. PDNS for high-risk individuals has about 600 registered users. — [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)
- **Mail Check**: 13,193 organisations, 402,796 domains, 1,014,887 Urgent or Advisory alerts. **Web Check**: 4,624 organisations, 133,913 domains/URLs, 569,467 alerts. — [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)
- **Suspicious Email Reporting Service (SERS)**: more than 10.9 million reports in the year, over 45 million since April 2020, and 412,000 malicious URLs removed since 2020. — [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)
- **Proactive Notifications Service** (pilot, "Minimum Viable Product"):
  - Netcraft finds vulnerable internet-facing systems from "open source information, such as publicly available software versions" and emails the owners.
  - Emails come from a netcraft.com address in plaintext, with no attachments and no requests for personal information or payment.
  - The service "does not cover all systems or vulnerabilities" and "must not be relied upon as the sole source of security alerts."
  - Sources: [NCSC Proactive Notifications](https://www.ncsc.gov.uk/information/proactive-notifications-service); [PDF dated 2026-07](https://www.ncsc.gov.uk/sites/default/files/2026-07/NCSC-Proactive-Notifications-Service.pdf)

**CiSP**
- The Cyber Security Information Sharing Partnership was "decommissioned on 28 November 2025" as part of NCSC's digital transformation. No successor is named. — [NCSC CiSP page](https://www.ncsc.gov.uk/cisp/home)
- Earlier plans for a "CiSP 2.0" (2021–2023) were never shown to have been delivered. — [UKAuthority (2021)](https://ukauthority.com/articles/ncsc-plans-for-new-version-of-cisp); [UKAuthority (spring 2023 relaunch plan)](https://ukauthority.com/articles/new-version-of-cisp-to-launch-in-spring-2023/)

**AI**
- NCSC's assessment "Impact of AI on cyber threat from now to 2027" (May 2025, launched at CYBERUK) judges that AI will "highly likely" raise the volume and impact of intrusions by improving existing TTPs. It expects AI to "compress the window between the disclosure and exploitation of vulnerabilities even further." It sees "almost certainly" a digital divide between systems that keep pace with AI-enabled threats and the rest. Judgements use the PHIA probability yardstick ("realistic possibility", "almost certainly", and so on). — [NCSC report](https://www.ncsc.gov.uk/report/impact-ai-cyber-threat-now-2027); [NCSC news](https://www.ncsc.gov.uk/news/ai-to-2027-threat-assessment)
- The 2025 ACD chapter does not describe any AI or ML used inside ACD services. — [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)

### Inferences
- Early Warning is the closest national analogue to the hackathon brief. The organisation registers its assets, the centre correlates external threat events against them, and it pushes typed, triaged findings. Each finding carries a status lifecycle (open, then fixed or risk-accepted) and a cadence (immediate for critical, daily digest, weekly vulnerability roll-up).
- NCSC reports outcome KPIs, not just volume: share resolved within 24 hours, median takedown time, year-on-year comparison. A prototype dashboard can mirror this with "time-to-alert" and "share of alerts acknowledged or fixed".
- The CiSP shutdown alongside growing push services suggests a move away from forum-style sharing toward automated, asset-matched notification. This is a judgement, not something NCSC stated.

### Gaps
- No published Early Warning lead-time metric: there is no measured time from event to alert.
- No description of how Early Warning ranks alerts beyond the three types, and no public API or format (STIX etc.) documented on the service page.
- Proactive Notifications pilot volumes are not published.
- I found no official NCSC statement on using LLMs for CTI triage internally.

---

## 3. European Union: ENISA, CERT-EU, Cyber Solidarity Act alert system ("European Cyber Shield"), EUVD

### Takeaway
The EU is building a federated, AI-labelled alert system: national and cross-border Cyber Hubs set up under the Cyber Solidarity Act, in force since 4 Feb 2025. Alongside it sit a regulator-run vulnerability database (EUVD, live May 2025) and a 24-hour exploited-vulnerability reporting duty for manufacturers under the Cyber Resilience Act (from 11 Sept 2026). Public technical detail on how the hubs' AI works is thin. The EUVD has documented coverage gaps.

### Cited Findings

**Cyber Solidarity Act and the European Cybersecurity Alert System**
- The Act entered into force on 4 Feb 2025. It creates a "European Cybersecurity Alert System" of National and Cross-Border Cyber Hubs interconnected across the EU that use "advanced technology such as Artificial Intelligence (AI) and data analytics" to detect threats and share warnings across borders. — [European Commission, Cyber Solidarity (updated 17 Aug 2026)](https://digital-strategy.ec.europa.eu/en/policies/cyber-solidarity)
- First phase (Nov 2022, Digital Europe Programme): two consortia of cross-border SOCs, now called Cyber Hubs, were selected. Cross-border hubs must interoperate, conclude cooperation agreements and cooperate closely with the CSIRTs Network. — [European Commission](https://digital-strategy.ec.europa.eu/en/policies/cyber-solidarity)
- Budget:
  - €100M is re-allocated within DIGITAL, bringing DIGITAL cybersecurity funding to €842.8M.
  - Hubs and preparedness for 2023–2027 could reach €551M, plus €115M of 2021–22 pilots.
  - Including member-state contributions, the total could reach about €1.109B.
  - Source: [European Commission](https://digital-strategy.ec.europa.eu/en/policies/cyber-solidarity)
- Also created:
  - a Cybersecurity Emergency Mechanism, covering preparedness testing, an EU Cybersecurity Reserve of private "trusted providers" and mutual assistance;
  - an Incident Review Mechanism, in which ENISA reviews significant or large-scale incidents.
  - Source: [European Commission](https://digital-strategy.ec.europa.eu/en/policies/cyber-solidarity)
- The "European Cybersecurity Shield" label appears in press coverage of the regulation. The Commission page does not use the term. — [SecurityWeek](https://www.securityweek.com/new-eu-regulation-establishes-european-cybersecurity-shield/amp/)
- 2026 funding calls for hosting or expanding cross-border hubs exist. A 28 May 2026 deadline is reported by a secondary source. — [ECCC call for expressions of interest](https://cybersecurity-centre.europa.eu/call-expression-interest-national-cyber-hubs_de); [Proposia (secondary)](https://proposia.ai/open-calls/cross-border-cyber-hubs-87e3a5)

**EUVD (EU Vulnerability Database)**
- Mandated by NIS2 Article 12. Launched and fully operational in May 2025. Built as a downstream complement to CVE (not a replacement) that enriches records with CVSS, CWE and exploitation status. — [CSA research note (May 2026)](https://labs.cloudsecurityalliance.org/research/csa-research-note-enisa-cve-root-dual-governance-20260518/); [BDO Malta](https://www.bdo.com.mt/en-gb/news/news-in-2025/enisa-launches-the-european-vulnerability-database)
- Three dashboards: critical, actively exploited, and EU-coordinated (handled by European CSIRTs). It runs on the open-source Vulnerability-Lookup software. EUVD IDs map to CVE IDs. CVE and KEV data are pulled in automatically. CSAF advisory support is planned or partial. — [Cybersecurity News](https://cybersecuritynews.com/enisa-launches-euvd); [InfoQ via x-cmd](https://x-cmd.com/blog/250611); [Tech Monitor](https://www.techmonitor.ai/?p=416660); [NSF summary](https://www.nsf.org/th/en/life-science-news/eu-launches-central-vulnerability-database-euvd)
- ENISA became a CVE Numbering Authority in Jan 2024 and a CVE Program Root on 20 Nov 2025. Seven CNAs transferred from the MITRE Root and four new ones joined. — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-enisa-cve-root-dual-governance-20260518/)
- Weakness: VulnCheck found more than 50,000 CVEs absent from EUVD's main API endpoint. The CSA note says EUVD "currently has significant gaps" and cannot yet be a sole-source feed. — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-enisa-cve-root-dual-governance-20260518/)
- Empirical study (arXiv 2602.14313, Feb 2026):
  - EUVD held 1,510 actively exploited and 1,291 CSIRT-coordinated vulnerabilities.
  - Spain's INCIBE coordinated a clear majority of the CSIRT-coordinated ones; ENISA itself about 2.1%.
  - The authors criticise the lack of documentation on how "active exploitation" is determined, and note the CRA is "mostly silent" on it.
  - The paper's collection date is printed as "15 Dec 2026", likely a typo for 2025.
  - Source: [Ruohonen, arXiv](https://arxiv.org/html/2602.14313v1)
- Cyber Resilience Act Article 14, from 11 Sept 2026: manufacturers must send an **early warning within 24 hours** of becoming aware of an actively exploited vulnerability, a notification within 72 hours and a final report within 14 days of a fix. Reports go through ENISA's Single Reporting Platform to the national CSIRT and ENISA. — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-enisa-cve-root-dual-governance-20260518/); [ENISA vulnerability services](https://www.enisa.europa.eu/topics/vulnerability-services)

**CERT-EU**
- The cybersecurity service for EU institutions, bodies, offices and agencies under Regulation (EU) 2023/2841. — [CERT-EU about](https://cert.europa.eu/about-us)
- Threat Landscape Report 2025 (published Apr 2026):
  - at least 174 distinct threat actors targeted Union entities or their ecosystem, up from 110 in 2024;
  - actors used AI for voice cloning, personalised phishing and deepfakes of officials;
  - a reportedly China-linked actor directed a "jailbroken agentic AI system against 30 entities," achieving autonomous intrusion in a few cases.
  - Source: [CERT-EU TLR 2025 blog](https://www.cert.europa.eu/blog/threat-landscape-report-2025)
- The report is published in PDF and JSON. — [CERT-EU TLR JSON endpoint](https://cert.europa.eu/publications/threat-intelligence/tlr2025/json)
- Tooling: MISP since about 2013; job listings cite MISP and OpenCTI. Indicators go to the constituency via MISP, with access tiers based on constituency status, NDA or MISP community membership. — [OSOR MISP case study](https://interoperable-europe.ec.europa.eu/collection/open-source-observatory-osor/document/case-study-misp); [CERT-EU presentation at ENISA](https://enisa.europa.eu/events/cti-eu-event/cti-eu-event-presentations/cert-eu-presentation)
- A CERT-EU "Cyber Threat Intelligence Framework" (13 Feb 2026) reportedly formalises how threats are classified, assessed and prioritised. This comes from a third-party blog; I found no primary source. — [andreafortuna.org](https://andreafortuna.org/2026/02/23/cert-eu-cti-framework/)

### Inferences
- The CRA's 24h/72h/14d cadence is a ready-made, legally anchored template for staged alert products: early warning, then notification, then final report.
- EUVD's three views (critical, exploited, coordinated) are a cheap, defensible dashboard layout for a prototype.
- EUVD runs on CIRCL's open-source Vulnerability-Lookup. A national database can therefore be bootstrapped from open-source tooling plus CVE/KEV sync, which is relevant to showing judges the approach is realistic.

### Gaps
- No public technical description of the Cyber Hubs' AI and analytics (models, data sources, formats). I could not confirm the names of the hub consortia or how many hubs exist in 2026.
- No EUVD API changelog or current entry count for 2026 found.
- ENISA Threat Landscape 2025 content on defensive AI was not retrieved.

---

## 4. Israel: INCD "Cyber Dome"

### Takeaway
Israel's Cyber Dome is publicly framed as a big-data, AI-driven national proactive-defence layer, with generative AI used to separate genuine threats from noise. However, almost no technical, scale or outcome data has been published. Treat it as a concept with press-level evidence only.

### Cited Findings
- Announced June 2022 at Tel Aviv University Cyber Week by INCD Director-General Gaby Portnoy as a "big-data and artificial intelligence approach to proactive defense." INCD said its teams thwarted about 1,500 attacks in the previous year. No operational date was given. — [JNS](https://www.jns.org/israel-national-cyber-directorate-announces-national-cyber-dome/); [The Register](https://www.theregister.com/2022/06/30/israel_cyber_dome/)
- October 2023 reporting: the Dome includes "generative AI platforms to help filter out genuine threats from the sea of threat intelligence and cyberattack claims" parsed daily. Staff reportedly come from IDF Unit 8200, IDF cyber units, Mossad and Shin Bet cyber units and the Defence Ministry. — [The Defense Post](https://www.thedefensepost.com/2023/10/17/israel-developing-cyber-dome); [The Week](https://www.theweek.in/magazine/theweek/cover/2023/10/14/how-israel-plans-for-hybrid-wars-of-the-future-with-the-cyber-dome.html)
- Analysts note "there are no definite details about the mechanisms and tools" of the initiative. — [MP-IDSA](https://www.idsa.in/publisher/from-iron-dome-to-cyber-dome-defending-israels-cyberspace/)
- Dark Reading covered "AI-powered Israeli Cyber Dome defense operation comes to life" (2023). The page returned HTTP 403, so its content was not verified. — [Dark Reading](https://www.darkreading.com/dr-global/ai-powered-israeli-cyber-dome-defense-operation-comes-to-life)

### Inferences
- The one concrete design idea is using an LLM to triage and filter a flood of threat-intel items and hacktivist "attack claims" into verified threats. That is directly relevant and copyable as an LLM triage step with a "claimed vs verified" label.

### Gaps
- No 2025–2026 primary INCD sources found on Cyber Dome status, scale, sensors, scoring or outcomes. No details found on INCD's information-sharing platform name or formats.

---

## 5. Singapore: CSA

### Takeaway
Singapore's public material emphasises partnerships with hyperscalers for AI-driven threat-intel sharing (Google, AWS, Microsoft, TRM Labs) and annual threat-landscape reporting. Little technical detail on its national sensor or sharing architecture is public.

### Cited Findings
- Singapore International Cyber Week, Oct 2025:
  - Google signed a Memorandum of Cooperation with CSA covering "AI-driven threat intelligence sharing, joint operations against malicious cyber activities, and technical co-development of AI-powered security solutions."
  - AWS signed an MOC on intelligence sharing and joint incident operations for systems of national importance.
  - TRM Labs is giving CSA access to its blockchain-intelligence platform with generative and reasoning AI features.
  - Sources: [CRN Asia](https://www.crnasia.com/news/2025/cybersecurity/csa-singapore-announces-partnerships-with-google); [FCC Singapore](https://www.fccsingapore.com/news/n/news/singapore-strengthens-its-cyber-defenses-with-google-aws-and-trm-labs.html)
- CSA also announced collaborations with Microsoft and Google on national cyber defence. — [CSA press release](https://www.csa.gov.sg/news-events/press-releases/csa-collaborates-with-microsoft-and-google-to-strengthen-national-cyber-defence-and-cybersecurity/)
- Singapore Cyber Landscape 2025/2026 (30 June 2026): threat actors are "increasingly harnessing artificial intelligence (AI) to conduct cyber-attacks at greater speed, scale and sophistication," and AI "also offers a powerful defensive tool." — [SCL 2025/2026 PDF](https://isomer-user-content.by.gov.sg/36/e3a2bc10-c70a-4b06-bf46-4847e1d8b358/Singapore%20Cyber%20Landscape%202025_2026.pdf); [Baker McKenzie summary](https://www.bakermckenzie.com/en/insight/publications/2026/07/singapore-csa-cyber-landscape-report-2025-2026)
- CSA, 3 Sept 2025:
  - ransomware cases rose from 132 (2023) to 159 (2024);
  - infected infrastructure rose 67% to 117,300 systems in 2024;
  - a Sept 2024 international botnet operation remediated 2,700 infected devices in Singapore;
  - Critical Information Infrastructure spans 11 sectors.
  - Source: [CSA press release](https://www.csa.gov.sg/news-events/press-releases/a-decade-of-strengthening-singapore-s-cyber-defence-amid-escalating-threats)
- CSA published guidelines and a companion guide on securing AI systems, and a discussion paper on securing agentic AI (Oct 2025). — [CSA press release](https://www.csa.gov.sg/news-events/press-releases/a-decade-of-strengthening-singapore-s-cyber-defence-amid-escalating-threats); [OpenGov Asia](https://opengovasia.com/singapore-expands-cybersecurity-measures-amid-ai-driven-threats/)

### Inferences
- Singapore's approach suggests that a small state buys AI capability through vendor partnerships rather than building it. For a prototype, "pluggable intel connectors" is the analogous design point.

### Gaps
- A search summary claimed CSA runs an "Automated Indicator Sharing Platform" for CII owners. I could not confirm this on a primary CSA page, so treat it as unverified. No details found on SingCERT alert formats, sensors or AI internals.

---

## 6. Japan: NICT NICTER and the DAEDALUS darknet alert system

### Takeaway
Japan's NICTER is the purest example of **sensor-led early warning**. About 280,000–300,000 unused IPv4 addresses (a "darknet") passively capture unsolicited traffic, about 701 billion packets in 2025. Surges in scanning reveal new worms, botnets and exploitation campaigns. DAEDALUS turns this into per-organisation alerts by telling an organisation when its own IP addresses appear as sources in darknet traffic, which means it likely has an infected or abused host.

### Cited Findings
- NICT operates a darknet monitoring system of about 300,000 IPv4 addresses. — [NICT CSRI team page](https://csl.nict.go.jp/en/team-3.html)
- NICTER Observation Report 2025:
  - about 701 billion packets observed in 2025, up about 2.2%;
  - about 2.5 million packets per IP address, a record, against about 2.42 million in 2024 and about 250,000 in 2015 (roughly tenfold);
  - about 280,000 darknet addresses, measured on 26 Dec because of maintenance;
  - about 55% of packets are presumed research or survey scans.
  - Sources: [NICTER report 2025 PDF](https://csl.nict.go.jp/report/NICTER_report_2025.pdf); [NICTER reports index](https://csl.nict.go.jp/en/nicter-report.html); [MIC 2026 Information & Communications White Paper](https://www.soumu.go.jp/johotsusintokei/whitepaper/ja/r08/html/nd21a210.html); [ScanNetSecurity (Sept 2026)](https://scan.netsecurity.ne.jp/article/2026/09/08/56149.html)
- The annual report covers annual and daily packet trends, per-port counts, scanners, IoT bot-infected hosts and DRDoS attacks. — [NICTER reports](https://csl.nict.go.jp/en/nicter-report.html)
- DAEDALUS (Direct Alert Environment for Darknet And Livenet Unified Security) is a real-time alert system built on NICTER's darknet. It identifies organisations whose addresses appear in darknet traffic and notifies them. Alerts are aggregated per source IP rather than sent per packet. — [NICT journal vol.63 no.2](https://www.nict.go.jp/publication/shuppan/kihou-journal/journal-vol63no2/journal-vol63no2-03-04.pdf); [GIGAZINE (2012)](https://www.gigazine.net/gsc_news/en/20120606-nict-daedalus)
- DAEDALUS rollout:
  - alerts to Japanese local governments from Nov 2013; 110 local governments registered by Jan 2014;
  - about 600 local governments receiving free alerts by 2018, out of about 1,700;
  - extended to ASEAN countries under the JASPER project.
  - Sources: [NICT News 1403 (2014)](https://www.nict.go.jp/en/data/nict-news/NICT_NEWS_1403_E.pdf); [NICT News 2018-472](https://www.nict.go.jp/data/nict-news/NICT_NEWS_2018-472_J.pdf); [MIC document](https://www.soumu.go.jp/main_content/000488151.pdf)
- Companion systems:
  - STARDUST: a targeted-attack lure environment, a "parallel network" for watching attackers over long periods.
  - WarpDrive: user-participation sensing of web-borne attacks, launched 2018 and relaunched 2022.
  - Sources: [NICT CSRI](https://csl.nict.go.jp/en/team-3.html); [ScanNetSecurity (2022)](https://scan.netsecurity.ne.jp/article/2022/06/02/47679.html)
- NICT publishes darknet datasets, for example "NICT Darknet Dataset 2022." — [NICT dataset](https://csdataset.nict.go.jp/darknet-2022)

### Inferences
- Darknet telemetry is a true **leading indicator**. Mass scanning for a port or service usually precedes broad exploitation, and a victim's own IP showing up as a scanner is an early sign of compromise. The roughly 55% research-scanner share shows the need for a "known benign scanner" allow-list before alerting.
- For a 24-hour prototype, live darknet capture is [no], since it needs a large unused IP block and also risks the no-active-network-activity rule. Replaying a published darknet dataset or simulated scan-rate time series with spike detection is [24h].

### Gaps
- No current (2025–26) count of DAEDALUS recipients. No published lead-time numbers, such as how many days before KEV or CVE a scan surge was seen. I did not see ML or LLM use described in the NICTER material I retrieved.

---

## 7. South Korea: KISA C-TAS

### Takeaway
KISA's C-TAS (Cyber Threat Analysis & Sharing, since 2014) is a national threat-intel sharing hub that was opened to all companies in C-TAS 2.0 (2021–22). In August 2026 KISA began piloting a per-company, attack-surface-tailored alert service. That is the same "register your assets, get matched alerts" model as NCSC Early Warning and the hackathon brief.

### Cited Findings
- KISA has provided threat information to companies through C-TAS since 2014. In Aug 2026, KISA and MSIT recruited companies for a trial "Attack Surface-Tailored Threat Alert Service":
  - it combines C-TAS threat data with attack surface management (ASM);
  - it monitors registered IPs, service domains and software in real time and flags threats to them;
  - the trial targets SMEs registered with C-TAS;
  - the aim is to verify "detection accuracy and operational stability."
  - Rationale: the older approach made it hard to spot threats specific to each firm's environment. No AI component is described.
  - Source: [Seoul Economic Daily (6 Aug 2026)](https://en.sedaily.com/technology/2026/08/06/kisa-launches-tailored-cyber-threat-alert-service-for-firms)
- C-TAS 2.0: C-TAS 1.0 was reorganised into a user-centred 2.0 with trial operation from Dec 2021 and full operation from Jan 2022, opened to any company that wants threat information. — [Byline Network (Dec 2021)](https://byline.network/2021/12/23-171/); [Boannews](https://m.boannews.com/html/detail.html?idx=103559)
- 2021-era scale: 112 participating organisations (public, private and military bodies, security vendors, ISPs) and about 200.1 million pieces of shared information. — [Asia Economy (2021)](https://cm.asiae.co.kr/en/article/2021052300123170551)
- KISA's Cyber Security Big Data Center aims to analyse threats with AI and big data and share the results with industry (2021). — [Asia Economy (2021)](https://cm.asiae.co.kr/en/article/2021052300123170551)

### Inferences
- In 2026, two national agencies (UK and Korea) independently converged on asset-matched alerting plus ASM. That supports framing the prototype as "national threat intel × organisation attack surface → tailored alert."

### Gaps
- Current C-TAS membership, data volumes, formats (STIX/TAXII or proprietary), AI internals and outcome metrics were not found. Most sources are 2015–2022 and in Korean.

---

## 8. Australia: ASD/ACSC (CTIS and partnership programs)

### Takeaway
Australia's CTIS is a two-way, machine-speed sharing platform with SIEM plug-ins for Microsoft Sentinel and Splunk. It has grown to more than 550 partners, who exchanged over 1 million IOCs in 2025-26, and it is reportedly mandatory for federal agencies since July 2025. It is a clear example of pushing intel straight into the tools defenders already use.

### Cited Findings
- Annual Cyber Threat Report 2025-26 (the 7th): CTIS "grew by 22% to over 550 partners, and shared over 1 million indicators of compromise via the platform." ASD's Cyber Security Partnership Program grew 12% to more than 149,500 partners, from more than 133,000 in 2024-25. These figures come from search-result extracts of cyber.gov.au pages; full-page fetches timed out. — [ACTR 2025-26 programs](https://www.cyber.gov.au/publication/annual-cyber-threat-report-2025-26/programs); [ACTR 2025-26 release](https://www.cyber.gov.au/news/asd-releases-seventh-annual-cyber-threat-report-2025-26); [Minister for Defence (14 Oct 2025, ACTR 2024-25)](https://www.minister.defence.gov.au/media-releases/2025-10-14/annual-cyber-threat-report-highlights-persistent-threat-individuals-across-australian-economy)
- CTIS is "a two-way platform for the sharing of information regarding malicious cyber activity and threats." — [GovTech Review](https://www.govtechreview.com.au/content/gov-security/news/asd-offering-two-way-threat-intelligence-service-897980467); [The Record](https://therecord.media/australia-spies-share-intel-and-want-victims-to-share-back)
- Integrations: a Microsoft Sentinel CTIS connector (March 2024), and a Splunk Enterprise Security plug-in (Sept 2025) letting partners "share and receive cyberthreat intelligence at machine speed." — [ASD blog](https://www.cyber.gov.au/blog/join-the-cyber-threat-intelligence-sharing-service-through-sentinel-or-splunk-enterprise-security); [GovTech Review (Splunk)](https://www.govtechreview.com.au/content/gov-security/news/asd-and-splunk-launch-ctis-plug-in-1323326616); [Splunk Lantern](https://lantern.splunk.com/Security_Use_Cases/Advanced_Threat_Detection/Integrating_with_the_ASD_CTIS)
- "As of July 2025, CTIS is now mandatory for federal government agencies." This is from a search snippet with an unclear publisher. — [Splunk blog](https://www.splunk.com/en_us/blog/security/how-splunk-and-asd-are-strengthening-national-cyber-resilience-through-ctis.html)
- Earlier trade reporting (undated) noted about 100 registered partners and rising platform costs. — [InnovationAus](https://www.innovationaus.com/?p=41791)

### Inferences
- Growth from about 100 to more than 550 partners correlates with frictionless SIEM integration and a federal mandate. Distribution through existing tools may matter more than intel volume. Directly analogous for a prototype: export alerts as STIX or JSON that a SIEM can ingest.

### Gaps
- Full ACTR 2025-26 figures could not be retrieved (fetch timeouts): incidents, notifications to entities and the AUPNS vulnerability-notification count. CTIS's underlying format is commonly reported as STIX/TAXII but was not verified this session. No published ASD use of LLMs found.

---

## 9. Germany: BSI (CERT-Bund, WID, CSAF)

### Takeaway
The BSI's early-warning output is standards-driven. CERT-Bund's Warn- und Informationsdienst (WID) publishes daily, product- and severity-filterable advisories, and BSI publishes machine-readable CSAF advisories through a well-known CSAF provider endpoint. It has a statutory warning power (§13 BSIG). Public evidence of AI inside BSI's warning pipeline is minimal.

### Cited Findings
- CERT-Bund publishes daily updates on vulnerabilities, patches and workarounds through WID, filterable by product and severity. Users subscribe via the WID portal. — [BSI Technische Sicherheitshinweise](https://bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage/Technische-Sicherheitshinweise-und-Warnungen/Technische-Sicherheitshinweise/technische-sicherheitshinweise.html?nn=918322); [WID feed listing](https://feeder.co/discover/67c86fd31a/wid-cert-bund-de-portal-wid-securityadvisory)
- BSI's security.txt points to a CSAF provider metadata file at `cert-bund.de/.well-known/csaf/provider-metadata.json`, the entry point for automated consumption. BSI recommends manufacturers publish advisories in CSAF with the "Security Advisory" profile. — [BSI security.txt](https://www.bsi.bund.de/.well-known/security.txt); [BSI FAQ for manufacturers](https://www.bsi.bund.de/EN/IT-Sicherheitsvorfall/IT-Schwachstellen/FAQ_Hersteller/FAQ_Hersteller_node.html)
- High-severity "Cybersicherheitswarnungen" are published as PDFs, for example on Fortinet, Cisco ASA and Juniper. — [example BSI warning PDF](https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2024/2024-213797-1032.pdf)
- Legal basis for public warnings: §13 BSIG. — [lxgesetze §13 BSIG](https://lxgesetze.de/bsig/13)
- "Die Lage der IT-Sicherheit in Deutschland 2025" (Nov 2025) finds "no all-clear". According to the BKA, about 80% of reported ransomware attacks hit SMEs. — [Notebookcheck](https://www.notebookcheck.com/BSI-Lagebericht-zur-IT-Sicherheit-Die-Letzten-beissen-die-Hunde-BSI-Chefin-warnt-vor-digitaler-Sorglosigkeit-in-Deutschland.1163427.0.html)
- BSI released a community draft of an AI audit framework ("A5") based on ISAE 3000. This concerns auditing AI, not using it for CTI. — [usd.de](https://www.usd.de/en/a5-bsi-audit-framework-trustworthy-ai/)

### Inferences
- CSAF is the EU/German standard for machine-readable advisories, and EUVD plans support for it. A prototype that ingests or emits CSAF 2.0 alongside STIX 2.1 signals standards alignment to judges.

### Gaps
- No BSI statement found on AI or LLM use in WID or CERT-Bund triage. Numeric Lagebericht 2025 figures, such as new vulnerabilities per day, were not retrieved.

---

## 10. How do these systems define "early" and measure lead time? What signals are treated as leading indicators?

### Takeaway
No agency publishes a single formal definition of "early." In practice "early" means **before harm to the specific recipient**: before encryption (PRNI), before compromise of a registered asset (NCSC Early Warning), or within a fixed statutory window (CRA 24 hours). Lead time is measured, where at all, as **time-to-notify or time-to-takedown**, not as forecast horizon. The leading indicators used are, roughly from earliest to latest: scanning/darknet activity, exposure of vulnerable services, PoC availability, automatable exploitation, evidence of in-the-wild exploitation (KEV), and initial-access activity at a named victim.

### Cited Findings
- **PRNI**: "early" means the window between initial access and encryption or exfiltration, which is "hours to days." Notification can happen "in less than an hour" and mostly the same day as the tip. — [CISA](https://www.cisa.gov/news-events/news/getting-ahead-ransomware-epidemic-cisas-pre-ransomware-notifications-help-organizations-stop-attacks); [SANS](https://www.sans.org/blog/cisas-pre-ransomware-notification-and-you)
- **NCSC Early Warning**: "inform your organisation as soon as possible." Compromise and abuse findings are emailed daily and exposures weekly, and appear immediately in the portal. — [MyNCSC](https://www.ncsc.gov.uk/collection/myncsc-help-centre/service-descriptions/early-warning)
- **NCSC Takedown KPIs**: 50% of takedowns in under 1 hour (about 4 hours the previous year); 79% resolved within 24 hours of detection. — [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)
- **CRA**: "early warning" is a legal term meaning within 24 hours of a manufacturer becoming aware of active exploitation (then 72 hours and 14 days). — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-enisa-cve-root-dual-governance-20260518/)
- **KEV is a lagging confirmation signal by design.** It requires reliable evidence of exploitation and excludes scanning and PoCs. — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities)
- VulnCheck's commercial exploit-intel data:
  - 28.96% of 2025 KEVs (VulnCheck's own catalogue, 884 entries) were exploited on or before the day their CVE was published, up from 23.6% in 2024;
  - 32.1% in 1H-2025 and 23.43% in 1H-2026;
  - its data "often precedes CISA's KEV catalog by days, months, or even years."
  - Sources: [VulnCheck 2026 State of Exploitation](https://www.vulncheck.com/blog/state-of-exploitation-2026); [VulnCheck 1H-2025](https://www.vulncheck.com/blog/state-of-exploitation-1h-2025); [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/zeroday-exploits-surge-vulncheck)
- NCSC expects AI to "compress the window between the disclosure and exploitation of vulnerabilities even further" to 2027. — [NCSC](https://www.ncsc.gov.uk/report/impact-ai-cyber-threat-now-2027)
- **Darknet scanning as a leading signal (NICTER)**: per-IP darknet packets rose about tenfold from 2015 to 2025. About 55% are research scans, which is noise. DAEDALUS alerts when an organisation's own IP appears as a darknet source. — [NICTER report 2025](https://csl.nict.go.jp/report/NICTER_report_2025.pdf); [NICT journal](https://www.nict.go.jp/publication/shuppan/kihou-journal/journal-vol63no2/journal-vol63no2-03-04.pdf)
- **SSVC leading-indicator ladder**: Exploitation moves from none to poc to active, and "Automatable = yes" flags CVEs likely to be mass-exploited. CISA publishes these per CVE, often before KEV entry. — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)
- **BOD 26-04** treats exposure (internet-facing) and exploit automation as urgency multipliers alongside KEV status. — [Qualys](https://docs.qualys.com/en/etm/latest/cisa_bod/bod_overview.htm)
- **Exposure signals**:
  - RVWP warns owners of internet-facing devices with ransomware-favoured vulnerabilities; 852 of 1,754 warnings (2023) led to action. — [ExecutiveGov](https://www.executivegov.com/articles/cisa-offers-update-on-ransomware-vulnerability-warning-pilot-program)
  - NCSC sent vulnerability reports on 187,000 IPs to 4,030 organisations. — [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)
  - KISA's ASM pilot flags threats to registered assets in real time. — [Seoul Economic Daily](https://en.sedaily.com/technology/2026/08/06/kisa-launches-tailored-cyber-threat-alert-service-for-firms)

### Inferences
- A practical hierarchy of lead-time signals for a prototype, from earliest and noisiest to latest and most certain:
  1. vendor advisory or CVE published, with a PoC or "Automatable = yes";
  2. scan or darknet surge on the affected port or service;
  3. exploitation reported by vendor or CERT, or a KEV/EUVD "exploited" flag;
  4. the organisation's own asset is exposed and matches;
  5. compromise indicators involving its own IP or domain.

  The confidence of the alert should rise as signals stack.
- The honest metric for a prototype is **time-to-alert**, measured from advisory ingest to the asset-matched alert, plus **lead over KEV**: how many days before the CVE's KEV `dateAdded` the prototype raised it. Both are computable offline from cached KEV data. The second is my proposed metric; no agency publishes it.

### Gaps
- No agency publishes a "lead time versus first exploitation" metric for its own warnings. I found no official average CISA KEV inclusion lag. No NICTER retrospective quantifying how many days scan surges preceded mass exploitation was retrieved.

---

## 11. AI/ML/LLM adoption for CTI triage and summarisation (2024–2026)

### Takeaway
Government adoption is real but conservative. Classical ML (decision-tree confidence scoring, NER-based PII redaction, unsupervised anomaly detection) is in production at CISA. LLMs are used for **internal search and summarisation with mandatory human validation**: CISAChat, and RAG drafting of tailored summaries. Generative AI for CTI-feed correlation and incident-report processing is still at concept or R&D stage. Israel and the EU publicly claim AI-driven filtering and detection without technical detail. Research and press evidence warns about hallucination and summary-quality problems in CTI.

### Cited Findings
- CISA AI use-case inventory, active cases:
  - DHS-4: NLP PII detection in AIS (operation).
  - DHS-5: decision-tree confidence scoring of AIS indicators (operation).
  - DHS-2403: unsupervised SOC anomaly detection over terabytes of daily sensor logs (operation).
  - DHS-106: unsupervised CI network anomaly detection for CyberSentry (initiation).
  - DHS-107: malware reverse engineering with deep learning and generative AI (initiation).
  - DHS-2335: "LLM with retrieval-augmented generation (RAG)" that drafts summaries of approved CISA products for different channels, which staff "validate and edit before publication" (initiation).
  - DHS-2306: "CISAChat", generative AI to search and summarise internal materials (implementation).
  - Not yet active: "Cyber Threat Intelligence Feed Correlation" (DHS-40, generative AI, initial conception); "Cyber Incident Reporting" (DHS-41, generative AI and NLP, R&D).
  - CISA reports zero rights- or safety-impacting AI uses.
  - Source: [CISA AI Use Cases](https://cisa.gov/ai/cisa-use-cases)
- GAO-24-106246 (Feb 2024): DHS does not verify whether inventory items are really AI; of the two cyber cases listed, one was not AI. DHS had not ensured that data used to develop the assessed AIS PII-detection model was reliable. — [GAO-24-106246](https://www.gao.gov/products/GAO-24-106246); [Federal News Network](https://federalnewsnetwork.com/artificial-intelligence/2024/02/dhs-list-of-ai-use-cases-found-inaccurate-gao-says/)
- Israel: Cyber Dome uses "generative AI platforms to help filter out genuine threats from the sea of threat intelligence and cyberattack claims" (2023 reporting). — [The Defense Post](https://www.thedefensepost.com/2023/10/17/israel-developing-cyber-dome)
- EU: the Cyber Hubs are to use "AI and data analytics" to detect and share threat warnings. — [European Commission](https://digital-strategy.ec.europa.eu/en/policies/cyber-solidarity)
- Singapore: Google–CSA MOC (Oct 2025) on "AI-driven threat intelligence sharing" and "co-development of AI-powered security solutions." — [CRN Asia](https://www.crnasia.com/news/2025/cybersecurity/csa-singapore-announces-partnerships-with-google)
- Korea: the KISA Cyber Security Big Data Center aims at AI and big-data threat analysis (2021). The 2026 ASM alert pilot does not mention AI. — [Asia Economy](https://cm.asiae.co.kr/en/article/2021052300123170551); [Seoul Economic Daily](https://en.sedaily.com/technology/2026/08/06/kisa-launches-tailored-cyber-threat-alert-service-for-firms)
- JCDC AI Cybersecurity Collaboration Playbook (Jan 2025): covers sharing information about AI-related incidents and vulnerabilities, not using AI for CTI. — [CISA](https://cisa.gov/news-events/news/cisa-jcdc-government-and-industry-partners-publish-ai-cybersecurity-collaboration-playbook)
- Sweden: the KTH "CORTEX" project is developing LLM-driven CTI generation, with CERT-SE (MSB) among anticipated users. Research stage, not a deployment. — [KTH Digital Futures](https://www.digitalfutures.kth.se/project/cortex-an-llm-driven-framework-for-enhanced-cti/)
- Evidence on summary quality: an arXiv preprint (2603.09452, 2026) describes the CTI workflow as triage, then deep search, then drafting. In its pilot, a sparse summary outscored a detailed one despite analysts preferring detail, and it says research benchmarks are inadequate for real CTI work. — [arXiv 2603.09452](https://arxiv.org/html/2603.09452v1)
- Hallucination risk: a Black Hat USA 2023 talk shows an LLM hallucinating risk details and wrongly judging an email benign during automated triage. — [Black Hat 2023 slides](https://i.blackhat.com/BH-US-23/Presentations/US-23-Grof-Miller-LLM-Powered-TI-Program.pdf)
- Attacker-side AI pressure cited by agencies:
  - NCSC: AI will raise intrusion volume and compress time-to-exploit. — [NCSC](https://www.ncsc.gov.uk/report/impact-ai-cyber-threat-now-2027)
  - CERT-EU: an agentic AI intrusion campaign against 30 entities. — [CERT-EU TLR 2025](https://www.cert.europa.eu/blog/threat-landscape-report-2025)
  - Singapore: AI-enabled attacks at greater speed and scale. — [SCL 2025/26](https://isomer-user-content.by.gov.sg/36/e3a2bc10-c70a-4b06-bf46-4847e1d8b358/Singapore%20Cyber%20Landscape%202025_2026.pdf)

### Inferences
- The pattern governments actually ship is: **classical ML for scoring, filtering and anomaly detection, plus LLM for drafting and summarising behind a human-validation gate, with RAG over approved sources.** A hackathon prototype that copies this (deterministic scoring, LLM only for explanation and summary, "analyst-validate" flag) matches government practice and is easier to defend to C-DAC judges than an LLM that decides risk on its own.
- CISA has listed "CTI feed correlation with generative AI" only at concept stage. So a working demo of LLM-assisted advisory-to-asset correlation is plausibly ahead of published government practice, which is useful framing but should be stated carefully.

### Gaps
- I found no published national-CERT evaluation (precision, recall, analyst time saved) of LLM triage or summarisation. NCSC, BSI, ASD and CSA internal LLM use for CTI is not publicly documented in the sources found. A reported June 2, 2026 US executive order on AI and cyber was seen only on a vendor blog and is unverified ([Babel Street](https://www.babelstreet.com/blog/2026-ai-executive-order-cyber-threat-hunting)).

---

## 12. Lessons and design patterns for a 24-hour AI early-warning prototype

### Takeaway
Copy the four things national systems demonstrably do well:
1. register assets and match intel to them (NCSC Early Warning, KISA ASM, DAEDALUS);
2. score with a transparent decision tree built on exploitation, automation, impact and exposure (SSVC, BOD 26-04);
3. push typed, staged, owner-specific alerts with a status lifecycle and a time-to-alert KPI (NCSC, PRNI, CRA);
4. confine the LLM to triage, summary and explanation with human validation (CISA DHS-2335, CISAChat).

Avoid AIS's failure mode, a high-volume IOC firehose with no owner context or confidence.

### Cited Findings
These are the design anchors, each tied to a source above. Feasibility labels are mine.

1. **Asset-registration and correlation core** [24h]. Load a simulated inventory (IPs, domains, product/vendor/version). Match each new advisory or CVE against it.
   - Pattern sources: [NCSC Early Warning](https://www.ncsc.gov.uk/collection/myncsc-help-centre/service-descriptions/early-warning), [KISA ASM alerts](https://en.sedaily.com/technology/2026/08/06/kisa-launches-tailored-cyber-threat-alert-service-for-firms).
   - The brief itself ("advisory, then asset inventory, then exposure, then risk, then alert") matches this.
2. **Three alert types, borrowed from NCSC** [24h]:
   - "Suspected compromise", when an IOC hits an owned IP or domain;
   - "Network abuse", when an owned asset appears as a source of scanning or abuse (the DAEDALUS idea);
   - "Known vulnerability / exposure", when a CVE matches an owned product and version and the asset is internet-facing.
   - Sources: [MyNCSC](https://www.ncsc.gov.uk/collection/myncsc-help-centre/service-descriptions/early-warning); [NICT DAEDALUS](https://www.nict.go.jp/publication/shuppan/kihou-journal/journal-vol63no2/journal-vol63no2-03-04.pdf)
3. **SSVC-style deterministic risk tree** [24h]. Inputs:
   - Exploitation: none / poc / active, from cached KEV and Vulnrichment JSON;
   - Automatable: yes / no;
   - Technical Impact: partial / total;
   - plus the organisation's own Exposure (internet-facing or internal) and Mission criticality (asset tag).

   Output four levels, e.g. Track / Track* / Attend / Act, the SSVC deployer vocabulary. Justify it as mirroring BOD 26-04's factors (exposure, KEV status, automation, technical impact). Show the decision path on screen for explainability.
   - Sources: [Vulnrichment](https://github.com/cisagov/vulnrichment); [Qualys BOD 26-04](https://docs.qualys.com/en/etm/latest/cisa_bod/bod_overview.htm). The SSVC deployer labels are not cited in this note; verify against CISA's SSVC guide.
4. **KEV-style inclusion gate** [24h]: only escalate to "Act" when there is reliable exploitation evidence and a clear remediation. Show "no fix available, compensating control" as a separate state. Do not treat a scan or PoC as exploitation. — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities)
5. **Confidence score per item, separate from severity** [24h]. CISA scores AIS submissions with a decision tree.
   - Copy the idea: confidence = f(source reliability, corroboration count, recency).
   - Label hacktivist "claims" as unverified until corroborated, which is the Cyber Dome framing.
   - Sources: [CISA DHS-5](https://cisa.gov/ai/cisa-use-cases); [Defense Post](https://www.thedefensepost.com/2023/10/17/israel-developing-cyber-dome)
6. **LLM only for triage, summary and explanation, behind a human gate** [24h with a local 7–8B model].
   - Run RAG over the cached advisory text to produce a short plain-English alert, likely affected assets and recommended action.
   - Mark output "DRAFT – analyst validate", as CISA does for DHS-2335. Keep the risk score deterministic.
   - Keep summaries sparse: research found sparse summaries outscored detailed ones.
   - Sources: [CISA AI Use Cases](https://cisa.gov/ai/cisa-use-cases); [arXiv 2603.09452](https://arxiv.org/html/2603.09452v1)
7. **LLM-assisted extraction of affected product and version from free-text advisories** [24h, with a regex/CPE fallback]. This is the step CISA lists as concept-stage "CTI feed correlation", a defensible novelty. Validate LLM output against inventory vocabularies to limit hallucination. — [CISA DHS-40](https://cisa.gov/ai/cisa-use-cases); [Black Hat 2023 hallucination example](https://i.blackhat.com/BH-US-23/Presentations/US-23-Grof-Miller-LLM-Powered-TI-Program.pdf)
8. **PII redaction and IOC defanging before display or sharing** [24h], with NER and regex as in CISA's AIS PII detector. This also satisfies the hackathon rule to defang IOCs on screen. — [CISA DHS-4](https://cisa.gov/ai/cisa-use-cases); [ACT-IAC](https://www.actiac.org/et-use-case/automated-pii-detection)
9. **Staged alert products using the CRA clock** [24h]: "Early warning (≤24h)", then "Notification (≤72h, with indicators and mitigations)", then "Final report (≤14 days after fix)". Show a countdown per alert. — [CSA note on CRA Art. 14](https://labs.cloudsecurityalliance.org/research/csa-research-note-enisa-cve-root-dual-governance-20260518/)
10. **Alert lifecycle and cadence copied from NCSC** [24h]:
    - status Open, then Marked as fixed or Risk accepted;
    - "Act" items pushed immediately, a daily digest for compromise and abuse, a weekly roll-up for exposures.
    - Source: [MyNCSC](https://www.ncsc.gov.uk/collection/myncsc-help-centre/service-descriptions/early-warning)
11. **Outcome KPIs on the dashboard, NCSC/PRNI style** [24h]:
    - median time from advisory ingest to alert (PRNI benchmark: under 1 hour, same day);
    - share of alerts acknowledged or fixed (RVWP benchmark: 852 of 1,754, about 49%);
    - lead over KEV: days the prototype flagged a CVE before its KEV `dateAdded`, computed by replaying cached history.
    - Sources: [SANS](https://www.sans.org/blog/cisas-pre-ransomware-notification-and-you); [ExecutiveGov](https://www.executivegov.com/articles/cisa-offers-update-on-ransomware-vulnerability-warning-pilot-program); [NCSC AR2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-02-resilience-at-scale/active-cyber-defence)
12. **EUVD-style three-pane national view** [24h]: Critical, Actively exploited, and "Coordinated/national-relevance" (assets in the national inventory affected). — [EUVD coverage](https://cybersecuritynews.com/enisa-launches-euvd)
13. **Standards-based output** [24h for JSON export, stretch for a TAXII server]:
    - emit each alert as a STIX 2.1 bundle (indicator, vulnerability, course-of-action) and/or a CSAF 2.0 advisory;
    - consume CVE JSON 5 records with CISA ADP (Vulnrichment) fields;
    - this mirrors ASD CTIS's SIEM plug-in distribution, the BSI/EUVD CSAF direction and CERT-EU's MISP/OpenCTI use.
    - Sources: [ASD CTIS Splunk plug-in](https://www.govtechreview.com.au/content/gov-security/news/asd-and-splunk-launch-ctis-plug-in-1323326616); [BSI CSAF](https://www.bsi.bund.de/.well-known/security.txt); [CERT-EU MISP](https://interoperable-europe.ec.europa.eu/collection/open-source-observatory-osor/document/case-study-misp)
14. **Darknet/scan-surge detector on replayed data** [24h with simulated or published data; live capture is no].
    - Compute per-port rolling z-scores on a scan-count time series and alert on spikes that match a CVE's service port.
    - Apply a "known research scanner" suppression list, since NICTER finds about 55% of darknet packets are research scans.
    - Use only published datasets or synthetic data, to honour the no-active-scanning rule.
    - Sources: [NICTER 2025](https://csl.nict.go.jp/report/NICTER_report_2025.pdf); [NICT darknet dataset](https://csdataset.nict.go.jp/darknet-2022)
15. **Calibrated-language templates** [24h]: phrase the likelihood in the AI-generated narrative with NCSC's PHIA yardstick ("realistic possibility", "likely", "almost certain"), mapped from the numeric score. — [NCSC AI-to-2027 report](https://www.ncsc.gov.uk/report/impact-ai-cyber-threat-now-2027)
16. **Pre-ransomware "evict now" playbook card** [24h]: when a compromise-type alert hits a critical asset, show a phone-first, under-1-hour mitigation checklist (isolate host, reset credentials, check for domain-admin creation). Attackers reach domain admin in as little as 8–9 minutes. — [SANS](https://www.sans.org/blog/cisas-pre-ransomware-notification-and-you); [CISA PRNI](https://www.cisa.gov/news-events/news/getting-ahead-ransomware-epidemic-cisas-pre-ransomware-notifications-help-organizations-stop-attacks)

### Inferences
**Anti-patterns to avoid, from documented weaknesses:**
- Firehose IOC sharing with no confidence or owner context; AIS participation fell from 304 to 135 and indicator volume by 93%. — [FedScoop](https://fedscoop.com/cisa-threat-information-sharing-dhs-oig-report/)
- Sensors with no analysis capacity; CyberSentry data went unreviewed after July 2025. — [CyberScoop](https://cyberscoop.com/contract-lapse-leaves-critical-infrastructure-cybersecurity-sensor-data-unanalyzed-at-national-lab/)
- A single vulnerability source with coverage gaps; EUVD is missing more than 50,000 CVEs. — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-enisa-cve-root-dual-governance-20260518/)
- Opaque "AI" claims with no published mechanism (Cyber Dome).
- AI inventories that mislabel non-AI as AI. — [GAO](https://www.gao.gov/products/GAO-24-106246)

**Suggested offline data set for the demo:** cached CISA KEV JSON, a slice of Vulnrichment CVE records, a few vendor and CERT advisories saved as text, and a synthetic national asset inventory of a few hundred assets across CII sectors (Singapore's 11 CII sectors are a ready taxonomy, see the [CSA press release](https://www.csa.gov.sg/news-events/press-releases/a-decade-of-strengthening-singapore-s-cyber-defence-amid-escalating-threats)). Optionally add a synthetic scan time series. All of these are passive and public or simulated, and run on one laptop.

**Recommended scoring line for judges:** "Risk = SSVC/BOD 26-04 decision tree over exploitation (KEV/Vulnrichment), automatable, technical impact, plus our asset exposure and criticality. Confidence is scored separately. The LLM explains but never decides." This has direct government precedent.

**Not feasible in 24h** [no]: live national sensor grids (EINSTEIN/CADS, CyberSentry, NICTER darknet), privileged feeds (NCSC), legal mandates (BOD 26-04, CRA reporting), human field-notification networks (PRNI). Emulate them with simulated data and say so explicitly.

### Gaps
- The SSVC deployer labels (Track / Track* / Attend / Act) and the exact SSVC deployer tree should be checked against CISA's SSVC guide; they were not fetched this session.
- STIX 2.1 and CSAF 2.0 field mappings for the export were not researched here.
- EPSS (FIRST's 30-day exploitation probability) is a useful extra non-government input. It was not researched this session; verify at first.org/epss before citing.
