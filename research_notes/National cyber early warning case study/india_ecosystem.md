# India's National Cyber Threat Early-Warning and Threat-Intelligence Ecosystem (Government + Industry), as of October 2026

Research date: 31 October 2026. Facts carry a year where they may be dated. cert-in.org.in and nciipc.gov.in were **not fetched directly** in this session. CERT-In facts come mainly from the PIB Backgrounder of 23 Jan 2026, plus press and parliamentary material. Facts marked "(prior knowledge, not re-fetched)" should be checked against the primary document before they go on a slide.

---

## 1. CERT-In: NCCC, Cyber Swachhta Kendra, advisories/CIVN, the 2022 Directions and later updates, AI initiatives, drills, sectoral CSIRTs

### Takeaway
CERT-In (Sec 70B, IT Act 2000, under MeitY) is the hub of India's civilian early warning. It runs three relevant systems:
- **NCCC**, which builds situational awareness from metadata.
- **Cyber Swachhta Kendra (CSK)**, which detects bot infections and notifies the owners.
- An **automated cyber threat exchange platform**, which shares threat information in near real time.

It also oversees sectoral CSIRTs (CSIRT-Fin, CSIRT-Power, telecom) and State CSIRTs. Since 2025 it has moved quickly on AI: an AI-driven DNS and phishing situational-awareness system, a high-severity advisory on frontier-AI attacks in April 2026, an AI cyber-defence "blueprint" in May 2026 with 12-hour patch windows, and AI-themed drills in June and July 2026. The legally binding core is still the April 2022 Directions (report within 6 hours, keep logs for 180 days). No amendment to them was found.

### Cited Findings

**Scale and outputs (2025), from the official PIB Backgrounder "CERT-In: India's Frontline Defender against Cyber Threats", 23 Jan 2026**
- In 2025 CERT-In handled **over 29.44 lakh (about 2.94 million) cyber incidents**. It issued **1,530 alerts, 390 vulnerability notes and 65 advisories**, and identified and published **29 CVEs**. — [PIB Backgrounder, 23 Jan 2026](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf); also reported by [IANS/Morung Express, 23 Jan 2026](https://morungexpress.com/cert-in-handled-over-2944-lakh-cyber-incidents-in-2025-gains-global-recognition)
- **231 cybersecurity audit organisations are empanelled.** Most audits were in banking and financial institutions, power and energy, and transport. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **Legal mandate (Sec 70B):** "prevention of cyberattacks, real-time monitoring of cyber threats, and swift coordination with stakeholders". — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **Core functions listed by PIB:** "Facilitating information sharing through its **automated cyber threat exchange platform**"; "Sharing **near-real time information** on existing and potential cyber threats with organisations covering all sectors"; "Operating CSKs for ensuring cyber hygiene & **a Command & Control Center** for facilitating monitoring of cyber threats and attack campaigns"; "Institutionalising responsible vulnerability disclosure"; guidance on implementing a cyber crisis management plan. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **The PIB infographic lists five CERT-In functions:** Information Management ("Collect, analyze, and share data on cyber incidents"), Threat Alerts ("Forecast and issue warnings on emerging cyber threats"), Incident Response, Coordination, and Advisories & Guidance (guidelines, advisories, vulnerability notes, whitepapers). — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **Budget:** the Union Budget 2025–26 allocated **₹782 crore for cybersecurity**. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)

**NCCC (National Cyber Coordination Centre)**
- PIB description: "NCCC, implemented by CERT-In, **monitors cyberspace at metadata level** to detect potential cyber security threats for situational awareness. It facilitates real-time information sharing with concerned organisations, State governments, and other stakeholders, enabling timely preventive and response actions." — [PIB Backgrounder, Jan 2026](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- Parliamentary replies say CERT-In "has set up the NCCC to generate necessary situational awareness of existing and potential cyber security threats and enable timely information sharing", and that **Phase-I is operational**. — [Rajya Sabha reply, 26 Jul 2024 (PDF)](https://rsdebate.nic.in/bitstream/123456789/749722/1/PQ_265_26072024_U546_p280_p280.pdf) (seen through a search summary; full text not read)
- **Unverified, secondary sources only:** Phase-I became operational in 2017 (sources disagree on July or August 2017), with metadata from about 20 ISP or organisation sites analysed. An older planned cost was Rs 985 crore. — [GKToday](https://www.gktoday.in/national-cyber-coordination-centre-operational-government/); [MediaNama 2021 on NCCC budget](https://www.medianama.com/2021/03/223-national-cybersecurity-coordination-centre-budget-estimate/). Privacy and civil-liberty concerns about NCCC's monitoring have been raised in commentary (same search set).

**AI-driven situational awareness at CERT-In (the most citable "AI early warning" fact)**
- The PIB infographic, citing the WEF white paper *Fighting Cyber-Enabled Fraud: A Systemic Defence Approach* (Dec 2025), says CERT-In's AI and situational-awareness systems:
  - processed **9,800 billion DNS queries**;
  - found **2.2 billion queries linked to malicious domains** and **128 million associated with phishing**;
  - led to **3,044 phishing sites mitigated**, affecting about **695,000 users**;
  - support regular sharing of DNS-based threat intelligence with international partners. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- The WEF *Global Cybersecurity Outlook 2025* highlighted CERT-In for "deployment of AI-driven situational awareness systems to analyse and detect malicious domains and phishing activities", and for sharing threat intelligence in real time. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- In Feb 2025 CERT-In co-signed the ANSSI-led report "Building Trust in AI through a Cyber-Risk-Based Approach". In Apr 2025 it contributed to the WEF/Oxford *Cyber Resilience Compass*. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)

**Cyber Swachhta Kendra (Botnet Cleaning and Malware Analysis Centre)**
- **Launched in 2017** under MeitY and the Digital India programme, and operated by CERT-In under Sec 70B. It works "in close coordination and collaboration with Internet Service Providers and Product/Antivirus companies". Functions: reporting incidents, alerting users, listing threats, providing removal tools. — [Pratiksha Ashok (UCLouvain), Botconf 2023 slides "Cyber Swachhta Bharat"](https://www.botconf.eu/wp-content/uploads/formidable/2/2023_ASHOK.pdf); [csk.gov.in About](https://www.csk.gov.in/about.html)
- PIB: the CSK "tracks networks of internet connected devices such as computers, mobile phones, IoT devices, and home routers—that are infected with malware", provides free tools, and works with industry, academia and ISPs "to identify compromised systems and alert users". **As of Dec 2025 it covers 98% of India's digital population** and sends large-scale notifications on botnet and malware infections. It has **onboarded 1,427 organisations**, and its free tools have been downloaded **89.55 lakh times**. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **CSK distributes free tools.** Bot removal tools come from eScan, K7 and Quick Heal. **C-DAC tools:** M-Kavach 2 (C-DAC Hyderabad, with MeitY support), USB Pratirodh, AppSamvid (application whitelisting) and Browser JSGuard. The CSK "Alerts" page lists threat write-ups such as Vidar, Zerobot, Panchan, BlackCat, SOVA, LockBit 2.0 and the India Ransomware Report H1-2022 (snapshot as of 2023). — [Botconf 2023 slides (screenshots of csk.gov.in)](https://www.botconf.eu/wp-content/uploads/formidable/2/2023_ASHOK.pdf)
- **CSIRT-Power's job is defined partly by CSK output.** It is "an extended arm of CERT-In for fortifying the cybersecurity posture of the Power Sector by coordinating and analysing cyber incidents, acting on cyber threat intelligence from CERT-In, taking proactive containment measures based on situational awareness details provided by CERT-In, ensuring cybersecurity audits are carried out and **mitigating vulnerabilities as reported by CERT-In's Cyber Swachhta Kendra**". — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)

**Sectoral and State CSIRTs**
- **CSIRT-Fin** is the "Computer Security Incident Response Team for the Financial Sector functioning under CERT-In". It handles coordinated incident response, information sharing and guidance for BFSI. CERT-In "oversees a network of CSIRTs operating at the sectoral and State/UT levels". Sectoral CSIRTs cover finance, power and telecom. State CSIRTs operate under State and UT governments. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **Cyber Crisis Management Plan (CCMP):** "CERT-In has also developed a CCMP for government bodies, providing structured guidance during major cyberattacks and cyber-terrorism incidents". — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)

**Advisories, vulnerability notes and CVE assignment**
- **ID schemes seen in sources:** advisories use **CIAD-YYYY-NNNN**, for example CIAD-2025-0018 and CIAD-2025-0019, issued after the April 2025 Pahalgam attack to warn CII operators and the financial sector about ransomware, DDoS and malware ([ORF, 7 May 2026](https://www.orfonline.org/research/operation-sindoor-at-one-taking-stock-of-india-s-cyber-preparedness)). Guidelines use **CIGU-YYYY-NNNN**, for example the May 2026 AI blueprint, CIGU-2026-0002 ([MediaNama, 27 May 2026](https://www.medianama.com/2026/05/223-cert-in-releases-blueprint-for-defending-against-ai-assisted-cyber-threats/)). White papers use **CIWP-YYYY-NNNN**, for example CIWP-2025-0001 (cited in the PIB references list).
- **Vulnerability notes (prior knowledge, not re-fetched):** they use **CIVN-YYYY-NNNN** and are published on cert-in.org.in. Each note carries a severity rating (Critical, High, Medium or Low) and sections for Software Affected, Overview, Target Audience, Risk Assessment, Impact Assessment, Description, Solution, Vendor Information, References and CVE Name. The format could not be verified this session because cert-in.org.in was not fetched.
- **CVE Numbering Authority:** CERT-In is an authorised CNA "for vulnerabilities impacting all products designed, developed and manufactured in India". — [radicalnotion.ai CNA profile (third-party)](https://radicalnotion.ai/cna/cert-in). The same third-party tracker counts **125 CVE records since 2022**, which is unverified. PIB gives 29 CVEs published in 2025. — [PIB](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **2025 publication list:**
  - Cybersecurity Guidelines for Smart City Infrastructure (Feb 2025)
  - Satcom advisory (Feb 2025)
  - India Ransomware Report (Mar 2025)
  - Digital Threat Report 2024 for BFSI (Apr 2025)
  - UAS/drone white paper (Apr 2025)
  - **Technical Guidelines on SBOM, QBOM & CBOM, HBOM, AIBOM, Version 2 (Jul 2025)**
  - **Comprehensive Cyber Security Audit Policy Guidelines (Jul 2025)**
  - Quantum Cyber Readiness white paper (Jul 2025)
  - 15 Elemental Cyber Defense Controls for MSMEs (Sep 2025)
  - Source: [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- The July 2025 Audit Policy Guidelines mandate **annual third-party audits** for public and private enterprises and extend audit scope to AI system security. — [MediaNama, May 2026](https://www.medianama.com/2026/05/223-cert-in-releases-blueprint-for-defending-against-ai-assisted-cyber-threats/)

**CERT-In Directions of 28 April 2022 (Sec 70B(6))**
- **Directions No. 20(3)/2022-CERT-In, dated 28 Apr 2022.** In force 60 days later (late June 2022). Specified incidents must be **reported within 6 hours** of noticing them or being notified. ICT system logs must be kept for a **rolling 180 days** within Indian jurisdiction. A Point of Contact must be appointed. — [PSA Legal](https://psalegal.com/new-cert-in-directions-overview-and-implications/); [AZB & Partners](https://www.azbpartners.com/bank/cert-in-directions/); [ManageEngine summary](https://www.manageengine.com/log-management/cyber-security/cert-in-compliance-for-indian-enterprises.html)
- **Other elements (prior knowledge, not re-fetched):**
  - ICT clocks must be synchronised to NTP servers of NIC or NPL, or traceable to them.
  - Annexure I lists about 20 reportable incident types (for example targeted scanning, compromise of critical systems, unauthorised access, website defacement, malicious code, attacks on servers, identity theft and phishing, DoS/DDoS, attacks on IoT, data breach and leak, and attacks on AI/ML applications per the FAQs).
  - Data centres, VPS, cloud and VPN providers must keep subscriber KYC data for 5 years.
  - Virtual-asset providers must keep KYC and transaction records.
  - Primary PDF: [cert-in.org.in Directions PDF](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf) (URL not fetched this session).
- **Amendments in 2024–2026: none found.** A source last reviewed in Sep 2026 still describes the 2022 instrument without any change. — [search summary of tcsa.in / ManageEngine, 2026](https://www.tcsa.in/learn/cert-in-directions-2022-explained). The 6-hour rule now also covers AI-related incidents "where applicable" — [WION, 29 Oct 2026](https://www.wionews.com/india-news/trust-deficit-how-is-india-strengthening-cybersecurity-in-age-of-ai-powered-threats-1793268629887). One low-quality blog cites "2026 IT (Amendment) Directions", which could not be verified — [eventussecurity.com](https://eventussecurity.com/cybersecurity/india/cyber-attacks/).

**AI initiatives (2026)**
- **27 Apr 2026: high-severity advisory.** CERT-In warned that advanced or "frontier" AI systems can automate vulnerability discovery and multi-stage attacks, with MSMEs among those at risk. Press headlines named specific frontier models, for example "Claude Mythos" and "GPT-5.5". The advisory number was not found. — [OECD AI Incident Monitor entry, 27 Apr 2026](https://oecd.ai/en/incidents/2026-04-27-2f4c); [WION, 29 Oct 2026](https://www.wionews.com/india-news/trust-deficit-how-is-india-strengthening-cybersecurity-in-age-of-ai-powered-threats-1793268629887)
- **25 May 2026: AI cyber-defence blueprint (CIGU-2026-0002).** All points below are from [MediaNama, 27 May 2026](https://www.medianama.com/2026/05/223-cert-in-releases-blueprint-for-defending-against-ai-assisted-cyber-threats/).
  - Status and shape: **advisory, not mandatory**. Nine areas in 14 sections.
  - Threats it names: AI-enabled reconnaissance and exploitation that compresses attacks "from days or weeks into hours"; AI phishing, deepfake and BEC; polymorphic AI malware; prompt injection, data poisoning and leakage.
  - Sectors flagged: government, finance, telecom, healthcare, energy, transport and DPI (Digital Public Infrastructure).
  - **Patch deadlines (Section 9):**

    | Vulnerability class | Deadline |
    |---|---|
    | Known-exploited, internet-facing | **12 hours** where feasible |
    | Critical, external | **1 day** |
    | Known-exploited, internal | **1 day** |
    | Critical, internal, on high-value systems | **3 days** |
    | High severity | **5 days** |

  - **AI governance (Section 12):** keep an AI asset inventory, detect shadow AI, govern agentic AI (permissions, audit logs, kill-switch), and keep an AIBOM alongside SBOM, QBOM and CBOM.
  - **Rollout in three phases:**
    - 0–7 days: MFA, vulnerability assessment and KEV patching, baseline monitoring.
    - 8–30 days: strengthen the SOC, integrate telemetry, build AI inventories, run tabletop exercises.
    - 31–60 days: red-team and adversarial-AI testing, AI-assisted defence.
  - It announces a **CERT-In AI Cyber Defence Center**, a dedicated unit for AI cybersecurity compliance.
  - **Criticisms:** no sector-specific guidance (hospitals, fintech and telecom get the same advice despite separate RBI, SEBI and DoT regimes); AI governance is not tied to board-level oversight; open-source models are not covered; audits are mandatory while the AI guidance is voluntary.
- **June–July 2026:** CERT-In ran **10 customised exercises and drills** themed on resilience against frontier AI-driven threats. MeitY said generative AI lowers the barrier for attackers and urged ministries, states and regulators to "urgently review" their security posture. MeitY released AI Governance Guidelines in Nov 2025, and an AI Safety Institute has been proposed. — [WION, 29 Oct 2026](https://www.wionews.com/india-news/trust-deficit-how-is-india-strengthening-cybersecurity-in-age-of-ai-powered-threats-1793268629887)

**Drills and exercises**
- **2025:** CERT-In ran **122 drills and exercises**, including tabletop exercises, with about **1,570 organisations**. Sectors: Defence, Paramilitary, Space, Atomic Energy, Telecom (ISPs), Finance, Power, Oil & Gas, Transportation, IT/ITeS and State Data Centres. It also ran 32 technical training programmes, 95 awareness sessions (91,065 participants) and trained 20,799 officials. — [PIB Backgrounder](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **Bharat NCX 2025** (National Cyber Exercise), 21 Jul–1 Aug 2025. Run by the **National Security Council Secretariat (NSCS) with Rashtriya Raksha University**. About 600 participants, live-fire simulations, a STRATEX decision exercise for senior leaders, a CISO Conclave and a startup exhibition. CERT-In DG Sanjay Bahl spoke there. — [Tribune](https://www.tribuneindia.com/news/business/bharat-ncx-2025-commences-to-bolster-indias-cybersecurity-preparedness); [Tripura Star News](https://www.tripurastarnews.com/bharat-cisos-conclave-and-cybersecurity-startup-exhibition-inaugurated-under-bharat-ncx-2025/)
- **H1 2026, from low-quality aggregators:** CERT-In reportedly ran two power-sector exercises (274 participants, 103 organisations) and mitigated about 3.5 lakh instances of malicious scanning and probing in finance. These figures are attributed to parliamentary data but were **not verified**. — [restcokami.com aggregator](https://restcokami.com/article/india-s-cyber-threats-financial-and-healthcare-sectors-under-attack)

### Inferences
- The official story CERT-In tells about itself (PIB 2026) is **AI-driven, metadata-level situational awareness, near-real-time sharing, and citizen-scale remediation** through CSK. A prototype that shows the loop "detect → enrich → score → notify the right entity → track remediation" matches the language CERT-In uses for itself.
- The **12h/1d/3d/5d patch deadlines** in the May 2026 blueprint give a ready-made, India-specific policy for SLAs and escalation. A prototype can attach a "CERT-In blueprint deadline" to each alert. That is more credible to Indian judges than CISA KEV due-dates alone.
- CSIRT-Power's mandate shows the intended flow: national situational awareness and CSK findings go to the sectoral CSIRT, then to entity remediation. A dashboard that sends alerts by **CII sector or sectoral CSIRT** mirrors this design.
- CERT-In's output is very large (1,530 alerts and 390 vulnerability notes a year) and is published as human-readable web or PDF pages. Mapping each item to a specific organisation's assets is therefore a real triage problem that AI can help with.

### Gaps
- No public technical description was found of the "automated cyber threat exchange platform": its formats (STIX/TAXII or MISP?), who can join, or its volumes. It could not be verified whether CERT-In publishes machine-readable IOC feeds publicly.
- No public data was found on CSK's sinkhole or sensor architecture (the number of sinkholes, honeypots or ISP feeds). Only coverage figures are public.
- NCCC Phase-II status and current sensor or ISP coverage: no recent official figure found.
- The CIVN page format and severity scale come from prior knowledge, because cert-in.org.in was not fetched.
- The number of the April 2026 frontier-AI advisory was not found.
- 2026 incident totals for CERT-In were not found; the latest official full-year figure is 2025.

---

## 2. NCIIPC: CII sectors, alerts and advisories, vulnerability disclosure, early warning

### Takeaway
NCIIPC (Sec 70A, created 2014, a unit of NTRO under the PMO) is the nodal agency for **Critical Information Infrastructure**. It covers six sectors, issues alerts and advisories, and runs a Responsible Vulnerability Disclosure Program, a 24x7 helpdesk and a "CII Range" IT/OT simulation facility. Its threat-forecasting role is defined on paper, but **no named public early-warning platform was found**. It has much less public visibility than CERT-In.

### Cited Findings
- Created under **Sec 70A, IT Act 2000** (amended 2008), by gazette notification on **16 Jan 2014**. It is a unit of the **National Technical Research Organisation (NTRO)**, which sits under the PMO. — [Wikipedia (NCIIPC)](https://en.wikipedia.org/wiki/National_Critical_Information_Infrastructure_Protection_Centre); [nciipc.gov.in About Us](https://nciipc.gov.in/about_us.html)
- **CII definition:** computer resources whose "incapacitation or destruction... shall have debilitating impact on national security, economy, public health or safety". — [Wikipedia](https://en.wikipedia.org/wiki/National_Critical_Information_Infrastructure_Protection_Centre)
- **Critical sectors:** **Power & Energy; Banking, Financial Services & Insurance; Telecom; Transport; Government; Strategic & Public Enterprises.** — [Wikipedia](https://en.wikipedia.org/wiki/National_Critical_Information_Infrastructure_Protection_Centre). Health is sometimes listed in other sources; that could not be verified here.
- **Functions:**
  - Issue advisories and vulnerability notes in coordination with CERT-In.
  - "Monitoring, collecting, and forecasting national-level CII threats" for early warning and situational awareness.
  - Identify CII so the government can notify it.
  - Direct critical sectors during threats.
  - Share incident and vulnerability information with CERT-In.
  - Run audit, certification and training programmes.
  - Source: [Wikipedia](https://en.wikipedia.org/wiki/National_Critical_Information_Infrastructure_Protection_Centre)
- **Responsible Vulnerability Disclosure Program (RVDP):** accepts reports on Indian CII from researchers and others through an online form or rvdp@nciipc.gov.in, and reporters can stay anonymous. Its scope is CII only. — [NCIIPC RVDP page](https://nciipc.gov.in/trending/RVDP.html)
- **24x7 incident helpdesk:** toll-free **1800-11-4430**, with incident reports to ir@nciipc.gov.in and a malware-sample repository address. — [nciipc.gov.in](https://nciipc.gov.in) (through a search summary)
- **Other programmes:**
  - "**CII Range**" IT/OT simulations to test critical-sector defences.
  - Preparedness surveys, risk assessments and audits.
  - Guidelines: CII identification, Cyber Security Audit baseline requirements, Incident Response SOP.
  - **Information Security Practices and Procedures for Protected System Rules, 2018.**
  - Quarterly newsletters (Jan 2017 to Apr 2024).
  - Source: [Wikipedia](https://en.wikipedia.org/wiki/National_Critical_Information_Infrastructure_Protection_Centre)

### Inferences
- For a "national" prototype, **NCIIPC's six CII sectors are the natural asset-criticality taxonomy**. An asset tagged "Power & Energy / CII-notified" should carry more weight in the risk score than a non-CII asset.
- NCIIPC's stated role ("forecasting national-level CII threats") is where an AI forecaster would fit institutionally. The lack of any public platform suggests that capability is classified or immature, so a prototype should present itself as a **decision-support layer for a sectoral SOC or CSIRT**, not as a replacement for NCIIPC.

### Gaps
- No public list of NCIIPC advisories from 2025–26, no named threat-intelligence or early-warning platform, and no CII-incident statistics were found. Newsletters stop at Apr 2024 per Wikipedia.
- Whether healthcare is formally a CII sector in 2026 could not be confirmed.

---

## 3. C-DAC: cybersecurity R&D products relevant to early warning and threat intelligence (honeynets, CTI, malware analysis, SOC/SIEM, OT, forensics, Indian-language tech)

### Takeaway
C-DAC, MeitY's R&D organisation, has a full **sensor-to-dashboard early-warning stack** in its catalogue. The most relevant pieces:
- **Cyber Threat Management System (CTMS)**, from C-DAC Mohali: honeypot sensors that emulate an organisation's attack surface feed a central collector. Analysis engines then do threat prediction, attack-surface enumeration and risk calculation, with an "integrated early warning system" and "India-specific cyber threat intelligence".
- **C-ADAR**, the C-DAC Attack Dataset and Analysis Repository: AI-based malware and URL detection, MITRE ATT&CK mapping, IoC extraction, and labelled datasets shared with researchers and law enforcement.
- **CDACSIEM**, SOC-as-a-Service, honeynet R&D, SCADA/OT security (a testbed, an OT asset-management tool, an OT SOC, and COPS Defender for IEC 60870-5-104), and a large cyber-forensics suite.
- Citizen tools distributed through CSK: M-Kavach 2, AppSamvid, USB Pratirodh, Browser JSGuard.

No 2026 C-DAC "AI early warning" launch was found.

### Cited Findings

**C-DAC cybersecurity portfolio (official page)**
- C-DAC's cyber-security page lists:
  - **Honeynet Technologies:** research into the latest attacks, building security tools, capturing new attacks, public awareness.
  - **SOC-as-a-Service:** 24x7 managed security and MDR with centralised monitoring.
  - **CDACSIEM:** aggregates, normalises and analyses logs for SOC analysts.
  - **Network Security:** adaptive IDS, dynamic firewall, UTM, and behaviour-based network management that learns new attack patterns.
  - **End-point Security:** against USB threats, data exfiltration, unknown applications, malware and browser threats.
  - **Mobile/Web Security.**
  - **Critical Infrastructure Security:** a **SCADA security testbed**, an **Asset Management Tool** for OT ("real-time risk assessment and alerting"), and a **Security Operations Center for OT**.
  - **Biometrics.**
  - Source: [C-DAC Cyber Security page](https://www.cdac.in/index.aspx?id=cyber_security)

**Cyber Threat Management System (CTMS), C-DAC Mohali (the closest C-DAC analogue to PS-01)**
- Described as "an integrated framework for monitoring analysis and enabling mitigation of cyber threats". It has a **client-server architecture**: client nodes run **honeypot sensors that emulate the organisation's attack surface** and capture attacks, which are sent to a **central collection server** for analysis, threat prediction and mitigation.
- Listed features:
  - a range of honeypot sensors;
  - "analysis engines for threat prediction";
  - "engines for continuous **attack surface enumeration and risk calculation**";
  - "an **integrated early warning system**";
  - "**India-specific cyber threat intelligence**";
  - "mitigation through real-time threat intelligence generation";
  - integration with **SIEMs, firewalls and other security tools**;
  - "a single dashboard for visualisation, monitoring, and management".
- Capabilities: attack capture, data collection and enrichment, analysis and CTI generation, and dissemination through a portal. Contact: Sh. Navdeep S. Chahal, Scientist-F, C-DAC Mohali. The page names no AI or ML technique, no STIX/TAXII/MITRE standard and no deployment.
- Source: [C-DAC CTMS product page](https://www.cdac.in/index.aspx?id=product_details&productId=CyberThreatManagementSystem)

**C-ADAR (C-DAC Attack Dataset and Analysis Repository)**
- Purpose: detects, classifies and shares malware and suspicious URLs, and generates **labelled attack datasets**.
- **Knowledge base:** malware families and strains, bytecodes, opcode sequences, strings, **malware images**, API-call sequences, behaviour reports, imports and DLLs, URLs, network traffic and feature vectors.
- **Analysis:** static, dynamic and visual analysis of Windows, Linux and IoT binaries (PE and ELF). It uses "artificial intelligence" for "real-time [detection] with minimal human interaction", plus signatures.
- **Threat-intelligence outputs:** **mapping to MITRE ATT&CK TTPs**, **IoC extraction for threat hunting**, and reputation analysis with open-source tools. **Client honeypots** monitor URLs for drive-by downloads.
- **Interfaces:** a dashboard with per-engine workflows and playbooks, a REST API, and dataset downloads for researchers, academics and **law enforcement**.
- Contact is C-DAC Mohali (the same scientist as CTMS). No date is given.
- Source: [C-DAC C-ADAR product page](https://www.cdac.in/index.aspx?id=product_details&productId=C-DACAttackDatasetandAnalysisRepository(C-ADAR))

**Other catalogue products**
- CDACSIEM (webSIEM), Cyber Threat Management System, C-ADAR, Digital Forensic Kiosk, Digital Evidence Management System (DEMS), Win-LiFT (Windows live forensics) and PhotoExaminer, plus TrueTraveller (portable forensic kit), TrueImager, DARPAN S3 NMS and Secure BOSS Linux. — [C-DAC Cyber Security & Forensics product catalogue](https://cdac.in/index.aspx?id=tap&tapcat=Cyber_Security_Forensics)

**C-DAC achievements and deployments (official "achievements" page; undated, likely cumulative)**
- **Endpoint tools:** AppSamvid (22,536 downloads), USB Pratirodh (34,897), **M-Kavach (2.78 lakh; launched free on 21 Feb 2017 under CERT-In's CSK)** and Browser JSGuard (27,299). — [C-DAC achievements](https://www.cdac.in/index.aspx?id=print_page&print=achieve_cyber_security_forensic)
- **Cyber Threat Analyzer:** threat-analysis and malware-capture solutions, including a **URL Analyzer & Classifier (UAC)** and dynamic analysis to confirm malicious URLs, "deployed across India". — [C-DAC achievements](https://www.cdac.in/index.aspx?id=print_page&print=achieve_cyber_security_forensic)
- **Network and web security:**
  - **Chakra**, a dynamic firewall with alert correlation, is deployed at the NIA (MHA).
  - **DARPAN NMS** is used for state government networks and NKN.
  - **WebSAFE**, an OWASP vulnerability-assessment framework, is deployed at STQC, DRDL and IDRBT Hyderabad.
  - Source: [C-DAC achievements](https://www.cdac.in/index.aspx?id=print_page&print=achieve_cyber_security_forensic)
- **ICS/OT:**
  - **COPS Defender** hardens the **IEC 60870-5-101/104** SCADA protocols, aligned with **IEC 62351**.
  - SCADA systems were built for two Sikkim hydel stations.
  - A SCADA RTU Security Monitoring Unit (anomaly detection) is in development.
  - Source: [C-DAC achievements](https://www.cdac.in/index.aspx?id=print_page&print=achieve_cyber_security_forensic)
- **Forensics:** more than 20 tools, over 2,000 copies with law enforcement, about 25 forensic labs, more than 600 reports submitted in courts, and about 3,000 officers trained. — [C-DAC achievements](https://www.cdac.in/index.aspx?id=print_page&print=achieve_cyber_security_forensic)
- **ISEA (Information Security Education & Awareness, run by C-DAC Hyderabad for MeitY):** 580 workshops (61,872 participants, 27 States/UTs), 14 lakh students and 13,170 government officers reached. C-DAC is also **CERT-In-empanelled** for VA/PT. — [C-DAC achievements](https://www.cdac.in/index.aspx?id=print_page&print=achieve_cyber_security_forensic)
- **M-Kavach 2** was developed by C-DAC Hyderabad with MeitY support. It helps users configure Android devices securely and spot bad apps. — [IIT Jodhpur security tools page](https://iitj.ac.in/cybersecurity/en/securitytools); [Vikaspedia](https://en.vikaspedia.in/education/digital-litercy/information-security/m-kavach-2)

**Indian-language technology (C-DAC GIST)**
- C-DAC's GIST (Graphics and Intelligence based Script Technology) group has **localised an information and data security awareness portal into Indian languages using its Go-Translate framework**. — [C-DAC GIST page](https://cdac.in/index.aspx?id=gist)
- Context: Quick Heal and Seqrite signed an MoU with MeitY's **BHASHINI** (Aug 2025) to offer cybersecurity awareness in **22 Indian languages**, because most security material exists only in English. — [APAC News Network, Aug 2025](https://apacnewsnetwork.com/2025/08/quick-heal-bhashini-collaborate-to-offer-cybersecurity-and-privacy-awareness-in-22-indian-languages/amp)

**Other C-DAC context**
- C-DAC worked with MeitY on cyber-forensic services (C-DAC Kolkata with IIT Patna). This is older and undated, about 2020. — [ELE Times](https://www.eletimes.ai/meity-preparing-ai-powered-arsenal-address-cyber-security)
- A C-DAC and Bank of India collaboration on quantum banking tools has been reported (2026). — [Quantum Zeitgeist](https://quantumzeitgeist.com/bank-india-quantum-banking-tools-c)

### Inferences
- **CTMS is the architecture to echo.** Its own feature list (sensors, central collector, analysis engines for prediction, attack-surface enumeration with risk calculation, early warning, India-specific CTI, SIEM integration, single dashboard) is close to what PS-01 asks for. Telling C-DAC judges "our pipeline follows the CTMS pattern (sensor → collector → enrichment → risk calculation → early warning → CTI dissemination) and adds an AI correlation layer" is likely to resonate. It is also accurate, because CTMS publicly names no AI technique.
- **C-ADAR conventions to reuse:** MITRE ATT&CK TTP mapping, IoC extraction, labelled datasets and a REST API. These are low-cost features in a prototype that signal "aligned with C-DAC's own CTI products".
- C-DAC's OT strength (IEC 60870-5-104, IEC 62351, SCADA testbed) means a scenario about a **power or CII OT advisory** (for example a vulnerability in a SCADA or RTU vendor product, matched to a simulated substation inventory) would play to judges' expertise.
- C-DAC's language work (GIST, Bhashini ecosystem) supports a **multilingual citizen and MSME alert** feature, such as Hindi or Marathi alert summaries, as a distinctly Indian differentiator.

### Gaps
- No public evidence was found of a 2025–26 C-DAC AI-based national early-warning or threat-intelligence platform launch, or of a C-DAC deepfake-detection tool (claims seen only on exam-prep blogs).
- CTMS and C-ADAR deployment status, users (CERT-In? NCIIPC?) and AI methods are not disclosed.
- The scale of C-DAC's honeynet sensor network (number of sensors, locations) and any data-sharing with CERT-In or CSK was not found.
- Download figures on the achievements page are undated.
- A search summary said the "Cyber Aware Digital Naagrik" programme is part of ISEA, but the source page was not verified. The list of languages ISEA content is available in was not found (check isea.gov.in or staysafeonline.in).

---

## 4. Policy and regulatory layer: MeitY, I4C, the National Cyber Security Strategy, the DPDP Act, RBI, SEBI CSCRF

### Takeaway
The mandates that require threat intelligence and SOCs are sectoral, and they are tightening. On reporting clocks:
- The **RBI 2026 Directions** (31 Jul 2026) require banks to run a 24x7 C-SOC with SIEM, gather and integrate threat intelligence, share it through IB-CART, and report incidents **within 6 hours on DAKSH**.
- **SEBI's CSCRF** (Aug 2024; deadlines extended to Aug 2025) requires SOC coverage for all regulated entities, with a **Market SOC** for smaller ones.
- The **DPDP Rules** (notified 13 Nov 2025) add a **72-hour** breach report to the Data Protection Board, on top of CERT-In's 6 hours.

On cyber fraud, the MHA's **I4C** runs the fraud early-warning stack: Suspect Registry, CFCFRMS, the Samanvaya and Pratibimb platforms, and the CFMC. **RBIH's MuleHunter.AI** is the clearest example of a **production government AI early-warning model** in India.

Overarching strategy is a gap: the **National Cyber Security Strategy has been in draft since 2020** and has not been released (as of May 2026).

### Cited Findings

**National Cyber Security Strategy (NCSS) and doctrine**
- The NCSS "has been in development since 2020 and has not been released" (as of 7 May 2026). ORF recommends speeding it up, fusing civil and military efforts, taking a proactive posture and making attribution credible. — [ORF, Sameer Patil, 7 May 2026](https://www.orfonline.org/research/operation-sindoor-at-one-taking-stock-of-india-s-cyber-preparedness)
- **Conflicting claim:** one outlet reports "Government of India has launched the National Cybersecurity Strategy 2026". There is no official notification and the claim is **unverified**. — [Education Post](https://educationpost.in/news/education/current-affairs/science-and-technology/india-launches-national-cybersecurity-strategy-2026). Contrary views: [IMPRI](https://www.impriindia.com/insights/policy-update/indias-national-cyber-security-strategy-2020-assessing-institutional-gaps-and-the-need-for-a-new-strategy/); [Civilsdaily](https://www.civilsdaily.com/news/status-of-indias-national-cyber-security-strategy/)
- India **declassified its Joint Doctrine for Cyberspace Operations (JDCO) in Aug 2025**. It lists deception, denial, degradation, disruption and destruction as effects, and names attribution as a capability gap. — [ORF, May 2026](https://www.orfonline.org/research/operation-sindoor-at-one-taking-stock-of-india-s-cyber-preparedness)
- The 2013 **National Cyber Security Policy** remains the formal policy. NCIIPC itself came out of it. — [Legacy IAS](https://www.legacyias.com/national-cyber-security-strategy/); [Wikipedia NCIIPC](https://en.wikipedia.org/wiki/National_Critical_Information_Infrastructure_Protection_Centre)

**MeitY (2025–26)**
- MeitY released **AI Governance Guidelines in Nov 2025**, with an AI Governance Group, a Technology & Policy Expert Committee and a proposed AI Safety Institute. In 2026 MeitY urged ministries, states and regulators to review their security posture against GenAI-enabled attacks. — [WION, 29 Oct 2026](https://www.wionews.com/india-news/trust-deficit-how-is-india-strengthening-cybersecurity-in-age-of-ai-powered-threats-1793268629887)

**I4C (Indian Cyber Crime Coordination Centre, MHA): the cyber-fraud early-warning stack**
- On **10 Sep 2024** (I4C Foundation Day) the government launched four things:
  - the **Suspect Registry**, a registry of identifiers built from the National Cybercrime Reporting Portal with banks and financial intermediaries;
  - the **Cyber Fraud Mitigation Centre (CFMC)**;
  - the **Samanvaya** platform for joint investigations;
  - the **Cyber Commandos** programme.
  - Source: [MediaNama, Sep 2024](https://www.medianama.com/2024/09/223-india-launches-central-cybercrime-registry-to-strengthen-fraud-prevention-and-national-cybersecurity/); [News On AIR, 10 Sep 2024](https://www.newsonair.gov.in/minister-amit-shah-addresses-inaugural-foundation-day-of-indian-cyber-crime-coordination-centre)
- **Lok Sabha reply of 17 Mar 2026** (as reported): CFCFRMS has saved more than **₹8,690 crore**, and the Suspect Registry has blocked **₹9,518 crore** of suspicious transactions. By **June 2026**, **30.48 lakh suspect identifiers** had come from banks and **32.08 lakh "Layer 1" mule accounts** had been shared with participating entities. — [Organiser, 26 Aug 2026](https://organiser.org/2026/08/26/377008/bharat/indias-digital-shield-how-i4c-is-winning-the-war-against-cybercrime/amp/). This is a partisan outlet, so the figures should be checked against the Lok Sabha record. An earlier 2025 summary put savings at about ₹5,100 crore. — [Drishti IAS, Sep 2025](https://www.drishtiias.com/daily-updates/daily-news-analysis/india-s-suspect-registry-and-cybersecurity-initiatives/print_manually)
- The **Pratibimb** module on Samanvaya maps the locations of criminals and criminal infrastructure on a map. It is credited with 6,046 arrests, 17,185 linkages and 36,296 investigation-assistance requests (Lok Sabha data, early 2025). — [InsightsonIndia, Mar 2025](https://www.insightsonindia.com/2025/03/15/pratibimb-module/)
- **Privacy concern:** the Samanvaya portal tracks about 1.8 million suspects. — [MediaNama, Dec 2025](https://www.medianama.com/2025/12/223-samanvaya-portal-tracks-1-8m-suspects-raises-privacy-concerns/)

**RBI and RBIH**
- **MuleHunter.AI**, an AI/ML mule-account detection model built by the Reserve Bank Innovation Hub, was piloted in Dec 2024. — [Business Standard, Dec 2024](https://www.business-standard.com/finance/news/rbi-innovation-hub-develops-mulehunter-ai-to-combat-mule-account-frauds-124120601042_1.html). It has been onboarded by **29 banks** per a Finance Ministry Rajya Sabha reply (date unclear in sources). — [search summary; taxguru](https://taxguru.in/?p=1063495)
- **Digital Payments Intelligence Platform (DPIP):** RBIH is building it with banks (7 banks in the pilot phase sharing data to train AI/ML models). In Sep 2025 the Finance Ministry pushed RBI to speed up the rollout. — [Business Standard, 30 Sep 2025](https://www.business-standard.com/finance/news/fin-min-pushes-rbi-to-expedite-launch-of-platform-to-curb-digital-frauds-125093000979_1.html). The Indian Digital Payment Intelligence Corporation (IDPIC) was reportedly incorporated as a Section 8 company on 16 Oct 2025 (**exam-prep sources only; unverified**). — [IASGyan](https://www.iasgyan.in/daily-current-affairs/operation-mule-hunt-crackdown-on-cyber-fraud-networks)
- **RBI (Commercial Banks – Cybersecurity, Technology: Risk, Resilience and Assurance Framework) Directions, 2026**: Ref. RBI/DoS/2026-27/410, dated **31 Jul 2026**, updated 1 Oct 2026. All requirements below are from [RBI Master Direction page](https://rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=13643).
  - **C-SOC:** "Round-the-clock Level 1 monitoring". "Correlation of logs through appropriate SIEM tools". Dynamic behaviour analysis. Malware defences with "behavioural detection capabilities".
  - **Threat intelligence:**
    - "Arrangements for threat intelligence gathering, monitoring, and analysing" (Para 46).
    - "Integration of threat intelligence and security information feeds", and collecting and sharing threat information from local, national and international sources (Paras 185–186).
    - Sharing threat intelligence with **IB-CART** (IDRBT) (Para 184).
  - **Incident reporting:** "report cyber incidents **within six hours of detection on DAKSH platform**" (to RBI), and "pro-actively notify CERT-In" (Para 182).
  - **Cyber Crisis Management Plan** covering detection, containment, response and recovery (Paras 192–193). Red teaming is optional (Para 162).
  - It repeals earlier cyber and IT-governance directions (Para 230).
  - The 2026 Directions contain no AI or ML mentions.
- The predecessor **Master Direction on IT Governance, Risk, Controls and Assurance Practices** was issued in Nov 2023 and took effect on 1 Apr 2024. — [The News Minute](https://www.thenewsminute.com/news/rbi-issues-new-directions-to-banks-nbfcs-on-it-governance-cyber-security)

**SEBI Cybersecurity and Cyber Resilience Framework (CSCRF)**
- **Circular of 20 Aug 2024 (CIR/2024/113).** Deadlines were extended several times: KRAs and DPs to 1 Apr 2025, all regulated entities to 30 Jun 2025, then to **31 Aug 2025** for most regulated entities (CIR/2025/96). — [Taxmann](https://www.taxmann.com/post/blog/sebi-extends-cscrf-deadline-for-regulated-entities); [The Week/PTI, 30 Jun 2025](https://www.theweek.in/wire-updates/business/2025/06/30/dcm101-biz-sebi-cyber-extension.html)
- **SOC coverage:** all regulated entities must have SOC monitoring, either their own or group SOC, the **Market SOC (M-SOC)**, or a third-party SOC. NSE and BSE run the Market SOC for small and self-certification entities and report its effectiveness to SEBI. AIF and PMS entities in the self-certification category with fewer than 100 clients are exempt from M-SOC. — [Uniqus](https://uniqus.com/cybersecurity-and-cyber-resilience-framework-cscrf-for-sebi-regulated-entities-res/); [Taxmann](https://www.taxmann.com/post/blog/sebi-extends-cscrf-deadline-for-regulated-entities)
- Threat intelligence appears as a SOC function. Sources may include CERT-In or third parties (from the 2023 consultation stage). — [CloudSEK knowledge base](https://cloudsek.com/knowledge-base/strengthening-digital-defense-sebis-cybersecurity-and-cyber-resilience-framework-explained); [Deloitte consultation note](https://www2.deloitte.com/content/dam/Deloitte/in/Documents/tax/Global%20Business%20Tax%20Alert/in-tax-gbt-Consultation-Paper-on-SEBI-Regulated-Entities-noexp.pdf)

**DPDP Act 2023 and DPDP Rules 2025**
- The **DPDP Rules were notified on 13 Nov 2025**. Under **Rule 7** a data fiduciary must tell the Data Protection Board about a breach without delay, then file a **detailed report within 72 hours** (extendable on request). Commencement is phased, and one source says breach provisions are fully enforceable only around **May 2027**. — [iPleaders, last verified 8 May 2026](https://blog.ipleaders.in/dpdp-rules-2025-operational-compliance-guide-for-indian-businesses/); [KS&K](https://ksandk.com/md/data-protection-and-data-privacy/dpdp-data-breach-notification-timeline/)
- **Two parallel clocks:** CERT-In's 6 hours and the DPDP Board's 72 hours both start from the same breach. Commentators debate whether this means duplication or a more complete regime. — [Bar & Bench](https://www.barandbench.com/view-point/obligations-under-cert-in-and-dpdp-not-a-zero-sum-game). The draft rules (Jan 2025) also covered encryption, logs and timely breach reporting. — [MediaNama, Jan 2025](https://www.medianama.com/2025/01/223-dpdp-rules-2025-encryption-logs-timely-reporting-data-breaches/)

### Inferences
- A prototype can show a **"regulatory clock" panel** for each incident, with the clocks chosen by sector:
  - CERT-In: 6 h.
  - RBI DAKSH: 6 h, for banks.
  - DPDP Board: 72 h, when personal data is involved.
  - SEBI CSCRF and M-SOC routing, for market entities.
  - CERT-In blueprint patch deadlines: 12h/1d/3d/5d.

  This is concrete, India-specific and relevant to compliance. Judges from a government R&D body will recognise every acronym.
- MuleHunter.AI and DPIP show that Indian regulators accept **AI/ML risk scoring** when it is built for the institution and trained on shared data. Presenting the prototype's model as "collaborative, sector-shared and explainable" fits this precedent.
- **DPDP implications for threat data:** IoCs such as IPs, domains and hashes are mostly not personal data. But victim notifications, leaked-credential monitoring (XVigil-style) and CSK-style user notification involve personal data. A prototype should minimise personal data, hash or redact credentials, and say so explicitly.

### Gaps
- The full RBI 2026 Directions PDF was not read beyond the summary of the C-SOC and threat-intelligence paragraphs. Whether the Directions cover NBFCs and cooperative banks (the C-Edge victims) is unclear. Commercial banks only, excluding SFBs, Payments Banks and LABs, per the search summary.
- The current SEBI CSCRF status after Aug 2025, and any 2026 amendments, were not checked.
- The DPDP commencement date for Rule 7 has not been confirmed from the Gazette.
- I4C figures come through secondary outlets; the Lok Sabha primary was not read.

---

## 5. Indian industry building AI threat-intelligence products: what AI they use and how they score risk

### Takeaway
Indian vendors have converged on **AI-native external threat intelligence plus attack-surface correlation, with prioritisation by exploitability, likelihood and impact rather than CVSS alone**:
- **CloudSEK:** XVigil, BeVigil, SVigil, AIVigil, and the Nexus AI attack-path engine.
- **Cyble:** Vision, and the Blaze AI agentic engine with a threat graph plus vector memory.
- **TAC Security:** ESOF, with neural-network cyber risk quantification "beyond CVSS".
- **Sequretek:** Percept XDR, with NLP querying.
- **Seqrite/Quick Heal:** an endpoint-telemetry threat report covering 8M+ endpoints.
- **Tata Communications and TCS:** CTI-as-a-service, Cyber Insights Platform.
- **WhizHack:** ZeroHack honeynet sensors.

None publishes its scoring formula.

### Cited Findings

**CloudSEK (Bengaluru)**
- The platform (updated May 2026) has these modules. Source for this list: [CloudSEK platform page](https://www.cloudsek.com/platform)
  - **XVigil:** digital risk protection, covering phishing, data leaks, brand impersonation, dark-web leaked credentials and takedowns.
  - **BeVigil:** attack-surface monitoring of shadow assets, misconfigurations and leaked credentials across "8 surfaces" (web, mobile, API, cloud).
  - **SVigil:** third- and fourth-party supply-chain risk.
  - **AIVigil:** AI attack surface, such as exposed MCP servers, vector stores and agentic workflows.
  - **Threat Intelligence:** actor profiles, CVE intelligence, ransomware.
  - **Nexus AI:** "Real-time insights and alerts on vulnerabilities and Initial Attack Vectors", with attack graphs, path validation and cross-domain correlation.
- **Scoring:**
  - Attack paths are "**Prioritised by likelihood & impact**". Signals are enriched with actor TTPs, exploited-CVE timelines, asset ownership and business context. "Noise is filtered; high-signal events are tagged". Output goes to SIEM, SOAR, ticketing and CISO dashboards. — [CloudSEK platform](https://www.cloudsek.com/platform)
  - Nexus "prioritizes risks based on **exploitability, impact, and attacker behaviour rather than severity score alone**". — [CloudSEK Nexus AI page](https://www.cloudsek.com/ar/platform/nexus-ai)
- Nexus was unveiled at GISEC 2025. — [CloudSEK event page](https://www.cloudsek.com/event/cloudsek-unveils-ai-powered-nexus-platform-at-gisec-global-2025). CloudSEK raised a $19M Series B1. — [CloudSEK](https://cloudsek.com/new). On Gartner Peer Insights it averages about 4.8/5, and one reviewer called it "slightly noisy until tuned right". — [Gartner Peer Insights](https://www.gartner.com/reviews/product/cloudsek-xvigil)

**Cyble (founded 2019 by Beenu Arora and Manish Chachada; offices in the US, India and elsewhere)**
- **Blaze AI** is described as "an agentic, AI-native engine" that unifies threat intelligence, digital risk protection and security operations. It combines "**Neural Memory (structured threat graph)** and **Vector Memory (semantic context)**". These are vendor claims. — [Cyble blog: Predictive cybersecurity with Blaze AI](https://cyble.com/blog/predictive-cybersecurity-cyble-blaze-ai/); [Cyble about](https://cyble.com/about-us/)
- Cyble was named a **Challenger in the inaugural 2026 Gartner Magic Quadrant for Cyberthreat Intelligence Technologies**. — [Cyble blog](https://cyble.com/blog/cyble-challenger-in-2026-gartner-cyberthreat-intelligence-technologies); [UNI/Business Wire India](https://uniindia.com/cyble-positioned-as-a-challenger-in-the-2026-gartner-magic-quadrant-for-cyberthreat-intelligence-technologies/business-wire-india/news/3839505.html). It was included in the Forrester External Threat Intelligence Service Providers Landscape, Q1 2026 (8 Apr 2026). — [Cyble press](https://cyble.com/press/external-threat-intelligence-landscape-q1-2026/). It won the VARINDIA 2026 "Best Threat Intelligence Platform" award in New Delhi. — [Cyble press](https://cyble.com/press/cyble-wins-best-threat-intelligence-platform/)
- Cyble Vision "prioritizes threats by real-world risk". No scoring methodology is published. — [Cyble Vision](https://cyble.com/cyble-vision/)

**TAC Security (ESOF)**
- ESOF is described as an AI-based vulnerability management platform with "5+ Million vulnerabilities" managed. Its "cyber score evaluates each vulnerability based on **severity, frequency, and potential impact**". Auto-prioritisation ranks by "**severity, potential impact, and exploitability**". — [TAC Security ESOF VMP](https://tacsecurity.com/revolutionize-your-cyber-defense-with-esof-vmp-transforming-vulnerability-management-for-the-modern-enterprise/)
- **Cyber Risk Quantification (CRQ)** turns vulnerabilities into dollar figures using an "AI-driven neural network", going "beyond... CVSS Score". No model details are given. — [TAC Security CRQ release](https://tacsecurity.com/tac-security-revolutionizes-cyber-risk-management-with-ai-powered-esof-cyber-risk-quantification/); [TAC CRQ in dollars](https://tacsecurity.com/tac-security-adds-cyber-risk-quantification-tool-to-esof-platform-to-translate-cyber-risk-into-dollars-for-better-decision-making/)

**Seqrite / Quick Heal Labs (Pune)**
- **India Cyber Threat Report 2026:**
  - **265.52 million detections across more than 8 million endpoints** (Oct 2024–Sep 2025), about 505 a minute.
  - Trojans and file infectors make up about 70%.
  - Top states: **Maharashtra, Gujarat, Delhi**.
  - Manufacturing, education and healthcare together account for about 47%.
  - The report predicts AI-assisted "cognitive intrusions" in 2026.
  - An addendum for Oct 2025–May 2026 counts **156.3M** malware detections, with a **March 2026 peak**.
  - Source: [Seqrite report page](https://www.seqrite.com/india-cyber-threat-report-2026/); [CRN India](https://www.crn.in/?p=74309)
- Quick Heal and Seqrite signed an MoU with **BHASHINI** to integrate Indian-language technology (22 languages) for awareness. — [APAC News Network, Aug 2025](https://apacnewsnetwork.com/2025/08/quick-heal-bhashini-collaborate-to-offer-cybersecurity-and-privacy-awareness-in-22-indian-languages/amp)
- Quick Heal supplies a free bot-removal tool through CSK. — [Botconf 2023 slides](https://www.botconf.eu/wp-content/uploads/formidable/2/2023_ASHOK.pdf)

**Sequretek (Mumbai)**
- **Percept XDR and NG-SIEM, Percept EDR, Percept IGA, plus managed security services.** The company cites "over 600 use cases across Threat Intelligence, Malware Intelligence, User Behavior and Entity Behavior analytics". Integrated **NLP lets users query threat-intelligence data conversationally**. — [Unite.AI interview with CEO Pankit Desai](https://www.unite.ai/pankit-desai-co-founder-and-ceo-sequretek-interview-series/); [Gartner Percept XDR](https://www.gartner.com/reviews/product/percept-xdr-and-ng-siem); [IndiaAI startup profile](https://indiaai.gov.in/startup/sequretek)

**Tata Communications / TCS**
- Tata Communications sells **Cyber Threat Intelligence as a Service (CTIaaS)** with MDR. — [Tata Communications CTIaaS brochure](https://www.tatacommunications.com/hubfs/library/security/documents/cyber-threat-intelligence-as-a-service-ctiaas-mdr-brochure.pdf)
- TCS launched a **Cyber Insights Platform** in Nov 2023, using AI and Amazon Security Lake. It also offers an older vendor-agnostic **Cyber Vigilance Platform**, and runs an AI-assisted multi-tenant SOC on FortiSIEM and FortiSOAR (vendor case study). — [Fortinet/TCS case study](https://www.casestudies.com/company/fortinet/case-study/tata-consultancy-services-strengthens-soc-compliance-with-fortinet-and-automates-security-across-thousands-of-devices). TCS-CERT is a CVE CNA. — [radicalnotion.ai](https://radicalnotion.ai/cna/tcs-cert)
- No 2026 Tata "agentic SOC" launch was confirmed.

**WhizHack (Gurugram): honeynet-sensor threat intelligence**
- **ZeroHack TRACE** is a decoy and sensor threat-intelligence framework for IT and OT. Its sensors can move periodically, and attacker interactions continuously enrich its threat database (vendor and listing claims). — [G2](https://g2.com/products/zerohack-trace/discuss); [Khaleej Times](https://www.khaleejtimes.com/kt-network/whizhack-technologies-forays-into-mena-with-its-flagship-zerohack?amp=1)
- **US Patent 12,413,622 B2** (9 Sep 2025), "System and method for generating cyber threat intelligence", covers honeynets that emulate services, sensors and a central data collector. — [Google Patents](https://patents.google.com/patent/US12413622)
- It has a Centre of Excellence with IIT Jodhpur on cyber-physical systems. — [Careers360](https://news.careers360.com/iit-jodhpur-whizhack-technologies-inaugurate-centre-of-excellence-in-cyber-physical-systems-security)

**Market sentiment**
- A survey reported by CXOToday found that 100% of Indian respondents plan to use AI in security operations, and the top expected use (53%) is automated anomaly detection. It also describes an "AI-SOC paradox", where hopes run into implementation hurdles. — [CXOToday](https://cxotoday.com/media-coverage/the-ai-soc-paradox-indian-companies-high-hopes-confront-implementation-hurdles/)

### Inferences
- The industry pattern is **"exposure × threat × business context" rather than CVSS**. A prototype should score risk explainably, with these inputs:
  - CVSS base score;
  - whether the flaw is known-exploited or has exploit availability;
  - asset exposure (internet-facing or not);
  - asset criticality (NCIIPC sector or CII flag);
  - threat-actor activity against India or the sector;
  - the CERT-In blueprint patch deadline.

  It should show each factor's contribution. This mirrors CloudSEK and TAC claims while being more transparent than either, which matters to government judges.
- Cyble's "threat graph + vector memory" design suggests a cheap hackathon pattern: a small knowledge graph (advisory → CVE → product → asset → sector), plus embeddings for fuzzy-matching advisory text to asset inventory entries.
- Seqrite's state-wise and sector-wise telemetry framing (Maharashtra tops the list) suits a Mumbai event, for example a demo map with a Maharashtra focus.

### Gaps
- No vendor publishes model architectures, training data or validation metrics for its risk scores. Every AI claim above is vendor-stated.
- Named Indian government customers for CloudSEK or Cyble threat intelligence were not found.
- Others were not researched in depth: Innefu Labs (AI for law enforcement), CyberXTron, Technisanct, Kratikal, Securonix (Indian-founded), and the Arete/K7 labs.

---

## 6. Recent Indian incidents (2022–2026) where early warning worked or failed, and stated gaps

### Takeaway
The record is mixed:
- **Worked:** pre-emptive CERT-In advisories (CIAD-2025-0018/0019) before Operation Sindoor, with only about 150 of about 1.5M attacks succeeding (Maharashtra Cyber). NPCI's rapid isolation of C-Edge in 2024 contained a supply-chain ransomware attack.
- **Failed or exposed gaps:**
  - AIIMS 2022: improper network segmentation and unpatched Zimbra.
  - Power-grid intrusions in 2020–22 (RedEcho), found by a **foreign** firm (Recorded Future), not Indian agencies.
  - Crypto-exchange hacks: WazirX in 2024 (about $235M) and CoinDCX in 2025 (about $44M).
  - Concentration risk among small banks.
- **Recurring stated gaps:** no released NCSS, weak attribution, a reactive posture, civil-military coordination, sector-agnostic AI guidance, reliance on foreign technology, and English-only awareness material.

### Cited Findings

**Operation Sindoor (Apr–May 2025): early warning largely worked**
- Days after the Pahalgam attack, CERT-In issued **CIAD-2025-0018 and CIAD-2025-0019**, warning CII operators and the financial sector about ransomware, DDoS and malware. ORF judged denial performance "reasonable". — [ORF, 7 May 2026](https://www.orfonline.org/research/operation-sindoor-at-one-taking-stock-of-india-s-cyber-preparedness)
- Maharashtra Cyber's report "**Road of Sindoor**" counted about **1.5 million attacks** by 7 APT groups, of which **only 150 succeeded** (for example a defacement of the Kulgaon Badlapur Municipal Council website). Origins included Pakistan, Bangladesh, the Middle East and Indonesia. This was a rare **public attribution** to Pakistan by an Indian agency. — [Tribune](https://www.tribuneindia.com/news/india/pakistan-allied-hackers-launched-15-lakh-cyber-attacks-on-indian-websites-only-150-successful/amp); [Free Press Journal](https://freepressjournal.in/tech/india-saw-15-lakh-cyberattack-attempts-during-operation-sindoor-150-systems-compromised-report). **Conflict:** ORF cites "10 million intrusions" from Maharashtra Cyber. — [ORF](https://www.orfonline.org/research/operation-sindoor-at-one-taking-stock-of-india-s-cyber-preparedness)
- The conflict brought a **deepfake disinformation** campaign, mostly on X. — [ORF](https://www.orfonline.org/research/operation-sindoor-at-one-taking-stock-of-india-s-cyber-preparedness)

**Power grid (2020–2022): domestic early warning failed to detect**
- "RedEcho's intrusions into power grids in 2020 and 2022 were identified by the US firm Recorded Future, not Indian agencies". ORF cites this as evidence of India's thin attribution record. — [ORF, May 2026](https://www.orfonline.org/research/operation-sindoor-at-one-taking-stock-of-india-s-cyber-preparedness)

**AIIMS Delhi ransomware (Nov 2022)**
- Detected on 23 Nov 2022. **5 servers** were affected and about **1.3 TB** of data was encrypted (MoS IT reply). Digital services were disrupted for about 2 weeks. — [Deccan Herald](https://www.deccanherald.com/amp/story/india%2F5-servers-of-aiims-were-affected-about-13-tb-of-data-encrypted-in-cyber-attack-mos-it-1172460.html) (the URL slug says "13-tb"; reports give 1.3 TB); [MediaNama, Feb 2023](https://www.medianama.com/2023/02/223-cyber-attack-aiims-rajya-sabha/)
- **CERT-In's finding: "improper network segmentation"**. Unpatched Zimbra (vulnerabilities known since early 2022) and staff use of unofficial email were flagged. CERT-In issued a special advisory to the Health Ministry. — [MediaNama](https://www.medianama.com/2023/02/223-cyber-attack-aiims-rajya-sabha/); [The Wire](https://thewire.in/health/aiims-servers-cyberattack-ransomware-rajya-sabha)

**C-Edge Technologies ransomware (Jul 2024): supply-chain concentration risk, contained**
- C-Edge, a TCS–SBI joint venture providing core banking for cooperative banks and RRBs, was hit. On being informed (around 26 July 2024), **NPCI temporarily isolated C-Edge** from its retail payment systems. About **300 small banks** lost UPI, ATM and IMPS services. Connectivity came back after an independent forensic review. The impact was limited to C-Edge's own data centre. — [Moneylife](https://www.moneylife.in/article/ransomware-attack-on-cbs-provider-hits-over-200-cooperative-and-regional-rural-banks-npci-restores-connectivity/74804.html); [CSO Online](https://www.csoonline.com/article/3480250/over-300-indian-banks-suffer-payment-disruption-from-ransomware-attack.html); [YourStory](https://yourstory.com/2024/08/npci-re-establishes-connectivity-with-c-edge-ransomeware-attack); [KPMG CTIP note, 1 Aug 2024](https://assets.kpmg.com/content/dam/kpmg/in/pdf/2024/08/kpmg-ctip-c-edge-01-aug-2024.pdf)

**Crypto exchanges**
- **WazirX (Jul 2024):** about $234–235M lost, linked to North Korea's Lazarus Group. **CoinDCX (Jul 2025):** about $44M drained from an internal liquidity account; customer wallets were not affected, but disclosure was criticised as delayed. In Oct 2026 CoinDCX denied a report of a new roughly $16M hack. — [Crowdfund Insider, Jul 2025](https://www.crowdfundinsider.com/2025/07/246185-crypto-exchange-coindcx-hacked-44m-in-funds-reportedly-stolen/); [Outlook Business](https://www.outlookbusiness.com/deeptech/tech/crypto-exchange-coindcx-hit-by-security-breach-44-million-drained); [IndraStra, Oct 2025](https://www.indrastra.com/2025/10/coindcx-trust-and-turning-point-for.html?m=0)

**2026 landscape, mostly unverified**
- The leak-site tracker ransomware.live lists **564 Indian victims** (cumulative). 2026 entries include a Mumbai cardiac hospital and others. These are **actor claims, not confirmed incidents**. — [ransomware.live India map](https://www.ransomware.live/map/IN)
- A claimed 18,855 healthcare cyber-threat instances in H1 2026 (attributed to parliamentary data) appears only on low-quality aggregator sites and is **unverified**. — [restcokami.com](https://restcokami.com/article/india-s-cyber-threats-financial-and-healthcare-sectors-under-attack)

**Stated systemic gaps (from authoritative or expert sources)**
- Strategy: no released NCSS since 2020. Process: a reactive posture, weak civil-military integration and weak attribution. Coverage: the JDCO excludes civilian CII. — [ORF, May 2026](https://www.orfonline.org/research/operation-sindoor-at-one-taking-stock-of-india-s-cyber-preparedness)
- The CERT-In AI blueprint has no sector-specific guidance and is voluntary rather than mandatory. — [MediaNama, May 2026](https://www.medianama.com/2026/05/223-cert-in-releases-blueprint-for-defending-against-ai-assisted-cyber-threats/)
- "India's defensive AI capability still trails global leaders, leaving it reliant on foreign technology" (expert view). — [WION, Oct 2026](https://www.wionews.com/india-news/trust-deficit-how-is-india-strengthening-cybersecurity-in-age-of-ai-powered-threats-1793268629887)
- Most cyber-awareness material is available only in English. — [APAC News Network, Aug 2025](https://apacnewsnetwork.com/2025/08/quick-heal-bhashini-collaborate-to-offer-cybersecurity-and-privacy-awareness-in-22-indian-languages/amp)
- The DPIP rollout was delayed and needed Finance Ministry pressure (Sep 2025). — [Business Standard](https://www.business-standard.com/finance/news/fin-min-pushes-rbi-to-expedite-launch-of-platform-to-curb-digital-frauds-125093000979_1.html)

### Inferences
- **Common thread in the failures:** the signal existed (a known Zimbra flaw; a vendor dependency; a foreign CTI report on RedEcho), but it was not **correlated with a specific asset owner in time**. This supports the PS-01 demo flow (new advisory → match to asset inventory → exposure → risk → alert) as the gap to target.
- **Concentration risk (C-Edge):** an early-warning tool should model **shared third-party dependencies**. One vendor advisory should fan out to every downstream entity that uses that vendor, for example the cooperative banks on one core-banking provider. This is a credible addition that CERT-In's broadcast advisories do not provide.
- **The Sindoor success shows that advisories plus sector reach work.** The prototype should show that it amplifies CERT-In's output with per-entity targeting, rather than competing with it.

### Gaps
- No official post-incident reports (CERT-In or parliamentary committee) were found for AIIMS, C-Edge or CoinDCX. Lessons are drawn from press coverage and parliamentary replies.
- Verified 2026 Indian critical-infrastructure incidents (power, telecom, hospitals) with official confirmation were not found.
- The Maharashtra Cyber "Road of Sindoor" primary report was not read; attack counts conflict between 1.5M and 10M.

---

## 7. Lessons and design patterns for a 24-hour AI early-warning prototype aimed at Indian judges

### Takeaway
Present the prototype as a **CTMS-style, India-native "advisory-to-asset" early-warning layer**. It should:
- ingest CERT-In-style advisories and vulnerability notes (CIAD/CIVN);
- correlate them, with AI help, against a simulated inventory tagged by **NCIIPC CII sector** and sectoral CSIRT;
- score risk explainably, combining exploitability, exposure, criticality, threat activity and the CERT-In blueprint deadline;
- issue routed, multilingual alerts with a **regulatory-clock** workflow (CERT-In 6h, RBI DAKSH 6h, DPDP 72h; blueprint patch deadlines 12h/1d/3d/5d).

This speaks C-DAC's own design language (sensors → collector → analysis engines → risk calculation → early warning → India-specific CTI → dashboard → SIEM) and targets documented gaps: sector-specific triage, supply-chain fan-out, machine-readable correlation, explainability and Indian-language dissemination.

### Cited Findings (terminology, standards and mandates worth naming on slides)
- **C-DAC's own early-warning vocabulary** (CTMS): "attack surface enumeration and risk calculation", "integrated early warning system", "India-specific cyber threat intelligence", "real-time threat intelligence generation", SIEM and firewall integration, "single dashboard". — [C-DAC CTMS](https://www.cdac.in/index.aspx?id=product_details&productId=CyberThreatManagementSystem)
- **C-ADAR conventions:** MITRE ATT&CK TTP mapping, IoC extraction for threat hunting, labelled datasets, REST API. — [C-DAC C-ADAR](https://www.cdac.in/index.aspx?id=product_details&productId=C-DACAttackDatasetandAnalysisRepository(C-ADAR))
- **CERT-In's self-description:** "situational awareness", "metadata level" (NCCC), "near-real time information", "automated cyber threat exchange platform", "AI-driven situational awareness systems", CSK, CCMP, sectoral CSIRTs (CSIRT-Fin, CSIRT-Power). — [PIB Backgrounder, Jan 2026](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **Legal and mandate anchors:**
  - IT Act **Sec 70B** (CERT-In) and **Sec 70A** (NCIIPC).
  - CERT-In Directions **No. 20(3)/2022** (6h reporting, 180-day logs). — [PSA Legal](https://psalegal.com/new-cert-in-directions-overview-and-implications/)
  - **CIGU-2026-0002** AI blueprint (12h KEV patching, AIBOM, AI asset inventory). — [MediaNama](https://www.medianama.com/2026/05/223-cert-in-releases-blueprint-for-defending-against-ai-assisted-cyber-threats/)
  - SBOM/HBOM/AIBOM/QBOM/CBOM Technical Guidelines v2 (Jul 2025). — [PIB](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
  - RBI 2026 Directions (C-SOC, threat-intelligence feed integration, IB-CART, DAKSH 6h). — [RBI](https://rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=13643)
  - SEBI CSCRF and Market SOC. — [Taxmann](https://www.taxmann.com/post/blog/sebi-extends-cscrf-deadline-for-regulated-entities)
  - DPDP Rules 2025, Rule 7 (72h). — [iPleaders](https://blog.ipleaders.in/dpdp-rules-2025-operational-compliance-guide-for-indian-businesses/)
- **NCIIPC CII sectors** to use as the criticality taxonomy: Power & Energy, BFSI, Telecom, Transport, Government, Strategic & Public Enterprises. — [Wikipedia](https://en.wikipedia.org/wiki/National_Critical_Information_Infrastructure_Protection_Centre)
- **OT standards C-DAC works with:** IEC 60870-5-101/104 and IEC 62351. — [C-DAC achievements](https://www.cdac.in/index.aspx?id=print_page&print=achieve_cyber_security_forensic)
- **Indian-language capability:** C-DAC GIST Go-Translate, and the BHASHINI ecosystem with 22 languages. — [C-DAC GIST](https://cdac.in/index.aspx?id=gist); [APAC News](https://apacnewsnetwork.com/2025/08/quick-heal-bhashini-collaborate-to-offer-cybersecurity-and-privacy-awareness-in-22-indian-languages/amp)
- **AI precedents regulators already accept:** CERT-In's AI DNS and phishing system (9,800 billion queries), RBIH's MuleHunter.AI, and I4C's Suspect Registry. — [PIB](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf); [Business Standard](https://www.business-standard.com/finance/news/rbi-innovation-hub-develops-mulehunter-ai-to-combat-mule-account-frauds-124120601042_1.html); [MediaNama](https://www.medianama.com/2024/09/223-india-launches-central-cybercrime-registry-to-strengthen-fraud-prevention-and-national-cybersecurity/)

### Inferences (design patterns and pitch guidance)

**What would resonate with C-DAC and Indian government judges**
1. **Mirror the CTMS architecture on the architecture slide:** Sources (CERT-In-style advisories, public CVE/KEV feeds, simulated honeypot or CSK-style logs) → Collector → Enrichment (CVE, product, ATT&CK) → AI correlation and scoring → Early-warning alerts → CTI dissemination (STIX-like JSON / REST API) → Dashboard. Say plainly: "the CTMS/C-ADAR pattern, with an AI correlation layer".
2. **Explainable scoring, not a black box.** Use an additive or weighted score whose factor breakdown appears on each alert. Suggested factors:
   - CVSS;
   - known-exploited flag or exploit-prediction probability (KEV/EPSS-style);
   - internet exposure;
   - NCIIPC sector criticality;
   - asset business criticality;
   - active threat-actor or campaign relevance to India or the sector;
   - time left on the CERT-In blueprint patch deadline.

   Map the result to bands (Critical/High/Medium/Low, matching CIVN-style severity). Government judges will ask "why is this critical?", so show the reasons.
3. **The AI's role should be clear and bounded.** Embeddings or LLM extraction parse unstructured advisory text into structured fields (products, versions, CVEs, TTPs, mitigations). Fuzzy matching links those fields to inventory entries, which inventories often name inconsistently. An LLM can draft the mitigation playbook and the CERT-In incident-report fields. Deterministic rules then decide severity, which keeps the result auditable. This answers the "explain the AI model" deliverable.
4. **Show a regulatory-clock workflow in the mitigation panel:**
   - CERT-In 6h report draft (with Directions incident-type picklist);
   - RBI DAKSH 6h, for bank assets;
   - DPDP 72h, when the asset holds personal data;
   - blueprint patch deadline: 12h KEV internet-facing, 1d critical, 3d, 5d;
   - SEBI M-SOC routing, for market entities.

   No Indian vendor surveyed shows this India-specific compliance overlay.
5. **Route by sector, CSIRT and supply chain.** Alerts should fan out to the right sectoral CSIRT (CSIRT-Fin, CSIRT-Power) and, through a dependency graph, to every entity sharing a vulnerable vendor. Use C-Edge 2024 as the motivating story: one vendor and about 300 banks.
6. **Multilingual alert summaries** (English plus Hindi and Marathi for a Mumbai audience) aimed at MSMEs and cooperative banks. Tie this to C-DAC GIST and Bhashini, and to the 98% CSK citizen reach that already depends on notifying users.
7. **An OT/CII scenario fits C-DAC expertise.** Correlate an ICS advisory (for example an RTU or SCADA product, IEC 60870-5-104) with a simulated state-utility substation inventory. Show CSIRT-Power routing and the CTMS-style OT asset tool.
8. **Name the AI-threat layer of 2026.** Add an "AI asset inventory / AIBOM" tab, or flag exposed AI infrastructure (MCP servers, model endpoints), echoing CERT-In's April and May 2026 frontier-AI guidance and CloudSEK's AIVigil category.

**Gaps in India's current systems that a prototype can credibly address, with the evidence for each**
- **Sector-agnostic guidance.** The prototype can tailor advisories by sector and regulator. — [MediaNama critique](https://www.medianama.com/2026/05/223-cert-in-releases-blueprint-for-defending-against-ai-assisted-cyber-threats/)
- **Mapping advisories to assets.** CERT-In issues about 1,530 alerts and 390 vulnerability notes a year as human-readable pages, which entities must triage by hand. AI parsing plus asset matching cuts the time to exposure. — [PIB](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf)
- **Supply-chain concentration blind spot.** Fan out alerts across dependency graphs (C-Edge).
- **Explainability and trust.** Vendors publish no scoring methodology. A transparent, auditable score suits government use.
- **Language.** Awareness and alerts are mostly in English. Multilingual alerts are a differentiator.
- **Attribution and campaign clustering** (ORF's gap). The prototype can cluster IoCs and alerts into "campaigns", for example a simulated Sindoor-style DDoS and defacement wave. It must be clearly labelled as analyst-assist, not attribution.
- **Several reporting clocks.** Unified tracking of the CERT-In, RBI, DPDP and SEBI clocks.

**Safety and credibility guardrails** (these are also hackathon rules)
- Use only passive public feeds and simulated data.
- Defang IoCs on screen.
- Minimise and redact personal data (DPDP).
- Run no active scanning.
- Present the tool as **decision support for CERT-In, sectoral CSIRTs, NCIIPC and SOCs**, not as a replacement.

### Gaps
- The judging criteria and the specific C-DAC centre or staff on the panel are unknown, so emphasis (OT versus BFSI versus citizen) is a guess. CTMS and C-ADAR are from C-DAC Mohali. ISEA and M-Kavach are from C-DAC Hyderabad.
- It is unknown whether CERT-In publishes a machine-readable advisory or CIVN feed (RSS, JSON, STIX). A prototype should cache sample advisory text offline instead of depending on live access to cert-in.org.in.
- The exact CIVN field structure and severity scale should be checked against a live CERT-In vulnerability note before the field names are shown as "CERT-In-compatible".
