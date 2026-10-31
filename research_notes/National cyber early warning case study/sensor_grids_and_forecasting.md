# Internet-Scale Sensor Networks, Honeypot/Decoy Grids and Cyber-Attack Forecasting as Early Warning (as of 31 Oct 2026)

Scope note: These notes cover scanning telemetry, honeypots and darknets, exposure scanning, forecasting research, beaconing detection and national deception programmes, and how each gives *early* warning. Facts are dated where older than 2026. Several headline numbers are vendor-published (GreyNoise, Censys, VulnCheck). I found no independent replication of the GreyNoise "spike precedes CVE" result. The final section turns the findings into design patterns and a simulated-data spec for the D3COY PS01 24-hour prototype.

---

## 1. GreyNoise: tagging mass scanning to CVEs, "early warning" spike research, classification, AI features

### Takeaway
GreyNoise runs a few thousand deception sensors and writes packet-content signatures ("tags") that map scanner and exploit traffic to specific CVEs. It classifies each source IP as benign, malicious, suspicious or unknown. Two in-house studies, from 2025 and April 2026, report that traffic surges against an edge-device vendor often come before a new CVE for that vendor. The 2025 study found 80% of 216 spikes were followed by a CVE within 6 weeks. The 2026 study found a median lead of 11 days. Both are correlational, vendor-run, and do not fully disclose their methods.

### Cited Findings
**Sensor grid scale (figures conflict by date and source)**
- GreyNoise's second annual retrospective press release cited "more than 3,100 sensors across over 200 countries" — [GreyNoise press](https://www.greynoise.io/press/greynoise-intelligence-publishes-second-annual-retrospective-to-help-international-cybersecurity-community-defend-against-internet-exploitation)
- The Feb 2025 release of the 2025 Mass Internet Exploitation Report described "nearly 4,000 sensors in over 200 countries" — [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/greynoise-intelligence-releases-new-research-on-cybersecurity-vulns)
- Launch coverage of the Global Observation Grid (GOG), which existed by Apr 2025, reported **5,000 sensors in 80 countries processing ~half a billion sessions/day** — [CIO Influence](https://cioinfluence.com/security/greynoise-intelligence-launches-global-observation-grid-to-provide-real-time-threat-intelligence-on-network-attacks/). An Apr 29, 2025 GreyNoise release lists the GOG launch among its achievements of the prior 24 months — [GreyNoise press](https://www.greynoise.io/press/cyber-defense-magazines-global-infosec-awards-2025-best-deception-based-security-vulnerability-intelligence-solution). The 200-country and 80-country figures do not reconcile, and no source explains the gap.
- GreyNoise describes the GOG (2026) as "a network of sensors that draws attacker scanning and exploitation onto infrastructure we control" — [GreyNoise blog, Sep 2026](https://www.greynoise.io/blog/ai-orchestrated-campaign-against-papercut-ng-mf)
- Scale in 2024: the GreyNoise "Today" view listed **348,125 IPs seen in the last day**, and 283,765 machines shared characteristics over the past 24 h — [Anatomy of a GreyNoise Tag, Mar 4 2024](https://www.greynoise.io/blog/anatomy-of-a-greynoise-tag)

**How tags map traffic to CVEs (2024 description)**
- Malicious and activity tags are built mainly from packet contents (pcap data field). Benign actor tags come from published IP lists or, failing that, rDNS, ASN and User-Agent — [Anatomy of a GreyNoise Tag](https://www.greynoise.io/blog/anatomy-of-a-greynoise-tag)
- Worked example, CVE-2018-9995. Analysts (1) isolate distinctive features of the captured packet (HTTP GET `/device.rsp` with `opt=user&cmd=list` and `Cookie: uid=admin`); (2) match them to the NVD description; (3) write a query over internal packet data; (4) tune it to catch variants such as capitalisation and parameter order without false positives; (5) attach a description and references — [Anatomy of a GreyNoise Tag](https://www.greynoise.io/blog/anatomy-of-a-greynoise-tag)
- Tag metadata includes **Intent** (Unknown / Malicious / Benign) and **Category** (Activity / Tool / Actor / Worm / Search Engine). Tags can carry CVE references and a recommended-block flag — [GreyNoise docs: classifications](https://docs.greynoise.io/docs/understanding-greynoise-classifications); [GreyNoise docs: Intelligence Module](https://docs.greynoise.io/docs/intelligence-module-investigate)

**IP classification logic**
- IPs are classified **benign, malicious, suspicious or unknown**. "Malicious" means not benign and carrying at least one malicious tag. "Suspicious" sits between malicious and benign. "Unknown" is scanning that meets none of the other criteria. A benign label overrides malicious tags, and GreyNoise audits benign actors and revokes the label if their intent changes — [GreyNoise docs](https://docs.greynoise.io/docs/understanding-greynoise-classifications)

**Early-warning research, 2025: "Early Warning Signals" (published Jul 31, 2025)**
- **216 spikes** in malicious activity seen by the GOG since Sep 2024. **80% were followed by a new CVE within 6 weeks, and 50% within 3 weeks.** The pattern was reported for enterprise edge technology such as VPNs, firewalls and remote access. Activity types were scanning, brute forcing and exploit attempts. The public page gives no thresholds or spike definition, and the full report is gated — [GreyNoise blog](https://www.greynoise.io/blog/greynoise-uncovers-early-warning-signals-emerging-vulnerabilities); [product page](https://www.greynoise.io/products/early-warning-cve-disclosure)

**Early-warning research, 2026: "Ten Days Before Zero" (Apr 20, 2026)**
- Dataset: **103 days, 147.8 M sessions, 276 vendor-specific tags, 18 network-infrastructure vendors**, covering roughly Dec 2025 to Mar 2026 — [GreyNoise blog](https://www.greynoise.io/blog/the-internet-changes-before-the-advisory-drops); [PRWeb release](https://www.prweb.com/releases/greynoise-intelligence-releases-new-report-outlining-how-cyber-threat-activity-precedes-vulnerability-disclosure-302746464.html)
- **104 surge events.** 68 preceded a vendor-matched CVE (my arithmetic: ~65%), covering 33 vulnerabilities across 16 vendor families. **Median lead time was 11 days.** 49% of surges came within 10 days of disclosure and 78% within 21 days — [GreyNoise blog](https://www.greynoise.io/blog/the-internet-changes-before-the-advisory-drops). The press release words this as "over half" followed by a vendor-matched CVE within 3 weeks — [PRWeb](https://www.prweb.com/releases/greynoise-intelligence-releases-new-report-outlining-how-cyber-threat-activity-precedes-vulnerability-disclosure-302746464.html). These two framings are not obviously identical.
- Signal characteristics: **session volume is the primary signal and IP count alone is weaker.** A simultaneous spike in sessions and IPs is the "highest confidence" warning, with lead time up to 21 days. **Distributed surges averaged 21.3 days of lead and concentrated-hosting surges 7.5 days.** **11 ASNs appeared across 3 or more vendor families** — [GreyNoise blog](https://www.greynoise.io/blog/the-internet-changes-before-the-advisory-drops)
- Cases: **Cisco CVE-2026-20127** (CVSS 10.0, zero-day, subject of a Five Eyes warning) had 8 surges, the earliest 39 days before disclosure. **SonicWall CVE-2026-0400** had 6 surges, with lead compressing from 37 to 3 days and **peak volume at 69x median**. **Fortinet CVE-2026-24858** (CVSS 9.4) gave about 1 day of warning — [GreyNoise blog](https://www.greynoise.io/blog/the-internet-changes-before-the-advisory-drops). A follow-up post flagged a new SonicWall spike that echoes the CVE-2026-0400 pattern and calls it a precedent, not a rule — [GreyNoise blog](https://www.greynoise.io/blog/sonicwall-scanning-spike-echoes-pattern-preceded-cve-2026-0400)
- GreyNoise says "statistical testing confirmed the pattern is not coincidence" but does not publish thresholds, baselines or test details — [GreyNoise blog](https://www.greynoise.io/blog/the-internet-changes-before-the-advisory-drops)

**Productised spike detection (Event Feeds, Feb 3, 2026)**
- **Vendor CVE Spike** feed: the user names a vendor. Tags matching that name by wildcard are mapped to their CVEs, and the feed alerts "only when exploitation activity across a vendor meaningfully increases" past a user-set threshold. Example payload fields: `vendor`, `event_type`, `old_state{benign_ip_count_1d, threat_ip_count_1d}`, `new_state{...}`, `timestamp`. Delivery is by webhook to SIEM or SOAR — [GreyNoise blog](https://www.greynoise.io/blog/introducing-vendor-cve-and-tag-spike)
- **Tag Spike** feed: watches for "significant changes in IP counts" per tag over a **rolling 2-hour window**, against a user-set percentage-increase threshold — [GreyNoise blog](https://www.greynoise.io/blog/introducing-vendor-cve-and-tag-spike)

**Exploitation-timing context from GreyNoise reports**
- 2025 Mass Internet Exploitation Report, covering 2024: **40% of exploited CVEs were 4+ years old** — [GreyNoise on X](https://x.com/GreyNoiseIO/status/1895111653085073612). Ransomware groups used **28%** of the KEV-listed vulnerabilities GreyNoise tracks. **Median time from disclosure to mass exploitation for edge KEVs was 0 days, against 5 days for all KEVs** — [GreyNoise Research](https://www.greynoise.io/category/greynoise-research)
- 2026 State of the Edge report: "more than half of remote code execution attempts originate from previously unseen IPs" — [GreyNoise press](https://www.greynoise.io/press/greynoise-releases-2026-state-of-the-edge-report)

**AI features and AI-era observations**
- **MCP server (Sep 18, 2025):** lets AI agents query IP reputation and actively exploited vulnerabilities in real time. It exposes classification, CVE tags, first and last seen, ASN and sensor hit counts — [GreyNoise press](https://www.greynoise.io/press/greynoise-intelligence-launches-model-context-protocol-mcp-server-power-future-of-agentic-soc); [Help Net Security](https://www.helpnetsecurity.com/2025/09/18/greynoise-mcp-server/); [GreyNoise blog](https://www.greynoise.io/blog/greynoise-intel-available-through-mcp). It can be paired with **GreyNoise Block** for automated dynamic IP blocking — [GreyNoise Block](https://www.greynoise.io/products/greynoise-block)
- GreyNoise has also deployed **MCP honeypots** that emulate AI-agent tool servers — [GreyNoise blog](https://www.greynoise.io/blog/deploying-mcp-honeypots). I saw the title only and did not read the findings.
- **AI-orchestrated campaign against PaperCut NG/MF (published Sep 9, 2026).** The vendor advisory came out Aug 27, 2026. An actor using "hundreds of AI agents" (Codex harness plus a DeepSeek model) got first RCE about 4 hours after workspace setup on Aug 31. On Sep 1 it compromised 11 organisations in 26 seconds and 78 in the first hour. In total it hit **at least 440 instances at 395 organisations in 48 countries**, with 12 reaching Domain Admin, the fastest in 5 minutes. CVEs involved: CVE-2026-81578 (auth bypass), CVE-2026-82078 (RCE), plus noPac CVE-2021-42278/42287 — [GreyNoise blog](https://www.greynoise.io/blog/ai-orchestrated-campaign-against-papercut-ng-mf)

### Inferences
- Implied per-sensor load: ~500 M sessions/day ÷ 5,000 sensors ≈ 100k sessions per sensor per day (≈1.2/s). This is my arithmetic. Sessions may be counted per IP rather than per sensor box, so treat it as an order of magnitude only.
- Implied surge rates: the 2025 study found about 216 spikes over roughly 10 months (~20/month). The 2026 study found 104 surges in 103 days (~1/day across 18 vendors). A national grid focused on edge vendors could therefore expect roughly one candidate surge per day, of which about two-thirds might end in a vendor CVE.
- Detection features GreyNoise points to: (a) session-volume surge, (b) unique-IP surge, (c) both together, (d) distributed versus concentrated hosting (concentrated gives shorter lead), (e) cross-vendor ASN overlap, (f) multiple waves with shrinking gaps (SonicWall: 37 → 25 → 10 → 3 days), (g) novelty of source IPs. A prototype can compute all of these cheaply.
- The PaperCut case shows that post-disclosure windows can now be hours. Pre-disclosure surge detection plus inventory matching is where an early-warning engine adds value.

### Gaps
- Exact spike definitions are unpublished in both GreyNoise reports: baseline window, z-score or multiple-of-median thresholds, the statistical test, and the chance base rate. Search snippets of press coverage ([SC World](https://www.scworld.com/news/greynoise-finds-attacker-activity-surges-before-vulnerability-disclosures), [Channel Dive](https://www.channeldive.com/news/vulnerability-disclosure-surges-warnings-greynoise/818011/)) mention "36% more than chance" and an activity breakdown of 42 scanning, 18 brute-force and 12 RCE spikes. I could not confirm these on the primary pages, so they are unverified.
- Total number of active tags and the median time from CVE publication to a new tag: not found.
- The sensor count and country count conflict (3,100/200+, ~4,000/200+, 5,000/80).
- No independent academic replication of "scanning precedes disclosure" was found.

---

## 2. Other sensor grids and exposure scanning: Shadowserver, SANS ISC/DShield, Honeynet Project, T-Pot, NICT NICTER, CAIDA telescope, Censys/Shodan, and how CERTs notify owners

### Takeaway
National-scale early warning in practice combines three data types. (1) **Darknets and telescopes** (NICTER ~280k IPs, CAIDA /9+/10) show *who is scanning what*. (2) **Honeypot grids** (Shadowserver, DShield, T-Pot, GreyNoise) capture *payloads that can be tied to CVEs*. (3) **Internet-wide exposure scans** (Shadowserver, Censys, Shodan) show *who is vulnerable*. CERTs join (2)+(3) to send daily per-constituency notifications. The measured outcome of this pipeline is partial remediation: CISA saw 38 of 67 notified owners mitigate, and a large share of exposed assets cannot be attributed to an owner at all.

### Cited Findings
**Shadowserver Foundation**
- Sources: daily Internet-wide scans, sinkholes, **honeypot sensors**, sandboxes and blocklists. Free reports go to **10,000+ vetted subscribers, including 135 national governments (201 national CSIRTs) covering 175 countries and territories** — [Shadowserver Network Reporting](https://www.shadowserver.org/what-we-do/network-reporting/)
- 2025 year in review: 201 nCSIRTs in 175 countries. Subscribers cover **~70% of North American, 67% of European and 57% of global IPv4 space by ASN**. The foundation has 22 staff and ~USD 6 M/yr operating cost. Victim notifications reach "millions of victims per day" — [Shadowserver 2025 review](https://www.shadowserver.org/news/shadowserver-2025-highlights-of-the-year-in-review/)
- Honeypot attack data is "reported out daily to nCSIRTs and subscribing network owners" via the Honeypot HTTP Scanner Events report. Sensor-observed exploitation feeds a daily **Top Exploited Vulnerability** list on the public dashboard, which can be filtered by country and is funded by UK FCDO — [Shadowserver 2025 review](https://www.shadowserver.org/news/shadowserver-2025-highlights-of-the-year-in-review/); [Dashboard enhancements](https://www.shadowserver.org/news/new-dashboard-attack-statistics-enhancements/)
- Honeypot report families include HTTP scanner, RDP, SMB, SNMP, IKEv2, brute force and ICS scanner events. A 2022 deck cited **over 1,500 honeypot instances** — [Shadowserver HTTP Scanner report PDF, Apr 2022](https://www.shadowserver.org/wp-content/uploads/2022/06/Honeypot_HTTP_Scanner_Events_Report_April_2022.pdf); [Shadowserver Mastodon](https://infosec.exchange/@shadowserver/111720367302375626)
- The **Honeypot Brute Force Events** report (default severity CRITICAL) has a 38-field schema: `timestamp, protocol, src_ip, src_port, src_asn, src_geo, src_region, src_city, src_hostname, src_naics, src_sector, device_vendor, device_type, device_model, severity, dst_ip, dst_port, dst_asn, dst_geo, dst_region, dst_city, dst_hostname, dst_naics, dst_sector, public_source, infection, family, tag, application, version, event_id, service, start_time, end_time, client_version, username, password, payload_url, payload_md5` — [Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/honeypot-brute-force-events-report/)
- 2025 exposure-scan examples of the speed of early warning:
  - **Ivanti CVE-2025-0282**: 2,048 likely vulnerable instances reported on 2025-01-09.
  - **SharePoint CVE-2025-53770**: ~9,300 exposed IPs, rising to ~17,000 vulnerable.
  - **React2Shell CVE-2025-55182**: 77,664 likely vulnerable IPs on 2025-12-05, rising to **>165,000 IPs and 644,000 domains three days later**.
  - **WatchGuard CVE-2025-14733**: 125,000 vulnerable.
  - **BADBOX 2.0/Vo1d**: up to 8 M infected IPs/day at peak.
  - Source for all of the above: [Shadowserver 2025 review](https://www.shadowserver.org/news/shadowserver-2025-highlights-of-the-year-in-review/)
- Capacity building: "Shadowserver-in-a-box" is a training system built on **IntelMQ + Elasticsearch + Kibana**, alongside a CCB toolkit for ingestion, analysis and alerting — [Shadowserver 2025 review](https://www.shadowserver.org/news/shadowserver-2025-highlights-of-the-year-in-review/)

**SANS Internet Storm Center / DShield**
- DShield was started by Johannes Ullrich in **2000** to collect home-user firewall logs and later added web, SSH (Cowrie) and other honeypot logs. Public feeds include daily source-IP summaries, Top 10 ports and a 30-day SSH username feed. Attribution is required and resale is not allowed — [ISC feeds doc](https://isc.sans.edu/feeds_doc.html); [DShield sensor how-to](https://isc.sans.edu/howto.html)
- The distributed sensors contribute "tens of millions of firewall and IDS records each day" — [hack.lu 2025 talk abstract](https://pretalx.com/hack-lu-2025/talk/C9ZDAR/)
- **Heavy-hitter noise (ISC diary 32100, 2025-07-14).** A single honeypot produced **~58 GB of web logs in one day**, beating a prior record of ~35 GB. Several honeypots exceeded 20 GB/day. One /24 (**6 unique IPs**) produced ~**20.08 billion** hits, and the path `/__api__/v1/config/domains` alone drew 33.2 billion. The analyst filtered out sources above **1,000,000 logs/day** to expose the baseline trend — [ISC diary 32100](https://isc.sans.edu/diary/32100). The diary title on the URL slug differs from the page content, but ISC diaries resolve by ID.

**Honeynet Project and T-Pot**
- The Honeynet Project's **HPFeeds** is a pub/sub protocol linking honeypots, botnet monitors and sandboxes (described from 2009). The project says data sharing is "one of the main ideas of Honeynet Project" but is limited by sensitive content in logs, which motivated anonymisation work — [Honeynet R&D overview 2012](https://www.tud.ttu.ee/im/Toomas.Lepik/Oldthings/MalwareOld/20120618_Honeynet_Project_David_Watson_RandD_Overview.pdf); [GSoC 2010 archive](https://google-melange.com/archive/gsoc/2010/orgs/honeynet)
- **T-Pot (Deutsche Telekom)** grew out of Telekom's honeypot project, which started in **2010** with Glastopf and added kippo, honeytrap and dionaea. It is now a Docker-based multi-honeypot platform (20+ honeypots, counts vary by version) on an Elastic stack with live attack maps. It feeds Telekom's community dashboard **Sicherheitstacho**. Version **24.04** moved from an ISO image to multi-distribution installs — [Telekom T-Pot concept 2015](https://github.security.telekom.com/2015/03/honeypot-tpot-concept.html); [T-Pot 24.04 release](https://github.security.telekom.com/2024/04/honeypot-tpot-24.04-released.html); [Telekom honeypot page](https://github.security.telekom.com/honeypot.html)

**Japan NICT NICTER (national darknet) and NOTICE**
- **NICTER Observation Report 2025 (released Feb 5, 2026):**
  - Darknet of **~280,000 IPs**.
  - **~701 billion packets in 2025**, a record since observation began in 2005 and +2.2% year on year.
  - **~2.5 M packets per IP per year**, up ~70k from 2024. The 2024 figure was ~2.42 M.
  - **~55%** of packets were research-type scans, down from ~60% in 2024.
  - Telnet/23 is declining. 80/TCP ranks 3rd and 443/TCP 5th.
  - **DRDoS: ~82.85 M attacks worldwide** (Japan ~900k) in 2025, against 30.95 M (Japan ~170k) in 2024.
  - **RapperBot** had ~60,000 infected IoT devices. Its C2 traffic stopped after the US DOJ charges in Aug 2025.
  - Sources: [NICT press release (JP)](https://www.nict.go.jp/press/2026/02/05-1.html); [NICTER Reports](https://csl.nict.go.jp/en/nicter-report.html); [NICT 2024 press](https://www.nict.go.jp/press/2025/02/13-1.html)
- NICTER is described as a composite system that correlates darknet observation with malware collection. It is housed under CYNEX, launched Apr 1, 2021 — [NICT press release](https://www.nict.go.jp/press/2026/02/05-1.html)
- **NOTICE** (started Feb 20, 2019) is run by MIC and NICT with ISPs. NICT surveys IoT devices with easily guessed credentials and gives the IP information to ISPs, which contact users. As of Dec 2025 it had **110 participating organisations (96 ISPs, 10 IoT makers, 2 SIers, 2 others)**. It became a formal NICT task from FY2024 — [MIC press 2020](https://www.soumu.go.jp/main_sosiki/joho_tsusin/eng/pressrelease/2020/1/28_2.html); [NICT Cyber 2025 slides](https://www2.nict.go.jp/csri/nict_cyber2025/Presentation%20materials_masashi-eto.pdf); [MIC document](https://www.soumu.go.jp/main_content/001016609.pdf)

**CAIDA / UCSD Network Telescope**
- The telescope monitors a **/9 and /10** (about 1/256 of IPv4) and collects **>3 TB of uncompressed traces per day** — [CAIDA near-real-time dataset](https://www.caida.org/catalog/datasets/telescope-near-real-time_dataset/). A 2023 course deck cites an archive of ~5 PB growing ~4 TB/day — [CAIDA slides](https://www.caida.org/catalog/media/2023_traffic_data_cse291e/traffic_data_cse291e.pdf). In Jan 2017 it captured >1 TB compressed per day — [CAIDA STARDUST proposal](https://www.caida.org/funding/stardust/stardust_proposal/)
- A dedicated "Patch Tuesday" dataset exists for studying scanning around disclosure days — [CAIDA Patch Tuesday dataset](https://www.caida.org/catalog/datasets/telescope-patch-tuesday_dataset/)

**Exposure data (Censys/Shodan) and CERT owner notification: workflow and outcomes**
- CERT.at describes proactively informing Austrian network operators using automated feeds plus urgent researcher reports — [CERT.at blog, Jun 2024](https://www.cert.at/en/blog/2024/6/how-we-cover-your-back)
- **2011 precedent:** after researchers used Shodan to find exposed control systems, ICS-CERT worked with ~**63 other CERTs** to notify owners — [CISA ICS-ALERT-11-343-01A](https://www.cisa.gov/news-events/ics-alerts/ics-alert-11-343-01a)
- **CISA 2021 administrative subpoenas:** CISA notified all **67** identifiable owners of vulnerable devices. Follow-up Shodan scans showed **38 of 67** had mitigated all devices. CISA cautions that disappearance from Shodan does not prove remediation — [CISA CY2021 subpoena factsheet](https://www.Cisa.Gov/sites/default/files/2023-01/CY2021_Admin_Subpoena_Summary_Factsheet_FINAL.pdf)
- **Censys 2026:** about **70% of ~134,000 Internet-exposed ICS hosts** sit on consumer or mobile networks, so owners often cannot be identified. Censys calls this the "notification gap" — [Censys 2026 State of the Internet](https://censys.com/?p=11187); [SecurityWeek 2024](https://www.securityweek.com/over-40000-internet-exposed-ics-devices-found-in-us-censys/)
- **CISA Pre-Ransomware Notification Initiative (PRNI)**, an early-warning outcome metric: **>1,200 notifications in 2023** and **2,131 by Nov 2024**. The program's former lead cited **>4,300 total since late 2022, ~USD 9 B in estimated averted damage, and warnings to at least 60 foreign governments** — [Cybersecurity Dive](https://www.cybersecuritydive.com/news/cisa-pre-ransomware-alerts/705046); [risky.biz](https://www.risky.biz/risky-bulletin-cisa-sent-2-100-pre-ransomware-alerts-this-year); [SANS blog](https://www.sans.org/blog/cisas-pre-ransomware-notification-and-you); [Utility Dive on lead's departure](https://www.utilitydive.com/news/cisa-loses-key-employee-behind-early-ransomware-warnings/808738/)
- Academic baseline: Li, Durumeric et al., "You've Got Vulnerability: Exploring Effective Vulnerability Notifications," USENIX Security 2016 — [Li et al. ;login: 2018 summary](https://www.usenix.org/publications/login/spring2018/li). A 2017 IETF MAPRG deck citing this work says publicity campaigns drew operator responses but no significant patching, and that IoT patch rates are low — [IETF MAPRG slides](https://datatracker.ietf.org/meeting/98/materials/slides-98-maprg-weak-keys-remain-widespread-in-network-devices-marcella-hastings-00.pdf)

### Inferences
- NICTER implies a per-darknet-IP background rate of ~2.5 M/365 ≈ **~6,850 packets/IP/day ≈ ~285/hour ≈ ~4.75/minute**. Across the whole darknet that is ~1.9 B packets/day (~22k pps). This is a good calibration for simulated background noise, with ~55% of it labelled "benign research scanner."
- The ISC diary shows that raw volume is dominated by a handful of IPs (6 IPs producing ~20 B hits). Spike detectors should count **unique sources and sessions, with per-source caps**, rather than raw events, or a single noisy scanner will dominate. GreyNoise's finding that sessions plus IPs together is the strongest signal is consistent with this.
- The React2Shell numbers (77k → 165k vulnerable IPs in 3 days) show that exposure is itself a time series. An early-warning engine should re-score exposure daily.
- The Shadowserver report schema (src/dst geo/ASN/sector, tag, CVE-like `tag`, `family`, `infection`, `service`) is a ready template for a national grid's event format. Including `dst_sector` and `dst_naics` is what allows sector-level national alerts.
- Notification outcomes (38/67 mitigated, and the 70% ICS attribution gap) argue for designing the prototype's mitigation workflow around the **owner-attribution step** (asset inventory → owner → sector CERT), not just detection.

### Gaps
- Current Shadowserver honeypot sensor count: only the 2022 figure (>1,500 instances) was found. The 2025 review says "thousands."
- DShield's current sensor count and authoritative reports-per-day: not found.
- NICTER's per-port percentages and NOTICE's 2025 notification counts: not retrieved, as they sit in Japanese PDFs.
- Li et al. 2016 exact patch-rate deltas: not retrieved.
- A Sicherheitstacho live URL and current T-Pot honeypot list: not confirmed.

---

## 3. Forecasting research: IARPA CAUSE, social media / dark web / exploit-repository signals, and measured lead times

### Takeaway
IARPA CAUSE (around 2015–2019) funded attack forecasting from "unconventional" signals such as social media, dark-web markets and news. The public record holds prototypes (e.g., USC ISI's EFFECT) and "preliminary" positive results, but no published final accuracy or lead-time evaluation. The most robust quantified forecasting results come from academic and community work:
- Liu et al. 2015 forecast breaches from external mismanagement and scanning signals at 90% TPR / 10% FPR.
- EPSS gives 30-day exploitation probability.
- Twitter-based exploit prediction (Sabottke 2015) did not beat a text baseline in a later replication.

Measured lead times have collapsed. Mandiant estimates mean time-to-exploit at −7 days for 2025, and VulnCheck found ~29% of newly exploited CVEs exploited on or before publication day. *Pre-disclosure* sensor signals therefore matter more than post-disclosure ones.

### Cited Findings
**IARPA CAUSE**
- CAUSE aimed to develop automated methods to forecast cyberattacks and detect emerging cyber phenomena, targeting detection "hours to weeks earlier" than current methods — [FCW 2014](https://fcw.com/blogs/the-spec/2014/12/spec-iarpa-cyber-proactive.aspx); [Nextgov 2015](https://www.nextgov.com/cybersecurity/2015/03/peering-into-the-cyber-future/207528/); [Military & Aerospace Electronics](https://www.militaryaerospace.com/computers/article/16713868/intelligence-researchers-get-ready-for-cause-cyber-security-program-to-forecast-cyber-attacks)
- Reported performers: BAE Systems, Charles River Analytics, Leidos and USC. Ground truth was attack data from cooperating companies — [BAE Systems](https://www.baesystems.com/en-us/article/developing-cyber-attack-prediction-capability-for-iarpa); [C4ISRNET 2015](https://www.c4isrnet.com/it-networks/2015/09/23/iarpa-s-high-stakes-intelligence-experiment/)
- USC ISI built **EFFECT**, an end-to-end forecasting prototype. Goyal et al. (arXiv 2018) used hacker forums, social media and blogs on the surface and dark web, with deep neural nets and autoregressive time-series models. They report a "significant lift" in F1 from top external signals but give no figures in the abstract — [arXiv 1806.03342](https://arxiv.org/abs/1806.03342)
- Related CAUSE-era work on imbalanced data and different time granularities — [Okutan et al., arXiv 1803.09560](https://arxiv.org/pdf/1803.09560)
- A 2017 NATO IST-152 workshop report says CAUSE performers had **preliminary** results that public sentiment, social media trends, news and dark-web transactions can help forecast incidents — [arXiv 1804.07646](https://arxiv.org/pdf/1804.07646)

**Other forecasting results**
- **Liu et al., "Cloudy with a Chance of Breach," USENIX Security 2015.** A Random Forest on externally observable features (DNS/BGP mismanagement plus time series of spam, phishing and *scanning* from the network) was trained and tested on >1,000 incident reports from 2013–14. It reached **90% TP, 10% FP, 90% accuracy**. Slides report 92% of breaches predicted at threshold 0.85, and note that mismanagement alone is a weak predictor but adds most value combined with malicious-activity features — [USENIX](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/liu); [paper PDF](https://web.eecs.umich.edu/~mingyan/pub/usenix15.pdf); [NANOG slides](https://archive.nanog.org/sites/default/files/wednesday_general_karir_cloudy-breach.pdf)
- **Sabottke, Suciu, Dumitraș, USENIX Security 2015**, a Twitter-based exploit detector — [USENIX](https://www.usenix.org/biblio/vulnerability-disclosure-age-social-media-exploiting-twitter-predicting-real-world-exploits). A 2017 replication found Twitter features gave **no improvement over a baseline** (F1 0.394 with all features against 0.359 for NVD text alone). It also flagged poisoning risk from open social data — [arXiv 1707.08015](https://arxiv.org/pdf/1707.08015)
- **EPSS (FIRST):** a daily probability that a CVE is exploited in the next 30 days. **v4 was released Mar 17, 2025** — [Empirical Security, EPSS v4](https://research.empiricalsecurity.com/research/introducing-epss-version-4); [EPSS paper arXiv 1908.04856](https://arxiv.org/pdf/1908.04856)

**Measured lead and lag times**
- **Mandiant M-Trends 2026:** mean time-to-exploit was **−7 days** in 2025, against −1 in 2024 and 63 days in 2018. It is a population mean, not per-CVE — reported via [Prioriq](https://prioriq.ai/en/blog/time-to-exploit-patch-window), [Jorge Laurel](https://jorgelaurel.com/writing/vulnerability-exploitation-is-moving-faster-what-the-2026-time-to-exploit-data-s/), and the [GreyNoise PRWeb release](https://www.prweb.com/releases/greynoise-intelligence-releases-new-report-outlining-how-cyber-threat-activity-precedes-vulnerability-disclosure-302746464.html). I did not open M-Trends itself.
- **VulnCheck:** of **884** newly exploited CVEs in 2025, **28.96%** were exploited on or before publication day, up from 23.6%. The 1H-2025 figure was 32.1% — [VulnCheck 1H-2025](https://www.vulncheck.com/blog/state-of-exploitation-1h-2025); [GreyNoise blog citing VulnCheck](https://www.greynoise.io/blog/the-internet-changes-before-the-advisory-drops)
- **Google GTIG:** **90 zero-days** exploited in the wild in 2025, about half against enterprise technology — cited in the [GreyNoise PRWeb release](https://www.prweb.com/releases/greynoise-intelligence-releases-new-report-outlining-how-cyber-threat-activity-precedes-vulnerability-disclosure-302746464.html)
- **Amazon MadPot** (honeypot telemetry) saw PHP2Shell exploitation **4 days before public disclosure**, with PoCs appearing within hours of the patch and used against sensors almost immediately — [AWS Security blog](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- **Akamai** honeypots saw exploitation of CVE-2024-4577 (PHP) within 24 hours of disclosure (2024) — [Akamai](https://www.akamai.com/blog/security-research/2024-php-exploit-cve-one-day-after-disclosure)
- **Trustwave SpiderLabs** honeypots saw FortiNAC exploitation 6 days after the public PoC. Mozi, Kinsing and Mirai accounted for 95% of exploit attempts (about 2023) — [SC World](https://www.scworld.com/news/quick-exploit-proof-of-concept-code)
- **Tenable:** median time to active exploitation of 5 days (2024 through Sep 2025) — [Tenable](https://www.tenable.com/blog/cyber-risk-lurks-in-the-vulnerability-disclosure-gaps)
- **GreyNoise:** median lead of a *pre-disclosure* surge is 11 days (Section 1). Median disclosure-to-mass-exploitation for edge KEVs is 0 days.

### Inferences
- The early-warning window now sits mostly *before* the advisory. Practical signals in that window are sensor surges (median ~11 days) and, weakly, chatter and social media. After the advisory, defenders often have hours to days: 0-day median for edge KEVs, ~4 hours from setup to first RCE for the AI-driven PaperCut actor.
- Forecasting models that worked in public evaluations (Liu 2015, EPSS) use **structured, externally observable telemetry**, including scanning activity. Social-media-only signals were fragile. For a 24-hour prototype, sensor-derived time series plus EPSS/KEV priors are more defensible than NLP over chatter.
- Since outcomes are rare and imbalanced (Okutan 2018), evaluation should report precision and recall at fixed lead-time horizons and compare against a chance base rate, as GreyNoise claims to do.

### Gaps
- No official IARPA CAUSE closeout report or final metrics (accuracy, lead time) was found.
- The original Sabottke 2015 precision and recall figures were not retrieved.
- No peer-reviewed, cross-vendor measurement of PoC-publication → mass-exploitation lag was found. Available numbers are vendor telemetry. A 22-minute PoC-to-exploit claim from a vendor blog ([Cyberpeace](https://cyberpeace.org/resources/blogs/rapid-exploitation-of-proof-of-concept-exploits-a-growing-cybersecurity-threat)) is unverified.

---

## 4. Beaconing / C2 detection on network logs (RITA-style periodicity and jitter analysis)

### Takeaway
RITA (Active Countermeasures) scores each source→destination pair from Zeek connection logs. It combines interval and size **Bowley skewness** (symmetry), **median absolute deviation about the median (MADM)** (dispersion) and **connection frequency** into a 0–1 score, where values near 1 suggest beaconing. The method is cheap and fits a prototype. Jitter weakens dispersion tests, and benign periodic services (NTP, updaters) cause false positives.

### Cited Findings
- RITA computes per pair: interval range, size range, interval and size mode (with counts), interval and size **skew** ("closer to 0 = very symmetric") and **dispersion** ("similar to standard deviation… closer to 0 = clustered"). The score combines interval skew, dispersion and duration with size skew, dispersion and mode. "The closer this score is to 1 the more likely… beaconing." The input is Zeek logs generated from pcap — [Active Countermeasures Threat Hunting Labs: Beacons](https://activecm.github.io/threat-hunting-labs/beacons/); [Active CM: Zeek + RITA](https://www.activecountermeasures.com/threat-hunting-over-the-network-with-zeek-and-rita/)
- Jitter: malware that adds random jitter around a mean (e.g., "30 s ± 5 s") still produces *symmetric* interval distributions, so skew remains useful. Dispersion becomes less effective "the more jitter added." Size skew matters less because sizes vary with tasking — [Threat Hunting Labs](https://activecm.github.io/threat-hunting-labs/beacons/)
- Score components as reimplemented in KQL (secondary, derived from RITA's analyzer.go):
  - `tsSkewScore = 1 − |Bowley skew of intervals|`
  - `tsMADMScore = 1 − MADM/30` (0 if MADM > 30 s)
  - `tsConnCountScore = connCount / (duration/10)`, where duration runs from first to last connection
  - interval score = mean of the three
  - data-size score is analogous, with a **32-byte** MADM cut-off
  - final = mean of interval and size scores
  - Source: [Blu Raven: Implementing RITA using KQL](https://book.bluraven.io/threat-hunting-and-detection/command-and-control/implementing-rita-using-kql). A Springer paper also cites RITA's analyzer.go for these scores — [Springer 2024](https://link.springer.com/article/10.1007/s10207-024-00879-z)
- Independent reimplementations probing the limits:
  - [beacon-spectrum](https://github.com/blurxy/beacon-spectrum) applies a Rayleigh phase-coherence test and argues periodicity alone "cannot separate a beacon from NTP."
  - [Zeek-beacon-floor](https://github.com/nilay-dave/Zeek-beacon-floor) measures where detection stops working as a function of the number of observed intervals and the jitter.
- 2026 preprint: "When Agents Look Like Beacons: NIDS Evasion by Model Context Protocol Traffic" — [arXiv 2609.19091](https://arxiv.org/pdf/2609.19091). I saw the title only, so this is a signal that AI-agent traffic now complicates periodicity-based detection.
- Practitioner walkthroughs: [Black Hills InfoSec](https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/); [TryHackMe AoC 2025 Day 22 write-up](https://medium.com/@patelaksht24/advent-of-cyber-2025-day-22-c2-detection-command-carol-893b949e05a8)

### Inferences
- Prototype recipe, about 50 lines of pandas. Group simulated `conn` records by (src, dst, dst_port). Require at least N≈20 connections. Compute inter-arrival deltas, Bowley skew `(Q1+Q3−2Q2)/(Q3−Q1)`, MADM and connection density. Do the same for bytes, then average. Flag scores ≥0.8 and allow-list known periodic services (NTP, update CDNs) to cut false positives.
- Synthetic test cases: a beacon at 60 s ± 10% and another at ± 50% jitter, a benign NTP poller (strictly periodic), an OS updater (hourly), and human browsing (bursty, heavy-tailed). This shows the skew/MADM trade-off honestly.
- This module fits the "post-compromise" leg of a national early-warning story: sensor surge → advisory → exposure → beacon from an exposed asset in simulated enterprise telemetry → escalated alert.

### Gaps
- I did not read RITA v5 source or docs directly. Formula details come from secondary reimplementations, and the thresholds may differ in the current release.
- No published false-positive rates for RITA on real enterprise traffic were found.

---

## 5. Deception technology in national defence (national honeynets: Japan, Israel, India)

### Takeaway
Japan (NICTER plus NOTICE) is the best-documented *national* darknet-to-notification pipeline. India has a C-DAC-built, nationally deployed honeypot network with a central repository, reportedly feeding CERT-In and the NCCC, though primary scope figures are not public. For Israel, I found evidence of national early-warning *alerting* (INCD) but no public evidence of a national honeynet. Shadowserver plays a quasi-national role for 201 nCSIRTs.

### Cited Findings
- **India / C-DAC "Honeynet Technologies":** C-DAC says its honeypots are "deployed across the country for continuous collection of latest attacks proactively." Data flows to a **central honeypot attack data repository**. It offers indigenous **IoT, web and ICS honeypots** and "India-specific cyber threat intelligence sharing with SIEM, SoC" — [C-DAC service page](https://www.cdac.in/index.aspx?id=service_details&serviceId=HoneynetTechnologies)
- **India, nationwide honeypot threat sensors:** news reporting describes a nationwide honeypot sensor network with central collection and analysis, with **CERT-In** using the resulting CTI in support of the **National Cyber Coordination Centre (NCCC)** mandate. This is a single secondary source with no primary MeitY or CERT-In confirmation found — [News Station Network](https://newsstation.media/latest-news/nationwide-deployment-of-honeypot-threat-sensors-unveiled-for-enhanced-cybersecurity/siddharatha/)
- CERT-In is India's national incident response agency and liaises with the NCSC office, NSC and NIB — [Wikipedia: CERT-In](https://en.wikipedia.org/wiki/Indian_Computer_Emergency_Response_Team)
- Indian academic honeynet work includes an IIT Kanpur deployment cited in an MDPI review — [MDPI Informatics 2025](https://www.mdpi.com/2227-9709/12/1/14) — and a multi-platform honeypot for CTI generation — [ResearchGate](https://www.researchgate.net/publication/338948680_Multi_Platform_Honeypot_for_Generation_of_Cyber_Threat_Intelligence)
- **Israel:** the INCD's 2025 annual report records **2,304 targeted alerts** to organisations about attempted attacks, up nearly 350% — [Calcalist](https://www.calcalistech.com/ctechnews/article/u0gajxyo8). The INCD's 2025–2028 strategy plans new real-time sharing and early-warning mechanisms — [BESA Center](https://besacenter.org/analysis-and-recommendations-for-israels-new-national-cyber-strategy/); [US trade.gov](https://www.trade.gov/market-intelligence/israel-cybersecurity-strategy-2025-strategic-gateway-us). A 2020 ETH Zurich report lists "early warning mechanisms" and sectoral centres among INCD functions — [ETH CSS 2020](https://css.ethz.ch/content/dam/ethz/special-interest/gess/cis/center-for-securities-studies/pdfs/Cyber-Reports-2020-09-Israel.pdf)
- **Japan:** NICTER darknet (~280k IPs, since 2005) plus the NOTICE ISP notification programme (110 organisations, 96 ISPs) — see Section 2 for details and sources.

### Inferences
- The pattern common to these national systems has five layers: **distributed sensors → central repository → enrichment (geo, ASN, sector, CVE tags) → constituency filtering → notification through ISPs, CERTs or sector bodies.** This is the architecture the D3COY prototype should mirror. C-DAC itself is the sponsor and operates a national honeypot programme, so framing the prototype as a simulated national honeypot grid of the C-DAC / CERT-In kind fits the brief.
- Israel's public metric is "targeted alerts sent," not sensor counts. A prototype dashboard KPI of alerts issued per sector, with lead time, is a defensible national-level outcome measure.

### Gaps
- No primary source was found for the size, sensor count or launch date of India's national honeypot network, or for CERT-In's honeypot use. Check CERT-In and MeitY annual reports.
- No public evidence was found of an Israeli national honeynet. This may be classified or simply undocumented.

---

## 6. Lessons and design patterns for a 24-hour prototype (simulated national decoy-sensor grid → early-warning engine)

### Takeaway
Build an offline, simulated "national decoy grid" that emits Shadowserver/GreyNoise-style events. The engine should detect **vendor- and tag-level surges** (sessions and unique IPs, robust baselines, a 2-hour rolling window), tag them to CVEs, and correlate them with a simulated asset inventory, EPSS/KEV and exposure. It should score risk and raise alerts with a measured lead time, plus an optional RITA-style beacon detector for the post-compromise leg. Calibrate the noise and bursts to the published magnitudes below. Use only documentation IP and ASN ranges, and touch no real networks.

### Cited Findings (calibration anchors for the simulation)
- Background darknet rate: ~2.5 M packets per IP per year, with ~55% from research scanners — [NICT](https://www.nict.go.jp/press/2026/02/05-1.html)
- Global unique scanners/day: ~348k IPs (2024) — [GreyNoise](https://www.greynoise.io/blog/anatomy-of-a-greynoise-tag)
- Heavy hitters: 6 IPs in one /24 → ~20 B web-honeypot hits. Use a filter at >1 M logs per source per day — [ISC diary 32100](https://isc.sans.edu/diary/32100)
- Burst shape: multiple waves (Cisco had 8 surges, the earliest 39 days before disclosure). Lead compressed from 37 → 25 → 10 → 3 days for SonicWall, with peak 69x median. Median lead was 11 days. Distributed surges led by 21.3 days and concentrated ones by 7.5 days. Sessions are the primary signal, and sessions with IPs together give highest confidence — [GreyNoise](https://www.greynoise.io/blog/the-internet-changes-before-the-advisory-drops)
- Spike alert mechanics: rolling 2-hour window, percentage-increase threshold, payload `old_state` / `new_state` with `benign_ip_count_1d` and `threat_ip_count_1d` — [GreyNoise Event Feeds](https://www.greynoise.io/blog/introducing-vendor-cve-and-tag-spike)
- Novelty: more than half of RCE attempts come from previously unseen IPs — [GreyNoise 2026 State of the Edge](https://www.greynoise.io/press/greynoise-releases-2026-state-of-the-edge-report)
- Post-disclosure exposure growth: 77,664 → >165,000 vulnerable IPs in 3 days (React2Shell) — [Shadowserver](https://www.shadowserver.org/news/shadowserver-2025-highlights-of-the-year-in-review/)
- Event schema template: the Shadowserver 38-field honeypot report — [Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/honeypot-brute-force-events-report/)
- Old CVEs remain in play: 40% of exploited CVEs were 4+ years old — [GreyNoise](https://x.com/GreyNoiseIO/status/1895111653085073612)
- Safe synthetic addressing: IPv4 documentation blocks 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 — [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737). Documentation ASNs 64496–64511 and 65536–65551 — [RFC 5398](https://www.rfc-editor.org/rfc/rfc5398)

### Inferences (design patterns and the simulated-data spec)

**A. Architecture (mirrors Shadowserver, NICTER and C-DAC)**
1. **Sensor layer (simulated).** About 40–80 virtual sensors spread across Indian regions and sectors (power, telecom, BFSI, health, government, education). Each has a **persona**, which is the device type it pretends to be: a Fortinet/SonicWall/Cisco VPN or firewall, Ivanti, an IoT camera, a Telnet/SSH IoT box, an RDP or SMB host, a Modbus/S7 ICS endpoint, a web CMS, or an MCP/AI-agent endpoint.
2. **Ingest.** Events go to an append-only store (SQLite or Parquet), modelled on IntelMQ-style collector → parser → expert bots → output.
3. **Enrichment.** Add geo, ASN and sector (dst), apply tag rules (regex on path, payload or credentials → `tag` → `cve`), and classify intent as benign, malicious, suspicious or unknown using GreyNoise logic: a benign scanner list overrides.
4. **Detection.** Run spike and burst detection per (tag), (vendor) and (dst_sector) on the counts below, plus clustering.
5. **Correlation.** Join an advisory or CVE with the asset inventory (vendor/product/version) and with exposure (whether the asset is internet-facing), plus EPSS and KEV priors.
6. **Scoring and alerting.** Produce a risk level and an alert with lead time, and route it through the mitigation workflow: owner → sector CERT → patch, block or hunt.
7. **Dashboard.** Show a threat map, a surge timeline, a CVE watchlist, sector risk heatmap and the alert queue.

**B. Event fields (synthetic, Shadowserver- and Cowrie-like)**
`event_id, timestamp (UTC ISO8601), sensor_id, sensor_region, sensor_sector, persona (vendor/product), protocol, dst_port, service, src_ip (RFC 5737 ranges only), src_port, src_asn (RFC 5398), src_asn_type (hosting/residential/mobile/research), src_country, session_id, event_type (connect|scan|login_failed|login_success|http_request|exploit_attempt|command|file_download), http_method, http_path, user_agent, username, password, payload_sha256 (fake, defanged), payload_url (defanged hxxp[:]//), bytes_in, bytes_out, duration_ms, tag, cve, intent (benign|malicious|suspicious|unknown), ja4/hassh (optional, synthetic), ground_truth_campaign_id (hidden label for evaluation)`

**C. Background noise model**
- Per-sensor arrivals follow a Poisson process with a diurnal modulation (±20–30%) and a weekly cycle. The base rate should be scaled down from NICTER's ~285 packets/IP/hour to something a laptop can handle, for example 50–200 events per sensor per hour.
- Source mix:
  - About 50–55% **benign research scanners**: a small fixed set of "known scanner" ASNs covering many ports, with regular sweeps every 4–24 h.
  - About 30% **unknown/opportunistic**: Mirai-style Telnet/SSH brute force from residential and mobile ASNs with common credential pairs, plus generic web crawls (`/`, `/.env`, `/wp-login.php`).
  - About 10–15% **malicious tagged**: old CVEs, with about 40% of them dated 4+ years.
- A Zipf/heavy-tailed volume per source, with 1–3 "firehose" IPs that each produce 10–100x the median. This tests per-source caps, following the ISC observation.
- Port weighting: 23 and 22 high (NICTER shows Telnet declining but still prominent), then 80, 443, 445, 3389, 8080, 8443, 502 (Modbus) and 5555.
- Sensor outages and gaps: some sensors go silent for hours, so the detector must not read missing data as a "drop" or a "spike."

**D. Campaign bursts (signal to inject)**
- **Pre-disclosure recon wave (the headline demo).** Choose a fictitious CVE on vendor X. Inject 3–6 surges against X personas at T−37, T−25, T−10 and T−3 days, compressed into a 24 h demo clock if needed. Each surge has session volume 10–70x the vendor's median and runs for 2–12 h.
  - Variant 1, **distributed**: many residential IPs and many sensors. This gives the longer lead.
  - Variant 2, **concentrated**: a few hosting-ASN IPs. This gives the shorter lead.
  - Some campaign ASNs should be reused across 2–3 vendors, mimicking GreyNoise's cross-vendor ASNs.
- **Disclosure event at T.** A simulated advisory (CERT-In or vendor style JSON) is published, and the engine back-links it to prior surges to compute the realised lead time.
- **Post-disclosure exploitation.** Within hours, exploit-attempt events with a tag/CVE match appear. Exposure counts for vendor X in the simulated national inventory double within about 3 simulated days (React2Shell shape). More than 50% of exploiting IPs are new, never seen before (State of the Edge).
- **Decoys for false positives.** A benign research scanner adds a new port (a large IP spike labelled benign). A firehose IP (sessions spike, IPs flat). A surge with no subsequent CVE: about 35% of surges should not be followed by a CVE, matching GreyNoise's ~65% hit rate.
- **Optional post-compromise.** One "exposed" simulated asset starts beaconing at 60 s ± 10–30% jitter to a defanged domain, alongside benign NTP and updater periodic flows, for the RITA module.

**E. Detection methods (lightweight, explainable for judges)**
- **Robust spike score** per key (tag/vendor/sector) per hour: `z = (x − median_28d) / (1.4826·MAD_28d)`. Alert when z ≥ 4 on sessions *and* z ≥ 3 on unique IPs, or on a 2-hour rolling percentage increase ≥ X%. Use EWMA or CUSUM for slow ramps. Kleinberg-style burst states are an optional alternative.
- **Confidence tiers** following GreyNoise: sessions only = low; IPs only = low; both = high. Distributed (many ASNs and sensors) = earlier warning. Concentrated hosting = shorter fuse.
- **Novelty** = share of source IPs unseen in the trailing 30 days.
- **Breadth** = number of sensors, regions and sectors hit.
- **Wave tracking** = intervals between successive surges on the same vendor, where shrinking gaps raise the score.
- **Clustering**: group sources by (ASN, payload hash or path set, credential set, port set, timing) with DBSCAN or Jaccard on feature sets to label campaigns. Flag ASNs appearing across ≥3 vendor families.
- **Tagging**: a rule table mapping regex/path/credential patterns to a tag, a CVE and an intent, in the style of GreyNoise's tag process. Unmatched high-volume payloads go to a "new pattern" queue, which is where an LLM summariser can be applied, offline or cached.

**F. Risk scoring (transparent formula for the "explain the AI/scoring" deliverable)**
- Example: `Risk = 100 × [w1·SurgeScore + w2·Novelty + w3·Breadth + w4·EPSS + w5·KEV_flag + w6·ExposureMatch(asset inventory, internet-facing, criticality of sector)]`
- Map the result to Low, Medium, High or Critical, and show the per-factor contributions on the dashboard.

**G. Evaluation the demo can show**
- Report the lead time of the first alert against the simulated disclosure. Compute precision and recall of "surge → CVE within 21 days" against the injected ground truth, and compare with a chance baseline built by shuffling surge dates.
- Report alert volume per day and the share of benign-scanner-caused alerts suppressed.

**H. Safety and compliance (D3COY rules)**
- No live honeypots, scanning or malware. All IPs and ASNs come from RFC 5737/5398 ranges. Indicators are defanged. Any real feed (CISA KEV, EPSS CSV, Shadowserver dashboard stats) is cached offline before the demo.

### Gaps
- No public, labelled honeypot dataset with ground-truth "campaign → CVE" links was identified. Simulation parameters are therefore inferred from the aggregate statistics above, not fitted to raw data.
- GreyNoise's exact spike thresholds are unpublished. The z-score and percentage thresholds above are design choices, not replications of GreyNoise's method.
