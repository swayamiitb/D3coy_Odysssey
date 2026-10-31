# Open-source CTI platforms and AI/ML/LLM R&D for cyber threat intelligence (as of 31 Oct 2026)

Scope note for the report writer: these notes cover (a) open-source CTI platform architectures and data models and (b) the state of the art in ML/NLP/LLMs for CTI, with a closing section of design lessons for a 24-hour prototype on an 8 GB GPU. Facts are dated where they are older than 2026. Numbers are quoted exactly as the source gives them. Where a source was only seen through a search snippet rather than fetched, that is flagged. Benchmark numbers from different papers use different protocols, so they are **not** directly comparable across papers.

---

## 1. Open-source CTI platform architectures and data models (MISP, OpenCTI, TheHive/Cortex, IntelOwl, Yeti), including MISP's indicator decay model

### Takeaway
MISP is an event/attribute store built for sharing. It adds context with taxonomies and galaxies, links data through a correlation engine, filters false positives with warninglists, and ages indicators with a taxonomy-driven decay score: base_score × a polynomial time decay, reset by sightings. OpenCTI is a STIX 2.1-native knowledge graph. It keeps a separate 0–100 indicator *score*, which decay rules age, and an entity *confidence*, which governs who may edit what. Both patterns are cheap to copy in a prototype: a score that combines source reliability with a time decay, warninglists, and correlation on exact values.

### Cited Findings

**MISP: data model, correlation, warninglists, export**
- MISP holds intelligence from single indicators up to linked objects inside events. Reports can be written in Markdown. Taxonomies and galaxies are shareable and add context for threat actors, malware, ransomware, tools and MITRE ATT&CK — [MISP features](https://www.misp-project.org/features/)
- The correlation engine matches on exact values and on "advanced patterns, including fuzzy hashes and CIDR overlaps", with adjustable controls. Correlation can be turned on or off per attribute. Distribution levels and custom sharing groups can be applied down to single attributes — [MISP features](https://www.misp-project.org/features/); [misp-website mirror](https://eugit.opencloud.lu/MISP/misp-website/commit/8701dc6748fa3443ae34b094e0dc0d0d9fc1be48)
- MISP exports MISP JSON, STIX 1 and 2, OpenIOC, CSV, text, Suricata, Snort, Zeek, RPZ and forensic cache formats. STIX 2.x conversion goes through the misp-stix library — [MISP features](https://www.misp-project.org/features/)
- Warninglists are lists of known-good or likely false-positive values. MISP shows an info or warning box at event and attribute level when a value matches one. Admins enable or disable each list globally — [misp-warninglists](https://eugit.opencloud.lu/MISP/misp-warninglists/src/commit/14edcbd433a6a15c5723975b6e438f66d91b45bf)
- Common practice (third-party guide, lower confidence) is to apply warninglists for RFC1918 ranges, Alexa/Tranco top sites and public DNS resolvers, and to search with warninglist enforcement so these values drop out. Enabling every public feed creates noise — [skill guide (secondary)](https://claudeskills.info/skills/mukul975/Anthropic-Cybersecurity-Skills/operationalizing-misp-threat-feeds/)
- MISP's feature page links "Default feeds" but does not describe over-correlation handling. I did not verify the mechanism (for example, a cap on correlations for very common values) in this session — [MISP features](https://www.misp-project.org/features/)

**MISP decaying of indicators (2019 design, still current)**
- The design is described in "Taxonomy driven indicator scoring in MISP threat intelligence platforms" (Mokaddem, Wagener, Dulaunoy, Iklody; arXiv 1902.03914, 2019) — [arXiv 1902.03914](https://arxiv.org/pdf/1902.03914)
- The score is `score = base_score × P`, where P depends on `lifetime` (when the score reaches 0) and `decay_speed`. The blog post gives only this simplified form — [MISP blog, 2019-09-12](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html)
- CIRCL training slides give the polynomial form `score(t) = base_score × (1 − (t/τ)^(1/δ))`, with t = time since the last sighting or creation, τ = lifetime and δ = decay rate. An indicator counts as decayed once its score falls below a threshold, and can be discarded when the score reaches 0. Lifetime is set per indicator type (short for IPs, long for hashes) — [MISP training a.5 decaying indicators](https://www.misp-project.org/misp-training/a.5-decaying-indicators.pdf); [TNC18 slides](https://tnc18.geant.org/getfile/tnc18_slides_ScoringMISPCW.pdf). The exact expression appears in CIRCL presentations, not in a verbatim docs page.
- `base_score` comes from the `numerical_value` of taxonomy tags. With one tag, base_score equals that tag's value (for example, admiralty-scale "Completely reliable" = 100). With several tags, a total weight of 100 is split across taxonomies. In the blog's worked example, admiralty-scale "Completely reliable" (100) plus phishing "high" (75) at 50/50 weights gives 87.50 — [MISP blog](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html)
- A sighting resets the score to base_score and starts a new decay from that point. In 2019, false-positive and expiration sightings were listed as future work — [MISP blog](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html)
- Default models ship in a separate repository, and the example default is the phishing model. Custom models can be shared or kept within one organisation. Custom formulas are possible by extending a base class with `computeScore` and `isDecayed` — [MISP blog](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html); [MISP training](https://www.misp-project.org/misp-training/a.5-decaying-indicators.pdf)
- API: `attribute/restSearch` accepts `includeDecayScore`, `excludeDecayed`, `decayingModel` (list of model IDs) and `modelOverrides` (for example `{"threshold": 30}`) — [MISP blog](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html)

**OpenCTI: architecture, score, decay, confidence**
- Architecture: one platform (UI plus GraphQL API, can scale horizontally behind a load balancer), Python workers that consume RabbitMQ and do asynchronous writes (recommended at least 1 platform per 3 workers), and connectors. Backing services are Elasticsearch ≥8.0 or OpenSearch ≥2.9, Redis ≥7.1, RabbitMQ ≥3.11, and S3/MinIO. Minimums are 8 GB RAM for Elasticsearch and 8 GB RAM for the core — [OpenCTI deployment overview](https://docs.opencti.io/latest/deployment/overview/)
- There are five connector types: external import (for example MITRE, MISP, CVE → STIX2), internal enrichment (for example Shodan), internal import file (STIX 2.1/PDF/HTML), internal export file (STIX 2.1/CSV/PDF), and stream (for example Splunk) — [OpenCTI deployment overview](https://docs.opencti.io/latest/deployment/overview/)
- Indicators start with a score from the data source, or **50 by default**. Decay rules, available since OpenCTI 6.0, have a `lifetime` (days to reach 0), a `decay factor` (speed), `reaction points` (scores at which the indicator is updated) and a `revoke score`. The indicator is revoked at whichever comes first, the revoke score or `valid_until`. Built-in rules apply by observable type and cannot be modified. A circuit breaker rejects repeated identical score updates from the same source. Indicators created before the 6.0 migration get no backward decay computation — [OpenCTI indicators lifecycle](https://docs.opencti.io/latest/usage/indicators-lifecycle); [OpenCTI decay rules](https://docs.opencti.io/latest/administration/decay-rules/); [Filigran blog](https://filigran.io/blog/introducing-decay-rules-implementation-for-indicators-in-opencti)
- Confidence is separate from score. Each user or group has a max confidence (0–100, or chosen through an Admiralty-scale selector). Users whose max confidence is below an entity's confidence cannot update or delete it, and when two values compete the lower one wins. The default reliability scale is the NATO Admiralty scale, which yields notations such as A1 or B2. Admins with "Bypass" get effective confidence 100. The rules differ slightly between 6.1 and later versions — [OpenCTI reliability & confidence (latest)](https://docs.opencti.io/latest/usage/reliability-confidence/); [6.4 docs](https://docs.opencti.io/6.4.X/usage/reliability-confidence/); [6.1 docs](https://docs.opencti.io/6.1.X/usage/reliability-confidence/)

**TheHive 5 / Cortex**
- TheHive 5 runs standalone or clustered. Each layer (application, Cassandra database, Elasticsearch index, file storage) can be deployed independently, with Nginx optional for TLS — [StrangeBee TheHive overview](https://docs.strangebee.com/thehive/overview/)
- Cortex runs **analyzers**, which enrich observables, and **responders**, which take containment actions. TheHive can use several Cortex instances, so analysts can choose one per OPSEC need — [StrangeBee analyzers](https://docs.strangebee.com/thehive/user-guides/organisation/notifications/analyzers); [StrangeBee responders](https://docs.strangebee.com/thehive/user-guides/organisation/notifications/responders)
- TheHive imports MISP events and exports cases as MISP events. Older community docs describe tag allow/deny-list and max-attribute filters, but these may be out of date for v5 — [StrangeBee overview](https://docs.strangebee.com/thehive/overview/); [older fork README](https://github.com/SDugo/TheHive)

**IntelOwl**
- IntelOwl is a Django/REST application deployed with Docker. Its plugin types are analyzers (external lookups such as VirusTotal and AbuseIPDB, or local tools such as Yara and Oletools), connectors (export to MISP or OpenCTI), pivots (chain analyses), visualizers and ingestors. Playbooks are saved lists of analyzers, connectors, pivots and visualizers for each observable type. Connectors are disabled by default, and `maximum_tlp` caps what gets shared outward — [IntelOwl GitHub](https://github.com/certego/IntelOwl); [Honeynet GSoC 2022 playbooks](https://honeynet.org/2022/10/06/gsoc-2022-project-summary-creating-playbooks-for-intelowl/); [IntelOwl Usage.md](https://github.com/intelowlproject/IntelOwl/blob/b8a9a4bae67fe1e053bfcba43e2e47f17b0b4950/docs/source/Usage.md)

**Yeti**
- Yeti is a "Forensics Intelligence" platform that bridges CTI and DFIR. It is written in Python and maintained since about 2017. Its data model has observables, entities (actors, TTPs, campaigns, malware) and indicators, linked into threat graphs stored in ArangoDB. It ingests feeds, enriches data and manages YARA, Sigma and DFIQ, exposes a web API, and is Apache-2.0 licensed — [Help Net Security 2023](https://www.helpnetsecurity.com/2023/10/12/yeti-threat-intelligence/); [hack.lu 2023 talk](https://pretalx.com/hack-lu-2023/talk/JAKAKS/); [LinuxLinks](https://www.linuxlinks.com/yeti-forensics-intelligence-platform/)

### Inferences
- The architecture shared by all five platforms is: (1) normalise everything to a small typed schema (MISP attributes/objects, STIX SDOs/SCOs, Yeti observables/entities); (2) separate *ingestion/enrichment plugins* from the core; (3) keep *provenance* (source, author, TLP) on every object; (4) compute scores outside the raw data so they can be re-derived. A prototype can copy this with SQLite tables plus a plugin folder.
- MISP's decay design is the simplest credible indicator-confidence model to reimplement in an hour: base score from source reliability (Admiralty) and other tags, a type-specific lifetime, polynomial decay, a reset on a new sighting, and a threshold to drop stale indicators. OpenCTI's version (initial score, lifetime, decay factor, reaction points, revoke score) has the same shape. It probably uses a similar polynomial curve, but that is not verified.
- OpenCTI's minimums (more than 16 GB RAM across Elasticsearch and the core) make it unsuitable to run *alongside* a local LLM on a hackathon laptop. Use its data model, not the deployment.

### Gaps
- I did not verify the exact OpenCTI decay formula or the built-in per-type default rule values (lifetimes, decay factors, revoke scores). The docs pages only show examples, and the values live in the platform UI or source code.
- MISP's over-correlation and "top correlations" controls are not documented in the sources fetched.
- I did not verify the numerical values that MISP's admiralty-scale taxonomy assigns to grades B–F and 2–6, beyond "Completely reliable" = 100.
- I did not check the TheHive 5 MISP-sync and responder configuration specifics.

---

## 2. STIX 2.1 / TAXII 2.1 essentials for exporting warnings; the Admiralty (NATO) reliability/credibility scale and how platforms apply confidence

### Takeaway
To export an early warning credibly, emit a STIX 2.1 bundle. It should contain an Indicator (pattern + valid_from/valid_until + confidence 0–100), Vulnerability, Identity (the source) and Relationship objects, plus a TLP marking, optionally served from a TAXII 2.1 collection. Map Admiralty credibility 1–5 to STIX confidence 90/70/50/30/10, the normative mapping in STIX 2.1 Part 1 Appendix B as implemented in python-stix2. Keep source reliability (A–F) separate from information credibility (1–6).

### Cited Findings
- STIX 2.1 (OASIS Standard, 2021) defines SDOs (Indicator, Vulnerability, Malware, Threat-Actor, Campaign, Intrusion-Set, Attack-Pattern, Course-of-Action, Infrastructure, Report, Note, Opinion, Grouping and others), SCOs (ipv4-addr, domain-name, file and others), and SROs (Relationship, Sighting). An Indicator requires `pattern`, `pattern_type` and `valid_from`, and may carry `valid_until`. All SDOs have an optional common `confidence` property (integer 0–100). Markings attach through `object_marking_refs` — [STIX 2.1 OS spec](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) (spec not re-fetched this session. These are core, long-stable spec facts.)
- TAXII 2.1 defines a Discovery endpoint, API Roots, Collections (GET objects, manifest, `added_after` filtering, envelopes) and the media type `application/taxii+json;version=2.1` — [TAXII 2.1 OS spec](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html) (not re-fetched). OASIS also publishes reference tooling: [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2), [medallion TAXII 2.1 server](https://github.com/oasis-open/cti-taxii-server) and [taxii2-client](https://github.com/oasis-open/cti-taxii-client)
- TLP 2.0 (FIRST, 2022) uses the labels CLEAR, GREEN, AMBER, AMBER+STRICT and RED — [FIRST TLP](https://www.first.org/tlp/)
- **STIX ↔ Admiralty credibility mapping** (STIX 2.1 Part 1, Appendix B, as implemented in python-stix2): Admiralty credibility 1 → 90, 2 → 70, 3 → 50, 4 → 30, 5 → 10, and 6 ("truth cannot be judged") → no confidence value. The reverse bands are 80–100 → 2 "Probably True", 60–79 → 3, 40–59 → 4, 20–39 → 5, and 0–19 → 6. The library's reverse table has no band for 1 "Confirmed by other sources", and it raises an error for level 6 — [python-stix2 confidence scales](https://stix2.readthedocs.io/en/latest/api/confidence/stix2.confidence.scales.html); [scales.py mirror](https://eugit.opencloud.lu/MISP/cti-python-stix2/raw/branch/pypi/stix2/confidence/scales.py)
- In a 2017 proposal, OASIS said the appendix would hold normative mappings (low/med/high, 0–10, WEP, Admiralty), and that these "MUST be used if any scale not 0-100 is used". That text is from the proposal stage, so check the final wording — [OASIS CTI list 2017-02](https://lists.oasis-open.org/archives/cti/201702/msg00048.html)
- CISA's AIS Scoring Framework (v1.0) builds on the Admiralty "Evaluation of Information Content" approach, and its appendices map scores to STIX confidence and opinion values — [CISA AIS Scoring Framework](https://www.cisa.gov/sites/default/files/publications/AIS%20Scoring%20Framework%20Used%20for%20Indicator%20Enrichment%20V1.0_508.pdf)
- OpenCTI uses the NATO Admiralty reliability scale by default and combines reliability with confidence into notations like "A1" or "B2" — [OpenCTI reliability & confidence](https://docs.opencti.io/latest/usage/reliability-confidence/). MISP carries the scale as the `admiralty-scale` taxonomy, whose numerical values feed the decay base_score ("Completely reliable" = 100) — [MISP blog](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html). MISP also publishes best-practice guidance on expressing confidence — [MISP best-practices: expressing confidence](https://eugit.opencloud.lu/MISP/best-practices-in-threat-intelligence/src/commit/2feb23a00baefa83785b16f4c863330bb203b3d6/best-practices/expressing-confidence.adoc)

### Inferences
- Admiralty letter grades (A Completely reliable → F Reliability cannot be judged) describe the **source**. Digit grades (1 Confirmed → 6 Truth cannot be judged) describe the **item**. In STIX, put source reliability on the Identity or in a custom property or label, and the item's credibility in `confidence`. Do not merge the two into a single number without saying so.
- For a demo, a STIX bundle exported to a file plus a stub TAXII collection (medallion) is enough to show interoperability, with no network calls required.
- An ML-derived score (for example, "LLM-extracted ATT&CK mapping") should be written as a lower `confidence`, or as a separate STIX `opinion`/`note` object with `created_by_ref` set to the model's Identity. That keeps machine-generated claims distinguishable from analyst ones.

### Gaps
- The verbatim STIX 2.1 Appendix B table was not fetched. The mapping above comes from the reference library, which handles level 1 and level 6 at the edges in its own way.
- I could not confirm whether any CTI platform publishes an official mapping from the six-by-six Admiralty matrix to a single 0–100 score.

---

## 3. ATT&CK mapping and TTP extraction: MITRE TRAM, CTID mappings (KEV→ATT&CK), CVE-LMTune (DIMVA 2026), SecureBERT/SecureBERT 2.0, TTPXHunter, AnnoCTR

### Takeaway
Mapping text to ATT&CK is still the weakest CTI task for small generative models, and fine-tuned encoders (SciBERT, SecureBERT, RoBERTa, ModernBERT-based SecureBERT 2.0) remain the most accurate and cheapest option. For CVE descriptions → ATT&CK, CVE-LMTune's SecureBERT classifier reports micro-F1 0.8168 over 175 sub-technique labels (2026). For sentence → TTP, TTPXHunter reports 92.42% F1 (2024). TRAM's SciBERT baseline scores only about 0.4 F1 on report data (per a 2025 re-evaluation). The authoritative open ground truth for vulnerability → ATT&CK is CTID's KEV mappings (PKEV, 2025).

### Cited Findings

**MITRE/CTID resources**
- TRAM (Threat Report ATT&CK Mapper), a CTID project, automates mapping of report text to ATT&CK. Its latest iteration "makes effective use of fine-tuned LLMs" — [CTID TRAM project](https://ctid.mitre.org/projects/threat-report-attck-mapper-tram/). TRAM II partner CrowdStrike reports the team compared BERT and GPT-2 before choosing fine-tuned **SciBERT** to meet target accuracy (vendor claim, about 2022) — [CrowdStrike blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-partners-with-mitre-engenuity-center-for-threat-informed-defense-to-develop-tram/)
- An independent 2025 evaluation (Web Conference 2025, arXiv 2505.03147) found TRAM with the original SciBERT to be the best baseline, at "F1-score of just over 0.4", and blamed overfitting and class imbalance. Zero-shot Llama2 did worse on six short reports (AEL set): 7B P/R/F1 0.2403/0.3736/0.2733, 13B 0.0911/0.2792/0.1199, 70B 0.1733/0.4306/0.2384. The 70B model found the most true positives but also produced the most false positives. Their fix was to summarise reports with GPT-3.5, then retrain SciBERT on a rebalanced, LLM-augmented dataset. This raised median F1 by about 7 points, with some techniques above 0.90 (T1070.004 F1 0.9231, T1566.001 0.9109) and others weak (T1570 F1 0.4762, recall 0.3125) — [arXiv 2505.03147](https://arxiv.org/html/2505.03147v1)
- **CTID Prioritize Known Exploited Vulnerabilities (PKEV, Feb 2025)** maps CISA KEV CVEs to ATT&CK (sub-)techniques by attack step, prioritising CVEs from 2021 on. The mappings, Navigator layers and methodology are published in Mappings Explorer. CTID found that mapping *all* CVEs to ATT&CK "was not feasible" — [CTID PKEV blog](https://ctid.mitre.org/blog/2025/02/13/pkev-blog/); [Mappings Explorer project](https://ctid.mitre.org/projects/mappings-explorer/); [mappings-explorer GitHub](https://github.com/center-for-threat-informed-defense/mappings-explorer)
- The older CTID "Mapping ATT&CK to CVE for Impact" methodology (about 2021) has migrated into Mappings Explorer. Mapping files export as Navigator layers, CSV, JSON, YAML or XLSX. Mappings Editor gained ATT&CK Sync in Nov 2025 — [mappings-editor wiki](https://github.com/center-for-threat-informed-defense/mappings-editor/wiki); [CTID blog Nov 2025](https://ctid.mitre.org/blog/2025/11/15/get-in-sync-with-attack-ctid/)
- KEV size: CISA added 245 entries in 2025 (+20%), for 1,484 total at the end of 2025 (press analysis, so verify against CISA's JSON feed) — [heise](https://heise.de/-11130552); [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Mapping CVEs to ATT&CK through CWE→CAPEC→ATT&CK chains is common in vendor tooling, but each taxonomy has gaps and inconsistencies — [Securin (vendor)](https://securin.io/wp-json/wp/v2/posts/7366)

**CVE-LMTune (DIMVA 2026)**
- Terranova, Rekbi, Lahmadi and Chrisment, "Multi-Taxonomy Vulnerability Classification with Hierarchically Finetuned Language Models", DIMVA 2026, Chania, July 2026. The work is a pipeline that collects labelled vulnerability data, builds a unified multi-label dataset across CWE, CAPEC and ATT&CK, and uses a DAG of specialised models, one per taxonomy level — [HAL record](https://hal-hceres.archives-ouvertes.fr/SUPERVIZ/hal-05502461v1)
- The flat ATT&CK classifiers on Hugging Face target 175 Enterprise sub-technique labels from 231,009 samples. Input is a CVE description, and output is one or more ATT&CK IDs. **SecureBERT variant: micro-F1 0.8168 at threshold 0.5**, the best of the three listed (BERT, DistilBERT, SecureBERT). The latest CVE update is 17/06/2026. The dataset is on Zenodo (DOI 10.5281/zenodo.16936476). Numbers are self-reported on model cards — [SecureBERT ATT&CK flat](https://huggingface.co/Sana9/securebert-vuln2attack-flat); [DistilBERT ATT&CK flat](https://huggingface.co/Sana9/distilbert-vuln2attack-flat); [BERT ATT&CK flat](https://huggingface.co/Sana9/bert-vuln2attack-flat); CWE/CAPEC siblings: [securebert-vuln2cwe-flat](https://huggingface.co/Sana9/securebert-vuln2cwe-flat), [securebert-vuln2capec-flat](https://huggingface.co/Sana9/securebert-vuln2capec-flat)

**TTPXHunter (2024)**
- Sentence → TTP classification over 193 TTPs, using a cybersecurity domain language model. It reports **92.42% F1** on an augmented sentence-TTP dataset of 39,296 samples and **97.09% F1** on a 149-report CTI report→TTP dataset. Its predecessor TTPHunter reached about 0.88 F1 on the top 50 TTPs. Limitation: a one-to-one classifier, one TTP per sentence — [arXiv 2403.03267](https://arxiv.org/html/2403.03267v3). A 2025 survey quotes different figures (NER 0.859, TTP classification 0.982), probably from a different version or setup — [SOC LLM survey arXiv 2509.10858](https://arxiv.org/pdf/2509.10858)

**AnnoCTR (LREC-COLING 2024)**
- 400 CTI reports donated by Intel471, Lab52, Proofpoint, QuoIntelligence and ZScaler, under CC-BY-SA 4.0. 120 reports are expert-annotated with ATT&CK tactics and techniques, *including implicit mentions*, plus named entities, TIMEX and concepts linked to Wikipedia and ATT&CK. Tasks are NER, entity linking and sentence-level tactic/technique classification, with a temporal 60/15/25 split. In few-shot settings, ATT&CK technique descriptions work well as augmentation data — [arXiv 2404.07765](https://arxiv.org/abs/2404.07765); [LREC-COLING via ACL Anthology author page](https://aclanthology.org/people/marc-muller/)

**SecureBERT 2.0 (Cisco, Oct 2025)**
- Built on ModernBERT and pretrained on more than 13B text tokens plus 53M code tokens (more than 13 times the original SecureBERT corpus). It handles 1024-token sequences and outputs 768-dim embeddings, under Apache-2.0. Variants are a bi-encoder, a cross-encoder, a code-vulnerability model and an NER model — [arXiv 2510.00240](https://arxiv.org/html/2510.00240v1); [HF bi-encoder card](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder/blob/main/README.md); [Cisco blog](https://blogs.cisco.com/?p=480754)
- **NER (CyNER test set, 717 rows; types Malware/Indicator/System/Organization/Vulnerability):** SecureBERT 2.0 F1 0.945 (P 0.927, R 0.965), against SecureBERT v1 0.7340 and CyBERT 0.3509 — [arXiv 2510.00240](https://arxiv.org/html/2510.00240v1)
- **Retrieval (cyber rules corpus, about 5k records):** bi-encoder R@1 88.83% / mAP 92.39%, against all-MiniLM-L6-v2 at 77.87% / 82.66% and AttackBERT at 74.39% / 80.40% — [arXiv 2510.00240](https://arxiv.org/html/2510.00240v1)
- **Code vulnerability detection (C/C++):** accuracy 0.655, F1 0.616, against CodeBERT at 0.627 / 0.3722. All numbers are self-reported by Cisco — [arXiv 2510.00240](https://arxiv.org/html/2510.00240v1)

**Small encoders vs 8B LLMs on CVE→CWE (2026)**
- A fine-tuned RoBERTa-base (125M) CVE→CWE classifier gets 87.4% top-1 and 60.7% macro-F1 on 27,780 held-out samples across 205 CWEs, against TF-IDF at 84.9% top-1 (macro-F1 15.5 points lower). On **CTIBench-RCM it gets 75.6% strict accuracy (95% CI 72.8–78.2)**, "statistically indistinguishable" from Foundation-Sec-8B-Reasoning's 75.3%. Caveats: training labels were refined by Claude Sonnet 4.6, the evaluation keeps only samples where NVD and AI labels agree, and no temporal split is described — [arXiv 2603.14911](https://arxiv.org/abs/2603.14911)
- CIRCL's **VLAI** (RoBERTa-base, 2025) predicts a severity class (low/medium/high/critical) from description text alone, with over 82% accuracy from fine-tuning on more than 600k vulnerabilities. Card accuracy varies across revisions (0.8231–0.8292). It is retrained daily and deployed in Vulnerability-Lookup for CVEs that have no CVSS — [arXiv 2507.03607](https://arxiv.org/html/2507.03607v1); [HF card](https://www.huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base)

### Inferences
- For a prototype, CVE description → ATT&CK and CVE → severity/CWE are **solved well enough by downloadable encoder models** (CVE-LMTune SecureBERT, VLAI, a RoBERTa CWE classifier). These run on CPU or under 1 GB of VRAM, leaving the GPU free for an 8B LLM that handles summarisation and explanation.
- The F1 for report-level TTP extraction varies hugely with granularity: about 0.4 for TRAM on realistic report data, against 92–97% for TTPXHunter on its own datasets. Any number quoted in a demo must state the unit (sentence vs report) and the label space (50 vs 193 vs 175 vs about 600+ techniques).
- CTID PKEV mappings are the best open "gold" set for evaluating vulnerability→ATT&CK mapping. However, CVE-LMTune's training data may overlap with them, so check before using them as a test set.

### Gaps
- I did not verify the CVE-LMTune peer-reviewed paper's own results tables, or how its ATT&CK labels were derived (CTID mappings vs CWE→CAPEC→ATT&CK propagation). This matters for leakage.
- I did not verify TRAM's current label set size or whether its LLM notebooks report F1.
- I did not check the current ATT&CK version (v18/v19) in October 2026.
- The PKEV mapping count (how many KEV CVEs are mapped) was not retrieved.

---

## 4. CTI benchmarks (CTIBench and 2025–2026 successors) and results for 8B-class models (Foundation-Sec-8B family, Llama-Primus, Qwen3)

### Takeaway
On CTIBench, the security-tuned 8B models (Foundation-Sec-8B-Reasoning: RCM 0.753, MCQA 0.691, ATE 0.491) beat general 8B models (Qwen3-8B: RCM 0.542, ATE 0.408. Llama-3.1-8B-Instruct: RCM 0.531, ATE 0.132) and approach GPT-4.1 on RCM (0.730). Harder 2025 benchmarks show a big gap remains. On AthenaBench, Qwen3-8B scores 11.8% on technique extraction and 5.5 F1 on mitigation recommendation, against about 76% and 32.6 for GPT-5. On CyberSOCEval, even frontier models score only 43–53%. Small models handle the *structured* tasks (CVSS/CWE) but not open-ended attribution or mitigation reasoning.

### Cited Findings

**CTIBench (Alam et al., 2024; NeurIPS 2024 Datasets & Benchmarks per [arXiv 2603.14911](https://arxiv.org/abs/2603.14911))**
- Tasks and metrics: CTI-MCQ (2,500 questions; accuracy), CTI-RCM (1,000 CVEs → CWE; accuracy), CTI-VSP (1,000 CVEs → CVSS v3.1 vector; mean absolute deviation), CTI-ATE (60 malware instances, 397 unique techniques; F1), and CTI-TAA (50 reports → threat actor; "correct" and "plausible" accuracy) — [arXiv 2406.07599v3](https://arxiv.org/html/2406.07599v3)
- Original results (2024): ChatGPT-4 MCQ 71.0, RCM 72.0, VSP MAD 1.31, ATE 0.6388, TAA 52/86. LLAMA3-70B 65.7, 65.9, 1.83, 0.4720, 52/80. **LLAMA3-8B 61.3, 44.7, 1.91, 0.1562, 28/36.** Gemini-1.5 65.4, 66.6, 1.09, 0.4612, 38/74 — [arXiv 2406.07599v3](https://arxiv.org/html/2406.07599v3)

**Foundation-Sec-8B family (Cisco Foundation AI; Llama-3.1-8B base)**
- Base (Apr 2025): trails GPT-4o-mini by 0.8 pts on CTIBench-MCQA, beats it by 6.1 pts on RCM, and edges Llama-3.1-70B on RCM by about 1 pt — [arXiv 2504.21039](https://arxiv.org/pdf/2504.21039). The HF base card (per search snippet) lists CTI-RCM 75.26 and CTI-MCQA 67.39 (5-shot, temperature 0.3) — [Cisco blog](https://blogs.cisco.com/ai/foundation-sec-8b)
- Instruct (Aug 2025): claims state-of-the-art RCM over GPT-4o-mini and Llama-3.1-70B-Instruct, competitive on MCQA. The 0-shot card reports MCQA 0.644 — [arXiv 2508.01059](https://arxiv.org/pdf/2508.01059); [HF Instruct card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/aa13cb996e7fc700e7efd6b7367992f14cf349c0/README.md)
- **Reasoning (arXiv 2601.21051, Jan 28 2026):** SFT on about 2M synthetic `<think>` traces, then RLVR with GRPO and a format penalty. Its table (mean of 5 seeds; reasoning models at T=0.6, top-p 0.95; instruct models at T=0.3) — [arXiv 2601.21051](https://arxiv.org/html/2601.21051); [HF card](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning):

| Model | MCQA | RCM | VSP | ATE | CTI-Reasoning | CWE-Pred | CyberMetric | SecBench |
|---|---|---|---|---|---|---|---|---|
| Foundation-Sec-8B-Reasoning | 0.691 | 0.753 | 0.856 | 0.491 | 0.411 | 0.704 | 0.843 | 0.725 |
| Foundation-Sec-8B-Instruct | 0.650 | 0.704 | 0.840 | 0.358 | 0.364 | 0.616 | 0.847 | 0.744 |
| Qwen-3-8B | 0.649 | 0.542 | 0.863 | 0.408 | 0.395 | 0.464 | 0.903 | 0.835 |
| Llama-3.1-8B-Instruct | 0.607 | 0.531 | 0.811 | 0.132 | 0.335 | 0.473 | 0.851 | 0.749 |
| Llama-Primus-Merged (8B) | 0.604 | 0.665 | 0.788 | 0.058 | 0.348 | 0.550 | 0.862 | 0.749 |
| Llama-Primus-Nemotron-70B | 0.705 | 0.664 | 0.239 | 0.268 | 0.485 | 0.613 | 0.906 | 0.830 |
| GPT-4.1 | 0.760 | 0.730 | 0.848 | 0.696 | 0.596 | 0.682 | 0.937 | 0.872 |
| GPT-5 | 0.819 | 0.728 | 0.903 | 0.578 | 0.643 | 0.701 | 0.941 | 0.888 |

  (VSP here is a CVSS-derived score where higher is better. ATE is micro-F1.)
- Discrepancy: search-engine summaries of the same report cite RCM 0.782, MCQA 0.704, and an Instruct RCM of 0.770 in "a second table". The table I fetched directly shows the values above, so treat 0.753/0.691 as canonical — [arXiv 2601.21051](https://arxiv.org/pdf/2601.21051)
- Same report: HarmBench pass rate 93.00% with a system prompt and 98.25% with Llama-Guard-3-8B. The authors say the model has no dedicated safety alignment and recommend extra safety layers. General ability: IFEval 83.7%, GSM8K 82.3%, HumanEval 79.9% — [arXiv 2601.21051](https://arxiv.org/html/2601.21051)
- An official Q8_0 GGUF of the Instruct model exists (`fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF`) — [HF profile listing (snippet)](https://huggingface.co/Frase/models). I found no announcement of a newer Foundation-sec model in 2026 beyond the Reasoning model.

**Llama-Primus (Trend Micro, Feb 2025)**
- Open cybersecurity pretraining, instruction and reasoning datasets. The models are Llama-Primus-Base, -Merged and -Reasoning, with about 15.9% gain on aggregated cyber benchmarks for the base — [arXiv 2502.11191](https://arxiv.org/html/2502.11191v2); [HF/featherless Llama-Primus-Merged](https://featherless.ai/models/trendmicro-ailab/Llama-Primus-Merged)

**AthenaBench (arXiv 2511.01144, Nov 2025): dynamic, regenerated from live ATT&CK/NVD**
- Tasks: CKT (knowledge MCQ), ATE (technique ID from scenario; accuracy), RCM, RMS (recommend ATT&CK mitigation IDs; F1), VSP, and TAA. Selected results (full set; combined score):
  - GPT-5: CKT 92.0, ATE 76.0, RCM 71.6, RMS 32.6, VSP 85.4, TAA 39.0, combined 66.1
  - Gemini-2.5-pro: combined 63.6
  - **Qwen3-8B: CKT 75.7, ATE 11.8, RCM 48.9, RMS 5.5, VSP 82.6, TAA 16.0, combined 40.1**
  - **Qwen3-4B: ATE 5.6, RMS 4.8, combined 37.5**
  - **Llama-3.1-8B: ATE 16.4, RMS 3.6, combined 38.8**
  - Llama-Primus-Merged: ATE 33.8, RCM 56.6, combined 43.7 (+4.9 over its base)
  - Llama-3.3-70B: combined 46.5
  - With web search, GPT-5 rose to ATE 79.6, RMS 51.9 and TAA 63.0
  - [arXiv 2511.01144v2](https://arxiv.org/html/2511.01144v2)
- Foundation-Sec-8B is **not** evaluated in AthenaBench — [arXiv 2511.01144v2](https://arxiv.org/html/2511.01144v2)

**CyberSOCEval (Meta, part of CyberSecEval 4; arXiv 2509.20166, Sept/Nov 2025)**
- The Threat Intelligence Reasoning set has 588 QAs built from 45 reports (CrowdStrike, CISA, NSA, IC3). Frontier-era models score about 43–53%, against about 1.7% random. Reasoning models gave little boost. "Far from saturating" — [arXiv 2509.20166](https://arxiv.org/html/2509.20166v2); [Meta AI](https://ai.meta.com/research/publications/cybersoceval-benchmarking-llms-capabilities-for-malware-analysis-and-threat-intelligence-reasoning/)
- A third-party re-run (CyberPal-2.0, arXiv 2510.14113) reports exact-match/Jaccard of Qwen3-8B 42.86/58.59, CyberPal-2.0-8B 38.61/65.60, CyberPal-2.0-4B 19.39/51.85, and Qwen3-4B 5.95/10.12. The setup differs from Meta's — [arXiv 2510.14113](https://arxiv.org/pdf/2510.14113)

**CTIArena (arXiv 2510.11974, Oct 2025)**
- Nine tasks across structured, unstructured and hybrid CTI. Models struggle closed-book but improve noticeably with retrieval augmentation — [arXiv 2510.11974](https://arxiv.org/abs/2510.11974v1)

**Reliability critique**
- Mezzi, Massacci and Tuma ("LLMs are unreliable for CTI", arXiv 2503.23175, v4 Nov 2025) tested three state-of-the-art LLMs on 350 real reports. The models were **inconsistent and overconfident**. Few-shot prompting and fine-tuning "only partially improve" results, and the models "cannot guarantee sufficient performance on real-size reports" — [arXiv 2503.23175](https://arxiv.org/abs/2503.23175)

### Inferences
- The best ≤8B generative choice for CTI Q&A and CWE/CVSS reasoning on local hardware is **Foundation-Sec-8B-Reasoning** (or -Instruct when lower latency matters, since the reasoning model emits long `<think>` traces). **Qwen3-8B** is a strong general alternative: it is better on VSP, CyberMetric and SecBench, but weaker on RCM.
- No 8B model is reliable at free-form ATT&CK technique ID generation (CTIBench-ATE 0.13–0.49, AthenaBench ATE 5.6–16.4% for general 8B models). Use classifiers or retrieval to produce candidate IDs, and let the LLM only choose or justify among them.
- CTIArena and AthenaBench's web-search results suggest retrieval (RAG over ATT&CK, CWE and KEV) is worth more than model size for small models. This holds for proprietary models in the papers and is a reasonable extrapolation to 8B.

### Gaps
- I found no AthenaBench or CyberSOCEval numbers for Foundation-Sec-8B or Foundation-Sec-8B-Reasoning.
- The exact Llama-Primus scores from its own paper were not verified. Only third-party tables are cited above.
- I did not verify a public CTIBench leaderboard URL.
- Results for Qwen3 at ≤4B on CTIBench (as opposed to AthenaBench) were not found.

---

## 5. LLM and agentic CTI systems (2024–2026): RAG, multi-agent pipelines, hallucination/grounding, prompt injection from malicious reports, mitigations

### Takeaway
The 2025–2026 literature has converged on *pipelines of narrow agents or steps*: extract → map to taxonomy → build relationships → emit STIX → validate. Building relationships remains the hardest step. RAG improves accuracy but opens a poisoning channel, because CTI feeds are attacker-influenced text. Defences combine source-authority weighting, keeping data separate from instructions, schema-constrained outputs and deterministic validation.

### Cited Findings
- **CTINexus** (Euro S&P 2025, Virginia Tech) builds a CTI knowledge graph with in-context learning. It retrieves optimal demonstrations for entity/relation extraction, aligns entities hierarchically for canonicalisation, and predicts long-distance relations to complete the graph. It is open source with a web UI on PyPI/GitHub — [arXiv 2410.21060](https://arxiv.org/abs/2410.21060); [PyPI ctinexus](https://pypi.org/project/ctinexus); [VT showcase](https://cyberinitiative.org/research/research-showcase/2025/ctinexus.html)
- **AZERG** (RAID 2025) fine-tunes LLMs for STIX entity and relationship extraction. Its dataset has 4,011 entities and 2,075 relationships from 141 reports, and it reports gains of 2–25% across tasks (abstract-level) — [HBKU record](https://elmi.hbku.edu.qa/en/publications/from-text-to-actionable-intelligence-automating-stix-entity-and-r/); [MBZUAI record](https://irep.mbzuai.ac.ae/items/d23cd31b-a546-464e-9f44-a49f129722de)
- **Open-weight multi-agent CVE→STIX** (arXiv 2607.16175, 2026): separate agents for object extraction, weakness mapping, ATT&CK mapping, relationship building, JSON generation and validation, using Gemma-4-31B and Codestral-22B. Relationship construction was the hardest stage — [arXiv 2607.16175](https://arxiv.org/pdf/2607.16175)
- **TIBlender** (arXiv 2606.04580, 2026) is a multi-agent *early-warning* system built from cross-platform social media evidence. It runs a five-step pipeline with an evaluation loop that sends weak evidence back for more investigation, and outputs STIX 2.1, JSON, PDF and Markdown — [arXiv 2606.04580](https://arxiv.org/pdf/2606.04580)
- **IntelForge** (BGU, IEEE venue Dec 2025) is a multi-agent enrichment framework that beats single-LLM baselines on agreement with human experts — [BGU CRIS](https://cris.bgu.ac.il/en/publications/intelforge-multi-agent-llm-framework-for-cyber-threat-intelligenc/)
- **TACTIC-KG** (arXiv 2607.05001, 2026) uses small, specialised LLM agent teams for ontology-grounded CTI KG construction — [alphaXiv 2607.05001](https://www.alphaxiv.org/abs/2607.05001.md)
- **CyberLLM-FINDS 2025** combines instruction-tuned domain LLMs with RAG and graph integration for MITRE evaluation — [arXiv 2601.06779](https://arxiv.org/pdf/2601.06779)
- **Hallucination and grounding:** LLMs on CTI are inconsistent and overconfident ([arXiv 2503.23175](https://arxiv.org/abs/2503.23175)). Zero-shot Llama2 TTP extraction is dominated by false positives, and larger models produced *more* of them ([arXiv 2505.03147](https://arxiv.org/html/2505.03147v1)). CTIArena shows closed-book failure that is partly fixed by retrieval ([arXiv 2510.11974](https://arxiv.org/abs/2510.11974v1))
- **Prompt injection via CTI content:**
  - Indirect prompt injection against LLM-integrated apps was established by Greshake et al. (2023) — [arXiv 2302.12173](https://arxiv.org/abs/2302.12173v1)
  - An AI-SOC threat model (arXiv 2609.10707, 2026) names log poisoning and *polluted external CTI feeds* as the main vectors. Its example is a malicious IP submitted with an "IoC description" that carries an injection payload — [arXiv 2609.10707](https://arxiv.org/pdf/2609.10707)
  - The "Promptware Kill Chain" (arXiv 2601.09625, 2026) proposes seven stages including persistence via memory and retrieval poisoning. At least 21 of the 36 cases it studied traverse four or more stages — [arXiv 2601.09625](https://arxiv.org/pdf/2601.09625)
  - CTI pipelines are open to evasion, flooding and poisoning, and evasion can enable downstream flooding and poisoning — [arXiv 2507.06252](https://arxiv.org/pdf/2507.06252v2)
- **Mitigations in the literature:**
  - **RAGRank** (ACSAC 2025 poster) applies PageRank-style source-credibility scores so that likely-malicious documents get lower authority in retrieval. It was tested on MS MARCO plus a proof-of-concept on CTI data. The abstract gives no numbers — [arXiv 2510.20768](https://arxiv.org/abs/2510.20768)
  - "Spotlighting" marks untrusted input by delimiting, datamarking or encoding it so the model treats it as data — [arXiv 2403.14720 (Hines et al., 2024)](https://arxiv.org/abs/2403.14720) (not re-fetched this session)
  - Foundation-Sec-8B-Reasoning's authors advise pairing the model with Llama-Guard; it reached 98.25% on HarmBench when paired — [arXiv 2601.21051](https://arxiv.org/html/2601.21051)

### Inferences
- For an early-warning prototype, the attack surface is the advisory or report text itself. An attacker-authored "advisory" could tell the summariser to downgrade severity or drop an IOC. The cheapest robust controls are:
  1. Never give the LLM tools or write access.
  2. Wrap report text in delimiters and state that it is data, not instructions.
  3. Force JSON schema output with enumerated fields.
  4. Validate every ID (CVE, CWE, ATT&CK) against local reference data.
  5. Compute severity, exposure and risk *deterministically* outside the LLM, so injected text cannot change the score.
  6. Show the source text span for each extracted claim.
- A multi-agent design is not necessary for a 24h demo. A linear pipeline of 4–5 deterministic-plus-LLM steps gives the same benefits (stage-level validation, explainability) with less to go wrong.

### Gaps
- I did not verify numerical results for CTINexus, AZERG, TIBlender, IntelForge or TACTIC-KG. Only abstracts and snippets were seen.
- I found no quantitative study measuring prompt-injection success rates *specifically* against CTI summarisation or extraction pipelines.
- Claims of a "340% YoY increase" in prompt injection (attributed to a CIS 2026 report via a vendor blog) could not be verified, so they are excluded.

---

## 6. Knowledge-graph and graph-ML approaches to correlate indicators, vulnerabilities, assets and campaigns; campaign clustering

### Takeaway
Production platforms correlate by *shared exact values* (MISP correlation, OpenCTI relationships, Yeti graphs in ArangoDB). Research systems use LLMs to build KGs from text (CTINexus, AttacKG+, LLM-TIKG, TACTIC-KG) and add link prediction. I found no strong, recent, openly benchmarked method for campaign clustering. The practical recipe is graph clustering over shared indicators and TTPs, *after* removing shared-infrastructure and warninglisted values.

### Cited Findings
- MISP correlates on exact values, fuzzy hashes and CIDR overlaps, with warninglists to suppress known-benign values — [MISP features](https://www.misp-project.org/features/)
- OpenCTI stores everything as a STIX 2.1 graph (entities plus relationships), ingested through connectors and exposed over GraphQL. Its relationship graph is commonly used to visualise campaign linkages — [OpenCTI deployment overview](https://docs.opencti.io/latest/deployment/overview/); [secondary skill doc](https://claudeskills.info/skills/mukul975/Anthropic-Cybersecurity-Skills/correlating-threat-campaigns/)
- Yeti links observables, entities (actors, TTPs, campaigns) and indicators into threat graphs on ArangoDB — [Help Net Security 2023](https://www.helpnetsecurity.com/2023/10/12/yeti-threat-intelligence/)
- CTINexus does LLM triplet extraction, hierarchical entity alignment and long-distance relation (link) prediction to complete CTI KGs (Euro S&P 2025) — [arXiv 2410.21060](https://arxiv.org/abs/2410.21060)
- AttacKG+ (Computers & Security 2025) uses LLMs to turn reports into layered attack graphs: a behaviour graph with technique labels above and a state summary below — [emergentmind summary](https://www.emergentmind.com/topics/attackg) (secondary)
- LLM-TIKG (Computers & Security 2025) converts unstructured reports into threat-intelligence KGs — [penligent blog (secondary, unverified)](https://penligent.ai/resources/blog/building-threat-intelligence-knowledge-graphs-with-llms-a-turning-point-for-cybersecurity)
- Campaign clustering sits between alert triage and attribution. It uses overlapping features such as file traits, command patterns, network endpoints, timing, and reuse of certificates or accounts — [NHI glossary (secondary)](https://nhimg.org/glossary/campaign-clustering/)
- Shared infrastructure (Cloudflare, CloudFront, bulletproof hosting) causes false campaign links. A shared IP alone does not establish linkage (practitioner guidance, secondary) — [skill doc](https://claudeskills.info/skills/mukul975/Anthropic-Cybersecurity-Skills/correlating-threat-campaigns/)
- Attributed-graph clustering with community outlier ranking has been used for insider-threat detection, an adjacent graph-ML method (2018) — [arXiv 1809.00231](https://arxiv.org/pdf/1809.00231)
- Hybrid vulnerability-to-ATT&CK knowledge (CVE↔CWE↔CAPEC↔ATT&CK) is the standard join path for linking vulnerabilities to adversary behaviour, but each link has gaps — [Securin (vendor)](https://securin.io/wp-json/wp/v2/posts/7366); [CTID PKEV](https://ctid.mitre.org/blog/2025/02/13/pkev-blog/)

### Inferences
- A defensible prototype graph uses nodes Advisory/Report, CVE, CWE, ATT&CK technique, CPE/product, Asset, IOC and Sector. Edges come from deterministic joins: CVE→CPE (NVD), CPE→Asset (inventory match), CVE→ATT&CK (CTID PKEV or a classifier), and Report→IOC (regex). Campaign clusters can then be connected components or Louvain/Leiden communities (networkx) over Report–IOC and Report–Technique edges, with edges weighted by IDF so common values count less. Warninglisted values and CDN ranges are dropped first.
- Graph neural networks are not justified for a 24h build. No labelled open campaign dataset of adequate size was found, and graph clustering is explainable, which matters for judges.

### Gaps
- I found no recent (2024–2026) peer-reviewed benchmark with published accuracy for *campaign clustering* or *IOC-based attribution* that a prototype could reuse.
- I did not retrieve numerical results for CTINexus link prediction, AttacKG+ or LLM-TIKG.
- I found no open dataset with ground-truth campaign labels for clustering evaluation. (The CTIBench-TAA and AthenaBench-TAA attribution tasks are the nearest proxy: 50 reports, and accuracy 16–39% for most models.)

---

## 7. How to evaluate a CTI AI system credibly with limited time: metrics, ground-truth sources, baselines

### Takeaway
Evaluate each pipeline stage separately against open, authoritative labels:
- CVE→CWE: CTIBench-RCM or NVD CWE
- CVE→CVSS/severity: CTIBench-VSP or NVD/CIRCL vulnerability-scores
- CVE→ATT&CK: CTID PKEV KEV mappings
- Report→TTP: AnnoCTR or TRAM data
- Exploited yes/no: CISA KEV

Report micro and macro F1 or accuracy with bootstrap confidence intervals, against a trivial baseline (TF-IDF+LR, keyword matching, majority class) and against a published model number. Use a temporal split or "post-cutoff" CVEs to avoid training-data leakage.

### Cited Findings
- **Ready-made test sets and numbers to compare against:**
  - CTIBench RCM: 1,000 CVEs, accuracy. Published numbers include RoBERTa 75.6%, Foundation-Sec-8B-Reasoning 75.3%, GPT-4.1 73.0%, ChatGPT-4 72.0% (2024) and LLAMA3-8B 44.7% (2024) — [arXiv 2406.07599v3](https://arxiv.org/html/2406.07599v3); [arXiv 2601.21051](https://arxiv.org/html/2601.21051); [arXiv 2603.14911](https://arxiv.org/abs/2603.14911)
  - CTIBench VSP: CVSS v3.1 MAD. ChatGPT-4 MAD 1.31 and LLAMA3-8B 1.91 (2024) — [arXiv 2406.07599v3](https://arxiv.org/html/2406.07599v3)
- **Statistical reporting:** the CVE→CWE RoBERTa paper reports a 95% CI (72.8–78.2%) and argues statistical indistinguishability, a good model to follow — [arXiv 2603.14911](https://arxiv.org/abs/2603.14911). Foundation-Sec reports means over 5 seeds with standard deviations — [arXiv 2601.21051](https://arxiv.org/html/2601.21051)
- **Baselines:** TF-IDF reaches 84.9% top-1 on CVE→CWE against RoBERTa's 87.4%, but RoBERTa's macro-F1 is 15.5 pts higher. Macro-F1 exposes long-tail failure that accuracy hides — [arXiv 2603.14911](https://arxiv.org/abs/2603.14911). TRAM/SciBERT at about 0.4 F1 is the published TTP baseline on report data — [arXiv 2505.03147](https://arxiv.org/html/2505.03147v1)
- **ATT&CK ground truth:**
  - CTID PKEV mappings of KEV CVEs, with Navigator layers and methodology — [CTID PKEV](https://ctid.mitre.org/blog/2025/02/13/pkev-blog/); [Mappings Explorer](https://ctid.mitre.org/projects/mappings-explorer/)
  - AnnoCTR's 120 expert-annotated reports (CC-BY-SA 4.0, temporal split) — [arXiv 2404.07765](https://arxiv.org/abs/2404.07765)
  - CVE-LMTune's Zenodo dataset (DOI 10.5281/zenodo.16936476), 231,009 samples — [HF card](https://huggingface.co/Sana9/securebert-vuln2attack-flat)
- **Severity ground truth:** the CIRCL `vulnerability-scores` dataset (more than 600k vulnerabilities) behind VLAI — [VLAI arXiv 2507.03607](https://arxiv.org/html/2507.03607v1); [HF card](https://www.huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base)
- **Exploitation ground truth:** the CISA KEV catalog (about 1,484 entries at end-2025) — [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [heise](https://heise.de/-11130552)
- **Product/asset matching ground truth:** NVD CVE API 2.0 configurations (CPE 2.3 match criteria) and the CPE dictionary — [NVD developers](https://nvd.nist.gov/developers/vulnerabilities); [NVD CPE](https://nvd.nist.gov/products/cpe). CISA "Vulnrichment" adds CWE, CVSS, CPE and SSVC to CVE records — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) (not re-fetched)
- **Leakage and label-quality cautions:** the RoBERTa paper evaluated only where NVD and AI labels agree, which likely inflates scores, and described no temporal split — [arXiv 2603.14911](https://arxiv.org/abs/2603.14911). AthenaBench was designed to be *regenerated from live ATT&CK/NVD* partly to resist contamination — [arXiv 2511.01144v2](https://arxiv.org/html/2511.01144v2)
- **Reliability metrics beyond accuracy:** consistency across repeated runs and confidence calibration. LLMs were found inconsistent and overconfident — [arXiv 2503.23175](https://arxiv.org/abs/2503.23175)

### Inferences
- A credible 1–2 hour evaluation plan:
  1. Sample 200 CVEs published *after* the model's training cutoff (for example, from the 2026 NVD feed).
  2. Score CWE accuracy against NVD/CNA labels, and score severity-class accuracy and CVSS-base MAD.
  3. Score ATT&CK micro-F1 on the KEV subset against CTID PKEV.
  4. For report extraction, measure IOC extraction precision and recall on 10–20 hand-labelled advisories (for example, CISA or CERT-In advisories), and measure TTP micro-F1 on 10 AnnoCTR test reports.
  5. Report 95% bootstrap CIs.
  6. Compare against (a) TF-IDF+LogReg, (b) a keyword or regex baseline, and (c) the published CTIBench number for the same model.
  7. For the end-to-end early-warning demo, use a *simulated asset inventory* with planted vulnerable CPEs and report alert precision and recall plus time-to-alert. This tests the advisory → exposure → risk → alert chain the brief asks for.
- Also report a hallucination rate: the share of emitted CVE, CWE or ATT&CK IDs that do not exist in the reference data, or are not supported by a source span. It is cheap to compute and persuasive.

### Gaps
- I did not verify the current NVD enrichment backlog status (October 2026), which affects how many recent CVEs have NVD-assigned CWE/CPE labels.
- I found no standard metric or benchmark for "early-warning lead time" in national CERT contexts.

---

## 8. Lessons and design patterns for a 24-hour prototype running local models on an 8 GB GPU: what to emulate, what to skip, how to evaluate credibly

### Takeaway
Build a thin, MISP/OpenCTI-shaped pipeline: ingest → deterministic normalisation and IOC extraction → small encoder classifiers (CWE, severity, ATT&CK) → deterministic asset/CPE correlation → a MISP-style decay plus Admiralty-weighted risk score → STIX 2.1 export. Use one quantised 8B LLM (Foundation-Sec-8B-Instruct/Reasoning or Qwen3-8B) only for grounded summaries and analyst explanations. Don't build the full platforms, multi-agent systems, GNNs or free-form ATT&CK generation. Evaluate stage by stage on public labels, with baselines and confidence intervals.

### Cited Findings (evidence behind each pattern)
- **Emulate MISP decay for indicator/alert freshness:** `score = base × (1 − (t/τ)^(1/δ))`, base from Admiralty and other taxonomy tags, reset on a new sighting, threshold to expire — [MISP training](https://www.misp-project.org/misp-training/a.5-decaying-indicators.pdf); [MISP blog](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html)
- **Emulate OpenCTI's split of score vs confidence:** indicator score (default 50, decays with reaction points and a revoke score) kept separate from entity confidence and source reliability (Admiralty A–F) — [OpenCTI indicators lifecycle](https://docs.opencti.io/latest/usage/indicators-lifecycle); [OpenCTI reliability & confidence](https://docs.opencti.io/latest/usage/reliability-confidence/)
- **Emulate MISP warninglists** to suppress benign IOCs before correlation — [misp-warninglists](https://eugit.opencloud.lu/MISP/misp-warninglists/src/commit/14edcbd433a6a15c5723975b6e438f66d91b45bf)
- **Emulate IntelOwl's playbook/plugin pattern and `maximum_tlp` gating** on export — [IntelOwl](https://github.com/certego/IntelOwl)
- **Export STIX 2.1 with Admiralty→confidence mapping** (1→90 … 5→10), using python-stix2 — [python-stix2 scales](https://stix2.readthedocs.io/en/latest/api/confidence/stix2.confidence.scales.html)
- **Use small encoders where they match or beat 8B LLMs:**
  - CVE→CWE: RoBERTa 125M 75.6% on CTIBench-RCM, roughly equal to Foundation-Sec-8B-Reasoning at 75.3% — [arXiv 2603.14911](https://arxiv.org/abs/2603.14911)
  - CVE→ATT&CK: CVE-LMTune SecureBERT micro-F1 0.8168 — [HF](https://huggingface.co/Sana9/securebert-vuln2attack-flat)
  - Severity: VLAI over 82% — [HF](https://www.huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base)
  - Security NER: SecureBERT 2.0 F1 0.945 on CyNER — [arXiv 2510.00240](https://arxiv.org/html/2510.00240v1)
  - Retrieval embeddings: SecureBERT 2.0 bi-encoder R@1 88.83% vs MiniLM 77.87% — [arXiv 2510.00240](https://arxiv.org/html/2510.00240v1)
- **Pick the 8B LLM by measured CTI performance:** Foundation-Sec-8B-Reasoning (RCM 0.753, MCQA 0.691), Foundation-Sec-8B-Instruct (RCM 0.704), Qwen3-8B (RCM 0.542, VSP 0.863, CyberMetric 0.903), Llama-3.1-8B-Instruct (RCM 0.531) — [arXiv 2601.21051](https://arxiv.org/html/2601.21051)
- **Do not trust 8B models to emit ATT&CK IDs or mitigations unaided:** AthenaBench ATE 5.6–16.4% and RMS F1 3.6–5.5 for Qwen3-4B/8B and Llama-3.1-8B — [arXiv 2511.01144v2](https://arxiv.org/html/2511.01144v2). Zero-shot Llama2 TTP F1 was 0.12–0.27 — [arXiv 2505.03147](https://arxiv.org/html/2505.03147v1)
- **Retrieval helps more than scale on CTI reasoning** (CTIArena; AthenaBench GPT-5 with search: ATE 79.6, RMS 51.9) — [arXiv 2510.11974](https://arxiv.org/abs/2510.11974v1); [arXiv 2511.01144v2](https://arxiv.org/html/2511.01144v2)
- **Treat advisory text as hostile input** (polluted CTI feeds, indirect prompt injection) — [arXiv 2609.10707](https://arxiv.org/pdf/2609.10707); [arXiv 2302.12173](https://arxiv.org/abs/2302.12173v1). Weight sources by authority (RAGRank idea) — [arXiv 2510.20768](https://arxiv.org/abs/2510.20768)
- **Disclose LLM unreliability** (inconsistent, overconfident) and keep a human in the loop — [arXiv 2503.23175](https://arxiv.org/abs/2503.23175)
- **Prefer a linear pipeline over agents.** Even published multi-agent STIX systems find relationship building the weak step — [arXiv 2607.16175](https://arxiv.org/pdf/2607.16175)
- **Official quantised Foundation-Sec builds exist** (Instruct Q8_0 GGUF) — [HF listing (snippet)](https://huggingface.co/Frase/models)

### Inferences (design recommendations; my synthesis, not sourced claims)
- **Memory budget on 8 GB VRAM (estimate, not from a cited source):** an 8B model at 4-bit (for example GGUF Q4_K_M, about 4.5–5 GB) fits with room for a 4–8k context KV cache. Q8_0 (about 8.5 GB) does **not** fit fully on 8 GB and would need partial CPU offload. Encoder models (125M–150M params) can run on CPU at interactive speed for single advisories, or share the GPU. Load the LLM through llama.cpp or Ollama, and keep encoders in PyTorch or ONNX on CPU.
- **What to emulate:**
  1. **MISP-style decay plus Admiralty base score** for indicators and alerts.
  2. **OpenCTI's score vs confidence split.**
  3. **Warninglists** (RFC1918, top domains, public DNS).
  4. **Deterministic CPE matching** from advisory to simulated asset inventory. This is the core of the brief's demo and must not depend on the LLM.
  5. **Risk = f(CVSS/VLAI severity, KEV membership, EPSS if cached, asset criticality and exposure, source reliability, decay)**, shown as an explainable formula on the dashboard.
  6. **STIX 2.1 bundle export** with TLP markings and `confidence`.
  7. **Retrieval over local ATT&CK STIX, CWE and KEV JSON**, with SecureBERT 2.0 or MiniLM embeddings, to give the LLM candidate IDs to choose from.
  8. **Source-span citations** in every LLM summary.
- **What to skip:**
  - Deploying full MISP, OpenCTI or TheHive. They are too heavy alongside a local LLM, and integration time eats the 24h.
  - Multi-agent orchestration frameworks.
  - GNNs and link prediction.
  - Fine-tuning any LLM. Fine-tuning a small encoder is optional, since pre-fine-tuned checkpoints exist.
  - Live scraping or active enrichment. Hackathon rules forbid anything resembling scanning, so use cached public feeds only and defang IOCs on screen.
  - Free-form LLM generation of CVE, CWE or ATT&CK IDs without validation.
- **Prompt-injection hygiene for the demo:** no tool calls from the LLM; delimit untrusted text; output in a JSON schema; validate IDs against the local catalogue; compute risk outside the LLM; optionally include one deliberately injected "malicious advisory" in the test set to *show* the defence working. That kind of demonstration is persuasive to judges.
- **How to evaluate credibly in about 2 hours:**
  1. CTIBench-RCM subset (for example 200 items), comparing your CWE classifier and your 8B LLM against published numbers (75.6% / 75.3% / 54.2% for RoBERTa / FS-8B-R / Qwen3-8B).
  2. Severity-class accuracy on recent 2026 CVEs with NVD scores, against VLAI and a TF-IDF baseline.
  3. ATT&CK micro-F1 on KEV CVEs against CTID PKEV, against a CWE→CAPEC→ATT&CK lookup baseline.
  4. End-to-end alert precision and recall on a simulated inventory with planted exposures.
  5. ID hallucination rate and consistency over 3 repeated LLM runs.

  Report 95% bootstrap CIs and state every caveat: protocol differences, label noise, possible training overlap.
- **Positioning for judges (C-DAC/national CERT framing):** say plainly that the AI does extraction and explanation, while the risk decision is a transparent, auditable formula with Admiralty-graded sources. This matches how MISP and OpenCTI treat confidence, and it answers the literature's main criticism that LLMs are overconfident and inconsistent.

### Gaps
- I found no published measurement of Foundation-Sec-8B or Qwen3-8B accuracy *after 4-bit quantisation* on CTIBench. Quantisation loss on these tasks is unquantified.
- I found no benchmark of throughput or latency for these models on 8 GB consumer GPUs from an authoritative source. The VRAM figures above are estimates.
- I did not verify EPSS's current version and data-download terms in this session. Confirm before caching EPSS scores ([FIRST EPSS](https://www.first.org/epss/)).
- Whether CVE-LMTune or VLAI checkpoints were trained on CVEs that overlap CTIBench or PKEV test items is unknown. This could inflate a prototype's self-reported evaluation numbers.
