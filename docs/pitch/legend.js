// Full forms of the cybersecurity short forms used on a slide, rendered as a small legend at its foot.
const GLOSSARY = [
  ['PS-01', 'Problem Statement 01'], ['CVE', 'Common Vulnerabilities and Exposures'], ['NVD', 'National Vulnerability Database (NIST)'],
  ['CISA', 'Cybersecurity and Infrastructure Security Agency (US)'], ['KEV', 'Known Exploited Vulnerabilities catalogue'],
  ['SSVC', 'Stakeholder-Specific Vulnerability Categorization'], ['EPSS', 'Exploit Prediction Scoring System'], ['FIRST', 'Forum of Incident Response and Security Teams'],
  ['CVSS', 'Common Vulnerability Scoring System'], ['CWE', 'Common Weakness Enumeration'], ['CPE', 'Common Platform Enumeration'], ['CNA', 'CVE Numbering Authority'],
  ['ATT&CK', 'MITRE Adversarial Tactics, Techniques and Common Knowledge'], ['C2', 'Command and Control (attacker infrastructure)'], ['IOC', 'Indicator of Compromise'],
  ['STIX', 'Structured Threat Information Expression'], ['TAXII', 'Trusted Automated Exchange of Intelligence Information'], ['CAP', 'Common Alerting Protocol'],
  ['SACHET', 'NDMA’s national alert dissemination platform'], ['NDMA', 'National Disaster Management Authority'], ['CERT-In', 'Indian Computer Emergency Response Team'],
  ['NCIIPC', 'National Critical Information Infrastructure Protection Centre'], ['CSIRT', 'Computer Security Incident Response Team'], ['SOC', 'Security Operations Centre'],
  ['SLA', 'Service Level Agreement'], ['MTTA', 'Mean Time To Acknowledge'], ['MTTR', 'Mean Time To Resolve'], ['OT', 'Operational Technology'], ['ICS', 'Industrial Control Systems'],
  ['SCADA', 'Supervisory Control and Data Acquisition'], ['VPN', 'Virtual Private Network'], ['WAF', 'Web Application Firewall'], ['IDS', 'Intrusion Detection System'],
  ['LLM', 'Large Language Model'], ['NLP', 'Natural Language Processing'], ['ML', 'Machine Learning'], ['NER', 'Named Entity Recognition'], ['ROC AUC', 'Receiver Operating Characteristic, Area Under the Curve'],
  ['TI', 'Threat Intelligence'], ['OSINT', 'Open-Source Intelligence'], ['DShield', 'SANS Internet Storm Center’s distributed sensor network'], ['SANS ISC', 'SANS Internet Storm Center'],
  ['RBI', 'Reserve Bank of India'], ['SEBI', 'Securities and Exchange Board of India'], ['DPDP', 'Digital Personal Data Protection (Act, 2023)'],
  ['SIM', 'simulated data, labelled as such'], ['REAL', 'real public data'], ['RITA', 'Real Intelligence Threat Analytics (beacon analysis)'], ['SQLi', 'SQL injection'], ['XSS', 'Cross-Site Scripting'],
  ['SIEM', 'Security Information and Event Management'], ['EDR', 'Endpoint Detection and Response'], ['ISACA', 'Information Systems Audit and Control Association'],
  ['C-DAC', 'Centre for Development of Advanced Computing'], ['DJS', 'Dwarkadas J. Sanghvi College of Engineering'], 
  ['ESA', 'European Space Agency (Copernicus Sentinel-2 imagery)'], ['NIST', 'National Institute of Standards and Technology (US)'], ['CTI', 'Cyber Threat Intelligence'],
  
]

function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') }

/** The glossary entries whose short form appears in the text, in glossary order. */
function legendFor(text) {
  const out = []
  for (const [k, v] of GLOSSARY) {
    const re = new RegExp('(^|[^A-Za-z0-9])' + esc(k) + '(?![A-Za-z0-9])')
    if (re.test(text)) out.push(k + ': ' + v)
  }
  return out
}

module.exports = { GLOSSARY, legendFor }
