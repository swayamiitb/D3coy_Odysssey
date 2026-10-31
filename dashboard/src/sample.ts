// LAYOUT FIXTURES ONLY. Used when neither the Odyssey backend nor a saved snapshot is reachable, and the
// app shows a "Sample data" banner the whole time. Organisations and assets come from the lead's simulated
// world (backend/app/sim/world.py); headline counts reuse figures published in docs/PS_COVERAGE.md; anything
// else here is filler for layout. Run `npm run snapshot` against the real backend before any demo.
import type {
  AlertDetail, Approval, Attacks, AutoEvent, Brief, Campaign, Card, Feed, ForecastEval, ForecastItem, ForecastView, IntelAdvisory, IntelSource,
  Lead, OrgProfile, PortTrend, Replay, RiskPlan, Soc, Technology, Ticket, Tier, Workflow,
} from './types'

const ISSUED = '2026-10-31T10:30:00Z'

const wf = (alert_id: string, state: Workflow['state'] = 'new'): Workflow => ({
  alert_id, state, outcome: null, owner: state === 'new' ? null : 'analyst@ncew', issued_at: ISSUED, updated_at: ISSUED,
  next_action: { new: 'acknowledge', reopened: 'start', acknowledged: 'start', mitigating: 'verify', verifying: 'resolve', closed: null }[state],
  history: [],
})

const card = (org_id: string, org_name: string, sector: string, cve_id: string, title: string, tier: Tier, risk: number,
  deadline_hours: number | null, kev: boolean, state: Workflow['state'] = 'new', headline: string | null = null): Card => ({
  id: `${org_id}:${cve_id}`, org_id, org_name, sector, cve_id, risk, tier, assets: 1, deadline_hours, kev, kev_due: null,
  epss: null, ssvc: {}, published: '2026-10-13', disputed: false, title, headline, workflow: wf(`${org_id}:${cve_id}`, state),
})

const cards: Card[] = [
  card('PWR-01', 'Vidyut Grid West Corp', 'Power & Energy', 'CVE-2026-104935', 'Ivanti Connect Secure', 'Compromise', 100, 6, true, 'new',
    'Ivanti VPN gateway likely compromised: beaconing to a known C2 server'),
  card('PWR-02', 'Tapti Thermal Energy Ltd', 'Power & Energy', 'CVE-2026-104935', 'Ivanti Connect Secure', 'Critical', 96, 12, true, 'acknowledged'),
  card('PWR-01', 'Vidyut Grid West Corp', 'Power & Energy', 'CVE-SAMPLE-0001', 'Siemens WinCC', 'High', 71, 120, false),
  card('TEL-02', 'Tarang Fibre Networks', 'Telecom', 'CVE-SAMPLE-0002', 'Cisco ASA', 'Critical', 88, 24, true, 'mitigating'),
  card('TRN-02', 'Godavari Port Authority', 'Transport', 'CVE-SAMPLE-0003', 'Cisco Secure Email Gateway', 'High', 64, 120, false),
  card('GOV-01', 'Lokseva Digital Services Directorate', 'Government', 'CVE-SAMPLE-0004', 'Sample web framework', 'Medium', 43, 336, false, 'verifying'),
]

const feed: Feed = { issued_at: ISSUED, counts: { needs_action: 5, compromise: 1, closed: 0 }, cards }

const ORGS: [string, string, string, string, string][] = [
  ['PWR-01', 'Vidyut Grid West Corp', 'Power & Energy', 'Maharashtra', 'mr'],
  ['PWR-02', 'Tapti Thermal Energy Ltd', 'Power & Energy', 'Gujarat', 'gu'],
  ['PWR-03', 'Sahyadri Hydro Power Ltd', 'Power & Energy', 'Karnataka', 'kn'],
  ['BFS-01', 'Navnidhi Bank', 'BFSI', 'Maharashtra', 'mr'],
  ['BFS-02', 'Kshitij Finance & Insurance', 'BFSI', 'Tamil Nadu', 'ta'],
  ['BFS-03', 'Suvarnarekha Co-operative Bank', 'BFSI', 'Odisha', 'or'],
  ['TEL-01', 'Sanchar Link Telecom', 'Telecom', 'Delhi', 'hi'],
  ['TEL-02', 'Tarang Fibre Networks', 'Telecom', 'Telangana', 'te'],
  ['TRN-01', 'Indrayani Metro Rail Corp', 'Transport', 'Maharashtra', 'mr'],
  ['TRN-02', 'Godavari Port Authority', 'Transport', 'Andhra Pradesh', 'te'],
  ['TRN-03', 'Vayupath Airports Ltd', 'Transport', 'Kerala', 'ml'],
  ['GOV-01', 'Lokseva Digital Services Directorate', 'Government', 'Rajasthan', 'hi'],
  ['GOV-02', 'State Treasury Computing Centre', 'Government', 'West Bengal', 'bn'],
  ['SPE-01', 'Shakti Precision Defence Works', 'Strategic & Public Enterprises', 'Uttar Pradesh', 'hi'],
  ['SPE-02', 'Aryabhata Space Components Ltd', 'Strategic & Public Enterprises', 'Karnataka', 'kn'],
]

const pressure = Array.from({ length: 30 }, (_, i) => {
  const d = new Date(Date.UTC(2026, 9, 2 + i))
  const wave = i >= 11 ? 6 + Math.round((i - 11) * 0.6) : 2 + (i % 3)
  return { date: d.toISOString().slice(0, 10), Compromise: i >= 20 ? 1 : 0, Critical: wave, High: 12 + (i % 5) }
})

// Real-signals-only lead (4 CVEs, median 20.5 d, up to 42.4 d) is from docs/PS_COVERAGE.md. The rows are filler chosen so
// the backend's median rule (sorted[len // 2]) gives 20.5; the Ivanti row is the simulated decoy-grid lead of the replay.
const lead: Lead = {
  acted_before_kev: 5, median_lead_days: 11.7, max_lead_days: 42.4, kev_after_go_live: 7, acted_same_day: 1, not_acted: 1,
  real_signals_only: { acted_before_kev: 4, median_lead_days: 20.5, max_lead_days: 42.4 },
  rows: [
    { cve: 'CVE-SAMPLE-0021', kev: '2026-10-20T00:00:00Z', first_action: '2026-09-07T14:24:00Z', basis: 'day-0 exploitation forecast', provenance: 'REAL', lead_days: 42.4 },
    { cve: 'CVE-SAMPLE-0022', kev: '2026-10-22T00:00:00Z', first_action: '2026-10-01T12:00:00Z', basis: 'CISA SSVC: exploitation active', provenance: 'REAL', lead_days: 20.5 },
    { cve: 'CVE-2026-104935', kev: '2026-10-13T00:00:00Z', first_action: '2026-10-01T06:20:00Z', basis: 'decoy-grid scanning surge', provenance: 'SIM', lead_days: 11.7 },
    { cve: 'CVE-SAMPLE-0023', kev: '2026-10-16T00:00:00Z', first_action: '2026-10-05T00:00:00Z', basis: 'vendor advisory says exploited', provenance: 'REAL', lead_days: 11 },
    { cve: 'CVE-SAMPLE-0024', kev: '2026-10-25T00:00:00Z', first_action: '2026-10-20T00:00:00Z', basis: 'day-0 exploitation forecast', provenance: 'REAL', lead_days: 5 },
    { cve: 'CVE-SAMPLE-0025', kev: '2026-10-27T00:00:00Z', first_action: '2026-10-27T03:00:00Z', basis: 'Added to CISA KEV (now confirmed exploited)', provenance: 'REAL', lead_days: 0 },
    { cve: 'CVE-SAMPLE-0026', kev: '2026-10-29T00:00:00Z', first_action: null, basis: null, provenance: null, lead_days: null },
  ],
}

const soc: Soc = {
  built_at: ISSUED,
  tiers: { Compromise: 1, Critical: 12, High: 31, Medium: 40 },
  pressure,
  autopilot: { counts: {}, go_live: '2026-08-01', actions: 288, by_mode: { auto: 241, approve: 47 }, pending: 4, lead },
  pending: 4,
  risk: { total_risk: 0, tickets: 344, for_50_pct: 93, for_80_pct: 205, assets_at_risk: 0 },
  orgs: ORGS.map(([id, name, sector, state, lang], i) => ({ id, name, sector, state, lang, critical: [3, 2, 1, 1, 0, 1, 0, 2, 0, 1, 0, 1, 0, 0, 0][i], compromise: i === 0 ? 1 : 0 })),
}

const approval = (id: number, kind: string, title: string, orgs: string[], basis: string, p: number | null, langs: string[]): Approval => ({
  id, proposed_at: '2026-10-31T09:40:00Z', kind, subject: title, org_id: orgs[0] ?? null, title, status: 'pending',
  decided_by: null, decided_at: null, note: null, orgs, count: orgs.length, basis, provenance: p == null ? 'REAL' : 'AI', p,
  preview: [title], items: [], recipients: orgs.map((o) => `ciso@${o.toLowerCase()}.example`), langs,
})

const approvals: Approval[] = [
  approval(1, 'forecast.advisory', 'Pre-emptive advisory: sample CVE forecast as likely to be exploited', ['PWR-03', 'TRN-01'], 'Day-0 forecast', 0.41, ['kn', 'mr']),
  approval(2, 'escalation.certin', 'Escalate the Vidyut Grid compromise to CERT-In and CSIRT-Power', ['PWR-01'], 'Bayesian P(compromise) above threshold', null, ['en']),
  approval(3, 'surge.warning', 'Warn Ivanti operators: scanning surge on the decoy grid', ['PWR-01', 'PWR-02', 'BFS-01', 'TEL-01'], 'Decoy-grid surge (SIM)', null, ['mr', 'gu', 'hi']),
  approval(4, 'advisory.notice', 'Notify WinCC operators about a new CISA ICS advisory', ['PWR-01', 'PWR-03'], 'CISA ICS advisory', null, ['mr', 'kn']),
]

const events: AutoEvent[] = [
  { seq: 3, ts: '2026-10-31T10:31:00Z', kind: 'auto.notice', subject: 'PWR-02:CVE-2026-104935', source: 'SENTINEL', provenance: 'AUTO', payload: { title: 'Critical notice sent in Gujarati' } },
  { seq: 2, ts: '2026-10-31T10:30:30Z', kind: 'auto.hunt', subject: 'PWR-01:CVE-2026-104935', source: 'SENTINEL', provenance: 'AUTO', payload: { title: 'Peer hunt started at other Ivanti operators' } },
  { seq: 1, ts: '2026-10-31T10:30:00Z', kind: 'auto.report_draft', subject: 'PWR-01:CVE-2026-104935', source: 'SENTINEL', provenance: 'AUTO', payload: { title: 'CERT-In incident report drafted' } },
]

const detail: AlertDetail = {
  org: { id: 'PWR-01', name: 'Vidyut Grid West Corp', sector: 'Power & Energy', state: 'Maharashtra', domain: 'vgwc.example', cii: 1 },
  vulnerability: {
    id: 'CVE-2026-104935', published: '2026-10-13',
    description: 'Authentication bypass in Ivanti Connect Secure that can be chained to remote code execution.',
    kev: { dateAdded: '2026-10-13', dueDate: '2026-10-20', requiredAction: 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.', vulnerabilityName: 'Ivanti Connect Secure Authentication Bypass' },
    epss: null, ssvc: { Exploitation: 'active', Automatable: 'yes', 'Technical Impact': 'total' }, cvss_vector: null, cvss_source: 'CNA', nvd_status: 'Received',
  },
  assets: [{
    asset_id: 'PWR-01-vpn-gw01', hostname: 'vpn-gw01', ip: '203.0.113.10', zone: 'internet', role: 'vpn', label: 'Ivanti Connect Secure',
    version: '22.8R2.4', owner: 'IT infrastructure', asset_tier: 1, L: 1, S: 0.86, V: 0.9, R: 1, K: 1.2, risk: 100, tier: 'Compromise',
    decision: 'Act', decision_path: ['Exploitation: active', 'Exposure: internet', 'Automatable: yes', 'Mission impact: high'],
    rules: [
      { id: 'KEV', crit: 4, text: 'Listed in CISA Known Exploited Vulnerabilities', evidence: 'dateAdded 2026-10-13', source: 'CISA_KEV' },
      { id: 'SSVC_ACTIVE', crit: 4, text: 'CISA SSVC Exploitation = active', evidence: 'ADP container', source: 'CISA_ADP' },
      { id: 'DECOY_SURGE', crit: 2, text: 'Scanning surge for this product on the decoy grid', evidence: 'surge from 2026-10-01', source: 'DECOY_GRID' },
    ],
    contributions: { likelihood: 55, severity: 26, evidence: 14 }, deadline_hours: 6, deadline_basis: 'Suspected compromise: report to CERT-In within 6 hours (Directions, 28 Apr 2022)',
    kev_due: '2026-10-20', config_hash: 'sample', exposure: { status: 'affected', votes: [
      { source: 'CNA', verdict: 'affected', strength: 'strong', reason: 'version before 22.8R2.5', span: '22.8R2.4 < 22.8R2.5' },
      { source: 'TEXT', verdict: 'affected', strength: 'medium', reason: 'advisory text range', span: 'before 22.8R2.5' },
    ] },
    bayes: { p_compromise: 0.83, prior: 0.3, decision: 'compromised', factors: [
      { factor: 'Exploited, internet-facing', value: 0.3, detail: 'prior from config' },
      { factor: 'C2 beacon every 60 s', value: 350, detail: 'likelihood ratio TPR 0.7 / FPR 0.002' },
    ] },
  }],
  actions: [
    { type: 'contain', step: 'Isolate vpn-gw01 from the internal network and force re-authentication of all sessions', source: 'Hunt playbook' },
    { type: 'report', step: 'Send the CERT-In incident report within 6 hours', source: 'CERT-In Directions 2022', due: '6 h' },
    { type: 'patch', step: 'Upgrade Ivanti Connect Secure 22.8R2.4 to 22.8R2.5', source: 'Vendor advisory' },
    { type: 'block', step: 'Block the C2 address at the perimeter (STIX bundle)', source: 'Feodo Tracker' },
  ],
  timeline: [],
  attack: { techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', why: 'internet-facing VPN', tactics: ['Initial Access'], url: 'https://attack.mitre.org/techniques/T1190/' }],
    mitigations: [{ id: 'M1051', name: 'Update Software', covers: 1, description: 'Patch the gateway', url: 'https://attack.mitre.org/mitigations/M1051/' }], source: 'sample' },
  scoring_config_hash: 'sample',
}

const replay: Replay = {
  asset: { id: 'PWR-01-vpn-gw01', hostname: 'vpn-gw01', label: 'Ivanti Connect Secure', version: '22.8R2.4', zone: 'internet' },
  cve_id: 'CVE-2026-104935', published: '2026-10-13', lead_days_before_disclosure: 12,
  steps: [
    { ts: '2026-10-01T06:00:00Z', kind: 'decoy.surge', provenance: 'SIM', event: 'Scanning surge for Ivanti Connect Secure on the decoy grid', tier: 'Watch', risk: 22, decision: 'Track', deadline_hours: null, deadline_basis: '', rules: ['DECOY_SURGE'], stage: 'pre-disclosure' },
    { ts: '2026-10-13T09:00:00Z', kind: 'cve.published', provenance: 'REAL', event: 'Ivanti discloses the flaw; CISA adds it to KEV', tier: 'Critical', risk: 96, decision: 'Act', deadline_hours: 12, deadline_basis: 'KEV, internet-facing', rules: ['KEV', 'SSVC_ACTIVE'], stage: 'disclosure' },
    { ts: '2026-10-14T02:10:00Z', kind: 'telemetry.beacon', provenance: 'SIM', event: 'vpn-gw01 beacons every 60 s to a Feodo-listed C2 address', tier: 'Compromise', risk: 100, decision: 'Act', deadline_hours: 6, deadline_basis: 'Suspected compromise', rules: ['KEV', 'SSVC_ACTIVE'], stage: 'compromise' },
  ],
}

const brief: Brief = {
  status: 'validated', model: 'mist:8b', seconds: 0, cached: true, problems: [], facts: {},
  brief: {
    headline: 'Sample brief: the Ivanti VPN gateway at Vidyut Grid is likely compromised',
    why_it_matters: [{ text: 'The flaw is on CISA’s exploited list and the gateway faces the internet.', cites: ['F1', 'F2'] }],
    what_to_do: [{ text: 'Isolate the gateway, report to CERT-In within 6 hours, then upgrade to 22.8R2.5.', cites: ['F3'] }],
  },
}

// ---------------------------------------------------------------- intelligence layer
// Threat intel, Organisations, Risk plan, Ahead of the threat. Same rule as above: headline figures come from
// docs/PS_COVERAGE.md (13 sources, 82,104 → 2,277 CVEs, 30 → 8 advisories, 13 WinCC assets at 7 operators,
// 93 / 205 of 344 changes, forecast 2.0% flagged / 61.1% caught / CVSS 16.7% / precision 5% / base rate 0.16%,
// no elevated DShield port this week); every other number is round filler. Telemetry series are flat on purpose.

const DAY = 86400_000
const SNAP = Date.UTC(2026, 9, 30)
const lastDays = (n: number) => Array.from({ length: n }, (_, i) => new Date(SNAP - (n - 1 - i) * DAY).toISOString().slice(0, 10))

const trend = (port: number, service: string, ratio = 1): PortTrend => ({
  port, service, last7_mean: Math.round(1000 * ratio), baseline_median: 1000, ratio, elevated: ratio >= 1.5, sources_last7: 100,
  series: lastDays(42).map((date, i) => ({ date, records: Math.round((1000 + ((i % 7) - 3) * 20) * (i >= 35 ? ratio : 1)) })),
})
const TRENDS: Record<number, PortTrend> = {
  443: trend(443, 'HTTPS / SSL-VPN'), 10443: trend(10443, 'FortiGate SSL-VPN', 1.1), 25: trend(25, 'SMTP', 0.9),
  102: trend(102, 'Siemens S7 (ICS)'), 80: trend(80, 'HTTP', 0.95),
}

const SURGES = [
  { tag: 'ivanti_cs', first: '2026-10-01', last: '2026-10-05', z_sessions: 5, z_ips: 4, sensors: 6 },
  { tag: 'fortios', first: '2026-10-24', last: '2026-10-28', z_sessions: 4, z_ips: 3, sensors: 4 },
]
const attacks: Attacks = {
  dshield: { top_ports: [], top_sources: [], trends: Object.values(TRENDS) },
  decoy: {
    daily: lastDays(42).flatMap((date) => ['ivanti_cs', 'fortios', 'confluence', 'panos'].map((tag) => {
      const surge = SURGES.some((s) => s.tag === tag && date >= s.first && date <= s.last)
      return { date, tag, sessions: surge ? 400 : 100, unique_ips: surge ? 40 : 10 }
    })),
    surges: SURGES,
  },
}

const WINCC_ORGS = ['PWR-01', 'PWR-02', 'PWR-03', 'TRN-01', 'TRN-02', 'GOV-02', 'SPE-01']

const sources: IntelSource[] = ([
  ['NVD CVE feeds', 'vulnerabilities', 'REAL', 'A', 82104, 2277, 'CVEs published in 2026 -> candidates naming constituency products'],
  ['CISA KEV', 'confirmed exploitation', 'REAL', 'A', 1000, 100, 'exploited-in-the-wild catalogue -> affecting our products'],
  ['CISA Vulnrichment (SSVC)', 'exploitation status', 'REAL', 'A', 1000, 100, 'ADP records -> SSVC updates on candidates'],
  ['FIRST EPSS', 'exploit likelihood', 'REAL', 'B', null, 1000, 'daily scores -> scored candidates'],
  ['CISA advisories', 'advisories (ICS, alerts)', 'REAL', 'A', 30, 8, 'latest advisories -> naming our products or CVEs'],
  ['SANS ISC DShield', 'attack telemetry', 'REAL', 'B', 100000, 10, 'attack records on today\'s top ports -> ports our services expose (tracked daily)'],
  ['abuse.ch Feodo Tracker', 'C2 indicators', 'REAL', 'B', 1000, 1, 'botnet C2 IPs -> seen in our telemetry'],
  ['OpenPhish', 'phishing URLs', 'REAL', 'C', 1000, 0, 'live phishing URLs -> impersonating constituency domains'],
  ['MITRE ATT&CK', 'adversary techniques', 'REAL', 'A', null, null, 'techniques + mitigations used in mapping'],
  ['Odyssey day-0 forecast', 'prediction (model)', 'REAL', 'B', 10000, 200, 'new CVEs scored on publication day -> flagged likely-to-be-exploited'],
  ['National decoy grid', 'attack telemetry', 'SIM', 'C', 10000, 2, 'decoy sessions -> scanning surges detected'],
  ['Enterprise firewall logs', 'own telemetry', 'SIM', 'B', null, 1, 'outbound flows -> beacons to known C2'],
  ['CERT-In style advisories', 'advisories', 'SIM', 'B', null, null, 'sample national advisories for the AI analyser'],
] as const).map(([name, kind, provenance, reliability, items, relevant, funnel]) => ({ name, kind, provenance, reliability, items, relevant, funnel, updated: ISSUED }))

const tech = (label: string, vendor: string, product: string, product_key: string, n: number[], campaign: Technology['campaign'], port: number): Technology => {
  const [assets, orgs, internet_facing, critical, high, kev_cves, forecast_cves, compromised_assets, assets_at_risk] = n
  const t = TRENDS[port]
  return { label, vendor, product, product_key, assets, orgs, internet_facing, critical, high, kev_cves, forecast_cves, compromised_assets,
    assets_at_risk, campaign, attack_trend: { port, service: t.service, ratio: t.ratio } }
}
const technologies: Technology[] = [
  tech('Ivanti Connect Secure', 'ivanti', 'connect_secure', 'ivanti_cs', [6, 4, 6, 3, 1, 2, 0, 1, 5], 'ACTIVE', 443),
  tech('Cisco ASA', 'cisco', 'asa', 'cisco_asa', [4, 2, 4, 1, 0, 1, 0, 0, 2], 'ACTIVE', 443),
  tech('Siemens WinCC', 'siemens', 'wincc', 'siemens_wincc', [13, 7, 0, 0, 3, 0, 1, 0, 3], null, 102),
  tech('Fortinet FortiOS', 'fortinet', 'fortios', 'fortios', [4, 2, 4, 0, 1, 0, 1, 0, 1], 'EMERGING', 10443),
  tech('Cisco Secure Email Gateway', 'cisco', 'secure_email_gateway', 'cisco_esa', [3, 2, 3, 0, 1, 0, 0, 0, 1], null, 25),
  tech('Sample web framework', 'sample', 'web_framework', 'php', [2, 1, 2, 0, 0, 0, 0, 0, 1], null, 80),
]

const campaigns: Campaign[] = [
  { id: 'ivanti_cs', product_key: 'ivanti_cs', title: 'Exploitation of Ivanti Connect Secure', status: 'ACTIVE', first_signal: '2026-10-01', last_exploit: '2026-10-13',
    early_warning_days: 12, cves: [{ cve: 'CVE-2026-104935', date: '2026-10-13', name: 'Ivanti Connect Secure Authentication Bypass' }, { cve: 'CVE-2026-111357', date: '2026-10-13', name: 'Ivanti Connect Secure' }],
    decoy_surges: [{ tag: 'ivanti_cs', first: '2026-10-01', last: '2026-10-05', z_sessions: 5, sensors: 6 }], chains: [{ asset_id: 'PWR-01-vpn-gw01', cves: ['CVE-2026-104935', 'CVE-2026-111357'] }],
    orgs_exposed: ['PWR-01', 'PWR-02', 'BFS-01', 'TEL-01'], sectors_exposed: ['Power & Energy', 'BFSI', 'Telecom'], assets_exposed: 6, max_risk: 100 },
  { id: 'cisco_asa', product_key: 'cisco_asa', title: 'Exploitation of Cisco ASA', status: 'ACTIVE', first_signal: '2026-10-10', last_exploit: '2026-10-10',
    early_warning_days: 0, cves: [{ cve: 'CVE-SAMPLE-0002', date: '2026-10-10', name: 'Cisco ASA (sample entry)' }], decoy_surges: [], chains: [],
    orgs_exposed: ['TEL-02', 'TRN-01'], sectors_exposed: ['Telecom', 'Transport'], assets_exposed: 4, max_risk: 88 },
  { id: 'fortios', product_key: 'fortios', title: 'Reconnaissance of Fortinet FortiOS', status: 'EMERGING', first_signal: null, last_exploit: null,
    early_warning_days: 0, cves: [], decoy_surges: [{ tag: 'fortios', first: '2026-10-24', last: '2026-10-28', z_sessions: 4, sensors: 4 }], chains: [],
    orgs_exposed: ['BFS-02', 'TRN-03'], sectors_exposed: ['BFSI', 'Transport'], assets_exposed: 4, max_risk: 40 },
]

const advisories: IntelAdvisory[] = [
  { id: 'icsa-sample-01', title: 'Siemens WinCC (sample advisory)', link: 'https://www.cisa.gov/news-events/cybersecurity-advisories', kind: 'ics', published: '2026-10-28',
    cves: ['CVE-SAMPLE-0006'], summary: 'Sample ICS advisory text.', relevant: true, cves_in_odyssey: ['CVE-SAMPLE-0006'],
    matches: [{ product: 'Siemens WinCC', product_key: 'siemens_wincc', assets: 13, orgs: 7, org_ids: WINCC_ORGS }] },
  { id: 'kev-sample-01', title: 'CISA adds one sample vulnerability to the KEV catalog', link: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', kind: 'kev', published: '2026-10-10',
    cves: ['CVE-SAMPLE-0002'], summary: 'Sample KEV alert.', relevant: true, cves_in_odyssey: ['CVE-SAMPLE-0002'], matches: [] },
  { id: 'icsa-sample-02', title: 'Sample PLC vendor (sample advisory, not in our inventory)', link: 'https://www.cisa.gov/news-events/cybersecurity-advisories', kind: 'ics', published: '2026-10-24',
    cves: [], summary: 'Sample.', relevant: false, cves_in_odyssey: [], matches: [] },
]

// Risk plan. National milestones (93 / 205 of 344) are from PS_COVERAGE; the curve shape and every ticket are filler.
const METHOD = 'asset risk = worst open path; one ticket per (organisation, product, installed version); urgency class first, then risk removed per unit of effort'
const curveAt = (k: number) => Math.round(1000 * (1 - Math.exp(-k / 134))) / 10
const orgName = Object.fromEntries(ORGS.map(([id, name]) => [id, name]))
type T = [string, string, string, string, string | null, string[], string, string, string[], number, Tier, number | null]
const TICKETS: T[] = [
  ['PWR-01', 'Ivanti Connect Secure', 'ivanti:connect_secure', '22.8R2.4', '22.8R2.5', ['vpn-gw01'], 'internet', 'IT infrastructure', ['CVE-2026-104935', 'CVE-2026-111357'], 2, 'Compromise', 6],
  ['PWR-02', 'Ivanti Connect Secure', 'ivanti:connect_secure', '22.8R2.4', '22.8R2.5', ['vpn-gw01'], 'internet', 'Network team', ['CVE-2026-104935'], 1, 'Critical', 12],
  ['TEL-02', 'Cisco ASA', 'cisco:asa', '1.0-sample', '1.1-sample', ['fw-edge01', 'fw-edge02'], 'internet', 'Network operations', ['CVE-SAMPLE-0002'], 1, 'Critical', 24],
  ['BFS-01', 'Ivanti Connect Secure', 'ivanti:connect_secure', '22.8R2.4', '22.8R2.5', ['vpn01'], 'internet', 'IT security', ['CVE-2026-104935'], 1, 'Critical', 24],
  ['TEL-01', 'Ivanti Connect Secure', 'ivanti:connect_secure', '22.8R2.4', '22.8R2.5', ['sslvpn01'], 'internet', 'Network team', ['CVE-2026-104935'], 1, 'High', 72],
  ['PWR-01', 'Siemens WinCC', 'siemens:wincc', '1.0-sample', null, ['scada-hmi01'], 'ot', 'OT engineering', ['CVE-SAMPLE-0001', 'CVE-SAMPLE-0006'], 0, 'High', 120],
  ['TRN-02', 'Cisco Secure Email Gateway', 'cisco:secure_email_gateway', '1.0-sample', '1.1-sample', ['mail-gw01'], 'dmz', 'Messaging', ['CVE-SAMPLE-0003'], 0, 'High', 120],
  ['PWR-03', 'Siemens WinCC', 'siemens:wincc', '1.0-sample', null, ['hmi02'], 'ot', 'OT engineering', ['CVE-SAMPLE-0006'], 0, 'High', 120],
  ['BFS-02', 'Fortinet FortiOS', 'fortinet:fortios', '1.0-sample', '1.1-sample', ['fw01'], 'internet', 'Network team', ['CVE-SAMPLE-0011'], 0, 'High', 120],
  ['GOV-01', 'Sample web framework', 'sample:web_framework', '1.0-sample', '1.1-sample', ['portal01', 'portal02'], 'dmz', 'Web team', ['CVE-SAMPLE-0004'], 0, 'Medium', 336],
  ['TRN-03', 'Fortinet FortiOS', 'fortinet:fortios', '1.0-sample', '1.1-sample', ['fw02'], 'internet', 'IT infrastructure', ['CVE-SAMPLE-0011'], 0, 'Medium', 336],
  ['GOV-02', 'Siemens WinCC', 'siemens:wincc', '1.0-sample', null, ['hmi01'], 'ot', 'OT engineering', ['CVE-SAMPLE-0006'], 0, 'Medium', 336],
]
const NATIONAL_TOTAL = 10000
const national: Ticket[] = TICKETS.map(([org_id, label, product, version, target_version, assets, zone, owner, cves, kev_cves, top_tier, deadline_hours], i) => {
  const pct = Math.round((curveAt(i + 1) - curveAt(i)) * 100) / 100
  return {
    rank: i + 1, org_id, org: orgName[org_id], label, product, version, target_version, fix_coverage: target_version ? `${cves.length}/${cves.length}` : `0/${cves.length}`,
    assets, n_assets: assets.length, zones: [zone], owners: [owner], cves, n_cves: cves.length, kev_cves, top_tier, deadline_hours,
    effort: 1 + 0.25 * (assets.length - 1), risk_removed: Math.round(pct * NATIONAL_TOTAL) / 100, pct, cum_pct: curveAt(i + 1),
  }
})
const riskNational: RiskPlan = {
  scope: 'national', total_risk: NATIONAL_TOTAL, accepted_risk: 0, assets_at_risk: 400, tickets: 344, for_50_pct: 93, for_80_pct: 205,
  curve: Array.from({ length: 61 }, (_, k) => ({ k, cum_pct: curveAt(k) })), plan: national, method: METHOD,
}
function riskFor(id: string): RiskPlan {
  const mine = national.filter((t) => t.org_id === id)
  const total = mine.reduce((s, t) => s + t.risk_removed, 0)
  let cum = 0
  const plan = mine.map((t, i) => {
    const pct = total ? Math.round((10000 * t.risk_removed) / total) / 100 : 0
    cum += pct
    return { ...t, rank: i + 1, pct, cum_pct: Math.min(100, Math.round(cum * 10) / 10) }
  })
  const needed = (share: number) => plan.find((t) => t.cum_pct >= share)?.rank ?? null
  return {
    scope: id, total_risk: Math.round(total * 10) / 10, accepted_risk: 0, assets_at_risk: plan.reduce((s, t) => s + t.n_assets, 0), tickets: plan.length,
    for_50_pct: needed(50), for_80_pct: needed(80), curve: [{ k: 0, cum_pct: 0 }, ...plan.map((t) => ({ k: t.rank, cum_pct: t.cum_pct }))], plan, method: METHOD,
  }
}

// Organisation profiles: built from the sample orgs, tickets and cards above.
const CSIRT: Record<string, string> = {
  'Power & Energy': 'CSIRT-Power', BFSI: 'CSIRT-Fin', Telecom: 'CSIRT-Telecom', Transport: 'CSIRT-Transport',
  Government: 'CERT-In (Govt.)', 'Strategic & Public Enterprises': 'NCIIPC',
}
const PORTS: Record<string, number[]> = {
  'Ivanti Connect Secure': [443], 'Cisco ASA': [443], 'Fortinet FortiOS': [443, 10443], 'Siemens WinCC': [102],
  'Cisco Secure Email Gateway': [25], 'Sample web framework': [80, 443], nginx: [80, 443],
}
const WORST: Record<Tier, number> = { Compromise: 4, Critical: 3, High: 2, Medium: 1, Watch: 0 }

function profile(i: number): OrgProfile {
  const [id, name, sector, state, lang] = ORGS[i]
  const o = soc.orgs[i]
  const plan = riskFor(id)
  const exposed = [
    ...plan.plan.filter((t) => t.zones.some((z) => z === 'internet' || z === 'dmz')).flatMap((t) => t.assets.map((hostname) => ({
      hostname, product: t.label, version: t.version, zone: t.zones[0], open_high: WORST[t.top_tier] >= 2 ? t.n_cves : 0, worst: WORST[t.top_tier],
      ports: PORTS[t.label] ?? [],
    }))),
    { hostname: 'www01', product: 'nginx', version: '1.0-sample', zone: 'internet', open_high: 0, worst: 0, ports: PORTS.nginx },
  ]
  const ports = [...new Set(exposed.flatMap((e) => e.ports))].sort((a, b) => a - b)
  const wincc = WINCC_ORGS.includes(id)
  const events: AutoEvent[] = id === 'PWR-01'
    ? [
        { seq: 13, ts: '2026-10-31T10:31:00Z', kind: 'auto.report', subject: 'PWR-01:CVE-2026-104935', source: 'SENTINEL', provenance: 'AUTO', payload: { org_id: id, lang, title: 'CERT-In incident report drafted for the Ivanti compromise' } },
        { seq: 12, ts: '2026-10-31T10:30:40Z', kind: 'auto.notify', subject: 'PWR-01:CVE-2026-104935', source: 'SENTINEL', provenance: 'AUTO', payload: { org_id: id, lang, title: 'Compromise notice: isolate vpn-gw01 and report to CERT-In within 6 hours' } },
        { seq: 11, ts: '2026-10-01T06:20:00Z', kind: 'auto.warn', subject: 'ivanti_cs', source: 'SENTINEL', provenance: 'SIM', payload: { org_id: id, lang, title: 'Early warning: scanning surge for Ivanti Connect Secure on the decoy grid' } },
      ]
    : [{ seq: 100 + i, ts: '2026-10-31T03:30:00Z', kind: 'auto.digest', subject: id, source: 'SENTINEL', provenance: 'AUTO', payload: { org_id: id, lang, title: 'Daily digest of open warnings' } }]
  return {
    org: { id, name, sector, state, domain: id === 'PWR-01' ? 'vgwc.example' : `${id.toLowerCase()}.example`, cii: ['Power & Energy', 'BFSI', 'Telecom', 'Transport'].includes(sector) ? 1 : 0 },
    language: lang, csirt: CSIRT[sector],
    tiers: { Compromise: o.compromise, Critical: Math.max(0, o.critical - o.compromise), High: 2, Medium: 3 },
    surface: { assets: 20, internet: exposed.filter((e) => e.zone === 'internet').length, dmz: exposed.filter((e) => e.zone === 'dmz').length, exposed },
    attack_activity: ports.filter((p) => TRENDS[p]).map((p) => ({ ...TRENDS[p], hosts: exposed.filter((e) => e.ports.includes(p)).map((e) => e.hostname) })),
    advisories: wincc ? [{ id: advisories[0].id, title: advisories[0].title, link: advisories[0].link, published: advisories[0].published, kind: 'ics', cves: advisories[0].cves }] : [],
    indicators: {
      c2_sightings: id === 'PWR-01' ? [{ ts: '2026-10-14T02:10:00Z', asset: 'PWR-01-vpn-gw01', c2: '198.51.100[.]23', malware: 'sample family' }] : [],
      own_ips_on_feodo: [], own_ips_in_dshield_top: [], feodo_c2: 1000, dshield_sources: 100,
    },
    impersonation: { domain: id === 'PWR-01' ? 'vgwc.example' : `${id.toLowerCase()}.example`, variants_checked: 100, found: [], brand_hits: [], phishing_hosts_scanned: 1000 },
    alerts: cards.filter((c) => c.org_id === id),
    risk: plan,
    inbox: events,
  }
}

// Day-0 forecast. Flag rate, recall, CVSS recall, precision and base rate are from PS_COVERAGE (10,000 CVEs and
// 16 exploited are round numbers chosen to match the 0.16% base rate); EPSS recall, AUC and the test period are filler.
const evalOf = (period: string, recall: number, cvss: number, epss: number): ForecastEval => ({
  period, cves: 10000, exploited: 16, base_rate_pct: 0.16, average_precision: 0.1, roc_auc: 0.9,
  odyssey: { flagged: 200, flag_rate_pct: 2.0, caught: 10, positives: 16, recall_pct: recall, precision_pct: 5 },
  baseline_cvss9: { flag_rate_pct: 10, recall_pct: 50 }, epss_today_hindsight: { flag_rate_pct: 2.0, recall_pct: epss },
  same_budget_recall_pct: { odyssey: recall, cvss, epss_today: epss },
  lead_days: { median: 10, mean: 10, ge_1_day_pct: 50, ge_7_days_pct: 50 }, calibration: [],
})
const fc = (cve: string, published: string, product: string, p: number, reasons: string[], median_days_to_exploit: number | null,
  org_ids: string[], assets: number, kev_added: string | null): ForecastItem => ({
  cve, published, product, p, reasons, median_days_to_exploit, orgs: org_ids.length, assets, org_ids, kev_added,
  description: `Sample description for ${product}.`,
})
const forecast: ForecastView = {
  since: '2026-09-16', flagged: 5, since_exploited: 3, lead,
  items: [
    fc('CVE-SAMPLE-0011', '2026-10-27', 'Fortinet FortiOS', 0.05, ['network-reachable without authentication', 'vendor has a history of exploited flaws'], 7, ['BFS-02', 'TRN-03'], 2, null),
    fc('CVE-SAMPLE-0012', '2026-10-20', 'Siemens WinCC', 0.04, ['remote code execution', 'ICS product'], 14, WINCC_ORGS, 13, null),
    fc('CVE-SAMPLE-0013', '2026-10-09', 'Cisco ASA', 0.05, ['network-reachable without authentication', 'edge device'], 7, ['TEL-02', 'TRN-01'], 4, '2026-10-13'),
    fc('CVE-SAMPLE-0014', '2026-10-02', 'Cisco Secure Email Gateway', 0.04, ['remote code execution', 'edge device'], 14, ['TRN-02'], 1, '2026-10-11'),
    fc('CVE-SAMPLE-0015', '2026-09-24', 'Ivanti Connect Secure', 0.06, ['vendor has a history of exploited flaws', 'edge device'], 7, ['PWR-01', 'PWR-02', 'BFS-01', 'TEL-01'], 6, '2026-10-08'),
  ],
  model: {
    threshold: 0.02, features: 'only what is known on publication day: no KEV, SSVC, EPSS or exploit references',
    live: evalOf('Aug–Oct 2026', 61.1, 16.7, 50), test: evalOf('Jan–Jul 2026', 50, 10, 50),
  },
}

const intelSample: Record<string, unknown> = {
  '/api/intel/sources': sources,
  '/api/intel/advisories': advisories,
  '/api/intel/technologies': technologies,
  '/api/intel/attacks': attacks,
  '/api/campaigns': campaigns,
  '/api/riskplan': riskNational,
  '/api/forecast': forecast,
  ...Object.fromEntries(ORGS.flatMap(([id], i) => [[`/api/orgs/${id}/profile`, profile(i)], [`/api/riskplan?org_id=${id}`, riskFor(id)]])),
}

export const SAMPLE: Record<string, unknown> = {
  ...intelSample,
  '/api/health': { status: 'ok', ledger_intact: true, models: { narrate: 'mist:8b', reason: 'foundation-sec:8b-reasoning' }, scoring_config_hash: 'sample' },
  '/api/soc': soc,
  '/api/feed': feed,
  '/api/approvals': approvals,
  '/api/autopilot': { summary: soc.autopilot, events },
  '/api/alerts/PWR-01/CVE-2026-104935': detail,
  '/api/replay/PWR-01/CVE-2026-104935': replay,
  '/api/alerts/PWR-01/CVE-2026-104935/brief': brief,
  '/api/alerts/PWR-01/CVE-2026-104935/workflow': wf('PWR-01:CVE-2026-104935'),
}
