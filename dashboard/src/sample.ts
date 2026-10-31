// LAYOUT FIXTURES ONLY. Used when neither the Odyssey backend nor a saved snapshot is reachable, and the
// app shows a "Sample data" banner the whole time. Organisations and assets come from the lead's simulated
// world (backend/app/sim/world.py); headline counts reuse figures published in docs/PS_COVERAGE.md; anything
// else here is filler for layout. Run `npm run snapshot` against the real backend before any demo.
import type { AlertDetail, Approval, AutoEvent, Brief, Card, Feed, Replay, Soc, Tier, Workflow } from './types'

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

const soc: Soc = {
  built_at: ISSUED,
  tiers: { Compromise: 1, Critical: 12, High: 31, Medium: 40 },
  pressure,
  autopilot: {
    counts: {}, go_live: '2026-08-01', actions: 288, by_mode: { auto: 241, approve: 47 }, pending: 4,
    lead: { acted_before_kev: 4, median_lead_days: 20.5, max_lead_days: 42.4, kev_after_go_live: 0, acted_same_day: 0, not_acted: 0,
      real_signals_only: { acted_before_kev: 4, median_lead_days: 20.5, max_lead_days: 42.4 }, rows: [] },
  },
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

export const SAMPLE: Record<string, unknown> = {
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
