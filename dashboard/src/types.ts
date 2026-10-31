// Response shapes of the Odyssey API, copied from the lead's frontend/src/api.ts
// (swayamiitb/D3coy_Odysssey @ 9b4bd37). Keep in sync when that file changes: this is our contract.

export type Tier = 'Compromise' | 'Critical' | 'High' | 'Medium' | 'Watch'
export type Provenance = 'REAL' | 'SIM' | 'AI' | 'HUMAN' | 'AUTO'

export interface AlertRow {
  id: string
  org_id: string
  org_name: string
  sector: string
  cve_id: string
  risk: number
  tier: Tier
  assets: number
  deadline_hours: number | null
  kev: boolean
  kev_due: string | null
  epss: number | null
  ssvc: Record<string, string>
  published: string | null
  disputed: boolean
  title: string
}

export interface Rule { id: string; crit: number; text: string; evidence: string; source: string }
export interface Vote { source: string; verdict: string; strength: string; reason: string; span: string }

export interface Bayes {
  p_compromise: number
  prior: number
  decision: 'compromised' | 'hunt' | 'no evidence of compromise'
  factors: { factor: string; value: number; detail: string }[]
}

export interface AttackMap {
  techniques: { id: string; name: string; why: string; tactics: string[]; url: string }[]
  mitigations: { id: string; name: string; covers: number; description: string; url: string }[]
  source: string
}

export interface AssetAssessment {
  asset_id: string
  hostname: string
  ip: string
  zone: string
  role: string
  label: string
  version: string
  owner: string
  asset_tier: number
  L: number
  S: number
  V: number
  R: number
  K: number
  risk: number
  tier: Tier
  decision: string
  decision_path: string[]
  rules: Rule[]
  contributions: { likelihood: number; severity: number; evidence: number }
  deadline_hours: number | null
  deadline_basis: string
  kev_due: string | null
  config_hash: string
  exposure: { status: string; votes: Vote[] }
  bayes?: Bayes
}

export interface AlertDetail {
  org: { id: string; name: string; sector: string; state: string; domain: string; cii: number }
  vulnerability: {
    id: string
    published: string
    description: string
    kev: { dateAdded: string; dueDate: string; requiredAction: string; vulnerabilityName: string } | null
    epss: number | null
    ssvc: Record<string, string>
    cvss_vector: string | null
    cvss_source: string | null
    nvd_status: string | null
  }
  assets: AssetAssessment[]
  actions: { type: string; step: string; source: string; due?: string }[]
  timeline: { seq: number; ts: string; kind: string; source: string; provenance: string; hash: string }[]
  attack?: AttackMap | null
  scoring_config_hash: string
}

export interface BriefBullet { text: string; cites: string[] }
export interface Brief {
  status: 'validated' | 'withheld'
  model: string
  brief: { headline: string; why_it_matters: BriefBullet[]; what_to_do: BriefBullet[] } | null
  problems: string[]
  facts: Record<string, string>
  seconds: number
  cached: boolean
  ledger_hash?: string
}

export interface ReplayStep {
  ts: string
  kind: string
  provenance: 'REAL' | 'SIM'
  event: string
  tier: Tier
  risk: number
  decision: string
  deadline_hours: number | null
  deadline_basis: string
  rules: string[]
  stage: string
}
export interface Replay {
  asset: { id: string; hostname: string; label: string; version: string; zone: string }
  cve_id: string
  published: string
  steps: ReplayStep[]
  lead_days_before_disclosure: number | null
}

export type WorkflowState = 'new' | 'acknowledged' | 'mitigating' | 'verifying' | 'closed' | 'reopened'
export interface Workflow {
  alert_id: string
  state: WorkflowState
  outcome: string | null
  owner: string | null
  issued_at: string
  updated_at: string
  next_action: string | null
  history?: { ts: string; kind: string; payload: { actor: string; from: string; to: string; note: string | null } }[]
}
export interface Card extends AlertRow { headline: string | null; workflow: Workflow }
export interface Feed { issued_at: string; counts: { needs_action: number; compromise: number; closed: number }; cards: Card[] }

export interface Health {
  status: string
  ledger_intact: boolean
  models: Record<string, string>
  scoring_config_hash: string
}

export interface AutoEvent {
  seq: number
  ts: string
  kind: string
  subject: string
  source: string
  provenance: Provenance
  payload: Record<string, unknown>
}

export interface LeadRow { cve: string; kev: string; first_action: string | null; basis: string | null; provenance: string | null; lead_days: number | null }
export interface LeadStats { acted_before_kev: number; median_lead_days: number | null; max_lead_days: number | null }
export interface Lead extends LeadStats {
  kev_after_go_live: number
  acted_same_day: number
  known_at_go_live?: number
  not_acted: number
  real_signals_only: LeadStats
  rows: LeadRow[]
}

export interface AutopilotSummary {
  counts: Record<string, number>
  go_live?: string
  actions?: number
  by_kind?: Record<string, number>
  by_mode?: { auto: number; approve: number }
  languages?: string[]
  pending?: number
  lead?: Lead
}

export interface Approval {
  id: number
  proposed_at: string
  kind: string
  subject: string
  org_id: string | null
  title: string
  status: 'pending' | 'approved' | 'rejected' | 'superseded'
  decided_by: string | null
  decided_at: string | null
  note: string | null
  orgs: string[]
  count: number
  basis: string | null
  provenance: string | null
  p: number | null
  preview: string[]
  items: { cve: string; asset: string; tier?: string; due?: string }[]
  recipients: string[]
  langs: string[]
}

export interface Soc {
  built_at: string
  tiers: Partial<Record<Tier, number>>
  pressure: { date: string; Compromise: number; Critical: number; High: number }[]
  autopilot: AutopilotSummary
  pending: number
  risk: { total_risk: number; tickets: number; for_50_pct: number | null; for_80_pct: number | null; assets_at_risk: number }
  orgs: { id: string; name: string; sector: string; state: string; critical: number; compromise: number; lang: string }[]
}

// Intelligence layer: threat intel, organisations, risk plan and the day-0 forecast. Copied from the same
// api.ts (swayamiitb/D3coy_Odysssey @ 9b4bd37). Lead, LeadRow and LeadStats are defined above.

export interface Campaign {
  id: string
  product_key: string
  title: string
  status: 'ACTIVE' | 'EMERGING' | 'DORMANT'
  first_signal: string | null
  last_exploit: string | null
  early_warning_days: number
  cves: { cve: string; date: string; name: string }[]
  decoy_surges: { tag: string; first: string; last: string; z_sessions: number; sensors: number }[]
  chains: { asset_id: string; cves: string[] }[]
  orgs_exposed: string[]
  sectors_exposed: string[]
  assets_exposed: number
  max_risk: number
}

export interface ForecastItem {
  cve: string
  published: string
  product: string | null
  p: number
  reasons: string[]
  median_days_to_exploit: number | null
  orgs: number
  assets: number
  org_ids: string[]
  description: string
  kev_added: string | null
}

export interface ForecastEval {
  period: string
  cves: number
  exploited: number
  base_rate_pct: number
  average_precision: number
  roc_auc: number
  odyssey: { flagged: number; flag_rate_pct: number; caught: number; positives: number; recall_pct: number; precision_pct: number }
  baseline_cvss9: { flag_rate_pct: number; recall_pct: number }
  epss_today_hindsight: { flag_rate_pct: number; recall_pct: number }
  same_budget_recall_pct: { odyssey: number; cvss: number; epss_today: number }
  lead_days?: { median: number; mean: number; ge_1_day_pct: number; ge_7_days_pct: number }
  calibration: { bin: string; n: number; mean_forecast: number; observed: number }[]
}

export interface ForecastView {
  since: string
  flagged: number
  since_exploited: number
  items: ForecastItem[]
  lead: Lead | null
  model: { threshold: number; features: string; live: ForecastEval; test: ForecastEval }
}

export interface Ticket {
  rank: number
  org_id: string
  org: string
  label: string
  product: string
  version: string
  target_version: string | null
  fix_coverage: string
  assets: string[]
  n_assets: number
  zones: string[]
  owners: string[]
  cves: string[]
  n_cves: number
  kev_cves: number
  top_tier: Tier
  deadline_hours: number | null
  effort: number
  risk_removed: number
  pct: number
  cum_pct: number
}

export interface RiskPlan {
  scope: string
  total_risk: number
  accepted_risk: number
  assets_at_risk: number
  tickets: number
  for_50_pct: number | null
  for_80_pct: number | null
  curve: { k: number; cum_pct: number }[]
  plan: Ticket[]
  method: string
}

export interface IntelSource {
  name: string
  kind: string
  provenance: 'REAL' | 'SIM'
  reliability: string | null
  items: number | null
  relevant: number | null
  funnel: string
  updated: string | null
}

export interface IntelAdvisory {
  id: string
  title: string
  link: string
  kind: 'ics' | 'kev' | 'other'
  published: string | null
  cves: string[]
  summary: string
  matches: { product: string; product_key: string; assets: number; orgs: number; org_ids: string[] }[]
  relevant: boolean
  cves_in_odyssey: string[]
}

export interface PortTrend {
  port: number
  service: string
  last7_mean: number
  baseline_median: number
  ratio: number
  elevated: boolean
  sources_last7: number
  series: { date: string; records: number }[]
  hosts?: string[]
}

export interface Attacks {
  dshield: {
    top_ports: { rank: number; targetport: number; records: number; targets: number; sources: number }[]
    top_sources: { ip: string; attacks: number; count: number; firstseen: string; lastseen: string }[]
    trends: PortTrend[]
  }
  decoy: {
    daily: { date: string; tag: string; sessions: number; unique_ips: number }[]
    surges: { tag: string; first: string; last: string; z_sessions: number; z_ips: number; sensors: number }[]
  }
}

export interface OrgProfile {
  org: { id: string; name: string; sector: string; state: string; domain: string; cii: number }
  language: string
  csirt: string
  tiers: Partial<Record<Tier, number>>
  surface: {
    assets: number
    internet: number
    dmz: number
    exposed: { hostname: string; product: string; version: string; zone: string; open_high: number; worst: number; ports: number[] }[]
  }
  attack_activity: PortTrend[]
  advisories: { id: string; title: string; link: string; published: string | null; kind: string; cves: string[] }[]
  indicators: {
    c2_sightings: { ts: string; asset: string; c2: string; malware: string }[]
    own_ips_on_feodo: string[]
    own_ips_in_dshield_top: string[]
    feodo_c2: number
    dshield_sources: number
  }
  impersonation: { domain: string; variants_checked: number; found: string[]; brand_hits: string[]; phishing_hosts_scanned: number }
  alerts: AlertRow[]
  risk: RiskPlan
  inbox: AutoEvent[]
}

export interface Technology {
  label: string
  vendor: string
  product: string
  product_key: string
  assets: number
  orgs: number
  internet_facing: number
  critical: number
  high: number
  kev_cves: number
  forecast_cves: number
  compromised_assets: number
  assets_at_risk: number
  campaign: 'ACTIVE' | 'EMERGING' | 'DORMANT' | null
  attack_trend: { port: number; service: string; ratio: number } | null
}
