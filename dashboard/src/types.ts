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
