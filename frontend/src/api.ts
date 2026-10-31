export type Tier = 'Compromise' | 'Critical' | 'High' | 'Medium' | 'Watch'

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

export interface Summary {
  snapshot_date: string
  funnel: {
    cves_published_this_month: number
    candidate_cves: number
    exposed_asset_cve_pairs: number
    actionable_alerts: number
    critical_alerts: number
    suspected_compromise: number
  }
  alerts_by_tier: Partial<Record<Tier, number>>
  sector_heatmap: Record<string, Partial<Record<Tier, number>>>
  orgs_exposed: number
  top_alerts: AlertRow[]
  epss_model: string
}

export interface Rule { id: string; crit: number; text: string; evidence: string; source: string }
export interface Vote { source: string; verdict: string; strength: string; reason: string; span: string }

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
  bayes?: import('./DecisionPanel').Bayes
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
  attack?: import('./AttackPanel').AttackMap | null
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

export interface Workflow {
  alert_id: string
  state: 'new' | 'acknowledged' | 'mitigating' | 'verifying' | 'closed' | 'reopened'
  outcome: string | null
  owner: string | null
  issued_at: string
  updated_at: string
  next_action: string | null
  history?: { ts: string; kind: string; payload: { actor: string; from: string; to: string; note: string | null } }[]
}
export interface Card extends AlertRow { headline: string | null; workflow: Workflow }
export interface Feed { issued_at: string; counts: { needs_action: number; compromise: number; closed: number }; cards: Card[] }
export interface LedgerEvent { seq: number; ts: string; kind: string; subject: string; source: string; provenance: string }

export interface TranslatedLine { source: string; text: string | null; status: 'validated' | 'withheld'; problems: string[] }
export interface Translation {
  lang: 'hi' | 'mr'
  model: string
  seconds: number
  headline: TranslatedLine
  why_it_matters: TranslatedLine[]
  what_to_do: TranslatedLine[]
  validated: number
  total: number
  cached: boolean
}

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

export interface Health {
  status: string
  ledger_intact: boolean
  models: Record<string, string>
  scoring_config_hash: string
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) throw new Error(`${res.status} ${path}`)
  return res.json() as Promise<T>
}

export const api = {
  health: () => get<Health>('/api/health'),
  summary: () => get<Summary>('/api/summary'),
  alerts: (q: { tier?: string; sector?: string } = {}) => {
    const params = new URLSearchParams(Object.entries(q).filter(([, v]) => v) as [string, string][])
    return get<AlertRow[]>(`/api/alerts?limit=400&${params}`)
  },
  alert: (orgId: string, cveId: string) => get<AlertDetail>(`/api/alerts/${orgId}/${cveId}`),
  brief: (orgId: string, cveId: string) => get<Brief>(`/api/alerts/${orgId}/${cveId}/brief`),
  replay: (orgId: string, cveId: string) => get<Replay>(`/api/replay/${orgId}/${cveId}`),
  feed: () => get<Feed>('/api/feed'),
  campaigns: () => get<Campaign[]>('/api/campaigns'),
  translate: (orgId: string, cveId: string, lang: 'hi' | 'mr') =>
    get<Translation>(`/api/alerts/${orgId}/${cveId}/brief/translate?lang=${lang}`),
  recent: () => get<LedgerEvent[]>('/api/events/recent?limit=25'),
  act: async (orgId: string, cveId: string, action: string) => {
    const res = await fetch(`/api/alerts/${orgId}/${cveId}/workflow/${action}`, { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json() as Promise<Workflow>
  },
}
