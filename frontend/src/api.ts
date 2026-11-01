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
export interface Language { code: string; tag: string; name: string; native: string; script: string; rtl: boolean }
export interface Translation {
  lang: string
  rtl: boolean
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

// ---------------------------------------------------------------- proactive layer
export type Provenance = 'REAL' | 'SIM' | 'AI' | 'HUMAN' | 'AUTO'

export interface AutoEvent {
  seq: number
  ts: string
  kind: string
  subject: string
  source: string
  provenance: Provenance
  payload: Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
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

export interface Soc {
  built_at: string
  tiers: Partial<Record<Tier, number>>
  pressure: { date: string; Compromise: number; Critical: number; High: number }[]
  autopilot: AutopilotSummary
  pending: number
  risk: { total_risk: number; tickets: number; for_50_pct: number | null; for_80_pct: number | null; assets_at_risk: number }
  orgs: { id: string; name: string; sector: string; state: string; critical: number; compromise: number; lang: string }[]
}

// --- HTTP shield: a real connected app, protected and red-teamed ---------------------------------------------
export interface NotifyChannel {
  name: string; type: 'slack' | 'discord' | 'teams' | 'webhook' | 'email'; enabled: boolean; configured: boolean
  destination: string | null; about: string | null; status: 'idle' | 'ok' | 'failing'; sent: number; failed: number
  last_ok: string | null; last_error: string | null; backing_off: boolean
}
export interface NotifyDelivery {
  ts: string; channel: string; type: string; destination: string; kind: string; subject: string; severity: string
  title: string; ok: boolean; ms: number; error: string | null; test: boolean; summary: boolean
}
export interface NotifyStatus {
  running: boolean; started: string; cursor: number; public_url: string | null; channels: NotifyChannel[]
  routing: { min_severity: string; kinds: string[]; dedupe_minutes: number; per_minute_cap: number }
  stats: { sent: number; failed: number; configured: number; live: number; duplicates_suppressed: number; held_by_cap: number }
  recent: NotifyDelivery[]; console_url: string | null
}
export interface ShieldApp {
  id: string; name: string; base_url: string | null; mode: 'monitor' | 'block'
  agent_mode: string | null; announced: boolean
  org_id: string | null; framework: string | null; first_seen: string; last_seen: string | null
  requests: number; attacks: number; blocked: number
}
export interface ShieldFinding {
  family: string; category: string; cwe: string; cwe_name: string; attack: string; attack_name: string
  severity: Tier; surface: string; param: string; evidence: string; why: string
}
export interface ShieldDetection {
  id: string; ts: string; app: string; source_ip: string; method: string; path: string
  category: string; severity: Tier; cwe: string; cwe_name: string; attack: string; attack_name: string
  families: string[]; findings: ShieldFinding[]; decision: string; success: boolean; redteam: string | null
}
export interface ShieldAttacker {
  ip: string; requests: number; attacks: number; worst: Tier | null; families: string[]
  blocked: boolean; block_reason: string | null; ua: string; first_seen: string
}
export interface ShieldEvent {
  ts: string; app: string; method: string; path: string; status: number | null; source_ip: string
  ua: string; worst: Tier | null; decision: string; families: string[]; n: number; redteam: string | null
}
export interface ShieldStatus {
  running: boolean; started: string; apps: ShieldApp[]
  stats: { events: number; attacks: number; blocked: number; sources: number; attackers: number; blocklist: number }
  events: ShieldEvent[]; findings: ShieldDetection[]; attackers: ShieldAttacker[]
  blocklist: { ip: string; reason: string; at: string; by: string; auto: boolean }[]
  families: string[]; ledger: { detections_hour: number; blocks: number }
}
export interface RedteamScenario { id: string; title: string; what: string; cases: number }
export interface RedteamCase {
  case_id: string; scenario: string; label: string; method: string; path: string; cwe: string | null
  kind: 'attack' | 'control'; quiet: boolean; http_status: number | null; error: string | null
  sent_ms: number; detected: boolean; blocked: boolean; severity: Tier | null; category: string | null
}
export interface RedteamReport {
  run_id: string; target: string; scenario: string; attacker_ip: string; user_ip: string
  started_at: string; finished_at: string; duration_ms: number
  sent: number; attacks_sent: number; controls_sent: number; detected: number; blocked: number
  missed: number; false_positives: number
  detection_rate: number | null; block_rate: number | null; precision: number | null; mean_ttd_ms: number | null
  scenarios: string[]; cases: RedteamCase[]; missed_cases: string[]; fp_cases: string[]
}

/* ---------------------------------------------------------------- the intelligence graph (/api/graph) */
export type FactValue = string | number | boolean | null | string[]
export interface GraphNode {
  id: string; kind: string; label: string; sub: string; risk: number | null; tier: Tier | null
  provenance: string; source: string; facts: Record<string, FactValue | undefined>
  last_seen: string | null; age_h: number | null; pulse: number; phase: string; degree: number
  ring: number; angle: number; r: number
}
export interface GraphEdge { from: string; to: string; kind: string; label: string; provenance: string; weight: number; last_seen: string | null }
export interface IntelGraph {
  focus: { kind: string; id: string | null; label: string }
  built_at: string; snapshot: string
  nodes: GraphNode[]; edges: GraphEdge[]; rings: number
  kinds: { id: string; label: string; count: number }[]
  breath: { fresh: number; today: number; week: number; fading: number; aged: number; events_last_hour: number
    last_event: string | null; live_ticks: number | null; live_detections: number }
  summary: { nodes: number; edges: number; real_edges: number; sim_edges: number; mixed_edges: number }
  provenance: { REAL: string[]; SIM: string[]; note: string }
}
export interface GraphNeighbour { id: string; kind: string; label: string; tier: Tier | null; pulse: number; relation: string; edge: string; provenance: string; direction: 'in' | 'out' }
export interface GraphEvent { ts: string; kind: string; subject: string; source: string; provenance: string; text: string }
export interface GraphCard {
  node: GraphNode; neighbours: GraphNeighbour[]; events: GraphEvent[]; live: Record<string, unknown>[]
  focus: IntelGraph['focus']; record: { kind: string; how: string }
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
  languages: () => get<Language[]>('/api/languages'),
  translate: (orgId: string, cveId: string, lang: string) =>
    get<Translation>(`/api/alerts/${orgId}/${cveId}/brief/translate?lang=${lang}`),
  recent: () => get<LedgerEvent[]>('/api/events/recent?limit=25'),
  soc: () => get<Soc>('/api/soc'),
  approvals: (status = 'pending') => get<Approval[]>(`/api/approvals?status=${status}`),
  decide: async (id: number, decision: 'approve' | 'reject', note?: string) => {
    const q = new URLSearchParams({ actor: 'analyst@ncew', ...(note ? { note } : {}) })
    const res = await fetch(`/api/approvals/${id}/${decision}?${q}`, { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json() as Promise<{ id: number; status: string; executed: number }>
  },
  autopilot: (q: { org_id?: string; kind?: string; limit?: number } = {}) => {
    const params = new URLSearchParams(Object.entries(q).filter(([, v]) => v != null).map(([k, v]) => [k, String(v)]))
    return get<{ summary: AutopilotSummary; events: AutoEvent[] }>(`/api/autopilot?${params}`)
  },
  forecast: () => get<ForecastView>('/api/forecast'),
  riskplan: (orgId?: string) => get<RiskPlan>(`/api/riskplan${orgId ? `?org_id=${orgId}` : ''}`),
  intelSources: () => get<IntelSource[]>('/api/intel/sources'),
  intelAdvisories: () => get<IntelAdvisory[]>('/api/intel/advisories'),
  attacks: () => get<Attacks>('/api/intel/attacks'),
  technologies: () => get<Technology[]>('/api/intel/technologies'),
  orgProfile: (orgId: string) => get<OrgProfile>(`/api/orgs/${orgId}/profile`),
  act: async (orgId: string, cveId: string, action: string) => {
    const res = await fetch(`/api/alerts/${orgId}/${cveId}/workflow/${action}`, { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json() as Promise<Workflow>
  },
  shield: () => get<ShieldStatus>('/api/shield'),
  notify: () => get<NotifyStatus>('/api/notify'),
  notifyTest: async (name: string) => {
    const res = await fetch(`/api/notify/test/${name}`, { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json() as Promise<NotifyDelivery>
  },
  notifyEnabled: async (name: string, on: boolean) => {
    const res = await fetch(`/api/notify/channels/${name}/enabled?on=${on}`, { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json() as Promise<NotifyChannel>
  },
  notifyReload: async () => {
    const res = await fetch('/api/notify/reload', { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json() as Promise<NotifyStatus>
  },
  redteamCatalogue: () => get<{ scenarios: RedteamScenario[] }>('/api/redteam/catalogue'),
  redteamRun: async (scenario?: string) => {
    const res = await fetch('/api/redteam/run', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(scenario && scenario !== 'all' ? { scenario } : {}) })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json() as Promise<RedteamReport>
  },
  shieldMode: async (appId: string, mode: 'monitor' | 'block') => {
    const res = await fetch(`/api/shield/apps/${appId}/mode?mode=${mode}`, { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json() as Promise<ShieldApp>
  },
  shieldBlock: async (ip: string) => {
    const res = await fetch(`/api/shield/block/${encodeURIComponent(ip)}`, { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json()
  },
  shieldUnblock: async (ip: string) => {
    const res = await fetch(`/api/shield/unblock/${encodeURIComponent(ip)}`, { method: 'POST' })
    if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
    return res.json()
  },
  graph: (focus?: string) => get<IntelGraph>(`/api/graph${focus ? `?focus=${encodeURIComponent(focus)}` : ''}`),
  graphNode: (id: string, focus?: string) =>
    get<GraphCard>(`/api/graph/node?id=${encodeURIComponent(id)}${focus ? `&focus=${encodeURIComponent(focus)}` : ''}`),
}
