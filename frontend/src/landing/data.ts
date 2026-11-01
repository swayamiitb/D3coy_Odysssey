// Data access with three modes, picked once at start-up:
//   live     – the Odyssey backend answers on /api (Vite proxies it; see vite.config.ts)
//   snapshot – real responses saved by scripts/snapshot.mjs into public/demo (offline demo, rule 14)
//   sample   – bundled layout fixtures (src/sample.ts), shown with a banner; never presented as real
import { useCallback, useEffect, useState } from 'react'
import { SAMPLE } from './sample'
import type {
  AlertDetail, AlertRow, Approval, Attacks, AutoEvent, AutopilotSummary, Brief, Campaign, Drill, Feed, ForecastView, Health, IntelAdvisory, IntelSource,
  LiveStatus, OrgProfile, RedteamReport, RedteamScenario, Replay, RiskPlan, ShieldApp, ShieldBlock, ShieldMode, ShieldStatus, Soc, Technology,
  Workflow,
} from './types'

export type Mode = 'live' | 'snapshot' | 'sample'

let mode: Mode = 'sample'
let snapshotTakenAt: string | null = null
const loadedAt = Date.now()

export const getMode = () => mode
export const getSnapshotTakenAt = () => snapshotTakenAt

async function withTimeout(url: string, ms: number): Promise<Response> {
  const ctl = new AbortController()
  const t = setTimeout(() => ctl.abort(), ms)
  try {
    return await fetch(url, { signal: ctl.signal })
  } finally {
    clearTimeout(t)
  }
}

export async function detectMode(): Promise<Mode> {
  // A slow first answer (a cold backend) gets one longer retry before the app settles for a snapshot or sample data.
  for (const ms of [2500, 5000]) {
    try {
      const r = await withTimeout('/api/health', ms)
      if (r.ok && (r.headers.get('content-type') ?? '').includes('json')) return (mode = 'live')
      break // it answered, just not as Odyssey: don't wait again
    } catch { /* backend not reachable yet */ }
  }
  try {
    const r = await withTimeout('/demo/manifest.json', 2500)
    if (r.ok && (r.headers.get('content-type') ?? '').includes('json')) {
      snapshotTakenAt = ((await r.json()) as { taken_at: string }).taken_at
      return (mode = 'snapshot')
    }
  } catch { /* no snapshot */ }
  return (mode = 'sample')
}

/** Clock for SLA countdowns: real time when live; in a snapshot it starts at the moment the snapshot was taken. */
export function now(): number {
  if (mode === 'snapshot' && snapshotTakenAt) return Date.parse(snapshotTakenAt) + (Date.now() - loadedAt)
  return Date.now()
}

/** Same mapping as scripts/snapshot.mjs: /api/a/b?x=1&y=2 -> /demo/api/a/b__x-1_y-2.json */
export function snapshotFile(path: string): string {
  const [p, q] = path.split('?')
  const suffix = q ? '__' + q.split('&').filter(Boolean).sort().join('_').replace(/=/g, '-') : ''
  return `/demo${p}${suffix}.json`
}

export class ReadOnlyError extends Error {}

async function get<T>(path: string): Promise<T> {
  if (mode === 'sample') {
    // Exact path first (e.g. a per-organisation risk plan), then the path without its query.
    const hit = SAMPLE[path] ?? SAMPLE[path.split('?')[0]]
    if (hit === undefined) throw new Error('Not in the sample data')
    return structuredClone(hit) as T
  }
  const res = await fetch(mode === 'live' ? path : snapshotFile(path))
  if (!res.ok) throw new Error(mode === 'live' ? `${res.status} ${path}` : 'Not in this snapshot')
  return res.json() as Promise<T>
}

/** POST, optionally with a JSON body (the red-team run takes one). */
async function post<T>(path: string, json?: unknown): Promise<T> {
  if (mode !== 'live') throw new ReadOnlyError('Read-only: connect to the Odyssey backend to act')
  const res = await fetch(path, json === undefined ? { method: 'POST' }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(json) })
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { detail?: unknown }
    throw new Error(typeof body.detail === 'string' ? body.detail : res.statusText || `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}

const qs = (o: Record<string, string | number | undefined | null>) =>
  new URLSearchParams(Object.entries(o).filter(([, v]) => v != null && v !== '').map(([k, v]) => [k, String(v)])).toString()

export const api = {
  health: () => get<Health>('/api/health'),
  soc: () => get<Soc>('/api/soc'),
  feed: () => get<Feed>('/api/feed'),
  alerts: (limit = 400) => get<AlertRow[]>(`/api/alerts?${qs({ limit })}`),
  approvals: (status = 'pending') => get<Approval[]>(`/api/approvals?${qs({ status })}`),
  alert: (org: string, cve: string) => get<AlertDetail>(`/api/alerts/${org}/${cve}`),
  replay: (org: string, cve: string) => get<Replay>(`/api/replay/${org}/${cve}`),
  brief: (org: string, cve: string) => get<Brief>(`/api/alerts/${org}/${cve}/brief`),
  workflow: (org: string, cve: string) => get<Workflow>(`/api/alerts/${org}/${cve}/workflow`),
  autopilot: (limit = 200) => get<{ summary: AutopilotSummary; events: AutoEvent[] }>(`/api/autopilot?${qs({ limit })}`),
  act: (org: string, cve: string, action: string, actor: string, note?: string) =>
    post<Workflow>(`/api/alerts/${org}/${cve}/workflow/${action}?${qs({ actor, note })}`),
  decide: (id: number, decision: 'approve' | 'reject', actor: string, note?: string) =>
    post<{ id: number; status: string; executed: number }>(`/api/approvals/${id}/${decision}?${qs({ actor, note })}`),
  intelSources: () => get<IntelSource[]>('/api/intel/sources'),
  intelAdvisories: () => get<IntelAdvisory[]>('/api/intel/advisories'),
  technologies: () => get<Technology[]>('/api/intel/technologies'),
  attacks: () => get<Attacks>('/api/intel/attacks'),
  campaigns: () => get<Campaign[]>('/api/campaigns'),
  riskplan: (orgId?: string) => get<RiskPlan>(orgId ? `/api/riskplan?${qs({ org_id: orgId })}` : '/api/riskplan'),
  orgProfile: (id: string) => get<OrgProfile>(`/api/orgs/${id}/profile`),
  forecast: () => get<ForecastView>('/api/forecast'),
  certinUrl: (org: string, cve: string) => `/api/alerts/${org}/${cve}/certin-report`,
  stixUrl: (org: string, cve: string) => `/api/alerts/${org}/${cve}/stix`,
  // Live engine (simulated decoy grid and flows, real feeds) and attack drills.
  live: () => get<LiveStatus>('/api/live'),
  drill: (scenario: string) => post<Drill>(`/api/live/drill/${encodeURIComponent(scenario)}`),
  // HTTP shield in front of a real app on this machine, and the local red-team runner.
  shield: () => get<ShieldStatus>('/api/shield'),
  shieldMode: (appId: string, m: ShieldMode) => post<ShieldApp>(`/api/shield/apps/${encodeURIComponent(appId)}/mode?${qs({ mode: m })}`),
  shieldBlock: (ip: string, reason: string) => post<ShieldBlock>(`/api/shield/block/${encodeURIComponent(ip)}?${qs({ reason })}`),
  shieldUnblock: (ip: string) => post<{ ip: string; unblocked: boolean }>(`/api/shield/unblock/${encodeURIComponent(ip)}`),
  redteamCatalogue: () => get<{ scenarios: RedteamScenario[] }>('/api/redteam/catalogue'),
  /** Fires real HTTP requests at the registered app and waits for the report (a few seconds). No scenario = all. */
  redteamRun: (scenario?: string) => post<RedteamReport>('/api/redteam/run', scenario && scenario !== 'all' ? { scenario } : {}),
}

export interface Loaded<T> { data: T | null; error: string | null; loading: boolean; reload: () => void }

/** Fetch on mount and whenever `key` changes; `load` = null skips. Errors stay inside the block that asked. */
export function useLoad<T>(load: (() => Promise<T>) | null, key: string): Loaded<T> {
  const [state, setState] = useState<{ data: T | null; error: string | null; loading: boolean }>({ data: null, error: null, loading: !!load })
  const [tick, setTick] = useState(0)
  const reload = useCallback(() => setTick((t) => t + 1), [])
  useEffect(() => {
    if (!load) return
    let alive = true
    setState((s) => ({ ...s, loading: true, error: null }))
    load()
      .then((data) => alive && setState({ data, error: null, loading: false }))
      .catch((e: unknown) => alive && setState({ data: null, error: e instanceof Error ? e.message : String(e), loading: false }))
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick])
  return { ...state, reload }
}

export interface Polled<T> extends Loaded<T> { at: number | null }

/** Live screens: fetch on mount, then every `ms` while the tab is visible; stops on unmount. Only the live backend is
 *  polled (a snapshot never changes). A failed refresh keeps the last good data and reports the error beside it. */
export function usePoll<T>(load: () => Promise<T>, key: string, ms: number): Polled<T> {
  const [state, setState] = useState<{ data: T | null; error: string | null; loading: boolean; at: number | null }>({ data: null, error: null, loading: true, at: null })
  const [tick, setTick] = useState(0)
  const reload = useCallback(() => setTick((t) => t + 1), [])
  useEffect(() => {
    let alive = true
    let busy = false
    const pull = (force = false) => {
      if (busy || (!force && document.visibilityState === 'hidden')) return
      busy = true
      load()
        .then((data) => { if (alive) setState({ data, error: null, loading: false, at: Date.now() }) })
        .catch((e: unknown) => { if (alive) setState((s) => ({ ...s, error: e instanceof Error ? e.message : String(e), loading: false })) })
        .finally(() => { busy = false })
    }
    setState((s) => (s.data === null ? { ...s, loading: true, error: null } : s))
    pull(true)
    if (mode !== 'live') return () => { alive = false }
    const id = setInterval(() => pull(), ms)
    const onShow = () => { if (document.visibilityState === 'visible') pull() }
    document.addEventListener('visibilitychange', onShow)
    return () => { alive = false; clearInterval(id); document.removeEventListener('visibilitychange', onShow) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick, ms])
  return { ...state, reload }
}

const ANALYST_KEY = 'odyssey-soc.analyst'
export function getAnalyst(): string {
  try { return localStorage.getItem(ANALYST_KEY) || 'analyst@ncew' } catch { return 'analyst@ncew' }
}
export function setAnalyst(v: string) {
  try { localStorage.setItem(ANALYST_KEY, v) } catch { /* private window */ }
}
