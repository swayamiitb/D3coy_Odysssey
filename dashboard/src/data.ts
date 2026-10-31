// Data access with three modes, picked once at start-up:
//   live     – the Odyssey backend answers on /api (Vite proxies it; see vite.config.ts)
//   snapshot – real responses saved by scripts/snapshot.mjs into public/demo (offline demo, rule 14)
//   sample   – bundled layout fixtures (src/sample.ts), shown with a banner; never presented as real
import { useCallback, useEffect, useState } from 'react'
import { SAMPLE } from './sample'
import type {
  AlertDetail, Approval, Attacks, AutoEvent, AutopilotSummary, Brief, Campaign, Feed, ForecastView, Health, IntelAdvisory, IntelSource,
  OrgProfile, Replay, RiskPlan, Soc, Technology, Workflow,
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
  try {
    const r = await withTimeout('/api/health', 2500)
    if (r.ok && (r.headers.get('content-type') ?? '').includes('json')) return (mode = 'live')
  } catch { /* backend not reachable */ }
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

async function post<T>(path: string): Promise<T> {
  if (mode !== 'live') throw new ReadOnlyError('Read-only: connect to the Odyssey backend to act')
  const res = await fetch(path, { method: 'POST' })
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { detail?: string }
    throw new Error(body.detail ?? res.statusText)
  }
  return res.json() as Promise<T>
}

const qs = (o: Record<string, string | number | undefined | null>) =>
  new URLSearchParams(Object.entries(o).filter(([, v]) => v != null && v !== '').map(([k, v]) => [k, String(v)])).toString()

export const api = {
  health: () => get<Health>('/api/health'),
  soc: () => get<Soc>('/api/soc'),
  feed: () => get<Feed>('/api/feed'),
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

const ANALYST_KEY = 'odyssey-soc.analyst'
export function getAnalyst(): string {
  try { return localStorage.getItem(ANALYST_KEY) || 'analyst@ncew' } catch { return 'analyst@ncew' }
}
export function setAnalyst(v: string) {
  try { localStorage.setItem(ANALYST_KEY, v) } catch { /* private window */ }
}
