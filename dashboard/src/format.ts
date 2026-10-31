import type { Tier } from './types'

export const TIER_RANK: Record<Tier, number> = { Compromise: 0, Critical: 1, High: 2, Medium: 3, Watch: 4 }
export const TIERS: Tier[] = ['Compromise', 'Critical', 'High', 'Medium', 'Watch']

export const num = (n: number | null | undefined, digits = 0) =>
  n == null ? '—' : n.toLocaleString('en-IN', { minimumFractionDigits: digits, maximumFractionDigits: digits })

const IST: Intl.DateTimeFormatOptions = { timeZone: 'Asia/Kolkata' }
export const dateTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString('en-IN', { ...IST, day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }) : '—'
export const date = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleDateString('en-IN', { ...IST, day: 'numeric', month: 'short', year: 'numeric' }) : '—'
export const clock = (ms: number) =>
  new Date(ms).toLocaleTimeString('en-IN', { ...IST, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })

export function duration(ms: number): string {
  const m = Math.floor(Math.abs(ms) / 60000)
  const d = Math.floor(m / 1440)
  const h = Math.floor((m % 1440) / 60)
  const mm = m % 60
  if (d > 0) return `${d} d ${h} h`
  if (h > 0) return `${h} h ${mm} m`
  return `${mm} m`
}

export type SlaState = 'none' | 'ok' | 'risk' | 'breached'
/** SLA = the deadline Odyssey set (CERT-In basis), counted from when the warning was issued. */
export function sla(issuedAt: string, hours: number | null, nowMs: number): { state: SlaState; leftMs: number; dueMs: number } {
  if (hours == null) return { state: 'none', leftMs: Infinity, dueMs: Infinity }
  const dueMs = Date.parse(issuedAt) + hours * 3600_000
  const leftMs = dueMs - nowMs
  const state: SlaState = leftMs < 0 ? 'breached' : leftMs < Math.min(hours * 3600_000 * 0.25, 4 * 3600_000) ? 'risk' : 'ok'
  return { state, leftMs, dueMs }
}

export const ACTION_LABEL: Record<string, string> = {
  acknowledge: 'Acknowledge',
  start: 'Start mitigation',
  verify: 'Patched, verify',
  resolve: 'Close as resolved',
  accept_risk: 'Accept risk',
  false_positive: 'False positive',
  reopen: 'Reopen',
}

export const STATE_LABEL: Record<string, string> = {
  new: 'New',
  acknowledged: 'Acknowledged',
  mitigating: 'Mitigating',
  verifying: 'Verifying',
  closed: 'Closed',
  reopened: 'Reopened',
}

/** "auto.report_draft" -> "Report draft" */
export const humanKind = (k: string) => {
  const s = k.split('.').slice(-1)[0].replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}
