import type { ReactNode } from 'react'
import type { Tier } from './api'

export const TIER_STYLE: Record<Tier, string> = {
  Compromise: 'bg-fuchsia-500/20 text-fuchsia-300 ring-fuchsia-400/60',
  Critical: 'bg-crit/15 text-crit ring-crit/40',
  High: 'bg-high/15 text-high ring-high/40',
  Medium: 'bg-med/15 text-med ring-med/40',
  Watch: 'bg-watch/15 text-watch ring-watch/40',
}
export const TIER_FILL: Record<Tier, string> = {
  Compromise: '#d946ef',
  Critical: '#ef4444',
  High: '#f59e0b',
  Medium: '#eab308',
  Watch: '#64748b',
}
export const TIERS: Tier[] = ['Compromise', 'Critical', 'High', 'Medium', 'Watch']

export function TierPill({ tier }: { tier: Tier }) {
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ring-1 ${TIER_STYLE[tier]}`}>
      {tier}
    </span>
  )
}

export function Badge({ children, tone = 'mute' }: { children: ReactNode; tone?: 'mute' | 'ok' | 'crit' | 'accent' }) {
  const tones = {
    mute: 'bg-panel-2 text-mute ring-line',
    ok: 'bg-ok/10 text-ok ring-ok/30',
    crit: 'bg-crit/10 text-crit ring-crit/30',
    accent: 'bg-accent/10 text-accent ring-accent/30',
  }
  return <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs ring-1 ${tones[tone]}`}>{children}</span>
}

export function Panel({ title, children, right }: { title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-panel">
      <header className="flex items-center justify-between border-b border-line px-4 py-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-mute">{title}</h2>
        {right}
      </header>
      <div className="p-4">{children}</div>
    </section>
  )
}

export function deadlineText(hours: number | null): string {
  if (hours == null) return '—'
  return hours < 48 ? `${hours} h` : `${Math.round(hours / 24)} d`
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  return iso.slice(0, 16).replace('T', ' ')
}
