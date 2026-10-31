import { ChevronRight } from 'lucide-react'
import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import type { Tier } from './api'

/* Uber Base-style building blocks. Rules: structure is black, white and grey; the one primary action per screen is a
   solid black pill; chips and inputs are grey-filled; colour carries meaning only (risk tiers as solid tags, green =
   done, blue = link). Headings are short, bold, sentence case. */

export const TIER_STYLE: Record<Tier, string> = {
  Compromise: 'bg-comp text-white',
  Critical: 'bg-crit text-white',
  High: 'bg-high text-white',
  Medium: 'bg-med text-black',
  Watch: 'bg-panel-2 text-mute',
}
export const TIER_FILL: Record<Tier, string> = {
  Compromise: '#7356bf',
  Critical: '#e11900',
  High: '#ff6937',
  Medium: '#ffc043',
  Watch: '#a6a6a6',
}
export const TIERS: Tier[] = ['Compromise', 'Critical', 'High', 'Medium', 'Watch']

export function TierPill({ tier }: { tier: Tier }) {
  return <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${TIER_STYLE[tier]}`}>{tier}</span>
}

export function Badge({ children, tone = 'mute' }: { children: ReactNode; tone?: 'mute' | 'ok' | 'crit' | 'accent' }) {
  const tones = {
    mute: 'bg-panel-2 text-mute',
    ok: 'bg-ok/12 text-ok',
    crit: 'bg-crit/10 text-crit',
    accent: 'bg-panel-2 text-text',
  }
  return <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>
}

/** Where a fact comes from: a quiet grey tag with a dot (green = REAL public data, hollow = SIM simulated sensor). */
export function Prov({ p, label }: { p?: string | null; label?: string }) {
  if (!p) return null
  const real = p === 'REAL'
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-panel-2 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-mute"
          title={real ? 'public, real-world data' : p === 'SIM' ? 'simulated sensor data, labelled as such' : p}>
      <span className={`h-1.5 w-1.5 rounded-full ${real ? 'bg-ok' : 'ring-1 ring-mute'}`} />{label ?? p}
    </span>
  )
}

/** Uber chips: one section at a time; grey when idle, black when chosen. */
export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: [T, string][] }) {
  return (
    <div className="flex flex-wrap gap-2">
      {items.map(([k, label]) => (
        <button key={k} onClick={() => onChange(k)}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${value === k ? 'bg-action text-ink' : 'bg-panel-2 text-text hover:bg-line'}`}>
          {label}
        </button>
      ))}
    </div>
  )
}

/** A card: bold sentence-case title, generous padding, no chrome. */
export function Panel({ title, children, right }: { title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section className="rounded-2xl border border-line bg-panel">
      <header className="flex items-center justify-between gap-3 px-5 pt-4 pb-2">
        <h2 className="text-lg font-bold">{title}</h2>
        {right}
      </header>
      <div className="px-5 pb-5">{children}</div>
    </section>
  )
}

/** Big number, short label: the Uber way of showing a figure (ETA, fare). */
export function Stat({ value, label, sub, tone }: { value: ReactNode; label: string; sub?: string; tone?: string }) {
  return (
    <div className="rounded-2xl bg-panel-2 px-5 py-4">
      <div className={`text-4xl font-bold tracking-tight tabular-nums ${tone ?? ''}`}>{value}</div>
      <div className="mt-1 text-sm font-medium">{label}</div>
      {sub && <div className="mt-0.5 text-xs text-mute">{sub}</div>}
    </div>
  )
}

/** List row: leading icon/avatar, title, subtitle, trailing value, chevron (Uber's recent places / trips). */
export function Row({ lead, title, sub, trail, onClick }: { lead?: ReactNode; title: ReactNode; sub?: ReactNode; trail?: ReactNode; onClick?: () => void }) {
  const Cmp = onClick ? 'button' : 'div'
  return (
    <Cmp onClick={onClick} className={`flex w-full items-center gap-3 border-b border-line py-3 text-left last:border-0 ${onClick ? 'hover:bg-panel-2/60' : ''}`}>
      {lead && <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-panel-2">{lead}</div>}
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium">{title}</div>
        {sub && <div className="truncate text-sm text-mute">{sub}</div>}
      </div>
      {trail && <div className="shrink-0 text-right text-sm">{trail}</div>}
      {onClick && <ChevronRight size={18} className="shrink-0 text-mute" />}
    </Cmp>
  )
}

/* Confirmation banner after an action (Uber's "Your ride is confirmed"). */
const ToastCtx = createContext<(msg: string) => void>(() => undefined)
export function ToastProvider({ children }: { children: ReactNode }) {
  const [msg, setMsg] = useState<string>()
  const show = useCallback((m: string) => {
    setMsg(m)
    window.setTimeout(() => setMsg((cur) => (cur === m ? undefined : cur)), 4200)
  }, [])
  return (
    <ToastCtx.Provider value={show}>
      {children}
      {msg && (
        <div className="toast-in fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-full bg-action px-5 py-3 text-sm font-medium text-ink shadow-2xl">
          {msg}
        </div>
      )}
    </ToastCtx.Provider>
  )
}
export const useToast = () => useContext(ToastCtx)

export function deadlineText(hours: number | null): string {
  if (hours == null) return '—'
  return hours < 48 ? `${hours} h` : `${Math.round(hours / 24)} d`
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  return iso.slice(0, 16).replace('T', ' ')
}
