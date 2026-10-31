import { ChevronRight, X } from 'lucide-react'
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import type { Tier } from './api'

/* Uber Base-style building blocks, "Oreo" layering: black bands (nav, Hero, footer, Band tone="black") around a white
   body with Base greys between. The one primary action per screen is a solid pill (black on white, white on black);
   chips and inputs are grey-filled; colour carries meaning only (risk tiers as solid tags, green = done, blue = link).
   Headings are short, bold, sentence case. */

/** Page width: one centred column with generous gutters, like Uber's website. */
export const WRAP = 'mx-auto w-full max-w-[1680px] px-10'

/** Black band under the nav: big white title, grey line, chips on the right, white figures below. */
export function Hero({ title, sub, tabs, children }: { title: ReactNode; sub?: ReactNode; tabs?: ReactNode; children?: ReactNode }) {
  return (
    <section className="bg-band text-white">
      <div className={`${WRAP} pt-12 pb-10`}>
        <div className="flex flex-wrap items-end justify-between gap-6">
          <div className="max-w-3xl">
            <h1 className="text-5xl font-bold tracking-tight">{title}</h1>
            {sub && <p className="mt-3 text-lg text-band-mute">{sub}</p>}
          </div>
          {tabs}
        </div>
        {children && <div className="mt-9">{children}</div>}
      </div>
    </section>
  )
}

/** Figures on a black band: white numbers on raised dark tiles; a coloured dot only where the number means risk. */
export function Figures({ items }: { items: { value: ReactNode; label: string; sub?: ReactNode; dot?: string }[] }) {
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl bg-band-3 xl:grid-cols-4">
      {items.map((k) => (
        <div key={k.label} className="bg-band-2 px-6 py-5">
          <div className="text-4xl font-bold tracking-tight tabular-nums text-white">{k.value}</div>
          <div className="mt-1.5 flex items-center gap-2 font-medium text-white">{k.dot && <span className={`h-2 w-2 rounded-full ${k.dot}`} />}{k.label}</div>
          {k.sub && <div className="mt-0.5 text-sm text-band-mute">{k.sub}</div>}
        </div>
      ))}
    </div>
  )
}

/** A full-width section: white, soft grey or black (the Oreo layers inside a page). */
export function Band({ tone = 'white', children, className = '' }: { tone?: 'white' | 'soft' | 'black'; children: ReactNode; className?: string }) {
  const bg = tone === 'black' ? 'bg-band text-white' : tone === 'soft' ? 'bg-soft' : 'bg-ink'
  return <section className={bg}><div className={`${WRAP} py-12 ${className}`}>{children}</div></section>
}

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

/** Uber chips: one section at a time. On white: grey idle, black chosen. On a black band: dark idle, white chosen. */
export function Tabs<T extends string>({ value, onChange, items, dark }: { value: T; onChange: (v: T) => void; items: [T, string][]; dark?: boolean }) {
  const on = dark ? 'bg-white text-black' : 'bg-action text-ink'
  const off = dark ? 'bg-band-3 text-white hover:bg-white/25' : 'bg-panel-2 text-text hover:bg-panel-3'
  return (
    <div className="flex flex-wrap gap-2">
      {items.map(([k, label]) => (
        <button key={k} onClick={() => onChange(k)}
                className={`rounded-full px-4 py-2 text-[15px] font-medium transition ${value === k ? on : off}`}>
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
      <header className="flex items-center justify-between gap-3 px-6 pt-5 pb-3">
        <h2 className="text-xl font-bold">{title}</h2>
        {right}
      </header>
      <div className="px-6 pb-6">{children}</div>
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

/** Section as on Uber's website: a big bold heading, one quiet line, an optional pill on the right, no card chrome. */
export function Section({ title, sub, action, children }: { title: ReactNode; sub?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return (
    <section>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">{title}</h2>
          {sub && <p className="mt-1.5 max-w-3xl text-mute">{sub}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

/** Quiet grey pill for "See all", "Details" and other secondary moves. */
export function Pill({ children, onClick }: { children: ReactNode; onClick: () => void }) {
  return (
    <button onClick={onClick} className="inline-flex items-center gap-1.5 rounded-full bg-panel-2 px-4 py-2 text-sm font-medium hover:bg-panel-3">
      {children}
    </button>
  )
}

/** Uber "Suggestions" card: grey, one figure, one line, one Details pill. Opens the detail in a sheet. */
export function Tile({ value, title, sub, onClick, cta = 'Details' }: { value: ReactNode; title: string; sub?: ReactNode; onClick: () => void; cta?: string }) {
  return (
    <button onClick={onClick} className="flex min-h-[200px] flex-col justify-between rounded-2xl bg-panel-2 p-6 text-left transition hover:bg-panel-3">
      <div>
        <div className="text-4xl font-bold tracking-tight tabular-nums">{value}</div>
        <div className="mt-2 text-lg font-semibold leading-snug">{title}</div>
        {sub && <div className="mt-1 text-sm text-mute">{sub}</div>}
      </div>
      <span className="mt-6 inline-flex w-fit items-center gap-1 rounded-full bg-panel px-4 py-2 text-sm font-medium">{cta} <ChevronRight size={14} /></span>
    </button>
  )
}

/** Details on demand: a sheet slides over from the right (Uber's trip details); Esc or the backdrop closes it. */
export function Sheet({ title, sub, onClose, children, wide }: { title: ReactNode; sub?: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/40" onClick={onClose}>
      <aside onClick={(e) => e.stopPropagation()}
             className={`m-3 flex h-[calc(100%-1.5rem)] ${wide ? 'w-[1180px]' : 'w-[760px]'} max-w-[96vw] flex-col overflow-hidden rounded-3xl bg-panel text-text shadow-2xl`}>
        <header className="flex items-start justify-between gap-4 border-b border-line px-8 py-6">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">{title}</h2>
            {sub && <p className="mt-1 text-mute">{sub}</p>}
          </div>
          <button onClick={onClose} title="Close" className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-panel-2 hover:bg-panel-3"><X size={18} /></button>
        </header>
        <div className="min-h-0 flex-1 overflow-auto px-8 py-6">{children}</div>
      </aside>
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
