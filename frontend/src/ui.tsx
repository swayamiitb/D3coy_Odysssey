import { ChevronRight, X } from 'lucide-react'
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import type { Tier } from './api'
import { Honeycomb } from './soc/Honeycomb'
import { Plexus } from './soc/Plexus'

/* Uber black-and-white building blocks with SOC accents (ui-07/08), "Oreo" layering: black bands (nav, page header,
   feature bands, footer) around a white body. A band carries .soc-dark, which re-points every token to the SOC-black
   set, so the same components work inside and outside it; .soc-light puts a white card back on a band. Elevation is
   lightness alone: cards one step up with a 1px hairline, wells another step. The one primary action per screen is a
   solid pill in the text colour (black on white, white on black); chips and inputs are grey-filled; colour carries
   meaning only (risk tiers as tinted pills, green = done, blue = link and selection). Headings are short, semibold,
   sentence case. Token names are the lead's; index.css re-points them. */

/** Page width: one centred column, gutters that shrink on small screens. */
export const WRAP = 'mx-auto w-full max-w-[1680px] px-4 sm:px-6 lg:px-10'

/* PS-01 key objectives (the D3COY 1.0 brief) and its explanation deliverable. Every page and tab names the ones it
   answers, in its header, so the six objectives can be traced to the screen that serves each (rule 16). */
export type ObjectiveKey = 'aggregation' | 'analysis' | 'warning' | 'risk' | 'recommendations' | 'dashboard' | 'explain'
export const OBJECTIVES: Record<ObjectiveKey, { n: string; name: string; ps: string; view: string; tab?: string }> = {
  aggregation: { n: '1', name: 'Threat Intelligence Aggregation', view: 'intel', tab: 'overview',
    ps: 'Collect and consolidate threat information from trusted feeds, public advisories, vulnerability databases, and simulated security logs.' },
  analysis: { n: '2', name: 'AI-Based Threat Analysis', view: 'intel', tab: 'graph',
    ps: 'Apply machine learning or natural language processing to identify suspicious indicators, recurring attack patterns, and relationships between reported threats.' },
  warning: { n: '3', name: 'Early Warning Generation', view: 'live',
    ps: 'Identify potentially emerging threats and generate timely alerts based on threat severity, confidence, and relevance.' },
  risk: { n: '4', name: 'Risk Prioritisation', view: 'intel', tab: 'risk',
    ps: 'Rank threats according to factors such as exploitability, asset criticality, potential impact, and available evidence.' },
  recommendations: { n: '5', name: 'Actionable Recommendations', view: 'soc', tab: 'cases',
    ps: 'Provide suggested mitigation measures, such as patching vulnerable systems, blocking known malicious indicators, or investigating suspicious activity.' },
  dashboard: { n: '6', name: 'Threat Intelligence Dashboard', view: 'now',
    ps: 'Display active threats, affected technologies, risk levels and alerts.' },
  explain: { n: 'D', name: 'Explanation of the AI model, scoring and mitigation workflow', view: 'proof', tab: 'how',
    ps: 'Expected deliverable: an explanation of the AI model, the threat scoring approach and the proposed mitigation workflow.' },
}

/** One objective as a quiet pill: its number in a ring, its name, the brief's own wording on hover. */
export function Objective({ k, onClick }: { k: ObjectiveKey; onClick?: () => void }) {
  const o = OBJECTIVES[k]
  const cls = 'inline-flex items-center gap-1.5 rounded-full border border-line bg-panel-2 py-0.5 pl-1 pr-2.5 text-[12px] font-medium text-mute'
  const body = <><span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-text text-[10px] font-semibold tabular-nums text-ink">{o.n}</span>{o.name}</>
  const title = `PS-01 ${o.n === 'D' ? 'deliverable' : `key objective ${o.n}`}: ${o.ps}`
  return onClick
    ? <button onClick={onClick} className={`${cls} transition-colors hover:border-line-2 hover:text-text`} title={title}>{body}</button>
    : <span className={cls} title={title}>{body}</span>
}

/** The objectives a page, tab or sheet serves, named in one line. */
export function Objectives({ keys, className = '' }: { keys: ObjectiveKey[]; className?: string }) {
  if (!keys.length) return null
  return (
    <div className={`flex flex-wrap items-center gap-1.5 ${className}`} aria-label="PS-01 objectives served here">
      <span className="mr-0.5 text-[11px] font-semibold uppercase tracking-wide text-faint">PS-01 {keys.length > 1 ? 'objectives' : 'objective'}</span>
      {keys.map((k) => <Objective key={k} k={k} />)}
    </div>
  )
}

/** Page header on a black band: where you are, the page's title and one line, tabs on the right, the figures below,
 *  the honeycomb moving quietly behind it all. */
export function Hero({ title, sub, tabs, objectives, children }: { title: ReactNode; sub?: ReactNode; tabs?: ReactNode; objectives?: ObjectiveKey[]; children?: ReactNode }) {
  return (
    <section className="soc-dark relative overflow-hidden border-b border-line">
      <Honeycomb />
      <div className={`${WRAP} relative z-10 pt-8 pb-8`}>
        <div className="flex flex-wrap items-end justify-between gap-5">
          <div className="min-w-0 max-w-3xl">
            <p className="flex items-center gap-1.5 text-[13px] text-faint">Odyssey <ChevronRight size={13} aria-hidden /> <span className="text-mute">{title}</span></p>
            <h1 className="mt-2 text-[32px] font-semibold leading-tight tracking-tight">{title}</h1>
            {sub && <p className="mt-1.5 text-[15px] text-mute">{sub}</p>}
            {objectives && <Objectives keys={objectives} className="mt-3" />}
          </div>
          {tabs}
        </div>
        {children && <div className="mt-7">{children}</div>}
      </div>
    </section>
  )
}

/** A page's headline figures: one surface cut into equal cells by 1px seams; grey label above, the figure below. A dot
 *  only where the number means risk or health; a delta only when it was measured. */
export function Figures({ items, glass }: { items: { value: ReactNode; label: string; sub?: ReactNode; dot?: string; delta?: ReactNode }[]; glass?: boolean }) {
  return (
    <div className={`soc-seams grid-cols-2 xl:grid-cols-4 ${glass ? 'is-glass' : ''}`}>
      {items.map((k) => (
        <div key={k.label} className="px-5 py-4">
          <div className="flex items-center gap-2 text-[13px] font-medium text-mute">{k.dot && <span className={`h-2 w-2 shrink-0 rounded-full ${k.dot}`} />}{k.label}</div>
          <div className="mt-2 flex flex-wrap items-baseline gap-x-2.5">
            <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums text-text">{k.value}</span>
            {k.delta}
          </div>
          {k.sub && <div className="mt-2 text-[13px] leading-snug text-faint">{k.sub}</div>}
        </div>
      ))}
    </div>
  )
}

/** The figure strip while its numbers load: the same four cells, grey bars where the figures will be. */
export function FiguresSkeleton() {
  return (
    <div className="soc-seams grid-cols-2 xl:grid-cols-4" aria-busy="true" aria-label="Loading figures">
      {[0, 1, 2, 3].map((i) => (
        <div key={i} className="px-5 py-4">
          <div className="h-3.5 w-28 rounded bg-panel-2" />
          <div className="mt-3 h-7 w-16 rounded bg-panel-2" />
          <div className="mt-3 h-3 w-40 rounded bg-panel-2" />
        </div>
      ))}
    </div>
  )
}

/** A full-width section of a page: white, soft grey, or a black band (the Oreo layers inside a page). The black band
 *  is where a page's results sit; the plexus (the team's second clip) moves behind them. */
export function Band({ tone = 'white', children, className = '' }: { tone?: 'white' | 'soft' | 'black'; children: ReactNode; className?: string }) {
  if (tone === 'black') {
    return (
      <section className="soc-dark relative overflow-hidden border-t border-line text-text">
        <Plexus />
        <div className={`${WRAP} relative z-10 py-12 ${className}`}>{children}</div>
      </section>
    )
  }
  const bg = tone === 'soft' ? 'bg-soft' : 'bg-ink'
  return <section className={`${bg} border-t border-line text-text`}><div className={`${WRAP} py-12 ${className}`}>{children}</div></section>
}

/* Risk tiers are a scale, not a rainbow: one hue each, used identically everywhere. Pills are a pale tint with the
   tier's colour as text; a solid fill is kept for the rare state that demands action (a suspected compromise). */
export const TIER_STYLE: Record<Tier, string> = {
  Compromise: 'bg-comp text-white',
  Critical: 'bg-crit/15 text-crit-ink ring-1 ring-inset ring-crit/30',
  High: 'bg-high/12 text-high-ink ring-1 ring-inset ring-high/25',
  Medium: 'bg-med/10 text-med-ink ring-1 ring-inset ring-med/25',
  Watch: 'bg-panel-2 text-mute',
}
export const TIER_FILL: Record<Tier, string> = {
  Compromise: '#8a63e8',
  Critical: '#e5383b',
  High: '#ff7a3d',
  Medium: '#f5c242',
  Watch: '#6e6e75',
}
export const TIERS: Tier[] = ['Compromise', 'Critical', 'High', 'Medium', 'Watch']

export function TierPill({ tier }: { tier: Tier }) {
  return <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${TIER_STYLE[tier]}`}>{tier}</span>
}

export function Badge({ children, tone = 'mute' }: { children: ReactNode; tone?: 'mute' | 'ok' | 'crit' | 'accent' }) {
  const tones = {
    mute: 'bg-panel-2 text-mute',
    ok: 'bg-ok/15 text-ok-ink',
    crit: 'bg-crit/15 text-crit-ink',
    accent: 'bg-accent/15 text-accent',
  }
  return <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>
}

/** Where a fact comes from: a quiet tag with a dot (green = REAL public data, hollow = SIM simulated sensor). */
export function Prov({ p, label }: { p?: string | null; label?: string }) {
  if (!p) return null
  const real = p === 'REAL'
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-line bg-panel-2 px-2 py-0.5 text-[10px] font-semibold uppercase text-mute"
          title={real ? 'public, real-world data' : p === 'SIM' ? 'simulated sensor data, labelled as such' : p}>
      <span className={`h-1.5 w-1.5 rounded-full ${real ? 'bg-ok' : 'ring-1 ring-mute'}`} />{label ?? p}
    </span>
  )
}

/** Segmented tabs: one section at a time. The chosen one is the solid pill (black on white, white on a band). */
export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: [T, string][]; dark?: boolean }) {
  return (
    <div className="flex max-w-full flex-wrap gap-1 rounded-[22px] border border-line bg-panel p-1">
      {items.map(([k, label]) => (
        <button key={k} onClick={() => onChange(k)} aria-pressed={value === k}
                className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-colors ${value === k ? 'bg-text text-ink' : 'text-mute hover:bg-panel-2 hover:text-text'}`}>
          {label}
        </button>
      ))}
    </div>
  )
}

/** A card: semibold sentence-case title, a hairline, no shadow. */
export function Panel({ title, children, right }: { title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section className="soc-card">
      <header className="flex items-center justify-between gap-3 px-5 pt-4 pb-3">
        <h2 className="text-[16px] font-semibold">{title}</h2>
        {right}
      </header>
      <div className="px-5 pb-5">{children}</div>
    </section>
  )
}

/** Big number, short label. */
export function Stat({ value, label, sub, tone }: { value: ReactNode; label: string; sub?: string; tone?: string }) {
  return (
    <div className="soc-card px-5 py-4">
      <div className="text-[13px] font-medium text-mute">{label}</div>
      <div className={`mt-1.5 text-[30px] font-semibold leading-none tracking-tight tabular-nums ${tone ?? ''}`}>{value}</div>
      {sub && <div className="mt-2 text-xs text-faint">{sub}</div>}
    </div>
  )
}

/** A section: a semibold heading, one quiet line, an optional action on the right. */
export function Section({ title, sub, action, children }: { title: ReactNode; sub?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return (
    <section>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-[22px] font-semibold tracking-tight">{title}</h2>
          {sub && <p className="mt-1 max-w-3xl text-[14px] text-mute">{sub}</p>}
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
    <button onClick={onClick} className="inline-flex items-center gap-1.5 rounded-full border border-line bg-panel-2 px-4 py-2 text-sm font-medium transition-colors hover:bg-panel-3">
      {children}
    </button>
  )
}

/** A suggestion card: one figure, one line, one Details pill. Opens the detail in a sheet. */
export function Tile({ value, title, sub, onClick, cta = 'Details' }: { value: ReactNode; title: string; sub?: ReactNode; onClick: () => void; cta?: string }) {
  return (
    <button onClick={onClick} className="soc-card flex min-h-[200px] flex-col justify-between p-6 text-left transition-colors hover:border-line-2 hover:bg-panel-4">
      <div>
        <div className="text-[34px] font-semibold leading-none tracking-tight tabular-nums">{value}</div>
        <div className="mt-3 text-[17px] font-semibold leading-snug">{title}</div>
        {sub && <div className="mt-1 text-sm text-mute">{sub}</div>}
      </div>
      <span className="mt-6 inline-flex w-fit items-center gap-1 rounded-full bg-panel-2 px-4 py-2 text-sm font-medium">{cta} <ChevronRight size={14} /></span>
    </button>
  )
}

/** Details on demand: a sheet slides over from the right; Esc or the backdrop closes it. */
export function Sheet({ title, sub, onClose, children, wide }: { title: ReactNode; sub?: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/70" onClick={onClose}>
      <aside onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true"
             className={`m-3 flex h-[calc(100%-1.5rem)] ${wide ? 'w-[1180px]' : 'w-[760px]'} max-w-[96vw] flex-col overflow-hidden rounded-2xl border border-line-2 bg-panel text-text`}>
        <header className="flex items-start justify-between gap-4 border-b border-line px-7 py-5">
          <div>
            <h2 className="text-[22px] font-semibold tracking-tight">{title}</h2>
            {sub && <p className="mt-1 text-mute">{sub}</p>}
          </div>
          <button onClick={onClose} title="Close" aria-label="Close" className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-panel-2 hover:bg-panel-3"><X size={18} /></button>
        </header>
        <div className="min-h-0 flex-1 overflow-auto px-7 py-6">{children}</div>
      </aside>
    </div>
  )
}

/** List row: leading icon, title, subtitle, trailing value, chevron. */
export function Row({ lead, title, sub, trail, onClick }: { lead?: ReactNode; title: ReactNode; sub?: ReactNode; trail?: ReactNode; onClick?: () => void }) {
  const Cmp = onClick ? 'button' : 'div'
  return (
    <Cmp onClick={onClick} className={`flex w-full items-center gap-3 border-b border-line py-3 text-left last:border-0 ${onClick ? 'transition-colors hover:bg-panel-2/50' : ''}`}>
      {lead && <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-panel-2">{lead}</div>}
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium">{title}</div>
        {sub && <div className="truncate text-sm text-mute">{sub}</div>}
      </div>
      {trail && <div className="shrink-0 text-right text-sm">{trail}</div>}
      {onClick && <ChevronRight size={18} className="shrink-0 text-faint" />}
    </Cmp>
  )
}

/* Confirmation banner after an action. */
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
        <div role="status" className="toast-in fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-full bg-action px-5 py-3 text-sm font-medium text-ink">
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
