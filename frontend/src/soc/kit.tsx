import { ChevronDown, ChevronRight } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { fetchJson } from '../api'
import { Prov } from '../ui'

/* SOC kit (ui-07): the parts the console's new panels share. One card recipe, one segmented control, honest deltas,
   the screenshot set's alert cards, a semicircle gauge, a stacked share bar and ranked bars. Colour only on data;
   text stays in text tokens. */

/** Fetch JSON, optionally re-polling; keeps the last good value and reports an error. An empty URL fetches nothing.
 *  Goes through api.ts's shared fetch, so panels asking for the same URL in the same second share one request. */
export function useJson<T>(url: string, deps: unknown[] = [], everyMs?: number): { data?: T; error?: string } {
  const [state, setState] = useState<{ data?: T; error?: string }>({})
  useEffect(() => {
    if (!url) return
    let alive = true
    const pull = () => fetchJson(url)
      .then((d) => { if (alive) setState({ data: d as T }) })
      .catch((e) => { if (alive) setState((s) => ({ ...s, error: String(e) })) })
    pull()
    const id = everyMs ? window.setInterval(pull, everyMs) : undefined
    return () => { alive = false; if (id) window.clearInterval(id) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, everyMs, ...deps])
  return url ? state : {}
}

export const nf = (v: number | null | undefined) => (v == null ? '—' : v.toLocaleString('en-IN'))
/** 2,607,470 → 2.6M; small numbers stay whole. */
export function compact(v: number | null | undefined): string {
  if (v == null) return '—'
  if (v >= 1e9) return `${(v / 1e9).toFixed(v >= 1e10 ? 0 : 1)}B`
  if (v >= 1e6) return `${(v / 1e6).toFixed(v >= 1e7 ? 0 : 1)}M`
  if (v >= 1e4) return `${Math.round(v / 1e3)}k`
  return v.toLocaleString('en-IN')
}
export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—'
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}
const REGION = (() => { try { return new Intl.DisplayNames(['en'], { type: 'region' }) } catch { return undefined } })()
// GeoLite also uses codes that are not countries (EU, AP, A1); Intl throws on those, so they stay as codes.
const NOT_COUNTRY: Record<string, string> = { EU: 'Europe (unspecified)', AP: 'Asia/Pacific (unspecified)', A1: 'Anonymous proxy', A2: 'Satellite provider' }
export const countryName = (cc: string): string => {
  if (NOT_COUNTRY[cc]) return NOT_COUNTRY[cc]
  try { return REGION?.of(cc) ?? cc } catch { return cc }
}

/** The console's card: a title, one quiet line, actions and provenance on the right, then the content. */
export function SocCard({ title, sub, right, prov, children, className = '', bodyClass = 'px-5 pb-5' }: {
  title: ReactNode; sub?: ReactNode; right?: ReactNode; prov?: ('REAL' | 'SIM')[]; children: ReactNode; className?: string; bodyClass?: string
}) {
  return (
    <section className={`soc-card flex min-w-0 flex-col ${className}`}>
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 px-5 pt-4 pb-3">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-[16px] font-semibold">{title}{prov?.map((p) => <Prov key={p} p={p} />)}</h2>
          {sub && <p className="mt-0.5 text-[13px] text-mute">{sub}</p>}
        </div>
        {right}
      </header>
      <div className={`min-h-0 flex-1 ${bodyClass}`}>{children}</div>
    </section>
  )
}

/** A small segmented control (ranges, views). */
export function Seg<T extends string>({ value, onChange, items, label }: { value: T; onChange: (v: T) => void; items: [T, string][]; label: string }) {
  return (
    <div role="group" aria-label={label} className="inline-flex shrink-0 rounded-full border border-line bg-ink p-0.5">
      {items.map(([k, l]) => (
        <button key={k} onClick={() => onChange(k)} aria-pressed={value === k}
                className={`rounded-full px-3 py-1 text-[12.5px] font-medium transition-colors ${value === k ? 'bg-panel-3 text-text' : 'text-mute hover:text-text'}`}>
          {l}
        </button>
      ))}
    </div>
  )
}

/** A measured change. Colour says good or bad, not up or down; no change is grey; the window is in words. */
export function Delta({ now, before, good, window }: { now: number; before: number; good: 'up' | 'down'; window: string }) {
  const d = now - before
  if (d === 0) return <span className="text-[13px] text-faint">no change {window}</span>
  const bad = good === 'down' ? d > 0 : d < 0
  const pct = before ? ` (${d > 0 ? '+' : '−'}${Math.abs(Math.round((100 * d) / before))}%)` : ' (new)'
  return (
    <span className={`text-[13px] font-medium tabular-nums ${bad ? 'text-crit-ink' : 'text-ok-ink'}`}>
      {d > 0 ? '+' : '−'}{Math.abs(d).toLocaleString('en-IN')}{pct} <span className="font-normal text-faint">{window}</span>
    </span>
  )
}

const ALERT_TONE = {
  comp: { card: 'border-comp/35 bg-comp/[0.07]', tile: 'bg-comp/20 text-comp-ink' },
  crit: { card: 'border-crit/35 bg-crit/[0.07]', tile: 'bg-crit/20 text-crit-ink' },
  accent: { card: 'border-accent/30 bg-accent/[0.06]', tile: 'bg-accent/20 text-accent' },
  ok: { card: 'border-ok/30 bg-ok/[0.06]', tile: 'bg-ok/20 text-ok-ink' },
}
/** An alert card: an icon tile, what happened, one line, one action. Tinted by what it is about. */
export function AlertCard({ tone, icon, title, sub, action, onClick }: {
  tone: keyof typeof ALERT_TONE; icon: ReactNode; title: ReactNode; sub: ReactNode; action: string; onClick: () => void
}) {
  const t = ALERT_TONE[tone]
  return (
    <button onClick={onClick} className={`group flex min-w-0 items-start gap-4 rounded-2xl border p-5 text-left transition-colors hover:bg-panel-2/40 ${t.card}`}>
      <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${t.tile}`}>{icon}</span>
      <span className="min-w-0 flex-1">
        <span className="block text-[15px] font-semibold leading-snug">{title}</span>
        <span className="mt-1 line-clamp-2 block text-[13px] leading-snug text-mute">{sub}</span>
        <span className="mt-3 inline-flex items-center gap-1 text-[13px] font-semibold text-text">{action}<ChevronRight size={14} className="transition-transform group-hover:translate-x-0.5" /></span>
      </span>
    </button>
  )
}

/** A semicircle gauge for one share (0..1), the value in the middle. The arc takes the colour of what it measures. */
export function Gauge({ value, label, sub, color }: { value: number | null; label: string; sub?: ReactNode; color: string }) {
  const v = value == null ? 0 : Math.max(0, Math.min(1, value))
  const r = 64, c = Math.PI * r
  return (
    <div className="flex min-w-0 flex-col items-center text-center">
      <svg viewBox="0 0 160 92" className="w-full max-w-[220px]" role="img" aria-label={`${label}: ${value == null ? 'no data' : `${Math.round(v * 100)}%`}`}>
        <path d="M 16 80 A 64 64 0 0 1 144 80" fill="none" stroke="var(--color-panel-3)" strokeWidth={12} strokeLinecap="round" />
        {value != null && <path d="M 16 80 A 64 64 0 0 1 144 80" fill="none" stroke={color} strokeWidth={12} strokeLinecap="round"
                                strokeDasharray={`${c * v} ${c}`} />}
        <text x={80} y={72} textAnchor="middle" fill="var(--color-text)" fontSize={28} fontWeight={600} style={{ fontVariantNumeric: 'tabular-nums' }}>
          {value == null ? '—' : `${Math.round(v * 100)}%`}
        </text>
      </svg>
      <div className="mt-1 text-[14px] font-semibold">{label}</div>
      {sub && <div className="mt-0.5 text-[12.5px] leading-snug text-mute">{sub}</div>}
    </div>
  )
}

/** Parts of a whole: one stacked bar with 2px seams, then the list with shares. */
export function StackBar({ parts, unit }: { parts: { label: string; value: number; color: string; note?: ReactNode }[]; unit: string }) {
  const total = parts.reduce((s, p) => s + p.value, 0) || 1
  return (
    <div>
      <div className="flex h-3 w-full gap-[2px] overflow-hidden rounded-full" role="img"
           aria-label={parts.map((p) => `${p.label} ${Math.round((100 * p.value) / total)}%`).join(', ')}>
        {parts.map((p) => <span key={p.label} className="h-full first:rounded-l-full last:rounded-r-full" style={{ width: `${(100 * p.value) / total}%`, background: p.color }} title={`${p.label}: ${p.value.toLocaleString('en-IN')} ${unit}`} />)}
      </div>
      <ul className="mt-4 space-y-2.5">
        {parts.map((p) => (
          <li key={p.label} className="flex items-center gap-3 text-[13.5px]">
            <span className="h-2.5 w-2.5 shrink-0 rounded-[3px]" style={{ background: p.color }} />
            <span className="min-w-0 flex-1 truncate">{p.label}{p.note && <span className="ml-2 text-faint">{p.note}</span>}</span>
            <span className="font-mono text-[13px] text-mute">{p.value.toLocaleString('en-IN')}</span>
            <span className="w-12 text-right font-mono text-[13px]">{((100 * p.value) / total).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Ranked bars: the leader in the accent colour it was given, the rest in grey (one series argues). */
export function BarList({ rows, color, onPick }: {
  rows: { key: string; label: ReactNode; value: number; sub?: ReactNode; hot?: boolean }[]; color: string; onPick?: (key: string) => void
}) {
  const max = Math.max(1, ...rows.map((r) => r.value))
  return (
    <ul className="space-y-3">
      {rows.map((r) => {
        const body = (
          <>
            <div className="flex items-baseline justify-between gap-3 text-[13.5px]">
              <span className="min-w-0 truncate font-medium">{r.label}{r.sub && <span className="ml-2 font-normal text-faint">{r.sub}</span>}</span>
              <span className="font-mono text-[13px]">{r.value.toLocaleString('en-IN')}</span>
            </div>
            <div className="mt-1.5 h-2 rounded-full bg-panel-2">
              <div className="h-full rounded-full" style={{ width: `${Math.max(2, (100 * r.value) / max)}%`, background: r.hot ? color : 'var(--color-line-2)' }} />
            </div>
          </>
        )
        return <li key={r.key}>{onPick ? <button onClick={() => onPick(r.key)} className="block w-full rounded-lg text-left hover:opacity-85">{body}</button> : body}</li>
      })}
    </ul>
  )
}

/** A strip of compact boxes, one panel open below (ui-10). Each box is a short summary with a visible Open/Close
 *  chevron; the open box is outlined and a notch points at its panel, which grows and shrinks in place, so the rows
 *  below simply move. One panel at a time; none open is allowed. Keyboard: Enter or Space on a box. */
export function TabBoxes<K extends string>({ label, items, defaultOpen = null }: {
  label: string
  items: { key: K; title: ReactNode; chip?: ReactNode; count?: ReactNode; preview: ReactNode; panel: ReactNode }[]
  defaultOpen?: K | null
}) {
  const [open, setOpen] = useState<K | null>(defaultOpen)
  const [shown, setShown] = useState<K | null>(defaultOpen)
  const [grown, setGrown] = useState(!!defaultOpen)
  useEffect(() => {
    if (open) {
      setShown(open)
      const id = requestAnimationFrame(() => requestAnimationFrame(() => setGrown(true)))
      return () => cancelAnimationFrame(id)
    }
    setGrown(false)
    const t = window.setTimeout(() => setShown(null), 360)
    return () => window.clearTimeout(t)
  }, [open])
  const cols = items.length >= 5 ? 'sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5' : items.length === 4 ? 'sm:grid-cols-2 xl:grid-cols-4' : items.length === 3 ? 'sm:grid-cols-3' : 'sm:grid-cols-2'
  const current = items.find((it) => it.key === shown)
  return (
    <div role="group" aria-label={label}>
      <div className={`grid gap-4 ${cols}`}>
        {items.map((it) => {
          const on = open === it.key
          return (
            <button key={it.key} onClick={() => setOpen(on ? null : it.key)} aria-expanded={on} aria-controls={`tabbox-${label}-${it.key}`}
                    className={`soc-pressable group relative flex min-h-[124px] flex-col rounded-2xl border p-4 text-left ${on ? 'is-open border-text bg-panel' : 'soc-dark soc-tile border-transparent'}`}>
              <span className="flex min-w-0 items-center gap-2 text-[15px] font-semibold"><span className="truncate">{it.title}</span>{it.chip}</span>
              <span className="mt-1.5 line-clamp-2 min-w-0 flex-1 text-[13px] leading-snug text-mute">{it.preview}</span>
              <span className="mt-3 flex items-end justify-between gap-3">
                <span className="text-[22px] font-semibold leading-none tabular-nums">{it.count ?? ''}</span>
                <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[12.5px] font-semibold transition-colors ${on ? 'border-text bg-panel text-text' : 'border-text bg-text text-ink'}`}>
                  {on ? 'Close' : 'Open'}<ChevronDown size={15} strokeWidth={2.5} className={`transition-transform duration-200 ${on ? 'rotate-180' : 'group-hover:translate-y-0.5'}`} />
                </span>
              </span>
              {on && <span aria-hidden className="absolute -bottom-[9px] left-1/2 h-4 w-4 -translate-x-1/2 rotate-45 border-b border-r border-text bg-panel" />}
            </button>
          )
        })}
      </div>
      <div className="soc-reveal" data-open={grown}>
        <div className="min-h-0 overflow-hidden">
          {current && <div id={`tabbox-${label}-${current.key}`} role="region" aria-label={typeof current.title === 'string' ? current.title : label} className="pt-4">{current.panel}</div>}
        </div>
      </div>
    </div>
  )
}

/** A whole number that counts to its new value when the data changes (600 ms, still under reduced motion). */
export function AnimatedNumber({ value, format = (v) => v.toLocaleString('en-IN') }: { value: number; format?: (v: number) => string }) {
  const [shown, setShown] = useState(value)
  const prev = useRef(value)
  useEffect(() => {
    const from = prev.current, to = value
    prev.current = value
    if (from === to || window.matchMedia('(prefers-reduced-motion: reduce)').matches) { setShown(to); return }
    const t0 = performance.now()
    let raf = 0
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / 600)
      setShown(Math.round(from + (to - from) * (1 - (1 - p) ** 3)))
      if (p < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [value])
  return <>{format(shown)}</>
}

/** A block's four states share one frame: loading keeps the shape, error says what broke. */
export function Pending({ error, h = 160, what }: { error?: string; h?: number; what: string }) {
  return (
    <div className="flex items-center justify-center rounded-xl border border-dashed border-line text-[13px] text-faint" style={{ height: h }}>
      {error ? `Couldn't load ${what} (${error}). Is the API on :8000?` : `Loading ${what}…`}
    </div>
  )
}
