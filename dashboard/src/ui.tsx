import { RotateCw } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { now } from './data'
import { duration, sla } from './format'
import type { Tier } from './types'

export const TIER_COLOR: Record<Tier, string> = {
  Compromise: 'var(--color-compromise)',
  Critical: 'var(--color-critical)',
  High: 'var(--color-high)',
  Medium: 'var(--color-medium)',
  Watch: 'var(--color-watch)',
}

/** One status mark per row: a small square in the tier colour, always with its word. */
export function TierMark({ tier, label = true }: { tier: Tier; label?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap">
      <span className="size-2 shrink-0 rounded-[2px]" style={{ background: TIER_COLOR[tier] }} aria-hidden />
      {label && <span>{tier}</span>}
    </span>
  )
}

export function Panel({ title, meta, action, children, className = '', pad = true }: {
  title?: string; meta?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; pad?: boolean
}) {
  return (
    <section className={`flex min-w-0 flex-col rounded-lg bg-panel ${className}`}>
      {title && (
        <header className="flex items-baseline justify-between gap-4 px-5 pt-4 pb-3">
          <div className="min-w-0">
            <h2 className="text-[15px] font-semibold">{title}</h2>
            {meta && <p className="mt-0.5 text-[13px] text-mute">{meta}</p>}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </header>
      )}
      <div className={pad ? 'px-5 pb-5' : 'pb-2'}>{children}</div>
    </section>
  )
}

export function Kpis({ items }: { items: { label: string; value: ReactNode; sub?: ReactNode; answer?: boolean; tone?: string }[] }) {
  return (
    // One card split by hairlines: the 1px gaps show the line colour behind the cells at every breakpoint.
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg bg-line sm:grid-cols-3 xl:grid-cols-6">
      {items.map((k) => (
        <div key={k.label} className="bg-panel px-5 py-4">
          <div className="text-[13px] text-mute">{k.label}</div>
          <div className={`num mt-1 font-semibold tracking-tight ${k.answer ? 'text-[34px] leading-10' : 'text-[26px] leading-10'}`} style={k.tone ? { color: k.tone } : undefined}>
            {k.value}
          </div>
          {k.sub && <div className="mt-0.5 text-[12px] text-faint">{k.sub}</div>}
        </div>
      ))}
    </div>
  )
}

export function Button({ children, onClick, variant = 'secondary', disabled, title, type = 'button', size = 'md' }: {
  children: ReactNode; onClick?: () => void; variant?: 'primary' | 'secondary' | 'ghost'; disabled?: boolean; title?: string
  type?: 'button' | 'submit'; size?: 'sm' | 'md'
}) {
  const base = 'inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-[filter,background-color] disabled:cursor-not-allowed whitespace-nowrap'
  const sz = size === 'sm' ? 'h-7 px-2.5 text-[13px]' : 'h-9 px-3.5 text-[14px]'
  const look = {
    primary: 'bg-text text-ground hover:brightness-90 active:brightness-75 disabled:bg-raised disabled:text-faint',
    secondary: 'bg-raised text-text hover:bg-[#28282b] active:bg-[#303033] disabled:text-faint',
    ghost: 'text-mute hover:bg-raised hover:text-text disabled:text-faint',
  }[variant]
  return (
    <button type={type} className={`${base} ${sz} ${look}`} onClick={onClick} disabled={disabled} title={title}>
      {children}
    </button>
  )
}

/** Loading: flat grey bars at real size, no shimmer. */
export function Bars({ rows = 4, h = 18 }: { rows?: number; h?: number }) {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="rounded bg-raised" style={{ height: h, width: `${92 - i * 9}%` }} />
      ))}
    </div>
  )
}

export function ErrorLine({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2 text-[13px] text-mute">
      <span>Couldn’t load this: {message}.</span>
      {onRetry && <Button size="sm" onClick={onRetry}><RotateCw size={13} /> Retry</Button>}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-3 text-[13px] text-mute">{children}</p>
}

export function useNow(intervalMs = 1000): number {
  const [t, setT] = useState(now())
  useEffect(() => {
    const id = setInterval(() => setT(now()), intervalMs)
    return () => clearInterval(id)
  }, [intervalMs])
  return t
}

/** Time left on the SLA; colour only when it is at risk or breached, and the words always say which. */
export function Countdown({ issuedAt, hours, closed }: { issuedAt: string; hours: number | null; closed?: boolean }) {
  const t = useNow(15000)
  if (closed) return <span className="text-faint">Done</span>
  const s = sla(issuedAt, hours, t)
  if (s.state === 'none') return <span className="text-faint">No deadline</span>
  if (s.state === 'breached') return <span className="num text-compromise">Overdue {duration(s.leftMs)}</span>
  return <span className={`num ${s.state === 'risk' ? 'text-critical' : ''}`}>{duration(s.leftMs)} left</span>
}

export function Provenance({ p }: { p: string | null | undefined }) {
  if (!p) return null
  const label: Record<string, string> = { REAL: 'Real', SIM: 'Simulated', AI: 'AI', AUTO: 'Odyssey', HUMAN: 'Analyst' }
  return <span className="whitespace-nowrap text-[12px] text-faint">{label[p] ?? p}</span>
}

/** A status square in one colour, always with its word (campaign status, elevated, confirmed…). */
export function Mark({ color, children }: { color: string; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap">
      <span className="size-2 shrink-0 rounded-[2px]" style={{ background: color }} aria-hidden />
      <span>{children}</span>
    </span>
  )
}

/** "Show all N" for lists capped at a few rows; renders nothing when the list is short. */
export function ShowAll({ total, cap, open, onToggle }: { total: number; cap: number; open: boolean; onToggle: () => void }) {
  if (total <= cap) return null
  return <button className="text-[13px] text-mute hover:text-text" onClick={onToggle}>{open ? 'Show fewer' : `Show all ${total}`}</button>
}

/** Single-series sparkline from zero: one hue, no fill. Optional shaded windows (index ranges), e.g. a detected surge. */
export function Spark({ values, bands = [], color = 'var(--color-mute)', h = 36, label }: {
  values: number[]; bands?: [number, number][]; color?: string; h?: number; label?: string
}) {
  if (values.length < 2) return null
  const w = 160
  const max = Math.max(...values) || 1
  const x = (i: number) => (i / (values.length - 1)) * w
  const y = (v: number) => h - 2 - (v / max) * (h - 4)
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="block w-full" style={{ height: h }} role="img" aria-label={label}>
      {bands.map(([a, b], i) => <rect key={i} x={x(a)} y={0} width={Math.max(x(b) - x(a), 2)} height={h} fill="var(--color-text)" opacity={0.1} />)}
      <polyline points={values.map((v, i) => `${x(i)},${y(v)}`).join(' ')} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  )
}
