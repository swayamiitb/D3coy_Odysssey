import { ShieldCheck, Siren } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Feed, Soc, Summary, Technology } from '../api'
import { TIER_FILL } from '../ui'
import { Countdown } from '../Now'
import { Delta, nf, Pending, useJson } from './kit'

/* The Now page's command-centre pieces taken from the reference screens (ui-08): the red alert banner, the score card,
   the threat-distribution donut, the security insight, exposure by sector and the security KPIs. Every number traces to
   an API field; the insight is written from those numbers by a template, not by a model. */

/** The red chip in the top bar: the one thing that cannot wait, with its clock. Shown only while a suspected compromise
 *  is open; click opens the incident. */
export function AlertChip({ tick, onOpen }: { tick: number; onOpen: (c: Feed['cards'][number]) => void }) {
  const { data } = useJson<Feed>('/api/feed', [tick], 20000)
  const c = data?.cards.find((x) => x.tier === 'Compromise')
  if (!data || !c) return null
  return (
    <button onClick={() => onOpen(c)} title={`${c.org_name}: ${c.cve_id}. Open the incident`}
            className="flex h-10 shrink-0 items-center gap-2 rounded-full bg-crit px-3 text-[13px] font-semibold text-white transition-opacity hover:opacity-90">
      <Siren size={14} className="soc-live" />
      <span className="hidden sm:inline">Compromise</span>
      <Countdown issuedAt={(c as typeof c & { issued_at?: string }).issued_at ?? data.issued_at} hours={c.deadline_hours} />
    </button>
  )
}

/** The full-width red banner, kept for pages that want it (the chip above is the default now). */
export function AlertBanner({ tick, onOpen }: { tick: number; onOpen: (c: Feed['cards'][number]) => void }) {
  const { data } = useJson<Feed>('/api/feed', [tick], 20000)
  const c = data?.cards.find((x) => x.tier === 'Compromise')
  if (!data || !c) return null
  return (
    <div className="bg-crit text-white">
      <div className="mx-auto flex w-full max-w-[1680px] flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2 text-[13.5px] sm:px-6 lg:px-10">
        <span className="flex items-center gap-2 font-semibold"><Siren size={15} /> Suspected compromise at {c.org_name}</span>
        <span className="hidden opacity-90 sm:inline">{c.cve_id} · {c.headline ?? c.title.split('.')[0]}</span>
        <span className="flex items-center gap-2">
          <span className="opacity-90">left to report to CERT-In</span>
          <Countdown issuedAt={(c as typeof c & { issued_at?: string }).issued_at ?? data.issued_at} hours={c.deadline_hours} />
        </span>
        <button onClick={() => onOpen(c)} className="ml-auto rounded-full bg-white px-3.5 py-1 text-[13px] font-semibold text-black transition-opacity hover:opacity-85">Review</button>
      </div>
    </div>
  )
}

interface Scorecard { funnel: { cves_this_month: number; candidates: number; actionable_alerts: number; critical_or_compromise: number; noise_reduction_x: number } }
/** The gradient score card: the product's one headline figure, from the measured funnel. */
export function ScoreCard() {
  const { data, error } = useJson<Scorecard>('/api/scorecard')
  return (
    <div className="flex min-h-[132px] flex-col justify-between rounded-2xl bg-[linear-gradient(135deg,#2f7bff_0%,#1549b8_100%)] px-5 py-4 text-white">
      <div className="flex items-center justify-between text-[13px] font-medium opacity-90"><span>Noise reduction</span><ShieldCheck size={15} /></div>
      {data ? (
        <>
          <div className="text-[34px] font-semibold leading-none tracking-tight tabular-nums">{data.funnel.noise_reduction_x}×</div>
          <div className="text-[12.5px] leading-snug opacity-90">{nf(data.funnel.cves_this_month)} CVEs this month → {nf(data.funnel.critical_or_compromise)} warnings that matter</div>
        </>
      ) : <div className="text-[13px] opacity-80">{error ? 'scorecard unavailable' : 'measuring…'}</div>}
    </div>
  )
}

const TIER_ORDER = ['Compromise', 'Critical', 'High', 'Medium'] as const
/** Threat distribution: a donut of open warnings by tier, the total in the middle, the shares beside it. */
export function TierDonut({ soc }: { soc?: Soc }) {
  if (!soc) return <Pending what="the distribution" h={200} />
  const parts = TIER_ORDER.map((t) => ({ t, n: soc.tiers[t] ?? 0 })).filter((p) => p.n > 0)
  const total = parts.reduce((s, p) => s + p.n, 0) || 1
  const r = 42, c = 2 * Math.PI * r
  let acc = 0
  return (
    <div className="flex flex-wrap items-center gap-5">
      <svg viewBox="0 0 110 110" className="h-[148px] w-[148px] shrink-0" role="img" aria-label={`${nf(total)} open warnings: ${parts.map((p) => `${p.t} ${Math.round((100 * p.n) / total)}%`).join(', ')}`}>
        <circle cx={55} cy={55} r={r} fill="none" stroke="var(--color-panel-2)" strokeWidth={12} />
        {parts.map((p) => {
          const len = (c * p.n) / total
          const el = <circle key={p.t} cx={55} cy={55} r={r} fill="none" stroke={TIER_FILL[p.t]} strokeWidth={12}
                             strokeDasharray={`${Math.max(0, len - 2)} ${c}`} strokeDashoffset={-acc} transform="rotate(-90 55 55)" />
          acc += len
          return el
        })}
        <text x={55} y={52} textAnchor="middle" fill="var(--color-text)" fontSize={19} fontWeight={600} style={{ fontVariantNumeric: 'tabular-nums' }}>{nf(total)}</text>
        <text x={55} y={67} textAnchor="middle" fill="var(--color-mute)" fontSize={9.5}>open warnings</text>
      </svg>
      <ul className="min-w-[180px] flex-1 space-y-2">
        {parts.map((p) => (
          <li key={p.t} className="flex items-center gap-2.5 text-[13.5px]">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: TIER_FILL[p.t] }} />
            <span className="flex-1">{p.t === 'Compromise' ? 'Suspected compromise' : p.t}</span>
            <span className="font-mono text-[13px] text-mute">{nf(p.n)}</span>
            <span className="w-12 text-right font-mono text-[13px]">{((100 * p.n) / total).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Security insight: the page's figures, read back as sentences. A template, so it never says more than the data. */
export function Insight({ soc, feed }: { soc?: Soc; feed?: Feed }) {
  const tech = useJson<Technology[]>('/api/intel/technologies').data
  if (!soc || !feed) return <Pending what="the insight" h={120} />
  const comp = feed.cards.filter((c) => c.tier === 'Compromise')
  const p = soc.pressure, last = p.at(-1), prev = p.at(-31) ?? p[0]
  const top = (tech ?? []).filter((t) => t.critical > 0).sort((a, b) => b.critical - a.critical)[0]
  const campaigns = (tech ?? []).filter((t) => t.campaign === 'ACTIVE').length
  const lines: ReactNode[] = []
  if (comp.length) lines.push(<>{comp.length === 1 ? 'One suspected compromise is' : `${comp.length} suspected compromises are`} open, at {[...new Set(comp.map((c) => c.org_name))].join(' and ')}; the CERT-In six-hour clock is running.</>)
  else lines.push(<>No asset shows signs of compromise right now.</>)
  if (last && prev) {
    const d = last.Critical - prev.Critical
    lines.push(<>Open Critical warnings {d === 0 ? 'held steady' : `${d > 0 ? 'rose' : 'fell'} by ${Math.abs(d)} (${Math.abs(Math.round((100 * d) / Math.max(1, prev.Critical)))}%)`} over the last 30 days, to {nf(last.Critical)}.</>)
  }
  if (top) lines.push(<>{top.label} carries the most, {top.critical} Critical at {top.orgs} operators{top.campaign === 'ACTIVE' ? ', and is under an active campaign' : ''}{campaigns > 1 ? ` (${campaigns} campaigns are active in all)` : ''}.</>)
  if (soc.risk.for_80_pct != null) lines.push(<>{soc.risk.for_80_pct} changes out of {nf(soc.risk.tickets)} would remove 80% of the national risk.</>)
  return (
    <div className="flex gap-4">
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-panel-2 text-text"><ShieldCheck size={18} /></span>
      <div className="min-w-0">
        <p className="text-[14px] leading-relaxed">{lines.map((l, i) => <span key={i}>{l} </span>)}</p>
        <p className="mt-2 text-[12px] text-faint">Written from this page's figures by a fixed template; no model involved. Sources: the warning feed, the replayed timelines, the technology inventory and the risk plan.</p>
      </div>
    </div>
  )
}

/** Exposure by sector: Critical warnings per critical-infrastructure sector; the sector with a compromise in purple. */
export function SectorExposure() {
  const { data, error } = useJson<Summary>('/api/summary')
  if (!data) return <Pending error={error} what="sector exposure" h={220} />
  const rows = Object.entries(data.sector_heatmap).map(([sector, t]) => ({ sector, crit: (t.Critical ?? 0) + (t.Compromise ?? 0), comp: t.Compromise ?? 0, high: t.High ?? 0 }))
    .sort((a, b) => b.crit - a.crit)
  const max = Math.max(1, ...rows.map((r) => r.crit))
  const total = rows.reduce((s, r) => s + r.crit, 0) || 1
  return (
    <ul className="space-y-3">
      {rows.map((r) => (
        <li key={r.sector}>
          <div className="flex items-baseline justify-between gap-3 text-[13.5px]">
            <span className="min-w-0 truncate font-medium">{r.sector}{r.comp > 0 && <span className="ml-2 font-normal text-comp-ink">{r.comp} suspected compromise</span>}</span>
            <span className="font-mono text-[13px]"><span className="text-mute">{Math.round((100 * r.crit) / total)}% · </span>{r.crit}</span>
          </div>
          <div className="mt-1.5 h-2 rounded-full bg-panel-2">
            <div className="h-full rounded-full" style={{ width: `${Math.max(2, (100 * r.crit) / max)}%`, background: r.comp ? TIER_FILL.Compromise : TIER_FILL.Critical }} />
          </div>
        </li>
      ))}
    </ul>
  )
}

interface Metrics { open: number; overdue: number; unassigned: number }
/** Security KPIs: the figures a CISO asks for, each with its basis. */
export function SecurityKpis({ soc }: { soc?: Soc }) {
  const { data: m } = useJson<Metrics>('/api/soc/metrics')
  if (!soc) return <Pending what="the KPIs" h={220} />
  const p = soc.pressure, last = p.at(-1), prev = p.at(-31) ?? p[0]
  const bm = soc.autopilot.by_mode
  const rows: { label: string; value: string; sub: ReactNode; pct?: number; color: string }[] = [
    { label: 'Critical warnings', value: nf(soc.tiers.Critical), color: TIER_FILL.Critical,
      sub: last && prev ? <Delta now={last.Critical} before={prev.Critical} good="down" window="open, vs 30 days ago" /> : `${nf(soc.tiers.High)} High` },
    { label: 'Response coverage', value: m ? `${Math.round((100 * (m.open - m.unassigned)) / Math.max(1, m.open))}%` : '—', color: 'var(--color-text)',
      pct: m ? (m.open - m.unassigned) / Math.max(1, m.open) : undefined, sub: m ? `${nf(m.open - m.unassigned)} of ${nf(m.open)} open cases have an owner` : 'from the case board' },
    { label: 'Inside deadline', value: m ? `${Math.round((100 * (m.open - m.overdue)) / Math.max(1, m.open))}%` : '—', color: m?.overdue ? TIER_FILL.Critical : 'var(--color-ok)',
      pct: m ? (m.open - m.overdue) / Math.max(1, m.open) : undefined, sub: m ? (m.overdue ? `${nf(m.overdue)} past the CERT-In timeline` : 'none past the CERT-In timeline') : 'CERT-In timelines' },
    { label: 'Handled on its own', value: bm ? `${Math.round((100 * bm.auto) / Math.max(1, bm.auto + bm.approve))}%` : '—', color: 'var(--color-accent)',
      pct: bm ? bm.auto / Math.max(1, bm.auto + bm.approve) : undefined, sub: bm ? `${nf(bm.auto)} of ${nf(bm.auto + bm.approve)} actions; the rest waited for a person` : undefined },
  ]
  return (
    <ul className="divide-y divide-line">
      {rows.map((r) => (
        <li key={r.label} className="flex items-center gap-4 py-2.5 first:pt-0 last:pb-0">
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-medium text-mute">{r.label}</div>
            <div className="mt-0.5 text-[12.5px] leading-snug text-faint">{r.sub}</div>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            {r.pct != null && <div className="hidden h-1.5 w-16 rounded-full bg-panel-2 sm:block"><div className="h-full rounded-full" style={{ width: `${Math.round(100 * r.pct)}%`, background: r.color }} /></div>}
            <span className="w-14 text-right text-[20px] font-semibold tabular-nums">{r.value}</span>
          </div>
        </li>
      ))}
    </ul>
  )
}
