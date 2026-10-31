import { useState } from 'react'
import { Area, CartesianGrid, ComposedChart, Line, ReferenceDot, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, useLoad } from '../data'
import { hours, num, pct } from '../format'
import type { RiskPlan } from '../types'
import { Bars, Empty, ErrorLine, Kpis, Panel, ShowAll, TierMark } from '../ui'

const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`
const TICK = { fill: '#8a8a8a', fontSize: 12 }

/** Cumulative share of open risk removed after k changes, in plan order. The API returns the curve ticket by ticket
 *  for the first 60 changes only; past that it gives the 50% / 80% milestones and the ticket count (100%), which the
 *  dashed line joins. The legend under the chart says so. */
function BurnDown({ r }: { r: RiskPlan }) {
  const last = r.curve[r.curve.length - 1]
  const data: { k: number; measured?: number; milestone?: number }[] = r.curve.map((c) => ({ k: c.k, measured: c.cum_pct }))
  const extended = !!last && r.tickets > last.k
  if (extended) {
    data[data.length - 1].milestone = last.cum_pct
    const ms: [number | null, number][] = [[r.for_50_pct, 50], [r.for_80_pct, 80], [r.tickets, 100]]
    for (const [k, v] of ms) if (k != null && k > last.k && v > last.cum_pct) data.push({ k, milestone: v })
  }
  const xMax = Math.max(r.tickets, last?.k ?? 0, 1)
  const ref = (y: 50 | 80, k: number | null) => (
    <ReferenceLine y={y} stroke="#6e6e73" strokeDasharray="4 4"
      label={{ value: k != null ? `${y}% after ${plural(k, 'change')}` : `${y}%: not reached`, position: 'insideBottomLeft', fill: '#a1a1a1', fontSize: 12 }} />
  )
  return (
    <>
      <div className="h-[260px]">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 12, right: 16, bottom: 0, left: -12 }}>
            <CartesianGrid vertical={false} stroke="#29292c" />
            <XAxis type="number" dataKey="k" domain={[0, xMax]} allowDecimals={false} tickLine={false} axisLine={false} tick={TICK} />
            <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tickFormatter={(v: number) => `${v}%`} tickLine={false} axisLine={false} tick={TICK} />
            <Tooltip cursor={{ stroke: '#3a3a3d' }} contentStyle={{ background: '#1f1f21', border: 'none', borderRadius: 6, fontSize: 13 }}
              labelFormatter={(k) => `After ${plural(Number(k), 'change')}`}
              formatter={(v, name) => [`${num(Number(v), 1)}% of risk removed`, name === 'milestone' ? 'Milestone' : 'Plan']} />
            {ref(50, r.for_50_pct)}
            {ref(80, r.for_80_pct)}
            <Area type="linear" dataKey="measured" stroke="var(--color-ok)" strokeWidth={2} fill="var(--color-ok)" fillOpacity={0.12} dot={false} isAnimationActive={false} />
            {extended && <Line type="linear" dataKey="milestone" stroke="var(--color-ok)" strokeWidth={2} strokeDasharray="5 5" dot={false} connectNulls isAnimationActive={false} />}
            {([[r.for_50_pct, 50], [r.for_80_pct, 80]] as const).map(([k, share]) => k != null && (
              // On the measured curve where it is known (one ticket can overshoot the share); on the milestone otherwise.
              <ReferenceDot key={share} x={k} y={r.curve.find((c) => c.k === k)?.cum_pct ?? share} r={3.5} fill="var(--color-ok)" stroke="none" />
            ))}
          </ComposedChart>
        </ResponsiveContainer>
      </div>
      <p className="mt-2 text-[12px] text-faint">
        Across: changes made, in plan order. Up: share of open risk removed.
        {extended && ` Solid: ticket by ticket for the first ${num(last.k)} changes. Dashed: joins the 50%, 80% and 100% milestones the plan reports beyond that.`}
      </p>
    </>
  )
}

function Tickets({ r }: { r: RiskPlan }) {
  const [all, setAll] = useState(false)
  const national = r.scope === 'national'
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1080px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 text-right font-normal">Rank</th>
              {national && <th className="pb-2 font-normal">Organisation</th>}
              <th className="pb-2 font-normal">Change</th>
              <th className="pb-2 pl-4 text-right font-normal">CVEs</th>
              <th className="pb-2 pl-6 font-normal">Top tier</th>
              <th className="pb-2 pl-6 text-right font-normal">Deadline</th>
              <th className="pb-2 pl-6 text-right font-normal" title="1 for one host, plus 0.25 for each extra host">Effort</th>
              <th className="pb-2 pl-6 text-right font-normal">Risk removed</th>
              <th className="px-5 pb-2 text-right font-normal">Cumulative</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {(all ? r.plan : r.plan.slice(0, 8)).map((t) => (
              <tr key={`${t.rank}-${t.org_id}-${t.product}`}>
                <td className="num px-5 py-2.5 text-right align-top text-mute">{t.rank}</td>
                {national && <td className="py-2.5 pr-4 align-top"><a href={`#/orgs/${t.org_id}`} className="hover:underline">{t.org}</a></td>}
                <td className="max-w-[380px] py-2.5 pr-4 align-top">
                  <span className="block">
                    {t.label} <span className="num">{t.version}</span>
                    {t.target_version ? <> → <span className="num font-medium">{t.target_version}</span></> : <span className="text-mute"> → no fixed release named; follow the vendor advisory</span>}
                  </span>
                  <span className="block truncate text-[13px] text-mute">{plural(t.n_assets, 'host')}: {t.assets.join(', ')} · owner {t.owners.join(', ') || '—'}</span>
                </td>
                <td className="num py-2.5 pl-4 text-right align-top whitespace-nowrap">{num(t.n_cves)}{t.kev_cves > 0 && <span className="block text-[13px] text-mute">{num(t.kev_cves)} KEV</span>}</td>
                <td className="py-2.5 pl-6 align-top"><TierMark tier={t.top_tier} /></td>
                <td className="num py-2.5 pl-6 text-right align-top whitespace-nowrap">{hours(t.deadline_hours)}</td>
                <td className="num py-2.5 pl-6 text-right align-top">{num(t.effort, 2)}</td>
                <td className="num py-2.5 pl-6 text-right align-top">{pct(t.pct)}</td>
                <td className="num px-5 py-2.5 text-right align-top">{pct(t.cum_pct)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-5 pt-1"><ShowAll total={r.plan.length} cap={8} open={all} onToggle={() => setAll((v) => !v)} /></div>
    </>
  )
}

export function RiskPlanScreen({ org }: { org?: string }) {
  const soc = useLoad(api.soc, 'soc')
  const plan = useLoad(() => api.riskplan(org), `risk:${org ?? 'national'}`)
  const r = plan.data
  const orgs = soc.data?.orgs ?? []
  const name = org ? orgs.find((o) => o.id === org)?.name ?? org : null

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4 pb-2">
        <div className="min-w-0">
          <h1 className="text-[26px] font-semibold tracking-tight">Risk plan</h1>
          <p className="text-mute">The fewest changes that remove the most risk{name ? ` at ${name}` : ' across the constituency'}, in the order to make them.</p>
        </div>
        <select value={org ?? ''} aria-label="Scope" onChange={(e) => { window.location.hash = e.target.value ? `/risk/${e.target.value}` : '/risk' }}
          className="h-9 max-w-full rounded-md bg-panel px-2.5 text-[13px] text-text outline-none">
          <option value="">All organisations (national)</option>
          {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
          {org && !orgs.some((o) => o.id === org) && <option value={org}>{org}</option>}
        </select>
      </div>

      {plan.error ? <Panel><ErrorLine message={plan.error} onRetry={plan.reload} /></Panel> : (
        <Kpis items={[
          { label: 'Changes for 50% of risk', value: r ? num(r.for_50_pct) : '—', answer: true, sub: r ? `of ${plural(r.tickets, 'ticket')}` : undefined },
          { label: 'Changes for 80% of risk', value: r ? num(r.for_80_pct) : '—', sub: r ? `of ${plural(r.tickets, 'ticket')}` : undefined },
          { label: 'Change tickets', value: r ? num(r.tickets) : '—', sub: 'one per organisation, product and version' },
          { label: 'Assets at risk', value: r ? num(r.assets_at_risk) : '—', sub: 'with an open warning' },
          { label: 'Open risk', value: r ? num(r.total_risk) : '—', sub: 'sum of each asset’s worst risk' },
          { label: 'Accepted risk', value: r ? num(r.accepted_risk) : '—', sub: 'closed by an analyst as accepted' },
        ]} />
      )}

      <Panel title="Burn-down" meta="How much open risk is gone after each change, if they are made in this order">
        {plan.loading ? <Bars rows={6} h={24} />
          : plan.error || !r ? <ErrorLine message={plan.error ?? 'no plan'} onRetry={plan.reload} />
          : r.tickets === 0 ? <Empty>No open risk: every warning here is closed or accepted.</Empty>
          : <BurnDown r={r} />}
        {r && (
          <p className="mt-3 text-[13px] text-mute">
            <span className="text-text">Method.</span> Each asset’s risk is its worst open warning. One ticket per organisation, product and installed version,
            with the lowest fixed release that clears every CVE on it. Tickets are ordered by urgency first (suspected compromise, then known-exploited),
            then by risk removed per unit of effort (1 per host, plus 0.25 per extra host).
          </p>
        )}
      </Panel>

      <Panel title="Change tickets" meta={r ? `Top ${num(r.plan.length)} of ${plural(r.tickets, 'ticket')}, in the order to make them` : 'In the order to make them'} pad={false}>
        {plan.loading ? <div className="px-5"><Bars rows={8} /></div>
          : plan.error || !r ? <div className="px-5"><ErrorLine message={plan.error ?? 'no plan'} onRetry={plan.reload} /></div>
          : r.plan.length === 0 ? <div className="px-5"><Empty>No change tickets.</Empty></div>
          : <Tickets r={r} />}
      </Panel>
    </div>
  )
}
