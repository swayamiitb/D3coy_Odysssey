import { ArrowRight } from 'lucide-react'
import { useState } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, now, useLoad } from '../data'
import { date, num, sla, STATE_LABEL, TIER_RANK } from '../format'
import type { Approval, Card, Soc } from '../types'
import { Bars, Button, Countdown, Empty, ErrorLine, Kpis, Panel, TierMark } from '../ui'

export const LANG: Record<string, string> = {
  as: 'Assamese', bn: 'Bengali', brx: 'Bodo', doi: 'Dogri', gu: 'Gujarati', hi: 'Hindi', kn: 'Kannada', ks: 'Kashmiri',
  kok: 'Konkani', mai: 'Maithili', ml: 'Malayalam', mni: 'Manipuri', mr: 'Marathi', ne: 'Nepali', or: 'Odia', pa: 'Punjabi',
  sa: 'Sanskrit', sat: 'Santali', sd: 'Sindhi', ta: 'Tamil', te: 'Telugu', ur: 'Urdu', en: 'English',
}

/** Open first, then by tier, then by the least time left. */
export function byUrgency(cards: Card[], t: number): Card[] {
  return [...cards].sort((a, b) => {
    const ca = a.workflow.state === 'closed' ? 1 : 0
    const cb = b.workflow.state === 'closed' ? 1 : 0
    if (ca !== cb) return ca - cb
    if (TIER_RANK[a.tier] !== TIER_RANK[b.tier]) return TIER_RANK[a.tier] - TIER_RANK[b.tier]
    return sla(a.workflow.issued_at, a.deadline_hours, t).leftMs - sla(b.workflow.issued_at, b.deadline_hours, t).leftMs
  })
}

export function CardRow({ c }: { c: Card }) {
  return (
    <a href={`#/incident/${c.org_id}/${c.cve_id}`}
      className="grid grid-cols-[110px_1fr_auto] items-center gap-x-4 gap-y-1 px-5 py-3 hover:bg-raised/60 sm:grid-cols-[120px_1fr_130px_110px_20px]">
      <TierMark tier={c.tier} />
      <div className="min-w-0">
        <div className="truncate font-medium">{c.headline ?? `${c.title} at ${c.org_name}`}</div>
        <div className="truncate text-[13px] text-mute">{c.org_name} · <span className="num">{c.cve_id}</span>{c.kev ? ' · on CISA KEV' : ''}</div>
      </div>
      <div className="text-right text-[13px] max-sm:col-start-3 max-sm:row-start-1">
        <Countdown issuedAt={c.workflow.issued_at} hours={c.deadline_hours} closed={c.workflow.state === 'closed'} />
      </div>
      <div className="text-[13px] text-mute max-sm:hidden">{STATE_LABEL[c.workflow.state]}</div>
      <ArrowRight size={15} className="text-faint max-sm:hidden" />
    </a>
  )
}

function Pressure({ soc }: { soc: Soc }) {
  const data = soc.pressure.map((p) => ({ date: p.date, value: p.Compromise + p.Critical }))
  const max = Math.max(4, ...data.map((d) => d.value))
  const top = Math.ceil((max * 1.15) / 4) * 4
  return (
    <div className="h-[220px]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
          <CartesianGrid vertical={false} stroke="#29292c" />
          <XAxis dataKey="date" tickLine={false} axisLine={false} minTickGap={48} tick={{ fill: '#8a8a8a', fontSize: 12 }}
            tickFormatter={(d: string) => new Date(d).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })} />
          <YAxis domain={[0, top]} tickCount={5} allowDecimals={false} tickLine={false} axisLine={false} tick={{ fill: '#8a8a8a', fontSize: 12 }} />
          <Tooltip cursor={{ stroke: '#3a3a3d' }} contentStyle={{ background: '#1f1f21', border: 'none', borderRadius: 6, fontSize: 13 }}
            labelFormatter={(d) => date(String(d))} formatter={(v) => [v, 'Critical or worse']} />
          <Area type="linear" dataKey="value" stroke="var(--color-critical)" strokeWidth={2} fill="var(--color-critical)" fillOpacity={0.12} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

function ApprovalRow({ a }: { a: Approval }) {
  return (
    <a href="#/decisions" className="block px-5 py-3 hover:bg-raised/60">
      <div className="line-clamp-2 font-medium">{a.title}</div>
      <div className="mt-0.5 text-[13px] text-mute">
        {a.orgs.length} organisation{a.orgs.length === 1 ? '' : 's'}{a.basis ? ` · ${a.basis}` : ''}{a.p != null ? ` · p = ${num(a.p, 2)}` : ''}
      </div>
    </a>
  )
}

export function Overview() {
  const soc = useLoad(api.soc, 'soc')
  const feed = useLoad(api.feed, 'feed')
  const approvals = useLoad(() => api.approvals('pending'), 'approvals')
  const [allOrgs, setAllOrgs] = useState(false)
  const t = now()

  const cards = feed.data?.cards ?? []
  const open = cards.filter((c) => c.workflow.state !== 'closed')
  const slas = open.map((c) => sla(c.workflow.issued_at, c.deadline_hours, t).state)
  const breached = slas.filter((s) => s === 'breached').length
  const atRisk = slas.filter((s) => s === 'risk').length
  const s = soc.data
  const lead = s?.autopilot.lead?.real_signals_only
  const compromise = s?.tiers.Compromise ?? 0

  return (
    <div className="space-y-4">
      <div className="pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">Overview</h1>
        <p className="text-mute">What needs a person now, across {s?.orgs.length ?? '—'} organisations.</p>
      </div>

      {soc.error ? <Panel><ErrorLine message={soc.error} onRetry={soc.reload} /></Panel> : (
        <Kpis items={[
          { label: 'Suspected compromise', value: s ? num(compromise) : '—', answer: true, tone: compromise > 0 ? 'var(--color-compromise)' : undefined, sub: '6-hour CERT-In clock' },
          { label: 'Critical warnings', value: s ? num(s.tiers.Critical ?? 0) : '—', sub: `${num(s?.tiers.High ?? null)} High` },
          { label: 'Awaiting your decision', value: s ? num(s.pending) : '—', sub: 'proposals from Odyssey' },
          { label: 'SLA breached', value: feed.data ? num(breached) : '—', tone: breached > 0 ? 'var(--color-compromise)' : undefined, sub: `${num(atRisk)} at risk, of ${num(open.length)} open` },
          { label: 'Acted on its own', value: s ? num(s.autopilot.by_mode?.auto ?? s.autopilot.actions ?? null) : '—', sub: s?.autopilot.go_live ? `since go-live, ${date(s.autopilot.go_live)}` : 'since go-live' },
          { label: 'Ahead of CISA KEV', value: lead?.median_lead_days != null ? `${num(lead.median_lead_days, 1)} d` : '—', sub: lead ? `median, ${lead.acted_before_kev} CVEs, real signals only` : 'real signals only' },
        ]} />
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
        <Panel title="Needs action now" meta="Open warnings, most urgent first" pad={false}
          action={<a href="#/queue" className="text-[13px] text-mute hover:text-text">View all {feed.data ? num(open.length) : ''}</a>}>
          {feed.loading ? <div className="px-5"><Bars rows={5} /></div>
            : feed.error ? <div className="px-5"><ErrorLine message={feed.error} onRetry={feed.reload} /></div>
            : open.length === 0 ? <div className="px-5"><Empty>Nothing open. Every warning is closed.</Empty></div>
            : <div className="divide-y divide-line/70">{byUrgency(open, t).slice(0, 6).map((c) => <CardRow key={c.id} c={c} />)}</div>}
        </Panel>

        <Panel title="Waiting for your decision" meta="Odyssey proposes; a person approves" pad={false}
          action={<a href="#/decisions" className="text-[13px] text-mute hover:text-text">Review all</a>}>
          {approvals.loading ? <div className="px-5"><Bars rows={4} /></div>
            : approvals.error ? <div className="px-5"><ErrorLine message={approvals.error} onRetry={approvals.reload} /></div>
            : (approvals.data ?? []).length === 0 ? <div className="px-5"><Empty>No proposals are waiting.</Empty></div>
            : <div className="divide-y divide-line/70">{approvals.data!.slice(0, 4).map((a) => <ApprovalRow key={a.id} a={a} />)}</div>}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
        <Panel title="Open warnings, day by day" meta="Critical or worse, replayed from the evidence ledger">
          {s ? <Pressure soc={s} /> : soc.error ? <ErrorLine message={soc.error} onRetry={soc.reload} /> : <Bars rows={6} h={24} />}
        </Panel>
        <Panel title="Who acted" meta="Graduated autonomy since go-live">
          {s ? (() => {
            const auto = s.autopilot.by_mode?.auto ?? 0
            const ask = s.autopilot.by_mode?.approve ?? 0
            const total = Math.max(auto + ask, 1)
            return (
              <div className="space-y-4">
                <div className="flex h-2 overflow-hidden rounded-full bg-raised" aria-hidden>
                  <div className="bg-text" style={{ width: `${(auto / total) * 100}%` }} />
                </div>
                <dl className="space-y-2 text-[14px]">
                  <div className="flex justify-between"><dt className="flex items-center gap-2"><span className="size-2 rounded-[2px] bg-text" />Ran on its own</dt><dd className="num">{num(auto)}</dd></div>
                  <div className="flex justify-between"><dt className="flex items-center gap-2"><span className="size-2 rounded-[2px] bg-raised ring-1 ring-line" />Proposed to an analyst</dt><dd className="num">{num(ask)}</dd></div>
                </dl>
                <p className="text-[13px] text-mute">Evidence-based notices, digests and hunts run on their own. Predictions, sensor-only warnings and regulator escalations always wait for a person.</p>
                <Button size="sm" variant="ghost" onClick={() => { window.location.hash = '/log' }}>Open the audit log <ArrowRight size={14} /></Button>
              </div>
            )
          })() : <Bars rows={4} />}
        </Panel>
      </div>

      <Panel title="Organisations" meta="Constituency, worst first" pad={false}
        action={s && s.orgs.length > 6 ? <button className="text-[13px] text-mute hover:text-text" onClick={() => setAllOrgs((v) => !v)}>{allOrgs ? 'Show fewer' : `Show all ${s.orgs.length}`}</button> : null}>
        {!s ? <div className="px-5"><Bars rows={5} /></div> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-[14px]">
              <thead>
                <tr className="text-left text-[12px] text-faint">
                  <th className="px-5 pb-2 font-normal">Organisation</th>
                  <th className="pb-2 font-normal">Sector</th>
                  <th className="pb-2 font-normal">State</th>
                  <th className="pb-2 text-right font-normal">Compromise</th>
                  <th className="pb-2 text-right font-normal">Critical</th>
                  <th className="px-5 pb-2 text-right font-normal">Alert language</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {(allOrgs ? s.orgs : s.orgs.slice(0, 6)).map((o) => (
                  <tr key={o.id}>
                    <td className="px-5 py-2.5 font-medium"><a href={`#/orgs/${o.id}`} className="hover:underline">{o.name}</a></td>
                    <td className="py-2.5 text-mute">{o.sector}</td>
                    <td className="py-2.5 text-mute">{o.state}</td>
                    <td className="num py-2.5 text-right" style={o.compromise > 0 ? { color: 'var(--color-compromise)' } : undefined}>{num(o.compromise)}</td>
                    <td className="num py-2.5 text-right">{num(o.critical)}</td>
                    <td className="px-5 py-2.5 text-right text-mute">{LANG[o.lang] ?? o.lang}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  )
}
