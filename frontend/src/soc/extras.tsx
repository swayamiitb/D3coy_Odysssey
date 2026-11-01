import { useState } from 'react'
import { CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { Attacks, Soc } from '../api'
import { TIER_FILL } from '../ui'
import { AnimatedNumber, BarList, Gauge, nf, Pending, SocCard, TabBoxes, useJson } from './kit'
import { ChannelsSection } from '../Channels'
import { AttackFamilies, DecisionsToday, ExposedHosts, FeedHealth, SensorGrid } from './telemetry'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Live = any
interface Approval { decided_at: string | null }

/** SOC overview's strip: case load, who carries the queue, decisions, the most exposed hosts; one open at a time. */
export function SocStrip({ tick, orgs, onOrg }: { tick: number; orgs?: Soc['orgs']; onOrg: (id: string) => void }) {
  const { data: m } = useJson<Metrics>('/api/soc/metrics', [tick])
  const ok = useJson<Approval[]>('/api/approvals?status=approved', [tick]).data
  const no = useJson<Approval[]>('/api/approvals?status=rejected', [tick]).data
  const top = m ? [...m.analysts].sort((a, b) => b.open - a.open)[0] : undefined
  return (
    <TabBoxes label="SOC overview" defaultOpen="load" items={[
      { key: 'load', title: 'Case load', count: m ? `${Math.round((100 * (m.open - m.unassigned)) / Math.max(1, m.open))}%` : '—',
        preview: m ? `${nf(m.open - m.unassigned)} of ${nf(m.open)} open cases have an owner · ${m.overdue ? `${m.overdue} past the deadline` : 'none past the deadline'}` : 'loading…',
        panel: <CaseLoad tick={tick} /> },
      { key: 'who', title: 'Who carries the queue', count: m ? nf(m.analysts.length) : '—',
        preview: top ? `${top.name} carries the most: ${top.open} open` : 'analysts on shift', panel: <WhoCarries tick={tick} /> },
      { key: 'dec', title: 'Decisions', chip: undefined, count: ok && no ? nf(ok.length + no.length) : '—',
        preview: ok && no ? `${nf(ok.length)} approved · ${nf(no.length)} rejected this week, by day and by who decided` : 'loading…',
        panel: <SocCard title="Decisions" prov={['SIM']} sub="Approved and rejected, by day; who decided; how long proposals waited"><DecisionsToday tick={tick} /></SocCard> },
      { key: 'hosts', title: 'Most exposed hosts', count: orgs ? nf(orgs.length) : '—',
        preview: 'Internet- and DMZ-facing hosts across every operator, worst warning first',
        panel: <SocCard title="Most exposed hosts" prov={['SIM']} sub="Internet- and DMZ-facing hosts across every operator, worst warning first"><ExposedHosts orgs={orgs} onOrg={onOrg} /></SocCard> },
    ]} />
  )
}

/** Live's strip: the decoy grid, feed health and the shield's attack families. */
export function LiveStrip({ s, onShield }: { s?: Live; onShield: () => void }) {
  const fresh = s ? s.feeds.filter((f: { status: string }) => f.status === 'fresh').length : 0
  const hot = s ? (s.tags as { label: string; z: number }[]).filter((t) => t.z >= 2).length : 0
  return (
    <TabBoxes label="Live grid" defaultOpen="grid" items={[
      { key: 'grid', title: 'Decoy grid', count: s ? `${s.sensors}` : '—', preview: s ? `${s.sensors} sensors · ${hot ? `${hot} product${hot > 1 ? 's' : ''} above z 2` : 'all products at baseline'}` : 'loading…',
        panel: <SocCard title="Decoy grid" prov={['SIM']} sub="Sessions per decoy product this cycle, and the 24 sensors"><SensorGrid s={s} /></SocCard> },
      { key: 'feeds', title: 'Feed health', count: s ? `${fresh}/${s.feeds.length}` : '—', preview: s ? `${fresh} of ${s.feeds.length} real feeds fresh, checked every 15 minutes` : 'loading…',
        panel: <SocCard title="Feed health" prov={['REAL']} sub="The real feeds read live, checked every 15 minutes"><FeedHealth s={s} /></SocCard> },
      { key: 'shield', title: 'Attack families on the shield', preview: 'What the HTTP shield caught, by family; blocked vs allowed',
        panel: <SocCard title="Attack families on the shield" prov={['SIM']} sub="What the HTTP shield caught, by family"><AttackFamilies onGo={onShield} /></SocCard> },
      { key: 'channels', title: 'Where the alerts go', preview: 'The apps a team already uses: each channel with a send-test and a mute, and what was delivered, to whom, how fast',
        panel: <div className="soc-card px-6 py-5"><ChannelsSection /></div> },
    ]} />
  )
}

/* One SOC panel per destination (ui-07), each on data only that page owns: the SOC's case load, Intel's attack
   telemetry, Live's throughput. */

interface Metrics { open: number; incidents: number; overdue: number; unassigned: number; analysts: { id: string; name: string; role: string; open: number; overdue: number }[] }

/** SOC: how much of the queue has an owner and is inside its deadline. */
export function CaseLoad({ tick }: { tick: number }) {
  const { data: m, error } = useJson<Metrics>('/api/soc/metrics', [tick])
  if (!m) return <Pending error={error} what="the case load" h={250} />
  const assigned = m.open ? (m.open - m.unassigned) / m.open : null
  const inSla = m.open ? (m.open - m.overdue) / m.open : null
  return (
    <SocCard title="Case load" sub="Every open case, from the case board">
      <div className="mx-auto grid max-w-[640px] grid-cols-2 gap-4 pt-1">
        <Gauge value={assigned} color="var(--color-text)" label="Have an owner" sub={`${nf(m.open - m.unassigned)} of ${nf(m.open)} open cases`} />
        <Gauge value={inSla} color={m.overdue ? TIER_FILL.Critical : 'var(--color-ok)'} label="Cases inside their deadline"
               sub={m.overdue ? `${nf(m.overdue)} cases past the CERT-In timeline` : 'no case past its CERT-In timeline; overdue warnings are escalated in the decisions queue'} />
      </div>
    </SocCard>
  )
}

/** SOC: who carries the queue, open cases per analyst. */
export function WhoCarries({ tick }: { tick: number }) {
  const { data: m, error } = useJson<Metrics>('/api/soc/metrics', [tick])
  if (!m) return <Pending error={error} what="the team" h={250} />
  const people = [...m.analysts].sort((a, b) => b.open - a.open)
  return (
    <SocCard title="Who carries the queue" sub="Open cases per analyst on shift">
      <BarList color="var(--color-text)" rows={people.map((a, i) => ({ key: a.id, label: a.name, sub: a.role, value: a.open, hot: i === 0 }))} />
    </SocCard>
  )
}

/** Intel: the ports the internet is attacking most this week (SANS ISC DShield). */
export function AttackTelemetry() {
  const { data, error } = useJson<Attacks>('/api/intel/attacks')
  const ports = (data?.dshield.top_ports ?? []).slice(0, 7)
  return (
    <SocCard title="Most attacked ports" prov={['REAL']} sub="SANS ISC DShield: reports per target port, worldwide">
      {!data ? <Pending error={error} what="attack telemetry" h={240} /> : (
        <BarList color={TIER_FILL.Critical}
                 rows={ports.map((p, i) => ({ key: String(p.targetport), label: <span className="font-mono">{p.targetport}</span>, sub: `${nf(p.sources)} sources · ${nf(p.targets)} targets`, value: p.records, hot: i === 0 }))} />
      )}
    </SocCard>
  )
}

type Tag = { tag: string; label: string; series: { s: number; z: number; d: boolean }[] }
/** Live: flows the decoy grid sees per detection cycle, and the three busiest products' sessions as lines (the one
 *  under a surge in red, like a throughput chart on a gateway console). Hover a cycle for its readout; the latest
 *  point pulses; the figures count to their new values as the engine ticks. */
export function Throughput({ s }: { s?: { flows: { per_tick: number[]; hosts: number }; tick_s: number; sensors: number; tags?: Tag[]; last_tick?: string } }) {
  const [hov, setHov] = useState<number | null>(null)
  if (!s) return <Pending what="throughput" h={250} />
  const tags = [...(s.tags ?? [])].sort((a, b) => (b.series.at(-1)?.s ?? 0) - (a.series.at(-1)?.s ?? 0)).slice(0, 3)
  const surge = [...(s.tags ?? [])].sort((a, b) => (b.series.at(-1)?.z ?? 0) - (a.series.at(-1)?.z ?? 0))[0]
  const lines = tags.map((t) => t.tag).includes(surge?.tag ?? '') || !surge || (surge.series.at(-1)?.z ?? 0) < 3 ? tags : [surge, ...tags.slice(0, 2)]
  const n = s.flows.per_tick.length
  const data = s.flows.per_tick.map((v, i) => {
    const row: Record<string, number> = { i: i - n + 1, flows: v }
    for (const t of lines) row[t.tag] = t.series[t.series.length - n + i]?.s ?? 0
    return row
  })
  const idx = hov != null && hov >= 0 && hov < n ? hov : n - 1
  const row = data[idx]
  const flowsAt = row?.flows ?? 0
  const mean = s.flows.per_tick.reduce((a, b) => a + b, 0) / Math.max(1, n)
  const sessionsAt = lines.reduce((a, t) => a + (row?.[t.tag] ?? 0), 0)
  const peak = Math.max(0, ...s.flows.per_tick)
  const colour = (t: Tag, i: number) => ((t.series.at(-1)?.z ?? 0) >= 3 ? TIER_FILL.Critical : i === 0 ? 'var(--color-text)' : i === 1 ? 'var(--color-faint)' : 'var(--color-line-2)')
  const lastTick = s.last_tick ? new Date(s.last_tick) : undefined
  return (
    <SocCard title="Throughput" prov={['SIM']} sub={`Decoy sessions per ${s.tick_s}-second cycle for the three busiest products, last ${n} cycles; a product under a surge turns red. Hover a cycle for its readout`}>
      <div className="flex flex-wrap items-baseline gap-x-3">
        <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums"><AnimatedNumber value={sessionsAt} /></span>
        <span className="text-[13px] text-mute">sessions {hov == null ? 'this cycle' : `${(n - 1 - idx) * s.tick_s} s ago`} on those three · {nf(flowsAt)} flows grid-wide</span>
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-faint">
        <span>mean <b className="font-mono text-mute">{Math.round(mean)}</b> · peak <b className="font-mono text-mute">{nf(peak)}</b> flows over {n} cycles · {nf(s.flows.hosts)} hosts · {s.sensors} sensors</span>
        <span className="flex items-center gap-1.5"><span className="soc-live h-1.5 w-1.5 rounded-full bg-ok" />live · every {s.tick_s} s{lastTick ? ` · last cycle ${lastTick.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}` : ''}</span>
      </div>
      <div className="mt-3 flex flex-wrap gap-4 text-[12px] text-mute">
        {lines.map((t, i) => <span key={t.tag} className="flex items-center gap-1.5"><span className="h-[3px] w-3.5 rounded-full" style={{ background: colour(t, i) }} />{t.label}{(t.series.at(-1)?.z ?? 0) >= 3 ? ` · surge z ${t.series.at(-1)?.z}` : ''}</span>)}
      </div>
      <div className="mt-2 h-[190px]">
        <ResponsiveContainer>
          <ComposedChart data={data} margin={{ top: 6, right: 6, bottom: 0, left: -18 }}
                         onMouseMove={(st) => { const l = st?.activeLabel; setHov(l == null ? null : data.findIndex((d) => d.i === Number(l))) }}
                         onMouseLeave={() => setHov(null)}>
            <CartesianGrid stroke="var(--color-line)" vertical={false} />
            <XAxis dataKey="i" tick={{ fill: 'var(--color-faint)', fontSize: 11 }} tickFormatter={(v: number) => (v === 0 ? 'now' : `${v * s.tick_s}s`)} minTickGap={36} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: 'var(--color-faint)', fontSize: 11 }} allowDecimals={false} axisLine={false} tickLine={false} width={44} />
            <Tooltip cursor={{ stroke: 'var(--color-line-2)' }} labelFormatter={(v) => (Number(v) === 0 ? 'this cycle' : `${-Number(v) * s.tick_s} s ago`)}
                     contentStyle={{ background: 'var(--color-panel)', border: '1px solid var(--color-line-2)', borderRadius: 10, fontSize: 12 }}
                     labelStyle={{ color: 'var(--color-text)', fontWeight: 600 }} itemStyle={{ color: 'var(--color-text)' }} />
            {lines.map((t, i) => <Line key={t.tag} type="monotone" dataKey={t.tag} name={t.label} stroke={colour(t, i)} strokeWidth={i === 0 || colour(t, i) === TIER_FILL.Critical ? 2 : 1.5} isAnimationActive={false}
                                       dot={i === 0 ? (p: { index?: number; cx?: number; cy?: number }) => (p.index === n - 1
                                         ? <circle key="last" cx={p.cx} cy={p.cy} r={4} fill={colour(t, i)} stroke="var(--color-panel)" strokeWidth={2} className="soc-live" />
                                         : <g key={p.index} />) : false} />)}
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </SocCard>
  )
}
