import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { Attacks } from '../api'
import { TIER_FILL } from '../ui'
import { BarList, Gauge, nf, Pending, SocCard, useJson } from './kit'

/* One SOC panel per destination (ui-07), each on data only that page owns: the SOC's case load, Intel's attack
   telemetry, Live's throughput. */

interface Metrics { open: number; incidents: number; overdue: number; unassigned: number; analysts: { id: string; name: string; role: string; open: number; overdue: number }[] }

/** SOC: how much of the queue has an owner and is inside its deadline, and who carries it. */
export function CaseLoad({ tick }: { tick: number }) {
  const { data: m, error } = useJson<Metrics>('/api/soc/metrics', [tick])
  if (!m) return <Pending error={error} what="the case load" h={250} />
  const assigned = m.open ? (m.open - m.unassigned) / m.open : null
  const inSla = m.open ? (m.open - m.overdue) / m.open : null
  const people = [...m.analysts].sort((a, b) => b.open - a.open)
  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <SocCard title="Case load" sub="Every open case, from the case board">
        <div className="grid grid-cols-2 gap-4 pt-1">
          <Gauge value={assigned} color="var(--color-text)" label="Have an owner" sub={`${nf(m.open - m.unassigned)} of ${nf(m.open)} open cases`} />
          <Gauge value={inSla} color={m.overdue ? TIER_FILL.Critical : 'var(--color-ok)'} label="Inside their deadline"
                 sub={m.overdue ? `${nf(m.overdue)} past the CERT-In timeline` : 'none past the CERT-In timeline'} />
        </div>
      </SocCard>
      <SocCard title="Who carries the queue" sub="Open cases per analyst on shift">
        <BarList color="var(--color-text)"
                 rows={people.map((a, i) => ({ key: a.id, label: a.name, sub: a.role, value: a.open, hot: i === 0 }))} />
      </SocCard>
    </div>
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

/** Live: flows the decoy grid sees per detection cycle, as the system runs. */
export function Throughput({ s }: { s?: { flows: { per_tick: number[]; hosts: number }; tick_s: number; sensors: number } }) {
  if (!s) return <Pending what="throughput" h={250} />
  const data = s.flows.per_tick.map((v, i) => ({ i: i - s.flows.per_tick.length + 1, flows: v }))
  const now = s.flows.per_tick.at(-1) ?? 0
  const mean = s.flows.per_tick.reduce((a, b) => a + b, 0) / Math.max(1, s.flows.per_tick.length)
  return (
    <SocCard title="Throughput" prov={['SIM']} sub={`Flows the decoy grid sees per ${s.tick_s}-second cycle, last ${s.flows.per_tick.length} cycles`}>
      <div className="flex flex-wrap items-baseline gap-x-3">
        <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{nf(now)}</span>
        <span className="text-[13px] text-mute">flows this cycle · mean {Math.round(mean)} · {nf(s.flows.hosts)} hosts · {s.sensors} sensors</span>
      </div>
      <div className="mt-3 h-[170px]">
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 6, right: 6, bottom: 0, left: -18 }}>
            <defs>
              <linearGradient id="tp-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f4f4f5" stopOpacity={0.22} />
                <stop offset="100%" stopColor="#f4f4f5" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--color-line)" vertical={false} />
            <XAxis dataKey="i" tick={{ fill: 'var(--color-faint)', fontSize: 11 }} tickFormatter={(v: number) => (v === 0 ? 'now' : `${v * s.tick_s}s`)} minTickGap={36} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: 'var(--color-faint)', fontSize: 11 }} allowDecimals={false} axisLine={false} tickLine={false} width={44} />
            <Tooltip cursor={{ stroke: 'var(--color-line-2)' }} labelFormatter={(v) => (Number(v) === 0 ? 'this cycle' : `${-Number(v) * s.tick_s} s ago`)}
                     contentStyle={{ background: 'var(--color-panel)', border: '1px solid var(--color-line-2)', borderRadius: 10, fontSize: 12 }}
                     labelStyle={{ color: 'var(--color-text)', fontWeight: 600 }} itemStyle={{ color: 'var(--color-text)' }} />
            <Area type="monotone" dataKey="flows" stroke="#f4f4f5" strokeWidth={1.8} fill="url(#tp-fill)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </SocCard>
  )
}
