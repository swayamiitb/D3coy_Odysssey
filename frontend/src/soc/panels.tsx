import { Activity, Bug, FileWarning, Radar, ShieldAlert, Siren } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Area, CartesianGrid, ComposedChart, Line, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { IntelSource, LedgerEvent, ShieldStatus, Soc, Technology } from '../api'
import { Prov, TIER_FILL, TierPill } from '../ui'
import { ago, AnimatedNumber, BarList, Delta, Gauge, nf, Pending, Seg, SocCard, StackBar, useJson } from './kit'

/* The screenshot set's panels, on the console's real data (ui-07): a live threats feed, the threat trend, a gauge pair,
   threats by technology and the intelligence sources. Every panel names where its numbers come from. */

interface LiveDetection { id: string; ts: string; kind: string; title: string; sensors: number; z: number; orgs_exposed: number }
interface LiveState { detections: LiveDetection[]; feeds: { name: string; status: string }[]; sensors: number; flows: { per_tick: number[]; hosts: number }; tick_s: number }

type FeedRow = { id: string; ts: string; icon: 'web' | 'decoy' | 'beacon' | 'flow' | 'intel'; title: string; line: string; tier?: 'Compromise' | 'Critical' | 'High' | 'Medium' | 'Watch'; tag?: string }

/** The live threat rows, shared by the feed card and the strip's summary box. */
export function useLiveThreatRows(): { rows: FeedRow[]; loaded: boolean; error?: string } {
  const shield = useJson<ShieldStatus>('/api/shield', [], 5000)
  const live = useJson<LiveState>('/api/live', [], 5000)
  const ledger = useJson<LedgerEvent[]>('/api/events/recent?limit=80', [], 10000)
  const rows = useMemo(() => {
    const out: FeedRow[] = []
    for (const f of shield.data?.findings ?? []) {
      out.push({ id: f.id, ts: f.ts, icon: 'web', title: `${f.category}${f.attack ? ` · ${f.attack}` : ''}`,
                 line: `${f.source_ip} → ${f.app} ${f.method} ${f.path}`, tier: f.severity, tag: f.redteam ? 'drill' : f.decision })
    }
    // The live engine emits several kinds of detection (a scanning surge, a C2 beacon, a flow anomaly); each keeps
    // its own icon, tier and wording.
    for (const d of live.data?.detections ?? []) {
      const k = d.kind ?? ''
      const beacon = /beacon|c2/i.test(k), flow = /flow|anomal/i.test(k)
      const grid = d.sensors != null ? `${d.sensors} decoy sensors${d.z != null ? ` · z ${d.z}` : ''} · ` : ''
      out.push({ id: d.id, ts: d.ts, icon: beacon ? 'beacon' : flow ? 'flow' : 'decoy', title: d.title,
                 line: `${grid}${d.orgs_exposed ?? 0} operators exposed`, tier: beacon ? 'Compromise' : flow ? 'Medium' : 'High', tag: k.replace(/_/g, ' ') })
    }
    // Quiet grid: fill with the newest exploitation confirmed by CISA (real), so the feed is never a blank box.
    for (const e of ledger.data ?? []) {
      if (out.length >= 7) break
      if (e.kind === 'kev.added') out.push({ id: `l-${e.seq}`, ts: e.ts, icon: 'intel', title: `${e.subject} confirmed exploited`, line: 'CISA KEV catalogue · REAL', tag: 'KEV' })
    }
    return out.sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 8)
  }, [shield.data, live.data, ledger.data])
  return { rows, loaded: !!(shield.data || live.data), error: shield.error ?? live.error }
}

/** Live threats: what the HTTP Shield and the decoy grid saw, newest first. */
export function LiveThreats({ onAll, cols }: { onAll: () => void; cols?: boolean }) {
  const { rows, loaded, error } = useLiveThreatRows()
  const Icon = { web: Bug, decoy: Radar, beacon: Siren, flow: Activity, intel: FileWarning }
  const tile = { web: 'bg-crit/12 text-crit-ink', decoy: 'bg-high/12 text-high-ink', beacon: 'bg-comp/15 text-comp-ink', flow: 'bg-med/15 text-med-ink', intel: 'bg-panel-2 text-mute' }
  return (
    <SocCard title={<><span className="soc-live h-2 w-2 rounded-full bg-ok" />Live threats</>} prov={['REAL', 'SIM']}
             sub="HTTP Shield detections, decoy-grid surges and new CISA KEV entries, newest first"
             right={<button onClick={onAll} className="text-[13px] font-medium text-accent hover:underline">Open Live</button>}>
      {!loaded ? <Pending error={error} what="live threats" h={300} /> : rows.length === 0 ? (
        <div className="flex h-[300px] flex-col items-center justify-center gap-1 text-center">
          <ShieldAlert size={20} className="text-faint" />
          <div className="text-[14px] font-medium">Quiet: no detections</div>
          <div className="text-[13px] text-faint">Run an attack drill on the Live page to see one arrive.</div>
        </div>
      ) : (
        <ul className={`-mx-1 ${cols ? 'grid gap-x-8 lg:grid-cols-2' : ''}`}>
          {rows.map((r) => {
            const I = Icon[r.icon]
            return (
              <li key={r.id} className="flex items-center gap-3 border-b border-line px-1 py-2.5 last:border-0">
                <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${tile[r.icon]}`}><I size={16} /></span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13.5px] font-medium">{r.title}</div>
                  <div className="truncate font-mono text-[12px] text-faint">{r.line}</div>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  {r.tier && <TierPill tier={r.tier} />}
                  <span className="text-[11.5px] text-faint">{r.tag ? `${r.tag} · ` : ''}{ago(r.ts)}</span>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </SocCard>
  )
}

/** Threat trend: open warnings by tier per day, replayed from every alert's timeline (the lead's `pressure`). Live for
 *  an analyst: hover any day for its readout and its change on the day before; the range's peak, low and mean; the
 *  mean as a dashed line; the latest point pulses; the headline counts to its new value when the data changes. */
export function ThreatTrend({ soc }: { soc?: Soc }) {
  const [range, setRange] = useState<'7' | '30' | '90'>('30')
  const [hov, setHov] = useState<number | null>(null)
  const all = soc?.pressure ?? []
  const data = all.slice(-Number(range))
  const last = data.at(-1), first = data[0]
  const i = hov != null && hov >= 0 && hov < data.length ? hov : data.length - 1
  const at = data[i], before = i > 0 ? data[i - 1] : undefined
  const peak = data.reduce((m, d) => (d.Critical > m.Critical ? d : m), data[0] ?? { date: '', Critical: 0, High: 0, Compromise: 0 })
  const low = data.reduce((m, d) => (d.Critical < m.Critical ? d : m), data[0] ?? peak)
  const mean = data.length ? Math.round(data.reduce((s, d) => s + d.Critical, 0) / data.length) : 0
  const built = soc?.built_at ? new Date(soc.built_at) : undefined
  return (
    <SocCard title="Threat trend" prov={['REAL', 'SIM']}
             sub="Open warnings on each day, replayed from every alert's timeline; hover a day for its readout"
             right={<Seg label="Range" value={range} onChange={setRange} items={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />}>
      {!soc || !at ? <Pending what="the trend" h={260} /> : (
        <>
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums"><AnimatedNumber value={at.Critical} /></span>
            <span className="text-[13px] text-mute">open Critical {hov == null ? 'today' : `on ${at.date.slice(5)}`}</span>
            {before && <Delta now={at.Critical} before={before.Critical} good="down" window={hov == null ? 'vs yesterday' : 'vs the day before'} />}
            {hov == null && last && first && last !== first && <Delta now={last.Critical} before={first.Critical} good="down" window={`vs ${range} days ago`} />}
          </div>
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-faint">
            <span><b className="font-mono text-mute">{nf(at.High)}</b> High · <b className="font-mono text-mute">{nf(at.Compromise)}</b> suspected compromise</span>
            <span>peak <b className="font-mono text-mute">{nf(peak.Critical)}</b> on {peak.date.slice(5)} · low <b className="font-mono text-mute">{nf(low.Critical)}</b> · mean <b className="font-mono text-mute">{nf(mean)}</b> over {data.length} days</span>
            {built && <span className="flex items-center gap-1.5"><span className="soc-live h-1.5 w-1.5 rounded-full bg-ok" />live · rebuilt {built.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}</span>}
          </div>
          <div className="mt-3 flex flex-wrap gap-4 text-[12px] text-mute">
            {(['Critical', 'High', 'Compromise'] as const).map((t) => (
              <span key={t} className="flex items-center gap-1.5"><span className="h-[3px] w-3.5 rounded-full" style={{ background: TIER_FILL[t] }} />{t === 'Compromise' ? 'Suspected compromise' : t}</span>
            ))}
            <span className="flex items-center gap-1.5"><span className="h-0 w-3.5 border-t border-dashed border-line-2" />mean</span>
          </div>
          <div className="mt-2 h-[330px]">
            <ResponsiveContainer>
              <ComposedChart data={data} margin={{ top: 8, right: 6, bottom: 0, left: -18 }}
                             onMouseMove={(st) => { const l = st?.activeLabel; setHov(l == null ? null : data.findIndex((d) => d.date === String(l))) }}
                             onMouseLeave={() => setHov(null)}>
                <defs>
                  <linearGradient id="trend-crit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={TIER_FILL.Critical} stopOpacity={0.32} />
                    <stop offset="100%" stopColor={TIER_FILL.Critical} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--color-line)" vertical={false} />
                <XAxis dataKey="date" tick={{ fill: 'var(--color-faint)', fontSize: 11 }} tickFormatter={(v: string) => v.slice(5)} minTickGap={28} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: 'var(--color-faint)', fontSize: 11 }} allowDecimals={false} axisLine={false} tickLine={false} width={44} />
                <Tooltip cursor={{ stroke: 'var(--color-line-2)' }}
                         contentStyle={{ background: 'var(--color-panel)', border: '1px solid var(--color-line-2)', borderRadius: 10, fontSize: 12 }}
                         labelStyle={{ color: 'var(--color-text)', fontWeight: 600 }} itemStyle={{ color: 'var(--color-text)' }} />
                <ReferenceLine y={mean} stroke="var(--color-line-2)" strokeDasharray="3 4" />
                <Area type="monotone" dataKey="Critical" stroke={TIER_FILL.Critical} strokeWidth={2} fill="url(#trend-crit)" isAnimationActive={false}
                      dot={(p: { index?: number; cx?: number; cy?: number }) => (p.index === data.length - 1
                        ? <circle key="last" cx={p.cx} cy={p.cy} r={4.5} fill={TIER_FILL.Critical} stroke="var(--color-panel)" strokeWidth={2} className="soc-live" />
                        : <g key={p.index} />)} />
                <Line type="monotone" dataKey="High" stroke={TIER_FILL.High} strokeWidth={1.6} dot={false} isAnimationActive={false} />
                <Line type="stepAfter" dataKey="Compromise" name="Suspected compromise" stroke={TIER_FILL.Compromise} strokeWidth={2} dot={false} isAnimationActive={false} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </SocCard>
  )
}

/** Two gauges: how much Odyssey does on its own, and how much of the constituency has a Critical warning. */
export function PostureGauges({ soc }: { soc?: Soc }) {
  const m = soc?.autopilot.by_mode
  const auto = m ? m.auto / Math.max(1, m.auto + m.approve) : null
  const withCrit = soc ? soc.orgs.filter((o) => o.critical > 0 || o.compromise > 0).length : 0
  const exposure = soc && soc.orgs.length ? withCrit / soc.orgs.length : null
  return (
    <SocCard title="Posture" sub="Two shares, from the autopilot ledger and the warnings">
      <div className="grid grid-cols-2 gap-4 pt-1">
        <Gauge value={auto} color="var(--color-text)" label="Handled on its own"
               sub={m ? `${nf(m.auto)} of ${nf(m.auto + m.approve)} actions; the rest waited for a person` : undefined} />
        <Gauge value={exposure} color={TIER_FILL.Critical} label="Operators exposed"
               sub={soc ? `${withCrit} of ${soc.orgs.length} have a Critical warning or worse` : undefined} />
      </div>
    </SocCard>
  )
}

/** Threats by technology: the products with the most Critical warnings; the leader in red. */
export function TechThreats({ onOpen }: { onOpen: () => void }) {
  const { data, error } = useJson<Technology[]>('/api/intel/technologies')
  const top = (data ?? []).filter((t) => t.critical > 0).sort((a, b) => b.critical - a.critical).slice(0, 6)
  const campaigns = (data ?? []).filter((t) => t.campaign === 'ACTIVE').length
  return (
    <SocCard title="Threats by technology" prov={['REAL']} sub="Critical warnings per product in the inventory"
             right={data ? <span className="rounded-full bg-crit/15 px-2.5 py-1 text-[12px] font-semibold text-crit-ink ring-1 ring-inset ring-crit/30">{campaigns} active campaign{campaigns === 1 ? '' : 's'}</span> : undefined}>
      {!data ? <Pending error={error} what="technologies" h={220} /> : (
        <>
          <BarList color={TIER_FILL.Critical}
                   rows={top.map((t, i) => ({ key: t.product_key, label: t.label, value: t.critical, sub: t.kev_cves ? `${t.kev_cves} KEV` : undefined, hot: i === 0 }))} />
          <button onClick={onOpen} className="mt-4 text-[13px] font-medium text-accent hover:underline">All technologies</button>
        </>
      )}
    </SocCard>
  )
}

// Identities, not tiers: the text colour, sky, blue, slate and greys, so no source reads as a risk level.
const SOURCE_COLORS = ['var(--color-text)', '#64d2ff', '#4f8cf7', '#9aa4b2', 'var(--color-faint)', 'var(--color-panel-3)']
/** Intelligence sources: what each feed contributed that touched the constituency's inventory. */
export function IntelSources() {
  const { data, error } = useJson<IntelSource[]>('/api/intel/sources')
  const rows = (data ?? []).filter((s) => (s.relevant ?? 0) > 0).sort((a, b) => (b.relevant ?? 0) - (a.relevant ?? 0))
  const head = rows.slice(0, 5), rest = rows.slice(5)
  const parts = [...head.map((s, i) => ({ label: s.name, value: s.relevant ?? 0, color: SOURCE_COLORS[i], note: <Prov p={s.provenance} /> })),
    ...(rest.length ? [{ label: `${rest.length} more`, value: rest.reduce((n, s) => n + (s.relevant ?? 0), 0), color: SOURCE_COLORS[5], note: undefined }] : [])]
  const total = rows.reduce((n, s) => n + (s.relevant ?? 0), 0)
  return (
    <SocCard title="Intelligence sources" sub="Signals that touched our inventory, by source">
      {!data ? <Pending error={error} what="sources" h={220} /> : (
        <>
          <div className="mb-4 flex items-baseline gap-2">
            <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{nf(total)}</span>
            <span className="text-[13px] text-mute">relevant signals from {rows.length} of {data.length} sources</span>
          </div>
          <StackBar parts={parts} unit="signals" />
        </>
      )}
    </SocCard>
  )
}
