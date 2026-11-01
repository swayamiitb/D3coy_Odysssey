import { Bug, FileWarning, Radar, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { IntelSource, LedgerEvent, ShieldStatus, Soc, Technology } from '../api'
import { Prov, TIER_FILL, TierPill } from '../ui'
import { ago, BarList, Delta, Gauge, nf, Pending, Seg, SocCard, StackBar, useJson } from './kit'

/* The screenshot set's panels, on the console's real data (ui-07): a live threats feed, the threat trend, a gauge pair,
   threats by technology and the intelligence sources. Every panel names where its numbers come from. */

interface LiveDetection { id: string; ts: string; kind: string; title: string; sensors: number; z: number; orgs_exposed: number }
interface LiveState { detections: LiveDetection[]; feeds: { name: string; status: string }[]; sensors: number; flows: { per_tick: number[]; hosts: number }; tick_s: number }

type FeedRow = { id: string; ts: string; icon: 'web' | 'decoy' | 'intel'; title: string; line: string; tier?: 'Compromise' | 'Critical' | 'High' | 'Medium' | 'Watch'; tag?: string }

/** Live threats: what the HTTP Shield and the decoy grid saw, newest first. */
export function LiveThreats({ onAll }: { onAll: () => void }) {
  const shield = useJson<ShieldStatus>('/api/shield', [], 5000)
  const live = useJson<LiveState>('/api/live', [], 5000)
  const ledger = useJson<LedgerEvent[]>('/api/events/recent?limit=80', [], 10000)
  const rows = useMemo(() => {
    const out: FeedRow[] = []
    for (const f of shield.data?.findings ?? []) {
      out.push({ id: f.id, ts: f.ts, icon: 'web', title: `${f.category}${f.attack ? ` · ${f.attack}` : ''}`,
                 line: `${f.source_ip} → ${f.app} ${f.method} ${f.path}`, tier: f.severity, tag: f.redteam ? 'drill' : f.decision })
    }
    for (const d of live.data?.detections ?? []) {
      out.push({ id: d.id, ts: d.ts, icon: 'decoy', title: d.title, line: `${d.sensors} decoy sensors · z ${d.z} · ${d.orgs_exposed} operators exposed`, tier: 'High', tag: 'surge' })
    }
    // Quiet grid: fill with the newest exploitation confirmed by CISA (real), so the feed is never a blank box.
    for (const e of ledger.data ?? []) {
      if (out.length >= 7) break
      if (e.kind === 'kev.added') out.push({ id: `l-${e.seq}`, ts: e.ts, icon: 'intel', title: `${e.subject} confirmed exploited`, line: 'CISA KEV catalogue · REAL', tag: 'KEV' })
    }
    return out.sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 7)
  }, [shield.data, live.data, ledger.data])
  const Icon = { web: Bug, decoy: Radar, intel: FileWarning }
  return (
    <SocCard title={<><span className="soc-live h-2 w-2 rounded-full bg-ok" />Live threats</>} prov={['REAL', 'SIM']}
             sub="HTTP Shield detections, decoy-grid surges and new CISA KEV entries, newest first"
             right={<button onClick={onAll} className="text-[13px] font-medium text-accent hover:underline">Open Live</button>}>
      {!shield.data && !live.data ? <Pending error={shield.error ?? live.error} what="live threats" h={300} /> : rows.length === 0 ? (
        <div className="flex h-[300px] flex-col items-center justify-center gap-1 text-center">
          <ShieldAlert size={20} className="text-faint" />
          <div className="text-[14px] font-medium">Quiet: no detections</div>
          <div className="text-[13px] text-faint">Run an attack drill on the Live page to see one arrive.</div>
        </div>
      ) : (
        <ul className="-mx-1">
          {rows.map((r) => {
            const I = Icon[r.icon]
            return (
              <li key={r.id} className="flex items-center gap-3 border-b border-line px-1 py-2.5 last:border-0">
                <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${r.icon === 'web' ? 'bg-crit/12 text-crit-ink' : r.icon === 'decoy' ? 'bg-high/12 text-high-ink' : 'bg-panel-2 text-mute'}`}><I size={16} /></span>
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

/** Threat trend: open warnings by tier per day, replayed from every alert's timeline (the lead's `pressure`). */
export function ThreatTrend({ soc }: { soc?: Soc }) {
  const [range, setRange] = useState<'7' | '30' | '90'>('30')
  const all = soc?.pressure ?? []
  const data = all.slice(-Number(range))
  const last = data.at(-1), first = data[0]
  return (
    <SocCard title="Threat trend" prov={['REAL', 'SIM']}
             sub="Open warnings on each day, replayed from every alert's timeline"
             right={<Seg label="Range" value={range} onChange={setRange} items={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />}>
      {!soc ? <Pending what="the trend" h={260} /> : (
        <>
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{nf(last?.Critical)}</span>
            <span className="text-[13px] text-mute">open Critical today</span>
            {last && first && <Delta now={last.Critical} before={first.Critical} good="down" window={`vs ${range} days ago`} />}
          </div>
          <div className="mt-3 flex flex-wrap gap-4 text-[12px] text-mute">
            {(['Critical', 'High', 'Compromise'] as const).map((t) => (
              <span key={t} className="flex items-center gap-1.5"><span className="h-[3px] w-3.5 rounded-full" style={{ background: TIER_FILL[t] }} />{t === 'Compromise' ? 'Suspected compromise' : t}</span>
            ))}
          </div>
          <div className="mt-2 h-[230px]">
            <ResponsiveContainer>
              <ComposedChart data={data} margin={{ top: 8, right: 6, bottom: 0, left: -18 }}>
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
                <Area type="monotone" dataKey="Critical" stroke={TIER_FILL.Critical} strokeWidth={2} fill="url(#trend-crit)" isAnimationActive={false} />
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
