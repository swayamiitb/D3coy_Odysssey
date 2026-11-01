import { Crosshair, Radar, ShieldAlert, Timer } from 'lucide-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import type { Approval, Campaign, Feed, ForecastView, LedgerEvent, OrgProfile, ShieldStatus, Soc, Tier } from '../api'
import { fetchJson } from '../api'
import { KIND, istTime } from '../proactive'
import { TIER_FILL, TierPill } from '../ui'
import { ago, BarList, nf, Pending, SocCard, useJson } from './kit'

/* Telemetry widgets (ui-09), each on data the API already serves and each saying where its numbers come from:
   the event ticker, the deadline timeline, the noise funnel, the forecast list, the decoy sensor grid, feed health,
   the shield's attack families, the ATT&CK strip, the campaign timeline, decisions and the most exposed hosts. */

interface Scorecard { funnel: { cves_this_month: number; candidates: number; actionable_alerts: number; critical_or_compromise: number; noise_reduction_x: number } }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Live = any

const HOUR = 3600_000

/** Everything Odyssey does, as a ticker: the hash-chained ledger, newest first, sliding by. */
export function EventTicker({ tick, onOpen }: { tick: number; onOpen: () => void }) {
  const { data } = useJson<LedgerEvent[]>('/api/events/recent?limit=40', [tick], 10000)
  const rows = (data ?? []).slice(0, 24)
  const item = (e: LedgerEvent) => {
    const k = KIND[e.kind]
    return (
      <span key={e.seq} className="inline-flex shrink-0 items-center gap-2 pr-8 text-[12.5px]">
        <span className={`h-1.5 w-1.5 rounded-full ${e.provenance === 'HUMAN' ? 'bg-ok' : e.provenance === 'REAL' ? 'bg-accent' : 'bg-faint'}`} />
        <span className="font-mono text-faint">{istTime(e.ts)}</span>
        <span className="font-medium text-text">{k?.label ?? e.kind}</span>
        <span className="text-mute">{e.subject.replace(/^org:/, '')}</span>
        <span className="rounded bg-panel-2 px-1 py-px text-[10px] font-semibold uppercase text-faint">{e.provenance}</span>
      </span>
    )
  }
  return (
    <button onClick={onOpen} aria-label="Everything Odyssey did, newest first; open the autopilot log"
            className="soc-dark group flex h-11 w-full items-center overflow-hidden rounded-xl border border-line text-left">
      <span className="flex h-full shrink-0 items-center gap-2 border-r border-line px-3 text-[12px] font-semibold"><span className="soc-live h-1.5 w-1.5 rounded-full bg-ok" />Ledger</span>
      <span className="relative min-w-0 flex-1 overflow-hidden">
        {rows.length === 0 ? <span className="px-3 text-[12.5px] text-faint">Waiting for the first ledger entry…</span> : (
          <span className="soc-ticker flex w-max items-center px-3 group-hover:[animation-play-state:paused]">
            {rows.map(item)}{rows.map((e) => ({ ...e, seq: e.seq + 1e9 })).map(item)}
          </span>
        )}
      </span>
    </button>
  )
}

type Card = Feed['cards'][number] & { issued_at?: string }
function dueOf(c: Card, fallback: string): number | null {
  if (c.deadline_hours == null) return null
  return new Date(c.issued_at ?? fallback).getTime() + c.deadline_hours * HOUR
}

/** How many warnings are due in the next 24 hours, and how many are already late (for the strip's summary box). */
export function deadlinesSummary(feed: Feed | undefined, now = Date.now()): { due: number; late: number; next?: { c: Card; due: number } } {
  if (!feed) return { due: 0, late: 0 }
  const items = feed.cards.map((c) => ({ c: c as Card, due: dueOf(c as Card, feed.issued_at) }))
    .filter((x): x is { c: Card; due: number } => x.due != null && x.due - now < 24 * HOUR)
    .sort((a, b) => a.due - b.due)
  return { due: items.length, late: items.filter((x) => x.due < now).length, next: items.find((x) => x.due >= now) }
}

/** The next 24 hours of CERT-In and KEV deadlines on one line; what is already late sits at the left edge. */
export function DeadlineTimeline({ feed, onOpen }: { feed?: Feed; onOpen: (c: Card) => void }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => { const id = setInterval(() => setNow(Date.now()), 30_000); return () => clearInterval(id) }, [])
  if (!feed) return <Pending what="the deadlines" h={200} />
  const items = feed.cards.map((c) => ({ c: c as Card, due: dueOf(c as Card, feed.issued_at) }))
    .filter((x): x is { c: Card; due: number } => x.due != null && x.due - now < 24 * HOUR)
    .sort((a, b) => a.due - b.due)
  const lanes: number[] = []
  const placed = items.slice(0, 40).map((x) => {
    const p = Math.max(0, Math.min(1, (x.due - now) / (24 * HOUR)))
    let lane = lanes.findIndex((end) => end + 0.045 < p)
    if (lane < 0) { lane = lanes.length; lanes.push(p) } else lanes[lane] = p
    return { ...x, p, lane: Math.min(lane, 3) }
  })
  const late = items.filter((x) => x.due < now).length
  const ticks = [0, 4, 8, 12, 16, 20, 24]
  return (
    <SocCard title="Deadlines, next 24 hours" prov={['REAL', 'SIM']} sub="CERT-In reporting clocks and KEV due dates on the open warnings; hover a marker, click to open"
             right={late ? <span className="rounded-full bg-crit/15 px-2.5 py-1 text-[12px] font-semibold text-crit-ink ring-1 ring-inset ring-crit/30">{late} already late</span> : <span className="text-[12px] text-faint">{items.length} due</span>}>
      <div className="relative mt-1 h-[108px]">
        <div className="absolute inset-x-0 top-[84px] h-px bg-line-2" />
        {ticks.map((h) => (
          <div key={h} className="absolute top-[72px] -translate-x-1/2 text-center" style={{ left: `${(100 * h) / 24}%` }}>
            <div className="mx-auto h-3 w-px bg-line-2" />
            <div className="mt-1 font-mono text-[10.5px] text-faint">{h === 0 ? 'now' : `+${h} h`}</div>
          </div>
        ))}
        {placed.map((x) => (
          <button key={x.c.id} onClick={() => onOpen(x.c)} title={`${x.c.org_name} · ${x.c.cve_id} · ${x.due < now ? 'late' : `due ${new Date(x.due).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}`}`}
                  aria-label={`${x.c.org_name}, ${x.c.cve_id}, ${x.c.tier}, ${x.due < now ? 'already late' : `due in ${Math.round((x.due - now) / HOUR)} hours`}`}
                  className="group absolute -translate-x-1/2 rounded-full p-1 transition-transform hover:scale-125 focus-visible:scale-125"
                  style={{ left: `${x.p * 100}%`, top: `${66 - x.lane * 16}px` }}>
            <span className="block h-3 w-3 rounded-full ring-2 ring-panel" style={{ background: TIER_FILL[x.c.tier] }} />
          </button>
        ))}
      </div>
      <ul className="mt-2 divide-y divide-line">
        {items.slice(0, 5).map((x) => (
          <li key={x.c.id}>
            <button onClick={() => onOpen(x.c)} className="flex w-full items-center gap-3 py-2 text-left hover:bg-panel-2/50">
              <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: TIER_FILL[x.c.tier] }} />
              <span className="min-w-0 flex-1 truncate text-[13.5px] font-medium">{x.c.org_name} <span className="font-mono text-[12.5px] text-mute">{x.c.cve_id}</span></span>
              <span className={`shrink-0 font-mono text-[13px] ${x.due < now ? 'text-crit-ink' : ''}`}>{x.due < now ? `${Math.round((now - x.due) / HOUR)} h late` : `${Math.max(0, Math.floor((x.due - now) / HOUR))} h ${Math.floor(((x.due - now) % HOUR) / 60000)} min`}</span>
            </button>
          </li>
        ))}
        {items.length === 0 && <li className="py-6 text-center text-[13px] text-faint">Nothing is due in the next 24 hours.</li>}
      </ul>
    </SocCard>
  )
}

/** The funnel the product is: every CVE this month, down to the warnings that matter. */
export function NoiseFunnel() {
  const { data, error } = useJson<Scorecard>('/api/scorecard')
  if (!data) return <Pending error={error} what="the funnel" h={220} />
  const f = data.funnel
  const steps = [
    { label: 'CVEs published this month', v: f.cves_this_month, note: 'NVD, real' },
    { label: 'Name a product we run', v: f.candidates, note: 'matched to the inventory' },
    { label: 'Affect an installed version', v: f.actionable_alerts, note: 'version evidence checked' },
    { label: 'Warnings that matter', v: f.critical_or_compromise, note: 'Critical or suspected compromise' },
  ]
  const max = steps[0].v || 1
  return (
    <div>
      <div className="flex items-baseline gap-2">
        <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{f.noise_reduction_x}×</span>
        <span className="text-[13px] text-mute">fewer things to look at</span>
      </div>
      <ol className="mt-4 space-y-2">
        {steps.map((s, i) => {
          const w = Math.max(10, 100 * Math.sqrt(s.v / max))
          return (
            <li key={s.label} className="flex items-center gap-3">
              <div className="w-[52%] shrink-0">
                <div className="mx-auto h-7 rounded-md transition-[width]" style={{ width: `${w}%`, background: i === steps.length - 1 ? TIER_FILL.Critical : `color-mix(in oklab, var(--color-text) ${28 + i * 14}%, var(--color-panel-2))` }} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-2"><span className="font-mono text-[15px] font-semibold tabular-nums">{nf(s.v)}</span><span className="truncate text-[13px]">{s.label}</span></div>
                <div className="text-[11.5px] text-faint">{s.note}</div>
              </div>
            </li>
          )
        })}
      </ol>
      <p className="mt-3 text-[11.5px] text-faint">Bar widths on a square-root scale, so the last step stays visible; the numbers are the measured ones.</p>
    </div>
  )
}

/** The day-0 forecast: new CVEs most likely to be exploited, before anyone confirms it. */
export function LikelyNext({ onOpen }: { onOpen: () => void }) {
  const { data, error } = useJson<ForecastView>('/api/forecast')
  if (!data) return <Pending error={error} what="the forecast" h={240} />
  const items = [...data.items].sort((a, b) => b.p - a.p).slice(0, 6)
  return (
    <div>
      <ul className="divide-y divide-line">
        {items.map((it) => (
          <li key={it.cve} className="flex items-center gap-3 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline gap-2"><span className="font-mono text-[13px] font-semibold">{it.cve}</span><span className="truncate text-[13px] text-mute">{it.product ?? 'product named in text'}</span></div>
              <div className="truncate text-[12px] text-faint">{it.orgs} operators · {it.assets} assets{it.median_days_to_exploit != null ? ` · typically exploited within ${it.median_days_to_exploit} d` : ''}{it.kev_added ? ' · now in KEV' : ''}</div>
            </div>
            <div className="w-24 shrink-0">
              <div className="flex items-baseline justify-end gap-1 font-mono text-[13px]"><span className="font-semibold">{Math.round(it.p * 100)}%</span><span className="text-[11px] text-faint">p</span></div>
              <div className="mt-1 h-1.5 rounded-full bg-panel-2"><div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(3, Math.min(100, it.p * 300))}%` }} /></div>
            </div>
          </li>
        ))}
      </ul>
      <div className="mt-3 flex items-center justify-between text-[12px] text-faint">
        <span>{nf(data.flagged)} flagged since {data.since}; {data.since_exploited} confirmed by CISA after we flagged them. Bars scaled to 33%.</span>
        <button onClick={onOpen} className="shrink-0 font-medium text-accent hover:underline">Threat picture</button>
      </div>
    </div>
  )
}

/** The decoy grid: eight decoy products with their live z-scores, and the 24 sensors with the ones a drill hit. */
export function SensorGrid({ s }: { s?: Live }) {
  if (!s) return <Pending what="the decoy grid" h={220} />
  const drill = s.drill ?? s.drills?.[0]
  const hit = new Set<string>(drill?.sensors ?? [])
  const sensors = Array.from({ length: s.sensors ?? 24 }, (_, i) => `DCY-${String(i + 1).padStart(2, '0')}`)
  return (
    <div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {(s.tags as { tag: string; label: string; z: number; sessions: number; series: { d: boolean }[] }[]).map((t) => {
          const hot = t.z >= 4, warm = t.z >= 2
          return (
            <div key={t.tag} className={`rounded-xl border px-3 py-2 ${hot ? 'border-crit/50 bg-crit/10' : warm ? 'border-high/40 bg-high/10' : 'border-line bg-panel-2'}`}>
              <div className="truncate text-[12px] font-medium">{t.label}</div>
              <div className="mt-1 flex items-baseline justify-between"><span className="font-mono text-[15px] font-semibold tabular-nums">{t.sessions}</span><span className={`font-mono text-[12px] ${hot ? 'text-crit-ink' : warm ? 'text-high-ink' : 'text-faint'}`}>z {t.z}</span></div>
            </div>
          )
        })}
      </div>
      <div className="mt-3 flex flex-wrap gap-1" role="img" aria-label={`${sensors.length} decoy sensors; ${hit.size} hit by the last drill`}>
        {sensors.map((id) => (
          <span key={id} title={id} className={`flex h-6 w-9 items-center justify-center rounded-md font-mono text-[9.5px] ${hit.has(id) ? 'bg-crit text-white' : 'bg-panel-2 text-faint'}`}>{id.slice(4)}</span>
        ))}
      </div>
      <p className="mt-2 text-[11.5px] text-faint">{sensors.length} decoy sensors (SIM), sessions per product this cycle; z is the robust score against the last 72 cycles, 4 and above with breadth is a surge.{hit.size ? ` Red: the ${hit.size} sensors the last drill hit.` : ''}</p>
    </div>
  )
}

/** Feed health: the real feeds the engine reads live, with freshness, items and the last check. */
export function FeedHealth({ s }: { s?: Live }) {
  if (!s) return <Pending what="the feeds" h={220} />
  return (
    <ul className="divide-y divide-line">
      {(s.feeds as { name: string; status: string; items: number | null; new: number | null; last_ok: string | null; last_try: string | null; ms: number | null; newest?: string; detail?: string }[]).map((f) => (
        <li key={f.name} className="flex items-center gap-3 py-2.5">
          <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${f.status === 'fresh' ? 'soc-live bg-ok' : f.status === 'offline' ? 'bg-crit' : 'bg-watch'}`} />
          <div className="min-w-0 flex-1">
            <div className="flex items-baseline gap-2"><span className="text-[13.5px] font-medium">{f.name}</span><span className={`text-[11px] font-semibold uppercase ${f.status === 'fresh' ? 'text-ok-ink' : 'text-mute'}`}>{f.status}</span></div>
            <div className="truncate text-[12px] text-faint">{f.detail ?? (f.newest ? `newest entry ${f.newest}` : '')}</div>
          </div>
          <div className="shrink-0 text-right font-mono text-[12.5px]">
            <div>{f.items != null ? nf(f.items) : '—'}{f.new ? <span className="text-ok-ink"> +{f.new}</span> : null}</div>
            <div className="text-[11px] text-faint">{ago(f.last_ok ?? f.last_try)}{f.ms != null ? ` · ${f.ms} ms` : ''}</div>
          </div>
        </li>
      ))}
    </ul>
  )
}

/** The HTTP shield's attack families, allowed vs blocked. */
export function AttackFamilies({ onGo }: { onGo: () => void }) {
  const { data, error } = useJson<ShieldStatus>('/api/shield', [], 5000)
  if (!data) return <Pending error={error} what="the shield" h={220} />
  const by = new Map<string, { n: number; blocked: number }>()
  for (const f of data.findings) {
    const v = by.get(f.category) ?? { n: 0, blocked: 0 }
    v.n += 1
    if (f.decision === 'block') v.blocked += 1
    by.set(f.category, v)
  }
  const rows = [...by.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 7)
  if (!rows.length) {
    return (
      <div className="flex h-[200px] flex-col items-center justify-center gap-1 text-center">
        <ShieldAlert size={20} className="text-faint" />
        <div className="text-[14px] font-medium">No attacks on the shield yet</div>
        <div className="text-[13px] text-faint">{nf(data.stats.events)} requests inspected. Run the red-team drill below to see families appear.</div>
        <button onClick={onGo} className="mt-2 text-[13px] font-medium text-accent hover:underline">Open the shield</button>
      </div>
    )
  }
  return (
    <>
      <BarList color={TIER_FILL.Critical} rows={rows.map(([k, v], i) => ({ key: k, label: k, value: v.n, sub: v.blocked ? `${v.blocked} blocked` : 'allowed (monitor)', hot: i === 0 }))} />
      <p className="mt-3 text-[11.5px] text-faint">{nf(data.stats.attacks)} attacks in {nf(data.stats.events)} requests from {data.stats.sources} sources; {data.stats.blocked} blocked inline.</p>
    </>
  )
}

const DETECTION_TTP: Record<string, [string, string]> = { surge: ['T1595', 'Active Scanning'], beacon: ['T1071', 'Application Layer Protocol (C2)'], anomaly: ['T1021', 'Remote Services (lateral movement)'] }
/** MITRE ATT&CK techniques seen: from the shield's findings and the live detectors. */
export function AttackStrip() {
  const shield = useJson<ShieldStatus>('/api/shield', [], 10000).data
  const live = useJson<Live>('/api/live', [], 10000).data
  const rows = useMemo(() => {
    const by = new Map<string, { name: string; n: number; from: Set<string> }>()
    const add = (id: string, name: string, from: string) => { const v = by.get(id) ?? { name, n: 0, from: new Set<string>() }; v.n += 1; v.from.add(from); by.set(id, v) }
    for (const f of shield?.findings ?? []) if (f.attack) add(f.attack, f.attack_name, 'HTTP shield')
    for (const d of live?.detections ?? []) { const t = DETECTION_TTP[d.kind]; if (t) add(t[0], t[1], 'decoy grid') }
    return [...by.entries()].sort((a, b) => b[1].n - a[1].n)
  }, [shield, live])
  if (!shield && !live) return <Pending what="techniques" h={160} />
  if (!rows.length) return <div className="flex h-[160px] items-center justify-center text-center text-[13px] text-faint">No technique observed yet. Techniques appear as the shield and the decoy grid detect attacks.</div>
  const max = rows[0][1].n
  return (
    <div className="flex flex-wrap gap-2">
      {rows.map(([id, v]) => (
        <a key={id} href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`} target="_blank" rel="noreferrer"
           className="flex min-w-[180px] flex-1 items-center gap-3 rounded-xl border border-line bg-panel-2 px-3 py-2 hover:border-line-2">
          <Crosshair size={15} className="shrink-0 text-crit-ink" />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13px]"><span className="font-mono font-semibold">{id}</span> {v.name}</span>
            <span className="block text-[11.5px] text-faint">{[...v.from].join(', ')}</span>
          </span>
          <span className="font-mono text-[13px] font-semibold">{v.n}</span>
          <span className="h-8 w-1 rounded-full bg-panel-3"><span className="block w-full rounded-full bg-crit" style={{ height: `${Math.max(10, (100 * v.n) / max)}%`, marginTop: `${100 - Math.max(10, (100 * v.n) / max)}%` }} /></span>
        </a>
      ))}
    </div>
  )
}

const DAY = 86_400_000
/** Campaigns on a time axis: from the first signal we saw to the exploit, with our lead time. */
export function CampaignTimeline({ camps }: { camps: Campaign[] }) {
  if (!camps.length) return <Pending what="campaigns" h={200} />
  const rows = [...camps].filter((c) => c.first_signal).sort((a, b) => (a.status === b.status ? b.early_warning_days - a.early_warning_days : a.status === 'ACTIVE' ? -1 : 1)).slice(0, 8)
  const t0 = Math.min(...rows.map((c) => new Date(c.first_signal!).getTime()))
  const t1 = Math.max(Date.now(), ...rows.map((c) => (c.last_exploit ? new Date(c.last_exploit).getTime() : 0)))
  const span = Math.max(DAY, t1 - t0)
  const x = (iso: string) => (100 * (new Date(iso).getTime() - t0)) / span
  const colour = (s: Campaign['status']) => (s === 'ACTIVE' ? TIER_FILL.Critical : s === 'EMERGING' ? TIER_FILL.High : 'var(--color-line-2)')
  return (
    <div>
      <ul className="space-y-2">
        {rows.map((c) => {
          const a = x(c.first_signal!), b = c.last_exploit ? x(c.last_exploit) : 100
          return (
            <li key={c.id} className="grid grid-cols-[150px_minmax(0,1fr)_64px] items-center gap-3 text-[12.5px]">
              <span className="truncate font-medium" title={c.title}>{c.title.replace(/^Exploitation of /, '')}</span>
              <div className="relative h-5">
                <div className="absolute inset-y-[9px] inset-x-0 h-px bg-line" />
                <div className="absolute top-[6px] h-2 rounded-full" style={{ left: `${a}%`, width: `${Math.max(1.5, b - a)}%`, background: colour(c.status) }} />
                <span className="absolute top-[3px] h-3.5 w-3.5 -translate-x-1/2 rounded-full border-2 border-panel bg-accent" style={{ left: `${a}%` }} title={`first signal ${c.first_signal}`} />
                {c.last_exploit && <span className="absolute top-[3px] h-3.5 w-3.5 -translate-x-1/2 rounded-full border-2 border-panel" style={{ left: `${b}%`, background: colour(c.status) }} title={`exploit ${c.last_exploit}`} />}
              </div>
              <span className="text-right font-mono"><span className="font-semibold">{c.early_warning_days} d</span> <span className="text-faint">early</span></span>
            </li>
          )
        })}
      </ul>
      <div className="mt-2 flex items-center justify-between font-mono text-[10.5px] text-faint"><span>{new Date(t0).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })}</span><span>today</span></div>
      <p className="mt-2 text-[11.5px] text-faint">Blue dot: our first signal (a decoy surge or a forecast). Coloured dot: the exploit confirmed. Bar colour: active, emerging or dormant.</p>
    </div>
  )
}

/** Human decisions: approved and rejected over the last days, who decided, how long proposals waited. */
export function DecisionsToday({ tick }: { tick: number }) {
  const ok = useJson<Approval[]>('/api/approvals?status=approved', [tick])
  const no = useJson<Approval[]>('/api/approvals?status=rejected', [tick])
  if (!ok.data || !no.data) return <Pending error={ok.error ?? no.error} what="decisions" h={220} />
  const all = [...ok.data, ...no.data].filter((a) => a.decided_at)
  const latest = all.reduce((m, a) => Math.max(m, new Date(a.decided_at!).getTime()), 0) || Date.now()
  const days = Array.from({ length: 7 }, (_, i) => { const d = new Date(latest - (6 - i) * DAY); return d.toISOString().slice(0, 10) })
  const per = days.map((d) => ({ d, ok: ok.data!.filter((a) => a.decided_at?.startsWith(d)).length, no: no.data!.filter((a) => a.decided_at?.startsWith(d)).length }))
  const max = Math.max(1, ...per.map((p) => p.ok + p.no))
  const waits = all.map((a) => (new Date(a.decided_at!).getTime() - new Date(a.proposed_at).getTime()) / 60000).sort((a, b) => a - b)
  const median = waits.length ? waits[Math.floor(waits.length / 2)] : null
  const who = new Map<string, number>()
  for (const a of all) who.set(a.decided_by ?? '—', (who.get(a.decided_by ?? '—') ?? 0) + 1)
  return (
    <div>
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{nf(all.length)}</span>
        <span className="text-[13px] text-mute">decisions in the week to {days.at(-1)?.slice(5)} · <span className="text-ok-ink">{nf(ok.data.length)} approved</span> · {nf(no.data.length)} rejected</span>
      </div>
      <div className="mt-4 flex h-20 items-end gap-1.5" role="img" aria-label={per.map((p) => `${p.d}: ${p.ok} approved, ${p.no} rejected`).join('; ')}>
        {per.map((p) => (
          <div key={p.d} className="flex flex-1 flex-col items-center gap-1">
            <div className="flex w-full flex-col justify-end" style={{ height: 60 }}>
              <div className="w-full rounded-t-sm bg-faint" style={{ height: `${(60 * p.no) / max}px` }} />
              <div className="w-full rounded-t-sm bg-ok" style={{ height: `${(60 * p.ok) / max}px` }} />
            </div>
            <span className="font-mono text-[10px] text-faint">{p.d.slice(8)}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[12.5px] text-mute">
        <span className="flex items-center gap-1.5"><Timer size={13} />median wait {median != null ? (median >= 60 ? `${(median / 60).toFixed(1)} h` : `${Math.round(median)} min`) : '—'}</span>
        {[...who.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([w, n]) => <span key={w}><b className="font-mono text-text">{n}</b> by {w}</span>)}
      </div>
    </div>
  )
}

const WORST: (Tier | undefined)[] = [undefined, 'Medium', 'High', 'Critical', 'Compromise']
interface Host { host: string; product: string; version: string; zone: string; openHigh: number; worst: number; ports: number[]; org: string; orgId: string }
/** The most exposed hosts across every operator: internet-facing, worst warning first. Profiles load once. */
export function ExposedHosts({ orgs, onOrg }: { orgs?: Soc['orgs']; onOrg: (id: string) => void }) {
  const [hosts, setHosts] = useState<Host[]>()
  const [error, setError] = useState<string>()
  const ids = useMemo(() => (orgs ?? []).map((o) => o.id).join(','), [orgs])
  useEffect(() => {
    if (!ids) return
    let alive = true
    Promise.all(ids.split(',').map((id) => fetchJson(`/api/orgs/${id}/profile`) as Promise<OrgProfile>))
      .then((ps) => {
        if (!alive) return
        const out: Host[] = []
        for (const p of ps) for (const e of p.surface.exposed) out.push({ host: e.hostname, product: e.product, version: e.version, zone: e.zone, openHigh: e.open_high, worst: e.worst, ports: e.ports, org: p.org.name, orgId: p.org.id })
        out.sort((a, b) => b.worst - a.worst || b.openHigh - a.openHigh)
        setHosts(out)
      })
      .catch((e) => alive && setError(String(e)))
    return () => { alive = false }
  }, [ids])
  if (!hosts) return <Pending error={error} what={`the exposed hosts of ${orgs?.length ?? '…'} operators`} h={260} />
  return (
    <div>
      <table className="w-full table-fixed text-[13px]">
        <colgroup><col className="w-[36%]" /><col className="w-[30%]" /><col className="hidden w-[18%] sm:table-column" /><col className="w-[8%]" /><col className="w-[8%]" /></colgroup>
        <thead><tr className="text-left text-[11.5px] text-faint"><th className="pb-2 font-medium">Host</th><th className="pb-2 font-medium">Product</th><th className="hidden pb-2 font-medium sm:table-cell">Operator</th><th className="pb-2 text-right font-medium">High+</th><th className="pb-2 text-right font-medium">Worst</th></tr></thead>
        <tbody className="divide-y divide-line">
          {hosts.slice(0, 8).map((h) => (
            <tr key={`${h.orgId}-${h.host}`} className="hover:bg-panel-2/50">
              <td className="truncate py-2 pr-2 font-mono text-[12.5px]" title={h.host}><span className="mr-1.5 rounded bg-panel-2 px-1 text-[10px] font-semibold uppercase text-faint">{h.zone.slice(0, 3)}</span>{h.host}</td>
              <td className="truncate py-2 pr-2" title={`${h.product} ${h.version}`}>{h.product} <span className="text-faint">{h.version}</span></td>
              <td className="hidden truncate py-2 pr-2 sm:table-cell"><button onClick={() => onOrg(h.orgId)} className="max-w-full truncate text-accent hover:underline">{h.org}</button></td>
              <td className="py-2 text-right font-mono">{h.openHigh}</td>
              <td className="py-2 pl-2 text-right">{WORST[h.worst] ? <TierPill tier={WORST[h.worst]!} /> : <span className="text-faint">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 text-[11.5px] text-faint">{nf(hosts.length)} internet- and DMZ-facing hosts across {orgs?.length} operators (SIM inventory; the CVEs behind the warnings are real).</p>
    </div>
  )
}

export function Lead({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return <span className="flex items-center gap-2">{icon}{children}</span>
}
export const RadarIcon = Radar
