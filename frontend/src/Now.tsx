import { ArrowRight, FileText, Inbox, ShieldCheck, ShieldX, Siren, TrendingUp, Wrench } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Card, type Feed, type ForecastView, type IntelSource, type Soc, type Summary, type Technology } from './api'
import { CertInReportModal } from './ExportPanel'
import { ApprovalQueue } from './proactive'
import { Honeycomb } from './soc/Honeycomb'
import { AlertCard, Delta, nf, SocCard, TabBoxes, useJson } from './soc/kit'
import { Insight, ScoreCard, SectorExposure, SecurityKpis, TierDonut } from './soc/overview'
import { IntelSources, LiveThreats, PostureGauges, TechThreats, ThreatTrend, useLiveThreatRows } from './soc/panels'
import { deadlinesSummary, DeadlineTimeline, EventTicker, LikelyNext, NoiseFunnel } from './soc/telemetry'
import { ThreatMap } from './soc/ThreatMap'
import { Band, Figures, Prov, Row, TIER_FILL, TierPill, useToast, WRAP } from './ui'

/* The duty desk, for a national CERT on shift (SOC black, ui-07). The header: the one sentence that matters and the
   trip card (one warning, one countdown, one action). Then the command centre: three alert cards, the headline
   figures, threat activity (where attacks start and whom they reach), live threats beside what is up next, the trend
   and the posture, threats by technology and the intelligence sources. Then what Odyssey did on its own, and the
   decisions only a person can make. */

const JOURNEY = [
  { key: 'new', label: 'Issued' },
  { key: 'acknowledged', label: 'Acknowledged' },
  { key: 'mitigating', label: 'Mitigating' },
  { key: 'verifying', label: 'Verifying' },
  { key: 'closed', label: 'Closed' },
]
const ACTION_LABEL: Record<string, string> = {
  acknowledge: 'Acknowledge',
  start: 'Start mitigation',
  verify: 'Patched, verify',
  resolve: 'Close as resolved',
}
const DONE_TOAST: Record<string, string> = {
  acknowledge: 'Acknowledged. The deadline clock keeps running.',
  start: 'Mitigation started.',
  verify: 'Marked patched: verification next.',
  resolve: 'Closed as resolved.',
  false_positive: 'Closed as a false positive. Recorded for calibration.',
}

function useNow(ms = 1000) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(id)
  }, [ms])
  return now
}

export function Countdown({ issuedAt, hours, big }: { issuedAt: string; hours: number | null; big?: boolean }) {
  const now = useNow()
  if (hours == null) return <span className="text-mute">no deadline</span>
  const left = new Date(issuedAt).getTime() + hours * 3600_000 - now
  const overdue = left < 0
  const abs = Math.abs(left)
  const h = Math.floor(abs / 3600_000)
  const m = Math.floor((abs % 3600_000) / 60_000)
  const s = Math.floor((abs % 60_000) / 1000)
  const text = `${overdue ? '−' : ''}${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
  return <span className={`font-mono tabular-nums ${overdue ? 'text-crit-ink' : ''} ${big ? 'text-[48px] font-semibold leading-none tracking-tight' : 'text-[13px] font-medium'}`}>{text}</span>
}

/** Trip progress: a thin bar with the current stage named. */
function Progress({ state }: { state: string }) {
  const idx = Math.max(0, JOURNEY.findIndex((j) => j.key === (state === 'reopened' ? 'acknowledged' : state)))
  return (
    <div>
      <div className="flex gap-1">
        {JOURNEY.map((j, i) => (
          <div key={j.key} className={`h-1.5 flex-1 rounded-full ${i < idx ? 'bg-ok' : i === idx ? 'bg-text' : 'bg-panel-3'}`} />
        ))}
      </div>
      <div className="mt-1.5 flex justify-between text-[11px] text-faint">
        {JOURNEY.map((j, i) => <span key={j.key} className={i === idx ? 'font-semibold text-text' : ''}>{j.label}</span>)}
      </div>
    </div>
  )
}

function title(c: Card) {
  return c.headline ?? `${c.cve_id} · ${c.title.split('.')[0]}`
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Live = any

/** One line in the header that proves the system is running: sensors, feeds, the last detection. */
function LiveStrip({ s, onOpen }: { s?: Live; onOpen: () => void }) {
  if (!s) return null
  const fresh = s.feeds.filter((f: { status: string }) => f.status === 'fresh').length
  const last = s.detections[0]
  return (
    <button onClick={onOpen} className="mt-7 flex flex-wrap items-center gap-x-3 gap-y-1 text-left text-[14px] text-mute transition-colors hover:text-text">
      <span className="flex items-center gap-2 font-semibold text-text"><span className="soc-live h-2 w-2 rounded-full bg-ok" /> Live</span>
      <span>{s.sensors} decoy sensors reporting</span><span className="text-faint">·</span>
      <span>{fresh}/{s.feeds.length} real feeds fresh</span><span className="text-faint">·</span>
      <span>{last ? `last detection: ${last.title.slice(0, 60)}${last.title.length > 60 ? '…' : ''}` : 'no detections: quiet'}</span>
    </button>
  )
}

/** The warnings in order of deadline, after the one in the header; two columns in the strip's wide panel. */
function UpNext({ rest, feed, onOpen, onGo }: { rest: Card[]; feed: Feed; onOpen: (c: Card) => void; onGo: (view: 'soc' | 'intel' | 'live', tab: string) => void }) {
  return (
    <SocCard title="Up next" sub="Warnings in order of deadline"
             right={<button onClick={() => onGo('soc', 'warnings')} className="text-[13px] font-medium text-accent hover:underline">All warnings</button>}>
      <div className="-mt-1 grid gap-x-8 lg:grid-cols-2">
        {rest.slice(0, 8).map((c) => (
          <Row key={c.id} onClick={() => onOpen(c)}
               lead={<span className="h-2.5 w-2.5 rounded-full" style={{ background: TIER_FILL[c.tier] }} />}
               title={title(c)} sub={`${c.org_name} · ${c.cve_id}`}
               trail={<Countdown issuedAt={(c as Card & { issued_at?: string }).issued_at ?? feed.issued_at} hours={c.deadline_hours} />} />
        ))}
      </div>
    </SocCard>
  )
}

export function Now({ onOpen, onOrg, onGo, tick }: {
  onOpen: (c: Card) => void; onOrg: (id: string) => void; onGo: (view: 'soc' | 'intel' | 'live', tab: string) => void; tick: number
}) {
  const [feed, setFeed] = useState<Feed>()
  const [soc, setSoc] = useState<Soc>()
  const [fc, setFc] = useState<ForecastView>()
  const [busy, setBusy] = useState(false)
  const [reportFor, setReportFor] = useState<Card>()
  const live = useJson<Live>('/api/live', [], 5000).data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const metrics = useJson<any>('/api/soc/metrics', [tick]).data
  const { rows: liveRows } = useLiveThreatRows()
  const tech = useJson<Technology[]>('/api/intel/technologies').data
  const summary = useJson<Summary>('/api/summary').data
  const sources = useJson<IntelSource[]>('/api/intel/sources').data
  const scorecard = useJson<{ funnel: { cves_this_month: number; critical_or_compromise: number; noise_reduction_x: number } }>('/api/scorecard').data
  const toast = useToast()
  const load = () => {
    api.feed().then(setFeed).catch(() => undefined)
    api.soc().then(setSoc).catch(() => undefined)
  }
  useEffect(load, [tick])
  useEffect(() => { api.forecast().then(setFc).catch(() => undefined) }, [])

  const act = (c: Card, action: string) => {
    setBusy(true)
    api.act(c.org_id, c.cve_id, action).then(() => { toast(DONE_TOAST[action] ?? 'Done.'); load() })
      .catch((e) => toast(String(e))).finally(() => setBusy(false))
  }

  if (!feed) return <div className="bg-band text-mute"><div className={`${WRAP} py-24 text-lg`}>Loading the national picture…</div></div>
  const [hero, ...rest] = feed.cards
  const next = hero?.workflow.next_action
  const auto = soc?.autopilot.by_mode?.auto
  const lead = soc?.autopilot.lead?.real_signals_only
  const langs = soc ? new Set(soc.orgs.map((o) => o.lang)).size : undefined
  const headline = feed.counts.compromise > 0
    ? 'A suspected compromise needs you now.'
    : feed.counts.needs_action > 0 ? `${feed.counts.needs_action} warnings need you.` : 'All quiet. Nothing needs you.'
  const compCard = feed.cards.find((c) => c.tier === 'Compromise')
  const fresh = live ? live.feeds.filter((f: { status: string }) => f.status === 'fresh').length : undefined
  const today = soc?.pressure.at(-1), yesterday = soc?.pressure.at(-2)
  const dl = deadlinesSummary(feed)
  const topFc = fc ? [...fc.items].sort((a, b) => b.p - a.p)[0] : undefined
  const techTop = (tech ?? []).filter((t) => t.critical > 0).sort((a, b) => b.critical - a.critical)[0]
  const sectorRows = summary ? Object.entries(summary.sector_heatmap).map(([k, t]) => [k, (t.Critical ?? 0) + (t.Compromise ?? 0)] as [string, number]).sort((a, b) => b[1] - a[1]) : []
  const sectorTop = sectorRows[0], sectorN = sectorRows.length
  const srcRows = (sources ?? []).filter((x) => (x.relevant ?? 0) > 0).sort((a, b) => (b.relevant ?? 0) - (a.relevant ?? 0))
  const srcTop = srcRows[0], srcN = sources ? srcRows.length : undefined
  const funnel = scorecard?.funnel

  return (
    <>
      <section className="soc-dark relative overflow-hidden border-b border-line">
        <Honeycomb />
        <div className={`${WRAP} relative z-10 grid items-center gap-10 py-10 xl:grid-cols-[1fr_520px]`}>
          <div className="min-w-0">
            <p className="text-[13px] text-mute">National CERT duty desk · {new Date(feed.issued_at).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })} IST</p>
            <h1 className="mt-4 max-w-3xl text-[40px] font-semibold leading-[1.05] tracking-tight sm:text-[52px]">{headline}</h1>
            <p className="mt-5 max-w-2xl text-[17px] leading-relaxed text-mute">
              {feed.counts.needs_action} warnings need action across {soc?.orgs.length ?? '…'} operators, each told in its own language{langs ? ` (${langs} in use)` : ''}.
              {' '}{soc?.pending ?? '…'} decisions wait for you; Odyssey handles the rest.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <button onClick={() => onGo('soc', 'overview')} className="rounded-full bg-text px-6 py-3.5 text-[15px] font-semibold text-ink transition-opacity hover:opacity-85">
                Review {soc?.pending ?? ''} decisions
              </button>
              <button onClick={() => onGo('soc', 'cases')} className="rounded-full border border-line-2 bg-panel-2 px-6 py-3.5 text-[15px] font-semibold text-text transition-colors hover:bg-panel-3">
                Open cases
              </button>
            </div>
            <LiveStrip s={live} onOpen={() => onGo('live', '')} />
          </div>

          {hero ? (
            <article className={`soc-light rounded-2xl border p-6 ${hero.tier === 'Compromise' ? 'border-comp/60' : 'border-line-2'}`}>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <TierPill tier={hero.tier} />
                {hero.kev && <span className="rounded-full bg-crit/15 px-2.5 py-0.5 text-xs font-medium text-crit-ink">exploited in the wild</span>}
                <span className="ml-auto font-mono text-xs text-mute">{hero.cve_id}</span>
              </div>
              <h3 className="text-[19px] font-semibold leading-snug">{title(hero)}</h3>
              <p className="mt-1 text-sm text-mute">{hero.org_name} · {hero.sector} · {hero.assets} asset{hero.assets > 1 ? 's' : ''}</p>
              <div className="my-5">
                <Countdown issuedAt={(hero as Card & { issued_at?: string }).issued_at ?? feed.issued_at} hours={hero.deadline_hours} big />
                <div className="mt-1.5 text-sm text-mute">{hero.tier === 'Compromise' ? 'left to report to CERT-In' : 'left to remediate'}</div>
              </div>
              <Progress state={hero.workflow.state} />
              {next && (
                <button disabled={busy} onClick={() => act(hero, next)}
                        className="mt-5 w-full rounded-full bg-action py-3.5 text-[15px] font-semibold text-ink transition-opacity hover:opacity-85 disabled:opacity-50">
                  {ACTION_LABEL[next] ?? next}
                </button>
              )}
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button onClick={() => onOpen(hero)} className="rounded-full bg-panel-2 px-4 py-2 text-sm font-medium hover:bg-panel-3">Why this warning?</button>
                {hero.tier === 'Compromise' && (
                  <button onClick={() => setReportFor(hero)} className="flex items-center gap-1.5 rounded-full bg-panel-2 px-4 py-2 text-sm font-medium hover:bg-panel-3">
                    <FileText size={14} /> CERT-In report
                  </button>
                )}
                {next && (
                  <button disabled={busy} onClick={() => act(hero, 'false_positive')} className="ml-auto flex items-center gap-1 px-2 py-2 text-sm text-mute hover:text-text">
                    <ShieldX size={14} /> False positive
                  </button>
                )}
              </div>
            </article>
          ) : <div className="rounded-2xl border border-line bg-panel p-8 text-xl font-semibold">All clear: no warning needs action.</div>}
        </div>
      </section>

      <main className={`${WRAP} space-y-8 py-12`}>
        <div className="grid gap-4 lg:grid-cols-3">
          {compCard ? (
            <AlertCard tone="comp" icon={<Siren size={18} />} onClick={() => onOpen(compCard)} action="Review the incident"
                       title={`${feed.counts.compromise} suspected compromise${feed.counts.compromise > 1 ? 's' : ''}`}
                       sub={`${compCard.org_name}: ${title(compCard)}`} />
          ) : (
            <AlertCard tone="ok" icon={<ShieldCheck size={18} />} onClick={() => onGo('soc', 'warnings')} action="See all warnings"
                       title="No suspected compromise" sub="No asset shows signs of compromise right now." />
          )}
          <AlertCard tone="accent" icon={<Inbox size={18} />} onClick={() => onGo('soc', 'overview')} action="Open the queue"
                     title={`${soc?.pending ?? '…'} decisions wait for you`}
                     sub="Notices, escalations and predictions that Odyssey will not send without a person." />
          <AlertCard tone="crit" icon={<Wrench size={18} />} onClick={() => onGo('intel', 'risk')} action="See the risk plan"
                     title={`${soc?.risk.for_80_pct ?? '…'} changes remove 80% of the risk`}
                     sub={`of ${nf(soc?.risk.tickets)} change tickets across ${nf(soc?.risk.assets_at_risk)} assets at risk`} />
        </div>

        <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)]">
          <ScoreCard />
          <div className="soc-seams grid-cols-2 md:grid-cols-3 xl:grid-cols-6">
            {[
              { label: 'Suspected compromise', value: soc ? nf(soc.tiers.Compromise ?? 0) : '—', dot: 'bg-comp',
                sub: !soc ? undefined : today && yesterday ? <Delta now={today.Compromise} before={yesterday.Compromise} good="down" window="vs yesterday" /> : ((soc.tiers.Compromise ?? 0) > 0 ? 'incident response under way' : 'none right now') },
              { label: 'Critical warnings', value: nf(soc?.tiers.Critical), dot: 'bg-crit',
                sub: today && yesterday ? <><Delta now={today.Critical} before={yesterday.Critical} good="down" window="open, vs yesterday" /><span className="block">{nf(soc?.tiers.High)} High · {nf(soc?.tiers.Medium)} Medium</span></> : undefined },
              { label: 'Open cases', value: nf(metrics?.open), sub: metrics ? `${metrics.incidents} incident response · ${metrics.unassigned} unassigned` : undefined },
              { label: 'Decisions waiting', value: nf(soc?.pending), sub: 'only a person can approve these' },
              { label: 'Assets at risk', value: nf(soc?.risk.assets_at_risk), sub: soc ? `${nf(soc.risk.tickets)} change tickets would clear them` : undefined },
              { label: 'Detections this hour', value: nf(live?.pipeline?.detections_hour), sub: live ? `${live.sensors} decoy sensors (SIM) · ${fresh}/${live.feeds.length} real feeds fresh` : undefined, dot: 'soc-live bg-ok' },
            ].map((k) => (
              <div key={k.label} className="px-5 py-4">
                <div className="flex items-center gap-2 text-[13px] font-medium text-mute">{k.dot && <span className={`h-2 w-2 shrink-0 rounded-full ${k.dot}`} />}{k.label}</div>
                <div className="mt-2 text-[30px] font-semibold leading-none tracking-tight tabular-nums">{k.value}</div>
                {k.sub && <div className="mt-2 text-[12.5px] leading-snug text-faint">{k.sub}</div>}
              </div>
            ))}
          </div>
        </div>

        <EventTicker tick={tick} onOpen={() => onGo('soc', 'log')} />

        <ThreatMap orgs={soc?.orgs} onOrg={onOrg} />

        {/* The feeds, as a strip of summary boxes with one panel open: less to scan, nothing taken away. */}
        <TabBoxes label="Feeds and deadlines" defaultOpen="next" items={[
          { key: 'live', title: 'Live threats', chip: <span className="soc-live h-2 w-2 shrink-0 rounded-full bg-ok" />, count: nf(liveRows.length),
            preview: liveRows[0] ? `Newest: ${liveRows[0].title}` : 'Quiet: no detections; run a drill on Live to see one',
            panel: <LiveThreats onAll={() => onGo('live', '')} cols /> },
          { key: 'next', title: 'Up next', count: nf(rest.length),
            preview: rest[0] ? <>{rest[0].org_name} · {rest[0].cve_id} · <Countdown issuedAt={(rest[0] as Card & { issued_at?: string }).issued_at ?? feed.issued_at} hours={rest[0].deadline_hours} /></> : 'No further warning waiting',
            panel: <UpNext rest={rest} feed={feed} onOpen={onOpen} onGo={onGo} /> },
          { key: 'due', title: 'Deadlines, next 24 h', count: nf(dl.due),
            preview: dl.late ? `${dl.late} already late${dl.next ? ` · next ${dl.next.c.org_name}` : ''}` : dl.next ? `None late · next: ${dl.next.c.org_name} · ${dl.next.c.cve_id}` : 'Nothing due in the next 24 hours',
            panel: <DeadlineTimeline feed={feed} onOpen={(c) => onOpen(c as Card)} /> },
          { key: 'likely', title: 'Likely to be exploited next', chip: <Prov p="REAL" />, count: fc ? nf(fc.flagged) : '—',
            preview: topFc ? `${topFc.cve} · ${topFc.product ?? 'product in text'} · ${Math.round(topFc.p * 100)}% · ${topFc.orgs} operators` : 'flagged on the day they were published',
            panel: <SocCard title="Likely to be exploited next" prov={['REAL']} sub="New CVEs on our exposed assets, flagged on the day they were published, before CISA confirms exploitation"><LikelyNext onOpen={() => onGo('intel', 'overview')} /></SocCard> },
        ]} />

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
          <div className="soc-dark rounded-2xl"><ThreatTrend soc={soc} /></div>
          <div className="grid gap-6">
            <SocCard className="soc-dark" title="Threat distribution" prov={['REAL', 'SIM']} sub="Open warnings by tier"><TierDonut soc={soc} /></SocCard>
            <SocCard title="Security insight" sub="This page, in four sentences"><Insight soc={soc} feed={feed} /></SocCard>
          </div>
        </div>

        <TabBoxes label="Analysis" defaultOpen="tech" items={[
          { key: 'tech', title: 'Threats by technology', chip: <Prov p="REAL" />, count: techTop ? nf(techTop.critical) : '—',
            preview: techTop ? `${techTop.label} carries the most Critical warnings${techTop.campaign === 'ACTIVE' ? ' and is under an active campaign' : ''}` : 'Critical warnings per product in the inventory',
            panel: <TechThreats onOpen={() => onGo('intel', 'threats')} /> },
          { key: 'sector', title: 'Exposure by sector', count: sectorTop ? nf(sectorTop[1]) : '—',
            preview: sectorTop ? `${sectorTop[0]} has the most Critical warnings; ${sectorN} sectors watched` : 'Critical warnings and suspected compromises per sector',
            panel: <SocCard title="Exposure by sector" prov={['REAL', 'SIM']} sub="Critical warnings and suspected compromises per sector"><SectorExposure /></SocCard> },
          { key: 'sources', title: 'Intelligence sources', count: srcN != null ? nf(srcN) : '—',
            preview: srcTop ? `${srcTop.name} contributed the most relevant signals` : 'Signals that touched our inventory, by source',
            panel: <IntelSources /> },
          { key: 'funnel', title: 'Noise funnel', chip: <Prov p="REAL" />, count: funnel ? `${funnel.noise_reduction_x}×` : '—',
            preview: funnel ? `${nf(funnel.cves_this_month)} CVEs this month → ${nf(funnel.critical_or_compromise)} warnings that matter` : 'From every CVE this month to the warnings that matter',
            panel: <SocCard title="Noise funnel" prov={['REAL']} sub="From every CVE this month to the warnings that matter"><NoiseFunnel /></SocCard> },
        ]} />

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
          <PostureGauges soc={soc} />
          <SocCard title="Security KPIs" sub="Each with its basis"><SecurityKpis soc={soc} /></SocCard>
        </div>
      </main>

      <Band tone="black">
        <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-[26px] font-semibold tracking-tight">Odyssey at work</h2>
            <p className="mt-1.5 text-[15px] text-mute">Proactive by design: it warns, predicts and notifies on its own, and asks a person before anything consequential.</p>
          </div>
          <button onClick={() => onGo('soc', 'log')} className="flex items-center gap-2 rounded-full bg-text px-5 py-3 text-[15px] font-semibold text-ink transition-opacity hover:opacity-85">
            See everything it did <ArrowRight size={16} />
          </button>
        </div>
        <Figures glass items={[
          { value: auto != null ? auto.toLocaleString('en-IN') : '—', label: 'actions on its own', sub: `since go-live on ${soc?.autopilot.go_live ?? '…'}` },
          { value: lead?.median_lead_days != null ? `${lead.median_lead_days} d` : '—', label: 'ahead of CISA KEV',
            sub: lead ? `median on real signals · ${lead.acted_before_kev} CVEs · up to ${lead.max_lead_days} d` : undefined },
          { value: fc ? fc.flagged.toLocaleString('en-IN') : '—', label: 'flagged before exploitation', sub: fc ? `${fc.since_exploited} since confirmed by CISA` : undefined, dot: 'bg-accent' },
          { value: '0', label: 'cloud calls', sub: 'every model runs on this laptop', dot: 'bg-ok' },
        ]} />
      </Band>

      <Band tone="soft">
        <div className="grid gap-8 xl:grid-cols-2">
          <div>
            <div className="mb-4 flex items-baseline justify-between">
              <h2 className="text-[26px] font-semibold tracking-tight">Needs your decision</h2>
              <button onClick={() => onGo('soc', 'overview')} className="text-sm font-medium text-accent hover:underline">See all {soc?.pending ?? ''}</button>
            </div>
            <ApprovalQueue limit={1} onChanged={load} hideMore />
          </div>
          <div>
            <h2 className="mb-4 text-[26px] font-semibold tracking-tight">Ahead of the threat</h2>
            <div className="soc-card px-5 py-2">
              {fc && (
                <Row onClick={() => onGo('intel', 'overview')} lead={<TrendingUp size={18} />}
                     title={`${fc.flagged} new CVEs flagged likely to be exploited`}
                     sub={`${fc.since_exploited} already confirmed by CISA after Odyssey flagged them`} />
              )}
              <Row onClick={() => onGo('intel', 'risk')} lead={<ArrowRight size={18} />}
                   title={`${soc?.risk.for_80_pct ?? '…'} changes remove 80% of the national risk`}
                   sub={`of ${soc?.risk.tickets ?? '…'} change tickets across ${soc?.risk.assets_at_risk ?? '…'} assets at risk`} />
            </div>
          </div>
        </div>
      </Band>
      {reportFor && <CertInReportModal orgId={reportFor.org_id} cveId={reportFor.cve_id} onClose={() => setReportFor(undefined)} />}
    </>
  )
}
