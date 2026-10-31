import { ExternalLink, Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Attacks, type Campaign, type IntelAdvisory, type IntelSource, type PortTrend, type Soc as SocData, type Technology } from './api'
import { ApprovalQueue, AutopilotFeed, useLanguages } from './proactive'
import { Rewind } from './Rewind'
import { Badge, Panel } from './ui'

const fmt = (n: number | null | undefined) => (n == null ? '—' : n.toLocaleString('en-IN'))

function Kpi({ value, label, sub, tone }: { value: string; label: string; sub?: string; tone?: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3">
      <div className={`text-3xl font-semibold tabular-nums ${tone ?? ''}`}>{value}</div>
      <div className="text-sm">{label}</div>
      {sub && <div className="mt-0.5 text-xs text-mute">{sub}</div>}
    </div>
  )
}

/** Single-series sparkline; optional shaded bands (e.g. detected surges). Text stays in text tokens. */
export function Spark({ values, bands = [], color = '#38bdf8', h = 36 }: { values: number[]; bands?: [number, number][]; color?: string; h?: number }) {
  if (values.length < 2) return null
  const w = 160
  const max = Math.max(...values) || 1
  const x = (i: number) => (i / (values.length - 1)) * w
  const y = (v: number) => h - 2 - (v / max) * (h - 4)
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-9 w-full" preserveAspectRatio="none" role="img">
      {bands.map(([a, b], i) => <rect key={i} x={x(a)} y={0} width={Math.max(x(b) - x(a), 2)} height={h} fill="#d946ef" opacity={0.18} />)}
      <polyline points={values.map((v, i) => `${x(i)},${y(v)}`).join(' ')} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

function PortCard({ t }: { t: PortTrend }) {
  const pct = Math.round((t.ratio - 1) * 100)
  return (
    <div className="rounded-lg border border-line bg-panel-2/50 p-2" title={`${t.service} (port ${t.port}): last 7 days averaged ${fmt(t.last7_mean)} attack records/day vs a 28-day median of ${fmt(t.baseline_median)}; ${fmt(t.sources_last7)} distinct sources/day`}>
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate text-xs">{t.service}</span>
        <span className={`font-mono text-xs ${t.elevated ? 'text-crit' : 'text-mute'}`}>{pct >= 0 ? '+' : ''}{pct}%</span>
      </div>
      <Spark values={t.series.map((s) => s.records)} color={t.elevated ? '#ef4444' : '#38bdf8'} />
      <div className="text-[10px] text-mute">:{t.port} · {fmt(t.last7_mean)}/day</div>
    </div>
  )
}

function Technologies({ rows }: { rows: Technology[] }) {
  return (
    <table className="w-full text-xs">
      <thead className="text-left text-mute">
        <tr>
          <th className="pb-1 font-normal">Technology</th><th className="pb-1 text-right font-normal">Orgs</th>
          <th className="pb-1 text-right font-normal" title="internet- or DMZ-facing assets">Exposed</th>
          <th className="pb-1 text-right font-normal">Critical</th><th className="pb-1 text-right font-normal">High</th>
          <th className="pb-1 text-right font-normal" title="CVEs in CISA KEV affecting this technology here">Exploited CVEs</th>
          <th className="pb-1 text-right font-normal" title="CVEs the day-0 forecast flags, not yet exploited">Likely next</th>
          <th className="pb-1 pl-3 font-normal">Campaign</th>
          <th className="pb-1 text-right font-normal" title="global attack records on its service port, last 7 days vs 28-day median (DShield)">Attacks</th>
        </tr>
      </thead>
      <tbody>
        {rows.filter((r) => r.assets_at_risk > 0).slice(0, 14).map((r) => (
          <tr key={r.label} className="border-t border-line/50">
            <td className="py-1.5 pr-2">
              <span className="font-medium">{r.label}</span>
              {r.compromised_assets > 0 && <span className="ml-2 text-fuchsia-300">{r.compromised_assets} compromised</span>}
            </td>
            <td className="py-1.5 text-right font-mono">{r.orgs}</td>
            <td className="py-1.5 text-right font-mono">{r.internet_facing}</td>
            <td className="py-1.5 text-right font-mono text-crit">{r.critical || '—'}</td>
            <td className="py-1.5 text-right font-mono text-high">{r.high || '—'}</td>
            <td className="py-1.5 text-right font-mono">{r.kev_cves || '—'}</td>
            <td className="py-1.5 text-right font-mono text-accent">{r.forecast_cves || '—'}</td>
            <td className="py-1.5 pl-3">{r.campaign ? <span className={`rounded px-1.5 text-[10px] font-semibold ${r.campaign === 'ACTIVE' ? 'bg-crit/20 text-crit' : 'bg-high/20 text-high'}`}>{r.campaign}</span> : <span className="text-mute">—</span>}</td>
            <td className="py-1.5 text-right font-mono text-mute">{r.attack_trend ? `${r.attack_trend.ratio >= 1 ? '+' : ''}${Math.round((r.attack_trend.ratio - 1) * 100)}% :${r.attack_trend.port}` : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function Campaigns({ rows }: { rows: Campaign[] }) {
  return (
    <ol className="space-y-2">
      {rows.slice(0, 7).map((c) => (
        <li key={c.id} className="rounded-xl bg-panel-2 p-2.5">
          <div className="flex items-center gap-2">
            <span className={`rounded px-1.5 text-[10px] font-semibold ${c.status === 'ACTIVE' ? 'bg-crit/20 text-crit' : 'bg-high/20 text-high'}`}>{c.status}</span>
            <span className="truncate text-sm">{c.title.replace(/^(Exploitation|Reconnaissance) of /, '')}</span>
          </div>
          <div className="mt-1 text-xs text-mute">
            {c.cves.length} exploited CVE{c.cves.length === 1 ? '' : 's'} · {c.orgs_exposed.length} orgs · {c.sectors_exposed.length} sectors
            {c.chains.length > 0 && ` · ${c.chains.length} chained assets`}
            {c.early_warning_days > 0 && <span className="text-accent"> · first signal {c.early_warning_days} d before disclosure</span>}
            {c.cves.length === 0 && c.decoy_surges.length > 0 && ' · decoy scanning only'}
          </div>
          {c.cves.length > 0 && <div className="mt-1 truncate font-mono text-[11px] text-mute">{c.cves.slice(0, 3).map((x) => x.cve).join(' · ')}</div>}
        </li>
      ))}
    </ol>
  )
}

function Sources({ rows }: { rows: IntelSource[] }) {
  return (
    <table className="w-full text-xs">
      <thead className="text-left text-mute">
        <tr><th className="pb-1 font-normal">Source</th><th className="pb-1 font-normal">Type</th><th className="pb-1 text-right font-normal">Items</th><th className="pb-1 text-right font-normal">Relevant</th><th className="pb-1 pl-2 font-normal">Grade</th></tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.name} className="border-t border-line/50" title={r.funnel}>
            <td className="py-1.5 pr-2"><div className="flex items-center gap-1.5"><Badge tone={r.provenance === 'REAL' ? 'ok' : 'accent'}>{r.provenance}</Badge><span>{r.name}</span></div></td>
            <td className="py-1.5 text-mute">{r.kind}</td>
            <td className="py-1.5 text-right font-mono">{fmt(r.items)}</td>
            <td className="py-1.5 text-right font-mono">{fmt(r.relevant)}</td>
            <td className="py-1.5 pl-2 font-mono text-mute">{r.reliability ?? '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function Advisories({ rows }: { rows: IntelAdvisory[] }) {
  // inventory matches first (they name our products), then advisories that track CVEs we already watch
  const relevant = rows.filter((r) => r.relevant)
    .sort((a, b) => b.matches.reduce((s, m) => s + m.assets, 0) - a.matches.reduce((s, m) => s + m.assets, 0)
      || (b.published ?? '').localeCompare(a.published ?? ''))
  return (
    <ol className="space-y-1.5">
      {relevant.slice(0, 8).map((a, i) => (
        <li key={a.link + i} className="rounded-lg bg-panel-2 px-3 py-2">
          <div className="flex items-center gap-2 text-xs">
            <Badge tone={a.kind === 'ics' ? 'accent' : a.kind === 'kev' ? 'crit' : 'mute'}>{a.kind === 'ics' ? 'ICS advisory' : a.kind === 'kev' ? 'KEV alert' : 'alert'}</Badge>
            <span className="text-mute">{a.published}</span>
            <a href={a.link} target="_blank" rel="noreferrer" className="ml-auto text-mute hover:text-accent"><ExternalLink size={12} /></a>
          </div>
          <div className="mt-0.5 truncate text-sm">{a.title}</div>
          <div className="truncate text-[11px] text-mute">
            {a.matches.length > 0
              ? a.matches.map((m) => `${m.product}: ${m.assets} assets at ${m.orgs} orgs`).join(' · ')
              : `tracks ${a.cves_in_odyssey.join(', ')}`}
          </div>
        </li>
      ))}
      <li className="text-[11px] text-mute">{relevant.length} of {rows.length} latest CISA advisories touch this constituency; the rest are filtered out.</li>
    </ol>
  )
}

export function Soc({ onOrg, tick }: { onOrg: (id: string) => void; tick: number }) {
  const [d, setD] = useState<SocData>()
  const [sources, setSources] = useState<IntelSource[]>([])
  const [adv, setAdv] = useState<IntelAdvisory[]>([])
  const [atk, setAtk] = useState<Attacks>()
  const [tech, setTech] = useState<Technology[]>([])
  const [camps, setCamps] = useState<Campaign[]>([])
  const [stamp, setStamp] = useState(0)
  const langs = useLanguages()
  useEffect(() => { api.soc().then(setD).catch(() => undefined) }, [tick, stamp])
  useEffect(() => {
    api.intelSources().then(setSources).catch(() => undefined)
    api.intelAdvisories().then(setAdv).catch(() => undefined)
    api.attacks().then(setAtk).catch(() => undefined)
    api.technologies().then(setTech).catch(() => undefined)
    api.campaigns().then(setCamps).catch(() => undefined)
  }, [])
  if (!d) return <div className="p-8 text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />Assembling the operations picture…</div>

  const lead = d.autopilot.lead
  const real = lead?.real_signals_only
  const auto = d.autopilot.by_mode?.auto ?? 0
  const decoyTags = ['ivanti_cs', 'confluence', 'fortios', 'panos']
  const daily = atk?.decoy.daily ?? []
  const dates = [...new Set(daily.map((r) => r.date))]
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 overflow-auto">
      <div className="flex flex-wrap items-baseline gap-3">
        <h2 className="text-3xl font-semibold">National SOC</h2>
        <span className="text-sm text-mute">monitoring since {d.autopilot.go_live} · picture built {d.built_at?.replace('T', ' ')} IST</span>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi value={fmt(d.tiers.Compromise ?? 0)} label="suspected compromise" sub="Bayesian decision model" tone="text-fuchsia-300" />
        <Kpi value={fmt(d.tiers.Critical ?? 0)} label="Critical warnings" sub={`${fmt(d.tiers.High ?? 0)} High · ${fmt(d.tiers.Medium ?? 0)} Medium`} tone="text-crit" />
        <Kpi value={fmt(auto)} label="actions taken on its own" sub={`notices, hunts, digests in ${d.autopilot.languages?.length ?? 0} languages`} tone="text-accent" />
        <Kpi value={fmt(d.pending)} label="await your decision" sub="predictions and escalations need a human" tone="text-high" />
        <Kpi value={real?.median_lead_days != null ? `${real.median_lead_days} d` : '—'} label="ahead of CISA KEV"
             sub={real ? `median on REAL signals, ${real.acted_before_kev} CVEs, up to ${real.max_lead_days} d` : undefined} tone="text-ok" />
        <Kpi value={d.risk.for_50_pct != null ? fmt(d.risk.for_50_pct) : '—'} label="changes remove 50% of risk"
             sub={`${fmt(d.risk.for_80_pct)} for 80% · ${fmt(d.risk.tickets)} tickets`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Panel title="Open warnings by tier, day by day" right={<span className="text-xs text-mute">replayed from the evidence ledger</span>}>
            <Rewind d={d} />
          </Panel>
        </div>
        <Panel title={`Needs your decision · ${d.pending}`} right={<span className="text-xs text-mute">human in the loop</span>}>
          <div className="max-h-72 overflow-auto pr-1"><ApprovalQueue limit={3} onChanged={() => setStamp((s) => s + 1)} /></div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Panel title="Active threats by technology" right={<span className="text-xs text-mute">what is under attack, and where we run it</span>}>
            <Technologies rows={tech} />
          </Panel>
        </div>
        <Panel title="Campaigns · correlated threats" right={<span className="text-xs text-mute">CVEs, chains, decoy surges per product</span>}>
          <Campaigns rows={camps} />
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Threat-intelligence aggregation" right={<span className="text-xs text-mute">hover a row for its funnel</span>}>
          <Sources rows={sources} />
        </Panel>
        <Panel title="Real attacks: global honeypot telemetry on our services" right={<Badge tone="ok">REAL · SANS ISC DShield</Badge>}>
          <p className="mb-2 text-xs text-mute">Daily attack records against the ports our constituency's internet-facing products listen on (since 1 Aug), last 7 days vs the 28-day median.</p>
          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            {(atk?.dshield.trends ?? []).map((t) => <PortCard key={t.port} t={t} />)}
          </div>
          <div className="mt-3 border-t border-line pt-3">
            <div className="mb-2 flex items-center gap-2 text-xs"><Badge tone="accent">SIM</Badge><span className="text-mute">National decoy grid, sessions per day (shaded: detected scanning surge)</span></div>
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
              {decoyTags.map((tag) => {
                const series = dates.map((dt) => daily.filter((r) => r.date === dt && r.tag === tag).reduce((s, r) => s + r.sessions, 0))
                const bands = (atk?.decoy.surges ?? []).filter((s) => s.tag === tag)
                  .map((s) => [dates.indexOf(s.first), dates.indexOf(s.last)] as [number, number])
                return (
                  <div key={tag} className="rounded-lg border border-line bg-panel-2/50 p-2">
                    <div className="text-xs">{tag}</div>
                    <Spark values={series} bands={bands} color="#8b98a9" />
                    <div className="text-[10px] text-mute">{bands.length ? `${bands.length} surge${bands.length > 1 ? 's' : ''}` : 'no surge'}</div>
                  </div>
                )
              })}
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Real advisories, matched to our inventory" right={<Badge tone="ok">REAL · CISA</Badge>}>
          <Advisories rows={adv} />
        </Panel>
        <Panel title="What Odyssey did on its own" right={<span className="text-xs text-mute">audit-trail events</span>}>
          <AutopilotFeed limit={150} tick={tick + stamp} height="max-h-96" />
        </Panel>
        <Panel title="Organisations">
          <table className="w-full text-xs">
            <thead className="text-left text-mute"><tr><th className="pb-1 font-normal">Organisation</th><th className="pb-1 font-normal">Language</th><th className="pb-1 text-right font-normal">Critical</th></tr></thead>
            <tbody>
              {d.orgs.map((o) => (
                <tr key={o.id} onClick={() => onOrg(o.id)} className="cursor-pointer border-t border-line/50 hover:bg-panel-2">
                  <td className="py-1.5 pr-2">
                    <div className="truncate">{o.name}</div>
                    <div className="text-[11px] text-mute">{o.sector} · {o.state}</div>
                  </td>
                  <td className="py-1.5">{langs[o.lang]?.native ?? o.lang}</td>
                  <td className="py-1.5 text-right">
                    <span className="font-mono text-crit">{o.critical}</span>
                    {o.compromise > 0 && <div className="text-[11px] text-fuchsia-300">{o.compromise} compromise</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </div>
  )
}
