import { ExternalLink, Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Campaign, type IntelAdvisory, type IntelSource, type Soc as SocData, type Technology, type RiskPlan } from './api'
import { Heatmap, type HeatData } from './Heatmap'
import { RiskPlanView } from './Orgs'
import { ForecastPanel } from './proactive'
import { Badge, Panel, Prov } from './ui'

const fmt = (n: number | null | undefined) => (n == null ? '—' : n.toLocaleString('en-IN'))


/** Single-series sparkline; optional shaded bands (e.g. detected surges). Text stays in text tokens. */
export function Spark({ values, bands = [], color = 'var(--color-accent)', h = 36, max: top }: { values: number[]; bands?: [number, number][]; color?: string; h?: number; max?: number }) {
  if (values.length < 2) return null
  const w = 160
  const max = top ?? (Math.max(...values) || 1)
  const x = (i: number) => (i / (values.length - 1)) * w
  const y = (v: number) => h - 2 - (v / max) * (h - 4)
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-9 w-full" preserveAspectRatio="none" role="img">
      {bands.map(([a, b], i) => <rect key={i} x={x(a)} y={0} width={Math.max(x(b) - x(a), 2)} height={h} fill="#d946ef" opacity={0.18} />)}
      <polyline points={values.map((v, i) => `${x(i)},${y(v)}`).join(' ')} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
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
              {r.compromised_assets > 0 && <span className="ml-2 text-comp">{r.compromised_assets} compromised</span>}
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
            <td className="py-1.5 pr-2"><div className="flex items-center gap-1.5"><Prov p={r.provenance} /><span>{r.name}</span></div></td>
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

export type SocSection = 'overview' | 'threats' | 'risk'

export function Soc({ section, tick }: { section: SocSection; tick: number }) {
  const [d, setD] = useState<SocData>()
  const [sources, setSources] = useState<IntelSource[]>([])
  const [adv, setAdv] = useState<IntelAdvisory[]>([])
  const [tech, setTech] = useState<Technology[]>([])
  const [camps, setCamps] = useState<Campaign[]>([])
  const [heat, setHeat] = useState<Record<string, HeatData>>()
  const [plan, setPlan] = useState<RiskPlan>()
  useEffect(() => { api.soc().then(setD).catch(() => undefined) }, [tick])
  useEffect(() => {
    api.intelSources().then(setSources).catch(() => undefined)
    api.intelAdvisories().then(setAdv).catch(() => undefined)
    api.technologies().then(setTech).catch(() => undefined)
    api.campaigns().then(setCamps).catch(() => undefined)
    api.riskplan().then(setPlan).catch(() => undefined)
    fetch('/api/heatmaps').then((r) => r.json()).then(setHeat).catch(() => undefined)
  }, [])
  if (!d) return <div className="p-8 text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />Assembling the threat picture…</div>

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-6">
      {section === 'overview' && (
        <>
          {heat && (
            <Panel title="Where the critical exposure is" right={<span className="text-xs text-mute">Critical warnings by technology and sector</span>}>
              <Heatmap data={heat.exposure} hue="crit" unit="Critical warnings" labelW={230} cellH={22} dateCols={false} />
            </Panel>
          )}
          <Panel title="Active threats by technology" right={<span className="text-xs text-mute">what is under attack, and where we run it</span>}>
            <Technologies rows={tech} />
          </Panel>
          <Panel title="Likely to be exploited next · day-0 forecast" right={<span className="text-xs text-mute">new CVEs on exposed assets, before CISA confirms</span>}>
            <ForecastPanel limit={8} />
          </Panel>
        </>
      )}

      {section === 'threats' && (
        <>
          {heat && (
            <Panel title="Real attacks on the services we run" right={<Prov p="REAL" label="REAL · SANS ISC DShield" />}>
              <p className="mb-3 text-sm text-mute">Daily attack records seen by a global honeypot network on the ports our internet-facing products listen on, since go-live. Each row runs from its own quietest day (light) to its busiest (dark).</p>
              <Heatmap data={heat.attacks} hue="accent" unit="attack records" labelW={200} />
            </Panel>
          )}
          {heat && (
            <Panel title="National decoy grid" right={<Prov p="SIM" label="SIM" />}>
              <p className="mb-3 text-sm text-mute">Sessions per product per day across 24 decoy sensors, each row from its own quietest day to its busiest. Outlined days are scanning surges the detector raised: the Ivanti ones preceded a real CVE, the Confluence one was stood down.</p>
              <Heatmap data={heat.decoy} hue="accent" unit="sessions" labelW={200} />
            </Panel>
          )}
          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title="Campaigns · correlated threats" right={<span className="text-xs text-mute">CVEs, chains, decoy surges</span>}>
              <Campaigns rows={camps} />
            </Panel>
            <div className="xl:col-span-2">
              <Panel title="Real advisories, matched to our inventory" right={<Prov p="REAL" label="REAL · CISA" />}>
                <Advisories rows={adv} />
              </Panel>
            </div>
          </div>
          <Panel title="Where the intelligence comes from" right={<span className="text-xs text-mute">hover a row for its funnel</span>}>
            <Sources rows={sources} />
          </Panel>
        </>
      )}

      {section === 'risk' && (
        <Panel title="National risk plan: the fewest changes that remove the most risk" right={<span className="text-xs text-mute">urgency first, then risk removed per unit of effort</span>}>
          {plan ? <RiskPlanView r={plan} limit={15} /> : <div className="text-xs text-mute"><Loader2 size={12} className="mr-1 inline animate-spin" />Ranking change tickets…</div>}
        </Panel>
      )}
    </div>
  )
}
