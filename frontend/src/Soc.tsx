import { ExternalLink, Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Campaign, type IntelAdvisory, type IntelSource, type Soc as SocData, type Technology, type RiskPlan } from './api'
import { BrandWatch } from './BrandWatch'
import { Heatmap, type HeatData } from './Heatmap'
import { SurfaceScan } from './SurfaceScan'
import { RiskPlanView } from './Orgs'
import { ForecastPanel } from './proactive'
import { Badge, Pill, Prov, Row, Section, Sheet, Tile, useToast } from './ui'

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
      {bands.map(([a, b], i) => <rect key={i} x={x(a)} y={0} width={Math.max(x(b) - x(a), 2)} height={h} fill="var(--color-crit)" opacity={0.14} />)}
      <polyline points={values.map((v, i) => `${x(i)},${y(v)}`).join(' ')} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  )
}


function Technologies({ rows }: { rows: Technology[] }) {
  return (
    <table className="w-full text-sm">
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
        {rows.filter((r) => r.assets_at_risk > 0).map((r) => (
          <tr key={r.label} className="border-t border-line">
            <td className="py-2.5 pr-2">
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
    <table className="w-full text-sm">
      <thead className="text-left text-mute">
        <tr><th className="pb-1 font-normal">Source</th><th className="pb-1 font-normal">Type</th><th className="pb-1 text-right font-normal">Items</th><th className="pb-1 text-right font-normal">Relevant</th><th className="pb-1 pl-2 font-normal">Grade</th></tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.name} className="border-t border-line" title={r.funnel}>
            <td className="py-2.5 pr-2"><div className="flex items-center gap-1.5"><Prov p={r.provenance} /><span>{r.name}</span></div></td>
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

/** Number of separate surges among the outlined heatmap cells (a run of consecutive days on one row is one surge). */
function surgeCount(marks: [number, number][] = []): number {
  const set = new Set(marks.map(([r, c]) => `${r}:${c}`))
  return marks.filter(([r, c]) => !set.has(`${r}:${c - 1}`)).length
}

/** Intel, Uber-simple: one question per tab, one visual, the rest as tiles that open sheets. */
export function Soc({ section, tick }: { section: SocSection; tick: number }) {
  const [d, setD] = useState<SocData>()
  const [sources, setSources] = useState<IntelSource[]>([])
  const [adv, setAdv] = useState<IntelAdvisory[]>([])
  const [tech, setTech] = useState<Technology[]>([])
  const [camps, setCamps] = useState<Campaign[]>([])
  const [heat, setHeat] = useState<Record<string, HeatData>>()
  const [plan, setPlan] = useState<RiskPlan>()
  const [sheet, setSheet] = useState<'tech' | 'forecast' | 'decoy' | 'campaigns' | 'sources' | 'advisories' | 'sitrep' | 'exports'>()
  const [lists, setLists] = useState<{ generated_at: string; how: string; lists: { id: string; title: string; for: string; rows: number }[] }>()
  const [report, setReport] = useState<{ generated_at: string; text: string }>()
  const toast = useToast()
  const openReport = () => {
    setSheet('sitrep')
    setReport(undefined)
    fetch('/api/sitrep').then((r) => r.json()).then(setReport).catch(() => toast('Could not write the report'))
  }
  useEffect(() => { api.soc().then(setD).catch(() => undefined) }, [tick])
  useEffect(() => {
    api.intelSources().then(setSources).catch(() => undefined)
    api.intelAdvisories().then(setAdv).catch(() => undefined)
    api.technologies().then(setTech).catch(() => undefined)
    api.campaigns().then(setCamps).catch(() => undefined)
    api.riskplan().then(setPlan).catch(() => undefined)
    fetch('/api/heatmaps').then((r) => r.json()).then(setHeat).catch(() => undefined)
    fetch('/api/risklists').then((r) => r.json()).then(setLists).catch(() => undefined)
  }, [])
  if (!d) return <div className="py-10 text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />Assembling the threat picture…</div>

  const atRisk = tech.filter((t) => t.critical > 0).sort((a, b) => b.compromised_assets - a.compromised_assets || b.critical - a.critical)
  const close = () => setSheet(undefined)
  const active = camps.filter((c) => c.status === 'ACTIVE').length
  const relevantAdv = adv.filter((a) => a.relevant).length

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-14">
      {section === 'overview' && (
        <>
          <Section title="What is under attack" sub="Technologies we run that have Critical warnings, compromised and most exposed first."
                   action={<Pill onClick={() => setSheet('tech')}>See all {atRisk.length}</Pill>}>
            <div className="grid gap-x-12 xl:grid-cols-2">
              {atRisk.slice(0, 6).map((t) => (
                <Row key={t.label} onClick={() => setSheet('tech')}
                     lead={<span className={`h-3 w-3 rounded-full ${t.compromised_assets ? 'bg-comp' : 'bg-crit'}`} />}
                     title={t.label}
                     sub={`${fmt(t.critical)} Critical at ${t.orgs} organisations · ${t.kev_cves} exploited CVE${t.kev_cves === 1 ? '' : 's'}`}
                     trail={t.compromised_assets ? <span className="font-semibold text-comp">{t.compromised_assets} compromised</span>
                       : t.campaign === 'ACTIVE' ? <span className="rounded-full bg-crit px-2.5 py-0.5 text-xs font-semibold text-white">Active campaign</span> : undefined} />
              ))}
            </div>
          </Section>
          {heat && (
            <Section title="Where the critical exposure is" sub="Critical warnings by technology and sector. Hover a cell for its count.">
              <Heatmap data={heat.exposure} hue="crit" unit="Critical warnings" labelW={230} cellH={24} dateCols={false} />
            </Section>
          )}
          <Section title="Likely to be exploited next" sub="New CVEs on our exposed assets, flagged on the day they are published, before CISA confirms exploitation."
                   action={<Pill onClick={() => setSheet('forecast')}>See all</Pill>}>
            <ForecastPanel limit={4} compact />
          </Section>
          <div className="grid gap-4 md:grid-cols-3">
            <Tile value={new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })} title="National situation report"
                  sub="the CERT's daily report, written from the live state: headline, compromises, clocks, activity, the risk plan" cta="Write it now" onClick={openReport} />
            <Tile value={lists ? lists.lists.reduce((n, l) => n + l.rows, 0).toLocaleString('en-IN') : '…'} title="Risk lists and STIX"
                  sub="scored lists of CVEs, addresses, domains and technologies for a SIEM, firewall or EDR, and the intelligence graph as a STIX 2.1 bundle" cta="Export" onClick={() => setSheet('exports')} />
          </div>
        </>
      )}

      {section === 'threats' && (
        <>
          {heat && (
            <Section title="Real attacks on the services we run" action={<Prov p="REAL" label="REAL · SANS ISC DShield" />}
                     sub="Daily attack records from a global honeypot network on the ports our internet-facing products use. Each row runs from its quietest day (light) to its busiest (dark).">
              <Heatmap data={heat.attacks} hue="accent" unit="attack records" labelW={200} />
            </Section>
          )}
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <Tile value={surgeCount(heat?.decoy.marks)} title="Scanning surges on our decoy grid" sub="24 sensors, simulated and labelled SIM" cta="See the grid" onClick={() => setSheet('decoy')} />
            <Tile value={active} title="Active campaigns" sub="exploited CVEs, chained assets and decoy surges, correlated" cta="See campaigns" onClick={() => setSheet('campaigns')} />
            <Tile value={relevantAdv} title="Real advisories that name our products" sub={`of the latest ${adv.length} CISA advisories`} cta="See advisories" onClick={() => setSheet('advisories')} />
            <Tile value={sources.length} title="Intelligence sources" sub={`${sources.filter((x) => x.provenance === 'REAL').length} real public feeds, the rest simulated and labelled`} cta="See sources" onClick={() => setSheet('sources')} />
          </div>
          <BrandWatch />
          <SurfaceScan orgId="PWR-01" defaultUrl="http://127.0.0.1:8080" />
        </>
      )}

      {section === 'risk' && (
        <Section title="The fewest changes that remove the most risk" sub="Urgency first (compromise, then known-exploited), then the most risk removed per unit of effort.">
          {plan ? <RiskPlanView r={plan} limit={10} /> : <div className="text-mute"><Loader2 size={14} className="mr-1 inline animate-spin" />Ranking change tickets…</div>}
        </Section>
      )}

      {sheet === 'tech' && <Sheet wide title="Every technology we run, by exposure" sub="Hover a column heading for what it counts." onClose={close}><Technologies rows={tech} /></Sheet>}
      {sheet === 'forecast' && <Sheet wide title="Likely to be exploited next" sub="Day-0 forecast for every new CVE on our exposed assets." onClose={close}><ForecastPanel limit={40} /></Sheet>}
      {sheet === 'decoy' && heat && (
        <Sheet wide title="National decoy grid" sub="Sessions per product per day across 24 decoy sensors (SIM). Outlined days are surges the detector raised: the Ivanti ones preceded a real CVE, the Confluence one was stood down." onClose={close}>
          <Heatmap data={heat.decoy} hue="accent" unit="sessions" labelW={200} />
        </Sheet>
      )}
      {sheet === 'campaigns' && <Sheet title="Campaigns" sub="Correlated threats: exploited CVEs, chained assets and decoy surges." onClose={close}><Campaigns rows={camps} /></Sheet>}
      {sheet === 'advisories' && <Sheet title="Real advisories that name our products" sub="Latest CISA advisories, matched to the inventory." onClose={close}><Advisories rows={adv} /></Sheet>}
      {sheet === 'sources' && <Sheet wide title="Where the intelligence comes from" sub="Hover a row for its funnel." onClose={close}><Sources rows={sources} /></Sheet>}
      {sheet === 'exports' && (
        <Sheet title="Risk lists and STIX" sub="Machine-readable and scored, with provenance on every row. Pull on a schedule, or stream the same alerts through the channels." onClose={close}>
          {!lists ? <div className="text-mute">Counting the lists…</div> : (
            <div>
              {lists.lists.map((l) => (
                <div key={l.id} className="flex items-center justify-between gap-4 border-t border-line py-3">
                  <div className="min-w-0">
                    <div className="font-medium">{l.title}</div>
                    <div className="text-xs text-mute">{l.rows.toLocaleString('en-IN')} rows · for {l.for}</div>
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <a className="rounded-full bg-panel-2 px-3 py-1.5 text-xs font-semibold hover:bg-panel-3" href={`/api/risklists/${l.id}?format=csv`} download={`odyssey-risklist-${l.id}.csv`}>CSV</a>
                    <a className="rounded-full bg-panel-2 px-3 py-1.5 text-xs font-semibold hover:bg-panel-3" href={`/api/risklists/${l.id}`} target="_blank" rel="noreferrer">JSON</a>
                  </div>
                </div>
              ))}
              <div className="flex items-center justify-between gap-4 border-t border-line py-3">
                <div className="min-w-0">
                  <div className="font-medium">The intelligence graph as a STIX 2.1 bundle</div>
                  <div className="text-xs text-mute">identities, vulnerabilities, software, campaigns, attack patterns, malware, intrusion sets (overlap, not attribution), indicators, sightings, relationships</div>
                </div>
                <a className="shrink-0 rounded-full bg-action px-4 py-1.5 text-xs font-semibold text-ink hover:opacity-85" href="/api/graph/stix" download="odyssey-graph.stix.json">Download</a>
              </div>
              <p className="pt-3 text-xs text-mute">{lists.how}</p>
            </div>
          )}
        </Sheet>
      )}
      {sheet === 'sitrep' && (
        <Sheet wide title="National cyber threat situation report" sub="Markdown, ready for CERT-In, NCIIPC and the sector CSIRTs. Every figure is on a screen here." onClose={close}>
          {!report ? <div className="text-mute"><Loader2 size={14} className="mr-1 inline animate-spin" />Writing the report from the live state…</div> : (
            <>
              <div className="mb-4 flex flex-wrap gap-2">
                <button onClick={() => { navigator.clipboard?.writeText(report.text); toast('Report copied') }} className="rounded-full bg-action px-5 py-2.5 text-sm font-semibold text-ink hover:opacity-85">Copy</button>
                <button onClick={() => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([report.text], { type: 'text/markdown' })); a.download = `odyssey-sitrep-${report.generated_at.slice(0, 10)}.md`; a.click() }}
                        className="rounded-full bg-panel-2 px-5 py-2.5 text-sm font-semibold hover:bg-panel-3">Download .md</button>
              </div>
              <pre className="whitespace-pre-wrap rounded-2xl bg-panel-2 p-6 font-sans text-[15px] leading-relaxed">{report.text}</pre>
            </>
          )}
        </Sheet>
      )}
    </div>
  )
}
