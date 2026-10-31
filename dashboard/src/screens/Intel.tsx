import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import { api, useLoad } from '../data'
import { change, date, num } from '../format'
import type { Attacks, Campaign, IntelAdvisory, IntelSource, PortTrend, Technology } from '../types'
import { Bars, Empty, ErrorLine, Kpis, Mark, Panel, ShowAll, Spark } from '../ui'

export const CAMPAIGN: Record<Campaign['status'], { word: string; color: string }> = {
  ACTIVE: { word: 'Active', color: 'var(--color-critical)' },
  EMERGING: { word: 'Emerging', color: 'var(--color-high)' },
  DORMANT: { word: 'Dormant', color: 'var(--color-watch)' },
}

/** Decoy-grid sensor tags → product names (falls back to the inventory's labels, then the tag). */
const DECOY_PRODUCT: Record<string, string> = {
  ivanti_cs: 'Ivanti Connect Secure', fortios: 'Fortinet FortiOS', confluence: 'Atlassian Confluence', panos: 'Palo Alto PAN-OS',
}

const ADVISORY_KIND: Record<IntelAdvisory['kind'], string> = { ics: 'ICS advisory', kev: 'KEV alert', other: 'Alert' }

const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`
const dayMonth = (iso: string) => new Date(iso).toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata', day: 'numeric', month: 'short' })

/** Elevated = the last 7 days average at least 1.5× the 28-day median (the backend's rule); the word always says which. */
export function TrendWord({ t }: { t: Pick<PortTrend, 'elevated'> }) {
  return t.elevated ? <Mark color="var(--color-critical)">Elevated</Mark> : <span className="text-mute">Normal</span>
}

export function trendSentence(trends: PortTrend[]): string {
  const up = trends.filter((t) => t.elevated)
  if (trends.length === 0) return 'No attack history is available for these ports.'
  if (up.length === 0) return `None of the ${num(trends.length)} ports is elevated this week: every one is below 1.5× its 28-day median.`
  return `${num(up.length)} of ${num(trends.length)} ports ${up.length === 1 ? 'is' : 'are'} elevated this week (at least 1.5× the 28-day median): ${up.map((t) => t.service).join(', ')}.`
}

function PortCard({ t }: { t: PortTrend }) {
  return (
    <div className="min-w-0 rounded-md bg-raised/60 px-3 py-2.5">
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate text-[13px]">{t.service}</span>
        <span className="num text-[12px] text-faint">:{t.port}</span>
      </div>
      <div className="my-1.5"><Spark values={t.series.map((s) => s.records)} color={t.elevated ? 'var(--color-critical)' : 'var(--color-mute)'} label={`${t.service} attack records per day`} /></div>
      <div className="flex items-baseline justify-between gap-2 text-[13px]">
        <TrendWord t={t} />
        <span className="num">{change(t.ratio)}</span>
      </div>
      <div className="num text-[12px] text-faint">{num(t.last7_mean)} a day vs {num(t.baseline_median)}</div>
    </div>
  )
}

function Telemetry({ a, products }: { a: Attacks; products: Record<string, string> }) {
  const trends = a.dshield.trends
  const dates = [...new Set(a.decoy.daily.map((r) => r.date))].sort()
  const tags = [...new Set(a.decoy.daily.map((r) => r.tag))]
  return (
    <div className="space-y-5">
      <div>
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h3 className="text-[14px] font-medium">Global honeypot attacks on the ports our services listen on</h3>
          <span className="text-[12px] text-faint">Real · SANS ISC DShield</span>
        </div>
        <p className="mt-0.5 text-[13px] text-mute">Attack records a day; last 7 days against the 28-day median. {trendSentence(trends)}</p>
        {trends.length === 0 ? <Empty>No port history in this data.</Empty> : (
          <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
            {trends.map((t) => <PortCard key={t.port} t={t} />)}
          </div>
        )}
      </div>
      <div>
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h3 className="text-[14px] font-medium">National decoy grid: scanning surges</h3>
          <span className="text-[12px] text-faint">Simulated</span>
        </div>
        <p className="mt-0.5 text-[13px] text-mute">Sessions a day on decoys posing as each product. Shaded: a detected surge. This telemetry is simulated for the demo.</p>
        {tags.length === 0 ? <Empty>No decoy telemetry in this data.</Empty> : (
          <div className="mt-3 grid grid-cols-2 gap-2 xl:grid-cols-4">
            {tags.map((tag) => {
              const series = dates.map((d) => a.decoy.daily.filter((r) => r.date === d && r.tag === tag).reduce((s, r) => s + r.sessions, 0))
              const surges = a.decoy.surges.filter((s) => s.tag === tag)
              const bands = surges.map((s) => [dates.indexOf(s.first), dates.indexOf(s.last)] as [number, number]).filter(([x, y]) => x >= 0 && y >= 0)
              return (
                <div key={tag} className="min-w-0 rounded-md bg-raised/60 px-3 py-2.5">
                  <div className="truncate text-[13px]">{products[tag] ?? DECOY_PRODUCT[tag] ?? tag}</div>
                  <div className="my-1.5"><Spark values={series} bands={bands} label={`${tag} decoy sessions per day`} /></div>
                  {surges.length === 0 ? <div className="text-[13px] text-mute">No surge</div> : surges.map((s) => (
                    <div key={s.first} className="text-[13px]">
                      <Mark color="var(--color-high)">Surge</Mark> <span className="num text-mute">{dayMonth(s.first)} – {dayMonth(s.last)}</span>
                      <div className="num text-[12px] text-faint">z = {num(s.z_sessions, 1)} · {plural(s.sensors, 'sensor')}</div>
                    </div>
                  ))}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

function Campaigns({ rows }: { rows: Campaign[] }) {
  const [all, setAll] = useState(false)
  return (
    <>
      <ol className="divide-y divide-line/70">
        {(all ? rows : rows.slice(0, 5)).map((c) => (
          <li key={c.id} className="px-5 py-3">
            <div className="flex items-baseline justify-between gap-3">
              <span className="min-w-0 truncate font-medium">{c.title.replace(/^(Exploitation|Reconnaissance) of /, '')}</span>
              <Mark color={CAMPAIGN[c.status].color}>{CAMPAIGN[c.status].word}</Mark>
            </div>
            <div className="text-[13px] text-mute">
              {c.cves.length ? plural(c.cves.length, 'exploited CVE') : 'No exploited CVE yet'} · {plural(c.orgs_exposed.length, 'organisation')} exposed
              {c.sectors_exposed.length > 0 && ` in ${c.sectors_exposed.join(', ')}`}
            </div>
            <div className="text-[13px] text-mute">
              {c.early_warning_days > 0
                ? <>Early warning: first signal <span className="num text-text">{num(c.early_warning_days)} days</span> before disclosure{c.decoy_surges.length ? ' (decoy grid, Simulated)' : ''}</>
                : c.cves.length === 0 && c.decoy_surges.length > 0 ? 'Decoy-grid scanning only (Simulated)' : 'No signal before disclosure'}
              {c.chains.length > 0 && ` · ${plural(c.chains.length, 'chained asset')}`}
            </div>
            {c.cves.length > 0 && <div className="num mt-0.5 truncate text-[12px] text-faint">{c.cves.map((x) => x.cve).join(' · ')}</div>}
          </li>
        ))}
      </ol>
      <div className="px-5 pt-1"><ShowAll total={rows.length} cap={5} open={all} onToggle={() => setAll((v) => !v)} /></div>
    </>
  )
}

function Advisories({ rows }: { rows: IntelAdvisory[] }) {
  const [all, setAll] = useState(false)
  const assets = (a: IntelAdvisory) => a.matches.reduce((s, m) => s + m.assets, 0)
  const relevant = rows.filter((r) => r.relevant).sort((a, b) => assets(b) - assets(a) || (b.published ?? '').localeCompare(a.published ?? ''))
  if (relevant.length === 0) return <div className="px-5"><Empty>None of the {num(rows.length)} latest CISA advisories names our products or CVEs.</Empty></div>
  return (
    <>
      <ol className="divide-y divide-line/70">
        {(all ? relevant : relevant.slice(0, 5)).map((a, i) => (
          <li key={a.link + i} className="px-5 py-3">
            <div className="text-[13px] text-mute">{ADVISORY_KIND[a.kind]} · <span className="num">{date(a.published)}</span></div>
            <a href={a.link} target="_blank" rel="noreferrer" className="font-medium underline-offset-2 hover:underline">
              {a.title} <ExternalLink size={12} className="inline align-baseline text-faint" />
            </a>
            <div className="text-[13px] text-mute">
              {a.matches.length > 0
                ? a.matches.map((m) => `${m.product}: ${plural(m.assets, 'asset')} at ${plural(m.orgs, 'organisation')}`).join(' · ')
                : <>Tracks <span className="num">{a.cves_in_odyssey.join(', ')}</span>, already in Odyssey</>}
            </div>
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap items-baseline justify-between gap-2 px-5 pt-1">
        <p className="text-[13px] text-mute">{num(relevant.length)} of {num(rows.length)} latest CISA advisories touch this constituency; the rest are filtered out.</p>
        <ShowAll total={relevant.length} cap={5} open={all} onToggle={() => setAll((v) => !v)} />
      </div>
    </>
  )
}

function Technologies({ rows }: { rows: Technology[] }) {
  const [all, setAll] = useState(false)
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[960px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">Product</th>
              <th className="pb-2 pl-4 text-right font-normal">Assets</th>
              <th className="pb-2 pl-4 text-right font-normal" title="Assets in the internet or DMZ zone">Internet-facing</th>
              <th className="pb-2 pl-4 text-right font-normal" title="Open warnings, Critical or worse">Critical</th>
              <th className="pb-2 pl-4 text-right font-normal">High</th>
              <th className="pb-2 pl-4 text-right font-normal" title="CVEs on CISA KEV affecting this product here">Exploited CVEs</th>
              <th className="pb-2 pl-4 text-right font-normal" title="CVEs the day-0 forecast flags, not yet exploited">Forecast CVEs</th>
              <th className="pb-2 pl-6 font-normal">Campaign</th>
              <th className="px-5 pb-2 text-right font-normal" title="Global attack records on its service port, last 7 days vs 28-day median (DShield, Real)">Attack trend</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {(all ? rows : rows.slice(0, 8)).map((r) => (
              <tr key={r.label}>
                <td className="px-5 py-2.5">
                  <span className="font-medium">{r.label}</span>
                  {r.compromised_assets > 0 && <span className="ml-2 text-[13px] text-compromise">{plural(r.compromised_assets, 'compromised asset')}</span>}
                  <span className="block text-[13px] text-mute">{plural(r.orgs, 'organisation')}</span>
                </td>
                <td className="num py-2.5 pl-4 text-right">{num(r.assets)}</td>
                <td className="num py-2.5 pl-4 text-right">{num(r.internet_facing)}</td>
                <td className="num py-2.5 pl-4 text-right">{num(r.critical)}</td>
                <td className="num py-2.5 pl-4 text-right">{num(r.high)}</td>
                <td className="num py-2.5 pl-4 text-right">{num(r.kev_cves)}</td>
                <td className="num py-2.5 pl-4 text-right">{num(r.forecast_cves)}</td>
                <td className="py-2.5 pl-6">{r.campaign ? <Mark color={CAMPAIGN[r.campaign].color}>{CAMPAIGN[r.campaign].word}</Mark> : <span className="text-faint">—</span>}</td>
                <td className="px-5 py-2.5 text-right text-[13px]">
                  {r.attack_trend ? (
                    <>
                      <span className="num">{change(r.attack_trend.ratio)}</span> <span className="text-mute">on :{r.attack_trend.port}</span>
                      <span className="block"><TrendWord t={{ elevated: r.attack_trend.ratio >= 1.5 }} /></span>
                    </>
                  ) : <span className="text-faint">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-5 pt-1"><ShowAll total={rows.length} cap={8} open={all} onToggle={() => setAll((v) => !v)} /></div>
    </>
  )
}

function Sources({ rows }: { rows: IntelSource[] }) {
  const [all, setAll] = useState(false)
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1040px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">Source</th>
              <th className="pb-2 font-normal">Data</th>
              <th className="pb-2 font-normal" title="Admiralty source reliability">Grade</th>
              <th className="pb-2 pl-4 text-right font-normal">Items</th>
              <th className="pb-2 pl-4 text-right font-normal">Relevant</th>
              <th className="pb-2 pl-6 font-normal">Funnel: items → relevant</th>
              <th className="px-5 pb-2 text-right font-normal">Updated</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {(all ? rows : rows.slice(0, 8)).map((r) => (
              <tr key={r.name}>
                <td className="px-5 py-2.5"><span className="font-medium">{r.name}</span><span className="block text-[13px] text-mute">{r.kind}</span></td>
                <td className={`py-2.5 ${r.provenance === 'SIM' ? 'text-text' : 'text-mute'}`}>{r.provenance === 'SIM' ? 'Simulated' : 'Real'}</td>
                <td className="py-2.5 text-mute">{r.reliability ?? '—'}</td>
                <td className="num py-2.5 pl-4 text-right">{num(r.items)}</td>
                <td className="num py-2.5 pl-4 text-right">{num(r.relevant)}</td>
                <td className="max-w-[360px] py-2.5 pl-6 text-[13px] text-mute">{r.funnel.replace(/\s*->\s*/g, ' → ')}</td>
                <td className="num px-5 py-2.5 text-right whitespace-nowrap text-mute">{date(r.updated)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-baseline justify-between gap-2 px-5 pt-1">
        <p className="text-[13px] text-mute">Grade is Admiralty source reliability: A completely reliable, B usually reliable, C fairly reliable.</p>
        <ShowAll total={rows.length} cap={8} open={all} onToggle={() => setAll((v) => !v)} />
      </div>
    </>
  )
}

export function Intel() {
  const sources = useLoad(api.intelSources, 'intel:sources')
  const adv = useLoad(api.intelAdvisories, 'intel:advisories')
  const tech = useLoad(api.technologies, 'intel:technologies')
  const atk = useLoad(api.attacks, 'intel:attacks')
  const camps = useLoad(api.campaigns, 'campaigns')

  const s = sources.data
  const nvd = s?.find((r) => r.name.startsWith('NVD'))
  const trends = atk.data?.dshield.trends
  const elevated = trends?.filter((t) => t.elevated).length ?? 0
  const relevantAdv = adv.data?.filter((a) => a.relevant).length
  const products = Object.fromEntries((tech.data ?? []).map((t) => [t.product_key, t.label]))

  return (
    <div className="space-y-4">
      <div className="pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">Threat intel</h1>
        <p className="text-mute">Every source Odyssey reads, what survives each filter, and what is being attacked right now.</p>
      </div>

      <Kpis items={[
        { label: 'Sources aggregated', value: s ? num(s.length) : '—', sub: s ? `${num(s.filter((r) => r.provenance === 'REAL').length)} Real · ${num(s.filter((r) => r.provenance === 'SIM').length)} Simulated` : undefined },
        { label: 'CVEs read this year', value: nvd ? num(nvd.items) : '—', sub: nvd ? `${num(nvd.relevant)} name our products` : 'NVD' },
        { label: 'Active campaigns', value: camps.data ? num(camps.data.filter((c) => c.status === 'ACTIVE').length) : '—', sub: camps.data ? `${num(camps.data.filter((c) => c.status === 'EMERGING').length)} emerging` : undefined },
        { label: 'Products at risk', value: tech.data ? num(tech.data.filter((t) => t.assets_at_risk > 0).length) : '—', sub: tech.data ? `of ${num(tech.data.length)} in the inventory` : undefined },
        { label: 'Elevated attack ports', value: trends ? `${num(elevated)} of ${num(trends.length)}` : '—', tone: elevated > 0 ? 'var(--color-critical)' : undefined, sub: 'DShield, last 7 days' },
        { label: 'Advisories that touch us', value: relevantAdv != null ? num(relevantAdv) : '—', sub: adv.data ? `of ${num(adv.data.length)} latest from CISA` : undefined },
      ]} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Campaigns" meta="Related threats grouped by targeted product, most urgent first" pad={false}>
          {camps.loading ? <div className="px-5"><Bars rows={4} /></div>
            : camps.error ? <div className="px-5"><ErrorLine message={camps.error} onRetry={camps.reload} /></div>
            : (camps.data ?? []).length === 0 ? <div className="px-5"><Empty>No campaigns: no product has recent exploitation or scanning.</Empty></div>
            : <Campaigns rows={camps.data!} />}
        </Panel>
        <Panel title="Real advisories, matched to our inventory" meta="Real · latest CISA advisories, matched by product name" pad={false}>
          {adv.loading ? <div className="px-5"><Bars rows={4} /></div>
            : adv.error ? <div className="px-5"><ErrorLine message={adv.error} onRetry={adv.reload} /></div>
            : <Advisories rows={adv.data ?? []} />}
        </Panel>
      </div>

      <Panel title="Real attack telemetry" meta="What is being attacked this week, next to our own decoy sensors">
        {atk.loading ? <Bars rows={4} h={28} />
          : atk.error ? <ErrorLine message={atk.error} onRetry={atk.reload} />
          : <Telemetry a={atk.data!} products={products} />}
      </Panel>

      <Panel title="Active threats by technology" meta="Each product in the constituency: exposure, open warnings, exploited and forecast CVEs, campaign, attack trend" pad={false}>
        {tech.loading ? <div className="px-5"><Bars rows={6} /></div>
          : tech.error ? <div className="px-5"><ErrorLine message={tech.error} onRetry={tech.reload} /></div>
          : (tech.data ?? []).length === 0 ? <div className="px-5"><Empty>No products in the inventory.</Empty></div>
          : <Technologies rows={tech.data!} />}
      </Panel>

      <Panel title="Threat-intelligence aggregation" meta="Every feed, what it adds, and how much of it matters to this constituency" pad={false}>
        {sources.loading ? <div className="px-5"><Bars rows={6} /></div>
          : sources.error ? <div className="px-5"><ErrorLine message={sources.error} onRetry={sources.reload} /></div>
          : (s ?? []).length === 0 ? <div className="px-5"><Empty>No sources reported.</Empty></div>
          : <Sources rows={s!} />}
      </Panel>
    </div>
  )
}
