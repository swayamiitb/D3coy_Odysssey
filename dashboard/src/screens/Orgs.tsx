import { ArrowLeft, ArrowRight, Search } from 'lucide-react'
import { useState } from 'react'
import { api, useLoad } from '../data'
import { change, date, dateTime, eventLabel, hours, num, pct } from '../format'
import type { OrgProfile, Tier } from '../types'
import { Bars, Empty, ErrorLine, Kpis, Mark, Panel, Provenance, ShowAll, Spark, TierMark } from '../ui'
import { TrendWord, trendSentence } from './Intel'
import { LANG } from './Overview'

const WORST: (Tier | null)[] = [null, 'Medium', 'High', 'Critical', 'Compromise']
const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`

export function OrgList() {
  const soc = useLoad(api.soc, 'soc')
  const [q, setQ] = useState('')
  const rows = (soc.data?.orgs ?? []).filter((o) => !q || `${o.name} ${o.sector} ${o.state} ${o.id}`.toLowerCase().includes(q.toLowerCase()))
  return (
    <div className="space-y-4">
      <div className="pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">Organisations</h1>
        <p className="text-mute">Organisation-based OSINT: open one to see what an outsider sees, what attacks its services, and what Odyssey sent it.</p>
      </div>
      <label className="flex h-9 max-w-sm items-center gap-2 rounded-md bg-panel px-2.5 text-mute">
        <Search size={15} />
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Organisation, sector or state"
          className="w-full bg-transparent text-[13px] text-text outline-none placeholder:text-faint" />
      </label>
      <Panel pad={false} title={soc.data ? plural(rows.length, 'organisation') : 'Organisations'} meta="Constituency, worst first">
        {soc.loading ? <div className="px-5"><Bars rows={8} /></div>
          : soc.error ? <div className="px-5"><ErrorLine message={soc.error} onRetry={soc.reload} /></div>
          : rows.length === 0 ? <div className="px-5"><Empty>No organisation matches “{q}”.</Empty></div>
          : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-[14px]">
                <thead>
                  <tr className="text-left text-[12px] text-faint">
                    <th className="px-5 pb-2 font-normal">Organisation</th>
                    <th className="pb-2 font-normal">Sector</th>
                    <th className="pb-2 font-normal">State</th>
                    <th className="pb-2 text-right font-normal">Compromise</th>
                    <th className="pb-2 text-right font-normal">Critical</th>
                    <th className="pb-2 pl-6 font-normal">Alert language</th>
                    <th className="w-10 px-5 pb-2" aria-hidden />
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/70">
                  {rows.map((o) => (
                    <tr key={o.id} className="hover:bg-raised/40">
                      <td className="px-5 py-2.5"><a href={`#/orgs/${o.id}`} className="font-medium hover:underline">{o.name}</a></td>
                      <td className="py-2.5 text-mute">{o.sector}</td>
                      <td className="py-2.5 text-mute">{o.state}</td>
                      <td className="num py-2.5 text-right" style={o.compromise > 0 ? { color: 'var(--color-compromise)' } : undefined}>{num(o.compromise)}</td>
                      <td className="num py-2.5 text-right">{num(o.critical)}</td>
                      <td className="py-2.5 pl-6 text-mute">{LANG[o.lang] ?? o.lang}</td>
                      <td className="px-5 py-2.5 text-right"><a href={`#/orgs/${o.id}`} aria-label={`Open ${o.name}`} className="text-faint hover:text-text"><ArrowRight size={15} /></a></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </Panel>
    </div>
  )
}

function Indicators({ p }: { p: OrgProfile }) {
  const ind = p.indicators
  const imp = p.impersonation
  const ownIps = [...ind.own_ips_on_feodo, ...ind.own_ips_in_dshield_top]
  const lookalikes = [...imp.found, ...imp.brand_hits]
  return (
    <div className="space-y-4 text-[14px]">
      <section>
        <h3 className="text-[13px] text-mute">Known C2 servers in its traffic</h3>
        {ind.c2_sightings.length ? (
          <ul className="mt-1 space-y-1">
            {ind.c2_sightings.map((s) => (
              <li key={s.ts + s.asset}>
                <Mark color="var(--color-compromise)">Beaconing</Mark> <span className="font-medium">{s.asset}</span> to <span className="num">{s.c2}</span>
                <span className="block text-[13px] text-mute">{s.malware}, listed on Feodo Tracker (Real) · seen in firewall logs (Simulated) since {dateTime(s.ts)}</span>
              </li>
            ))}
          </ul>
        ) : <p className="mt-1"><span className="text-ok">None found.</span> <span className="text-mute">Checked against {num(ind.feodo_c2)} live Feodo Tracker C2 addresses.</span></p>}
      </section>
      <section>
        <h3 className="text-[13px] text-mute">Its own IP addresses on attacker lists</h3>
        {ownIps.length ? (
          <p className="mt-1"><Mark color="var(--color-critical)">Listed</Mark> <span className="num">{ownIps.join(', ')}</span></p>
        ) : <p className="mt-1"><span className="text-ok">None.</span> <span className="text-mute">Not on Feodo Tracker, not among the top {num(ind.dshield_sources)} DShield attack sources.</span></p>}
      </section>
      <section>
        <h3 className="text-[13px] text-mute">Look-alike domains in live phishing feeds</h3>
        {lookalikes.length ? (
          <p className="mt-1"><Mark color="var(--color-critical)">Found</Mark> <span className="num">{lookalikes.join(', ')}</span></p>
        ) : <p className="mt-1"><span className="text-ok">None found.</span> <span className="text-mute">{num(imp.variants_checked)} variants of <span className="num">{imp.domain}</span> checked against {num(imp.phishing_hosts_scanned)} live phishing hosts (OpenPhish, Real).</span></p>}
      </section>
    </div>
  )
}

function Profile({ p }: { p: OrgProfile }) {
  const [allSvc, setAllSvc] = useState(false)
  const [allInbox, setAllInbox] = useState(false)
  const t = p.tiers
  const s = p.surface
  const lang = LANG[p.language] ?? p.language
  return (
    <>
      <div className="pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">{p.org.name}</h1>
        <p className="text-mute">
          {p.org.sector} · {p.org.state} · <span className="num">{p.org.domain}</span> · alerts in {lang} · sector CSIRT {p.csirt ?? '—'}
          {p.org.cii ? ' · Critical information infrastructure' : ''}
        </p>
      </div>

      <Kpis items={[
        { label: 'Suspected compromise', value: num(t.Compromise ?? 0), answer: true, tone: (t.Compromise ?? 0) > 0 ? 'var(--color-compromise)' : undefined, sub: 'open, by CVE' },
        { label: 'Critical', value: num(t.Critical ?? 0), sub: 'open, by CVE' },
        { label: 'High', value: num(t.High ?? 0), sub: 'open, by CVE' },
        { label: 'Medium', value: num(t.Medium ?? 0), sub: 'open, by CVE' },
        { label: 'Internet-facing services', value: num(s.internet + s.dmz), sub: `${num(s.internet)} internet · ${num(s.dmz)} DMZ · of ${num(s.assets)} assets` },
        { label: 'Changes for 80% of risk', value: num(p.risk.for_80_pct), sub: `of ${plural(p.risk.tickets, 'ticket')}` },
      ]} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Open warnings" meta="High or worse, worst first" pad={false}>
          {p.alerts.length === 0 ? <div className="px-5"><Empty>No open High or worse warnings.</Empty></div> : (
            <ul className="divide-y divide-line/70">
              {p.alerts.map((a) => (
                <li key={a.id}>
                  <a href={`#/incident/${a.org_id}/${a.cve_id}`} className="grid grid-cols-[110px_1fr_auto] items-center gap-x-4 px-5 py-2.5 hover:bg-raised/60">
                    <TierMark tier={a.tier} />
                    <span className="min-w-0">
                      <span className="block truncate font-medium">{a.title}</span>
                      <span className="num block truncate text-[13px] text-mute">{a.cve_id}{a.kev ? ' · on CISA KEV' : ''}</span>
                    </span>
                    <span className="text-right text-[13px] text-mute">due in <span className="num text-text">{hours(a.deadline_hours)}</span></span>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Threat indicators" meta="C2 traffic, its IPs on attacker lists, look-alike domains">
          <Indicators p={p} />
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Attacks on its services worldwide" meta="Real · SANS ISC DShield, last 7 days vs the 28-day median">
          {p.attack_activity.length === 0 ? <Empty>No attack history for the ports it exposes.</Empty> : (
            <>
              <p className="text-[13px] text-mute">{trendSentence(p.attack_activity)}</p>
              <ul className="mt-2 divide-y divide-line/70">
                {p.attack_activity.map((a) => (
                  <li key={a.port} className="grid grid-cols-[minmax(0,1fr)_96px_auto] items-center gap-4 py-2.5">
                    <span className="min-w-0">
                      <span className="block truncate">{a.service} <span className="num text-faint">:{a.port}</span></span>
                      <span className="block truncate text-[13px] text-mute">{a.hosts?.length ? `${plural(a.hosts.length, 'host')} ${a.hosts.length === 1 ? 'listens' : 'listen'} here: ${a.hosts.join(', ')}` : 'No host listed'}</span>
                    </span>
                    <Spark values={a.series.map((x) => x.records)} color={a.elevated ? 'var(--color-critical)' : 'var(--color-mute)'} h={28} label={`${a.service} attack records per day`} />
                    <span className="text-right text-[13px]"><span className="num block">{change(a.ratio)}</span><TrendWord t={a} /></span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Panel>
        <Panel title="Real advisories naming its products" meta="Real · latest CISA advisories" pad={false}>
          {p.advisories.length === 0 ? <div className="px-5"><Empty>None of the latest CISA advisories names its products.</Empty></div> : (
            <ul className="divide-y divide-line/70">
              {p.advisories.map((a) => (
                <li key={a.link} className="px-5 py-2.5">
                  <a href={a.link} target="_blank" rel="noreferrer" className="font-medium underline-offset-2 hover:underline">{a.title}</a>
                  <span className="block text-[13px] text-mute">{a.kind === 'ics' ? 'ICS advisory' : a.kind === 'kev' ? 'KEV alert' : 'Alert'} · <span className="num">{date(a.published)}</span>{a.cves.length ? <> · <span className="num">{a.cves.slice(0, 3).join(', ')}</span>{a.cves.length > 3 ? ` +${a.cves.length - 3}` : ''}</> : ''}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel title="Internet-facing services" meta="What an outsider can reach: internet and DMZ hosts, worst open warning first" pad={false}
        action={<ShowAll total={s.exposed.length} cap={8} open={allSvc} onToggle={() => setAllSvc((v) => !v)} />}>
        {s.exposed.length === 0 ? <div className="px-5"><Empty>No internet or DMZ hosts in its inventory.</Empty></div> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-[14px]">
              <thead>
                <tr className="text-left text-[12px] text-faint">
                  <th className="px-5 pb-2 font-normal">Host</th>
                  <th className="pb-2 font-normal">Product</th>
                  <th className="pb-2 font-normal">Zone</th>
                  <th className="pb-2 font-normal">Ports</th>
                  <th className="pb-2 text-right font-normal" title="Open warnings, High or worse">Open High+</th>
                  <th className="px-5 pb-2 font-normal">Worst</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {(allSvc ? s.exposed : s.exposed.slice(0, 8)).map((a) => {
                  const w = WORST[a.worst] ?? null
                  return (
                    <tr key={a.hostname}>
                      <td className="num px-5 py-2.5 font-medium">{a.hostname}</td>
                      <td className="py-2.5">{a.product} <span className="num text-mute">{a.version}</span></td>
                      <td className="py-2.5 text-mute">{a.zone === 'dmz' ? 'DMZ' : a.zone.charAt(0).toUpperCase() + a.zone.slice(1)}</td>
                      <td className="num py-2.5 text-mute">{a.ports.length ? a.ports.join(', ') : '—'}</td>
                      <td className="num py-2.5 text-right">{num(a.open_high)}</td>
                      <td className="px-5 py-2.5">{w ? <TierMark tier={w} /> : <span className="text-faint">None open</span>}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Risk plan: what to fix first" meta={p.risk.tickets ? `${plural(p.risk.tickets, 'change ticket')}; ${num(p.risk.for_50_pct)} ${p.risk.for_50_pct === 1 ? 'removes' : 'remove'} half of its risk` : 'No open risk'} pad={false}
          action={<a href={`#/risk/${p.org.id}`} className="text-[13px] text-mute hover:text-text">Full plan</a>}>
          {p.risk.plan.length === 0 ? <div className="px-5"><Empty>Nothing to change: no open warning needs a fix.</Empty></div> : (
            <ol className="divide-y divide-line/70">
              {p.risk.plan.slice(0, 5).map((k) => (
                <li key={k.rank} className="grid grid-cols-[24px_minmax(0,1fr)_auto] gap-3 px-5 py-2.5">
                  <span className="num text-faint">{k.rank}</span>
                  <span className="min-w-0">
                    <span className="block">Upgrade {k.label} <span className="num">{k.version}</span>{k.target_version ? <> → <span className="num">{k.target_version}</span></> : <span className="text-mute"> (no fixed release named; follow the vendor advisory)</span>}</span>
                    <span className="block truncate text-[13px] text-mute">{plural(k.n_assets, 'host')} · {plural(k.n_cves, 'CVE')}{k.kev_cves ? `, ${num(k.kev_cves)} known exploited` : ''} · owner {k.owners.join(', ') || '—'}</span>
                  </span>
                  <span className="text-right text-[13px]">
                    <span className="num block">−{pct(k.pct)}</span>
                    <span className="block text-mute">due in <span className="num">{hours(k.deadline_hours)}</span></span>
                  </span>
                </li>
              ))}
            </ol>
          )}
        </Panel>
        <Panel title="Inbox" meta={`What Odyssey sent it, in ${lang}. Delivery is simulated.`} pad={false}
          action={<ShowAll total={p.inbox.length} cap={6} open={allInbox} onToggle={() => setAllInbox((v) => !v)} />}>
          {p.inbox.length === 0 ? <div className="px-5"><Empty>Odyssey has sent it nothing yet.</Empty></div> : (
            <ul className="divide-y divide-line/70">
              {(allInbox ? p.inbox : p.inbox.slice(0, 6)).map((e) => {
                const title = String(e.payload.title ?? e.payload.summary ?? e.subject)
                const l = e.payload.lang ? LANG[String(e.payload.lang)] ?? String(e.payload.lang) : null
                return (
                  <li key={e.seq} className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 px-5 py-2.5">
                    <span className="min-w-0">
                      <span className="block font-medium">{eventLabel(e.kind)}</span>
                      <span className="block text-[13px] text-mute">{title}</span>
                    </span>
                    <span className="text-right text-[13px]">
                      <span className="num block text-mute">{dateTime(e.ts)}</span>
                      <span className="block">{l && <span className="text-[12px] text-faint">{l} · </span>}<Provenance p={e.provenance} /></span>
                    </span>
                  </li>
                )
              })}
            </ul>
          )}
        </Panel>
      </div>
    </>
  )
}

export function Organisation({ id }: { id: string }) {
  const p = useLoad(() => api.orgProfile(id), `org:${id}`)
  return (
    <div className="space-y-4">
      <a href="#/orgs" className="inline-flex items-center gap-1.5 text-[13px] text-mute hover:text-text"><ArrowLeft size={14} /> Organisations</a>
      {p.loading ? <><Panel><Bars rows={2} h={24} /></Panel><Panel><Bars rows={6} /></Panel></>
        : p.error || !p.data ? <Panel><ErrorLine message={p.error ?? 'no profile'} onRetry={p.reload} /></Panel>
        : <Profile p={p.data} />}
    </div>
  )
}
