import { Globe, Loader2, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type OrgProfile, type RiskPlan, type Soc } from './api'
import { AutopilotFeed, useLanguages } from './proactive'
import { Heatmap, type HeatData } from './Heatmap'
import { OrgThreatMap } from './OrgThreatMap'
import { Spark } from './Soc'
import { Badge, deadlineText, Pill, Prov, Row, Section, Stat, Tabs, TIER_FILL, TierPill } from './ui'

const WORST = ['—', 'Medium', 'High', 'Critical', 'Compromise'] as const
interface SupplierRow { id: string; name: string; service: string; labels: string[]; critical_cves: number }

export function RiskPlanView({ r, compact, limit }: { r: RiskPlan; compact?: boolean; limit?: number }) {
  return (
    <div>
      <p className="mb-3 text-mute">
        {r.tickets} change tickets cover {r.assets_at_risk} assets at risk. <b className="text-text">{r.for_50_pct ?? '—'}</b> changes remove half
        of the risk; <b className="text-text">{r.for_80_pct ?? '—'}</b> remove 80%.
      </p>
      {!compact && (
        <div className="mb-3 h-36">
          <ResponsiveContainer>
            <LineChart data={r.curve} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid stroke="var(--color-line)" strokeDasharray="2 4" vertical={false} />
              <XAxis dataKey="k" minTickGap={56} tickLine={false} tick={{ fill: 'var(--color-faint)', fontSize: 11 }} />
              <YAxis domain={[0, 100]} ticks={[0, 50, 80, 100]} tickLine={false} axisLine={false} tick={{ fill: 'var(--color-faint)', fontSize: 11 }} tickFormatter={(v: number) => `${v}%`} />
              <Tooltip contentStyle={{ background: 'var(--color-panel)', border: '1px solid var(--color-line)', borderRadius: 12, fontSize: 12 }} formatter={(v) => [`${v}% of risk removed`, '']} labelFormatter={(k) => `after ${k} change(s)`} />
              <ReferenceLine y={50} stroke="var(--color-mute)" strokeDasharray="3 3" />
              <ReferenceLine y={80} stroke="var(--color-mute)" strokeDasharray="3 3" />
              <Line type="monotone" dataKey="cum_pct" stroke="var(--color-ok)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
      <ol>
        {r.plan.slice(0, limit ?? (compact ? 5 : 8)).map((t) => (
          <li key={t.rank} className="flex items-center gap-4 border-b border-line py-3 last:border-0">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm font-bold text-white" style={{ background: TIER_FILL[t.top_tier] }}>{t.rank}</span>
            <div className="min-w-0 flex-1">
              <div className="truncate font-medium">
                Upgrade {t.label} {t.version}{t.target_version ? <> to <span className="font-mono text-sm">{t.target_version}</span></> : ' (vendor advisory)'}
              </div>
              <div className="truncate text-sm text-mute">
                {r.scope === 'national' && <>{t.org_id} · </>}{t.n_assets} host{t.n_assets === 1 ? '' : 's'} · {t.n_cves} CVE{t.n_cves === 1 ? '' : 's'}
                {t.kev_cves > 0 && <span className="text-crit"> ({t.kev_cves} exploited)</span>} · {t.owners[0]}
              </div>
            </div>
            <div className="w-28 shrink-0 text-right">
              <div className="font-semibold tabular-nums">−{t.pct.toFixed(1)}%</div>
              <div className="text-xs text-mute">due {deadlineText(t.deadline_hours)}</div>
            </div>
          </li>
        ))}
      </ol>
    </div>
  )
}

function OrgInbox({ orgId }: { orgId: string }) {
  const [heat, setHeat] = useState<HeatData>()
  useEffect(() => { fetch(`/api/heatmaps?org_id=${orgId}`).then((r) => r.json()).then((h) => setHeat(h.autopilot)).catch(() => undefined) }, [orgId])
  return (
    <>
      {heat && (
        <Section title="What Odyssey sent, day by day" sub="Notices, digests, advisories and warnings for this organisation since go-live.">
          <Heatmap data={heat} hue="accent" unit="messages" labelW={180} />
        </Section>
      )}
      <Section title="Inbox" sub="Simulated delivery, in the organisation's own language.">
        <AutopilotFeed orgId={orgId} limit={120} height="max-h-[60vh]" />
      </Section>
    </>
  )
}

function Profile({ p, onAlert, onGraph }: { p: OrgProfile; onAlert: (orgId: string, cveId: string) => void; onGraph?: (orgId: string) => void }) {
  const langs = useLanguages()
  const lang = langs[p.language]
  const imp = p.impersonation
  const [tab, setTab] = useState<'overview' | 'risk' | 'osint' | 'inbox'>('overview')
  const [all, setAll] = useState(false)
  const found = [...imp.found, ...imp.brand_hits]
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-12">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-4xl font-bold tracking-tight">{p.org.name}</h2>
          {!!p.org.cii && <Badge>Critical Information Infrastructure</Badge>}
        </div>
        <p className="mt-2 text-lg text-mute">
          {p.org.sector} · {p.org.state} · warned in {lang ? `${lang.native} (${lang.name})` : p.language} · sector CSIRT {p.csirt}
        </p>
        <div className="mt-6"><Tabs value={tab} onChange={setTab} items={[['overview', 'Overview'], ['risk', 'Risk plan'], ['osint', 'What outsiders see'], ['inbox', 'Inbox']]} /></div>
      </div>

      {tab === 'overview' && (
        <>
          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            {[
              { v: `${p.surface.internet + p.surface.dmz}`, l: 'internet-facing services', s: `${p.surface.assets} assets in inventory` },
              { v: `${(p.tiers.Compromise ?? 0) + (p.tiers.Critical ?? 0)}`, l: 'Critical warnings', s: p.tiers.Compromise ? `${p.tiers.Compromise} suspected compromise` : `${p.tiers.High ?? 0} High` },
              { v: `${p.risk.for_80_pct ?? '—'}`, l: 'changes remove 80% of risk', s: `of ${p.risk.tickets} tickets` },
              { v: `${p.inbox.length}`, l: 'notices from Odyssey', s: lang ? `in ${lang.native}` : undefined },
            ].map((k) => <Stat key={k.l} value={k.v} label={k.l} sub={k.s} />)}
          </div>
          <Section title="Threat map" sub="What is recorded against this organisation, from the outside world through its internet-facing services to its crown jewels. A subset of the national picture; every line carries its source."
                   action={onGraph ? <Pill onClick={() => onGraph(p.org.id)}>Open in the intelligence graph</Pill> : undefined}>
            <OrgThreatMap orgId={p.org.id} onAlert={onAlert} />
          </Section>
          <div className="grid gap-12 xl:grid-cols-2">
            <Section title="Open warnings" sub="Highest risk first." action={p.alerts.length > 6 ? <Pill onClick={() => setAll(!all)}>{all ? 'Show fewer' : `See all ${p.alerts.length}`}</Pill> : undefined}>
              {p.alerts.slice(0, all ? undefined : 6).map((a) => (
                <Row key={a.id} onClick={() => onAlert(a.org_id, a.cve_id)}
                     lead={<span className="h-3 w-3 rounded-full" style={{ background: TIER_FILL[a.tier] }} />}
                     title={<span className="font-mono text-sm">{a.cve_id}</span>} sub={a.title}
                     trail={<span className="text-mute">due {deadlineText(a.deadline_hours)}</span>} />
              ))}
            </Section>
            <Section title="Fix first" sub="The changes that remove the most risk."><RiskPlanView r={p.risk} compact /></Section>
          </div>
        </>
      )}
      {tab === 'risk' && <Section title="Risk plan: what to fix, in order"><RiskPlanView r={p.risk} /></Section>}
      {tab === 'inbox' && <OrgInbox orgId={p.org.id} />}

      {tab === 'osint' && (
        <div className="grid gap-12 xl:grid-cols-2">
          <Section title="Services anyone can reach" sub="From the inventory: internet- and DMZ-facing hosts, worst warning first." action={<Globe size={18} className="text-mute" />}>
            {p.surface.exposed.slice(0, 10).map((a) => (
              <Row key={a.hostname} lead={<span className="text-[10px] font-bold uppercase">{a.zone.slice(0, 3)}</span>}
                   title={<span className="font-mono text-sm">{a.hostname}</span>} sub={`${a.product} ${a.version} · port ${a.ports.join(', ')}`}
                   trail={a.worst ? <TierPill tier={WORST[a.worst] as 'Medium'} /> : <span className="text-mute">—</span>} />
            ))}
          </Section>
          <div className="flex flex-col gap-12">
            <Section title="Is anyone impersonating it?" sub="Live threat feeds, checked for this organisation.">
              <Row lead={<ShieldCheck size={18} className={p.indicators.c2_sightings.length ? 'text-crit' : 'text-ok'} />}
                   title={p.indicators.c2_sightings.length ? `${p.indicators.c2_sightings.length} host beaconing to known C2` : 'No known C2 in its traffic'}
                   sub={p.indicators.c2_sightings.length ? p.indicators.c2_sightings.map((x) => `${x.asset} → ${x.c2} (${x.malware})`).join(' · ') : `checked against ${p.indicators.feodo_c2} live Feodo Tracker C2 addresses`} />
              <Row lead={<ShieldCheck size={18} className={found.length ? 'text-crit' : 'text-ok'} />}
                   title={found.length ? `${found.length} look-alike domain${found.length > 1 ? 's' : ''} in phishing feeds` : 'No look-alike domains in phishing feeds'}
                   sub={found.length ? found.join(', ') : `${imp.variants_checked} variants of ${imp.domain} vs ${imp.phishing_hosts_scanned} live phishing hosts`} />
              <Row lead={<ShieldCheck size={18} className={p.indicators.own_ips_in_dshield_top.length + p.indicators.own_ips_on_feodo.length ? 'text-crit' : 'text-ok'} />}
                   title={`${p.indicators.own_ips_in_dshield_top.length + p.indicators.own_ips_on_feodo.length} of its IPs on attacker lists`}
                   sub={`DShield top ${p.indicators.dshield_sources} sources and Feodo Tracker`} />
            </Section>
            {((p as unknown as { suppliers?: SupplierRow[] }).suppliers ?? []).length > 0 && (
              <Section title="Its suppliers" sub="Providers whose systems it depends on. An advisory on what they run reaches it even where it does not run that software itself."
                       action={<Prov p="SIM" label="SIM supplier graph" />}>
                {((p as unknown as { suppliers?: SupplierRow[] }).suppliers ?? []).map((sp) => (
                  <Row key={sp.id} lead={<span className="text-[10px] font-bold">SUP</span>} title={`${sp.name} · ${sp.service}`}
                       sub={`runs ${sp.labels.join(', ')}`}
                       trail={sp.critical_cves ? <span className="font-semibold text-crit">{sp.critical_cves} Critical CVEs</span> : <span className="text-mute">none Critical</span>} />
                ))}
              </Section>
            )}
            <Section title="Attacks on these services worldwide" action={<Prov p="REAL" label="REAL · DShield" />}>
              <div className="grid grid-cols-2 gap-3">
                {p.attack_activity.slice(0, 4).map((t) => (
                  <div key={t.port} className="rounded-2xl bg-panel-2 p-3">
                    <div className="flex items-baseline justify-between text-sm">
                      <span className="font-medium">{t.service} <span className="text-mute">:{t.port}</span></span>
                      <span className={t.elevated ? 'font-semibold text-crit' : 'text-mute'}>{t.ratio >= 1 ? '+' : ''}{Math.round((t.ratio - 1) * 100)}%</span>
                    </div>
                    <Spark values={t.series.map((x) => x.records)} color={t.elevated ? 'var(--color-crit)' : 'var(--color-accent)'} />
                  </div>
                ))}
              </div>
              <p className="mt-2 text-sm text-mute">Last 7 days against the 28-day median.</p>
            </Section>
            {p.advisories.length > 0 && (
              <Section title="Real advisories naming its products">
                {p.advisories.map((a) => <Row key={a.link} onClick={() => window.open(a.link, '_blank', 'noreferrer')} title={a.title} sub={a.published} />)}
              </Section>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export function Orgs({ selected, onSelect, onAlert, onGraph }: { selected?: string; onSelect: (id: string) => void; onAlert: (orgId: string, cveId: string) => void; onGraph?: (orgId: string) => void }) {
  const [list, setList] = useState<Soc['orgs']>([])
  const [p, setP] = useState<OrgProfile>()
  const langs = useLanguages()
  useEffect(() => { api.soc().then((s) => setList(s.orgs)).catch(() => undefined) }, [])
  const id = selected ?? list[0]?.id
  useEffect(() => {
    if (!id) return
    setP(undefined)
    api.orgProfile(id).then(setP).catch(() => undefined)
  }, [id])
  return (
    <>
      <aside className="sticky top-24 flex max-h-[calc(100vh-7rem)] w-80 shrink-0 flex-col gap-1 self-start overflow-auto pr-1">
        <div className="mb-2 text-xl font-bold">{list.length} organisations</div>
        {list.map((o) => (
          <button key={o.id} onClick={() => onSelect(o.id)}
                  className={`flex items-center gap-3 rounded-2xl px-3 py-2.5 text-left ${o.id === id ? 'bg-panel-2' : 'hover:bg-panel-2/60'}`}>
            <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-xs font-bold ${o.compromise ? 'bg-comp text-white' : 'bg-panel-2 text-text'}`}>
              {o.name.split(' ').filter((w) => /^[A-Z]/.test(w)).slice(0, 2).map((w) => w[0]).join('')}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-semibold">{o.name}</span>
              <span className="block truncate text-xs text-mute">{o.sector} · {langs[o.lang]?.native ?? o.lang}</span>
            </span>
            <span className="text-right"><span className="block text-sm font-bold text-crit">{o.critical}</span><span className="block text-[10px] text-mute">critical</span></span>
          </button>
        ))}
      </aside>
      {p ? <Profile p={p} onAlert={onAlert} onGraph={onGraph} /> : <div className="p-8 text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />Building the organisation profile…</div>}
    </>
  )
}
