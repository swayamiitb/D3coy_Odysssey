import { Globe, Loader2, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type OrgProfile, type RiskPlan, type Soc } from './api'
import { AutopilotFeed, useLanguages } from './proactive'
import { Spark } from './Soc'
import { Badge, deadlineText, Panel, Prov, Tabs, TIER_FILL, TierPill } from './ui'

const WORST = ['—', 'Medium', 'High', 'Critical', 'Compromise'] as const

export function RiskPlanView({ r, compact, limit }: { r: RiskPlan; compact?: boolean; limit?: number }) {
  return (
    <div>
      <p className="mb-2 text-xs text-mute">
        {r.tickets} change tickets cover {r.assets_at_risk} assets at risk. Fix in this order: <b className="text-text">{r.for_50_pct ?? '—'}</b> changes remove half
        of the risk, <b className="text-text">{r.for_80_pct ?? '—'}</b> remove 80%. Urgency first (compromise, then known-exploited), then most risk per unit of effort.
      </p>
      {!compact && (
        <div className="mb-3 h-36">
          <ResponsiveContainer>
            <LineChart data={r.curve} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid stroke="var(--color-line)" strokeDasharray="2 4" vertical={false} />
              <XAxis dataKey="k" tick={{ fill: 'var(--color-mute)', fontSize: 11 }} label={{ value: 'changes made', fill: 'var(--color-mute)', fontSize: 11, position: 'insideBottomRight', offset: -2 }} />
              <YAxis domain={[0, 100]} tick={{ fill: 'var(--color-mute)', fontSize: 11 }} tickFormatter={(v: number) => `${v}%`} />
              <Tooltip contentStyle={{ background: 'var(--color-panel)', border: '1px solid #243041', fontSize: 12 }} formatter={(v) => [`${v}% of risk removed`, '']} labelFormatter={(k) => `after ${k} change(s)`} />
              <ReferenceLine y={50} stroke="var(--color-mute)" strokeDasharray="3 3" />
              <ReferenceLine y={80} stroke="var(--color-mute)" strokeDasharray="3 3" />
              <Line type="monotone" dataKey="cum_pct" stroke="var(--color-ok)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
      <ol className="space-y-1.5">
        {r.plan.slice(0, limit ?? (compact ? 5 : 8)).map((t) => (
          <li key={t.rank} className="flex items-center gap-3 rounded-lg bg-panel-2 px-3 py-2">
            <span className="w-5 shrink-0 text-right font-mono text-xs text-mute">{t.rank}</span>
            <span className="h-8 w-1 shrink-0 rounded" style={{ background: TIER_FILL[t.top_tier] }} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm">
                Upgrade {t.label} {t.version}{t.target_version ? <> → <span className="font-mono text-text">{t.target_version}</span></> : ' (vendor advisory)'}
              </div>
              <div className="truncate text-[11px] text-mute">
                {r.scope === 'national' && <>{t.org_id} · </>}{t.n_assets} host{t.n_assets === 1 ? '' : 's'} · {t.n_cves} CVE{t.n_cves === 1 ? '' : 's'}
                {t.kev_cves > 0 && <span className="text-crit"> ({t.kev_cves} known-exploited)</span>} · owner {t.owners[0]}
              </div>
            </div>
            <div className="w-24 shrink-0 text-right text-xs">
              <div className="font-mono">−{t.pct.toFixed(1)}%</div>
              <div className="text-mute">due {deadlineText(t.deadline_hours)}</div>
            </div>
          </li>
        ))}
      </ol>
    </div>
  )
}

function Profile({ p, onAlert }: { p: OrgProfile; onAlert: (orgId: string, cveId: string) => void }) {
  const langs = useLanguages()
  const lang = langs[p.language]
  const imp = p.impersonation
  const [tab, setTab] = useState<'overview' | 'risk' | 'osint' | 'inbox'>('overview')
  const warnings = (
    <Panel title="Open warnings">
      <ol className="space-y-1.5">
        {p.alerts.map((a) => (
          <li key={a.id}>
            <button onClick={() => onAlert(a.org_id, a.cve_id)} className="flex w-full items-center gap-3 rounded-lg bg-panel-2 px-3 py-2 text-left hover:ring-1 hover:ring-accent/40">
              <TierPill tier={a.tier} />
              <span className="font-mono text-sm">{a.cve_id}</span>
              <span className="min-w-0 flex-1 truncate text-xs text-mute">{a.title}</span>
              <span className="text-xs text-mute">due {deadlineText(a.deadline_hours)}</span>
            </button>
          </li>
        ))}
      </ol>
    </Panel>
  )
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 overflow-auto [&>*]:shrink-0">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-3xl font-semibold">{p.org.name}</h2>
            {!!p.org.cii && <Badge>Critical Information Infrastructure</Badge>}
          </div>
          <p className="text-sm text-mute">
            {p.org.sector} · {p.org.state} · <span className="font-mono">{p.org.domain}</span> · alerts in {lang ? `${lang.native} (${lang.name})` : p.language} ·
            sector CSIRT {p.csirt}
          </p>
        </div>
        <Tabs value={tab} onChange={setTab} items={[['overview', 'Overview'], ['risk', 'Risk plan'], ['osint', 'OSINT'], ['inbox', 'Inbox']]} />
      </div>

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        {[
          { v: `${p.surface.internet + p.surface.dmz}`, l: 'internet/DMZ-facing services', s: `${p.surface.assets} assets in inventory` },
          { v: `${(p.tiers.Compromise ?? 0) + (p.tiers.Critical ?? 0)}`, l: 'Critical warnings', s: p.tiers.Compromise ? `${p.tiers.Compromise} suspected compromise` : `${p.tiers.High ?? 0} High` },
          { v: `${p.risk.for_80_pct ?? '—'}`, l: 'changes to remove 80% of risk', s: `of ${p.risk.tickets} tickets` },
          { v: `${p.inbox.length}`, l: 'notices from Odyssey', s: lang ? `delivered in ${lang.native}` : undefined },
        ].map((k) => (
          <div key={k.l} className="rounded-xl border border-line bg-panel px-4 py-3">
            <div className="text-3xl font-semibold tabular-nums">{k.v}</div>
            <div className="text-sm">{k.l}</div>
            {k.s && <div className="text-xs text-mute">{k.s}</div>}
          </div>
        ))}
      </div>

      {tab === 'overview' && (
        <div className="grid gap-4 xl:grid-cols-2">
          {warnings}
          <Panel title="Fix first"><RiskPlanView r={p.risk} compact /></Panel>
        </div>
      )}
      {tab === 'risk' && <Panel title="Risk plan: what to fix, in order"><RiskPlanView r={p.risk} /></Panel>}
      {tab === 'inbox' && (
        <Panel title="Inbox: what Odyssey sent, unprompted" right={<span className="text-xs text-mute">simulated delivery</span>}>
          <AutopilotFeed orgId={p.org.id} limit={120} height="max-h-[60vh]" />
        </Panel>
      )}

      {tab === 'osint' && <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="OSINT: what an outsider sees" right={<Globe size={14} className="text-mute" />}>
          <table className="w-full text-xs">
            <thead className="text-left text-mute"><tr><th className="pb-1 font-normal">Service</th><th className="pb-1 font-normal">Zone</th><th className="pb-1 text-right font-normal">Worst</th></tr></thead>
            <tbody>
              {p.surface.exposed.slice(0, 12).map((a) => (
                <tr key={a.hostname} className="border-t border-line/50">
                  <td className="py-1.5 pr-2"><div className="truncate font-mono">{a.hostname}</div><div className="truncate text-[11px] text-mute">{a.product} {a.version} · :{a.ports.join(', :')}</div></td>
                  <td className="py-1.5 text-mute">{a.zone}</td>
                  <td className="py-1.5 text-right">{a.worst ? <TierPill tier={WORST[a.worst] as 'Medium'} /> : <span className="text-mute">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Attacks on these services worldwide" right={<Prov p="REAL" label="REAL · DShield" />}>
          <div className="space-y-2">
            {p.attack_activity.map((t) => (
              <div key={t.port} className="rounded-lg bg-panel-2 p-2">
                <div className="flex items-baseline justify-between text-xs">
                  <span>{t.service} <span className="text-mute">:{t.port}</span></span>
                  <span className={t.elevated ? 'text-crit' : 'text-mute'}>{t.ratio >= 1 ? '+' : ''}{Math.round((t.ratio - 1) * 100)}% vs 28-day median</span>
                </div>
                <Spark values={t.series.map((s) => s.records)} color={t.elevated ? 'var(--color-crit)' : 'var(--color-accent)'} />
                <div className="truncate text-[10px] text-mute">{t.hosts?.length} of this organisation's hosts listen here</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Indicators, impersonation, advisories">
          <div className="space-y-3 text-xs">
            <div>
              <div className="mb-1 font-semibold text-mute">Known C2 in this organisation's traffic</div>
              {p.indicators.c2_sightings.length ? p.indicators.c2_sightings.map((s) => (
                <div key={s.ts} className="text-crit">{s.asset}: beacons to {s.c2} ({s.malware}, Feodo Tracker) since {s.ts.slice(0, 16).replace('T', ' ')}</div>
              )) : <div className="text-ok"><ShieldCheck size={12} className="mr-1 inline" />none: checked against {p.indicators.feodo_c2} live Feodo C2 addresses</div>}
              <div className="text-mute">Own IPs on attacker lists: {p.indicators.own_ips_in_dshield_top.length + p.indicators.own_ips_on_feodo.length} (DShield top {p.indicators.dshield_sources} sources, Feodo)</div>
            </div>
            <div>
              <div className="mb-1 font-semibold text-mute">Look-alike domains in live phishing feeds</div>
              {imp.found.length || imp.brand_hits.length
                ? <div className="text-crit">{[...imp.found, ...imp.brand_hits].join(', ')}</div>
                : <div className="text-ok"><ShieldCheck size={12} className="mr-1 inline" />none: {imp.variants_checked} variants of {imp.domain} vs {imp.phishing_hosts_scanned} live phishing hosts</div>}
            </div>
            <div>
              <div className="mb-1 font-semibold text-mute">Real advisories naming its products</div>
              {p.advisories.length ? p.advisories.map((a) => (
                <a key={a.link} href={a.link} target="_blank" rel="noreferrer" className="block truncate text-accent hover:underline">{a.published} · {a.title}</a>
              )) : <div className="text-mute">none in the latest CISA advisories</div>}
            </div>
          </div>
        </Panel>
      </div>}
    </div>
  )
}

export function Orgs({ selected, onSelect, onAlert }: { selected?: string; onSelect: (id: string) => void; onAlert: (orgId: string, cveId: string) => void }) {
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
      <aside className="flex w-72 shrink-0 flex-col gap-1 overflow-auto">
        <div className="mb-1 text-xs uppercase tracking-wider text-mute">Organisations · {list.length}</div>
        {list.map((o) => (
          <button key={o.id} onClick={() => onSelect(o.id)}
                  className={`rounded-xl border px-3 py-2 text-left ${o.id === id ? 'border-accent/60 bg-accent/10' : 'border-line bg-panel hover:bg-panel-2'}`}>
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-sm">{o.name}</span>
              <span className="font-mono text-xs text-crit">{o.critical}</span>
            </div>
            <div className="truncate text-[11px] text-mute">
              {o.sector} · {langs[o.lang]?.native ?? o.lang}{o.compromise > 0 && <span className="text-comp"> · compromise</span>}
            </div>
          </button>
        ))}
      </aside>
      {p ? <Profile p={p} onAlert={onAlert} /> : <div className="p-8 text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />Building the organisation profile…</div>}
    </>
  )
}
