import { CheckSquare, FileCheck2, Link2, X } from 'lucide-react'
import { useState } from 'react'
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { AlertDetail as Detail } from './api'
import { AttackPanel } from './AttackPanel'
import { BriefPanel } from './BriefPanel'
import { DecisionPanel } from './DecisionPanel'
import { ExportPanel } from './ExportPanel'
import { RelatedPanel } from './RelatedPanel'
import { ReplayPanel } from './ReplayPanel'
import { Badge, deadlineText, fmtDate, Panel, Prov, Stat, Tabs, TierPill } from './ui'

/* One warning, Uber trip-details style: what it is and how urgent at the top (three figures), then one question per
   tab: what to do (summary), why this score, how it unfolded, what it relates to. */

const CRIT_LABEL = ['', 'context', 'corroborating', 'strong', 'confirmed']
const VERDICT_TONE: Record<string, 'crit' | 'ok' | 'mute'> = { affected: 'crit', not_affected: 'ok', unknown: 'mute' }
type Tab = 'summary' | 'why' | 'history' | 'related'
interface Clock { who: string; what: string; hours: number | null; route?: string }
interface Supplier { id: string; name: string; service: string; only_via_supplier: number; dependents: { org_id: string; name: string; runs_it_too: boolean }[] }

export function AlertDetail({ d, onClose }: { d: Detail; onClose: () => void }) {
  const [assetIdx, setAssetIdx] = useState(0)
  const [tab, setTab] = useState<Tab>('summary')
  const a = d.assets[assetIdx]
  const v = d.vulnerability
  const waterfall = [
    { name: 'Exploitability', value: a.contributions.likelihood },
    { name: 'Impact', value: a.contributions.severity },
    { name: 'Evidence', value: a.contributions.evidence },
  ]
  const p = a.bayes ? a.bayes.p_compromise * 100 : null
  const clocks: Clock[] = (a as unknown as { obligations?: Clock[] }).obligations ?? []
  const supply: Supplier[] = (d as unknown as { supply_chain?: Supplier[] }).supply_chain ?? []

  return (
    <aside className="flex h-full w-[800px] max-w-[96vw] shrink-0 flex-col overflow-hidden rounded-3xl bg-panel text-text shadow-2xl">
      <header className="border-b border-line px-8 pt-6 pb-5">
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <TierPill tier={a.tier} />
              {v.kev && <Badge tone="crit">exploited in the wild (CISA KEV)</Badge>}
              <span className="font-mono text-sm text-mute">{v.id}</span>
            </div>
            <h2 className="mt-2 text-2xl font-bold leading-snug">{v.kev?.vulnerabilityName ?? v.description.slice(0, 110)}</h2>
            <p className="mt-1 text-mute">{d.org.name} · {d.org.sector} · {d.org.state}</p>
          </div>
          <div className="flex shrink-0 items-start gap-4">
            <div className="text-right">
              <div className="text-5xl font-bold leading-none tabular-nums">{a.risk.toFixed(0)}</div>
              <div className="mt-1 text-xs text-mute">risk out of 100</div>
            </div>
            <button onClick={onClose} title="Close" className="flex h-10 w-10 items-center justify-center rounded-full bg-panel-2 hover:bg-panel-3"><X size={18} /></button>
          </div>
        </div>
        <div className="mt-5 grid grid-cols-3 gap-3">
          <Stat value={deadlineText(a.deadline_hours)} label="to act" sub={a.tier === 'Compromise' ? 'report to CERT-In' : a.kev_due ? `CISA KEV due ${a.kev_due}` : 'CERT-In Blueprint (indicative)'} />
          <Stat value={a.decision} label="SSVC decision" sub={a.decision_path.slice(0, 2).join(' · ')} />
          <Stat value={p != null ? `${p < 1 ? p.toFixed(2) : p.toFixed(1)}%` : '—'} label="chance of compromise" sub={p != null && p >= 50 ? 'suspected compromise' : 'hunt at 20%, compromise at 50%'} />
        </div>
        <div className="mt-5">
          <Tabs value={tab} onChange={setTab} items={[['summary', 'What to do'], ['why', 'Why this score'], ['history', 'How it unfolded'], ['related', 'Related']]} />
        </div>
      </header>

      <div className="min-h-0 flex-1 space-y-6 overflow-auto px-8 py-6">
        {tab === 'summary' && (
          <>
            {clocks.length > 0 && (
              <Panel title="Clocks that apply" right={<span className="text-xs text-mute">India's reporting and patch deadlines for this warning</span>}>
                {clocks.map((c: Clock) => (
                  <div key={c.who + c.what} className="flex items-start gap-4 border-b border-line py-3 last:border-0">
                    <div className="w-20 shrink-0 text-xl font-bold tabular-nums">{c.hours != null ? deadlineText(c.hours) : '—'}</div>
                    <div className="min-w-0">
                      <div className="font-semibold">{c.who}</div>
                      <div className="text-sm text-mute">{c.what}{c.route ? ` · ${c.route}` : ''}</div>
                    </div>
                  </div>
                ))}
              </Panel>
            )}
            <BriefPanel orgId={d.org.id} cveId={v.id} />
            <Panel title="Recommended actions">
              <ul className="space-y-3">
                {d.actions.map((x, i) => (
                  <li key={i} className="flex gap-3">
                    <CheckSquare size={16} className="mt-0.5 shrink-0 text-mute" />
                    <div>
                      <span className="mr-2 rounded-full bg-panel-2 px-2 py-0.5 text-xs font-semibold uppercase">{x.type}</span>
                      {x.step}
                      <div className="text-sm text-mute">{x.source}{x.due ? ` · due ${x.due}` : ''}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
            <ExportPanel orgId={d.org.id} cveId={v.id} compromise={a.tier === 'Compromise'} />
          </>
        )}

        {tab === 'why' && (
          <>
            <DecisionPanel bayes={a.bayes} />
            <Panel title="The score, factor by factor">
              <div className="mb-2 font-mono text-sm text-mute">
                Risk = 100 · R {a.R} · K {a.K} · (0.55·L {a.L} + 0.30·S {a.S} + 0.15·V {a.V})
              </div>
              <div className="h-28">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={waterfall} layout="vertical" margin={{ left: 10, right: 20 }}>
                    <XAxis type="number" domain={[0, 100]} hide />
                    <YAxis type="category" dataKey="name" width={90} tick={{ fill: 'var(--color-mute)', fontSize: 12 }} />
                    <Tooltip contentStyle={{ background: 'var(--color-panel)', border: '1px solid var(--color-line)', borderRadius: 12 }} />
                    <Bar dataKey="value" fill="var(--color-text)" radius={4} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-3 grid grid-cols-5 gap-2 text-center">
                {([['L', 'exploitability'], ['S', 'impact'], ['V', 'evidence'], ['R', 'exposure'], ['K', 'asset criticality']] as const)
                  .map(([k, label]) => (
                    <div key={k} className="rounded-xl bg-panel-2 p-2">
                      <div className="font-mono text-lg font-semibold">{a[k]}</div>
                      <div className="text-xs text-mute">{label}</div>
                    </div>
                  ))}
              </div>
            </Panel>
            <Panel title={`Evidence behind it · ${a.rules.length} rule${a.rules.length === 1 ? '' : 's'}`}>
              <ul className="space-y-2.5">
                {a.rules.map((r) => (
                  <li key={r.id} className="flex items-start gap-3">
                    <span className={`mt-0.5 rounded-full px-2 text-xs font-semibold ${r.crit >= 4 ? 'bg-crit text-white' : r.crit === 3 ? 'bg-high text-white' : 'bg-panel-2 text-mute'}`}>{r.crit}</span>
                    <div>
                      <div>{r.text}</div>
                      <div className="text-sm text-mute">{r.evidence} · source {r.source} · {CRIT_LABEL[r.crit]}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
            <Panel title="Is the installed version affected?" right={<Badge tone={a.R >= 0.6 ? 'crit' : 'ok'}>{a.exposure.status}</Badge>}>
              {d.assets.length > 1 && (
                <div className="mb-3 flex flex-wrap gap-2">
                  {d.assets.map((x, i) => (
                    <button key={x.asset_id} onClick={() => setAssetIdx(i)}
                            className={`rounded-full px-3 py-1 text-sm font-medium ${i === assetIdx ? 'bg-action text-ink' : 'bg-panel-2 hover:bg-panel-3'}`}>
                      {x.hostname.split('.')[0]}
                    </button>
                  ))}
                </div>
              )}
              <p className="mb-3 text-sm text-mute">
                {a.hostname} · {a.ip} · {a.label} <span className="font-mono text-text">{a.version}</span> · zone {a.zone} · tier {a.asset_tier} · owner {a.owner}
              </p>
              <table className="w-full text-sm">
                <tbody>
                  {a.exposure.votes.map((vt) => (
                    <tr key={vt.source} className="border-t border-line align-top">
                      <td className="py-2 pr-3 font-mono">{vt.source}</td>
                      <td className="py-2 pr-3"><Badge tone={VERDICT_TONE[vt.verdict] ?? 'mute'}>{vt.verdict.replace('_', ' ')}</Badge></td>
                      <td className="py-2 text-mute">
                        {vt.reason}
                        {vt.span && <div className="mt-0.5 italic">"{vt.span}"</div>}
                        {vt.strength === 'default' && <div className="text-high">weak: vendor default status</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </>
        )}

        {tab === 'history' && (
          <>
            <ReplayPanel orgId={d.org.id} cveId={v.id} />
            <Panel title="Evidence, in the audit trail" right={<span className="flex items-center gap-1 text-xs text-ok"><FileCheck2 size={12} /> scoring config {d.scoring_config_hash}</span>}>
              <ol className="space-y-2 text-sm">
                {d.timeline.map((e) => (
                  <li key={e.seq} className="flex items-center gap-3">
                    <span className="w-36 shrink-0 font-mono text-xs text-mute">{fmtDate(e.ts)}</span>
                    <Prov p={e.provenance} />
                    <span className="min-w-0 truncate">{e.kind}</span>
                    <span className="truncate text-mute">· {e.source}</span>
                    <span className="ml-auto flex shrink-0 items-center gap-0.5 font-mono text-xs text-mute"><Link2 size={10} />{e.hash.slice(0, 8)}</span>
                  </li>
                ))}
              </ol>
            </Panel>
          </>
        )}

        {tab === 'related' && (
          <>
            {supply.length > 0 && (
              <Panel title="Through suppliers" right={<Prov p="SIM" label="SIM supplier graph" />}>
                {supply.map((sp: Supplier) => (
                  <div key={sp.id} className="border-b border-line py-3 last:border-0">
                    <div className="font-semibold">{sp.name} <span className="font-normal text-mute">· {sp.service}</span></div>
                    <div className="mt-1 text-sm text-mute">
                      Runs {a.label} for {sp.dependents.length} organisation{sp.dependents.length === 1 ? '' : 's'}; {sp.only_via_supplier} of them
                      do not run it themselves and are reached only through this supplier. Each is asked to confirm the supplier's patch status.
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {sp.dependents.map((x) => <Badge key={x.org_id}>{x.name}{x.runs_it_too ? '' : ' · via supplier only'}</Badge>)}
                    </div>
                  </div>
                ))}
              </Panel>
            )}
            <AttackPanel attack={d.attack} />
            <RelatedPanel orgId={d.org.id} cveId={v.id} />
            <Panel title="The vulnerability, as published">
              <p className="leading-relaxed text-mute">{v.description}</p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {v.cvss_vector && <Badge>{v.cvss_vector} ({v.cvss_source})</Badge>}
                {v.epss != null && <Badge>EPSS {v.epss.toFixed(3)}</Badge>}
                {Object.entries(v.ssvc).map(([k, val]) => <Badge key={k}>{k}: {val}</Badge>)}
                {v.nvd_status && <Badge>NVD: {v.nvd_status}</Badge>}
              </div>
            </Panel>
          </>
        )}
      </div>
    </aside>
  )
}
