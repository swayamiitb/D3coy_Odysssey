import { CheckSquare, Clock, FileCheck2, Link2, X } from 'lucide-react'
import { useState } from 'react'
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { AlertDetail as Detail } from './api'
import { BriefPanel } from './BriefPanel'
import { ExportPanel } from './ExportPanel'
import { RelatedPanel } from './RelatedPanel'
import { ReplayPanel } from './ReplayPanel'
import { Badge, deadlineText, fmtDate, Panel, TierPill } from './ui'

const CRIT_LABEL = ['', 'context', 'corroborating', 'strong', 'confirmed']
const VERDICT_TONE: Record<string, 'crit' | 'ok' | 'mute'> = { affected: 'crit', not_affected: 'ok', unknown: 'mute' }

export function AlertDetail({ d, onClose }: { d: Detail; onClose: () => void }) {
  const [assetIdx, setAssetIdx] = useState(0)
  const a = d.assets[assetIdx]
  const v = d.vulnerability
  const waterfall = [
    { name: 'Likelihood', value: a.contributions.likelihood },
    { name: 'Severity', value: a.contributions.severity },
    { name: 'Evidence', value: a.contributions.evidence },
  ]

  return (
    <aside className="flex h-full w-[560px] max-w-[95vw] shrink-0 flex-col overflow-hidden rounded-2xl border border-line bg-panel shadow-2xl">
      <header className="flex items-start justify-between gap-3 border-b border-line p-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-accent">{v.id}</span>
            <TierPill tier={a.tier} />
            {v.kev && <Badge tone="crit">CISA KEV</Badge>}
          </div>
          <div className="mt-1 text-sm">{v.kev?.vulnerabilityName ?? v.description.slice(0, 90)}</div>
          <div className="text-xs text-mute">{d.org.name} · {d.org.sector} · {d.org.state}</div>
        </div>
        <div className="text-right">
          <div className="font-mono text-4xl font-semibold leading-none">{a.risk.toFixed(0)}</div>
          <div className="text-xs text-mute">risk / 100</div>
        </div>
        <button onClick={onClose} className="text-mute hover:text-text"><X size={18} /></button>
      </header>

      <div className="min-h-0 flex-1 space-y-3 overflow-auto p-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded border border-crit/30 bg-crit/5 p-3">
            <div className="flex items-center gap-1 text-xs text-mute"><Clock size={12} /> Remediation deadline</div>
            <div className="font-mono text-2xl">{deadlineText(a.deadline_hours)}</div>
            <div className="text-xs text-mute">
              {a.deadline_basis}{a.tier !== 'Compromise' && a.deadline_hours != null ? ' · CERT-In Blueprint (indicative)' : ''}
            </div>
            {a.kev_due && <div className="mt-1 text-xs">CISA KEV due {a.kev_due}</div>}
          </div>
          <div className="rounded border border-line bg-panel-2 p-3">
            <div className="text-xs text-mute">SSVC decision</div>
            <div className="text-lg font-semibold">{a.decision}</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {a.decision_path.map((p) => <Badge key={p}>{p}</Badge>)}
            </div>
          </div>
        </div>

        <ReplayPanel orgId={d.org.id} cveId={v.id} />

        <BriefPanel orgId={d.org.id} cveId={v.id} />

        <Panel title="Why this score — glass-box breakdown">
          <div className="mb-2 font-mono text-xs text-mute">
            Risk = 100 · R {a.R} · K {a.K} · (0.55·L {a.L} + 0.30·S {a.S} + 0.15·V {a.V})
          </div>
          <div className="h-28">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={waterfall} layout="vertical" margin={{ left: 10, right: 20 }}>
                <XAxis type="number" domain={[0, 100]} hide />
                <YAxis type="category" dataKey="name" width={80} tick={{ fill: '#8b98a9', fontSize: 12 }} />
                <Tooltip contentStyle={{ background: '#121821', border: '1px solid #243041' }} />
                <Bar dataKey="value" fill="#38bdf8" radius={3} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 grid grid-cols-5 gap-2 text-center text-xs">
            {([['L', 'likelihood'], ['S', 'severity'], ['V', 'confidence'], ['R', 'relevance'], ['K', 'asset context']] as const)
              .map(([k, label]) => (
                <div key={k} className="rounded bg-panel-2 p-1.5">
                  <div className="font-mono text-base">{a[k]}</div>
                  <div className="text-mute">{label}</div>
                </div>
              ))}
          </div>
        </Panel>

        <Panel title={`Evidence rules fired (${a.rules.length})`}>
          <ul className="space-y-1.5 text-xs">
            {a.rules.map((r) => (
              <li key={r.id} className="flex items-start gap-2">
                <span className={`mt-0.5 rounded px-1.5 font-mono ${r.crit >= 4 ? 'bg-crit/20 text-crit' : r.crit === 3 ? 'bg-high/20 text-high' : 'bg-panel-2 text-mute'}`}>
                  {r.crit}
                </span>
                <div>
                  <div>{r.text}</div>
                  <div className="text-mute">{r.evidence} · source {r.source} · {CRIT_LABEL[r.crit]}</div>
                </div>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Exposure — three-source version reconciliation"
               right={<Badge tone={a.R >= 0.6 ? 'crit' : 'ok'}>{a.exposure.status}</Badge>}>
          {d.assets.length > 1 && (
            <div className="mb-2 flex flex-wrap gap-1">
              {d.assets.map((x, i) => (
                <button key={x.asset_id} onClick={() => setAssetIdx(i)}
                        className={`rounded px-2 py-0.5 text-xs ${i === assetIdx ? 'bg-accent/20 text-accent' : 'bg-panel-2 text-mute'}`}>
                  {x.hostname.split('.')[0]}
                </button>
              ))}
            </div>
          )}
          <div className="mb-2 text-xs text-mute">
            {a.hostname} · {a.ip} · {a.label} <span className="font-mono text-text">{a.version}</span> · zone {a.zone} · tier {a.asset_tier} · owner {a.owner}
          </div>
          <table className="w-full text-xs">
            <tbody>
              {a.exposure.votes.map((vt) => (
                <tr key={vt.source} className="border-t border-line/60 align-top">
                  <td className="py-1.5 pr-2 font-mono">{vt.source}</td>
                  <td className="pr-2"><Badge tone={VERDICT_TONE[vt.verdict] ?? 'mute'}>{vt.verdict.replace('_', ' ')}</Badge></td>
                  <td className="text-mute">
                    {vt.reason}
                    {vt.span && <div className="mt-0.5 italic">"{vt.span}"</div>}
                    {vt.strength === 'default' && <div className="text-med">weak: vendor default status</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <ExportPanel orgId={d.org.id} cveId={v.id} compromise={a.tier === 'Compromise'} />

        <RelatedPanel orgId={d.org.id} cveId={v.id} />

        <Panel title="Recommended actions">
          <ul className="space-y-2 text-xs">
            {d.actions.map((x, i) => (
              <li key={i} className="flex gap-2">
                <CheckSquare size={14} className="mt-0.5 shrink-0 text-mute" />
                <div>
                  <span className="mr-1 rounded bg-panel-2 px-1.5 uppercase text-accent">{x.type}</span>
                  {x.step}
                  <div className="text-mute">{x.source}{x.due ? ` · due ${x.due}` : ''}</div>
                </div>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Evidence timeline — hash-chained ledger"
               right={<span className="flex items-center gap-1 text-xs text-ok"><FileCheck2 size={12} /> config {d.scoring_config_hash}</span>}>
          <ol className="space-y-1.5 text-xs">
            {d.timeline.map((e) => (
              <li key={e.seq} className="flex items-center gap-2">
                <span className="w-32 font-mono text-mute">{fmtDate(e.ts)}</span>
                <Badge tone={e.provenance === 'REAL' ? 'ok' : 'accent'}>{e.provenance}</Badge>
                <span>{e.kind}</span>
                <span className="text-mute">· {e.source}</span>
                <span className="ml-auto flex items-center gap-0.5 font-mono text-mute"><Link2 size={10} />{e.hash.slice(0, 8)}</span>
              </li>
            ))}
          </ol>
        </Panel>

        <Panel title="Source description">
          <p className="text-xs leading-relaxed text-mute">{v.description}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {v.cvss_vector && <Badge>{v.cvss_vector} ({v.cvss_source})</Badge>}
            {v.epss != null && <Badge>EPSS {v.epss.toFixed(3)}</Badge>}
            {Object.entries(v.ssvc).map(([k, val]) => <Badge key={k}>{k}: {val}</Badge>)}
            {v.nvd_status && <Badge>NVD: {v.nvd_status}</Badge>}
          </div>
        </Panel>
      </div>
    </aside>
  )
}
