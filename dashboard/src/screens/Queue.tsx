import { Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { api, getAnalyst, getMode, now, useLoad } from '../data'
import { ACTION_LABEL, num, STATE_LABEL, TIERS } from '../format'
import type { Card, Tier, Workflow } from '../types'
import { Bars, Button, Countdown, Empty, ErrorLine, Panel, TierMark } from '../ui'
import { byUrgency } from './Overview'

const STATE_FILTERS = [['open', 'Open'], ['new', 'New'], ['acknowledged', 'Acknowledged'], ['mitigating', 'Mitigating'], ['verifying', 'Verifying'], ['closed', 'Closed'], ['all', 'All']] as const

function NextAction({ c, onDone }: { c: Card; onDone: (w: Workflow) => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const action = c.workflow.next_action
  if (!action) return <span className="text-[13px] text-faint">—</span>
  const live = getMode() === 'live'
  return (
    <span className="inline-flex flex-col items-end gap-1">
      <Button size="sm" disabled={busy || !live} title={live ? undefined : 'Read-only data: connect to the Odyssey backend to act'}
        onClick={async () => {
          setBusy(true); setErr(null)
          try { onDone(await api.act(c.org_id, c.cve_id, action, getAnalyst())) } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
          setBusy(false)
        }}>
        {ACTION_LABEL[action] ?? action}
      </Button>
      {err && <span className="text-[12px] text-compromise">{err}</span>}
    </span>
  )
}

export function Queue() {
  const feed = useLoad(api.feed, 'feed')
  const [tier, setTier] = useState<Tier | 'all'>('all')
  const [state, setState] = useState<string>('open')
  const [sector, setSector] = useState('all')
  const [q, setQ] = useState('')
  const [updated, setUpdated] = useState<Record<string, Workflow>>({})

  const cards = useMemo(() => (feed.data?.cards ?? []).map((c) => (updated[c.id] ? { ...c, workflow: updated[c.id] } : c)), [feed.data, updated])
  const sectors = useMemo(() => [...new Set(cards.map((c) => c.sector))].sort(), [cards])
  const rows = byUrgency(cards.filter((c) =>
    (tier === 'all' || c.tier === tier) &&
    (sector === 'all' || c.sector === sector) &&
    (state === 'all' || (state === 'open' ? c.workflow.state !== 'closed' : c.workflow.state === state)) &&
    (!q || `${c.org_name} ${c.cve_id} ${c.title} ${c.headline ?? ''}`.toLowerCase().includes(q.toLowerCase())),
  ), now())

  return (
    <div className="space-y-4">
      <div className="pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">Triage queue</h1>
        <p className="text-mute">Every warning, most urgent first. Move each one through acknowledge, mitigate, verify and close.</p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex rounded-md bg-panel p-0.5" role="group" aria-label="Tier">
          {(['all', ...TIERS] as const).map((t) => (
            <button key={t} onClick={() => setTier(t)} aria-pressed={tier === t}
              className={`h-8 rounded-[5px] px-3 text-[13px] ${tier === t ? 'bg-raised text-text' : 'text-mute hover:text-text'}`}>
              {t === 'all' ? 'All tiers' : t}
            </button>
          ))}
        </div>
        <select value={state} onChange={(e) => setState(e.target.value)} aria-label="State"
          className="h-9 rounded-md bg-panel px-2.5 text-[13px] text-text outline-none">
          {STATE_FILTERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <select value={sector} onChange={(e) => setSector(e.target.value)} aria-label="Sector"
          className="h-9 rounded-md bg-panel px-2.5 text-[13px] text-text outline-none">
          <option value="all">All sectors</option>
          {sectors.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <label className="flex h-9 min-w-[220px] flex-1 items-center gap-2 rounded-md bg-panel px-2.5 text-mute sm:max-w-sm">
          <Search size={15} />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Organisation, CVE or product"
            className="w-full bg-transparent text-[13px] text-text outline-none placeholder:text-faint" />
        </label>
      </div>

      <Panel pad={false} title={feed.data ? `${num(rows.length)} warning${rows.length === 1 ? '' : 's'}` : 'Warnings'}
        meta={feed.data ? `of ${num(cards.length)} in the feed` : undefined}>
        {feed.loading ? <div className="px-5"><Bars rows={8} /></div>
          : feed.error ? <div className="px-5"><ErrorLine message={feed.error} onRetry={feed.reload} /></div>
          : rows.length === 0 ? <div className="px-5"><Empty>No warnings match these filters.</Empty></div>
          : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[920px] text-[14px]">
                <thead>
                  <tr className="text-left text-[12px] text-faint">
                    <th className="px-5 pb-2 font-normal">Tier</th>
                    <th className="pb-2 font-normal">Warning</th>
                    <th className="pb-2 text-right font-normal">Risk</th>
                    <th className="pb-2 text-right font-normal">Deadline</th>
                    <th className="pb-2 pl-6 font-normal">State</th>
                    <th className="pb-2 font-normal">Owner</th>
                    <th className="px-5 pb-2 text-right font-normal">Next step</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/70">
                  {rows.map((c) => (
                    <tr key={c.id} className="hover:bg-raised/40">
                      <td className="px-5 py-3 align-top"><TierMark tier={c.tier} /></td>
                      <td className="max-w-0 py-3 pr-4 align-top">
                        <a href={`#/incident/${c.org_id}/${c.cve_id}`} className="block hover:underline">
                          <span className="block truncate font-medium">{c.headline ?? `${c.title} at ${c.org_name}`}</span>
                          <span className="block truncate text-[13px] text-mute">{c.org_name} · {c.sector} · <span className="num">{c.cve_id}</span>{c.kev ? ' · on CISA KEV' : ''}</span>
                        </a>
                      </td>
                      <td className="num py-3 text-right align-top">{num(c.risk)}</td>
                      <td className="py-3 text-right align-top text-[13px]"><Countdown issuedAt={c.workflow.issued_at} hours={c.deadline_hours} closed={c.workflow.state === 'closed'} /></td>
                      <td className="py-3 pl-6 align-top text-[13px] text-mute">{STATE_LABEL[c.workflow.state]}</td>
                      <td className="py-3 align-top text-[13px] text-mute">{c.workflow.owner ?? '—'}</td>
                      <td className="px-5 py-2 text-right align-top"><NextAction c={c} onDone={(w) => setUpdated((u) => ({ ...u, [c.id]: w }))} /></td>
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
