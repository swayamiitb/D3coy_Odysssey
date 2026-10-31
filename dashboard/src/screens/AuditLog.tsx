import { useState } from 'react'
import { api, useLoad } from '../data'
import { dateTime, humanKind, num } from '../format'
import { Bars, Empty, ErrorLine, Panel, Provenance } from '../ui'

export function AuditLog() {
  const log = useLoad(() => api.autopilot(300), 'autopilot')
  const health = useLoad(api.health, 'health')
  const [kind, setKind] = useState('all')
  const events = log.data?.events ?? []
  const kinds = [...new Set(events.map((e) => e.kind))].sort()
  const rows = events.filter((e) => kind === 'all' || e.kind === kind)
  const title = (p: Record<string, unknown>) => String(p.title ?? p.summary ?? p.text ?? '')

  return (
    <div className="space-y-4">
      <div className="pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">Audit log</h1>
        <p className="text-mute">Everything Odyssey did on its own, and every human decision on its proposals. Each entry is hash-chained to the one before it.</p>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-[13px]">
        <span className="text-mute">Ledger integrity:</span>
        {health.data ? <span className={health.data.ledger_intact ? 'text-ok' : 'text-compromise'}>{health.data.ledger_intact ? 'Intact, no entry changed' : 'Broken: an entry was changed'}</span>
          : health.error ? <span className="text-faint">unknown</span> : <span className="text-faint">checking…</span>}
        <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Event type" className="ml-auto h-9 rounded-md bg-panel px-2.5 text-text outline-none">
          <option value="all">All event types</option>
          {kinds.map((k) => <option key={k} value={k}>{humanKind(k)}</option>)}
        </select>
      </div>
      <Panel pad={false} title={log.data ? `${num(rows.length)} event${rows.length === 1 ? '' : 's'}` : 'Events'}>
        {log.loading ? <div className="px-5"><Bars rows={8} /></div>
          : log.error ? <div className="px-5"><ErrorLine message={log.error} onRetry={log.reload} /></div>
          : rows.length === 0 ? <div className="px-5"><Empty>No events yet.</Empty></div>
          : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-[14px]">
                <thead>
                  <tr className="text-left text-[12px] text-faint">
                    <th className="px-5 pb-2 font-normal">When</th>
                    <th className="pb-2 font-normal">What</th>
                    <th className="pb-2 font-normal">Subject</th>
                    <th className="px-5 pb-2 text-right font-normal">By</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/70">
                  {rows.slice(0, 200).map((e) => (
                    <tr key={e.seq}>
                      <td className="num px-5 py-2.5 align-top whitespace-nowrap text-mute">{dateTime(e.ts)}</td>
                      <td className="py-2.5 pr-4 align-top">{humanKind(e.kind)}{title(e.payload) && <span className="block text-[13px] text-mute">{title(e.payload)}</span>}</td>
                      <td className="num py-2.5 pr-4 align-top text-[13px] text-mute">{e.subject}</td>
                      <td className="px-5 py-2.5 text-right align-top"><Provenance p={e.provenance} /></td>
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
