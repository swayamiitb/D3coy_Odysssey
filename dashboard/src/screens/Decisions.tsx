import { useState } from 'react'
import { api, getAnalyst, getMode, useLoad } from '../data'
import { dateTime, humanKind, num } from '../format'
import type { Approval } from '../types'
import { Bars, Button, Empty, ErrorLine, Panel, Provenance } from '../ui'
import { LANG } from './Overview'

function Proposal({ a, onDecided }: { a: Approval; onDecided: () => void }) {
  const [reason, setReason] = useState('')
  const [rejecting, setRejecting] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const live = getMode() === 'live'
  const decide = async (d: 'approve' | 'reject') => {
    setBusy(true); setErr(null)
    try { await api.decide(a.id, d, getAnalyst(), d === 'reject' ? reason : undefined); onDecided() } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
    setBusy(false)
  }
  const ro = live ? undefined : 'Read-only data: connect to the Odyssey backend to decide'
  return (
    <li className="px-5 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="font-medium">{a.title}</div>
          <div className="mt-0.5 flex flex-wrap gap-x-3 text-[13px] text-mute">
            <span>{humanKind(a.kind)}</span>
            {a.basis && <span>Basis: {a.basis}</span>}
            {a.p != null && <span className="num">Probability {num(a.p * 100)}%</span>}
            <Provenance p={a.provenance} />
            <span>Proposed {dateTime(a.proposed_at)}</span>
          </div>
        </div>
        {a.status === 'pending' ? (
          <div className="flex gap-2">
            <Button variant="primary" disabled={!live || busy} title={ro} onClick={() => decide('approve')}>Approve and send</Button>
            <Button disabled={!live || busy} title={ro} onClick={() => setRejecting((v) => !v)}>Reject</Button>
          </div>
        ) : (
          <span className="text-[13px] text-mute">{a.status === 'approved' ? 'Approved' : a.status === 'rejected' ? 'Rejected' : 'Superseded by evidence'}{a.decided_by ? ` by ${a.decided_by}` : ''}{a.decided_at ? `, ${dateTime(a.decided_at)}` : ''}</span>
        )}
      </div>
      <dl className="mt-3 grid gap-x-6 gap-y-1 text-[13px] sm:grid-cols-[120px_1fr]">
        <dt className="text-faint">Organisations</dt><dd>{a.orgs.join(', ') || '—'}</dd>
        {a.langs.length > 0 && <><dt className="text-faint">Languages</dt><dd>{a.langs.map((l) => LANG[l] ?? l).join(', ')}</dd></>}
        {a.recipients.length > 0 && <><dt className="text-faint">Recipients</dt><dd className="truncate">{a.recipients.slice(0, 4).join(', ')}{a.recipients.length > 4 ? ` and ${a.recipients.length - 4} more` : ''}</dd></>}
        {a.items.length > 0 && <><dt className="text-faint">Covers</dt><dd>{a.items.map((i) => `${i.cve} on ${i.asset}`).join(' · ')}</dd></>}
        {a.note && <><dt className="text-faint">Reason</dt><dd>{a.note}</dd></>}
      </dl>
      {rejecting && (
        <div className="mt-3 flex flex-wrap gap-2">
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why reject? Recorded to calibrate Odyssey" aria-label="Reason"
            className="h-9 min-w-[260px] flex-1 rounded-md bg-raised px-3 text-[13px] outline-none placeholder:text-faint" />
          <Button disabled={!reason || busy} onClick={() => decide('reject')}>Confirm reject</Button>
        </div>
      )}
      {err && <p className="mt-2 text-[13px] text-compromise">{err}</p>}
    </li>
  )
}

export function Decisions() {
  const [tab, setTab] = useState<'pending' | 'approved' | 'rejected'>('pending')
  const list = useLoad(() => api.approvals(tab), `approvals:${tab}`)
  return (
    <div className="space-y-4">
      <div className="pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">Decisions</h1>
        <p className="text-mute">Human in the loop. Odyssey proposes predictions, sensor-only warnings and regulator escalations; nothing is sent until a person approves.</p>
      </div>
      <div className="flex rounded-md bg-panel p-0.5 sm:w-fit" role="tablist">
        {(['pending', 'approved', 'rejected'] as const).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
            className={`h-8 flex-1 rounded-[5px] px-4 text-[13px] ${tab === t ? 'bg-raised text-text' : 'text-mute hover:text-text'}`}>
            {t === 'pending' ? 'Waiting' : t === 'approved' ? 'Approved' : 'Rejected'}
          </button>
        ))}
      </div>
      <Panel pad={false} title={list.data ? `${num(list.data.length)} proposal${list.data.length === 1 ? '' : 's'}` : 'Proposals'}>
        {list.loading ? <div className="px-5"><Bars rows={5} /></div>
          : list.error ? <div className="px-5"><ErrorLine message={list.error} onRetry={list.reload} /></div>
          : list.data!.length === 0 ? <div className="px-5"><Empty>{tab === 'pending' ? 'Nothing is waiting for a decision.' : 'None yet.'}</Empty></div>
          : <ul className="divide-y divide-line/70">{list.data!.map((a) => <Proposal key={a.id} a={a} onDecided={list.reload} />)}</ul>}
      </Panel>
    </div>
  )
}
