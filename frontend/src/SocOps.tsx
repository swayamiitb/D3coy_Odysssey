import { Check, ClipboardCopy, Loader2, ShieldAlert, Wrench } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Soc } from './api'
import { Heatmap, type HeatData } from './Heatmap'
import { Countdown } from './Now'
import { ApprovalQueue, AutopilotFeed, istTime } from './proactive'
import { Rewind } from './Rewind'
import { SystemView } from './SystemView'
import { Panel, TierPill, useToast } from './ui'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Case = any

const STATUS_LABEL: Record<string, string> = { new: 'New', in_progress: 'In progress', contained: 'Contained', resolved: 'Resolved', false_positive: 'False positive' }
const initials = (name: string) => name.split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase()

async function post(path: string, body?: unknown) {
  const res = await fetch(path, { method: 'POST', headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined })
  if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
  return res.json()
}

export function OpsOverview({ tick, onCases }: { tick: number; onCases: () => void }) {
  const [d, setD] = useState<Soc>()
  const [m, setM] = useState<any>()
  const [heat, setHeat] = useState<Record<string, HeatData>>()
  const [hand, setHand] = useState<string>()
  const [stamp, setStamp] = useState(0)
  const toast = useToast()
  useEffect(() => {
    api.soc().then(setD).catch(() => undefined)
    fetch('/api/soc/metrics').then((r) => r.json()).then(setM).catch(() => undefined)
  }, [tick, stamp])
  useEffect(() => { fetch('/api/heatmaps').then((r) => r.json()).then(setHeat).catch(() => undefined) }, [tick])
  if (!d || !m) return <div className="p-8 text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />Opening the SOC…</div>
  const auto = d.autopilot.by_mode?.auto ?? 0
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-6">
      <p className="text-lg text-mute">Since {d.autopilot.go_live} Odyssey acted <b className="text-text">{auto.toLocaleString('en-IN')}</b> times on its own; people decided the rest.</p>
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Panel title="Open warnings, day by day" right={<span className="text-xs text-mute">replay to watch the SOC's last 90 days</span>}>
            <Rewind d={d} />
          </Panel>
        </div>
        <Panel title={`Needs your decision · ${d.pending}`}>
          <div className="max-h-[24rem] overflow-auto pr-1"><ApprovalQueue limit={2} onChanged={() => setStamp((s) => s + 1)} /></div>
        </Panel>
      </div>
      {heat && (
        <Panel title="Odyssey at work, day by day" right={<span className="text-xs text-mute">autopilot actions by type since go-live</span>}>
          <Heatmap data={heat.autopilot} hue="accent" unit="actions" labelW={180} />
        </Panel>
      )}
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Team on shift" right={<button onClick={onCases} className="text-sm font-medium text-accent hover:underline">Open cases</button>}>
          {m.analysts.map((a: any) => (
            <div key={a.id} className="flex items-center gap-3 border-b border-line py-2.5 last:border-0">
              <span className="flex h-10 w-10 items-center justify-center rounded-full bg-panel-2 text-xs font-bold">{a.name === 'You' ? 'AN' : initials(a.name)}</span>
              <div className="min-w-0 flex-1"><div className="font-semibold">{a.name}</div><div className="text-sm text-mute">{a.role}</div></div>
              <div className="w-40">
                <div className="h-2 rounded-full bg-panel-2"><div className="h-2 rounded-full bg-action" style={{ width: `${Math.min(100, (100 * a.open) / Math.max(1, m.open))}%` }} /></div>
                <div className="mt-1 text-right text-xs text-mute">{a.open} open{a.overdue ? <span className="text-crit"> · {a.overdue} overdue</span> : ''}{a.incidents ? ` · ${a.incidents} IR` : ''}</div>
              </div>
            </div>
          ))}
        </Panel>
        <Panel title="Shift handover" right={hand && <button onClick={() => { navigator.clipboard?.writeText(hand); toast('Handover copied') }} className="flex items-center gap-1 text-sm font-medium text-accent hover:underline"><ClipboardCopy size={14} /> Copy</button>}>
          {hand ? <pre className="whitespace-pre-wrap rounded-2xl bg-panel-2 p-4 font-sans text-sm leading-relaxed">{hand}</pre> : (
            <div>
              <p className="mb-3 text-sm text-mute">One click writes what the next shift must know: open cases, SLA breaches, decisions waiting and the top priorities, from the live state.</p>
              <button onClick={() => fetch('/api/soc/handover').then((r) => r.json()).then((h) => setHand(h.text))}
                      className="rounded-full bg-action px-5 py-2.5 text-sm font-semibold text-ink hover:opacity-85">Write handover</button>
            </div>
          )}
        </Panel>
      </div>
    </div>
  )
}

export function CaseBoard({ tick, onAlert }: { tick: number; onAlert: (orgId: string, cveId: string) => void }) {
  const [filter, setFilter] = useState<'open' | 'mine' | 'unassigned' | 'incident' | 'overdue' | 'closed'>('open')
  const [list, setList] = useState<Case[]>()
  const [sel, setSel] = useState<string>()
  const [c, setC] = useState<Case>()
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [stamp, setStamp] = useState(0)
  const toast = useToast()
  useEffect(() => {
    const q = filter === 'mine' ? 'status=open&owner=analyst@ncew' : filter === 'unassigned' ? 'status=open&owner=unassigned'
      : filter === 'closed' ? 'status=resolved' : 'status=open'
    fetch(`/api/cases?${q}`).then((r) => r.json()).then((rows: Case[]) => {
      const out = filter === 'incident' ? rows.filter((x) => x.kind === 'incident') : filter === 'overdue' ? rows.filter((x) => x.overdue) : rows
      setList(out)
      if (!sel && out[0]) setSel(out[0].id)
    }).catch(() => setList([]))
  }, [filter, tick, stamp]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (sel) fetch(`/api/cases/${sel}`).then((r) => r.json()).then(setC).catch(() => undefined) }, [sel, stamp])

  const act = (path: string, msg: string, body?: unknown) => {
    setBusy(true)
    post(path, body).then(() => { toast(msg); setStamp((s) => s + 1) }).catch((e) => toast(String(e))).finally(() => setBusy(false))
  }

  return (
    <div className="flex min-w-0 flex-1 items-start gap-6">
      <div className="sticky top-24 flex max-h-[calc(100vh-7rem)] w-[460px] shrink-0 flex-col">
        <div className="mb-3 flex flex-wrap gap-2">
          {([['open', 'Open'], ['mine', 'Mine'], ['unassigned', 'Unassigned'], ['incident', 'Incidents'], ['overdue', 'Overdue'], ['closed', 'Closed']] as const).map(([k, l]) => (
            <button key={k} onClick={() => { setFilter(k); setSel(undefined) }}
                    className={`rounded-full px-3.5 py-1.5 text-sm font-medium ${filter === k ? 'bg-action text-ink' : 'bg-panel-2 hover:bg-line'}`}>{l}</button>
          ))}
        </div>
        <div className="min-h-0 flex-1 overflow-auto pr-1">
          {!list && <div className="text-sm text-mute">Loading cases…</div>}
          {list?.length === 0 && <div className="rounded-2xl bg-panel-2 p-4 text-sm text-mute">No cases here.</div>}
          {list?.map((x) => (
            <button key={x.id} onClick={() => setSel(x.id)}
                    className={`mb-1 flex w-full items-start gap-3 rounded-2xl px-3 py-3 text-left ${sel === x.id ? 'bg-panel-2' : 'hover:bg-panel-2/60'}`}>
              <span className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${x.kind === 'incident' ? 'bg-comp text-white' : 'bg-panel-2 text-text'}`}>
                {x.kind === 'incident' ? <ShieldAlert size={16} /> : <Wrench size={15} />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-semibold">{x.title}</span>
                <span className="block truncate text-sm text-mute">{x.org_name} · {x.owner ?? 'unassigned'}</span>
                {x.progress.done > 0 && (
                  <span className="mt-1.5 block h-1 w-full rounded-full bg-panel-3">
                    <span className="block h-1 rounded-full bg-ok" style={{ width: `${(100 * x.progress.done) / x.progress.total}%` }} />
                  </span>
                )}
              </span>
              <span className="shrink-0 text-right">
                <span className={`block text-xs font-semibold ${x.overdue ? 'text-crit' : ''}`}>{x.overdue ? 'overdue' : STATUS_LABEL[x.status]}</span>
                <span className="block font-mono text-[11px] text-faint">{x.id}</span>
              </span>
            </button>
          ))}
        </div>
      </div>

      <div className="min-w-0 flex-1">
        {!c ? <div className="p-8 text-mute">Select a case.</div> : (
          <div className="flex flex-col gap-4 [&>*]:shrink-0">
            <div className="rounded-3xl border border-line bg-panel p-6">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <TierPill tier={c.severity} />
                <span className="rounded-full bg-panel-2 px-2.5 py-0.5 text-xs font-medium">{STATUS_LABEL[c.status]}</span>
                <span className="text-sm text-mute">{c.id} · {c.kind === 'incident' ? 'incident response' : 'remediation'} · opened {istTime(c.created_at)}</span>
              </div>
              <h3 className="text-2xl font-bold leading-snug">{c.title}</h3>
              <p className="mt-1 text-mute">{c.org_name}{c.assets?.length ? ` · ${c.assets.slice(0, 3).join(', ')}${c.assets.length > 3 ? ` +${c.assets.length - 3}` : ''}` : ''}</p>
              <div className="mt-4 flex flex-wrap items-end justify-between gap-4">
                <div>
                  {c.status !== 'resolved' && c.status !== 'false_positive' && c.due_at ? (
                    <><Countdown issuedAt={c.due_at} hours={0} big /><div className="text-sm text-mute">{c.overdue ? 'past the SLA' : 'left on the SLA'}</div></>
                  ) : <div className="text-lg font-semibold text-ok">Closed {c.resolved_at ? istTime(c.resolved_at) : ''}</div>}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <select value={c.owner ?? ''} onChange={(e) => act(`/api/cases/${c.id}/assign?owner=${encodeURIComponent(e.target.value)}`, `Assigned to ${c.roster.find((a: any) => a.id === e.target.value)?.name ?? 'nobody'}`)}
                          className="rounded-full bg-panel-2 px-4 py-2.5 text-sm font-medium outline-none">
                    <option value="">Unassigned</option>
                    {c.roster.map((a: any) => <option key={a.id} value={a.id}>{a.name} · {a.role}</option>)}
                  </select>
                  {c.owner !== 'analyst@ncew' && c.status !== 'resolved' && (
                    <button disabled={busy} onClick={() => act(`/api/cases/${c.id}/assign?owner=analyst@ncew`, 'Assigned to you')}
                            className="rounded-full bg-panel-2 px-4 py-2.5 text-sm font-semibold hover:bg-line">Assign to me</button>
                  )}
                </div>
              </div>
              <div className="mt-5 flex flex-wrap items-center gap-2">
                {c.next && (
                  <button disabled={busy} onClick={() => act(`/api/cases/${c.id}/advance`, `${c.id}: ${c.next.label}`)}
                          className="rounded-full bg-action px-6 py-3 text-base font-semibold text-ink hover:opacity-85 disabled:opacity-50">{c.next.label}</button>
                )}
                {c.status !== 'resolved' && c.status !== 'false_positive' ? (
                  <button disabled={busy} onClick={() => act(`/api/cases/${c.id}/advance?to=false_positive`, `${c.id} closed as a false positive`)}
                          className="rounded-full bg-panel-2 px-5 py-3 text-sm font-semibold hover:bg-line">False positive</button>
                ) : (
                  <button disabled={busy} onClick={() => act(`/api/cases/${c.id}/advance?to=in_progress`, `${c.id} reopened`)}
                          className="rounded-full bg-panel-2 px-5 py-3 text-sm font-semibold hover:bg-line">Reopen</button>
                )}
              </div>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <Panel title={`Playbook · ${c.progress.done}/${c.progress.total}`}>
                <div className="mb-3 h-1.5 rounded-full bg-panel-2"><div className="h-1.5 rounded-full bg-ok" style={{ width: `${(100 * c.progress.done) / c.progress.total}%` }} /></div>
                {c.playbook.map((s: any, i: number) => (
                  <button key={i} disabled={busy} onClick={() => act(`/api/cases/${c.id}/step?index=${i}&done=${!s.done}`, s.done ? 'Step reopened' : 'Step done')}
                          className="flex w-full items-start gap-3 border-b border-line py-2.5 text-left last:border-0">
                    <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${s.done ? 'bg-ok text-white' : 'ring-2 ring-line'}`}>{s.done && <Check size={12} />}</span>
                    <span className="min-w-0 flex-1">
                      <span className={`block text-sm ${s.done ? 'text-mute line-through' : ''}`}>{s.step}</span>
                      {s.done && <span className="block text-xs text-mute">{s.by} · {istTime(s.at)}</span>}
                    </span>
                  </button>
                ))}
              </Panel>
              <Panel title={`Linked warnings · ${c.linked.length}`}>
                {c.linked.map((l: any) => (
                  <button key={l.id} onClick={() => onAlert(l.org_id, l.cve_id)} className="flex w-full items-center gap-3 border-b border-line py-2.5 text-left last:border-0 hover:bg-panel-2/60">
                    {l.tier && <TierPill tier={l.tier} />}
                    <span className="min-w-0 flex-1">
                      <span className="block font-mono text-sm">{l.cve_id}{l.kev && <span className="ml-2 font-sans text-xs text-crit">known-exploited</span>}</span>
                      <span className="block truncate text-xs text-mute">{l.description}</span>
                    </span>
                  </button>
                ))}
              </Panel>
            </div>

            <Panel title="Notes and activity">
              <div className="space-y-3">
                {[...c.notes].reverse().map((n: any, i: number) => (
                  <div key={i} className="flex gap-3">
                    <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-panel-2 text-[10px] font-bold">{n.by === 'Odyssey' ? 'OD' : n.by === 'You' ? 'AN' : initials(n.by)}</span>
                    <div><div className="text-sm"><b>{n.by}</b> <span className="text-mute">· {istTime(n.ts)}</span></div><div className="text-sm">{n.text}</div></div>
                  </div>
                ))}
              </div>
              <form onSubmit={(e) => { e.preventDefault(); if (note.trim()) { act(`/api/cases/${c.id}/note`, 'Note added', { text: note }); setNote('') } }} className="mt-4 flex gap-2">
                <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note for the team…"
                       className="min-w-0 flex-1 rounded-full bg-panel-2 px-4 py-2.5 text-sm outline-none" />
                <button className="rounded-full bg-action px-5 py-2.5 text-sm font-semibold text-ink">Add</button>
              </form>
            </Panel>
          </div>
        )}
      </div>
    </div>
  )
}

export function OpsLog({ tick }: { tick: number }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4">
      <Panel title="Everything Odyssey did on its own, and every human decision" right={<span className="text-xs text-mute">hash-chained audit trail</span>}>
        <AutopilotFeed limit={600} tick={tick} height="max-h-[70vh]" />
      </Panel>
    </div>
  )
}

export { SystemView }
