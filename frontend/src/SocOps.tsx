import { Check, ClipboardCopy, Loader2, ShieldAlert, Wrench } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type AlertRow, type Soc, type Tier } from './api'
import { Heatmap, type HeatData } from './Heatmap'
import { Countdown } from './Now'
import { AdaptiveSection } from './Adaptive'
import { ApprovalQueue, AutopilotFeed, istTime } from './proactive'
import { Rewind } from './Rewind'
import { SystemView } from './SystemView'
import { deadlineText, Pill, Row, Section, Sheet, TIER_FILL, TierPill, Tile, useToast } from './ui'

/* The SOC, Uber-simple: each tab answers one question with one main thing on screen; everything else is a tile that
   opens a sheet. */

/* eslint-disable @typescript-eslint/no-explicit-any */
type Case = any

const STATUS_LABEL: Record<string, string> = { new: 'New', in_progress: 'In progress', contained: 'Contained', resolved: 'Resolved', false_positive: 'False positive' }
const initials = (name: string) => name.split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase()

async function post(path: string, body?: unknown) {
  const res = await fetch(path, { method: 'POST', headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined })
  if (!res.ok) throw new Error((await res.json()).detail ?? res.statusText)
  return res.json()
}

const Spin = ({ text }: { text: string }) => <div className="py-10 text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />{text}</div>

export function OpsOverview({ tick, onCases, onWarnings }: { tick: number; onCases: () => void; onWarnings: () => void }) {
  const [d, setD] = useState<Soc>()
  const [m, setM] = useState<any>()
  const [heat, setHeat] = useState<Record<string, HeatData>>()
  const [hand, setHand] = useState<string>()
  const [sheet, setSheet] = useState<'decisions' | 'replay' | 'handover'>()
  const [stamp, setStamp] = useState(0)
  const toast = useToast()
  useEffect(() => {
    api.soc().then(setD).catch(() => undefined)
    fetch('/api/soc/metrics').then((r) => r.json()).then(setM).catch(() => undefined)
  }, [tick, stamp])
  useEffect(() => { fetch('/api/heatmaps').then((r) => r.json()).then(setHeat).catch(() => undefined) }, [tick])
  if (!d || !m) return <Spin text="Opening the SOC…" />
  const auto = d.autopilot.by_mode?.auto ?? 0
  const now = d.pressure.at(-1)
  const openNow = now ? now.Compromise + now.Critical + now.High : 0
  const warnings = (d.tiers.Compromise ?? 0) + (d.tiers.Critical ?? 0) + (d.tiers.High ?? 0) + (d.tiers.Medium ?? 0)
  const writeHandover = () => {
    setSheet('handover')
    fetch('/api/soc/handover').then((r) => r.json()).then((h) => setHand(h.text)).catch(() => undefined)
  }

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-14">
      <div className="grid gap-12 xl:grid-cols-[1.3fr_1fr]">
        <Section title="Needs your decision" sub="Odyssey proposes; a person approves anything consequential."
                 action={<Pill onClick={() => setSheet('decisions')}>See all {d.pending}</Pill>}>
          <ApprovalQueue limit={1} hideMore onChanged={() => setStamp((s) => s + 1)} />
        </Section>
        <Section title="Team on shift" action={<Pill onClick={onCases}>Open cases</Pill>}>
          <div>
            {m.analysts.map((a: any) => (
              <Row key={a.id} lead={<span className="text-xs font-bold">{a.name === 'You' ? 'AN' : initials(a.name)}</span>}
                   title={a.name} sub={a.role}
                   trail={<span><b className="tabular-nums">{a.open}</b> <span className="text-mute">open</span>{a.overdue ? <span className="block text-xs font-medium text-crit">{a.overdue} overdue</span> : null}</span>} />
            ))}
          </div>
        </Section>
      </div>

      {heat && (
        <Section title="Odyssey at work, day by day" sub={`${auto.toLocaleString('en-IN')} actions on its own since go-live on ${d.autopilot.go_live}; people decided the rest.`}>
          <Heatmap data={heat.autopilot} hue="accent" unit="actions" labelW={180} />
        </Section>
      )}

      <AdaptiveSection />

      <div className="grid gap-4 md:grid-cols-3">
        <Tile value={openNow} title="Replay the last 90 days" sub="open warnings day by day, and when each was raised" cta="Replay" onClick={() => setSheet('replay')} />
        <Tile value={m.open} title="Write the shift handover" sub="open cases, SLA breaches and decisions, from the live state" cta="Write handover" onClick={writeHandover} />
        <Tile value={warnings.toLocaleString('en-IN')} title="Every warning, ranked by risk" sub="filter by tier and sector, open any for its evidence" cta="Open the list" onClick={onWarnings} />
      </div>

      {sheet === 'decisions' && (
        <Sheet title={`Needs your decision · ${d.pending}`} sub="Predictions, escalations and advisory notices wait here until a person approves or rejects them." onClose={() => setSheet(undefined)}>
          <ApprovalQueue limit={1000} onChanged={() => setStamp((s) => s + 1)} />
        </Sheet>
      )}
      {sheet === 'replay' && (
        <Sheet wide title="Open warnings, day by day" sub="Press replay to watch the SOC's last 90 days." onClose={() => setSheet(undefined)}>
          <Rewind d={d} />
        </Sheet>
      )}
      {sheet === 'handover' && (
        <Sheet title="Shift handover" sub="What the next shift must know, written from the live state." onClose={() => setSheet(undefined)}>
          {hand ? (
            <>
              <pre className="whitespace-pre-wrap rounded-2xl bg-panel-2 p-5 font-sans text-[15px] leading-relaxed">{hand}</pre>
              <button onClick={() => { navigator.clipboard?.writeText(hand); toast('Handover copied') }}
                      className="mt-4 flex items-center gap-2 rounded-full bg-action px-5 py-3 font-semibold text-ink hover:opacity-85"><ClipboardCopy size={16} /> Copy handover</button>
            </>
          ) : <Spin text="Writing the handover…" />}
        </Sheet>
      )}
    </div>
  )
}

const TIER_CHIPS: [Tier | undefined, string][] = [[undefined, 'All'], ['Compromise', 'Compromise'], ['Critical', 'Critical'], ['High', 'High'], ['Medium', 'Medium']]
const SECTORS = ['Power & Energy', 'BFSI', 'Telecom', 'Transport', 'Government', 'Strategic & Public Enterprises']

/** Every warning as one ranked list: chips for tier, a pill for sector, rows that open the evidence sheet. */
export function WarningList({ tick, onOpen }: { tick: number; onOpen: (orgId: string, cveId: string) => void }) {
  const [tier, setTier] = useState<Tier>()
  const [sector, setSector] = useState<string>()
  const [rows, setRows] = useState<AlertRow[]>()
  const [shown, setShown] = useState(25)
  useEffect(() => {
    api.alerts({ tier, sector }).then((all) => setRows(all.filter((r) => r.tier !== 'Watch'))).catch(() => setRows([]))
  }, [tier, sector, tick])
  return (
    <div className="min-w-0 flex-1">
      <Section title="Every warning, ranked by risk" sub="Highest risk first. Open any warning for its evidence, brief and actions.">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          {TIER_CHIPS.map(([t, label]) => (
            <button key={label} onClick={() => { setTier(t); setShown(25) }}
                    className={`rounded-full px-4 py-2 text-[15px] font-medium ${tier === t ? 'bg-action text-ink' : 'bg-panel-2 hover:bg-panel-3'}`}>{label}</button>
          ))}
          <span className="mx-1 h-6 w-px bg-line" />
          <select value={sector ?? ''} onChange={(e) => { setSector(e.target.value || undefined); setShown(25) }}
                  className={`rounded-full px-4 py-2 text-[15px] font-medium outline-none ${sector ? 'bg-action text-ink' : 'bg-panel-2 hover:bg-panel-3'}`}>
            <option value="">All sectors</option>
            {SECTORS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        {!rows ? <Spin text="Ranking warnings…" /> : (
          <div className="max-w-5xl">
            {rows.slice(0, shown).map((r) => (
              <Row key={r.id} onClick={() => onOpen(r.org_id, r.cve_id)}
                   lead={<span className="h-3 w-3 rounded-full" style={{ background: TIER_FILL[r.tier] }} />}
                   title={<span><span className="font-mono text-sm">{r.cve_id}</span> <span className="text-mute">·</span> {r.title}</span>}
                   sub={`${r.org_name} · ${r.sector} · ${r.assets} asset${r.assets === 1 ? '' : 's'}${r.kev ? ' · exploited in the wild' : ''}`}
                   trail={<span><b className="tabular-nums">{Math.round(r.risk)}</b> <span className="text-mute">risk</span><span className="block text-xs text-mute">due {deadlineText(r.deadline_hours)}</span></span>} />
            ))}
            <div className="mt-4 flex items-center gap-3 text-sm text-mute">
              Showing {Math.min(shown, rows.length)} of {rows.length.toLocaleString('en-IN')}
              {shown < rows.length && <Pill onClick={() => setShown(shown + 50)}>Show more</Pill>}
            </div>
          </div>
        )}
      </Section>
    </div>
  )
}

export function CaseBoard({ tick, onAlert }: { tick: number; onAlert: (orgId: string, cveId: string) => void }) {
  const [filter, setFilter] = useState<'open' | 'mine' | 'unassigned' | 'overdue' | 'closed'>('open')
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
      const out = filter === 'overdue' ? rows.filter((x) => x.overdue) : rows
      setList(out)
      if (!sel && out[0]) setSel(out[0].id)
    }).catch(() => setList([]))
  }, [filter, tick, stamp]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (sel) fetch(`/api/cases/${sel}`).then((r) => r.json()).then(setC).catch(() => undefined) }, [sel, stamp])

  const act = (path: string, msg: string, body?: unknown) => {
    setBusy(true)
    post(path, body).then(() => { toast(msg); setStamp((s) => s + 1) }).catch((e) => toast(String(e))).finally(() => setBusy(false))
  }
  const open = c && c.status !== 'resolved' && c.status !== 'false_positive'

  return (
    <div className="flex min-w-0 flex-1 items-start gap-10">
      <div className="sticky top-24 flex max-h-[calc(100vh-7rem)] w-[440px] shrink-0 flex-col">
        <div className="mb-4 flex flex-wrap gap-2">
          {([['open', 'Open'], ['mine', 'Mine'], ['unassigned', 'Unassigned'], ['overdue', 'Overdue'], ['closed', 'Closed']] as const).map(([k, l]) => (
            <button key={k} onClick={() => { setFilter(k); setSel(undefined) }}
                    className={`rounded-full px-3.5 py-1.5 text-sm font-medium ${filter === k ? 'bg-action text-ink' : 'bg-panel-2 hover:bg-panel-3'}`}>{l}</button>
          ))}
        </div>
        <div className="min-h-0 flex-1 overflow-auto pr-1">
          {!list && <div className="text-sm text-mute">Loading cases…</div>}
          {list?.length === 0 && <div className="rounded-2xl bg-panel-2 p-5 text-mute">No cases here.</div>}
          {list?.map((x) => (
            <button key={x.id} onClick={() => setSel(x.id)}
                    className={`mb-1 flex w-full items-center gap-3 rounded-2xl px-3 py-3 text-left ${sel === x.id ? 'bg-panel-2' : 'hover:bg-soft'}`}>
              <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${x.kind === 'incident' ? 'bg-comp text-white' : 'bg-panel-2 text-text'}`}>
                {x.kind === 'incident' ? <ShieldAlert size={17} /> : <Wrench size={16} />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-semibold">{x.title}</span>
                <span className="block truncate text-sm text-mute">{x.org_name}</span>
              </span>
              <span className={`shrink-0 text-xs font-semibold ${x.overdue ? 'text-crit' : 'text-mute'}`}>{x.overdue ? 'overdue' : STATUS_LABEL[x.status]}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="min-w-0 max-w-4xl flex-1">
        {!c ? <div className="p-8 text-mute">Select a case.</div> : (
          <div className="flex flex-col gap-10">
            <div>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <TierPill tier={c.severity} />
                <span className="rounded-full bg-panel-2 px-2.5 py-0.5 text-xs font-medium">{STATUS_LABEL[c.status]}</span>
                <span className="text-sm text-mute">{c.id} · {c.kind === 'incident' ? 'incident response' : 'remediation'}</span>
              </div>
              <h2 className="min-w-0 break-words text-[28px] font-semibold leading-tight tracking-tight">{c.title}</h2>
              <p className="mt-2 text-lg text-mute">{c.org_name}{c.assets?.length ? ` · ${c.assets.slice(0, 2).join(', ')}${c.assets.length > 2 ? ` +${c.assets.length - 2} more` : ''}` : ''}</p>
              <div className="mt-6 rounded-3xl bg-panel-2 p-6">
                {open && c.due_at ? (
                  <><Countdown issuedAt={c.due_at} hours={0} big /><div className="text-mute">{c.overdue ? 'past the SLA' : 'left on the SLA'} · owner {c.roster.find((a: any) => a.id === c.owner)?.name ?? 'nobody yet'}</div></>
                ) : <div className="text-2xl font-bold text-ok">Closed {c.resolved_at ? istTime(c.resolved_at) : ''}</div>}
                <div className="mt-5 flex flex-wrap items-center gap-2">
                  {c.next && (
                    <button disabled={busy} onClick={() => act(`/api/cases/${c.id}/advance`, `${c.id}: ${c.next.label}`)}
                            className="rounded-full bg-action px-7 py-3.5 text-base font-semibold text-ink hover:opacity-85 disabled:opacity-50">{c.next.label}</button>
                  )}
                  {open && c.owner !== 'analyst@ncew' && (
                    <button disabled={busy} onClick={() => act(`/api/cases/${c.id}/assign?owner=analyst@ncew`, 'Assigned to you')}
                            className="rounded-full bg-panel px-5 py-3.5 font-semibold hover:bg-panel-3">Assign to me</button>
                  )}
                  <select value={c.owner ?? ''} onChange={(e) => act(`/api/cases/${c.id}/assign?owner=${encodeURIComponent(e.target.value)}`, `Assigned to ${c.roster.find((a: any) => a.id === e.target.value)?.name ?? 'nobody'}`)}
                          className="rounded-full bg-panel px-4 py-3.5 text-sm font-medium outline-none hover:bg-panel-3" title="Reassign">
                    <option value="">Unassigned</option>
                    {c.roster.map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}
                  </select>
                  {open ? (
                    <button disabled={busy} onClick={() => act(`/api/cases/${c.id}/advance?to=false_positive`, `${c.id} closed as a false positive`)}
                            className="ml-auto px-3 py-3 text-sm font-medium text-mute hover:text-text">False positive</button>
                  ) : (
                    <button disabled={busy} onClick={() => act(`/api/cases/${c.id}/advance?to=in_progress`, `${c.id} reopened`)}
                            className="rounded-full bg-panel px-5 py-3.5 font-semibold hover:bg-panel-3">Reopen</button>
                  )}
                </div>
              </div>
            </div>

            <Section title="Playbook" sub={`${c.progress.done} of ${c.progress.total} steps done. Tick a step when it is done; it is recorded with your name.`}>
              <div className="mb-2 h-1.5 rounded-full bg-panel-2"><div className="h-1.5 rounded-full bg-ok" style={{ width: `${(100 * c.progress.done) / c.progress.total}%` }} /></div>
              {c.playbook.map((s: any, i: number) => (
                <button key={i} disabled={busy} onClick={() => act(`/api/cases/${c.id}/step?index=${i}&done=${!s.done}`, s.done ? 'Step reopened' : 'Step done')}
                        className="flex w-full items-center gap-4 border-b border-line py-3.5 text-left last:border-0 hover:bg-soft">
                  <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full ${s.done ? 'bg-ok text-white' : 'ring-2 ring-panel-3'}`}>{s.done && <Check size={14} />}</span>
                  <span className="min-w-0 flex-1">
                    <span className={`block ${s.done ? 'text-mute line-through' : ''}`}>{s.step}</span>
                    {s.done && <span className="block text-xs text-mute">{s.by} · {istTime(s.at)}</span>}
                  </span>
                </button>
              ))}
            </Section>

            <Section title="Why this case" sub="The warnings it came from. Open one for the evidence.">
              {c.linked.map((l: any) => (
                <Row key={l.id} onClick={() => onAlert(l.org_id, l.cve_id)} lead={<span className="h-3 w-3 rounded-full" style={{ background: TIER_FILL[(l.tier ?? 'Watch') as Tier] }} />}
                     title={<span><span className="font-mono text-sm">{l.cve_id}</span>{l.kev && <span className="ml-2 text-sm text-crit">exploited in the wild</span>}</span>}
                     sub={l.description} />
              ))}
            </Section>

            <Section title="Notes">
              <form onSubmit={(e) => { e.preventDefault(); if (note.trim()) { act(`/api/cases/${c.id}/note`, 'Note added', { text: note }); setNote('') } }} className="mb-4 flex gap-2">
                <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note for the team…"
                       className="min-w-0 flex-1 rounded-full bg-panel-2 px-5 py-3 outline-none" />
                <button className="rounded-full bg-action px-6 py-3 font-semibold text-ink">Add</button>
              </form>
              {[...c.notes].reverse().slice(0, 6).map((n: any, i: number) => (
                <div key={i} className="flex gap-3 border-b border-line py-3 last:border-0">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-panel-2 text-[11px] font-bold">{n.by === 'Odyssey' ? 'OD' : n.by === 'You' ? 'AN' : initials(n.by)}</span>
                  <div><div className="text-sm"><b>{n.by}</b> <span className="text-mute">· {istTime(n.ts)}</span></div><div>{n.text}</div></div>
                </div>
              ))}
            </Section>
          </div>
        )}
      </div>
    </div>
  )
}

export function OpsLog({ tick }: { tick: number }) {
  return (
    <div className="min-w-0 max-w-5xl flex-1">
      <Section title="Everything Odyssey did" sub="Every action it took on its own and every human decision, newest first. Each entry is hash-chained to the one before.">
        <AutopilotFeed limit={600} tick={tick} height="max-h-[75vh]" />
      </Section>
    </div>
  )
}

export { SystemView }
