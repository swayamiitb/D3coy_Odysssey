import { ExternalLink, Loader2, Siren } from 'lucide-react'
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { istTime } from './proactive'
import { Badge, Prov, Row, Section, Sheet, Stat, Tile, useToast } from './ui'

/* Disaster alerts from NDMA's SACHET, India's national CAP 1.2 alert feed (public domain, read-only). Odyssey reads the
   public RSS every 15 minutes, matches each alert to the states our operators sit in (sender office, state or district
   named, regional script) and asks: is this outage the weather, or an attack? Odyssey emits its own warnings in the same
   CAP format (SACHET-compatible, status Exercise) and validates every inbound CAP on its own loopback endpoint before
   trusting it: flood, size, DTD, form, fields, sender, replay, expiry. The red-team fires ten hostile CAP messages at
   that endpoint only; nothing is ever sent to SACHET or any third party. Feed facts are REAL; red-team runs are SIM
   exercises. No LLM is involved. */

type FeedStatus = 'fresh' | 'snapshot' | 'offline'
type Refusal = 'rate_limited' | 'oversize' | 'xxe' | 'malformed' | 'missing_fields' | 'untrusted_sender' | 'replay' | 'stale'

interface StateMatch { state: string; basis: string; confidence: number }
interface OrgMatch { org_id: string; name: string; sector: string; state: string; basis: string; confidence: number }
interface SachetItem {
  identifier: string; title: string; description: string; category: string; author: string; link: string; published: string
  states: StateMatch[]; orgs: OrgMatch[]
}
interface Decision {
  id: number; ts: string; accepted: boolean; reason: Refusal | null; detail: string | null; identifier: string; sender: string
  status: string | null; msg_type: string | null; event: string; severity: string | null; areas: string[]; states: unknown[]; orgs: unknown[]
  source_ip: string; redteam: string | null; bytes: number
}
interface SachetFeed {
  status: FeedStatus | string; fetched_at: string | null; last_try: string | null; detail: string; ms: number; source: string
  provenance: string; url: string; count: number; matched: number; by_state: Record<string, number>
}
interface SachetView {
  feed: SachetFeed; alerts: SachetItem[]; matched_alerts: SachetItem[]; inbound: Decision[]; decisions: Decision[]
  ingest: { accepted: number; refused: Record<Refusal, number>; total: number }
  trusted: { domains: string[]; prefixes: string[]; own: string }
  limits: { max_bytes: number; rate_per_minute: number }
  how: string; endpoint: string; provenance: { feed: string; inbound: string }
}
interface CapInfo {
  language: string; category: string; event: string; urgency: string; severity: string; certainty: string
  headline: string; description: string; instruction: string; expires: string | null; areas: string[]
}
interface CapAlert {
  identifier: string; sender: string; sent: string; status: string; msgType: string; scope: string; references: string
  expires: string | null; namespace: string; infos: CapInfo[]; states: StateMatch[]
}
interface RedteamCase { name: string; what: string; expected: string; got: string; pass: boolean; ms: number; technique: string | null; cwe: string | null }
interface RedteamResult {
  run_id: string; target: string; cases: RedteamCase[]; passed: number; total: number; planted_secret_leaked: boolean
  seconds: number; label: string; how: string
}

const FEED_URL = '/api/sachet?live=true&limit=40'
const REFUSALS: Refusal[] = ['rate_limited', 'oversize', 'xxe', 'malformed', 'missing_fields', 'untrusted_sender', 'replay', 'stale']
const REFUSAL_LABEL: Record<Refusal, string> = {
  rate_limited: 'flood cap', oversize: 'oversize', xxe: 'XXE / entity declaration', malformed: 'malformed',
  missing_fields: 'missing fields', untrusted_sender: 'untrusted sender', replay: 'replay', stale: 'stale',
}
const CASE_LABEL: Record<string, string> = {
  xxe_external_entity: 'XXE external entity', billion_laughs: 'Billion laughs', forged_sender: 'Forged sender', legitimate: 'Legitimate',
  replay: 'Replay', stale: 'Stale', malformed: 'Malformed', oversize: 'Oversize', stored_script: 'Stored script', flood: 'Flood',
}

const fmt = (n: number | null | undefined) => (n == null ? '—' : n.toLocaleString('en-IN'))
const when = (iso: string | null | undefined) => (iso ? istTime(iso) : '—')
const trim110 = (s: string) => (s.length > 110 ? `${s.slice(0, 109).trimEnd()}…` : s)
const humanise = (name: string) => CASE_LABEL[name] ?? name.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
/** "controlroom@ndma.gov.in (IMD Chennai)" → "(IMD Chennai)"; empty when the author names no office. */
const office = (author: string) => { const m = /\(([^)]+)\)\s*$/.exec(author || ''); return m ? `(${m[1]})` : '' }
const sumRefused = (r: Record<string, number> | undefined) => Object.values(r ?? {}).reduce((a, b) => a + b, 0)
const refusalLabel = (r: string | null) => (r ? REFUSAL_LABEL[r as Refusal] ?? r : 'refused')

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init)
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    throw new Error(typeof body?.detail === 'string' ? body.detail : `HTTP ${r.status}`)
  }
  return r.json() as Promise<T>
}

/** Small grey chip; mono for senders and identifiers. */
function Chip({ children, mono, title }: { children: ReactNode; mono?: boolean; title?: string }) {
  return (
    <span title={title} className={`inline-flex items-center gap-1 rounded-full bg-panel-2 px-2.5 py-0.5 text-xs font-medium text-mute ${mono ? 'font-mono' : ''}`}>
      {children}
    </span>
  )
}

/** Feed health on one line: a dot (green = read live, grey = snapshot or offline), the figures, then the states the feed covers. */
function StatusLine({ feed }: { feed: SachetFeed }) {
  const fresh = feed.status === 'fresh'
  const word = fresh ? 'live' : feed.status === 'snapshot' ? 'snapshot' : 'offline'
  const states = Object.entries(feed.by_state ?? {}).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 8)
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        <span className={`h-2 w-2 shrink-0 rounded-full ${fresh ? 'bg-ok' : 'bg-faint'}`} />
        <span className="font-medium">{word}</span>
        <span className="text-mute">{fmt(feed.count)} alerts · {fmt(feed.matched)} touch an operator · read {when(feed.fetched_at)}</span>
        {!fresh && feed.detail && <span className="text-faint">· {feed.detail}</span>}
      </div>
      {states.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {states.map(([state, n]) => (
            <span key={state} className="inline-flex items-center gap-1.5 rounded-full bg-panel-2 px-3 py-1 text-xs font-medium">
              {state}: <span className="text-mute tabular-nums">{fmt(n)}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

/** One matched alert: category in the circle, the title as the feed gives it (regional scripts included), the match on one line,
    the operators concerned on the right. */
function AlertRow({ a, onClick }: { a: SachetItem; onClick: () => void }) {
  const st = [...a.states].sort((x, y) => y.confidence - x.confidence)[0]
  const names = [...new Set(a.orgs.map((o) => o.name))]
  const sub = [st?.state, st?.basis, when(a.published), office(a.author)].filter(Boolean).join(' · ')
  return (
    <Row onClick={onClick}
         lead={<span className="text-[10px] font-semibold uppercase tracking-wide">{a.category || '—'}</span>}
         title={<span dir="auto" title={a.title}>{trim110(a.title)}</span>}
         sub={sub}
         trail={names.length > 0 ? (
           <span className="flex items-center gap-1">
             {names.slice(0, 3).map((n) => <Chip key={n}>{n}</Chip>)}
             {names.length > 3 && <Chip title={names.slice(3).join(', ')}>+{names.length - 3}</Chip>}
           </span>
         ) : undefined} />
  )
}

function Fact({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-mute">{label}</div>
      <div className={`mt-0.5 break-all text-sm ${mono ? 'font-mono' : ''}`}>{value || '—'}</div>
    </div>
  )
}

/** One <info> block of a CAP message, every field as text: the headline may carry anything the sender wrote. */
function InfoBlock({ info, i }: { info: CapInfo; i: number }) {
  return (
    <div className="rounded-2xl bg-panel-2 p-5">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="accent">{info.language || 'language not given'}</Badge>
        {info.category && <Chip>{info.category}</Chip>}
        {info.event && <Chip>{info.event}</Chip>}
        {info.severity && <Chip>severity {info.severity}</Chip>}
        {info.urgency && <Chip>urgency {info.urgency}</Chip>}
        {info.certainty && <Chip>certainty {info.certainty}</Chip>}
        <span className="ml-auto text-xs text-faint">info {i + 1}</span>
      </div>
      <p dir="auto" className="mt-3 font-semibold leading-snug">{info.headline || <span className="text-mute">No headline</span>}</p>
      {info.description && <p dir="auto" className="mt-2 whitespace-pre-wrap text-sm">{info.description}</p>}
      {info.instruction && (
        <div className="mt-3">
          <div className="text-xs text-mute">Instruction</div>
          <p dir="auto" className="mt-0.5 whitespace-pre-wrap text-sm">{info.instruction}</p>
        </div>
      )}
      <div className="mt-3">
        <div className="text-xs text-mute">Areas</div>
        {info.areas.length === 0
          ? <p className="mt-0.5 text-sm text-mute">No area named.</p>
          : <ul className="mt-0.5 list-inside list-disc text-sm">{info.areas.map((ar, k) => <li key={k} dir="auto">{ar}</li>)}</ul>}
      </div>
      {info.expires && <div className="mt-3 text-xs text-mute">Expires {when(info.expires)} IST</div>}
    </div>
  )
}

/** The full CAP message behind a feed item, fetched from sachet.ndma.gov.in only; a refusal is shown as the server's reason. */
function AlertSheet({ item, onClose }: { item: SachetItem; onClose: () => void }) {
  const [cap, setCap] = useState<CapAlert>()
  const [err, setErr] = useState<string>()
  useEffect(() => {
    let alive = true
    getJson<CapAlert>(`/api/sachet/alert?url=${encodeURIComponent(item.link)}`)
      .then((d) => alive && setCap(d))
      .catch((e: Error) => alive && setErr(e.message))
    return () => { alive = false }
  }, [item.link])
  return (
    <Sheet title="SACHET alert" onClose={onClose}
           sub={<span className="flex flex-wrap items-center gap-2"><span dir="auto">{trim110(item.title)}</span><Prov p="REAL" label="REAL · NDMA SACHET, public domain" /></span>}>
      {err && <div className="rounded-2xl bg-panel-2 p-5 text-mute"><span className="font-semibold text-text">Not fetched.</span> {err}</div>}
      {!err && !cap && <div className="py-6 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Reading the CAP message from sachet.ndma.gov.in…</div>}
      {cap && (
        <div className="flex flex-col gap-8">
          <div className="grid grid-cols-2 gap-x-6 gap-y-4 md:grid-cols-3">
            <Fact label="Identifier" value={cap.identifier} mono />
            <Fact label="Sender" value={cap.sender} mono />
            <Fact label="Sent" value={cap.sent ? `${when(cap.sent)} IST` : ''} />
            <Fact label="Status" value={cap.status} />
            <Fact label="Scope" value={cap.scope} />
            <Fact label="Message type" value={cap.msgType} />
            <Fact label="Expires" value={cap.expires ? `${when(cap.expires)} IST` : ''} />
            <Fact label="States concerned" value={cap.states.map((s) => s.state).join(', ')} />
            <Fact label="Category" value={item.category} />
          </div>
          <div>
            <h3 className="text-xl font-bold">Info blocks</h3>
            <p className="mt-1 text-sm text-mute">Every language the sender published, shown as text exactly as received.</p>
            <div className="mt-3 flex flex-col gap-3">
              {cap.infos.length === 0 && <div className="rounded-2xl bg-panel-2 p-5 text-mute">This message carries no info block.</div>}
              {cap.infos.map((info, i) => <InfoBlock key={i} info={info} i={i} />)}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <a href={item.link} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
              Open on SACHET <ExternalLink size={13} />
            </a>
            <span className="text-xs text-faint">{cap.namespace}</span>
          </div>
        </div>
      )}
    </Sheet>
  )
}

/** One inbound decision on one line: when, accepted or refused and why, who sent it, the identifier, exercise when the red-team sent it. */
function DecisionLine({ d }: { d: Decision }) {
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 border-b border-line py-1.5 text-xs last:border-0" title={d.detail ?? undefined}>
      <span className="tabular-nums text-mute">{istTime(d.ts)}</span>
      <span className="font-medium">{d.accepted ? 'accepted' : `refused · ${refusalLabel(d.reason)}`}</span>
      <span className="max-w-[16rem] truncate text-mute">{d.sender || '—'}</span>
      <span className="max-w-[16rem] truncate font-mono text-mute">{d.identifier || '—'}</span>
      {d.redteam && <Badge>exercise</Badge>}
    </div>
  )
}

/** The SACHET feed, the operators it touches, and the guard that validates every inbound CAP. Polls every 30 s; the API caches 15 min. */
export function SachetPanel({ compact }: { compact?: boolean }) {
  const [view, setView] = useState<SachetView>()
  const [err, setErr] = useState<string>()
  const [open, setOpen] = useState<SachetItem>()
  const [running, setRunning] = useState(false)
  const [rt, setRt] = useState<RedteamResult>()
  const [rtErr, setRtErr] = useState<string>()
  const toast = useToast()

  const refresh = useCallback(() => {
    getJson<SachetView>(FEED_URL).then((d) => { setView(d); setErr(undefined) }).catch((e: Error) => setErr(e.message))
  }, [])
  useEffect(() => {
    let alive = true
    const pull = () => getJson<SachetView>(FEED_URL)
      .then((d) => { if (alive) { setView(d); setErr(undefined) } })
      .catch((e: Error) => alive && setErr(e.message))
    pull()
    const id = setInterval(pull, 30_000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  const runRedteam = () => {
    if (running) return
    setRunning(true)
    setRtErr(undefined)
    getJson<RedteamResult>('/api/sensor/cap/redteam', { method: 'POST' })
      .then((d) => {
        setRt(d)
        toast(`${d.passed}/${d.total} red-team cases passed in ${d.seconds} s · exercise on our own endpoint, nothing sent out`)
        refresh()
      })
      .catch((e: Error) => { setRtErr(e.message); toast(`Red-team did not run: ${e.message}`) })
      .finally(() => setRunning(false))
  }

  const shown = view ? view.matched_alerts.slice(0, compact ? 4 : 8) : []
  const refused = view ? sumRefused(view.ingest.refused) : 0
  const decisions = view ? view.decisions.slice(0, 10) : []

  return (
    <>
      <Section title="Disaster alerts (SACHET)"
               sub="India's national CAP alert feed, read every 15 minutes and matched to the operators' states: is this outage the weather, or an attack? Odyssey also emits its own warnings in the same CAP format and validates every inbound CAP before trusting it."
               action={<Prov p="REAL" label="REAL · NDMA SACHET, public domain, read-only" />}>
        {err && !view && <div className="rounded-2xl bg-panel-2 p-5 text-mute">The SACHET reader is not answering yet: {err}. Retrying every 30 s.</div>}
        {!err && !view && <div className="py-6 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Reading the SACHET feed…</div>}
        {view && (
          <div className="flex flex-col gap-10">
            {/* (a) feed health */}
            <StatusLine feed={view.feed} />

            {/* (b) figures */}
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Stat value={fmt(view.feed.matched)} label="Alerts touching operators" sub={`of ${fmt(view.feed.count)} in the feed`} />
              <Stat value={fmt(view.ingest.accepted)} label="Inbound CAP accepted" sub="validated, then drawn on the graph" />
              <Stat value={fmt(refused)} label="Inbound CAP refused" sub={`of ${fmt(view.ingest.total)} received`} />
              <Stat value="8" label="Guard checks" sub="flood, size, DTD, form, fields, sender, replay, expiry" />
            </div>

            {/* (c) matched alerts */}
            <div>
              <h3 className="text-xl font-bold">Alerts on our operators' states</h3>
              <p className="mt-1 text-sm text-mute">Matched on the sender's office, a state or district named, or the script the alert is written in. Open one for the full CAP message.</p>
              <div className="mt-2">
                {shown.length === 0 && <div className="rounded-2xl bg-panel-2 p-5 text-mute">No SACHET alert touches an operator's state right now.</div>}
                {shown.map((a, i) => <AlertRow key={`${a.identifier}-${i}`} a={a} onClick={() => setOpen(a)} />)}
              </div>
              {view.matched_alerts.length > shown.length && (
                <p className="mt-2 text-xs text-mute">{fmt(view.matched_alerts.length - shown.length)} more matched alert{view.matched_alerts.length - shown.length === 1 ? '' : 's'} in this read.</p>
              )}
            </div>

            {/* (d) the guard */}
            <div>
              <h3 className="text-xl font-bold">Validate, don't trust</h3>
              <p className="mt-1 text-sm text-mute">Every inbound CAP walks the guard ladder before Odyssey trusts it; every decision is in the audit trail. The red-team fires ten hostile messages at Odyssey's own loopback endpoint and nothing else.</p>
              <div className="mt-4 grid gap-8 xl:grid-cols-2">
                <div>
                  <h4 className="text-sm font-medium">Refused, by reason</h4>
                  <ul className="mt-1 divide-y divide-line">
                    {REFUSALS.map((r) => (
                      <li key={r} className="flex items-center justify-between py-1.5 text-sm">
                        <span>{REFUSAL_LABEL[r]}</span>
                        <span className="tabular-nums text-mute">{fmt(view.ingest.refused[r] ?? 0)}</span>
                      </li>
                    ))}
                  </ul>
                  <h4 className="mt-6 text-sm font-medium">Trusted senders</h4>
                  <p className="mt-1 text-xs text-mute">Agency domains and identifier prefixes an inbound CAP must come from; anything else is refused as an untrusted sender.</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {view.trusted.domains.map((d) => <Chip key={d} mono title="trusted domain">{d}</Chip>)}
                    {view.trusted.prefixes.map((p) => <Chip key={p} mono title="trusted identifier prefix">{p}</Chip>)}
                    {view.trusted.own && <Chip mono title="Odyssey's own sender">{view.trusted.own}</Chip>}
                  </div>
                  <p className="mt-3 text-xs text-faint">Limits: {Math.round(view.limits.max_bytes / 1048576)} MB per message, {view.limits.rate_per_minute} per minute per source. Endpoint {view.endpoint}.</p>
                </div>

                <div>
                  <button disabled={running} onClick={runRedteam} title="Ten hostile CAP messages against Odyssey's own loopback endpoint; logged as an exercise"
                          className="inline-flex items-center gap-2 rounded-full bg-action px-6 py-3 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-40">
                    {running ? <Loader2 size={16} className="animate-spin" /> : <Siren size={16} />}Run the CAP red-team
                  </button>
                  {running && <p className="mt-3 text-sm text-mute"><Loader2 size={14} className="mr-1 inline animate-spin" />Firing 10 hostile alerts at our own endpoint…</p>}
                  {rtErr && !running && <p className="mt-3 text-sm text-mute">The red-team did not run: {rtErr}</p>}
                  {!rt && !running && !rtErr && (
                    <p className="mt-3 text-sm text-mute">XXE, billion laughs, a forged sender, a replay, a stale alert, malformed XML, a 3 MB body, a stored script, a flood, and one legitimate alert that must get through. Under two seconds, loopback only.</p>
                  )}
                  {rt && !running && (
                    <div className="mt-4">
                      <div className="text-sm font-medium">{rt.passed}/{rt.total} cases passed · {rt.seconds} s · planted secret leaked: {rt.planted_secret_leaked ? 'yes' : 'no'}</div>
                      <div className="mt-1 text-xs text-mute">{rt.label} · {rt.how}</div>
                      <div className="mt-2">
                        {rt.cases.map((c) => (
                          <Row key={c.name}
                               lead={<span className={`h-3 w-3 rounded-full ${c.pass ? 'bg-ok' : 'bg-crit'}`} />}
                               title={<span title={`${humanise(c.name)} · ${c.what}`}>{humanise(c.name)} · {c.what}</span>}
                               sub={[`expected ${c.expected}, got ${c.got}`, c.cwe, c.technique].filter(Boolean).join(' · ')}
                               trail={<span className="font-mono text-xs text-mute">{c.ms} ms</span>} />
                        ))}
                      </div>
                    </div>
                  )}

                  <h4 className="mt-6 text-sm font-medium">Recent decisions</h4>
                  <p className="mt-1 text-xs text-mute">The last ten inbound CAP messages and what the guard decided. <span className="text-faint">{view.provenance.inbound}.</span></p>
                  <div className="mt-1">
                    {decisions.length === 0 && <div className="py-3 text-sm text-mute">No inbound CAP yet. Run the red-team to exercise the guard.</div>}
                    {decisions.map((d) => <DecisionLine key={d.id} d={d} />)}
                  </div>
                </div>
              </div>
            </div>

            {/* (e) footer */}
            <p className="text-xs text-mute">Odyssey's own warnings download as CAP 1.2 from any warning sheet (SACHET-compatible, status Exercise). Nothing is sent to SACHET.</p>
          </div>
        )}
      </Section>
      {open && <AlertSheet item={open} onClose={() => setOpen(undefined)} />}
    </>
  )
}

/** A grey suggestion tile for another screen: how many SACHET alerts touch an operator right now, one line, Open. */
export function DisasterTile({ onOpen }: { onOpen: () => void }) {
  const [matched, setMatched] = useState<number>()
  useEffect(() => {
    let alive = true
    getJson<SachetView>('/api/sachet?live=true&limit=1').then((d) => alive && setMatched(d.feed.matched)).catch(() => undefined)
    return () => { alive = false }
  }, [])
  return (
    <Tile value={matched == null ? '—' : fmt(matched)} title="Disaster alerts (SACHET)"
          sub="live national CAP feed matched to our operators' states; inbound CAP validated" cta="Open" onClick={onOpen} />
  )
}
