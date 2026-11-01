import { Bell, Eye, EyeOff, Plus, Trash2 } from 'lucide-react'
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { Badge, Pill, Row, Section, Stat, TIERS, TierPill, useToast } from './ui'

/* Watchlists: an analyst watches any entity of the intelligence graph (a technology, a CVE, a C2 address, a threat
   group, an organisation, an asset) with a rule: fresh evidence, a worsening tier, a new connection, or any of those.
   The live engine evaluates every watch every 15 s; a firing is written to the hash-chained audit trail (watch.fired)
   and delivered through the channels. Rules are edge-triggered, so a watch fires on the change, not on every check,
   and every firing names the change that caused it. No LLM is involved. */

type Tier = 'Compromise' | 'Critical' | 'High' | 'Medium' | 'Watch'
type RuleKind = 'any' | 'fresh' | 'tier' | 'connect'
type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

interface Rule { kind: RuleKind; pulse?: number; tier?: Tier }
interface WatchState { pulse?: number; tier?: Tier | null; last_seen?: string | null; degree?: number; risk?: number | null }
interface Firing { ts: string; reason: string; severity: Severity }
interface Watch {
  id: number; created_at: string; owner: string | null; target: string; label: string | null; kind: string | null
  rule: Rule; rule_text: string; note: string | null; status: 'active' | 'paused'
  last_state: WatchState; last_eval: string | null; fired: number; last_fired: string | null; recent: Firing[]
}
interface WatchEvent { id: number; ts: string; watch_id: number; target: string; label: string | null; reason: string; severity: Severity; payload: Record<string, unknown> }
interface Suggestion { target: string; label: string; kind: string; tier: Tier | null; pulse: number; sub: string }
interface WatchData { watches: Watch[]; events: WatchEvent[]; suggestions: Suggestion[]; rules: Record<string, string>; default_rule: Rule }

const KIND_LABEL: Record<string, string> = {
  org: 'Organisation', asset: 'Asset', product: 'Technology', cve: 'Vulnerability', campaign: 'Campaign', technique: 'Technique',
  malware: 'Malware family', actor: 'Threat group', indicator: 'Indicator', supplier: 'Supplier', signal: 'Live signal',
}
const KIND_CODE: Record<string, string> = {
  org: 'ORG', asset: 'HOST', product: 'TECH', cve: 'CVE', campaign: 'CAMP', technique: 'ATT', malware: 'MAL', actor: 'GRP', indicator: 'IOC', supplier: 'SUP', signal: 'LIVE',
}
const RULE_NAME: Record<string, string> = { any: 'Any change', fresh: 'Fresh evidence', tier: 'Worsening tier', connect: 'New connection' }
const SEV_TONE: Record<Severity, 'crit' | 'accent' | 'mute'> = { Critical: 'crit', High: 'crit', Medium: 'accent', Low: 'mute' }
const FALLBACK_RULES: Record<string, string> = {
  any: 'fresh evidence, a worsening tier or a new connection', fresh: 'fresh evidence (pulse rises above the threshold, or new evidence is recorded)',
  tier: 'the worst open tier reaches the threshold or worse', connect: 'a new connection appears in the graph',
}

const kindOf = (target: string, kind?: string | null) => kind || target.split(':', 1)[0]
const kindLabel = (k: string) => KIND_LABEL[k] ?? k
const kindCode = (k: string) => KIND_CODE[k] ?? k.slice(0, 4).toUpperCase()
const when = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }) : '—'
const times = (n: number) => `${n} time${n === 1 ? '' : 's'}`

/* Fetch with the API's error detail attached, so a 404 can be told apart from a bad rule or an outage. */
async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init)
  if (!r.ok) {
    let detail = `${r.status} ${r.statusText}`
    try {
      const j: unknown = await r.json()
      if (typeof j === 'object' && j !== null && typeof (j as { detail?: unknown }).detail === 'string') detail = (j as { detail: string }).detail
    } catch { /* not a JSON body */ }
    throw Object.assign(new Error(detail), { status: r.status })
  }
  return r.json() as Promise<T>
}
function post<T>(url: string, body?: unknown): Promise<T> {
  return call<T>(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
}
const statusOf = (e: unknown): number | undefined =>
  typeof e === 'object' && e !== null && typeof (e as { status?: unknown }).status === 'number' ? (e as { status: number }).status : undefined
const msgOf = (e: unknown) => (e instanceof Error ? e.message : String(e))
/** The message shown to the operator for a failed add: the graph has no such node, the rule is bad, or the API is away. */
const addError = (e: unknown) => (statusOf(e) === 404 ? 'No such entity in the graph' : msgOf(e))
const addWatch = (target: string, rule?: Rule) => post<Watch>('/api/watches', rule ? { target, rule } : { target })

function WatchForm({ rules, defaultRule, onAdd }: { rules: Record<string, string>; defaultRule: Rule; onAdd: (target: string, rule: Rule) => Promise<void> }) {
  const [target, setTarget] = useState('')
  const [kind, setKind] = useState<RuleKind>(defaultRule.kind ?? 'any')
  const [tier, setTier] = useState<Tier>(defaultRule.tier ?? 'Critical')
  const [err, setErr] = useState<string>()
  const [busy, setBusy] = useState(false)
  const kinds = (Object.keys(rules).length ? Object.keys(rules) : Object.keys(FALLBACK_RULES)) as RuleKind[]
  const tierMatters = kind === 'any' || kind === 'tier'
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const t = target.trim()
    if (!t) { setErr('Type a node id, for example product:fortios'); return }
    setBusy(true)
    setErr(undefined)
    onAdd(t, { kind, pulse: defaultRule.pulse ?? 0.5, tier })
      .then(() => setTarget(''))
      .catch((x) => setErr(msgOf(x)))
      .finally(() => setBusy(false))
  }
  const field = 'rounded-full bg-panel-2 px-4 py-2 text-sm outline-none focus:ring-1 focus:ring-text'
  return (
    <form onSubmit={submit}>
      <div className="text-sm font-semibold">Watch an entity</div>
      <p className="mt-0.5 text-xs text-mute">Any node id of the graph; the hover card and the entity card show it. The rule fires on the change, not on every check.</p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="product:fortios · cve:CVE-2026-104935 · actor:G0007" spellCheck={false}
               aria-label="Node id" className={`min-w-[260px] flex-1 font-mono ${field}`} />
        <select value={kind} onChange={(e) => setKind(e.target.value as RuleKind)} aria-label="Rule" className={field}>
          {kinds.map((k) => <option key={k} value={k}>{RULE_NAME[k] ?? k}</option>)}
        </select>
        <select value={tier} onChange={(e) => setTier(e.target.value as Tier)} aria-label="Tier threshold" disabled={!tierMatters}
                title={tierMatters ? 'fires when the worst open tier reaches this or worse' : 'the tier threshold only applies to the tier rules'}
                className={`${field} disabled:opacity-40`}>
          {TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <button type="submit" disabled={busy} className="inline-flex items-center gap-1.5 rounded-full bg-action px-4 py-2 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-40">
          <Plus size={14} /> Add
        </button>
      </div>
      <p className="mt-2 text-xs text-mute">Fires on {rules[kind] ?? FALLBACK_RULES[kind]}{tierMatters ? `; tier threshold ${tier}` : ''}.</p>
      {err && <p className="mt-1 text-sm text-mute">{err}</p>}
    </form>
  )
}

/** The watchlist: what is watched, with which rule, what fired, and the means to add, pause or remove a watch. */
export function Watchlist({ onOpen }: { onOpen?: (nodeId: string) => void }) {
  const [d, setD] = useState<WatchData & { fetched_at: number }>()
  const [err, setErr] = useState<string>()
  const [tick, setTick] = useState(0)
  const [busy, setBusy] = useState<string>()
  const [armed, setArmed] = useState<number>()
  const [showEvents, setShowEvents] = useState(false)
  const armTimer = useRef<number | undefined>(undefined)
  const toast = useToast()
  const refresh = useCallback(() => setTick((t) => t + 1), [])

  useEffect(() => {
    let alive = true
    const pull = () => call<WatchData>('/api/watches')
      .then((x) => { if (!alive) return; setD({ ...x, fetched_at: Date.now() }); setErr(undefined) })
      .catch((e) => alive && setErr(msgOf(e)))
    pull()
    const id = window.setInterval(pull, 10_000)
    return () => { alive = false; window.clearInterval(id) }
  }, [tick])
  useEffect(() => () => window.clearTimeout(armTimer.current), [])

  const add = async (target: string, rule?: Rule): Promise<void> => {
    if (busy) return
    setBusy(target)
    try {
      const w = await addWatch(target, rule)
      toast(`Watching ${w.label ?? target}`)
      refresh()
    } catch (e) {
      throw new Error(addError(e))
    } finally {
      setBusy(undefined)
    }
  }
  const act = (w: Watch, action: 'pause' | 'resume' | 'delete') => {
    const name = w.label ?? w.target
    setBusy(`#${w.id}`)
    post<{ watch: Watch | null; status: string }>(`/api/watches/${w.id}/${action}`)
      .then(() => { toast(action === 'delete' ? `Removed ${name}` : action === 'pause' ? `Paused ${name}` : `Resumed ${name}`); refresh() })
      .catch((e) => toast(msgOf(e)))
      .finally(() => setBusy(undefined))
  }
  /* Remove asks for a second click within five seconds instead of a browser dialog. */
  const remove = (w: Watch) => {
    window.clearTimeout(armTimer.current)
    if (armed === w.id) { setArmed(undefined); act(w, 'delete'); return }
    setArmed(w.id)
    armTimer.current = window.setTimeout(() => setArmed(undefined), 5000)
  }

  const watches = d?.watches ?? []
  const events = d?.events ?? []
  const suggestions = d?.suggestions ?? []
  const active = watches.filter((w) => w.status === 'active').length
  const paused = watches.filter((w) => w.status === 'paused').length
  const dayAgo = (d?.fetched_at ?? 0) - 24 * 3600_000   // measured from the fetch, so a render never reads the clock
  const fired24 = events.filter((e) => new Date(e.ts).getTime() >= dayAgo).length
  const fired24Text = events.length >= 40 && fired24 === events.length ? `${fired24}+` : fired24
  const lastFired = watches.reduce<string | null>((m, w) => (w.last_fired && (!m || w.last_fired > m) ? w.last_fired : m), null)
  const small = 'inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-semibold transition disabled:opacity-40'

  return (
    <Section title="Watchlist"
             sub="Watch any entity of the graph; a rule fires on fresh evidence, a worsening tier or a new connection, is written to the audit trail and delivered through the channels.">
      <div className="grid grid-cols-3 gap-3">
        <Stat value={d ? active : '…'} label="Active watches" sub={d ? `evaluated every 15 s · ${watches.length} in all` : 'reading the watchlist'} />
        <Stat value={d ? fired24Text : '…'} label="Fired in the last 24 h" sub={lastFired ? `last at ${when(lastFired)}` : 'nothing fired yet'} />
        <Stat value={d ? paused : '…'} label="Paused" sub="kept, not evaluated" />
      </div>
      {err && <p className="mt-3 text-sm text-mute">Could not read the watchlist ({err}). {d ? 'Showing the last state.' : 'Retrying every 10 s.'}</p>}
      {!d && !err && <p className="mt-3 text-sm text-mute">Reading the watchlist…</p>}

      <div className="mt-8 grid gap-10 xl:grid-cols-[1.15fr_1fr]">
        <div className="min-w-0">
          <div className="text-sm font-semibold">Suggested now</div>
          <p className="mt-0.5 text-xs text-mute">The riskiest technologies and vulnerabilities, every C2 address seen, the active campaigns and the closest threat group that are not watched yet. One click adds the default rule.</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {suggestions.map((s) => (
              <Pill key={s.target} onClick={() => add(s.target).catch((e) => toast(msgOf(e)))}>
                <Plus size={14} /> {s.label} <span className="text-xs text-mute">{kindLabel(s.kind)}</span>
              </Pill>
            ))}
            {d && suggestions.length === 0 && <span className="text-sm text-mute">Everything worth watching right now is already on the list.</span>}
          </div>

          <div className="mt-8 text-sm font-semibold">Watched</div>
          <div className="mt-1">
            {watches.map((w) => {
              const k = kindOf(w.target, w.kind)
              const name = w.label ?? w.target
              const last = w.recent[0]
              const isBusy = busy === `#${w.id}`
              return (
                <Row key={w.id}
                     lead={<span className="text-[9px] font-bold tracking-wide text-mute" title={kindLabel(k)}>{kindCode(k)}</span>}
                     title={<span className="flex items-center gap-2">
                       {onOpen
                         ? <button onClick={() => onOpen(w.target)} title={`Open ${w.target}`} className="truncate text-left hover:underline">{name}</button>
                         : <span className="truncate" title={w.target}>{name}</span>}
                       <span className="shrink-0 rounded-full bg-panel-2 px-2 py-0.5 text-xs font-medium text-mute">{kindLabel(k)}</span>
                       {w.status === 'paused' && <span className="shrink-0 text-xs font-medium text-mute">paused</span>}
                     </span>}
                     sub={`${w.rule_text || FALLBACK_RULES[w.rule.kind] || w.rule.kind} · fired ${times(w.fired)}${last ? ` · ${last.reason}` : ''}`}
                     trail={<span className="flex items-center gap-2">
                       {w.last_state.tier && <TierPill tier={w.last_state.tier} />}
                       <button disabled={isBusy} onClick={() => act(w, w.status === 'active' ? 'pause' : 'resume')}
                               title={w.status === 'active' ? 'Pause: keep the watch, stop evaluating it' : 'Resume evaluating this watch'}
                               className={`${small} bg-panel-2 hover:bg-panel-3`}>
                         {w.status === 'active' ? <><EyeOff size={13} /> Pause</> : <><Eye size={13} /> Resume</>}
                       </button>
                       <button disabled={isBusy} onClick={() => remove(w)}
                               title={armed === w.id ? 'Click again to remove this watch' : 'Remove this watch (asks for a second click)'}
                               className={`${small} ${armed === w.id ? 'bg-action text-ink hover:opacity-85' : 'bg-panel-2 hover:bg-panel-3'}`}>
                         <Trash2 size={13} /> {armed === w.id ? 'Remove?' : 'Remove'}
                       </button>
                     </span>} />
              )
            })}
            {d && watches.length === 0 && (
              <div className="rounded-2xl bg-panel-2 p-5 text-sm text-mute">Nothing is watched yet. Pick a suggestion above, or type a node id on the right.</div>
            )}
          </div>
        </div>

        <div className="flex min-w-0 flex-col gap-8">
          <WatchForm rules={d?.rules ?? FALLBACK_RULES} defaultRule={d?.default_rule ?? { kind: 'any', pulse: 0.5, tier: 'Critical' }} onAdd={add} />

          <div>
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold">Recent firings</div>
                <p className="mt-0.5 text-xs text-mute">Each one is a watch.fired entry in the audit trail and a card in the channels.</p>
              </div>
              <Pill onClick={() => setShowEvents((v) => !v)}>{showEvents ? 'Hide' : `Show ${events.length}`}</Pill>
            </div>
            {showEvents && (
              <div className="mt-2">
                {events.map((e) => (
                  <Row key={e.id}
                       lead={<Bell size={15} className="text-mute" />}
                       title={<span className="flex items-center gap-2">
                         <Badge tone={SEV_TONE[e.severity] ?? 'mute'}>{e.severity}</Badge>
                         {onOpen
                           ? <button onClick={() => onOpen(e.target)} title={`Open ${e.target}`} className="truncate text-left hover:underline">{e.label ?? e.target}</button>
                           : <span className="truncate" title={e.target}>{e.label ?? e.target}</span>}
                       </span>}
                       sub={e.reason}
                       trail={<span className="text-xs text-mute">{when(e.ts)}</span>} />
                ))}
                {d && events.length === 0 && (
                  <div className="rounded-2xl bg-panel-2 p-5 text-sm text-mute">No watch has fired yet. A firing needs a change: new evidence on the entity, a worse tier, or a new connection.</div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </Section>
  )
}

/** A small pill that puts one entity on the watchlist with the default rule, and shows that it is already there. */
export function WatchButton({ target, label }: { target: string; label: string }) {
  /* `known` remembers which target the one GET on mount answered for, so a re-render with a new target never shows a stale state. */
  const [known, setKnown] = useState<{ target: string; watching: boolean }>()
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  useEffect(() => {
    let alive = true
    call<WatchData>('/api/watches')
      .then((d) => { if (alive) setKnown({ target, watching: d.watches.some((w) => w.target === target) }) })
      .catch(() => undefined)
    return () => { alive = false }
  }, [target])
  const on = known?.target === target && known.watching
  const click = () => {
    setBusy(true)
    addWatch(target)
      .then(() => { setKnown({ target, watching: true }); toast(`Watching ${label}`) })
      .catch((e) => toast(addError(e)))
      .finally(() => setBusy(false))
  }
  return (
    <button onClick={click} disabled={on || busy} title={on ? 'On the watchlist: fires on fresh evidence, a worse tier or a new connection' : `Watch ${label}`}
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-semibold transition ${on ? 'bg-panel-2 text-mute' : 'bg-panel-2 text-text hover:bg-panel-3'} ${busy ? 'opacity-60' : ''}`}>
      {on ? <Bell size={13} /> : <Eye size={13} />} {on ? 'Watching' : busy ? 'Watching…' : 'Watch'}
    </button>
  )
}
