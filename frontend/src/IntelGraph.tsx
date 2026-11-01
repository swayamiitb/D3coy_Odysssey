import { ExternalLink, Eye, Loader2 } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import { api, type FactValue, type GraphCard, type GraphNode, type IntelGraph as ApiGraph, type Soc, type Tier } from './api'
import { fmtDate, Pill, Prov, Row, Section, Sheet, Stat, TierPill, useToast } from './ui'

/* The intelligence graph: every entity Odyssey knows about and how they connect, drawn from the record and refreshed
   every 5 seconds. Organisations sit at the centre, then the technologies they run, the vulnerabilities and campaigns
   on those technologies, the ATT&CK techniques and malware families, and on the outer ring the threat groups, the
   indicators, the suppliers and the live signals. Nodes breathe with fresh evidence and lie still as it ages. Nothing
   here is generated: positions are deterministic, every element carries its provenance, and threat groups are
   technique overlap with the ATT&CK record, not attribution.

   Three things sit on top of the drawing. Replay: a slider over the instants /api/graph/replay offers; away from "now"
   the graph is fetched once with as_of=<instant>, later evidence is left out and pulses are aged to it, and the live
   poll resumes when the slider returns to now. Watch: the card's header carries a Watch pill that files the entity on
   the watchlist (/api/watches), which the live engine evaluates every 15 s. Deep link: ?node=<id> (or the initialNode
   prop) opens that entity's card after the first graph load; an id the current graph does not hold still opens, and the
   card says so instead of failing. */

/* Types this file owns: the replay steps and the watchlist rows it reads. api.ts stays as it is. */
type Graph = ApiGraph & { as_of?: string | null }
interface ReplayStep { id: string; label: string; at: string | null }
interface WatchRow { id: number | string; target: string; label: string; status: 'active' | 'paused' }

const W = 1200, H = 720, CX = 600, CY = 360, RMAX = 330, ASPECT = 1.55
const TIER_FILL: Record<string, string> = {
  Compromise: 'var(--color-comp)', Critical: 'var(--color-crit)', High: 'var(--color-high)', Medium: 'var(--color-med)', Watch: 'var(--color-panel-3)',
}
const KIND_LABEL: Record<string, string> = {
  org: 'Organisation', asset: 'Asset', product: 'Technology', cve: 'Vulnerability', campaign: 'Campaign', technique: 'ATT&CK technique',
  malware: 'Malware family', actor: 'Threat group', indicator: 'Indicator', supplier: 'Supplier', signal: 'Live signal',
}
const KIND_CODE: Record<string, string> = {
  org: 'ORG', asset: 'HOST', product: 'TECH', cve: 'CVE', campaign: 'CAMP', technique: 'ATT', malware: 'MAL', actor: 'GRP', indicator: 'IOC', supplier: 'SUP', signal: 'LIVE',
}
const PHASE: Record<string, string> = { fresh: 'fresh, last hour', today: 'today', week: 'this week', fading: 'fading, under 30 days', aged: 'aged' }
const DASH: Record<string, string | undefined> = { REAL: undefined, SIM: '3 3', 'REAL · SIM': '6 3' }
/* Which facts a reader wants per kind, in reading order. Everything else stays on the card's full list. */
const FACTS: Record<string, [string, string][]> = {
  org: [['Open warnings', 'open_warnings'], ['Critical', 'critical'], ['Open cases', 'open_cases'], ['Worst tier', 'worst'], ['Sector', 'sector'], ['State', 'state'], ['Critical Information Infrastructure', 'cii'], ['Domain', 'domain']],
  asset: [['Hostname', 'hostname'], ['Zone', 'zone'], ['Role', 'role'], ['Asset tier', 'asset_tier'], ['Open warnings', 'open_warnings']],
  product: [['Assets', 'assets'], ['Internet-facing assets', 'exposed_assets'], ['Organisations', 'orgs'], ['Open warnings', 'open_warnings'], ['Exploited CVEs', 'exploited_cves']],
  cve: [['Published', 'published'], ['Added to CISA KEV', 'kev_added'], ['KEV due', 'kev_due'], ['Ransomware use', 'ransomware'], ['EPSS', 'epss'], ['SSVC exploitation', 'ssvc_exploitation'], ['Assets', 'assets'], ['Organisations', 'orgs'], ['Flags', 'flags']],
  campaign: [['Status', 'status'], ['First signal', 'first_signal'], ['Last exploitation', 'last_exploit'], ['Early warning (days)', 'early_warning_days'], ['Exploited CVEs', 'cves'], ['Organisations exposed', 'orgs_exposed'], ['Chained assets', 'chained_assets'], ['Decoy surges', 'decoy_surges']],
  technique: [['Tactics', 'tactics'], ['Why it applies', 'rule']],
  malware: [['Family', 'name'], ['ATT&CK software', 'attack_id']],
  actor: [['Also known as', 'aliases'], ['ATT&CK record', 'description'], ['Techniques in common', 'overlap'], ['Malware in common', 'malware'], ['Techniques documented', 'techniques_documented']],
  indicator: [['Type', 'type'], ['Malware', 'malware'], ['Seen from', 'seen_from'], ['Beacon interval (s)', 'interval_s'], ['Source', 'source'], ['Impersonates', 'impersonates']],
  supplier: [['Service', 'service'], ['Dependent organisations', 'dependents'], ['Runs', 'runs'], ['Critical CVEs on what it runs', 'critical_cves']],
  signal: [['Signal', 'signal'], ['When', 'ts'], ['Drill', 'drill'], ['Seconds to detect', 'seconds_to_detect'], ['z-score', 'z'], ['C2', 'c2'], ['Asset', 'asset'], ['First', 'first'], ['Last', 'last'], ['Sensors', 'sensors'], ['Category', 'category'], ['CWE', 'cwe'], ['Decision', 'decision'], ['Path', 'path'], ['Source address', 'source_ip'], ['Application', 'app'], ['Hits', 'hits'], ['Red-team run', 'redteam']],
}
const COUNT_FACTS = new Set(['cves', 'orgs_exposed', 'dependents'])

function fact(key: string, v: FactValue | undefined): string | undefined {
  if (v == null || v === '' || (Array.isArray(v) && v.length === 0)) return undefined
  if (typeof v === 'boolean') return v ? 'Yes' : 'No'
  if (Array.isArray(v)) return COUNT_FACTS.has(key) ? `${v.length}` : v.slice(0, 8).join(', ') + (v.length > 8 ? ` and ${v.length - 8} more` : '')
  if (key === 'epss' && typeof v === 'number') return `${(v * 100).toFixed(1)}% in 30 days`
  if (key === 'ts' && typeof v === 'string') return fmtDate(v)
  if (typeof v === 'number') return Number.isInteger(v) ? v.toLocaleString('en-IN') : v.toFixed(2)
  return String(v)
}

function Facts({ n, compact }: { n: GraphNode; compact?: boolean }) {
  const rows = (FACTS[n.kind] ?? []).map(([label, key]) => [label, fact(key, n.facts[key])] as const).filter((r) => r[1] !== undefined)
  if (!rows.length) return null
  return (
    <dl className={`grid grid-cols-[auto_1fr] gap-x-4 ${compact ? 'gap-y-1 text-xs' : 'gap-y-1.5 text-sm'}`}>
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-mute">{label}</dt>
          <dd className={`min-w-0 break-words ${label === 'ATT&CK record' ? '' : 'font-medium'}`}>{value}</dd>
        </div>
      ))}
    </dl>
  )
}

function Glyph({ kind, fill, size = 10 }: { kind: string; fill: string; size?: number }) {
  const r = size / 2
  const hollow = fill === 'none'
  const stroke = hollow ? 'var(--color-text)' : 'var(--color-panel)'
  const f = hollow ? 'var(--color-panel)' : fill
  return (
    <svg width={size + 4} height={size + 4} viewBox={`${-r - 2} ${-r - 2} ${size + 4} ${size + 4}`} aria-hidden>
      {kind === 'actor' ? <rect x={-r} y={-r} width={size} height={size} transform="rotate(45)" fill={f} stroke={stroke} strokeWidth={1.2} />
        : kind === 'signal' ? <polygon points={`0,${-r * 1.2} ${r * 1.1},${r * 0.8} ${-r * 1.1},${r * 0.8}`} fill={f} stroke={stroke} strokeWidth={1.2} />
        : <circle r={r} fill={f} stroke={stroke} strokeWidth={1.2} />}
    </svg>
  )
}

interface Placed { x: number; y: number; anchor: 'start' | 'end' | 'middle' }
interface Box { x1: number; x2: number; y1: number; y2: number }
const overlaps = (a: Box, b: Box) => a.x1 < b.x2 && b.x1 < a.x2 && a.y1 < b.y2 && b.y1 < a.y2
const textWidth = (s: string, px = 11) => s.length * px * 0.53 + 4
const drawn = (n: GraphNode) => short(n.kind === 'product' ? n.label.replace(/\s*\([^)]*\)\s*$/, '') : n.label, n.kind === 'org' ? 26 : n.kind === 'asset' ? 18 : 30)
const short = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s)

/* Labels are placed greedily, highest priority first, in the first of four slots (beside the node on its outer side,
   then the inner side, below, above) that is inside the drawing and does not cover another label or node. A label
   with no free slot is left to the hover, so nothing is ever drawn on top of something else. */
function placeLabels(items: { id: string; x: number; y: number; text: string; rad: number; cos: number; px: number }[], fixed: Box[]): Record<string, Placed> {
  const placed = [...fixed]
  const out: Record<string, Placed> = {}
  for (const it of items) {
    const w = textWidth(it.text, it.px), d = it.rad + 5, k = it.rad + 3
    const out_: Placed['anchor'] = it.cos >= 0 ? 'start' : 'end', in_: Placed['anchor'] = it.cos >= 0 ? 'end' : 'start'
    const ox = it.cos >= 0 ? 1 : -1
    const cands: [Placed['anchor'], number, number][] = [
      [out_, it.x + ox * d, it.y + 4], [in_, it.x - ox * d, it.y + 4],
      ['middle', it.x, it.y + d + 10], ['middle', it.x, it.y - d - 2],
      [out_, it.x + ox * k, it.y + k + 9], [out_, it.x + ox * k, it.y - k - 1],
      [in_, it.x - ox * k, it.y + k + 9], [in_, it.x - ox * k, it.y - k - 1],
    ]
    for (const [anchor, x, y] of cands) {
      const x1 = anchor === 'start' ? x : anchor === 'end' ? x - w : x - w / 2
      const box = { x1, x2: x1 + w, y1: y - 10, y2: y + 2 }
      if (box.x1 < 2 || box.x2 > W - 2 || box.y1 < 2 || box.y2 > H - 2) continue
      if (placed.some((b) => overlaps(b, box))) continue
      placed.push(box)
      out[it.id] = { x, y, anchor }
      break
    }
  }
  return out
}

const radius = (n: GraphNode) => 4.5 + (n.risk ?? 0) / 20
/* Ring radii by ring index: the inner rings (organisations, technologies) get room for their labels, the outer ring
   stays at the edge. A ring with one node (the organisation in focus) sits at the centre. */
const RADII: Record<number, number[]> = { 5: [0.4, 0.57, 0.76, 0.89, 1], 6: [0.34, 0.5, 0.66, 0.8, 0.9, 1] }
const ringR = (n: GraphNode, rings: number) => (n.r <= 0 ? 0 : (RADII[rings] ?? Array.from({ length: rings }, (_, i) => (i + 1) / rings))[n.ring] ?? 1)
const place = (n: GraphNode, rings: number) => {
  const rr = ringR(n, rings)
  return { x: CX + rr * RMAX * ASPECT * Math.cos(n.angle), y: CY + rr * RMAX * Math.sin(n.angle) }
}

function layout(g: Graph) {
  const pos: Record<string, { x: number; y: number }> = {}
  for (const n of g.nodes) pos[n.id] = place(n, g.rings)
  const ringsOf: Record<number, { r: number; kinds: string[] }> = {}
  for (const n of g.nodes) {
    const e = (ringsOf[n.ring] ??= { r: ringR(n, g.rings), kinds: [] })
    if (!e.kinds.includes(n.kind)) e.kinds.push(n.kind)
  }
  const rings = Object.entries(ringsOf).map(([ring, e]) => ({ ring: Number(ring), r: e.r, label: e.kinds.map((k) => KIND_LABEL[k] ?? k).join(' · ') }))
    .filter((r) => r.r > 0).sort((a, b) => a.r - b.r)
  const fixed: Box[] = g.nodes.map((n) => { const p = pos[n.id], r = radius(n) + 1; return { x1: p.x - r, x2: p.x + r, y1: p.y - r, y2: p.y + r } })
  for (const r of rings) {
    const y = CY - r.r * RMAX - 12, w = textWidth(r.label) * 0.86
    fixed.push({ x1: CX - w / 2, x2: CX + w / 2, y1: y - 9, y2: y + 2 })
  }
  const byRisk = (a: GraphNode, b: GraphNode) => (b.risk ?? 0) - (a.risk ?? 0)
  const prio: Record<string, number> = { org: 0, product: 1, asset: 2 }
  const always = g.nodes.filter((n) => n.kind in prio).sort((a, b) => prio[a.kind] - prio[b.kind] || byRisk(a, b))
  const auto = g.nodes.filter((n) => !(n.kind in prio) && (n.pulse >= 0.5 || n.tier === 'Compromise' || n.tier === 'Critical')).sort(byRisk).slice(0, 18)
  const labels = placeLabels([...always, ...auto].map((n) => ({ id: n.id, ...pos[n.id], text: drawn(n), rad: radius(n), cos: Math.cos(n.angle), px: n.kind === 'org' ? 11 : 10.5 })), fixed)
  return { pos, rings, labels }
}

function curve(a: { x: number; y: number }, b: { x: number; y: number }) {
  const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2
  const cx = mx + (CX - mx) * 0.18, cy = my + (CY - my) * 0.18   // a gentle bow towards the centre keeps parallel edges apart
  return `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`
}

function Shape({ n, r, fill, stroke, strokeWidth, className, style }: { n: GraphNode; r: number; fill: string; stroke: string; strokeWidth: number; className?: string; style?: CSSProperties }) {
  if (n.kind === 'actor') return <rect x={-r} y={-r} width={2 * r} height={2 * r} transform="rotate(45)" fill={fill} stroke={stroke} strokeWidth={strokeWidth} className={className} style={style} />
  if (n.kind === 'signal') return <polygon points={`0,${-r * 1.25} ${r * 1.15},${r * 0.85} ${-r * 1.15},${r * 0.85}`} fill={fill} stroke={stroke} strokeWidth={strokeWidth} className={className} style={style} />
  return <circle r={r} fill={fill} stroke={stroke} strokeWidth={strokeWidth} className={className} style={style} />
}

function provOf(p: string) { return p.startsWith('REAL') ? 'REAL' : 'SIM' }

/* Node ids are built from defanged values already (indicator:50[.]16[.]16[.]211). A hand-typed deep link may not be,
   so an indicator id is defanged once more before it is drawn anywhere. */
function displayId(id: string): string {
  if (!id.startsWith('indicator:')) return id
  return 'indicator:' + id.slice('indicator:'.length).replace(/\[\.\]/g, '.').replace(/\./g, '[.]').replace(/^http/i, 'hxxp')
}

function HoverPanel({ n }: { n: GraphNode }) {
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-lg font-semibold leading-tight">{n.label}</span>
        {n.tier && <TierPill tier={n.tier} />}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-mute">
        <span className="font-semibold uppercase tracking-wide">{KIND_LABEL[n.kind] ?? n.kind}</span>
        <Prov p={provOf(n.provenance)} label={n.provenance} />
      </div>
      {n.sub && <p className="mt-2 text-sm">{n.sub}</p>}
      <p className="mt-1 text-xs text-mute">{n.last_seen ? `last evidence ${fmtDate(n.last_seen)} · ${PHASE[n.phase] ?? n.phase}` : 'no dated evidence in the record yet'}{n.risk != null ? ` · risk ${Math.round(n.risk)}` : ''}</p>
      <div className="mt-3"><Facts n={n} compact /></div>
      {n.kind === 'actor' && typeof n.facts.note === 'string' && <div className="mt-3 rounded-xl border border-line bg-panel p-3 text-xs text-mute">{n.facts.note}</div>}
      <p className="mt-3 text-xs text-mute">{n.source}</p>
      <p className="mt-3 text-xs text-mute">Click for the full card: connections and the evidence behind it.</p>
    </div>
  )
}

/* The Watch pill in the card's header. It reads the watchlist once when the card opens, so an entity already on it
   shows "Watching"; a click files the entity with the default rule and the live engine takes it from there. */
function WatchButton({ target, label }: { target: string; label: string }) {
  const toast = useToast()
  const [state, setState] = useState<'checking' | 'idle' | 'busy' | 'watching'>('checking')
  useEffect(() => {
    let alive = true
    fetch('/api/watches')
      .then((r) => (r.ok ? (r.json() as Promise<{ watches: WatchRow[] }>) : Promise.reject(new Error(`${r.status} /api/watches`))))
      .then((d) => alive && setState(d.watches.some((w) => w.target === target) ? 'watching' : 'idle'))
      .catch(() => alive && setState('idle'))
    return () => { alive = false }
  }, [target])
  const add = async () => {
    if (state !== 'idle') return
    setState('busy')
    try {
      const res = await fetch('/api/watches', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target }) })
      if (!res.ok) {
        const d = (await res.json().catch(() => ({}))) as { detail?: string }
        throw new Error(d.detail ?? `${res.status}`)
      }
      setState('watching')
      toast(`Watching ${label}. The live engine checks it every 15 s and a firing lands in the live feed.`)
    } catch (e) {
      setState('idle')
      toast(`Could not watch ${label} (${e instanceof Error ? e.message : String(e)})`)
    }
  }
  const watching = state === 'watching'
  return (
    <button type="button" onClick={add} disabled={state !== 'idle'} data-watch={target}
            title={watching ? 'On the watchlist: the live engine evaluates it every 15 s' : 'Add to the watchlist with the default rule (any change at Critical or above, or fresh evidence)'}
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition ${watching ? 'bg-action text-ink' : 'bg-panel-2 text-text hover:bg-panel-3 disabled:opacity-60'}`}>
      {state === 'busy' || state === 'checking' ? <Loader2 size={12} className="animate-spin" /> : <Eye size={12} />}
      {watching ? 'Watching' : 'Watch'}
    </button>
  )
}

function Card({ id, focus, onClose, onOpen }: { id: string; focus?: string; onClose: () => void; onOpen: (id: string) => void }) {
  const [c, setC] = useState<GraphCard>()
  const [err, setErr] = useState<string>()
  const [missing, setMissing] = useState(false)
  /* The parent keys this card by id and focus, so a new entity mounts a fresh card; the effect only fetches. The card
     endpoint answers 404 for an id the current graph does not hold (a deep link to another view's asset, or an entity
     the record has not seen); that is a state of the card, not a failure. */
  useEffect(() => {
    let alive = true
    fetch(`/api/graph/node?id=${encodeURIComponent(id)}${focus ? `&focus=${encodeURIComponent(focus)}` : ''}`)
      .then(async (res) => {
        if (res.status === 404) { if (alive) setMissing(true); return }
        if (!res.ok) throw new Error(`${res.status} /api/graph/node`)
        const d = (await res.json()) as GraphCard
        if (alive) setC(d)
      })
      .catch((e) => alive && setErr(String(e)))
    return () => { alive = false }
  }, [id, focus])
  const n = c?.node
  const url = n && typeof n.facts.url === 'string' ? n.facts.url : undefined
  const kind = id.split(':')[0]
  return (
    <Sheet wide onClose={onClose}
           title={n ? <span className="flex flex-wrap items-center gap-3">{n.label}{n.tier && <TierPill tier={n.tier} />}<Prov p={provOf(n.provenance)} label={n.provenance} /><WatchButton target={n.id} label={n.label} /></span>
                   : missing ? <span className="font-mono text-xl">{displayId(id)}</span> : 'Intelligence card'}
           sub={n ? `${KIND_LABEL[n.kind] ?? n.kind}${n.sub ? ` · ${n.sub}` : ''}` : missing ? (KIND_LABEL[kind] ?? 'Entity') : undefined}>
      {err && <div className="text-mute">Could not load this card ({err}).</div>}
      {missing && (
        <div className="rounded-2xl bg-panel-2 p-5" data-card-missing>
          <div className="text-lg font-semibold">Not in the current graph</div>
          <p className="mt-2 text-sm text-mute">
            The record has no entity <span className="font-mono">{displayId(id)}</span> in {focus ? `the ${focus} view` : 'the national view'} right now.
            {kind === 'asset' ? ' Assets are drawn only inside their own organisation’s view: pick that organisation above and open the link again.' : ' It may sit in another organisation’s view, or the record has not seen it yet.'}
          </p>
        </div>
      )}
      {!c && !err && !missing && <div className="text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />Reading the record…</div>}
      {c && n && (
        <div className="grid gap-10 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
          <div className="flex min-w-0 flex-col gap-8">
            <div>
              <h3 className="text-[16px] font-semibold">What this is</h3>
              <p className="mt-2 text-mute">{c.record.how}</p>
              <p className="mt-2 text-xs text-mute">{n.source}{n.last_seen ? ` · last evidence ${fmtDate(n.last_seen)} (${PHASE[n.phase] ?? n.phase})` : ''}</p>
              {url && <a href={url} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-1 text-sm text-accent hover:underline">{url.replace(/^https?:\/\//, '')} <ExternalLink size={13} /></a>}
            </div>
            <div>
              <h3 className="text-[16px] font-semibold">Facts</h3>
              <div className="mt-3"><Facts n={n} /></div>
              {n.kind === 'actor' && typeof n.facts.note === 'string' && <div className="mt-4 rounded-2xl bg-panel-2 p-4 text-sm text-mute">{n.facts.note}</div>}
            </div>
          </div>
          <div className="flex min-w-0 flex-col gap-8">
            <div>
              <h3 className="text-[16px] font-semibold">Connected</h3>
              <p className="mt-1 text-sm text-mute">{c.neighbours.length} connection{c.neighbours.length === 1 ? '' : 's'} in the record. Open one to follow the thread.</p>
              <div className="mt-2">
                {c.neighbours.map((m) => (
                  <Row key={`${m.id}-${m.edge}`} onClick={() => onOpen(m.id)}
                       lead={<span className="text-[9px] font-bold tracking-wide text-mute">{KIND_CODE[m.kind] ?? m.kind.slice(0, 4).toUpperCase()}</span>}
                       title={m.label} sub={`${m.relation} · ${m.provenance}`} trail={m.tier ? <TierPill tier={m.tier} /> : undefined} />
                ))}
                {c.neighbours.length === 0 && <div className="py-3 text-sm text-mute">No connections drawn for this node.</div>}
              </div>
            </div>
            <div>
              <h3 className="text-[16px] font-semibold">Evidence</h3>
              <p className="mt-1 text-sm text-mute">{c.events.length ? `The latest ${c.events.length} entries of the audit trail that name it.` : 'No audit-trail entries name this node; it is drawn from the reference record alone.'}</p>
              <ul className="mt-2">
                {c.events.map((e, i) => (
                  <li key={i} className="flex items-start gap-3 border-b border-line py-2 text-sm last:border-0">
                    <span className="w-32 shrink-0 font-mono text-xs text-mute">{fmtDate(e.ts)}</span>
                    <span className="w-32 shrink-0 truncate font-medium" title={e.kind}>{e.kind}</span>
                    <span className="min-w-0 flex-1 truncate text-mute" title={e.text || e.subject}>{e.text || e.subject}</span>
                    <Prov p={provOf(e.provenance)} label={e.provenance} />
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </Sheet>
  )
}

export function IntelGraph({ focus, onFocus, initialNode }: { focus?: string; onFocus: (orgId?: string) => void; initialNode?: string }) {
  /* The drawing is stored with the focus it was fetched for: a change of focus is a different graph, so the view derives
     an empty drawing (and the loading state) until the new one lands, while a change of replay instant keeps the current
     drawing on screen until the next frame arrives, so the slider does not flash. */
  const [gs, setGs] = useState<{ focus?: string; g: Graph }>()
  const [errAt, setErrAt] = useState<{ focus?: string; msg: string }>()
  const g = gs && gs.focus === focus ? gs.g : undefined
  const err = errAt && errAt.focus === focus ? errAt.msg : undefined
  const [orgs, setOrgs] = useState<Soc['orgs']>([])
  const [hover, setHover] = useState<string>()
  const [kindSel, setKindSel] = useState<string>()
  const [card, setCard] = useState<string>()
  const [fresh, setFresh] = useState<Set<string>>(new Set())
  const prev = useRef<Set<string> | null>(null)
  /* Replay: the instants on offer and the one chosen; 'now' is the live view. */
  const [steps, setSteps] = useState<ReplayStep[]>([])
  const [stepId, setStepId] = useState('now')
  /* Deep link: ?node=<id> in the address, or the initialNode prop. It opens once the first graph has loaded and is
     cleared together with the card, so closing the card does not reopen it. */
  const [deepLink, setDeepLink] = useState<string | undefined>(() => initialNode ?? new URLSearchParams(window.location.search).get('node') ?? undefined)
  const shown = card ?? (gs && deepLink ? deepLink : undefined)
  const closeCard = () => { setCard(undefined); setDeepLink(undefined) }

  const found = steps.findIndex((s) => s.id === stepId)
  const stepIdx = found < 0 ? Math.max(0, steps.length - 1) : found
  const step: ReplayStep | undefined = steps[stepIdx]
  const asOf = step?.at ?? null
  const atNow = asOf == null

  useEffect(() => { api.soc().then((s) => setOrgs(s.orgs)).catch(() => undefined) }, [])
  useEffect(() => {
    let alive = true
    fetch('/api/graph/replay')
      .then((r) => (r.ok ? (r.json() as Promise<{ steps: ReplayStep[] }>) : Promise.reject(new Error(`${r.status} /api/graph/replay`))))
      .then((d) => alive && Array.isArray(d.steps) && setSteps(d.steps))
      .catch(() => undefined)
    return () => { alive = false }
  }, [])
  useEffect(() => {
    let alive = true
    prev.current = null      // the ping marks nodes new since the previous poll of the same view; a new view or instant starts clean
    const q = new URLSearchParams()
    if (focus) q.set('focus', focus)
    if (asOf) q.set('as_of', asOf)
    const qs = q.toString()
    const pull = () => fetch(`/api/graph${qs ? `?${qs}` : ''}`)
      .then((r) => (r.ok ? (r.json() as Promise<Graph>) : Promise.reject(new Error(`${r.status} /api/graph`))))
      .then((d) => {
        if (!alive) return
        const ids = new Set(d.nodes.map((n) => n.id))
        setFresh(prev.current ? new Set([...ids].filter((id) => !prev.current!.has(id))) : new Set())
        prev.current = ids
        setHover((h) => (h && !ids.has(h) ? undefined : h))
        setGs({ focus, g: d })
        setErrAt(undefined)
      }).catch((e) => alive && !prev.current && setErrAt({ focus, msg: String(e) }))
    pull()
    if (asOf) return () => { alive = false }     // a past instant does not change: one fetch per step, no polling
    const id = setInterval(pull, 5000)
    return () => { alive = false; clearInterval(id) }
  }, [focus, asOf])

  const L = useMemo(() => (g ? layout(g) : undefined), [g])

  const pills = (
    <div className="mb-5 flex flex-wrap gap-2">
      {[{ id: undefined as string | undefined, name: 'India, all operators' }, ...orgs].map((o) => (
        <button key={o.id ?? 'national'} onClick={() => onFocus(o.id)}
                className={`rounded-full px-3.5 py-1.5 text-sm font-medium transition ${(focus ?? undefined) === o.id ? 'bg-action text-ink' : 'bg-panel-2 text-text hover:bg-panel-3'}`}>
          {o.name}
        </button>
      ))}
    </div>
  )
  const replay = steps.length > 1 ? (
    <div className="mb-5 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-2xl bg-panel-2 px-5 py-3" data-replay>
      <span className="text-sm font-semibold">Replay</span>
      <input type="range" min={0} max={steps.length - 1} step={1} value={stepIdx} aria-label="Replay the record as of"
             onChange={(e) => setStepId(steps[Number(e.target.value)]?.id ?? 'now')}
             className="h-1.5 w-64 max-w-full cursor-pointer" style={{ accentColor: 'var(--color-text)' }} />
      <span className="text-sm font-medium tabular-nums">{step?.label ?? 'now'}</span>
      {!atNow && step?.at && <span className="text-xs text-mute">{fmtDate(step.at)} UTC</span>}
      {!atNow && <Pill onClick={() => setStepId('now')}>Now</Pill>}
    </div>
  ) : null
  const header = (
    <Section title="The intelligence graph"
             sub="Every entity Odyssey knows about and how they connect. Nodes breathe with fresh evidence and lie still as it ages; threat groups are overlap with the ATT&CK record, not attribution.">
      {pills}
      {replay}
      {err && <div className="rounded-2xl bg-panel-2 p-5 text-crit">{err}</div>}
      {!err && (!g || !L) && <div className="rounded-2xl bg-panel-2 p-5 text-mute"><Loader2 className="mr-2 inline animate-spin" size={16} />Drawing the intelligence graph from the record…</div>}
    </Section>
  )
  if (err || !g || !L) {
    return (
      <div className="flex min-w-0 flex-1 flex-col">
        {header}
        {shown && <Card key={`${shown}|${focus ?? ''}`} id={shown} focus={focus} onClose={closeCard} onOpen={setCard} />}
      </div>
    )
  }

  const { pos, rings, labels } = L
  const byId: Record<string, GraphNode> = {}
  for (const n of g.nodes) byId[n.id] = n
  const linked = new Set<string>()
  if (hover) for (const e of g.edges) if (e.from === hover || e.to === hover) { linked.add(e.from); linked.add(e.to) }
  const dim = (n: GraphNode) => {
    if (hover) return n.id === hover || linked.has(n.id) ? 1 : 0.2
    if (kindSel) return n.kind === kindSel ? 1 : 0.15
    return 1
  }
  const hov = hover ? byId[hover] : undefined
  const b = g.breath
  const lastEvidence = g.nodes.reduce<string | null>((m, n) => (n.last_seen && (!m || n.last_seen > m) ? n.last_seen : m), null)
  const timeOf = (iso: string | null) => (iso ? new Date(iso).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' }) : '—')

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-6">
      <Section title="The intelligence graph"
               sub="Every entity Odyssey knows about and how they connect. Nodes breathe with fresh evidence and lie still as it ages; threat groups are overlap with the ATT&CK record, not attribution.">
        {pills}
        {replay}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat value={b.fresh} label="Fresh" sub="evidence in the last hour" />
          <Stat value={b.today} label="Today" sub="evidence under 24 hours old" />
          <Stat value={b.week} label="This week" sub="under 7 days" />
          <Stat value={b.fading} label="Fading" sub="under 30 days" />
          <Stat value={b.aged} label="Aged" sub="older than 30 days, drawn still" />
        </div>
        <p className="mt-3 text-sm text-mute">
          <b className="text-text">{b.events_last_hour.toLocaleString('en-IN')}</b> events in the last hour · last evidence <b className="text-text">{timeOf(lastEvidence ?? b.last_event)}</b>
          {b.live_ticks != null && <> · live engine tick {b.live_ticks.toLocaleString('en-IN')}</>} · {g.focus.label} · {atNow ? 'refreshes every 5 s' : `replay as of ${step?.label ?? g.as_of ?? 'the chosen instant'}`}
        </p>

        {!atNow && step && (
          <div className="mt-6 rounded-xl bg-panel-2 px-4 py-2 text-xs text-mute" data-replay-banner>
            Replaying the record as of <b className="font-semibold text-text">{step.label}</b> ({fmtDate(step.at)} UTC) · nodes that did not exist yet are absent; pulses are aged to that instant
          </div>
        )}
        <div className={`${atNow ? 'mt-6' : 'mt-3'} flex items-start gap-5`}>
          <div className="min-w-0 flex-1 overflow-x-auto rounded-2xl bg-soft p-2">
            <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full min-w-[900px]" data-intelgraph role="img" aria-label={`Intelligence graph: ${g.focus.label}`}
                 onMouseLeave={() => setHover(undefined)}>
              {rings.map((r) => (
                <g key={r.ring}>
                  <ellipse cx={CX} cy={CY} rx={r.r * RMAX * ASPECT} ry={r.r * RMAX} fill="none" stroke="var(--color-line)" strokeWidth={1} />
                  <text x={CX} y={CY - r.r * RMAX - 12} textAnchor="middle" fontSize={9.5} fontWeight={600} letterSpacing={0.6} fill="var(--color-faint)"
                        paintOrder="stroke" stroke="var(--color-soft)" strokeWidth={3}>{r.label.toUpperCase()}</text>
                </g>
              ))}
              {g.focus.kind === 'national' && (
                <g>
                  <text x={CX} y={CY - 4} textAnchor="middle" fontSize={13} fontWeight={700} fill="var(--color-text)">{g.focus.label}</text>
                  <text x={CX} y={CY + 14} textAnchor="middle" fontSize={10.5} fill="var(--color-mute)">{g.summary.nodes} nodes · {g.summary.edges} connections · {g.summary.real_edges} from public data</text>
                </g>
              )}

              {g.edges.map((e) => {
                const a = pos[e.from], c = pos[e.to]
                if (!a || !c) return null
                const on = hover && (e.from === hover || e.to === hover)
                const off = hover ? !on : kindSel ? byId[e.from]?.kind !== kindSel && byId[e.to]?.kind !== kindSel : false
                return <path key={`${e.from}|${e.to}|${e.kind}`} d={curve(a, c)} fill="none"
                             stroke={on ? 'var(--color-text)' : 'var(--color-faint)'} strokeWidth={0.6 + Math.min(3, e.weight) * 0.35 + (on ? 0.5 : 0)}
                             strokeDasharray={DASH[e.provenance]} opacity={on ? 0.9 : off ? 0.04 : e.kind === 'runs' || e.kind === 'owns' ? 0.09 : 0.22} />
              })}

              {/* breathing halos and new-node pings live in their own layer, so a node's own box stays still for pointers */}
              {g.nodes.map((n) => {
                if (n.pulse < 0.05 && !fresh.has(n.id)) return null
                const p = pos[n.id], r = radius(n)
                return (
                  <g key={`h-${n.id}`} transform={`translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`} opacity={dim(n)} style={{ pointerEvents: 'none' }}>
                    {n.pulse >= 0.05 && (
                      <circle r={r + 3} fill={n.tier ? TIER_FILL[n.tier] : 'var(--color-faint)'} opacity={0.25 * n.pulse} className="breath"
                              style={{ '--breath': `${(1.6 + 3.4 * (1 - n.pulse)).toFixed(2)}s` } as CSSProperties} />
                    )}
                    {fresh.has(n.id) && <circle r={r + 2} fill="none" stroke="var(--color-text)" strokeWidth={1.5} className="ping" />}
                  </g>
                )
              })}

              {g.nodes.map((n) => {
                const p = pos[n.id], r = radius(n)
                const fill = n.tier ? TIER_FILL[n.tier] : 'var(--color-panel)'
                const stroke = n.tier ? 'var(--color-panel)' : 'var(--color-text)'
                return (
                  <g key={n.id} transform={`translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`} opacity={dim(n)} data-node={n.id} style={{ cursor: 'pointer' }}
                     onMouseEnter={() => setHover(n.id)} onClick={() => setCard(n.id)}>
                    <Shape n={n} r={r} fill={fill} stroke={stroke} strokeWidth={1.5} />
                  </g>
                )
              })}

              {g.nodes.map((n) => {
                const l = labels[n.id]
                if (!l || n.id === hover) return null
                return <text key={`l-${n.id}`} x={l.x} y={l.y} textAnchor={l.anchor} fontSize={n.kind === 'org' ? 11 : 10.5} fontWeight={n.kind === 'org' ? 600 : 400}
                             fill="var(--color-text)" opacity={dim(n)} paintOrder="stroke" stroke="var(--color-soft)" strokeWidth={3} strokeLinejoin="round"
                             style={{ pointerEvents: 'none' }}>{drawn(n)}</text>
              })}
              {hov && (() => {
                const p = pos[hov.id], r = radius(hov), right = Math.cos(hov.angle) >= 0 && p.x < W - 220
                return (
                  <g style={{ pointerEvents: 'none' }}>
                    <circle cx={p.x} cy={p.y} r={r + 4} fill="none" stroke="var(--color-text)" strokeWidth={1.5} />
                    <text x={right ? p.x + r + 8 : p.x - r - 8} y={p.y + 4} textAnchor={right ? 'start' : 'end'} fontSize={12} fontWeight={700} fill="var(--color-text)"
                          paintOrder="stroke" stroke="var(--color-soft)" strokeWidth={4} strokeLinejoin="round">{short(hov.label, 40)}</text>
                    <text x={right ? p.x + r + 8 : p.x - r - 8} y={p.y + 17} textAnchor={right ? 'start' : 'end'} fontSize={9.5} fill="var(--color-mute)"
                          paintOrder="stroke" stroke="var(--color-soft)" strokeWidth={3} strokeLinejoin="round">{KIND_LABEL[hov.kind] ?? hov.kind}{hov.tier ? ` · ${hov.tier}` : ''}</text>
                  </g>
                )
              })()}
            </svg>
          </div>

          <aside className="sticky top-24 w-[360px] shrink-0 self-start rounded-2xl bg-panel-2 p-5 text-sm">
            {hov ? <HoverPanel n={hov} /> : (
              <div>
                <div className="text-lg font-semibold leading-tight">{g.focus.label}</div>
                <p className="mt-1 text-xs text-mute">{g.summary.nodes} nodes · {g.summary.edges} edges · {g.summary.real_edges} REAL edges · {g.summary.mixed_edges} REAL · SIM · {g.summary.sim_edges} SIM</p>
                <div className="mt-4 text-xs font-semibold uppercase tracking-wide text-mute">Real, public data</div>
                <ul className="mt-1 space-y-0.5">{g.provenance.REAL.map((x) => <li key={x} className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-ok" />{x}</li>)}</ul>
                <div className="mt-4 text-xs font-semibold uppercase tracking-wide text-mute">Simulated, labelled SIM</div>
                <ul className="mt-1 space-y-0.5">{g.provenance.SIM.map((x) => <li key={x} className="flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full ring-1 ring-mute" />{x}</li>)}</ul>
                <div className="mt-4 rounded-xl border border-line bg-panel p-3 text-xs text-mute">{g.provenance.note}</div>
                <p className="mt-4 text-xs text-mute">Hover a node for its record; click it for the full card. Snapshot {g.snapshot}, built {fmtDate(g.built_at)}{g.as_of ? `, replayed as of ${fmtDate(g.as_of)} UTC` : ''}.</p>
              </div>
            )}
          </aside>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          {g.kinds.map((k) => (
            <button key={k.id} onClick={() => setKindSel(kindSel === k.id ? undefined : k.id)}
                    className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition ${kindSel === k.id ? 'bg-action text-ink' : 'bg-panel-2 text-text hover:bg-panel-3'}`}>
              <Glyph kind={k.id} fill={kindSel === k.id ? 'var(--color-ink)' : 'none'} size={9} />{k.label} <span className={kindSel === k.id ? 'opacity-70' : 'text-mute'}>{k.count}</span>
            </button>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-mute">
          <span className="flex items-center gap-1"><Glyph kind="actor" fill="none" size={9} />threat group</span>
          <span className="flex items-center gap-1"><Glyph kind="signal" fill="none" size={9} />live signal</span>
          <span className="flex items-center gap-1"><Glyph kind="org" fill="none" size={9} />everything else</span>
          <span className="ml-2">fill = worst open tier:</span>
          {(['Compromise', 'Critical', 'High', 'Medium'] as Tier[]).map((t) => (
            <span key={t} className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full" style={{ background: TIER_FILL[t] }} />{t}</span>
          ))}
          <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full border border-text bg-panel" />no tier (reference record)</span>
          <span className="ml-2 flex items-center gap-1.5"><span className="relative flex h-3 w-3 items-center justify-center"><span className="absolute h-3 w-3 rounded-full bg-faint/30" /><span className="h-1.5 w-1.5 rounded-full bg-faint" /></span>halo = evidence pulse (fresh breathes fast)</span>
          <span className="flex items-center gap-1.5"><svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke="var(--color-faint)" strokeWidth="2" /></svg>REAL</span>
          <span className="flex items-center gap-1.5"><svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke="var(--color-faint)" strokeWidth="2" strokeDasharray="6 3" /></svg>REAL · SIM</span>
          <span className="flex items-center gap-1.5"><svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke="var(--color-faint)" strokeWidth="2" strokeDasharray="3 3" /></svg>SIM</span>
        </div>
      </Section>

      {shown && <Card key={`${shown}|${focus ?? ''}`} id={shown} focus={focus} onClose={closeCard} onOpen={setCard} />}
    </div>
  )
}
