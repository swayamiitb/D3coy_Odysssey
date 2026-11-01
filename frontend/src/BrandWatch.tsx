import { AlertTriangle, Bug, ExternalLink, Loader2, MessageSquare, Newspaper, Search, ShieldAlert } from 'lucide-react'
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { istTime } from './proactive'
import { Badge, Pill, Prov, Row, Section, Sheet, Stat, Tile, useToast } from './ui'

/* Brand and social watch: what passive, public sources say about a brand or an organisation. Certificate transparency
   (crt.sh) for look-alike certificates, URLhaus and OpenPhish for malicious and phishing URLs on look-alike hosts, news,
   Hacker News and Reddit for risk mentions. Every read is of a public feed; nothing touches the organisation or the
   sites found. Hits are scored by explicit rules on the API, stored defanged and labelled REAL. No LLM is involved. */

type HitKind = 'lookalike_cert' | 'malicious_url' | 'phishing_url' | 'mention'

interface BrandHit {
  id: number
  ts: string
  term: string
  org_id: string | null
  source: string
  kind: HitKind
  channel: string
  value: string
  url: string
  title: string | null
  snippet: string | null
  score: number
  provenance: string
  evidence: string | null
  first_seen?: string
  last_seen?: string
}

interface SourceState { status: 'fresh' | 'offline' | 'not run' | string; count?: number; ms?: number; detail?: string }

interface LastScan { ts: string; sources: Record<string, SourceState>; hits: number; new_hits: number; seconds: number }

interface BrandTerm {
  term: string
  org_id: string | null
  hits: number
  max_score: number | null
  by_kind: Partial<Record<HitKind, number>>
  top: BrandHit[]
  last_scan: LastScan | null
}

interface BrandSummary {
  generated_at: string
  org_id: string | null
  terms: BrandTerm[]
  totals: { terms: number; hits: number; high: number; scans: number }
  sources: ({ name: string } & SourceState)[]
  last_scan: string | null
  provenance: string
  how: string
}

interface ScanResult {
  ts: string
  terms: string[]
  org_id: string | null
  sources: Record<string, SourceState>
  hits: number
  new_hits: number
  ledger_events: number
  seconds: number
  online: number
  offline: number
  provenance: string
  top: BrandHit[]
}

const KINDS: HitKind[] = ['lookalike_cert', 'malicious_url', 'phishing_url', 'mention']
const KIND_LABEL: Record<HitKind, string> = {
  lookalike_cert: 'look-alike certificates', malicious_url: 'malicious URLs', phishing_url: 'phishing URLs', mention: 'mentions',
}
const KIND_ONE: Record<HitKind, string> = {
  lookalike_cert: 'look-alike certificate', malicious_url: 'malicious URL', phishing_url: 'phishing URL', mention: 'mention',
}
const SOURCE_ORDER = ['crt.sh', 'URLhaus', 'OpenPhish', 'Google News', 'Hacker News', 'Reddit']
const HOST_KINDS = new Set<HitKind>(['lookalike_cert', 'malicious_url', 'phishing_url'])

/** Display form of a host or URL: hxxp and [.] so it is never clickable by accident. Rows arrive defanged already. */
const defang = (v: string) => (v.includes('[.]') ? v : v.replace(/^https?:\/\//i, (m) => m.replace(/http/i, 'hxxp')).replace(/\./g, '[.]'))
const fmt = (n: number | null | undefined) => (n == null ? '—' : n.toLocaleString('en-IN'))

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init)
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    throw new Error(typeof body?.detail === 'string' ? body.detail : `HTTP ${r.status}`)
  }
  return r.json() as Promise<T>
}

const summaryUrl = (orgId?: string) => `/api/brand${orgId ? `?org_id=${encodeURIComponent(orgId)}` : ''}`

/** One glyph per kind; a mention from the news reads as a newspaper, one from Hacker News or Reddit as a speech bubble. */
function KindIcon({ kind, channel, size = 18 }: { kind: HitKind; channel?: string; size?: number }) {
  if (kind === 'lookalike_cert') return <ShieldAlert size={size} />
  if (kind === 'malicious_url') return <Bug size={size} />
  if (kind === 'phishing_url') return <AlertTriangle size={size} />
  return channel && channel !== 'news' ? <MessageSquare size={size} /> : <Newspaper size={size} />
}

/** Score as a tag: Critical colour at 80 and above, High at 60, otherwise quiet grey. The number stays legible. */
function ScoreBadge({ score }: { score: number }) {
  const n = Math.round(score)
  if (n >= 80) return <Badge tone="crit">{n}</Badge>
  if (n >= 60) return <span className="inline-flex items-center gap-1 rounded-full bg-high/15 px-2.5 py-0.5 text-xs font-medium text-high">{n}</span>
  return <Badge>{n}</Badge>
}

function HitRow({ h }: { h: BrandHit }) {
  const hostLike = HOST_KINDS.has(h.kind)
  const title = hostLike ? defang(h.title || h.value) : (h.title || h.value)
  const sub = [h.evidence || KIND_ONE[h.kind], h.source, istTime(h.ts)].join(' · ')
  return (
    <Row lead={<KindIcon kind={h.kind} channel={h.channel} />}
         title={<span className={hostLike ? 'font-mono text-[13px]' : ''} title={h.snippet ?? undefined}>{title}</span>}
         sub={sub}
         trail={<span className="flex items-center gap-2">
           <ScoreBadge score={h.score} />
           {h.url && (
             <a href={h.url} target="_blank" rel="noreferrer" title="Open the public source in a new tab"
                className="flex h-8 w-8 items-center justify-center rounded-full bg-panel-2 text-mute hover:bg-panel-3 hover:text-text">
               <ExternalLink size={14} />
             </a>
           )}
         </span>} />
  )
}

/** One chip per public source: a green dot when the last scan read it, grey when it was offline or has not run yet. */
function SourceStrip({ sources }: { sources: BrandSummary['sources'] }) {
  const rows = [...sources].sort((a, b) => SOURCE_ORDER.indexOf(a.name) - SOURCE_ORDER.indexOf(b.name))
  return (
    <div className="flex flex-wrap gap-2">
      {rows.map((s) => {
        const fresh = s.status === 'fresh'
        const hint = fresh ? `read in ${fmt(s.ms)} ms` : s.status === 'offline' ? `offline${s.detail ? `: ${s.detail}` : ''}` : 'not read yet'
        return (
          <span key={s.name} title={hint} className="inline-flex items-center gap-1.5 rounded-full bg-panel-2 px-3 py-1 text-xs font-medium">
            <span className={`h-1.5 w-1.5 rounded-full ${fresh ? 'bg-ok' : 'bg-faint'}`} />
            {s.name}
            <span className={fresh ? 'text-mute' : 'text-faint'}>{fresh ? fmt(s.count ?? 0) : s.status === 'offline' ? 'offline' : '—'}</span>
          </span>
        )
      })}
    </div>
  )
}

function Chip({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button onClick={onClick}
            className={`inline-flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-sm font-medium transition ${on ? 'bg-action text-ink' : 'bg-panel-2 text-text hover:bg-panel-3'}`}>
      {children}
    </button>
  )
}

/** Every hit on record for this organisation (or every term), newest and highest score first, filtered by kind. */
function AllHitsSheet({ orgId, onClose }: { orgId?: string; onClose: () => void }) {
  const [kind, setKind] = useState<HitKind | 'all'>('all')
  // the rows are stored with the query that produced them, so a change of filter shows the loader instead of stale rows
  const [got, setGot] = useState<{ q: string; rows: BrandHit[] }>()
  const [err, setErr] = useState<string>()
  const params = new URLSearchParams({ limit: '100' })
  if (orgId) params.set('org_id', orgId)
  if (kind !== 'all') params.set('kind', kind)
  const q = params.toString()
  useEffect(() => {
    let alive = true
    getJson<{ rows: BrandHit[] }>(`/api/brand/hits?${q}`)
      .then((d) => alive && setGot({ q, rows: d.rows }))
      .catch((e: Error) => alive && setErr(e.message))
    return () => { alive = false }
  }, [q])
  const rows = got && got.q === q ? got.rows : undefined
  return (
    <Sheet wide title="All hits" onClose={onClose}
           sub={<span className="flex items-center gap-2">Everything the public sources returned{orgId ? ' for this organisation' : ''}, highest score first, 100 at most. <Prov p="REAL" label="REAL · public sources" /></span>}>
      <div className="mb-4 flex flex-wrap gap-2">
        <Chip on={kind === 'all'} onClick={() => setKind('all')}>All kinds</Chip>
        {KINDS.map((k) => <Chip key={k} on={kind === k} onClick={() => setKind(k)}><KindIcon kind={k} size={14} />{KIND_LABEL[k]}</Chip>)}
      </div>
      {err && <div className="rounded-2xl bg-panel-2 p-5 text-crit">{err}</div>}
      {!err && !rows && <div className="py-6 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Reading the record…</div>}
      {rows && rows.length === 0 && <div className="rounded-2xl bg-panel-2 p-5 text-mute">No hits of this kind yet. Scan to read the public sources now.</div>}
      {rows && rows.map((h) => <HitRow key={h.id} h={h} />)}
    </Sheet>
  )
}

function TermBlock({ t }: { t: BrandTerm }) {
  const kinds = KINDS.filter((k) => (t.by_kind[k] ?? 0) > 0)
  return (
    <div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="text-lg font-semibold">{t.term}</span>
        <span className="text-sm text-mute">{fmt(t.hits)} hit{t.hits === 1 ? '' : 's'}{t.max_score != null && ` · top score ${Math.round(t.max_score)}`}</span>
        {t.last_scan && <span className="text-sm text-faint">· last read {istTime(t.last_scan.ts)}</span>}
        <span className="ml-auto flex flex-wrap gap-1.5">
          {kinds.map((k) => (
            <span key={k} className="inline-flex items-center gap-1.5 rounded-full bg-panel-2 px-2.5 py-0.5 text-xs font-medium">
              <KindIcon kind={k} size={12} />{KIND_LABEL[k]} <span className="text-mute">{fmt(t.by_kind[k])}</span>
            </span>
          ))}
        </span>
      </div>
      <div className="mt-1">
        {t.top.length === 0
          ? <div className="py-3 text-sm text-mute">Nothing found for this term in the last read.</div>
          : t.top.map((h) => <HitRow key={h.id} h={h} />)}
      </div>
    </div>
  )
}

/** Brand and social monitoring for one organisation, or for any term the operator types. Passive public sources only. */
export function BrandWatch({ orgId }: { orgId?: string }) {
  // summary and last scan are stored with the organisation they belong to, so switching organisations never shows another's figures
  const [sum, setSum] = useState<{ org?: string; data: BrandSummary }>()
  const [err, setErr] = useState<string>()
  const [term, setTerm] = useState('')
  const [scanning, setScanning] = useState(false)
  const [lastScan, setLastScan] = useState<{ org?: string; data: ScanResult }>()
  const [sheet, setSheet] = useState(false)
  const toast = useToast()
  const s = sum && sum.org === orgId ? sum.data : undefined
  const last = lastScan && lastScan.org === orgId ? lastScan.data : undefined

  const refresh = useCallback(() => {
    getJson<BrandSummary>(summaryUrl(orgId)).then((d) => { setSum({ org: orgId, data: d }); setErr(undefined) }).catch((e: Error) => setErr(e.message))
  }, [orgId])
  useEffect(() => {
    let alive = true
    const pull = () => getJson<BrandSummary>(summaryUrl(orgId))
      .then((d) => { if (alive) { setSum({ org: orgId, data: d }); setErr(undefined) } })
      .catch((e: Error) => alive && setErr(e.message))
    pull()
    const id = setInterval(pull, 30_000)
    return () => { alive = false; clearInterval(id) }
  }, [orgId])

  const scan = () => {
    if (scanning) return
    const body = orgId ? { org_id: orgId } : { term: term.trim().toLowerCase() }
    if (!orgId && !term.trim()) { toast('Type a brand or product term to watch'); return }
    setScanning(true)
    getJson<ScanResult>('/api/brand/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then((d) => {
        setLastScan({ org: orgId, data: d })
        toast(`${fmt(d.hits)} hit${d.hits === 1 ? '' : 's'}, ${fmt(d.new_hits)} new · ${d.online} of ${d.online + d.offline} sources answered in ${d.seconds} s`)
        refresh()
      })
      .catch((e: Error) => toast(`Scan failed: ${e.message}`))
      .finally(() => setScanning(false))
  }

  const sub = orgId
    ? 'Impersonation and risk mentions of this organisation in public sources: certificate transparency, URLhaus, OpenPhish, news, Hacker News, Reddit. Passive reads; nothing touches the organisation.'
    : 'Watch any brand or product term in public sources.'
  const total = s?.totals.hits ?? 0

  return (
    <>
      <Section title="Brand and social watch" sub={sub}
               action={<span className="flex flex-wrap items-center gap-2">
                 <Prov p="REAL" label="REAL · public sources" />
                 <Pill onClick={() => setSheet(true)}>All hits{s ? ` (${fmt(total)})` : ''}</Pill>
               </span>}>
        {err && !s && <div className="rounded-2xl bg-panel-2 p-5 text-mute">Brand monitoring is not answering yet: {err}. Retrying every 30 s.</div>}
        {!err && !s && <div className="py-6 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Reading the brand record…</div>}
        {s && (
          <div className="flex flex-col gap-6">
            <SourceStrip sources={s.sources} />

            <div className="flex flex-wrap items-center gap-3">
              {orgId ? (
                <Pill onClick={scan}>{scanning ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />} Scan now</Pill>
              ) : (
                <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (!scanning) scan() }}>
                  <label className="sr-only" htmlFor="brand-term">Term to watch</label>
                  <input id="brand-term" value={term} onChange={(e) => setTerm(e.target.value)} placeholder="Term to watch" autoComplete="off" spellCheck={false}
                         className="w-72 rounded-full bg-panel-2 px-4 py-2.5 text-sm outline-none placeholder:text-faint focus:ring-2 focus:ring-text/20" />
                  <button type="submit" disabled={scanning || !term.trim()}
                          className="inline-flex items-center gap-1.5 rounded-full bg-action px-5 py-2.5 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-40">
                    {scanning ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />} Scan
                  </button>
                </form>
              )}
              {scanning && <span className="text-sm text-mute"><Loader2 size={14} className="mr-1.5 inline animate-spin" />Reading public sources… (10 to 25 s)</span>}
              {!scanning && s.last_scan && <span className="text-sm text-mute">Last read {istTime(s.last_scan)} · {fmt(s.totals.scans)} scan{s.totals.scans === 1 ? '' : 's'} on record</span>}
            </div>

            {last && !scanning && (
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <Stat value={fmt(last.hits)} label="Hits" sub={`for ${last.terms.join(', ')}`} />
                <Stat value={fmt(last.new_hits)} label="New" sub={last.ledger_events ? `${fmt(last.ledger_events)} entered the audit trail` : 'nothing new scored 70 or more'} />
                <Stat value={<>{last.online}<span className="text-mute"> / {last.offline}</span></>} label="Sources online / offline" sub="of six public feeds" />
                <Stat value={`${last.seconds} s`} label="Seconds" sub="to read every source" />
              </div>
            )}

            {s.terms.length === 0 || total === 0 ? (
              <div className="rounded-2xl bg-panel-2 p-5 text-mute">No hits yet. Scan to read the public sources now.</div>
            ) : (
              <div className="flex flex-col gap-8">
                {[...s.terms].sort((a, b) => b.hits - a.hits || a.term.localeCompare(b.term)).map((t) => <TermBlock key={t.term} t={t} />)}
              </div>
            )}

            <p className="text-xs text-mute">{s.how}</p>
          </div>
        )}
      </Section>
      {sheet && <AllHitsSheet orgId={orgId} onClose={() => setSheet(false)} />}
    </>
  )
}

/** A grey suggestion tile for another screen: total hits on record, one line, Open. */
export function BrandTile({ orgId, onOpen }: { orgId?: string; onOpen: () => void }) {
  const [s, setS] = useState<BrandSummary>()
  useEffect(() => {
    let alive = true
    getJson<BrandSummary>(summaryUrl(orgId)).then((d) => alive && setS(d)).catch(() => undefined)
    return () => { alive = false }
  }, [orgId])
  return (
    <Tile value={s ? fmt(s.totals.hits) : '—'} title="Brand and social watch"
          sub="look-alike certificates, malicious and phishing URLs, risk mentions" cta="Open" onClick={onOpen} />
  )
}
