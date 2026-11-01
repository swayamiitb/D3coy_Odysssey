import { Check, Download, FileJson, FileSpreadsheet, Loader2, Server, Upload } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Badge, fmtDate, Pill, Prov, Row, Section, Stat, TierPill, useToast } from './ui'

/* Indicators: bring in what a partner sends (a CSV, a plain list, an advisory, a STIX 2.1 bundle), match every indicator
   against our own telemetry and exposure, keep it with its source and TLP, and hand it on as CSV, STIX 2.1 or over TAXII.
   Nothing here calls a language model: extraction is pattern-based, matching is a lookup against the record, and every
   match carries where it came from: SIM for our simulated sensors (flows, sightings, the HTTP shield), REAL for public
   feeds (abuse.ch Feodo Tracker, CISA KEV, OpenPhish). Indicators are shown defanged everywhere. */

type IocType = 'ipv4-addr' | 'domain-name' | 'url' | 'file:sha256' | 'file:sha1' | 'file:md5' | 'vulnerability'
type Severity = 'Critical' | 'High' | 'Medium' | null
type Tlp = 'WHITE' | 'GREEN' | 'AMBER' | 'RED'

interface IocMatch { where: string; detail: string; provenance: string; severity?: Severity; org_id?: string; asset_id?: string }
interface IocEnrich { source: string; detail: string; provenance: string }
interface IocRow {
  id: number; value: string; defanged: string; type: IocType; matched: boolean | number; severity: Severity
  matches: IocMatch[]; enrich: IocEnrich[]
  source?: string; tlp?: Tlp; tags?: string[]; added_at?: string; first_seen?: string; last_seen?: string
}
interface ImportResult {
  source: string; tlp: Tlp; format: 'text' | 'csv' | 'stix'; found: number; new: number; matched: number
  by_type: Record<string, number>; seconds: number; indicators: IocRow[]
}
interface ImportRecord { id: number; ts: string; source: string; tlp: Tlp; format: string; found: number; new: number; matched: number; by_type: Record<string, number>; seconds: number }
interface Held { total: number; matched: number; by_type: Record<string, number>; imports: ImportRecord[]; indicators: IocRow[] }
interface TaxiiCollection { id: string; title: string; alias?: string; description?: string }
interface TaxiiTest { base?: string; collections: TaxiiCollection[]; error?: string }

const TLPS: Tlp[] = ['WHITE', 'GREEN', 'AMBER', 'RED']
const TYPE_LABEL: Record<string, string> = {
  'ipv4-addr': 'IPv4', 'domain-name': 'Domain', url: 'URL', 'file:sha256': 'SHA-256', 'file:sha1': 'SHA-1', 'file:md5': 'MD5', vulnerability: 'CVE',
}
const FORMAT_LABEL: Record<string, string> = { text: 'text', csv: 'CSV', stix: 'STIX 2.1' }
const DOT: Record<string, string> = { Critical: 'bg-crit', High: 'bg-high', Medium: 'bg-med' }
const SEV_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2 }
const SAMPLE = '# partner CSIRT, TLP:AMBER\n50[.]16[.]16[.]211  QakBot C2\nhxxps://update-vgwc[.]com/kyc/verify\nCVE-2026-104935\n203.0.113.66\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
const PLACEHOLDER = 'Paste anything: a CSV, a list, an advisory, a STIX 2.1 bundle. IPv4 addresses, domains, URLs, hashes and CVE ids are extracted, refanged and matched.'

const typeLabel = (t: string) => TYPE_LABEL[t] ?? t
const provOf = (p: string) => (p.startsWith('REAL') ? 'REAL' : 'SIM')
const n = (v: number) => v.toLocaleString('en-IN')
/** Matched rows first, then by severity, then in the order they were found. */
const sortRows = (rows: IocRow[]) => [...rows].sort((a, b) =>
  Number(Boolean(b.matched)) - Number(Boolean(a.matched)) || (SEV_RANK[a.severity ?? ''] ?? 9) - (SEV_RANK[b.severity ?? ''] ?? 9) || a.id - b.id)

const PRIMARY = 'inline-flex items-center gap-2 rounded-full bg-action px-5 py-2.5 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-40'
const TH = 'pb-2 pr-3 font-normal'

/** A coloured dot (the worst match severity) and where it matched, each with the provenance of that record. Hover for the details. */
function Matched({ r }: { r: IocRow }) {
  const on = Boolean(r.matched)
  if (!on) return <span className="flex items-center gap-2 text-mute"><span className="h-2.5 w-2.5 shrink-0 rounded-full ring-1 ring-faint" />no match</span>
  const tip = r.matches.map((m) => `${m.where}: ${m.detail} (${m.provenance})`).join('\n')
  return (
    <span className="flex items-start gap-2" title={tip || 'matched'}>
      <span className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${DOT[r.severity ?? ''] ?? 'bg-faint'}`} />
      <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {r.matches.length === 0 && <span>matched</span>}
        {r.matches.map((m, i) => (
          <span key={`${m.where}-${i}`} className="inline-flex items-center gap-1.5">{m.where}<Prov p={provOf(m.provenance)} label={m.provenance} /></span>
        ))}
      </span>
    </span>
  )
}

function SeverityCell({ s }: { s: Severity }) {
  return s ? <TierPill tier={s} /> : <span className="text-mute">—</span>
}

/** Enrichment from the public feeds and the record, each with its provenance; hover for the feed. */
function Enrichment({ rows }: { rows: IocEnrich[] }) {
  if (!rows.length) return <span className="text-mute">—</span>
  return (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      {rows.map((e, i) => (
        <span key={`${e.source}-${i}`} className="inline-flex items-center gap-1.5" title={e.source}>{e.detail}<Prov p={provOf(e.provenance)} label={e.provenance} /></span>
      ))}
    </span>
  )
}

function ImportTable({ rows }: { rows: IocRow[] }) {
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-mute">
        <tr><th className={TH}>Indicator</th><th className={TH}>Type</th><th className={TH}>Matched</th><th className={TH}>Severity</th><th className="pb-2 font-normal">Enrichment</th></tr>
      </thead>
      <tbody>
        {sortRows(rows).map((r) => (
          <tr key={r.id} className="border-t border-line align-top">
            <td className="py-2.5 pr-3 font-mono text-[13px] break-all">{r.defanged}</td>
            <td className="whitespace-nowrap py-2.5 pr-3 text-mute">{typeLabel(r.type)}</td>
            <td className="py-2.5 pr-3"><Matched r={r} /></td>
            <td className="py-2.5 pr-3"><SeverityCell s={r.severity} /></td>
            <td className="py-2.5"><Enrichment rows={r.enrich} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function HeldTable({ rows }: { rows: IocRow[] }) {
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-mute">
        <tr>
          <th className={TH}>Indicator</th><th className={TH}>Type</th><th className={TH}>Source</th><th className={TH}>Severity</th>
          <th className={TH}>Matched</th><th className="pb-2 font-normal whitespace-nowrap">Last seen</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.id} className="border-t border-line align-top">
            <td className="py-2 pr-3 font-mono text-[13px] break-all">{r.defanged}</td>
            <td className="whitespace-nowrap py-2 pr-3 text-mute">{typeLabel(r.type)}</td>
            <td className="py-2 pr-3"><span className="font-medium">{r.source ?? '—'}</span>{r.tlp && <span className="ml-1.5 text-xs text-mute">TLP:{r.tlp}</span>}</td>
            <td className="py-2 pr-3"><SeverityCell s={r.severity} /></td>
            <td className="py-2 pr-3"><Matched r={r} /></td>
            <td className="whitespace-nowrap py-2 font-mono text-xs text-mute">{fmtDate(r.last_seen)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** The Indicators page of the Intel view: bring indicators in, see what is held, hand it on. */
export function IocImport() {
  const toast = useToast()
  const [text, setText] = useState('')
  const [source, setSource] = useState('analyst paste')
  const [tlp, setTlp] = useState<Tlp>('AMBER')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string>()
  const [res, setRes] = useState<ImportResult>()
  const [held, setHeld] = useState<Held>()
  const [matchedOnly, setMatchedOnly] = useState(false)
  const [taxii, setTaxii] = useState<TaxiiTest>()
  const [taxiiBusy, setTaxiiBusy] = useState(false)

  const refresh = useCallback(() => {
    fetch(`/api/iocs?limit=200&matched_only=${matchedOnly}`).then((r) => r.json()).then(setHeld).catch(() => undefined)
  }, [matchedOnly])
  useEffect(() => {
    let alive = true
    const pull = () => fetch(`/api/iocs?limit=200&matched_only=${matchedOnly}`).then((r) => r.json()).then((d) => alive && setHeld(d)).catch(() => undefined)
    pull()
    const id = setInterval(pull, 15000)   // the live engine re-matches addresses against the flows every 15 s
    return () => { alive = false; clearInterval(id) }
  }, [matchedOnly])

  const run = async () => {
    if (!text.trim() || busy) return
    setBusy(true)
    setErr(undefined)
    try {
      const r = await fetch('/api/iocs/import', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text, source: source.trim() || 'analyst paste', tlp }) })
      const d = await r.json()
      if (!r.ok) throw new Error(typeof d?.detail === 'string' ? d.detail : `HTTP ${r.status}`)
      setRes(d as ImportResult)
      toast(`${d.found} indicator${d.found === 1 ? '' : 's'} found, ${d.matched} matched in ${d.seconds} s`)
      refresh()
    } catch (e) {
      setErr(`Could not import: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setBusy(false)
    }
  }

  /* The dashboard's own origin first (the API serves /taxii2/ next to /api/); on the Vite dev server, which proxies only
     /api, fall back to the API on port 8000 so the test still reaches a real TAXII server. */
  const testTaxii = async () => {
    setTaxiiBusy(true)
    setTaxii(undefined)
    const bases = [...new Set([window.location.origin, `${window.location.protocol}//${window.location.hostname}:8000`])]
    for (const base of bases) {
      try {
        const r = await fetch(`${base}/taxii2/odyssey/collections/`, { headers: { Accept: 'application/taxii+json;version=2.1' } })
        if (!r.ok || !(r.headers.get('content-type') ?? '').includes('json')) continue
        const d = (await r.json()) as { collections: TaxiiCollection[] }
        setTaxii({ base, collections: d.collections ?? [] })
        setTaxiiBusy(false)
        return
      } catch { /* try the next base */ }
    }
    setTaxii({ collections: [], error: 'No TAXII server answered on this origin or on port 8000.' })
    setTaxiiBusy(false)
  }

  const origin = window.location.origin
  const lines = text.split('\n').filter((l) => l.trim()).length

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-14">
      <Section title="Bring in indicators"
               sub="Paste what a partner sent. Every IPv4 address, domain, URL, hash and CVE id is extracted, refanged and matched against our telemetry and exposure, then kept with its source and TLP. Matches from our simulated sensors are labelled SIM; enrichment from public feeds (Feodo Tracker, CISA KEV, OpenPhish) is REAL. No language model is involved.">
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={10} placeholder={PLACEHOLDER} spellCheck={false}
                  className="w-full resize-y rounded-2xl bg-panel-2 p-4 font-mono text-sm outline-none ring-1 ring-transparent placeholder:text-faint focus:ring-text" />
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-mute">Source
            <input value={source} onChange={(e) => setSource(e.target.value)} placeholder="analyst paste"
                   className="w-56 rounded-full bg-panel-2 px-4 py-2 text-sm text-text outline-none focus:ring-1 focus:ring-text" />
          </label>
          <label className="flex items-center gap-2 text-sm text-mute">TLP
            <select value={tlp} onChange={(e) => setTlp(e.target.value as Tlp)}
                    className="rounded-full bg-panel-2 px-4 py-2 text-sm font-medium text-text outline-none focus:ring-1 focus:ring-text">
              {TLPS.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <button type="button" onClick={() => { setText(SAMPLE); setErr(undefined) }} className="text-sm font-medium text-accent hover:underline">Try an example</button>
          <span className="ml-auto text-xs text-mute">{lines ? `${n(lines)} line${lines === 1 ? '' : 's'}` : 'nothing pasted yet'}</span>
          <button onClick={run} disabled={busy || !text.trim()} className={PRIMARY}>
            {busy ? <Loader2 size={16} className="animate-spin" /> : <Upload size={16} />} {busy ? 'Matching…' : 'Import and match'}
          </button>
        </div>
        {err && <div className="mt-3 rounded-2xl bg-panel-2 px-4 py-3 text-sm">{err}</div>}

        {res && (
          <div className="mt-8">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Stat value={n(res.found)} label="Found" sub={`read as ${FORMAT_LABEL[res.format] ?? res.format} · ${res.source} · TLP:${res.tlp}`} />
              <Stat value={n(res.new)} label="New" sub="not held before this import" />
              <Stat value={n(res.matched)} label="Matched" sub="against our telemetry or exposure" tone={res.matched ? undefined : 'text-mute'} />
              <Stat value={res.seconds.toFixed(2)} label="Seconds" sub="extract, refang, match, enrich" />
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {Object.entries(res.by_type).sort((a, b) => b[1] - a[1]).map(([t, c]) => (
                <Badge key={t}>{typeLabel(t)} <span className="font-semibold text-text">{n(c)}</span></Badge>
              ))}
            </div>
            <div className="mt-5">
              {res.indicators.length ? <ImportTable rows={res.indicators} /> : <div className="rounded-2xl bg-panel-2 p-5 text-mute">Nothing recognisable in that paste.</div>}
            </div>
          </div>
        )}
      </Section>

      <Section title="What is held" sub="Every indicator kept, with its source, TLP and where it matched. Addresses and domains are re-matched against the live flows every 15 s; a new match fires into the live feed."
               action={<Pill onClick={() => setMatchedOnly((v) => !v)}>{matchedOnly ? <><Check size={14} /> Matched only</> : 'Show matched only'}</Pill>}>
        {!held ? <div className="py-6 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Reading the indicator store…</div> : (
          <>
            <div className="grid grid-cols-3 gap-3 md:max-w-2xl">
              <Stat value={n(held.total)} label="Indicators held" sub={Object.entries(held.by_type).sort((a, b) => b[1] - a[1]).map(([t, c]) => `${n(c)} ${typeLabel(t)}`).join(' · ') || 'none yet'} />
              <Stat value={n(held.matched)} label="Matched" sub="in telemetry or exposure" tone={held.matched ? undefined : 'text-mute'} />
              <Stat value={n(held.imports.length)} label="Imports" sub="the last ten are listed" />
            </div>
            <div className="mt-6 grid gap-10 xl:grid-cols-[minmax(0,1.75fr)_minmax(0,1fr)]">
              <div className="min-w-0">
                {held.indicators.length === 0
                  ? <div className="rounded-2xl bg-panel-2 p-5 text-mute">{matchedOnly ? 'No held indicator has matched yet.' : 'Nothing held yet. Paste indicators above, or try the example.'}</div>
                  : <HeldTable rows={held.indicators} />}
                {held.indicators.length >= 200 && <p className="mt-2 text-xs text-mute">Showing the first 200; export the full set below.</p>}
              </div>
              <div className="min-w-0">
                <h3 className="text-xl font-bold">Previous imports</h3>
                {held.imports.length === 0 && <div className="mt-2 rounded-2xl bg-panel-2 p-5 text-mute">No imports yet.</div>}
                <div className="mt-1">
                  {held.imports.map((i) => (
                    <Row key={i.id}
                         lead={<span className="text-[9px] font-bold tracking-wide text-mute">{(FORMAT_LABEL[i.format] ?? i.format).replace(' 2.1', '').toUpperCase()}</span>}
                         title={<span>{i.source} <span className="text-xs font-normal text-mute">TLP:{i.tlp}</span></span>}
                         sub={`${fmtDate(i.ts)} · read as ${FORMAT_LABEL[i.format] ?? i.format} · ${i.seconds} s`}
                         trail={<span className="tabular-nums"><span className="text-mute">{n(i.found)} found · {n(i.new)} new · </span><b>{n(i.matched)} matched</b></span>} />
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </Section>

      <Section title="Exchange" sub="Hand the indicators on in the formats the rest of the stack reads. Every row carries its severity, where it matched and its provenance.">
        <div className="max-w-5xl">
          <Row lead={<FileSpreadsheet size={18} />} title="Indicators as CSV"
               sub="one row per indicator: value, defanged form, type, severity, where it matched, enrichment, source, TLP, first and last seen"
               trail={<a href="/api/iocs/export?format=csv" download="odyssey-indicators.csv" className={PRIMARY}><Download size={14} /> Download</a>} />
          <Row lead={<FileJson size={18} />} title="Indicators as STIX 2.1"
               sub="a bundle of indicator objects with STIX patterns, confidence and provenance, for OpenCTI, MISP or any STIX consumer"
               trail={<a href="/api/iocs/export?format=stix" download="odyssey-indicators.stix.json" className={PRIMARY}><Download size={14} /> Download</a>} />
          <Row lead={<Server size={18} />} title="TAXII 2.1 server"
               sub={<span>discovery <span className="font-mono text-text">{origin}/taxii2/</span> · collections <span className="font-mono text-text">graph</span>, <span className="font-mono text-text">indicators</span>, <span className="font-mono text-text">vulnerabilities</span></span>}
               trail={<button onClick={testTaxii} disabled={taxiiBusy} className="inline-flex items-center gap-2 rounded-full bg-panel-2 px-4 py-2 text-sm font-medium hover:bg-panel-3 disabled:opacity-40">
                 {taxiiBusy ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />} Test it
               </button>} />
          <p className="mt-3 text-sm text-mute">Any TAXII client (OpenCTI, MISP, a SIEM) can pull the graph, the indicators and the vulnerabilities; read-only; bearer token when ODYSSEY_TAXII_TOKEN is set.</p>
          {taxii && (
            <div className="mt-3 rounded-2xl bg-panel-2 px-4 py-3 text-sm">
              {taxii.error ? <span className="text-mute">{taxii.error}</span> : (
                <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="inline-flex items-center gap-1.5 font-medium"><Check size={14} className="text-ok" /> {taxii.collections.length} collection{taxii.collections.length === 1 ? '' : 's'}</span>
                  {taxii.collections.map((c) => <span key={c.id} title={c.description ?? c.id}>{c.title}{c.alias && <span className="ml-1 font-mono text-xs text-mute">{c.alias}</span>}</span>)}
                  <span className="ml-auto font-mono text-xs text-mute">{taxii.base}/taxii2/odyssey/collections/</span>
                </span>
              )}
            </div>
          )}
        </div>
      </Section>
    </div>
  )
}
