import { ExternalLink, Loader2, ShieldCheck } from 'lucide-react'
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { istTime } from './proactive'
import { Badge, Prov, Row, Section, Sheet, TierPill, useToast } from './ui'

/* The consented attack-surface scan. Odyssey assesses only systems the operator has proved they own: a loopback or
   private address, or an application the Odyssey agent announced. It reads the target's own HTTP answers over GET and
   HEAD (at most 40 requests, no payloads), grades the posture A to F, and names every finding with its CWE, the
   evidence and the fix. A refusal is a decision the server explains, not an error, so it is shown in a grey well.
   Everything here is REAL: it is what the target itself answered. No LLM is involved. */

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
type Grade = 'A' | 'B' | 'C' | 'D' | 'E' | 'F'

interface Finding {
  check: string; severity: Severity; title: string; detail: string; evidence: string; cwe: string; fix: string
  path: string | null; provenance: string
}
interface Product { product_key: string; known_cves_in_constituency: number }
/** What POST /api/surface/scan returns, and what a stored scan is normalised to. */
interface ScanResult {
  id?: number; ts: string; target: string; host: string; port?: number; org_id: string | null
  status: 'done' | 'refused' | 'unreachable'; reason: string | null; score: number | null; grade: Grade | null
  n_findings: number; requests: number; seconds: number; provenance: 'REAL'
  severity_counts: Record<Severity, number>; products?: Product[]; findings: Finding[]; how?: string
}
/** A row of GET /api/surface: the scans table plus the findings it stored (check_name, not check; findings is a count). */
interface StoredFinding { check_name: string; severity: Severity; title: string; detail: string; evidence: string; cwe: string; fix: string; path: string | null; provenance: string }
interface StoredScan {
  id: number; ts: string; target: string; host: string; org_id: string | null; consent: string; score: number | null; grade: Grade | null
  findings: number; seconds: number; requests: number; status: string; reason: string | null; findings_list: StoredFinding[]
}
interface CanScan { url: string; allowed: boolean; reason: string }

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
const ORDER: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }
/** Severity as a dot (the Row lead is a 40px circle, too small for a pill). Low and Info stay grey. */
const DOT: Record<Severity, string> = { Critical: 'bg-crit', High: 'bg-high', Medium: 'bg-med', Low: 'bg-faint', Info: 'bg-faint' }
/** Grade as a text colour on a grey well: A/B done, C Medium, D High, E/F Critical. Never a fill. */
const GRADE_TONE: Record<Grade, string> = { A: 'text-ok', B: 'text-ok', C: 'text-med', D: 'text-high', E: 'text-crit', F: 'text-crit' }
const PRODUCT_LABEL: Record<string, string> = {
  fastapi: 'FastAPI', django: 'Django', flask: 'Flask', express: 'Express', laravel: 'Laravel', wordpress: 'WordPress',
  nginx: 'nginx', httpd: 'Apache httpd', tomcat: 'Apache Tomcat', win2022: 'Windows Server (IIS)',
}

const DEFAULT_URL = 'http://127.0.0.1:8080'
const cweUrl = (cwe: string) => `https://cwe.mitre.org/data/definitions/${cwe.replace(/\D/g, '')}.html`
/** Whether the server would accept this target, and why, without scanning it. undefined when the API is unreachable. */
const canScan = (u: string): Promise<CanScan | undefined> =>
  fetch(`/api/surface/can-scan?url=${encodeURIComponent(u)}`).then((r) => r.json() as Promise<CanScan>).catch(() => undefined)
const bySeverity = (a: Finding, b: Finding) => ORDER[a.severity] - ORDER[b.severity]
const emptyCounts = (): Record<Severity, number> => ({ Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 })
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`

/** A stored scan has no severity_counts or products; rebuild what we can from its findings. */
function fromStored(s: StoredScan): ScanResult {
  const findings: Finding[] = s.findings_list.map((f) => ({
    check: f.check_name, severity: f.severity, title: f.title, detail: f.detail, evidence: f.evidence, cwe: f.cwe, fix: f.fix, path: f.path, provenance: f.provenance,
  })).sort(bySeverity)
  const counts = emptyCounts()
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1
  return {
    id: s.id, ts: s.ts, target: s.target, host: s.host, org_id: s.org_id, status: s.status === 'done' ? 'done' : s.status === 'unreachable' ? 'unreachable' : 'refused',
    reason: s.reason, score: s.score, grade: s.grade, n_findings: s.findings, requests: s.requests, seconds: s.seconds, provenance: 'REAL',
    severity_counts: counts, findings,
  }
}

function SeverityTag({ s }: { s: Severity }) {
  return s === 'Low' || s === 'Info' ? <Badge>{s}</Badge> : <TierPill tier={s} />
}

function Chip({ children, dot }: { children: ReactNode; dot?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-panel-2 px-3 py-1 text-xs font-medium">
      {dot && <span className={`h-2 w-2 rounded-full ${dot}`} />}{children}
    </span>
  )
}

/** The grade, the score and what was scanned, on one grey well. The letter is the only coloured text. */
function GradeTile({ r }: { r: ScanResult }) {
  return (
    <div className="flex items-center gap-7 rounded-2xl bg-panel-2 px-7 py-6">
      <div className={`text-7xl font-bold leading-none tracking-tight ${r.grade ? GRADE_TONE[r.grade] : 'text-mute'}`}>{r.grade ?? '—'}</div>
      <div className="min-w-0">
        <div className="text-3xl font-bold tabular-nums">{r.score ?? '—'}<span className="text-base font-medium text-mute"> / 100</span></div>
        <div className="mt-1 truncate font-mono text-sm font-medium">{r.target}</div>
        <div className="mt-1 flex flex-wrap items-center gap-x-1.5 text-xs text-mute">
          <span>{istTime(r.ts)} IST · {plural(r.requests, 'request')} · {r.seconds}s{r.org_id ? ` · ${r.org_id}` : ''}</span>
          <Prov p="REAL" />
        </div>
      </div>
    </div>
  )
}

export function SurfaceScan({ orgId, defaultUrl }: { orgId?: string; defaultUrl?: string }) {
  const [url, setUrl] = useState(defaultUrl ?? DEFAULT_URL)
  const [consent, setConsent] = useState(false)
  const [can, setCan] = useState<CanScan>()
  const [checking, setChecking] = useState(true)
  const [busy, setBusy] = useState(false)
  const [refusal, setRefusal] = useState<string>()
  const [result, setResult] = useState<ScanResult>()
  const [open, setOpen] = useState<Finding>()
  const [history, setHistory] = useState<StoredScan[]>()
  const toast = useToast()

  const loadHistory = useCallback(() => {
    fetch(`/api/surface?org_id=${encodeURIComponent(orgId ?? '')}`)
      .then((r) => r.json())
      .then((d: { scans: StoredScan[] }) => setHistory(d.scans ?? []))
      .catch(() => undefined)
  }, [orgId])
  useEffect(() => { loadHistory() }, [loadHistory])

  /** On focus-out: ask the server whether it would accept this target, without scanning it. */
  const check = (target: string) => {
    const u = target.trim()
    if (!u) { setCan(undefined); return }
    setChecking(true)
    canScan(u).then(setCan).finally(() => setChecking(false))
  }
  /* The same question once at start for the prefilled URL, so the verdict line is never empty. */
  useEffect(() => {
    let alive = true
    canScan((defaultUrl ?? DEFAULT_URL).trim()).then((d) => { if (alive) { setCan(d); setChecking(false) } })
    return () => { alive = false }
  }, [defaultUrl])

  const scan = () => {
    if (!consent || busy || !url.trim()) return
    setBusy(true)
    setRefusal(undefined)
    const body: Record<string, unknown> = { url: url.trim(), consent: true }
    if (orgId) body.org_id = orgId
    fetch('/api/surface/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(async (r) => {
        const d: unknown = await r.json().catch(() => ({}))
        if (r.status === 400) {
          const detail = typeof d === 'object' && d !== null && typeof (d as { detail?: unknown }).detail === 'string' ? (d as { detail: string }).detail : 'the scanner refused this target'
          setRefusal(detail)
          loadHistory()
          return
        }
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const res = d as ScanResult
        res.findings = [...res.findings].sort(bySeverity)
        setResult(res)
        toast(`Scanned ${res.host} in ${res.seconds}s: grade ${res.grade}, ${plural(res.n_findings, 'finding')}`)
        loadHistory()
      })
      .catch((e: Error) => toast(`Scan failed: ${e.message}`))
      .finally(() => setBusy(false))
  }

  /** A previous scan replaces the result area; a refused one shows its reason in the well instead. */
  const load = (s: StoredScan) => {
    if (s.status !== 'done') {
      setRefusal(`${s.target}, ${istTime(s.ts)} IST: ${s.reason ?? s.status}`)
      return
    }
    setRefusal(undefined)
    setResult(fromStored(s))
  }

  const counts = result ? SEVERITIES.filter((s) => (result.severity_counts[s] ?? 0) > 0) : []

  return (
    <Section title="Attack surface, with consent"
             sub="Odyssey scans only systems you have proved you own: a private or loopback address, or an app announced by the Odyssey agent. GET and HEAD only, at most 40 requests, no payloads."
             action={<Prov p="REAL" label="REAL · the target's own responses" />}>
      <div className="flex flex-col gap-10">
        {/* the form */}
        <div>
          <label htmlFor="surface-url" className="text-sm font-medium">Application URL</label>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <input id="surface-url" value={url} spellCheck={false} placeholder="http://127.0.0.1:8080"
                   onChange={(e) => { setUrl(e.target.value); setCan(undefined) }} onBlur={(e) => check(e.target.value)}
                   onKeyDown={(e) => { if (e.key === 'Enter') scan() }}
                   className="min-w-[320px] flex-1 rounded-full bg-panel-2 px-5 py-3 font-mono text-sm outline-none ring-1 ring-transparent focus:ring-text" />
            <button disabled={!consent || busy || !url.trim()} onClick={scan} title={consent ? 'Run the read-only scan' : 'Tick the consent box first'}
                    className="inline-flex items-center gap-2 rounded-full bg-action px-6 py-3 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-40">
              {busy ? <Loader2 size={16} className="animate-spin" /> : <ShieldCheck size={16} />}{busy ? 'Scanning…' : 'Scan'}
            </button>
          </div>
          <label className="mt-4 flex w-fit cursor-pointer items-center gap-2.5 text-sm">
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="h-4 w-4 accent-black" />
            I own this system and consent to a read-only scan
          </label>
          <div className="mt-3 flex items-center gap-2 text-sm text-mute">
            <span className={`h-2 w-2 shrink-0 rounded-full ${can?.allowed ? 'bg-ok' : 'bg-faint'}`} />
            {checking ? 'Asking the server whether this target can be scanned…'
              : can ? can.reason
              : 'Leave the field to check whether this target would be accepted.'}
          </div>
          {busy && <p className="mt-3 text-sm text-mute"><Loader2 size={14} className="mr-1 inline animate-spin" />Reading the target's own responses: headers, well-known paths, service ports. Up to 40 requests, a few seconds.</p>}
          {refusal && (
            <div className="mt-4 rounded-2xl bg-panel-2 p-5 text-mute">
              <span className="font-semibold text-text">Not scanned.</span> {refusal}
            </div>
          )}
        </div>

        {/* the result */}
        {!result && !refusal && !busy && (
          <div className="rounded-2xl bg-panel-2 p-6 text-mute">
            Nothing shown yet. Tick the box and press Scan, or open a previous scan below. Every finding carries its evidence, a CWE and a fix.
          </div>
        )}
        {result && (
          <div className="flex flex-col gap-6">
            <div className="grid gap-6 xl:grid-cols-[minmax(0,460px)_1fr]">
              <GradeTile r={result} />
              <div className="flex flex-col justify-center gap-4">
                <div>
                  <div className="text-sm font-medium">{plural(result.n_findings, 'finding')} by severity</div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {counts.map((s) => <Chip key={s} dot={DOT[s]}>{result.severity_counts[s]} {s}</Chip>)}
                    {counts.length === 0 && <span className="text-sm text-mute">No findings: nothing the scanner checks for answered.</span>}
                  </div>
                </div>
                <div>
                  <div className="text-sm font-medium">Fingerprinted software</div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {result.products?.map((p) => (
                      <Chip key={p.product_key}>{PRODUCT_LABEL[p.product_key] ?? p.product_key} · {plural(p.known_cves_in_constituency, 'known CVE')} in the constituency</Chip>
                    ))}
                    {result.products && result.products.length === 0 && <span className="text-sm text-mute">No framework or server named itself in the responses.</span>}
                    {!result.products && <span className="text-sm text-mute">Fingerprints are not kept for earlier scans; run it again to see them.</span>}
                  </div>
                </div>
                {result.how && <p className="text-xs text-mute">{result.how}</p>}
              </div>
            </div>
            <div>
              {result.findings.map((f, i) => (
                <Row key={`${f.check}-${f.title}-${i}`} onClick={() => setOpen(f)}
                     lead={<span className={`h-3 w-3 rounded-full ${DOT[f.severity]}`} />}
                     title={<span className="flex items-center gap-2"><SeverityTag s={f.severity} /><span className="truncate">{f.title}</span></span>}
                     sub={`${f.detail} · ${f.cwe}`}
                     trail={f.path ? <span className="font-mono text-xs text-mute">{/^\d+$/.test(f.path) ? `port ${f.path}` : f.path}</span> : undefined} />
              ))}
            </div>
          </div>
        )}

        {/* previous scans */}
        <div>
          <h3 className="text-xl font-bold">Previous scans</h3>
          <p className="mt-1 text-sm text-mute">{orgId ? `Scans recorded for ${orgId}, newest first.` : 'Every scan recorded, newest first.'} Open one to bring its findings back.</p>
          <div className="mt-2">
            {!history && <div className="py-3 text-sm text-mute"><Loader2 size={14} className="mr-1 inline animate-spin" />Reading the scan log…</div>}
            {history && history.length === 0 && <div className="py-3 text-sm text-mute">No scans recorded yet.</div>}
            {history?.map((s) => (
              <Row key={s.id} onClick={() => load(s)}
                   lead={<span className="text-sm font-bold">{s.grade ?? '—'}</span>}
                   title={<span className="flex items-center gap-2"><span className="truncate font-mono">{s.target}</span>{result?.id === s.id && <Badge tone="accent">Shown</Badge>}</span>}
                   sub={`${istTime(s.ts)} IST · ${s.status === 'done' ? `${plural(s.requests, 'request')} in ${s.seconds}s` : `${s.status}: ${s.reason ?? ''}`}${s.org_id ? ` · ${s.org_id}` : ''}`}
                   trail={s.status === 'done'
                     ? <span><span className="block font-semibold tabular-nums">{s.grade} · {s.score}/100</span><span className="block text-xs text-mute">{plural(s.findings, 'finding')}</span></span>
                     : <Badge>{s.status}</Badge>} />
            ))}
          </div>
        </div>

        <p className="text-sm text-mute">Public addresses are refused: deploy the Odyssey agent on the app or run the scanner from inside the network.</p>
      </div>

      {open && (
        <Sheet onClose={() => setOpen(undefined)}
               title={<span className="flex flex-wrap items-center gap-3">{open.title}<SeverityTag s={open.severity} /><Prov p="REAL" /></span>}
               sub={`${open.check} check · ${open.detail}`}>
          <div className="flex flex-col gap-8">
            <div>
              <h3 className="text-xl font-bold">Evidence</h3>
              <p className="mt-1 text-sm text-mute">What the target itself answered. Nothing was sent beyond GET and HEAD.</p>
              <pre className="mt-3 whitespace-pre-wrap break-all rounded-2xl bg-panel-2 p-4 font-mono text-sm leading-relaxed">{open.evidence}</pre>
            </div>
            <div>
              <h3 className="text-xl font-bold">Fix</h3>
              <p className="mt-2">{open.fix}</p>
            </div>
            <div>
              <h3 className="text-xl font-bold">Weakness</h3>
              <a href={cweUrl(open.cwe)} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-1 text-sm text-accent hover:underline">
                {open.cwe} on cwe.mitre.org <ExternalLink size={13} />
              </a>
            </div>
            {open.path && (
              <div>
                <h3 className="text-xl font-bold">Where</h3>
                <p className="mt-2 font-mono text-sm">{/^\d+$/.test(open.path) ? `TCP port ${open.path}` : open.path}</p>
              </div>
            )}
          </div>
        </Sheet>
      )}
    </Section>
  )
}
