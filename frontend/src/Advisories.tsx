import { ClipboardPaste, Loader2, ScanText, ShieldCheck, Sparkles } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Badge, deadlineText, Prov, TierPill } from './ui'
import type { Tier } from './api'

interface Exposure {
  asset_id: string; org_id: string; org: string; sector: string; hostname: string; version: string; zone: string
  status: string; tier: Tier; risk: number; deadline_hours: number | null; decision: string; reason: string
}
interface Analysis {
  id: string; title: string; provenance: string
  iocs: Record<'cves' | 'ips' | 'domains' | 'urls' | 'sha256', string[]>
  entities: { type: string; text: string; score: number }[]
  product: { id: string | null; label: string | null; method: string; evidence: string | null }
  constraints: { op: string; version: string; polarity: string; start?: string }[]
  predicted_cvss: { vector: string | null; score: number | null }
  exploitation_claim: string | null
  exposed: Exposure[]; cleared: Exposure[]; unknown: Exposure[]
  sectors_targeted: string[]
  timings: Record<string, number>
  cached?: boolean
}
interface Item { id: string; title: string; severity: string; published: string; provenance: string; note: string; text: string; analysis: Analysis }

const IOC_LABEL = { ips: 'IP', domains: 'Domain', urls: 'URL', sha256: 'SHA-256' } as const

function constraintText(c: Analysis['constraints'][number]) {
  const v = c.op === 'range' ? `${c.start} → ${c.version}` : `${c.op === 'lt' ? 'before' : 'up to'} ${c.version}`
  return `${c.polarity === 'unaffected' ? 'not affected: ' : ''}${v}`
}

function AnalysisView({ a, text }: { a: Analysis; text?: string }) {
  const iocCount = (Object.keys(IOC_LABEL) as (keyof typeof IOC_LABEL)[]).reduce((n, k) => n + a.iocs[k].length, 0)
  const orgs = new Set(a.exposed.map((e) => e.org_id))
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-xl border border-line bg-panel-2 p-4">
          <div className="text-xs text-mute">Product identified</div>
          <div className="mt-1 text-lg font-semibold">{a.product.label ?? 'None in our estate'}</div>
          <div className="mt-1 text-xs text-mute">{a.product.method}</div>
        </div>
        <div className="rounded-xl border border-line bg-panel-2 p-4">
          <div className="text-xs text-mute">Exposed</div>
          <div className="mt-1 text-lg font-semibold">{a.exposed.length} assets · {orgs.size} orgs</div>
          <div className="mt-1 text-xs text-mute">{a.cleared.length} cleared by version evidence</div>
        </div>
        <div className="rounded-xl border border-line bg-panel-2 p-4">
          <div className="text-xs text-mute">Severity (ML, from text)</div>
          <div className="mt-1 text-lg font-semibold">{a.predicted_cvss.score ?? '—'}</div>
          <div className="mt-1 truncate font-mono text-[10px] text-mute">{a.predicted_cvss.vector}</div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1 text-xs">
        {a.exploitation_claim && <Badge tone="crit">exploitation claimed: "{a.exploitation_claim}"</Badge>}
        {a.sectors_targeted.map((s) => <Badge key={s} tone="accent">targets {s}</Badge>)}
        {a.constraints.map((c, i) => <Badge key={i}>{constraintText(c)}</Badge>)}
        {a.iocs.cves.map((c) => <Badge key={c}>{c}</Badge>)}
        <span className="ml-auto text-mute">analysed in {a.timings.total_ms} ms{a.cached ? ' (cached)' : ''}</span>
      </div>

      {a.exposed.length > 0 && (
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-mute">Who must act</div>
          <table className="w-full text-sm">
            <tbody>
              {a.exposed.map((e) => (
                <tr key={e.asset_id} className="border-t border-line/60">
                  <td className="py-2 pr-3"><TierPill tier={e.tier} /></td>
                  <td className="pr-3">{e.org}<div className="text-xs text-mute">{e.sector}</div></td>
                  <td className="pr-3 font-mono text-xs">{e.hostname}<div className="text-mute">{e.version} · {e.zone}</div></td>
                  <td className="pr-3 font-mono text-xs">{deadlineText(e.deadline_hours)}</td>
                  <td className="text-xs text-mute">{e.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      {a.cleared.length > 0 && (
        <section>
          <div className="mb-2 flex items-center gap-1 text-xs uppercase tracking-wider text-mute"><ShieldCheck size={12} className="text-ok" /> Cleared — no alert sent</div>
          <div className="flex flex-wrap gap-1">
            {a.cleared.map((e) => <Badge key={e.asset_id} tone="ok">{e.org_id} · {e.version}</Badge>)}
          </div>
        </section>
      )}

      {iocCount > 0 && (
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-mute">Indicators (defanged) — ready to block</div>
          <div className="space-y-1">
            {(Object.keys(IOC_LABEL) as (keyof typeof IOC_LABEL)[]).flatMap((k) => a.iocs[k].map((v) => (
              <div key={k + v} className="flex items-center gap-2 text-xs">
                <span className="w-16 shrink-0 text-mute">{IOC_LABEL[k]}</span>
                <code className="truncate rounded bg-ink px-2 py-0.5">{v}</code>
              </div>
            )))}
          </div>
        </section>
      )}

      <section>
        <div className="mb-2 flex items-center gap-1 text-xs uppercase tracking-wider text-mute"><Sparkles size={12} /> Entities (SecureBERT 2.0, on-device)</div>
        <div className="flex flex-wrap gap-1">
          {a.entities.map((e) => <Badge key={e.type + e.text}>{e.type}: {e.text}</Badge>)}
        </div>
      </section>

      {a.product.evidence && (
        <div className="text-xs text-mute">Product evidence quoted by the model: "<span className="text-text">{a.product.evidence}</span>"</div>
      )}
      {text && <details className="text-xs text-mute"><summary className="cursor-pointer">Source text</summary><p className="mt-2 leading-relaxed">{text}</p></details>}
    </div>
  )
}

export function Advisories() {
  const [items, setItems] = useState<Item[]>()
  const [sel, setSel] = useState(0)
  const [paste, setPaste] = useState('')
  const [pasted, setPasted] = useState<Analysis>()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string>()

  useEffect(() => { fetch('/api/advisories').then((r) => r.json()).then(setItems).catch((e) => setErr(String(e))) }, [])

  const analyse = async () => {
    setBusy(true); setErr(undefined)
    try {
      const r = await fetch('/api/advisories/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: paste }) })
      if (!r.ok) throw new Error((await r.json()).detail)
      setPasted(await r.json())
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  if (!items) return <div className="flex items-center gap-2 p-8 text-mute"><Loader2 className="animate-spin" size={16} /> Reading the advisory inbox…</div>
  const current = items[sel]

  return (
    <div className="flex min-w-0 flex-1 gap-5">
      <aside className="flex w-96 shrink-0 flex-col gap-3 overflow-auto">
        <div className="rounded-2xl border border-line bg-panel p-4">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold"><ClipboardPaste size={14} /> Paste any advisory</div>
          <textarea value={paste} onChange={(e) => setPaste(e.target.value)} rows={5}
                    placeholder="Paste a CERT-In note, vendor bulletin or email. Odyssey finds the product, versions and indicators, and tells you who is exposed."
                    className="w-full resize-none rounded-lg border border-line bg-ink p-2 text-xs outline-none focus:border-accent" />
          <button onClick={analyse} disabled={busy || paste.trim().length < 40}
                  className="mt-2 flex w-full items-center justify-center gap-2 rounded-full bg-accent py-2 text-sm font-semibold text-ink disabled:opacity-40">
            {busy ? <Loader2 size={14} className="animate-spin" /> : <ScanText size={14} />} Analyse
          </button>
        </div>
        <div className="text-xs uppercase tracking-wider text-mute">Advisory inbox</div>
        {items.map((it, i) => (
          <button key={it.id} onClick={() => { setSel(i); setPasted(undefined) }}
                  className={`rounded-xl border p-3 text-left ${i === sel && !pasted ? 'border-accent bg-panel-2' : 'border-line bg-panel hover:bg-panel-2'}`}>
            <div className="flex items-center gap-2">
              <Prov p={it.provenance} />
              <span className="font-mono text-xs text-mute">{it.id}</span>
            </div>
            <div className="mt-1 text-sm font-medium">{it.title}</div>
            <div className="mt-1 text-xs text-mute">
              {it.analysis.exposed.length ? `${it.analysis.exposed.length} assets exposed` : it.analysis.sectors_targeted.length ? `campaign · ${it.analysis.sectors_targeted.join(', ')}` : 'no exposure'}
            </div>
          </button>
        ))}
      </aside>
      <section className="min-w-0 flex-1 overflow-auto rounded-2xl border border-line bg-panel p-6">
        {err && <div className="mb-3 text-sm text-crit">{err}</div>}
        {pasted ? (
          <>
            <h2 className="mb-4 text-2xl font-semibold">Pasted advisory</h2>
            <AnalysisView a={pasted} text={paste} />
          </>
        ) : (
          <>
            <div className="mb-1 flex items-center gap-2"><Prov p={current.provenance} /><span className="font-mono text-xs text-mute">{current.id} · {current.published?.slice(0, 10)}</span></div>
            <h2 className="mb-1 text-2xl font-semibold">{current.title}</h2>
            <p className="mb-4 text-xs text-mute">{current.note}</p>
            <AnalysisView a={current.analysis} text={current.text} />
          </>
        )}
      </section>
    </div>
  )
}
