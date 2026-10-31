import { Loader2, ScanText, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { Tier } from './api'
import { Badge, deadlineText, Pill, Prov, Row, Section, Sheet, Stat, TIER_FILL } from './ui'

/* Advisories, Uber-simple: the inbox on the left; on the right one advisory answered as "what is it, who must act,
   what to block". How the text was read (entities, references, source) waits behind one pill. */

interface Exposure {
  asset_id: string; org_id: string; org: string; sector: string; hostname: string; version: string; zone: string
  status: string; tier: Tier; risk: number; deadline_hours: number | null; decision: string; reason: string
}
interface Analysis {
  id: string; title: string; provenance: string
  iocs: Record<'cves' | 'ips' | 'domains' | 'urls' | 'sha256', string[]> & { references?: string[] }
  entities: { type: string; text: string; score: number }[]
  product: { id: string | null; label: string | null; method: string; evidence: string | null }
  constraints: { op: string; version: string; polarity: string; start?: string }[]
  predicted_cvss: { vector: string | null; score: number | null }
  exploitation_claim: string | null
  exposed: Exposure[]; cleared: Exposure[]; unknown: Exposure[]
  sectors_targeted: string[]
  timings: Record<string, number>
  cached?: boolean
  guard?: { verdict: string; p_injection?: number; rules?: string[]; model?: string }
  supply_chain?: { id: string; name: string; service: string; dependents: { org_id: string; name: string; runs_it_too: boolean }[] }[]
}
interface Item { id: string; title: string; severity: string; published: string; provenance: string; note: string; text: string; analysis: Analysis }

const IOC_LABEL = { ips: 'IP address', domains: 'Domain', urls: 'URL', sha256: 'File hash' } as const
const TIER_RANK: Record<string, number> = { Compromise: 0, Critical: 1, High: 2, Medium: 3, Watch: 4 }

function constraintText(c: Analysis['constraints'][number]) {
  const v = c.op === 'range' ? `${c.start} → ${c.version}` : `${c.op === 'lt' ? 'before' : 'up to'} ${c.version}`
  return `${c.polarity === 'unaffected' ? 'not affected: ' : ''}${v}`
}

function AnalysisView({ a, text }: { a: Analysis; text?: string }) {
  const [all, setAll] = useState(false)
  const [how, setHow] = useState(false)
  const iocs = (Object.keys(IOC_LABEL) as (keyof typeof IOC_LABEL)[]).flatMap((k) => a.iocs[k].map((v) => [k, v] as const))
  const supply = a.supply_chain ?? []
  // one row per organisation: worst tier, earliest deadline, its hosts and versions
  const byOrg = Object.values(a.exposed.reduce<Record<string, Exposure[]>>((m, e) => { (m[e.org_id] ??= []).push(e); return m }, {}))
    .map((es) => es.sort((x, y) => TIER_RANK[x.tier] - TIER_RANK[y.tier]))
    .sort((x, y) => TIER_RANK[x[0].tier] - TIER_RANK[y[0].tier] || y.length - x.length)
  const hostile = a.guard && a.guard.verdict !== 'clean'
  return (
    <div className="flex flex-col gap-10">
      {hostile && (
        <div className="rounded-3xl bg-band p-6 text-white">
          <div className="flex items-center gap-3">
            <span className="rounded-full bg-crit px-3 py-1 text-xs font-semibold">Prompt injection {a.guard!.verdict}</span>
            <span className="text-sm text-band-mute">{a.guard!.model ?? 'guard'}{a.guard!.rules?.length ? ` · rules: ${a.guard!.rules.join(', ')}` : ''}</span>
          </div>
          <p className="mt-3 text-lg">This advisory carries instructions aimed at AI systems. The security model was never given its text:
            the product, versions, exposure and indicators below come from the deterministic layer only, and nothing it asks for was done.</p>
        </div>
      )}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <Stat value={<span className="text-2xl leading-tight">{a.product.label ?? 'Not in our estate'}</span>} label="product identified" sub={a.product.method} />
        <Stat value={`${a.exposed.length}`} label={`assets exposed at ${byOrg.length} organisation${byOrg.length === 1 ? '' : 's'}`} sub={`${a.cleared.length} cleared by version evidence`} />
        <Stat value={a.predicted_cvss.score ?? '—'} label="severity, read from the text" sub="CVSS predicted on the CPU" />
      </div>

      {(a.exploitation_claim || a.sectors_targeted.length > 0 || a.constraints.length > 0) && (
        <div className="flex flex-wrap items-center gap-2">
          {a.exploitation_claim && <Badge tone="crit">exploitation claimed: "{a.exploitation_claim}"</Badge>}
          {a.sectors_targeted.map((s) => <Badge key={s} tone="accent">targets {s}</Badge>)}
          {a.constraints.map((c, i) => <Badge key={i}>{constraintText(c)}</Badge>)}
        </div>
      )}

      {byOrg.length > 0 && (
        <Section title="Who must act" sub="One row per organisation, most urgent first. Each is notified in its own language once an analyst approves."
                 action={byOrg.length > 6 ? <Pill onClick={() => setAll(!all)}>{all ? 'Show fewer' : `See all ${byOrg.length}`}</Pill> : undefined}>
          {byOrg.slice(0, all ? undefined : 6).map((es) => (
            <Row key={es[0].org_id} lead={<span className="h-3 w-3 rounded-full" style={{ background: TIER_FILL[es[0].tier] }} />}
                 title={es[0].org}
                 sub={`${es.length} asset${es.length === 1 ? '' : 's'}: ${es.slice(0, 3).map((e) => `${e.hostname.split('.')[0]} (${e.version})`).join(', ')}${es.length > 3 ? '…' : ''} · ${es[0].sector}`}
                 trail={<span><b>{es[0].tier}</b><span className="block text-xs text-mute">due {deadlineText(es[0].deadline_hours)}</span></span>} />
          ))}
        </Section>
      )}

      {supply.length > 0 && (
        <Section title="Through suppliers" sub="Providers that run this product for other organisations. Their dependents are asked to confirm the supplier is patched, even if they do not run it themselves."
                 action={<Prov p="SIM" label="SIM supplier graph" />}>
          {supply.map((sp) => (
            <Row key={sp.id} lead={<span className="text-[10px] font-bold">SUP</span>} title={`${sp.name} · ${sp.service}`}
                 sub={sp.dependents.map((x) => x.name + (x.runs_it_too ? '' : ' (via supplier only)')).join(', ')}
                 trail={<span><b>{sp.dependents.length}</b><span className="block text-xs text-mute">organisations</span></span>} />
          ))}
        </Section>
      )}

      {iocs.length > 0 && (
        <Section title="Ready to block" sub="Indicators from the advisory, defanged. Vendor and CERT links are kept apart and never blocked.">
          {iocs.map(([k, v]) => (
            <Row key={k + v} lead={<span className="text-[10px] font-bold">{k === 'sha256' ? 'SHA' : k === 'ips' ? 'IP' : k === 'urls' ? 'URL' : 'DNS'}</span>}
                 title={<code className="text-sm">{v}</code>} sub={IOC_LABEL[k]} />
          ))}
        </Section>
      )}

      <div className="flex flex-wrap items-center gap-3 text-sm text-mute">
        <Pill onClick={() => setHow(true)}>How Odyssey read it</Pill>
        analysed on this laptop in {a.timings.total_ms} ms{a.cached ? ' (cached)' : ''}
      </div>

      {how && (
        <Sheet wide title="How Odyssey read this advisory" sub="Guard model first, then SecureBERT 2.0 entities, version parsing and a closed-set product match against the inventory." onClose={() => setHow(false)}>
          <div className="flex flex-col gap-10">
            {a.cleared.length > 0 && (
              <Section title="Cleared, no alert sent" sub="Installed versions outside the affected ranges.">
                <div className="flex flex-wrap gap-1.5">
                  {a.cleared.map((e) => <Badge key={e.asset_id} tone="ok"><ShieldCheck size={12} /> {e.org_id} · {e.version}</Badge>)}
                </div>
              </Section>
            )}
            {(a.iocs.references?.length ?? 0) > 0 && (
              <Section title="Reference links" sub="Vendor and CERT guidance: for reading, not for blocking.">
                {a.iocs.references!.map((u) => <a key={u} href={u} target="_blank" rel="noreferrer" className="block truncate py-1 text-accent hover:underline">{u}</a>)}
              </Section>
            )}
            <Section title="Entities" sub="Found by SecureBERT 2.0 on the CPU; shown as context, never used to decide.">
              <div className="flex flex-wrap gap-1.5">
                {a.entities.map((e) => <Badge key={e.type + e.text}>{e.type}: {e.text}</Badge>)}
              </div>
            </Section>
            {a.product.evidence && <p className="text-mute">Product evidence quoted by the model: "<span className="text-text">{a.product.evidence}</span>"</p>}
            {text && <Section title="Source text"><p className="whitespace-pre-wrap leading-relaxed text-mute">{text}</p></Section>}
          </div>
        </Sheet>
      )}
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

  if (!items) return <div className="flex items-center gap-2 py-10 text-mute"><Loader2 className="animate-spin" size={16} /> Reading the advisory inbox…</div>
  const current = items[sel]

  return (
    <div className="flex min-w-0 flex-1 items-start gap-12">
      <aside className="sticky top-24 flex max-h-[calc(100vh-7rem)] w-[400px] shrink-0 flex-col gap-6 overflow-auto pr-1">
        <div className="rounded-2xl bg-panel-2 p-5">
          <div className="mb-3 text-xl font-bold">Paste any advisory</div>
          <textarea value={paste} onChange={(e) => setPaste(e.target.value)} rows={5}
                    placeholder="A CERT-In note, vendor bulletin or email. Odyssey finds the product, versions and indicators, and who is exposed."
                    className="w-full resize-none rounded-xl bg-panel p-3 text-sm outline-none ring-1 ring-line focus:ring-text" />
          <button onClick={analyse} disabled={busy || paste.trim().length < 40}
                  className="mt-3 flex w-full items-center justify-center gap-2 rounded-full bg-action py-3 font-semibold text-ink disabled:opacity-40">
            {busy ? <Loader2 size={16} className="animate-spin" /> : <ScanText size={16} />} Analyse
          </button>
        </div>
        <div>
          <div className="mb-1 text-xl font-bold">Inbox</div>
          {items.map((it, i) => (
            <button key={it.id} onClick={() => { setSel(i); setPasted(undefined) }}
                    className={`mb-1 w-full rounded-2xl px-4 py-3 text-left ${i === sel && !pasted ? 'bg-panel-2' : 'hover:bg-soft'}`}>
              <div className="flex items-center gap-2"><Prov p={it.provenance} /><span className="font-mono text-xs text-faint">{it.id}</span></div>
              <div className="mt-1 font-semibold leading-snug">{it.title}</div>
              <div className="text-sm text-mute">
                {it.analysis.guard && it.analysis.guard.verdict !== 'clean' && <span className="mr-2 font-semibold text-crit">injection blocked ·</span>}
                {it.analysis.exposed.length ? `${it.analysis.exposed.length} assets exposed` : it.analysis.sectors_targeted.length ? `campaign · ${it.analysis.sectors_targeted.join(', ')}` : 'no exposure'}
              </div>
            </button>
          ))}
        </div>
      </aside>
      <section className="min-w-0 max-w-5xl flex-1">
        {err && <div className="mb-4 rounded-2xl bg-crit/10 px-4 py-3 text-crit">{err}</div>}
        {pasted ? (
          <>
            <h2 className="mb-8 text-4xl font-bold tracking-tight">Pasted advisory</h2>
            <AnalysisView key="pasted" a={pasted} text={paste} />
          </>
        ) : (
          <>
            <div className="mb-2 flex items-center gap-2"><Prov p={current.provenance} /><span className="font-mono text-sm text-faint">{current.id} · {current.published?.slice(0, 10)}</span></div>
            <h2 className="text-4xl font-bold tracking-tight">{current.title}</h2>
            <p className="mt-2 mb-8 text-mute">{current.note}</p>
            <AnalysisView key={current.id} a={current.analysis} text={current.text} />
          </>
        )}
      </section>
    </div>
  )
}
