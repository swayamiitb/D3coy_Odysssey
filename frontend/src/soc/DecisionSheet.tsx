import { Check, ChevronRight, Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { Tier } from '../api'
import { Badge, Objectives, Prov, Sheet, TierPill, useToast } from '../ui'

/* Step-by-step decision support for one warning (ui-15): evidence, options with the recommended one and why,
   confirm, done. Nothing runs until the person presses the last button; every step then taken is a hash-chained
   ledger event and comes back with its reference. Human in the loop, by construction. */

interface Evidence { label: string; value: string; detail?: string | null; source?: string | null; provenance?: string }
interface Option { id: string; label: string; why: string; steps: string[]; effects: string[]; available: boolean; recommended: boolean; targets?: Target[] }
interface Target { to: string; why: string; default: boolean }
interface Brief {
  alert: string; org: { id: string; name: string; sector: string; state: string; cii: boolean }; cve: string; tier: Tier; risk: number
  exploited: boolean; exposure: string; deadline_hours: number | null; deadline_basis: string | null
  evidence: Evidence[]; clocks: { who: string; what: string; hours: number | null; route?: string }[]
  options: Option[]; recommended: string; recommended_why: string; targets: Target[]
  workflow: { state: string }; case: { id: string; title: string; status: string } | null; pending: { id: number; title: string }[]
}
interface Executed { executed: { step: string; detail?: string; ref?: string; kind: string; case?: string }[]; workflow: { state: string }; case: { id: string; status: string } | null; audit: string }

const STEPS = ['Evidence', 'Options', 'Confirm', 'Done']

export function DecisionSheet({ org, cve, onClose, onDone, onGo }: {
  org: string; cve: string; onClose: () => void; onDone?: () => void; onGo?: (view: 'soc', tab: string) => void
}) {
  const toast = useToast()
  const [b, setB] = useState<Brief>()
  const [err, setErr] = useState<string>()
  const [step, setStep] = useState(0)
  const [choice, setChoice] = useState<string>()
  const [targets, setTargets] = useState<string[]>([])
  const [notify, setNotify] = useState(true)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<Executed>()

  useEffect(() => {
    fetch(`/api/decide/${org}/${cve}`).then(async (r) => { if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText); return r.json() as Promise<Brief> })
      .then((x) => { setB(x); setChoice(x.recommended); setTargets(x.targets.filter((t) => t.default).map((t) => t.to)) })
      .catch((e) => setErr(String(e.message ?? e)))
  }, [org, cve])

  const run = () => {
    if (!b || !choice) return
    setBusy(true)
    fetch(`/api/decide/${org}/${cve}`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision: choice, note: note || null, escalate_to: choice === 'escalate' || targets.length ? targets : [], notify_org: notify }) })
      .then(async (r) => { if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText); return r.json() as Promise<Executed> })
      .then((x) => { setDone(x); setStep(3); toast('Decision carried out and recorded.'); onDone?.() })
      .catch((e) => toast(String(e.message ?? e)))
      .finally(() => setBusy(false))
  }

  const picked = b?.options.find((o) => o.id === choice)
  return (
    <Sheet title={<span className="flex flex-wrap items-center gap-2">Decide: <span className="font-mono">{cve}</span>{b && <TierPill tier={b.tier} />}</span>}
           sub={b ? `${b.org.name} · ${b.org.sector} · risk ${b.risk.toFixed(0)} of 100 · warning ${b.workflow.state}` : 'Loading the evidence…'} onClose={onClose}>
      <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-auto px-7 py-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <ol className="flex flex-wrap items-center gap-1 text-[13px]">
            {STEPS.map((s, i) => (
              <li key={s} className="flex items-center gap-1">
                <span className={`flex h-6 min-w-6 items-center justify-center rounded-full px-2 font-semibold ${i === step ? 'bg-text text-ink' : i < step ? 'bg-ok/20 text-ok-ink' : 'bg-panel-2 text-mute'}`}>{i < step ? <Check size={13} /> : i + 1}</span>
                <span className={i === step ? 'font-semibold' : 'text-mute'}>{s}</span>
                {i < STEPS.length - 1 && <ChevronRight size={14} className="mx-1 text-faint" />}
              </li>
            ))}
          </ol>
          <Objectives keys={['recommendations', 'risk']} />
        </div>
        {err && <div className="rounded-xl bg-crit/10 p-4 text-sm text-crit-ink">{err}</div>}
        {!b && !err && <div className="py-10 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Gathering the evidence…</div>}

        {b && step === 0 && (
          <>
            <div className="rounded-2xl border border-line-2 bg-panel-2 p-4">
              <div className="text-[13px] font-medium uppercase tracking-wide text-faint">Odyssey recommends</div>
              <div className="mt-1 text-[17px] font-semibold">{b.options.find((o) => o.recommended)?.label}</div>
              <p className="mt-1 text-sm text-mute">{b.recommended_why}</p>
            </div>
            <ul className="divide-y divide-line">
              {b.evidence.map((e, i) => (
                <li key={i} className="flex items-start gap-4 py-2.5">
                  <span className="w-36 shrink-0 text-[13px] font-medium text-mute">{e.label}</span>
                  <span className="min-w-0 flex-1 text-[14px]">{e.value}{e.detail && <span className="block text-[12.5px] text-mute">{e.detail}</span>}
                    <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[12px] text-faint">{e.source}{e.provenance && <Prov p={e.provenance.startsWith('REAL') ? 'REAL' : 'SIM'} label={e.provenance} />}</span></span>
                </li>
              ))}
            </ul>
            {b.clocks.length > 0 && (
              <div>
                <div className="mb-2 text-[13px] font-medium uppercase tracking-wide text-faint">Clocks that apply</div>
                <ul className="space-y-1.5 text-[14px]">{b.clocks.map((c, i) => <li key={i}><b>{c.who}</b>: {c.what}{c.hours != null ? ` · ${c.hours} h` : ''}</li>)}</ul>
              </div>
            )}
            {(b.case || b.pending.length > 0) && (
              <div className="flex flex-wrap gap-2 text-[13px] text-mute">
                {b.case && <Badge tone="accent">Case {b.case.id} · {b.case.status.replace('_', ' ')}</Badge>}
                {b.pending.map((p) => <Badge key={p.id}>Proposal waiting: {p.title.slice(0, 60)}</Badge>)}
              </div>
            )}
          </>
        )}

        {b && step === 1 && (
          <div className="grid gap-3 md:grid-cols-2">
            {b.options.filter((o) => o.available).map((o) => (
              <button key={o.id} onClick={() => setChoice(o.id)} aria-pressed={choice === o.id}
                      className={`rounded-2xl border p-4 text-left transition-colors ${choice === o.id ? 'border-text bg-panel-2' : 'border-line hover:border-line-2'}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="text-[15px] font-semibold">{o.label}</div>
                  {o.recommended && <Badge tone="ok">recommended</Badge>}
                </div>
                <p className="mt-1 text-[13px] text-mute">{o.why}</p>
                <ol className="mt-2 list-decimal space-y-0.5 pl-5 text-[13px]">{o.steps.slice(0, 4).map((s, i) => <li key={i}>{s}</li>)}</ol>
                <p className="mt-2 text-[12px] text-faint">Then: {o.effects.join(' · ')}</p>
              </button>
            ))}
          </div>
        )}

        {b && step === 2 && picked && (
          <>
            <div className="rounded-2xl border border-line-2 bg-panel-2 p-4">
              <div className="text-[13px] font-medium uppercase tracking-wide text-faint">You chose</div>
              <div className="mt-1 text-[17px] font-semibold">{picked.label}</div>
              <p className="mt-1 text-sm text-mute">{picked.why}</p>
            </div>
            <div>
              <div className="mb-2 text-[13px] font-medium uppercase tracking-wide text-faint">Escalate to</div>
              <div className="flex flex-wrap gap-2">
                {b.targets.map((t) => (
                  <label key={t.to} title={t.why} className={`flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1.5 text-[13px] ${targets.includes(t.to) ? 'border-text bg-panel-2' : 'border-line'}`}>
                    <input type="checkbox" className="accent-black" checked={targets.includes(t.to)}
                           onChange={(e) => setTargets(e.target.checked ? [...targets, t.to] : targets.filter((x) => x !== t.to))} />{t.to}
                  </label>
                ))}
                <span className="self-center text-[12px] text-faint">{choice === 'escalate' ? 'at least one' : 'optional'}</span>
              </div>
            </div>
            <label className="flex items-center gap-2 text-[14px]">
              <input type="checkbox" className="accent-black" checked={notify} onChange={(e) => setNotify(e.target.checked)} />
              Send the organisation a notice in its own language
            </label>
            <label className="block">
              <span className="text-[13px] font-medium text-mute">Note for the audit trail</span>
              <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Why this decision (optional)"
                        className="mt-1 w-full resize-y rounded-xl bg-panel-2 p-3 text-sm outline-none ring-1 ring-transparent placeholder:text-faint focus:ring-text" />
            </label>
          </>
        )}

        {step === 3 && done && (
          <>
            <ul className="space-y-2">
              {done.executed.map((s, i) => (
                <li key={i} className="flex items-start gap-3 rounded-xl bg-panel-2 px-4 py-3">
                  <Check size={16} className="mt-0.5 shrink-0 text-ok" />
                  <div className="min-w-0"><div className="font-medium">{s.step}</div>{s.detail && <div className="text-[13px] text-mute">{s.detail}</div>}</div>
                  {s.ref && <span className="ml-auto shrink-0 font-mono text-[11px] text-faint">{s.ref}</span>}
                </li>
              ))}
            </ul>
            <p className="text-[13px] text-mute">{done.audit}</p>
          </>
        )}
      </div>
      <footer className="flex items-center justify-between gap-3 border-t border-line px-7 py-4">
        <button onClick={() => (step === 0 || step === 3 ? onClose() : setStep(step - 1))} className="rounded-full border border-line px-4 py-2 text-sm font-medium hover:bg-panel-2">
          {step === 0 || step === 3 ? 'Close' : 'Back'}
        </button>
        <div className="flex items-center gap-2">
          {step === 3 && done?.case && onGo && <button onClick={() => { onGo('soc', 'cases'); onClose() }} className="rounded-full border border-line px-4 py-2 text-sm font-medium hover:bg-panel-2">Open case {done.case.id}</button>}
          {b && step < 2 && <button onClick={() => setStep(step + 1)} className="rounded-full bg-text px-5 py-2 text-sm font-semibold text-ink hover:opacity-85">{step === 0 ? 'See the options' : 'Confirm'}</button>}
          {b && step === 2 && (
            <button disabled={busy || (choice === 'escalate' && !targets.length)} onClick={run}
                    className="rounded-full bg-action px-5 py-2 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-40">
              {busy ? 'Carrying out…' : `Carry out: ${picked?.label ?? ''}`}
            </button>
          )}
        </div>
      </footer>
    </Sheet>
  )
}
