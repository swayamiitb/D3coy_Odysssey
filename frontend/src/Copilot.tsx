import { Bot, Loader2, Send, ShieldCheck, ShieldOff, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useLanguages } from './proactive'
import { Badge } from './ui'

interface Point { text: string; cites: string[] }
interface TLine { source: string; text: string | null; status: string }
interface Answer {
  question: string
  model: string
  route: Record<string, string | boolean>
  facts: Record<string, string>
  status: 'validated' | 'withheld'
  answer: { answer: string; points: Point[] } | null
  problems: string[]
  seconds: number
  cached: boolean
  translation?: { lang: string; rtl?: boolean; results?: TLine[]; error?: string }
}

const EXAMPLES = [
  'Which power-sector organisations face known-exploited issues?',
  'What should Vidyut Grid West Corp fix first?',
  'Which new CVEs are likely to be exploited soon?',
  'What did Odyssey do on its own recently?',
  'Tell me about CVE-2026-104935',
  'What is waiting for my approval?',
]

export function Copilot({ onClose, initial }: { onClose: () => void; initial?: string }) {
  const [q, setQ] = useState('')
  const [lang, setLang] = useState('en')
  const [busy, setBusy] = useState(false)
  const [a, setA] = useState<Answer>()
  const [err, setErr] = useState<string>()
  const [fact, setFact] = useState<string>()
  const langs = useLanguages()

  const ask = (question: string) => {
    if (question.trim().length < 4) return
    setQ(question)
    setBusy(true); setErr(undefined); setFact(undefined)
    fetch('/api/copilot', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question, lang }) })
      .then(async (r) => { if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText); return r.json() })
      .then(setA).catch((e) => setErr(String(e))).finally(() => setBusy(false))
  }
  useEffect(() => { if (initial) ask(initial) }, [initial]) // eslint-disable-line react-hooks/exhaustive-deps
  const tr = a?.translation?.results
  return (
    <div className="flex h-full w-[34rem] max-w-[95vw] flex-col rounded-2xl border border-line bg-panel shadow-2xl">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <Bot size={18} className="text-accent" />
        <div className="min-w-0 flex-1">
          <div className="font-semibold">Ask Odyssey</div>
          <div className="text-xs text-mute">Answers only from Odyssey's own data. Every point cites a fact; unverifiable answers are withheld.</div>
        </div>
        <button onClick={onClose} className="rounded p-1 text-mute hover:text-text"><X size={16} /></button>
      </header>
      <div className="flex-1 space-y-3 overflow-auto p-4">
        {!a && !busy && (
          <div className="flex flex-wrap gap-1.5">
            {EXAMPLES.map((e) => (
              <button key={e} onClick={() => ask(e)} className="rounded-full bg-panel-2 px-3 py-1 text-left text-xs text-mute hover:text-text">{e}</button>
            ))}
          </div>
        )}
        {busy && <div className="flex items-center gap-2 text-sm text-mute"><Loader2 size={14} className="animate-spin" /> The local security model is choosing a query, reading the results and checking its answer…</div>}
        {err && <div className="text-sm text-crit">{err}</div>}
        {a && !busy && (
          <div className="space-y-3">
            <div className="rounded-xl bg-panel-2 px-3 py-2 text-sm">{a.question}</div>
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              {a.status === 'validated' ? <Badge tone="ok"><ShieldCheck size={12} /> validated</Badge> : <Badge tone="crit"><ShieldOff size={12} /> withheld</Badge>}
              <Badge>tool: {String(a.route.tool)}</Badge>
              {Object.entries(a.route).filter(([k]) => k !== 'tool').map(([k, v]) => <Badge key={k}>{k}: {String(v)}</Badge>)}
              <span className="text-mute">{a.model} · {a.cached ? 'cached' : `${a.seconds}s`}</span>
            </div>
            {a.answer ? (
              <div className="space-y-2 text-sm" dir={a.translation?.rtl ? 'rtl' : 'ltr'}>
                <div className="font-medium">{tr?.[0]?.status === 'validated' ? tr[0].text : a.answer.answer}</div>
                <ul className="space-y-1.5">
                  {a.answer.points.map((p, i) => {
                    const t = tr?.[i + 1]
                    return (
                      <li key={i} className="text-xs leading-relaxed">
                        {t?.status === 'validated' ? t.text : p.text}{' '}
                        <span dir="ltr">
                          {p.cites.map((c) => (
                            <button key={c} onClick={() => setFact(c)} className="mr-0.5 rounded bg-panel-2 px-1 font-mono text-accent hover:bg-accent/20">{c}</button>
                          ))}
                        </span>
                        {t && t.status !== 'validated' && <Badge tone="crit">translation withheld</Badge>}
                      </li>
                    )
                  })}
                </ul>
                {fact && <div className="rounded border border-accent/30 bg-accent/5 p-2 text-xs text-mute" dir="ltr"><span className="font-mono text-accent">[{fact}]</span> {a.facts[fact]}</div>}
              </div>
            ) : (
              <div className="text-xs text-mute">
                The answer failed validation and is withheld ({a.problems.slice(0, 2).join('; ')}). The facts Odyssey found:
              </div>
            )}
            <details className="text-xs text-mute" open={!a.answer}>
              <summary className="cursor-pointer">Facts used ({Object.keys(a.facts).length})</summary>
              <ol className="mt-1 space-y-1">
                {Object.entries(a.facts).map(([k, v]) => <li key={k}><span className="font-mono text-accent">[{k}]</span> {v}</li>)}
              </ol>
            </details>
            <button onClick={() => { setA(undefined); setQ('') }} className="text-xs text-accent hover:underline">Ask something else</button>
          </div>
        )}
      </div>
      <form onSubmit={(e) => { e.preventDefault(); ask(q) }} className="flex items-center gap-2 border-t border-line p-3">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Ask about organisations, CVEs, risk, forecasts…"
               className="min-w-0 flex-1 rounded-full bg-panel-2 px-4 py-2 text-sm outline-none ring-accent/40 focus:ring-2" />
        <select value={lang} onChange={(e) => setLang(e.target.value)} title="Answer language"
                className="w-24 rounded-full bg-panel-2 px-2 py-2 text-xs outline-none">
          <option value="en">English</option>
          {Object.values(langs).sort((x, y) => x.name.localeCompare(y.name)).map((l) => <option key={l.code} value={l.code}>{l.native}</option>)}
        </select>
        <button disabled={busy} className="rounded-full bg-accent p-2 text-ink disabled:opacity-50"><Send size={16} /></button>
      </form>
    </div>
  )
}
