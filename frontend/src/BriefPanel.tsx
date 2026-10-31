import { Bot, Languages, Loader2, ShieldCheck, ShieldOff } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Brief, type Language, type TranslatedLine, type Translation } from './api'
import { Badge, Panel } from './ui'

let LANGS: Promise<Language[]> | undefined  // fetched once per session from the local IndicTrans2 service

export function BriefPanel({ orgId, cveId }: { orgId: string; cveId: string }) {
  const [brief, setBrief] = useState<Brief>()
  const [error, setError] = useState<string>()
  const [openFact, setOpenFact] = useState<string>()
  const [lang, setLang] = useState('en')
  const [langs, setLangs] = useState<Language[]>([])
  const [tr, setTr] = useState<Record<string, Translation>>({})
  const [trBusy, setTrBusy] = useState(false)

  useEffect(() => {
    LANGS ??= api.languages().catch(() => [])
    LANGS.then((l) => setLangs([...l].sort((a, b) => a.name.localeCompare(b.name))))
  }, [])

  useEffect(() => {
    setBrief(undefined)
    setError(undefined)
    setLang('en')
    setTr({})
    api.brief(orgId, cveId).then(setBrief).catch((e) => setError(String(e)))
  }, [orgId, cveId])

  const pick = (l: string) => {
    setLang(l)
    if (l === 'en' || tr[l]) return
    setTrBusy(true)
    api.translate(orgId, cveId, l).then((t) => setTr((m) => ({ ...m, [l]: t })))
      .catch((e) => setError(String(e))).finally(() => setTrBusy(false))
  }

  const status = brief && (brief.status === 'validated'
    ? <Badge tone="ok"><ShieldCheck size={12} /> validated</Badge>
    : <Badge tone="crit"><ShieldOff size={12} /> withheld</Badge>)
  const current = langs.find((x) => x.code === lang)
  const toggle = brief?.brief && (
    <div className="flex items-center gap-1 rounded-full bg-panel-2 p-0.5">
      {['en', 'hi'].map((l) => (
        <button key={l} onClick={() => pick(l)}
                className={`rounded-full px-2 py-0.5 text-xs ${lang === l ? 'bg-accent font-semibold text-ink' : 'text-mute hover:text-text'}`}>
          {l === 'en' ? 'EN' : 'हिन्दी'}
        </button>
      ))}
      {langs.length > 0 && (
        <select value={lang === 'en' || lang === 'hi' ? '' : lang} onChange={(e) => e.target.value && pick(e.target.value)}
                title={`${langs.length} scheduled Indian languages, translated on this laptop`}
                className={`max-w-36 rounded-full bg-transparent px-1.5 py-0.5 text-xs outline-none ${lang !== 'en' && lang !== 'hi' ? 'bg-accent font-semibold text-ink' : 'text-mute'}`}>
          <option value="">+{langs.length - 1} languages</option>
          {langs.filter((x) => x.code !== 'hi').map((x) => (
            <option key={x.code} value={x.code}>{x.native} · {x.name}</option>
          ))}
        </select>
      )}
    </div>
  )
  const t = lang !== 'en' ? tr[lang] : undefined

  if (lang !== 'en') {
    return (
      <Panel title="AI analyst brief" right={<div className="flex items-center gap-2">{toggle}{status}</div>}>
        {error && <div className="text-xs text-crit">{error}</div>}
        {(trBusy || !t) && !error && (
          <div className="flex items-center gap-2 text-xs text-mute">
            <Loader2 size={14} className="animate-spin" /> IndicTrans2 is translating the validated brief into {current?.name ?? lang} on this laptop…
          </div>
        )}
        {t && (
          <div className="space-y-2 text-sm">
            <div dir={t.rtl ? 'rtl' : 'ltr'} lang={lang} className="space-y-2">
              <Line l={t.headline} strong />
              <div className="text-xs font-semibold uppercase tracking-wide text-mute" dir="ltr">Why it matters</div>
              {t.why_it_matters.map((x, i) => <Line key={i} l={x} />)}
              <div className="text-xs font-semibold uppercase tracking-wide text-mute" dir="ltr">What to do</div>
              {t.what_to_do.map((x, i) => <Line key={i} l={x} />)}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-1 text-xs text-mute">
              <Languages size={12} /> {current ? `${current.name} (${current.script} script)` : lang} · translated on-device by
              IndicTrans2 (AI4Bharat) · {t.validated}/{t.total} sentences validated (identifiers preserved, script checked;
              failures shown in English, never guessed) · {t.cached ? 'cached' : `${t.seconds}s`}
            </div>
          </div>
        )}
      </Panel>
    )
  }

  return (
    <Panel title="AI analyst brief" right={<div className="flex items-center gap-2">{toggle}{status}</div>}>
      {!brief && !error && (
        <div className="flex items-center gap-2 text-xs text-mute">
          <Loader2 size={14} className="animate-spin" /> Local security model is writing a grounded brief…
        </div>
      )}
      {error && <div className="text-xs text-crit">{error}</div>}
      {brief?.brief && (
        <div className="space-y-2 text-sm">
          <div className="font-medium">{brief.brief.headline}</div>
          <div className="text-xs font-semibold uppercase tracking-wide text-mute">Why it matters</div>
          <Bullets items={brief.brief.why_it_matters} onCite={setOpenFact} />
          <div className="text-xs font-semibold uppercase tracking-wide text-mute">What to do</div>
          <Bullets items={brief.brief.what_to_do} onCite={setOpenFact} />
          {openFact && brief.facts[openFact] && (
            <div className="rounded border border-accent/30 bg-accent/5 p-2 text-xs text-mute">
              <span className="font-mono text-accent">[{openFact}]</span> {brief.facts[openFact]}
            </div>
          )}
        </div>
      )}
      {brief && !brief.brief && (
        <div className="text-xs text-mute">
          The brief failed validation and is withheld; the deterministic card above remains authoritative.
          <ul className="mt-1 list-disc pl-4">{brief.problems.map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
      )}
      {brief && (
        <div className="mt-3 flex flex-wrap items-center gap-1 text-xs text-mute">
          <Bot size={12} /> AI-generated by <span className="font-mono">{brief.model}</span> (local) ·
          every claim cites a fact · numbers checked against facts · {brief.cached ? 'cached' : `${brief.seconds}s`}
          {brief.ledger_hash && <span className="font-mono">· ledger {brief.ledger_hash.slice(0, 8)}</span>}
        </div>
      )}
    </Panel>
  )
}

function Line({ l, strong }: { l: TranslatedLine; strong?: boolean }) {
  if (l.status === 'validated') return <div className={strong ? 'font-medium' : 'text-xs leading-relaxed'}>{l.text}</div>
  return (
    <div className="text-xs leading-relaxed text-mute" dir="ltr" lang="en">
      {l.source} <Badge tone="crit">translation withheld</Badge>
    </div>
  )
}

function Bullets({ items, onCite }: { items: { text: string; cites: string[] }[]; onCite: (f: string) => void }) {
  return (
    <ul className="space-y-1.5">
      {items.map((b, i) => (
        <li key={i} className="text-xs leading-relaxed">
          {b.text.replace(/\s*\((F\d+(?:,\s*F\d+)*)\)/g, '')}{' '}
          {b.cites.map((c) => (
            <button key={c} onClick={() => onCite(c)} className="mr-0.5 rounded bg-panel-2 px-1 font-mono text-accent hover:bg-accent/20">
              {c}
            </button>
          ))}
        </li>
      ))}
    </ul>
  )
}
