import { BookOpen, Bot, Building2, Cpu, FileSearch, FlaskConical, LayoutDashboard, LayoutList, Radar, ShieldCheck, WifiOff, Zap } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Advisories } from './Advisories'
import { AlertDetail } from './AlertDetail'
import { AlertQueue } from './AlertQueue'
import { Copilot } from './Copilot'
import { HowItWorks } from './HowItWorks'
import { api, type AlertDetail as Detail, type AlertRow, type Health, type LedgerEvent, type Summary, type Tier } from './api'
import { Now } from './Now'
import { Orgs } from './Orgs'
import { Funnel, SectorHeatmap } from './Overview'
import { Proof } from './Proof'
import { Pulse } from './Pulse'
import { Soc } from './Soc'
import { Badge } from './ui'

type View = 'now' | 'soc' | 'orgs' | 'advisories' | 'explore' | 'proof' | 'how'

export default function App() {
  const [view, setView] = useState<View>(() => (new URLSearchParams(window.location.search).get('view') as View) || 'now')
  const [summary, setSummary] = useState<Summary>()
  const [health, setHealth] = useState<Health>()
  const [rows, setRows] = useState<AlertRow[]>([])
  const [tier, setTier] = useState<Tier>()
  const [sector, setSector] = useState<string>()
  const [selected, setSelected] = useState<{ id: string; org_id: string; cve_id: string }>()
  const [org, setOrg] = useState<string | undefined>(() => new URLSearchParams(window.location.search).get('org') ?? undefined)
  const [detail, setDetail] = useState<Detail>()
  const [error, setError] = useState<string>()
  const [live, setLive] = useState<LedgerEvent[]>([])
  const [tick, setTick] = useState(0)
  const [connected, setConnected] = useState(false)
  const [copilot, setCopilot] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    api.summary().then(setSummary).catch((e) => setError(String(e)))
    api.health().then(setHealth).catch(() => undefined)
    const deep = new URLSearchParams(window.location.search).get('alert')
    if (deep?.includes(':')) {
      const [org_id, cve_id] = deep.split(':')
      setSelected({ id: deep, org_id, cve_id })
    }
  }, [tick])

  // Live: every new ledger entry (analyst action, AI brief, telemetry) is pushed here and refreshes the views.
  useEffect(() => {
    if (new URLSearchParams(window.location.search).has('nolive')) return // static mode for screenshots/printing
    const es = new EventSource('/api/stream')
    esRef.current = es
    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.addEventListener('ledger', (msg) => {
      const ev = JSON.parse((msg as MessageEvent).data) as LedgerEvent
      setLive((l) => [...l.slice(-50), ev])
      setTick((t) => t + 1)
    })
    return () => es.close()
  }, [])

  useEffect(() => {
    if (view !== 'explore') return
    api.alerts({ tier, sector }).then((all) => setRows(all.filter((r) => r.tier !== 'Watch'))).catch((e) => setError(String(e)))
  }, [tier, sector, view, tick])

  useEffect(() => {
    if (!selected) return setDetail(undefined)
    api.alert(selected.org_id, selected.cve_id).then(setDetail).catch((e) => setError(String(e)))
  }, [selected])

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-line px-6 py-3">
        <div className="flex items-center gap-3">
          <Radar className="text-accent" />
          <div>
            <h1 className="text-base font-semibold tracking-wide">ODYSSEY <span className="font-normal text-mute">· National Cyber Early Warning</span></h1>
            <p className="text-xs text-mute">Know first. Act first. Every warning explained.</p>
          </div>
          <nav className="ml-6 flex rounded-full bg-panel p-1">
            {([['now', 'Now', Zap], ['soc', 'SOC', LayoutDashboard], ['orgs', 'Organisations', Building2], ['advisories', 'Advisories', FileSearch], ['explore', 'All warnings', LayoutList], ['proof', 'Proof', FlaskConical], ['how', 'How it works', BookOpen]] as const).map(([k, label, Icon]) => (
              <button key={k} onClick={() => setView(k)}
                      className={`flex items-center gap-1.5 rounded-full px-4 py-1.5 text-sm ${view === k ? 'bg-accent text-ink font-semibold' : 'text-mute hover:text-text'}`}>
                <Icon size={14} /> {label}
              </button>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setCopilot(true)}
                  className="flex items-center gap-1.5 rounded-full bg-accent/15 px-3 py-1 text-sm text-accent ring-1 ring-accent/40 hover:bg-accent/25">
            <Bot size={14} /> Ask Odyssey
          </button>
          <Badge tone={connected ? 'ok' : 'crit'}>
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'animate-pulse bg-ok' : 'bg-crit'}`} /> {connected ? 'live' : new URLSearchParams(window.location.search).has('nolive') ? 'static' : 'offline'}
          </Badge>
          {health && (
            <Badge tone={health.ledger_intact ? 'ok' : 'crit'}>
              <ShieldCheck size={12} /> audit trail {health.ledger_intact ? 'intact' : 'TAMPERED'}
            </Badge>
          )}
          {health && <Badge tone="accent"><Cpu size={12} /> on-device AI · {health.models.narrate}</Badge>}
          <Badge><WifiOff size={12} /> 0 cloud calls</Badge>
        </div>
      </header>

      {error && <div className="bg-crit/10 px-6 py-2 text-sm text-crit">Cannot reach the engine ({error}). Start the API on :8000.</div>}

      <main className="flex min-h-0 flex-1 gap-5 p-5">
        {view === 'proof' ? (
          <Proof />
        ) : view === 'how' ? (
          <HowItWorks />
        ) : view === 'soc' ? (
          <Soc tick={tick} onOrg={(id) => { setOrg(id); setView('orgs') }} />
        ) : view === 'orgs' ? (
          <Orgs selected={org} onSelect={setOrg} onAlert={(o, c) => setSelected({ id: `${o}:${c}`, org_id: o, cve_id: c })} />
        ) : view === 'advisories' ? (
          <Advisories />
        ) : view === 'now' ? (
          <>
            <Now onOpen={(c) => setSelected(c)} tick={tick} />
            <Pulse summary={summary} live={live} />
          </>
        ) : (
          <>
            <div className="flex w-80 shrink-0 flex-col gap-4 overflow-auto">
              {summary && <Funnel s={summary} />}
              {summary && <SectorHeatmap s={summary} active={sector} onPick={setSector} />}
            </div>
            <AlertQueue rows={rows} tier={tier} onTier={setTier} selected={selected?.id} onSelect={setSelected} />
          </>
        )}
      </main>

      {copilot && (
        <div className="fixed inset-0 z-30 flex justify-end bg-black/40" onClick={() => setCopilot(false)}>
          <div className="h-full p-3" onClick={(e) => e.stopPropagation()}><Copilot onClose={() => setCopilot(false)} /></div>
        </div>
      )}

      {detail && selected && (
        <div className="fixed inset-0 z-20 flex justify-end bg-black/50 backdrop-blur-sm" onClick={() => setSelected(undefined)}>
          <div className="h-full p-3" onClick={(e) => e.stopPropagation()}>
            <AlertDetail key={selected.id} d={detail} onClose={() => setSelected(undefined)} />
          </div>
        </div>
      )}
    </div>
  )
}
