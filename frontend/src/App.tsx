import { Building2, FlaskConical, Radar, Search, ShieldCheck, Telescope, Zap } from 'lucide-react'
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
import { Tabs } from './ui'

/* Four destinations, one question each (Uber-like): what needs me now, what is happening, who is at risk, why
   should I trust it. Everything else is a tab inside one of them, or a sheet that slides in. */
type View = 'now' | 'intel' | 'orgs' | 'proof'
type IntelTab = 'overview' | 'threats' | 'risk' | 'advisories' | 'warnings' | 'log'
type ProofTab = 'evidence' | 'how'

const LEGACY: Record<string, [View, string?]> = {
  soc: ['intel', 'overview'], advisories: ['intel', 'advisories'], explore: ['intel', 'warnings'], how: ['proof', 'how'],
}

function initial(): { view: View; tab?: string } {
  const q = new URLSearchParams(window.location.search)
  const v = q.get('view') ?? 'now'
  if (LEGACY[v]) return { view: LEGACY[v][0], tab: q.get('tab') ?? LEGACY[v][1] }
  return { view: (['now', 'intel', 'orgs', 'proof'].includes(v) ? v : 'now') as View, tab: q.get('tab') ?? undefined }
}

function PageHead({ title, sub, children }: { title: string; sub: string; children?: React.ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 className="text-3xl font-semibold">{title}</h2>
        <p className="text-sm text-mute">{sub}</p>
      </div>
      {children}
    </div>
  )
}

export default function App() {
  const start = initial()
  const [view, setView] = useState<View>(start.view)
  const [intelTab, setIntelTab] = useState<IntelTab>((start.view === 'intel' && start.tab as IntelTab) || 'overview')
  const [proofTab, setProofTab] = useState<ProofTab>((start.view === 'proof' && start.tab as ProofTab) || 'evidence')
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
  const askParam = new URLSearchParams(window.location.search).get('ask') ?? undefined // ?ask=<question> opens the copilot
  const [copilot, setCopilot] = useState(askParam != null)
  const esRef = useRef<EventSource | null>(null)
  const staticMode = new URLSearchParams(window.location.search).has('nolive')

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
    if (staticMode) return // static mode for screenshots/printing
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
  }, [staticMode])

  useEffect(() => {
    if (view !== 'intel' || intelTab !== 'warnings') return
    api.alerts({ tier, sector }).then((all) => setRows(all.filter((r) => r.tier !== 'Watch'))).catch((e) => setError(String(e)))
  }, [tier, sector, view, intelTab, tick])

  useEffect(() => {
    if (!selected) return setDetail(undefined)
    api.alert(selected.org_id, selected.cve_id).then(setDetail).catch((e) => setError(String(e)))
  }, [selected])

  const openAlert = (o: string, c: string) => setSelected({ id: `${o}:${c}`, org_id: o, cve_id: c })
  const status = connected ? 'live' : staticMode ? 'static' : 'offline'

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 border-b border-line px-6 py-3">
        <div className="flex items-center gap-2.5">
          <Radar className="text-accent" size={22} />
          <div className="leading-tight">
            <div className="text-base font-semibold tracking-wide">ODYSSEY</div>
            <div className="text-[11px] text-mute">National Cyber Early Warning</div>
          </div>
        </div>
        <nav className="ml-4 flex rounded-full bg-panel p-1 ring-1 ring-line">
          {([['now', 'Now', Zap], ['intel', 'Intel', Telescope], ['orgs', 'Organisations', Building2], ['proof', 'Proof', FlaskConical]] as const).map(([k, label, Icon]) => (
            <button key={k} onClick={() => setView(k)}
                    className={`flex items-center gap-1.5 rounded-full px-4 py-1.5 text-sm ${view === k ? 'bg-text font-semibold text-ink' : 'text-mute hover:text-text'}`}>
              <Icon size={14} /> {label}
            </button>
          ))}
        </nav>
        <button onClick={() => setCopilot(true)}
                className="ml-auto flex w-80 max-w-[30vw] items-center gap-2 rounded-full bg-panel px-4 py-2 text-left text-sm text-mute ring-1 ring-line hover:ring-accent/60">
          <Search size={15} /> <span className="truncate">Ask Odyssey anything…</span>
        </button>
        <div className="flex items-center gap-2 rounded-full px-3 py-1.5 text-xs text-mute ring-1 ring-line"
             title={health ? `audit trail ${health.ledger_intact ? 'intact' : 'TAMPERED'} · models: ${health.models.narrate} (GPU) + CPU encoders · no cloud calls` : undefined}>
          <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'animate-pulse bg-ok' : status === 'static' ? 'bg-mute' : 'bg-crit'}`} />
          {status}
          <span className="text-line">|</span>
          <ShieldCheck size={12} className={health?.ledger_intact === false ? 'text-crit' : ''} /> audit {health?.ledger_intact === false ? 'TAMPERED' : 'intact'}
          <span className="text-line">|</span>
          on-device · 0 cloud
        </div>
      </header>

      {error && <div className="bg-crit/10 px-6 py-2 text-sm text-crit">Cannot reach the engine ({error}). Start the API on :8000.</div>}

      <main className="flex min-h-0 flex-1 gap-5 p-5">
        {view === 'now' && (
          <>
            <Now onOpen={(c) => setSelected(c)} tick={tick} />
            <Pulse summary={summary} live={live} />
          </>
        )}

        {view === 'intel' && (
          <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
            <PageHead title="Intel" sub="What is happening across the constituency: threats, sources, advisories, and what Odyssey did about them.">
              <Tabs value={intelTab} onChange={setIntelTab}
                    items={[['overview', 'Overview'], ['threats', 'Threats & sources'], ['risk', 'Risk plan'], ['advisories', 'Advisories'], ['warnings', 'All warnings'], ['log', 'Autopilot log']]} />
            </PageHead>
            <div className="flex min-h-0 flex-1 gap-5">
              {intelTab === 'advisories' ? <Advisories />
                : intelTab === 'warnings' ? (
                  <>
                    <div className="flex w-80 shrink-0 flex-col gap-4 overflow-auto">
                      {summary && <Funnel s={summary} />}
                      {summary && <SectorHeatmap s={summary} active={sector} onPick={setSector} />}
                    </div>
                    <AlertQueue rows={rows} tier={tier} onTier={setTier} selected={selected?.id} onSelect={setSelected} />
                  </>
                ) : <Soc section={intelTab} tick={tick} />}
            </div>
          </div>
        )}

        {view === 'orgs' && <Orgs selected={org} onSelect={setOrg} onAlert={openAlert} />}

        {view === 'proof' && (
          <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
            <PageHead title="Proof" sub="Why to trust it: measured on this laptop, re-runnable on demand, and explained end to end.">
              <Tabs value={proofTab} onChange={setProofTab} items={[['evidence', 'Evidence'], ['how', 'How it works']]} />
            </PageHead>
            <div className="flex min-h-0 flex-1">{proofTab === 'evidence' ? <Proof /> : <HowItWorks />}</div>
          </div>
        )}
      </main>

      {copilot && (
        <div className="fixed inset-0 z-30 flex justify-end bg-black/40" onClick={() => setCopilot(false)}>
          <div className="h-full p-3" onClick={(e) => e.stopPropagation()}><Copilot onClose={() => setCopilot(false)} initial={askParam && askParam !== '1' ? askParam : undefined} /></div>
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
