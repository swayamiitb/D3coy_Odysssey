import { Moon, Radar, Search, ShieldCheck, Sun } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Advisories } from './Advisories'
import { AlertDetail } from './AlertDetail'
import { AlertQueue } from './AlertQueue'
import { Copilot } from './Copilot'
import { HowItWorks } from './HowItWorks'
import { api, type AlertDetail as Detail, type AlertRow, type Health, type Summary, type Tier } from './api'
import { Now } from './Now'
import { Orgs } from './Orgs'
import { Funnel, SectorHeatmap } from './Overview'
import { Proof } from './Proof'
import { Soc } from './Soc'
import { Tabs, ToastProvider } from './ui'

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

/** Light (Uber-style) by default; dark one click away. Remembered per browser; ?theme=dark|light overrides. */
function useTheme(): ['light' | 'dark', () => void] {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const q = new URLSearchParams(window.location.search).get('theme')
    if (q === 'dark' || q === 'light') return q
    try { return localStorage.getItem('odyssey-theme') === 'dark' ? 'dark' : 'light' } catch { return 'light' }
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('odyssey-theme', theme) } catch { /* private mode: theme still applies */ }
  }, [theme])
  return [theme, () => setTheme((t) => (t === 'light' ? 'dark' : 'light'))]
}

function PageHead({ title, sub, children }: { title: string; sub: string; children?: React.ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">{title}</h2>
        <p className="mt-1 text-mute">{sub}</p>
      </div>
      {children}
    </div>
  )
}

export default function App() {
  const start = initial()
  const [theme, toggleTheme] = useTheme()
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
  const [tick, setTick] = useState(0)
  const [connected, setConnected] = useState(false)
  const askParam = new URLSearchParams(window.location.search).get('ask') ?? undefined // ?ask=<question> opens the copilot
  const [copilot, setCopilot] = useState(askParam != null)
  const [menu, setMenu] = useState(false)
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
    es.addEventListener('ledger', () => {
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
    <ToastProvider>
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-8 border-b border-line px-8 py-3.5">
        <button onClick={() => setView('now')} className="flex items-center gap-2">
          <Radar size={22} />
          <span className="text-xl font-bold tracking-tight">Odyssey</span>
        </button>
        <nav className="flex items-center gap-6">
          {([['now', 'Now'], ['intel', 'Intel'], ['orgs', 'Organisations'], ['proof', 'Proof']] as const).map(([k, label]) => (
            <button key={k} onClick={() => setView(k)}
                    className={`border-b-2 py-1.5 text-[15px] font-medium transition ${view === k ? 'border-text text-text' : 'border-transparent text-mute hover:text-text'}`}>
              {label}
            </button>
          ))}
        </nav>
        <button onClick={() => setCopilot(true)}
                className="ml-auto flex w-96 max-w-[32vw] items-center gap-2.5 rounded-full bg-panel-2 px-5 py-2.5 text-left text-[15px] font-medium text-mute hover:bg-line">
          <Search size={17} className="text-text" /> <span className="truncate">Ask Odyssey anything</span>
        </button>
        <div className="relative">
          <button onClick={() => setMenu(!menu)} title="Analyst menu"
                  className="relative flex h-10 w-10 items-center justify-center rounded-full bg-panel-2 text-sm font-bold hover:bg-line">
            AN
            <span className={`absolute right-0 top-0 h-2.5 w-2.5 rounded-full ring-2 ring-ink ${connected ? 'bg-ok' : status === 'static' ? 'bg-watch' : 'bg-crit'}`} />
          </button>
          {menu && (
            <div className="absolute right-0 top-12 z-40 w-72 rounded-2xl bg-panel p-2 shadow-2xl ring-1 ring-line" onMouseLeave={() => setMenu(false)}>
              <div className="px-3 py-2">
                <div className="font-bold">Analyst on duty</div>
                <div className="text-sm text-mute">analyst@ncew · National CERT desk</div>
              </div>
              <button onClick={toggleTheme} className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-sm hover:bg-panel-2">
                {theme === 'light' ? <Moon size={16} /> : <Sun size={16} />} {theme === 'light' ? 'Dark mode' : 'Light mode'}
              </button>
              <div className="mt-1 space-y-1.5 border-t border-line px-3 pt-2.5 pb-1.5 text-sm text-mute">
                <div className="flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${connected ? 'bg-ok' : 'bg-watch'}`} /> {status === 'live' ? 'Live updates on' : status === 'static' ? 'Static view' : 'Offline'}</div>
                <div className="flex items-center gap-2"><ShieldCheck size={14} className={health?.ledger_intact === false ? 'text-crit' : 'text-ok'} /> Audit trail {health?.ledger_intact === false ? 'TAMPERED' : 'intact'}</div>
                <div>AI on this laptop: {health?.models.narrate ?? '…'} (GPU) + CPU models · 0 cloud calls</div>
              </div>
            </div>
          )}
        </div>
      </header>

      {error && <div className="bg-crit/10 px-6 py-2 text-sm text-crit">Cannot reach the engine ({error}). Start the API on :8000.</div>}

      <main className="flex min-h-0 flex-1 gap-5 px-8 py-6">
        {view === 'now' && (
          <Now onOpen={(c) => setSelected(c)} tick={tick} onOrg={(id) => { setOrg(id); setView('orgs') }}
               onGo={(v, t) => { setView(v); setIntelTab(t) }} />
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
    </ToastProvider>
  )
}
