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
import { Footer, IntelFigures, OrgsFigures, ProofFigures, SocFigures, TopNav, type View } from './Shell'
import { Soc } from './Soc'
import { CaseBoard, OpsLog, OpsOverview, SystemView } from './SocOps'
import { Hero, Tabs, ToastProvider, WRAP } from './ui'

/* Five destinations, one question each (Uber-like): what needs me now, how operations run, what is happening, who
   is at risk, why should I trust it. Every page is the same Oreo: black nav, black hero band with the page's four
   figures, white body, black footer. Details slide in as sheets. */
type SocTab = 'overview' | 'cases' | 'warnings' | 'log' | 'system'
type IntelTab = 'overview' | 'threats' | 'risk' | 'advisories'
type ProofTab = 'evidence' | 'how'

const LEGACY: Record<string, [View, string?]> = {
  advisories: ['intel', 'advisories'], explore: ['soc', 'warnings'], how: ['proof', 'how'], cases: ['soc', 'cases'],
}

function initial(): { view: View; tab?: string } {
  const q = new URLSearchParams(window.location.search)
  const v = q.get('view') ?? 'now'
  if (LEGACY[v]) return { view: LEGACY[v][0], tab: q.get('tab') ?? LEGACY[v][1] }
  return { view: (['now', 'soc', 'intel', 'orgs', 'proof'].includes(v) ? v : 'now') as View, tab: q.get('tab') ?? undefined }
}

export default function App() {
  const start = initial()
  const [view, setView] = useState<View>(start.view)
  const [socTab, setSocTab] = useState<SocTab>((start.view === 'soc' && start.tab as SocTab) || 'overview')
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
  const [pending, setPending] = useState<number>()
  const esRef = useRef<EventSource | null>(null)
  const staticMode = new URLSearchParams(window.location.search).has('nolive')

  useEffect(() => {
    api.summary().then(setSummary).catch((e) => setError(String(e)))
    api.health().then(setHealth).catch(() => undefined)
    api.soc().then((d) => setPending(d.pending)).catch(() => undefined)
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
    if (view !== 'soc' || socTab !== 'warnings') return
    api.alerts({ tier, sector }).then((all) => setRows(all.filter((r) => r.tier !== 'Watch'))).catch((e) => setError(String(e)))
  }, [tier, sector, view, socTab, tick])

  useEffect(() => {
    if (!selected) return setDetail(undefined)
    api.alert(selected.org_id, selected.cve_id).then(setDetail).catch((e) => setError(String(e)))
  }, [selected])

  const openAlert = (o: string, c: string) => setSelected({ id: `${o}:${c}`, org_id: o, cve_id: c })
  const status = connected ? 'live' : staticMode ? 'static' : 'offline'

  const go = (v: View, t?: string) => {
    setView(v)
    if (t && v === 'soc') setSocTab(t as SocTab)
    if (t && v === 'intel') setIntelTab(t as IntelTab)
    if (t && v === 'proof') setProofTab(t as ProofTab)
    window.scrollTo({ top: 0 })
  }

  return (
    <ToastProvider>
    <div className="flex min-h-screen flex-col bg-ink">
      <TopNav view={view} go={go} onAsk={() => setCopilot(true)} pending={pending} connected={connected} status={status} health={health} />

      {error && <div className="bg-crit px-6 py-2 text-sm font-medium text-white">Cannot reach the engine ({error}). Start the API on :8000.</div>}

      {view === 'now' && (
        <Now onOpen={(c) => setSelected(c)} tick={tick} onOrg={(id) => { setOrg(id); go('orgs') }} onGo={(v, t) => go(v, t)} />
      )}

      {view === 'soc' && (
        <>
          <Hero title="SOC" sub="Operations: cases and owners, decisions, every warning, what the autopilot did, and the platform's health."
                tabs={<Tabs dark value={socTab} onChange={setSocTab}
                            items={[['overview', 'Overview'], ['cases', 'Cases'], ['warnings', 'All warnings'], ['log', 'Autopilot log'], ['system', 'System']]} />}>
            <SocFigures tick={tick} />
          </Hero>
          <main className={`${WRAP} flex flex-1 gap-6 py-10`}>
            {socTab === 'overview' ? <OpsOverview tick={tick} onCases={() => setSocTab('cases')} />
              : socTab === 'cases' ? <CaseBoard tick={tick} onAlert={openAlert} />
              : socTab === 'log' ? <OpsLog tick={tick} />
              : socTab === 'system' ? <SystemView />
              : (
                <>
                  <div className="flex w-80 shrink-0 flex-col gap-4">
                    {summary && <Funnel s={summary} />}
                    {summary && <SectorHeatmap s={summary} active={sector} onPick={setSector} />}
                  </div>
                  <AlertQueue rows={rows} tier={tier} onTier={setTier} selected={selected?.id} onSelect={setSelected} />
                </>
              )}
          </main>
        </>
      )}

      {view === 'intel' && (
        <>
          <Hero title="Intel" sub="The threat picture: where the exposure is, what is under attack, what comes next, and how to cut the risk."
                tabs={<Tabs dark value={intelTab} onChange={setIntelTab}
                            items={[['overview', 'Overview'], ['threats', 'Threats & sources'], ['risk', 'Risk plan'], ['advisories', 'Advisories']]} />}>
            <IntelFigures tick={tick} />
          </Hero>
          <main className={`${WRAP} flex flex-1 gap-6 py-10`}>
            {intelTab === 'advisories' ? <Advisories /> : <Soc section={intelTab} tick={tick} />}
          </main>
        </>
      )}

      {view === 'orgs' && (
        <>
          <Hero title="Organisations" sub="The constituency: each operator's exposure, what to fix first, what an outsider sees, and every notice it received.">
            <OrgsFigures />
          </Hero>
          <main className={`${WRAP} flex flex-1 gap-8 py-10`}>
            <Orgs selected={org} onSelect={setOrg} onAlert={openAlert} />
          </main>
        </>
      )}

      {view === 'proof' && (
        <>
          <Hero title="Proof" sub="Why to trust it: measured on this laptop, re-runnable on demand, and explained end to end."
                tabs={<Tabs dark value={proofTab} onChange={setProofTab} items={[['evidence', 'Evidence'], ['how', 'How it works']]} />}>
            <ProofFigures />
          </Hero>
          <main className={`${WRAP} flex flex-1 py-10`}>{proofTab === 'evidence' ? <Proof /> : <HowItWorks />}</main>
        </>
      )}

      <Footer go={go} health={health} />

      {copilot && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/40" onClick={() => setCopilot(false)}>
          <div className="h-full p-3" onClick={(e) => e.stopPropagation()}><Copilot onClose={() => setCopilot(false)} initial={askParam && askParam !== '1' ? askParam : undefined} /></div>
        </div>
      )}

      {detail && selected && (
        <div className="fixed inset-0 z-40 flex justify-end bg-black/50 backdrop-blur-sm" onClick={() => setSelected(undefined)}>
          <div className="h-full p-3" onClick={(e) => e.stopPropagation()}>
            <AlertDetail key={selected.id} d={detail} onClose={() => setSelected(undefined)} />
          </div>
        </div>
      )}
    </div>
    </ToastProvider>
  )
}
