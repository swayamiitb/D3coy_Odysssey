import { useEffect, useRef, useState, type CSSProperties } from 'react'
import { Advisories } from './Advisories'
import { AlertDetail } from './AlertDetail'
import { HowItWorks } from './HowItWorks'
import { IntelGraph } from './IntelGraph'
import { IocImport } from './IocImport'
import { Watchlist } from './Watchlist'
import { Live, LiveFigures, useLive } from './Live'
import { api, type AlertDetail as Detail, type Health, type Soc as SocData } from './api'
import { Now } from './Now'
import { Orgs } from './Orgs'
import { Proof } from './Proof'
import { Footer, IntelFigures, OrgsFigures, ProofFigures, SocFigures, TopNav, type Go, type View } from './Shell'
import { Soc } from './Soc'
import { CaseBoard, OpsLog, OpsOverview, SystemView, WarningList } from './SocOps'
import { AttackTelemetry, LiveStrip, SocStrip, Throughput } from './soc/extras'
import { LiveThreatMap } from './soc/LiveThreatMap'
import { AlertChip } from './soc/overview'
import { IntelSources } from './soc/panels'
import { Rail, RAIL_NARROW, RAIL_WIDE, useRail } from './soc/Rail'
import { RealFeedsStrip } from './soc/realfeeds'
import { CommandPalette } from './soc/Search'
import { Hero, Tabs, ToastProvider, WRAP, type ObjectiveKey } from './ui'

/* Five destinations, one question each (Uber-like): what needs me now, how operations run, what is happening, who
   is at risk, why should I trust it. Every page is the same Oreo: black nav, black hero band with the page's four
   figures, white body, black footer. Details slide in as sheets. */
type SocTab = 'overview' | 'cases' | 'warnings' | 'log' | 'system'
type IntelTab = 'overview' | 'graph' | 'indicators' | 'threats' | 'risk' | 'advisories'
type ProofTab = 'evidence' | 'how'

/* The PS-01 key objective(s) each page and tab answers, named in its header (ui.tsx OBJECTIVES, rule 16). */
const OBJ: Record<string, ObjectiveKey[]> = {
  live: ['warning', 'aggregation'],
  'soc:overview': ['dashboard', 'recommendations'], 'soc:cases': ['recommendations'], 'soc:warnings': ['warning', 'risk'],
  'soc:log': ['warning'], 'soc:system': ['analysis'],
  'intel:overview': ['aggregation', 'dashboard'], 'intel:graph': ['analysis'], 'intel:indicators': ['aggregation'],
  'intel:threats': ['analysis', 'aggregation'], 'intel:risk': ['risk', 'recommendations'], 'intel:advisories': ['analysis', 'aggregation'],
  orgs: ['risk', 'recommendations'],
  'proof:evidence': ['explain', 'analysis'], 'proof:how': ['explain'],
}

const LEGACY: Record<string, [View, string?]> = {
  advisories: ['intel', 'advisories'], explore: ['soc', 'warnings'], how: ['proof', 'how'], cases: ['soc', 'cases'],
}

function initial(): { view: View; tab?: string } {
  const q = new URLSearchParams(window.location.search)
  const v = q.get('view') ?? 'now'
  if (LEGACY[v]) return { view: LEGACY[v][0], tab: q.get('tab') ?? LEGACY[v][1] }
  return { view: (['now', 'live', 'soc', 'intel', 'orgs', 'proof'].includes(v) ? v : 'now') as View, tab: q.get('tab') ?? undefined }
}

/** Live: the running system. One poll feeds the hero figures and the page. */
function LivePage({ go }: { go: Go }) {
  const s = useLive()
  return (
    <>
      <Hero title="Live" sub="Odyssey running right now: sensors, real feeds, detectors and the autopilot, refreshed every few seconds." objectives={OBJ.live}>
        <LiveFigures s={s} />
      </Hero>
      <main className={`${WRAP} flex flex-1 flex-col gap-12 py-12`}>
        <LiveStrip s={s} onShield={() => window.scrollTo({ top: 900, behavior: 'smooth' })} />
        <LiveThreatMap s={s} />
        <Throughput s={s} />
        <Live s={s} onGo={(v, t) => go(v, t)} />
      </main>
    </>
  )
}

export default function App() {
  const start = initial()
  const [view, setView] = useState<View>(start.view)
  const [socTab, setSocTab] = useState<SocTab>((start.view === 'soc' && start.tab as SocTab) || 'overview')
  const [intelTab, setIntelTab] = useState<IntelTab>((start.view === 'intel' && start.tab as IntelTab) || 'overview')
  const [proofTab, setProofTab] = useState<ProofTab>((start.view === 'proof' && start.tab as ProofTab) || 'evidence')
  const [graphFocus, setGraphFocus] = useState<string | undefined>(() => new URLSearchParams(window.location.search).get('focus') ?? undefined)
  const [graphNode, setGraphNode] = useState<string | undefined>(() => new URLSearchParams(window.location.search).get('node') ?? undefined)
  const [health, setHealth] = useState<Health>()
  const [selected, setSelected] = useState<{ id: string; org_id: string; cve_id: string }>()
  const [org, setOrg] = useState<string | undefined>(() => new URLSearchParams(window.location.search).get('org') ?? undefined)
  const [detail, setDetail] = useState<Detail>()
  const [error, setError] = useState<string>()
  const [tick, setTick] = useState(0)
  const [connected, setConnected] = useState(false)
  const [pending, setPending] = useState<number>()
  const [socOrgs, setSocOrgs] = useState<SocData['orgs']>()
  const [search, setSearch] = useState(false)
  const [railWide, toggleRail] = useRail()
  const esRef = useRef<EventSource | null>(null)
  const staticMode = new URLSearchParams(window.location.search).has('nolive')

  // Ctrl/⌘K opens the search from anywhere in the console.
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setSearch((s) => !s) }
    }
    window.addEventListener('keydown', key)
    return () => window.removeEventListener('keydown', key)
  }, [])

  useEffect(() => {
    api.health().then((h) => { setHealth(h); setError(undefined) }).catch((e) => setError(String(e)))
    api.soc().then((d) => { setPending(d.pending); setSocOrgs(d.orgs) }).catch(() => undefined)
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
    if (!selected) return setDetail(undefined)
    api.alert(selected.org_id, selected.cve_id).then(setDetail).catch((e) => setError(String(e)))
  }, [selected])

  const openAlert = (o: string, c: string) => setSelected({ id: `${o}:${c}`, org_id: o, cve_id: c })
  const status = connected ? 'live' : staticMode ? 'static' : 'offline'

  const go = (v: View, t?: string) => {
    setView(v)
    if (t && v === 'soc') setSocTab(t as SocTab)
    if (t && v === 'intel') {
      if (t.startsWith('graph')) { setIntelTab('graph'); const f = t.split(':')[1]; if (f) setGraphFocus(f) } else setIntelTab(t as IntelTab)
    }
    if (t && v === 'proof') setProofTab(t as ProofTab)
    window.scrollTo({ top: 0 })
  }

  const tab = view === 'soc' ? socTab : view === 'intel' ? intelTab : view === 'proof' ? proofTab : undefined

  return (
    <ToastProvider>
    <Rail view={view} tab={tab} go={go} wide={railWide} onToggle={toggleRail} connected={connected} health={health} />
    <div className="flex min-h-screen flex-col bg-ink xl:pl-[var(--rail)]" style={{ '--rail': `${railWide ? RAIL_WIDE : RAIL_NARROW}px` } as CSSProperties}>
      <TopNav view={view} go={go} pending={pending} connected={connected} status={status} health={health} onSearch={() => setSearch(true)}
              alert={<AlertChip tick={tick} onOpen={(c) => setSelected({ id: c.id, org_id: c.org_id, cve_id: c.cve_id })} />} />
      <CommandPalette open={search} onClose={() => setSearch(false)} go={go} onOrg={(id) => { setOrg(id); go('orgs') }} onAlert={openAlert} />

      {error && <div className="bg-crit px-6 py-2 text-sm font-medium text-white">Cannot reach the engine ({error}). Start the API on :8000.</div>}

      {view === 'now' && (
        <Now onOpen={(c) => setSelected(c)} tick={tick} onOrg={(id) => { setOrg(id); go('orgs') }} onGo={(v, t) => go(v, t)} />
      )}

      {view === 'live' && <LivePage go={go} />}

      {view === 'soc' && (
        <>
          <Hero title="SOC" sub="Cases, decisions and everything Odyssey did, in one place." objectives={OBJ[`soc:${socTab}`]}
                tabs={<Tabs dark value={socTab} onChange={setSocTab}
                            items={[['overview', 'Overview'], ['cases', 'Cases'], ['warnings', 'Warnings'], ['log', 'Log'], ['system', 'System']]} />}>
            <SocFigures tick={tick} />
          </Hero>
          <main className={`${WRAP} flex flex-1 py-12`}>
            {socTab === 'overview' ? (
              <div className="w-full min-w-0 space-y-12">
                <SocStrip tick={tick} orgs={socOrgs} onOrg={(id) => { setOrg(id); go('orgs') }} />
                <OpsOverview tick={tick} onCases={() => setSocTab('cases')} onWarnings={() => setSocTab('warnings')} />
              </div>
            )
              : socTab === 'cases' ? <CaseBoard tick={tick} onAlert={openAlert} />
              : socTab === 'log' ? <OpsLog tick={tick} />
              : socTab === 'system' ? <SystemView />
              : <WarningList tick={tick} onOpen={openAlert} />}
          </main>
        </>
      )}

      {view === 'intel' && (
        <>
          <Hero title="Intel" sub="What is under attack, where we are exposed, and what to fix first." objectives={OBJ[`intel:${intelTab}`]}
                tabs={<Tabs dark value={intelTab} onChange={setIntelTab}
                            items={[['overview', 'Overview'], ['graph', 'Graph'], ['indicators', 'Indicators'], ['threats', 'Threats'], ['risk', 'Risk plan'], ['advisories', 'Advisories']]} />}>
            <IntelFigures tick={tick} />
          </Hero>
          <main className={`${WRAP} flex flex-1 gap-6 py-12`}>
            {intelTab === 'advisories' ? <Advisories /> : intelTab === 'indicators' ? <IocImport /> : intelTab === 'graph' ? (
              <div className="flex min-w-0 flex-1 flex-col gap-14">
                <IntelGraph focus={graphFocus} onFocus={setGraphFocus} initialNode={graphNode} />
                <Watchlist onOpen={(id) => { setGraphNode(id); window.scrollTo({ top: 0 }) }} />

              </div>
            ) : intelTab === 'overview' ? (
              <div className="w-full min-w-0 space-y-12">
                <RealFeedsStrip />
                <div className="grid gap-6 xl:grid-cols-2"><IntelSources /><AttackTelemetry /></div>
                <Soc section={intelTab} tick={tick} />
              </div>
            ) : <Soc section={intelTab} tick={tick} />}
          </main>
        </>
      )}

      {view === 'orgs' && (
        <>
          <Hero title="Organisations" sub="Every operator we protect: its exposure, its fixes and what we told it." objectives={OBJ.orgs}>
            <OrgsFigures />
          </Hero>
          <main className={`${WRAP} flex flex-1 gap-10 py-12`}>
            <Orgs selected={org} onSelect={setOrg} onAlert={openAlert} onGraph={(id) => go('intel', `graph:${id}`)} />
          </main>
        </>
      )}

      {view === 'proof' && (
        <>
          <Hero title="Proof" sub="Every claim measured on this laptop. Open any card for the evidence, or re-run it." objectives={OBJ[`proof:${proofTab}`]}
                tabs={<Tabs dark value={proofTab} onChange={setProofTab} items={[['evidence', 'Evidence'], ['how', 'How it works']]} />}>
            <ProofFigures health={health} />
          </Hero>
          <main className={`${WRAP} flex flex-1 py-12`}>{proofTab === 'evidence' ? <Proof /> : <HowItWorks />}</main>
        </>
      )}

      <Footer go={go} health={health} />

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
