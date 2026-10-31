import { Activity, Building2, Gavel, LayoutGrid, ListChecks, Menu, Radar, ScrollText, ShieldCheck, Telescope, TrendingDown, X } from 'lucide-react'
import { Component, useEffect, useState, type ReactNode } from 'react'
import { api, getAnalyst, getMode, getSnapshotTakenAt, setAnalyst, useLoad } from './data'
import { clock, dateTime } from './format'
import { AuditLog } from './screens/AuditLog'
import { Decisions } from './screens/Decisions'
import { Forecast } from './screens/Forecast'
import { Incident } from './screens/Incident'
import { Intel } from './screens/Intel'
import { Live } from './screens/Live'
import { Landing } from './screens/Landing'
import { Organisation, OrgList } from './screens/Orgs'
import { Overview } from './screens/Overview'
import { Queue } from './screens/Queue'
import { RiskPlanScreen } from './screens/RiskPlan'
import { Shield } from './screens/Shield'
import { rememberScroll } from './scroll'
import { useNow } from './ui'

/** Hash routes: #/ (the landing story, outside the console) · #/overview · #/queue · #/decisions · #/log
 *  · #/incident/<org>/<cve> · #/intel · #/orgs · #/orgs/<id> · #/risk · #/risk/<org> · #/ahead */
export function useRoute(): string[] {
  const read = () => window.location.hash.replace(/^#\/?/, '').split('/').filter(Boolean)
  const [parts, setParts] = useState(read)
  useEffect(() => {
    let current = read()[0] ?? ''
    const on = () => {
      rememberScroll(current)
      const next = read()
      current = next[0] ?? ''
      setParts(next)
      // Console screens open at the top; the landing restores where the reader left it (see scroll.ts).
      if (current !== '') window.scrollTo(0, 0)
    }
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return parts
}

/** If the landing ever fails to render, the console is still one click away. */
class LandingBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  componentDidCatch(e: unknown) { console.error('landing', e) }
  render() {
    if (!this.state.failed) return this.props.children
    return (
      <div className="landing flex flex-col items-center justify-center gap-5 p-8 text-center">
        <p className="text-[18px]">The story couldn't load.</p>
        <a href="#/overview" className="pill pill-primary">Open the console</a>
      </div>
    )
  }
}

export const go = (path: string) => { window.location.hash = path }

function NavItem({ href, icon, label, count, active, onClick }: { href: string; icon: ReactNode; label: string; count?: number; active: boolean; onClick?: () => void }) {
  return (
    <a href={href} onClick={onClick} aria-current={active ? 'page' : undefined}
      className={`flex h-9 items-center gap-2.5 rounded-md px-2.5 text-[14px] ${active ? 'bg-raised text-text' : 'text-mute hover:bg-raised/60 hover:text-text'}`}>
      <span className="text-faint">{icon}</span>
      <span className="flex-1">{label}</span>
      {count != null && count > 0 && <span className="num text-[13px] text-mute">{count}</span>}
    </a>
  )
}

function DataSource() {
  const mode = getMode()
  const text = mode === 'live' ? 'Live · Odyssey API' : mode === 'snapshot' ? `Snapshot · ${dateTime(getSnapshotTakenAt())}` : 'Sample data'
  return (
    <div className="flex items-center gap-2 text-[13px] text-mute">
      <span className={`size-1.5 rounded-full ${mode === 'live' ? 'bg-ok' : mode === 'snapshot' ? 'bg-medium' : 'bg-critical'}`} aria-hidden />
      {text}
    </div>
  )
}

function Analyst() {
  const [name, setName] = useState(getAnalyst())
  return (
    <label className="block text-[12px] text-faint">
      Signed in as
      <input value={name} onChange={(e) => { setName(e.target.value); setAnalyst(e.target.value) }}
        className="mt-1 h-8 w-full rounded-md bg-raised px-2 text-[13px] text-text outline-none focus-visible:outline-2" />
    </label>
  )
}

/** The landing is its own page: no sidebar, no console chrome, and no per-second console clock re-rendering it. */
export default function App() {
  const route = useRoute()
  return (route[0] ?? '') === '' ? <LandingBoundary><Landing /></LandingBoundary> : <Console route={route} />
}

function Console({ route }: { route: string[] }) {
  const [menu, setMenu] = useState(false)
  const t = useNow(1000)
  const feed = useLoad(api.feed, 'feed')
  const soc = useLoad(api.soc, 'soc')
  const screen = route[0] ?? ''
  const needsAction = feed.data?.counts.needs_action
  const pending = soc.data?.pending

  const nav = (
    <nav className="space-y-0.5" onClick={() => setMenu(false)}>
      <NavItem href="#/overview" icon={<LayoutGrid size={16} />} label="Overview" active={screen === 'overview'} />
      <NavItem href="#/queue" icon={<ListChecks size={16} />} label="Triage queue" count={needsAction} active={screen === 'queue' || screen === 'incident'} />
      <NavItem href="#/decisions" icon={<Gavel size={16} />} label="Decisions" count={pending} active={screen === 'decisions'} />
      <NavItem href="#/log" icon={<ScrollText size={16} />} label="Audit log" active={screen === 'log'} />
      <div className="px-2.5 pt-5 pb-1.5 text-[12px] text-faint">Live defence</div>
      <NavItem href="#/live" icon={<Activity size={16} />} label="Live grid" active={screen === 'live'} />
      <NavItem href="#/shield" icon={<ShieldCheck size={16} />} label="HTTP Shield" active={screen === 'shield'} />
      <div className="px-2.5 pt-5 pb-1.5 text-[12px] text-faint">Intelligence</div>
      <NavItem href="#/intel" icon={<Radar size={16} />} label="Threat intel" active={screen === 'intel'} />
      <NavItem href="#/orgs" icon={<Building2 size={16} />} label="Organisations" active={screen === 'orgs'} />
      <NavItem href="#/risk" icon={<TrendingDown size={16} />} label="Risk plan" active={screen === 'risk'} />
      <NavItem href="#/ahead" icon={<Telescope size={16} />} label="Ahead of the threat" active={screen === 'ahead'} />
    </nav>
  )
  const brand = (
    <a href="#/overview" className="flex items-center gap-2.5">
      <img src="/mark.svg" alt="" className="size-7" />
      <span>
        <span className="block text-[15px] font-semibold leading-5">Odyssey SOC</span>
        <span className="block text-[12px] leading-4 text-faint">National · {soc.data ? soc.data.orgs.length : 15} organisations</span>
      </span>
    </a>
  )

  let body: ReactNode
  if (screen === 'queue') body = <Queue />
  else if (screen === 'decisions') body = <Decisions />
  else if (screen === 'log') body = <AuditLog />
  else if (screen === 'incident' && route[1] && route[2]) body = <Incident org={route[1]} cve={route[2]} />
  else if (screen === 'intel') body = <Intel />
  else if (screen === 'orgs') body = route[1] ? <Organisation key={route[1]} id={route[1]} /> : <OrgList />
  else if (screen === 'risk') body = <RiskPlanScreen org={route[1]} />
  else if (screen === 'ahead') body = <Forecast />
  else if (screen === 'live') body = <Live />
  else if (screen === 'shield') body = <Shield />
  else body = <Overview />

  return (
    <div className="min-h-full lg:grid lg:grid-cols-[232px_1fr]">
      <aside className="sticky top-0 hidden h-screen flex-col gap-6 px-4 py-5 lg:flex">
        {brand}
        {nav}
        <div className="mt-auto space-y-4">
          <Analyst />
          <DataSource />
        </div>
      </aside>

      {/* Phone and tablet: the sidebar folds into a top bar with a menu sheet. */}
      <div className="sticky top-0 z-20 flex h-14 items-center justify-between bg-ground px-4 lg:hidden">
        {brand}
        <button className="flex size-11 items-center justify-center rounded-md text-mute hover:bg-raised" onClick={() => setMenu(true)} aria-label="Open menu">
          <Menu size={20} />
        </button>
      </div>
      {menu && (
        <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setMenu(false)}>
          <div className="ml-auto flex h-full w-72 flex-col gap-6 bg-panel p-4 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">{brand}
              <button className="flex size-11 items-center justify-center rounded-md text-mute hover:bg-raised" onClick={() => setMenu(false)} aria-label="Close menu"><X size={20} /></button>
            </div>
            {nav}
            <div className="mt-auto space-y-4"><Analyst /><DataSource /></div>
          </div>
        </div>
      )}

      <main className="min-w-0 px-4 pb-16 sm:px-6 lg:pl-2 lg:pr-6">
        {getMode() === 'sample' && (
          <div className="mt-4 rounded-lg bg-raised px-4 py-2.5 text-[13px] text-mute">
            <span className="font-medium text-critical">Sample data.</span> Neither the Odyssey backend nor a saved snapshot was found, so these numbers are layout filler. Start the backend or run <code>npm run snapshot</code> before showing anyone.
          </div>
        )}
        <div className="flex h-14 items-center justify-end gap-5 text-[13px] text-mute max-lg:hidden">
          <span>Warnings built {dateTime(soc.data?.built_at)}</span>
          <span className="num text-text">{clock(t)} IST</span>
        </div>
        {body}
      </main>
    </div>
  )
}
