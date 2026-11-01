import { Moon, Search, ShieldCheck, Sun } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { api, type Health, type Soc, type Technology } from './api'
import { Honeycomb } from './soc/Honeycomb'
import { Figures, FiguresSkeleton, WRAP } from './ui'

/** The night-shift switch: the whole console goes SOC black. Remembered per browser; main.tsx applies it before paint. */
export function useNight(): [boolean, () => void] {
  const [night, setNight] = useState(() => document.documentElement.classList.contains('night'))
  const toggle = () => {
    const on = !night
    setNight(on)
    document.documentElement.classList.toggle('night', on)
    try { localStorage.setItem('odyssey-night', on ? '1' : '0') } catch { /* private mode */ }
  }
  return [night, toggle]
}

/* The frame around every page: the top bar (pill navigation, live status, the decisions count, the analyst), the
   page's own header with its figures, and the footer. SOC black throughout (ui-07). */

export type View = 'now' | 'live' | 'soc' | 'intel' | 'orgs' | 'proof'
export type Go = (view: View, tab?: string) => void

const NAV: [View, string][] = [['now', 'Now'], ['live', 'Live'], ['soc', 'SOC'], ['intel', 'Intel'], ['orgs', 'Organisations'], ['proof', 'Proof']]

export function TopNav({ view, go, pending, connected, status, health, onSearch, alert }: {
  view: View; go: Go; pending?: number; connected: boolean; status: string; health?: Health; onSearch: () => void; alert?: ReactNode
}) {
  const [menu, setMenu] = useState(false)
  const [night, toggleNight] = useNight()
  const dot = connected ? 'soc-live bg-ok' : status === 'static' ? 'bg-watch' : 'bg-crit'
  return (
    <header className="soc-dark sticky top-0 z-30 border-b border-line">
      <div className={`${WRAP} flex h-16 items-center gap-3 sm:gap-5`}>
        <button onClick={() => go('now')} className="flex shrink-0 items-center gap-2.5 rounded-lg xl:hidden" aria-label="Odyssey: Now">
          <img src="/mark.svg" alt="" className="h-8 w-8" />
          <span className="hidden text-[18px] font-semibold tracking-tight lg:inline">Odyssey</span>
        </button>
        <nav aria-label="Console" className="min-w-0 overflow-x-auto [scrollbar-width:none]">
          <div className="flex w-max items-center gap-1 rounded-full border border-line bg-panel p-1">
            {NAV.map(([k, label]) => (
              <button key={k} onClick={() => go(k)} aria-current={view === k ? 'page' : undefined}
                      className={`flex items-center gap-2 rounded-full px-2.5 py-1.5 text-[13px] font-medium transition-colors lg:px-3.5 lg:text-[14px] ${view === k ? 'bg-text text-ink' : 'text-mute hover:bg-panel-2 hover:text-text'}`}>
                {k === 'live' && <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'soc-live bg-ok' : 'bg-watch'}`} />}
                {label}
              </button>
            ))}
          </div>
        </nav>
        <div className="ml-auto flex shrink-0 items-center gap-2 sm:gap-3">
          {alert}
          <button onClick={onSearch} aria-label="Search threats, operators or CVEs (Ctrl+K)"
                  className="flex h-10 items-center gap-2 rounded-full border border-line bg-panel px-3 text-[13px] text-mute transition-colors hover:border-line-2 hover:text-text xl:w-[230px] 2xl:w-[300px]">
            <Search size={15} className="shrink-0" />
            <span className="hidden min-w-0 flex-1 truncate text-left xl:inline">Search threats, CVEs…</span>
            <kbd className="hidden rounded-md border border-line bg-panel-2 px-1.5 py-0.5 font-sans text-[11px] text-faint xl:inline">⌘K</kbd>
          </button>
          <span className="hidden items-center gap-2 rounded-full border border-line px-3 py-1.5 text-[13px] text-mute lg:flex">
            <span className={`h-2 w-2 rounded-full ${dot}`} />
            {status === 'live' ? 'Live' : status === 'static' ? 'Static view' : 'Offline'}
          </span>
          <button onClick={() => go('live')} className="hidden rounded-full border border-line-2 bg-panel-2 px-4 py-2 text-[14px] font-semibold text-text transition-colors hover:bg-panel-3 2xl:inline">
            Run a drill
          </button>
          <button onClick={() => go('soc', 'overview')} className="rounded-full bg-text px-4 py-2 text-[14px] font-semibold text-ink transition-opacity hover:opacity-85">
            {pending != null ? <><span className="tabular-nums">{pending}</span><span className="hidden sm:inline"> decisions</span></> : 'Decisions'}
          </button>
          <button onClick={toggleNight} aria-pressed={night} aria-label={night ? 'Night shift on: switch to the white console' : 'Night shift: turn the whole console black'}
                  title={night ? 'Night shift on' : 'Night shift'}
                  className="flex h-10 w-10 items-center justify-center rounded-full border border-line text-mute transition-colors hover:bg-panel-2 hover:text-text">
            {night ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <div className="relative">
            <button onClick={() => setMenu(!menu)} title="Analyst menu" aria-expanded={menu}
                    className="flex items-center gap-2.5 rounded-full p-1 transition-colors hover:bg-panel-2 2xl:pr-3">
              <span className="relative flex h-8 w-8 items-center justify-center rounded-full bg-panel-3 text-[12px] font-semibold">
                AN
                <span className={`absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full ring-2 ring-band ${dot}`} />
              </span>
              <span className="hidden text-left leading-tight 2xl:block">
                <span className="block text-[13px] font-medium">Analyst on duty</span>
                <span className="block text-[12px] text-faint">SOC analyst</span>
              </span>
            </button>
            {menu && (
              <div className="absolute right-0 top-12 z-40 w-72 rounded-2xl border border-line-2 bg-panel p-2 text-text" onMouseLeave={() => setMenu(false)}>
                <div className="px-3 py-2">
                  <div className="font-semibold">Analyst on duty</div>
                  <div className="text-sm text-mute">analyst@ncew · National CERT desk</div>
                </div>
                <div className="mt-1 space-y-1.5 border-t border-line px-3 pt-2.5 pb-1.5 text-sm text-mute">
                  <div className="flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${connected ? 'bg-ok' : 'bg-watch'}`} /> {status === 'live' ? 'Live updates on' : status === 'static' ? 'Static view' : 'Offline'}</div>
                  <div className="flex items-center gap-2"><ShieldCheck size={14} className={health?.ledger_intact === false ? 'text-crit' : 'text-ok'} /> Audit trail {health?.ledger_intact === false ? 'TAMPERED' : 'intact'}</div>
                  <div>Everything runs on this laptop · 0 cloud calls</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}

const FOOT: [string, [string, View, string?][]][] = [
  ['Operate', [['Now', 'now'], ['Live and attack drills', 'live'], ['SOC overview', 'soc', 'overview'], ['Cases', 'soc', 'cases'], ['All warnings', 'soc', 'warnings'], ['Autopilot log', 'soc', 'log']]],
  ['Understand', [['Threat picture', 'intel', 'overview'], ['Threats & sources', 'intel', 'threats'], ['Risk plan', 'intel', 'risk'], ['Advisories', 'intel', 'advisories'], ['Organisations', 'orgs']]],
  ['Trust', [['Evidence', 'proof', 'evidence'], ['How it works', 'proof', 'how'], ['System telemetry', 'soc', 'system']]],
]

export function Footer({ go, health }: { go: Go; health?: Health }) {
  return (
    <footer className="soc-dark relative overflow-hidden border-t border-line">
      <Honeycomb />
      <div className={`${WRAP} relative z-10 pt-12 pb-10`}>
        <div className="flex items-center gap-2.5"><img src="/mark.svg" alt="" className="h-7 w-7" /><span className="text-[20px] font-semibold tracking-tight">Odyssey</span></div>
        <p className="mt-3 max-w-md text-band-mute">National cyber threat early warning for India's critical infrastructure, running entirely on this laptop.</p>
        <div className="mt-10 grid gap-10 md:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_1.6fr]">
          {FOOT.map(([head, links]) => (
            <div key={head}>
              <h4 className="mb-3 text-[14px] font-semibold">{head}</h4>
              <ul className="space-y-2.5">
                {links.map(([label, v, t]) => (
                  <li key={label}><button onClick={() => { go(v, t); window.scrollTo({ top: 0 }) }} className="text-[14px] text-band-mute transition-colors hover:text-text">{label}</button></li>
                ))}
              </ul>
            </div>
          ))}
          <div>
            <h4 className="mb-3 text-[14px] font-semibold">Data</h4>
            <p className="text-[14px] leading-relaxed text-band-mute">
              <span className="text-text">Real, public:</span> NVD, CISA KEV, CISA Vulnrichment (SSVC), FIRST EPSS, CISA advisories and ICS advisories,
              SANS ISC DShield (located by RIPEstat), abuse.ch Feodo Tracker, OpenPhish, MITRE ATT&CK, blocklist.de, Exploit-DB,
              ransomware.live, Have I Been Pwned, GitHub Advisory Database, Tor Project, Spamhaus DROP, Emerging Threats.
            </p>
            <p className="mt-2 text-[14px] leading-relaxed text-band-mute">
              <span className="text-text">Simulated, labelled SIM wherever shown:</span> national decoy grid, enterprise firewall logs,
              CERT-In style advisories.
            </p>
          </div>
        </div>
        <div className="mt-12 flex flex-wrap items-center justify-between gap-4 border-t border-line pt-6 text-sm text-band-mute">
          <span>© 2026 Team Odyssey · D3COY 1.0 · PS-01 AI-Based National Cyber Threat Early Warning System</span>
          <span className="flex items-center gap-2">
            <ShieldCheck size={14} className={health?.ledger_intact === false ? 'text-crit' : 'text-ok'} />
            Audit trail {health?.ledger_intact === false ? 'tampered' : 'intact'} · runs entirely on this laptop · 0 cloud calls
          </span>
        </div>
      </div>
    </footer>
  )
}

/* ---------------------------------------------------------------- hero figures, one row per destination */

const n = (v: number | null | undefined) => (v == null ? '—' : v.toLocaleString('en-IN'))

export function SocFigures({ tick }: { tick: number }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [m, setM] = useState<any>()
  const [d, setD] = useState<Soc>()
  useEffect(() => {
    fetch('/api/soc/metrics').then((r) => r.json()).then(setM).catch(() => undefined)
    api.soc().then(setD).catch(() => undefined)
  }, [tick])
  if (!m || !d) return <FiguresSkeleton />
  return (
    <Figures items={[
      { value: n(m.open), label: 'open cases', sub: `${m.incidents} incident response · ${m.unassigned} unassigned` },
      { value: n(m.overdue), label: 'past their SLA', sub: 'deadlines from CERT-In timelines', dot: m.overdue ? 'bg-crit' : 'bg-ok' },
      { value: n(d.pending), label: 'await your decision', sub: 'predictions, escalations, advisory notices' },
      { value: m.mtta_h != null ? `${m.mtta_h} h` : '—', label: 'mean time to acknowledge',
        sub: m.mttr_h != null ? `resolve ${m.mttr_h} h · SLA met ${m.sla_pct ?? '—'}%` : "measured from analysts' actions" },
    ]} />
  )
}

export function IntelFigures({ tick }: { tick: number }) {
  const [d, setD] = useState<Soc>()
  const [tech, setTech] = useState<Technology[]>()
  useEffect(() => { api.soc().then(setD).catch(() => undefined) }, [tick])
  useEffect(() => { api.technologies().then(setTech).catch(() => undefined) }, [])
  if (!d || !tech) return <FiguresSkeleton />
  const real = d.autopilot.lead?.real_signals_only
  return (
    <Figures items={[
      { value: n(d.tiers.Critical), label: 'Critical warnings', sub: `+ ${n(d.tiers.Compromise ?? 0)} suspected compromise · ${n(d.tiers.High)} High · ${n(d.tiers.Medium)} Medium`, dot: 'bg-crit' },
      { value: n(tech.filter((t) => t.critical > 0).length), label: 'technologies under attack', sub: `of ${tech.length} in the constituency's inventory` },
      { value: n(tech.reduce((s, t) => s + t.forecast_cves, 0)), label: 'likely to be exploited next', sub: 'flagged on day 0, not yet confirmed', dot: 'bg-accent' },
      { value: real?.median_lead_days != null ? `${real.median_lead_days} d` : '—', label: 'ahead of CISA KEV',
        sub: real ? `median on real signals · ${real.acted_before_kev} CVEs · up to ${real.max_lead_days} d` : undefined },
    ]} />
  )
}

export function OrgsFigures() {
  const [d, setD] = useState<Soc>()
  useEffect(() => { api.soc().then(setD).catch(() => undefined) }, [])
  if (!d) return <FiguresSkeleton />
  const sectors = new Set(d.orgs.map((o) => o.sector)).size
  const langs = new Set(d.orgs.map((o) => o.lang)).size
  const states = new Set(d.orgs.map((o) => o.state)).size
  const comp = d.orgs.filter((o) => o.compromise > 0).length
  return (
    <Figures items={[
      { value: d.orgs.length, label: 'organisations watched', sub: `${sectors} critical sectors · ${states} states` },
      { value: langs, label: 'languages', sub: 'every notice in the organisation\'s own language' },
      { value: n(d.orgs.reduce((s, o) => s + o.critical, 0)), label: 'warnings need action', sub: `${n(d.tiers.Critical)} Critical + ${n(d.tiers.Compromise ?? 0)} suspected compromise`, dot: 'bg-crit' },
      { value: comp, label: 'suspected compromise', sub: comp ? 'incident response under way' : 'none', dot: comp ? 'bg-comp' : 'bg-ok' },
    ]} />
  )
}

export function ProofFigures({ health }: { health?: Health }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [d, setD] = useState<any>()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [t, setT] = useState<any>()
  useEffect(() => {
    fetch('/api/scorecard').then((r) => r.json()).then(setD).catch(() => undefined)
    fetch('/api/telemetry').then((r) => r.json()).then(setT).catch(() => undefined)
  }, [])
  if (!d) return <FiguresSkeleton />
  return (
    <Figures items={[
      { value: `${d.funnel.noise_reduction_x}×`, label: 'noise reduction',
        sub: `${n(d.funnel.cves_this_month)} CVEs this month → ${d.funnel.critical_or_compromise} critical warnings` },
      { value: '0', label: 'cloud calls', sub: 'every model runs on this laptop', dot: 'bg-ok' },
      { value: '8B', label: 'largest model, security-tuned', sub: 'fits an 8 GB laptop GPU; encoders and ML on the CPU' },
      { value: t ? n(t.ledger.events) : '—', label: 'audit-trail events', sub: health?.ledger_intact === false ? 'chain BROKEN' : 'hash-chained, verified intact',
        dot: health?.ledger_intact === false ? 'bg-crit' : 'bg-ok' },
    ]} />
  )
}
