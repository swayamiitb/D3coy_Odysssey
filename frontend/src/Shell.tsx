import { ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Health, type Soc, type Technology } from './api'
import { Figures, WRAP } from './ui'

/* The Oreo frame around every page: black nav on top, black footer at the bottom, the page's own black hero band in
   between, and a white body. */

export type View = 'now' | 'live' | 'soc' | 'intel' | 'orgs' | 'proof'
export type Go = (view: View, tab?: string) => void

const NAV: [View, string][] = [['now', 'Now'], ['live', 'Live'], ['soc', 'SOC'], ['intel', 'Intel'], ['orgs', 'Organisations'], ['proof', 'Proof']]

export function TopNav({ view, go, pending, connected, status, health }: {
  view: View; go: Go; pending?: number; connected: boolean; status: string; health?: Health
}) {
  const [menu, setMenu] = useState(false)
  return (
    <header className="sticky top-0 z-30 bg-band text-white">
      <div className={`${WRAP} flex h-16 items-center gap-5`}>
        <button onClick={() => go('now')} className="mr-3 text-2xl font-bold tracking-tight">Odyssey</button>
        <nav className="flex items-center gap-1">
          {NAV.map(([k, label]) => (
            <button key={k} onClick={() => go(k)}
                    className={`flex items-center gap-2 rounded-full px-3.5 py-2 text-[15px] font-medium transition ${view === k ? 'bg-band-3 text-white' : 'text-white hover:bg-band-3'}`}>
              {k === 'live' && <span className={`h-2 w-2 rounded-full ${connected ? 'animate-pulse bg-ok' : 'bg-watch'}`} />}
              {label}
            </button>
          ))}
        </nav>
        <button onClick={() => go('soc', 'overview')} className="ml-auto rounded-full bg-white px-4 py-2 text-[15px] font-medium text-black hover:bg-panel-3">
          {pending != null ? `${pending} decisions` : 'Decisions'}
        </button>
        <div className="relative">
          <button onClick={() => setMenu(!menu)} title="Analyst menu"
                  className="relative flex h-10 w-10 items-center justify-center rounded-full bg-band-3 text-sm font-bold hover:bg-white/25">
            AN
            <span className={`absolute right-0 top-0 h-2.5 w-2.5 rounded-full ring-2 ring-band ${connected ? 'bg-ok' : status === 'static' ? 'bg-watch' : 'bg-crit'}`} />
          </button>
          {menu && (
            <div className="absolute right-0 top-12 z-40 w-72 rounded-2xl bg-panel p-2 text-text shadow-2xl ring-1 ring-line" onMouseLeave={() => setMenu(false)}>
              <div className="px-3 py-2">
                <div className="font-bold">Analyst on duty</div>
                <div className="text-sm text-mute">analyst@ncew · National CERT desk</div>
              </div>
              <div className="mt-1 space-y-1.5 border-t border-line px-3 pt-2.5 pb-1.5 text-sm text-mute">
                <div className="flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${connected ? 'bg-ok' : 'bg-watch'}`} /> {status === 'live' ? 'Live updates on' : status === 'static' ? 'Static view' : 'Offline'}</div>
                <div className="flex items-center gap-2"><ShieldCheck size={14} className={health?.ledger_intact === false ? 'text-crit' : 'text-ok'} /> Audit trail {health?.ledger_intact === false ? 'TAMPERED' : 'intact'}</div>
                <div>AI on this laptop: {health?.models.narrate ?? '…'} (GPU) + CPU models · 0 cloud calls</div>
              </div>
            </div>
          )}
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
    <footer className="bg-band text-white">
      <div className={`${WRAP} pt-14 pb-10`}>
        <div className="text-2xl font-bold tracking-tight">Odyssey</div>
        <p className="mt-2 max-w-md text-band-mute">National cyber threat early warning for India's critical infrastructure, running entirely on this laptop.</p>
        <div className="mt-10 grid gap-10 md:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_1.6fr]">
          {FOOT.map(([head, links]) => (
            <div key={head}>
              <h4 className="mb-3 font-bold">{head}</h4>
              <ul className="space-y-2.5">
                {links.map(([label, v, t]) => (
                  <li key={label}><button onClick={() => { go(v, t); window.scrollTo({ top: 0 }) }} className="text-band-mute hover:text-white">{label}</button></li>
                ))}
              </ul>
            </div>
          ))}
          <div>
            <h4 className="mb-3 font-bold">Data</h4>
            <p className="leading-relaxed text-band-mute">
              <span className="text-white">Real, public:</span> NVD, CISA KEV, CISA Vulnrichment (SSVC), FIRST EPSS, CISA advisories,
              SANS ISC DShield, abuse.ch Feodo Tracker, OpenPhish, MITRE ATT&CK.
            </p>
            <p className="mt-2 leading-relaxed text-band-mute">
              <span className="text-white">Simulated, labelled SIM wherever shown:</span> national decoy grid, enterprise firewall logs,
              CERT-In style advisories.
            </p>
          </div>
        </div>
        <div className="mt-12 flex flex-wrap items-center justify-between gap-4 border-t border-band-3 pt-6 text-sm text-band-mute">
          <span>© 2026 Team Odyssey · D3COY 1.0 · PS-01 AI-Based National Cyber Threat Early Warning System</span>
          <span className="flex items-center gap-2">
            <ShieldCheck size={14} className={health?.ledger_intact === false ? 'text-crit' : 'text-ok'} />
            Audit trail {health?.ledger_intact === false ? 'tampered' : 'intact'} · {health?.models.narrate ?? 'security LLM'} on the GPU · 0 cloud calls
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
  if (!m || !d) return <div className="h-[118px]" />
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
  if (!d || !tech) return <div className="h-[118px]" />
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
  if (!d) return <div className="h-[118px]" />
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
  if (!d) return <div className="h-[118px]" />
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
