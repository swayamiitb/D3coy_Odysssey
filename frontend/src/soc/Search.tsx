import { Building2, Cpu, FileWarning, LayoutGrid, Search } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { AlertRow, Soc, Technology } from '../api'
import type { View } from '../Shell'
import { TierPill } from '../ui'
import { useJson } from './kit'

/* The command palette (ui-08): Ctrl/⌘K from anywhere, or the search in the top bar. Searches the console's pages,
   the operators, the open warnings (CVE, product, operator) and the technology inventory; Enter opens the first hit,
   arrows move, Esc closes. All data comes from the API the page already uses. */

const PAGES: { label: string; hint: string; view: View; tab?: string }[] = [
  { label: 'Now', hint: 'the duty desk', view: 'now' },
  { label: 'Live', hint: 'sensors, feeds, drills, the HTTP shield', view: 'live' },
  { label: 'SOC overview', hint: 'decisions and the team', view: 'soc', tab: 'overview' },
  { label: 'Cases', hint: 'the case board', view: 'soc', tab: 'cases' },
  { label: 'All warnings', hint: 'every open warning', view: 'soc', tab: 'warnings' },
  { label: 'Autopilot log', hint: 'everything Odyssey did', view: 'soc', tab: 'log' },
  { label: 'System', hint: 'telemetry of the running system', view: 'soc', tab: 'system' },
  { label: 'Threat picture', hint: 'what is under attack', view: 'intel', tab: 'overview' },
  { label: 'Threats & sources', hint: 'technologies, campaigns, feeds', view: 'intel', tab: 'threats' },
  { label: 'Risk plan', hint: 'the changes that remove the most risk', view: 'intel', tab: 'risk' },
  { label: 'Advisories', hint: 'CISA and CERT-In style advisories', view: 'intel', tab: 'advisories' },
  { label: 'Organisations', hint: 'every operator we protect', view: 'orgs' },
  { label: 'Proof', hint: 'every claim, measured', view: 'proof', tab: 'evidence' },
  { label: 'How it works', hint: 'the pipeline, step by step', view: 'proof', tab: 'how' },
]

type Hit = { key: string; group: 'Pages' | 'Operators' | 'Warnings' | 'Technologies'; title: string; sub?: string; trail?: React.ReactNode; run: () => void }

export function CommandPalette({ open, onClose, go, onOrg, onAlert }: {
  open: boolean; onClose: () => void; go: (v: View, t?: string) => void; onOrg: (id: string) => void; onAlert: (orgId: string, cveId: string) => void
}) {
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const soc = useJson<Soc>(open ? '/api/soc' : '', [open]).data
  const alerts = useJson<AlertRow[]>(open ? '/api/alerts?limit=400' : '', [open]).data
  const tech = useJson<Technology[]>(open ? '/api/intel/technologies' : '', [open]).data

  useEffect(() => {
    if (!open) return
    setQ('')
    setActive(0)
    const id = window.setTimeout(() => input.current?.focus(), 30)
    return () => window.clearTimeout(id)
  }, [open])

  const hits = useMemo<Hit[]>(() => {
    const s = q.trim().toLowerCase()
    const has = (...xs: (string | null | undefined)[]) => !s || xs.some((x) => x?.toLowerCase().includes(s))
    const done = (f: () => void) => () => { f(); onClose() }
    const pages: Hit[] = PAGES.filter((p) => has(p.label, p.hint)).slice(0, s ? 4 : 6)
      .map((p) => ({ key: `p-${p.label}`, group: 'Pages', title: p.label, sub: p.hint, run: done(() => go(p.view, p.tab)) }))
    const orgs: Hit[] = (soc?.orgs ?? []).filter((o) => has(o.name, o.id, o.sector, o.state)).slice(0, s ? 5 : 3)
      .map((o) => ({ key: `o-${o.id}`, group: 'Operators', title: o.name, sub: `${o.sector} · ${o.state}`, trail: <span className="font-mono text-[12px] text-mute">{o.critical} Critical</span>, run: done(() => onOrg(o.id)) }))
    const warns: Hit[] = s ? (alerts ?? []).filter((a) => has(a.cve_id, a.org_name, a.title, a.sector)).slice(0, 6)
      .map((a) => ({ key: `a-${a.id}`, group: 'Warnings', title: `${a.cve_id} · ${a.title.split('.')[0].slice(0, 70)}`, sub: `${a.org_name} · risk ${a.risk.toFixed(0)}`, trail: <TierPill tier={a.tier} />, run: done(() => onAlert(a.org_id, a.cve_id)) })) : []
    const techs: Hit[] = s ? (tech ?? []).filter((t) => has(t.label, t.vendor, t.product)).slice(0, 4)
      .map((t) => ({ key: `t-${t.product_key}`, group: 'Technologies', title: t.label, sub: `${t.assets} assets at ${t.orgs} operators`, trail: <span className="font-mono text-[12px] text-mute">{t.critical} Critical</span>, run: done(() => go('intel', 'threats')) })) : []
    return [...orgs, ...warns, ...techs, ...pages]
  }, [q, soc, alerts, tech, go, onOrg, onAlert, onClose])

  useEffect(() => { setActive(0) }, [q])
  if (!open) return null
  const icon = { Pages: LayoutGrid, Operators: Building2, Warnings: FileWarning, Technologies: Cpu }
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(hits.length - 1, a + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)) }
    else if (e.key === 'Enter') { e.preventDefault(); hits[active]?.run() }
    else if (e.key === 'Escape') onClose()
  }
  let lastGroup = ''
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 pt-[12vh]" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-label="Search" onClick={(e) => e.stopPropagation()} onKeyDown={onKey}
           className="soc-light w-full max-w-[640px] overflow-hidden rounded-2xl border border-line-2">
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search size={18} className="shrink-0 text-mute" />
          <input ref={input} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search threats, operators, CVEs or pages…"
                 className="h-14 min-w-0 flex-1 bg-transparent text-[16px] outline-none placeholder:text-faint" />
          <kbd className="rounded-md border border-line bg-panel-2 px-1.5 py-0.5 text-[11px] text-faint">Esc</kbd>
        </div>
        <ul className="max-h-[60vh] overflow-auto p-2" role="listbox">
          {hits.length === 0 && <li className="px-3 py-6 text-center text-[14px] text-mute">{alerts ? 'Nothing matches.' : 'Loading the index…'}</li>}
          {hits.map((h, i) => {
            const head = h.group !== lastGroup
            lastGroup = h.group
            const I = icon[h.group]
            return (
              <li key={h.key} role="option" aria-selected={i === active}>
                {head && <div className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wide text-faint">{h.group}</div>}
                <button onClick={h.run} onMouseEnter={() => setActive(i)}
                        className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left ${i === active ? 'bg-panel-2' : ''}`}>
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-panel-2 text-mute"><I size={15} /></span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[14px] font-medium">{h.title}</span>
                    {h.sub && <span className="block truncate text-[12.5px] text-mute">{h.sub}</span>}
                  </span>
                  {h.trail}
                </button>
              </li>
            )
          })}
        </ul>
        <div className="flex items-center gap-4 border-t border-line px-4 py-2 text-[11.5px] text-faint">
          <span><kbd className="rounded border border-line px-1">↑↓</kbd> move</span><span><kbd className="rounded border border-line px-1">Enter</kbd> open</span>
          <span className="ml-auto">Operators and warnings from the live API</span>
        </div>
      </div>
    </div>
  )
}
