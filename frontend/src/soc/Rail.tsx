import { Activity, BadgeCheck, Building2, ChevronsLeft, ChevronsRight, Crosshair, LayoutDashboard, Shield, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import type { Health } from '../api'
import type { Go, View } from '../Shell'

/* The left rail (ui-08), from the deltavehicle and Aurelium screens: an icon rail on wide screens that expands to
   labels with each destination's sections underneath (Security > Overview / Threats / ... ). The top bar's pill
   navigation stays; the rail is a second way in, remembered per browser. Hidden below 1280px, where the pills do
   the job. */

export const RAIL_NARROW = 60
export const RAIL_WIDE = 232

const ITEMS: { view: View; label: string; icon: typeof Shield; tabs?: [string, string][] }[] = [
  { view: 'now', label: 'Now', icon: LayoutDashboard },
  { view: 'live', label: 'Live', icon: Activity },
  { view: 'soc', label: 'SOC', icon: Shield, tabs: [['overview', 'Overview'], ['cases', 'Cases'], ['warnings', 'Warnings'], ['log', 'Autopilot log'], ['system', 'System']] },
  { view: 'intel', label: 'Intel', icon: Crosshair, tabs: [['overview', 'Threat picture'], ['graph', 'Intelligence graph'], ['indicators', 'Indicators'], ['threats', 'Threats & sources'], ['risk', 'Risk plan'], ['advisories', 'Advisories']] },
  { view: 'orgs', label: 'Organisations', icon: Building2 },
  { view: 'proof', label: 'Proof', icon: BadgeCheck, tabs: [['evidence', 'Evidence'], ['how', 'How it works']] },
]

export function useRail(): [boolean, () => void] {
  const [wide, setWide] = useState(() => { try { return localStorage.getItem('odyssey-rail') === 'wide' } catch { return false } })
  const toggle = () => {
    const w = !wide
    setWide(w)
    try { localStorage.setItem('odyssey-rail', w ? 'wide' : 'narrow') } catch { /* private mode */ }
  }
  return [wide, toggle]
}

export function Rail({ view, tab, go, wide, onToggle, connected, health }: {
  view: View; tab?: string; go: Go; wide: boolean; onToggle: () => void; connected: boolean; health?: Health
}) {
  return (
    <aside className="soc-dark fixed inset-y-0 left-0 z-40 hidden flex-col border-r border-line xl:flex" style={{ width: wide ? RAIL_WIDE : RAIL_NARROW }} aria-label="Sections">
      <button onClick={() => go('now')} className="flex h-16 items-center gap-2.5 px-3.5" aria-label="Odyssey: Now">
        <img src="/mark.svg" alt="" className="h-8 w-8 shrink-0" />
        {wide && <span className="text-[18px] font-semibold tracking-tight">Odyssey</span>}
      </button>
      <nav className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto px-2.5 pt-2">
        {ITEMS.map((it) => {
          const on = view === it.view
          const I = it.icon
          return (
            <div key={it.view}>
              <button onClick={() => go(it.view)} title={wide ? undefined : it.label} aria-current={on ? 'page' : undefined}
                      className={`flex h-10 w-full items-center gap-3 rounded-xl px-2.5 text-[14px] font-medium transition-colors ${on ? 'bg-text text-ink' : 'text-mute hover:bg-panel-2 hover:text-text'}`}>
                <I size={18} className="shrink-0" />
                {wide && <span className="truncate">{it.label}</span>}
                {it.view === 'live' && <span className={`ml-auto h-1.5 w-1.5 shrink-0 rounded-full ${connected ? 'soc-live bg-ok' : 'bg-watch'} ${wide ? '' : 'absolute left-8 top-2'}`} />}
              </button>
              {wide && on && it.tabs && (
                <ul className="my-1 ml-[22px] border-l border-line pl-1">
                  {it.tabs.map(([k, l]) => (
                    <li key={k}>
                      <button onClick={() => go(it.view, k)} aria-current={tab === k ? 'true' : undefined}
                              className={`block w-full rounded-lg px-3 py-1.5 text-left text-[13px] transition-colors ${tab === k ? 'bg-panel-2 font-medium text-text' : 'text-mute hover:text-text'}`}>{l}</button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )
        })}
      </nav>
      <div className="border-t border-line px-2.5 py-2">
        <button onClick={() => go('proof', 'evidence')} title={wide ? undefined : `Audit trail ${health?.ledger_intact === false ? 'tampered' : 'intact'}`}
                className="flex h-10 w-full items-center gap-3 rounded-xl px-2.5 text-[13px] text-mute transition-colors hover:bg-panel-2 hover:text-text">
          <ShieldCheck size={18} className={`shrink-0 ${health?.ledger_intact === false ? 'text-crit' : 'text-ok'}`} />
          {wide && <span className="truncate">Audit trail {health?.ledger_intact === false ? 'tampered' : 'intact'}</span>}
        </button>
        <button onClick={onToggle} aria-label={wide ? 'Collapse the sidebar' : 'Expand the sidebar'} aria-expanded={wide}
                className="flex h-10 w-full items-center gap-3 rounded-xl px-2.5 text-[13px] text-mute transition-colors hover:bg-panel-2 hover:text-text">
          {wide ? <ChevronsLeft size={18} className="shrink-0" /> : <ChevronsRight size={18} className="shrink-0" />}
          {wide && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  )
}
