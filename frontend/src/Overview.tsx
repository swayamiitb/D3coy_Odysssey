import type { Summary, Tier } from './api'
import { Panel, TIER_FILL, TIERS } from './ui'

const SECTORS = ['Power & Energy', 'BFSI', 'Telecom', 'Transport', 'Government', 'Strategic & Public Enterprises']

export function Funnel({ s }: { s: Summary }) {
  const steps = [
    { label: 'CVEs published this month (NVD)', value: s.funnel.cves_published_this_month },
    { label: 'Relevant to the national estate', value: s.funnel.candidate_cves },
    { label: 'Version-verified exposures', value: s.funnel.exposed_asset_cve_pairs },
    { label: 'Actionable warnings (org × CVE)', value: s.funnel.actionable_alerts },
    { label: 'Critical — act now', value: s.funnel.critical_alerts },
  ]
  const max = steps[0].value || 1
  return (
    <Panel title="Signal → warning funnel">
      <ol className="space-y-2">
        {steps.map((st, i) => (
          <li key={st.label}>
            <div className="flex justify-between text-xs text-mute">
              <span>{st.label}</span>
              <span className="font-mono text-text">{st.value?.toLocaleString('en-IN')}</span>
            </div>
            <div className="mt-1 h-1.5 rounded bg-panel-2">
              <div
                className={`h-1.5 rounded ${i === steps.length - 1 ? 'bg-crit' : 'bg-accent'}`}
                style={{ width: `${Math.max(2, (100 * Math.log10(st.value + 1)) / Math.log10(max + 1))}%` }}
              />
            </div>
          </li>
        ))}
      </ol>
    </Panel>
  )
}

export function SectorHeatmap({ s, active, onPick }: { s: Summary; active?: string; onPick: (sector?: string) => void }) {
  const tiers = TIERS.filter((t) => t !== 'Watch') as Tier[]
  const max = Math.max(1, ...SECTORS.flatMap((sec) => tiers.map((t) => s.sector_heatmap[sec]?.[t] ?? 0)))
  return (
    <Panel title="National exposure by NCIIPC sector" right={active && (
      <button className="text-xs text-accent" onClick={() => onPick(undefined)}>clear</button>
    )}>
      <table className="w-full border-separate border-spacing-1 text-xs">
        <thead>
          <tr>
            <th />
            {tiers.map((t) => <th key={t} className="font-normal text-mute">{t}</th>)}
          </tr>
        </thead>
        <tbody>
          {SECTORS.map((sec) => (
            <tr key={sec} className={`cursor-pointer ${active === sec ? 'outline outline-accent' : ''}`} onClick={() => onPick(sec)}>
              <td className="pr-2 text-mute">{sec.replace(' & Public Enterprises', ' & PSE')}</td>
              {tiers.map((t) => {
                const n = s.sector_heatmap[sec]?.[t] ?? 0
                return (
                  <td key={t} className="h-8 rounded text-center font-mono"
                      style={{ background: n ? `${TIER_FILL[t]}${Math.round(30 + (190 * n) / max).toString(16).padStart(2, '0')}` : 'var(--color-panel-2)' }}>
                    {n || ''}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}
