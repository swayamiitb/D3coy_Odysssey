import { ShieldAlert } from 'lucide-react'
import type { AlertRow, Tier } from './api'
import { Badge, deadlineText, TIER_FILL, TierPill, TIERS } from './ui'

interface Props {
  rows: AlertRow[]
  tier?: Tier
  onTier: (t?: Tier) => void
  selected?: string
  onSelect: (row: AlertRow) => void
}

export function AlertQueue({ rows, tier, onTier, selected, onSelect }: Props) {
  return (
    <section className="flex min-h-0 min-w-0 flex-1 flex-col rounded-lg border border-line bg-panel">
      <header className="flex items-center justify-between border-b border-line px-4 py-2">
        <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-mute">
          <ShieldAlert size={14} /> Early-warning queue · ranked by risk
        </h2>
        <div className="flex gap-1">
          {[undefined, ...TIERS.filter((t) => t !== 'Watch')].map((t) => (
            <button key={t ?? 'all'} onClick={() => onTier(t as Tier | undefined)}
                    className={`rounded px-2 py-0.5 text-xs ${tier === t ? 'bg-accent/20 text-accent' : 'text-mute hover:text-text'}`}>
              {t ?? 'All'}
            </button>
          ))}
        </div>
      </header>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-panel text-left text-xs text-mute">
            <tr>
              <th className="px-4 py-2 font-normal">Risk</th>
              <th className="font-normal">Tier</th>
              <th className="font-normal">Vulnerability</th>
              <th className="font-normal">Organisation</th>
              <th className="font-normal">Assets</th>
              <th className="font-normal">Deadline</th>
              <th className="font-normal">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} onClick={() => onSelect(r)}
                  className={`cursor-pointer border-t border-line/60 hover:bg-panel-2 ${selected === r.id ? 'bg-panel-2' : ''}`}>
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2">
                    <span className="w-10 font-mono">{r.risk.toFixed(0)}</span>
                    <div className="h-1.5 w-16 rounded bg-panel-2">
                      <div className="h-1.5 rounded" style={{ width: `${r.risk}%`, background: TIER_FILL[r.tier] }} />
                    </div>
                  </div>
                </td>
                <td><TierPill tier={r.tier} /></td>
                <td className="max-w-md py-2 pr-3">
                  <div className="font-mono text-xs text-accent">{r.cve_id}</div>
                  <div className="truncate text-xs text-mute" title={r.title}>{r.title}</div>
                </td>
                <td className="pr-3">
                  <div className="text-xs">{r.org_name}</div>
                  <div className="text-xs text-mute">{r.sector}</div>
                </td>
                <td className="font-mono text-xs">{r.assets}</td>
                <td className="font-mono text-xs">{deadlineText(r.deadline_hours)}</td>
                <td className="pr-3">
                  <div className="flex flex-wrap gap-1">
                    {r.kev && <Badge tone="crit">KEV</Badge>}
                    {r.ssvc?.Exploitation === 'active' && <Badge tone="crit">active</Badge>}
                    {r.disputed && <Badge tone="accent">disputed</Badge>}
                    {r.epss != null && <Badge>EPSS {r.epss.toFixed(2)}</Badge>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
