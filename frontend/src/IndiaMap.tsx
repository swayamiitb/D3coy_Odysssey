import { X } from 'lucide-react'
import { useState } from 'react'
import type { Soc } from './api'
import { useLanguages } from './proactive'

/* Tile map of India (one rounded square per state, placed roughly where it lies). A tile cartogram keeps the map
   simple and avoids drawing contested boundaries; states take the colour of their worst open risk. */
const TILES: [string, string, number, number][] = [
  ['JK', 'Jammu & Kashmir', 2, 0], ['LA', 'Ladakh', 3, 0],
  ['PB', 'Punjab', 1, 1], ['HP', 'Himachal Pradesh', 2, 1], ['UK', 'Uttarakhand', 3, 1], ['AR', 'Arunachal Pradesh', 8, 1],
  ['RJ', 'Rajasthan', 0, 2], ['HR', 'Haryana', 1, 2], ['DL', 'Delhi', 2, 2], ['UP', 'Uttar Pradesh', 3, 2],
  ['BR', 'Bihar', 4, 2], ['SK', 'Sikkim', 5, 2], ['AS', 'Assam', 7, 2], ['NL', 'Nagaland', 8, 2],
  ['GJ', 'Gujarat', 0, 3], ['MP', 'Madhya Pradesh', 1, 3], ['CG', 'Chhattisgarh', 2, 3], ['JH', 'Jharkhand', 3, 3],
  ['WB', 'West Bengal', 4, 3], ['ML', 'Meghalaya', 6, 3], ['MN', 'Manipur', 8, 3],
  ['MH', 'Maharashtra', 1, 4], ['TS', 'Telangana', 2, 4], ['OD', 'Odisha', 3, 4], ['TR', 'Tripura', 6, 4], ['MZ', 'Mizoram', 7, 4],
  ['GA', 'Goa', 0, 5], ['KA', 'Karnataka', 1, 5], ['AP', 'Andhra Pradesh', 2, 5],
  ['KL', 'Kerala', 1, 6], ['TN', 'Tamil Nadu', 2, 6],
]
const STEP = 76
const SIZE = 66

type OrgRow = Soc['orgs'][number]

export function IndiaMap({ orgs, onOrg }: { orgs: OrgRow[]; onOrg: (id: string) => void }) {
  const [open, setOpen] = useState<string>()
  const langs = useLanguages()
  const byState = new Map<string, OrgRow[]>()
  for (const o of orgs) byState.set(o.state, [...(byState.get(o.state) ?? []), o])
  const name = (code: string) => TILES.find((t) => t[0] === code)?.[1] ?? code
  // calm map: one red that deepens with the share of Critical warnings; only a suspected compromise is purple
  const maxCrit = Math.max(1, ...[...byState.values()].map((rs) => rs.reduce((s, o) => s + o.critical, 0)))
  const shade = (rows: OrgRow[] | undefined) => {
    if (!rows) return { fill: 'var(--color-panel)', opacity: 1, dark: false }
    if (rows.some((o) => o.compromise > 0)) return { fill: 'var(--color-comp)', opacity: 1, dark: true }
    const crit = rows.reduce((s, o) => s + o.critical, 0)
    const opacity = crit ? 0.28 + 0.72 * (crit / maxCrit) : 0.25
    return { fill: crit ? 'var(--color-crit)' : 'var(--color-high)', opacity, dark: opacity >= 0.55 }
  }
  const states = [...byState.keys()].length
  const openRows = open ? byState.get(name(open)) ?? [] : []

  return (
    <div className="relative h-full min-h-[420px] overflow-hidden rounded-3xl bg-map">
      <div className="absolute left-5 top-4 z-10">
        <div className="text-lg font-bold">India</div>
        <div className="text-sm text-mute">{orgs.length} critical-infrastructure operators in {states} states</div>
      </div>
      <svg viewBox={`-20 -10 ${9 * STEP + 40} ${7 * STEP + 30}`} className="absolute inset-0 m-auto h-[88%] w-[92%]" role="img" aria-label="Map of India by state">
        {TILES.map(([code, full, c, r]) => {
          const rows = byState.get(full)
          const x = c * STEP, y = r * STEP + 30
          const comp = rows?.some((o) => o.compromise > 0)
          const crit = rows?.reduce((s, o) => s + o.critical, 0) ?? 0
          return (
            <g key={code} onClick={() => rows && setOpen(code)} style={{ cursor: rows ? 'pointer' : 'default' }}>
              <title>{rows ? `${full}: ${rows.length} organisation(s), ${crit} Critical warnings` : full}</title>
              {comp && (
                <circle cx={x + SIZE / 2} cy={y + SIZE / 2} r={SIZE / 2} fill="var(--color-comp)">
                  <animate attributeName="r" values={`${SIZE / 2};${SIZE / 2 + 18}`} dur="1.8s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.45;0" dur="1.8s" repeatCount="indefinite" />
                </circle>
              )}
              <rect x={x} y={y} width={SIZE} height={SIZE} rx={14} fill="var(--color-panel)" stroke="var(--color-line)" strokeWidth={1.5} />
              {rows && <rect x={x} y={y} width={SIZE} height={SIZE} rx={14} fill={shade(rows).fill}
                             fillOpacity={shade(rows).opacity * (open && open !== code ? 0.6 : 1)} />}
              <text x={x + SIZE / 2} y={y + SIZE / 2 + 5} textAnchor="middle" fontSize={15} fontWeight={700}
                    fill={rows && shade(rows).dark ? '#ffffff' : rows ? 'var(--color-text)' : 'var(--color-mute)'}>{code}</text>
              {rows && (
                <g>
                  <circle cx={x + SIZE - 4} cy={y + 4} r={11} fill="var(--color-text)" />
                  <text x={x + SIZE - 4} y={y + 8} textAnchor="middle" fontSize={11} fontWeight={700} fill="var(--color-ink)">{rows.length}</text>
                </g>
              )}
            </g>
          )
        })}
      </svg>
      <div className="absolute bottom-4 left-5 z-10 flex flex-wrap gap-3 text-xs text-mute">
        <span className="flex items-center gap-1.5"><span className="h-3 w-3 rounded bg-comp" />Suspected compromise</span>
        <span className="flex items-center gap-1.5">
          <span className="flex"><span className="h-3 w-3 rounded-l bg-crit/30" /><span className="h-3 w-3 bg-crit/65" /><span className="h-3 w-3 rounded-r bg-crit" /></span>
          fewer → more Critical warnings
        </span>
        <span className="flex items-center gap-1.5"><span className="flex h-4 w-4 items-center justify-center rounded-full bg-text text-[9px] font-bold text-ink">n</span>operators</span>
      </div>
      {open && (
        <div className="absolute right-4 top-4 z-20 w-80 rounded-2xl bg-panel p-4 shadow-2xl">
          <div className="mb-1 flex items-center justify-between">
            <div className="font-bold">{name(open)}</div>
            <button onClick={() => setOpen(undefined)} className="rounded-full p-1 text-mute hover:bg-panel-2"><X size={16} /></button>
          </div>
          {openRows.map((o) => (
            <button key={o.id} onClick={() => onOrg(o.id)} className="flex w-full items-center gap-3 border-b border-line py-2.5 text-left last:border-0 hover:bg-panel-2/60">
              <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${o.compromise ? 'bg-comp' : o.critical ? 'bg-crit' : 'bg-high'}`} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{o.name}</div>
                <div className="truncate text-xs text-mute">{o.sector} · alerts in {langs[o.lang]?.native ?? o.lang}</div>
              </div>
              <div className="text-right text-xs"><b className="text-sm">{o.critical}</b><div className="text-mute">critical</div></div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
