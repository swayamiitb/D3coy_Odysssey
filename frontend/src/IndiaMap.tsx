import { X } from 'lucide-react'
import { useState } from 'react'
import type { Soc } from './api'
import { useLanguages } from './proactive'

/* Hex-tile map of India (one hexagon per state, placed roughly where it lies). A tile cartogram keeps the map simple and
   avoids drawing contested boundaries; states take the colour of their worst open risk: one red that deepens with the
   Critical warnings, purple where an asset is suspected compromised. SOC black (ui-07). */
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
const R = 36                      // hexagon radius (pointy top)
const W = Math.sqrt(3) * R        // hexagon width
const HEX = Array.from({ length: 6 }, (_, i) => {
  const a = (Math.PI / 180) * (60 * i - 90)
  return `${(R * Math.cos(a)).toFixed(2)},${(R * Math.sin(a)).toFixed(2)}`
}).join(' ')
const pos = (c: number, r: number): [number, number] => [c * W + (r % 2 ? W / 2 : 0) + W / 2, r * 1.5 * R + R]

type OrgRow = Soc['orgs'][number]

export function IndiaMap({ orgs, onOrg, bare }: { orgs: OrgRow[]; onOrg: (id: string) => void; bare?: boolean }) {
  const [open, setOpen] = useState<string>()
  const [hover, setHover] = useState<string>()
  const langs = useLanguages()
  const byState = new Map<string, OrgRow[]>()
  for (const o of orgs) byState.set(o.state, [...(byState.get(o.state) ?? []), o])
  const name = (code: string) => TILES.find((t) => t[0] === code)?.[1] ?? code
  const maxCrit = Math.max(1, ...[...byState.values()].map((rs) => rs.reduce((s, o) => s + o.critical, 0)))
  const shade = (rows: OrgRow[] | undefined) => {
    if (!rows) return { fill: 'var(--color-panel-2)', strong: false }
    if (rows.some((o) => o.compromise > 0)) return { fill: 'var(--color-comp)', strong: true }
    const crit = rows.reduce((s, o) => s + o.critical, 0)
    if (!crit) return { fill: 'color-mix(in oklab, var(--color-high) 32%, var(--color-panel-2))', strong: false }
    const pct = Math.round(30 + 70 * (crit / maxCrit))
    return { fill: `color-mix(in oklab, var(--color-crit) ${pct}%, var(--color-panel-2))`, strong: pct >= 55 }
  }
  const states = [...byState.keys()].length
  const openRows = open ? byState.get(name(open)) ?? [] : []

  return (
    <div className={`relative h-full min-h-[420px] overflow-hidden ${bare ? '' : 'rounded-2xl border border-line bg-ink'}`}>
      <div className="absolute left-5 top-4 z-10">
        <div className="text-[15px] font-semibold">India</div>
        <div className="text-[13px] text-mute">{orgs.length} critical-infrastructure operators in {states} states</div>
      </div>
      <svg viewBox={`-12 -6 ${9 * W + W / 2 + 24} ${6 * 1.5 * R + 2 * R + 40}`} className="absolute inset-0 m-auto h-[84%] w-[92%]" role="img" aria-label="Map of India by state">
        {TILES.map(([code, full, c, r]) => {
          const rows = byState.get(full)
          const [x, y] = pos(c, r)
          const comp = rows?.some((o) => o.compromise > 0)
          const crit = rows?.reduce((s, o) => s + o.critical, 0) ?? 0
          const sh = shade(rows)
          const dim = open && open !== code
          const lit = hover === code || open === code
          return (
            <g key={code} transform={`translate(${x.toFixed(1)} ${(y + 24).toFixed(1)})`}
               onClick={() => rows && setOpen(code)} onMouseEnter={() => setHover(code)} onMouseLeave={() => setHover(undefined)}
               onKeyDown={(e) => { if (rows && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); setOpen(code) } }}
               tabIndex={rows ? 0 : undefined} role={rows ? 'button' : undefined}
               aria-label={rows ? `${full}: ${rows.length} operator(s), ${crit} Critical warnings${comp ? ', suspected compromise' : ''}` : undefined}
               style={{ cursor: rows ? 'pointer' : 'default', opacity: dim ? 0.45 : 1, transition: 'opacity 160ms ease' }}>
              <title>{rows ? `${full}: ${rows.length} organisation(s), ${crit} Critical warnings` : full}</title>
              {comp && <polygon points={HEX} fill="none" stroke="var(--color-comp)" strokeWidth={2} className="soc-ring" />}
              <polygon points={HEX} transform="scale(0.94)" fill={sh.fill}
                       stroke={lit ? 'var(--color-text)' : rows ? 'color-mix(in oklab, var(--color-text) 14%, transparent)' : 'var(--color-line)'}
                       strokeWidth={lit ? 2 : 1} />
              <text y={5} textAnchor="middle" fontSize={14} fontWeight={600} style={{ fontFamily: 'var(--font-mono)' }}
                    fill={sh.strong ? '#ffffff' : rows ? 'var(--color-text)' : 'var(--color-faint)'}>{code}</text>
              {rows && (
                <g transform={`translate(${(R * 0.62).toFixed(1)} ${(-R * 0.62).toFixed(1)})`}>
                  <circle r={10} fill="var(--color-text)" />
                  <text y={4} textAnchor="middle" fontSize={11} fontWeight={700} fill="var(--color-ink)">{rows.length}</text>
                </g>
              )}
            </g>
          )
        })}
      </svg>
      <div className="absolute bottom-4 left-5 z-10 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-mute">
        <span className="flex items-center gap-1.5"><span className="h-3 w-3 rounded-[3px] bg-comp" />Suspected compromise</span>
        <span className="flex items-center gap-1.5">
          <span className="flex"><span className="h-3 w-3 rounded-l-[3px]" style={{ background: 'color-mix(in oklab, var(--color-crit) 30%, var(--color-panel-2))' }} /><span className="h-3 w-3" style={{ background: 'color-mix(in oklab, var(--color-crit) 65%, var(--color-panel-2))' }} /><span className="h-3 w-3 rounded-r-[3px] bg-crit" /></span>
          fewer to more Critical warnings
        </span>
        <span className="flex items-center gap-1.5"><span className="flex h-4 w-4 items-center justify-center rounded-full bg-text text-[9px] font-bold text-ink">n</span>operators</span>
      </div>
      {open && (
        <div className="absolute right-4 top-4 z-20 w-80 rounded-2xl border border-line-2 bg-panel p-4">
          <div className="mb-1 flex items-center justify-between">
            <div className="font-semibold">{name(open)}</div>
            <button onClick={() => setOpen(undefined)} aria-label="Close" className="rounded-full p-1 text-mute hover:bg-panel-2"><X size={16} /></button>
          </div>
          {openRows.map((o) => (
            <button key={o.id} onClick={() => onOrg(o.id)} className="flex w-full items-center gap-3 border-b border-line py-2.5 text-left last:border-0 hover:bg-panel-2/60">
              <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${o.compromise ? 'bg-comp' : o.critical ? 'bg-crit' : 'bg-high'}`} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{o.name}</div>
                <div className="truncate text-xs text-mute">{o.sector} · alerts in {langs[o.lang]?.native ?? o.lang}</div>
              </div>
              <div className="text-right text-xs"><b className="font-mono text-sm">{o.critical}</b><div className="text-mute">critical</div></div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
