import { X } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import type { Soc } from '../../api'
import { stateName } from '../../landing/geo/geo'
import { useLanguages } from '../../proactive'
import { indiaStates } from './world'

/* India as a honeycomb (ui-09): about four hundred small hexagons filling the official outline of India, by state.
   The state drawings from @svg-maps/india are rasterised once, off screen, with one colour per state; a hex grid is
   laid over the drawing and every hex whose centre falls on a state takes that state. States with operators carry
   the Critical heat (one red that deepens with the share of Critical warnings; purple where an asset is a suspected
   compromise); the rest stay quiet. Hover lifts a state; click opens its operators, with a way into the 3D site view. */

const VB_W = 612, VB_H = 696
const R = 11.5 // hex radius in drawing units: about 430 hexes over India
const SQ3 = Math.sqrt(3)
const HEX = Array.from({ length: 6 }, (_, i) => { const a = (Math.PI / 180) * (60 * i - 90); return `${(R * 0.92 * Math.cos(a)).toFixed(2)},${(R * 0.92 * Math.sin(a)).toFixed(2)}` }).join(' ')

const CODE: Record<string, string> = {
  'Andhra Pradesh': 'AP', 'Arunachal Pradesh': 'AR', Assam: 'AS', Bihar: 'BR', Chhattisgarh: 'CG', Goa: 'GA', Gujarat: 'GJ', Haryana: 'HR',
  'Himachal Pradesh': 'HP', Jharkhand: 'JH', Karnataka: 'KA', Kerala: 'KL', 'Madhya Pradesh': 'MP', Maharashtra: 'MH', Manipur: 'MN',
  Meghalaya: 'ML', Mizoram: 'MZ', Nagaland: 'NL', Odisha: 'OD', Punjab: 'PB', Rajasthan: 'RJ', Sikkim: 'SK', 'Tamil Nadu': 'TN',
  Telangana: 'TS', Tripura: 'TR', 'Uttar Pradesh': 'UP', Uttarakhand: 'UK', 'West Bengal': 'WB', Delhi: 'DL', 'Jammu and Kashmir': 'JK',
  Ladakh: 'LA', Puducherry: 'PY', Chandigarh: 'CH', 'Andaman and Nicobar Islands': 'AN', Lakshadweep: 'LD', 'Dadra and Nagar Haveli': 'DN',
  'Daman and Diu': 'DD', 'Dadra and Nagar Haveli and Daman and Diu': 'DD',
}

interface Hex { x: number; y: number; s: number }
interface StateCells { name: string; code: string; cx: number; cy: number; n: number }
let GRID: { hexes: Hex[]; states: StateCells[] } | undefined

/** Lay the hex grid over the rasterised states, once per page. */
function buildGrid(): { hexes: Hex[]; states: StateCells[] } {
  if (GRID) return GRID
  const states = indiaStates()
  const cv = document.createElement('canvas')
  cv.width = VB_W
  cv.height = VB_H
  const ctx = cv.getContext('2d', { willReadFrequently: true })!
  states.forEach((st, i) => { ctx.fillStyle = `rgb(${(i + 1) & 255},${(i + 1) >> 8},0)`; ctx.fill(st.path) })
  const px = ctx.getImageData(0, 0, VB_W, VB_H).data
  const at = (x: number, y: number) => {
    const xi = Math.round(x), yi = Math.round(y)
    if (xi < 0 || yi < 0 || xi >= VB_W || yi >= VB_H) return -1
    const o = (yi * VB_W + xi) * 4
    return px[o + 3] ? px[o] + px[o + 1] * 256 - 1 : -1
  }
  const hexes: Hex[] = []
  const w = SQ3 * R, h = 1.5 * R
  for (let row = 0; row * h < VB_H + R; row++) {
    for (let col = 0; col * w < VB_W + w; col++) {
      const x = col * w + (row % 2 ? w / 2 : 0), y = row * h
      // a hex belongs to the state most of its seven sample points land on; a hex with its centre on land is kept
      // even when only that point is, so thin states (Sikkim, Goa, the north-east) stay in the honeycomb
      const votes = new Map<number, number>()
      const pts: [number, number][] = [[0, 0], [R * 0.45, 0], [-R * 0.45, 0], [0, R * 0.45], [0, -R * 0.45], [R * 0.32, R * 0.32], [-R * 0.32, -R * 0.32]]
      for (const [dx, dy] of pts) {
        const s = at(x + dx, y + dy)
        if (s >= 0) votes.set(s, (votes.get(s) ?? 0) + (dx === 0 && dy === 0 ? 3 : 1))
      }
      let best = -1, bestN = 0
      for (const [s, n] of votes) if (n > bestN) { best = s; bestN = n }
      if (best >= 0 && bestN >= 3) hexes.push({ x, y, s: best })
    }
  }
  const cells: StateCells[] = states.map((st) => ({ name: stateName(st.name), code: CODE[stateName(st.name)] ?? st.name.slice(0, 2).toUpperCase(), cx: 0, cy: 0, n: 0 }))
  for (const hx of hexes) { const c = cells[hx.s]; c.cx += hx.x; c.cy += hx.y; c.n += 1 }
  for (const c of cells) if (c.n) { c.cx /= c.n; c.cy /= c.n }
  GRID = { hexes, states: cells }
  return GRID
}

type OrgRow = Soc['orgs'][number]

export function IndiaHex({ orgs, onOrg, onSite, focus }: { orgs: OrgRow[]; onOrg: (id: string) => void; onSite?: (state: string) => void; focus?: string }) {
  const [grid, setGrid] = useState<ReturnType<typeof buildGrid>>()
  const [hover, setHover] = useState<string>()
  const [open, setOpen] = useState<string>()
  const langs = useLanguages()
  useEffect(() => { setGrid(buildGrid()) }, [])

  const byState = useMemo(() => {
    const m = new Map<string, OrgRow[]>()
    for (const o of orgs) { const k = stateName(o.state); m.set(k, [...(m.get(k) ?? []), o]) }
    return m
  }, [orgs])
  // the heat scale runs over the states without a compromise (the compromise state is violet, not on the scale)
  const maxCrit = Math.max(1, ...[...byState.values()].filter((rs) => !rs.some((o) => o.compromise > 0)).map((rs) => rs.reduce((s, o) => s + o.critical, 0)))
  const heatOf = (name: string) => { const rows = byState.get(name); return rows ? Math.min(1, rows.reduce((s, o) => s + o.critical, 0) / maxCrit) : 0 }
  // One hue family per meaning, alive across each state: the heat runs from amber through red to crimson with the
  // share of Critical warnings; the compromise state is violet; quiet states are a cool graphite. Every hex gets its
  // own shade from a seeded noise (±9% lightness), so a state reads as a surface with grain rather than a flat fill.
  const seed = (x: number, y: number) => { const s = Math.sin(x * 12.9898 + y * 78.233) * 43758.5453; return s - Math.floor(s) }
  const fillOf = (name: string, hx: Hex): string => {
    const rows = byState.get(name)
    const g = (seed(hx.x, hx.y) - 0.5) * 0.18
    if (!rows) return `oklch(${(0.24 + g * 0.6).toFixed(3)} 0.012 250)`
    if (rows.some((o) => o.compromise > 0)) return `oklch(${(0.62 + g).toFixed(3)} 0.2 292)`
    const k = heatOf(name) // 0..1
    const hue = 55 - 35 * k   // amber (55) towards crimson (20)
    const l = 0.66 - 0.16 * k + g
    return `oklch(${l.toFixed(3)} ${(0.17 + 0.05 * k).toFixed(3)} ${hue.toFixed(0)})`
  }
  const delayOf = (hx: Hex) => `${(((hx.x + hx.y * 0.6) / (VB_W + VB_H * 0.6)) * 7).toFixed(2)}s`
  const lit = hover ?? focus
  const openRows = open ? byState.get(open) ?? [] : []
  const states = byState.size

  return (
    <div className="relative h-full min-h-[420px] overflow-hidden">
      <div className="absolute left-5 top-4 z-10">
        <div className="text-[15px] font-semibold">India</div>
        <div className="text-[13px] text-mute">{orgs.length} critical-infrastructure operators in {states} states</div>
      </div>
      {grid ? (
        <svg viewBox={`-6 -6 ${VB_W + 12} ${VB_H + 12}`} className="absolute inset-0 m-auto h-[88%] w-[94%]" role="img"
             aria-label={`Map of India by state: ${[...byState.entries()].map(([s, rs]) => `${s} ${rs.reduce((n, o) => n + o.critical, 0)} Critical`).join(', ')}`}>
          {grid.states.map((c, si) => {
            if (!c.n) return null
            const rows = byState.get(c.name)
            const on = lit === c.name, dim = (lit && !on) || (open && open !== c.name)
            return (
              <g key={c.name} data-state={c.name} onMouseEnter={() => setHover(c.name)} onMouseLeave={() => setHover(undefined)}
                 onClick={() => rows && setOpen(c.name)} role={rows ? 'button' : undefined} tabIndex={rows ? 0 : undefined}
                 onKeyDown={(e) => { if (rows && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); setOpen(c.name) } }}
                 aria-label={rows ? `${c.name}: ${rows.length} operator${rows.length > 1 ? 's' : ''}, ${rows.reduce((n, o) => n + o.critical, 0)} Critical warnings` : undefined}
                 style={{ cursor: rows ? 'pointer' : 'default', opacity: dim ? 0.38 : 1, transition: 'opacity 160ms ease' }}>
                <title>{c.name}{rows ? `: ${rows.length} operator(s), ${rows.reduce((n, o) => n + o.critical, 0)} Critical` : ''}</title>
                {grid.hexes.filter((h) => h.s === si).map((h, i) => (
                  <polygon key={i} points={HEX} transform={`translate(${h.x.toFixed(1)} ${h.y.toFixed(1)})${on ? ' scale(1.08)' : ''}`} fill={fillOf(c.name, h)}
                           className={rows ? (rows.some((o) => o.compromise > 0) ? 'hex-live hex-comp' : 'hex-live') : 'hex-quiet'} style={{ animationDelay: delayOf(h) }}
                           stroke={on ? 'var(--color-text)' : 'rgba(0,0,0,0.35)'} strokeWidth={on ? 0.9 : 0.6} />
                ))}
              </g>
            )
          })}
          {grid.states.map((c) => c.n >= 4 && (
            <text key={`l-${c.name}`} x={c.cx} y={c.cy + 3} textAnchor="middle" fontSize={c.n >= 12 ? 10 : 8} fontWeight={600} style={{ fontFamily: 'var(--font-mono)', pointerEvents: 'none' }}
                  fill={!byState.has(c.name) ? 'var(--color-mute)' : byState.get(c.name)!.some((o) => o.compromise > 0) || heatOf(c.name) >= 0.55 ? '#ffffff' : '#141416'}>{c.code}</text>
          ))}
        </svg>
      ) : <div className="absolute inset-0 flex items-center justify-center text-[13px] text-faint">Laying the honeycomb…</div>}
      <div className="absolute bottom-4 left-5 z-10 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-mute">
        <span className="flex items-center gap-1.5"><span className="h-3 w-3 rounded-[3px] bg-comp" />Suspected compromise</span>
        <span className="flex items-center gap-1.5">
          <span className="flex"><span className="h-3 w-3 rounded-l-[3px]" style={{ background: 'color-mix(in oklab, var(--color-crit) 32%, var(--color-panel-2))' }} /><span className="h-3 w-3" style={{ background: 'color-mix(in oklab, var(--color-crit) 66%, var(--color-panel-2))' }} /><span className="h-3 w-3 rounded-r-[3px] bg-crit" /></span>
          fewer to more Critical warnings
        </span>
        <span className="flex items-center gap-1.5"><span className="h-3 w-3 rounded-[3px] bg-panel-2 ring-1 ring-inset ring-line-2" />no operator watched</span>
      </div>
      {lit && !open && (
        <div className="pointer-events-none absolute right-4 top-4 z-10 rounded-xl border border-line-2 bg-panel px-3 py-2 text-[12.5px]">
          <div className="font-semibold">{lit}</div>
          <div className="text-mute">{byState.get(lit) ? `${byState.get(lit)!.length} operator${byState.get(lit)!.length > 1 ? 's' : ''} · ${byState.get(lit)!.reduce((n, o) => n + o.critical, 0)} Critical` : 'no operator watched here'}</div>
        </div>
      )}
      {open && (
        <div className="absolute right-4 top-4 z-20 w-80 rounded-2xl border border-line-2 bg-panel p-4">
          <div className="mb-1 flex items-center justify-between">
            <div className="font-semibold">{open}</div>
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
          {onSite && <button onClick={() => { onSite(open); setOpen(undefined) }} className="mt-3 w-full rounded-full bg-text py-2 text-[13px] font-semibold text-ink hover:opacity-85">Open the 3D site view</button>}
        </div>
      )}
    </div>
  )
}
