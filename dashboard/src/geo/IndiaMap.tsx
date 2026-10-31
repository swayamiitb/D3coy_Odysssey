// India by state for the landing story (a product fragment, marked data-ui). Fills only divide the country: one cool
// family of five tones where neighbours never share one, a slight lift where operators are watched, and oxblood where
// one is suspected compromised. Threat sits on top: one dot per operator (size = Critical warnings), state labels, and
// in the last beat each top state's worst real CVE. Boundaries: @svg-maps/india (MapSVG, CC BY 4.0), credited under
// the story. Hover, focus or tap a state for its card; the ranked list beside the map is the same data without a map.
import india from '@svg-maps/india'
import { useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import { num } from '../format'
import type { AlertRow } from '../types'
import { STATE_CENTROID } from './geo'

interface Shape { id: string; name: string; path: string }
const MAP = india as unknown as { viewBox: string; locations: Shape[] }
const [, , VW, VH] = MAP.viewBox.split(' ').map(Number)

/** Hand-checked map colouring: no two neighbouring states share a tone (--map-1 … --map-5 in index.css). */
const TONE_OF: Record<string, number> = {
  'Jammu and Kashmir': 0, 'Himachal Pradesh': 1, Punjab: 2, Chandigarh: 0, Haryana: 3, Delhi: 0, Uttarakhand: 2,
  'Uttar Pradesh': 4, Rajasthan: 1, 'Madhya Pradesh': 0, Gujarat: 2, 'Dadra and Nagar Haveli': 0, 'Daman and Diu': 4,
  Maharashtra: 3, Chhattisgarh: 1, Jharkhand: 2, Bihar: 0, 'West Bengal': 3, Odisha: 0, Telangana: 2,
  'Andhra Pradesh': 4, Karnataka: 0, Goa: 1, Kerala: 2, 'Tamil Nadu': 1, Puducherry: 3, Sikkim: 0, Assam: 1,
  Meghalaya: 2, 'Arunachal Pradesh': 4, Nagaland: 0, Manipur: 2, Mizoram: 3, Tripura: 0,
  'Andaman and Nicobar Islands': 2, Lakshadweep: 3,
}
/** Label nudges (viewBox units) where neighbouring labels and chips would collide. */
const NUDGE: Record<string, [number, number]> = {
  Telangana: [44, -4], 'Andhra Pradesh': [44, 16], Karnataka: [-14, 0], Kerala: [-10, 8], 'Tamil Nadu': [14, 6],
  Delhi: [-38, -26], 'Uttar Pradesh': [16, 0], Rajasthan: [-6, 0], 'West Bengal': [10, 0], Maharashtra: [-44, 0],
}

// India's extent on this map (official outline): W 68.11, E 97.40, N 37.08, S 6.75 (Indira Point). Mercator.
const merc = (lat: number) => Math.log(Math.tan(Math.PI / 4 + (lat * Math.PI) / 360))
const EXT = { w: 68.11, e: 97.4, n: 37.08, s: 6.75 }

export interface StateThreat {
  name: string
  /** `critical` counts Critical warnings only; a suspected compromise is its own tier, counted in `compromise`. */
  operators: { id: string; name: string; critical: number; compromise: number }[]
  critical: number
  compromise: number
  top: AlertRow | null
}

interface Box { x: number; y: number; w: number; h: number }

const plural = (n: number, one: string, many: string) => `${num(n)} ${n === 1 ? one : many}`

/** What a screen reader hears for a state, and the first line of its card. */
export function describeState(t: StateThreat): string {
  return `${t.name}: ${plural(t.operators.length, 'operator', 'operators')}, ${plural(t.critical, 'Critical warning', 'Critical warnings')}`
    + (t.compromise ? `, ${plural(t.compromise, 'compromise warning', 'compromise warnings')}` : '')
}

/** A place attacks come from: a country with attack reports (DShield) or botnet command servers (Feodo Tracker). */
export interface Origin { id: string; name: string; kind: 'attack' | 'c2'; at: [number, number]; note: string }

const rad = (d: number) => (d * Math.PI) / 180
/** Great-circle initial bearing from the map's centre (22.7N, 82.8E) to a place: 0 = north, clockwise, radians. */
function bearing([lat, lng]: [number, number]): number {
  const [p1, l1, p2, l2] = [rad(22.7), rad(82.8), rad(lat), rad(lng)]
  return Math.atan2(Math.sin(l2 - l1) * Math.cos(p2), Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(l2 - l1))
}
/** Push bearings apart until neighbours are at least 20° apart, keeping their order around the compass. */
function spreadBearings<T extends { b: number }>(xs: T[]): T[] {
  const gap = rad(20)
  const out = [...xs].sort((a, b) => a.b - b.b).map((x) => ({ ...x }))
  for (let pass = 0; pass < 8; pass++) {
    for (let i = 1; i < out.length; i++) {
      const d = out[i].b - out[i - 1].b
      if (d < gap) { const push = (gap - d) / 2; out[i - 1].b -= push; out[i].b += push }
    }
  }
  return out
}

export function IndiaMap({ threats, names, showCves, entered, interactive, hover, onHover, origins = [], showAttacks = false }: {
  threats: StateThreat[]; names: Record<string, string | null>; showCves: boolean; entered: boolean; interactive: boolean
  hover: string | null; onHover: (name: string | null) => void
  /** Attack origins, strongest first; drawn as arrows in the last beat. */
  origins?: Origin[]; showAttacks?: boolean
}) {
  const group = useRef<SVGGElement>(null)
  const [frame, setFrame] = useState<Box | null>(null)
  const [centres, setCentres] = useState<Record<string, [number, number]>>({})

  // Calibrate lat/lng -> viewBox from the drawn outline, and keep each state's shape centre for the entrance wave.
  useLayoutEffect(() => {
    const g = group.current
    if (!g) return
    const b = g.getBBox()
    setFrame({ x: b.x, y: b.y, w: b.width, h: b.height })
    const c: Record<string, [number, number]> = {}
    g.querySelectorAll<SVGPathElement>('path[data-name]').forEach((p) => {
      const pb = p.getBBox()
      c[p.dataset.name!] = [pb.x + pb.width / 2, pb.y + pb.height / 2]
    })
    setCentres(c)
  }, [])

  const project = (lat: number, lng: number): [number, number] | null => {
    if (!frame) return null
    const x = frame.x + ((lng - EXT.w) / (EXT.e - EXT.w)) * frame.w
    const y = frame.y + ((merc(EXT.n) - merc(lat)) / (merc(EXT.n) - merc(EXT.s))) * frame.h
    return [x, y]
  }

  const byName = useMemo(() => new Map(threats.map((t) => [t.name, t])), [threats])
  const hot = threats.find((t) => t.compromise > 0)
  const maxCrit = Math.max(1, ...threats.flatMap((t) => t.operators.map((o) => o.critical)))
  // Threats arrive ranked (compromise first, then Critical); the top three carry their worst CVE in the last beat.
  const chipRank = new Map(threats.slice(0, 3).filter((t) => t.top).map((t, i) => [t.name, i]))
  const origin = hot ? centres[hot.name] : undefined

  const placed = threats.flatMap((t) => {
    const c = STATE_CENTROID[t.name]
    const at = c ? project(c[0], c[1]) : null
    return at ? [{ t, at }] : []
  })
  const pct = ([x, y]: [number, number]): CSSProperties => ({ left: `${(x / VW) * 100}%`, top: `${(y / VH) * 100}%` })

  // One dot per operator; several in one state fan out on a small circle. Size = Critical warnings, for every operator.
  const dots = placed.flatMap(({ t, at }) => t.operators.map((o, i) => {
    const n = t.operators.length
    const a = (2 * Math.PI * i) / n - Math.PI / 2
    const [x, y] = n > 1 ? [at[0] + 9 * Math.cos(a), at[1] + 9 * Math.sin(a)] : at
    const comp = o.compromise > 0
    const r = 2.4 + 4.6 * Math.sqrt(o.critical / maxCrit)
    return { id: o.id, x, y, r: comp ? Math.max(r, 5) : r, comp, critical: o.critical }
  }))

  // Attack arrows: each origin sits around India in its true compass direction (great-circle bearing from the map's
  // centre), spread so no two crowd; each ends on one of the operators with the most Critical warnings.
  const placedOrigins = spreadBearings(origins.map((o) => ({ o, b: bearing(o.at) })))
  // Pair origins and targets in the same compass order, so the arrows fan in without crossing.
  const targets = [...dots].sort((a, b) => b.critical - a.critical).slice(0, placedOrigins.length)
    .sort((a, b) => Math.atan2(a.x - VW / 2, VH / 2 - a.y) - Math.atan2(b.x - VW / 2, VH / 2 - b.y))
  const arrows = placedOrigins.slice(0, targets.length).map(({ o, b }, i) => {
    const from: [number, number] = [VW / 2 + 335 * Math.sin(b), Math.max(64, VH / 2 - 375 * Math.cos(b))] // below the header
    const tgt = targets[i]
    const to: [number, number] = [tgt.x, tgt.y]
    // Bend each curve a little to one side, then stop short of the dot so the head sits on its edge.
    const [mx, my] = [(from[0] + to[0]) / 2, (from[1] + to[1]) / 2]
    const [dx, dy] = [to[0] - from[0], to[1] - from[1]]
    const len = Math.hypot(dx, dy) || 1
    const c: [number, number] = [mx - (dy / len) * len * 0.18, my + (dx / len) * len * 0.18]
    const [ex, ey] = [to[0] - c[0], to[1] - c[1]]
    const el = Math.hypot(ex, ey) || 1
    const end: [number, number] = [to[0] - (ex / el) * (tgt.r + 2), to[1] - (ey / el) * (tgt.r + 2)]
    return {
      o, from, to: end, angle: (Math.atan2(ey, ex) * 180) / Math.PI,
      d: `M${from[0].toFixed(1)},${from[1].toFixed(1)} Q${c[0].toFixed(1)},${c[1].toFixed(1)} ${end[0].toFixed(1)},${end[1].toFixed(1)}`,
      color: o.kind === 'c2' ? 'var(--color-c2)' : 'var(--color-attack)',
    }
  })
  const tip = hover ? byName.get(hover) : undefined
  const tipAt = hover ? (placed.find((p) => p.t.name === hover)?.at ?? centres[hover]) : undefined
  const operators = threats.reduce((n, t) => n + t.operators.length, 0)
  const summary = hot
    ? `Map of India: ${plural(operators, 'operator', 'operators')} in ${plural(threats.length, 'state', 'states')}. ${hot.name} has a suspected compromise.`
    : `Map of India: ${plural(operators, 'operator', 'operators')} in ${plural(threats.length, 'state', 'states')}.`

  return (
    <div data-ui className={`india-map relative aspect-[612/696] h-full max-w-full ${entered ? 'is-in' : ''}`} onMouseLeave={() => onHover(null)}>
      <svg viewBox={MAP.viewBox} className="absolute inset-0 size-full overflow-visible" role="group" aria-label={summary}>
        <g ref={group}>
          {MAP.locations.map((s) => {
            const t = byName.get(s.name)
            const fill = t?.compromise ? 'var(--map-hot)' : `var(--map-${(TONE_OF[s.name] ?? 0) + 1}${t ? '-lit' : ''})`
            const c = centres[s.name]
            const delay = origin && c ? Math.hypot(c[0] - origin[0], c[1] - origin[1]) * 0.6 : 0
            const focusable = interactive && !!t
            return (
              <path key={s.id} d={s.path} data-name={s.name}
                className={`india-state ${hover === s.name ? 'is-hover' : ''}`}
                style={{ '--fill': fill, transitionDelay: entered ? `${delay}ms, ${delay}ms, 0ms` : '0ms', pointerEvents: interactive ? 'auto' : 'none' } as CSSProperties}
                tabIndex={focusable ? 0 : undefined} role={focusable ? 'button' : undefined} aria-label={t && focusable ? describeState(t) : undefined}
                onMouseEnter={() => onHover(s.name)} onFocus={() => onHover(s.name)} onBlur={() => onHover(null)}
                onClick={() => onHover(hover === s.name ? null : s.name)} />
            )
          })}
        </g>
        {arrows.map((a, i) => (
          <g key={a.o.id} className={`india-attack pointer-events-none ${showAttacks ? 'is-on' : ''}`} style={{ '--d': `${150 + i * 140}ms` } as CSSProperties}>
            <defs>
              <linearGradient id={`atk-${a.o.id}`} gradientUnits="userSpaceOnUse" x1={a.from[0]} y1={a.from[1]} x2={a.to[0]} y2={a.to[1]}>
                <stop offset="0" stopColor={a.color} stopOpacity="0.05" />
                <stop offset="1" stopColor={a.color} stopOpacity="1" />
              </linearGradient>
            </defs>
            <path className="glow" d={a.d} fill="none" stroke={a.color} strokeWidth={7} strokeLinecap="round" />
            <path className="line" d={a.d} pathLength={1} fill="none" stroke={`url(#atk-${a.o.id})`} strokeWidth={2} strokeLinecap="round" />
            <path className="head" d="M0,0 L-9,-4.5 L-9,4.5 Z" fill={a.color} transform={`translate(${a.to[0]} ${a.to[1]}) rotate(${a.angle})`} />
            <circle className="origin" cx={a.from[0]} cy={a.from[1]} r={4.5} fill={a.color} stroke="var(--color-ground)" strokeWidth={1.5} />
            <circle className="ripple" cx={a.to[0]} cy={a.to[1]} r={6} fill="none" stroke={a.color} strokeWidth={1.5} />
          </g>
        ))}
        {dots.map((d) => (
          <g key={d.id} className="pointer-events-none">
            {d.comp && <circle cx={d.x} cy={d.y} r={d.r} className="india-ring" />}
            <circle cx={d.x} cy={d.y} r={d.r} stroke="var(--color-ground)" strokeWidth={1.5}
              fill={d.comp ? 'var(--color-compromise)' : d.critical > 0 ? 'var(--color-critical)' : 'var(--color-watch)'} />
          </g>
        ))}
      </svg>

      {/* Where the attacks come from: one label per origin, on a solid plate, above its point. */}
      {arrows.map((a, i) => {
        // Two short lines, kept inside the frame: labels near an edge hang inward from their point.
        const edge = a.from[0] > VW * 0.8 ? '-translate-x-[calc(100%-10px)] text-right' : a.from[0] < VW * 0.15 ? '-translate-x-[10px] text-left' : '-translate-x-1/2 text-center'
        return (
          <div key={a.o.id} className={`india-origin-label pointer-events-none absolute ${edge} -translate-y-[calc(100%+10px)] rounded-lg bg-ground px-2 py-1 text-[12px] leading-tight whitespace-nowrap ${showAttacks ? 'is-on' : ''}`}
            style={{ ...pct(a.from), '--d': `${150 + i * 140}ms` } as CSSProperties}>
            <div className="font-medium text-text">{a.o.name}</div>
            <div className="fig text-mute">{a.o.note}</div>
          </div>
        )
      })}

      {/* Direct labels: state and Critical count; in the last beat, the worst real CVE of each top state. */}
      {placed.map(({ t, at }) => {
        const [dx, dy] = NUDGE[t.name] ?? [0, 0]
        const rank = chipRank.get(t.name)
        return (
          <div key={t.name} className="india-label pointer-events-none absolute -translate-x-1/2 pt-3.5 text-center leading-tight max-lg:hidden" style={pct([at[0] + dx, at[1] + dy])}>
            <div className="whitespace-nowrap text-[12px] font-medium tracking-[0.01em] text-text">{t.name}</div>
            <div className="num whitespace-nowrap text-[12px] text-text/85">{num(t.critical)} Critical</div>
            {t.top && rank != null && (
              <a href={`#/incident/${t.top.org_id}/${t.top.cve_id}`} tabIndex={showCves ? 0 : -1} aria-hidden={!showCves}
                className={`india-cve mt-1 inline-flex items-center gap-1.5 whitespace-nowrap rounded-full bg-ground px-2 py-0.5 text-[12px] text-text ${showCves ? 'is-on pointer-events-auto' : ''}`}
                style={{ '--d': `${250 + rank * 60}ms` } as CSSProperties}>
                <span className="font-mono">{t.top.cve_id}</span>
                {names[t.top.id] && <span className="text-mute">{names[t.top.id]}</span>}
                {t.top.kev && <span className="text-mute">KEV</span>}
              </a>
            )}
          </div>
        )
      })}

      {tip && tipAt && interactive && (
        <div role="status" className="india-tip pointer-events-none absolute z-10 w-64 -translate-x-1/2 -translate-y-[calc(100%+14px)] max-md:translate-y-3.5 rounded-lg bg-raised p-3 text-[12px] leading-snug" style={pct(tipAt)}>
          <div className="text-[13px] font-medium">{tip.name}</div>
          <div className="mt-1 text-mute">{plural(tip.operators.length, 'operator', 'operators')}: {tip.operators.map((o) => o.name).join(', ')}</div>
          <div className="num mt-1">
            {plural(tip.critical, 'Critical warning', 'Critical warnings')}
            {tip.compromise ? <>, <span className="text-compromise">{plural(tip.compromise, 'compromise warning', 'compromise warnings')}</span></> : null}
          </div>
          {tip.top && (
            <div className="mt-2 border-t border-line pt-2">
              <div><span className="font-mono">{tip.top.cve_id}</span>{names[tip.top.id] ? <span className="text-mute">, {names[tip.top.id]}</span> : null}</div>
              <div className="mt-0.5 text-mute">
                {tip.top.kev ? 'In CISA KEV' : 'Not in CISA KEV'}{tip.top.epss != null ? `, EPSS ${num(tip.top.epss, 2)}` : ''}
              </div>
              <div className="mt-0.5 line-clamp-2 text-mute">{tip.top.title}</div>
            </div>
          )}
          <div className="mt-2 text-faint">Operators simulated; CVE, KEV and EPSS real</div>
        </div>
      )}
      {hover && !tip && interactive && tipAt && (
        <div className="india-tip pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-[calc(100%+8px)] rounded-md bg-raised px-2 py-1 text-[12px] text-mute" style={pct(tipAt)}>
          {hover}: no monitored operators
        </div>
      )}
    </div>
  )
}
