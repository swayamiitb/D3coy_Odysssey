// India by state for the landing story. Fills only divide the country (five muted tones, neighbours always differ);
// threat lives on top: one dot per operator (size = Critical warnings, red pulse = suspected compromise), a label per
// state with operators, and in the last beat each top state's worst real CVE. Boundaries: @svg-maps/india (CC BY 4.0).
import india from '@svg-maps/india'
import { useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import { num } from '../format'
import type { AlertRow } from '../types'
import { STATE_CENTROID } from './geo'

interface Shape { id: string; name: string; path: string }
const MAP = india as unknown as { viewBox: string; locations: Shape[] }
const [, , VW, VH] = MAP.viewBox.split(' ').map(Number)

/** Five low-chroma tones for a dark ground: calm, distinct, never a rainbow. */
const TONES = [
  'oklch(0.40 0.035 252)', // slate blue
  'oklch(0.43 0.030 200)', // teal grey
  'oklch(0.38 0.035 290)', // violet grey
  'oklch(0.45 0.028 155)', // sage
  'oklch(0.36 0.025 228)', // deep steel
]
/** Hand-checked map colouring: no two neighbouring states share a tone. */
const TONE_OF: Record<string, number> = {
  'Jammu and Kashmir': 0, 'Himachal Pradesh': 1, Punjab: 2, Chandigarh: 0, Haryana: 3, Delhi: 0, Uttarakhand: 2,
  'Uttar Pradesh': 4, Rajasthan: 1, 'Madhya Pradesh': 0, Gujarat: 2, 'Dadra and Nagar Haveli': 0, 'Daman and Diu': 4,
  Maharashtra: 3, Chhattisgarh: 1, Jharkhand: 2, Bihar: 0, 'West Bengal': 3, Odisha: 0, Telangana: 2,
  'Andhra Pradesh': 4, Karnataka: 0, Goa: 1, Kerala: 2, 'Tamil Nadu': 1, Puducherry: 3, Sikkim: 0, Assam: 1,
  Meghalaya: 2, 'Arunachal Pradesh': 4, Nagaland: 0, Manipur: 2, Mizoram: 3, Tripura: 0,
  'Andaman and Nicobar Islands': 2, Lakshadweep: 3,
}
/** Label nudges (viewBox units) where neighbouring labels would collide. */
const NUDGE: Record<string, [number, number]> = {
  Telangana: [16, -6], 'Andhra Pradesh': [24, 14], Karnataka: [-14, 0], Kerala: [-10, 8], 'Tamil Nadu': [14, 6],
  Delhi: [-38, -26], 'Uttar Pradesh': [16, 0], Rajasthan: [-6, 0], 'West Bengal': [10, 0], Maharashtra: [-24, 0],
}

// India's extent on this map (official outline): W 68.11, E 97.40, N 37.08, S 6.75 (Indira Point). Mercator.
const merc = (lat: number) => Math.log(Math.tan(Math.PI / 4 + (lat * Math.PI) / 360))
const EXT = { w: 68.11, e: 97.4, n: 37.08, s: 6.75 }

export interface StateThreat {
  name: string
  operators: { id: string; name: string; critical: number; compromise: number }[]
  critical: number
  compromise: number
  top: AlertRow | null
}

interface Box { x: number; y: number; w: number; h: number }

export function IndiaMap({ threats, showCves, entered, interactive }: {
  threats: StateThreat[]; showCves: boolean; entered: boolean; interactive: boolean
}) {
  const group = useRef<SVGGElement>(null)
  const [frame, setFrame] = useState<Box | null>(null)
  const [centres, setCentres] = useState<Record<string, [number, number]>>({})
  const [hover, setHover] = useState<string | null>(null)

  // Calibrate lat/lng -> viewBox from the drawn outline, and keep each state's shape centre for the entrance ripple.
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
  const ranked = [...threats].sort((a, b) => b.compromise - a.compromise || b.critical - a.critical)
  const withCve = new Set(ranked.slice(0, 4).filter((t) => t.top).map((t) => t.name))
  const origin = hot ? centres[hot.name] : undefined

  const placed = threats.flatMap((t) => {
    const c = STATE_CENTROID[t.name]
    const at = c ? project(c[0], c[1]) : null
    return at ? [{ t, at }] : []
  })
  const pct = ([x, y]: [number, number]): CSSProperties => ({ left: `${(x / VW) * 100}%`, top: `${(y / VH) * 100}%` })
  const tip = hover ? byName.get(hover) : undefined
  const tipAt = hover ? (placed.find((p) => p.t.name === hover)?.at ?? centres[hover]) : undefined

  return (
    <div className={`india-map relative aspect-[612/696] h-full max-w-full ${entered ? 'is-in' : ''}`} onMouseLeave={() => setHover(null)}>
      <svg viewBox={MAP.viewBox} className="absolute inset-0 size-full overflow-visible" role="img" aria-label="Map of India by state, with monitored operators">
        <g ref={group}>
          {MAP.locations.map((s) => {
            const c = centres[s.name]
            const delay = origin && c ? Math.hypot(c[0] - origin[0], c[1] - origin[1]) * 1.6 : 0
            return (
              <path key={s.id} d={s.path} data-name={s.name}
                className={`india-state ${hover === s.name ? 'is-hover' : ''}`}
                style={{ fill: TONES[TONE_OF[s.name] ?? 0], transitionDelay: entered ? `${delay}ms, ${delay}ms, 0ms` : '0ms', pointerEvents: interactive ? 'auto' : 'none' }}
                onMouseEnter={() => setHover(s.name)} />
            )
          })}
        </g>
        {hot && MAP.locations.filter((s) => s.name === hot.name).map((s) => <path key="hot" d={s.path} className="india-hot" />)}
        {placed.flatMap(({ t, at }) => t.operators.map((o, i) => {
          const n = t.operators.length
          const a = (2 * Math.PI * i) / n - Math.PI / 2
          const [x, y] = n > 1 ? [at[0] + 9 * Math.cos(a), at[1] + 9 * Math.sin(a)] : at
          const r = o.compromise > 0 ? 6 : 2.6 + 4.2 * Math.sqrt(o.critical / maxCrit)
          return (
            <g key={o.id} className="pointer-events-none">
              {o.compromise > 0 && <circle cx={x} cy={y} r={r} className="india-ring" />}
              <circle cx={x} cy={y} r={r} fill={o.compromise > 0 ? 'var(--color-compromise)' : 'var(--color-critical)'}
                stroke="var(--color-ground)" strokeWidth={1.2} />
            </g>
          )
        }))}
      </svg>

      {/* Direct labels: state, Critical count, and in the last beat the worst real CVE for the top states. */}
      {placed.map(({ t, at }) => {
        const [dx, dy] = NUDGE[t.name] ?? [0, 0]
        return (
          <div key={t.name} className="pointer-events-none absolute -translate-x-1/2 pt-3.5 text-center leading-tight max-lg:hidden" style={pct([at[0] + dx, at[1] + dy])}>
            <div className={`whitespace-nowrap text-[12px] font-medium ${t.compromise > 0 ? 'text-compromise' : 'text-text'}`}>{t.name}</div>
            <div className="num whitespace-nowrap text-[11px] text-mute">{num(t.critical)} Critical</div>
            {t.top && (
              <div className={`india-cve mt-1 inline-flex items-center gap-1 whitespace-nowrap rounded-md bg-ground/85 px-1.5 py-0.5 text-[11px] text-text ring-1 ring-line ${showCves && withCve.has(t.name) ? 'is-on' : ''}`}>
                <span className="num">{t.top.cve_id}</span>{t.top.kev && <span className="text-critical">KEV</span>}
              </div>
            )}
          </div>
        )
      })}

      {tip && tipAt && interactive && (
        <div className="pointer-events-none absolute z-10 w-64 -translate-x-1/2 -translate-y-[calc(100%+14px)] rounded-lg bg-raised/95 p-3 text-[12px] shadow-2xl ring-1 ring-line backdrop-blur" style={pct(tipAt)}>
          <div className="text-[13px] font-medium">{tip.name}</div>
          <div className="mt-1 text-mute">{tip.operators.length} operator{tip.operators.length === 1 ? '' : 's'}: {tip.operators.map((o) => o.name).join(', ')}</div>
          <div className="num mt-1">{num(tip.critical)} Critical{tip.compromise ? <span className="text-compromise"> · {tip.compromise} compromise</span> : null}</div>
          {tip.top && (
            <div className="mt-2 border-t border-line pt-2">
              <div className="num">{tip.top.cve_id}{tip.top.kev ? <span className="text-critical"> · CISA KEV</span> : null}{tip.top.epss != null ? <span className="whitespace-nowrap text-mute"> · EPSS {num(tip.top.epss, 2)}</span> : null}</div>
              <div className="mt-0.5 line-clamp-2 text-mute">{tip.top.title}</div>
            </div>
          )}
        </div>
      )}
      {hover && !tip && interactive && tipAt && (
        <div className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-[calc(100%+8px)] rounded-md bg-raised/95 px-2 py-1 text-[12px] text-mute ring-1 ring-line" style={pct(tipAt)}>
          {hover} · no monitored operators
        </div>
      )}

      <div className="absolute right-0 bottom-0 text-[10px] text-faint">Boundaries: MapSVG via svg-maps, CC BY 4.0</div>
    </div>
  )
}
