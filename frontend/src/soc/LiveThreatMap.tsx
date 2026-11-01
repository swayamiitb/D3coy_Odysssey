import { Component, lazy, Suspense, useMemo, useState, type CSSProperties, type ReactNode } from 'react'
import type { Soc } from '../api'
import feodo from '../landing/geo/feodo.json'
import { COUNTRY_CENTROID, STATE_CENTROID, stateName } from '../landing/geo/geo'
import { Prov } from '../ui'
import { Seg, SocCard, useJson } from './kit'
import { IPS_LOCATED, originsFromData, routesFor, snapshotLabel, targetsFrom, type OriginFilter } from './map/data'
import { OriginRail } from './map/OriginRail'
import type { ImageryInfo, LiveArc } from './map/ThreatGlobe'
import { WorldMap } from './map/WorldMap'

/* The Live page's threat map (ui-15): the satellite-view globe (CesiumJS) carrying the real attack origins, the
   operators' states and, as they happen, the live engine's C2 beacon detections. The globe loads on demand (its code
   is a separate chunk); if it cannot start (no WebGL, the chunk missing) the 2D map takes its place, so the page
   never loses the picture. The card says which imagery is on screen and which token slot serves it, never the token. */

const ThreatGlobe = lazy(() => import('./map/ThreatGlobe').then((m) => ({ default: m.ThreatGlobe })))

const DARK = {
  '--color-ink': '#000000', '--color-panel': '#0e0e10', '--color-soft': '#060607', '--color-panel-2': '#1a1a1d',
  '--color-panel-3': '#26262a', '--color-panel-4': '#141416', '--color-line': '#222225', '--color-line-2': '#2e2e33',
  '--color-text': '#f4f4f5', '--color-mute': '#a1a1a8', '--color-faint': '#76767d', '--color-accent': '#4f8cf7',
  '--color-crit': '#e5383b', '--color-high': '#ff7a3d', '--color-med': '#f5c242', '--color-comp': '#8a63e8', '--color-ok': '#22b45f',
  '--color-crit-ink': '#ff6b66', '--color-high-ink': '#ff9d6b', '--color-comp-ink': '#b49cff', '--color-ok-ink': '#4fd486',
  '--color-map': '#0e0e10', colorScheme: 'dark', background: '#050506', color: '#f4f4f5', borderRadius: '1rem',
} as CSSProperties

const FILTERS: [OriginFilter, string][] = [['all', 'All origins'], ['attack', 'Attack sources'], ['c2', 'Botnet C2']]

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Live = any
interface Detection { id: string; ts: string; kind: string; title: string; org_id?: string; asset?: string; c2?: string; drill?: string | null }

/** A chunk that failed to load or a globe that threw must not take the page down: the 2D map takes over. */
class Guard extends Component<{ fallback: (why: string) => ReactNode; children: ReactNode }, { why?: string }> {
  state: { why?: string } = {}
  static getDerivedStateFromError(e: unknown) { return { why: e instanceof Error ? e.message : String(e) } }
  render() { return this.state.why ? this.props.fallback(this.state.why) : this.props.children }
}

const refang = (s: string) => s.replace(/\[\.\]/g, '.').replace(/^hxxp/, 'http')
const C2_COUNTRY = new Map(feodo.entries.map((e) => [e.ip, e.country]))

/** The live engine's beacon detections as arcs: the operator's state to the C2's country (Feodo Tracker locates it). */
function liveArcs(detections: Detection[] | undefined, orgs: Soc['orgs'] | undefined): LiveArc[] {
  if (!detections || !orgs) return []
  const state = new Map(orgs.map((o) => [o.id, stateName(o.state)]))
  const out: LiveArc[] = []
  for (const d of detections) {
    if (d.kind !== 'beacon' || !d.c2 || !d.org_id) continue
    const st = state.get(d.org_id)
    const at = st ? STATE_CENTROID[st] : undefined
    if (!st || !at) continue
    const cc = C2_COUNTRY.get(refang(d.c2))
    const c2at = cc ? COUNTRY_CENTROID[cc] : undefined
    out.push({ id: d.id, state: st, at, c2: d.c2, c2cc: cc, c2at, title: d.title })
    if (out.length >= 6) break
  }
  return out
}

export function LiveThreatMap({ s }: { s?: Live }) {
  const soc = useJson<Soc>('/api/soc', [], 30000).data
  const [view, setView] = useState<'world' | 'india'>('world')
  const [paths, setPaths] = useState<'hover' | 'all'>('all')
  const [filter, setFilter] = useState<OriginFilter>('all')
  const [focus, setFocus] = useState<string>()
  const [imagery, setImagery] = useState<ImageryInfo>({ name: 'starting', status: 'loading', slots: 0 })
  const [fallback, setFallback] = useState<string>()

  const all = useMemo(originsFromData, [])
  const targets = useMemo(() => targetsFrom(soc?.orgs ?? []), [soc])
  const allRoutes = useMemo(() => routesFor(all, targets), [all, targets])
  const origins = useMemo(() => (filter === 'all' ? all : all.filter((o) => o.kind === filter)), [all, filter])
  const routes = useMemo(() => allRoutes.filter((r) => filter === 'all' || r.o.kind === filter), [allRoutes, filter])
  const arcs = useMemo(() => liveArcs(s?.detections as Detection[] | undefined, soc?.orgs), [s, soc])
  const drill = s?.drill?.status === 'running' ? s.drill : undefined
  const other = ((s?.detections as Detection[] | undefined) ?? []).filter((d) => d.kind !== 'beacon').slice(0, 3)

  const dot = imagery.status === 'ok' ? 'bg-ok' : imagery.status === 'loading' ? 'animate-pulse bg-accent' : imagery.status === 'offline' ? 'bg-high' : 'bg-crit'
  const imageryLine = fallback ? `2D map: the globe could not start (${fallback})`
    : imagery.status === 'loading' ? `Loading ${imagery.name}…`
      : imagery.status === 'ok' ? `${imagery.name} · ${imagery.detail}`
        : imagery.status === 'offline' ? `${imagery.name}${imagery.detail ? ` · ${imagery.detail}` : ''}` : imagery.detail ?? imagery.name

  const select = (
    <label className="relative">
      <span className="sr-only">Show origins</span>
      <select value={filter} onChange={(e) => { setFilter(e.target.value as OriginFilter); setFocus(undefined) }}
              className="h-9 appearance-none rounded-lg border border-line bg-panel/90 pl-3 pr-8 text-[13px] font-medium text-text backdrop-blur hover:bg-panel-2 focus-visible:outline-2 focus-visible:outline-accent">
        {FILTERS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
      </select>
      <svg className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-mute" width="12" height="12" viewBox="0 0 12 12" aria-hidden>
        <path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </label>
  )

  const flat = (why: string) => (
    <div className="relative h-full">
      <WorldMap origins={origins} targets={targets} routes={routes} focus={focus} showAll={paths === 'all'} onFocus={setFocus} onPick={() => undefined} paused={false} topLeft={select} />
      <span className="sr-only">{why}</span>
    </div>
  )

  return (
    <div className="soc-dark rounded-2xl" style={DARK}>
      <SocCard title="Live threat map" prov={['REAL', 'SIM']} className="!bg-[#0e0e10]"
               sub={`Satellite view of where attacks start and the operators they reach; the live engine's C2 beacons draw as they are detected. ${arcs.length ? `${arcs.length} live beacon${arcs.length > 1 ? 's' : ''} on the map.` : 'No live beacon right now: run the implant drill below to see one.'}`}
               right={
                 <div className="flex flex-wrap items-center gap-2">
                   <Seg label="Attack paths" value={paths} onChange={setPaths} items={[['hover', 'Paths on hover'], ['all', 'All paths']]} />
                   <Seg label="View" value={view} onChange={setView} items={[['world', 'World'], ['india', 'India']]} />
                 </div>
               }
               bodyClass="">
        <div className="grid border-t border-line xl:grid-cols-[minmax(0,1fr)_380px]">
          <div className="relative h-[360px] min-w-0 overflow-hidden rounded-bl-2xl sm:h-[460px] md:h-[560px] max-xl:rounded-none">
            {fallback ? flat(fallback) : (
              <Guard fallback={(why) => { queueMicrotask(() => setFallback(why)); return flat(why) }}>
                <Suspense fallback={<div className="flex h-full items-center justify-center bg-black text-[13px] text-white/60">Loading the globe…</div>}>
                  <ThreatGlobe origins={origins} targets={targets} routes={routes} live={arcs} focus={focus} showAll={paths === 'all'} view={view}
                               paused={false} onFocus={setFocus} onImagery={setImagery} onFail={setFallback} />
                </Suspense>
              </Guard>
            )}
            {!fallback && <div className="absolute left-3 top-3 z-10 flex flex-wrap items-center gap-2">{select}
              <span className="inline-flex h-9 items-center gap-2 rounded-lg border border-line bg-panel/90 px-3 text-[12.5px] text-mute backdrop-blur">
                <span className="h-1.5 w-1.5 rounded-full bg-ok" />Origins {snapshotLabel()} · {IPS_LOCATED.toLocaleString('en-IN')} IPs located
              </span></div>}
            {drill && (
              <div className="absolute right-3 top-3 z-10 rounded-lg border border-accent/40 bg-black/70 px-3 py-1.5 text-[12.5px] text-white backdrop-blur">
                <span className="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-accent" />Drill running: {drill.title}
              </div>
            )}
          </div>
          <aside className="min-w-0 border-t border-line xl:border-l xl:border-t-0">
            <OriginRail origins={origins} focus={focus} onFocus={setFocus} />
          </aside>
        </div>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-line px-5 py-3 text-[12.5px] text-mute">
          <span className="inline-flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${dot}`} />Imagery: {imageryLine}</span>
          <span className="inline-flex items-center gap-1.5"><Prov p="REAL" /> attack origins (SANS ISC DShield, located by RIPEstat), botnet C2 (abuse.ch Feodo Tracker), live C2 indicators</span>
          <span className="inline-flex items-center gap-1.5"><Prov p="SIM" /> operators, landing points, the beacon sightings</span>
          {arcs.length > 0 && <span className="text-text">Live: {arcs.map((a) => `${a.state} → C2 ${a.c2}${a.c2cc ? ` (${a.c2cc})` : ''}`).join(' · ')}</span>}
          {other.length > 0 && <span>Not on the map (no geography): {other.map((d) => d.title.slice(0, 48)).join(' · ')}</span>}
        </div>
      </SocCard>
    </div>
  )
}
