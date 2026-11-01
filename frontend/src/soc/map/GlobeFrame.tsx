import { Component, lazy, Suspense, useState, type ReactNode } from 'react'
import type { ImageryInfo, LiveArc } from './ThreatGlobe'
import { WorldMap, type WorldMapProps } from './WorldMap'

/* The satellite-view globe as the template for every world threat map (ui-15), with the 2D map as its understudy:
   the globe's code is a separate chunk loaded on demand; if it cannot start (no WebGL, the chunk missing, a throw)
   the 2D map takes the same props and the same place, so the picture never disappears. */

const ThreatGlobe = lazy(() => import('./ThreatGlobe').then((m) => ({ default: m.ThreatGlobe })))

class Guard extends Component<{ fallback: (why: string) => ReactNode; children: ReactNode }, { why?: string }> {
  state: { why?: string } = {}
  static getDerivedStateFromError(e: unknown) { return { why: e instanceof Error ? e.message : String(e) } }
  render() { return this.state.why ? this.props.fallback(this.state.why) : this.props.children }
}

export type GlobeFrameProps = WorldMapProps & { live?: LiveArc[]; view?: 'world' | 'india'; onImagery?: (i: ImageryInfo) => void; overlay?: ReactNode }

export function GlobeFrame(props: GlobeFrameProps) {
  const [fallback, setFallback] = useState<string>()
  const { live, view, onImagery, overlay, ...world } = props
  const flat = <WorldMap {...world} />
  if (fallback) return flat
  return (
    <Guard fallback={(why) => { queueMicrotask(() => setFallback(why)); return flat }}>
      <Suspense fallback={<div className="flex h-full items-center justify-center bg-black text-[13px] text-white/60">Loading the satellite view…</div>}>
        <ThreatGlobe origins={world.origins} targets={world.targets} routes={world.routes} live={live ?? []} focus={world.focus} showAll={world.showAll}
                     view={view ?? 'world'} paused={world.paused} onFocus={world.onFocus} onPick={world.onPick}
                     onImagery={onImagery ?? (() => undefined)} onFail={setFallback} />
      </Suspense>
      {world.topLeft && <div className="absolute left-3 top-3 z-10 flex flex-wrap items-center gap-2">{world.topLeft}</div>}
      {overlay}
    </Guard>
  )
}

/** One quiet line saying which imagery is on screen (never the token itself). */
export function imageryLine(i: ImageryInfo | undefined): { text: string; dot: string } {
  if (!i) return { text: 'Imagery: starting', dot: 'animate-pulse bg-accent' }
  const dot = i.status === 'ok' ? 'bg-ok' : i.status === 'loading' ? 'animate-pulse bg-accent' : i.status === 'offline' ? 'bg-high' : 'bg-crit'
  const text = i.status === 'loading' ? `Loading ${i.name}…` : i.status === 'ok' ? `${i.name} · ${i.detail ?? ''}`
    : i.status === 'offline' ? `${i.name}${i.detail ? ` · ${i.detail}` : ''}` : i.detail ?? i.name
  return { text: `Imagery: ${text}`, dot }
}
