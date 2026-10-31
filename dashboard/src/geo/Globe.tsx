import createGlobe, { type COBEOptions } from 'cobe'
import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'

/** Called on every animation frame with the time in ms; returns what changed (camera, markers, arcs, colours). */
export type GlobeFrame = (ms: number) => Partial<COBEOptions>

const BASE: Omit<COBEOptions, 'width' | 'height' | 'devicePixelRatio'> = {
  phi: 0, theta: 0.25, dark: 1, diffuse: 1.15, mapSamples: 20000, mapBrightness: 5, mapBaseBrightness: 0.02,
  baseColor: [0.24, 0.24, 0.26], markerColor: [1, 0.62, 0.04], glowColor: [0.13, 0.13, 0.15],
  markers: [], arcs: [], arcColor: [1, 0.27, 0.23], arcWidth: 0.9, arcHeight: 0.32, markerElevation: 0.015,
}

function hasWebGL(): boolean {
  try {
    const c = document.createElement('canvas')
    return !!(c.getContext('webgl2') || c.getContext('webgl'))
  } catch { return false }
}

/** A cobe globe sized to its box. The canvas is created outside React because cobe re-parents it into its own
 *  wrapper (which also holds the CSS anchors that labels position against), so React must never own that node.
 *  Children render on top, in the same box, and can anchor to `--cobe-<id>` / `--cobe-arc-<id>`. */
export function Globe({ frame, children, fallback }: { frame: RefObject<GlobeFrame>; children?: ReactNode; fallback?: ReactNode }) {
  const host = useRef<HTMLDivElement>(null)
  const [ok] = useState(hasWebGL)

  useEffect(() => {
    const el = host.current
    if (!el || !ok) return
    const canvas = document.createElement('canvas')
    canvas.style.cssText = 'width:100%;height:100%;display:block;contain:layout paint size'
    canvas.setAttribute('aria-hidden', 'true')
    el.append(canvas)
    const box = () => {
      const r = el.getBoundingClientRect()
      return { width: Math.max(1, Math.round(r.width)), height: Math.max(1, Math.round(r.height)) }
    }
    const globe = createGlobe(canvas, {
      ...BASE, ...box(), devicePixelRatio: Math.min(window.devicePixelRatio || 1, 2), ...frame.current?.(performance.now()),
    })

    let raf = 0
    let visible = true
    const loop = (ms: number) => {
      if (visible) globe.update(frame.current?.(ms) ?? {})
      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)

    const ro = new ResizeObserver(() => globe.update(box()))
    ro.observe(el)
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting })
    io.observe(el)
    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      io.disconnect()
      globe.destroy()
      canvas.parentElement?.remove() // cobe's wrapper div, with the canvas and anchors inside
    }
  }, [frame, ok])

  if (!ok) return <>{fallback}</>
  return (
    <div className="relative size-full">
      <div ref={host} className="absolute inset-0" />
      {children}
    </div>
  )
}
