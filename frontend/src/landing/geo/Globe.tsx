import createGlobe, { type COBEOptions } from 'cobe'
import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'

/** Called on every animation frame with the time in ms; returns what changed (camera, markers, arcs, colours),
 *  or null when nothing needs drawing (for example while another layer covers the globe). */
export type GlobeFrame = (ms: number) => Partial<COBEOptions> | null

const BASE: Omit<COBEOptions, 'width' | 'height' | 'devicePixelRatio'> = {
  // The sphere separates from the black ground by a tone step, not a glow: in dark mode the ocean renders at about
  // baseColor x 0.1 (a #1f1f1f disc), land dots are near white, and the glow is black, so it adds nothing.
  phi: 0, theta: 0.25, dark: 1, diffuse: 1.6, mapSamples: 20000, mapBrightness: 7, mapBaseBrightness: 0.03,
  baseColor: [1.2, 1.2, 1.2], markerColor: [1, 0.62, 0.04], glowColor: [0, 0, 0],
  markers: [], arcs: [], arcColor: [1, 0.27, 0.23], arcWidth: 1.3, arcHeight: 0.45, markerElevation: 0.015,
}

export function hasWebGL(): boolean {
  try {
    const c = document.createElement('canvas')
    return !!(c.getContext('webgl2') || c.getContext('webgl'))
  } catch { return false }
}

/** A cobe globe sized to its box. The canvas is created outside React because cobe re-parents it into its own
 *  wrapper (which also holds the CSS anchors that labels position against), so React must never own that node.
 *  Children render on top, in the same box, and can anchor to `--cobe-<id>` / `--cobe-arc-<id>`. */
export function Globe({ frame, children, fallback, label, still = false, onFail }: {
  frame: RefObject<GlobeFrame>; children?: ReactNode; fallback?: ReactNode; label: string
  /** Draw a few frames (long enough for cobe's land texture to decode), then stop: the reduced-motion pose. */
  still?: boolean
  /** Told when the globe can't draw (no context, creation failed, context lost), so the page can change course. */
  onFail?: () => void
}) {
  const host = useRef<HTMLDivElement>(null)
  const [ok, setOk] = useState(hasWebGL)
  const failRef = useRef(onFail)
  useEffect(() => { failRef.current = onFail })
  useEffect(() => { if (!ok) failRef.current?.() }, [ok])

  useEffect(() => {
    const el = host.current
    if (!el || !ok) return
    const canvas = document.createElement('canvas')
    canvas.className = 'globe-canvas' // fades in once, so the empty sphere and the late land texture never pop
    canvas.style.cssText = 'width:100%;height:100%;display:block;contain:layout paint size'
    canvas.setAttribute('aria-hidden', 'true')
    el.append(canvas)
    // A lost GPU context (driver reset, sleep) would leave a blank globe: show the fallback instead.
    const lost = (e: Event) => { e.preventDefault(); setOk(false) }
    canvas.addEventListener('webglcontextlost', lost)
    const box = () => {
      const r = el.getBoundingClientRect()
      return { width: Math.max(1, Math.round(r.width)), height: Math.max(1, Math.round(r.height)) }
    }
    // A large canvas at DPR 2 is ~3.6 MP of shader per frame; 1.5 above 800 CSS px keeps it inside the frame budget.
    const dpr = Math.min(window.devicePixelRatio || 1, el.clientWidth > 800 ? 1.5 : 2)
    let globe: ReturnType<typeof createGlobe>
    try {
      globe = createGlobe(canvas, { ...BASE, ...box(), devicePixelRatio: dpr, ...(frame.current?.(performance.now()) ?? {}) })
    } catch (e) {
      console.error('globe', e)
      canvas.remove()
      setOk(false)
      return
    }

    let raf = 0
    let visible = true
    let frames = 0
    const loop = (ms: number) => {
      if (!still || ++frames < 30) raf = requestAnimationFrame(loop) // schedule first: one bad frame can't stop it
      if (!visible) return
      try {
        const next = frame.current?.(ms)
        if (next) globe.update(next)
      } catch (e) { console.error('globe frame', e) }
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
      canvas.removeEventListener('webglcontextlost', lost)
      globe.destroy()
      // cobe frees its buffers but not the context; release it so returning to the page doesn't stack contexts.
      ;(canvas.getContext('webgl2') ?? canvas.getContext('webgl'))?.getExtension('WEBGL_lose_context')?.loseContext()
      canvas.parentElement?.remove() // cobe's wrapper div, with the canvas and anchors inside
    }
  }, [frame, ok, still])

  if (!ok) return <>{fallback}</>
  return (
    <div className="relative size-full" role="img" aria-label={label}>
      <div ref={host} className="absolute inset-0" />
      <div aria-hidden>{children}</div>
    </div>
  )
}
