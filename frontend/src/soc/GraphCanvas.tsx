import { useEffect, useRef, type MutableRefObject } from 'react'
import type { GraphEdge, GraphNode } from '../api'

/* The intelligence graph's drawing (ui-13): a true circle on a canvas, so a hundred nodes and four hundred edges
   animate at 60 frames a second with no React work per frame. Rings from the centre: organisations, technologies,
   vulnerabilities, campaigns and techniques, then the outer ring. Nodes sit on their ring at the angle the record
   gives them. Hover lights a node and everything it touches, labels every neighbour and dims the rest; the halos of
   fresh evidence breathe; the latest evidence runs along its edges as moving light. The drawing fits its box, so it
   is a circle at every width; drag to pan and wheel to zoom when it gets dense. */

export interface Layout { pos: Record<string, { x: number; y: number; r: number; ring: number }>; rings: { r: number; label: string }[] }
export interface GraphView {
  nodes: GraphNode[]; edges: GraphEdge[]; layout: Layout
  hover?: string; kindSel?: string; fresh: Set<string>; focusLabel: string; centre: string
}
export interface Hit { id: string; x: number; y: number; r: number }

const TIER: Record<string, string> = { Compromise: '#8a63e8', Critical: '#e5383b', High: '#ff7a3d', Medium: '#f5c242' }
const TIER_LIGHT: Record<string, string> = { Compromise: '#7356bf', Critical: '#e11900', High: '#ff6937', Medium: '#f5b800' }

/** Draw the graph each frame. Coordinates are unit-circle based: the layout is in [-1, 1], scaled to the box. */
export function GraphCanvas({ view, onHover, onPick, dark }: {
  view: MutableRefObject<GraphView>; onHover: (id?: string) => void; onPick: (id: string) => void; dark: boolean
}) {
  const box = useRef<HTMLDivElement>(null)
  const cv = useRef<HTMLCanvasElement>(null)
  const hits = useRef<Hit[]>([])
  const cam = useRef({ k: 1, x: 0, y: 0 })
  const darkRef = useRef(dark)
  darkRef.current = dark

  useEffect(() => {
    const el = cv.current!, host = box.current!
    const ctx = el.getContext('2d')!
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let W = 0, H = 0, dpr = 1, raf = 0, visible = true, last = 0
    const size = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1)
      W = host.clientWidth
      H = host.clientHeight
      el.width = Math.round(W * dpr)
      el.height = Math.round(H * dpr)
      el.style.width = `${W}px`
      el.style.height = `${H}px`
    }
    size()
    const ro = new ResizeObserver(size)
    ro.observe(host)
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting })
    io.observe(host)

    const frame = (now: number) => {
      raf = requestAnimationFrame(frame)
      if (!visible || document.hidden || !W || !H) return
      if (now - last < 1000 / 60) return
      last = now
      const v = view.current
      const { pos, rings } = v.layout
      const isDark = darkRef.current
      const c = cam.current
      const R = Math.min(W, H) * 0.47 * c.k
      const cx = W / 2 + c.x, cy = H / 2 + c.y
      const P = (p: { x: number; y: number }) => [cx + p.x * R, cy + p.y * R] as [number, number]
      const ink = isDark ? '244,244,245' : '0,0,0'
      const line = isDark ? '255,255,255' : '0,0,0'
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, W, H)

      // rings and their names
      ctx.lineWidth = 1
      ctx.font = `600 ${Math.max(9, Math.min(11, R / 34))}px "Inter Variable", "Segoe UI", system-ui, sans-serif`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      for (const rg of rings) {
        ctx.strokeStyle = `rgba(${line},${isDark ? 0.09 : 0.07})`
        ctx.beginPath()
        ctx.arc(cx, cy, rg.r * R, 0, Math.PI * 2)
        ctx.stroke()
        // the name sits on the ring at eleven o'clock, in a small plate, clear of the node field
        const ang = -Math.PI * 0.72
        const lx = cx + rg.r * R * Math.cos(ang), ly = cy + rg.r * R * Math.sin(ang)
        const w = ctx.measureText(rg.label).width + 14
        ctx.fillStyle = isDark ? '#141416' : '#ececec'
        ctx.beginPath()
        ctx.roundRect(lx - w / 2, ly - 8, w, 16, 8)
        ctx.fill()
        ctx.fillStyle = `rgba(${ink},0.6)`
        ctx.fillText(rg.label, lx, ly)
      }

      const hover = v.hover
      const linked = new Set<string>()
      if (hover) for (const e of v.edges) if (e.from === hover || e.to === hover) { linked.add(e.from); linked.add(e.to) }
      const byId = new Map(v.nodes.map((n) => [n.id, n]))
      const alphaOf = (n: GraphNode) => (hover ? (n.id === hover || linked.has(n.id) ? 1 : 0.14) : v.kindSel ? (n.kind === v.kindSel ? 1 : 0.12) : 1)

      // edges: a quadratic bow towards the centre; dashes by provenance; the hovered node's edges lit
      for (const e of v.edges) {
        const a = pos[e.from], b = pos[e.to]
        if (!a || !b) continue
        const on = hover ? e.from === hover || e.to === hover : false
        const off = hover ? !on : v.kindSel ? byId.get(e.from)?.kind !== v.kindSel && byId.get(e.to)?.kind !== v.kindSel : false
        const [ax, ay] = P(a), [bx, by] = P(b)
        const mx = (ax + bx) / 2, my = (ay + by) / 2
        const qx = mx + (cx - mx) * 0.22, qy = my + (cy - my) * 0.22
        const base = e.kind === 'runs' || e.kind === 'owns' ? 0.07 : 0.16
        ctx.strokeStyle = on ? (isDark ? '#f4f4f5' : '#000000') : `rgba(${line},${off ? 0.025 : base})`
        ctx.lineWidth = (0.6 + Math.min(3, e.weight) * 0.3 + (on ? 0.8 : 0)) * Math.min(1.4, R / 330)
        ctx.setLineDash(e.provenance === 'SIM' ? [3, 3] : e.provenance === 'REAL · SIM' ? [6, 3] : [])
        ctx.globalAlpha = on ? 0.95 : 1
        ctx.beginPath()
        ctx.moveTo(ax, ay)
        ctx.quadraticCurveTo(qx, qy, bx, by)
        ctx.stroke()
      }
      ctx.setLineDash([])
      ctx.globalAlpha = 1

      // moving light along the freshest edges: evidence travelling through the record
      if (!reduced) {
        const t = (now / 2600) % 1
        let k = 0
        for (const e of v.edges) {
          const na = byId.get(e.from), nb = byId.get(e.to)
          if (!na || !nb) continue
          const pulse = Math.max(na.pulse, nb.pulse)
          if (pulse < 0.6) continue
          if (hover && !(e.from === hover || e.to === hover)) continue
          k++
          if (k > 60) break
          const a = pos[e.from], b = pos[e.to]
          const [ax, ay] = P(a), [bx, by] = P(b)
          const mx = (ax + bx) / 2, my = (ay + by) / 2
          const qx = mx + (cx - mx) * 0.22, qy = my + (cy - my) * 0.22
          const tt = (t + k * 0.137) % 1
          const u = 1 - tt
          const x = u * u * ax + 2 * u * tt * qx + tt * tt * bx, y = u * u * ay + 2 * u * tt * qy + tt * tt * by
          const col = TIER[nb.tier ?? ''] ?? TIER[na.tier ?? ''] ?? (isDark ? '#f4f4f5' : '#000000')
          ctx.fillStyle = col
          ctx.globalAlpha = 0.9 * pulse
          ctx.beginPath()
          ctx.arc(x, y, 1.8 * Math.min(1.4, R / 330), 0, Math.PI * 2)
          ctx.fill()
        }
        ctx.globalAlpha = 1
      }

      // halos: fresh evidence breathes, faster the fresher; a new node pings once
      for (const n of v.nodes) {
        const p = pos[n.id]
        if (!p) continue
        const a = alphaOf(n)
        const [x, y] = P(p)
        const r = p.r * Math.min(1.4, R / 330)
        if (n.pulse >= 0.05 && a > 0.5) {
          const period = 1600 + 3400 * (1 - n.pulse)
          const ph = reduced ? 0.5 : (now % period) / period
          const s = 1 + 0.9 * Math.sin(ph * Math.PI)
          ctx.fillStyle = (isDark ? TIER : TIER_LIGHT)[n.tier ?? ''] ?? `rgba(${ink},0.6)`
          ctx.globalAlpha = 0.22 * n.pulse * (1 - 0.5 * Math.sin(ph * Math.PI)) * a
          ctx.beginPath()
          ctx.arc(x, y, (r + 3) * s, 0, Math.PI * 2)
          ctx.fill()
        }
        if (v.fresh.has(n.id) && !reduced) {
          const ph = ((now / 1200) % 1)
          ctx.strokeStyle = isDark ? '#f4f4f5' : '#000000'
          ctx.globalAlpha = (1 - ph) * a
          ctx.lineWidth = 1.5
          ctx.beginPath()
          ctx.arc(x, y, (r + 2) * (1 + 2.2 * ph), 0, Math.PI * 2)
          ctx.stroke()
        }
      }
      ctx.globalAlpha = 1

      // nodes: fill by worst open tier, shape by kind (diamond = threat group, triangle = live signal)
      const hitList: Hit[] = []
      const shape = (n: GraphNode, x: number, y: number, r: number) => {
        ctx.beginPath()
        if (n.kind === 'actor') { ctx.moveTo(x, y - r * 1.3); ctx.lineTo(x + r * 1.3, y); ctx.lineTo(x, y + r * 1.3); ctx.lineTo(x - r * 1.3, y); ctx.closePath() }
        else if (n.kind === 'signal') { ctx.moveTo(x, y - r * 1.3); ctx.lineTo(x + r * 1.2, y + r * 0.9); ctx.lineTo(x - r * 1.2, y + r * 0.9); ctx.closePath() }
        else ctx.arc(x, y, r, 0, Math.PI * 2)
      }
      for (const n of v.nodes) {
        const p = pos[n.id]
        if (!p) continue
        const [x, y] = P(p)
        const r = p.r * Math.min(1.4, R / 330)
        const a = alphaOf(n)
        const fill = n.tier ? (isDark ? TIER : TIER_LIGHT)[n.tier] : (isDark ? '#0e0e10' : '#ffffff')
        ctx.globalAlpha = a
        shape(n, x, y, hover === n.id ? r + 1.5 : r)
        ctx.fillStyle = fill
        ctx.fill()
        ctx.lineWidth = n.tier ? 1.5 : 1.3
        ctx.strokeStyle = n.tier ? (isDark ? '#0e0e10' : '#ffffff') : (isDark ? '#f4f4f5' : '#000000')
        ctx.stroke()
        hitList.push({ id: n.id, x, y, r: Math.max(9, r + 4) })
      }
      ctx.globalAlpha = 1
      hits.current = hitList

      // the hovered node's ring, and the name of every node it touches
      if (hover) {
        const h = byId.get(hover), hp = hover ? pos[hover] : undefined
        if (h && hp) {
          const [x, y] = P(hp)
          ctx.strokeStyle = isDark ? '#f4f4f5' : '#000000'
          ctx.lineWidth = 1.6
          ctx.beginPath()
          ctx.arc(x, y, hp.r * Math.min(1.4, R / 330) + 5, 0, Math.PI * 2)
          ctx.stroke()
          ctx.font = `500 ${Math.max(10, Math.min(11.5, R / 32))}px "Inter Variable", "Segoe UI", system-ui, sans-serif`
          ctx.textBaseline = 'middle'
          const placed: { x1: number; x2: number; y1: number; y2: number }[] = []
          const label = (n: GraphNode, bold = false) => {
            const q = pos[n.id]
            if (!q) return
            const [nx, ny] = P(q)
            const text = n.label.length > 34 ? n.label.slice(0, 33) + '…' : n.label
            if (bold) ctx.font = `700 ${Math.max(11, Math.min(13, R / 28))}px "Inter Variable", "Segoe UI", system-ui, sans-serif`
            const w = ctx.measureText(text).width + 10
            const right = nx >= cx
            let lx = right ? nx + q.r + 7 : nx - q.r - 7 - w, ly = ny
            // slide down until the label is clear of the ones already placed
            for (let i = 0; i < 12 && placed.some((b) => lx < b.x2 && lx + w > b.x1 && ly - 8 < b.y2 && ly + 8 > b.y1); i++) ly += 14
            placed.push({ x1: lx, x2: lx + w, y1: ly - 8, y2: ly + 8 })
            ctx.fillStyle = isDark ? 'rgba(14,14,16,0.92)' : 'rgba(255,255,255,0.92)'
            ctx.fillRect(lx, ly - 8, w, 16)
            ctx.fillStyle = bold ? (isDark ? '#f4f4f5' : '#000000') : `rgba(${ink},0.85)`
            ctx.textAlign = 'left'
            ctx.fillText(text, lx + 5, ly)
            if (bold) ctx.font = `500 ${Math.max(10, Math.min(11.5, R / 32))}px "Inter Variable", "Segoe UI", system-ui, sans-serif`
          }
          label(h, true)
          const neigh = [...linked].filter((id) => id !== hover).map((id) => byId.get(id)!).filter(Boolean).sort((a, b) => (b.risk ?? 0) - (a.risk ?? 0)).slice(0, 28)
          for (const n of neigh) label(n)
        }
      } else {
        // at rest: the organisations and the technologies are named; everything else names itself on hover
        ctx.font = `500 ${Math.max(9.5, Math.min(11, R / 34))}px "Inter Variable", "Segoe UI", system-ui, sans-serif`
        ctx.textBaseline = 'middle'
        const placed: { x1: number; x2: number; y1: number; y2: number }[] = []
        const named = v.nodes.filter((n) => n.kind === 'org' || n.kind === 'product' || n.tier === 'Compromise' || (n.pulse >= 0.9 && n.kind !== 'cve'))
          .sort((a, b) => (a.kind === 'org' ? 0 : 1) - (b.kind === 'org' ? 0 : 1) || (b.risk ?? 0) - (a.risk ?? 0))
        for (const n of named) {
          const q = pos[n.id]
          if (!q) continue
          const a = alphaOf(n)
          if (a < 0.5) continue
          const [nx, ny] = P(q)
          const text = (n.kind === 'product' ? n.label.replace(/\s*\([^)]*\)\s*$/, '') : n.label)
          const t = text.length > 26 ? text.slice(0, 25) + '…' : text
          ctx.font = `${n.kind === 'org' ? 600 : 500} ${Math.max(9.5, Math.min(11, R / 34))}px "Inter Variable", "Segoe UI", system-ui, sans-serif`
          const w = ctx.measureText(t).width + 8
          const right = nx >= cx
          const lx = right ? nx + q.r + 6 : nx - q.r - 6 - w
          const bx = { x1: lx, x2: lx + w, y1: ny - 7, y2: ny + 7 }
          if (bx.x1 < 2 || bx.x2 > W - 2 || placed.some((b) => bx.x1 < b.x2 && bx.x2 > b.x1 && bx.y1 < b.y2 && bx.y2 > b.y1)) continue
          placed.push(bx)
          ctx.fillStyle = isDark ? 'rgba(14,14,16,0.85)' : 'rgba(246,246,246,0.85)'
          ctx.fillRect(lx, ny - 7, w, 14)
          ctx.fillStyle = `rgba(${ink},${n.kind === 'org' ? 0.95 : 0.75})`
          ctx.textAlign = 'left'
          ctx.fillText(t, lx + 4, ny)
        }
        // the centre
        ctx.textAlign = 'center'
        ctx.font = `700 ${Math.max(12, Math.min(15, R / 24))}px "Inter Variable", "Segoe UI", system-ui, sans-serif`
        ctx.fillStyle = `rgba(${ink},0.95)`
        ctx.fillText(v.focusLabel, cx, cy - 7)
        ctx.font = `400 ${Math.max(9.5, Math.min(11, R / 34))}px "Inter Variable", "Segoe UI", system-ui, sans-serif`
        ctx.fillStyle = `rgba(${ink},0.55)`
        ctx.fillText(v.centre, cx, cy + 9)
      }
    }
    raf = requestAnimationFrame(frame)

    // pointer: hover by nearest hit, click opens, drag pans, wheel zooms
    let drag: { x: number; y: number; cx: number; cy: number; moved: boolean } | null = null
    const at = (e: { clientX: number; clientY: number }) => { const r = el.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top] as [number, number] }
    const nearest = (x: number, y: number) => {
      let best: Hit | undefined, bd = Infinity
      for (const h of hits.current) { const d = Math.hypot(h.x - x, h.y - y); if (d < h.r && d < bd) { best = h; bd = d } }
      return best
    }
    const onMove = (e: PointerEvent) => {
      const [x, y] = at(e)
      if (drag) {
        if (Math.hypot(x - drag.x, y - drag.y) > 3) drag.moved = true
        cam.current = { ...cam.current, x: drag.cx + (x - drag.x), y: drag.cy + (y - drag.y) }
        return
      }
      const h = nearest(x, y)
      el.style.cursor = h ? 'pointer' : 'grab'
      onHover(h?.id)
    }
    const onDown = (e: PointerEvent) => { const [x, y] = at(e); drag = { x, y, cx: cam.current.x, cy: cam.current.y, moved: false }; el.setPointerCapture(e.pointerId) }
    const onUp = (e: PointerEvent) => {
      const [x, y] = at(e)
      const was = drag
      drag = null
      el.releasePointerCapture(e.pointerId)
      if (was && !was.moved) { const h = nearest(x, y); if (h) onPick(h.id) }
    }
    const onLeave = () => { if (!drag) onHover(undefined) }
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const [x, y] = at(e)
      const c = cam.current
      const k = Math.max(0.8, Math.min(3.2, c.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)))
      // zoom about the pointer
      const f = k / c.k
      cam.current = { k, x: x - W / 2 - (x - W / 2 - c.x) * f, y: y - H / 2 - (y - H / 2 - c.y) * f }
    }
    const onDbl = () => { cam.current = { k: 1, x: 0, y: 0 } }
    el.addEventListener('pointermove', onMove)
    el.addEventListener('pointerdown', onDown)
    el.addEventListener('pointerup', onUp)
    el.addEventListener('pointerleave', onLeave)
    el.addEventListener('wheel', onWheel, { passive: false })
    el.addEventListener('dblclick', onDbl)
    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      io.disconnect()
      el.removeEventListener('pointermove', onMove)
      el.removeEventListener('pointerdown', onDown)
      el.removeEventListener('pointerup', onUp)
      el.removeEventListener('pointerleave', onLeave)
      el.removeEventListener('wheel', onWheel)
      el.removeEventListener('dblclick', onDbl)
    }
  }, [view, onHover, onPick])

  return (
    <div ref={box} className="relative h-full w-full">
      <canvas ref={cv} className="absolute inset-0 touch-none" aria-hidden />
    </div>
  )
}

/** Unit-circle layout from the record's ring and angle: ring radii leave room for the inner labels; the focus organisation sits at the centre. */
export function circleLayout(nodes: GraphNode[], rings: number, kindLabel: Record<string, string>): Layout {
  const RADII: Record<number, number[]> = { 5: [0.36, 0.56, 0.74, 0.88, 1], 6: [0.3, 0.48, 0.64, 0.78, 0.9, 1] }
  const table = RADII[rings] ?? Array.from({ length: rings }, (_, i) => (i + 1) / rings)
  const pos: Layout['pos'] = {}
  const ringsOf: Record<number, { r: number; kinds: string[] }> = {}
  for (const n of nodes) {
    const rr = n.r <= 0 ? 0 : table[n.ring] ?? 1
    pos[n.id] = { x: rr * Math.cos(n.angle), y: rr * Math.sin(n.angle), r: 4 + (n.risk ?? 0) / 22, ring: n.ring }
    if (rr > 0) {
      const e = (ringsOf[n.ring] ??= { r: rr, kinds: [] })
      if (!e.kinds.includes(n.kind)) e.kinds.push(n.kind)
    }
  }
  const ringList = Object.values(ringsOf).map((e) => ({ r: e.r, label: e.kinds.map((k) => (kindLabel[k] ?? k).toUpperCase()).join(' · ') })).sort((a, b) => a.r - b.r)
  return { pos, rings: ringList }
}
