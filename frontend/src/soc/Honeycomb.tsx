import { useEffect, useRef } from 'react'

/* The motion behind every page header (ui-09): a dark honeycomb, hexagons slowly rising and sinking with a little
   light on their rims, after the team's reference clip. Drawn on a canvas at a low contrast so figures and headings
   stay the subject; a hex lifts about once a second; still under reduced motion and when the tab is hidden. */

const R = 26                 // hex radius in CSS px
const SQ3 = Math.sqrt(3)
const LIFT_MS = 2600

interface Cell { x: number; y: number; base: number; t0: number; from: number; to: number }

export function Honeycomb({ className = '' }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const cv = ref.current!
    const ctx = cv.getContext('2d')!
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let cells: Cell[] = []
    let W = 0, H = 0, dpr = 1, raf = 0, visible = true, last = 0
    const seed = (x: number, y: number) => { const s = Math.sin(x * 12.9898 + y * 78.233) * 43758.5453; return s - Math.floor(s) }
    const build = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1)
      const box = cv.parentElement!
      W = box.clientWidth
      H = box.clientHeight
      cv.width = Math.round(W * dpr)
      cv.height = Math.round(H * dpr)
      cv.style.width = `${W}px`
      cv.style.height = `${H}px`
      cells = []
      const w = SQ3 * R, h = 1.5 * R
      for (let row = -1; row * h < H + R; row++) {
        for (let col = -1; col * w < W + w; col++) {
          const x = col * w + (row % 2 ? w / 2 : 0), y = row * h
          const b = 0.35 + 0.65 * seed(col, row)
          cells.push({ x, y, base: b, t0: -1e9, from: 0, to: 0 })
        }
      }
    }
    const hex = (x: number, y: number, r: number) => {
      ctx.beginPath()
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 180) * (60 * i - 90)
        const px = x + r * Math.cos(a), py = y + r * Math.sin(a)
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py)
      }
      ctx.closePath()
    }
    const draw = (now: number) => {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, W, H)
      // metallic tiles: a light from the top left, so every tile has a bright edge and a dark one, and a lifted
      // tile catches more of it (the look of the clip)
      for (const c of cells) {
        const p = Math.min(1, (now - c.t0) / LIFT_MS)
        const e = p < 0.5 ? 2 * p * p : 1 - (-2 * p + 2) ** 2 / 2
        const lift = c.from + (c.to - c.from) * e
        const r = R - 2 - lift * 1.2
        const top = 0.06 + c.base * 0.1 + lift * 0.3, bottom = 0.02 + c.base * 0.04 + lift * 0.1
        const g = ctx.createLinearGradient(c.x - r, c.y - r, c.x + r, c.y + r)
        g.addColorStop(0, `rgba(255,255,255,${top.toFixed(3)})`)
        g.addColorStop(1, `rgba(255,255,255,${bottom.toFixed(3)})`)
        hex(c.x, c.y, r)
        ctx.fillStyle = g
        ctx.fill()
        ctx.strokeStyle = `rgba(255,255,255,${(0.1 + lift * 0.45).toFixed(3)})`
        ctx.lineWidth = lift > 0.02 ? 1.4 : 1
        ctx.stroke()
      }
      // the seams between tiles
      ctx.strokeStyle = 'rgba(0,0,0,0.55)'
      ctx.lineWidth = 2
      for (const c of cells) { hex(c.x, c.y, R - 1); ctx.stroke() }
    }
    const frame = (now: number) => {
      raf = requestAnimationFrame(frame)
      if (!visible || document.hidden) return
      if (now - last < 1000 / 30) return
      last = now
      // a few tiles a second start to rise or sink
      if (Math.random() < 0.09 && cells.length) {
        const c = cells[Math.floor(Math.random() * cells.length)]
        const p = Math.min(1, (now - c.t0) / LIFT_MS)
        c.from = c.from + (c.to - c.from) * p
        c.to = c.to > 0.5 ? 0 : 0.6 + Math.random() * 0.4
        c.t0 = now
      }
      draw(now)
    }
    build()
    const ro = new ResizeObserver(() => { build(); draw(performance.now()) })
    ro.observe(cv.parentElement!)
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting })
    io.observe(cv)
    if (still) {
      for (const c of cells) if (seed(c.x, c.y) > 0.8) { c.to = 0.7; c.t0 = -1e9; c.from = 0.7 }
      draw(0)
    } else raf = requestAnimationFrame(frame)
    return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect() }
  }, [])
  return <canvas ref={ref} aria-hidden className={`pointer-events-none absolute inset-0 ${className}`} />
}
