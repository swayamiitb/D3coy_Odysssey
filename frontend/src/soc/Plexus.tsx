import { useEffect, useRef } from 'react'

/* The motion behind the figure strips (ui-09), after the team's second reference clip: a plexus, white nodes drifting
   slowly in depth with thin lines joining the ones near each other, on black. Canvas, 30 frames a second while on
   screen, one still frame under reduced motion. Low contrast on purpose: the numbers in front stay the subject. */

interface Node { x: number; y: number; z: number; vx: number; vy: number; tw: number }

export function Plexus({ className = '' }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const cv = ref.current!
    const ctx = cv.getContext('2d')!
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let nodes: Node[] = []
    let W = 0, H = 0, dpr = 1, raf = 0, visible = true, last = 0
    const build = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1)
      const box = cv.parentElement!
      W = box.clientWidth
      H = box.clientHeight
      cv.width = Math.round(W * dpr)
      cv.height = Math.round(H * dpr)
      cv.style.width = `${W}px`
      cv.style.height = `${H}px`
      const n = Math.min(150, Math.max(30, Math.round((W * H) / 5200)))
      nodes = Array.from({ length: n }, () => {
        const z = 0.35 + Math.random() * 0.65
        const a = Math.random() * Math.PI * 2, sp = (5 + Math.random() * 9) * z
        return { x: Math.random() * W, y: Math.random() * H, z, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp, tw: Math.random() * Math.PI * 2 }
      })
    }
    const draw = (now: number) => {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, W, H)
      const D = Math.min(200, Math.max(130, W * 0.13))
      ctx.lineWidth = 0.8
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i]
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j]
          const dx = a.x - b.x, dy = a.y - b.y
          const reach = D * ((a.z + b.z) / 2)
          const d2 = dx * dx + dy * dy
          if (d2 > reach * reach) continue
          const d = Math.sqrt(d2)
          ctx.strokeStyle = `rgba(255,255,255,${((1 - d / reach) * 0.5 * ((a.z + b.z) / 2)).toFixed(3)})`
          ctx.beginPath()
          ctx.moveTo(a.x, a.y)
          ctx.lineTo(b.x, b.y)
          ctx.stroke()
        }
      }
      for (const n of nodes) {
        const tw = 0.75 + 0.25 * Math.sin(now / 900 + n.tw)
        const r = (0.9 + 1.9 * n.z) * tw
        if (n.z > 0.7) {
          const g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 4)
          g.addColorStop(0, `rgba(255,255,255,${(0.5 * tw).toFixed(3)})`)
          g.addColorStop(1, 'rgba(255,255,255,0)')
          ctx.fillStyle = g
          ctx.beginPath()
          ctx.arc(n.x, n.y, r * 4, 0, Math.PI * 2)
          ctx.fill()
        }
        ctx.fillStyle = `rgba(255,255,255,${(0.45 + 0.5 * n.z).toFixed(3)})`
        ctx.beginPath()
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2)
        ctx.fill()
      }
    }
    const frame = (now: number) => {
      raf = requestAnimationFrame(frame)
      if (!visible || document.hidden || !W) return
      const dt = Math.min(0.1, (now - last) / 1000)
      if (now - last < 1000 / 30) return
      last = now
      for (const n of nodes) {
        n.x += n.vx * dt
        n.y += n.vy * dt
        if (n.x < -10) n.x = W + 10; else if (n.x > W + 10) n.x = -10
        if (n.y < -10) n.y = H + 10; else if (n.y > H + 10) n.y = -10
      }
      draw(now)
    }
    build()
    const ro = new ResizeObserver(() => { build(); draw(performance.now()) })
    ro.observe(cv.parentElement!)
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting })
    io.observe(cv)
    if (still) draw(0); else raf = requestAnimationFrame(frame)
    return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect() }
  }, [])
  return <canvas ref={ref} aria-hidden className={`pointer-events-none absolute inset-0 z-0 ${className}`} />
}
