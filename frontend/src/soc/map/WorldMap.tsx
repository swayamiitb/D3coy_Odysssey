import { Minus, Plus, RotateCcw } from 'lucide-react'
import { useEffect, useRef, useState, type PointerEvent as RPointerEvent, type ReactNode } from 'react'
import { countryName } from '../kit'
import { ATTACK, C2, COMP, type Origin, type Route, type Target } from './data'
import { flagImage } from './flags'
import {
  baseScale, clampView, drawBase, frameFor, homeView, INDIA_VIEW, indiaStates, indiaTransform, loadCoarse, loadFine, mercY, rad,
  toScreen, type Frame, type View, type WorldLayer,
} from './world'

/* The World view (ui-08): a real 2D map (world-atlas countries, India drawn from its official outline by state), the
   attack origins and the Indian operator states always on it, and attack paths only on intent: hover or focus an
   origin (here or in the list beside the map) and its arcs draw and keep firing; leave and they clear. Click a
   target state to fly into it; the parent then opens the 3D site view. */

const K_MAX = 9
const K_STEP = 1.8
const K_PICK = 18
const still = () => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

interface Anim { from: View; to: View; t0: number; dur: number; anchor?: { px: number; py: number; sx: number; sy: number }; done?: () => void }
interface Shot { r: Route; t0: number; dur: number }
interface Ripple { x: number; y: number; t0: number; col: string }
interface Hit { x: number; y: number; r: number; kind: 'origin' | 'target'; id: string; title: string; lines: string[] }

const ease = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2)
const rgba = (hex: string, a: number) => {
  const n = parseInt(hex.slice(1), 16)
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`
}

export interface WorldMapProps {
  origins: Origin[]
  targets: Target[]
  routes: Route[]
  focus?: string
  showAll: boolean
  onFocus: (id?: string) => void
  onPick: (state: string) => void
  paused: boolean
  topLeft?: ReactNode
}

export function WorldMap(props: WorldMapProps) {
  const { origins, targets, paused, topLeft } = props
  const wrap = useRef<HTMLDivElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const live = useRef(props)
  live.current = props
  const [tip, setTip] = useState<{ x: number; y: number; title: string; lines: string[] }>()
  const [k, setK] = useState(1)
  const [busy, setBusy] = useState(false)
  const [hoverState, setHoverState] = useState<string>()

  // the imperative side of the map: the view, its animation, drag, hits; shared by the loop and the handlers
  const st = useRef({
    view: homeView(), anim: undefined as Anim | undefined, W: 0, H: 0, prev: undefined as View | undefined,
    hits: [] as Hit[], drag: undefined as { x: number; y: number; v: View; moved: boolean; id: number } | undefined,
    hoverOrigin: undefined as string | undefined, hoverState: undefined as string | undefined, picking: false, touched: false,
  })

  const animateTo = (to: View, dur: number, anchor?: Anim['anchor'], done?: () => void) => {
    const s = st.current
    s.touched = true
    if (still() || dur <= 0) { s.view = to; s.anim = undefined; setK(to.k); done?.(); return }
    s.anim = { from: { ...s.view }, to, t0: performance.now(), dur, anchor, done }
    setK(to.k)
  }

  const zoomBy = (dir: 1 | -1) => {
    const s = st.current
    const v = s.anim?.to ?? s.view
    if (dir > 0) {
      const nk = Math.min(K_MAX, v.k * K_STEP)
      const t = 0.62
      animateTo(clampView({ k: nk, x: v.x + (INDIA_VIEW.x - v.x) * t, y: v.y + (INDIA_VIEW.y - v.y) * t }, s.W, s.H), 520)
    } else {
      const home = homeView(s.W, s.H)
      const nk = Math.max(home.k, v.k / K_STEP)
      animateTo(nk <= home.k + 0.001 ? home : clampView({ ...v, k: nk }, s.W, s.H), 520)
    }
  }
  const reset = () => animateTo(homeView(st.current.W, st.current.H), 650)

  const pick = (state: string) => {
    const s = st.current
    const t = live.current.targets.find((x) => x.state === state)
    if (!t || s.picking) return
    s.picking = true
    setBusy(true)
    setTip(undefined)
    s.prev = { ...(s.anim?.to ?? s.view) }
    const f = frameFor(s.view, s.W, s.H)
    const [sx, sy] = toScreen(f, t.at[0], t.at[1])
    animateTo({ k: Math.max(K_PICK, s.view.k * 2), x: rad(t.at[1]), y: mercY(t.at[0]) }, 760,
      { px: rad(t.at[1]), py: mercY(t.at[0]), sx, sy }, () => { live.current.onPick(state) })
  }

  // coming back from the site view: fly back out to where the analyst was
  useEffect(() => {
    const s = st.current
    if (!paused && s.picking) {
      s.picking = false
      setBusy(false)
      animateTo(s.prev ?? homeView(s.W, s.H), 680)
    }
  }, [paused])

  useEffect(() => {
    const cv = canvas.current!, box = wrap.current!
    const ctx = cv.getContext('2d')!
    const base = document.createElement('canvas')
    const bctx = base.getContext('2d')!
    const reduced = still()
    const s = st.current
    let raf = 0, visible = true, dpr = 1, baseKey = ''
    let coarse: WorldLayer | undefined, fine: WorldLayer | undefined
    const shots: Shot[] = []
    const ripples: Ripple[] = []
    let nextLaunch = 0
    loadCoarse().then((w) => { coarse = w })
    loadFine().then((w) => { fine = w })

    const size = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1)
      s.W = box.clientWidth
      s.H = box.clientHeight
      cv.width = base.width = Math.max(1, Math.round(s.W * dpr))
      cv.height = base.height = Math.max(1, Math.round(s.H * dpr))
      s.view = s.touched ? clampView(s.view, s.W, s.H) : homeView(s.W, s.H)
      setK(s.view.k)
      baseKey = ''
    }
    size()
    const ro = new ResizeObserver(size)
    ro.observe(box)
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting })
    io.observe(box)

    const curve = (a: [number, number], b: [number, number]) => {
      const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2
      const dx = b[0] - a[0], dy = b[1] - a[1], len = Math.hypot(dx, dy) || 1
      const lift = Math.min(len * 0.3, s.H * 0.34)
      return { a, b, c: [mx + (dy / len) * lift * (dx > 0 ? -1 : 1) * 0.35, my - Math.abs(dx / len) * lift] as [number, number] }
    }
    type Q = ReturnType<typeof curve>
    const at = (q: Q, t: number): [number, number] => {
      const u = 1 - t
      return [u * u * q.a[0] + 2 * u * t * q.c[0] + t * t * q.b[0], u * u * q.a[1] + 2 * u * t * q.c[1] + t * t * q.b[1]]
    }

    const label = (text: string, x: number, y: number, align: CanvasTextAlign, color: string) => {
      ctx.textAlign = align
      ctx.lineWidth = 3
      ctx.strokeStyle = 'rgba(5,5,6,0.9)'
      ctx.strokeText(text, x, y)
      ctx.fillStyle = color
      ctx.fillText(text, x, y)
    }

    const frame = (now: number) => {
      raf = requestAnimationFrame(frame)
      const p = live.current
      if (!visible || document.hidden || !s.W || (p.paused && !s.anim)) return
      const { W, H } = s

      // view animation
      if (s.anim) {
        const a = s.anim
        const t = Math.min(1, (now - a.t0) / a.dur)
        const e = ease(t)
        const kk = Math.exp(Math.log(a.from.k) + (Math.log(a.to.k) - Math.log(a.from.k)) * e)
        if (a.anchor) {
          const sc = baseScale(W, H) * kk
          const sx = a.anchor.sx + (W / 2 - a.anchor.sx) * e, sy = a.anchor.sy + (H / 2 - a.anchor.sy) * e
          s.view = { k: kk, x: a.anchor.px - (sx - W / 2) / sc, y: a.anchor.py + (sy - H / 2) / sc }
        } else {
          s.view = { k: kk, x: a.from.x + (a.to.x - a.from.x) * e, y: a.from.y + (a.to.y - a.from.y) * e }
        }
        if (t >= 1) { s.view = a.to; s.anim = undefined; a.done?.() }
      }
      const v = s.view
      const f: Frame = frameFor(v, W, H)

      // base map, cached until the view changes; the detailed countries once the view is still
      const moving = !!s.anim || !!s.drag?.moved
      const layer = !moving && fine ? fine : coarse ?? fine
      const fills = new Map<string, string>()
      const maxCrit = Math.max(1, ...p.targets.map((t) => t.critical))
      for (const t of p.targets) {
        fills.set(t.state, t.compromise ? 'rgb(70,52,118)' : `rgb(${Math.round(62 + 52 * (t.critical / maxCrit))},${Math.round(36 - 4 * (t.critical / maxCrit))},${Math.round(44 + 4 * (t.critical / maxCrit))})`)
      }
      const key = `${W}x${H}@${dpr}|${v.k.toFixed(4)},${v.x.toFixed(6)},${v.y.toFixed(6)}|${layer === fine ? 'f' : 'c'}${layer ? 1 : 0}|${[...fills.values()].join()}`
      if (key !== baseKey) {
        drawBase(bctx, W, H, dpr, f, layer, fills, !moving)
        baseKey = key
      }
      ctx.setTransform(1, 0, 0, 1, 0, 0)
      ctx.drawImage(base, 0, 0)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

      // the hovered target state lifts
      if (s.hoverState) {
        const shape = indiaStates().find((x) => x.name === s.hoverState)
        if (shape) {
          const [a, e, g] = indiaTransform(f)
          ctx.setTransform(dpr * a, 0, 0, dpr * a, dpr * e, dpr * g)
          ctx.fillStyle = 'rgba(255,255,255,0.09)'
          ctx.fill(shape.path)
          ctx.strokeStyle = 'rgba(244,244,245,0.85)'
          ctx.lineWidth = 1.3 / a
          ctx.stroke(shape.path)
          ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
        }
      }

      // attack paths: only for the origin in focus, or every one with "All"
      const focus = p.focus
      const active = p.showAll ? p.routes : focus ? p.routes.filter((r) => r.o.id === focus) : []
      const qs = new Map<Route, Q>()
      for (const r of active) qs.set(r, curve(toScreen(f, r.o.at[0], r.o.at[1]), toScreen(f, r.t.at[0], r.t.at[1])))
      for (const [r, q] of qs) {
        const col = r.o.kind === 'attack' ? ATTACK : C2
        const on = focus ? r.o.id === focus : true
        const gr = ctx.createLinearGradient(q.a[0], q.a[1], q.b[0], q.b[1])
        gr.addColorStop(0, rgba(col, on ? 0.12 : 0.05))
        gr.addColorStop(1, rgba(col, on ? (focus ? 0.95 : 0.5) : 0.12))
        ctx.strokeStyle = gr
        ctx.lineWidth = focus && on ? 1.6 : 1.1
        ctx.beginPath()
        ctx.moveTo(q.a[0], q.a[1])
        ctx.quadraticCurveTo(q.c[0], q.c[1], q.b[0], q.b[1])
        ctx.stroke()
      }

      // projectiles keep firing along the active paths, at random moments and speeds
      for (let i = shots.length - 1; i >= 0; i--) if (!qs.has(shots[i].r)) shots.splice(i, 1)
      if (!reduced && active.length) {
        if (now >= nextLaunch && shots.length < 14) {
          shots.push({ r: active[Math.floor(Math.random() * active.length)], t0: now, dur: 1100 + Math.random() * 1700 })
          nextLaunch = now + (focus ? 120 + Math.random() * 520 : 200 + Math.random() * 760)
        }
        for (let i = shots.length - 1; i >= 0; i--) {
          const sh = shots[i], q = qs.get(sh.r)!
          const t = (now - sh.t0) / sh.dur
          const col = sh.r.o.kind === 'attack' ? ATTACK : C2
          if (t >= 1) {
            ripples.push({ x: q.b[0], y: q.b[1], t0: now, col })
            shots.splice(i, 1)
            continue
          }
          const e = t ** 1.25
          const N = 18
          ctx.lineCap = 'round'
          for (let j = 0; j < N; j++) {
            const t0 = Math.max(0, e - 0.16 * (j / N)), t1 = Math.max(0, e - 0.16 * ((j + 1) / N))
            if (t0 === t1) break
            const p0 = at(q, t0), p1 = at(q, t1)
            ctx.strokeStyle = rgba(col, 0.95 * (1 - j / N))
            ctx.lineWidth = 2.4 * (1 - j / N) + 0.4
            ctx.beginPath()
            ctx.moveTo(p0[0], p0[1])
            ctx.lineTo(p1[0], p1[1])
            ctx.stroke()
          }
          const h = at(q, e)
          const glow = ctx.createRadialGradient(h[0], h[1], 0, h[0], h[1], 8)
          glow.addColorStop(0, rgba(col, 0.55))
          glow.addColorStop(1, rgba(col, 0))
          ctx.fillStyle = glow
          ctx.beginPath()
          ctx.arc(h[0], h[1], 8, 0, Math.PI * 2)
          ctx.fill()
          ctx.fillStyle = '#ffffff'
          ctx.beginPath()
          ctx.arc(h[0], h[1], 1.9, 0, Math.PI * 2)
          ctx.fill()
        }
      }
      for (let i = ripples.length - 1; i >= 0; i--) {
        const rp = ripples[i]
        const t = (now - rp.t0) / 700
        if (t >= 1 || !active.length) { ripples.splice(i, 1); continue }
        ctx.strokeStyle = rgba(rp.col, 0.85 * (1 - t))
        ctx.lineWidth = 1.4
        ctx.beginPath()
        ctx.arc(rp.x, rp.y, 3 + 15 * ease(t), 0, Math.PI * 2)
        ctx.stroke()
        if (t < 0.3) {
          ctx.fillStyle = `rgba(255,255,255,${0.9 * (1 - t / 0.3)})`
          ctx.beginPath()
          ctx.arc(rp.x, rp.y, 3.2, 0, Math.PI * 2)
          ctx.fill()
        }
      }
      ctx.lineCap = 'butt'

      // targets: the Indian operator states (simulated operators)
      const hits: Hit[] = []
      const routeTargets = new Set(active.map((r) => r.t.state))
      ctx.font = '600 11px "Inter Variable", "Segoe UI", system-ui, sans-serif'
      ctx.textBaseline = 'middle'
      for (const t of p.targets) {
        const [x, y] = toScreen(f, t.at[0], t.at[1])
        const dim = focus && !routeTargets.has(t.state)
        const r = 2.4 + 2.6 * Math.sqrt(t.critical / maxCrit)
        ctx.globalAlpha = dim ? 0.45 : 1
        if (t.compromise) {
          const ph = reduced ? 0.4 : ((now / 1900) % 1)
          ctx.strokeStyle = rgba(COMP, 0.7 * (1 - ph))
          ctx.lineWidth = 1.3
          ctx.beginPath()
          ctx.arc(x, y, r + 3 + 9 * ph, 0, Math.PI * 2)
          ctx.stroke()
        }
        ctx.fillStyle = t.compromise ? COMP : '#ffffff'
        ctx.beginPath()
        ctx.arc(x, y, t.compromise ? r + 0.8 : r, 0, Math.PI * 2)
        ctx.fill()
        if (s.hoverState === t.state || routeTargets.has(t.state)) {
          ctx.strokeStyle = 'rgba(255,255,255,0.9)'
          ctx.lineWidth = 1.2
          ctx.beginPath()
          ctx.arc(x, y, r + 4, 0, Math.PI * 2)
          ctx.stroke()
        }
        if (v.k >= 2.6 || s.hoverState === t.state || (focus && routeTargets.has(t.state))) {
          label(t.state, x + r + 6, y, 'left', 'rgba(244,244,245,0.95)')
        }
        ctx.globalAlpha = 1
        const ops = t.orgs.map((o) => `${o.name} · ${o.sector}`)
        hits.push({ x, y, r: Math.max(11, r + 6), kind: 'target', id: t.state, title: t.state,
                    lines: [...ops, `${t.critical} Critical warnings${t.compromise ? ' · suspected compromise' : ''} · operators simulated (SIM)`,
                            t.gov.length ? `Click for the 3D site view of ${t.gov.length} government agenc${t.gov.length > 1 ? 'ies' : 'y'}` : 'Click for the site view (no government agency here)'] })
      }

      // origins: attack sources pulse; botnet C2s are rings
      p.origins.forEach((o, i) => {
        const [x, y] = toScreen(f, o.at[0], o.at[1])
        if (x < -40 || y < -40 || x > W + 40 || y > H + 40) return
        const on = focus === o.id
        const col = o.kind === 'attack' ? ATTACK : C2
        ctx.globalAlpha = focus && !on ? 0.35 : 1
        const ph = reduced ? 0.35 : (((now + i * 530) / (o.kind === 'attack' ? 2200 : 3000)) % 1)
        ctx.strokeStyle = rgba(col, 0.6 * (1 - ph))
        ctx.lineWidth = 1.2
        ctx.beginPath()
        ctx.arc(x, y, 4 + (on ? 14 : 10) * ph, 0, Math.PI * 2)
        ctx.stroke()
        if (o.kind === 'attack') {
          ctx.fillStyle = col
          ctx.beginPath()
          ctx.arc(x, y, on ? 5 : 4, 0, Math.PI * 2)
          ctx.fill()
        } else {
          ctx.strokeStyle = col
          ctx.lineWidth = 1.8
          ctx.beginPath()
          ctx.arc(x, y, on ? 5 : 4, 0, Math.PI * 2)
          ctx.stroke()
          ctx.fillStyle = col
          ctx.beginPath()
          ctx.arc(x, y, 1.3, 0, Math.PI * 2)
          ctx.fill()
        }
        // flag + code beside the marker (a C2 sharing a country with an attack source keeps its label on the left)
        const left = o.kind === 'c2'
        const twin = left && p.origins.some((a) => a.kind === 'attack' && a.cc === o.cc)
        const img = flagImage(o.cc)
        const lx = left ? x - 11 : x + 11
        if (twin) { /* the attack source beside it carries the country's label */ } else if (img) {
          const fw = 15, fh = 10
          const fx = left ? lx - fw : lx
          ctx.fillStyle = 'rgba(5,5,6,0.9)'
          ctx.fillRect(fx - 1, y - fh / 2 - 1, fw + 2, fh + 2)
          ctx.drawImage(img, fx, y - fh / 2, fw, fh)
          label(o.cc, left ? fx - 4 : fx + fw + 4, y, left ? 'right' : 'left', 'rgba(244,244,245,0.95)')
        } else {
          label(o.cc, lx, y, left ? 'right' : 'left', 'rgba(244,244,245,0.95)')
        }
        ctx.globalAlpha = 1
        hits.push({ x, y, r: 13, kind: 'origin', id: o.id, title: `${countryName(o.cc)} · ${o.kind === 'attack' ? 'attack source' : 'botnet C2'}`,
                    lines: [o.note, o.kind === 'attack' ? `${o.records.toLocaleString('en-IN')} reports to DShield · REAL` : 'abuse.ch Feodo Tracker · REAL'] })
      })
      ctx.textAlign = 'left'
      s.hits = hits
    }
    raf = requestAnimationFrame(frame)
    return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect() }
  }, [])

  // --- pointer: hover for focus and tooltips, drag to pan, click a target state to fly in -----------------------------
  const local = (e: RPointerEvent) => {
    const r = wrap.current!.getBoundingClientRect()
    return [e.clientX - r.left, e.clientY - r.top] as const
  }
  const hitAt = (x: number, y: number): Hit | undefined => {
    const s = st.current
    let best: Hit | undefined, bd = Infinity
    for (const h of s.hits) {
      const d = Math.hypot(h.x - x, h.y - y)
      if (d < h.r && d < bd) { best = h; bd = d }
    }
    if (best) return best
    // anywhere inside a target state counts too
    const f = frameFor(s.view, s.W, s.H)
    const [a, e, g] = indiaTransform(f)
    const cv = canvas.current
    const ctx = cv?.getContext('2d')
    if (!cv || !ctx || !s.W) return undefined
    const dpr = cv.width / s.W
    const states = indiaStates()
    ctx.save()
    ctx.setTransform(dpr * a, 0, 0, dpr * a, dpr * e, dpr * g)
    try {
      for (const t of live.current.targets) {
        const shape = states.find((x) => x.name === t.state)
        if (shape && ctx.isPointInPath(shape.path, x * dpr, y * dpr)) return s.hits.find((h) => h.kind === 'target' && h.id === t.state)
      }
    } finally { ctx.restore() }
    return undefined
  }
  const setHover = (h: Hit | undefined) => {
    const s = st.current
    const o = h?.kind === 'origin' ? h.id : undefined
    if (o !== s.hoverOrigin) {
      if (o) live.current.onFocus(o)
      else if (s.hoverOrigin) live.current.onFocus(undefined)
      s.hoverOrigin = o
    }
    const ts = h?.kind === 'target' ? h.id : undefined
    if (ts !== s.hoverState) { s.hoverState = ts; setHoverState(ts) }
    setTip(h ? { x: h.x, y: h.y, title: h.title, lines: h.lines } : undefined)
  }

  const onDown = (e: RPointerEvent) => {
    if (busy || e.button !== 0) return
    const [x, y] = local(e)
    st.current.drag = { x, y, v: { ...st.current.view }, moved: false, id: e.pointerId }
  }
  const onMove = (e: RPointerEvent) => {
    const s = st.current
    const [x, y] = local(e)
    if (s.drag) {
      const dx = x - s.drag.x, dy = y - s.drag.y
      if (!s.drag.moved && Math.hypot(dx, dy) > 4) {
        s.drag.moved = true
        try { wrap.current?.setPointerCapture(s.drag.id) } catch { /* pointer already gone */ }
        setTip(undefined)
      }
      if (s.drag.moved) {
        const sc = baseScale(s.W, s.H) * s.drag.v.k
        s.anim = undefined
        s.touched = true
        s.view = clampView({ k: s.drag.v.k, x: s.drag.v.x - dx / sc, y: s.drag.v.y + dy / sc }, s.W, s.H)
        return
      }
    }
    if (!busy) setHover(hitAt(x, y))
  }
  const onUp = (e: RPointerEvent) => {
    const s = st.current
    const d = s.drag
    s.drag = undefined
    if (!d || d.moved || busy) return
    const [x, y] = local(e)
    const h = hitAt(x, y)
    if (h?.kind === 'target') pick(h.id)
    else if (h?.kind === 'origin') { s.hoverOrigin = h.id; live.current.onFocus(h.id) }
    else if (e.pointerType !== 'mouse') { s.hoverOrigin = undefined; live.current.onFocus(undefined); setTip(undefined) }
  }
  const onLeave = () => { if (!st.current.drag?.moved) setHover(undefined) }

  const summary = `World map. Attack sources (DShield, real): ${origins.filter((o) => o.kind === 'attack').map((o) => countryName(o.cc)).join(', ') || 'none'}. `
    + `Botnet C2 servers (Feodo Tracker, real): ${origins.filter((o) => o.kind === 'c2').map((o) => countryName(o.cc)).join(', ') || 'none'}. `
    + `Indian operator states (simulated): ${targets.map((t) => `${t.state} ${t.critical} Critical${t.compromise ? ', suspected compromise' : ''}`).join('; ')}.`

  const btn = 'flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-panel/90 text-text backdrop-blur transition-colors hover:bg-panel-3 disabled:cursor-default disabled:text-faint disabled:hover:bg-panel/90'
  return (
    <div className="relative h-full w-full overflow-hidden" style={{ background: '#050506' }}>
      <div ref={wrap} className={`absolute inset-0 touch-none select-none ${busy ? '' : hoverState ? 'cursor-pointer' : 'cursor-grab active:cursor-grabbing'}`}
           onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerLeave={onLeave} onPointerCancel={() => { st.current.drag = undefined }}>
        <canvas ref={canvas} className="absolute inset-0 h-full w-full" role="img" aria-label={summary} />
      </div>
      {tip && !busy && (
        <div className="pointer-events-none absolute z-20 w-[272px] rounded-xl border border-line-2 bg-panel/95 px-3 py-2.5 text-[12.5px] shadow-[0_12px_40px_rgba(0,0,0,0.55)] backdrop-blur"
             style={{ left: Math.max(8, Math.min(tip.x + 16, (wrap.current?.clientWidth ?? 0) - 282)), top: Math.max(8, Math.min(tip.y - 18, (wrap.current?.clientHeight ?? 0) - 140)) }}>
          <div className="font-semibold text-text">{tip.title}</div>
          {tip.lines.map((l, i) => <div key={i} className={`mt-0.5 ${i === tip.lines.length - 1 ? 'text-text' : 'text-mute'}`}>{l}</div>)}
        </div>
      )}

      {topLeft && <div className="absolute left-3 top-3 z-10 flex flex-wrap items-center gap-2">{topLeft}</div>}
      <div className="absolute right-3 top-3 z-10 flex flex-col gap-1.5">
        <button className={btn} onClick={() => zoomBy(1)} disabled={busy || k >= K_MAX - 0.01} aria-label="Zoom in towards India"><Plus size={16} /></button>
        <button className={btn} onClick={() => zoomBy(-1)} disabled={busy || k <= homeView(st.current.W, st.current.H).k + 0.001} aria-label="Zoom out"><Minus size={16} /></button>
        <button className={btn} onClick={reset} disabled={busy} aria-label="Reset the view to the whole world"><RotateCcw size={14} /></button>
      </div>

      <div className="pointer-events-none absolute bottom-3 left-4 right-4 z-10 flex flex-wrap items-end justify-between gap-x-4 gap-y-1.5 text-[12px] text-mute">
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: ATTACK }} />Attack source (DShield, REAL)</span>
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ boxShadow: `inset 0 0 0 1.5px ${C2}` }} />Botnet C2 (Feodo, REAL)</span>
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-white" />Operator state (SIM)</span>
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: COMP }} />Suspected compromise</span>
        </div>
        <span className="hidden rounded-full border border-line bg-panel/85 px-2.5 py-1 text-[11.5px] text-mute backdrop-blur sm:inline">
          Hover an origin for its attack paths · click a target state for the 3D site view
        </span>
      </div>

      {/* keyboard route into the site view: invisible until focused */}
      <div className="absolute bottom-12 right-3 z-20 flex flex-col items-end gap-1">
        {targets.map((t) => (
          <button key={t.state} onClick={() => pick(t.state)} disabled={busy}
                  className="sr-only rounded-lg border border-line-2 bg-panel px-3 py-1.5 text-[12.5px] text-text focus:not-sr-only">
            Open the 3D site view of {t.state}
          </button>
        ))}
      </div>
    </div>
  )
}
