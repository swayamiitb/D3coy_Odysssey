// The last beat's stage: the globe unrolls into a flat world map, dot by dot (the same land mask cobe draws from), and
// attacks fly from where they start to the Indian operators they reach: thin projectiles in waves of three or four,
// picked at random, each landing with one ripple. Drawn on a 2D canvas; reduced motion gets the arcs drawn once.
import { useEffect, useRef, type RefObject } from 'react'
import type { LatLng } from './geo'
import { WORLD_MASK } from './worldMask'

export interface Shot { name: string; kind: 'attack' | 'c2'; at: LatLng }
export interface FlatState { unroll: number; active: boolean }

const rad = (d: number) => (d * Math.PI) / 180
const clamp = (x: number, a = 0, b = 1) => Math.min(b, Math.max(a, x))
const smooth = (t: number) => t * t * (3 - 2 * t)
const CENTRE: LatLng = [22.7, 82.8] // the globe's pose when it starts to unroll: India facing us
// The flat map shows where the story happens: 125°W to 155°E and 50°S to 80°N (no Antarctica, little Pacific).
const FLAT = { lng: 15, halfLng: 140, lat: 15, halfLat: 65 }

/** India, roughly (lat, lng), to colour its dots. Coarse on purpose: the dots are 1.5° apart. */
const INDIA_POLY: LatLng[] = [
  [35.5, 74.5], [37.0, 77.0], [35.3, 79.8], [32.5, 79.3], [30.4, 81.1], [28.0, 84.0], [26.4, 88.0], [27.9, 88.2], [27.9, 91.6],
  [29.4, 96.0], [28.0, 97.4], [26.0, 95.0], [23.6, 94.2], [21.9, 92.6], [23.7, 91.7], [24.6, 92.2], [25.2, 89.8], [26.4, 89.7],
  [22.0, 88.9], [21.5, 87.0], [19.3, 85.0], [16.3, 82.3], [15.2, 80.3], [13.2, 80.3], [10.3, 79.8], [8.1, 77.5], [8.9, 76.6],
  [12.8, 74.8], [15.6, 73.8], [19.0, 72.8], [21.0, 72.6], [22.3, 69.0], [23.6, 68.2], [24.3, 70.5], [27.9, 70.0], [30.1, 73.4],
  [32.5, 74.6], [33.8, 74.0],
]
function inIndia([lat, lng]: LatLng): boolean {
  let inside = false
  for (let i = 0, j = INDIA_POLY.length - 1; i < INDIA_POLY.length; j = i++) {
    const [yi, xi] = INDIA_POLY[i], [yj, xj] = INDIA_POLY[j]
    if ((yi > lat) !== (yj > lat) && lng < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) inside = !inside
  }
  return inside
}

interface Dot { lat: number; lng: number; india: boolean; c: string }

/** Land dots on a 1.5° grid from the 256x128 equirectangular mask. */
async function landDots(): Promise<Dot[]> {
  const img = new Image()
  img.src = WORLD_MASK
  await img.decode()
  const cv = document.createElement('canvas')
  cv.width = img.width
  cv.height = img.height
  const cx = cv.getContext('2d')!
  cx.drawImage(img, 0, 0)
  const px = cx.getImageData(0, 0, cv.width, cv.height).data
  const land = (lat: number, lng: number) => {
    const x = Math.min(cv.width - 1, Math.floor(((lng + 180) / 360) * cv.width))
    const y = Math.min(cv.height - 1, Math.floor(((90 - lat) / 180) * cv.height))
    return px[(y * cv.width + x) * 4] > 127
  }
  const out: Dot[] = []
  for (let lat = -56; lat <= 78; lat += 1.5) {
    for (let lng = -180; lng < 180; lng += 1.5) {
      if (!land(lat, lng)) continue
      const india = inIndia([lat, lng])
      // India in jewel tones: sapphire in the north shading to teal in the south.
      const k = clamp((lat - 8) / 28)
      out.push({ lat, lng, india, c: india ? `oklch(${0.62 + 0.06 * (1 - k)} 0.17 ${195 + 67 * k})` : '' })
    }
  }
  return out
}

export function FlatWorld({ state, globeBox, shots, targets, still }: {
  state: RefObject<FlatState>; globeBox: RefObject<HTMLDivElement | null>
  shots: Shot[]; targets: LatLng[]; still: boolean
}) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const props = useRef({ shots, targets, still })
  useEffect(() => { props.current = { shots, targets, still } })

  useEffect(() => {
    const cv = canvas.current
    if (!cv) return
    const ctx = cv.getContext('2d')
    if (!ctx) return
    let dots: Dot[] = []
    let alive = true
    landDots().then((d) => { if (alive) dots = d }).catch(() => undefined)

    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    let W = 0, H = 0
    const resize = () => {
      const r = cv.getBoundingClientRect()
      W = r.width; H = r.height
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr)
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(cv)

    // Projectiles in flight: random waves of 3 or 4 different origins, each to a random target, then a ripple.
    type Live = { from: [number, number]; to: [number, number]; c: [number, number]; t0: number; dur: number; color: string }
    let flying: Live[] = []
    let nextWave = 0
    const colorOf = (k: Shot['kind']) => (k === 'c2' ? '#64d2ff' : '#ff5d8f')

    let raf = 0
    const draw = (now: number) => {
      raf = requestAnimationFrame(draw)
      const s = state.current
      if (!s || (s.unroll <= 0 && !s.active)) { if (cv.style.opacity !== '0') { cv.style.opacity = '0'; ctx.clearRect(0, 0, cv.width, cv.height) } return }
      cv.style.opacity = '1'
      const { shots: list, targets: tg, still: calm } = props.current
      const e = smooth(clamp(s.unroll))
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, W, H)

      // Where the globe is (same box and radius as cobe at scale 1), and where the flat map goes (right of the captions).
      const cr = cv.getBoundingClientRect()
      const gb = globeBox.current?.getBoundingClientRect()
      const gx = gb ? gb.left - cr.left + gb.width / 2 : W * 0.7
      const gy = gb ? gb.top - cr.top + gb.height / 2 : H / 2
      const R = gb ? 0.8 * (gb.height / 2) : H * 0.35
      const left0 = 40 + Math.min(520, 0.41 * W) + 32
      const aspect = FLAT.halfLng / FLAT.halfLat
      let fw = W - 32 - left0, fh = fw / aspect
      if (fh > H - 56 - 64) { fh = H - 56 - 64; fw = fh * aspect }
      const fx = left0 + (W - 32 - left0 - fw) / 2, fy = 56 + (H - 56 - fh) / 2
      const flat = ([lat, lng]: LatLng): [number, number] => {
        let d = lng - FLAT.lng
        if (d > 180) d -= 360
        if (d < -180) d += 360
        return [fx + fw / 2 + (d / FLAT.halfLng) * (fw / 2), fy + fh / 2 - ((lat - FLAT.lat) / FLAT.halfLat) * (fh / 2)]
      }
      const inFrame = (x: number, y: number) => x >= fx - 2 && x <= fx + fw + 2 && y >= fy - 2 && y <= fy + fh + 2
      const [p0, l0] = [rad(CENTRE[0]), rad(CENTRE[1])]

      // The ocean disc fades as the sphere opens out.
      if (e < 1) {
        ctx.globalAlpha = 1 - e
        ctx.fillStyle = '#1c1c1c'
        ctx.beginPath(); ctx.arc(gx, gy, R, 0, Math.PI * 2); ctx.fill()
      }
      for (const d of dots) {
        const p = rad(d.lat), l = rad(d.lng) - l0
        const cosc = Math.sin(p0) * Math.sin(p) + Math.cos(p0) * Math.cos(p) * Math.cos(l)
        const ox = gx + R * Math.cos(p) * Math.sin(l)
        const oy = gy - R * (Math.cos(p0) * Math.sin(p) - Math.sin(p0) * Math.cos(p) * Math.cos(l))
        const [qx, qy] = flat([d.lat, d.lng])
        // The far side appears as it unrolls; land outside the flat frame fades away instead of crossing the captions.
        const a = (cosc > 0 ? 1 : e) * (inFrame(qx, qy) ? 1 : 1 - e)
        if (a <= 0.01) continue
        ctx.globalAlpha = a * (d.india ? 1 : 0.5 + 0.2 * (1 - e))
        ctx.fillStyle = d.india ? d.c : '#ffffff'
        const size = d.india ? 2.2 : 1.6
        ctx.fillRect(ox + (qx - ox) * e - size / 2, oy + (qy - oy) * e - size / 2, size, size)
      }
      ctx.globalAlpha = 1
      if (e < 0.98) return

      // Origins and targets, then the projectiles.
      const ends = tg.map(flat)
      ctx.font = '500 12px "Inter Variable", system-ui, sans-serif'
      ctx.textAlign = 'center'
      // Origin labels: above the point if there is room, else below, else to a side, never on top of another label.
      const boxes: [number, number, number, number][] = []
      const free = (b: [number, number, number, number]) => boxes.every((o) => b[0] + b[2] <= o[0] || o[0] + o[2] <= b[0] || b[1] + b[3] <= o[1] || o[1] + o[3] <= b[1])
      for (const sh of list) {
        const [x, y] = flat(sh.at)
        ctx.fillStyle = colorOf(sh.kind)
        ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill()
        const w = ctx.measureText(sh.name).width + 12, h = 17
        const tries: [number, number, number, number][] = [
          [x - w / 2, y - 7 - h, w, h], [x - w / 2, y + 7, w, h], [x + 7, y - h / 2, w, h], [x - 7 - w, y - h / 2, w, h],
          [x - w / 2, y - 9 - 2 * h, w, h], [x - w / 2, y + 9 + h, w, h],
        ]
        const b = tries.find(free) ?? tries[0]
        boxes.push(b)
        ctx.fillStyle = '#000'
        ctx.globalAlpha = 0.85
        ctx.fillRect(b[0], b[1], b[2], b[3])
        ctx.globalAlpha = 1
        ctx.fillStyle = '#ffffff'
        ctx.fillText(sh.name, b[0] + b[2] / 2, b[1] + 12.5)
      }
      for (const [x, y] of ends) {
        ctx.strokeStyle = 'rgba(255,255,255,0.7)'
        ctx.lineWidth = 1
        ctx.beginPath(); ctx.arc(x, y, 3.5, 0, Math.PI * 2); ctx.stroke()
      }
      const arc = (from: [number, number], to: [number, number]): [number, number] => {
        const [mx, my] = [(from[0] + to[0]) / 2, (from[1] + to[1]) / 2]
        return [mx, my - Math.hypot(to[0] - from[0], to[1] - from[1]) * 0.28] // lob it: projectiles arc upward
      }
      const at = (f: [number, number], c: [number, number], t: [number, number], u: number): [number, number] =>
        [(1 - u) ** 2 * f[0] + 2 * (1 - u) * u * c[0] + u * u * t[0], (1 - u) ** 2 * f[1] + 2 * (1 - u) * u * c[1] + u * u * t[1]]

      if (calm || !s.active) {
        // Reduced motion: every route once, thin and still.
        list.forEach((sh, i) => {
          const f = flat(sh.at), t = ends[i % Math.max(1, ends.length)] ?? f, c = arc(f, t)
          ctx.strokeStyle = colorOf(sh.kind)
          ctx.globalAlpha = 0.7
          ctx.lineWidth = 1.1
          ctx.beginPath(); ctx.moveTo(f[0], f[1]); ctx.quadraticCurveTo(c[0], c[1], t[0], t[1]); ctx.stroke()
        })
        ctx.globalAlpha = 1
        return
      }

      if (now >= nextWave && flying.length === 0 && list.length && ends.length) {
        const size = Math.min(list.length, Math.random() < 0.5 ? 3 : 4)
        const pick = [...list].sort(() => Math.random() - 0.5).slice(0, size)
        flying = pick.map((sh) => {
          const from = flat(sh.at), to = ends[Math.floor(Math.random() * ends.length)]
          return { from, to, c: arc(from, to), t0: now + Math.random() * 350, dur: 1100 + Math.random() * 500, color: colorOf(sh.kind) }
        })
      }
      ctx.lineCap = 'round'
      flying = flying.filter((f) => {
        const u = (now - f.t0) / f.dur
        if (u < 0) return true
        if (u <= 1) {
          const k = smooth(u)
          // A thin fading tail behind a bright head.
          const steps = 24, tail = 0.38
          for (let i = 0; i < steps; i++) {
            const a = Math.max(0, k - tail * (1 - i / steps)), b = Math.max(0, k - tail * (1 - (i + 1) / steps))
            const [x1, y1] = at(f.from, f.c, f.to, a), [x2, y2] = at(f.from, f.c, f.to, b)
            ctx.strokeStyle = f.color
            ctx.globalAlpha = ((i + 1) / steps) ** 1.4
            ctx.lineWidth = 1.2
            ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke()
          }
          const [hx, hy] = at(f.from, f.c, f.to, k)
          ctx.globalAlpha = 1
          ctx.shadowColor = f.color
          ctx.shadowBlur = 14
          ctx.fillStyle = '#ffffff'
          ctx.beginPath(); ctx.arc(hx, hy, 2.6, 0, Math.PI * 2); ctx.fill()
          ctx.shadowBlur = 0
          return true
        }
        const r = (now - f.t0 - f.dur) / 600 // one ripple where it lands
        if (r > 1) return false
        ctx.globalAlpha = 1 - r
        ctx.strokeStyle = f.color
        ctx.lineWidth = 1.2
        ctx.beginPath(); ctx.arc(f.to[0], f.to[1], 3 + 12 * smooth(r), 0, Math.PI * 2); ctx.stroke()
        ctx.globalAlpha = 1
        return true
      })
      if (flying.length === 0 && now > nextWave) nextWave = now + 350 + Math.random() * 450
    }
    raf = requestAnimationFrame(draw)
    return () => { alive = false; cancelAnimationFrame(raf); ro.disconnect() }
  }, [state, globeBox])

  return <canvas ref={canvas} className="pointer-events-none absolute inset-0 size-full" style={{ opacity: 0 }} aria-hidden />
}
