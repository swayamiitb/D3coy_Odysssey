import { Minus, Plus, RotateCcw } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type PointerEvent } from 'react'
import type { Soc } from '../api'
import { IndiaMap } from '../IndiaMap'
import attackers from '../landing/geo/attackers.json'
import feodo from '../landing/geo/feodo.json'
import { inIndia } from '../landing/geo/FlatWorld'
import { COUNTRY_CENTROID, STATE_CENTROID, stateName, type LatLng } from '../landing/geo/geo'
import { WORLD_MASK } from '../landing/geo/worldMask'
import { compact, countryName, Seg, SocCard } from './kit'

/* Threat activity (ui-07): the Now page's signature, replacing the flat "Across India" tile map as the first thing under
   the fold. World: a dotted map (the land mask the landing's globe uses) with real attack origins (SANS ISC DShield's
   top attacking IPs, located by RIPEstat; abuse.ch Feodo Tracker botnet C2s) arcing into the Indian operators with the
   most Critical warnings, and a ranked list of origins beside it. India: the lead's state map, restyled. Where an arc
   lands is simulated (the operators are), and the legend says so. Reduced motion: arcs drawn once, nothing flies. */

type OrgRow = Soc['orgs'][number]
interface Origin { id: string; cc: string; kind: 'attack' | 'c2'; at: LatLng; ips: number; records: number; note: string }
interface Target { state: string; at: LatLng; orgs: number; critical: number; compromise: boolean }

const ATTACK = '#ff5d8f' // an attack source: an identity shared with the landing story, not a risk tier
const C2 = '#64d2ff'     // a botnet command-and-control server
const COMP = '#8a63e8'
const K_MAX = 3

function originsFromData(): Origin[] {
  const out: Origin[] = attackers.countries.map((c) => ({
    id: `a-${c.country}`, cc: c.country, kind: 'attack' as const, at: [c.lat, c.lon] as LatLng, ips: c.ips, records: c.records,
    note: `${c.ips} of DShield's top ${attackers.ips_located} IPs${c.city ? ` · ${c.city}` : ''}`,
  }))
  const c2 = new Map<string, { n: number; malware: Set<string> }>()
  for (const e of feodo.entries) {
    const v = c2.get(e.country) ?? { n: 0, malware: new Set<string>() }
    v.n += 1
    v.malware.add(e.malware)
    c2.set(e.country, v)
  }
  for (const [cc, v] of c2) {
    const at = COUNTRY_CENTROID[cc]
    if (!at) continue
    out.push({ id: `c-${cc}`, cc, kind: 'c2', at: [at[0] - 2.5, at[1] + 3], ips: v.n, records: 0, note: `${v.n} Feodo C2 server${v.n > 1 ? 's' : ''} · ${[...v.malware].join(', ')}` })
  }
  return out
}

function targetsFrom(orgs: OrgRow[]): Target[] {
  const by = new Map<string, Target>()
  for (const o of orgs) {
    const st = stateName(o.state)
    const at = STATE_CENTROID[st]
    if (!at) continue
    const t = by.get(st) ?? { state: st, at, orgs: 0, critical: 0, compromise: false }
    t.orgs += 1
    t.critical += o.critical
    t.compromise ||= o.compromise > 0
    by.set(st, t)
  }
  return [...by.values()].sort((a, b) => Number(b.compromise) - Number(a.compromise) || b.critical - a.critical)
}

interface Dot { lat: number; lng: number; india: boolean }
let DOTS: Promise<{ coarse: Dot[]; fine: Dot[] }> | undefined
function landDots() {
  DOTS ??= (async () => {
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
    const grid = (step: number) => {
      const out: Dot[] = []
      for (let lat = -56; lat <= 82; lat += step) for (let lng = -180; lng < 180; lng += step) {
        if (land(lat, lng)) out.push({ lat, lng, india: inIndia([lat, lng]) })
      }
      return out
    }
    return { coarse: grid(1.5), fine: grid(0.75) }
  })()
  return DOTS
}

/** The view at zoom k: the whole stage at 1, India at K_MAX. */
function viewAt(k: number, aspect: number) {
  const t = (k - 1) / (K_MAX - 1)
  const latSpan = Math.max(116, 268 / aspect) / k
  const cLat = 16 + (22 - 16) * t
  const cLng = 14 + (82 - 14) * t
  return { lat1: cLat + latSpan / 2, lng0: cLng - (latSpan * aspect) / 2, s: 1 / latSpan }
}

function WorldCanvas({ origins, targets, focus, setFocus, zoom }: {
  origins: Origin[]; targets: Target[]; focus?: string; setFocus: (id?: string) => void; zoom: number
}) {
  const wrap = useRef<HTMLDivElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const live = useRef({ focus, zoom })
  live.current = { focus, zoom }
  const [tip, setTip] = useState<{ x: number; y: number; title: string; lines: string[] }>()
  const hits = useRef<{ x: number; y: number; r: number; title: string; lines: string[]; id?: string }[]>([])

  // Each origin reaches two of the operator states with the most Critical warnings (simulated landing points).
  const routes = useMemo(() => {
    const top = targets.slice(0, 6)
    return top.length ? origins.flatMap((o, i) => [top[i % top.length], top[(i + 2) % top.length]].map((t) => ({ o, t }))) : []
  }, [origins, targets])

  useEffect(() => {
    const cv = canvas.current!, box = wrap.current!
    const ctx = cv.getContext('2d')!
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let dots: { coarse: Dot[]; fine: Dot[] } | undefined
    let raf = 0, visible = true, W = 0, H = 0, dpr = 1, k = live.current.zoom
    const flying: { r: number; t0: number; dur: number }[] = []
    let nextLaunch = 0
    landDots().then((d) => { dots = d })

    const size = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1)
      W = box.clientWidth
      H = box.clientHeight
      cv.width = Math.round(W * dpr)
      cv.height = Math.round(H * dpr)
    }
    size()
    const ro = new ResizeObserver(size)
    ro.observe(box)
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting })
    io.observe(box)

    const frame = (now: number) => {
      raf = requestAnimationFrame(frame)
      if (!visible || document.hidden || !W) return
      const goal = live.current.zoom
      k = still ? goal : k + (goal - k) * 0.14
      if (Math.abs(goal - k) < 0.002) k = goal
      const v = viewAt(k, W / H)
      const px = H * v.s
      const P = (lat: number, lng: number): [number, number] => [(lng - v.lng0) * px, (v.lat1 - lat) * px]
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, W, H)

      // land
      if (dots) {
        const set = k > 1.7 ? dots.fine : dots.coarse
        const step = k > 1.7 ? 0.75 : 1.5
        const d = Math.max(1.4, Math.min(2.8, step * px * 0.4))
        for (const dt of set) {
          const [x, y] = P(dt.lat, dt.lng)
          if (x < -4 || y < -4 || x > W + 4 || y > H + 4) continue
          ctx.fillStyle = dt.india ? 'rgba(244,244,245,0.55)' : 'rgba(255,255,255,0.2)'
          ctx.fillRect(x - d / 2, y - d / 2, d, d)
        }
      }

      const f = live.current.focus
      const curve = (a: [number, number], b: [number, number]) => {
        const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2
        const dx = b[0] - a[0], dy = b[1] - a[1], len = Math.hypot(dx, dy) || 1
        const lift = Math.min(len * 0.28, H * 0.32)
        return { a, b, c: [mx + (dy / len) * lift * (dx > 0 ? -1 : 1), my - Math.abs(dx / len) * lift] as [number, number] }
      }
      const at = (q: ReturnType<typeof curve>, t: number): [number, number] => {
        const u = 1 - t
        return [u * u * q.a[0] + 2 * u * t * q.c[0] + t * t * q.b[0], u * u * q.a[1] + 2 * u * t * q.c[1] + t * t * q.b[1]]
      }

      // arcs, drawn once each frame: faint, or bright for the focused origin
      const qs = routes.map(({ o, t }) => ({ o, t, q: curve(P(o.at[0], o.at[1]), P(t.at[0], t.at[1])) }))
      for (const { o, q } of qs) {
        const on = f ? f === o.id : false
        ctx.strokeStyle = o.kind === 'attack' ? ATTACK : C2
        ctx.globalAlpha = on ? 0.9 : f ? 0.07 : still ? 0.5 : 0.3
        ctx.lineWidth = on ? 1.4 : 1
        ctx.beginPath()
        ctx.moveTo(q.a[0], q.a[1])
        ctx.quadraticCurveTo(q.c[0], q.c[1], q.b[0], q.b[1])
        ctx.stroke()
      }
      ctx.globalAlpha = 1

      // projectiles: one at a time from any origin, at random moments and speeds
      if (!still && qs.length) {
        if (now >= nextLaunch && flying.length < 5) {
          const pool = f ? qs.map((_, i) => i).filter((i) => qs[i].o.id === f) : qs.map((_, i) => i)
          flying.push({ r: pool[Math.floor(Math.random() * pool.length)], t0: now, dur: 1300 + Math.random() * 2200 })
          nextLaunch = now + (Math.random() < 0.25 ? 120 + Math.random() * 200 : 450 + Math.random() * 1400)
        }
        for (let i = flying.length - 1; i >= 0; i--) {
          const s = flying[i], r = qs[s.r]
          if (!r) { flying.splice(i, 1); continue }
          const t = (now - s.t0) / s.dur
          if (t >= 1.35) { flying.splice(i, 1); continue }
          const col = r.o.kind === 'attack' ? ATTACK : C2
          if (t <= 1) {
            const e = t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2
            ctx.strokeStyle = col
            for (let j = 0; j < 14; j++) {
              const t0 = Math.max(0, e - 0.2 * (j / 14)), t1 = Math.max(0, e - 0.2 * ((j + 1) / 14))
              const p0 = at(r.q, t0), p1 = at(r.q, t1)
              ctx.globalAlpha = 0.9 * (1 - j / 14)
              ctx.lineWidth = 1.6
              ctx.beginPath()
              ctx.moveTo(p0[0], p0[1])
              ctx.lineTo(p1[0], p1[1])
              ctx.stroke()
            }
            const h = at(r.q, e)
            ctx.globalAlpha = 1
            ctx.fillStyle = '#ffffff'
            ctx.beginPath()
            ctx.arc(h[0], h[1], 2, 0, Math.PI * 2)
            ctx.fill()
          } else {
            const p = (t - 1) / 0.35
            ctx.globalAlpha = 0.8 * (1 - p)
            ctx.strokeStyle = col
            ctx.lineWidth = 1.2
            ctx.beginPath()
            ctx.arc(r.q.b[0], r.q.b[1], 3 + 12 * p, 0, Math.PI * 2)
            ctx.stroke()
          }
        }
        ctx.globalAlpha = 1
      }

      // markers, and what the pointer can hover
      const hit: typeof hits.current = []
      ctx.font = '600 11px "Cascadia Mono", Consolas, ui-monospace, monospace'
      ctx.textBaseline = 'middle'
      for (const t of targets) {
        const [x, y] = P(t.at[0], t.at[1])
        ctx.fillStyle = t.compromise ? COMP : '#ffffff'
        ctx.beginPath()
        ctx.arc(x, y, t.compromise ? 4 : 2.6, 0, Math.PI * 2)
        ctx.fill()
        if (t.compromise) {
          ctx.strokeStyle = COMP
          ctx.globalAlpha = 0.55
          ctx.lineWidth = 1.2
          ctx.beginPath()
          ctx.arc(x, y, 8, 0, Math.PI * 2)
          ctx.stroke()
          ctx.globalAlpha = 1
        }
        hit.push({ x, y, r: 9, title: t.state, lines: [`${t.orgs} operator${t.orgs > 1 ? 's' : ''} · ${t.critical} Critical warnings${t.compromise ? ' · suspected compromise' : ''}`, 'Operators are simulated (SIM)'] })
      }
      for (const o of origins) {
        const [x, y] = P(o.at[0], o.at[1])
        const on = f === o.id
        const col = o.kind === 'attack' ? ATTACK : C2
        ctx.globalAlpha = f && !on ? 0.4 : 1
        if (o.kind === 'attack') {
          ctx.fillStyle = col
          ctx.beginPath()
          ctx.arc(x, y, on ? 5 : 4, 0, Math.PI * 2)
          ctx.fill()
        } else {
          ctx.strokeStyle = col
          ctx.lineWidth = 1.6
          ctx.beginPath()
          ctx.arc(x, y, on ? 5 : 4, 0, Math.PI * 2)
          ctx.stroke()
        }
        ctx.strokeStyle = col
        ctx.globalAlpha = (f && !on ? 0.15 : 0.35)
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.arc(x, y, on ? 11 : 9, 0, Math.PI * 2)
        ctx.stroke()
        ctx.globalAlpha = f && !on ? 0.4 : 1
        ctx.fillStyle = 'rgba(244,244,245,0.85)'
        if (o.kind === 'attack') ctx.fillText(o.cc, x + 12, y - 1)
        else if (!origins.some((a) => a.kind === 'attack' && a.cc === o.cc)) {
          ctx.textAlign = 'right'
          ctx.fillText(o.cc, x - 12, y + 1)
          ctx.textAlign = 'left'
        }
        ctx.globalAlpha = 1
        hit.push({ x, y, r: 12, id: o.id, title: `${countryName(o.cc)} (${o.kind === 'attack' ? 'attack source' : 'botnet C2'})`,
                   lines: [o.note, o.kind === 'attack' ? `${o.records.toLocaleString('en-IN')} reports to DShield · REAL` : 'abuse.ch Feodo Tracker · REAL'] })
      }
      hits.current = hit
    }
    raf = requestAnimationFrame(frame)
    return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect() }
  }, [origins, targets, routes])

  const onMove = (e: PointerEvent) => {
    const r = wrap.current!.getBoundingClientRect()
    const x = e.clientX - r.left, y = e.clientY - r.top
    let best: (typeof hits.current)[number] | undefined, bd = Infinity
    for (const h of hits.current) {
      const d = Math.hypot(h.x - x, h.y - y)
      if (d < h.r && d < bd) { best = h; bd = d }
    }
    setTip(best ? { x: best.x, y: best.y, title: best.title, lines: best.lines } : undefined)
    setFocus(best?.id)
  }

  return (
    <div ref={wrap} className="relative h-full w-full" onPointerMove={onMove} onPointerLeave={() => { setTip(undefined); setFocus(undefined) }}>
      <canvas ref={canvas} className="absolute inset-0 h-full w-full" aria-hidden />
      {tip && (
        <div className="pointer-events-none absolute z-10 w-64 rounded-xl border border-line-2 bg-panel px-3 py-2.5 text-[12.5px]"
             style={{ left: Math.min(tip.x + 14, (wrap.current?.clientWidth ?? 0) - 270), top: Math.max(8, tip.y - 18) }}>
          <div className="font-semibold text-text">{tip.title}</div>
          {tip.lines.map((l) => <div key={l} className="mt-0.5 text-mute">{l}</div>)}
        </div>
      )}
    </div>
  )
}

export function ThreatMap({ orgs, onOrg }: { orgs?: OrgRow[]; onOrg: (id: string) => void }) {
  const [mode, setMode] = useState<'world' | 'india'>('world')
  const [zoom, setZoom] = useState(1)
  const [focus, setFocus] = useState<string>()
  const origins = useMemo(originsFromData, [])
  const targets = useMemo(() => targetsFrom(orgs ?? []), [orgs])
  const ranked = [...origins].sort((a, b) => b.records - a.records || b.ips - a.ips)
  const maxRec = Math.max(1, ...ranked.map((o) => o.records))
  const taken = attackers.taken_at.slice(0, 10)

  const zoomBtn = 'flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-panel/90 text-mute transition-colors hover:bg-panel-2 hover:text-text disabled:opacity-40'
  return (
    <SocCard title="Threat activity" prov={['REAL', 'SIM']}
             sub={mode === 'world' ? 'Where attacks start, and the Indian operators they reach' : 'Where the warnings are: states by their operators’ Critical warnings'}
             right={<Seg label="Map" value={mode} onChange={setMode} items={[['world', 'World'], ['india', 'India']]} />}
             bodyClass="">
      <div className="grid border-t border-line xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="relative min-w-0">
          {mode === 'world' ? (
            <div className="relative h-[250px] w-full sm:h-[380px] md:h-[480px] xl:h-full xl:min-h-[540px]">
              <WorldCanvas origins={origins} targets={targets} focus={focus} setFocus={setFocus} zoom={zoom} />
              <div className="absolute right-3 top-3 flex flex-col gap-1.5">
                <button className={zoomBtn} onClick={() => setZoom((z) => Math.min(K_MAX, +(z + 1).toFixed(2)))} disabled={zoom >= K_MAX} aria-label="Zoom in towards India"><Plus size={16} /></button>
                <button className={zoomBtn} onClick={() => setZoom((z) => Math.max(1, +(z - 1).toFixed(2)))} disabled={zoom <= 1} aria-label="Zoom out"><Minus size={16} /></button>
                <button className={zoomBtn} onClick={() => setZoom(1)} disabled={zoom === 1} aria-label="Reset the view"><RotateCcw size={14} /></button>
              </div>
              <div className="pointer-events-none absolute bottom-3 left-4 flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-mute">
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: ATTACK }} />Attack source (DShield, REAL)</span>
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full ring-[1.5px] ring-inset" style={{ color: C2, boxShadow: `inset 0 0 0 1.5px ${C2}` }} />Botnet C2 (Feodo, REAL)</span>
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-white" />Operator state (SIM)</span>
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-comp" />Suspected compromise</span>
              </div>
            </div>
          ) : (
            <div className="h-[520px] xl:h-full xl:min-h-[560px]">{orgs ? <IndiaMap orgs={orgs} onOrg={onOrg} bare /> : <div className="h-full bg-panel-2" />}</div>
          )}
        </div>

        <aside className="min-w-0 border-t border-line xl:border-l xl:border-t-0">
          {mode === 'world' ? (
            <div className="flex h-full flex-col p-4">
              <div className="flex items-baseline justify-between px-1">
                <h3 className="text-[14px] font-semibold">Top attack origins</h3>
                <span className="text-[12px] text-faint">reports</span>
              </div>
              <ol className="mt-2 flex-1 space-y-0.5">
                {ranked.map((o, i) => (
                  <li key={o.id}>
                    <button onMouseEnter={() => setFocus(o.id)} onMouseLeave={() => setFocus(undefined)} onFocus={() => setFocus(o.id)} onBlur={() => setFocus(undefined)}
                            className={`w-full rounded-xl px-2.5 py-1.5 text-left transition-colors ${focus === o.id ? 'bg-panel-2' : 'hover:bg-panel-2/60'}`}>
                      <div className="flex items-center gap-2.5">
                        <span className="w-4 text-right font-mono text-[12px] text-faint">{i + 1}</span>
                        <span className="flex h-6 w-8 shrink-0 items-center justify-center rounded-md border border-line bg-ink font-mono text-[11px] font-semibold">{o.cc}</span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-[13.5px] font-medium">{countryName(o.cc)}</span>
                          <span className="block truncate text-[12px] text-faint">{o.note}</span>
                        </span>
                        <span className="font-mono text-[13px]">{o.kind === 'attack' ? compact(o.records) : `${o.ips} C2`}</span>
                      </div>
                      <div className="ml-[3.6rem] mt-1 h-[3px] rounded-full bg-panel-3">
                        <div className="h-full rounded-full" style={{ width: `${o.kind === 'attack' ? Math.max(3, (100 * o.records) / maxRec) : 3}%`, background: o.kind === 'attack' ? ATTACK : C2 }} />
                      </div>
                    </button>
                  </li>
                ))}
              </ol>
              <p className="mt-3 px-1 text-[12px] leading-snug text-faint">
                SANS ISC DShield top attacking IPs, located by RIPEstat, and abuse.ch Feodo Tracker, taken {taken}. Which operator each arc reaches is simulated.
              </p>
            </div>
          ) : (
            <div className="p-4">
              <div className="flex items-baseline justify-between px-1">
                <h3 className="text-[14px] font-semibold">States by Critical warnings</h3>
                <span className="text-[12px] text-faint">Critical</span>
              </div>
              <ol className="mt-2 space-y-0.5">
                {targets.slice(0, 9).map((t, i) => (
                  <li key={t.state} className="flex items-center gap-2.5 rounded-xl px-2.5 py-2">
                    <span className="w-4 text-right font-mono text-[12px] text-faint">{i + 1}</span>
                    <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${t.compromise ? 'bg-comp' : 'bg-crit'}`} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13.5px] font-medium">{t.state}</span>
                      <span className="block text-[12px] text-faint">{t.orgs} operator{t.orgs > 1 ? 's' : ''}{t.compromise ? ' · suspected compromise' : ''}</span>
                    </span>
                    <span className="font-mono text-[13px]">{t.critical}</span>
                  </li>
                ))}
              </ol>
              <p className="mt-3 px-1 text-[12px] leading-snug text-faint">Operators are simulated (SIM); their warnings come from real CVEs. Open a state on the map for its operators.</p>
            </div>
          )}
        </aside>
      </div>
    </SocCard>
  )
}
