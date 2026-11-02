import * as Cesium from 'cesium'
import { useEffect, useRef, useState } from 'react'
import { countryName } from '../kit'
import { ATTACK, C2, COMP, CRIT, type Origin, type Route, type Target } from './data'

/* The live threat map on a satellite-view world (CesiumJS, flat 2D scene on Web Mercator), ui-15. The same data as the 2D map, on imagery:
   REAL attack origins (SANS ISC DShield's top attacking IPs, located by RIPEstat) and botnet C2 countries (abuse.ch
   Feodo Tracker), the Indian operator states they are drawn reaching (SIM landing points), and the live engine's
   beacon detections as arcs from the operator's state to the C2's country, with the attack paths animated as
   projectiles. Imagery comes from Cesium ion (Sentinel-2 first, then Bing Maps Aerial) through the configured
   tokens in turn (VITE_CESIUM_ION_TOKENS, comma-separated: when one stops answering or runs out of credit the next
   takes over), and from the bundled Natural Earth II tiles when there is no network or no token, so the globe never
   depends on the network (rule 14). No terrain is streamed: the ellipsoid alone keeps credit use to the imagery. */

declare global { interface Window { CESIUM_BASE_URL?: string } }
if (typeof window !== 'undefined' && !window.CESIUM_BASE_URL) window.CESIUM_BASE_URL = '/cesium/'

const TOKENS = String(import.meta.env.VITE_CESIUM_ION_TOKENS ?? '').split(',').map((s) => s.trim()).filter(Boolean)
/** Satellite layers on Cesium ion, in order of preference: Sentinel-2 is a cloud-free mosaic and costs no Bing session. */
const ION_LAYERS = [{ id: 3954, name: 'Sentinel-2 (ESA Copernicus) via Cesium ion' }, { id: 2, name: 'Bing Maps Aerial via Cesium ion' }]
const ATTEMPT_MS = 9000       // one imagery candidate gets this long to answer before the next is tried
const ERRORS_TO_ROTATE = 6    // tile failures within a minute that make the globe move to the next token or layer
const STILL = () => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

export interface ImageryInfo { name: string; status: 'loading' | 'ok' | 'offline' | 'none'; slot?: number; slots: number; detail?: string }
export interface LiveArc { id: string; state: string; at: [number, number]; c2: string; c2cc?: string; c2at?: [number, number]; title: string }

interface Candidate { kind: 'ion' | 'offline'; name: string; assetId?: number; token?: string; slot?: number }

function candidates(): Candidate[] {
  const out: Candidate[] = []
  for (const layer of ION_LAYERS) TOKENS.forEach((token, i) => out.push({ kind: 'ion', name: layer.name, assetId: layer.id, token, slot: i + 1 }))
  out.push({ kind: 'offline', name: 'Natural Earth II (bundled, offline)' })
  return out
}

const css = (hex: string, a = 1) => Cesium.Color.fromCssColorString(hex).withAlpha(a)
const deg = (at: [number, number], h = 0) => Cesium.Cartesian3.fromDegrees(at[1], at[0], h)
// A flat satellite map (Cesium's 2D scene on Web Mercator), framed like the canvas map: the world crop, and India.
const WORLD = Cesium.Rectangle.fromDegrees(-135, -52, 172, 74)
const INDIA = Cesium.Rectangle.fromDegrees(58, 3, 102, 39)

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${what}: no answer in ${ms / 1000} s`)), ms)
    p.then((v) => { clearTimeout(t); resolve(v) }, (e) => { clearTimeout(t); reject(e) })
  })
}

export interface ThreatGlobeProps {
  origins: Origin[]
  targets: Target[]
  routes: Route[]
  live: LiveArc[]
  focus?: string
  showAll: boolean
  view: 'world' | 'india'
  paused: boolean
  onFocus: (id?: string) => void
  onPick?: (state: string) => void
  onImagery: (info: ImageryInfo) => void
  onFail: (why: string) => void
}

/** The globe. Entities are rebuilt when the data changes; the camera, the imagery and the shots live across renders. */
export function ThreatGlobe(props: ThreatGlobeProps) {
  const box = useRef<HTMLDivElement>(null)
  const credit = useRef<HTMLDivElement>(null)
  const live = useRef(props)
  live.current = props
  const viewerRef = useRef<Cesium.Viewer>(null)
  const [tip, setTip] = useState<{ x: number; y: number; title: string; lines: string[] }>()
  const shots = useRef<{ id: string; r: Route; t0: number; dur: number }[]>([])

  // ---- the viewer, once
  useEffect(() => {
    const el = box.current!
    let viewer: Cesium.Viewer
    try {
      if (TOKENS[0]) Cesium.Ion.defaultAccessToken = TOKENS[0]
      viewer = new Cesium.Viewer(el, {
        baseLayer: false, animation: false, timeline: false, baseLayerPicker: false, geocoder: false, homeButton: false,
        sceneModePicker: false, navigationHelpButton: false, fullscreenButton: false, infoBox: false, selectionIndicator: false,
        vrButton: false, skyBox: false, creditContainer: credit.current!, requestRenderMode: false,
        sceneMode: Cesium.SceneMode.SCENE2D, mapProjection: new Cesium.WebMercatorProjection(),
        contextOptions: { webgl: { powerPreference: 'high-performance', antialias: true, failIfMajorPerformanceCaveat: false } },
      })
    } catch (e) {
      live.current.onFail(e instanceof Error ? e.message : String(e))
      return
    }
    viewerRef.current = viewer
    const scene = viewer.scene
    scene.backgroundColor = Cesium.Color.BLACK
    scene.globe.baseColor = css('#0b1626')
    scene.globe.enableLighting = false
    scene.globe.showGroundAtmosphere = true
    scene.highDynamicRange = false
    scene.fog.enabled = false
    const ctl = scene.screenSpaceCameraController
    ctl.minimumZoomDistance = 420_000   // about level 8 imagery at most: enough to read a state, cheap on credits
    ctl.maximumZoomDistance = 32_000_000
    ctl.enableTilt = false
    viewer.camera.setView({ destination: WORLD })

    // ---- imagery: the candidates in turn, each with a short clock; tile failures move to the next
    let cancelled = false
    let errors: number[] = []
    let current: Cesium.ImageryLayer | undefined
    const list = candidates()
    const report = (info: ImageryInfo) => { if (!cancelled) live.current.onImagery(info) }
    const tryFrom = async (i: number): Promise<void> => {
      if (cancelled) return
      if (i >= list.length) { report({ name: 'no imagery', status: 'none', slots: TOKENS.length, detail: 'every source failed; the globe shows its base colour' }); return }
      const c = list[i]
      report({ name: c.name, status: 'loading', slot: c.slot, slots: TOKENS.length })
      try {
        const provider: Cesium.ImageryProvider = c.kind === 'ion'
          ? await withTimeout(Cesium.IonImageryProvider.fromAssetId(c.assetId!, { accessToken: c.token }), ATTEMPT_MS, c.name)
          : await withTimeout(Cesium.TileMapServiceImageryProvider.fromUrl(Cesium.buildModuleUrl('Assets/Textures/NaturalEarthII')), ATTEMPT_MS, c.name)
        if (cancelled) return
        if (current) viewer.imageryLayers.remove(current, true)
        current = viewer.imageryLayers.addImageryProvider(provider)
        errors = []
        provider.errorEvent.addEventListener(() => {
          const now = performance.now()
          errors = errors.filter((t) => now - t < 60_000)
          errors.push(now)
          if (errors.length >= ERRORS_TO_ROTATE && current && i + 1 < list.length) {
            errors = []
            report({ name: c.name, status: 'offline', slot: c.slot, slots: TOKENS.length, detail: 'tiles stopped answering; moving on' })
            void tryFrom(i + 1)
          }
        })
        report({ name: c.name, status: c.kind === 'ion' ? 'ok' : 'offline', slot: c.slot, slots: TOKENS.length,
                 detail: c.kind === 'ion' ? `token ${c.slot} of ${TOKENS.length}` : 'bundled tiles, no network needed' })
      } catch (e) {
        report({ name: c.name, status: 'offline', slot: c.slot, slots: TOKENS.length, detail: e instanceof Error ? e.message : String(e) })
        await tryFrom(i + 1)
      }
    }
    void tryFrom(0)

    // ---- hover and click: entities carry what to say
    const handler = new Cesium.ScreenSpaceEventHandler(scene.canvas)
    let hoverOrigin: string | undefined
    handler.setInputAction((m: Cesium.ScreenSpaceEventHandler.MotionEvent) => {
      const picked = scene.pick(m.endPosition)
      const ent = picked?.id instanceof Cesium.Entity ? picked.id : undefined
      const meta = ent?.properties?.getValue(Cesium.JulianDate.now()) as { title?: string; lines?: string[]; origin?: string } | undefined
      if (meta?.title) {
        setTip({ x: m.endPosition.x, y: m.endPosition.y, title: meta.title, lines: meta.lines ?? [] })
        if (meta.origin && meta.origin !== hoverOrigin) { hoverOrigin = meta.origin; live.current.onFocus(meta.origin) }
        el.style.cursor = 'pointer'
      } else {
        setTip(undefined)
        el.style.cursor = ''
        if (hoverOrigin) { hoverOrigin = undefined; live.current.onFocus(undefined) }
      }
    }, Cesium.ScreenSpaceEventType.MOUSE_MOVE)
    handler.setInputAction((m: Cesium.ScreenSpaceEventHandler.PositionedEvent) => {
      const picked = scene.pick(m.position)
      const ent = picked?.id instanceof Cesium.Entity ? picked.id : undefined
      const meta = ent?.properties?.getValue(Cesium.JulianDate.now()) as { origin?: string; target?: [number, number]; state?: string } | undefined
      if (meta?.target && meta.state && live.current.onPick) live.current.onPick(meta.state)
      else if (meta?.target) viewer.camera.flyTo({ destination: Cesium.Rectangle.fromDegrees(meta.target[1] - 7, meta.target[0] - 5, meta.target[1] + 7, meta.target[0] + 5), duration: 1.4 })
      else if (meta?.origin) live.current.onFocus(meta.origin)
    }, Cesium.ScreenSpaceEventType.LEFT_CLICK)

    // ---- render only while on screen and allowed
    let seen = true
    const sync = () => { viewer.useDefaultRenderLoop = seen && !live.current.paused && document.visibilityState === 'visible' }
    const io = new IntersectionObserver((es) => { seen = es.some((e) => e.isIntersecting); sync() }, { threshold: 0.05 })
    io.observe(el)
    document.addEventListener('visibilitychange', sync)
    const pauseTimer = setInterval(sync, 1000)

    return () => {
      cancelled = true
      clearInterval(pauseTimer)
      document.removeEventListener('visibilitychange', sync)
      io.disconnect()
      handler.destroy()
      viewerRef.current = null
      viewer.destroy()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ---- the camera follows the World / India switch
  useEffect(() => {
    const v = viewerRef.current
    if (!v || v.isDestroyed()) return
    v.camera.flyTo({ destination: props.view === 'india' ? INDIA : WORLD, duration: STILL() ? 0 : 1.4 })
  }, [props.view])

  // ---- entities: origins, targets, routes, live arcs, and the projectile pool
  useEffect(() => {
    const v = viewerRef.current
    if (!v || v.isDestroyed()) return
    const ents = v.entities
    ents.suspendEvents()
    ents.removeAll()
    const { origins, targets, routes, live: arcs, focus, showAll } = props
    const maxRec = Math.max(1, ...origins.filter((o) => o.kind === 'attack').map((o) => o.records))
    const labelled = new Set([...origins].filter((o) => o.kind === 'attack').sort((a, b) => b.records - a.records).slice(0, 12).map((o) => o.id))
    const font = '600 12px Inter, "Inter Variable", system-ui, sans-serif'
    // state labels only once the camera is near enough that they do not pile up on India; country labels always
    const label = (text: string, color: string, dy = -12, near = false): Cesium.LabelGraphics.ConstructorOptions => ({
      text, font, fillColor: css(color), outlineColor: css('#000000', 0.9), outlineWidth: 3, style: Cesium.LabelStyle.FILL_AND_OUTLINE,
      pixelOffset: new Cesium.Cartesian2(0, dy), verticalOrigin: Cesium.VerticalOrigin.BOTTOM,
      translucencyByDistance: new Cesium.NearFarScalar(2.5e6, 1, 3e7, 0.6), disableDepthTestDistance: 0,
      distanceDisplayCondition: near ? new Cesium.DistanceDisplayCondition(0, 16_000_000) : undefined,
    })

    for (const o of origins) {
      const share = o.kind === 'attack' ? o.records / maxRec : 0.25
      const color = o.kind === 'attack' ? ATTACK : C2
      const name = countryName(o.cc)
      const lines = o.kind === 'attack'
        ? [`${o.ips} attacking IPs · ${o.records.toLocaleString('en-IN')} reports`, ...(o.network ? [o.network] : []), 'REAL · SANS ISC DShield, located by RIPEstat']
        : [o.note, 'REAL · abuse.ch Feodo Tracker']
      ents.add({
        id: o.id, position: deg(o.at, 0),
        point: { pixelSize: 5 + Math.sqrt(share) * 13, color: css(color, 0.92), outlineColor: css('#000000', 0.7), outlineWidth: 1.5 },
        label: labelled.has(o.id) || o.id === focus ? label(name, o.kind === 'attack' ? '#ffd6e3' : '#d6f1ff') : undefined,
        properties: { title: `${name} · ${o.kind === 'attack' ? 'attack source' : 'botnet C2'}`, lines, origin: o.id },
      })
    }
    for (const t of targets) {
      const color = t.compromise ? COMP : CRIT
      ents.add({
        id: `t-${t.state}`, position: deg(t.at, 0),
        point: { pixelSize: 5 + Math.min(6, t.critical * 0.8), color: css(color, 0.95), outlineColor: css('#ffffff', 0.9), outlineWidth: 1.5 },
        label: label(t.state, '#ffffff', -13, !t.compromise),
        properties: { title: t.state, target: t.at, state: t.state,
                      lines: [`${t.orgs.length} operator${t.orgs.length > 1 ? 's' : ''} · ${t.critical} Critical warnings${t.compromise ? ' · suspected compromise' : ''}`,
                              'SIM · operators and landing points are simulated'] },
      })
    }
    const lit = routes.filter((r) => (focus ? r.o.id === focus : showAll))
    for (const r of lit) {
      ents.add({
        id: `r-${r.o.id}-${r.t.state}`,
        polyline: { positions: [deg(r.o.at, 90_000), deg(r.t.at, 90_000)], width: focus ? 2.4 : 1.1, arcType: Cesium.ArcType.GEODESIC,
                    material: focus ? new Cesium.PolylineGlowMaterialProperty({ glowPower: 0.22, taperPower: 0.9, color: css(r.o.kind === 'attack' ? ATTACK : C2, 0.95) })
                                    : css(r.o.kind === 'attack' ? ATTACK : C2, 0.16) },
      })
    }
    for (const a of arcs) {
      if (!a.c2at) continue
      ents.add({
        id: `live-${a.id}`,
        polyline: { positions: [deg(a.at, 120_000), deg(a.c2at, 120_000)], width: 3.2, arcType: Cesium.ArcType.GEODESIC,
                    material: new Cesium.PolylineGlowMaterialProperty({ glowPower: 0.3, taperPower: 0.7, color: css(COMP, 1) }) },
      })
      ents.add({
        id: `live-c2-${a.id}`, position: deg(a.c2at, 0),
        point: { pixelSize: new Cesium.CallbackProperty(() => 7 + 5 * Math.abs(Math.sin(performance.now() / 420)), false) as unknown as number,
                 color: css(COMP, 0.95), outlineColor: css('#ffffff', 0.9), outlineWidth: 2 },
        label: label(`live C2 · ${a.c2}`, '#e6dcff', -14),
        properties: { title: a.title, lines: [`C2 ${a.c2}${a.c2cc ? ` in ${countryName(a.c2cc)}` : ''}`, 'REAL indicator (Feodo Tracker) · SIM sighting, detected live'] },
      })
    }
    // the projectile pool: a dozen moving points whose positions are computed per frame along the lit (or all) paths
    const pool = focus ? lit : showAll ? routes : routes
    shots.current = []
    const POOL = STILL() || !pool.length ? 0 : 12
    let nextLaunch = performance.now() + 300
    const geodesics = new Map<string, { g: Cesium.EllipsoidGeodesic; len: number }>()
    const geo = (r: Route) => {
      const k = `${r.o.id}>${r.t.state}`
      let g = geodesics.get(k)
      if (!g) {
        const eg = new Cesium.EllipsoidGeodesic(Cesium.Cartographic.fromDegrees(r.o.at[1], r.o.at[0]), Cesium.Cartographic.fromDegrees(r.t.at[1], r.t.at[0]))
        g = { g: eg, len: eg.surfaceDistance }
        geodesics.set(k, g)
      }
      return g
    }
    const launch = (slot: number, now: number) => {
      const r = pool[Math.floor(Math.random() * pool.length)]
      const { len } = geo(r)
      shots.current[slot] = { id: `shot-${slot}`, r, t0: now, dur: 1600 + len / 8000 + Math.random() * 1600 }
      nextLaunch = now + (focus ? 90 + Math.random() * 260 : 160 + Math.random() * 900)
    }
    const at = (r: Route, f: number) => {
      const c = geo(r).g.interpolateUsingFraction(Math.max(0, Math.min(1, f)))
      return Cesium.Cartesian3.fromRadians(c.longitude, c.latitude, 50_000)
    }
    const current = (slot: number): { r: Route; f: number } | undefined => {
      const now = performance.now()
      let s = shots.current[slot]
      if ((!s || now - s.t0 > s.dur) && now >= nextLaunch) { launch(slot, now); s = shots.current[slot] }
      if (!s || now - s.t0 > s.dur) return undefined
      const t = (now - s.t0) / s.dur
      return { r: s.r, f: t * t * (3 - 2 * t) }
    }
    const shotColor = (slot: number) => new Cesium.CallbackProperty(() => {
      const s = shots.current[slot]
      return css(s ? (s.r.o.kind === 'attack' ? ATTACK : C2) : '#000000', s ? 1 : 0)
    }, false) as unknown as Cesium.Color
    for (let i = 0; i < POOL; i++) {
      const slot = i
      ents.add({
        id: `shot-${slot}`,
        position: new Cesium.CallbackProperty(() => { const c = current(slot); return c ? at(c.r, c.f) : undefined }, false) as unknown as Cesium.Cartesian3,
        point: { pixelSize: 5, color: shotColor(slot), disableDepthTestDistance: 0 },
      })
      ents.add({
        id: `tail-${slot}`,
        polyline: {
          positions: new Cesium.CallbackProperty(() => {
            const c = current(slot)
            if (!c) return []
            const n = 14, back = Math.min(c.f, 0.22)
            const out: Cesium.Cartesian3[] = []
            for (let k = 0; k <= n; k++) out.push(at(c.r, c.f - back * (k / n)))  // head first, so the glow tapers toward the tail
            return out
          }, false) as unknown as Cesium.Cartesian3[],
          width: 3, arcType: Cesium.ArcType.NONE,
          material: new Cesium.PolylineGlowMaterialProperty({ glowPower: 0.35, taperPower: 0.5, color: shotColor(slot) }),
        },
      })
    }
    ents.resumeEvents()
    v.scene.requestRender()
  }, [props.origins, props.targets, props.routes, props.live, props.focus, props.showAll, props])

  return (
    <div className="relative h-full w-full bg-black">
      <div ref={box} className="h-full w-full [&_.cesium-widget]:h-full [&_.cesium-widget>canvas]:h-full [&_.cesium-widget>canvas]:w-full [&_.cesium-viewer]:h-full [&_.cesium-viewer-bottom]:hidden" />
      <div ref={credit} className="pointer-events-auto absolute bottom-1 right-2 z-10 max-w-[70%] text-[10px] leading-tight text-white/60 [&_a]:text-white/70 [&_img]:inline [&_img]:h-3 [&_img]:opacity-70" />
      {tip && (
        <div className="pointer-events-none absolute z-20 max-w-xs rounded-xl border border-white/15 bg-black/80 px-3 py-2 text-[12.5px] text-white shadow-xl backdrop-blur"
             style={{ left: Math.min(tip.x + 14, (box.current?.clientWidth ?? 600) - 260), top: Math.max(8, tip.y - 12) }}>
          <div className="font-semibold">{tip.title}</div>
          {tip.lines.map((l, i) => <div key={i} className={i === tip.lines.length - 1 ? 'mt-0.5 text-[11px] uppercase tracking-wide text-white/55' : 'text-white/80'}>{l}</div>)}
        </div>
      )}
    </div>
  )
}
