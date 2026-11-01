import { ArrowLeft, ArrowUpRight, Navigation } from 'lucide-react'
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
import type { OrgProfile } from '../../api'
import { compact, countryName } from '../kit'
import { campusFor, campusSpots, type BuildingSpec } from './campus'
import { ATTACK, bearing, C2, COMP, isGov, snapshotLabel, spreadBearings, type Origin, type OrgRow, type Target } from './data'
import { Flag } from './flags'

/* The 3D site view (ui-08, SIM): click a target state on the map and the card flies into it. The government agencies
   and public-sector bodies there each get a small campus of labelled buildings that fit their sector; incoming
   attacks arc in from the horizon in the real direction of each attack origin (great-circle bearing from the state)
   and strike the internet-facing building; a suspected compromise beacons straight up to its C2. Operators and
   buildings are simulated; the attack sources are real. Reduced motion: no orbit, nothing in flight, the incoming
   paths drawn still. No WebGL: the same agencies and buildings as a list. */

type Status = 'attack' | 'comp' | 'quiet'
interface Bld extends BuildingSpec { key: string; org: OrgRow; wx: number; wz: number; status: Status }
interface Campus { org: OrgRow; at: { x: number; z: number }; blds: Bld[] }
interface Horizon { o: Origin; b: number }

const STATUS: Record<Status, { label: string; cls: string; dot: string }> = {
  attack: { label: 'Under attack', cls: 'bg-[#e5383b]/20 text-[#ff8a87]', dot: '#e5383b' },
  comp: { label: 'Suspected compromise', cls: 'bg-[#8a63e8]/25 text-[#c4b0ff]', dot: COMP },
  quiet: { label: 'Quiet', cls: 'bg-white/10 text-[#c8c8ce]', dot: '#8e8e96' },
}
const SHORT_SECTOR: Record<string, string> = {
  'Power & Energy': 'Power', Transport: 'Transport', Government: 'Government', 'Strategic & Public Enterprises': 'Strategic PSU',
}
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`
const agencies = (n: number) => plural(n, 'government agency', 'government agencies')

function hasWebGL(): boolean {
  try {
    const c = document.createElement('canvas')
    return !!(c.getContext('webgl2') || c.getContext('webgl'))
  } catch { return false }
}

function useProfiles(ids: string[]): Record<string, OrgProfile> {
  const [m, setM] = useState<Record<string, OrgProfile>>({})
  const key = ids.join(',')
  useEffect(() => {
    let alive = true
    for (const id of key ? key.split(',') : []) {
      fetch(`/api/orgs/${encodeURIComponent(id)}/profile`)
        .then((r) => (r.ok ? (r.json() as Promise<OrgProfile>) : null))
        .then((p) => { if (alive && p) setM((s) => ({ ...s, [id]: p })) })
        .catch(() => { /* the labels keep their roles without exposure lines */ })
    }
    return () => { alive = false }
  }, [key])
  return m
}

/** The top internet-facing assets of an operator, for its internet-edge label. */
function exposures(p: OrgProfile | undefined, n = 2): string[] {
  if (!p) return []
  return p.surface.exposed.filter((e) => e.zone === 'internet')
    .sort((a, b) => b.open_high - a.open_high || b.worst - a.worst).slice(0, n)
    .map((e) => `${e.hostname} · ${e.product} ${e.version} · ${e.open_high} open High`)
}
function beaconLine(p: OrgProfile | undefined): string | undefined {
  const s = p?.indicators.c2_sightings[0]
  return s ? `C2 beacon · ${s.malware} → ${s.c2}` : undefined
}

function buildLayout(gov: OrgRow[]): Campus[] {
  const spots = campusSpots(gov.length)
  return gov.map((org, i) => {
    const specs = campusFor(org.sector)
    const beacon = org.compromise > 0 ? (specs.find((b) => b.kind === 'dc') ?? specs[0]).role : undefined
    return {
      org, at: spots[i],
      blds: specs.map((b) => ({
        ...b, key: `${org.id}|${b.role}`, org, wx: spots[i].x + b.x, wz: spots[i].z + b.z,
        status: b.kind === 'edge' ? 'attack' : b.role === beacon ? 'comp' : 'quiet',
      })),
    }
  })
}

// --- three.js helpers ----------------------------------------------------------------------------------------------
function windowCanvas(kind: 'office' | 'edge' | 'dc', seed: number): HTMLCanvasElement {
  let r = seed * 9301 + 49297
  const rnd = () => { r = (r * 9301 + 49297) % 233280; return r / 233280 }
  const c = document.createElement('canvas')
  c.width = 256
  c.height = 512
  const g = c.getContext('2d')!
  g.fillStyle = '#000'
  g.fillRect(0, 0, 256, 512)
  if (kind === 'dc') {
    for (let y = 0; y < 512; y += 16) { g.fillStyle = '#0d0f13'; g.fillRect(0, y + 9, 256, 3) }
    for (let i = 0; i < 70; i++) {
      g.fillStyle = rnd() < 0.6 ? '#2fe38a' : '#4f9dff'
      g.globalAlpha = 0.5 + rnd() * 0.5
      g.fillRect(Math.floor(rnd() * 60) * 4 + 6, Math.floor(rnd() * 32) * 16 + 4, 3, 2)
    }
    g.globalAlpha = 1
  } else {
    const lit = kind === 'edge' ? 0.55 : 0.42
    for (let row = 0; row < 16; row++) for (let col = 0; col < 8; col++) {
      const x = col * 32 + 5, y = row * 32 + 7
      if (rnd() < lit) {
        const warm = rnd() < (kind === 'edge' ? 0.25 : 0.6)
        g.fillStyle = warm ? '#ffd29a' : '#b7d3ff'
        g.globalAlpha = 0.45 + rnd() * 0.55
      } else {
        g.fillStyle = '#1a1d24'
        g.globalAlpha = 1
      }
      g.fillRect(x, y, 22, 17)
    }
    g.globalAlpha = 1
    g.fillStyle = '#07080a'
    for (let col = 0; col <= 8; col++) g.fillRect(col * 32, 0, 2, 512)
  }
  return c
}

const POINT_VS = `
  attribute float asize; attribute vec3 acolor; varying vec3 vColor; uniform float scale;
  void main() { vColor = acolor; vec4 mv = modelViewMatrix * vec4(position, 1.0);
    gl_PointSize = asize * scale / max(1.0, -mv.z); gl_Position = projectionMatrix * mv; }`
const POINT_FS = `
  varying vec3 vColor;
  void main() { float d = length(gl_PointCoord - 0.5); float a = smoothstep(0.5, 0.0, d); a *= a;
    if (a < 0.01) discard; gl_FragColor = vec4(vColor * a, a); }`
const BEAM_VS = `varying vec2 vUv; void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`
const BEAM_FS = `
  uniform vec3 color; uniform float time; varying vec2 vUv;
  void main() { float t = vUv.y; float fade = pow(1.0 - t, 1.5);
    float f = fract(t * 7.0 - time * 0.8); float band = smoothstep(0.0, 0.03, f) * smoothstep(0.14, 0.03, f);
    float a = fade * (0.28 + 0.95 * band); gl_FragColor = vec4(color * a, a); }`

const HIT = new THREE.Color(0xff3b30)
interface Missile { on: boolean; o?: Origin; S: THREE.Vector3; Q: THREE.Vector3; E: THREE.Vector3; t0: number; dur: number; col: THREE.Color; b?: number }
interface Ring { mesh: THREE.Mesh; mat: THREE.MeshBasicMaterial; on: boolean; t0: number; dur: number; r0: number; r1: number; a: number }

// --- the scene -------------------------------------------------------------------------------------------------------
function Scene({ target, layout, origins, focus, profiles, reduced, onOrg, onFail }: {
  target: Target; layout: Campus[]; origins: Origin[]; focus?: string; profiles: Record<string, OrgProfile>; reduced: boolean
  onOrg: (id: string) => void; onFail: () => void
}) {
  const box = useRef<HTMLDivElement>(null)
  const compass = useRef<HTMLDivElement>(null)
  const labelsBox = useRef<HTMLDivElement>(null)
  const els = useRef(new Map<string, HTMLDivElement>())
  const sizes = useRef(new Map<string, { w: number; h: number }>())
  const [selected, setSelected] = useState<string>()
  const [narrow, setNarrow] = useState(false)
  const horizons = useMemo<Horizon[]>(() => spreadBearings(origins.map((o) => ({ o, b: bearing(target.at, o.at) }))), [origins, target])
  const live = useRef({ focus, horizons, reduced })
  live.current = { focus, horizons, reduced }
  const staticPaths = useRef<(h: Horizon[]) => void>(() => {})
  const blds = useMemo(() => layout.flatMap((c) => c.blds), [layout])

  // measure the labels once they render (the loop places them without touching layout)
  useLayoutEffect(() => {
    for (const [k, el] of els.current) {
      const card = el.querySelector<HTMLElement>('[data-card]')
      if (card) sizes.current.set(k, { w: card.offsetWidth, h: card.offsetHeight })
    }
  })

  useEffect(() => { staticPaths.current(horizons) }, [horizons])

  useEffect(() => {
    const host = box.current!
    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: 'high-performance' })
    } catch {
      onFail()
      return
    }
    const trash: { dispose(): void }[] = []
    const keep = <T extends { dispose(): void }>(x: T) => { trash.push(x); return x }
    renderer.setPixelRatio(Math.min(2, window.devicePixelRatio || 1))
    renderer.setClearColor(0x050506, 1)
    const cv = renderer.domElement
    cv.className = 'absolute inset-0 h-full w-full'
    cv.setAttribute('role', 'img')
    cv.setAttribute('aria-label', `Simulated 3D site view of ${target.state}: ${layout.map((c) => `${c.org.name} (${c.org.sector}), buildings: ${c.blds.map((b) => `${b.role}, ${STATUS[b.status].label}`).join('; ')}`).join('. ')}.`)
    host.prepend(cv)

    const scene = new THREE.Scene()
    scene.fog = new THREE.FogExp2(0x050506, 0.0021)
    const camera = new THREE.PerspectiveCamera(38, 1, 1, 5000)
    const controls = new OrbitControls(camera, cv)
    controls.enabled = false
    controls.enableDamping = true
    controls.dampingFactor = 0.08
    controls.enablePan = false
    controls.minPolarAngle = 0.12
    controls.maxPolarAngle = 1.33
    controls.autoRotateSpeed = 0.55
    const span = layout.length <= 1 ? 1 : layout.length === 2 ? 1.45 : 1.75
    const R_END = 150 * span
    controls.minDistance = 70
    controls.maxDistance = R_END * 2.2
    const look = new THREE.Vector3(0, 20, 0)
    controls.target.copy(look)

    // light: moonlight, a cool sky, and one red light that flares where a hit lands
    scene.add(new THREE.HemisphereLight(0x8ea4d8, 0x050506, 1.1))
    const moon = new THREE.DirectionalLight(0xcfdcff, 1.5)
    moon.position.set(-180, 260, 140)
    scene.add(moon)
    const flare = new THREE.PointLight(0xff3b30, 0, 160, 1.6)
    scene.add(flare)

    // ground, grid, roads, street lights
    const ground = new THREE.Mesh(keep(new THREE.PlaneGeometry(6000, 6000)), keep(new THREE.MeshStandardMaterial({ color: 0x07080b, roughness: 1 })))
    ground.rotation.x = -Math.PI / 2
    scene.add(ground)
    const grid = new THREE.GridHelper(1600, 80, 0x20242c, 0x14171c)
    grid.position.y = 0.03
    const gm = grid.material as THREE.LineBasicMaterial
    gm.transparent = true
    gm.opacity = 0.7
    keep(grid.geometry)
    keep(gm)
    scene.add(grid)

    const roadMat = keep(new THREE.MeshStandardMaterial({ color: 0x101217, roughness: 0.95 }))
    const dashMat = keep(new THREE.MeshBasicMaterial({ color: 0x3b3f49 }))
    const lampPos: number[] = []
    const road = (x: number, z: number, len: number, along: 'x' | 'z', w = 9) => {
      const m = new THREE.Mesh(keep(new THREE.PlaneGeometry(along === 'x' ? len : w, along === 'x' ? w : len)), roadMat)
      m.rotation.x = -Math.PI / 2
      m.position.set(x, 0.05, z)
      scene.add(m)
      const n = Math.floor(len / 12)
      const dash = keep(new THREE.PlaneGeometry(along === 'x' ? 5 : 0.5, along === 'x' ? 0.5 : 5))
      for (let i = 0; i < n; i++) {
        const d = new THREE.Mesh(dash, dashMat)
        d.rotation.x = -Math.PI / 2
        const o = -len / 2 + 6 + i * 12
        d.position.set(along === 'x' ? x + o : x, 0.08, along === 'x' ? z : z + o)
        scene.add(d)
      }
      for (let o = -len / 2; o <= len / 2; o += 26) {
        if (along === 'x') lampPos.push(x + o, 7, z + w / 2 + 1.5, x + o + 13, 7, z - w / 2 - 1.5)
        else lampPos.push(x + w / 2 + 1.5, 7, z + o, x - w / 2 - 1.5, 7, z + o + 13)
      }
    }
    const xs = layout.map((c) => c.at.x), zs = layout.map((c) => c.at.z)
    const minX = Math.min(...xs) - 52, maxX = Math.max(...xs) + 52, maxZ = Math.max(...zs) + 52, minZ = Math.min(...zs) - 52
    road((minX + maxX) / 2, maxZ, 1400, 'x', 11)
    road(minX, (minZ + maxZ) / 2, 1400, 'z', 11)
    road(maxX, (minZ + maxZ) / 2, 1400, 'z', 9)
    road((minX + maxX) / 2, minZ, maxX - minX, 'x', 9)
    for (const c of layout) {
      if (c.at.x - 52 > minX + 1 && c.at.x - 52 < maxX - 1) road(c.at.x - 52, c.at.z, 104, 'z', 9)
    }

    // the campuses
    const texCache = new Map<string, THREE.CanvasTexture>()
    const sideMat = (kind: 'office' | 'edge' | 'dc', variant: number, cols: number, rows: number, intensity: number) => {
      const id = `${kind}${variant}`
      let base = texCache.get(id)
      if (!base) { base = keep(new THREE.CanvasTexture(windowCanvas(kind, variant + 3))); base.colorSpace = THREE.SRGBColorSpace; texCache.set(id, base) }
      const t = keep(base.clone())
      t.wrapS = t.wrapT = THREE.RepeatWrapping
      t.repeat.set(Math.max(0.25, cols / 8), Math.max(0.12, rows / 16))
      t.anisotropy = 4
      t.needsUpdate = true
      return keep(new THREE.MeshStandardMaterial({ color: 0x15181e, roughness: 0.78, metalness: 0.3, emissive: 0xffffff, emissiveMap: t, emissiveIntensity: intensity }))
    }
    const roofMat = keep(new THREE.MeshStandardMaterial({ color: 0x1b1e25, roughness: 0.9, metalness: 0.1 }))
    const detailMat = keep(new THREE.MeshStandardMaterial({ color: 0x2a2e37, roughness: 0.7, metalness: 0.4 }))
    const glassMat = keep(new THREE.MeshStandardMaterial({ color: 0x0b1626, emissive: 0x3d7bd9, emissiveIntensity: 0.55, roughness: 0.2, metalness: 0.6 }))
    const redLight = keep(new THREE.MeshBasicMaterial({ color: 0xff2a2a }))
    const lobbyMat = keep(new THREE.MeshBasicMaterial({ color: 0x9fc2ff, transparent: true, opacity: 0.55 }))

    interface Live { b: Bld; edge: THREE.LineBasicMaterial; base: THREE.Color; sides: THREE.MeshStandardMaterial[]; flash: number; top: THREE.Vector3 }
    const built: Live[] = []
    const blinkers: THREE.Mesh[] = []
    const beams: THREE.ShaderMaterial[] = []
    const beaconRings: { x: number; z: number }[] = []
    layout.forEach((c, ci) => {
      const comp = c.org.compromise > 0
      const plate = new THREE.Mesh(keep(new THREE.PlaneGeometry(88, 88)), keep(new THREE.MeshStandardMaterial({ color: 0x0c0e12, roughness: 1 })))
      plate.rotation.x = -Math.PI / 2
      plate.position.set(c.at.x, 0.07, c.at.z)
      scene.add(plate)
      const fence = new THREE.LineLoop(keep(new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(-43, 0, -43), new THREE.Vector3(43, 0, -43), new THREE.Vector3(43, 0, 43), new THREE.Vector3(-43, 0, 43),
      ])), keep(new THREE.LineBasicMaterial({ color: comp ? COMP : 0x2c313b, transparent: true, opacity: comp ? 0.9 : 0.8 })))
      fence.position.set(c.at.x, 0.15, c.at.z)
      scene.add(fence)
      for (const b of c.blds) {
        const kind = b.kind === 'dc' ? 'dc' : b.kind === 'edge' ? 'edge' : 'office'
        const rows = b.h / 3.6
        const mx = sideMat(kind, ci * 4 + (b.kind === 'tower' ? 0 : 1), b.d / 4, rows, kind === 'dc' ? 1.3 : 0.95)
        const mz = sideMat(kind, ci * 4 + (b.kind === 'tower' ? 2 : 3), b.w / 4, rows, kind === 'dc' ? 1.3 : 0.95)
        const geo = keep(new THREE.BoxGeometry(b.w, b.h, b.d))
        geo.translate(0, b.h / 2, 0)
        const mesh = new THREE.Mesh(geo, [mx, mx, roofMat, roofMat, mz, mz])
        mesh.position.set(b.wx, 0, b.wz)
        scene.add(mesh)
        const baseEdge = new THREE.Color(b.status === 'comp' ? COMP : b.status === 'attack' ? 0x6b7282 : 0x434957)
        const edgeMat = keep(new THREE.LineBasicMaterial({ color: baseEdge.clone(), transparent: true, opacity: 0.95 }))
        const edges = new THREE.LineSegments(keep(new THREE.EdgesGeometry(geo)), edgeMat)
        edges.position.copy(mesh.position)
        scene.add(edges)
        // a lit lobby band at street level
        const lobby = new THREE.Mesh(keep(new THREE.BoxGeometry(b.w + 0.4, 1.2, b.d + 0.4)), lobbyMat)
        lobby.position.set(b.wx, 1.4, b.wz)
        scene.add(lobby)
        // rooftop detail by kind
        const add = (g: THREE.BufferGeometry, m: THREE.Material, x: number, y: number, z: number) => {
          const o = new THREE.Mesh(keep(g), m)
          o.position.set(b.wx + x, y, b.wz + z)
          scene.add(o)
          return o
        }
        if (b.kind === 'tower') {
          add(new THREE.BoxGeometry(b.w * 0.5, 4, b.d * 0.5), detailMat, 0, b.h + 2, 0)
          add(new THREE.CylinderGeometry(0.25, 0.25, 12, 6), detailMat, 0, b.h + 10, 0)
          blinkers.push(add(new THREE.SphereGeometry(0.7, 10, 8), redLight, 0, b.h + 16.4, 0))
        } else if (b.kind === 'dc') {
          for (let i = 0; i < 4; i++) add(new THREE.BoxGeometry(3.6, 2.2, 3.6), detailMat, -b.w / 2 + 4 + i * ((b.w - 8) / 3), b.h + 1.1, -b.d / 4)
          add(new THREE.BoxGeometry(b.w * 0.7, 1.6, 2.4), detailMat, 0, b.h + 0.8, b.d / 4)
        } else if (b.kind === 'edge') {
          add(new THREE.CylinderGeometry(0.35, 0.5, 16, 8), detailMat, b.w / 4, b.h + 8, -b.d / 4)
          const dish = add(new THREE.SphereGeometry(2.6, 16, 8, 0, Math.PI * 2, 0, Math.PI / 2.6), detailMat, -b.w / 5, b.h + 2.6, b.d / 5)
          dish.rotation.x = Math.PI * 0.75
          blinkers.push(add(new THREE.SphereGeometry(0.55, 10, 8), redLight, b.w / 4, b.h + 16.4, -b.d / 4))
        } else if (b.kind === 'design') {
          add(new THREE.BoxGeometry(b.w * 0.6, 3, b.d * 0.5), glassMat, 0, b.h + 1.5, 0)
        } else {
          add(new THREE.BoxGeometry(b.w * 0.35, 3, b.d * 0.4), detailMat, -b.w / 5, b.h + 1.5, 0)
          const dish = add(new THREE.SphereGeometry(2, 14, 8, 0, Math.PI * 2, 0, Math.PI / 2.6), detailMat, b.w / 4, b.h + 2, 0)
          dish.rotation.x = Math.PI * 0.7
        }
        if (b.status === 'comp') {
          const beam = keep(new THREE.ShaderMaterial({
            uniforms: { color: { value: new THREE.Color(COMP) }, time: { value: 0 } }, vertexShader: BEAM_VS, fragmentShader: BEAM_FS,
            transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide,
          }))
          const g = keep(new THREE.CylinderGeometry(1.4, 2.2, 360, 20, 1, true))
          g.translate(0, 180, 0)
          const m = new THREE.Mesh(g, beam)
          m.position.set(b.wx, b.h, b.wz)
          scene.add(m)
          beams.push(beam)
          beaconRings.push({ x: b.wx, z: b.wz })
        }
        built.push({ b, edge: edgeMat, base: baseEdge, sides: [mx, mz], flash: 0, top: new THREE.Vector3(b.wx, b.h, b.wz) })
      }
    })

    // street lights: one glow point each
    const glowMat = (scale: number) => keep(new THREE.ShaderMaterial({
      uniforms: { scale: { value: scale } }, vertexShader: POINT_VS, fragmentShader: POINT_FS,
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    }))
    const lampGeo = keep(new THREE.BufferGeometry())
    lampGeo.setAttribute('position', new THREE.Float32BufferAttribute(lampPos, 3))
    lampGeo.setAttribute('asize', new THREE.Float32BufferAttribute(new Array(lampPos.length / 3).fill(5), 1))
    lampGeo.setAttribute('acolor', new THREE.Float32BufferAttribute(Array.from({ length: lampPos.length / 3 }, () => [1.0, 0.72, 0.42]).flat(), 3))
    const lampMat = glowMat(1)
    scene.add(new THREE.Points(lampGeo, lampMat))

    // rings: impact shockwaves, beacon pulses, a slow radar sweep
    const ringGeo = keep(new THREE.RingGeometry(0.9, 1, 72))
    ringGeo.rotateX(-Math.PI / 2)
    const rings: Ring[] = Array.from({ length: 22 }, () => {
      const mat = keep(new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide }))
      const mesh = new THREE.Mesh(ringGeo, mat)
      mesh.visible = false
      scene.add(mesh)
      return { mesh, mat, on: false, t0: 0, dur: 1, r0: 1, r1: 2, a: 1 }
    })
    const ring = (x: number, y: number, z: number, col: THREE.ColorRepresentation, r0: number, r1: number, dur: number, a: number, now: number) => {
      const r = rings.find((q) => !q.on) ?? rings[0]
      r.on = true
      r.t0 = now
      r.dur = dur
      r.r0 = r0
      r.r1 = r1
      r.a = a
      r.mat.color.set(col)
      r.mesh.position.set(x, y, z)
      r.mesh.visible = true
    }

    // missiles: one Points cloud for every head and trail, one for impact flashes
    const POOL = 18, TRAIL = 48, STEP = 0.0034
    const mPos = new Float32Array(POOL * TRAIL * 3), mCol = new Float32Array(POOL * TRAIL * 3), mSize = new Float32Array(POOL * TRAIL)
    const mGeo = keep(new THREE.BufferGeometry())
    mGeo.setAttribute('position', new THREE.BufferAttribute(mPos, 3))
    mGeo.setAttribute('acolor', new THREE.BufferAttribute(mCol, 3))
    mGeo.setAttribute('asize', new THREE.BufferAttribute(mSize, 1))
    const mMat = glowMat(1)
    const mPts = new THREE.Points(mGeo, mMat)
    mPts.frustumCulled = false
    scene.add(mPts)
    // a thin bright core under the glow, so a trail reads as one streak
    const SEG = TRAIL - 1
    const lPos = new Float32Array(POOL * SEG * 6), lCol = new Float32Array(POOL * SEG * 6)
    const lGeo = keep(new THREE.BufferGeometry())
    lGeo.setAttribute('position', new THREE.BufferAttribute(lPos, 3))
    lGeo.setAttribute('color', new THREE.BufferAttribute(lCol, 3))
    const lMat = keep(new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending }))
    const lSegs = new THREE.LineSegments(lGeo, lMat)
    lSegs.frustumCulled = false
    scene.add(lSegs)
    const FL = 12
    const fPos = new Float32Array(FL * 3), fCol = new Float32Array(FL * 3), fSize = new Float32Array(FL)
    const fGeo = keep(new THREE.BufferGeometry())
    fGeo.setAttribute('position', new THREE.BufferAttribute(fPos, 3))
    fGeo.setAttribute('acolor', new THREE.BufferAttribute(fCol, 3))
    fGeo.setAttribute('asize', new THREE.BufferAttribute(fSize, 1))
    const fMat = glowMat(1)
    const fPts = new THREE.Points(fGeo, fMat)
    fPts.frustumCulled = false
    scene.add(fPts)
    const flashes = Array.from({ length: FL }, () => ({ on: false, t0: 0, p: new THREE.Vector3() }))

    const missiles: Missile[] = Array.from({ length: POOL }, () => ({ on: false, S: new THREE.Vector3(), Q: new THREE.Vector3(), E: new THREE.Vector3(), t0: 0, dur: 1, col: new THREE.Color() }))
    const edgeIdx = built.map((x, i) => (x.b.kind === 'edge' ? i : -1)).filter((i) => i >= 0)
    const dirOf = (b: number) => new THREE.Vector3(Math.sin((b * Math.PI) / 180), 0, -Math.cos((b * Math.PI) / 180))
    const bez = (m: Missile, t: number, out: THREE.Vector3) => {
      const u = 1 - t
      return out.set(0, 0, 0).addScaledVector(m.S, u * u).addScaledVector(m.Q, 2 * u * t).addScaledVector(m.E, t * t)
    }
    const launch = (now: number) => {
      const hz = live.current.horizons.filter((h) => !live.current.focus || h.o.id === live.current.focus)
      if (!hz.length || !edgeIdx.length) return
      const m = missiles.find((q) => !q.on)
      if (!m) return
      const h = hz[Math.floor(Math.random() * hz.length)]
      const bi = edgeIdx[Math.floor(Math.random() * edgeIdx.length)]
      const tb = built[bi]
      const dir = dirOf(h.b)
      const side = new THREE.Vector3(-dir.z, 0, dir.x)
      m.S.copy(dir).multiplyScalar(300 + Math.random() * 90).addScaledVector(side, (Math.random() - 0.5) * 140)
      m.S.y = 80 + Math.random() * 70
      m.E.set(tb.b.wx + (Math.random() - 0.5) * tb.b.w * 0.6, tb.b.h + 0.4, tb.b.wz + (Math.random() - 0.5) * tb.b.d * 0.6)
      m.Q.copy(m.S).add(m.E).multiplyScalar(0.5)
      m.Q.y += 40 + m.S.distanceTo(m.E) * 0.12
      m.t0 = now
      m.dur = 2000 + Math.random() * 1600
      m.col.set(h.o.kind === 'attack' ? ATTACK : '#64d2ff')
      m.o = h.o
      m.b = bi
      m.on = true
    }
    const impact = (m: Missile, now: number) => {
      const tb = built[m.b!]
      tb.flash = 1
      flare.position.set(m.E.x, m.E.y + 8, m.E.z)
      flare.intensity = 9000
      ring(m.E.x, m.E.y + 0.3, m.E.z, m.col, 1.5, 16, 650, 0.95, now)
      ring(tb.b.wx, 0.25, tb.b.wz, 0xff4d4d, Math.max(tb.b.w, tb.b.d) * 0.6, Math.max(tb.b.w, tb.b.d) * 2.2, 1100, 0.6, now)
      const f = flashes.find((q) => !q.on) ?? flashes[0]
      f.on = true
      f.t0 = now
      f.p.copy(m.E)
    }

    // reduced motion: the incoming paths drawn still, one per origin to each internet edge
    let pathGroup: THREE.Group | undefined
    const drawStatic = (hz: Horizon[]) => {
      if (pathGroup) {
        scene.remove(pathGroup)
        pathGroup.traverse((o) => { if (o instanceof THREE.Line) { o.geometry.dispose(); (o.material as THREE.Material).dispose() } })
        pathGroup = undefined
      }
      if (!live.current.reduced) return
      pathGroup = new THREE.Group()
      const tmp: Missile = { on: true, S: new THREE.Vector3(), Q: new THREE.Vector3(), E: new THREE.Vector3(), t0: 0, dur: 1, col: new THREE.Color() }
      for (const h of hz) for (const bi of edgeIdx) {
        const tb = built[bi]
        tmp.S.copy(dirOf(h.b)).multiplyScalar(340)
        tmp.S.y = 110
        tmp.E.set(tb.b.wx, tb.b.h + 0.4, tb.b.wz)
        tmp.Q.copy(tmp.S).add(tmp.E).multiplyScalar(0.5)
        tmp.Q.y += 40 + tmp.S.distanceTo(tmp.E) * 0.12
        const pts = Array.from({ length: 49 }, (_, i) => bez(tmp, i / 48, new THREE.Vector3()))
        pathGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
          new THREE.LineBasicMaterial({ color: h.o.kind === 'attack' ? ATTACK : C2, transparent: true, opacity: 0.55 })))
      }
      scene.add(pathGroup)
    }
    staticPaths.current = drawStatic
    drawStatic(live.current.horizons)

    // size, visibility
    let W = 1, H = 1
    const fit = () => {
      W = Math.max(1, host.clientWidth)
      H = Math.max(1, host.clientHeight)
      renderer.setSize(W, H, false)
      camera.aspect = W / H
      camera.updateProjectionMatrix()
      const sc = (H * renderer.getPixelRatio()) / (2 * Math.tan((camera.fov * Math.PI) / 360))
      for (const m of [lampMat, mMat, fMat]) m.uniforms.scale.value = sc
      setNarrow(W < 640)
    }
    fit()
    const ro = new ResizeObserver(fit)
    ro.observe(host)
    let visible = true
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting })
    io.observe(host)

    // camera: straight down first (where the 2D map left off), then tilt and orbit
    const POLAR = THREE.MathUtils.degToRad(54)
    const startCam = () => camera.position.setFromSphericalCoords(R_END * 2.3, 0.0015, 0).add(look)
    if (reduced) {
      camera.position.setFromSphericalCoords(R_END, POLAR, THREE.MathUtils.degToRad(-18)).add(look)
      controls.enabled = true
      controls.update()
    } else startCam()
    camera.lookAt(look)
    let introT0 = performance.now() + 120
    let introDone = reduced
    let nextLaunch = performance.now() + 900
    let last = performance.now()
    let radarT0 = performance.now()
    const v = new THREE.Vector3()
    const tmpV = new THREE.Vector3()
    const place = new Map<string, { dx: number; lift: number }>()
    const shown = new Map<string, { dx: number; lift: number }>()
    let raf = 0

    const frame = (now: number) => {
      raf = requestAnimationFrame(frame)
      if (!visible || document.hidden) { last = now; return }
      const gap = now - last
      last = now
      if (gap > 120) {
        // the tab or card was away: shift every clock so nothing jumps
        const d = gap - 16
        introT0 += d
        nextLaunch += d
        radarT0 += d
        for (const m of missiles) m.t0 += d
        for (const r of rings) r.t0 += d
        for (const f of flashes) f.t0 += d
      }
      const motion = !live.current.reduced

      if (!introDone) {
        const u = Math.min(1, Math.max(0, (now - introT0) / 2300))
        const e = u < 0.5 ? 4 * u * u * u : 1 - (-2 * u + 2) ** 3 / 2
        camera.position.setFromSphericalCoords(R_END * (2.3 - 1.3 * e), 0.0015 + (POLAR - 0.0015) * e, THREE.MathUtils.degToRad(-18) * e).add(look)
        camera.lookAt(look)
        if (u >= 1) {
          introDone = true
          if (labelsBox.current) labelsBox.current.style.opacity = '1'
          controls.enabled = true
          controls.autoRotate = motion
          controls.update()
        }
      } else {
        controls.autoRotate = motion
        controls.update()
      }

      // missiles
      if (motion && introDone && now >= nextLaunch) {
        launch(now)
        nextLaunch = now + (live.current.focus ? 260 : 380) + Math.random() * 900
      }
      let k = 0
      lCol.fill(0)
      missiles.forEach((m, mi) => {
        if (m.on && m.o && live.current.focus && m.o.id !== live.current.focus) m.on = false
        if (m.on && now - m.t0 >= m.dur) { m.on = false; impact(m, now) }
        if (!m.on || !motion) {
          for (let i = 0; i < TRAIL; i++, k++) mSize[k] = 0
          return
        }
        const t = Math.max(0, (now - m.t0) / m.dur)
        const e = t ** 1.15
        const born = Math.min(1, t / 0.12)
        const k0 = k
        for (let i = 0; i < TRAIL; i++, k++) {
          const tt = Math.max(0, e - i * STEP)
          bez(m, tt, tmpV)
          mPos[k * 3] = tmpV.x
          mPos[k * 3 + 1] = tmpV.y
          mPos[k * 3 + 2] = tmpV.z
          const fade = (1 - i / TRAIL) ** 1.4
          if (i === 0) {
            mCol[k * 3] = born; mCol[k * 3 + 1] = born; mCol[k * 3 + 2] = born
            mSize[k] = 10
          } else {
            mCol[k * 3] = m.col.r * fade * 0.85 * born
            mCol[k * 3 + 1] = m.col.g * fade * 0.85 * born
            mCol[k * 3 + 2] = m.col.b * fade * 0.85 * born
            mSize[k] = tt === 0 ? 0 : 1 + 5.5 * fade
          }
        }
        for (let i = 0; i < SEG; i++) {
          const a = (k0 + i) * 3, b = (k0 + i + 1) * 3, o = (mi * SEG + i) * 6
          lPos[o] = mPos[a]; lPos[o + 1] = mPos[a + 1]; lPos[o + 2] = mPos[a + 2]
          lPos[o + 3] = mPos[b]; lPos[o + 4] = mPos[b + 1]; lPos[o + 5] = mPos[b + 2]
          if (mSize[(k0 + i + 1)] === 0) continue
          const f0 = born * (1 - i / SEG) ** 1.2, f1 = born * (1 - (i + 1) / SEG) ** 1.2
          const w0 = i === 0 ? 0.6 * born : 0
          lCol[o] = Math.min(1, m.col.r * f0 + w0); lCol[o + 1] = Math.min(1, m.col.g * f0 + w0); lCol[o + 2] = Math.min(1, m.col.b * f0 + w0)
          lCol[o + 3] = m.col.r * f1; lCol[o + 4] = m.col.g * f1; lCol[o + 5] = m.col.b * f1
        }
      })
      lGeo.attributes.position.needsUpdate = true
      lGeo.attributes.color.needsUpdate = true
      mGeo.attributes.position.needsUpdate = true
      mGeo.attributes.acolor.needsUpdate = true
      mGeo.attributes.asize.needsUpdate = true
      flashes.forEach((f, i) => {
        const t = (now - f.t0) / 380
        if (!f.on || t >= 1) { f.on = false; fSize[i] = 0; return }
        fPos[i * 3] = f.p.x; fPos[i * 3 + 1] = f.p.y + 1; fPos[i * 3 + 2] = f.p.z
        fCol[i * 3] = 1; fCol[i * 3 + 1] = 0.55 * (1 - t) + 0.3; fCol[i * 3 + 2] = 0.4 * (1 - t)
        fSize[i] = 46 * (1 - t) ** 0.6
      })
      fGeo.attributes.position.needsUpdate = true
      fGeo.attributes.acolor.needsUpdate = true
      fGeo.attributes.asize.needsUpdate = true

      // rings, beacons, hit flashes, blinkers, radar
      for (const r of rings) {
        if (!r.on) continue
        const t = (now - r.t0) / r.dur
        if (t >= 1) { r.on = false; r.mesh.visible = false; continue }
        const e = 1 - (1 - t) ** 3
        const s = r.r0 + (r.r1 - r.r0) * e
        r.mesh.scale.set(s, 1, s)
        r.mat.opacity = r.a * (1 - t)
      }
      if (motion && Math.floor(now / 1400) !== Math.floor((now - gap) / 1400)) {
        for (const b of beaconRings) ring(b.x, 0.3, b.z, COMP, 8, 30, 1300, 0.8, now)
      }
      if (motion && now - radarT0 > 5200) { radarT0 = now; ring(0, 0.2, 0, 0x4f8cf7, 4, 420, 4200, 0.35, now) }
      for (const bm of beams) bm.uniforms.time.value = motion ? now / 1000 : 0
      for (const x of built) {
        if (x.flash > 0.002) {
          x.flash *= Math.pow(0.9, gap / 16.7)
          x.edge.color.copy(x.base).lerp(HIT, Math.min(1, x.flash * 1.3))
          for (const s of x.sides) s.emissive.setRGB(1, 1 - 0.75 * x.flash, 1 - 0.8 * x.flash)
        } else if (x.flash !== 0) {
          x.flash = 0
          x.edge.color.copy(x.base)
          for (const s of x.sides) s.emissive.setRGB(1, 1, 1)
        }
      }
      flare.intensity *= Math.pow(0.86, gap / 16.7)
      const blinkOn = !motion || (now % 1500) < 260
      for (const b of blinkers) b.visible = blinkOn

      renderer.render(scene, camera)

      // compass and labels follow the camera
      const az = Math.atan2(camera.position.x - controls.target.x, camera.position.z - controls.target.z)
      if (compass.current) compass.current.style.transform = `rotate(${az}rad)`
      const items: { key: string; x: number; y: number; d: number; prio: number }[] = []
      for (const x of built) {
        v.set(x.b.wx, x.b.h + (x.b.kind === 'tower' || x.b.kind === 'edge' ? 17 : 4), x.b.wz)
        const d = camera.position.distanceTo(v)
        v.project(camera)
        items.push({ key: x.b.key, x: ((v.x + 1) / 2) * W, y: ((1 - v.y) / 2) * H, d: v.z > 1 ? -1 : d, prio: x.b.status === 'attack' ? 0 : x.b.status === 'comp' ? 1 : 2 })
      }
      for (const h of live.current.horizons) {
        v.copy(dirOf(h.b)).multiplyScalar(330)
        v.y = 60
        const d = camera.position.distanceTo(v)
        v.project(camera)
        items.push({ key: `h:${h.o.id}`, x: ((v.x + 1) / 2) * W, y: ((1 - v.y) / 2) * H, d: v.z > 1 ? -1 : d, prio: 3 })
      }
      const placed: { x0: number; x1: number; y0: number; y1: number }[] = []
      const free = (r: { x0: number; x1: number; y0: number; y1: number }) =>
        r.x0 >= 2 && r.x1 <= W - 2 && r.y0 >= 2 && !placed.some((p) => r.x0 < p.x1 + 4 && r.x1 > p.x0 - 4 && r.y0 < p.y1 + 3 && r.y1 > p.y0 - 3)
      items.sort((a, b) => a.prio - b.prio || a.d - b.d)
      for (const it of items) {
        const el = els.current.get(it.key)
        if (!el) continue
        const sz = sizes.current.get(it.key) ?? { w: 160, h: 36 }
        const off = it.d < 0 || it.x < -sz.w / 2 || it.x > W + sz.w / 2 || it.y < -20 || it.y > H + 40
        if (off) { el.style.visibility = 'hidden'; continue }
        const rect = (dx: number, lift: number) => it.prio === 3
          ? { x0: it.x - sz.w / 2, x1: it.x + sz.w / 2, y0: it.y - sz.h / 2, y1: it.y + sz.h / 2 }
          : { x0: it.x + dx - sz.w / 2, x1: it.x + dx + sz.w / 2, y0: it.y - lift - sz.h, y1: it.y - lift }
        let pos = place.get(it.key)
        if (it.prio === 3) pos = { dx: 0, lift: 0 }
        else if (!pos || !free(rect(pos.dx, pos.lift))) {
          // keep the last spot while it stays clear; otherwise the first clear one: above, beside, then higher
          pos = undefined
          search: for (const lift of [14, 40, 66, 92, 118, 144, -(sz.h + 16), -(sz.h + 42)]) {
            for (const dx of [0, -(sz.w / 2 + 10), sz.w / 2 + 10]) {
              if (free(rect(dx, lift))) { pos = { dx, lift }; break search }
            }
          }
          pos ??= { dx: 0, lift: 14 }
        }
        place.set(it.key, pos)
        const cur = shown.get(it.key) ?? { ...pos }
        cur.dx += (pos.dx - cur.dx) * 0.2
        cur.lift += (pos.lift - cur.lift) * 0.2
        shown.set(it.key, cur)
        placed.push(rect(pos.dx, pos.lift))
        el.style.visibility = 'visible'
        el.style.transform = `translate3d(${it.x.toFixed(1)}px, ${it.y.toFixed(1)}px, 0)`
        el.style.setProperty('--dx', `${cur.dx.toFixed(1)}px`)
        el.style.setProperty('--lift', `${cur.lift.toFixed(1)}px`)
        // the leader runs from the anchor to the card's near edge: its bottom when above, its top when below
        const ly = cur.lift >= 0 ? cur.lift : cur.lift + sz.h
        el.style.setProperty('--len', `${Math.hypot(cur.dx, ly).toFixed(1)}px`)
        el.style.setProperty('--ang', `${Math.atan2(cur.dx, ly).toFixed(4)}rad`)
        el.style.zIndex = String(it.prio === 3 ? 1 : 1000 - Math.round(it.d))
      }
    }
    raf = requestAnimationFrame(frame)

    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      io.disconnect()
      controls.dispose()
      staticPaths.current = () => {}
      if (pathGroup) pathGroup.traverse((o) => { if (o instanceof THREE.Line) { o.geometry.dispose(); (o.material as THREE.Material).dispose() } })
      for (const t of trash) t.dispose()
      renderer.dispose()
      renderer.forceContextLoss()
      cv.remove()
    }
    // the scene is rebuilt only when the campuses change; focus, origins and motion are read live
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout])

  const reg = (key: string) => (el: HTMLDivElement | null) => { if (el) els.current.set(key, el); else els.current.delete(key) }

  return (
    <div ref={box} className="absolute inset-0 overflow-hidden">
      <div ref={labelsBox} className="absolute inset-0 transition-opacity duration-500" style={{ opacity: reduced ? 1 : 0 }}>
        {/* building labels: role, agency, sector and status; the internet edge also names its most exposed asset */}
        {blds.map((b) => {
          const p = profiles[b.org.id]
          const lines = b.kind === 'edge' ? exposures(p, 2) : []
          const beacon = b.status === 'comp' ? beaconLine(p) : undefined
          const open = selected === b.key
          const st = STATUS[b.status]
          return (
            <div key={b.key} ref={reg(b.key)} className="pointer-events-none absolute left-0 top-0" style={{ visibility: 'hidden' }}>
              <span className="absolute left-0 top-0 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full" style={{ background: st.dot, boxShadow: `0 0 8px ${st.dot}` }} />
              <span className="absolute bottom-0 left-0 w-px origin-bottom" style={{ height: 'var(--len)', transform: 'translateX(-50%) rotate(var(--ang))', background: `linear-gradient(to top, ${st.dot}, rgba(255,255,255,0.3))` }} />
              <div data-card className={`pointer-events-auto absolute -translate-x-1/2 rounded-md border bg-[#0a0a0c]/90 text-left shadow-[0_6px_22px_rgba(0,0,0,0.65)] backdrop-blur-sm ${open ? 'border-white/45' : 'border-white/[0.16]'} w-max ${narrow ? 'max-w-[180px]' : 'max-w-[270px]'}`}
                   style={{ left: 'var(--dx)', bottom: 'var(--lift)' }}>
                <button onClick={() => setSelected(open ? undefined : b.key)} aria-expanded={open}
                        aria-label={`${b.role}, ${b.org.name}, ${b.org.sector}, ${st.label}. ${open ? 'Hide' : 'Show'} details`}
                        className="block w-full rounded-md px-2 py-1 text-left focus-visible:outline-2 focus-visible:outline-[#4f8cf7]">
                  <span className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: st.dot }} />
                    <span className="truncate text-[11.5px] font-semibold leading-tight text-[#f4f4f5]">{b.role}</span>
                    {!narrow && <span className={`shrink-0 rounded-full px-1.5 text-[9.5px] font-semibold leading-[15px] ${st.cls}`}>{st.label}</span>}
                  </span>
                  <span className="mt-px block truncate text-[10.5px] leading-tight text-[#b4b4bb]">{b.org.name}{narrow ? '' : ` · ${SHORT_SECTOR[b.org.sector] ?? b.org.sector}`}</span>
                  {lines.slice(0, open ? 2 : narrow ? 0 : 1).map((l) => <span key={l} className="mt-px block truncate font-mono text-[10px] leading-tight text-[#ff9d9b]">{l}</span>)}
                  {beacon && !narrow && <span className="mt-px block truncate font-mono text-[10px] leading-tight text-[#c4b0ff]">{beacon}</span>}
                </button>
                {open && (
                  <div className="border-t border-white/10 px-2 pb-1.5 pt-1">
                    {narrow && <span className={`mb-1 inline-block rounded-full px-1.5 text-[9.5px] font-semibold leading-[15px] ${st.cls}`}>{st.label}</span>}
                    <div className="text-[10.5px] text-[#b4b4bb]">{b.org.sector} · {b.org.critical} Critical warnings{b.org.compromise ? ` · ${b.org.compromise} compromise` : ''}</div>
                    {narrow && lines.map((l) => <div key={l} className="truncate font-mono text-[10px] text-[#ff9d9b]">{l}</div>)}
                    {narrow && beacon && <div className="truncate font-mono text-[10px] text-[#c4b0ff]">{beacon}</div>}
                    <button onClick={() => onOrg(b.org.id)}
                            className="mt-1.5 inline-flex items-center gap-1 rounded-md bg-white px-2 py-1 text-[11px] font-semibold text-black hover:bg-white/85">
                      Open organisation<ArrowUpRight size={12} />
                    </button>
                  </div>
                )}
              </div>
            </div>
          )
        })}
        {/* the real origins, on the horizon in their true direction */}
        {horizons.map((h) => {
          const on = focus === h.o.id
          const col = h.o.kind === 'attack' ? ATTACK : C2
          return (
            <div key={h.o.id} ref={reg(`h:${h.o.id}`)} className="pointer-events-none absolute left-0 top-0" style={{ visibility: 'hidden' }}>
              <div data-card className="absolute left-0 flex -translate-x-1/2 -translate-y-1/2 items-center gap-1.5 whitespace-nowrap rounded-full border bg-black/70 px-2 py-0.5 text-[11px] backdrop-blur-sm"
                   style={{ borderColor: on ? col : 'rgba(255,255,255,0.14)', opacity: focus && !on ? 0.4 : 1 }}>
                <Flag cc={h.o.cc} className="h-[10px] w-[15px]" />
                <span className="font-medium text-[#f4f4f5]">{narrow ? h.o.cc : countryName(h.o.cc)}</span>
                {!narrow && <span className="text-[#b4b4bb]">{h.o.kind === 'attack' ? `${compact(h.o.records)} reports` : `C2 · ${h.o.ips}`}</span>}
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: col }} />
              </div>
            </div>
          )
        })}
      </div>
      {/* compass */}
      <div className="pointer-events-none absolute right-3 top-3 flex h-11 w-11 items-center justify-center rounded-full border border-white/15 bg-black/60 backdrop-blur" aria-hidden>
        <div ref={compass} className="relative flex h-full w-full items-start justify-center">
          <span className="mt-[3px] text-[9px] font-bold text-[#ff6b66]">N</span>
          <Navigation size={14} className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 text-white/80" />
        </div>
      </div>
      <div className="pointer-events-none absolute bottom-2 left-3 flex flex-wrap gap-x-3 gap-y-1 text-[11.5px] text-[#b4b4bb]">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: ATTACK }} />Attack source (REAL)</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: C2 }} />Botnet C2 (REAL)</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: COMP }} />C2 beacon (SIM)</span>
        {reduced && <span>Reduced motion: incoming paths shown still</span>}
      </div>
    </div>
  )
}

/** Without WebGL: the same agencies and buildings, as a list. */
function AgencyList({ layout, profiles, onOrg }: { layout: Campus[]; profiles: Record<string, OrgProfile>; onOrg: (id: string) => void }) {
  return (
    <div className="absolute inset-0 overflow-y-auto p-4">
      <p className="mb-3 text-[12.5px] text-[#b4b4bb]">3D needs WebGL, which this browser has turned off. The same site, as a list:</p>
      <ul className="grid gap-3 md:grid-cols-2">
        {layout.map((c) => (
          <li key={c.org.id} className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-[14px] font-semibold">{c.org.name}</div>
                <div className="text-[12px] text-[#b4b4bb]">{c.org.sector} · {c.org.critical} Critical warnings</div>
              </div>
              <button onClick={() => onOrg(c.org.id)} className="shrink-0 rounded-md bg-white px-2 py-1 text-[12px] font-semibold text-black">Open organisation</button>
            </div>
            <ul className="mt-2 space-y-1">
              {c.blds.map((b) => (
                <li key={b.key} className="text-[12px]">
                  <span className="font-medium">{b.role}</span> <span className={`ml-1 rounded-full px-1.5 py-[1px] text-[10px] font-semibold ${STATUS[b.status].cls}`}>{STATUS[b.status].label}</span>
                  {b.kind === 'edge' && exposures(profiles[c.org.id]).map((l) => <div key={l} className="font-mono text-[11px] text-[#ff9d9b]">{l}</div>)}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function SiteView({ target, origins, focus, onBack, onOrg }: {
  target: Target; origins: Origin[]; focus?: string; onBack: () => void; onOrg: (id: string) => void
}) {
  const gov = target.gov
  const priv = target.orgs.filter((o) => !isGov(o))
  const layout = useMemo(() => buildLayout(gov), [gov])
  const profiles = useProfiles(gov.map((o) => o.id))
  const reduced = useMemo(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches, [])
  const webgl = useMemo(hasWebGL, [])
  const [failed, setFailed] = useState(false)
  const back = useRef<HTMLButtonElement>(null)
  const onBackRef = useRef(onBack)
  onBackRef.current = onBack

  useEffect(() => {
    back.current?.focus({ preventScroll: true })
    const key = (e: KeyboardEvent) => { if (e.key === 'Escape') onBackRef.current() }
    window.addEventListener('keydown', key)
    return () => window.removeEventListener('keydown', key)
  }, [])

  return (
    <div className="absolute inset-0 z-30 flex flex-col soc-site-in" style={{ background: '#050506' }}>
      <style>{`@keyframes soc-site-in { from { opacity: 0 } to { opacity: 1 } } .soc-site-in { animation: soc-site-in 420ms ease-out both }
        @media (prefers-reduced-motion: reduce) { .soc-site-in { animation: none } }`}</style>
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-white/10 px-3 py-2.5 sm:px-4">
        <button ref={back} onClick={onBack}
                className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-white/15 bg-white/[0.06] px-2.5 text-[12.5px] font-semibold text-[#f4f4f5] hover:bg-white/[0.12]">
          <ArrowLeft size={14} />Back to the map
        </button>
        <h3 className="min-w-0 text-[14px]">
          <span className="font-semibold text-[#f4f4f5]">{target.state}</span>
          <span className="text-[#b4b4bb]"> · {agencies(gov.length)}</span>
        </h3>
        <span className="inline-flex items-center gap-1 rounded-full border border-white/15 bg-white/[0.06] px-2 py-0.5 text-[10px] font-semibold uppercase text-[#c8c8ce]">
          <span className="h-1.5 w-1.5 rounded-full ring-1 ring-[#c8c8ce]" />SIM site view
        </span>
        <span className="ml-auto hidden text-[12px] text-[#9d9da5] lg:inline">Drag to orbit · scroll to zoom · Esc to go back</span>
      </header>

      <div className="relative min-h-0 flex-1">
        {gov.length === 0 ? (
          <div className="flex h-full items-center justify-center p-6">
            <div className="max-w-md text-center">
              <div className="text-[15px] font-semibold text-[#f4f4f5]">No government agency in {target.state}</div>
              <p className="mt-1.5 text-[13px] leading-snug text-[#b4b4bb]">
                The site view builds government agencies and public-sector bodies only. The operators watched here are private-sector:
              </p>
              <ul className="mt-3 space-y-1.5">
                {target.orgs.map((o) => (
                  <li key={o.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-left">
                    <span className="min-w-0"><span className="block truncate text-[13px] font-medium text-[#f4f4f5]">{o.name}</span>
                      <span className="block text-[12px] text-[#b4b4bb]">{o.sector} · {o.critical} Critical warnings</span></span>
                    <button onClick={() => onOrg(o.id)} className="shrink-0 rounded-md bg-white px-2 py-1 text-[12px] font-semibold text-black hover:bg-white/85">Open organisation</button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ) : webgl && !failed ? (
          <Scene target={target} layout={layout} origins={origins} focus={focus} profiles={profiles} reduced={reduced} onOrg={onOrg} onFail={() => setFailed(true)} />
        ) : (
          <AgencyList layout={layout} profiles={profiles} onOrg={onOrg} />
        )}
      </div>

      <footer className="border-t border-white/10 px-3 py-2.5 text-[12px] leading-snug text-[#b4b4bb] sm:px-4">
        {gov.length > 0 && (
          <div className="mb-2 flex flex-wrap gap-2">
            {layout.map((c) => {
              const s: 'comp' | 'attack' = c.org.compromise > 0 ? 'comp' : 'attack'
              return (
                <div key={c.org.id} className="flex min-w-0 items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] py-1 pl-2.5 pr-1">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: STATUS[s].dot }} />
                  <span className="min-w-0 truncate"><span className="font-medium text-[#f4f4f5]">{c.org.name}</span> · {c.org.sector} · {c.org.critical} Critical</span>
                  <button onClick={() => onOrg(c.org.id)} aria-label={`Open organisation ${c.org.name}`}
                          className="ml-1 inline-flex shrink-0 items-center gap-0.5 rounded-md px-1.5 py-0.5 text-[11.5px] font-semibold text-[#8fb4ff] hover:bg-white/10">
                    Open<ArrowUpRight size={12} />
                  </button>
                </div>
              )
            })}
          </div>
        )}
        {priv.length > 0 && gov.length > 0 && (
          <p>Private-sector operators in this state (no buildings drawn): {priv.map((o) => `${o.name} (${o.sector})`).join(', ')}.</p>
        )}
        <p>Simulated site view (SIM): operators and buildings are simulated; the attack sources are real (DShield, Feodo Tracker, {snapshotLabel()}), shown in their true direction from {target.state}.</p>
      </footer>
    </div>
  )
}
