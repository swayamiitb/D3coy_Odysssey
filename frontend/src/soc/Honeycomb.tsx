import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js'

/* The motion behind every page header (ui-09), after the team's reference clip: a wall of dark metal hexagonal tiles,
   bevelled, lit from the top left, tiles rising towards the camera and sinking back over about a second and a half,
   several in motion at any moment. Real 3D (three.js, one instanced mesh), drawn only while the header is on screen
   and the tab is visible; a single still frame under reduced motion; nothing at all without WebGL. */

const R = 40                       // tile radius in px
const DEPTH = 16                   // tile thickness
const RISE = 44                    // the furthest a tile comes towards the camera
const SQ3 = Math.sqrt(3)

interface Tile { x: number; y: number; from: number; to: number; t0: number; dur: number }

export function Honeycomb({ className = '' }: { className?: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const box = ref.current!
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'low-power' })
    } catch { return }
    renderer.setPixelRatio(Math.min(1.5, window.devicePixelRatio || 1))
    renderer.setClearColor(0x000000, 1)
    renderer.toneMapping = THREE.ACESFilmicToneMapping
    renderer.toneMappingExposure = 0.9
    renderer.outputColorSpace = THREE.SRGBColorSpace
    const cv = renderer.domElement
    cv.style.position = 'absolute'
    cv.style.inset = '0'
    box.appendChild(cv)

    const scene = new THREE.Scene()
    const pmrem = new THREE.PMREMGenerator(renderer)
    const env = pmrem.fromScene(new RoomEnvironment(), 0.04).texture
    scene.environment = env
    const camera = new THREE.PerspectiveCamera(26, 1, 10, 6000)
    const key = new THREE.DirectionalLight(0xffffff, 2.6)
    key.position.set(-0.9, 1.1, 1.4)
    const fill = new THREE.DirectionalLight(0xffffff, 0.5)
    fill.position.set(1, -0.6, 0.8)
    scene.add(key, fill, new THREE.AmbientLight(0xffffff, 0.2))

    // one bevelled hexagonal prism, pointy-top, in px units
    const shape = new THREE.Shape()
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 180) * (60 * i - 90)
      const px = R * 0.9 * Math.cos(a), py = R * 0.9 * Math.sin(a)
      if (i === 0) shape.moveTo(px, py); else shape.lineTo(px, py)
    }
    shape.closePath()
    const geo = new THREE.ExtrudeGeometry(shape, { depth: DEPTH, bevelEnabled: true, bevelThickness: 5, bevelSize: 3.6, bevelSegments: 3, curveSegments: 1 })
    const mat = new THREE.MeshStandardMaterial({ color: 0x232327, metalness: 0.88, roughness: 0.4, envMapIntensity: 1.0 })
    let mesh: THREE.InstancedMesh | undefined
    let tiles: Tile[] = []
    let W = 0, H = 0, raf = 0, visible = true
    const m4 = new THREE.Matrix4()
    const col = new THREE.Color()
    const seed = (x: number, y: number) => { const s = Math.sin(x * 12.9898 + y * 78.233) * 43758.5453; return s - Math.floor(s) }

    const build = () => {
      W = box.clientWidth
      H = box.clientHeight
      if (!W || !H) return
      renderer.setSize(W, H, false)
      camera.aspect = W / H
      // the plane of the tile tops fills the box; the camera sits a little above centre, so the tiles' sides show
      const dist = (H / 2) / Math.tan((camera.fov * Math.PI) / 360)
      camera.position.set(0, H * 0.16, dist)
      camera.lookAt(0, 0, 0)
      camera.updateProjectionMatrix()
      if (mesh) { scene.remove(mesh); mesh.dispose() }
      const w = SQ3 * R, h = 1.5 * R
      const cols = Math.ceil(W / w) + 4, rows = Math.ceil(H / h) + 4
      mesh = new THREE.InstancedMesh(geo, mat, cols * rows)
      tiles = []
      let i = 0
      for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
        const x = (c - cols / 2) * w + (r % 2 ? w / 2 : 0), y = (r - rows / 2) * h
        tiles.push({ x, y, from: 0, to: 0, t0: -1e9, dur: 1500 })
        col.setHSL(0, 0, 0.1 + 0.12 * seed(c, r))
        mesh.setColorAt(i++, col)
      }
      scene.add(mesh)
    }
    const place = (now: number) => {
      if (!mesh) return
      tiles.forEach((t, i) => {
        const p = Math.max(0, Math.min(1, (now - t.t0) / t.dur))
        const e = p < 0.5 ? 2 * p * p : 1 - (-2 * p + 2) ** 2 / 2
        m4.makeTranslation(t.x, t.y, t.from + (t.to - t.from) * e - DEPTH)
        mesh!.setMatrixAt(i, m4)
      })
      mesh.instanceMatrix.needsUpdate = true
    }
    const render = () => renderer.render(scene, camera)
    // start a tile moving: up if it is down, down if it is up, from wherever it is right now
    const kick = (t: Tile, now: number, delay = 0) => {
      const p = Math.min(1, (now - t.t0) / t.dur)
      const e = p < 0.5 ? 2 * p * p : 1 - (-2 * p + 2) ** 2 / 2
      t.from = t.from + (t.to - t.from) * e
      t.to = t.to > RISE * 0.3 ? 0 : RISE * (0.45 + 0.55 * Math.random())
      t.dur = 320 + Math.random() * 260
      t.t0 = now + delay
    }
    let nextRipple = 0
    const frame = (now: number) => {
      raf = requestAnimationFrame(frame)
      if (!visible || document.hidden || !mesh || !tiles.length) return
      // four times the clip's pace: a dozen single tiles a second, and every second or so a ripple that spreads
      // from one tile through its neighbours, so the motion has a pattern as well as the scatter
      if (Math.random() < 0.22) kick(tiles[Math.floor(Math.random() * tiles.length)], now)
      if (now >= nextRipple) {
        nextRipple = now + 900 + Math.random() * 900
        const c = tiles[Math.floor(Math.random() * tiles.length)]
        const reach = SQ3 * R * (2.2 + Math.random() * 1.6)
        for (const t of tiles) {
          const d = Math.hypot(t.x - c.x, t.y - c.y)
          if (d <= reach) kick(t, now, d * 2.2)
        }
      }
      place(now)
      render()
    }
    build()
    const ro = new ResizeObserver(() => { build(); place(performance.now()); render() })
    ro.observe(box)
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting })
    io.observe(box)
    if (still) {
      for (const t of tiles) if (seed(t.x, t.y) > 0.82) { t.from = t.to = RISE * 0.6 }
      place(0)
      render()
    } else raf = requestAnimationFrame(frame)
    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      io.disconnect()
      if (mesh) { scene.remove(mesh); mesh.dispose() }
      geo.dispose()
      mat.dispose()
      env.dispose()
      pmrem.dispose()
      renderer.dispose()
      cv.remove()
    }
  }, [])
  return (
    <div ref={ref} aria-hidden className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`}>
      <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(0,0,0,0.12),rgba(0,0,0,0.42))]" style={{ zIndex: 1 }} />
    </div>
  )
}
