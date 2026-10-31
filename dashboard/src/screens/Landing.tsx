// The landing page: one story on one pinned stage, outside the console (#/; the console is #/overview).
//   1 Far from home – real botnet command servers (abuse.ch Feodo Tracker, bundled) on a 3D globe
//   2 At home       – the globe dives into a flat India state map: operators, Critical warnings, a ranked list
//   3 The evidence  – back on the globe, one arc: a simulated gateway's beacon to a real QakBot server
//   4 What to do    – the map with each top state's worst real CVE, the CERT-In clock, the decisions waiting
// Every number names its source and whether it is real or simulated (CLAUDE.md rule 17). Reduced motion, no WebGL or a
// short screen get the finished page instead: the four beats stacked, each with its own still picture.
import type { COBEOptions } from 'cobe'
import { ArrowRight } from 'lucide-react'
import { useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import { api, getMode, getSnapshotTakenAt, useLoad } from '../data'
import { date, dateTime, duration, num, sla } from '../format'
import attackers from '../geo/attackers.json'
import feodo from '../geo/feodo.json'
import { anglesFor, COUNTRY_CENTROID, MAP_CENTRE, refang, sideOf, slerp, spread, STATE_CENTROID, stateName, type LatLng } from '../geo/geo'
import { Globe, hasWebGL, type GlobeFrame } from '../geo/Globe'
import { describeState, IndiaMap, type Origin, type StateThreat } from '../geo/IndiaMap'
import { takeScroll } from '../scroll'
import type { Card, Soc } from '../types'
import { useNow } from '../ui'

type RGB = [number, number, number]
const clamp = (x: number, a = 0, b = 1) => Math.min(b, Math.max(a, x))
const ease = (a: number, b: number, x: number) => { const t = clamp((x - a) / (b - a)); return t * t * (3 - 2 * t) }
const lerp = (a: number, b: number, t: number) => a + (b - a) * t
const mixRGB = (a: RGB, b: RGB, t: number): RGB => [lerp(a[0], b[0], t), lerp(a[1], b[1], t), lerp(a[2], b[2], t)]
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-')
const plural = (n: number, one: string, many: string) => `${num(n)} ${n === 1 ? one : many}`
/** Near-certain and small probabilities keep a decimal (98.7%, 3.2%); the rest round (18%). */
const pct = (x: number) => `${num(x * 100, x >= 0.95 || x < 0.1 ? 1 : 0)}%`
const regionName = (() => {
  try { const d = new Intl.DisplayNames(['en'], { type: 'region' }); return (cc: string) => d.of(cc) ?? cc } catch { return (cc: string) => cc }
})()
/** "in the United States", "in Japan". */
const inCountry = (cc: string) => {
  const n = regionName(cc)
  return /^(United|Netherlands|Philippines|Czech|Bahamas|Gambia|Maldives)/.test(n) ? `the ${n}` : n
}

/** cobe takes colours as RGB arrays; read them from the CSS tokens once, so the globe and the page never drift apart. */
let tokens: { red: RGB; orange: RGB; c2: RGB } | null = null
function palette() {
  if (tokens) return tokens
  const css = getComputedStyle(document.documentElement)
  const read = (name: string, fallback: RGB): RGB => {
    const m = /^#([0-9a-f]{6})$/i.exec(css.getPropertyValue(name).trim())
    if (!m) return fallback
    const n = parseInt(m[1], 16)
    return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255]
  }
  tokens = { red: read('--color-compromise', [1, 0.27, 0.23]), orange: read('--color-critical', [1, 0.62, 0.04]), c2: read('--color-c2', [0.39, 0.82, 1]) }
  return tokens
}

// ---- camera ------------------------------------------------------------------------------------------------------

interface Cam { phi: number; theta: number; scale: number }
const shortWay = (from: number, to: number) => {
  let d = (to - from) % (2 * Math.PI)
  if (d > Math.PI) d -= 2 * Math.PI
  if (d < -Math.PI) d += 2 * Math.PI
  return d
}
/** Blend two cameras. Once a turn has begun it keeps its direction (dir), so a drifting start never flips it 180°. */
function mixCam(a: Cam, b: Cam, t: number, dir = 0): Cam {
  let d = shortWay(a.phi, b.phi)
  if (dir && d !== 0 && Math.sign(d) !== dir) d += dir * 2 * Math.PI
  return { phi: a.phi + d * t, theta: lerp(a.theta, b.theta, t), scale: lerp(a.scale, b.scale, t) }
}
const camAt = (p: LatLng, scale: number): Cam => ({ ...anglesFor(p), scale })

const INDIA_SCALE = 1.85
/** India's height on cobe's sphere as a share of its radius (lat 6.75–37.08 seen from the map's centre). */
const INDIA_FRACTION = 0.523
const INDIA_CAM = camAt(MAP_CENTRE, INDIA_SCALE)

// ---- scene -------------------------------------------------------------------------------------------------------

interface OrgDot { id: string; at: LatLng; critical: number; compromise: number }
interface Scene {
  orgs: OrgDot[] // drawing order: a compromised operator last, on top of its neighbours
  maxCrit: number
  c2: { id: string; ip: string; malware: string; country: string; online: boolean; at: LatLng }[]
  /** One label per country, hung on that country's first server. */
  c2Countries: { id: string; country: string; count: number; online: number }[]
  /** Only markers that carry a label get an id: every id costs cobe an anchor element per frame. */
  labelled: Set<string>
  beacon: { from: LatLng; to: LatLng; c2Id: string; orgId: string } | null
}

function buildScene(soc: Soc | null, beaconOrg: string | null, beaconIp: string | null): Scene {
  const byState = new Map<string, Soc['orgs']>()
  for (const o of soc?.orgs ?? []) {
    const s = stateName(o.state)
    byState.set(s, [...(byState.get(s) ?? []), o])
  }
  const orgs: OrgDot[] = []
  for (const [state, list] of byState) {
    const c = STATE_CENTROID[state]
    if (!c) continue
    // The API counts Critical-or-worse per operator; the compromise tier is shown on its own.
    list.forEach((o, i) => orgs.push({ id: o.id, at: spread(c, i, list.length), critical: o.critical - o.compromise, compromise: o.compromise }))
  }
  orgs.sort((a, b) => a.compromise - b.compromise)
  const c2 = feodo.entries.flatMap((e, i) => {
    const at = COUNTRY_CENTROID[e.country]
    return at ? [{ id: `c2-${i}`, ip: e.ip, malware: e.malware, country: e.country, online: e.status === 'online', at: spread(at, i % 3, 3) }] : []
  })
  const c2Countries: Scene['c2Countries'] = []
  for (const c of c2) {
    const g = c2Countries.find((x) => x.country === c.country)
    if (g) { g.count++; g.online += c.online ? 1 : 0 } else c2Countries.push({ id: c.id, country: c.country, count: 1, online: c.online ? 1 : 0 })
  }
  const from = orgs.find((o) => o.id === beaconOrg)?.at
  const target = beaconIp ? c2.find((c) => c.ip === beaconIp) : undefined
  const beacon = from && target && beaconOrg ? { from, to: target.at, c2Id: target.id, orgId: beaconOrg } : null
  return {
    orgs, maxCrit: Math.max(1, ...orgs.map((o) => o.critical)), c2, c2Countries, beacon,
    labelled: new Set([...c2Countries.map((g) => g.id), ...(beacon ? [beacon.c2Id] : [])]),
  }
}

// ---- timeline ----------------------------------------------------------------------------------------------------

/** Scroll timeline (p = 0..1). The map takes over from the globe twice; the arc completes at 0.66 and holds. */
const T = {
  toIndia: [0.12, 0.28], dive1: [0.27, 0.35], fade1: [0.29, 0.36], undive: [0.44, 0.49], arc: [0.5, 0.66],
  arcFade: [0.74, 0.79], back: [0.75, 0.83], dive2: [0.81, 0.89], fade2: [0.83, 0.9],
} as const
const at = (k: keyof typeof T, p: number) => ease(T[k][0], T[k][1], p)
/** How much of the India map shows over the globe. */
const mapShare = (p: number) => at('fade1', p) * (1 - at('undive', p)) + at('fade2', p)
/** How far the camera has dived towards the map's size. */
const diveShare = (p: number) => Math.max(at('dive1', p) * (1 - at('undive', p)), at('dive2', p))
const EDGES = [0.27, 0.48, 0.8] // beat boundaries
const RAIL = [
  { title: 'Far from home', p: 0.06 }, { title: 'At home', p: 0.4 }, { title: 'The evidence', p: 0.7 }, { title: 'What to do now', p: 0.97 },
]

interface Pose { worldPhi: number; dir: number; diveScale: number }
/** The globe's state at scroll progress p. Pure: everything the picture shows comes from here. */
function frameFor(s: Scene, p: number, pose: Pose): Partial<COBEOptions> {
  const { red, orange, c2 } = palette()
  const arcT = at('arc', p)
  let cam = mixCam({ phi: pose.worldPhi, theta: 0.28, scale: 1 }, INDIA_CAM, at('toIndia', p), pose.dir)
  if (s.beacon && p >= 0.49) {
    // Stand side-on to the arc's great circle, so the arc reads as a curve with both ends in view; hold; come back.
    const n = sideOf(s.beacon.from, s.beacon.to)
    const side = mixCam(INDIA_CAM, camAt([Math.min(60, n[0] + 28), n[1]], 0.95), ease(0, 0.35, arcT))
    cam = mixCam(side, INDIA_CAM, at('back', p))
  }
  cam = { ...cam, scale: cam.scale + (pose.diveScale - INDIA_SCALE) * diveShare(p) }
  const grow = ease(0.2, 0.38, p)
  const markers: COBEOptions['markers'] = [
    ...s.c2.map((c) => ({ ...(s.labelled.has(c.id) ? { id: c.id } : {}), location: c.at, color: c2, size: c.online ? 0.06 : 0.035 })),
    ...s.orgs.map((o) => ({
      ...(s.beacon?.orgId === o.id ? { id: `org-${slug(o.id)}` } : {}), location: o.at, color: o.compromise > 0 ? red : orange,
      size: grow * Math.max(o.compromise > 0 ? 0.02 : 0, 0.008 + 0.016 * Math.sqrt(o.critical / s.maxCrit)),
    })),
  ]
  const fade = at('arcFade', p)
  const arcs: COBEOptions['arcs'] = s.beacon && arcT > 0.001 && fade < 0.999
    ? [{ from: s.beacon.from, to: slerp(s.beacon.from, s.beacon.to, arcT), color: mixRGB(red, [0, 0, 0], fade) }]
    : []
  const dim = ease(0.5, 0.58, p) * (1 - ease(0.74, 0.82, p)) // the evidence chapter: land dims, the arc carries it
  return { ...cam, markers, arcs, mapBrightness: lerp(7, 4.6, dim) }
}

// ---- small pieces ------------------------------------------------------------------------------------------------

function useMedia(q: string): boolean {
  const [on, setOn] = useState(() => window.matchMedia(q).matches)
  useEffect(() => {
    const m = window.matchMedia(q)
    const ch = () => setOn(m.matches)
    m.addEventListener('change', ch)
    return () => m.removeEventListener('change', ch)
  }, [q])
  return on
}

/** Counts up to `to` once, writing text directly (no React render per frame); interrupted, it lands on the truth. */
function CountUp({ to, run }: { to: number | null | undefined; run: boolean }) {
  const el = useRef<HTMLSpanElement>(null)
  const done = useRef(false)
  useLayoutEffect(() => {
    const node = el.current
    if (!node || to == null) return
    const final = num(to)
    node.textContent = final
    if (!run || done.current) return
    done.current = true
    const t0 = performance.now()
    let raf = 0
    const tick = (t: number) => {
      const k = clamp((t - t0) / 900)
      node.textContent = num(Math.round(to * (1 - (1 - k) ** 3)))
      if (k < 1) raf = requestAnimationFrame(tick)
    }
    node.textContent = num(0)
    raf = requestAnimationFrame(tick)
    return () => { cancelAnimationFrame(raf); node.textContent = final }
  }, [to, run])
  return to == null ? <Skel w="3ch" /> : <span ref={el} className="fig" />
}

/** A loading placeholder that keeps the line's shape: flat, no shimmer. */
function Skel({ w }: { w: string }) {
  return <span className="inline-block h-[0.75em] rounded-md bg-raised align-baseline" style={{ width: w }} aria-label="Loading" />
}

const H1 = 'max-w-[14ch] text-balance text-[clamp(44px,5.6vw,80px)] font-semibold leading-[0.95] tracking-[-0.04em] -ml-[0.04em]'
const H2 = 'max-w-[17ch] text-balance text-[clamp(34px,4vw,60px)] font-semibold leading-[1] tracking-[-0.035em]'
const LEAD = 'mt-5 max-w-[30rem] text-[17px] leading-[1.55] text-text sm:text-[18px]'
const LINE = 'max-w-[30rem] text-[15px] leading-relaxed text-mute'

function Count({ i }: { i: number }) {
  return <p className="fig mb-5 text-[15px] text-mute">{i + 1} of 4</p>
}

function Key({ color, children }: { color: string; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 text-[15px] text-mute">
      <span className="size-2.5 shrink-0 rounded-full" style={{ background: color }} aria-hidden />
      {children}
    </span>
  )
}

/** Live, snapshot, sample and a backend that stopped answering are four different states, said in the header. */
function ModeBadge({ down }: { down: string | null }) {
  const mode = getMode()
  const [long, short] = down ? ['Backend not answering', 'Offline']
    : mode === 'live' ? ['Live from the Odyssey API', 'Live']
    : mode === 'snapshot' ? [`Snapshot from ${dateTime(getSnapshotTakenAt())}`, 'Snapshot']
    : ['Sample data, not real', 'Sample']
  return (
    <span className="inline-flex items-center gap-2 text-[14px] text-mute">
      <span className={`size-1.5 rounded-full ${!down && mode === 'live' ? 'bg-ok' : 'bg-mute'}`} aria-hidden />
      <span className="max-sm:hidden">{long}</span><span className="sm:hidden">{short}</span>
    </span>
  )
}

/** The landing's own header. One white pill per screen: it turns grey on the last beat, where the incident is primary. */
function LandingHeader({ quiet, down, still }: { quiet: boolean; down: string | null; still: boolean }) {
  return (
    <header className="fixed inset-x-0 top-0 z-30 flex h-14 items-center justify-between gap-4 bg-ground px-5 sm:px-8 md:px-10">
      <a href="#/" aria-label="Odyssey, back to the top" translate="no" className="flex min-w-0 items-center gap-2.5"
        onClick={(e) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: still ? 'auto' : 'smooth' }) }}>
        <img src="/mark.svg" alt="" width={28} height={28} className="size-7" />
        <span className="text-[18px] font-semibold tracking-[-0.01em]">Odyssey</span>
        <span className="truncate text-[14px] text-mute max-lg:hidden">National cyber early warning</span>
      </a>
      <div className="flex shrink-0 items-center gap-5">
        <ModeBadge down={down} />
        <a href="#/overview" className={`pill pill-sm ${quiet ? 'pill-secondary' : 'pill-primary'}`}>Open the console</a>
      </div>
    </header>
  )
}

/** The reporting deadline as the hero figure: a ticking clock, red only once it is overdue, its meaning in words. */
function HeroClock({ card }: { card: Card }) {
  const t = useNow(1000)
  const s = sla(card.workflow.issued_at, card.deadline_hours, t)
  if (s.state === 'none') return null
  const ms = Math.abs(s.leftMs)
  const pad = (n: number) => String(n).padStart(2, '0')
  const text = `${pad(Math.floor(ms / 3_600_000))}:${pad(Math.floor((ms % 3_600_000) / 60_000))}:${pad(Math.floor((ms % 60_000) / 1000))}`
  const late = s.state === 'breached'
  return (
    <div role="timer" aria-label={late ? `Overdue by ${duration(s.leftMs)}` : `${duration(s.leftMs)} left to report to CERT-In`}>
      <div className={`fig text-[clamp(44px,5.6vw,80px)] font-semibold leading-none tracking-[-0.02em] ${late ? 'text-compromise' : 'text-text'}`}>
        {late ? '−' : ''}{text}
      </div>
      <div className="mt-2 text-[15px] text-mute">
        {late ? `past the CERT-In ${card.deadline_hours}-hour deadline` : `left to report to CERT-In (${card.deadline_hours}-hour rule), due ${dateTime(new Date(s.dueMs).toISOString())}`}
      </div>
    </div>
  )
}

/** Maps carry a list: the map shows where, this shows how much. Hover, focus and tap are shared with the map. */
function StateList({ threats, hover, onHover, loading }: {
  threats: StateThreat[]; hover: string | null; onHover: (s: string | null) => void; loading: boolean
}) {
  if (!threats.length) return <p className={LINE}>{loading ? 'Loading the states…' : 'No operators to show.'}</p>
  const max = Math.max(1, ...threats.map((t) => t.critical))
  const rows = threats.slice(0, 6)
  const operators = threats.reduce((n, t) => n + t.operators.length, 0)
  return (
    <div>
      <p className="mb-3 text-[15px] text-mute">Critical warnings by state</p>
      <ol className="space-y-1 [&>li:nth-child(n+5)]:max-sm:hidden" onMouseLeave={() => onHover(null)}>
        {rows.map((t) => (
          <li key={t.name}>
            <button type="button" aria-label={describeState(t)} aria-pressed={hover === t.name}
              onMouseEnter={() => onHover(t.name)} onFocus={() => onHover(t.name)} onClick={() => onHover(hover === t.name ? null : t.name)}
              className={`grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 rounded-md px-2 py-1.5 text-left -mx-2 ${hover === t.name ? 'bg-raised' : ''}`}>
              <span className="truncate text-[15px]">
                {t.name}<span className="text-mute"> {plural(t.operators.length, 'operator', 'operators')}{t.compromise ? ', suspected compromise' : ''}</span>
              </span>
              <span className="fig text-[15px]">{num(t.critical)}</span>
              <span className="col-span-2 block h-[3px]" aria-hidden>
                <span className="block h-full rounded-full" style={{ width: `${(t.critical / max) * 100}%`, background: t.compromise ? 'var(--color-compromise)' : '#545454' }} />
              </span>
            </button>
          </li>
        ))}
      </ol>
      {threats.length > rows.length && (
        <a href="#/orgs" className="mt-2 inline-block text-[15px] text-accent hover:underline">See all {num(operators)} operators</a>
      )}
    </div>
  )
}

function Credits() {
  const link = 'text-accent hover:underline'
  return (
    <footer className="mx-auto max-w-[1200px] px-5 py-12 text-[15px] leading-relaxed text-mute sm:px-8 md:px-10">
      Map boundaries: <a className={link} rel="noreferrer" href="https://github.com/VictorCazanave/svg-maps">@svg-maps/india</a> by{' '}
      <a className={link} rel="noreferrer" href="https://mapsvg.com">MapSVG</a>, <a className={link} rel="noreferrer" href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>,
      with pre-2019 divisions (Ladakh is drawn inside Jammu and Kashmir). Botnet servers:{' '}
      <a className={link} rel="noreferrer" href="https://feodotracker.abuse.ch/">abuse.ch Feodo Tracker</a>. The operators, their assets and
      firewall logs are simulated.
    </footer>
  )
}

/** A globe frozen at one pose of the story: the reduced-motion picture for beats 1 and 3. */
function StillGlobe({ scene, pose, label, children }: { scene: Scene; pose: number; label: string; children: ReactNode }) {
  const frame = useRef<GlobeFrame>(() => null)
  useLayoutEffect(() => { frame.current = () => frameFor(scene, pose, { worldPhi: pose * 2.2, dir: 0, diveScale: INDIA_SCALE }) })
  return <Globe frame={frame} still label={label} fallback={<p className="p-6 text-[15px] text-mute">This browser can't draw the globe.</p>}>{children}</Globe>
}

// ---- the page ----------------------------------------------------------------------------------------------------

const ROLE: Record<string, string> = { vpn: 'VPN gateway', firewall: 'firewall', mail: 'mail gateway', web: 'web server', proxy: 'proxy' }

export function Landing() {
  const soc = useLoad(api.soc, 'soc')
  const feed = useLoad(api.feed, 'feed')
  const sources = useLoad(api.intelSources, 'sources')
  const alerts = useLoad(() => api.alerts(400), 'alerts:400')
  const cards = feed.data?.cards ?? []
  const openComp = cards.filter((c) => c.tier === 'Compromise' && c.workflow.state !== 'closed')
  const hot: Card | undefined = openComp[0]
  const profile = useLoad(hot ? () => api.orgProfile(hot.org_id) : null, `profile:${hot?.org_id}`)
  const detail = useLoad(hot ? () => api.alert(hot.org_id, hot.cve_id) : null, `alert:${hot?.id}`)

  const sighting = profile.data?.indicators.c2_sightings[0]
  const c2Ip = sighting ? refang(sighting.c2) : null
  const c2Entry = feodo.entries.find((e) => e.ip === c2Ip)
  const asset = detail.data?.assets.find((a) => a.rules.some((r) => r.id === 'IOC_SIGHTING')) ?? detail.data?.assets[0]
  const beaconRule = asset?.rules.find((r) => r.id === 'IOC_SIGHTING')
  const bayes = asset?.bayes
  const sample = getMode() === 'sample'
  const down = soc.error ?? feed.error
  const retry = () => { soc.reload(); feed.reload(); sources.reload(); alerts.reload() }

  const scene = useMemo(() => buildScene(soc.data, sighting && hot ? hot.org_id : null, c2Ip), [soc.data, sighting, hot, c2Ip])

  // Where attacks come from (last beat): the countries behind the most DShield attack reports, topped up to seven with
  // the countries hosting Feodo Tracker's botnet command servers when DShield names fewer.
  const origins = useMemo<Origin[]>(() => {
    const list: Origin[] = attackers.countries.flatMap((c) => {
      const at = COUNTRY_CENTROID[c.country]
      return at ? [{ id: `a-${c.country}`, name: regionName(c.country), kind: 'attack' as const, at, note: `${num(c.records)} reports` }] : []
    })
    for (const g of scene.c2Countries) {
      const at = COUNTRY_CENTROID[g.country]
      if (list.length < 7 && at && !list.some((o) => o.id.endsWith(`-${g.country}`))) {
        list.push({ id: `c-${g.country}`, name: regionName(g.country), kind: 'c2', at, note: plural(g.count, 'botnet server', 'botnet servers') })
      }
    }
    return list.slice(0, 7)
  }, [scene])

  // Per-state threat: operators, Critical warnings (Critical only; the compromise tier is separate) and the worst CVE.
  const threats = useMemo<StateThreat[]>(() => {
    const out = new Map<string, StateThreat>()
    for (const o of soc.data?.orgs ?? []) {
      const name = stateName(o.state)
      const t = out.get(name) ?? { name, operators: [], critical: 0, compromise: 0, top: null }
      const critical = o.critical - o.compromise
      t.operators.push({ id: o.id, name: o.name, critical, compromise: o.compromise })
      t.critical += critical
      t.compromise += o.compromise
      out.set(name, t)
    }
    const stateOf = new Map((soc.data?.orgs ?? []).map((o) => [o.id, stateName(o.state)]))
    // The compromised operator's state shows the open incident its button opens; other states their riskiest alert.
    const hotRow = hot ? (alerts.data ?? []).find((a) => a.id === hot.id) : undefined
    if (hotRow) { const t = out.get(stateOf.get(hotRow.org_id) ?? ''); if (t) t.top = hotRow }
    for (const a of alerts.data ?? []) {
      const t = out.get(stateOf.get(a.org_id) ?? '')
      if (t && !t.top && (a.tier === 'Compromise' || a.tier === 'Critical')) t.top = a
    }
    return [...out.values()].sort((a, b) => b.compromise - a.compromise || b.critical - a.critical)
  }, [soc.data, alerts.data, hot])
  const unplaced = threats.filter((t) => !STATE_CENTROID[t.name]).reduce((n, t) => n + t.operators.length, 0)

  // CVE identifiers travel with a human name: the affected product, from each top CVE's assessment.
  const topAlerts = threats.slice(0, 3).flatMap((t) => (t.top ? [t.top] : []))
  const names = useLoad(
    topAlerts.length
      ? () => Promise.all(topAlerts.map((a) => api.alert(a.org_id, a.cve_id)
          .then((d) => [a.id, d.assets[0]?.label ?? null] as const)
          .catch(() => [a.id, null] as const))).then((rows) => Object.fromEntries(rows) as Record<string, string | null>)
      : null,
    `names:${topAlerts.map((a) => a.id).join(',')}`,
  )
  const productNames = names.data ?? {}

  // ---- which version of the page
  const reduce = useMedia('(prefers-reduced-motion: reduce)')
  // The pinned story needs room for a picture and a caption side by side; phones and short screens get the stacked page.
  const short = useMedia('(max-height: 599px), (max-width: 767px)')
  const [webgl] = useState(hasWebGL)
  const [failed, setFailed] = useState(false)
  const still = reduce || short || !webgl || failed

  const [beatIdx, setBeatIdx] = useState(0)
  const [mapIn, setMapIn] = useState(false)
  const [attacksOn, setAttacksOn] = useState(false) // arrows draw once India has fully opened in the last beat
  const [hover, setHover] = useState<string | null>(null)
  const onIndia = beatIdx === 1 || beatIdx === 3

  useEffect(() => { document.title = 'Odyssey · National cyber early warning'; return () => { document.title = 'Odyssey SOC' } }, [])
  // Back from the console returns to the same beat (scroll.ts remembers where the reader left).
  useLayoutEffect(() => { const y = takeScroll(''); if (y) window.scrollTo(0, y) }, [])

  // ---- the pinned stage: measured once per resize, written once per frame, straight onto the elements that use it
  const story = useRef<HTMLElement>(null)
  const stage = useRef<HTMLDivElement>(null)
  const figureEl = useRef<HTMLDivElement>(null)
  const globeEl = useRef<HTMLDivElement>(null)
  const mapEl = useRef<HTMLDivElement>(null)
  const b0El = useRef<HTMLDivElement>(null)
  const b2El = useRef<HTMLDivElement>(null)
  const box = useRef({ top: 0, range: 1, globeH: 1, mapH: 1 })
  const motion = useRef({ p: 0, last: 0, t0: 0, spin: 0, dir: 0, beat: 0, mapIn: false, atk: false, key: '', mk: '', ak: '', ms: null as Scene | null, as: null as Scene | null })
  const written = useRef<Record<string, string>>({})
  const sceneRef = useRef(scene)

  useLayoutEffect(() => {
    if (still) return
    const el = story.current, st = stage.current, g = globeEl.current, f = figureEl.current
    if (!el || !st || !g || !f) return
    const measure = () => {
      box.current = { top: el.getBoundingClientRect().top + window.scrollY, range: Math.max(1, el.offsetHeight - st.offsetHeight), globeH: g.offsetHeight, mapH: f.offsetHeight }
      motion.current.key = ''
    }
    measure()
    const ro = new ResizeObserver(measure)
    ;[el, g, f].forEach((n) => ro.observe(n))
    return () => ro.disconnect()
  }, [still])

  const frame = useRef<GlobeFrame>(() => null)
  useLayoutEffect(() => {
    sceneRef.current = scene
    const put = (k: string, el: HTMLElement | null, prop: string, v: string) => {
      if (!el || written.current[k] === v) return
      written.current[k] = v
      el.style.setProperty(prop, v)
    }
    frame.current = (ms: number) => {
      const m = motion.current
      const b = box.current
      const target = clamp((window.scrollY - b.top) / b.range)
      // Ease the hand: a wheel notch or PageDown glides instead of jumping (the first frame starts where we are).
      const dt = m.last ? Math.min(64, ms - m.last) : 16
      m.p = m.last ? m.p + (target - m.p) * (1 - Math.exp(-dt / 110)) : target
      if (Math.abs(target - m.p) < 1e-4) m.p = target
      m.last = ms
      if (!m.t0) m.t0 = ms
      const p = m.p

      const share = mapShare(p)
      const diveScale = b.mapH / (0.8 * (b.globeH / 2) * INDIA_FRACTION) // India on the globe = India on the map
      const camScale = INDIA_SCALE + (diveScale - INDIA_SCALE) * diveShare(p)
      const mapScale = clamp((0.8 * camScale * (b.globeH / 2) * INDIA_FRACTION) / b.mapH, 0.6, 1)
      // The hand-off is an iris: the map opens in a widening circle from India's centre while the globe dives into it
      // (72% of the box diagonal covers the corners), and the globe fades only once the circle is wide.
      const crossing = share > 0 && share < 1
      put('globe', globeEl.current, 'opacity', (1 - ease(0.45, 1, share)).toFixed(3))
      put('map', mapEl.current, 'opacity', Math.min(1, share * 4).toFixed(3))
      put('mapClip', mapEl.current, 'clip-path', crossing ? `circle(${(share * 72).toFixed(2)}% at 50% 50%)` : 'none')
      put('mapScale', mapEl.current, 'scale', crossing ? mapScale.toFixed(4) : '1')
      put('mapWill', mapEl.current, 'will-change', crossing ? 'opacity, scale, clip-path' : 'auto')
      put('b0', b0El.current, 'opacity', (1 - ease(0.14, 0.24, p)).toFixed(3))
      put('b2', b2El.current, 'opacity', (ease(0.56, 0.62, p) * (1 - ease(0.72, 0.77, p))).toFixed(3))

      // Beat, with a little hysteresis so a reader parked on a boundary doesn't make the captions flicker.
      let bi = m.beat
      while (bi < 3 && p >= EDGES[bi] + 0.008) bi++
      while (bi > 0 && p < EDGES[bi - 1] - 0.008) bi--
      if (bi !== m.beat) { m.beat = bi; setBeatIdx(bi) }
      if (!m.mapIn && share >= 0.35) { m.mapIn = true; setMapIn(true) } // the map's wave plays once, where it's seen
      const atk = p >= 0.895
      if (atk !== m.atk) { m.atk = atk; setAttacksOn(atk) }

      // The world turns for a few seconds on arrival, then holds (WCAG 2.2.2); scrolling turns it further.
      const turn = at('toIndia', p)
      m.spin += dt * 0.00012 * (1 - ease(3000, 5000, ms - m.t0)) * (1 - turn)
      const worldPhi = m.spin + p * 2.2
      if (turn === 0) m.dir = 0
      else if (!m.dir) m.dir = Math.sign(shortWay(worldPhi, INDIA_CAM.phi)) || 1

      if (share >= 0.999) { m.key = ''; return null } // the map covers the globe: let the GPU rest
      const key = `${p.toFixed(5)}|${worldPhi.toFixed(4)}|${b.globeH}|${b.mapH}`
      if (key === m.key) return null // nothing moved
      m.key = key
      const s = sceneRef.current
      const f = frameFor(s, p, { worldPhi, dir: m.dir, diveScale })
      // cobe re-uploads marker and arc buffers whenever they are passed: pass them only when they change.
      const mk = ease(0.2, 0.38, p).toFixed(3)
      if (m.mk === mk && m.ms === s) delete f.markers
      else { m.mk = mk; m.ms = s }
      const ak = `${at('arc', p).toFixed(4)}|${at('arcFade', p).toFixed(3)}`
      if (m.ak === ak && m.as === s) delete f.arcs
      else { m.ak = ak; m.as = s }
      return f
    }
  })

  const scrollToP = (p: number) => {
    const b = box.current
    window.scrollTo({ top: b.top + p * b.range, behavior: 'smooth' })
  }

  // ---- words, all computed from the data
  const s = soc.data
  const feeds = (sources.data ?? []).filter((x) => x.provenance === 'REAL' && !/model/i.test(x.kind))
  const items = (name: string) => feeds.find((f) => f.name === name)?.items ?? null
  const cves = items('NVD CVE feeds'), kevs = items('CISA KEV'), attacks = items('SANS ISC DShield')
  const updated = feeds.map((f) => f.updated).filter((u): u is string => !!u).sort((a, b) => Date.parse(a) - Date.parse(b)).at(-1) ?? null
  const online = feodo.entries.filter((e) => e.status === 'online').length
  const nOrgs = s?.orgs.length ?? 0
  const nStates = threats.length
  const sectors = new Set((s?.orgs ?? []).map((o) => o.sector)).size
  const mostCrit = [...threats].sort((a, b) => b.critical - a.critical)[0]
  const compStates = threats.filter((t) => t.compromise > 0)
  const compOrgs = [...new Set(openComp.map((c) => c.org_name))]
  const pending = s?.pending ?? null
  const real = (what: string) => (sample ? 'Sample data, not real.' : what)

  const evidence = beaconRule && /(\d+)\s+connections?\s+every\s+~?([\d.]+)\s*s/i.exec(beaconRule.evidence)
  const period = evidence ? Number(evidence[2]) : null
  const rate = period == null ? null : period >= 45 && period <= 75 ? 'about one a minute' : `about one every ${Math.round(period)} seconds`
  const prior = bayes?.factors[0]
  const reasons = prior ? [
    /exposed=True/.test(prior.detail) && 'runs an affected version',
    /internet-facing=True/.test(prior.detail) && 'faces the internet',
    /exploited in the wild=True/.test(prior.detail) && 'carries a flaw exploited in the wild',
  ].filter(Boolean) as string[] : []
  const factor = bayes?.factors.find((f) => /beacon/i.test(f.factor))?.value
  const joined = (xs: string[]) => xs.length < 2 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs.at(-1)}`

  const downBlock = down ? (
    <>
      <h2 className={H2}>Odyssey isn't answering</h2>
      <p className={LEAD}>The page couldn't reach the Odyssey backend ({down}). Nothing here is a guess, so the numbers are left out.</p>
      <button type="button" className="pill pill-secondary mt-6" onClick={retry}>Try again</button>
    </>
  ) : null

  const beats: { say: string; body: ReactNode }[] = [
    {
      say: 'Attacks start far from home',
      body: (
        <>
          <h1 className={H1}>Attacks start far from home</h1>
          <p className={LEAD}>
            Odyssey reads {feeds.length ? num(feeds.length) : 'the'} public threat feeds and warns India's critical-infrastructure
            operators about the threats that can reach them.
          </p>
          {cves != null && kevs != null && (
            <p className={`${LINE} mt-4`}>
              {sample ? 'Sample data, not real: ' : null}<span className="fig">{num(cves)}</span> CVEs, <span className="fig">{num(kevs)}</span> known-exploited entries
              {attacks ? <> and <span className="fig">{num(attacks / 1e6, 1)} million</span> attack records</> : null}, updated {dateTime(updated)}.
            </p>
          )}
          <div className="mt-6"><Key color="var(--color-c2)">Botnet command server: {num(feodo.entries.length)} listed, {num(online)} online</Key></div>
          <p className={`${LINE} mt-2`}>Real: abuse.ch Feodo Tracker list of {date(feodo.taken_at)}.</p>
        </>
      ),
    },
    {
      say: s ? `${num(s.tiers.Critical ?? 0)} Critical warnings at home` : 'Critical warnings at home',
      body: downBlock ?? (
        <>
          <h2 className={H2}>{s ? <><CountUp to={s.tiers.Critical ?? 0} run={!still && beatIdx === 1} /> Critical warnings at home</> : <><Skel w="3ch" /> Critical warnings at home</>}</h2>
          <p className={LEAD}>
            {s ? <>They fall on {plural(nOrgs, 'simulated operator', 'simulated operators')} in {plural(nStates, 'state', 'states')} and {plural(sectors, 'sector', 'sectors')}.</> : 'Loading the operators…'}
            {mostCrit ? <> {mostCrit.name} has the most{compStates.length === 1 ? (compStates[0] === mostCrit ? ', and the only suspected compromise' : `; ${compStates[0].name} has the only suspected compromise`) : ''}.</> : null}
          </p>
          <div className="mt-6 max-w-[26rem]"><StateList threats={threats} hover={hover} onHover={setHover} loading={soc.loading} /></div>
          {unplaced > 0 && <p className={`${LINE} mt-2`}>{plural(unplaced, 'operator is', 'operators are')} not placed on the map.</p>}
          <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2">
            <Key color="var(--color-critical)">Operator, sized by Critical warnings</Key>
            <Key color="var(--color-compromise)">Suspected compromise</Key>
          </div>
          <p className={`${LINE} mt-2`}>{sample ? 'Sample data, not real.' : `Simulated: the ${num(nOrgs)} operators. Real: their CVEs, from NVD, CISA KEV and FIRST EPSS.`}</p>
        </>
      ),
    },
    {
      say: sighting ? 'One gateway is calling a botnet' : 'The evidence',
      body: downBlock ?? (
        <>
          <h2 className={H2}>
            {sighting ? 'One gateway is calling a botnet'
              : (feed.loading || profile.loading) ? 'Checking gateway telemetry'
              : (profile.error || detail.error) ? 'The evidence didn’t load'
              : 'No gateway is calling a known botnet'}
          </h2>
          {sighting && hot ? (
            <>
              <p className={`${LEAD} [overflow-wrap:anywhere]`}>
                <span translate="no">{asset?.hostname ?? sighting.asset}</span>, {asset ? `a ${ROLE[asset.role] ?? asset.label}` : 'an asset'} at {hot.org_name},
                has made {evidence ? <><span className="fig">{num(Number(evidence[1]))}</span> connections to</> : 'connections to'}{' '}
                <span className="fig" translate="no">{sighting.c2}</span>{rate ? `, ${rate}` : ''}. abuse.ch Feodo Tracker lists that address
                as a {sighting.malware} command server{c2Entry ? ` in ${inCountry(c2Entry.country)}` : ''}.
              </p>
              {bayes && (
                <p className={`${LEAD} mt-3`}>
                  Odyssey's model puts the chance of compromise at <span className="fig">{pct(bayes.p_compromise)}</span>.
                  {reasons.length ? <> The gateway starts at <span className="fig">{pct(bayes.prior)}</span> because it {joined(reasons)}</> : null}
                  {reasons.length && factor ? <>; the beacon multiplies those odds by <span className="fig">{num(factor)}</span>.</> : reasons.length ? '.' : null}
                </p>
              )}
              <a href={`#/incident/${hot.org_id}/${hot.cve_id}`} className="mt-4 inline-block text-[15px] text-accent hover:underline">See the evidence</a>
              <p className={`${LINE} mt-4`}>{sample ? 'Sample data, not real.' : `Simulated: the firewall logs that show the beacon. Real: the ${sighting.malware} server, from abuse.ch Feodo Tracker.`}</p>
            </>
          ) : (
            <p className={LEAD}>
              {(feed.loading || profile.loading) ? 'Looking for beacons from the operators’ gateways to known botnet servers.'
                : (profile.error || detail.error) ? `The gateway telemetry didn't load (${profile.error ?? detail.error}).`
                : 'No operator gateway is talking to a server on abuse.ch Feodo Tracker in this data.'}
            </p>
          )}
        </>
      ),
    },
    {
      say: pending ? `${plural(pending, 'decision needs', 'decisions need')} a person` : 'What to do now',
      body: downBlock ?? (
        <>
          <h2 className={H2}>{pending == null ? <><Skel w="2ch" /> decisions need a person</> : pending ? <>{plural(pending, 'decision needs', 'decisions need')} a person</> : 'Nothing is waiting for a person'}</h2>
          <p className={LEAD}>
            {compOrgs.length === 1 ? <>{compOrgs[0]} is suspected compromised, with {openComp.length === 1 ? '1 open warning and its evidence' : `${num(openComp.length)} open warnings and the evidence for each`}.</>
              : compOrgs.length > 1 ? <>{plural(compOrgs.length, 'operator is', 'operators are')} suspected compromised, with {num(openComp.length)} open warnings and the evidence for each.</>
              : feed.data ? 'No operator is suspected compromised right now.' : 'Loading the warnings…'}
            {pending ? <> Odyssey has proposed {plural(pending, 'action', 'actions')}, and none runs until a person approves it.</> : null}
          </p>
          {hot && <div className="mt-6"><HeroClock card={hot} /></div>}
          <div className="mt-6 flex flex-wrap items-center gap-x-6 gap-y-3">
            {hot && <a href={`#/incident/${hot.org_id}/${hot.cve_id}`} className="pill pill-primary">Open the incident <ArrowRight size={16} aria-hidden /></a>}
            {pending ? <a href="#/decisions" className="text-[15px] text-accent hover:underline">Review {plural(pending, 'decision', 'decisions')}</a> : null}
          </div>
          {origins.length > 0 && (
            <div className="mt-6 flex flex-wrap gap-x-5 gap-y-2">
              <Key color="var(--color-attack)">Attack reports, SANS ISC DShield</Key>
              {origins.some((o) => o.kind === 'c2') && <Key color="var(--color-c2)">Botnet command servers, Feodo Tracker</Key>}
            </div>
          )}
          {topAlerts.length > 0 && (
            <div className="mt-6 lg:hidden">
              <p className="mb-2 text-[15px] text-mute">{sample ? 'Worst CVE in the top states (sample data)' : 'Worst real CVE in the top states'}</p>
              <ol className="space-y-1.5">
                {threats.slice(0, 3).flatMap((t) => (t.top ? [{ t, a: t.top }] : [])).map(({ t, a }) => (
                  <li key={t.name} className="text-[15px] [overflow-wrap:anywhere]">
                    <a href={`#/incident/${a.org_id}/${a.cve_id}`} className="group">
                      <span>{t.name}: </span>
                      <span className="fig underline-offset-4 group-hover:underline" translate="no">{a.cve_id}</span>
                      {productNames[a.id] ? <span className="text-mute">, {productNames[a.id]}</span> : null}
                      {a.kev ? <span className="text-mute">, in CISA KEV</span> : null}
                    </a>
                  </li>
                ))}
              </ol>
            </div>
          )}
          <p className={`${LINE} mt-3`}>
            {real(`Real: the CVEs, the CERT-In 6-hour rule and where the arrows start (DShield's top attacking countries, located by RIPEstat on ${date(attackers.taken_at)}${origins.some((o) => o.kind === 'c2') ? ', and Feodo Tracker botnet servers' : ''}). Simulated: the operators, incidents and proposals, and where the arrows land (the operators with the most Critical warnings).`)}
          </p>
        </>
      ),
    },
  ]

  // Globe labels: decorative duplicates of the captions (aria-hidden inside Globe), on solid plates.
  const worldLabels = scene.c2Countries.map((g) => (
    <span key={g.id} className="globe-label globe-label-right" style={{ '--anchor': `--cobe-${g.id}`, opacity: `var(--cobe-visible-${g.id}, 0)` } as CSSProperties}>
      <span className="text-text">{regionName(g.country)}</span>: {plural(g.count, 'server', 'servers')}{g.online ? `, ${num(g.online)} online` : ''}
    </span>
  ))
  const evidenceLabels = scene.beacon && hot ? (
    <>
      <span className="globe-label globe-label-left globe-label-alert" style={{ '--anchor': `--cobe-org-${slug(scene.beacon.orgId)}`, opacity: `var(--cobe-visible-org-${slug(scene.beacon.orgId)}, 0)` } as CSSProperties}>
        {hot.org_name}
      </span>
      <span className="globe-label globe-label-right text-text" style={{ '--anchor': `--cobe-${scene.beacon.c2Id}`, opacity: `var(--cobe-visible-${scene.beacon.c2Id}, 0)` } as CSSProperties}>
        {sighting?.malware} server <span className="fig">{sighting?.c2}</span>
      </span>
    </>
  ) : null
  const globeLabel = `Globe: ${plural(feodo.entries.length, 'botnet command server', 'botnet command servers')} on abuse.ch Feodo Tracker, ${num(online)} online on ${date(feodo.taken_at)}`
    + (scene.beacon && hot && sighting ? `; a beacon from ${hot.org_name} (simulated logs) to the ${sighting.malware} server ${sighting.c2}` : '')

  if (still) {
    // The finished page: no pinning, no spin, no scrubbing. Each beat beside its own still picture.
    const figure = (i: number) => {
      if (i === 0) return <div className="relative mx-auto aspect-square w-full max-w-[520px]"><StillGlobe scene={scene} pose={0.02} label={globeLabel}>{worldLabels}</StillGlobe></div>
      if (i === 2) return scene.beacon ? <div className="relative mx-auto aspect-square w-full max-w-[520px]"><StillGlobe scene={scene} pose={0.7} label={globeLabel}>{evidenceLabels}</StillGlobe></div> : null
      return (
        // The stacked page's map is smaller than the stage's: its CVEs live in the beat-4 list beside it, not as chips.
        <div className="mx-auto aspect-[612/696] w-full max-w-[560px]">
          <IndiaMap threats={threats} names={productNames} showCves={false} entered interactive hover={hover} onHover={setHover} origins={i === 3 ? origins : []} showAttacks={i === 3} />
        </div>
      )
    }
    return (
      <div className="landing">
        <LandingHeader quiet={false} down={down} still />
        <main className="mx-auto max-w-[1200px] space-y-24 px-5 pt-24 pb-8 sm:px-8 md:px-10">
          {beats.map((b, i) => (
            <section key={i} aria-label={b.say} className="grid grid-cols-1 items-center gap-10 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <div className="min-w-0"><Count i={i} />{b.body}</div>
              <div className="min-w-0">{figure(i)}</div>
            </section>
          ))}
        </main>
        <Credits />
      </div>
    )
  }

  return (
    <div className="landing">
      <LandingHeader quiet={beatIdx === 3} down={down} still={false} />
      <main>
        <section ref={story} className="relative h-[460svh]" aria-label="Odyssey in four steps">
          <div ref={stage} className="landing-stage sticky top-0 h-svh overflow-hidden">
            <div ref={figureEl} className="landing-figure">
              <div ref={globeEl} className="landing-globe">
                <Globe frame={frame} label={globeLabel} onFail={() => setFailed(true)}>
                  <div ref={b0El}>{worldLabels}</div>
                  <div ref={b2El} className="landing-b2">{evidenceLabels}</div>
                </Globe>
              </div>
              <div ref={mapEl} className="landing-map" inert={!onIndia} aria-hidden={!onIndia}>
                <IndiaMap threats={threats} names={productNames} showCves={beatIdx === 3} entered={mapIn} interactive={onIndia} hover={hover} onHover={setHover} origins={origins} showAttacks={attacksOn} />
              </div>
            </div>

            {/* Captions: under the figure on solid black on phones; a left column from md. */}
            <div className="absolute inset-x-0 top-[calc(56px+38svh)] bottom-0 overflow-hidden bg-ground px-5 pt-3 pb-6 sm:px-8 md:inset-y-0 md:top-14 md:right-auto md:flex md:w-[calc(var(--cap)_+_40px)] md:items-center md:bg-transparent md:p-0 md:pl-10">
              <div className="grid w-full">
                {beats.map((b, i) => (
                  <div key={i} inert={i !== beatIdx}
                    className={`landing-beat col-start-1 row-start-1 self-start md:self-center ${i === beatIdx ? 'is-on' : i < beatIdx ? 'is-past' : ''}`}>
                    <Count i={i} />
                    {b.body}
                  </div>
                ))}
              </div>
            </div>
            <p className="sr-only" aria-live="polite">{`${beatIdx + 1} of 4. ${beats[beatIdx].say}`}</p>

            {/* Step rail: where you are; each mark jumps to its beat. */}
            <nav className="absolute top-1/2 left-2 hidden -translate-y-1/2 flex-col md:flex" aria-label="Story steps">
              {RAIL.map((r, i) => (
                <button key={r.title} type="button" title={r.title} aria-label={`${i + 1} of 4: ${r.title}`} aria-current={i === beatIdx ? 'step' : undefined}
                  onClick={() => scrollToP(r.p)} className="group flex h-11 w-6 items-center justify-center">
                  <span className={`block h-8 w-[3px] origin-center rounded-full transition-[scale,background-color] duration-200 ease-out ${i === beatIdx ? 'scale-y-100 bg-text' : 'scale-y-[0.375] bg-faint group-hover:bg-mute'}`} />
                </button>
              ))}
            </nav>
          </div>
        </section>
      </main>
      <Credits />
    </div>
  )
}
