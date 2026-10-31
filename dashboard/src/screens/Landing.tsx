// The landing story: a pinned globe that the scroll drives through four beats.
//   1 world    – real botnet C2 servers (abuse.ch Feodo Tracker, bundled snapshot)
//   2 India    – the globe dives into a flat state map: one dot per operator, Critical counts per state
//   3 evidence – back on the globe, an arc grows from the compromised operator to the C2 its gateway beaconed to
//   4 act      – the India map again, with each top state's worst real CVE; what a person must do now
// Every layer says whether it is real or simulated (CLAUDE.md rule 17). Reduced motion gets a still, stacked version.
import type { COBEOptions } from 'cobe'
import { ArrowDown, ArrowRight } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import { api, useLoad } from '../data'
import { num } from '../format'
import feodo from '../geo/feodo.json'
import { anglesFor, COUNTRY_CENTROID, INDIA, refang, sideOf, slerp, spread, STATE_CENTROID, type LatLng } from '../geo/geo'
import { Globe, type GlobeFrame } from '../geo/Globe'
import { IndiaMap, type StateThreat } from '../geo/IndiaMap'
import type { Card, Soc } from '../types'
import { Countdown } from '../ui'

type RGB = [number, number, number]
const RED: RGB = [1, 0.27, 0.23]      // --color-compromise
const ORANGE: RGB = [1, 0.62, 0.04]   // --color-critical
const BLUE: RGB = [0.39, 0.82, 1]     // botnet C2 server (identity, not a tier)

const clamp = (x: number, a = 0, b = 1) => Math.min(b, Math.max(a, x))
const ease = (a: number, b: number, x: number) => { const t = clamp((x - a) / (b - a)); return t * t * (3 - 2 * t) }
const lerp = (a: number, b: number, t: number) => a + (b - a) * t
const mixRGB = (a: RGB, b: RGB, t: number): RGB => [lerp(a[0], b[0], t), lerp(a[1], b[1], t), lerp(a[2], b[2], t)]
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-')
const vars = (o: Record<string, string | number>) => o as CSSProperties

interface Cam { phi: number; theta: number; scale: number }
/** Blend two cameras, turning the short way round. */
function mixCam(a: Cam, b: Cam, t: number): Cam {
  let d = (b.phi - a.phi) % (2 * Math.PI)
  if (d > Math.PI) d -= 2 * Math.PI
  if (d < -Math.PI) d += 2 * Math.PI
  return { phi: a.phi + d * t, theta: lerp(a.theta, b.theta, t), scale: lerp(a.scale, b.scale, t) }
}
const camAt = (p: LatLng, scale: number): Cam => ({ ...anglesFor(p), scale })

interface OrgDot { id: string; name: string; state: string; at: LatLng; critical: number; compromise: number }
interface Scene {
  orgs: OrgDot[]
  states: { name: string; at: LatLng; count: number }[]
  c2: { id: string; ip: string; malware: string; country: string; online: boolean; at: LatLng }[]
  /** One label per country, hung on that country's first server. */
  c2Countries: { id: string; country: string; count: number; online: number }[]
  beacon: { from: LatLng; to: LatLng; c2Id: string } | null
}

const regionName = (() => {
  try { const d = new Intl.DisplayNames(['en'], { type: 'region' }); return (cc: string) => d.of(cc) ?? cc } catch { return (cc: string) => cc }
})()

function buildScene(soc: Soc | null, beaconOrg: string | null, beaconIp: string | null): Scene {
  const byState = new Map<string, Soc['orgs']>()
  for (const o of soc?.orgs ?? []) byState.set(o.state, [...(byState.get(o.state) ?? []), o])
  const orgs: OrgDot[] = []
  const states: Scene['states'] = []
  for (const [state, list] of byState) {
    const c = STATE_CENTROID[state]
    if (!c) continue
    states.push({ name: state, at: c, count: list.length })
    list.forEach((o, i) => orgs.push({ id: o.id, name: o.name, state, at: spread(c, i, list.length), critical: o.critical, compromise: o.compromise }))
  }
  const c2 = feodo.entries.flatMap((e, i) => {
    const at = COUNTRY_CENTROID[e.country]
    // Several servers in one country fan out a little so each stays visible.
    return at ? [{ id: `c2-${i}`, ip: e.ip, malware: e.malware, country: e.country, online: e.status === 'online', at: spread(at, i % 3, 3) }] : []
  })
  const c2Countries: Scene['c2Countries'] = []
  for (const c of c2) {
    const g = c2Countries.find((x) => x.country === c.country)
    if (g) { g.count++; g.online += c.online ? 1 : 0 } else c2Countries.push({ id: c.id, country: c.country, count: 1, online: c.online ? 1 : 0 })
  }
  const from = orgs.find((o) => o.id === beaconOrg)?.at
  const target = beaconIp ? c2.find((c) => c.ip === beaconIp) : undefined
  return { orgs, states, c2, c2Countries, beacon: from && target ? { from, to: target.at, c2Id: target.id } : null }
}

/** Scroll timeline (p = 0..1). The India map takes over from the globe twice: once for the constituency, once at the end. */
const T = {
  toIndia: [0.12, 0.28], dive1: [0.27, 0.34], undive: [0.44, 0.49], arc: [0.5, 0.74], arcFade: [0.74, 0.79],
  back: [0.75, 0.83], dive2: [0.81, 0.88],
} as const
const at = (k: keyof typeof T, p: number) => ease(T[k][0], T[k][1], p)
/** How much of the India map shows over the globe. */
const mapShare = (p: number) => at('dive1', p) * (1 - at('undive', p)) + at('dive2', p)

/** The globe's state for scroll progress p (0..1) and time ms. Pure: everything the picture shows comes from here. */
function frameFor(s: Scene, p: number, ms: number, still: boolean): Partial<COBEOptions> {
  const toIndia = still ? 1 : at('toIndia', p)
  const arcT = still ? 1 : at('arc', p)
  const back = still ? 1 : at('back', p)
  const beat = (t: number) => (still ? 0 : 0.5 + 0.5 * Math.sin(ms / t))

  const world: Cam = { phi: still ? 0 : ms * 0.00012, theta: 0.28, scale: 1 }
  const india = camAt(INDIA, 1.85)
  let cam = mixCam(world, india, toIndia)
  if (s.beacon && p >= 0.49 && !still) {
    // Pull back to a side-on view, perpendicular to the arc's great circle, so the arc reads as a curve over the top
    // of the globe with both ends in view. Then hold while it grows, and return to India.
    const n = sideOf(s.beacon.from, s.beacon.to)
    const sideCam = mixCam(india, camAt([Math.min(60, n[0] + 28), n[1]], 0.95), ease(0, 0.35, arcT))
    cam = mixCam(sideCam, india, back)
  }
  // Dive: zoom hard into India while the flat map fades in over it.
  if (!still) cam.scale += 1.3 * Math.max(at('dive1', p) * (1 - at('undive', p)), at('dive2', p))

  const maxCrit = Math.max(1, ...s.orgs.map((o) => o.critical))
  const grow = still ? 1 : ease(0.2, 0.38, p)
  const markers: COBEOptions['markers'] = [
    ...s.c2.map((c) => ({
      id: c.id, location: c.at, color: BLUE,
      size: c.online ? 0.05 + 0.02 * beat(260) : 0.035,
    })),
    // Compromised operators last, so their dot draws on top of neighbours in the same state.
    ...[...s.orgs].sort((a, b) => a.compromise - b.compromise).map((o) => ({
      id: `org-${slug(o.id)}`, location: o.at, color: o.compromise > 0 ? RED : ORANGE,
      size: grow * (o.compromise > 0 ? 0.024 + 0.012 * beat(200) : 0.007 + 0.013 * Math.sqrt(o.critical / maxCrit)),
    })),
  ]
  // The beacon arc pulses while it travels, then fades out before the camera returns to India (no line across the map).
  const fade = still ? 0 : at('arcFade', p)
  const arcs: COBEOptions['arcs'] = s.beacon && arcT > 0.001 && fade < 0.999 && !still
    ? [{ id: 'beacon', from: s.beacon.from, to: slerp(s.beacon.from, s.beacon.to, arcT), color: mixRGB(mixRGB(RED, [1, 0.62, 0.56], beat(220)), [0.1, 0.1, 0.12], fade) }]
    : []
  const heat = still ? 0 : ease(0.5, 0.58, p) * (1 - ease(0.74, 0.82, p))
  return {
    ...cam, markers, arcs,
    glowColor: mixRGB([0.36, 0.38, 0.46], [0.6, 0.13, 0.1], heat),
    mapBrightness: lerp(7, 4.6, heat),
  }
}

/** Scroll progress through the element: 0 when its top meets the viewport top, 1 when its bottom meets the bottom. */
function progressOf(el: HTMLElement | null): number {
  if (!el) return 0
  const r = el.getBoundingClientRect()
  return clamp(-r.top / Math.max(1, r.height - window.innerHeight))
}

function useReducedMotion(): boolean {
  const q = '(prefers-reduced-motion: reduce)'
  const [reduce, setReduce] = useState(() => window.matchMedia(q).matches)
  useEffect(() => {
    const m = window.matchMedia(q)
    const on = () => setReduce(m.matches)
    m.addEventListener('change', on)
    return () => m.removeEventListener('change', on)
  }, [])
  return reduce
}

/** Counts up to `to` the first time `run` is true. */
function CountUp({ to, run, digits = 0 }: { to: number | null | undefined; run: boolean; digits?: number }) {
  const [v, setV] = useState(0)
  const done = useRef(false)
  useEffect(() => {
    if (to == null || !run || done.current) return
    done.current = true
    let raf = 0
    const t0 = performance.now()
    const tick = (t: number) => {
      const k = clamp((t - t0) / 900)
      setV(to * (1 - (1 - k) ** 3))
      if (k < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [to, run])
  if (to == null) return <>—</>
  return <span className="num">{num(done.current ? v : to, digits)}</span>
}

function Tag({ children }: { children: ReactNode }) {
  return <span className="rounded-full bg-raised/80 px-2.5 py-1 text-[12px] text-mute backdrop-blur">{children}</span>
}

function Key({ color, children, ring }: { color: string; children: ReactNode; ring?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 text-[13px] text-mute">
      <span className={`size-2.5 shrink-0 rounded-full ${ring ? 'ring-4 ring-compromise/25' : ''}`} style={{ background: color }} aria-hidden />
      {children}
    </span>
  )
}

export function Landing() {
  const soc = useLoad(api.soc, 'soc')
  const feed = useLoad(api.feed, 'feed')
  const sources = useLoad(api.intelSources, 'sources')
  const cards = feed.data?.cards ?? []
  const hot: Card | undefined = cards.find((c) => c.tier === 'Compromise' && c.workflow.state !== 'closed') ?? cards.find((c) => c.tier === 'Compromise')
  const profile = useLoad(hot ? () => api.orgProfile(hot.org_id) : null, `profile:${hot?.org_id}`)
  const detail = useLoad(hot ? () => api.alert(hot.org_id, hot.cve_id) : null, `alert:${hot?.id}`)

  const sighting = profile.data?.indicators.c2_sightings[0]
  const c2Ip = sighting ? refang(sighting.c2) : null
  const c2Entry = feodo.entries.find((e) => e.ip === c2Ip)
  const asset = detail.data?.assets.find((a) => a.rules.some((r) => r.id === 'IOC_SIGHTING')) ?? detail.data?.assets[0]
  const beaconRule = asset?.rules.find((r) => r.id === 'IOC_SIGHTING')

  const scene = useMemo(() => buildScene(soc.data, hot?.org_id ?? null, c2Ip), [soc.data, hot?.org_id, c2Ip])
  const still = useReducedMotion()

  // Per-state threat for the India map: operators, Critical counts, and the worst real CVE (alerts come risk-sorted).
  const alerts = useLoad(() => api.alerts(400), 'alerts:400')
  const threats = useMemo<StateThreat[]>(() => {
    const out = new Map<string, StateThreat>()
    for (const o of soc.data?.orgs ?? []) {
      const t = out.get(o.state) ?? { name: o.state, operators: [], critical: 0, compromise: 0, top: null }
      t.operators.push({ id: o.id, name: o.name, critical: o.critical, compromise: o.compromise })
      t.critical += o.critical
      t.compromise += o.compromise
      out.set(o.state, t)
    }
    const stateOf = new Map((soc.data?.orgs ?? []).map((o) => [o.id, o.state]))
    for (const a of alerts.data ?? []) {
      const t = out.get(stateOf.get(a.org_id) ?? '')
      if (t && !t.top && (a.tier === 'Compromise' || a.tier === 'Critical')) t.top = a
    }
    return [...out.values()]
  }, [soc.data, alerts.data])

  const story = useRef<HTMLElement>(null)
  const stage = useRef<HTMLDivElement>(null)
  const [beatIdx, setBeatIdx] = useState(0)
  const sceneRef = useRef(scene)
  sceneRef.current = scene
  const beatRef = useRef(0)

  // One function per frame: read the scroll, publish it to CSS, and hand the globe its state.
  const frame = useRef<GlobeFrame>(() => ({}))
  frame.current = (ms: number) => {
    const p = still ? 1 : progressOf(story.current)
    const st = stage.current?.style
    if (st) {
      st.setProperty('--p', p.toFixed(4))
      st.setProperty('--b0', (1 - ease(0.14, 0.24, p)).toFixed(3))                       // world labels
      st.setProperty('--b2', (ease(0.54, 0.6, p) * (1 - ease(0.72, 0.77, p))).toFixed(3)) // evidence labels
      st.setProperty('--map', (still ? 1 : mapShare(p)).toFixed(3))                    // India map over the globe
      st.setProperty('--heat', (ease(0.5, 0.58, p) * (1 - ease(0.74, 0.82, p))).toFixed(3))
    }
    const b = p < 0.27 ? 0 : p < 0.48 ? 1 : p < 0.8 ? 2 : 3
    if (b !== beatRef.current) { beatRef.current = b; setBeatIdx(b) }
    return frameFor(sceneRef.current, p, ms, still)
  }

  const s = soc.data
  const real = (sources.data ?? []).filter((x) => x.provenance === 'REAL')
  const records = real.reduce((n, x) => n + (x.items ?? 0), 0)
  const critical = s?.tiers.Critical ?? null
  const compromise = s?.tiers.Compromise ?? null
  const compromisedOrgs = s ? s.orgs.filter((o) => o.compromise > 0).length : null
  const plural = (n: number | null, one: string, many: string) => `${n ?? '—'} ${n === 1 ? one : many}`

  /** Scroll so the story sits at progress p (the rail), or past it (skip). */
  const scrollToP = (p: number) => {
    const el = story.current
    if (!el) return
    const top = el.getBoundingClientRect().top + window.scrollY
    window.scrollTo({ top: top + p * (el.offsetHeight - window.innerHeight), behavior: 'smooth' })
  }
  const skip = () => document.getElementById('overview-start')?.scrollIntoView({ behavior: still ? 'auto' : 'smooth' })
  const online = feodo.entries.filter((e) => e.status === 'online').length

  const beats: { eyebrow: string; body: ReactNode }[] = [
    {
      eyebrow: 'Odyssey · national cyber early warning',
      body: (
        <>
          <h1 className="text-[clamp(40px,5.4vw,76px)] font-semibold leading-[0.98] tracking-[-0.035em]">
            Attacks start<br />far from home.
          </h1>
          <p className="mt-5 max-w-[30rem] text-[17px] leading-relaxed text-mute">
            Odyssey reads every public threat feed, every day: <CountUp to={records || null} run={beatIdx === 0} /> records
            from {real.length || '—'} sources in tonight's snapshot, from CVE lists to botnet trackers.
          </p>
          <div className="mt-6 flex flex-wrap gap-x-5 gap-y-2">
            <Key color="#64d2ff">Botnet C2 server · {feodo.entries.length} listed, {online} online</Key>
          </div>
          <div className="mt-3 flex flex-wrap gap-2"><Tag>Real · {feodo.source}</Tag></div>
          <button onClick={skip} className="mt-8 inline-flex items-center gap-1.5 text-[13px] text-faint hover:text-text">
            Skip to the console <ArrowDown size={13} />
          </button>
        </>
      ),
    },
    {
      eyebrow: '02 · Who it matters to',
      body: (
        <>
          <h2 className="text-[clamp(32px,3.8vw,52px)] font-semibold leading-[1.02] tracking-[-0.03em]">
            {s?.orgs.length ?? '—'} operators.<br />{scene.states.length || '—'} states.<br />
            <span className="text-critical"><CountUp to={critical} run={beatIdx === 1} /> Critical.</span>
          </h2>
          <p className="mt-5 max-w-[30rem] text-[16px] leading-relaxed text-mute">
            Each dot is a critical-infrastructure operator Odyssey protects. The bigger the dot, the more Critical
            warnings it carries. Red means one of its assets is suspected compromised. Hover a state for its worst CVE.
          </p>
          <div className="mt-6 flex flex-wrap gap-x-5 gap-y-2">
            <Key color="var(--color-critical)">Operator · size = Critical warnings</Key>
            <Key color="var(--color-compromise)" ring>Suspected compromise</Key>
          </div>
          <div className="mt-3 flex flex-wrap gap-2"><Tag>Simulated operators</Tag><Tag>Real CVEs, CISA KEV, EPSS</Tag></div>
        </>
      ),
    },
    {
      eyebrow: '03 · The evidence',
      body: (
        <>
          <h2 className="text-[clamp(32px,3.8vw,52px)] font-semibold leading-[1.02] tracking-[-0.03em]">
            One gateway is<br /><span className="text-compromise">calling a botnet.</span>
          </h2>
          {sighting ? (
            <p className="mt-5 max-w-[31rem] text-[16px] leading-relaxed text-mute">
              <span className="text-text">{asset?.hostname ?? sighting.asset}</span> at {hot?.org_name} is talking to{' '}
              <span className="num text-text">{sighting.c2}</span>, a {sighting.malware} command server on Feodo Tracker
              {c2Entry ? ` (${c2Entry.country})` : ''}{beaconRule ? `: ${beaconRule.evidence}` : ''}.
              {asset?.bayes ? <> Odyssey puts the chance of compromise at <span className="num text-text">{num(asset.bayes.p_compromise * 100, 1)}%</span>.</> : null}
            </p>
          ) : (
            <p className="mt-5 max-w-[30rem] text-[16px] text-mute">{profile.loading || feed.loading ? 'Loading the evidence…' : 'No beacon to a known C2 in this data.'}</p>
          )}
          <div className="mt-6 flex flex-wrap gap-2"><Tag>Beacon · simulated firewall logs</Tag><Tag>C2 address · real</Tag></div>
        </>
      ),
    },
    {
      eyebrow: '04 · What a person does now',
      body: (
        <>
          <h2 className="text-[clamp(28px,2.7vw,40px)] font-semibold leading-[1.06] tracking-[-0.03em]">
            <span className="text-compromise">{plural(compromisedOrgs, 'operator', 'operators')} suspected compromised.</span><br />
            {plural(s?.pending ?? null, 'decision', 'decisions')} waiting<br />for a person.
          </h2>
          <p className="mt-4 text-[16px] text-mute">{plural(compromise, 'compromise warning', 'compromise warnings')} behind it, evidence attached to each.</p>
          {hot && (
            <p className="mt-5 text-[16px] text-mute">
              CERT-In report due in <span className="text-text"><Countdown issuedAt={hot.workflow.issued_at} hours={hot.deadline_hours} closed={hot.workflow.state === 'closed'} /></span>
            </p>
          )}
          <div className="mt-7 flex flex-wrap gap-3">
            {hot && (
              <a href={`#/incident/${hot.org_id}/${hot.cve_id}`} className="inline-flex h-10 items-center gap-2 rounded-md bg-text px-4 text-[14px] font-medium text-ground hover:brightness-90">
                Open the incident <ArrowRight size={15} />
              </a>
            )}
            <a href="#/decisions" className="inline-flex h-10 items-center gap-2 rounded-md bg-raised px-4 text-[14px] font-medium hover:bg-[#28282b]">Review decisions</a>
            <button onClick={skip} className="inline-flex h-10 items-center gap-1.5 rounded-md px-3 text-[14px] text-mute hover:bg-raised hover:text-text">
              Full overview <ArrowDown size={15} />
            </button>
          </div>
        </>
      ),
    },
  ]

  const labels = (
    <>
      <div style={{ opacity: 'var(--b0, 1)' }}>
        {scene.c2Countries.map((g) => (
          <span key={g.id} className="globe-label globe-label-right" style={vars({ '--anchor': `--cobe-${g.id}`, opacity: `var(--cobe-visible-${g.id}, 0)` })}>
            <span className="text-text">{regionName(g.country)}</span> · {g.count} C2{g.online ? `, ${g.online} online` : ''}
          </span>
        ))}
      </div>
      {scene.beacon && hot && (
        <div style={{ opacity: 'var(--b2, 0)' }}>
          <a href={`#/orgs/${hot.org_id}`} className="globe-label globe-label-left globe-label-strong globe-label-alert" style={vars({ '--anchor': `--cobe-org-${slug(hot.org_id)}`, opacity: `var(--cobe-visible-org-${slug(hot.org_id)}, 0)` })}>
            {hot.org_name}
          </a>
          <span className="globe-label globe-label-right globe-label-strong" style={vars({ '--anchor': `--cobe-${scene.beacon.c2Id}`, opacity: `var(--cobe-visible-${scene.beacon.c2Id}, 0)` })}>
            {sighting?.malware} C2 · <span className="num">{sighting?.c2}</span>
          </span>
        </div>
      )}
    </>
  )

  const fallback = <div className="flex size-full items-center justify-center text-[13px] text-faint">This browser has no WebGL, so the globe is off.</div>
  const onIndia = beatIdx === 1 || beatIdx === 3

  if (still) {
    // Reduced motion: no pinning, no spin, no scrubbing. The four beats in order beside the finished India map.
    return (
      <section className="mb-10 grid items-start gap-8 pt-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="space-y-12">{beats.map((b) => <div key={b.eyebrow}><div className="mb-3 text-[13px] text-faint">{b.eyebrow}</div>{b.body}</div>)}</div>
        <div ref={stage} className="flex h-[88vh] justify-center lg:sticky lg:top-6">
          <IndiaMap threats={threats} showCves entered interactive />
        </div>
      </section>
    )
  }

  return (
    <section ref={story} className="relative -mx-4 sm:-mx-6 lg:-ml-2 lg:-mr-6" style={{ height: '460vh' }} aria-label="Odyssey in four steps">
      <div ref={stage} className="landing-stage sticky top-0 h-screen overflow-hidden">
        <div className="landing-glow pointer-events-none absolute inset-0" aria-hidden />

        <div className="landing-globe absolute inset-x-0 top-[calc(56px+2vh)] mx-auto aspect-square w-[min(94vw,62vh)] lg:inset-x-auto lg:right-[-6%] lg:top-1/2 lg:w-[min(118vh,66vw)] lg:-translate-y-1/2">
          <Globe frame={frame} fallback={fallback}>{labels}</Globe>
        </div>
        {/* India, flat and big, slightly right: takes over from the globe on the India beats. */}
        <div className={`landing-map absolute inset-x-0 top-[calc(56px+1vh)] flex h-[44vh] justify-center lg:inset-x-auto lg:top-[5vh] lg:right-[3%] lg:h-[90vh] ${onIndia ? '' : 'pointer-events-none'}`}>
          <IndiaMap threats={threats} showCves={beatIdx === 3} entered={onIndia} interactive={onIndia} />
        </div>
        {/* Keeps the captions readable when the zoomed globe slides under them. */}
        <div className="pointer-events-none absolute inset-x-0 bottom-0 h-[58%] bg-gradient-to-t from-ground via-ground/90 to-transparent lg:inset-y-0 lg:right-auto lg:h-auto lg:w-[46%] lg:bg-gradient-to-r lg:via-ground/80" aria-hidden />

        {/* Captions: the active beat is in, the rest are out. Bottom on phones, left column from lg. */}
        <div className="absolute inset-x-0 bottom-0 px-5 pb-8 sm:px-8 lg:inset-y-0 lg:right-auto lg:flex lg:w-[min(520px,41%)] lg:items-center lg:pb-0 lg:pl-10">
          <div className="grid w-full">
            {beats.map((b, i) => (
              <div key={b.eyebrow} inert={i !== beatIdx}
                className={`landing-beat col-start-1 row-start-1 self-end lg:self-center ${i === beatIdx ? 'is-on' : i < beatIdx ? 'is-past' : ''}`}>
                <div className="mb-4 text-[13px] text-faint">{b.eyebrow}</div>
                {b.body}
              </div>
            ))}
          </div>
        </div>

        {/* Progress rail: where you are in the story; each mark jumps to its beat. */}
        <nav className="absolute top-1/2 left-3 hidden -translate-y-1/2 flex-col lg:flex" aria-label="Story steps">
          {beats.map((b, i) => (
            <button key={b.eyebrow} onClick={() => scrollToP([0.08, 0.4, 0.64, 0.97][i])} aria-label={b.eyebrow}
              aria-current={i === beatIdx ? 'step' : undefined} className="group flex h-10 w-6 items-center justify-center">
              <span className={`block w-[3px] rounded-full transition-[height,background-color] duration-300 ${i === beatIdx ? 'h-8 bg-text' : 'h-3 bg-line group-hover:bg-mute'}`} />
            </button>
          ))}
        </nav>
        <div className="landing-cue absolute bottom-6 left-1/2 flex -translate-x-1/2 items-center gap-2 text-[13px] text-faint max-lg:hidden" aria-hidden>
          Scroll <ArrowDown size={14} className="animate-bounce" />
        </div>
      </div>
    </section>
  )
}
