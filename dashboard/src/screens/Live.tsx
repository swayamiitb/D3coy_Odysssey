import { Check, Play, RotateCw } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { api, getMode, getSnapshotTakenAt, ReadOnlyError, usePoll } from '../data'
import { clock, dateTime, num } from '../format'
import type { Drill, LiveDetection, LiveDetectionKind, LiveFeed, LiveStatus, LiveTag, LiveTagPoint } from '../types'
import { Bars, Button, Empty, ErrorLine, Kpis, Mark, Panel, ShowAll, Spark, useNow } from '../ui'

/** The backend's surge threshold on decoy sessions (live.py). Its detector also needs unique sources at z ≥ 3 on at
 *  least 3 sensors before it fires, so a product can be over the line a tick before the detection lands. */
const SURGE_Z = 4
const RAISED_Z = 2
const POLL_MS = 2500

const KIND: Record<LiveDetectionKind, string> = { surge: 'Scanning surge', beacon: 'C2 beacon', anomaly: 'Flow anomaly' }
const STEP: Record<LiveDetectionKind, string> = {
  surge: 'Scanning surge detected', beacon: 'Implant beacon detected', anomaly: 'Lateral movement detected',
}

export const time = (iso: string | null | undefined) => (iso ? clock(Date.parse(iso)) : '—')

/** "12 s ago", "3 min ago", against the console clock (the snapshot's clock in snapshot mode). */
export function ago(iso: string | null | undefined, t: number): string {
  if (!iso) return '—'
  const s = Math.max(0, Math.round((t - Date.parse(iso)) / 1000))
  return s < 60 ? `${s} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`
}

const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`

/** When a polled screen last updated. A failed refresh says so inline, with Retry; a snapshot says it is frozen. */
export function Freshness({ at, error, onRetry }: { at: number | null; error: string | null; onRetry: () => void }) {
  const mode = getMode()
  if (mode === 'snapshot') return <p className="text-[13px] text-mute">Saved snapshot from {dateTime(getSnapshotTakenAt())}: frozen, not updating.</p>
  if (mode === 'sample') return null // the console's sample banner already says it
  if (error && at) {
    return (
      <div className="flex flex-wrap items-center gap-3 text-[13px] text-mute">
        <span>Couldn’t refresh: {error}. Showing the reading from <span className="num">{clock(at)}</span> IST.</span>
        <Button size="sm" onClick={onRetry}><RotateCw size={13} /> Retry</Button>
      </div>
    )
  }
  return <p className="num text-[13px] text-mute">{at ? `Updated ${clock(at)} IST, every ${num(POLL_MS / 1000, 1)} s` : 'Connecting…'}</p>
}

/** One action at a time per block; the error (or the read-only notice) stays inline under it, never an alert. */
export function useAction() {
  const [busy, setBusy] = useState<string | null>(null)
  const [err, setErr] = useState<{ text: string; readOnly: boolean } | null>(null)
  const run = async (id: string, fn: () => Promise<unknown>, after?: () => void) => {
    setBusy(id)
    setErr(null)
    try {
      await fn()
      after?.()
    } catch (e) {
      setErr({ text: e instanceof Error ? e.message : String(e), readOnly: e instanceof ReadOnlyError })
    }
    setBusy(null)
  }
  return { busy, err, run }
}

export function ActionError({ err }: { err: { text: string; readOnly: boolean } | null }) {
  if (!err) return null
  return <p className={`mt-2 text-[13px] ${err.readOnly ? 'text-mute' : 'text-compromise'}`} role="status">{err.text}</p>
}

/** Panel body: the content once data exists; else flat bars while loading, or the error with Retry. */
function Body({ s, loading, error, retry, rows = 4, pad = false, children }: {
  s: LiveStatus | null; loading: boolean; error: string | null; retry: () => void; rows?: number; pad?: boolean; children: (s: LiveStatus) => ReactNode
}) {
  if (s) return <>{children(s)}</>
  const box = pad ? '' : 'px-5'
  return <div className={box}>{loading ? <Bars rows={rows} /> : <ErrorLine message={error ?? 'no data'} onRetry={retry} />}</div>
}

/** Consecutive drill-boosted ticks as shaded index ranges for the sparkline. */
function drillRuns(series: LiveTagPoint[]): [number, number][] {
  const out: [number, number][] = []
  series.forEach((p, i) => {
    if (!p.d) return
    const last = out.at(-1)
    if (last && last[1] === i - 1) last[1] = i
    else out.push([i, i])
  })
  return out
}

/** The newest surge detection for this product, if it landed within the detector's 24-tick cooldown window. */
function recentSurge(s: LiveStatus, t: LiveTag): LiveDetection | undefined {
  const ref = s.last_tick ? Date.parse(s.last_tick) : Date.now()
  return s.detections.find((d) => d.kind === 'surge' && d.product === t.label && ref - Date.parse(d.ts) <= 24 * s.tick_s * 1000)
}

function Engine({ s, t }: { s: LiveStatus; t: number }) {
  const ticking = s.running && s.last_tick != null && t - Date.parse(s.last_tick) < s.tick_s * 3000
  return (
    <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[13px] text-mute">
      {ticking ? <Mark color="var(--color-ok)"><span className="text-text">Engine running</span></Mark>
        : <span className="text-text">{s.running ? 'Engine not ticking' : 'Engine stopped'}</span>}
      <span className="num">Cycle every {num(s.tick_s)} s, last at {time(s.last_tick)} IST ({ago(s.last_tick, t)})</span>
      <span className="num">{plural(s.ticks, 'cycle')} since {time(s.started_at)}</span>
      {s.tick_ms_p50 != null && <span className="num">{num(s.tick_ms_p50)} ms per cycle, median</span>}
    </p>
  )
}

function Answer({ s }: { s: LiveStatus }) {
  if (s.tags.length === 0) return <p className="text-[15px]">No decoy readings yet: the grid reports after its first cycle.</p>
  const hot = s.tags.filter((t) => t.z >= SURGE_Z).sort((a, b) => b.z - a.z)
  if (hot.length === 0) {
    const top = [...s.tags].sort((a, b) => b.z - a.z)[0]
    return (
      <p className="text-[15px]">
        <span className="font-semibold">No: all {num(s.tags.length)} products on the decoy grid are within their normal range.</span>{' '}
        <span className="text-mute">Highest now: {top.label}, z = <span className="num">{num(top.z, 1)}</span>; a surge is 4 or more.</span>
      </p>
    )
  }
  const first = hot[0]
  const det = recentSurge(s, first)
  return (
    <p className="text-[15px]">
      <span className="font-semibold">Yes: {hot.map((t) => t.label).join(', ')} {hot.length === 1 ? 'is' : 'are'} surging on the decoy grid.</span>{' '}
      <span className="text-mute">
        {hot.length > 1 && `${first.label}: `}<span className="num">{num(first.sessions)}</span> sessions this tick, z = <span className="num">{num(first.z, 1)}</span>
        {first.series.at(-1)?.d ? ' (drill traffic, simulated)' : ' (simulated sensors)'}.{' '}
        {det ? <>The surge detector fired at <span className="num">{time(det.ts)}</span> IST on {plural(det.sensors ?? 0, 'sensor')}.</>
          : 'Not yet confirmed by the surge detector, which also needs more unique sources (z ≥ 3) on at least 3 sensors.'}
      </span>
    </p>
  )
}

function Grid({ s }: { s: LiveStatus }) {
  // Surging products first (worst first); the rest keep the backend's order, so rows don't jump on every refresh.
  const rows = [...s.tags].sort((a, b) => {
    const ha = a.z >= SURGE_Z, hb = b.z >= SURGE_Z
    return ha !== hb ? (ha ? -1 : 1) : ha ? b.z - a.z : 0
  })
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">Product the decoys pose as</th>
              <th className="pb-2 pl-4 text-right font-normal">Sessions this tick</th>
              <th className="pb-2 pl-4 text-right font-normal" title="Robust z-score of this tick's sessions against the last 72 ticks">z now</th>
              <th className="pb-2 pl-6 font-normal">Last {num(rows[0]?.series.length ?? 0)} ticks</th>
              <th className="px-5 pb-2 font-normal">State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {rows.map((t) => {
              const hot = t.z >= SURGE_Z
              const det = hot ? recentSurge(s, t) : undefined
              return (
                <tr key={t.tag}>
                  <td className="px-5 py-2.5 font-medium">{t.label}</td>
                  <td className="num py-2.5 pl-4 text-right">{num(t.sessions)}</td>
                  <td className="num py-2.5 pl-4 text-right">{num(t.z, 1)}</td>
                  <td className="w-[200px] py-2.5 pl-6">
                    <Spark values={t.series.map((p) => p.s)} bands={drillRuns(t.series)} h={28} color={hot ? 'var(--color-high)' : 'var(--color-mute)'}
                      label={`${t.label}: decoy sessions per tick`} />
                  </td>
                  <td className="px-5 py-2.5 whitespace-nowrap">
                    {hot ? <Mark color="var(--color-high)">Surge{t.series.at(-1)?.d ? ', drill' : ''}</Mark>
                      : t.z >= RAISED_Z ? <span>Raised</span> : <span className="text-mute">Normal</span>}
                    {det && <span className="num block text-[12px] text-faint">Detected {time(det.ts)}</span>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <p className="px-5 pt-2 text-[13px] text-mute">
        Simulated: {num(s.sensors)} decoy sensors posing as {num(s.tags.length)} products; one tick is one sensor-hour, every {num(s.tick_s)} s.
        z compares this tick's sessions with the last 72 ticks; 4 or more is a surge. Shaded ticks are drill traffic.
      </p>
    </>
  )
}

function Progress({ d }: { d: Drill }) {
  const watching = d.status === 'running'
  const steps: { name: string; done: boolean; extra: ReactNode }[] = [
    {
      name: 'Attack traffic started', done: true,
      extra: <><span className="num">{time(d.started_at)}</span> IST, {d.scenario === 'scan' ? `on ${plural(d.sensors.length, 'decoy sensor')}` : `from ${d.victim_host} at ${d.victim_org}`}</>,
    },
    ...d.expect.map((k) => {
      const x = d.detected[k]
      return {
        name: STEP[k], done: !!x,
        extra: x ? <><span className="num">{num(x.seconds, 1)} s</span> after the start, at <span className="num">{time(x.at)}</span></> : watching ? 'Watching…' : 'Not detected',
      }
    }),
    ...(d.expect.includes('beacon') ? [
      { name: 'Notice, CERT-In draft and hunt sent; incident case opened', done: !!d.case, extra: d.case ?? (watching ? 'On detection, no human needed' : 'No case opened') },
      {
        name: 'Warnings on the host re-scored', done: d.rescored != null,
        extra: d.rescored != null ? `${plural(d.rescored, 'warning')} now a suspected compromise, with a fresh 6-hour clock` : 'Bayesian model, once the beacon is seen',
      },
    ] : []),
    ...(d.expect.includes('surge') ? [{
      name: 'Early warning proposed', done: !!d.detected.surge,
      extra: d.detected.surge ? <>Waiting for a person in <a href="#/decisions" className="text-text underline-offset-2 hover:underline">Decisions</a></> : 'On detection; it waits for a person',
    }] : []),
  ]
  const ttd = Math.max(0, ...Object.values(d.detected).map((x) => x?.seconds ?? 0))
  return (
    <div>
      <div className="flex flex-wrap items-baseline justify-between gap-x-3">
        <h3 className="text-[14px] font-medium">{d.title}</h3>
        <span className="text-[13px]">
          {watching ? 'Running' : d.status === 'passed' ? <>Detected in <span className="num">{num(ttd, 1)} s</span></> : 'Missed'}
        </span>
      </div>
      <p className="num text-[12px] text-faint">{d.id}: simulated traffic, labelled DRILL in the audit log</p>
      <ol className="mt-3 space-y-2.5">
        {steps.map((st) => (
          <li key={st.name} className="flex gap-3">
            <span className={`mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full ${st.done ? 'bg-text text-ground' : 'bg-raised'}`} aria-hidden>
              {st.done && <Check size={12} strokeWidth={3} />}
            </span>
            <span className="min-w-0">
              <span className="block">{st.name}<span className="sr-only">{st.done ? ': done' : ': pending'}</span></span>
              <span className="block text-[13px] text-mute">{st.extra}</span>
            </span>
          </li>
        ))}
      </ol>
      {d.seconds != null && <p className="mt-3 text-[13px] text-mute">Finished after <span className="num">{num(d.seconds, 1)} s</span>.</p>}
    </div>
  )
}

function Drills({ s, onStarted }: { s: LiveStatus; onStarted: () => void }) {
  const act = useAction()
  const running = s.drill?.status === 'running'
  const last = s.drill ?? s.drills[0] ?? null
  return (
    <div className="space-y-5">
      <div className="grid gap-x-8 gap-y-5 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div>
          <table className="w-full text-[14px]">
            <thead>
              <tr className="text-left text-[12px] text-faint">
                <th className="pb-2 font-normal">Drill and what to expect</th>
                <th className="pb-2 pl-4 text-right font-normal"><span className="sr-only">Start</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/70">
              {s.catalogue.map((c) => (
                <tr key={c.id}>
                  <td className="py-3 align-top"><span className="font-medium">{c.title}</span><span className="block text-[13px] text-mute">{c.what}</span></td>
                  <td className="py-3 pl-4 text-right align-top">
                    <Button size="sm" disabled={running || act.busy !== null} onClick={() => act.run(c.id, () => api.drill(c.id), onStarted)}
                      title={running ? `${s.drill?.id} is still running` : undefined}>
                      <Play size={13} /> {act.busy === c.id ? 'Starting…' : 'Start'}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {running && <p className="mt-2 text-[13px] text-mute">{s.drill?.id} is running; the next drill can start when it ends.</p>}
          <ActionError err={act.err} />
        </div>
        <div className="min-w-0">
          {last ? <Progress d={last} /> : <Empty>No drill since the engine started. Start one to watch each detection and the response, with the time to detect.</Empty>}
        </div>
      </div>
      {s.drills.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-[14px]">
            <thead>
              <tr className="text-left text-[12px] text-faint">
                <th className="pb-2 font-normal">Earlier drills</th>
                <th className="pb-2 pl-4 font-normal">Result</th>
                <th className="pb-2 pl-4 text-right font-normal">Detectors fired</th>
                <th className="pb-2 pl-4 text-right font-normal">Time to detect</th>
                <th className="pb-2 pl-6 font-normal">Incident case</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/70">
              {s.drills.map((d) => {
                const fired = Object.values(d.detected)
                return (
                  <tr key={d.id}>
                    <td className="py-2.5"><span className="font-medium">{d.title}</span><span className="num block text-[12px] text-faint">{d.id}</span></td>
                    <td className="py-2.5 pl-4">{d.status === 'passed' ? 'Detected' : d.status === 'missed' ? 'Missed' : 'Running'}</td>
                    <td className="num py-2.5 pl-4 text-right">{num(fired.length)} of {num(d.expect.length)}</td>
                    <td className="num py-2.5 pl-4 text-right">{d.status === 'passed' ? `${num(Math.max(...fired.map((x) => x?.seconds ?? 0)), 1)} s` : '—'}</td>
                    <td className="num py-2.5 pl-6 text-mute">{d.case ?? '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function Detections({ s }: { s: LiveStatus }) {
  const [all, setAll] = useState(false)
  const rows = s.detections
  return (
    <>
      {rows.length === 0 ? <div className="px-5"><Empty>Quiet: nothing has fired since the engine started at {time(s.started_at)} IST. Start a drill to see a detection.</Empty></div> : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-[14px]">
              <thead>
                <tr className="text-left text-[12px] text-faint">
                  <th className="px-5 pb-2 font-normal">Time (IST)</th>
                  <th className="pb-2 font-normal">Detector</th>
                  <th className="pb-2 pl-4 font-normal">What it saw</th>
                  <th className="pb-2 pl-4 font-normal">Drill</th>
                  <th className="px-5 pb-2 text-right font-normal">Time to detect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {(all ? rows : rows.slice(0, 8)).map((d) => (
                  <tr key={d.id} className="align-top">
                    <td className="num px-5 py-2.5 whitespace-nowrap text-mute">{time(d.ts)}</td>
                    <td className="py-2.5 whitespace-nowrap">{KIND[d.kind] ?? d.kind}</td>
                    <td className="py-2.5 pl-4">{d.title}</td>
                    <td className="num py-2.5 pl-4 whitespace-nowrap text-mute" title={d.drill ? undefined : 'Not a drill'}>{d.drill ?? '—'}</td>
                    <td className="num px-5 py-2.5 text-right">{d.seconds_to_detect != null ? `${num(d.seconds_to_detect, 1)} s` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="px-5 pt-1"><ShowAll total={rows.length} cap={8} open={all} onToggle={() => setAll((v) => !v)} /></div>
        </>
      )}
      <dl className="mt-3 grid gap-x-4 gap-y-1 px-5 text-[13px] sm:grid-cols-[130px_1fr]">
        {s.detectors.map((d) => (
          <div key={d.name} className="contents">
            <dt className="text-faint">{d.name}</dt>
            <dd className="text-mute">{d.how.replace(/>=/g, '≥').replace(/<=/g, '≤')}</dd>
          </div>
        ))}
      </dl>
    </>
  )
}

const FEED_STATUS: Record<LiveFeed['status'], ReactNode> = {
  fresh: <Mark color="var(--color-ok)">Fresh</Mark>,
  offline: <span className="text-mute">Offline, serving the snapshot</span>,
  waiting: <span className="text-mute">Waiting for the first check</span>,
}

function Feeds({ s, t }: { s: LiveStatus; t: number }) {
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">Feed</th>
              <th className="pb-2 font-normal">Status</th>
              <th className="pb-2 pl-4 text-right font-normal">Items</th>
              <th className="pb-2 pl-4 text-right font-normal" title="New since the build snapshot">New</th>
              <th className="pb-2 pl-6 font-normal">Checked</th>
              <th className="px-5 pb-2 font-normal">What it found</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {s.feeds.map((f) => (
              <tr key={f.name}>
                <td className="px-5 py-2.5 font-medium whitespace-nowrap">{f.name}</td>
                <td className="py-2.5 whitespace-nowrap">{FEED_STATUS[f.status] ?? f.status}</td>
                <td className="num py-2.5 pl-4 text-right">{num(f.items)}</td>
                <td className="num py-2.5 pl-4 text-right">{num(f.new)}</td>
                <td className="num py-2.5 pl-6 whitespace-nowrap text-mute">{ago(f.last_ok ?? f.last_try, t)}{f.ms != null ? `, ${num(f.ms)} ms` : ''}</td>
                <td className="px-5 py-2.5 text-[13px] text-mute">{f.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="px-5 pt-2 text-[13px] text-mute">Real public feeds, re-read every 15 minutes when the network is up; new entries are matched to the inventory at once. If the network is down they say so and the snapshot keeps serving.</p>
    </>
  )
}

export function Live() {
  const live = usePoll(api.live, 'live', POLL_MS)
  const t = useNow(1000)
  const s = live.data
  const p = s?.pipeline
  const hot = s?.tags.filter((x) => x.z >= SURGE_Z).length
  const sessions = s?.tags.reduce((n, x) => n + x.sessions, 0)
  const fresh = s?.feeds.filter((f) => f.status === 'fresh').length
  const kev = s?.feeds.find((f) => f.name === 'CISA KEV')
  const frame = { s: s ?? null, loading: live.loading, error: live.error, retry: live.reload }

  return (
    <div className="space-y-4">
      <div className="space-y-1.5 pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">Live grid</h1>
        <p className="text-mute">What the running system is doing now. The national decoy grid and the firewall flows are simulated (one tick is one sensor-hour); the three threat feeds are real.</p>
        {s && <Engine s={s} t={t} />}
        <Freshness at={live.at} error={live.error} onRetry={live.reload} />
      </div>

      {s && <Answer s={s} />}

      <Kpis items={[
        { label: 'Products surging now', value: num(hot), answer: true, tone: hot ? 'var(--color-high)' : undefined, sub: s ? `of ${num(s.tags.length)} on the decoy grid, z ≥ 4` : undefined },
        { label: 'Detections, last hour', value: num(p?.detections_hour), sub: 'Surge, C2 beacon, flow anomaly' },
        { label: 'Decoy sessions this tick', value: num(sessions), sub: s ? `${num(s.sensors)} sensors, simulated` : undefined },
        { label: 'Firewall flows this tick', value: num(s?.flows.per_tick.at(-1)), sub: s ? `${num(s.flows.hosts)} internal hosts, simulated` : undefined },
        { label: 'Autopilot actions, last hour', value: num(p?.auto_hour), sub: p ? `${num(p.pending)} waiting for a decision` : undefined },
        { label: 'Real feeds fresh', value: s ? `${num(fresh)} of ${num(s.feeds.length)}` : '—', sub: kev ? `CISA KEV checked ${ago(kev.last_ok ?? kev.last_try, t)}` : undefined },
      ]} />

      <Panel title="Decoy grid, per product" meta="Simulated sensors: sessions per tick, with the surge flag the detector uses" pad={false}>
        <Body {...frame} rows={6}>{(x) => <Grid s={x} />}</Body>
      </Panel>

      <Panel title="Attack drills" meta="Inject simulated attack traffic and watch Odyssey detect and respond, end to end, with the time to detect">
        <Body {...frame} pad>{(x) => <Drills s={x} onStarted={live.reload} />}</Body>
      </Panel>

      <Panel title="Detections" meta="Newest first. Each one is in the audit log with its evidence; the sensors behind them are simulated" pad={false}>
        <Body {...frame}>{(x) => <Detections s={x} />}</Body>
      </Panel>

      <Panel title="Real feeds" meta="CISA KEV, abuse.ch Feodo Tracker and OpenPhish, matched to the inventory as they arrive" pad={false}>
        <Body {...frame} rows={3}>{(x) => <Feeds s={x} t={t} />}</Body>
      </Panel>
    </div>
  )
}
