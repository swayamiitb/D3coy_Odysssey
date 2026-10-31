import { useEffect, useState } from 'react'
import { Section } from './ui'

/* The detectors tuning themselves from what people decided, shown next to their defaults with the reason. */

/* eslint-disable @typescript-eslint/no-explicit-any */

export function AdaptiveSection() {
  const [a, setA] = useState<any>()
  useEffect(() => {
    let alive = true
    const pull = () => fetch('/api/adaptive').then((r) => (r.ok ? r.json() : undefined)).then((d) => alive && d && setA(d)).catch(() => undefined)
    pull()
    const id = setInterval(pull, 10000)
    return () => { alive = false; clearInterval(id) }
  }, [])
  if (!a) return null
  const tuned = a.surge.filter((s: any) => s.z !== s.base)
  const orgsTuned = a.anomaly.filter((o: any) => o.z !== o.base)
  const focus = a.feed.focus_until && new Date(a.feed.focus_until) > new Date()
  return (
    <Section title="Detectors adapting to your decisions"
             sub="Thresholds are re-derived every minute from the record: false alarms raise them, confirmed detections lower them, and nothing moves outside its bounds. Each change is in the audit trail with its reason.">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl bg-panel-2 p-5">
          <div className="text-3xl font-bold tabular-nums">{tuned.length}<span className="text-base font-medium text-mute"> / {a.surge.length}</span></div>
          <div className="mt-1 font-semibold">surge thresholds tuned</div>
          <div className="mt-2 space-y-1 text-sm text-mute">
            {tuned.length === 0 && <div>all products at the default z ≥ {a.surge[0]?.base}</div>}
            {tuned.slice(0, 4).map((s: any) => <div key={s.tag}><b className="text-text">{s.tag}</b> z ≥ {s.z} <span>({s.why})</span></div>)}
          </div>
        </div>
        <div className="rounded-2xl bg-panel-2 p-5">
          <div className="text-3xl font-bold tabular-nums">{orgsTuned.length}<span className="text-base font-medium text-mute"> / {a.anomaly.length}</span></div>
          <div className="mt-1 font-semibold">organisations with a raised anomaly gate</div>
          <div className="mt-2 space-y-1 text-sm text-mute">
            {orgsTuned.length === 0 && <div>all at the default z ≥ {a.anomaly[0]?.base}</div>}
            {orgsTuned.slice(0, 4).map((o: any) => <div key={o.org_id}><b className="text-text">{o.org_id}</b> z ≥ {o.z} <span>({o.why})</span></div>)}
          </div>
        </div>
        <div className="rounded-2xl bg-panel-2 p-5">
          <div className="text-3xl font-bold tabular-nums">{a.beacon.focused_orgs.length ? a.beacon.focus : a.beacon.base}</div>
          <div className="mt-1 font-semibold">connections to call an implant</div>
          <div className="mt-2 text-sm text-mute">{a.beacon.focused_orgs.length ? `${a.beacon.focus} for ${a.beacon.focused_orgs.join(', ')} (open suspected compromise), ${a.beacon.base} elsewhere` : `${a.beacon.base} everywhere; drops to ${a.beacon.focus} where an organisation has an open suspected compromise`}</div>
        </div>
        <div className="rounded-2xl bg-panel-2 p-5">
          <div className="text-3xl font-bold tabular-nums">{Math.round(a.feed.current_s / 60)} min</div>
          <div className="mt-1 font-semibold">between feed checks{focus ? ' · focused' : ''}</div>
          <div className="mt-2 text-sm text-mute">{focus ? `${a.feed.focus_why}; back to ${a.feed.base_s / 60} min at ${new Date(a.feed.focus_until).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}` : `every ${a.feed.base_s / 60} min; ${a.feed.focus_s / 60} min for an hour after a Critical intake, a live compromise or a drill`}</div>
        </div>
      </div>
      {a.changes.length > 0 && (
        <div className="mt-4">
          {a.changes.slice(0, 5).map((c: any, i: number) => (
            <div key={i} className="flex flex-wrap gap-x-3 border-b border-line py-2 text-sm last:border-0">
              <span className="font-medium">{c.what}</span><span className="tabular-nums text-mute">{c.from} → {c.to}</span><span className="text-mute">{c.why}</span>
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}
