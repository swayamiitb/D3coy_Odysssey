import { Activity, ArrowRight, Check, Loader2, Radar, ScanSearch, ShieldAlert, Waypoints } from 'lucide-react'
import { useEffect, useState } from 'react'
import { ChannelsSection } from './Channels'
import { istTime } from './proactive'
import { ShieldSection } from './Shield'
import { Spark } from './Soc'
import { Figures, Pill, Row, Section, useToast } from './ui'

/* eslint-disable @typescript-eslint/no-explicit-any */
type LiveState = any

const KIND: Record<string, { icon: typeof Radar; label: string }> = {
  intake: { icon: ScanSearch, label: 'New CVE taken in' },
  surge: { icon: Radar, label: 'Scanning surge' },
  beacon: { icon: ShieldAlert, label: 'C2 beacon' },
  anomaly: { icon: Waypoints, label: 'Flow anomaly' },
}

function ago(iso?: string | null): string {
  if (!iso) return 'not yet'
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  return s < 60 ? `${s} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`
}

/** Hero figures for the Live page, fed by the same poll as the page. */
export function LiveFigures({ s }: { s?: LiveState }) {
  if (!s) return <div className="h-[118px]" />
  const fresh = s.feeds.filter((f: any) => f.status === 'fresh').length
  return (
    <Figures items={[
      { value: `${s.sensors}/${s.sensors}`, label: 'decoy sensors reporting', sub: 'national grid, simulated (SIM); one tick is one sensor-hour', dot: 'bg-ok' },
      { value: `${fresh}/${s.feeds.length}`, label: 'real feeds fresh', sub: `NVD, KEV, Feodo, OpenPhish · checked ${ago(s.feeds[0]?.last_ok ?? s.feeds[0]?.last_try)}`, dot: fresh === s.feeds.length ? 'bg-ok' : 'bg-high' },
      { value: s.pipeline.detections_hour, label: 'detections in the last hour', sub: 'surge, C2 beacon, flow anomaly' },
      { value: s.tick_ms_p50 != null ? `${Math.round(s.tick_ms_p50)} ms` : '—', label: 'per detection cycle', sub: `every ${s.tick_s} s · ${s.ticks.toLocaleString('en-IN')} cycles since start` },
    ]} />
  )
}

export function useLive(ms = 2500): LiveState | undefined {
  const [s, setS] = useState<LiveState>()
  useEffect(() => {
    let alive = true
    const pull = () => fetch('/api/live').then((r) => (r.ok ? r.json() : undefined)).then((d) => alive && d && setS(d)).catch(() => undefined)
    pull()
    const id = setInterval(pull, ms)
    return () => { alive = false; clearInterval(id) }
  }, [ms])
  return s
}

function Stage({ title, value, sub, status }: { title: string; value: React.ReactNode; sub: string; status: 'ok' | 'busy' | 'warn' }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col rounded-2xl bg-panel-2 p-5">
      <div className="flex items-center justify-between gap-2 text-sm font-semibold">
        {title}
        <span className={`h-2.5 w-2.5 rounded-full ${status === 'ok' ? 'bg-ok' : status === 'busy' ? 'animate-pulse bg-accent' : 'bg-high'}`} />
      </div>
      <div className="mt-3 text-3xl font-bold tabular-nums">{value}</div>
      <div className="mt-1 text-sm text-mute">{sub}</div>
    </div>
  )
}

function DrillCard({ d }: { d: any }) {
  const labels: Record<string, string> = { surge: 'Scanning surge detected', beacon: 'Implant beacon detected', anomaly: 'Lateral movement detected', intake: 'CVE matched to installed versions, scored, acted on' }
  const steps = [
    d.scenario === 'cve'
      ? { name: `${d.cve} published (simulated, NVD format)`, at: d.started_at, done: true, extra: d.intake ? `${d.intake.exposed} exposed assets at ${d.intake.orgs.length} organisations · ${d.intake.worst} · ${d.intake.action}` : 'taking it in…' }
      : { name: 'Attack traffic started', at: d.started_at, done: true, extra: d.scenario === 'scan' ? `${d.sensors.length} decoy sensors` : `from ${d.victim_host}` },
    ...d.expect.map((k: string) => ({ name: labels[k], done: !!d.detected[k], at: d.detected[k]?.at, extra: d.detected[k] ? `${d.detected[k].seconds} s after the start` : 'watching…' })),
    ...(d.expect.includes('beacon') ? [{ name: 'Notice, CERT-In draft, hunt; incident case opened', done: !!d.case, at: undefined, extra: d.case ?? 'on detection, no human needed' }] : []),
    ...(d.expect.includes('beacon') ? [{ name: 'Warnings on the host re-scored live', done: d.rescored != null, at: undefined, extra: d.rescored != null ? `${d.rescored} now a suspected compromise, with a fresh 6-hour clock` : 'Bayesian model, beacon observed' }] : []),
    ...(d.expect.includes('surge') ? [{ name: 'Early warning proposed: waits for your decision', done: !!d.detected.surge, at: undefined, extra: 'Now → Needs your decision' }] : []),
  ]
  return (
    <div className="rounded-3xl bg-band p-7 text-white">
      <div className="flex flex-wrap items-center gap-3">
        <span className={`rounded-full px-3 py-1 text-xs font-semibold ${d.status === 'running' ? 'bg-accent' : d.status === 'passed' ? 'bg-ok' : 'bg-crit'}`}>
          {d.status === 'running' ? 'Running' : d.status === 'passed' ? 'Detected' : 'Missed'}
        </span>
        <span className="font-mono text-sm text-band-mute">{d.id}</span>
        {d.seconds != null && <span className="ml-auto text-sm text-band-mute">finished in {d.seconds} s</span>}
      </div>
      <h3 className="mt-3 text-3xl font-bold">{d.title}</h3>
      <p className="mt-1 text-band-mute">{d.victim_org && d.scenario !== 'scan' && d.scenario !== 'cve' ? `Target: ${d.victim_host} at ${d.victim_org}. ` : ''}Simulated {d.scenario === 'cve' ? 'CVE' : 'traffic'}, labelled DRILL in the audit trail.</p>
      <ol className="mt-6 space-y-3">
        {steps.map((s) => (
          <li key={s.name} className="flex items-center gap-4">
            <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${s.done ? 'bg-ok' : 'bg-band-3'}`}>
              {s.done ? <Check size={16} /> : <Loader2 size={16} className="animate-spin text-band-mute" />}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block font-semibold">{s.name}</span>
              <span className="block text-sm text-band-mute">{s.extra}{s.at ? ` · ${istTime(s.at)}` : ''}</span>
            </span>
          </li>
        ))}
      </ol>
    </div>
  )
}

export function Live({ s, onGo }: { s?: LiveState; onGo: (view: 'soc' | 'now', tab?: string) => void }) {
  const toast = useToast()
  const [busy, setBusy] = useState<string>()
  if (!s) return <div className="py-10 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Connecting to the live engine…</div>
  const start = (id: string) => {
    setBusy(id)
    fetch(`/api/live/drill/${id}`, { method: 'POST' })
      .then(async (r) => { if (!r.ok) throw new Error((await r.json()).detail); return r.json() })
      .then((d) => toast(`${d.id} started: watch it below`))
      .catch((e) => toast(String(e.message ?? e)))
      .finally(() => setBusy(undefined))
  }
  const p = s.pipeline
  const running = s.drill?.status === 'running'
  const lastDrill = s.drill ?? s.drills[0]
  const flowsNow = s.flows.per_tick.at(-1) ?? 0
  const sessionsNow = s.tags.reduce((n: number, t: any) => n + t.sessions, 0)
  const fresh = s.feeds.filter((f: any) => f.status === 'fresh').length

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-16">
      <ShieldSection onGo={onGo} />
      <ChannelsSection />
      <Section title="The pipeline, right now" sub="What each stage did in the last hour. Every number refreshes on its own; nothing here is a static report.">
        <div className="flex flex-col gap-2 xl:flex-row xl:items-stretch">
          {[
            { title: 'Sources', value: `${fresh}/${s.feeds.length}`, sub: 'real feeds fresh · 13 sources in all', status: fresh === s.feeds.length ? 'ok' : 'warn' },
            { title: 'Sensors', value: sessionsNow.toLocaleString('en-IN'), sub: `decoy sessions this tick · ${flowsNow} firewall flows`, status: 'ok' },
            { title: 'Detectors', value: p.detections_hour, sub: `detections in the last hour · ${s.detectors.length} running`, status: running ? 'busy' : 'ok' },
            { title: 'Autopilot', value: p.auto_hour, sub: 'actions on its own in the last hour', status: 'ok' },
            { title: 'Decisions', value: p.pending, sub: `waiting for a person · ${p.human_hour} decided this hour`, status: p.pending ? 'warn' : 'ok' },
            { title: 'SOC', value: p.open_cases, sub: `open cases · ${p.live_cases} opened by live detection`, status: 'ok' },
          ].map((st, i, arr) => (
            <div key={st.title} className="flex min-w-0 flex-1 items-stretch gap-2">
              <Stage {...(st as any)} />
              {i < arr.length - 1 && <ArrowRight className="hidden shrink-0 self-center text-faint xl:block" size={18} />}
            </div>
          ))}
        </div>
      </Section>

      <Section title="Run an attack drill" sub="Inject simulated attack traffic and watch Odyssey detect and respond, end to end. Drills are labelled DRILL in the audit trail.">
        <div className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
          <div className="flex flex-col gap-3">
            {s.catalogue.map((c: any) => (
              <div key={c.id} className="rounded-2xl bg-panel-2 p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-lg font-bold">{c.title}</div>
                    <p className="mt-1 text-sm text-mute">{c.what}</p>
                  </div>
                  <button disabled={running || !!busy} onClick={() => start(c.id)}
                          className="shrink-0 rounded-full bg-action px-5 py-2.5 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-40">
                    {busy === c.id ? 'Starting…' : 'Start'}
                  </button>
                </div>
              </div>
            ))}
          </div>
          {lastDrill ? <DrillCard d={lastDrill} /> : (
            <div className="flex items-center justify-center rounded-3xl bg-soft p-10 text-center text-mute">
              Start a drill to see the attack, each detection and the response, step by step, with the time to detect.
            </div>
          )}
        </div>
        {s.drills.length > 0 && (
          <div className="mt-6">
            {s.drills.slice(0, 5).map((d: any) => (
              <Row key={d.id} lead={d.status === 'passed' ? <Check size={18} className="text-ok" /> : <ShieldAlert size={18} className="text-crit" />}
                   title={d.title} sub={`${d.id} · ${Object.keys(d.detected).length} of ${d.expect.length} detections${d.case ? ` · ${d.case}` : ''}`}
                   trail={<span className={d.status === 'passed' ? 'font-semibold text-ok' : 'font-semibold text-crit'}>{d.status === 'passed' ? `detected in ${Math.max(...Object.values(d.detected).map((x: any) => x.seconds))} s` : 'missed'}</span>} />
            ))}
          </div>
        )}
      </Section>

      <Section title="New CVEs, taken in live" sub="Real CVEs from NVD that name a product we run, matched to installed versions, forecast and acted on the moment they appear. The snapshot covers everything before."
               action={<span className="rounded-full bg-panel-2 px-3 py-1 text-xs font-semibold">REAL · NVD</span>}>
        {(s.intakes ?? []).length === 0 && (
          <div className="rounded-2xl bg-panel-2 p-5 text-mute">
            {s.feeds.find((f: any) => f.name === 'NVD (new CVEs)')?.detail ?? 'Waiting for the first NVD check.'}
          </div>
        )}
        {(s.intakes ?? []).slice(0, 8).map((t: any) => (
          <Row key={t.cve} lead={<span className="h-3 w-3 rounded-full" style={{ background: t.worst === 'Critical' || t.worst === 'Compromise' ? 'var(--color-crit)' : t.worst === 'High' ? 'var(--color-high)' : t.worst === 'Medium' ? 'var(--color-med)' : 'var(--color-watch)' }} />}
               title={<span><span className="font-mono text-sm">{t.cve}</span> <span className="text-mute">·</span> {t.product ?? 'product named in text'}</span>}
               sub={`${t.exposed} exposed asset${t.exposed === 1 ? '' : 's'} at ${t.orgs.length} organisation${t.orgs.length === 1 ? '' : 's'} · ${t.action}${t.forecast?.flag ? ` · day-0 forecast ${Math.round(t.forecast.p * 100)}%` : ''}${t.kev ? ' · in CISA KEV' : ''}`}
               trail={<span><b>{t.worst}</b><span className="block text-xs text-mute">{t.minutes_since_publication != null ? `${t.minutes_since_publication} min after publication` : 'published date unknown'}</span></span>} />
        ))}
      </Section>

      <Section title="Sensor streams" sub="Decoy-grid sessions per product, one point per tick. The number is the robust z-score against the last 72 ticks; 4 and above, with breadth across sensors, is a surge."
               action={<Pill onClick={() => onGo('soc', 'system')}><Activity size={14} /> System vital signs</Pill>}>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {s.tags.map((t: any) => {
            const hot = t.z >= 4 ? 'text-crit' : t.z >= 2 ? 'text-high' : 'text-mute'
            const bands: [number, number][] = t.series.map((x: any, i: number) => (x.d ? [i, i + 1] : null)).filter(Boolean)
            return (
              <div key={t.tag} className="rounded-2xl bg-panel-2 p-4">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate font-semibold">{t.label}</span>
                  <span className={`shrink-0 text-sm font-semibold tabular-nums ${hot}`}>z {t.z}</span>
                </div>
                <Spark values={t.series.map((x: any) => x.s)} bands={bands} color={t.z >= 4 ? 'var(--color-crit)' : 'var(--color-accent)'} h={40} />
                <div className="text-xs text-mute">{t.sessions} sessions this tick</div>
              </div>
            )
          })}
        </div>
      </Section>

      <div className="grid gap-12 xl:grid-cols-2">
        <Section title="Detections" sub="Newest first. Each one is in the audit trail with its evidence.">
          {s.detections.length === 0 && <div className="rounded-2xl bg-panel-2 p-5 text-mute">Quiet: nothing unusual since the engine started. Start a drill to see a detection.</div>}
          {s.detections.slice(0, 8).map((d: any) => {
            const K = KIND[d.kind] ?? { icon: ScanSearch, label: d.kind }
            return (
              <Row key={d.id} lead={<K.icon size={18} />} title={d.title}
                   sub={`${K.label} · ${istTime(d.ts)}${d.drill ? ` · ${d.drill}` : ''}`}
                   trail={d.seconds_to_detect != null ? <span className="text-sm font-semibold">{d.seconds_to_detect} s</span> : undefined} />
            )
          })}
        </Section>
        <Section title="Real feeds" sub="Checked every 15 minutes when the network is up; new entries are matched to the inventory at once.">
          {s.feeds.map((f: any) => (
            <Row key={f.name} lead={<span className={`h-3 w-3 rounded-full ${f.status === 'fresh' ? 'bg-ok' : f.status === 'offline' ? 'bg-crit' : 'bg-watch'}`} />}
                 title={f.name} sub={f.detail}
                 trail={<span><b>{f.items != null ? f.items.toLocaleString('en-IN') : '—'}</b><span className="block text-xs text-mute">{f.status === 'fresh' ? `${ago(f.last_ok)} · ${f.ms} ms` : f.status}</span></span>} />
          ))}
          <div className="mt-3 text-sm text-mute">EPSS, CISA advisories, SSVC, DShield and ATT&CK come from the build snapshot and refresh with each rebuild; NVD, KEV, Feodo and OpenPhish are also read live.</div>
        </Section>
      </div>
    </div>
  )
}
