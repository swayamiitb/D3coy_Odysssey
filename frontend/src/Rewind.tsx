import { Pause, Play, RotateCcw } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Area, AreaChart, CartesianGrid, Legend, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type AutoEvent, type Soc } from './api'
import { KIND, istTime } from './proactive'
import { TIER_FILL } from './ui'

const STEP_MS = 380 // one day per step: Aug-Oct in about 35 seconds
const COUNTED: [string, string[]][] = [
  ['early warnings', ['auto.warn', 'auto.forecast']],
  ['notices sent', ['auto.notify', 'auto.digest', 'auto.baseline', 'auto.advisory']],
  ['hunts', ['auto.hunt']],
  ['escalations', ['auto.escalate', 'auto.escalate_sla']],
  ['human decisions', ['analyst.approve', 'analyst.reject']],
]

/** Open warnings by tier over time, with a replay of everything Odyssey did, day by day. */
export function Rewind({ d }: { d: Soc }) {
  const [events, setEvents] = useState<AutoEvent[]>([])
  const [cursor, setCursor] = useState<number>() // index into d.pressure; undefined = full picture
  const [playing, setPlaying] = useState(false)
  const timer = useRef<ReturnType<typeof setInterval> | undefined>(undefined)
  useEffect(() => { api.autopilot({ limit: 1500 }).then((r) => setEvents([...r.events].reverse())).catch(() => undefined) }, [])

  const start = d.pressure.findIndex((p) => p.date >= (d.autopilot.go_live ?? ''))
  useEffect(() => { // ?at=YYYY-MM-DD freezes the replay on that day (presentations, screenshots)
    const at = new URLSearchParams(window.location.search).get('at')
    const i = at ? d.pressure.findIndex((p) => p.date >= at) : -1
    if (i >= 0) setCursor(i)
  }, [d.pressure])
  useEffect(() => {
    if (!playing) return
    timer.current = setInterval(() => {
      setCursor((c) => {
        const next = (c ?? Math.max(start, 0)) + 1
        if (next >= d.pressure.length - 1) { setPlaying(false); return d.pressure.length - 1 }
        return next
      })
    }, STEP_MS)
    return () => clearInterval(timer.current)
  }, [playing, start, d.pressure.length])

  const day = cursor != null ? d.pressure[cursor].date : undefined
  const data = useMemo(() => d.pressure.map((p, i) => (cursor == null || i <= cursor ? p
    : { date: p.date, Compromise: null, Critical: null, High: null })), [d.pressure, cursor])
  const upto = useMemo(() => (day ? events.filter((e) => e.ts.slice(0, 10) <= day && e.kind !== 'auto.proposed') : events), [events, day])
  const counts = COUNTED.map(([label, kinds]) => [label, upto.filter((e) => kinds.includes(e.kind)).length] as const)
  const recent = upto.filter((e) => ['auto.warn', 'auto.confirm', 'auto.stand_down', 'auto.forecast', 'auto.notify',
    'auto.escalate', 'auto.hunt', 'auto.report', 'auto.advisory'].includes(e.kind)).slice(-5).reverse()

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <button onClick={() => { if (cursor == null || cursor >= d.pressure.length - 1) setCursor(Math.max(start, 0)); setPlaying(!playing) }}
                className="flex items-center gap-1.5 rounded-full bg-accent px-3 py-1 text-xs font-semibold text-ink hover:brightness-110">
          {playing ? <Pause size={12} /> : <Play size={12} />} {playing ? 'Pause' : cursor == null ? 'Replay since go-live' : 'Resume'}
        </button>
        {cursor != null && !playing && (
          <button onClick={() => setCursor(undefined)} className="flex items-center gap-1 text-xs text-mute hover:text-text"><RotateCcw size={12} /> full picture</button>
        )}
        {day && <span className="font-mono text-sm">{day}</span>}
        <div className="ml-auto flex flex-wrap gap-3 text-xs">
          {counts.map(([label, n]) => <span key={label}><b className="font-mono text-text">{n}</b> <span className="text-mute">{label}</span></span>)}
        </div>
      </div>
      <div className="h-56">
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -8 }}>
            <CartesianGrid stroke="#243041" strokeDasharray="2 4" vertical={false} />
            <XAxis dataKey="date" tick={{ fill: '#8b98a9', fontSize: 11 }} tickFormatter={(v: string) => v.slice(5)} minTickGap={24} />
            <YAxis tick={{ fill: '#8b98a9', fontSize: 11 }} allowDecimals={false} />
            <Tooltip contentStyle={{ background: '#0b0f14', border: '1px solid #243041', fontSize: 12 }} labelStyle={{ color: '#e6edf3' }} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <ReferenceLine x={d.autopilot.go_live} stroke="#8b98a9" strokeDasharray="3 3" label={{ value: 'go-live', fill: '#8b98a9', fontSize: 11, position: 'insideTopLeft' }} />
            {day && <ReferenceLine x={day} stroke="#38bdf8" strokeWidth={2} />}
            {(['High', 'Critical', 'Compromise'] as const).map((t) => (
              <Area key={t} type="stepAfter" dataKey={t} stackId="1" stroke={TIER_FILL[t]} fill={TIER_FILL[t]} fillOpacity={0.35} strokeWidth={2} isAnimationActive={false} />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>
      {cursor != null && (
        <ol className="mt-2 space-y-1">
          {recent.map((e) => {
            const k = KIND[e.kind]
            const Icon = k?.icon
            return (
              <li key={e.seq} className="flex items-center gap-2 text-xs">
                {Icon && <Icon size={13} className={`shrink-0 ${k.tone}`} />}
                <span className="w-24 shrink-0 text-mute">{istTime(e.ts)}</span>
                <span className="truncate">{e.payload.title}</span>
              </li>
            )
          })}
          {recent.length === 0 && <li className="text-xs text-mute">Monitoring started; nothing has needed action yet.</li>}
        </ol>
      )}
    </div>
  )
}
