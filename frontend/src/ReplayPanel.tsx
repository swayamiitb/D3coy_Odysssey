import { Pause, Play, RotateCcw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type Replay } from './api'
import { Badge, deadlineText, fmtDate, Panel, Prov, TIER_FILL, TierPill } from './ui'

export function ReplayPanel({ orgId, cveId }: { orgId: string; cveId: string }) {
  const [data, setData] = useState<Replay>()
  const [cursor, setCursor] = useState<number>(-1) // -1 = show everything (static view)
  const [playing, setPlaying] = useState(false)

  useEffect(() => {
    setData(undefined)
    setCursor(-1)
    api.replay(orgId, cveId).then(setData).catch(() => undefined)
  }, [orgId, cveId])

  useEffect(() => {
    if (!playing || !data) return
    const id = setInterval(() => {
      setCursor((c) => {
        if (c + 1 >= data.steps.length) {
          setPlaying(false)
          return data.steps.length - 1
        }
        return c + 1
      })
    }, 1400)
    return () => clearInterval(id)
  }, [playing, data])

  if (!data || data.steps.length === 0) return null
  const visible = cursor < 0 ? data.steps : data.steps.slice(0, cursor + 1)
  const current = visible[visible.length - 1]
  const chart = data.steps.map((s, i) => ({
    i, label: s.ts.slice(5, 10), risk: i < visible.length ? s.risk : null, tier: s.tier,
  }))

  return (
    <Panel
      title="Early-warning timeline — deterministic replay"
      right={
        <div className="flex items-center gap-1">
          {data.lead_days_before_disclosure != null && data.lead_days_before_disclosure > 0 && (
            <Badge tone="accent">first warning {data.lead_days_before_disclosure} days before disclosure</Badge>
          )}
          <button
            onClick={() => {
              if (playing) return setPlaying(false)
              if (cursor < 0 || cursor >= data.steps.length - 1) setCursor(0)
              setPlaying(true)
            }}
            className="rounded bg-accent/20 p-1 text-accent hover:bg-accent/30" title={playing ? 'Pause' : 'Replay'}
          >
            {playing ? <Pause size={14} /> : <Play size={14} />}
          </button>
          <button onClick={() => { setPlaying(false); setCursor(-1) }} className="rounded p-1 text-mute hover:text-text" title="Show all">
            <RotateCcw size={14} />
          </button>
        </div>
      }
    >
      <div className="mb-2 flex items-center gap-3 rounded border border-line bg-panel-2 p-2">
        <TierPill tier={current.tier} />
        <span className="font-mono text-2xl">{current.risk.toFixed(0)}</span>
        <span className="text-xs text-mute">deadline {deadlineText(current.deadline_hours)} · {current.deadline_basis}</span>
      </div>
      <div className="h-36">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chart} margin={{ left: -20, right: 10, top: 5 }}>
            <CartesianGrid stroke="var(--color-line)" strokeDasharray="3 3" />
            <XAxis dataKey="label" tick={{ fill: 'var(--color-mute)', fontSize: 11 }} />
            <YAxis domain={[0, 100]} tick={{ fill: 'var(--color-mute)', fontSize: 11 }} />
            <Tooltip contentStyle={{ background: 'var(--color-panel)', border: '1px solid var(--color-line-2)', borderRadius: 10 }} />
            <Line type="stepAfter" dataKey="risk" stroke="var(--color-accent)" strokeWidth={2} isAnimationActive={false}
                  dot={(p) => {
                    const { cx, cy, payload, index } = p as { cx: number; cy: number; payload: { tier: keyof typeof TIER_FILL; risk: number | null }; index: number }
                    if (payload.risk == null) return <g key={index} />
                    return <circle key={index} cx={cx} cy={cy} r={5} fill={TIER_FILL[payload.tier]} stroke="var(--color-panel)" strokeWidth={2} />
                  }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <ol className="mt-2 space-y-1.5 text-xs">
        {visible.map((s, i) => (
          <li key={i} className={`flex items-start gap-2 ${i === visible.length - 1 && cursor >= 0 ? 'rounded bg-accent/10 p-1' : ''}`}>
            <span className="w-24 shrink-0 font-mono text-mute">{fmtDate(s.ts).slice(5)}</span>
            <Prov p={s.provenance} />
            <span className="flex-1">{s.event}</span>
            <TierPill tier={s.tier} />
          </li>
        ))}
      </ol>
      <div className="mt-2 text-xs text-mute">
        REAL = public record (CVE/CNA, CISA KEV, CISA SSVC). SIM = simulated national telemetry (decoy grid, firewall logs).
        Every step is re-scored from the evidence ledger as of that moment.
      </div>
    </Panel>
  )
}
