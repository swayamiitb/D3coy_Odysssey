import { Activity, Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Spark } from './Soc'
import { Panel, Stat } from './ui'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Tele = any

/** System telemetry, live: the platform measuring itself (refreshes every 3 s). */
export function SystemView() {
  const [t, setT] = useState<Tele>()
  const [err, setErr] = useState<string>()
  useEffect(() => {
    let alive = true
    const pull = () => fetch('/api/telemetry').then((r) => r.json()).then((d) => alive && setT(d)).catch((e) => setErr(String(e)))
    pull()
    const id = setInterval(pull, 3000)
    return () => { alive = false; clearInterval(id) }
  }, [])
  if (!t) return <div className="p-8 text-mute">{err ?? <><Loader2 size={16} className="mr-2 inline animate-spin" />Reading the system's vital signs…</>}</div>
  const h = t.host
  const series = t.series as { cpu: number; gpu: number; ram: number; vram: number }[]
  const prov = Object.entries(t.ledger.by_provenance as Record<string, number>).sort((a, b) => b[1] - a[1])
  const provTotal = prov.reduce((s, [, n]) => s + n, 0) || 1
  const stages = (t.pipeline.stages as { stage: string; seconds: number }[])
  const stageMax = Math.max(1, ...stages.map((s) => s.seconds))
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-5">
      <div className="flex items-center gap-2 text-sm text-mute">
        <span className="h-2 w-2 animate-pulse rounded-full bg-ok" /> Live · refreshes every 3 s · up {Math.floor(t.uptime_s / 60)} min
      </div>
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-5">
        <Stat value={h.cpu != null ? `${Math.round(h.cpu)}%` : '—'} label="CPU" sub="i9 · ML models, translation, API" />
        <Stat value={h.ram ? `${h.ram.used_gb} GB` : '—'} label="Memory" sub={h.ram ? `${h.ram.percent}% of ${h.ram.total_gb} GB` : undefined} />
        <Stat value={h.gpu ? `${Math.round(h.gpu.util)}%` : '—'} label="GPU load" sub={h.gpu ? `${h.gpu.name} · ${h.gpu.temp_c}°C · ${h.gpu.power_w} W` : 'nvidia-smi unavailable'} />
        <Stat value={h.gpu ? `${h.gpu.vram_used_gb} GB` : '—'} label="VRAM in use" sub={h.gpu ? `of ${h.gpu.vram_total_gb} GB` : undefined} />
        <Stat value={`${t.ledger.events.toLocaleString('en-IN')}`} label="audit-trail events" sub={`${t.ledger.per_min} new per minute`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Load, last minutes" right={<span className="flex items-center gap-1 text-xs text-mute"><Activity size={12} /> sampled every 3 s</span>}>
          <div className="grid grid-cols-2 gap-4">
            {([['CPU %', 'cpu', 'var(--color-text)', 100], ['GPU %', 'gpu', 'var(--color-accent)', 100], ['Memory %', 'ram', 'var(--color-mute)', 100],
               ['VRAM GB', 'vram', 'var(--color-comp)', h.gpu?.vram_total_gb ?? 8]] as const).map(([label, key, color, top]) => (
              <div key={key}>
                <div className="flex justify-between text-sm"><span className="font-medium">{label}</span><span className="tabular-nums text-mute">{series.at(-1)?.[key] ?? '—'}</span></div>
                <div className="rounded-lg bg-soft px-1"><Spark values={series.map((s) => s[key] ?? 0)} color={color} h={44} max={top} /></div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="AI resident on this laptop">
          {h.models.length ? h.models.map((m: any) => (
            <div key={m.name} className="flex items-center justify-between border-b border-line py-2.5 last:border-0">
              <div><div className="font-semibold">{m.name}</div><div className="text-sm text-mute">{m.params} parameters · context {m.context}</div></div>
              <div className="text-right"><div className="text-xl font-bold">{m.vram_gb} GB</div><div className="text-xs text-mute">in VRAM</div></div>
            </div>
          )) : <div className="text-sm text-mute">No model loaded right now (Ollama unloads idle models).</div>}
          <div className="mt-2 text-xs text-mute">Encoders (SecureBERT 2.0, DeBERTa guard), classic ML and IndicTrans2 run on the CPU; 0 cloud calls.</div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="AI work, measured" right={<span className="text-xs text-mute">every model call is timed and its output checked</span>}>
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-mute"><tr><th className="pb-2 font-normal">Job</th><th className="pb-2 font-normal">Model</th><th className="pb-2 text-right font-normal">Runs</th><th className="pb-2 text-right font-normal">p50</th><th className="pb-2 text-right font-normal">p95</th><th className="pb-2 text-right font-normal">tok/s</th><th className="pb-2 text-right font-normal" title="share of output that passed its checks (facts, numbers, placeholders, script)">Checked OK</th></tr></thead>
            <tbody>
              {([...(t.ai as any[]).map((r) => ({ ...r, live: true })), ...(t.ai_record as any[] ?? [])]).map((r) => (
                <tr key={(r.live ? 'live' : 'rec') + r.role + r.model} className="border-t border-line">
                  <td className="py-2 font-medium">{r.role}{r.live && <span className="ml-2 rounded-full bg-ok px-2 py-0.5 text-[10px] font-semibold text-white">live</span>}</td>
                  <td className="max-w-56 truncate py-2 text-mute" title={r.model}>{r.model}</td>
                  <td className="py-2 text-right tabular-nums">{r.calls}</td><td className="py-2 text-right tabular-nums">{r.p50_s}s</td>
                  <td className="py-2 text-right tabular-nums">{r.p95_s}s</td><td className="py-2 text-right tabular-nums">{r.tokens_per_s ?? '—'}</td>
                  <td className="py-2 text-right tabular-nums">{r.ok_pct}%</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt-3 text-xs text-mute">
            <b className="text-text">live</b>: calls since the API started ({t.ai.length ? t.ai.reduce((s: number, r: any) => s + r.calls, 0) : 0}).
            Other rows: every stored answer, timed when it was first generated and served from the content-addressed cache since.
          </div>
        </Panel>
        <Panel title="API latency by route" right={<span className="text-xs text-mute">last 400 requests per route</span>}>
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-mute"><tr><th className="pb-2 font-normal">Route</th><th className="pb-2 text-right font-normal">Calls</th><th className="pb-2 text-right font-normal">p50</th><th className="pb-2 text-right font-normal">p95</th><th className="pb-2 text-right font-normal">Errors</th></tr></thead>
            <tbody>
              {(t.api as any[]).slice(0, 12).map((r) => (
                <tr key={r.route} className="border-t border-line">
                  <td className="max-w-80 truncate py-2 font-mono text-xs" title={r.route}>{r.route}</td>
                  <td className="py-2 text-right tabular-nums">{r.calls}</td><td className="py-2 text-right tabular-nums">{r.p50_ms} ms</td>
                  <td className="py-2 text-right tabular-nums">{r.p95_ms} ms</td>
                  <td className={`py-2 text-right tabular-nums ${r.errors ? 'text-crit' : 'text-mute'}`}>{r.errors}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Where the audit trail comes from">
          <div className="flex h-4 overflow-hidden rounded-full">
            {prov.map(([p, n], i) => (
              <div key={p} title={`${p}: ${n}`} style={{ width: `${(100 * n) / provTotal}%`, background: ['var(--color-text)', 'var(--color-accent)', 'var(--color-ok)', 'var(--color-comp)', 'var(--color-high)', 'var(--color-mute)'][i % 6] }} />
            ))}
          </div>
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm">
            {prov.map(([p, n], i) => (
              <span key={p} className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: ['var(--color-text)', 'var(--color-accent)', 'var(--color-ok)', 'var(--color-comp)', 'var(--color-high)', 'var(--color-mute)'][i % 6] }} />
                {p} <b className="tabular-nums">{n.toLocaleString('en-IN')}</b>
              </span>
            ))}
          </div>
          <div className="mt-2 text-xs text-mute">REAL public feeds · SIM sensors · AI model outputs · AUTO autopilot · HUMAN analyst decisions. Every event is hash-chained.</div>
        </Panel>
        <Panel title="Last build, stage by stage" right={<span className="text-xs text-mute">{t.pipeline.built_at?.replace('T', ' ')}</span>}>
          {stages.length ? (
            <div className="space-y-2">
              {stages.map((s) => (
                <div key={s.stage} className="grid grid-cols-[200px_1fr_56px] items-center gap-3 text-sm">
                  <span className="truncate">{s.stage}</span>
                  <div className="h-2.5 rounded-full bg-panel-2"><div className="h-2.5 rounded-full bg-action" style={{ width: `${Math.max(2, (100 * s.seconds) / stageMax)}%` }} /></div>
                  <span className="text-right tabular-nums text-mute">{s.seconds}s</span>
                </div>
              ))}
            </div>
          ) : <div className="text-sm text-mute">Stage timings appear after the next rebuild.</div>}
        </Panel>
      </div>
    </div>
  )
}
