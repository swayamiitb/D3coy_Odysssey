import { Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Spark } from './Soc'
import { Row, Section, Sheet, Stat, Tile } from './ui'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Tele = any

const PROV_COLOR = ['var(--color-text)', 'var(--color-accent)', 'var(--color-ok)', 'var(--color-comp)', 'var(--color-high)', 'var(--color-faint)']

/** System telemetry, live: the platform measuring itself (refreshes every 3 s). Vital signs on screen, the
 *  breakdowns (AI jobs, API routes, audit trail, build stages) one tap away. */
export function SystemView() {
  const [t, setT] = useState<Tele>()
  const [err, setErr] = useState<string>()
  const [sheet, setSheet] = useState<'ai' | 'api' | 'ledger' | 'build'>()
  useEffect(() => {
    let alive = true
    const pull = () => fetch('/api/telemetry').then((r) => r.json()).then((d) => alive && setT(d)).catch((e) => setErr(String(e)))
    pull()
    const id = setInterval(pull, 3000)
    return () => { alive = false; clearInterval(id) }
  }, [])
  if (!t) return <div className="py-10 text-mute">{err ?? <><Loader2 size={16} className="mr-2 inline animate-spin" />Reading the system's vital signs…</>}</div>
  const h = t.host
  const series = t.series as { cpu: number; gpu: number; ram: number; vram: number }[]
  const prov = Object.entries(t.ledger.by_provenance as Record<string, number>).sort((a, b) => b[1] - a[1])
  const provTotal = prov.reduce((s, [, n]) => s + n, 0) || 1
  const stages = (t.pipeline.stages as { stage: string; seconds: number }[])
  const stageMax = Math.max(1, ...stages.map((s) => s.seconds))
  const ai = [...(t.ai as any[]).map((r) => ({ ...r, live: true })), ...((t.ai_record as any[]) ?? [])]
  const runs = ai.reduce((s, r) => s + r.calls, 0)
  const p50s = (t.api as any[]).map((r) => r.p50_ms).filter((v) => v != null).sort((a, b) => a - b)
  const apiP50 = p50s.length ? p50s[Math.floor(p50s.length / 2)] : null

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-14">
      <Section title="Vital signs" sub={<span className="flex items-center gap-2"><span className="h-2 w-2 animate-pulse rounded-full bg-ok" /> Live from this laptop, every 3 seconds.</span>}>
        <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
          <Stat value={h.cpu != null ? `${Math.round(h.cpu)}%` : '—'} label="CPU" sub="ML models, translation, API" />
          <Stat value={h.gpu ? `${Math.round(h.gpu.util)}%` : '—'} label="GPU" sub={h.gpu ? `${h.gpu.name.replace('NVIDIA GeForce ', '')} · ${h.gpu.temp_c}°C` : 'nvidia-smi unavailable'} />
          <Stat value={h.gpu ? `${h.gpu.vram_used_gb} GB` : '—'} label="VRAM in use" sub={h.gpu ? `of ${h.gpu.vram_total_gb} GB` : undefined} />
          <Stat value={h.ram ? `${h.ram.used_gb} GB` : '—'} label="Memory" sub={h.ram ? `${h.ram.percent}% of ${h.ram.total_gb} GB` : undefined} />
        </div>
      </Section>

      <div className="grid gap-12 xl:grid-cols-2">
        <Section title="Load, last minutes">
          <div className="grid grid-cols-2 gap-5">
            {([['CPU %', 'cpu', 'var(--color-text)', 100], ['GPU %', 'gpu', 'var(--color-accent)', 100], ['Memory %', 'ram', 'var(--color-faint)', 100],
               ['VRAM GB', 'vram', 'var(--color-comp)', h.gpu?.vram_total_gb ?? 8]] as const).map(([label, key, color, top]) => (
              <div key={key}>
                <div className="flex justify-between text-sm"><span className="font-medium">{label}</span><span className="tabular-nums text-mute">{series.at(-1)?.[key] ?? '—'}</span></div>
                <div className="mt-1 rounded-xl bg-panel-2 px-1.5 py-1"><Spark values={series.map((s) => s[key] ?? 0)} color={color} h={44} max={top} /></div>
              </div>
            ))}
          </div>
        </Section>
        <Section title="AI on this laptop" sub="Nothing leaves the machine: 0 cloud calls.">
          {h.models.length ? h.models.map((m: any) => (
            <Row key={m.name} lead={<span className="text-xs font-bold">GPU</span>} title={m.name} sub={`${m.params} parameters · context ${m.context}`}
                 trail={<span><b>{m.vram_gb} GB</b><span className="block text-xs text-mute">in VRAM</span></span>} />
          )) : <Row lead={<span className="text-xs font-bold">GPU</span>} title="Security LLM idle" sub="Ollama unloads it when idle; the next question loads it again" />}
          <Row lead={<span className="text-xs font-bold">CPU</span>} title="SecureBERT 2.0, DeBERTa guard, IndicTrans2, classic ML" sub="encoders, prompt-injection guard, 22-language translation, scoring" />
        </Section>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Tile value={runs.toLocaleString('en-IN')} title="AI jobs, timed and checked" sub="briefs, copilot answers, translations, advisory analysis" onClick={() => setSheet('ai')} />
        <Tile value={apiP50 != null ? `${apiP50} ms` : '—'} title="Typical API response" sub={`median across ${t.api.length} routes since start`} onClick={() => setSheet('api')} />
        <Tile value={t.ledger.events.toLocaleString('en-IN')} title="Audit-trail events" sub={`${t.ledger.per_min} new per minute · hash-chained`} onClick={() => setSheet('ledger')} />
        <Tile value={stages.length ? `${Math.round(stages.reduce((s, x) => s + x.seconds, 0))} s` : '—'} title="Last full rebuild" sub={t.pipeline.built_at?.replace('T', ' ').slice(0, 16) ?? 'not yet timed'} onClick={() => setSheet('build')} />
      </div>

      {sheet === 'ai' && (
        <Sheet wide title="AI jobs, timed and checked" sub="Live rows are calls since the API started; the rest were timed when first generated and are served from the content-addressed cache." onClose={() => setSheet(undefined)}>
          <table className="w-full">
            <thead className="text-left text-sm text-mute"><tr><th className="pb-3 font-normal">Job</th><th className="pb-3 font-normal">Model</th><th className="pb-3 text-right font-normal">Runs</th><th className="pb-3 text-right font-normal">Median</th><th className="pb-3 text-right font-normal">p95</th><th className="pb-3 text-right font-normal">tokens/s</th><th className="pb-3 text-right font-normal" title="share of output that passed its checks (facts, numbers, placeholders, script)">Passed checks</th></tr></thead>
            <tbody>
              {ai.map((r) => (
                <tr key={(r.live ? 'live' : 'rec') + r.role + r.model} className="border-t border-line">
                  <td className="py-3 font-medium">{r.role}{r.live && <span className="ml-2 rounded-full bg-ok px-2 py-0.5 text-[10px] font-semibold text-white">live</span>}</td>
                  <td className="max-w-64 truncate py-3 text-mute" title={r.model}>{r.model}</td>
                  <td className="py-3 text-right tabular-nums">{r.calls}</td><td className="py-3 text-right tabular-nums">{r.p50_s} s</td>
                  <td className="py-3 text-right tabular-nums">{r.p95_s} s</td><td className="py-3 text-right tabular-nums">{r.tokens_per_s ?? '—'}</td>
                  <td className="py-3 text-right tabular-nums">{r.ok_pct}%</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-4 text-sm text-mute">Anything that fails its checks is withheld (briefs, answers) or falls back to English (translation); it is never shown as if it passed.</p>
        </Sheet>
      )}
      {sheet === 'api' && (
        <Sheet title="API response time by route" sub="The last 400 requests per route since the API started." onClose={() => setSheet(undefined)}>
          <table className="w-full">
            <thead className="text-left text-sm text-mute"><tr><th className="pb-3 font-normal">Route</th><th className="pb-3 text-right font-normal">Calls</th><th className="pb-3 text-right font-normal">Median</th><th className="pb-3 text-right font-normal">p95</th><th className="pb-3 text-right font-normal">Errors</th></tr></thead>
            <tbody>
              {(t.api as any[]).map((r) => (
                <tr key={r.route} className="border-t border-line">
                  <td className="max-w-80 truncate py-2.5 font-mono text-sm" title={r.route}>{r.route}</td>
                  <td className="py-2.5 text-right tabular-nums">{r.calls}</td><td className="py-2.5 text-right tabular-nums">{r.p50_ms} ms</td>
                  <td className="py-2.5 text-right tabular-nums">{r.p95_ms} ms</td>
                  <td className={`py-2.5 text-right tabular-nums ${r.errors ? 'text-crit' : 'text-mute'}`}>{r.errors}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Sheet>
      )}
      {sheet === 'ledger' && (
        <Sheet title="Where the audit trail comes from" sub="Every event is hash-chained to the one before it; any edit breaks the chain." onClose={() => setSheet(undefined)}>
          <div className="flex h-5 overflow-hidden rounded-full">
            {prov.map(([p, n], i) => <div key={p} title={`${p}: ${n}`} style={{ width: `${(100 * n) / provTotal}%`, background: PROV_COLOR[i % 6] }} />)}
          </div>
          <div className="mt-5">
            {prov.map(([p, n], i) => (
              <Row key={p} lead={<span className="h-3 w-3 rounded-full" style={{ background: PROV_COLOR[i % 6] }} />} title={p}
                   sub={({ REAL: 'public feeds', SIM: 'simulated sensors, labelled', AI: 'model outputs', AUTO: 'autopilot actions', HUMAN: 'analyst decisions' } as Record<string, string>)[p] ?? ''}
                   trail={<b className="tabular-nums">{n.toLocaleString('en-IN')}</b>} />
            ))}
          </div>
        </Sheet>
      )}
      {sheet === 'build' && (
        <Sheet title="Last full rebuild, stage by stage" sub={`Built ${t.pipeline.built_at?.replace('T', ' ') ?? ''} from the offline feed snapshot.`} onClose={() => setSheet(undefined)}>
          {stages.length ? (
            <div className="space-y-4">
              {stages.map((s) => (
                <div key={s.stage}>
                  <div className="mb-1 flex justify-between"><span>{s.stage}</span><span className="tabular-nums text-mute">{s.seconds} s</span></div>
                  <div className="h-2.5 rounded-full bg-panel-2"><div className="h-2.5 rounded-full bg-action" style={{ width: `${Math.max(2, (100 * s.seconds) / stageMax)}%` }} /></div>
                </div>
              ))}
            </div>
          ) : <div className="text-mute">Stage timings appear after the next rebuild.</div>}
        </Sheet>
      )}
    </div>
  )
}
