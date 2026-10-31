import { CircleCheck, CircleX, FlaskConical, Loader2, Play } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type ForecastEval, type ForecastView, type Soc } from './api'
import { Badge } from './ui'

/** Same alert budget, different policy: share of later-exploited CVEs each would have caught on day 0. */
function Budget({ e }: { e: ForecastEval }) {
  const rows = [
    { name: 'Odyssey day-0 forecast', v: e.same_budget_recall_pct.odyssey, ours: true, note: 'only facts known on publication day' },
    { name: 'CVSS ≥ 9 ranking', v: e.same_budget_recall_pct.cvss, note: 'severity is not likelihood' },
    { name: 'EPSS today (hindsight)', v: e.same_budget_recall_pct.epss_today, note: 'scored months later, after exploitation was seen' },
  ]
  return (
    <div className="space-y-2.5">
      {rows.map((r) => (
        <div key={r.name} className="grid grid-cols-[190px_1fr_56px] items-center gap-3" title={r.note}>
          <div className={`text-sm ${r.ours ? 'font-semibold' : 'text-mute'}`}>{r.name}</div>
          <div className="relative h-5">
            <div className="absolute inset-y-2 left-0 right-0 rounded-sm bg-panel-2" />
            <div className="absolute inset-y-1 left-0 rounded-r-[4px]" style={{ width: `${r.v}%`, background: r.ours ? '#38bdf8' : '#64748b' }} />
          </div>
          <div className="text-right font-mono text-sm">{r.v}%</div>
        </div>
      ))}
    </div>
  )
}

export function ForecastProof() {
  const [f, setF] = useState<ForecastView>()
  useEffect(() => { api.forecast().then(setF).catch(() => undefined) }, [])
  if (!f) return null
  const { live, test } = f.model
  return (
    <section className="rounded-2xl border border-line bg-panel p-6">
      <div className="mb-1 flex items-center gap-2">
        <h3 className="text-lg font-semibold">Predicting exploitation on day 0</h3>
        <Badge tone="ok">REAL data · out-of-time</Badge>
      </div>
      <p className="mb-4 text-sm text-mute">
        Trained on NVD 2021–2025, frozen on 31 Jul 2026, then scored every CVE published Aug–Oct 2026 ({live.cves.toLocaleString('en-IN')} CVEs, {live.exploited} later
        added to CISA KEV). Features use only what is known on publication day: no KEV, SSVC, EPSS or exploit references.
      </p>
      <div className="grid gap-6 xl:grid-cols-2">
        <div>
          <div className="mb-2 text-xs uppercase tracking-wider text-mute">Caught with the same alert budget ({live.odyssey.flag_rate_pct}% of new CVEs)</div>
          <Budget e={live} />
        </div>
        <div className="grid grid-cols-2 gap-3 text-sm">
          {[
            [`${live.odyssey.recall_pct}%`, `of later-exploited CVEs flagged on day 0 (Aug–Oct)`],
            [`${test.odyssey.recall_pct}%`, `same on Jan–Jul 2026 (${test.odyssey.flag_rate_pct}% flagged)`],
            [`${test.lead_days?.median ?? '—'} d`, `median warning before CISA KEV (Jan–Jul); ${test.lead_days?.ge_7_days_pct ?? '—'}% by a week or more`],
            [`${live.roc_auc} / ${test.roc_auc}`, 'ROC AUC, Aug–Oct / Jan–Jul'],
          ].map(([v, l]) => (
            <div key={l} className="rounded-xl bg-panel-2 p-3">
              <div className="text-2xl font-semibold tabular-nums">{v}</div>
              <div className="text-xs text-mute">{l}</div>
            </div>
          ))}
        </div>
      </div>
      <p className="mt-4 text-xs text-mute">
        Calibration (Aug–Oct): {live.calibration.filter((c) => c.n >= 4).map((c) => `forecast ${(c.mean_forecast * 100).toFixed(1)}% → observed ${(c.observed * 100).toFixed(1)}% (n=${c.n.toLocaleString('en-IN')})`).join(' · ')}.
        Honest reading: precision is low ({live.odyssey.precision_pct}%) because exploitation is rare (base rate {live.base_rate_pct}%); the forecast proposes, an analyst approves.
      </p>
    </section>
  )
}

export function LeadProof() {
  const [s, setS] = useState<Soc>()
  useEffect(() => { api.soc().then(setS).catch(() => undefined) }, [])
  const lead = s?.autopilot.lead
  if (!s || !lead) return null
  const mode = s.autopilot.by_mode
  const rows = lead.rows.filter((r) => r.lead_days != null).sort((a, b) => (b.lead_days ?? 0) - (a.lead_days ?? 0))
  return (
    <section className="rounded-2xl border border-line bg-panel p-6">
      <div className="mb-1 flex items-center gap-2">
        <h3 className="text-lg font-semibold">Ahead of CISA, on our own constituency</h3>
        <Badge tone="ok">REAL CVEs</Badge><Badge tone="accent">REAL + SIM signals, attributed</Badge>
      </div>
      <p className="mb-4 text-sm text-mute">
        Since go-live ({s.autopilot.go_live}) CISA added {lead.kev_after_go_live} CVEs that hit exposed assets here. Odyssey acted on {lead.acted_before_kev} of
        them a day or more before the listing (median {lead.median_lead_days} d), {lead.acted_same_day} within the same day, and {lead.not_acted} needed no notice.
        On REAL public signals alone: <b className="text-text">{lead.real_signals_only.acted_before_kev} CVEs, median {lead.real_signals_only.median_lead_days} d, up to {lead.real_signals_only.max_lead_days} d</b>.
      </p>
      <table className="w-full text-sm">
        <thead className="text-left text-xs text-mute"><tr><th className="pb-2 font-normal">CVE</th><th className="pb-2 font-normal">First action</th><th className="pb-2 font-normal">On the basis of</th><th className="pb-2 text-right font-normal">Lead over KEV</th></tr></thead>
        <tbody>
          {rows.slice(0, 8).map((r) => (
            <tr key={r.cve} className="border-t border-line/60">
              <td className="py-2 font-mono">{r.cve}</td>
              <td className="py-2 text-mute">{r.first_action?.slice(0, 10)}</td>
              <td className="py-2"><Badge tone={r.provenance === 'REAL' ? 'ok' : 'accent'}>{r.provenance}</Badge> <span className="text-xs text-mute">{(r.basis ?? '').slice(0, 64)}</span></td>
              <td className={`py-2 text-right font-mono ${(r.lead_days ?? 0) >= 1 ? 'text-ok' : 'text-mute'}`}>{(r.lead_days ?? 0) >= 1 ? `${r.lead_days} d` : 'same day'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {mode && (
        <p className="mt-4 text-xs text-mute">
          Graduated autonomy: {mode.auto} evidence-based actions ran on their own; {mode.approve} predictions, sensor-only warnings and escalations were
          proposed for a human (history approved by a simulated duty officer, labelled SIM); {s.pending} wait for you now.
        </p>
      )}
    </section>
  )
}

interface BenchResult { layer: string; name: string; passed: boolean; detail: string; seconds: number }
interface Bench { ran_at: string | null; seconds?: number; passed?: number; total?: number; results: BenchResult[] }

export function TestBench() {
  const [b, setB] = useState<Bench>()
  const [busy, setBusy] = useState(false)
  useEffect(() => { fetch('/api/tests/last').then((r) => r.json()).then(setB).catch(() => undefined) }, [])
  const run = () => {
    setBusy(true)
    fetch('/api/tests/run', { method: 'POST' }).then((r) => r.json()).then(setB).finally(() => setBusy(false))
  }
  const layers = ['detection checks', 'integrity', 'engine tests']
  return (
    <section className="rounded-2xl border border-line bg-panel p-6">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <h3 className="text-lg font-semibold">Test bench: run it now</h3>
        {b?.ran_at && <Badge tone={b.passed === b.total ? 'ok' : 'crit'}>{b.passed}/{b.total} passed · {b.seconds}s · {b.ran_at.slice(11, 19)}</Badge>}
        <button onClick={run} disabled={busy}
                className="ml-auto flex items-center gap-2 rounded-full bg-accent px-4 py-1.5 text-sm font-semibold text-ink hover:brightness-110 disabled:opacity-50">
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />} {busy ? 'Running…' : 'Run all tests'}
        </button>
      </div>
      <p className="mb-4 text-sm text-mute">
        Detectors are tested on attack telemetry with negative controls (a detector that never says no proves nothing), the audit trail is
        re-verified, and the full engine test suite runs on this laptop.
      </p>
      {!b?.ran_at && !busy && <div className="flex items-center gap-2 text-sm text-mute"><FlaskConical size={14} /> Not run in this session yet.</div>}
      {busy && <div className="flex items-center gap-2 text-sm text-mute"><Loader2 size={14} className="animate-spin" /> Running detectors, guard model and the engine test suite…</div>}
      {b?.ran_at && !busy && layers.map((layer) => {
        const rs = b.results.filter((r) => r.layer === layer)
        if (!rs.length) return null
        const shown = layer === 'engine tests' ? rs.filter((r) => !r.passed).concat(rs.filter((r) => r.passed).slice(0, 6)) : rs
        return (
          <div key={layer} className="mb-3">
            <div className="mb-1 text-xs uppercase tracking-wider text-mute">{layer} · {rs.filter((r) => r.passed).length}/{rs.length} passed</div>
            <ul className="space-y-1">
              {shown.map((r) => (
                <li key={r.name} className="flex items-start gap-2 text-sm">
                  {r.passed ? <CircleCheck size={15} className="mt-0.5 shrink-0 text-ok" /> : <CircleX size={15} className="mt-0.5 shrink-0 text-crit" />}
                  <div className="min-w-0">
                    <div className="truncate">{r.name}</div>
                    {r.detail && <div className="text-xs text-mute">{r.detail}</div>}
                  </div>
                </li>
              ))}
              {layer === 'engine tests' && rs.length > shown.length && <li className="text-xs text-mute">… and {rs.length - shown.length} more passing tests</li>}
            </ul>
          </div>
        )
      })}
    </section>
  )
}
