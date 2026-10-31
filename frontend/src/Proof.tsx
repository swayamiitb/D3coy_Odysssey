import { useEffect, useState } from 'react'
import { api, type ForecastView, type Soc } from './api'
import { ForecastProof, LeadProof, TestBench } from './ProofProactive'
import { Badge, Prov, Section, Sheet, Stat, Tile } from './ui'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Scorecard = any

function Figure({ value, label, sub }: { value: string; label: string; sub?: string }) {
  return <Stat value={value} label={label} sub={sub} />
}

/** Emphasis bars: one series, ours in the accent hue, baselines in recessive gray, direct value labels. */
function MissBars({ rows }: { rows: { name: string; value: number; ours?: boolean; note: string }[] }) {
  const [hover, setHover] = useState<number>()
  return (
    <div className="space-y-3" role="table" aria-label="Share of known-exploited CVEs each triage policy would miss">
      {rows.map((r, i) => (
        <div key={r.name} role="row" className="grid grid-cols-[180px_1fr_64px] items-center gap-3"
             onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(undefined)}>
          <div role="cell" className={`text-sm ${r.ours ? 'font-semibold' : 'text-mute'}`}>{r.name}</div>
          <div role="cell" className="relative h-6">
            <div className="absolute inset-y-2 left-0 right-0 rounded-sm bg-panel-2" />
            <div className="absolute inset-y-1 left-0 rounded-r-[4px] transition-all"
                 style={{ width: `${Math.max(r.value, 0.6)}%`, background: r.ours ? 'var(--color-accent)' : 'var(--color-faint)' }} />
            {hover === i && (
              <div className="absolute -top-9 left-0 z-10 rounded-md border border-line bg-ink px-2 py-1 text-xs shadow-lg">
                {r.name}: misses <b>{r.value}%</b> · {r.note}
              </div>
            )}
          </div>
          <div role="cell" className="text-right font-mono text-sm">{r.value}%</div>
        </div>
      ))}
    </div>
  )
}

function Table({ head, rows }: { head: string[]; rows: (string | number)[][] }) {
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-xs text-mute">
        <tr>{head.map((h) => <th key={h} className="pb-2 font-normal">{h}</th>)}</tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-t border-line/60">
            {r.map((c, j) => (
              <td key={j} className={`py-2 pr-4 align-top ${j === 0 || j === r.length - 1 ? '' : 'font-mono'} ${j === r.length - 1 ? 'text-mute' : ''}`}>{c}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** One cell per scheduled language: measured share of brief sentences that passed the translation validator. */
function IndicGrid({ r }: { r: Scorecard }) {
  const langs = Object.entries(r.languages) as [string, any][]
  const n = r.sentences?.length ?? langs[0]?.[1].total
  return (
    <section className="rounded-2xl border border-line bg-panel p-6">
      <div className="mb-1 flex items-center gap-2">
        <h3 className="text-lg font-semibold">Every warning in all {langs.length} scheduled Indian languages</h3>
        <Badge tone="ok">{r.validated}/{r.total} validated</Badge>
      </div>
      <p className="mb-4 text-sm text-mute">
        {n} real brief sentences per language (CVE ids, version lists, hostnames, IPs, dates), translated on the CPU by
        IndicTrans2. A sentence is shown only if every identifier survives exactly, every Latin word comes from the source
        and the text is in the right script; otherwise the English line is shown. Hover a language for what was withheld.
      </p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-6">
        {langs.map(([code, x]) => (
          <div key={code} className="rounded-lg border border-line/60 bg-panel-2/40 p-2.5"
               title={x.withheld?.length ? x.withheld.map((w: any) => `${w.source}… — ${w.problems.join('; ')}`).join('\n') : 'all sentences validated'}>
            <div className="flex items-baseline justify-between gap-2">
              <span className="truncate text-base" lang={code} dir={x.script === 'Arab' ? 'rtl' : 'ltr'}>{x.native ?? x.name}</span>
              <span className="font-mono text-sm tabular-nums">{x.validated}/{x.total}</span>
            </div>
            <div className="mt-1 h-1 rounded-full bg-panel-2">
              <div className="h-1 rounded-full bg-accent" style={{ width: `${(100 * x.validated) / x.total}%` }} />
            </div>
            <div className="mt-1 text-[11px] text-mute">{x.name} · {x.script}</div>
          </div>
        ))}
      </div>
    </section>
  )
}

type ProofSheet = 'bench' | 'lead' | 'forecast' | 'policy' | 'indic' | 'exposure' | 'models'

/** Proof, Uber-simple: one card per claim with its headline number; the evidence opens in a sheet. */
export function Proof() {
  const [d, setD] = useState<Scorecard>()
  const [bench, setBench] = useState<any>()
  const [fc, setFc] = useState<ForecastView>()
  const [soc, setSoc] = useState<Soc>()
  const [sheet, setSheet] = useState<ProofSheet>()
  useEffect(() => {
    fetch('/api/scorecard').then((r) => r.json()).then(setD).catch(() => undefined)
    fetch('/api/tests/last').then((r) => r.json()).then(setBench).catch(() => undefined)
    api.forecast().then(setFc).catch(() => undefined)
    api.soc().then(setSoc).catch(() => undefined)
  }, [sheet])
  if (!d) return <div className="py-10 text-mute">Computing the scorecard from local data…</div>

  const bt = d.backtest
  const ext = (d.models.extraction_kev2026 ?? []) as any[]
  const cti = [...(d.models.cti_round1 ?? []), ...(d.models.cti_round3 ?? [])] as any[]
  const clf = d.models.text_classifiers
  const ctiRows: (string | number)[][] = [
    ...(clf ? [[`${clf.model}`, `${clf.rcm_acc_pct}% (top-3 ${clf.rcm_top3_pct}%)`, clf.vsp_mad, 'standard ML, CPU']] : []),
    ...cti.filter((r) => !r.model.startsWith('qwen3:4b')).map((r) => [
      r.model, `${r.rcm_acc_pct}%`, r.vsp_invalid ? 'invalid output' : r.vsp_mad,
      r.model.startsWith('qwen') ? 'general LLM (baseline only)' : 'security LLM']),
  ]
  const lead = soc?.autopilot.lead?.real_signals_only
  const live = fc?.model.live
  const indic = d.models.indic22
  const close = () => setSheet(undefined)

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-14">
      <Section title="Claims you can check" sub="Each card is measured on this laptop from real data, or re-run on the spot. Open one for the evidence.">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Tile value={bench?.ran_at ? `${bench.passed}/${bench.total}` : 'Run'} title="Tests pass, attacks included"
                sub="detectors with negative controls, the audit trail and the engine" cta="Run them now" onClick={() => setSheet('bench')} />
          <Tile value={lead?.median_lead_days != null ? `${lead.median_lead_days} d` : '—'} title="Ahead of CISA on our own constituency"
                sub={lead ? `median on real public signals · ${lead.acted_before_kev} CVEs · up to ${lead.max_lead_days} d` : undefined} onClick={() => setSheet('lead')} />
          <Tile value={live ? `${live.odyssey.recall_pct}%` : '—'} title="Of exploited CVEs flagged on day 0"
                sub={live ? `out-of-time test, Aug–Oct · CVSS ≥ 9 caught ${live.same_budget_recall_pct.cvss}% at the same budget` : undefined} onClick={() => setSheet('forecast')} />
          <Tile value={`${bt.missed_pct.epss_alone}%`} title="Of exploited CVEs that EPSS alone would miss"
                sub={`${bt.kev_entries} CISA-confirmed CVEs; Odyssey's evidence rules miss ${bt.missed_pct.our_evidence_rules}%`} onClick={() => setSheet('policy')} />
          {indic && <Tile value={`${Object.keys(indic.languages).length}`} title="Indian languages, checked sentence by sentence"
                          sub={`${indic.validated}/${indic.total} translated sentences passed every check`} onClick={() => setSheet('indic')} />}
          <Tile value={d.exposure.cleared_by_version_evidence.toLocaleString('en-IN')} title="False alarms prevented by version evidence"
                sub="patched or unaffected branches are never alerted" onClick={() => setSheet('exposure')} />
          <Tile value={`${d.briefs.validated}/${d.briefs.total}`} title="AI briefs passed the fact check"
                sub={`${d.briefs.first_attempt} on the first attempt; failures are withheld, never shown`} onClick={() => setSheet('models')} />
          <Tile value={`${ext.length + ctiRows.length}`} title="Model runs compared on 2026 data"
                sub="each AI job goes to whichever model measured best" onClick={() => setSheet('models')} />
        </div>
      </Section>

      {sheet === 'bench' && <Sheet wide title="Test bench" sub="Run it now: detectors on attack telemetry with negative controls, the audit trail, the engine test suite." onClose={close}><TestBench /></Sheet>}
      {sheet === 'lead' && <Sheet wide title="Ahead of CISA, on our own constituency" sub="Every CVE CISA added since go-live that hit an exposed asset here, and when Odyssey first acted." onClose={close}><LeadProof /></Sheet>}
      {sheet === 'forecast' && <Sheet wide title="Predicting exploitation on day 0" sub="Trained on 2021–2025, frozen on 31 Jul 2026, scored on everything published after." onClose={close}><ForecastProof /></Sheet>}
      {sheet === 'policy' && (
        <Sheet wide title="Which triage policy misses real attacks?" sub={`${bt.kev_entries} CVEs that CISA confirmed exploited in the wild (${bt.window[0]} → ${bt.window[1]}). Lower is better.`} onClose={close}>
          <div className="mb-3"><Prov p="REAL" label="REAL data" /></div>
          <MissBars rows={[
            { name: 'EPSS ≥ 0.1 alone', value: bt.missed_pct.epss_alone, note: "even with today's scores (hindsight)" },
            { name: 'CVSS ≥ 9.0 alone', value: bt.missed_pct.cvss_alone, note: 'severity is not exploitation' },
            { name: 'Odyssey evidence rules', value: bt.missed_pct.our_evidence_rules, ours: true,
              note: `${bt.corroborated_without_kev}/${bt.kev_entries} also flagged by channels other than KEV` },
          ]} />
          <p className="mt-6 leading-relaxed text-mute">
            Honest reading: KEV listing is itself one of our rules, so 0% is by construction. The meaningful figure is that{' '}
            {bt.corroborated_without_kev} of {bt.kev_entries} were also caught by CISA SSVC ({bt.channels.cisa_ssvc_active}) or
            vendor "exploited in the wild" text ({bt.channels.vendor_itw_claim}). {bt.channels.note}
          </p>
          <div className="mt-4 flex flex-wrap gap-1.5 text-sm">
            <span className="text-mute">Exploited, yet EPSS below 0.01:</span>
            {bt.examples_low_epss.map((x: any) => <Badge key={x.cve}>{x.cve} · EPSS {x.epss}</Badge>)}
          </div>
        </Sheet>
      )}
      {sheet === 'indic' && indic && <Sheet wide title="Every warning in every scheduled Indian language" sub="Translated on the CPU by IndicTrans2; a sentence is shown only if it passes every check." onClose={close}><IndicGrid r={indic} /></Sheet>}
      {sheet === 'exposure' && (
        <Sheet title="Exposure precision" sub="Version evidence decides whether an asset is affected; disagreements go to an analyst." onClose={close}>
          <div className="grid gap-3">
            <Figure value={d.exposure.cleared_by_version_evidence.toLocaleString('en-IN')} label="asset × CVE pairs cleared by version evidence" sub="patched or unaffected branches are not alerted" />
            <Figure value={d.exposure.disputed_flagged_for_analyst.toLocaleString('en-IN')} label="disputed: sources disagree" sub="flagged for an analyst; treated as exposed, never silently cleared" />
            <Figure value="0" label="false 'affected' on the real Ivanti case" sub={d.exposure.unit_tests} />
          </div>
        </Sheet>
      )}
      {sheet === 'models' && (
        <Sheet wide title="Measured, not assumed" sub="Every AI job is benchmarked on 2026 data, newer than any model's training, and goes to whatever measured best." onClose={close}>
          <h3 className="mb-1 text-xl font-bold">Reading advisories: product extraction</h3>
          <p className="mb-4 text-mute">All 2026 CISA-KEV CVEs, strict match to KEV's own vendor/product names. 95% intervals.</p>
          <Table head={['Model', 'Vendor', 'Product', 's/item']}
                 rows={ext.map((r) => [r.model, `${r.vendor_pct}% [${r.vendor_ci95.join('–')}]`, `${r.product_pct}%`, r.median_s])} />
          <p className="mt-3 mb-10 text-sm text-mute">
            Statistically tied, and most misses are naming granularity ("SMA1000" vs "SMA1000 Appliances"), so Odyssey decides product identity by
            closed-set matching to the inventory, never free text.
          </p>
          <h3 className="mb-1 text-xl font-bold">Root cause (CWE) and severity (CVSS)</h3>
          <p className="mb-4 text-mute">40 CVEs from 2026, newer than every model's training data.</p>
          <Table head={['Model', 'CWE top-1', 'CVSS error', 'Type']} rows={ctiRows} />
          <p className="mt-3 text-sm text-mute">
            Classic ML handles structured labels, the security LLM explains. AI briefs: {d.briefs.validated}/{d.briefs.total} passed the fact validator,
            {' '}{d.briefs.first_attempt} on the first attempt; failures are withheld.
          </p>
        </Sheet>
      )}
    </div>
  )
}
