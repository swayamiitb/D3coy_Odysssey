import { useEffect, useState } from 'react'
import { ForecastProof, LeadProof, TestBench } from './ProofProactive'
import { Badge, Prov, Stat } from './ui'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Scorecard = any

function Tile({ value, label, sub }: { value: string; label: string; sub?: string }) {
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
                 style={{ width: `${Math.max(r.value, 0.6)}%`, background: r.ours ? 'var(--color-accent)' : '#64748b' }} />
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

export function Proof() {
  const [d, setD] = useState<Scorecard>()
  useEffect(() => { fetch('/api/scorecard').then((r) => r.json()).then(setD) }, [])
  if (!d) return <div className="p-8 text-mute">Computing the scorecard from local data…</div>

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

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-6">

      <TestBench />
      <ForecastProof />
      <LeadProof />

      <section className="rounded-2xl border border-line bg-panel p-6">
        <div className="mb-1 flex items-center gap-2">
          <h3 className="text-lg font-semibold">Which triage policy misses real attacks?</h3>
          <Prov p="REAL" label="REAL data" />
        </div>
        <p className="mb-5 text-sm text-mute">
          {bt.kev_entries} CVEs that CISA confirmed exploited in the wild ({bt.window[0]} → {bt.window[1]}).
          Lower is better.
        </p>
        <MissBars rows={[
          { name: 'EPSS ≥ 0.1 alone', value: bt.missed_pct.epss_alone, note: "even with today's scores (hindsight)" },
          { name: 'CVSS ≥ 9.0 alone', value: bt.missed_pct.cvss_alone, note: 'severity is not exploitation' },
          { name: 'Odyssey evidence rules', value: bt.missed_pct.our_evidence_rules, ours: true,
            note: `${bt.corroborated_without_kev}/${bt.kev_entries} also flagged by channels other than KEV` },
        ]} />
        <p className="mt-4 text-xs text-mute">
          Honest reading: KEV listing is itself one of our rules, so 0% is by construction. The meaningful figure is that{' '}
          {bt.corroborated_without_kev} of {bt.kev_entries} were also caught by CISA SSVC ({bt.channels.cisa_ssvc_active}) or
          vendor "exploited in the wild" text ({bt.channels.vendor_itw_claim}). {bt.channels.note}
        </p>
        <div className="mt-3 flex flex-wrap gap-1 text-xs">
          <span className="text-mute">Exploited, yet EPSS below 0.01:</span>
          {bt.examples_low_epss.map((x: any) => <Badge key={x.cve}>{x.cve} · EPSS {x.epss}</Badge>)}
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-2">
        <section className="rounded-2xl border border-line bg-panel p-6">
          <h3 className="mb-1 text-lg font-semibold">Reading advisories: product extraction</h3>
          <p className="mb-4 text-sm text-mute">All 2026 CISA-KEV CVEs, strict match to KEV's own vendor/product names. 95% intervals.</p>
          <Table head={['Model', 'Vendor', 'Product', 's/item']}
                 rows={ext.map((r) => [r.model, `${r.vendor_pct}% [${r.vendor_ci95.join('–')}]`, `${r.product_pct}%`, r.median_s])} />
          <p className="mt-3 text-xs text-mute">
            Statistically tied, and most misses are naming granularity ("SMA1000" vs "SMA1000 Appliances"), so Odyssey decides
            product identity by closed-set matching to the inventory, never free text.
          </p>
        </section>
        <section className="rounded-2xl border border-line bg-panel p-6">
          <h3 className="mb-1 text-lg font-semibold">Root cause (CWE) & severity (CVSS)</h3>
          <p className="mb-4 text-sm text-mute">40 CVEs from 2026, newer than every model's training data.</p>
          <Table head={['Model', 'CWE top-1', 'CVSS error', 'Type']} rows={ctiRows} />
          <p className="mt-3 text-xs text-mute">
            Result-driven design: classic ML handles structured labels, the security LLM explains. Each job goes to whatever measured best.
          </p>
        </section>
      </div>

      <section className="rounded-2xl border border-line bg-panel p-6">
        <h3 className="mb-3 text-lg font-semibold">Exposure precision</h3>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Tile value={d.exposure.cleared_by_version_evidence.toLocaleString('en-IN')} label="asset × CVE pairs cleared by version evidence" sub="patched or unaffected branches are not alerted" />
          <Tile value={d.exposure.disputed_flagged_for_analyst.toLocaleString('en-IN')} label="disputed: sources disagree" sub="flagged for an analyst; treated as exposed, never silently cleared" />
          <Tile value="0" label="false 'affected' on the real Ivanti case" sub={d.exposure.unit_tests} />
        </div>
      </section>

      {d.models.indic22 && <IndicGrid r={d.models.indic22} />}
    </div>
  )
}
