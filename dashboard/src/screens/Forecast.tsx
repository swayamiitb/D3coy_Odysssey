import { useState } from 'react'
import { api, useLoad } from '../data'
import { date, num, pct } from '../format'
import type { ForecastEval, ForecastItem, Lead, LeadStats } from '../types'
import { Bars, Empty, ErrorLine, Kpis, Mark, Panel, Provenance, ShowAll } from '../ui'

const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`
const daysBetween = (a: string, b: string) => Math.round((Date.parse(b) - Date.parse(a)) / 86400_000)

function Items({ items, base, names }: { items: ForecastItem[]; base: number | null; names: Record<string, string> }) {
  const [all, setAll] = useState(false)
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1080px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">CVE</th>
              <th className="pb-2 font-normal">Published</th>
              <th className="pb-2 text-right font-normal" title="Model probability that the CVE will be exploited">Probability</th>
              <th className="pb-2 pl-6 font-normal">Why the model flags it</th>
              <th className="pb-2 text-right font-normal" title="Median days from publication to exploitation for comparable CVEs">Median days to exploit</th>
              <th className="pb-2 text-right font-normal">Exposed here</th>
              <th className="px-5 pb-2 font-normal">What happened next</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {(all ? items : items.slice(0, 8)).map((i) => (
              <tr key={i.cve}>
                <td className="px-5 py-2.5 align-top">
                  <span className="num block font-medium">{i.cve}</span>
                  <span className="block text-[13px] text-mute">{i.product ?? '—'}</span>
                </td>
                <td className="num py-2.5 align-top whitespace-nowrap text-mute">{date(i.published)}</td>
                <td className="py-2.5 pl-4 text-right align-top whitespace-nowrap">
                  <span className="num block">{pct(i.p * 100)}</span>
                  {base ? <span className="num block text-[12px] text-faint">{num(i.p / base)}× base rate</span> : null}
                </td>
                <td className="max-w-[320px] py-2.5 pl-6 align-top text-[13px] text-mute">{i.reasons.length ? i.reasons.slice(0, 3).join('; ') : '—'}</td>
                <td className="num py-2.5 text-right align-top">{i.median_days_to_exploit != null ? `${num(i.median_days_to_exploit)} d` : '—'}</td>
                <td className="py-2.5 text-right align-top" title={i.org_ids.map((o) => names[o] ?? o).join(', ')}>
                  <span className="num block">{plural(i.orgs, 'org')}</span>
                  <span className="num block text-[13px] text-mute">{plural(i.assets, 'asset')}</span>
                </td>
                <td className="px-5 py-2.5 align-top">
                  {i.kev_added ? (
                    <>
                      <Mark color="var(--color-critical)">Confirmed by CISA on {date(i.kev_added)}</Mark>
                      <span className="block pl-4 text-[13px] text-mute">{(() => { const d = daysBetween(i.published, i.kev_added!); return d > 0 ? `${plural(d, 'day')} after publication` : 'on the day of publication' })()}</span>
                    </>
                  ) : <span className="text-mute">Not exploited yet</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-baseline justify-between gap-2 px-5 pt-1">
        <p className="text-[13px] text-mute">Each flag is a proposal: an analyst approves every pre-emptive advisory before it goes out.</p>
        <ShowAll total={items.length} cap={8} open={all} onToggle={() => setAll((v) => !v)} />
      </div>
    </>
  )
}

/** Same alert budget, three policies: share of the later-exploited CVEs each caught. One hue; ours at full strength. */
function Evaluation({ e, test, features }: { e: ForecastEval; test: ForecastEval | null; features: string | null }) {
  const rows = [
    { name: 'Odyssey day-0 forecast', v: e.same_budget_recall_pct.odyssey, ours: true, note: 'only facts known on the day of publication' },
    { name: 'CVSS ≥ 9 ranking', v: e.same_budget_recall_pct.cvss, note: 'severity is not likelihood' },
    { name: 'EPSS today, in hindsight', v: e.same_budget_recall_pct.epss_today, note: 'scored months later, after exploitation was seen' },
  ]
  const p = e.odyssey.precision_pct
  return (
    <div className="space-y-4">
      <p className="text-[13px] text-mute">
        Frozen model, scored out of time on {e.period}: {num(e.cves)} new CVEs, {num(e.exploited)} later added to CISA KEV.
        Each method may flag the same {pct(e.odyssey.flag_rate_pct)} of new CVEs. Share of the exploited ones each caught:
      </p>
      <div className="space-y-2.5">
        {rows.map((r) => (
          <div key={r.name} className="grid grid-cols-[minmax(0,150px)_1fr_56px] items-center gap-3 sm:grid-cols-[190px_1fr_56px]">
            <span className={`text-[14px] ${r.ours ? 'font-medium' : 'text-mute'}`}>{r.name}<span className="block text-[12px] font-normal text-faint">{r.note}</span></span>
            <span className="h-2 rounded-full bg-raised"><span className={`block h-2 rounded-full ${r.ours ? 'bg-text' : 'bg-text/40'}`} style={{ width: `${Math.min(100, r.v ?? 0)}%` }} /></span>
            <span className="num text-right">{pct(r.v)}</span>
          </div>
        ))}
      </div>
      <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[14px]">
        <dt className="text-mute">Precision</dt>
        <dd><span className="num">{pct(p)}</span> <span className="text-mute">· about 1 in {p ? num(100 / p) : '—'} flagged CVEs is later exploited</span></dd>
        <dt className="text-mute">Base rate</dt>
        <dd><span className="num">{pct(e.base_rate_pct, 2)}</span> <span className="text-mute">· exploitation is rare, so precision stays low</span></dd>
        {test && <><dt className="text-mute">Earlier test</dt><dd className="text-mute">{test.period}: <span className="num text-text">{pct(test.odyssey.recall_pct)}</span> caught at <span className="num">{pct(test.odyssey.flag_rate_pct)}</span> flagged</dd></>}
        <dt className="text-mute">ROC AUC</dt>
        <dd className="num">{num(e.roc_auc, 2)}{test ? ` · ${num(test.roc_auc, 2)} on ${test.period}` : ''}</dd>
      </dl>
      <p className="text-[14px]">Because precision is low, a forecast is a <span className="font-medium">proposal for a human</span>. An analyst approves or rejects it; none is sent on its own.</p>
      {features && <p className="text-[12px] text-faint">Features: {features}.</p>}
    </div>
  )
}

function LeadBlock({ title, s, note }: { title: string; s: LeadStats; note: string }) {
  return (
    <div className="rounded-md bg-raised/60 px-4 py-3">
      <div className="text-[13px] text-mute">{title}</div>
      <div className="num mt-1 text-[26px] font-semibold leading-8 tracking-tight">{s.median_lead_days != null ? `${num(s.median_lead_days, 1)} d` : '—'}</div>
      <div className="text-[13px] text-mute">median · up to <span className="num text-text">{s.max_lead_days != null ? `${num(s.max_lead_days, 1)} d` : '—'}</span> · {plural(s.acted_before_kev, 'CVE')}</div>
      <div className="mt-0.5 text-[12px] text-faint">{note}</div>
    </div>
  )
}

function LeadView({ lead }: { lead: Lead }) {
  const [all, setAll] = useState(false)
  const rows = [...lead.rows].sort((a, b) => (b.lead_days ?? -1) - (a.lead_days ?? -1))
  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-2">
        <LeadBlock title="Real signals only" s={lead.real_signals_only} note="CISA SSVC, vendor text, the day-0 forecast" />
        <LeadBlock title="All signals" s={lead} note="adds the decoy grid, which is Simulated" />
      </div>
      <p className="text-[13px] text-mute">
        Since go-live CISA added {plural(lead.kev_after_go_live, 'CVE')} that hit exposed assets here: Odyssey acted on {num(lead.acted_before_kev)} a day or more
        before the listing, {num(lead.acted_same_day)} on the same day, and {num(lead.not_acted)} not before the listing.
      </p>
      {rows.length === 0 ? <Empty>No CVE rows in this data.</Empty> : (
        <>
          <div className="-mx-5 overflow-x-auto">
            <table className="w-full min-w-[480px] text-[14px]">
              <thead>
                <tr className="text-left text-[12px] text-faint">
                  <th className="px-5 pb-2 font-normal">CVE</th>
                  <th className="pb-2 font-normal">First action, on the basis of</th>
                  <th className="px-5 pb-2 text-right font-normal">Lead over KEV</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {(all ? rows : rows.slice(0, 6)).map((r) => (
                  <tr key={r.cve}>
                    <td className="num px-5 py-2.5 align-top whitespace-nowrap">{r.cve}<span className="block text-[12px] text-faint">on KEV {date(r.kev)}</span></td>
                    <td className="py-2.5 pr-3 align-top text-[13px]">
                      {r.first_action ? <><span className="num">{date(r.first_action)}</span> <span className="text-mute">· {r.basis ?? '—'}</span></> : <span className="text-faint">No action before the listing</span>}
                      {r.provenance && <span className="block"><Provenance p={r.provenance} /></span>}
                    </td>
                    <td className="num px-5 py-2.5 text-right align-top whitespace-nowrap">
                      {r.lead_days == null ? <span className="text-faint">Not acted</span> : r.lead_days >= 1 ? `${num(r.lead_days, 1)} d` : <span className="text-mute">Same day</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <ShowAll total={rows.length} cap={6} open={all} onToggle={() => setAll((v) => !v)} />
        </>
      )}
    </div>
  )
}

export function Forecast() {
  const f = useLoad(api.forecast, 'forecast')
  const soc = useLoad(api.soc, 'soc')
  const d = f.data
  const live = d?.model.live ?? null
  const base = live?.base_rate_pct ? live.base_rate_pct / 100 : null
  const lead = d?.lead ?? soc.data?.autopilot.lead ?? null
  const real = lead?.real_signals_only
  const names = Object.fromEntries((soc.data?.orgs ?? []).map((o) => [o.id, o.name]))

  return (
    <div className="space-y-4">
      <div className="pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">Ahead of the threat</h1>
        <p className="text-mute">New CVEs Odyssey expects to be exploited, flagged on the day they are published, before anyone exploits them.</p>
      </div>

      {f.error ? <Panel><ErrorLine message={f.error} onRetry={f.reload} /></Panel> : (
        <Kpis items={[
          { label: 'Flagged CVEs', value: d ? num(d.flagged) : '—', sub: d ? `on exposed assets, since ${date(d.since)}` : undefined },
          { label: 'Since confirmed by CISA', value: d ? num(d.since_exploited) : '—', sub: 'added to KEV after we flagged them' },
          { label: 'Caught on day 0', value: live ? pct(live.odyssey.recall_pct) : '—', answer: true, sub: live ? `of later-exploited CVEs, ${live.period}` : undefined },
          { label: 'Alert budget', value: live ? pct(live.odyssey.flag_rate_pct) : '—', sub: 'of new CVEs flagged' },
          { label: 'Precision', value: live ? pct(live.odyssey.precision_pct) : '—', sub: live ? `base rate ${pct(live.base_rate_pct, 2)}` : undefined },
          { label: 'Ahead of CISA KEV', value: real?.median_lead_days != null ? `${num(real.median_lead_days, 1)} d` : '—', sub: real ? `median, real signals only, ${plural(real.acted_before_kev, 'CVE')}` : 'real signals only' },
        ]} />
      )}

      <Panel title="Flagged CVEs, newest first" meta={d ? `${plural(d.flagged, 'CVE')} on exposed assets since ${date(d.since)}; ${num(d.since_exploited)} since confirmed exploited` : 'Recent CVEs the day-0 model flags'} pad={false}>
        {f.loading ? <div className="px-5"><Bars rows={6} /></div>
          : f.error ? <div className="px-5"><ErrorLine message={f.error} onRetry={f.reload} /></div>
          : (d?.items ?? []).length === 0 ? <div className="px-5"><Empty>Nothing flagged on exposed assets in this window.</Empty></div>
          : <Items items={d!.items} base={base} names={names} />}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="How good is the forecast" meta="Honest evaluation, real CVEs, out of time">
          {f.loading ? <Bars rows={5} />
            : f.error ? <ErrorLine message={f.error} onRetry={f.reload} />
            : !live ? <Empty>No evaluation was reported for this model.</Empty>
            : <Evaluation e={live} test={d?.model.test ?? null} features={d?.model.features ?? null} />}
        </Panel>
        <Panel title="Lead over CISA KEV" meta="Days between Odyssey’s first action on a CVE and its addition to CISA KEV">
          {f.loading && soc.loading ? <Bars rows={5} />
            : !lead ? (f.error ? <ErrorLine message={f.error} onRetry={f.reload} /> : <Empty>No lead measurement yet.</Empty>)
            : <LeadView lead={lead} />}
        </Panel>
      </div>
    </div>
  )
}
