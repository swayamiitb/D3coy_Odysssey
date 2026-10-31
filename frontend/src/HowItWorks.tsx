import { ArrowRight, Bot, Building2, UserCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type AlertDetail, type ForecastView, type IntelSource, type Soc } from './api'
import { Badge, Section, TierPill } from './ui'

/* eslint-disable @typescript-eslint/no-explicit-any */
const fmt = (n: number | null | undefined) => (n == null ? '—' : n.toLocaleString('en-IN'))

/** One step of the pipeline, Uber-card style: number, name, one line, one measured figure. */
function Stage({ n, title, line, stat, unit }: { n: number; title: string; line: string; stat?: string; unit?: string }) {
  return (
    <div className="flex flex-col justify-between rounded-2xl bg-panel-2 p-6">
      <div>
        <div className="flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-full bg-action text-sm font-bold text-ink">{n}</span>
          <span className="text-xl font-bold">{title}</span>
        </div>
        <p className="mt-3 text-mute">{line}</p>
      </div>
      <div className="mt-5"><span className="text-3xl font-bold tabular-nums">{stat ?? '—'}</span> <span className="text-mute">{unit}</span></div>
    </div>
  )
}

function Factor({ k, name, value, feeds }: { k: string; name: string; value?: number; feeds: string }) {
  return (
    <div className="rounded-2xl bg-panel-2 p-5" title={feeds}>
      <div className="flex items-baseline justify-between">
        <span className="font-mono text-2xl font-bold">{k}</span>
        {value != null && <span className="font-mono text-2xl">{value}</span>}
      </div>
      <div className="mt-1 font-semibold">{name}</div>
      <div className="mt-1 text-sm text-mute">{feeds}</div>
    </div>
  )
}

export function HowItWorks() {
  const [ex, setEx] = useState<AlertDetail>()
  const [card, setCard] = useState<any>()
  const [fc, setFc] = useState<ForecastView>()
  const [src, setSrc] = useState<IntelSource[]>([])
  const [soc, setSoc] = useState<Soc>()
  useEffect(() => {
    // a live High-tier warning whose factors are not all 1, so the arithmetic is visible
    api.alerts({ tier: 'High' }).then((rows) => {
      const r = rows.find((x) => x.risk >= 45 && x.risk <= 85) ?? rows[0]
      if (r) api.alert(r.org_id, r.cve_id).then(setEx).catch(() => undefined)
    }).catch(() => undefined)
    fetch('/api/scorecard').then((r) => r.json()).then(setCard).catch(() => undefined)
    api.forecast().then(setFc).catch(() => undefined)
    api.intelSources().then(setSrc).catch(() => undefined)
    api.soc().then(setSoc).catch(() => undefined)
  }, [])
  const a = ex?.assets[0]
  const real = src.filter((s) => s.provenance === 'REAL').length
  const mist = (card?.models?.extraction_kev2026 ?? []).find((r: any) => r.model?.startsWith('mist'))
  const clf = card?.models?.text_classifiers
  const indic = card?.models?.indic22
  const live = fc?.model.live

  const models: [string, string, string, string, string][] = [
    ['Explain each warning and read advisories', 'MiST 8B (cybersecurity-tuned LLM)', 'LLM · Ollama', 'GPU',
      `${card ? `${card.briefs.validated}/${card.briefs.total} briefs pass the fact validator` : ''}${mist ? ` · vendor extraction ${mist.vendor_pct}%` : ''}`],
    ['Deep reasoning on critical alerts (batch)', 'Foundation-Sec-8B-Reasoning', 'security LLM', 'GPU', 'free-text analysis, never on the critical path'],
    ['Find products, versions, indicators in advisory text', 'SecureBERT 2.0 NER + IOC rules', 'security encoder', 'CPU', 'defanged IOCs, version vs IP disambiguation'],
    ['Relate threats to each other', 'SecureBERT 2.0 bi-encoder', 'embeddings', 'CPU', 'nearest threats + campaigns per product'],
    ['Root cause (CWE) and severity (CVSS) when missing', 'TF-IDF + linear models', 'classic ML', 'CPU', clf ? `CWE top-1 ${clf.rcm_acc_pct}% · CVSS error ${clf.vsp_mad}` : ''],
    ['Will a new CVE be exploited? (day 0)', 'TF-IDF + leak-free history → logistic regression', 'classic ML', 'CPU',
      live ? `catches ${live.odyssey.recall_pct}% of later-exploited CVEs flagging ${live.odyssey.flag_rate_pct}%` : ''],
    ['Is this asset compromised?', 'Bayesian decision model', 'probabilistic', 'CPU', 'every factor shown as a likelihood ratio'],
    ['Detect scanning surges and C2 beacons', 'robust z-score · periodicity/jitter', 'statistics', 'CPU', 'negative controls pass (test bench)'],
    ['Spot unusual host traffic (lateral movement)', 'IsolationForest + robust-z gate', 'classic ML', 'CPU', '0 alerts in 240 quiet sensor-hours; drill caught (test bench)'],
    ['Block instructions hidden in advisories', 'DeBERTa-v3 injection classifier + rules', 'encoder', 'CPU', 'hostile 5/5 caught · benign 0/5 blocked'],
    ['Warnings in 22 Indian languages', 'IndicTrans2 (AI4Bharat) + validator', 'seq2seq', 'CPU', indic ? `${indic.validated}/${indic.total} sentences validated` : ''],
  ]

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-16">
      <Section title="From signal to action, in six steps" sub="Every step runs on this laptop; each figure is from the current build.">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Stage n={1} title="Aggregate" line="Vulnerability databases, public advisories, real attack telemetry, threat indicators and security logs." stat={`${src.length}`} unit={`sources, ${real} real public feeds`} />
          <Stage n={2} title="Analyse" line="Security models read every CVE and advisory, and forecast exploitation on the day a CVE is published." stat={fc ? fmt(fc.flagged) : undefined} unit="new CVEs flagged likely to be exploited" />
          <Stage n={3} title="Correlate" line="Every CVE is matched to the versions actually installed, and joined with attack and sensor telemetry." stat={card ? fmt(card.funnel.cves_this_month) : undefined} unit={card ? `CVEs this month → ${fmt(card.funnel.candidates)} relevant` : ''} />
          <Stage n={4} title="Prioritise" line="Exploitability, impact, evidence, asset criticality and relevance; an SSVC decision sets the tier and deadline." stat={soc ? fmt(soc.tiers.Critical) : undefined} unit={soc ? `Critical · ${fmt(soc.tiers.Compromise)} suspected compromise` : ''} />
          <Stage n={5} title="Warn" line="Notices go out in each organisation's language; predictions and escalations wait for a person." stat={soc ? fmt(soc.autopilot.by_mode?.auto) : undefined} unit={soc ? `automatic actions · ${fmt(soc.pending)} awaiting you` : ''} />
          <Stage n={6} title="Act" line="Patch to a named fixed release, block indicators, and follow the risk plan: fewest changes, most risk removed." stat={soc ? fmt(soc.risk.for_80_pct) : undefined} unit="changes remove 80% of the risk" />
        </div>
      </Section>

      <Section title="The AI models" sub="Each job goes to the model that measured best on 2026 data. Language models only explain; the deterministic engine decides scores, tiers and deadlines.">
        <table className="w-full">
          <thead className="text-left text-sm text-mute">
            <tr><th className="pb-3 font-normal">Job</th><th className="pb-3 font-normal">Model</th><th className="pb-3 font-normal">Runs on</th><th className="pb-3 font-normal">Measured here</th></tr>
          </thead>
          <tbody>
            {models.map(([job, model, , where, measured]) => (
              <tr key={job} className="border-t border-line">
                <td className="py-3 pr-4">{job}</td>
                <td className="py-3 pr-4 font-semibold">{model}</td>
                <td className="py-3 pr-4"><span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${where === 'GPU' ? 'bg-action text-ink' : 'bg-panel-2'}`}>{where}</span></td>
                <td className="py-3 text-sm text-mute">{measured}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-4 text-sm text-mute">
          Every sentence a language model writes is checked against numbered facts; unverifiable text is withheld, never shown. No cloud calls, no fallbacks to other models.
        </p>
      </Section>

      <Section title="Threat scoring, in the open" sub="One formula for every warning; hover a factor for what feeds it.">
        <div className="mb-6 rounded-2xl bg-band px-6 py-5 font-mono text-2xl text-white">Risk = 100 × R × K × (0.55·L + 0.30·S + 0.15·V)</div>
        <div className="grid grid-cols-2 gap-3 xl:grid-cols-5">
          <Factor k="L" name="Exploitability" value={a?.L} feeds="CISA KEV, SSVC, decoy exploits, vendor claims, EPSS, day-0 forecast." />
          <Factor k="S" name="Potential impact" value={a?.S} feeds="SSVC technical impact or CVSS impact; floor for OT and safety systems." />
          <Factor k="V" name="Evidence" value={a?.V} feeds="Independent sources combined, each weighted by its reliability grade." />
          <Factor k="K" name="Asset criticality" value={a?.K} feeds="Asset tier, internet or DMZ exposure, blast radius to crown jewels." />
          <Factor k="R" name="Relevance" value={a?.R} feeds="Is the installed version affected? NVD, the CNA and advisory text vote." />
        </div>
        {a && ex && (
          <div className="mt-6 rounded-2xl border border-line p-5">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="text-mute">Worked example, live:</span><TierPill tier={a.tier} />
              <span className="font-mono">{ex.vulnerability.id}</span><span className="text-mute">on {a.hostname} ({ex.org.name})</span>
            </div>
            <div className="font-mono">
              100 × {a.R} × {a.K} × (0.55×{a.L} + 0.30×{a.S} + 0.15×{a.V}) = <b className="text-text">{a.risk}</b>
            </div>
            <p className="mt-2 text-sm text-mute">
              The tier comes from the decision path, not the number: {a.decision_path.join(' → ')}. Deadline {a.deadline_hours} h ({a.deadline_basis}).
              {a.bayes && (a.tier === 'Compromise'
                ? <> P(compromise) is {(a.bayes.p_compromise * 100).toFixed(1)}%, which makes it a Compromise and starts CERT-In's 6-hour clock.</>
                : <> P(compromise) is {(a.bayes.p_compromise * 100).toFixed(2)}%: at 20% Odyssey orders a threat hunt, at 50% it declares a suspected compromise and starts CERT-In's 6-hour clock.</>)}
            </p>
          </div>
        )}
      </Section>

      <Section title="Who does what" sub="Graduated autonomy: Odyssey acts on evidence, a person decides on predictions and escalations, the organisation fixes.">
        <div className="grid gap-4 xl:grid-cols-3">
          {[
            { icon: Bot, who: 'Odyssey, on its own', steps: ['scores every new CVE, advisory and signal against the inventory', 'sends Critical notices at once, in the organisation\'s language', 'drafts the CERT-In report on a suspected compromise', 'hunts the same C2 across every organisation'] },
            { icon: UserCheck, who: 'An analyst decides', steps: ['approves or rejects predictions and sensor-only warnings', 'approves reports to CERT-In, sector CSIRTs and NCIIPC', 'works SOC cases with their playbooks and SLAs', 'marks false positives, which recalibrates the detectors'] },
            { icon: Building2, who: 'The organisation acts', steps: ['acknowledges the warning; the clock is visible', 'patches in risk-plan order: named release, owner, deadline', 'or applies the compensating control while patching', 'verifies, then closes; all of it is in the audit trail'] },
          ].map(({ icon: Icon, who, steps }) => (
            <div key={who} className="rounded-2xl bg-panel-2 p-6">
              <div className="mb-3 flex items-center gap-2 text-xl font-bold"><Icon size={20} /> {who}</div>
              <ol className="space-y-2 text-mute">{steps.map((st, i) => <li key={st} className="flex gap-2"><span className="font-semibold text-text">{i + 1}</span>{st}</li>)}</ol>
            </div>
          ))}
        </div>
        <div className="mt-6 flex flex-wrap items-center gap-2 text-sm">
          <span className="text-mute">Every warning:</span>
          {['Issued', 'Acknowledged', 'Mitigating', 'Verifying', 'Closed'].map((st, i, arr) => (
            <span key={st} className="flex items-center gap-2"><Badge tone={i === arr.length - 1 ? 'ok' : 'mute'}>{st}</Badge>{i < arr.length - 1 && <ArrowRight size={14} className="text-mute" />}</span>
          ))}
        </div>
        <p className="mt-3 text-sm text-mute">Deadlines follow the CERT-In Blueprint (indicative): compromise report 6 h · known-exploited on internet or crown-jewel assets 12 h · critical external 24 h · critical internal 72 h · high 5 d · medium 14 d.</p>
      </Section>
    </div>
  )
}
