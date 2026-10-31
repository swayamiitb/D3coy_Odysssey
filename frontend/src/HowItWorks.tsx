import { ArrowRight, Bot, Building2, UserCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type AlertDetail, type ForecastView, type IntelSource, type Soc } from './api'
import { Badge, TierPill } from './ui'

/* eslint-disable @typescript-eslint/no-explicit-any */
const fmt = (n: number | null | undefined) => (n == null ? '—' : n.toLocaleString('en-IN'))

function Stage({ n, title, body, stat }: { n: number; title: string; body: string[]; stat?: string }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col rounded-xl border border-line bg-panel p-3">
      <div className="mb-1 flex items-center gap-2">
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-action text-xs font-semibold text-ink">{n}</span>
        <span className="font-semibold">{title}</span>
      </div>
      <ul className="flex-1 space-y-0.5 text-xs text-mute">{body.map((b) => <li key={b}>· {b}</li>)}</ul>
      {stat && <div className="mt-2 rounded bg-panel-2 px-2 py-1 font-mono text-xs text-accent">{stat}</div>}
    </div>
  )
}

function Factor({ k, name, value, feeds }: { k: string; name: string; value?: number; feeds: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel-2/50 p-3">
      <div className="flex items-baseline justify-between">
        <span className="font-mono text-lg text-accent">{k}</span>
        {value != null && <span className="font-mono text-lg">{value}</span>}
      </div>
      <div className="text-sm font-medium">{name}</div>
      <div className="mt-1 text-xs text-mute">{feeds}</div>
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
    ['Explain each warning, read advisories, answer analysts', 'MiST 8B (cybersecurity-tuned LLM)', 'LLM · Ollama', 'GPU',
      `${card ? `${card.briefs.validated}/${card.briefs.total} briefs pass the fact validator` : ''}${mist ? ` · vendor extraction ${mist.vendor_pct}%` : ''}`],
    ['Deep reasoning on critical alerts (batch)', 'Foundation-Sec-8B-Reasoning', 'security LLM', 'GPU', 'free-text analysis, never on the critical path'],
    ['Find products, versions, indicators in advisory text', 'SecureBERT 2.0 NER + IOC rules', 'security encoder', 'CPU', 'defanged IOCs, version vs IP disambiguation'],
    ['Relate threats to each other', 'SecureBERT 2.0 bi-encoder', 'embeddings', 'CPU', 'nearest threats + campaigns per product'],
    ['Root cause (CWE) and severity (CVSS) when missing', 'TF-IDF + linear models', 'classic ML', 'CPU', clf ? `CWE top-1 ${clf.rcm_acc_pct}% · CVSS error ${clf.vsp_mad}` : ''],
    ['Will a new CVE be exploited? (day 0)', 'TF-IDF + leak-free history → logistic regression', 'classic ML', 'CPU',
      live ? `catches ${live.odyssey.recall_pct}% of later-exploited CVEs flagging ${live.odyssey.flag_rate_pct}%` : ''],
    ['Is this asset compromised?', 'Bayesian decision model', 'probabilistic', 'CPU', 'every factor shown as a likelihood ratio'],
    ['Detect scanning surges and C2 beacons', 'robust z-score · periodicity/jitter', 'statistics', 'CPU', 'negative controls pass (test bench)'],
    ['Block instructions hidden in advisories', 'DeBERTa-v3 injection classifier + rules', 'encoder', 'CPU', 'hostile 5/5 caught · benign 0/5 blocked'],
    ['Warnings in 22 Indian languages', 'IndicTrans2 (AI4Bharat) + validator', 'seq2seq', 'CPU', indic ? `${indic.validated}/${indic.total} sentences validated` : ''],
  ]

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-5 overflow-auto [&>*]:shrink-0">

      <section>
        <div className="mb-2 text-xs uppercase tracking-wider text-mute">1 · The pipeline</div>
        <div className="flex flex-col gap-2 xl:flex-row xl:items-stretch">
          {[
            { title: 'Aggregate', body: ['vulnerability databases (NVD, KEV, EPSS, SSVC)', 'public advisories (CISA, CERT-In style)', 'attack telemetry (DShield, decoy grid)', 'indicators (Feodo C2, phishing)', 'security logs (SIM)'], stat: `${src.length} sources · ${real} real` },
            { title: 'Analyse (AI)', body: ['extract products, versions, IOCs', 'classify root cause and severity', 'forecast exploitation on day 0', 'relate threats into campaigns', 'guard against injected instructions'], stat: fc ? `${fmt(fc.flagged)} likely-exploited flagged` : undefined },
            { title: 'Correlate', body: ['match every CVE to the asset inventory', 'reconcile 3 exposure sources per version', 'chain CVEs on the same asset', 'join telemetry: surges, exploits, beacons'], stat: card ? `${fmt(card.funnel.cves_this_month)} CVEs → ${fmt(card.funnel.candidates)} relevant` : undefined },
            { title: 'Prioritise', body: ['exploitability × impact × evidence', 'asset criticality, exposure, blast radius', 'SSVC decision → tier and deadline', 'Bayesian compromise decision'], stat: soc ? `${fmt(soc.tiers.Critical)} Critical · ${fmt(soc.tiers.Compromise)} compromise` : undefined },
            { title: 'Warn', body: ['immediate notices in the state\'s language', 'daily digests, go-live baseline', 'predictions & escalations need approval', 'CERT-In report drafted on compromise'], stat: soc ? `${fmt(soc.autopilot.by_mode?.auto)} automatic · ${fmt(soc.pending)} awaiting you` : undefined },
            { title: 'Act', body: ['patch to a named fixed release', 'block indicators, restrict interfaces', 'investigate with a hunt playbook', 'risk plan: fewest changes, most risk removed'], stat: soc ? `${soc.risk.for_80_pct} changes remove 80% of risk` : undefined },
          ].map((s, i, arr) => (
            <div key={s.title} className="flex min-w-0 flex-1 items-stretch gap-2">
              <Stage n={i + 1} {...s} />
              {i < arr.length - 1 && <ArrowRight className="hidden shrink-0 self-center text-mute xl:block" size={18} />}
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-line bg-panel p-6">
        <div className="mb-3 text-xs uppercase tracking-wider text-mute">2 · The AI models (each job goes to what measured best)</div>
        <table className="w-full text-sm">
          <thead className="text-left text-xs text-mute">
            <tr><th className="pb-2 font-normal">Job</th><th className="pb-2 font-normal">Model</th><th className="pb-2 font-normal">Type</th><th className="pb-2 font-normal">Runs on</th><th className="pb-2 font-normal">Measured here</th></tr>
          </thead>
          <tbody>
            {models.map(([job, model, kind, where, measured]) => (
              <tr key={job} className="border-t border-line/60">
                <td className="py-2 pr-3">{job}</td>
                <td className="py-2 pr-3 font-medium">{model}</td>
                <td className="py-2 pr-3 text-mute">{kind}</td>
                <td className="py-2 pr-3"><Badge tone={where === 'GPU' ? 'accent' : 'mute'}>{where}</Badge></td>
                <td className="py-2 text-xs text-mute">{measured}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-xs text-mute">
          Guardrails: the deterministic engine is the source of truth for scores, tiers and deadlines; language models only explain, and every
          sentence they write is checked against numbered facts (unverifiable text is withheld, never shown). No cloud calls; no fallbacks to other models.
        </p>
      </section>

      <section className="rounded-2xl border border-line bg-panel p-6">
        <div className="mb-1 text-xs uppercase tracking-wider text-mute">3 · Threat scoring (glass box)</div>
        <div className="mb-4 font-mono text-lg">Risk = 100 × R × K × (0.55·L + 0.30·S + 0.15·V)</div>
        <div className="grid grid-cols-2 gap-3 xl:grid-cols-5">
          <Factor k="L" name="Exploitability" value={a?.L} feeds="CISA KEV, SSVC 'active', exploits on decoys, vendor 'exploited in the wild', EPSS, day-0 forecast. Named rules set evidence floors." />
          <Factor k="S" name="Potential impact" value={a?.S} feeds="SSVC technical impact or CVSS impact; floor for OT / safety systems." />
          <Factor k="V" name="Evidence (confidence)" value={a?.V} feeds="Noisy-OR over independent origins, each weighted by its Admiralty reliability grade." />
          <Factor k="K" name="Asset criticality" value={a?.K} feeds="Asset tier (CII floor), internet/DMZ exposure, blast radius to tier-1 systems." />
          <Factor k="R" name="Relevance (exposure)" value={a?.R} feeds="Is the installed version affected? NVD, CNA and advisory text vote; disputes are flagged." />
        </div>
        {a && ex && (
          <div className="mt-4 rounded-xl bg-panel-2 p-4 text-sm">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="text-mute">Worked example, live:</span><TierPill tier={a.tier} />
              <span className="font-mono text-accent">{ex.vulnerability.id}</span><span className="text-mute">on {a.hostname} ({ex.org.name})</span>
            </div>
            <div className="font-mono text-xs leading-relaxed">
              100 × {a.R} × {a.K} × (0.55×{a.L} + 0.30×{a.S} + 0.15×{a.V}) = <b className="text-text">{a.risk}</b>
            </div>
            <div className="mt-2 text-xs text-mute">
              The tier comes from the decision path, not the number: {a.decision_path.join(' → ')}. Deadline {a.deadline_hours} h ({a.deadline_basis}).
              {a.bayes && (a.tier === 'Compromise'
                ? <> The Bayesian model puts P(compromise) at {(a.bayes.p_compromise * 100).toFixed(1)}%, which turns the tier into Compromise and starts CERT-In's 6-hour clock.</>
                : <> The Bayesian model puts P(compromise) at {(a.bayes.p_compromise * 100).toFixed(2)}%: at 20% Odyssey would order a threat hunt, at 50% it would declare a suspected compromise and start CERT-In's 6-hour clock (as it did for the Ivanti VPN at Vidyut Grid, 98.7%).</>)}
            </div>
          </div>
        )}
      </section>

      <section className="rounded-2xl border border-line bg-panel p-6">
        <div className="mb-3 text-xs uppercase tracking-wider text-mute">4 · Mitigation workflow (who does what)</div>
        <div className="grid gap-4 xl:grid-cols-3">
          {[
            { icon: Bot, who: 'Odyssey, on its own', tone: 'text-accent', steps: ['scores every new CVE, advisory and telemetry signal against the inventory', 'sends Critical/Compromise notices at once, in the organisation\'s language', 'folds High warnings and new KEV listings into a daily digest', 'drafts the CERT-In incident report on suspected compromise', 'hunts the same C2 across every organisation; warns exposed peers', 'watches deadlines and proposes escalation when they slip'] },
            { icon: UserCheck, who: 'Analyst decides', tone: 'text-high', steps: ['approves or rejects predictions (day-0 forecast advisories)', 'approves sensor-only early warnings (decoy-grid surges)', 'approves reports to CERT-In, sector CSIRTs and NCIIPC', 'marks false positives, which feeds detector calibration', 'asks the copilot; every answer cites its facts'] },
            { icon: Building2, who: 'Organisation acts', tone: 'text-ok', steps: ['acknowledges the warning (the clock is visible)', 'patches in risk-plan order: named fixed release, owner, deadline', 'or applies the compensating control while patching', 'verifies, then closes; reopening is one click', 'everything is in the hash-chained audit trail'] },
          ].map(({ icon: Icon, who, tone, steps }) => (
            <div key={who} className="rounded-xl border border-line bg-panel-2/40 p-4">
              <div className={`mb-2 flex items-center gap-2 font-semibold ${tone}`}><Icon size={16} /> {who}</div>
              <ol className="space-y-1 text-xs text-mute">{steps.map((s, i) => <li key={s}><span className="mr-1 font-mono text-text">{i + 1}.</span>{s}</li>)}</ol>
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-mute">Journey of every warning:</span>
          {['Issued', 'Acknowledged', 'Mitigating', 'Verifying', 'Closed'].map((s, i, arr) => (
            <span key={s} className="flex items-center gap-2"><Badge tone={i === arr.length - 1 ? 'ok' : 'mute'}>{s}</Badge>{i < arr.length - 1 && <ArrowRight size={12} className="text-mute" />}</span>
          ))}
          <span className="ml-2 text-mute">Deadlines (CERT-In Blueprint, indicative): compromise report 6 h · known-exploited on internet/crown-jewel 12 h · critical external 24 h · critical internal 72 h · high 5 d · medium 14 d.</span>
        </div>
      </section>
    </div>
  )
}
