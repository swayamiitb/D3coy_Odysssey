import { ArrowLeft, ExternalLink } from 'lucide-react'
import { useState } from 'react'
import { api, getAnalyst, getMode, snapshotFile, useLoad } from '../data'
import { ACTION_LABEL, dateTime, date, humanKind, num, STATE_LABEL, TIER_RANK } from '../format'
import type { AlertDetail, AssetAssessment, Workflow, WorkflowState } from '../types'
import { Bars, Button, Countdown, Empty, ErrorLine, Panel, Provenance, TierMark } from '../ui'

const STEPS: WorkflowState[] = ['new', 'acknowledged', 'mitigating', 'verifying', 'closed']
const VALID: Record<string, WorkflowState[]> = {
  acknowledge: ['new', 'reopened'], start: ['acknowledged', 'reopened'], verify: ['mitigating'], resolve: ['verifying', 'mitigating'],
  accept_risk: ['new', 'acknowledged', 'mitigating', 'verifying'], false_positive: ['new', 'acknowledged', 'mitigating', 'verifying'], reopen: ['closed'],
}
const CRIT = ['', 'Context', 'Corroborating', 'Strong', 'Confirmed']

function worst(d: AlertDetail): AssetAssessment | undefined {
  return [...d.assets].sort((a, b) => TIER_RANK[a.tier] - TIER_RANK[b.tier] || b.risk - a.risk)[0]
}

function Response({ org, cve, wf, onChange }: { org: string; cve: string; wf: Workflow; onChange: (w: Workflow) => void }) {
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const live = getMode() === 'live'
  const state = wf.state === 'reopened' ? 'acknowledged' : wf.state
  const idx = STEPS.indexOf(state)
  const actions = Object.keys(VALID).filter((a) => VALID[a].includes(wf.state))
  const primary = wf.next_action && actions.includes(wf.next_action) ? wf.next_action : null
  const run = async (a: string) => {
    setBusy(a); setErr(null)
    try { onChange(await api.act(org, cve, a, getAnalyst(), note || undefined)); setNote('') } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
    setBusy(null)
  }
  return (
    <Panel title="Response" meta={wf.outcome ? `Closed as ${wf.outcome.replace(/_/g, ' ')}` : `Owner: ${wf.owner ?? 'unassigned'}`}>
      <ol className="grid grid-cols-5 gap-1" aria-label="Workflow">
        {STEPS.map((s, i) => (
          <li key={s} className="min-w-0">
            <div className={`h-1 rounded-full ${i <= idx ? 'bg-text' : 'bg-raised'}`} />
            <div className={`mt-2 truncate text-[13px] ${i === idx ? 'font-medium text-text' : 'text-faint'}`}>{STATE_LABEL[s]}</div>
          </li>
        ))}
      </ol>
      <div className="mt-5 flex flex-wrap items-center gap-2">
        <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note for the audit trail (optional)" aria-label="Note"
          className="h-9 min-w-[220px] flex-1 rounded-md bg-raised px-3 text-[13px] outline-none placeholder:text-faint" />
        {primary && <Button variant="primary" disabled={!live || !!busy} onClick={() => run(primary)} title={live ? undefined : 'Read-only data: connect to the Odyssey backend to act'}>{ACTION_LABEL[primary]}</Button>}
        {actions.filter((a) => a !== primary).map((a) => (
          <Button key={a} disabled={!live || !!busy} onClick={() => run(a)} title={live ? undefined : 'Read-only data: connect to the Odyssey backend to act'}>{ACTION_LABEL[a]}</Button>
        ))}
      </div>
      {!live && <p className="mt-2 text-[12px] text-faint">Read-only data. Actions are recorded only when this console is connected to the Odyssey backend.</p>}
      {err && <p className="mt-2 text-[13px] text-compromise">{err}</p>}
      {(wf.history ?? []).length > 0 && (
        <ul className="mt-4 space-y-1.5 text-[13px]">
          {[...(wf.history ?? [])].reverse().map((h, i) => (
            <li key={i} className="flex gap-3">
              <span className="num w-28 shrink-0 text-faint">{dateTime(h.ts)}</span>
              <span className="text-mute"><span className="text-text">{h.payload.actor}</span> moved it from {STATE_LABEL[h.payload.from] ?? h.payload.from} to {STATE_LABEL[h.payload.to] ?? h.payload.to}{h.payload.note ? `: “${h.payload.note}”` : ''}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

function Why({ a }: { a: AssetAssessment }) {
  const parts = [
    { label: 'Likelihood', w: 0.55, v: a.L, pts: a.contributions.likelihood },
    { label: 'Severity', w: 0.3, v: a.S, pts: a.contributions.severity },
    { label: 'Evidence', w: 0.15, v: a.V, pts: a.contributions.evidence },
  ]
  const maxPts = Math.max(...parts.map((p) => p.pts), 1)
  return (
    <Panel title="Why this warning" meta="Fixed rules set the score; the AI only explains it">
      <p className="text-[13px] text-mute">Risk = 100 × relevance × importance × (55% likelihood + 30% severity + 15% evidence), capped at 100</p>
      <div className="mt-4 space-y-2.5">
        {parts.map((p) => (
          <div key={p.label} className="grid grid-cols-[150px_1fr_56px] items-center gap-3 text-[14px]">
            <span>{p.label} <span className="text-faint">· {Math.round(p.w * 100)}%</span></span>
            <span className="h-2 rounded-full bg-raised"><span className="block h-2 rounded-full bg-text" style={{ width: `${(p.pts / maxPts) * 100}%` }} /></span>
            <span className="num text-right">{num(p.v, 2)}</span>
          </div>
        ))}
        <div className="grid grid-cols-[150px_1fr_56px] gap-3 pt-1 text-[14px]">
          <span>Relevance <span className="text-faint">× </span></span><span className="text-[13px] text-mute">Is this exact version affected?</span><span className="num text-right">{num(a.R, 2)}</span>
          <span>Importance <span className="text-faint">× </span></span><span className="text-[13px] text-mute">Criticality, exposure, blast radius</span><span className="num text-right">{num(a.K, 2)}</span>
          <span className="font-semibold">Risk</span><span className="text-[13px] text-mute">{a.decision ? `SSVC decision: ${a.decision}` : ''}</span><span className="num text-right font-semibold">{num(a.risk)}</span>
        </div>
      </div>
      {a.rules.length > 0 && (
        <>
          <h3 className="mt-5 text-[13px] font-medium text-mute">Evidence that fired</h3>
          <ul className="mt-2 divide-y divide-line/70">
            {a.rules.map((r) => (
              <li key={r.id} className="grid grid-cols-[110px_1fr] gap-3 py-2 text-[14px]">
                <span className="text-mute">{CRIT[r.crit] ?? r.crit}</span>
                <span>{r.text}<span className="block text-[12px] text-faint">{r.source}{r.evidence ? ` · ${r.evidence}` : ''}</span></span>
              </li>
            ))}
          </ul>
        </>
      )}
      {a.exposure.votes.length > 0 && (
        <>
          <h3 className="mt-5 text-[13px] font-medium text-mute">Is version {a.version} affected? <span className="text-text">{a.exposure.status}</span></h3>
          <ul className="mt-2 space-y-1.5 text-[13px]">
            {a.exposure.votes.map((v, i) => (
              <li key={i} className="grid grid-cols-[110px_1fr] gap-3"><span className="text-mute">{v.source}</span><span>{v.verdict}: {v.reason}</span></li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  )
}

export function Incident({ org, cve }: { org: string; cve: string }) {
  const key = `${org}/${cve}`
  const detail = useLoad(() => api.alert(org, cve), `alert:${key}`)
  const replay = useLoad(() => api.replay(org, cve), `replay:${key}`)
  const brief = useLoad(() => api.brief(org, cve), `brief:${key}`)
  const wf = useLoad(() => api.workflow(org, cve), `wf:${key}`)
  const [wfLocal, setWfLocal] = useState<Workflow | null>(null)
  const workflow = wfLocal ?? wf.data
  const d = detail.data
  const a = d ? worst(d) : undefined
  const mode = getMode()
  const reportUrl = (u: string) => (mode === 'live' ? u : mode === 'snapshot' ? snapshotFile(u) : null)

  return (
    <div className="space-y-4">
      <a href="#/queue" className="inline-flex items-center gap-1.5 text-[13px] text-mute hover:text-text"><ArrowLeft size={14} /> Triage queue</a>

      {detail.loading ? <Panel><Bars rows={3} h={24} /></Panel>
        : detail.error || !d || !a ? <Panel><ErrorLine message={detail.error ?? 'no assessment'} onRetry={detail.reload} /></Panel>
        : (
          <div className="flex flex-wrap items-end justify-between gap-4 pb-1">
            <div className="min-w-0">
              <h1 className="text-[26px] font-semibold tracking-tight">{a.label} at {d.org.name}</h1>
              <p className="text-mute"><span className="num">{d.vulnerability.id}</span> · {d.org.sector} · {d.org.state}{d.vulnerability.kev ? ' · on CISA KEV' : ''}</p>
            </div>
            <div className="flex items-end gap-6">
              <div><div className="text-[13px] text-mute">Tier</div><div className="mt-1 text-[15px] font-medium"><TierMark tier={a.tier} /></div></div>
              <div><div className="text-[13px] text-mute">Risk</div><div className="num text-[30px] font-semibold leading-9">{num(a.risk)}</div></div>
              <div className="text-right"><div className="text-[13px] text-mute">Deadline</div>
                <div className="mt-1 text-[15px]">{workflow ? <Countdown issuedAt={workflow.issued_at} hours={a.deadline_hours} closed={workflow.state === 'closed'} /> : '—'}</div>
              </div>
            </div>
          </div>
        )}

      {a?.deadline_basis && <p className="-mt-2 text-[13px] text-faint">Deadline basis: {a.deadline_basis}</p>}

      {wf.error ? <Panel title="Response"><ErrorLine message={wf.error} onRetry={wf.reload} /></Panel>
        : workflow ? <Response org={org} cve={cve} wf={workflow} onChange={setWfLocal} /> : <Panel title="Response"><Bars rows={2} /></Panel>}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="space-y-4">
          <Panel title="Playbook" meta="Response steps for this warning, from fixed catalogues">
            {!d ? <Bars rows={4} /> : d.actions.length === 0 ? <Empty>No steps for this warning.</Empty> : (
              <ol className="divide-y divide-line/70">
                {d.actions.map((s, i) => (
                  <li key={i} className="grid grid-cols-[28px_1fr] gap-2 py-2.5">
                    <span className="num text-faint">{i + 1}</span>
                    <span>{s.step}<span className="block text-[12px] text-faint">{humanKind(s.type)} · {s.source}{s.due ? ` · due ${s.due}` : ''}</span></span>
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          <Panel title="Timeline" meta={replay.data?.lead_days_before_disclosure != null ? `First warned ${num(replay.data.lead_days_before_disclosure)} days before public disclosure` : 'How the risk changed as evidence arrived'}>
            {replay.loading ? <Bars rows={4} /> : replay.error ? <ErrorLine message={replay.error} onRetry={replay.reload} /> : (
              <ol className="relative space-y-4 border-l border-line pl-5">
                {replay.data!.steps.map((s, i) => (
                  <li key={i} className="relative">
                    <span className="absolute top-1.5 -left-[25px] size-2 rounded-full" style={{ background: `var(--color-${s.tier.toLowerCase()})` }} aria-hidden />
                    <div className="flex flex-wrap items-baseline gap-x-3 text-[13px]">
                      <span className="num text-mute">{dateTime(s.ts)}</span><Provenance p={s.provenance} />
                    </div>
                    <div className="mt-0.5">{s.event}</div>
                    <div className="text-[13px] text-mute">{s.tier} · risk <span className="num">{num(s.risk)}</span>{s.decision ? ` · ${s.decision}` : ''}{s.deadline_basis ? ` · ${s.deadline_basis}` : ''}</div>
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          {a ? <Why a={a} /> : null}

          <Panel title="AI brief" meta={brief.data ? `${brief.data.model} · ${brief.data.status === 'validated' ? 'passed the fact check' : 'withheld: failed the fact check'}` : 'AI-generated, fact-checked'}>
            {brief.loading ? <Bars rows={3} /> : brief.error ? <ErrorLine message={brief.error} onRetry={brief.reload} />
              : !brief.data?.brief ? <Empty>No brief: it was withheld because it failed the fact check. {brief.data?.problems.join('; ')}</Empty> : (
                <div className="space-y-3">
                  <p className="text-[15px] font-medium">{brief.data.brief.headline}</p>
                  {(['why_it_matters', 'what_to_do'] as const).map((k) => (
                    <div key={k}>
                      <h3 className="text-[13px] text-mute">{k === 'why_it_matters' ? 'Why it matters' : 'What to do'}</h3>
                      <ul className="mt-1 list-disc space-y-1 pl-5">
                        {brief.data!.brief![k].map((b, i) => <li key={i}>{b.text} <span className="text-[12px] text-faint">{b.cites.join(', ')}</span></li>)}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
          </Panel>
        </div>

        <div className="space-y-4">
          {a?.bayes && (
            <Panel title="Compromise check" meta="Bayesian model over exposure, exploitation and telemetry">
              <div className="flex items-baseline justify-between">
                <span className="num text-[30px] font-semibold" style={a.bayes.decision === 'compromised' ? { color: 'var(--color-compromise)' } : undefined}>{num(a.bayes.p_compromise * 100)}%</span>
                <span className="text-mute">{a.bayes.decision}</span>
              </div>
              <p className="text-[13px] text-faint">Chance this system is already breached · prior {num(a.bayes.prior * 100, 1)}%</p>
              <ul className="mt-3 space-y-1.5 text-[13px]">
                {a.bayes.factors.map((f, i) => <li key={i}><span className="text-text">{f.factor}</span> <span className="text-faint">· {f.detail}</span></li>)}
              </ul>
            </Panel>
          )}

          <Panel title="Affected assets" pad={false}>
            {!d ? <div className="px-5"><Bars rows={2} /></div> : (
              <ul className="divide-y divide-line/70">
                {d.assets.map((x) => (
                  <li key={x.asset_id} className="px-5 py-2.5">
                    <div className="flex justify-between gap-3"><span className="font-medium">{x.hostname}</span><TierMark tier={x.tier} /></div>
                    <div className="text-[13px] text-mute">{x.label} {x.version} · {x.zone} · {x.exposure.status}</div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          {d && (
            <Panel title="Vulnerability">
              <p className="text-[14px]">{d.vulnerability.description}</p>
              <dl className="mt-3 grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[13px]">
                <dt className="text-mute">Published</dt><dd>{date(d.vulnerability.published)}</dd>
                {d.vulnerability.kev && <><dt className="text-mute">CISA KEV</dt><dd>Added {date(d.vulnerability.kev.dateAdded)}, due {date(d.vulnerability.kev.dueDate)}</dd></>}
                {Object.entries(d.vulnerability.ssvc).flatMap(([k, v]) => [<dt key={k} className="text-mute">SSVC {k.toLowerCase()}</dt>, <dd key={k + 'v'}>{v}</dd>])}
                <dt className="text-mute">EPSS</dt><dd className="num">{d.vulnerability.epss == null ? '—' : num(d.vulnerability.epss, 3)}</dd>
              </dl>
              {d.vulnerability.kev?.requiredAction && <p className="mt-3 text-[13px] text-mute">CISA required action: {d.vulnerability.kev.requiredAction}</p>}
            </Panel>
          )}

          {d?.attack && d.attack.techniques.length > 0 && (
            <Panel title="MITRE ATT&CK" meta="Mapped by rules, not generated">
              <ul className="space-y-1.5 text-[13px]">
                {d.attack.techniques.map((t) => <li key={t.id}><a href={t.url} target="_blank" rel="noreferrer" className="num text-text underline-offset-2 hover:underline">{t.id}</a> {t.name} <span className="text-faint">· {t.tactics.join(', ')}</span></li>)}
              </ul>
              {d.attack.mitigations.length > 0 && (
                <ul className="mt-3 space-y-1.5 text-[13px]">
                  {d.attack.mitigations.map((m) => <li key={m.id}><a href={m.url} target="_blank" rel="noreferrer" className="num underline-offset-2 hover:underline">{m.id}</a> {m.name}</li>)}
                </ul>
              )}
            </Panel>
          )}

          <Panel title="Reports" meta="Drafts for regulators and partners">
            <div className="flex flex-col gap-2">
              {([['CERT-In incident report', api.certinUrl(org, cve)], ['STIX 2.1 bundle', api.stixUrl(org, cve)]] as const).map(([label, u]) => {
                const href = reportUrl(u)
                return href
                  ? <a key={label} href={href} target="_blank" rel="noreferrer" className="flex h-9 items-center justify-between rounded-md bg-raised px-3 text-[14px] hover:bg-[#28282b]">{label}<ExternalLink size={14} className="text-faint" /></a>
                  : <span key={label} className="flex h-9 items-center rounded-md bg-raised px-3 text-[14px] text-faint" title="Not available in sample data">{label}</span>
              })}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  )
}
