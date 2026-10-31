import { FileText, ShieldX, TrendingUp } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Card, type Feed, type ForecastView, type Soc } from './api'
import { CertInReportModal } from './ExportPanel'
import { IndiaMap } from './IndiaMap'
import { ApprovalQueue } from './proactive'
import { Row, TIER_FILL, TierPill, useToast } from './ui'

/* Uber's ride screen, for a national CERT: a task panel on the left (one trip card, one black action, then what is
   next) and the live map on the right. Details slide in on demand. */

const JOURNEY = [
  { key: 'new', label: 'Issued' },
  { key: 'acknowledged', label: 'Acknowledged' },
  { key: 'mitigating', label: 'Mitigating' },
  { key: 'verifying', label: 'Verifying' },
  { key: 'closed', label: 'Closed' },
]
const ACTION_LABEL: Record<string, string> = {
  acknowledge: 'Acknowledge',
  start: 'Start mitigation',
  verify: 'Patched, verify',
  resolve: 'Close as resolved',
}
const DONE_TOAST: Record<string, string> = {
  acknowledge: 'Acknowledged. The deadline clock keeps running.',
  start: 'Mitigation started.',
  verify: 'Marked patched: verification next.',
  resolve: 'Closed as resolved.',
  false_positive: 'Closed as a false positive. Recorded for calibration.',
}

function useNow(ms = 1000) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(id)
  }, [ms])
  return now
}

export function Countdown({ issuedAt, hours, big }: { issuedAt: string; hours: number | null; big?: boolean }) {
  const now = useNow()
  if (hours == null) return <span className="text-mute">no deadline</span>
  const left = new Date(issuedAt).getTime() + hours * 3600_000 - now
  const overdue = left < 0
  const abs = Math.abs(left)
  const h = Math.floor(abs / 3600_000)
  const m = Math.floor((abs % 3600_000) / 60_000)
  const s = Math.floor((abs % 60_000) / 1000)
  const text = `${overdue ? '−' : ''}${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
  return <span className={`tabular-nums ${overdue ? 'text-crit' : ''} ${big ? 'text-5xl font-bold tracking-tight' : 'text-sm font-medium'}`}>{text}</span>
}

/** Trip progress: a thin bar like Uber's ETA bar, with the current stage named. */
function Progress({ state }: { state: string }) {
  const idx = Math.max(0, JOURNEY.findIndex((j) => j.key === (state === 'reopened' ? 'acknowledged' : state)))
  return (
    <div>
      <div className="flex gap-1">
        {JOURNEY.map((j, i) => (
          <div key={j.key} className={`h-1.5 flex-1 rounded-full ${i < idx ? 'bg-ok' : i === idx ? 'bg-action' : 'bg-panel-2'}`} />
        ))}
      </div>
      <div className="mt-1.5 flex justify-between text-[11px] text-mute">
        {JOURNEY.map((j, i) => <span key={j.key} className={i === idx ? 'font-semibold text-text' : ''}>{j.label}</span>)}
      </div>
    </div>
  )
}

function title(c: Card) {
  return c.headline ?? `${c.cve_id} · ${c.title.split('.')[0]}`
}

export function Now({ onOpen, onOrg, onGo, tick }: {
  onOpen: (c: Card) => void; onOrg: (id: string) => void; onGo: (view: 'intel', tab: 'threats' | 'overview') => void; tick: number
}) {
  const [feed, setFeed] = useState<Feed>()
  const [soc, setSoc] = useState<Soc>()
  const [fc, setFc] = useState<ForecastView>()
  const [busy, setBusy] = useState(false)
  const [reportFor, setReportFor] = useState<Card>()
  const toast = useToast()
  const load = () => {
    api.feed().then(setFeed).catch(() => undefined)
    api.soc().then(setSoc).catch(() => undefined)
  }
  useEffect(load, [tick])
  useEffect(() => { api.forecast().then(setFc).catch(() => undefined) }, [])

  const act = (c: Card, action: string) => {
    setBusy(true)
    api.act(c.org_id, c.cve_id, action).then(() => { toast(DONE_TOAST[action] ?? 'Done.'); load() })
      .catch((e) => toast(String(e))).finally(() => setBusy(false))
  }

  if (!feed) return <div className="p-8 text-mute">Loading the national picture…</div>
  const [hero, ...rest] = feed.cards
  const next = hero?.workflow.next_action

  return (
    <div className="flex min-h-0 flex-1 gap-5">
      <div className="flex w-[460px] shrink-0 flex-col gap-5 overflow-auto pr-1 [&>*]:shrink-0">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">{feed.counts.needs_action} warnings need you</h2>
          <p className="mt-1 text-mute">
            {feed.counts.compromise > 0 && <span className="font-medium text-comp">{feed.counts.compromise} suspected compromise · </span>}
            {soc?.pending ?? '…'} decisions waiting · {feed.counts.closed} closed
          </p>
        </div>

        {hero ? (
          <article className="rounded-3xl border border-line bg-panel p-5 shadow-[0_8px_30px_rgb(0_0_0/0.08)]">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <TierPill tier={hero.tier} />
              {hero.kev && <span className="rounded-full bg-panel-2 px-2.5 py-0.5 text-xs font-medium">exploited in the wild</span>}
              <span className="ml-auto font-mono text-xs text-mute">{hero.cve_id}</span>
            </div>
            <h3 className="text-xl font-bold leading-snug">{title(hero)}</h3>
            <p className="mt-1 text-sm text-mute">{hero.org_name} · {hero.sector} · {hero.assets} asset{hero.assets > 1 ? 's' : ''}</p>
            <div className="my-5">
              <Countdown issuedAt={feed.issued_at} hours={hero.deadline_hours} big />
              <div className="text-sm text-mute">{hero.tier === 'Compromise' ? 'left to report to CERT-In' : 'left to remediate'}</div>
            </div>
            <Progress state={hero.workflow.state} />
            {next && (
              <button disabled={busy} onClick={() => act(hero, next)}
                      className="mt-5 w-full rounded-full bg-action py-3.5 text-base font-semibold text-ink hover:opacity-85 disabled:opacity-50">
                {ACTION_LABEL[next] ?? next}
              </button>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button onClick={() => onOpen(hero)} className="rounded-full bg-panel-2 px-4 py-2 text-sm font-medium hover:bg-line">Why this warning?</button>
              {hero.tier === 'Compromise' && (
                <button onClick={() => setReportFor(hero)} className="flex items-center gap-1.5 rounded-full bg-panel-2 px-4 py-2 text-sm font-medium hover:bg-line">
                  <FileText size={14} /> CERT-In report
                </button>
              )}
              {next && (
                <button disabled={busy} onClick={() => act(hero, 'false_positive')} className="ml-auto flex items-center gap-1 px-2 py-2 text-sm text-mute hover:text-text">
                  <ShieldX size={14} /> False positive
                </button>
              )}
            </div>
          </article>
        ) : <div className="rounded-3xl bg-panel-2 p-6 text-lg font-semibold text-ok">All clear: no warning needs action.</div>}

        <section>
          <div className="mb-2 flex items-baseline justify-between">
            <h3 className="text-lg font-bold">Needs your decision</h3>
            <button onClick={() => onGo('intel', 'overview')} className="text-sm font-medium text-accent hover:underline">See all {soc?.pending ?? ''}</button>
          </div>
          <ApprovalQueue limit={1} onChanged={load} hideMore />
        </section>

        <section>
          <h3 className="mb-1 text-lg font-bold">Up next</h3>
          <div>
            {rest.slice(0, 6).map((c) => (
              <Row key={c.id} onClick={() => onOpen(c)}
                   lead={<span className="h-3 w-3 rounded-full" style={{ background: TIER_FILL[c.tier] }} />}
                   title={title(c)} sub={`${c.org_name} · ${c.cve_id}`}
                   trail={<Countdown issuedAt={feed.issued_at} hours={c.deadline_hours} />} />
            ))}
          </div>
        </section>

        {fc && (
          <section>
            <h3 className="mb-1 text-lg font-bold">Ahead of the threat</h3>
            <Row onClick={() => onGo('intel', 'threats')} lead={<TrendingUp size={18} />}
                 title={`${fc.flagged} new CVEs flagged likely to be exploited`}
                 sub={`${fc.since_exploited} already confirmed by CISA after Odyssey flagged them`} />
          </section>
        )}
      </div>

      <div className="min-w-0 flex-1">
        {soc ? <IndiaMap orgs={soc.orgs} onOrg={onOrg} /> : <div className="h-full rounded-3xl bg-map" />}
      </div>
      {reportFor && <CertInReportModal orgId={reportFor.org_id} cveId={reportFor.cve_id} onClose={() => setReportFor(undefined)} />}
    </div>
  )
}
