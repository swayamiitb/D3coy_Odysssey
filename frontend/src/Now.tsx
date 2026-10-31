import { ArrowRight, Check, ChevronRight, Clock, FileText, ShieldX } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Card, type Feed } from './api'
import { CertInReportModal } from './ExportPanel'
import { ApprovalQueue, ForecastPanel } from './proactive'
import { Panel, TIER_FILL, TierPill } from './ui'

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
  verify: 'Patched — verify',
  resolve: 'Close as resolved',
}

function useNow(ms = 1000) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(id)
  }, [ms])
  return now
}

function Countdown({ issuedAt, hours, big }: { issuedAt: string; hours: number | null; big?: boolean }) {
  const now = useNow()
  if (hours == null) return <span className="text-mute">no deadline</span>
  const left = new Date(issuedAt).getTime() + hours * 3600_000 - now
  const overdue = left < 0
  const abs = Math.abs(left)
  const h = Math.floor(abs / 3600_000)
  const m = Math.floor((abs % 3600_000) / 60_000)
  const s = Math.floor((abs % 60_000) / 1000)
  const text = `${overdue ? '-' : ''}${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
  return (
    <span className={`font-mono tabular-nums ${overdue ? 'text-crit' : ''} ${big ? 'text-4xl font-semibold' : 'text-sm'}`}>
      {text}
    </span>
  )
}

function Journey({ state, compact }: { state: string; compact?: boolean }) {
  const idx = Math.max(0, JOURNEY.findIndex((j) => j.key === (state === 'reopened' ? 'acknowledged' : state)))
  return (
    <ol className="flex items-center gap-1">
      {JOURNEY.map((j, i) => (
        <li key={j.key} className="flex flex-1 items-center gap-1">
          <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold
            ${i < idx ? 'bg-ok text-ink' : i === idx ? 'bg-accent text-ink ring-4 ring-accent/20' : 'bg-panel-2 text-mute'}`}>
            {i < idx ? <Check size={12} /> : i + 1}
          </span>
          {!compact && <span className={`hidden text-xs xl:inline ${i === idx ? 'text-text' : 'text-mute'}`}>{j.label}</span>}
          {i < JOURNEY.length - 1 && <span className={`h-px flex-1 ${i < idx ? 'bg-ok' : 'bg-line'}`} />}
        </li>
      ))}
    </ol>
  )
}

function title(c: Card) {
  return c.headline ?? `${c.cve_id} · ${c.title.split('.')[0]}`
}

function ActionButtons({ c, onChanged, size }: { c: Card; onChanged: () => void; size: 'lg' | 'sm' }) {
  const [busy, setBusy] = useState(false)
  const next = c.workflow.next_action
  const run = (action: string) => {
    setBusy(true)
    api.act(c.org_id, c.cve_id, action).then(onChanged).finally(() => setBusy(false))
  }
  if (!next) return null
  return (
    <div className="flex items-center gap-2">
      <button disabled={busy} onClick={() => run(next)}
              className={`flex items-center gap-2 rounded-full bg-accent font-semibold text-ink transition hover:brightness-110 disabled:opacity-50
                ${size === 'lg' ? 'px-6 py-3 text-base' : 'px-4 py-1.5 text-sm'}`}>
        {ACTION_LABEL[next] ?? next} <ArrowRight size={size === 'lg' ? 18 : 14} />
      </button>
      {size === 'lg' && (
        <button disabled={busy} onClick={() => run('false_positive')}
                className="flex items-center gap-1 rounded-full px-4 py-3 text-sm text-mute hover:text-text">
          <ShieldX size={14} /> False positive
        </button>
      )}
    </div>
  )
}

export function Now({ onOpen, tick }: { onOpen: (c: Card) => void; tick: number }) {
  const [feed, setFeed] = useState<Feed>()
  const load = () => api.feed().then(setFeed).catch(() => undefined)
  useEffect(() => { load() }, [tick])
  const [reportFor, setReportFor] = useState<Card>()

  if (!feed) return <div className="p-8 text-mute">Loading the national picture…</div>
  const [hero, ...rest] = feed.cards
  if (!hero) {
    return <div className="flex flex-1 items-center justify-center text-xl text-ok">All clear — no warnings need action.</div>
  }
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 overflow-auto [&>*]:shrink-0">
      <div className="flex items-baseline gap-3">
        <h2 className="text-3xl font-semibold">{feed.counts.needs_action} warnings need action</h2>
        {feed.counts.compromise > 0 && (
          <span className="text-lg text-fuchsia-300">{feed.counts.compromise} suspected compromise</span>
        )}
        <span className="text-sm text-mute">· {feed.counts.closed} closed</span>
      </div>

      <article className="relative overflow-hidden rounded-2xl border border-line bg-panel p-6 shadow-2xl">
        <div className="absolute inset-y-0 left-0 w-1.5" style={{ background: TIER_FILL[hero.tier] }} />
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2">
              <TierPill tier={hero.tier} />
              <span className="font-mono text-sm text-accent">{hero.cve_id}</span>
              {hero.kev && <span className="text-xs text-crit">exploited in the wild</span>}
            </div>
            <h3 className="text-2xl font-semibold leading-snug">{title(hero)}</h3>
            <p className="mt-2 text-mute">{hero.org_name} · {hero.sector} · {hero.assets} asset{hero.assets > 1 ? 's' : ''} exposed</p>
          </div>
          <div className="shrink-0 text-right">
            <div className="flex items-center justify-end gap-1 text-xs uppercase tracking-wide text-mute"><Clock size={12} /> time left</div>
            <Countdown issuedAt={feed.issued_at} hours={hero.deadline_hours} big />
            <div className="text-xs text-mute">{hero.tier === 'Compromise' ? 'CERT-In incident report' : 'remediation deadline'}</div>
          </div>
        </div>
        <div className="my-6"><Journey state={hero.workflow.state} /></div>
        <div className="flex items-center justify-between">
          <ActionButtons c={hero} onChanged={load} size="lg" />
          <div className="flex items-center gap-4">
            {hero.tier === 'Compromise' && (
              <button onClick={() => setReportFor(hero)}
                      className="flex items-center gap-1 rounded-full px-4 py-2 text-sm text-fuchsia-300 ring-1 ring-fuchsia-400/50 hover:bg-fuchsia-500/10">
                <FileText size={14} /> Draft CERT-In report
              </button>
            )}
            <button onClick={() => onOpen(hero)} className="flex items-center gap-1 text-sm text-accent hover:underline">
              Why this warning? <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </article>
      {reportFor && <CertInReportModal orgId={reportFor.org_id} cveId={reportFor.cve_id} onClose={() => setReportFor(undefined)} />}

      <div className="grid gap-4 2xl:grid-cols-2">
        <Panel title="Needs your decision" right={<span className="text-xs text-mute">Odyssey proposes, you decide</span>}>
          <ApprovalQueue limit={1} onChanged={load} />
        </Panel>
        <Panel title="Ahead of the threat · day-0 exploitation forecast" right={<span className="text-xs text-mute">before CISA confirms</span>}>
          <ForecastPanel limit={3} compact />
        </Panel>
      </div>

      <div className="space-y-2">
        <div className="text-xs uppercase tracking-wider text-mute">Up next</div>
        {rest.map((c) => (
          <article key={c.id} className="flex items-center gap-4 rounded-xl border border-line bg-panel px-4 py-3 hover:bg-panel-2">
            <span className="h-10 w-1 shrink-0 rounded" style={{ background: TIER_FILL[c.tier] }} />
            <button onClick={() => onOpen(c)} className="min-w-0 flex-1 text-left">
              <div className="truncate font-medium">{title(c)}</div>
              <div className="truncate text-xs text-mute">{c.org_name} · {c.sector} · <span className="font-mono">{c.cve_id}</span></div>
            </button>
            <div className="w-36 shrink-0" title={c.workflow.state}><Journey state={c.workflow.state} compact /></div>
            <div className="w-24 shrink-0 text-right"><Countdown issuedAt={feed.issued_at} hours={c.deadline_hours} /></div>
            <div className="w-44 shrink-0 text-right"><ActionButtons c={c} onChanged={load} size="sm" /></div>
          </article>
        ))}
      </div>
    </div>
  )
}
