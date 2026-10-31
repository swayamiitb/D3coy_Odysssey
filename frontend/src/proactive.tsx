import {
  BadgeCheck, ClipboardList, CircleCheck, CircleSlash, Crosshair, FileText, Hand, Loader2, Mail, Radar, Send,
  ShieldAlert, Timer, TrendingUp, Undo2, UserCheck, UserX, type LucideIcon,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Approval, type AutoEvent, type ForecastView, type Language } from './api'
import { Badge, Prov } from './ui'

/* ------------------------------------------------------------------ shared vocabulary */

export const KIND: Record<string, { label: string; icon: LucideIcon; tone: string }> = {
  'auto.forecast': { label: 'Pre-emptive advisory', icon: TrendingUp, tone: 'text-mute' },
  'auto.warn': { label: 'Early warning', icon: Radar, tone: 'text-mute' },
  'auto.confirm': { label: 'Warning confirmed', icon: CircleCheck, tone: 'text-mute' },
  'auto.stand_down': { label: 'Stand-down', icon: CircleSlash, tone: 'text-mute' },
  'auto.notify': { label: 'Notice sent', icon: Send, tone: 'text-mute' },
  'auto.advisory': { label: 'Advisory notice', icon: Send, tone: 'text-mute' },
  'auto.digest': { label: 'Daily digest', icon: Mail, tone: 'text-mute' },
  'auto.baseline': { label: 'Go-live baseline', icon: ClipboardList, tone: 'text-mute' },
  'auto.escalate': { label: 'Reported to regulator', icon: ShieldAlert, tone: 'text-comp' },
  'auto.escalate_sla': { label: 'SLA escalation', icon: Timer, tone: 'text-crit' },
  'auto.report': { label: 'Report drafted', icon: FileText, tone: 'text-comp' },
  'auto.hunt': { label: 'Threat hunt', icon: Crosshair, tone: 'text-mute' },
  'auto.proposed': { label: 'Proposed', icon: Hand, tone: 'text-high' },
  'auto.withdrawn': { label: 'Withdrawn', icon: Undo2, tone: 'text-mute' },
  'analyst.approve': { label: 'Approved', icon: UserCheck, tone: 'text-ok' },
  'analyst.reject': { label: 'Rejected', icon: UserX, tone: 'text-mute' },
}

let LANGS: Promise<Record<string, Language>> | undefined
export function useLanguages(): Record<string, Language> {
  const [m, setM] = useState<Record<string, Language>>({})
  useEffect(() => {
    LANGS ??= api.languages().then((l) => Object.fromEntries(l.map((x) => [x.code, x]))).catch(() => ({}))
    LANGS.then(setM)
  }, [])
  return m
}

export function istTime(ts: string): string {
  return new Date(ts).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })
}

export function ProvBadge({ p }: { p?: string | null }) {
  if (!p) return null
  return <Prov p={p} />
}

/** Who acted: the autopilot on its own, a (simulated) duty officer, or a named analyst. */
export function Autonomy({ e }: { e: AutoEvent }) {
  const by = e.payload.approved_by as string | undefined
  if (e.kind.startsWith('analyst.')) {
    const actor = e.payload.actor as string
    return <Badge><UserCheck size={11} /> {actor}</Badge>
  }
  if (e.kind === 'auto.proposed') return <Badge tone="crit"><Hand size={11} /> needs a human</Badge>
  if (by) return <Badge tone={by.includes('SIM') ? 'accent' : 'ok'}><BadgeCheck size={11} /> approved · {by}</Badge>
  return <Badge><span className="font-semibold">AUTO</span></Badge>
}

/* ------------------------------------------------------------------ human in the loop */

const PROPOSAL: Record<string, string> = {
  'auto.forecast': 'Pre-emptive advisory (prediction)',
  'auto.warn': 'Early warning (sensor-only signal)',
  'auto.escalate': 'Report to regulator',
  'auto.escalate_sla': 'SLA escalation to sector CSIRT',
  'auto.advisory': 'New advisory: notify exposed organisations',
}
const REJECT_REASONS = ['False positive', 'Not relevant to these organisations', 'Already handled']

export function ApprovalQueue({ onChanged, limit = 6 }: { onChanged?: () => void; limit?: number }) {
  const [items, setItems] = useState<Approval[]>()
  const [done, setDone] = useState<Record<number, string>>({})
  const [busy, setBusy] = useState<number>()
  const [rejecting, setRejecting] = useState<number>()
  const [all, setAll] = useState(false)
  const langs = useLanguages()
  const load = () => api.approvals().then(setItems).catch(() => setItems([]))
  useEffect(() => { load() }, [])

  const decide = (a: Approval, approve: boolean, note?: string) => {
    setBusy(a.id)
    api.decide(a.id, approve ? 'approve' : 'reject', note)
      .then((r) => {
        setDone((d) => ({ ...d, [a.id]: approve ? `Sent ${r.executed} notice${r.executed === 1 ? '' : 's'} (simulated delivery), logged in the audit trail` : `Rejected: ${note}. Recorded for detector calibration.` }))
        onChanged?.()
      })
      .catch((e) => setDone((d) => ({ ...d, [a.id]: String(e) })))
      .finally(() => { setBusy(undefined); setRejecting(undefined) })
  }

  if (!items) return <div className="text-xs text-mute"><Loader2 size={12} className="mr-1 inline animate-spin" />Loading proposals…</div>
  if (items.length === 0) return <div className="text-sm text-ok">Nothing waits for you: every proposal has been decided.</div>
  const shown = all ? items : items.slice(0, limit)
  return (
    <div className="space-y-2">
      {shown.map((a) => (
        <article key={a.id} className={`rounded-xl border p-3 ${done[a.id] ? 'border-ok/40 bg-ok/5' : 'border-high/40 bg-high/5'}`}>
          <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
            <span className="font-semibold uppercase tracking-wide text-high">{PROPOSAL[a.kind] ?? a.kind}</span>
            {a.basis && <span className="text-mute">· {a.basis}</span>}
            <ProvBadge p={a.provenance} />
            <span className="ml-auto text-mute">proposed {istTime(a.proposed_at)} IST</span>
          </div>
          <div className="text-sm font-medium">{a.title}</div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-mute">
            <span>{a.orgs.length} organisation{a.orgs.length === 1 ? '' : 's'}</span>
            {a.langs.length > 0 && <span>in {a.langs.map((l) => langs[l]?.native ?? l).join(' · ')}</span>}
            {a.recipients.length > 0 && a.kind.startsWith('auto.escalate') && <span>to {a.recipients.join(', ')}</span>}
          </div>
          {a.preview[0] && <div className="mt-2 rounded-lg bg-panel-2 px-3 py-2 text-xs leading-relaxed text-mute">“{a.preview[0]}”</div>}
          {a.items.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {a.items.map((i) => <Badge key={i.cve + i.asset}><span className="font-mono">{i.cve}</span> · {i.asset.split('.')[0]}</Badge>)}
            </div>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {done[a.id] ? (
              <span className="text-xs text-ok">{done[a.id]}</span>
            ) : rejecting === a.id ? (
              <>
                <span className="text-xs text-mute">Why?</span>
                {REJECT_REASONS.map((r) => (
                  <button key={r} disabled={busy === a.id} onClick={() => decide(a, false, r)}
                          className="rounded-full px-3 py-1 text-xs ring-1 ring-line hover:bg-panel-2">{r}</button>
                ))}
                <button onClick={() => setRejecting(undefined)} className="text-xs text-mute hover:text-text">cancel</button>
              </>
            ) : (
              <>
                <button disabled={busy === a.id} onClick={() => decide(a, true)}
                        className="flex items-center gap-1.5 rounded-full bg-action px-4 py-1.5 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-50">
                  {busy === a.id ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />} Approve &amp; send
                </button>
                <button onClick={() => setRejecting(a.id)} className="rounded-full px-3 py-1.5 text-sm text-mute hover:text-text">Reject</button>
              </>
            )}
          </div>
        </article>
      ))}
      {items.length > limit && (
        <button onClick={() => setAll(!all)} className="text-xs text-accent hover:underline">
          {all ? 'Show fewer' : `Show all ${items.length} proposals`}
        </button>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ what Odyssey did on its own */

const FILTERS: Record<string, (k: string) => boolean> = {
  All: () => true,
  'Warnings & forecasts': (k) => ['auto.forecast', 'auto.warn', 'auto.confirm', 'auto.stand_down', 'auto.withdrawn'].includes(k),
  Notices: (k) => ['auto.notify', 'auto.advisory', 'auto.digest', 'auto.baseline'].includes(k),
  'Escalations & hunts': (k) => ['auto.escalate', 'auto.escalate_sla', 'auto.report', 'auto.hunt'].includes(k),
  'Human decisions': (k) => k.startsWith('analyst.') || k === 'auto.proposed',
}

export function AutopilotFeed({ orgId, limit = 120, tick, height = 'max-h-[28rem]' }: { orgId?: string; limit?: number; tick?: number; height?: string }) {
  const [events, setEvents] = useState<AutoEvent[]>()
  const [filter, setFilter] = useState('All')
  const langs = useLanguages()
  useEffect(() => { api.autopilot({ org_id: orgId, limit }).then((r) => setEvents(r.events)).catch(() => setEvents([])) }, [orgId, limit, tick])
  if (!events) return <div className="text-xs text-mute"><Loader2 size={12} className="mr-1 inline animate-spin" />Loading…</div>
  const rows = events.filter((e) => FILTERS[filter](e.kind))
  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-1">
        {Object.keys(FILTERS).map((f) => (
          <button key={f} onClick={() => setFilter(f)}
                  className={`rounded-full px-2.5 py-0.5 text-xs ${filter === f ? 'bg-text font-semibold text-ink' : 'bg-panel-2 text-mute hover:text-text'}`}>{f}</button>
        ))}
      </div>
      <ol className={`space-y-1.5 overflow-auto pr-1 ${height}`}>
        {rows.map((e) => {
          const k = KIND[e.kind] ?? { label: e.kind, icon: Hand, tone: 'text-mute' }
          const Icon = k.icon
          const lang = e.payload.lang as string | undefined
          return (
            <li key={e.seq} className="flex gap-2 rounded-lg px-2 py-1.5 hover:bg-panel-2">
              <Icon size={15} className={`mt-0.5 shrink-0 ${k.tone}`} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-2 text-xs">
                  <span className={`font-semibold ${k.tone}`}>{k.label}</span>
                  <span className="text-mute">{istTime(e.ts)}</span>
                  {e.payload.org_id && <span className="font-mono text-mute">{e.payload.org_id}</span>}
                  {lang && <span className="text-mute">· {langs[lang]?.native ?? lang}</span>}
                  <span className="ml-auto"><Autonomy e={e} /></span>
                </div>
                <div className="truncate text-xs leading-relaxed" title={e.payload.title ?? e.payload.reason}>
                  {e.payload.title ?? (e.kind.startsWith('analyst.') ? `${e.payload.action?.replace('auto.', '')} for ${(e.payload.orgs ?? []).length} organisation(s)${e.payload.note ? ` · ${e.payload.note}` : ''}` : e.subject)}
                </div>
              </div>
            </li>
          )
        })}
        {rows.length === 0 && <li className="text-xs text-mute">No events of this kind.</li>}
      </ol>
    </div>
  )
}

/* ------------------------------------------------------------------ ahead of the threat */

export function ForecastPanel({ limit = 8, compact }: { limit?: number; compact?: boolean }) {
  const [f, setF] = useState<ForecastView>()
  useEffect(() => { api.forecast().then(setF).catch(() => undefined) }, [])
  if (!f) return <div className="text-xs text-mute"><Loader2 size={12} className="mr-1 inline animate-spin" />Scoring new CVEs…</div>
  const live = f.model.live
  const base = live.base_rate_pct / 100
  return (
    <div>
      {compact ? (
        <p className="mb-3 text-xs text-mute">Flags {live.odyssey.flag_rate_pct}% of new CVEs on day 0; caught {live.odyssey.recall_pct}% of those CISA later confirmed exploited (out-of-time test).</p>
      ) : <p className="mb-3 text-xs leading-relaxed text-mute">
        On the day a CVE is published, before anyone exploits it, Odyssey's model asks: will this one be weaponised?
        Frozen on 31 Jul and never tuned since: in Aug–Oct it flagged <b className="text-text">{live.odyssey.flag_rate_pct}%</b> of new CVEs and caught
        {' '}<b className="text-text">{live.odyssey.recall_pct}%</b> of the ones CISA later confirmed exploited. CVSS ≥ 9 at the same alert budget caught {live.same_budget_recall_pct.cvss}%.
      </p>}
      <ol className="space-y-1.5">
        {f.items.slice(0, limit).map((i) => {
          const lead = i.kev_added ? Math.round((new Date(i.kev_added).getTime() - new Date(i.published).getTime()) / 86400_000) : null
          return (
            <li key={i.cve} className="flex items-center gap-3 rounded-lg bg-panel-2 px-3 py-2">
              <div className="w-12 shrink-0 text-right">
                <div className="font-mono text-sm font-semibold">{Math.round(i.p / base)}×</div>
                <div className="text-[10px] text-mute">base rate</div>
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 text-sm">
                  <span className="font-mono">{i.cve}</span>
                  <span className="truncate text-mute">{i.product}</span>
                </div>
                <div className="truncate text-[11px] text-mute">
                  published {i.published.slice(0, 10)} · {i.orgs} org{i.orgs === 1 ? '' : 's'}, {i.assets} asset{i.assets === 1 ? '' : 's'} · {i.reasons.slice(0, 2).join(', ')}
                </div>
              </div>
              <div className="w-32 shrink-0 text-right text-xs">
                {i.kev_added ? (
                  <span className="text-crit">CISA KEV {lead != null && lead > 0 ? `${lead} d later` : 'same day'}</span>
                ) : (
                  <span className="text-mute">not exploited yet{i.median_days_to_exploit != null ? ` · vendor median ${i.median_days_to_exploit} d to exploitation` : ''}</span>
                )}
              </div>
            </li>
          )
        })}
      </ol>
      <div className="mt-2 text-[11px] text-mute">
        {f.flagged} flagged CVEs on exposed assets since {f.since}; {f.since_exploited} have since been confirmed exploited by CISA.
      </div>
    </div>
  )
}
