import {
  BadgeCheck, Briefcase, ClipboardList, CircleCheck, CircleSlash, Crosshair, FileText, FlaskConical, Hand, Loader2, Mail,
  Radar, Send, ShieldAlert, Timer, TrendingUp, Undo2, UserCheck, UserX, Waypoints, type LucideIcon,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Approval, type AutoEvent, type ForecastView, type Language } from './api'
import { Badge, Prov, useToast } from './ui'

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
  'auto.case_opened': { label: 'Case opened', icon: Briefcase, tone: 'text-comp' },
  'live.detect.surge': { label: 'Surge detected', icon: Radar, tone: 'text-high' },
  'live.detect.beacon': { label: 'C2 beacon detected', icon: ShieldAlert, tone: 'text-crit' },
  'live.detect.anomaly': { label: 'Flow anomaly detected', icon: Waypoints, tone: 'text-high' },
  'live.rescore': { label: 'Warnings re-scored live', icon: ShieldAlert, tone: 'text-comp' },
  'live.drill.start': { label: 'Drill started', icon: FlaskConical, tone: 'text-mute' },
  'live.drill.end': { label: 'Drill finished', icon: FlaskConical, tone: 'text-mute' },
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
  'auto.forecast': 'Pre-emptive advisory',
  'auto.warn': 'Early warning',
  'auto.escalate': 'Report to regulator',
  'auto.escalate_sla': 'SLA escalation',
  'auto.advisory': 'New advisory',
}
const REJECT_REASONS = ['False positive', 'Not relevant to these organisations', 'Already handled']

export function ApprovalQueue({ onChanged, limit = 6, hideMore }: { onChanged?: () => void; limit?: number; hideMore?: boolean }) {
  const [items, setItems] = useState<Approval[]>()
  const [done, setDone] = useState<Record<number, string>>({})
  const [busy, setBusy] = useState<number>()
  const [rejecting, setRejecting] = useState<number>()
  const [all, setAll] = useState(false)
  const [open, setOpen] = useState<number>()
  const toast = useToast()
  const langs = useLanguages()
  const load = () => api.approvals().then(setItems).catch(() => setItems([]))
  useEffect(() => { load() }, [])

  const decide = (a: Approval, approve: boolean, note?: string) => {
    setBusy(a.id)
    api.decide(a.id, approve ? 'approve' : 'reject', note)
      .then((r) => {
        const msg = approve
          ? `Sent ${r.executed} notice${r.executed === 1 ? '' : 's'}${a.langs.length ? ` in ${a.langs.length} language${a.langs.length === 1 ? '' : 's'}` : ''} · logged`
          : `Rejected (${note}) · recorded for calibration`
        setDone((d) => ({ ...d, [a.id]: `✓ ${msg}` }))
        toast(msg)
        onChanged?.()
      })
      .catch((e) => setDone((d) => ({ ...d, [a.id]: String(e) })))
      .finally(() => { setBusy(undefined); setRejecting(undefined) })
  }

  if (!items) return <div className="text-xs text-mute"><Loader2 size={12} className="mr-1 inline animate-spin" />Loading proposals…</div>
  if (items.length === 0) return <div className="rounded-2xl bg-panel-2 p-4 text-sm font-medium text-ok">Nothing waits for you: every proposal is decided.</div>
  const shown = all ? items : items.slice(0, limit)
  return (
    <div className="space-y-3">
      {shown.map((a) => (
        <article key={a.id} className="rounded-2xl border border-line bg-panel p-4">
          <div className="mb-1.5 flex flex-wrap items-center gap-2 text-xs text-mute">
            <span className="font-semibold text-text">{PROPOSAL[a.kind] ?? a.kind}</span>
            {a.basis && <span>· {a.basis}</span>}
            <ProvBadge p={a.provenance} />
            <span className="ml-auto">{istTime(a.proposed_at)}</span>
          </div>
          <div className="text-[15px] font-semibold leading-snug">{a.title}</div>
          <div className="mt-1 text-sm text-mute">
            {a.orgs.length} organisation{a.orgs.length === 1 ? '' : 's'}
            {a.langs.length > 0 && <> · in {a.langs.map((l) => langs[l]?.native ?? l).join(' · ')}</>}
            {a.recipients.length > 0 && a.kind.startsWith('auto.escalate') && <> · to {a.recipients.join(', ')}</>}
          </div>
          {open === a.id && (
            <div className="mt-3 space-y-2">
              {a.preview[0] && <div className="rounded-xl bg-panel-2 px-3 py-2.5 text-sm leading-relaxed">{a.preview[0]}</div>}
              {a.items.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {a.items.map((i) => <Badge key={i.cve + i.asset}><span className="font-mono">{i.cve}</span> · {i.asset.split('.')[0]}</Badge>)}
                </div>
              )}
            </div>
          )}
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {done[a.id] ? (
              <span className="text-sm font-medium text-ok">{done[a.id]}</span>
            ) : rejecting === a.id ? (
              <>
                {REJECT_REASONS.map((r) => (
                  <button key={r} disabled={busy === a.id} onClick={() => decide(a, false, r)}
                          className="rounded-full bg-panel-2 px-3.5 py-2 text-sm font-medium hover:bg-line">{r}</button>
                ))}
                <button onClick={() => setRejecting(undefined)} className="px-2 text-sm text-mute hover:text-text">Cancel</button>
              </>
            ) : (
              <>
                <button disabled={busy === a.id} onClick={() => decide(a, true)}
                        className="flex items-center gap-1.5 rounded-full bg-action px-5 py-2.5 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-50">
                  {busy === a.id && <Loader2 size={14} className="animate-spin" />} Approve &amp; send
                </button>
                <button onClick={() => setRejecting(a.id)} className="rounded-full bg-panel-2 px-5 py-2.5 text-sm font-semibold hover:bg-line">Reject</button>
                <button onClick={() => setOpen(open === a.id ? undefined : a.id)} className="ml-auto text-sm font-medium text-accent hover:underline">
                  {open === a.id ? 'Hide' : 'Preview'}
                </button>
              </>
            )}
          </div>
        </article>
      ))}
      {items.length > limit && !hideMore && (
        <button onClick={() => setAll(!all)} className="text-sm font-medium text-accent hover:underline">
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
        <p className="mb-2 text-sm text-mute">Flags {live.odyssey.flag_rate_pct}% of new CVEs on day 0 and caught {live.odyssey.recall_pct}% of those CISA later confirmed exploited (out-of-time test).</p>
      ) : <p className="mb-4 leading-relaxed text-mute">
        On the day a CVE is published, before anyone exploits it, Odyssey's model asks: will this one be weaponised?
        Frozen on 31 Jul and never tuned since: in Aug–Oct it flagged <b className="text-text">{live.odyssey.flag_rate_pct}%</b> of new CVEs and caught
        {' '}<b className="text-text">{live.odyssey.recall_pct}%</b> of the ones CISA later confirmed exploited. CVSS ≥ 9 at the same alert budget caught {live.same_budget_recall_pct.cvss}%.
      </p>}
      <ol>
        {f.items.slice(0, limit).map((i) => {
          const lead = i.kev_added ? Math.round((new Date(i.kev_added).getTime() - new Date(i.published).getTime()) / 86400_000) : null
          return (
            <li key={i.cve} className="flex items-center gap-4 border-b border-line py-3 last:border-0">
              <div className="flex h-12 w-12 shrink-0 flex-col items-center justify-center rounded-full bg-panel-2" title="times the base rate of exploitation">
                <span className="text-sm font-bold tabular-nums leading-none">{Math.round(i.p / base)}×</span>
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate font-medium"><span className="font-mono text-sm">{i.cve}</span> <span className="text-mute">·</span> {i.product}</div>
                <div className="truncate text-sm text-mute">
                  {i.orgs} organisation{i.orgs === 1 ? '' : 's'}, {i.assets} asset{i.assets === 1 ? '' : 's'} · {i.reasons.slice(0, 2).join(', ')}
                </div>
              </div>
              <div className="w-56 shrink-0 text-right text-sm">
                {i.kev_added ? (
                  <span className="font-medium text-crit">CISA confirmed {lead != null && lead > 0 ? `${lead} d later` : 'same day'}</span>
                ) : (
                  <span className="text-mute">not exploited yet</span>
                )}
              </div>
            </li>
          )
        })}
      </ol>
      <div className="mt-3 text-sm text-mute">
        {f.flagged} flagged CVEs on exposed assets since {f.since}; {f.since_exploited} have since been confirmed exploited by CISA.
      </div>
    </div>
  )
}
