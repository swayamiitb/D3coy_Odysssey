import { BellRing, ExternalLink, Hash, Loader2, Mail, MessageSquare, Power, RefreshCw, Send, Webhook, X } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { api, type NotifyChannel, type NotifyStatus, type Tier } from './api'
import { istTime } from './proactive'
import { Pill, Row, Section, TIERS, TierPill, useToast } from './ui'

/* Where the alerts go: the apps a team already uses. Each channel is a row with a Send-test button that really sends
   and a mute toggle; the right column shows what was delivered, to whom, how fast, or why it failed. */

const ICON: Record<NotifyChannel['type'], typeof Mail> = { slack: Hash, discord: MessageSquare, teams: MessageSquare, webhook: Webhook, email: Mail }
const LABEL: Record<NotifyChannel['type'], string> = { slack: 'Slack', discord: 'Discord', teams: 'Microsoft Teams', webhook: 'Webhook', email: 'E-mail' }

function useNotify(ms = 2500): { s?: NotifyStatus; refresh: () => void } {
  const [s, setS] = useState<NotifyStatus>()
  const refresh = useCallback(() => { api.notify().then(setS).catch(() => undefined) }, [])
  useEffect(() => {
    let alive = true
    const pull = () => api.notify().then((d) => alive && setS(d)).catch(() => undefined)
    pull()
    const id = setInterval(pull, ms)
    return () => { alive = false; clearInterval(id) }
  }, [ms])
  return { s, refresh }
}

export function ChannelsSection() {
  const { s, refresh } = useNotify()
  const toast = useToast()
  const [busy, setBusy] = useState<string>()

  if (!s) return <div className="py-6 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Connecting to the channels…</div>

  const test = (c: NotifyChannel) => {
    setBusy(c.name)
    api.notifyTest(c.name)
      .then((d) => { toast(d.ok ? `Delivered to ${c.name} in ${d.ms} ms` : `${c.name}: ${d.error}`); refresh() })
      .catch((e) => toast(String(e.message ?? e)))
      .finally(() => setBusy(undefined))
  }
  const toggle = (c: NotifyChannel) => {
    api.notifyEnabled(c.name, !c.enabled)
      .then(() => { toast(c.enabled ? `${c.name} muted` : `${c.name} on`); refresh() })
      .catch((e) => toast(String(e.message ?? e)))
  }
  const reload = () => {
    api.notifyReload()
      .then((d) => { toast(`Channels reloaded: ${d.stats.configured} configured`); refresh() })
      .catch((e) => toast(String(e.message ?? e)))
  }
  const live = s.channels.filter((c) => c.configured && c.enabled)
  const stats = [
    { v: live.length, k: 'channels live', sub: `${s.stats.configured} configured of ${s.channels.length}` },
    { v: s.stats.sent, k: 'alerts delivered', sub: s.stats.failed ? `${s.stats.failed} failed` : 'no failures' },
    { v: s.stats.duplicates_suppressed, k: 'repeats folded', sub: `one per source every ${s.routing.dedupe_minutes} min` },
    { v: s.stats.held_by_cap, k: 'held by the cap', sub: `${s.routing.per_minute_cap} a minute, then a summary` },
  ]

  return (
    <Section title="Alerts delivered to your apps"
             sub="What Odyssey decides leaves this laptop the way your team already works: an attack blocked at a protected app, a C2 beacon, a new CVE, a case, a decision waiting for you, each one card in Slack, Discord, Teams, e-mail or any app with a webhook. The analysis stays here; only the alerts you route go out, and every delivery is in the audit trail."
             action={<span className="flex flex-wrap gap-2">
               {s.console_url && <Pill onClick={() => window.open(s.console_url!, '_blank', 'noopener')}><ExternalLink size={14} /> Open the Ops Console</Pill>}
               <Pill onClick={reload}><RefreshCw size={14} /> Reload channels</Pill>
             </span>}>
      <div className="grid gap-6 xl:grid-cols-[1fr_1.15fr]">
        <div>
          {s.channels.map((c) => {
            const I = ICON[c.type]
            const tone = !c.configured ? 'text-faint' : c.status === 'failing' ? 'text-crit' : c.status === 'ok' ? 'text-ok' : 'text-text'
            const state = !c.configured ? `not configured · ${c.about ?? ''}`
              : c.status === 'failing' ? `${c.destination} · failing: ${c.last_error}`
              : `${c.destination} · ${c.last_ok ? `last delivered ${istTime(c.last_ok)}` : 'ready'} · ${c.sent} sent${c.failed ? `, ${c.failed} failed` : ''}`
            return (
              <Row key={c.name} lead={<I size={18} className={tone} />}
                   title={<span className="flex items-center gap-2">{c.name}
                     <span className="rounded-full bg-panel-2 px-2 py-0.5 text-xs font-medium text-mute">{LABEL[c.type]}</span>
                     {!c.enabled && <span className="text-xs font-medium text-mute">muted</span>}
                   </span>}
                   sub={state}
                   trail={<span className="flex items-center gap-2">
                     <button disabled={!c.configured || busy === c.name} onClick={() => test(c)}
                             className="flex items-center gap-1.5 rounded-full bg-action px-3.5 py-1.5 text-sm font-semibold text-ink hover:opacity-85 disabled:opacity-40">
                       {busy === c.name ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />} Send test
                     </button>
                     <button disabled={!c.configured} onClick={() => toggle(c)} title={c.enabled ? 'Mute this channel' : 'Turn this channel on'}
                             className={`flex h-9 w-9 items-center justify-center rounded-full bg-panel-2 hover:bg-panel-3 disabled:opacity-40 ${c.enabled ? 'text-text' : 'text-faint'}`}>
                       <Power size={15} />
                     </button>
                   </span>} />
            )
          })}
          <p className="mt-4 text-sm text-mute">
            Connect yours: put the webhook URL (or SMTP details) in <span className="font-mono">config/notify.local.json</span> or the
            environment (<span className="font-mono">ODYSSEY_SLACK_WEBHOOK</span>, <span className="font-mono">ODYSSEY_DISCORD_WEBHOOK</span>, …),
            then <b>Reload channels</b> and <b>Send test</b>. Links in the cards use <span className="font-mono">ODYSSEY_PUBLIC_URL</span>, so a
            tunnelled dashboard (cloudflared, ngrok) opens from a phone. See <span className="font-mono">agent/README.md</span>.
          </p>
        </div>
        <div className="flex flex-col gap-3">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {stats.map((x) => (
              <div key={x.k} className="rounded-2xl bg-panel-2 p-4">
                <div className="text-[22px] font-semibold tabular-nums">{x.v.toLocaleString('en-IN')}</div>
                <div className="text-sm font-medium">{x.k}</div>
                <div className="truncate text-xs text-mute">{x.sub}</div>
              </div>
            ))}
          </div>
          <div className="mt-2 text-sm font-semibold">Recent deliveries</div>
          {s.recent.length === 0 && (
            <div className="rounded-2xl bg-panel-2 p-5 text-mute">Nothing delivered yet. Attack the protected app above, start a drill, or send a test.</div>
          )}
          {s.recent.slice(0, 8).map((d, i) => (
            <Row key={`${d.ts}-${d.channel}-${i}`}
                 lead={d.ok ? <BellRing size={16} className="text-ok" /> : <X size={16} className="text-crit" />}
                 title={<span className="flex items-center gap-2">
                   {TIERS.includes(d.severity as Tier) && <TierPill tier={d.severity as Tier} />}
                   <span className="truncate">{d.title}</span>
                 </span>}
                 sub={`${d.test ? 'test · ' : ''}${d.kind} → ${d.channel} (${d.destination})${d.error ? ` · ${d.error}` : ''}`}
                 trail={<span>
                   <span className={`block text-xs font-semibold ${d.ok ? 'text-ok' : 'text-crit'}`}>{d.ok ? `delivered · ${d.ms} ms` : 'failed'}</span>
                   <span className="block text-xs text-mute">{istTime(d.ts)}</span>
                 </span>} />
          ))}
          <p className="text-xs text-mute">Routed: {s.routing.kinds.join(', ')}, at {s.routing.min_severity} and above.</p>
        </div>
      </div>
    </Section>
  )
}
