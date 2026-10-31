import { Activity } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, type Campaign, type LedgerEvent, type Summary } from './api'
import { Badge, TIER_FILL } from './ui'

const SECTORS = ['Power & Energy', 'BFSI', 'Telecom', 'Transport', 'Government', 'Strategic & Public Enterprises']
const KIND_LABEL: Record<string, string> = {
  'vuln.published': 'CVE published',
  'kev.added': 'Added to CISA KEV',
  'ssvc.updated': 'CISA SSVC updated',
  'decoy.surge': 'Decoy grid surge',
  'decoy.exploit': 'Exploit seen on decoys',
  'ioc.sighting': 'C2 beacon detected',
  'model.output': 'AI brief issued',
}
const TONE: Record<string, 'ok' | 'accent' | 'crit' | 'mute'> = { REAL: 'ok', SIM: 'accent', AI: 'mute', HUMAN: 'crit' }

export function Pulse({ summary, live }: { summary?: Summary; live: LedgerEvent[] }) {
  const [recent, setRecent] = useState<LedgerEvent[]>([])
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  useEffect(() => {
    api.recent().then(setRecent).catch(() => undefined)
    api.campaigns().then(setCampaigns).catch(() => undefined)
  }, [])
  const events = [...live].reverse().concat(recent).filter((e, i, arr) => arr.findIndex((x) => x.seq === e.seq) === i).slice(0, 14)

  return (
    <aside className="flex w-80 shrink-0 flex-col gap-4 overflow-auto">
      <section className="rounded-2xl border border-line bg-panel p-4">
        <div className="mb-3 text-xs uppercase tracking-wider text-mute">National pulse · NCIIPC sectors</div>
        <div className="grid grid-cols-2 gap-2">
          {SECTORS.map((s) => {
            const h = summary?.sector_heatmap[s] ?? {}
            const hot = (h.Compromise ?? 0) > 0 ? 'Compromise' : (h.Critical ?? 0) > 0 ? 'Critical' : 'High'
            return (
              <div key={s} className="rounded-xl border border-line bg-panel-2 p-3">
                <div className="truncate text-xs text-mute">{s.replace(' & Public Enterprises', ' & PSE')}</div>
                <div className="mt-1 flex items-baseline gap-1">
                  <span className="text-2xl font-semibold" style={{ color: TIER_FILL[hot] }}>
                    {(h.Compromise ?? 0) + (h.Critical ?? 0)}
                  </span>
                  <span className="text-xs text-mute">critical</span>
                </div>
                {(h.Compromise ?? 0) > 0 && <div className="text-xs text-fuchsia-300">{h.Compromise} compromise</div>}
              </div>
            )
          })}
        </div>
      </section>

      <section className="rounded-2xl border border-line bg-panel p-4">
        <div className="mb-3 text-xs uppercase tracking-wider text-mute">Campaigns · related threats</div>
        <ol className="space-y-2">
          {campaigns.slice(0, 5).map((c) => (
            <li key={c.id} className="rounded-xl bg-panel-2 p-2.5">
              <div className="flex items-center gap-2">
                <span className={`rounded px-1.5 text-[10px] font-semibold ${c.status === 'ACTIVE' ? 'bg-crit/20 text-crit' : 'bg-high/20 text-high'}`}>{c.status}</span>
                <span className="truncate text-sm">{c.title.replace(/^(Exploitation|Reconnaissance) of /, '')}</span>
              </div>
              <div className="mt-1 text-xs text-mute">
                {c.cves.length} exploited CVE{c.cves.length === 1 ? '' : 's'} · {c.orgs_exposed.length} orgs
                {c.chains.length > 0 && ` · ${c.chains.length} chained assets`}
                {c.early_warning_days > 0 && <span className="text-accent"> · first signal {c.early_warning_days}d before disclosure</span>}
                {c.cves.length === 0 && c.decoy_surges.length > 0 && ' · decoy scanning only'}
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="flex min-h-0 flex-1 flex-col rounded-2xl border border-line bg-panel p-4">
        <div className="mb-3 flex items-center gap-2 text-xs uppercase tracking-wider text-mute">
          <Activity size={12} className="text-ok" /> Live evidence stream
          <span className="ml-auto h-2 w-2 animate-pulse rounded-full bg-ok" />
        </div>
        <ol className="space-y-2 overflow-auto text-xs">
          {events.map((e) => (
            <li key={e.seq} className="flex items-start gap-2">
              <Badge tone={TONE[e.provenance] ?? 'mute'}>{e.provenance}</Badge>
              <div className="min-w-0">
                <div className="truncate">{KIND_LABEL[e.kind] ?? e.kind.replace('analyst.', 'Analyst: ')}</div>
                <div className="truncate font-mono text-mute">{e.subject} · {e.ts.slice(5, 16).replace('T', ' ')}</div>
              </div>
            </li>
          ))}
        </ol>
      </section>
    </aside>
  )
}
