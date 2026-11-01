import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import type { Soc } from '../api'
import { Objectives, Prov } from '../ui'
import { DecisionSheet } from './DecisionSheet'
import { Seg, useJson } from './kit'
import { ProfilePicker, profileQuery, useProfile } from './profile'

/* The incoming CVE stream on the Live page (ui-15): every CVE NVD publishes or changes, read every two minutes,
   ranked for the analyst by a transparent sum (severity, our inventory, KEV, exploited-in-the-wild text, the day-0
   forecast, freshness, the analyst's profile). Every row says which terms applied. A row that touches an
   organisation can be decided on the spot, step by step. */

interface Ours { label: string; assets: number; orgs: number; org_ids: string[] }
interface Row {
  cve: string; published: string | null; last_modified: string | null; status: string | null; description: string
  cvss: number | null; severity: string; cwe: string | null; vendors: string[]; ours: Ours[]; exposed: number; worst: string | null
  orgs: string[]; kev: boolean; itw: boolean; forecast: { p: number; flag: boolean } | null; priority: number; for_you: number
  reasons: string[]; profile_reason: string | null
}
interface Incoming { rows: Row[]; total: number; matching: number; ours: number; exploited: number; last_check: string | null; last_batch: number; seen_total: number; how: string }

const ago = (iso?: string | null) => {
  if (!iso) return 'not yet'
  const s = Math.max(0, Math.round((Date.now() - new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z').getTime()) / 1000))
  return s < 60 ? `${s} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`
}
const tone = (p: number) => (p >= 80 ? 'var(--color-crit)' : p >= 60 ? 'var(--color-high)' : p >= 40 ? 'var(--color-med)' : 'var(--color-faint)')
const FILTERS: ['all' | 'profile' | 'ours' | 'exploited', string][] = [['all', 'All'], ['profile', 'Your profile'], ['ours', 'Our technologies'], ['exploited', 'Exploited or forecast']]

export function IncomingCves({ onAlert }: { onAlert?: (org: string, cve: string) => void }) {
  const [profile] = useProfile()
  const soc = useJson<Soc>('/api/soc', [], 60000).data
  const [only, setOnly] = useState<'all' | 'profile' | 'ours' | 'exploited'>('all')
  const url = `/api/live/incoming?only=${only}&limit=50&${profileQuery(profile)}`
  const { data, error } = useJson<Incoming>(url, [url], 30000)
  const [decide, setDecide] = useState<{ org: string; cve: string }>()
  const [open, setOpen] = useState<string>()
  return (
    <div className="soc-card px-6 py-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="flex flex-wrap items-center gap-2 text-[16px] font-semibold">Incoming CVEs, ranked for you <Prov p="REAL" /></h2>
          <p className="mt-0.5 text-[13px] text-mute">Every CVE NVD publishes or changes, read every two minutes and ranked by severity, our inventory, exploitation evidence, the day-0 forecast and your profile. Each row says why.</p>
          <Objectives keys={['aggregation', 'warning', 'risk']} className="mt-2" />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ProfilePicker orgs={soc?.orgs} />
          <Seg label="Show" value={only} onChange={setOnly} items={FILTERS} />
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12.5px] text-mute">
        {data ? <>
          <span><b className="text-text">{data.total.toLocaleString('en-IN')}</b> in the stream</span>
          <span><b className="text-text">{data.ours}</b> name our technologies</span>
          <span><b className="text-text">{data.exploited}</b> exploited or forecast</span>
          <span>last read {ago(data.last_check)} · {data.last_batch} new in that read · {data.seen_total.toLocaleString('en-IN')} seen since start</span>
        </> : error ? <span className="text-crit-ink">{error}</span> : <span>Waiting for the first NVD read (within two minutes of start)…</span>}
      </div>
      <ol className="mt-3 divide-y divide-line">
        {(data?.rows ?? []).map((r) => {
          const org = r.orgs[0] ?? r.ours[0]?.org_ids[0]
          const isOpen = open === r.cve
          return (
            <li key={r.cve} className="py-2.5">
              <div className="grid grid-cols-[52px_minmax(0,1fr)_auto] items-start gap-3">
                <button onClick={() => setOpen(isOpen ? undefined : r.cve)} className="text-left" title={r.reasons.join(' · ')}>
                  <span className="block text-[20px] font-semibold leading-none tabular-nums" style={{ color: tone(r.for_you) }}>{r.for_you}</span>
                  <span className="mt-1 block h-1 rounded-full bg-panel-3"><span className="block h-1 rounded-full" style={{ width: `${r.for_you}%`, background: tone(r.for_you) }} /></span>
                </button>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <a href={`https://nvd.nist.gov/vuln/detail/${r.cve}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-mono text-[13.5px] font-semibold hover:underline">{r.cve}<ExternalLink size={11} /></a>
                    <span className="text-[12px] text-faint">{r.published ? `published ${ago(r.published)}` : 'no date'}{r.last_modified && r.last_modified !== r.published ? ` · changed ${ago(r.last_modified)}` : ''}</span>
                    {r.cvss != null ? <span className="rounded-full bg-panel-2 px-2 py-0.5 text-[11px] font-semibold">CVSS {r.cvss} {r.severity.toLowerCase()}</span> : <span className="rounded-full bg-panel-2 px-2 py-0.5 text-[11px] text-mute">awaiting analysis</span>}
                    {r.kev && <span className="rounded-full bg-crit/15 px-2 py-0.5 text-[11px] font-semibold text-crit-ink">CISA KEV</span>}
                    {r.itw && <span className="rounded-full bg-crit/15 px-2 py-0.5 text-[11px] font-semibold text-crit-ink">exploited in the wild</span>}
                    {r.forecast?.flag && <span className="rounded-full bg-accent/15 px-2 py-0.5 text-[11px] font-semibold text-accent">forecast {Math.round(r.forecast.p * 100)}%</span>}
                    {r.ours.length > 0 && <span className="rounded-full bg-high/15 px-2 py-0.5 text-[11px] font-semibold text-high-ink">ours: {r.ours.map((o) => o.label).slice(0, 2).join(', ')}{r.ours.length > 2 ? ` +${r.ours.length - 2}` : ''}</span>}
                    {r.worst && r.worst !== 'Watch' && <span className="rounded-full bg-panel-2 px-2 py-0.5 text-[11px] font-semibold">{r.exposed} exposed · {r.worst}</span>}
                    {r.profile_reason && <span className="rounded-full border border-text px-2 py-0.5 text-[11px] font-semibold">your profile</span>}
                  </div>
                  <p className="mt-1 truncate text-[13px] text-mute" title={r.description}>{r.description}</p>
                  {isOpen && (
                    <div className="mt-2 rounded-xl bg-panel-2 p-3 text-[12.5px]">
                      <div className="font-medium">Why {r.for_you}:</div>
                      <ul className="mt-1 list-disc space-y-0.5 pl-5 text-mute">{r.reasons.map((x, i) => <li key={i}>{x}</li>)}{r.profile_reason && <li>{r.profile_reason} (+15)</li>}</ul>
                      {r.ours.length > 0 && <div className="mt-2 text-mute">Run by: {r.ours.map((o) => `${o.label} (${o.assets} assets at ${o.orgs} organisation${o.orgs !== 1 ? 's' : ''})`).join(' · ')}</div>}
                      {r.cwe && <div className="mt-1 text-faint">{r.cwe}{r.vendors.length ? ` · ${r.vendors.join(', ')}` : ''}</div>}
                    </div>
                  )}
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1.5">
                  {org && r.orgs.length > 0 && <button onClick={() => setDecide({ org, cve: r.cve })} className="rounded-full bg-text px-3.5 py-1.5 text-[12.5px] font-semibold text-ink hover:opacity-85">Decide</button>}
                  {org && r.orgs.length > 0 && onAlert && <button onClick={() => onAlert(org, r.cve)} className="text-[12.5px] font-medium text-accent hover:underline">Open warning</button>}
                  {!r.orgs.length && <button onClick={() => setOpen(isOpen ? undefined : r.cve)} className="text-[12.5px] font-medium text-mute hover:text-text">{isOpen ? 'Less' : 'Why'}</button>}
                </div>
              </div>
            </li>
          )
        })}
        {data && data.rows.length === 0 && <li className="py-6 text-center text-[13px] text-mute">Nothing matches this view yet.</li>}
      </ol>
      {data && <p className="mt-3 text-[12px] text-faint">{data.how}</p>}
      {decide && <DecisionSheet org={decide.org} cve={decide.cve} onClose={() => setDecide(undefined)} />}
    </div>
  )
}
