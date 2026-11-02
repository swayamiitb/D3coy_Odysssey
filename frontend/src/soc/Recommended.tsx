import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import type { Soc, Tier } from '../api'
import { Objectives, Prov, TierPill } from '../ui'
import { DecisionSheet } from './DecisionSheet'
import { TabBoxes, useJson } from './kit'
import { ProfilePicker, profileLabel, profileQuery, useProfile } from './profile'

/* "Most concerning now", for this analyst (ui-15): one strip of four boxes with one open at a time, the page's own
   dropdown pattern, so a page gains a recommendation layer without gaining weight. Organisations most at risk,
   threat groups and malware the record overlaps with (ATT&CK overlap, never attribution), technologies under
   pressure, and the next steps, each with its reasons and a Decide that opens the step-by-step support. */

interface Org { org_id: string; name: string; sector: string; score: number; in_profile: boolean; compromise: number; critical: number; reasons: string[]; top_cve: string | null; top_tier: Tier }
interface Actor { id: string; name: string; group_id?: string; aliases: string[]; url?: string; malware: string[]; overlap: string[]; basis?: string; note?: string; error?: string }
interface Malware { id: string; name: string; url?: string; sub?: string; tier?: Tier | null }
interface Tech { label: string; product_key: string; score: number; in_profile: boolean; reasons: string[]; assets: number; orgs: number; error?: string }
interface Step { kind: string; title: string; why?: string; org_id?: string; org?: string; cve?: string; tier?: string; recommended?: string; view?: string; tab?: string }
interface Reco { generated_at: string; orgs: Org[]; technologies: Tech[]; actors: Actor[]; malware: Malware[]; next_steps: Step[]; how: Record<string, string> }

type Go = (view: 'soc' | 'intel' | 'live', tab: string) => void

export function Recommended({ onOrg, onAlert, onGo }: { onOrg: (id: string) => void; onAlert: (org: string, cve: string) => void; onGo: Go }) {
  const [profile] = useProfile()
  const soc = useJson<Soc>('/api/soc', [], 60000).data
  const q = profileQuery(profile)
  const { data, error } = useJson<Reco>(`/api/recommendations?${q}`, [q], 30000)
  const [decide, setDecide] = useState<{ org: string; cve: string }>()
  const orgs = data?.orgs ?? []
  const actors = (data?.actors ?? []).filter((a) => !a.error)
  const techs = (data?.technologies ?? []).filter((t) => !t.error)
  const steps = data?.next_steps ?? []
  const Btn = ({ onClick, children, primary }: { onClick: () => void; children: string; primary?: boolean }) => (
    <button onClick={onClick} className={primary ? 'rounded-full bg-text px-3.5 py-1.5 text-[12.5px] font-semibold text-ink hover:opacity-85' : 'text-[12.5px] font-medium text-accent hover:underline'}>{children}</button>
  )
  return (
    <section>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-[22px] font-semibold tracking-tight">Most concerning now, {profileLabel(profile, soc?.orgs)}</h2>
          <p className="mt-1 max-w-3xl text-[14px] text-mute">Ranked with the reasons shown, from the record only. Threat groups are overlap with the public ATT&CK record, never attribution. Every item can be decided step by step.</p>
          <Objectives keys={['analysis', 'recommendations', 'risk']} className="mt-2" />
        </div>
        <ProfilePicker orgs={soc?.orgs} />
      </div>
      {error && <div className="mb-3 rounded-xl bg-crit/10 p-3 text-sm text-crit-ink">{error}</div>}
      <TabBoxes label="Recommendations" defaultOpen="steps" items={[
        { key: 'steps', title: 'Next steps', count: `${steps.length}`,
          preview: steps[0] ? steps[0].title : 'Nothing to do right now',
          panel: (
            <div className="soc-card px-6 py-5">
              <ol className="divide-y divide-line">
                {steps.map((s, i) => (
                  <li key={i} className="flex items-start gap-4 py-3">
                    <span className="w-6 shrink-0 text-right font-mono text-[13px] text-mute">{i + 1}</span>
                    <div className="min-w-0 flex-1">
                      <div className="font-medium">{s.title}</div>
                      {s.why && <div className="text-[13px] text-mute">{s.why}</div>}
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      {s.tier && <TierPill tier={s.tier as Tier} />}
                      {s.org_id && s.cve && <Btn primary onClick={() => setDecide({ org: s.org_id!, cve: s.cve! })}>Decide</Btn>}
                      {s.org_id && s.cve && <Btn onClick={() => onAlert(s.org_id!, s.cve!)}>Open</Btn>}
                      {s.view && <Btn primary onClick={() => onGo(s.view as 'soc', s.tab ?? '')}>Go</Btn>}
                    </div>
                  </li>
                ))}
              </ol>
              {data && <p className="mt-3 text-[12px] text-faint">{data.how.next_steps}</p>}
            </div>
          ) },
        { key: 'orgs', title: 'Organisations most at risk', count: `${orgs.filter((o) => o.compromise || o.critical).length}`,
          preview: orgs[0] ? `${orgs[0].name}: ${orgs[0].reasons[0]}` : 'No organisation at elevated risk',
          panel: (
            <div className="soc-card px-6 py-5">
              <ol className="divide-y divide-line">
                {orgs.map((o, i) => (
                  <li key={o.org_id} className="flex items-start gap-4 py-3">
                    <span className="w-6 shrink-0 text-right font-mono text-[13px] text-mute">{i + 1}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2 font-medium">{o.name}<span className="text-[12px] font-normal text-mute">{o.sector}</span>{o.in_profile && <span className="rounded-full border border-text px-2 py-0.5 text-[11px] font-semibold">your profile</span>}</div>
                      <div className="text-[13px] text-mute">{o.reasons.join(' · ')}</div>
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      <TierPill tier={o.top_tier} />
                      {o.top_cve && <Btn primary onClick={() => setDecide({ org: o.org_id, cve: o.top_cve! })}>Decide</Btn>}
                      <Btn onClick={() => onOrg(o.org_id)}>Open</Btn>
                    </div>
                  </li>
                ))}
              </ol>
              {data && <p className="mt-3 text-[12px] text-faint">{data.how.orgs}</p>}
            </div>
          ) },
        { key: 'actors', title: 'Threat groups and malware', chip: <Prov p="REAL" />, count: `${actors.length + (data?.malware.length ?? 0)}`,
          preview: actors[0] ? `${actors[0].name}: ${actors[0].basis ?? ''}` : 'No overlap with a recorded group yet',
          panel: (
            <div className="soc-card grid gap-6 px-6 py-5 lg:grid-cols-2">
              <div>
                <h3 className="text-[14px] font-semibold">Threat groups whose recorded tradecraft overlaps what we see</h3>
                <ul className="mt-2 divide-y divide-line">
                  {actors.map((a) => (
                    <li key={a.id} className="py-2.5">
                      <div className="flex flex-wrap items-center gap-2 font-medium">
                        {a.url ? <a href={a.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:underline">{a.name}<ExternalLink size={11} /></a> : a.name}
                        {a.group_id && <span className="font-mono text-[11px] text-faint">{a.group_id}</span>}
                        {a.aliases.length > 0 && <span className="text-[12px] text-mute">also {a.aliases.slice(0, 2).join(', ')}</span>}
                      </div>
                      <div className="text-[13px] text-mute">{a.basis}{a.malware.length ? ` · malware seen: ${a.malware.join(', ')}` : ''}{a.overlap.length ? ` · techniques: ${a.overlap.slice(0, 5).join(', ')}` : ''}</div>
                    </li>
                  ))}
                  {actors.length === 0 && <li className="py-3 text-[13px] text-mute">No group overlaps the techniques and malware seen so far.</li>}
                </ul>
                <p className="mt-2 text-[12px] text-faint">{data?.how.actors}</p>
              </div>
              <div>
                <h3 className="text-[14px] font-semibold">Malware families in the record</h3>
                <ul className="mt-2 divide-y divide-line">
                  {(data?.malware ?? []).map((m) => (
                    <li key={m.id} className="flex items-center gap-3 py-2.5">
                      <div className="min-w-0 flex-1">
                        <div className="font-medium">{m.url ? <a href={m.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:underline">{m.name}<ExternalLink size={11} /></a> : m.name}</div>
                        <div className="text-[13px] text-mute">{m.sub}</div>
                      </div>
                      {m.tier && <TierPill tier={m.tier} />}
                    </li>
                  ))}
                  {(data?.malware ?? []).length === 0 && <li className="py-3 text-[13px] text-mute">No malware family seen in the telemetry yet.</li>}
                </ul>
                <Btn onClick={() => onGo('intel', 'graph')}>Open the intelligence graph</Btn>
              </div>
            </div>
          ) },
        { key: 'tech', title: 'Technologies under pressure', count: `${techs.length}`,
          preview: techs[0] ? `${techs[0].label}: ${techs[0].reasons[0] ?? ''}` : 'No technology under pressure',
          panel: (
            <div className="soc-card px-6 py-5">
              <ol className="divide-y divide-line">
                {techs.map((t, i) => (
                  <li key={t.product_key} className="flex items-start gap-4 py-3">
                    <span className="w-6 shrink-0 text-right font-mono text-[13px] text-mute">{i + 1}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2 font-medium">{t.label}<span className="text-[12px] font-normal text-mute">{t.assets} assets at {t.orgs} organisations</span>{t.in_profile && <span className="rounded-full border border-text px-2 py-0.5 text-[11px] font-semibold">your profile</span>}</div>
                      <div className="text-[13px] text-mute">{t.reasons.join(' · ')}</div>
                    </div>
                  </li>
                ))}
              </ol>
              <div className="mt-3 flex items-center justify-between"><p className="text-[12px] text-faint">{data?.how.technologies}</p><Btn onClick={() => onGo('intel', 'threats')}>All technologies</Btn></div>
            </div>
          ) },
      ]} />
      {decide && <DecisionSheet org={decide.org} cve={decide.cve} onClose={() => setDecide(undefined)} onGo={(v, t) => onGo(v, t)} />}
    </section>
  )
}
