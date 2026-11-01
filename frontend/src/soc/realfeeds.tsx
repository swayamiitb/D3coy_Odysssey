import { ExternalLink } from 'lucide-react'
import type { ReactNode } from 'react'
import { Prov, TIER_FILL } from '../ui'
import raw from './data/realfeeds.json'
import { BarList, compact, nf, SocCard, TabBoxes } from './kit'

/* Five more kinds of real, open threat intelligence (ui-11), bundled by scripts/real-feeds-2.mjs and shown as one
   strip: ransomware victims in India, data breaches, ICS/OT advisories, open-source supply-chain advisories, and the
   anonymisation and criminal networks an attacker hides behind. Every box names its source and the day it was taken. */

interface Keyed { key: string; n: number }
interface RealFeeds {
  taken_at: string
  ransomware?: { source: string; url: string; what: string; total: number; groups: Keyed[]; sectors: Keyed[]; by_month: Keyed[]; by_year: Keyed[]; recent: { victim: string; group: string; sector: string | null; discovered: string; size: string | null }[] }
  breaches?: { source: string; url: string; what: string; total: number; accounts: number; verified: number; india: Breach[]; largest: Breach[]; by_year: Keyed[]; recent: Breach[] }
  ics?: { source: string; url: string; what: string; total: number; vendors: Keyed[]; by_month: Keyed[]; recent: { id: string; title: string; vendor: string; link: string; date: string }[] }
  supply?: { source: string; url: string; what: string; total: number; since: string; ecosystems: Keyed[]; recent: { id: string; cve: string | null; summary: string; published: string; cvss: number | null; ecosystems: string[]; packages: string[] }[] }
  networks?: { sources: { name: string; url: string; what: string; count: number; unit: string; addresses?: number; largest?: { cidr: string; sbl: string; addresses: number }[] }[] }
}
interface Breach { name: string; title: string; domain: string; date: string; accounts: number; verified: boolean; classes: string[] }
const F = raw as RealFeeds
const taken = F.taken_at.slice(0, 10)

function Source({ name, url, what }: { name: string; url: string; what: string }) {
  return (
    <p className="mt-3 text-[11.5px] leading-snug text-faint">
      <a href={url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-mute hover:underline">{name}<ExternalLink size={10} /></a>, {what}; taken {taken}.
    </p>
  )
}
function Missing({ what }: { what: string }) {
  return <p className="py-8 text-center text-[13px] text-faint">The {what} feed was not fetched on this build; run scripts/real-feeds-2.mjs with the network up.</p>
}
/** Twelve months as small bars, the latest in red. */
function Months({ rows, unit }: { rows: Keyed[]; unit: string }) {
  const max = Math.max(1, ...rows.map((r) => r.n))
  return (
    <div className="flex h-16 items-end gap-1.5" role="img" aria-label={rows.map((r) => `${r.key}: ${r.n} ${unit}`).join('; ')}>
      {rows.map((r, i) => (
        <div key={r.key} className="flex min-w-0 flex-1 flex-col items-center gap-1" title={`${r.key}: ${r.n} ${unit}`}>
          <div className="w-full rounded-t-sm" style={{ height: `${Math.max(2, (52 * r.n) / max)}px`, background: i === rows.length - 1 ? TIER_FILL.Critical : 'var(--color-line-2)' }} />
          <span className="truncate font-mono text-[9.5px] text-faint">{r.key.length === 4 ? r.key.slice(2) : r.key.slice(5)}</span>
        </div>
      ))}
    </div>
  )
}
const Row = ({ children }: { children: ReactNode }) => <li className="flex items-center gap-3 py-2 text-[13px]">{children}</li>

export function RansomwarePanel() {
  const r = F.ransomware
  return (
    <SocCard title="Ransomware victims in India" prov={['REAL']} sub="Organisations in India named on ransomware groups' leak sites">
      {!r ? <Missing what="ransomware" /> : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
          <div>
            <div className="flex items-baseline gap-2"><span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{nf(r.total)}</span><span className="text-[13px] text-mute">victims named since {r.by_year[0]?.key}</span></div>
            <div className="mt-4"><Months rows={r.by_month} unit="victims" /></div>
            <h4 className="mt-5 text-[13px] font-semibold">Groups naming the most Indian victims</h4>
            <div className="mt-2"><BarList color={TIER_FILL.Critical} rows={r.groups.map((g, i) => ({ key: g.key, label: g.key, value: g.n, hot: i === 0 }))} /></div>
          </div>
          <div>
            <h4 className="text-[13px] font-semibold">Most recent</h4>
            <ul className="mt-1 divide-y divide-line">
              {r.recent.slice(0, 10).map((v) => (
                <Row key={`${v.victim}-${v.discovered}`}>
                  <span className="min-w-0 flex-1"><span className="block truncate font-medium">{v.victim}</span><span className="block truncate text-[12px] text-faint">{v.sector ?? 'sector unknown'}</span></span>
                  <span className="shrink-0 rounded-full bg-crit/12 px-2 py-0.5 text-[11px] font-semibold text-crit-ink">{v.group}</span>
                  <span className="w-20 shrink-0 text-right font-mono text-[12px] text-mute">{v.discovered}</span>
                </Row>
              ))}
            </ul>
            <h4 className="mt-4 text-[13px] font-semibold">By sector</h4>
            <p className="mt-1 text-[12.5px] text-mute">{r.sectors.map((s) => `${s.key} ${s.n}`).join(' · ')}</p>
          </div>
          <div className="lg:col-span-2"><Source name={r.source} url={r.url} what={r.what} /></div>
        </div>
      )}
    </SocCard>
  )
}

export function BreachesPanel() {
  const b = F.breaches
  return (
    <SocCard title="Data breaches" prov={['REAL']} sub="Breaches with the accounts exposed; Indian services first">
      {!b ? <Missing what="breaches" /> : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
          <div>
            <div className="flex flex-wrap items-baseline gap-x-3"><span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{nf(b.india.length)}</span><span className="text-[13px] text-mute">Indian services breached · {nf(b.total)} breaches worldwide · {compact(b.accounts)} accounts exposed</span></div>
            <ul className="mt-3 divide-y divide-line">
              {b.india.map((x) => (
                <Row key={x.name}>
                  <span className="min-w-0 flex-1"><span className="block truncate font-medium">{x.title}</span><span className="block truncate text-[12px] text-faint">{x.domain} · {x.classes.slice(0, 4).join(', ')}</span></span>
                  <span className="shrink-0 font-mono text-[12.5px]">{compact(x.accounts)}</span>
                  <span className="w-20 shrink-0 text-right font-mono text-[12px] text-mute">{x.date}</span>
                </Row>
              ))}
            </ul>
          </div>
          <div>
            <h4 className="text-[13px] font-semibold">Breaches per year</h4>
            <div className="mt-2"><Months rows={b.by_year} unit="breaches" /></div>
            <h4 className="mt-5 text-[13px] font-semibold">Largest ever</h4>
            <div className="mt-2"><BarList color="var(--color-text)" rows={b.largest.slice(0, 6).map((x, i) => ({ key: x.name, label: x.title, sub: x.date.slice(0, 4), value: x.accounts, hot: i === 0 }))} /></div>
          </div>
          <div className="lg:col-span-2"><Source name={b.source} url={b.url} what={b.what} /></div>
        </div>
      )}
    </SocCard>
  )
}

export function IcsPanel() {
  const x = F.ics
  return (
    <SocCard title="ICS / OT advisories" prov={['REAL']} sub="CISA's advisories for industrial control systems, the kind that run power, water and transport">
      {!x ? <Missing what="ICS advisories" /> : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <div>
            <div className="flex items-baseline gap-2"><span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{nf(x.total)}</span><span className="text-[13px] text-mute">advisories in the current feed, newest first</span></div>
            <ul className="mt-3 divide-y divide-line">
              {x.recent.slice(0, 12).map((a) => (
                <Row key={a.link}>
                  <span className="min-w-0 flex-1"><a href={a.link} target="_blank" rel="noreferrer" className="block truncate font-medium hover:underline">{a.title.replace(/\s*\(ICS.*$/, '')}</a><span className="block font-mono text-[11.5px] text-faint">{a.id || 'advisory'}</span></span>
                  <span className="w-20 shrink-0 text-right font-mono text-[12px] text-mute">{a.date}</span>
                </Row>
              ))}
            </ul>
          </div>
          <div>
            <h4 className="text-[13px] font-semibold">Vendors in the feed</h4>
            <div className="mt-2"><BarList color={TIER_FILL.High} rows={x.vendors.slice(0, 8).map((v, i) => ({ key: v.key, label: v.key, value: v.n, hot: i === 0 }))} /></div>
          </div>
          <div className="lg:col-span-2"><Source name={x.source} url={x.url} what={x.what} /></div>
        </div>
      )}
    </SocCard>
  )
}

export function SupplyPanel() {
  const s = F.supply
  return (
    <SocCard title="Supply-chain advisories" prov={['REAL']} sub="Critical advisories for open-source packages, the software everyone builds on">
      {!s ? <Missing what="supply-chain" /> : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <div>
            <div className="flex items-baseline gap-2"><span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums">{nf(s.total)}</span><span className="text-[13px] text-mute">critical advisories since {s.since}</span></div>
            <ul className="mt-3 divide-y divide-line">
              {s.recent.slice(0, 12).map((a) => (
                <Row key={a.id}>
                  <span className="min-w-0 flex-1"><span className="block truncate font-medium">{a.summary || a.id}</span><span className="block truncate font-mono text-[11.5px] text-faint">{a.cve ?? a.id} · {a.packages.join(', ') || a.ecosystems.join(', ')}</span></span>
                  {a.cvss != null && <span className="shrink-0 rounded-full bg-crit/12 px-2 py-0.5 font-mono text-[11px] font-semibold text-crit-ink">{a.cvss.toFixed(1)}</span>}
                  <span className="w-20 shrink-0 text-right font-mono text-[12px] text-mute">{a.published}</span>
                </Row>
              ))}
            </ul>
          </div>
          <div>
            <h4 className="text-[13px] font-semibold">Ecosystems</h4>
            <div className="mt-2"><BarList color={TIER_FILL.Critical} rows={s.ecosystems.map((e, i) => ({ key: e.key, label: e.key, value: e.n, hot: i === 0 }))} /></div>
          </div>
          <div className="lg:col-span-2"><Source name={s.source} url={s.url} what={s.what} /></div>
        </div>
      )}
    </SocCard>
  )
}

export function NetworksPanel() {
  const n = F.networks
  return (
    <SocCard title="Anonymisation and criminal networks" prov={['REAL']} sub="Where an attacker hides: Tor exits, netblocks run by criminals, hosts already compromised">
      {!n ? <Missing what="networks" /> : (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            {n.sources.map((s) => (
              <div key={s.name} className="rounded-xl border border-line p-4">
                <div className="text-[13px] font-medium text-mute">{s.name}</div>
                <div className="mt-1.5 text-[28px] font-semibold leading-none tracking-tight tabular-nums">{nf(s.count)}</div>
                <div className="mt-1 text-[12.5px] text-faint">{s.unit}{s.addresses ? ` · ${compact(s.addresses)} addresses` : ''}</div>
                <p className="mt-2 text-[12.5px] leading-snug text-mute">{s.what}</p>
              </div>
            ))}
          </div>
          {n.sources.find((s) => s.largest)?.largest && (
            <>
              <h4 className="mt-5 text-[13px] font-semibold">Largest criminal netblocks (Spamhaus DROP)</h4>
              <ul className="mt-1 divide-y divide-line">
                {n.sources.find((s) => s.largest)!.largest!.map((b) => (
                  <Row key={b.cidr}><span className="flex-1 font-mono text-[12.5px]">{b.cidr}</span><span className="font-mono text-[12px] text-mute">{b.sbl}</span><span className="w-24 text-right font-mono text-[12.5px]">{compact(b.addresses)} addresses</span></Row>
                ))}
              </ul>
            </>
          )}
          <p className="mt-3 text-[11.5px] leading-snug text-faint">{n.sources.map((s) => s.name).join(' · ')}; taken {taken}. Used by the lead's engine to check whether any operator's own address appears on an attacker list.</p>
        </>
      )}
    </SocCard>
  )
}

/** The strip: five boxes, one panel open. */
export function RealFeedsStrip() {
  const r = F.ransomware, b = F.breaches, x = F.ics, s = F.supply, n = F.networks
  return (
    <TabBoxes label="Real-world threat intelligence" defaultOpen="ransomware" items={[
      { key: 'ransomware', title: 'Ransomware in India', chip: <Prov p="REAL" />, count: r ? nf(r.total) : '—',
        preview: r ? `${r.recent[0]?.victim ?? ''} named by ${r.recent[0]?.group ?? ''} on ${r.recent[0]?.discovered ?? ''} · ${r.groups[0]?.key} names the most` : 'ransomware.live', panel: <RansomwarePanel /> },
      { key: 'breaches', title: 'Data breaches', chip: <Prov p="REAL" />, count: b ? nf(b.india.length) : '—',
        preview: b ? `Indian services in Have I Been Pwned; latest ${b.india[0]?.title ?? ''} (${b.india[0]?.date ?? ''}) · ${compact(b.accounts)} accounts exposed worldwide` : 'Have I Been Pwned', panel: <BreachesPanel /> },
      { key: 'ics', title: 'ICS / OT advisories', chip: <Prov p="REAL" />, count: x ? nf(x.total) : '—',
        preview: x ? `Latest: ${x.recent[0]?.title.replace(/\s*\(ICS.*$/, '') ?? ''} (${x.recent[0]?.date ?? ''})` : 'CISA ICS advisories', panel: <IcsPanel /> },
      { key: 'supply', title: 'Supply-chain advisories', chip: <Prov p="REAL" />, count: s ? nf(s.total) : '—',
        preview: s ? `Critical open-source advisories since ${s.since} · ${s.ecosystems.slice(0, 3).map((e) => `${e.key} ${e.n}`).join(' · ')}` : 'GitHub Advisory Database', panel: <SupplyPanel /> },
      { key: 'networks', title: 'Criminal networks', chip: <Prov p="REAL" />, count: n ? nf(n.sources.reduce((t, q) => t + q.count, 0)) : '—',
        preview: n ? n.sources.map((q) => `${nf(q.count)} ${q.unit}`).join(' · ') : 'Tor, Spamhaus, Emerging Threats', panel: <NetworksPanel /> },
    ]} />
  )
}
