import type { Soc } from '../../api'
import attackers from '../../landing/geo/attackers.json'
import feodo from '../../landing/geo/feodo.json'
import { COUNTRY_CENTROID, STATE_CENTROID, stateName, type LatLng } from '../../landing/geo/geo'

/* Threat activity data (ui-08): where attacks start (REAL: SANS ISC DShield's top attacking IPs located by RIPEstat;
   abuse.ch Feodo Tracker botnet C2 servers), and the Indian operator states they are drawn reaching (SIM: the
   operators are simulated, so which state an arc lands in is simulated too). */

export type OrgRow = Soc['orgs'][number]
export type OriginKind = 'attack' | 'c2'
export type OriginFilter = 'all' | OriginKind

export interface Origin {
  id: string
  cc: string
  kind: OriginKind
  at: LatLng
  /** attack: located IPs among DShield's top list; c2: Feodo C2 servers */
  ips: number
  /** DShield reports (attack sources only; 0 for C2) */
  records: number
  /** share of the attack sources' DShield reports, 0..1 (null for C2) */
  share: number | null
  note: string
  malware: string[]
  /** the network (ASN name) behind the country's most-reported IP, from DShield's IP lookup */
  network?: string | null
}

export interface Target {
  state: string
  at: LatLng
  orgs: OrgRow[]
  gov: OrgRow[]
  critical: number
  compromise: boolean
}

export const ATTACK = '#ff5d8f' // an attack source: an identity shared with the landing story, not a risk tier
export const C2 = '#64d2ff'     // a botnet command-and-control server
export const COMP = '#8a63e8'
export const CRIT = '#e5383b'
export const TAKEN_AT = attackers.taken_at
export const IPS_LOCATED = attackers.ips_located

/** Sectors treated as government agencies and public-sector bodies (they get buildings in the site view). */
export const GOV_SECTORS = new Set(['Government', 'Strategic & Public Enterprises', 'Power & Energy', 'Transport'])
export const isGov = (o: OrgRow) => GOV_SECTORS.has(o.sector)

export function originsFromData(): Origin[] {
  const countries = attackers.countries.filter((c) => /^[A-Z]{2}$/.test(c.country)) // GeoLite's "?" and region codes are not places
  const total = countries.reduce((s, c) => s + c.records, 0) || 1
  const out: Origin[] = countries.map((c) => {
    const net = (c as { top_network?: string | null }).top_network
    const network = net && net !== 'not routed' ? net : null
    return {
      id: `a-${c.country}`, cc: c.country, kind: 'attack' as const, at: [c.lat, c.lon] as LatLng, ips: c.ips, records: c.records,
      share: c.records / total, malware: [], network,
      note: `${c.ips} of DShield's top ${attackers.ips_located.toLocaleString('en-IN')} attacking IPs${c.city ? ` · ${c.city}` : ''}${network ? ` · ${network}` : ''}`,
    }
  })
  const c2 = new Map<string, { n: number; malware: Set<string> }>()
  for (const e of feodo.entries) {
    const v = c2.get(e.country) ?? { n: 0, malware: new Set<string>() }
    v.n += 1
    v.malware.add(e.malware)
    c2.set(e.country, v)
  }
  for (const [cc, v] of c2) {
    const c = COUNTRY_CENTROID[cc]
    if (!c) continue
    // nudged off the centroid; a country that is also an attack source keeps its two markers well apart
    const twin = out.find((o) => o.kind === 'attack' && o.cc === cc && Math.hypot(o.at[0] - c[0], o.at[1] - c[1]) < 6)
    const at: LatLng = twin ? [twin.at[0] - 5, twin.at[1] + 9] : [c[0] - 2.5, c[1] + 3]
    out.push({ id: `c-${cc}`, cc, kind: 'c2', at, ips: v.n, records: 0, share: null, malware: [...v.malware],
               note: `${v.n} Feodo C2 server${v.n > 1 ? 's' : ''} · ${[...v.malware].join(', ')}` })
  }
  return out
}

export function targetsFrom(orgs: OrgRow[]): Target[] {
  const by = new Map<string, Target>()
  for (const o of orgs) {
    const st = stateName(o.state)
    const at = STATE_CENTROID[st]
    if (!at) continue
    const t = by.get(st) ?? { state: st, at, orgs: [], gov: [], critical: 0, compromise: false }
    t.orgs.push(o)
    if (isGov(o)) t.gov.push(o)
    t.critical += o.critical
    t.compromise ||= o.compromise > 0
    by.set(st, t)
  }
  return [...by.values()].sort((a, b) => Number(b.compromise) - Number(a.compromise) || b.critical - a.critical)
}

export interface Route { o: Origin; t: Target }
/** Each origin reaches two of the six operator states with the most Critical warnings (simulated landing points). */
export function routesFor(origins: Origin[], targets: Target[]): Route[] {
  const top = targets.slice(0, 6)
  if (!top.length) return []
  return origins.flatMap((o, i) => {
    const a = top[i % top.length], b = top[(i + 2) % top.length]
    return (a === b ? [a] : [a, b]).map((t) => ({ o, t }))
  })
}

const rad = (d: number) => (d * Math.PI) / 180
/** Initial great-circle bearing from a to b, degrees clockwise from north. */
export function bearing([lat1, lng1]: LatLng, [lat2, lng2]: LatLng): number {
  const [p1, p2, dl] = [rad(lat1), rad(lat2), rad(lng2 - lng1)]
  const b = Math.atan2(Math.sin(dl) * Math.cos(p2), Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(dl))
  return ((b * 180) / Math.PI + 360) % 360
}

/** Push bearings apart (keeping their order) so no two horizons overlap. */
export function spreadBearings<T extends { b: number }>(xs: T[], gapDeg = 14): T[] {
  const out = [...xs].sort((a, b) => a.b - b.b).map((x) => ({ ...x }))
  for (let pass = 0; pass < 10; pass++) {
    for (let i = 1; i < out.length; i++) {
      const d = out[i].b - out[i - 1].b
      if (d < gapDeg) { const push = (gapDeg - d) / 2; out[i - 1].b -= push; out[i].b += push }
    }
  }
  return out
}

/** "31 Oct" from the snapshot's timestamp, in the viewer's time zone. */
export function snapshotLabel(iso = TAKEN_AT): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso.slice(0, 10) : d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })
}
