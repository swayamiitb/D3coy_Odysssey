// Where the world's attackers are: SANS ISC DShield's most-reported attacking IPs (real), located by country with
// RIPEstat (RIPE NCC's public API, MaxMind GeoLite data), bundled into src/landing/geo/attackers.json so the console's
// threat map and the landing's attack arrows work offline (CLAUDE.md rule 14). The Odyssey API lists the IPs but not
// where they are. Each country keeps the location of its most-reported IP, its top network (DShield's IP lookup:
// ASN and name), and its share of every located report.
//
//   node scripts/landing-attackers.mjs                                 # DShield's own API, top 2000 attacking IPs
//   TOP_IPS=100 node scripts/landing-attackers.mjs                     # fewer
//   node scripts/landing-attackers.mjs D:\D3coy_Odysssey\data\raw\dshield\sources.json   # or a saved list
import { readFile, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const TOP_IPS = Number(process.env.TOP_IPS ?? 2000) // the most-reported IPs to locate
const KEEP = Number(process.env.KEEP ?? 60)         // countries to keep (by reports)
const CONCURRENCY = 8
const UA = 'odyssey-d3coy (hackathon research; https://github.com/swayamiitb/D3coy_Odysssey)'
const src = process.argv[2] ?? `https://isc.sans.edu/api/sources/attacks/${TOP_IPS}?json`
const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'landing', 'geo', 'attackers.json')

const getJson = async (url) => (await fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(25_000) })).json()

let sources, takenAt
if (/^https?:/.test(src)) {
  const body = await getJson(src)
  sources = body.dshield?.top_sources ?? body
  takenAt = new Date().toISOString()
} else {
  sources = JSON.parse(await readFile(src, 'utf8'))
  takenAt = (await stat(src)).mtime.toISOString()
}
sources = [...sources].map((s) => ({ ip: s.ip, count: Number(s.count ?? 0), attacks: Number(s.attacks ?? 0), firstseen: s.firstseen, lastseen: s.lastseen }))
  .sort((a, b) => b.count - a.count).slice(0, TOP_IPS)
console.log(`${sources.length} attacking IPs to locate`)

// locate every IP (a small worker pool, so a public service is not hammered)
const located = []
let next = 0, done = 0
async function worker() {
  while (next < sources.length) {
    const s = sources[next++]
    try {
      const body = await getJson(`https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encodeURIComponent(s.ip)}&sourceapp=odyssey-d3coy`)
      const loc = body.data?.located_resources?.[0]?.locations?.[0]
      // GeoLite answers "?" or a region code (EU, AP) for some IPs; only real country codes are kept
      if (loc?.country && /^[A-Z]{2}$/.test(loc.country) && !['EU', 'AP', 'A1', 'A2'].includes(loc.country)) located.push({ ...s, country: loc.country, lat: loc.latitude, lon: loc.longitude, city: loc.city || null })
    } catch (e) {
      console.log(`${s.ip}: lookup failed (${e.message})`)
    }
    if (++done % 200 === 0) console.log(`${done}/${sources.length} located`)
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker))
console.log(`${located.length} of ${sources.length} IPs located`)

const byCountry = new Map()
for (const s of located) {
  const c = byCountry.get(s.country) ?? { country: s.country, ips: 0, records: 0, targets: 0, lat: s.lat, lon: s.lon, city: s.city, top_ip: s.ip, top_ip_records: s.count, first_seen: s.firstseen, last_seen: s.lastseen }
  c.ips++
  c.records += s.count
  c.targets += s.attacks
  if (s.count > c.top_ip_records) { c.top_ip = s.ip; c.top_ip_records = s.count; c.lat = s.lat; c.lon = s.lon; c.city = s.city }
  if (s.firstseen && (!c.first_seen || s.firstseen < c.first_seen)) c.first_seen = s.firstseen
  if (s.lastseen && (!c.last_seen || s.lastseen > c.last_seen)) c.last_seen = s.lastseen
  byCountry.set(s.country, c)
}
const countries = [...byCountry.values()].sort((a, b) => b.records - a.records).slice(0, KEEP)

// the top network behind each kept country: DShield's IP lookup (ASN, name, the feeds that saw it)
for (const c of countries) {
  try {
    const body = await getJson(`https://isc.sans.edu/api/ip/${c.top_ip}?json`)
    const ip = body.ip ?? {}
    c.top_asn = ip.as ?? null
    c.top_network = ip.asname ?? null
    c.top_ip_feeds = ip.threatfeeds ? Object.keys(ip.threatfeeds) : []
  } catch (e) {
    console.log(`${c.top_ip}: DShield lookup failed (${e.message})`)
  }
  await new Promise((r) => setTimeout(r, 150))
}

const totalRecords = located.reduce((n, s) => n + s.count, 0)
await writeFile(out, JSON.stringify({
  source: 'SANS ISC DShield top attacking IPs', located_by: 'RIPEstat (MaxMind GeoLite)', networks_by: 'SANS ISC DShield IP lookup',
  taken_at: takenAt, ips_requested: sources.length, ips_located: located.length, records_located: totalRecords, countries,
}, null, 2) + '\n')
console.log(`Saved ${countries.length} countries (${totalRecords.toLocaleString()} reports) to src/landing/geo/attackers.json`)
