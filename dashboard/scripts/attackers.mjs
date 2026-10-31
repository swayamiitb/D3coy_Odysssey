// Where the world's top attackers are: SANS ISC DShield's most-reported attacking IPs (real), located by country with
// RIPEstat (RIPE NCC's public API, MaxMind GeoLite data), bundled into src/geo/attackers.json so the landing's attack
// arrows work offline (CLAUDE.md rule 14). The Odyssey API lists the IPs but not where they are.
//
//   node scripts/attackers.mjs                                                  # top sources from the running API
//   node scripts/attackers.mjs D:\D3coy_Odysssey\data\raw\dshield\sources.json  # or the backend's saved list (100 IPs)
import { readFile, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = process.argv[2] ?? 'http://127.0.0.1:8000/api/intel/attacks'
const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'geo', 'attackers.json')
const TOP_IPS = Number(process.env.TOP_IPS ?? 100) // the most-reported IPs to locate
const KEEP = 7 // countries to keep

let sources, takenAt
if (/^https?:/.test(src)) {
  const body = await (await fetch(src, { signal: AbortSignal.timeout(20_000) })).json()
  sources = body.dshield?.top_sources ?? body
  takenAt = new Date().toISOString()
} else {
  sources = JSON.parse(await readFile(src, 'utf8'))
  takenAt = (await stat(src)).mtime.toISOString()
}
sources = [...sources].sort((a, b) => (b.count ?? 0) - (a.count ?? 0)).slice(0, TOP_IPS)

const byCountry = new Map()
for (const s of sources) {
  const url = `https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encodeURIComponent(s.ip)}&sourceapp=odyssey-d3coy`
  try {
    const body = await (await fetch(url, { signal: AbortSignal.timeout(20_000) })).json()
    const loc = body.data?.located_resources?.[0]?.locations?.[0]
    if (!loc?.country) { console.log(`${s.ip}: no location`); continue }
    // Each country keeps the location of its most-reported IP (sources are sorted by reports), not the country centre.
    const c = byCountry.get(loc.country) ?? { country: loc.country, ips: 0, records: 0, targets: 0, lat: loc.latitude, lon: loc.longitude, city: loc.city || null }
    c.ips++
    c.records += s.count ?? 0
    c.targets += s.attacks ?? 0
    byCountry.set(loc.country, c)
    console.log(`${s.ip}: ${loc.country}`)
  } catch (e) {
    console.log(`${s.ip}: lookup failed (${e.message})`)
  }
  await new Promise((r) => setTimeout(r, 250)) // be polite to a public service
}

const countries = [...byCountry.values()].sort((a, b) => b.records - a.records).slice(0, KEEP)
await writeFile(out, JSON.stringify({
  source: 'SANS ISC DShield top attacking IPs', located_by: 'RIPEstat (MaxMind GeoLite)', taken_at: takenAt,
  ips_located: sources.length, countries,
}, null, 2) + '\n')
console.log(`Saved ${countries.length} countries to src/geo/attackers.json`)
