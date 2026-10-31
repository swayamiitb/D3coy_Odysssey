// Save abuse.ch Feodo Tracker's botnet C2 list into src/geo/feodo.json, bundled into the build so the landing globe's
// world layer is real data that works offline (CLAUDE.md rule 14). The Odyssey API does not expose C2 countries.
//
//   node scripts/feodo.mjs                                              # download the public list
//   node scripts/feodo.mjs D:\D3coy_Odysssey\data\raw\feodo_ipblocklist.json   # or reuse a saved snapshot
import { readFile, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const URL_DEFAULT = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'
const src = process.argv[2] ?? URL_DEFAULT
const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'geo', 'feodo.json')

let rows, takenAt
if (/^https?:/.test(src)) {
  const res = await fetch(src, { signal: AbortSignal.timeout(30_000) })
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${src}`)
  rows = await res.json()
  takenAt = new Date().toISOString()
} else {
  rows = JSON.parse(await readFile(src, 'utf8'))
  takenAt = (await stat(src)).mtime.toISOString() // when that snapshot was saved
}

const entries = rows.map((r) => ({
  ip: r.ip_address, port: r.port, country: r.country, malware: r.malware, status: r.status, last_online: r.last_online,
}))
await writeFile(out, JSON.stringify({ source: 'abuse.ch Feodo Tracker', url: URL_DEFAULT, taken_at: takenAt, entries }, null, 2) + '\n')
console.log(`Saved ${entries.length} C2 servers (${entries.filter((e) => e.status === 'online').length} online) to src/geo/feodo.json`)
