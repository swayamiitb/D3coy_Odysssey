// Save real Odyssey API responses into public/demo so the SOC console runs with no backend and no network
// (DEMO mode, CLAUDE.md rule 14). Read-only: GET requests only.
//
//   node scripts/snapshot.mjs                         # backend on http://127.0.0.1:8000
//   node scripts/snapshot.mjs http://127.0.0.1:8000   # or any reachable Odyssey backend
//
// File names follow snapshotFile() in src/data.ts:  /api/a/b?x=1 -> public/demo/api/a/b__x-1.json
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const base = (process.argv[2] ?? process.env.ODYSSEY_API ?? 'http://127.0.0.1:8000').replace(/\/$/, '')
const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'demo')

function fileFor(path) {
  const [p, q] = path.split('?')
  const suffix = q ? '__' + q.split('&').filter(Boolean).sort().join('_').replace(/=/g, '-') : ''
  return join(outDir, ...`${p}${suffix}.json`.split('/').filter(Boolean))
}

let saved = 0
const failed = []
async function save(path, timeoutMs = 120_000) {
  try {
    const res = await fetch(base + path, { signal: AbortSignal.timeout(timeoutMs) })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const body = await res.json()
    const file = fileFor(path)
    await mkdir(dirname(file), { recursive: true })
    await writeFile(file, JSON.stringify(body))
    saved++
    return body
  } catch (e) {
    failed.push(`${path} (${e.message})`)
    return null
  }
}

const health = await save('/api/health', 5000)
if (!health) {
  console.error(`No Odyssey backend at ${base}. Start it first, or pass its URL.`)
  process.exit(1)
}

const [soc] = await Promise.all([
  save('/api/soc'),
  save('/api/approvals?status=pending'),
  save('/api/approvals?status=approved'),
  save('/api/approvals?status=rejected'),
  save('/api/autopilot?limit=300'),
  save('/api/alerts?limit=400'), // landing map: worst real CVE per state
  // Intelligence screens: threat intel, risk plan, ahead of the threat.
  save('/api/intel/sources'),
  save('/api/intel/advisories'),
  save('/api/intel/technologies'),
  save('/api/intel/attacks'),
  save('/api/campaigns'),
  save('/api/riskplan'),
  save('/api/forecast'),
])

// Every organisation gets its profile and its own risk plan (org ids from /api/soc).
const orgs = soc?.orgs ?? []
for (const o of orgs) {
  await Promise.all([save(`/api/orgs/${o.id}/profile`), save(`/api/riskplan?org_id=${encodeURIComponent(o.id)}`)])
  process.stdout.write(`\r${orgs.indexOf(o) + 1}/${orgs.length} organisations saved`)
}
if (orgs.length) process.stdout.write('\n')

const feed = await save('/api/feed')

// Every warning in the feed gets its incident page: detail, replay, brief, workflow and both report drafts.
const cards = feed?.cards ?? []
for (const c of cards) {
  const a = `/api/alerts/${c.org_id}/${c.cve_id}`
  await Promise.all([
    save(a), save(`/api/replay/${c.org_id}/${c.cve_id}`), save(`${a}/brief`), save(`${a}/workflow`),
    save(`${a}/certin-report`), save(`${a}/stix`),
  ])
  process.stdout.write(`\r${cards.indexOf(c) + 1}/${cards.length} warnings saved`)
}

await writeFile(join(outDir, 'manifest.json'), JSON.stringify({ taken_at: new Date().toISOString(), base, files: saved }, null, 2))
console.log(`\nSaved ${saved} responses from ${base} into public/demo.`)
if (failed.length) console.log(`Skipped ${failed.length}:\n  ${failed.slice(0, 20).join('\n  ')}`)
