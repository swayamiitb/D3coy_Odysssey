// Two more real, open feeds, bundled so the console works offline (CLAUDE.md rule 14):
//   blocklist.de   attacking IPs reported in the last 48 hours, by the service they attacked (SSH, web, mail, bots…)
//   Exploit-DB     the public exploit index (GitLab), reduced to the set of CVEs that have a public exploit
//
//   node scripts/real-feeds.mjs            # writes src/soc/data/services.json and public/data/exploitdb.json (served, fetched lazily)
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'soc', 'data')
const pub = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'data')
await mkdir(dir, { recursive: true })
await mkdir(pub, { recursive: true })
const UA = 'odyssey-d3coy (hackathon research; https://github.com/swayamiitb/D3coy_Odysssey)'
const text = async (url) => (await fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(60_000) })).text()
const takenAt = new Date().toISOString()

// blocklist.de: one list per attacked service; a line is an IP
const SERVICES = [
  ['ssh', 'SSH', 'brute force and scans against SSH'],
  ['apache', 'Web servers', 'attacks on Apache, nginx and other web servers'],
  ['mail', 'Mail', 'attacks on mail servers (SMTP, IMAP, POP3)'],
  ['imap', 'IMAP', 'IMAP logins'],
  ['ftp', 'FTP', 'FTP logins'],
  ['sip', 'VoIP (SIP)', 'SIP scans and registrations'],
  ['bots', 'Bots', 'bots: spam, scraping, comment and form abuse'],
  ['ircbot', 'IRC bots', 'IRC command-and-control bots'],
  ['strongips', 'Persistent attackers', 'the IPs reported most, across every service'],
]
const services = []
for (const [key, label, what] of SERVICES) {
  try {
    const body = await text(`https://lists.blocklist.de/lists/${key}.txt`)
    const ips = body.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
    services.push({ key, label, what, ips: ips.length })
    console.log(`${label}: ${ips.length} IPs`)
  } catch (e) {
    console.log(`${label}: failed (${e.message})`)
  }
}
await writeFile(join(dir, 'services.json'), JSON.stringify({
  source: 'blocklist.de', url: 'https://www.blocklist.de/', window: 'last 48 hours', taken_at: takenAt, services,
}, null, 2) + '\n')

// Exploit-DB: files_exploits.csv has one row per exploit; the codes column lists CVE ids ("CVE-2024-1234;CVE-…")
const csv = await text('https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv')
const lines = csv.split('\n')
const head = lines[0].split(',')
const codesIdx = head.indexOf('codes'), dateIdx = head.indexOf('date_published'), idIdx = head.indexOf('id'), verifiedIdx = head.indexOf('verified')
const cves = new Map() // cve -> { exploits, first, verified }
let rows = 0
for (const line of lines.slice(1)) {
  if (!line) continue
  // a light CSV split: quoted fields may hold commas, so walk the quotes
  const cells = []
  let cur = '', q = false
  for (const ch of line) {
    if (ch === '"') q = !q
    else if (ch === ',' && !q) { cells.push(cur); cur = '' }
    else cur += ch
  }
  cells.push(cur)
  rows++
  const codes = (cells[codesIdx] ?? '').match(/CVE-\d{4}-\d{4,}/g)
  if (!codes) continue
  for (const cve of new Set(codes)) {
    const v = cves.get(cve) ?? { exploits: 0, first: cells[dateIdx] ?? '', verified: 0, edb: Number(cells[idIdx]) || null }
    v.exploits++
    if (cells[verifiedIdx] === '1') v.verified++
    if (cells[dateIdx] && (!v.first || cells[dateIdx] < v.first)) { v.first = cells[dateIdx]; v.edb = Number(cells[idIdx]) || v.edb }
    cves.set(cve, v)
  }
}
const sorted = Object.fromEntries([...cves.entries()].sort((a, b) => a[0].localeCompare(b[0])))
await writeFile(join(pub, 'exploitdb.json'), JSON.stringify({
  source: 'Exploit-DB (OffSec) public exploit index', url: 'https://gitlab.com/exploit-database/exploitdb', taken_at: takenAt,
  exploits: rows, cves_with_exploit: cves.size, by_cve: sorted,
}) + '\n')
console.log(`Exploit-DB: ${rows} exploits, ${cves.size} CVEs with a public exploit`)
