// Five more real, open feeds of different kinds (ui-11), bundled into one file so the console works offline
// (CLAUDE.md rule 14): ransomware leak-site victims in India, data breaches, ICS/OT advisories, open-source
// supply-chain advisories, and anonymisation and criminal networks. No keys, no scraping of pages: public APIs,
// RSS and plain-text lists only.
//
//   node scripts/real-feeds-2.mjs          # writes src/soc/data/realfeeds.json
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'soc', 'data')
await mkdir(dir, { recursive: true })
const UA = 'odyssey-d3coy (hackathon research; https://github.com/swayamiitb/D3coy_Odysssey)'
const text = async (url) => (await fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(60_000) })).text()
const json = async (url) => (await fetch(url, { headers: { 'user-agent': UA, accept: 'application/json' }, signal: AbortSignal.timeout(60_000) })).json()
const takenAt = new Date().toISOString()
const month = (iso) => (iso ?? '').slice(0, 7)
const count = (rows, f) => { const m = new Map(); for (const r of rows) { const k = f(r); if (k) m.set(k, (m.get(k) ?? 0) + 1) } return m }
const topN = (counter, n) => [...counter.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ key: k, n: v }))
const series = (counter, n) => [...counter.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(-n).map(([k, v]) => ({ key: k, n: v }))
const feeds = { taken_at: takenAt }

// 1. ransomware leak-site victims in India (ransomware.live, open API; it answers HTML to some clients, so a saved
//    copy of the same endpoint can be passed with RW_FILE=<path>)
try {
  let rows
  try {
    rows = JSON.parse(await text('https://api.ransomware.live/v2/countryvictims/IN'))
  } catch (e) {
    if (!process.env.RW_FILE) throw e
    rows = JSON.parse((await import('node:fs/promises')).readFile ? await (await import('node:fs/promises')).readFile(process.env.RW_FILE, 'utf8') : '')
    console.log(`ransomware.live: using the saved copy ${process.env.RW_FILE}`)
  }
  const list = (Array.isArray(rows) ? rows : rows.data ?? []).map((r) => ({
    victim: r.website || r.post_title || '', group: r.group_name || r.group || '', sector: r.activity || null,
    discovered: (r.discovered || r.published || '').slice(0, 10), size: r.data_size || null,
  })).filter((r) => r.victim).sort((a, b) => b.discovered.localeCompare(a.discovered))
  feeds.ransomware = {
    source: 'ransomware.live', url: 'https://www.ransomware.live/', what: 'victims in India named on ransomware leak sites',
    total: list.length, groups: topN(count(list, (r) => r.group), 8), sectors: topN(count(list, (r) => r.sector), 8),
    by_month: series(count(list, (r) => month(r.discovered)), 12), by_year: series(count(list, (r) => r.discovered.slice(0, 4)), 6), recent: list.slice(0, 40),
  }
  console.log(`ransomware.live: ${list.length} victims in India`)
} catch (e) { console.log(`ransomware.live failed (${e.message})`) }

// 2. data breaches (Have I Been Pwned, open breaches API)
try {
  const rows = await json('https://haveibeenpwned.com/api/v3/breaches')
  const all = rows.map((b) => ({ name: b.Name, title: b.Title, domain: b.Domain, date: b.BreachDate, accounts: b.PwnCount, verified: !!b.IsVerified, classes: (b.DataClasses ?? []).slice(0, 6) }))
  const india = all.filter((b) => /\.in$/.test(b.domain) || /india/i.test(b.title)).sort((a, b) => b.date.localeCompare(a.date))
  feeds.breaches = {
    source: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/', what: 'data breaches, with the accounts exposed in each',
    total: all.length, accounts: all.reduce((n, b) => n + (b.accounts || 0), 0), verified: all.filter((b) => b.verified).length,
    india, largest: [...all].sort((a, b) => b.accounts - a.accounts).slice(0, 8),
    by_year: series(count(all, (b) => b.date.slice(0, 4)), 10), recent: [...all].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 10),
  }
  console.log(`HIBP: ${all.length} breaches, ${india.length} Indian`)
} catch (e) { console.log(`HIBP failed (${e.message})`) }

// 3. ICS/OT advisories (CISA, RSS)
try {
  const xml = await text('https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml')
  const items = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].map((m) => m[1])
  const field = (it, tag) => {
    const m = it.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))
    return m ? m[1].replace(/^<!\[CDATA\[/, '').replace(/\]\]>$/, '').trim() : ''
  }
  const list = items.map((it) => {
    const title = field(it, 'title').replace(/&amp;/g, '&')
    const id = (title.match(/ICS[A-Z]*-\d{2}-\d{3}-\d{2}/) ?? [''])[0]
    const vendor = title.replace(/\s*\(ICS.*$/, '').split(/\s+/).slice(0, 2).join(' ')
    const d = new Date(field(it, 'pubDate'))
    return { id, title: title.slice(0, 120), vendor, link: field(it, 'link'), date: Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10) }
  }).filter((x) => x.title).sort((a, b) => b.date.localeCompare(a.date))
  feeds.ics = {
    source: 'CISA ICS advisories', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories', what: 'advisories for industrial control systems: power, water, transport, manufacturing',
    total: list.length, vendors: topN(count(list, (x) => x.vendor), 10), by_month: series(count(list, (x) => month(x.date)), 12), recent: list.slice(0, 40),
  }
  console.log(`CISA ICS: ${list.length} advisories`)
} catch (e) { console.log(`CISA ICS failed (${e.message})`) }

// 4. open-source supply-chain advisories (GitHub Advisory Database, critical, latest hundred)
try {
  const rows = await json('https://api.github.com/advisories?per_page=100&severity=critical')
  const list = rows.map((a) => ({
    id: a.ghsa_id, cve: a.cve_id, summary: (a.summary ?? '').replace(/\*\*UNSUPPORTED WHEN ASSIGNED\*\*/g, '').replace(/\s+/g, ' ').trim().slice(0, 110),
    published: (a.published_at ?? '').slice(0, 10), cvss: a.cvss?.score ?? null,
    ecosystems: [...new Set((a.vulnerabilities ?? []).map((v) => v.package?.ecosystem).filter(Boolean))],
    packages: [...new Set((a.vulnerabilities ?? []).map((v) => v.package?.name).filter(Boolean))].slice(0, 3),
  }))
  feeds.supply = {
    source: 'GitHub Advisory Database', url: 'https://github.com/advisories', what: 'critical advisories for open-source packages, the software supply chain',
    total: list.length, since: list.at(-1)?.published ?? '', ecosystems: topN(count(list.flatMap((a) => a.ecosystems), (e) => e), 8), recent: list.slice(0, 40),
  }
  console.log(`GHSA: ${list.length} critical advisories since ${feeds.supply.since}`)
} catch (e) { console.log(`GHSA failed (${e.message})`) }

// 5. anonymisation and criminal networks: Tor exit nodes, Spamhaus DROP netblocks, Emerging Threats compromised hosts
try {
  const tor = (await text('https://check.torproject.org/torbulkexitlist')).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
  const drop = (await text('https://www.spamhaus.org/drop/drop.txt')).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith(';'))
    .map((l) => { const [cidr, sbl] = l.split(';').map((x) => x.trim()); const bits = Number(cidr.split('/')[1] ?? 32); return { cidr, sbl, addresses: 2 ** (32 - bits) } })
  const etc = (await text('https://rules.emergingthreats.net/blockrules/compromised-ips.txt')).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
  feeds.networks = {
    sources: [
      { name: 'Tor Project exit list', url: 'https://check.torproject.org/torbulkexitlist', what: 'Tor exit nodes: traffic that cannot be attributed to a sender', count: tor.length, unit: 'exit nodes' },
      { name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/', what: 'netblocks hijacked or run by criminals, to be dropped at the edge', count: drop.length, unit: 'netblocks', addresses: drop.reduce((n, d) => n + d.addresses, 0), largest: [...drop].sort((a, b) => b.addresses - a.addresses).slice(0, 6) },
      { name: 'Emerging Threats compromised hosts', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', what: 'hosts known to be compromised and used in attacks', count: etc.length, unit: 'hosts' },
    ],
  }
  console.log(`networks: ${tor.length} Tor exits, ${drop.length} DROP netblocks, ${etc.length} compromised hosts`)
} catch (e) { console.log(`networks failed (${e.message})`) }

await writeFile(join(dir, 'realfeeds.json'), JSON.stringify(feeds, null, 1) + '\n')
console.log('Saved src/soc/data/realfeeds.json')
