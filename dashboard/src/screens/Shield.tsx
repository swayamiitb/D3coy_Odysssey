import { Play } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { api, getAnalyst, useLoad, usePoll } from '../data'
import { dateTime, num, pct } from '../format'
import type { RedteamReport, RedteamScenario, ShieldApp, ShieldAttacker, ShieldBlock, ShieldDetection, ShieldMode, ShieldStatus } from '../types'
import { Bars, Button, Empty, ErrorLine, Kpis, Panel, ShowAll, TierMark } from '../ui'
import { ActionError, Freshness, time, useAction } from './Live'

const POLL_MS = 2500

/** Attack families as the shield names them (engine/webattack.py signatures, shield.py behavioural rules). */
const FAMILY: Record<string, string> = {
  sqli: 'SQL injection', xss: 'Cross-site scripting', traversal: 'Path traversal', lfi: 'File inclusion', cmdi: 'Command injection',
  ssti: 'Template injection', ssrf: 'Server-side request forgery', jndi: 'Log4Shell (JNDI)', deser: 'Insecure deserialization',
  crlf: 'Response splitting', probe: 'Admin and secret-file probes', scanner: 'Scanner fingerprint', bruteforce: 'Credential brute force',
  scan: 'Scanning sweep',
}
const family = (f: string) => FAMILY[f] ?? f

/** RFC 5737 documentation ranges: the red team's spoofed sources. Never a real host. */
const docIp = (ip: string) => /^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip)

const MODES: { id: ShieldMode; word: string }[] = [{ id: 'monitor', word: 'Monitor' }, { id: 'block', word: 'Block' }]
const known = (m: string) => m === 'monitor' || m === 'block'

const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`
const list = (xs: string[], cap = 3) => (xs.length <= cap ? xs.join(', ') : `${xs.slice(0, cap).join(', ')} and ${num(xs.length - cap)} more`)

/** Panel body: the content once data exists; else flat bars while loading, or the error with Retry. */
function Body<T>({ data, loading, error, retry, rows = 4, children }: {
  data: T | null; loading: boolean; error: string | null; retry: () => void; rows?: number; children: (d: T) => ReactNode
}) {
  if (data) return <>{children(data)}</>
  return <div className="px-5">{loading ? <Bars rows={rows} /> : <ErrorLine message={error ?? 'no data'} onRetry={retry} />}</div>
}

function Answer({ s }: { s: ShieldStatus }) {
  const names = s.apps.map((a) => a.name).join(', ') || 'the protected app'
  const open = s.attackers.filter((a) => !a.blocked)
  const blocking = s.apps.some((a) => a.mode === 'block')
  const how = blocking
    ? <>In Block mode, attacks rated High or worse are dropped before they reach the app; <span className="num">{num(s.stats.blocked)}</span> requests dropped so far.</>
    : <>No app is in Block mode, so new attacks are flagged, not dropped; only sources on the block list are dropped (<span className="num">{num(s.stats.blocked)}</span> requests so far).</>
  if (s.stats.attackers === 0) {
    return (
      <p className="text-[15px]">
        <span className="font-semibold">No one has attacked {names} since the shield started at <span className="num">{time(s.started)}</span> IST.</span>{' '}
        <span className="text-mute">Run a red-team scenario below to test it.</span>
      </p>
    )
  }
  return (
    <p className="text-[15px]">
      <span className="font-semibold">
        {plural(s.stats.attackers, 'source')} attacked {names}; {open.length === 0 ? 'every one is blocked' : `${num(open.length)} ${open.length === 1 ? 'is' : 'are'} not blocked`}.
      </span>{' '}
      <span className="text-mute">{open.length > 0 && <>Not blocked: <span className="num">{list(open.map((a) => a.ip))}</span>. </>}{how}</span>
    </p>
  )
}

function Apps({ apps, onChanged }: { apps: ShieldApp[]; onChanged: () => void }) {
  const act = useAction()
  const odd = apps.filter((a) => !known(a.mode))
  if (apps.length === 0) {
    return <div className="px-5"><Empty>No app is connected. Start the demo portal, or add the Odyssey agent to an app, and its requests appear here.</Empty></div>
  }
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">App</th>
              <th className="pb-2 font-normal">Address</th>
              <th className="pb-2 pl-4 text-right font-normal">Requests</th>
              <th className="pb-2 pl-4 text-right font-normal">Attacks</th>
              <th className="pb-2 pl-4 text-right font-normal" title="Requests dropped inline with HTTP 403">Blocked</th>
              <th className="px-5 pb-2 text-right font-normal">Mode</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {apps.map((a) => (
              <tr key={a.id}>
                <td className="px-5 py-3">
                  <span className="font-medium">{a.name}</span>
                  <span className="block text-[13px] text-mute">
                    {a.framework ?? 'App'}{a.org_id && <>, run by <a href={`#/orgs/${a.org_id}`} className="text-text underline-offset-2 hover:underline">{a.org_id}</a></>}
                  </span>
                </td>
                <td className="py-3 text-mute">{a.base_url ?? '—'}</td>
                <td className="num py-3 pl-4 text-right">{num(a.requests)}</td>
                <td className="num py-3 pl-4 text-right">{num(a.attacks)}</td>
                <td className="num py-3 pl-4 text-right">{num(a.blocked)}</td>
                <td className="px-5 py-3 text-right">
                  <div className="inline-flex rounded-md bg-ground p-0.5" role="radiogroup" aria-label={`${a.name}: shield mode`}>
                    {MODES.map((m) => (
                      <button key={m.id} type="button" role="radio" aria-checked={a.mode === m.id} disabled={act.busy !== null}
                        onClick={() => a.mode !== m.id && act.run(a.id, () => api.shieldMode(a.id, m.id), onChanged)}
                        className={`h-7 rounded-[5px] px-3 text-[13px] disabled:cursor-not-allowed ${a.mode === m.id ? 'bg-raised text-text' : 'text-mute hover:text-text'}`}>
                        {m.word}
                      </button>
                    ))}
                  </div>
                  {!known(a.mode) && <span className="block pt-1 text-[12px] text-faint">Reports “{a.mode}”: acts as Monitor</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="space-y-1 px-5 pt-2 text-[13px] text-mute">
        <p><span className="text-text">Monitor:</span> attacks are detected and recorded, and a block is proposed in Decisions; the app serves every request.</p>
        <p><span className="text-text">Block:</span> attacks rated High or worse are dropped before they reach the app (HTTP 403) and their source joins the block list.</p>
        {odd.map((a) => (
          <p key={a.id}>{a.name} registered with “{a.mode}” from its agent, which drops whatever Odyssey blocks. Odyssey blocks attacks only in Block mode, so for now they are flagged, not dropped. Choose Block to drop them.</p>
        ))}
        <ActionError err={act.err} />
      </div>
    </>
  )
}

function Detections({ rows }: { rows: ShieldDetection[] }) {
  const [all, setAll] = useState(false)
  if (rows.length === 0) return <div className="px-5"><Empty>No attacks detected yet. Run a red-team scenario to see them here.</Empty></div>
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1100px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">Time (IST)</th>
              <th className="pb-2 font-normal">Severity</th>
              <th className="pb-2 pl-4 font-normal">Attack</th>
              <th className="pb-2 pl-4 font-normal">Request and evidence</th>
              <th className="pb-2 pl-4 font-normal">Source</th>
              <th className="px-5 pb-2 font-normal">Decision</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {(all ? rows : rows.slice(0, 10)).map((d) => {
              const f = d.findings[0]
              return (
                <tr key={d.id} className="align-top">
                  <td className="num px-5 py-2.5 whitespace-nowrap text-mute">{time(d.ts)}</td>
                  <td className="py-2.5"><TierMark tier={d.severity} /></td>
                  <td className="py-2.5 pl-4">
                    <span className="font-medium">{d.category}</span>
                    <span className="block text-[13px] text-mute">{d.cwe} {d.cwe_name}</span>
                    <span className="block text-[13px] text-mute">ATT&amp;CK {d.attack} {d.attack_name}</span>
                  </td>
                  <td className="max-w-[440px] py-2.5 pl-4">
                    <span className="block break-all">{d.method} {d.path}</span>
                    {f && <span className="block truncate text-[13px] text-faint" title={f.why}>{f.surface}{f.param ? ` “${f.param}”` : ''}: {f.evidence}</span>}
                  </td>
                  <td className="py-2.5 pl-4 whitespace-nowrap">
                    <span className="num">{d.source_ip}</span>
                    <span className="block text-[13px] text-mute">{d.redteam ? <>Red team <span className="num">{d.redteam}</span></> : 'Real traffic'}</span>
                  </td>
                  <td className="px-5 py-2.5 whitespace-nowrap">
                    {d.decision === 'block' ? 'Blocked' : 'Allowed, flagged'}
                    {d.success && <span className="block text-[13px] text-mute">App answered 2xx: likely succeeded</span>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-baseline justify-between gap-2 px-5 pt-1">
        <p className="text-[13px] text-mute">Evidence is defanged by the shield. The audit log keeps one entry per source and attack type every 20 seconds.</p>
        <ShowAll total={rows.length} cap={10} open={all} onToggle={() => setAll((v) => !v)} />
      </div>
    </>
  )
}

const blockReason = () => `Blocked by ${getAnalyst()} from the SOC console`

function Attackers({ rows, total, onChanged }: { rows: ShieldAttacker[]; total: number; onChanged: () => void }) {
  const act = useAction()
  if (rows.length === 0) return <div className="px-5"><Empty>No attackers yet: no request has matched an attack signature or a behavioural rule.</Empty></div>
  const toggle = (a: ShieldAttacker) =>
    act.run(a.ip, () => (a.blocked ? api.shieldUnblock(a.ip) : api.shieldBlock(a.ip, blockReason())), onChanged)
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1040px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">Source</th>
              <th className="pb-2 font-normal">Worst</th>
              <th className="pb-2 pl-4 text-right font-normal">Attacks</th>
              <th className="pb-2 pl-4 text-right font-normal">Requests</th>
              <th className="pb-2 pl-6 font-normal">Attack types</th>
              <th className="pb-2 pl-4 font-normal">First seen</th>
              <th className="pb-2 pl-4 font-normal">Status</th>
              <th className="px-5 pb-2 text-right font-normal"><span className="sr-only">Action</span></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {rows.map((a) => (
              <tr key={a.ip} className="align-top">
                <td className="px-5 py-2.5">
                  <span className="num font-medium">{a.ip}</span>
                  <span className="block text-[13px] text-mute">{docIp(a.ip) ? 'Simulated source (documentation address)' : 'Real source address'}</span>
                  {a.ua && <span className="block max-w-[260px] truncate text-[12px] text-faint" title={a.ua}>{a.ua}</span>}
                </td>
                <td className="py-2.5">{a.worst ? <TierMark tier={a.worst} /> : <span className="text-faint">—</span>}</td>
                <td className="num py-2.5 pl-4 text-right">{num(a.attacks)}</td>
                <td className="num py-2.5 pl-4 text-right">{num(a.requests)}</td>
                <td className="py-2.5 pl-6 text-mute">{a.families.map(family).join(', ') || '—'}</td>
                <td className="num py-2.5 pl-4 whitespace-nowrap text-mute">{dateTime(a.first_seen)}</td>
                <td className="py-2.5 pl-4">
                  {a.blocked ? <>Blocked{a.block_reason && <span className="block text-[13px] text-mute">{a.block_reason}</span>}</> : <span className="text-mute">Not blocked</span>}
                </td>
                <td className="px-5 py-2.5 text-right">
                  <Button size="sm" variant={a.blocked ? 'secondary' : 'primary'} disabled={act.busy !== null} onClick={() => toggle(a)}>
                    {act.busy === a.ip ? 'Saving…' : a.blocked ? 'Unblock' : 'Block'}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-5 pt-1">
        {total > rows.length && <p className="text-[13px] text-mute">Showing the {num(rows.length)} worst of {num(total)} attackers.</p>}
        <ActionError err={act.err} />
      </div>
    </>
  )
}

function Blocklist({ rows, onChanged }: { rows: ShieldBlock[]; onChanged: () => void }) {
  const act = useAction()
  if (rows.length === 0) return <div className="px-5"><Empty>The block list is empty: every source can reach the app.</Empty></div>
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="px-5 pb-2 font-normal">Address</th>
              <th className="pb-2 pl-4 font-normal">Reason</th>
              <th className="pb-2 pl-4 font-normal">Added</th>
              <th className="pb-2 pl-4 font-normal">By</th>
              <th className="px-5 pb-2 text-right font-normal"><span className="sr-only">Action</span></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {rows.map((b) => (
              <tr key={b.ip}>
                <td className="num px-5 py-2.5 font-medium">{b.ip}</td>
                <td className="py-2.5 pl-4 text-mute">{b.reason}</td>
                <td className="num py-2.5 pl-4 whitespace-nowrap text-mute">{dateTime(b.at)}</td>
                <td className="py-2.5 pl-4 whitespace-nowrap">{b.auto ? 'Odyssey, automatically' : 'Analyst'}</td>
                <td className="px-5 py-2.5 text-right">
                  <Button size="sm" disabled={act.busy !== null} onClick={() => act.run(b.ip, () => api.shieldUnblock(b.ip), onChanged)}>
                    {act.busy === b.ip ? 'Saving…' : 'Unblock'}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-5 pt-1"><ActionError err={act.err} /></div>
    </>
  )
}

function Report({ r, titles, blocking }: { r: RedteamReport; titles: Record<string, string>; blocking: boolean }) {
  const [all, setAll] = useState(false)
  const by = new Map<string, { n: number; hit: number; blk: number; ctl: number; fp: number }>()
  for (const c of r.cases) {
    const a = by.get(c.scenario) ?? { n: 0, hit: 0, blk: 0, ctl: 0, fp: 0 }
    if (c.kind === 'attack') { a.n++; if (c.detected) a.hit++; if (c.blocked) a.blk++ } else { a.ctl++; if (c.detected) a.fp++ }
    by.set(c.scenario, a)
  }
  const cells = [
    { k: 'Attacks detected', v: `${num(r.detected)} of ${num(r.attacks_sent)}` },
    { k: 'Blocked inline', v: `${num(r.blocked)} of ${num(r.attacks_sent)}` },
    { k: 'Missed', v: num(r.missed) },
    { k: 'Benign requests flagged', v: `${num(r.false_positives)} of ${num(r.controls_sent)}` },
    { k: 'Precision', v: pct(r.precision != null ? r.precision * 100 : null, 0) },
    { k: 'Mean time to detect', v: r.mean_ttd_ms != null ? `${num(r.mean_ttd_ms)} ms` : '—' },
  ]
  return (
    <div className="mt-5 space-y-3 border-t border-line/70 pt-4">
      <div>
        <div className="flex flex-wrap items-baseline justify-between gap-x-3">
          <h3 className="text-[14px] font-medium">Last run: {r.scenario === 'all' ? 'every scenario' : titles[r.scenario] ?? r.scenario}</h3>
          <span className="num text-[12px] text-faint">{r.run_id}, {time(r.started_at)} IST</span>
        </div>
        <p className="mt-0.5 text-[13px] text-mute">
          {plural(r.attacks_sent, 'attack')} from <span className="num">{r.attacker_ip}</span> and {plural(r.controls_sent, 'benign request')} from a
          customer at <span className="num">{r.user_ip}</span>, sent over HTTP to {r.target} in <span className="num">{num(r.duration_ms / 1000, 1)} s</span>.
          Both addresses are documentation ranges: simulated sources, real requests.
        </p>
      </div>
      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
        {cells.map((c) => (
          <div key={c.k} className="rounded-md bg-raised/60 px-3 py-2.5">
            <dt className="text-[12px] text-faint">{c.k}</dt>
            <dd className="num mt-0.5 text-[18px] font-semibold">{c.v}</dd>
          </div>
        ))}
      </dl>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[560px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="pb-2 font-normal">Scenario</th>
              <th className="pb-2 pl-4 text-right font-normal">Attacks</th>
              <th className="pb-2 pl-4 text-right font-normal">Detected</th>
              <th className="pb-2 pl-4 text-right font-normal">Blocked</th>
              <th className="pb-2 pl-4 text-right font-normal">Benign flagged</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {[...by].map(([id, a]) => (
              <tr key={id}>
                <td className="py-2">{titles[id] ?? id}</td>
                <td className="num py-2 pl-4 text-right">{num(a.n)}</td>
                <td className="num py-2 pl-4 text-right">{num(a.hit)}</td>
                <td className="num py-2 pl-4 text-right">{num(a.blk)}</td>
                <td className="num py-2 pl-4 text-right">{a.ctl ? `${num(a.fp)} of ${num(a.ctl)}` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="space-y-1 text-[13px] text-mute">
        {r.missed_cases.length > 0 && <p><span className="text-text">Missed:</span> {r.missed_cases.join(', ')}</p>}
        {r.fp_cases.length > 0 && <p><span className="text-text">Benign requests flagged:</span> {r.fp_cases.join(', ')}</p>}
        {r.missed_cases.length === 0 && r.fp_cases.length === 0 && <p>Every attack was detected and no benign request was flagged.</p>}
        {r.blocked === 0 && r.detected > 0 && <p>None was blocked: {blocking ? 'the attacks were rated below High.' : 'the app was not in Block mode. Switch it to Block above and run again.'}</p>}
      </div>
      <button className="text-[13px] text-mute hover:text-text" onClick={() => setAll((v) => !v)}>{all ? 'Hide the requests' : `Show all ${num(r.sent)} requests`}</button>
      {all && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-[14px]">
            <thead>
              <tr className="text-left text-[12px] text-faint">
                <th className="pb-2 font-normal">Request</th>
                <th className="pb-2 pl-4 font-normal">Kind</th>
                <th className="pb-2 pl-4 text-right font-normal">HTTP</th>
                <th className="pb-2 pl-4 text-right font-normal" title="Request round trip, during which the agent asked the shield">Time</th>
                <th className="pb-2 pl-6 font-normal">Shield verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/70">
              {r.cases.map((c) => (
                <tr key={c.case_id} className="align-top">
                  <td className="py-2"><span>{c.label}</span><span className="block text-[13px] text-faint">{c.method} {c.path}{c.cwe ? `, ${c.cwe}` : ''}</span></td>
                  <td className="py-2 pl-4 text-mute">{c.kind === 'attack' ? 'Attack' : 'Benign'}</td>
                  <td className="num py-2 pl-4 text-right">{c.http_status ?? c.error ?? '—'}</td>
                  <td className="num py-2 pl-4 text-right">{num(c.sent_ms)} ms</td>
                  <td className="py-2 pl-6">
                    {c.detected ? <span className="inline-flex flex-wrap items-center gap-x-2">{c.severity && <TierMark tier={c.severity} />}<span>{c.blocked ? 'Blocked' : 'Flagged'}</span></span>
                      : <span className="text-mute">{c.kind === 'attack' ? 'Not detected' : 'Not flagged'}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function RedTeam({ cat, target, blocking, onRan }: { cat: RedteamScenario[]; target: string; blocking: boolean; onRan: () => void }) {
  const act = useAction()
  const [report, setReport] = useState<RedteamReport | null>(null)
  const titles = Object.fromEntries(cat.map((c) => [c.id, c.title]))
  const total = cat.reduce((n, c) => n + c.cases, 0)
  const run = (id: string) => act.run(id, async () => setReport(await api.redteamRun(id)), onRan)
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3">
        <p className="text-[13px] text-mute">Target: {target}. Each case carries the run id; repeated probes and login attempts count once.</p>
        <Button variant="primary" disabled={act.busy !== null} onClick={() => run('all')}>
          <Play size={14} /> {act.busy === 'all' ? 'Running every scenario…' : `Run all (${num(total)} cases)`}
        </Button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-[14px]">
          <thead>
            <tr className="text-left text-[12px] text-faint">
              <th className="pb-2 font-normal">Scenario and what it sends</th>
              <th className="pb-2 pl-4 text-right font-normal">Cases</th>
              <th className="pb-2 pl-4 text-right font-normal"><span className="sr-only">Run</span></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/70">
            {cat.map((c) => (
              <tr key={c.id}>
                <td className="py-2.5"><span className="font-medium">{c.title}</span><span className="block text-[13px] text-mute">{c.what}</span></td>
                <td className="num py-2.5 pl-4 text-right">{num(c.cases)}</td>
                <td className="py-2.5 pl-4 text-right">
                  <Button size="sm" disabled={act.busy !== null} onClick={() => run(c.id)}><Play size={13} /> {act.busy === c.id ? 'Running…' : 'Run'}</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-[13px] text-mute" aria-live="polite">
        {act.busy && `Sending ${act.busy === 'all' ? 'every scenario' : titles[act.busy] ?? act.busy} to ${target}; the report follows in a few seconds.`}
      </p>
      <ActionError err={act.err} />
      {report && <Report r={report} titles={titles} blocking={blocking} />}
    </>
  )
}

export function Shield() {
  const sh = usePoll(api.shield, 'shield', POLL_MS)
  const cat = useLoad(api.redteamCatalogue, 'redteam:catalogue')
  const s = sh.data
  const open = s?.attackers.filter((a) => !a.blocked).length
  const auto = s?.blocklist.filter((b) => b.auto).length ?? 0
  const target = s?.apps.find((a) => a.base_url)?.base_url ?? 'the protected app'
  const blocking = !!s?.apps.some((a) => a.mode === 'block')
  const frame = { loading: sh.loading, error: sh.error, retry: sh.reload }

  return (
    <div className="space-y-4">
      <div className="space-y-1.5 pb-2">
        <h1 className="text-[26px] font-semibold tracking-tight">HTTP Shield</h1>
        <p className="text-mute">
          A real web app on this machine, with the Odyssey agent in front of it: every request it receives is inspected here for attacks.
          Red-team attacks are real HTTP requests generated on this machine, from simulated documentation-range addresses; nothing leaves the machine.
        </p>
        <Freshness at={sh.at} error={sh.error} onRetry={sh.reload} />
      </div>

      {s && <Answer s={s} />}

      <Kpis items={[
        { label: 'Attackers not blocked', value: num(open), answer: true, sub: s ? `of ${plural(s.stats.attackers, 'attacker')} seen` : undefined },
        { label: 'Attacks detected', value: num(s?.stats.attacks), sub: s ? `in ${plural(s.stats.events, 'request')} inspected` : undefined },
        { label: 'Requests blocked', value: num(s?.stats.blocked), sub: 'Dropped inline, HTTP 403' },
        { label: 'On the block list', value: num(s?.stats.blocklist), sub: s ? `${num(auto)} by Odyssey, ${num(s.blocklist.length - auto)} by an analyst` : undefined },
        { label: 'Attack types seen', value: num(s?.families.length), sub: s ? (s.families.length ? list(s.families.map(family), 2) : 'None yet') : undefined },
        { label: 'Audit-log detections, last hour', value: num(s?.ledger.detections_hour), sub: 'One per source and type every 20 s' },
      ]} />

      <Panel title="Protected app" meta="Real: a web app running on this machine, connected through the Odyssey agent" pad={false}>
        <Body data={s ?? null} {...frame} rows={2}>{(x) => <Apps apps={x.apps} onChanged={sh.reload} />}</Body>
      </Panel>

      <Panel title="Red team" meta="Real HTTP attacks sent from this machine to the protected app, labelled as an exercise in the audit log. Loopback and private targets only">
        {cat.loading ? <Bars rows={4} />
          : cat.error ? <ErrorLine message={cat.error} onRetry={cat.reload} />
          : (cat.data?.scenarios ?? []).length === 0 ? <Empty>The backend lists no red-team scenarios.</Empty>
          : <RedTeam cat={cat.data!.scenarios} target={target} blocking={blocking} onRan={sh.reload} />}
      </Panel>

      <Panel title="Attackers" meta="Every source that sent an attack, worst first. Block one and the agent drops its traffic; unblock to restore it" pad={false}>
        <Body data={s ?? null} {...frame}>{(x) => <Attackers rows={x.attackers} total={x.stats.attackers} onChanged={sh.reload} />}</Body>
      </Panel>

      <Panel title="Detections" meta="Attacks on the app, newest first, with the CWE, the ATT&CK technique and the shield's decision" pad={false}>
        <Body data={s ?? null} {...frame} rows={6}>{(x) => <Detections rows={x.findings} />}</Body>
      </Panel>

      <Panel title="Block list" meta="Sources the agent drops before they reach the app" pad={false}>
        <Body data={s ?? null} {...frame} rows={2}>{(x) => <Blocklist rows={x.blocklist} onChanged={sh.reload} />}</Body>
      </Panel>
    </div>
  )
}
