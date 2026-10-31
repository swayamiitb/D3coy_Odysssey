import { Activity, Ban, Bug, Check, Crosshair, Globe, Loader2, Play, Server, Shield as ShieldIcon, ShieldAlert, ShieldCheck, Swords, X } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { api, type RedteamReport, type RedteamScenario, type ShieldApp, type ShieldStatus, type Tier } from './api'
import { istTime } from './proactive'
import { Pill, Row, Section, TierPill, useToast } from './ui'

function useShield(ms = 2500): { s?: ShieldStatus; refresh: () => void } {
  const [s, setS] = useState<ShieldStatus>()
  const refresh = useCallback(() => {
    api.shield().then(setS).catch(() => undefined)
  }, [])
  useEffect(() => {
    let alive = true
    const pull = () => api.shield().then((d) => alive && setS(d)).catch(() => undefined)
    pull()
    const id = setInterval(pull, ms)
    return () => { alive = false; clearInterval(id) }
  }, [ms])
  return { s, refresh }
}

function pct(v: number | null): string {
  return v == null ? '—' : `${Math.round(v * 100)}%`
}

/** The protected-app card with the live Monitor/Block toggle. */
function AppCard({ app, onChange }: { app: ShieldApp; onChange: () => void }) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const setMode = (mode: 'monitor' | 'block') => {
    if (mode === app.mode) return
    setBusy(true)
    api.shieldMode(app.id, mode)
      .then(() => { toast(mode === 'block' ? `${app.name}: now blocking attacks inline` : `${app.name}: monitoring only`); onChange() })
      .catch((e) => toast(String(e.message ?? e)))
      .finally(() => setBusy(false))
  }
  return (
    <div className="rounded-3xl bg-band p-7 text-white">
      <div className="flex flex-wrap items-center gap-3">
        <Server size={18} className="text-band-mute" />
        <span className="text-xl font-bold">{app.name}</span>
        <span className="rounded-full bg-band-3 px-2.5 py-0.5 text-xs text-band-mute">{app.framework ?? 'app'}</span>
        <span className="ml-auto flex items-center gap-2 text-sm text-band-mute">
          <span className={`h-2 w-2 rounded-full ${app.mode === 'block' ? 'animate-pulse bg-ok' : 'bg-accent'}`} />
          agent connected
        </span>
      </div>
      {app.base_url && <div className="mt-1 font-mono text-sm text-band-mute">{app.base_url}</div>}
      <div className="mt-5 grid grid-cols-3 gap-3">
        {[['requests', app.requests], ['attacks caught', app.attacks], ['blocked', app.blocked]].map(([k, v]) => (
          <div key={k} className="rounded-2xl bg-band-2 p-4">
            <div className="text-3xl font-bold tabular-nums">{(v as number).toLocaleString('en-IN')}</div>
            <div className="text-xs text-band-mute">{k}</div>
          </div>
        ))}
      </div>
      <div className="mt-5">
        <div className="mb-2 text-sm text-band-mute">Enforcement</div>
        <div className="inline-flex rounded-full bg-band-2 p-1">
          {(['monitor', 'block'] as const).map((m) => (
            <button key={m} disabled={busy} onClick={() => setMode(m)}
                    className={`flex items-center gap-2 rounded-full px-4 py-2 text-sm font-semibold transition disabled:opacity-50 ${app.mode === m ? (m === 'block' ? 'bg-crit text-white' : 'bg-white text-black') : 'text-band-mute hover:text-white'}`}>
              {m === 'monitor' ? <ShieldCheck size={15} /> : <Ban size={15} />}
              {m === 'monitor' ? 'Monitor' : 'Block inline'}
            </button>
          ))}
        </div>
        <p className="mt-2 text-sm text-band-mute">
          {app.mode === 'block'
            ? 'Attacks are dropped before they reach the app (HTTP 403); the source is added to the block list.'
            : 'Attacks are detected and recorded; a block is proposed for an analyst. The app serves every request.'}
        </p>
      </div>
    </div>
  )
}

/** The measured red-team report, shown after a run (mirrors the attack-drill card). */
function ReportCard({ r, onClose }: { r: RedteamReport; onClose: () => void }) {
  const stats = [
    { v: `${r.detected}/${r.attacks_sent}`, k: 'attacks detected', good: r.detected === r.attacks_sent },
    { v: pct(r.detection_rate), k: 'detection rate', good: (r.detection_rate ?? 0) >= 1 },
    { v: `${r.blocked}/${r.attacks_sent}`, k: 'blocked inline', good: r.blocked > 0 },
    { v: pct(r.precision), k: 'precision (no false alarms)', good: (r.precision ?? 0) >= 1 },
    { v: r.mean_ttd_ms != null ? `${Math.round(r.mean_ttd_ms)} ms` : '—', k: 'mean time to detect', good: true },
    { v: `${r.false_positives}`, k: 'false positives', good: r.false_positives === 0 },
  ]
  const byScenario = Object.entries(
    r.cases.filter((c) => c.kind === 'attack').reduce<Record<string, { n: number; hit: number; blk: number }>>((acc, c) => {
      const a = (acc[c.scenario] ??= { n: 0, hit: 0, blk: 0 })
      a.n++; if (c.detected) a.hit++; if (c.blocked) a.blk++
      return acc
    }, {}),
  )
  return (
    <div className="rounded-3xl bg-band p-7 text-white">
      <div className="flex flex-wrap items-center gap-3">
        <Swords size={18} className="text-med" />
        <span className="font-mono text-sm text-band-mute">{r.run_id}</span>
        <span className="rounded-full bg-band-3 px-2.5 py-0.5 text-xs">{r.sent} requests in {(r.duration_ms / 1000).toFixed(1)} s</span>
        <button onClick={onClose} className="ml-auto text-band-mute hover:text-white"><X size={18} /></button>
      </div>
      <h3 className="mt-3 text-2xl font-bold">Red-team result</h3>
      <p className="mt-1 text-sm text-band-mute">
        {r.attacks_sent} real attacks from {r.attacker_ip} and {r.controls_sent} benign requests from a legitimate
        customer ({r.user_ip}), fired over HTTP at {r.target}.
      </p>
      <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3">
        {stats.map((s) => (
          <div key={s.k} className="rounded-2xl bg-band-2 p-4">
            <div className={`text-3xl font-bold tabular-nums ${s.good ? 'text-ok' : 'text-high'}`}>{s.v}</div>
            <div className="mt-1 text-xs text-band-mute">{s.k}</div>
          </div>
        ))}
      </div>
      <div className="mt-6 space-y-2">
        {byScenario.map(([id, a]) => (
          <div key={id} className="flex items-center gap-3 text-sm">
            <span className={`flex h-6 w-6 items-center justify-center rounded-full ${a.hit === a.n ? 'bg-ok' : 'bg-high'}`}>
              {a.hit === a.n ? <Check size={13} /> : <span className="text-xs font-bold">{a.n - a.hit}</span>}
            </span>
            <span className="w-40 font-semibold capitalize">{id}</span>
            <span className="text-band-mute">detected {a.hit}/{a.n}{a.blk ? ` · blocked ${a.blk}` : ''}</span>
          </div>
        ))}
      </div>
      {r.missed_cases.length > 0 && <p className="mt-4 text-sm text-high">Missed: {r.missed_cases.join(', ')}</p>}
      {r.fp_cases.length > 0 && <p className="mt-2 text-sm text-high">False positives: {r.fp_cases.join(', ')}</p>}
      {r.missed_cases.length === 0 && r.fp_cases.length === 0 &&
        <p className="mt-4 text-sm text-ok">Every attack was caught and no benign request was flagged.</p>}
    </div>
  )
}

export function ShieldSection({ onGo }: { onGo: (view: 'soc' | 'now', tab?: string) => void }) {
  const { s, refresh } = useShield()
  const toast = useToast()
  const [cat, setCat] = useState<RedteamScenario[]>([])
  const [busy, setBusy] = useState<string>()
  const [report, setReport] = useState<RedteamReport>()

  useEffect(() => { api.redteamCatalogue().then((d) => setCat(d.scenarios)).catch(() => undefined) }, [])

  const run = (scenario: string) => {
    setBusy(scenario)
    toast(scenario === 'all' ? 'Red-team started: firing real attacks at the app…' : `Red-team: ${scenario}…`)
    api.redteamRun(scenario)
      .then((r) => { setReport(r); refresh(); toast(`Caught ${r.detected}/${r.attacks_sent} attacks in ${(r.duration_ms / 1000).toFixed(1)} s`) })
      .catch((e) => toast(String(e.message ?? e)))
      .finally(() => setBusy(undefined))
  }
  const block = (ip: string, blocked: boolean) => {
    ;(blocked ? api.shieldUnblock(ip) : api.shieldBlock(ip))
      .then(() => { toast(blocked ? `${ip} unblocked` : `${ip} blocked`); refresh() })
      .catch((e) => toast(String(e.message ?? e)))
  }

  if (!s) return <div className="py-6 text-mute"><Loader2 size={16} className="mr-2 inline animate-spin" />Connecting to the HTTP shield…</div>
  const app = s.apps[0]
  const running = busy != null

  return (
    <div className="flex flex-col gap-16">
      <Section title="A real app, protected"
               sub="Odyssey's HTTP shield sits in front of a live web application through a drop-in agent, and inspects every request for attacks — SQL injection, XSS, path traversal, command injection, template/SSRF/Log4Shell, scanning and brute force. This is the same engine working on real traffic, not a simulation.">
        {app ? (
          <div className="grid gap-6 xl:grid-cols-[1.1fr_1fr]">
            <AppCard app={app} onChange={refresh} />
            <div className="flex flex-col gap-3">
              {[
                { icon: Activity, v: s.stats.events, k: 'requests inspected', sub: `${s.stats.sources} distinct sources` },
                { icon: ShieldAlert, v: s.stats.attacks, k: 'attacks detected', sub: `${s.ledger.detections_hour} in the last hour` },
                { icon: Ban, v: s.stats.blocked, k: 'requests blocked inline', sub: `${s.stats.blocklist} sources on the block list` },
                { icon: Crosshair, v: s.stats.attackers, k: 'attackers seen', sub: s.families.length ? s.families.join(', ') : 'none yet' },
              ].map((x) => (
                <div key={x.k} className="flex items-center gap-4 rounded-2xl bg-panel-2 p-4">
                  <x.icon size={20} className="shrink-0 text-mute" />
                  <div className="min-w-0 flex-1">
                    <span className="text-2xl font-bold tabular-nums">{x.v.toLocaleString('en-IN')}</span>
                    <span className="ml-2 font-medium">{x.k}</span>
                    <div className="truncate text-sm text-mute">{x.sub}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="rounded-3xl bg-soft p-8 text-mute">
            <Globe className="mb-3" /> No app is connected yet. Start the bundled target portal, or drop the Odyssey
            agent into your own app (see below), and its requests will appear here.
          </div>
        )}
        <p className="mt-5 text-sm text-mute">
          Connect any app in three lines: <code className="rounded bg-panel-2 px-1.5 py-0.5 font-mono text-[13px]">app.add_middleware(OdysseyShield, app_id="my-app", mode="enforce")</code>.
          Agents ship for ASGI (FastAPI/Starlette/Django), WSGI (Flask) and Express, plus an access-log tailer for apps you can't modify. See <span className="font-mono">agent/README.md</span>.
        </p>
      </Section>

      <Section title="Red-team the shield"
               sub="Prove it. Fire a curated set of real attack requests at the protected app over the wire and watch Odyssey catch and (in block mode) drop them — with the detection rate, block rate, precision and time-to-detect measured, not asserted. Loopback/private targets only; every request is labelled as an exercise in the audit trail.">
        <div className="grid gap-6 xl:grid-cols-[1fr_1.15fr]">
          <div className="flex flex-col gap-3">
            <button disabled={running} onClick={() => run('all')}
                    className="flex items-center justify-center gap-2 rounded-2xl bg-action px-5 py-4 text-base font-semibold text-ink hover:opacity-85 disabled:opacity-40">
              {busy === 'all' ? <Loader2 size={18} className="animate-spin" /> : <Play size={18} />}
              Run all attacks ({cat.reduce((n, c) => n + c.cases, 0)} requests)
            </button>
            <div className="grid gap-2 sm:grid-cols-2">
              {cat.map((c) => (
                <button key={c.id} disabled={running} onClick={() => run(c.id)}
                        className="flex items-start justify-between gap-2 rounded-2xl bg-panel-2 p-4 text-left hover:bg-panel-3 disabled:opacity-40">
                  <span>
                    <span className="block font-semibold">{c.title}</span>
                    <span className="mt-0.5 block text-xs text-mute">{c.what}</span>
                  </span>
                  {busy === c.id ? <Loader2 size={16} className="mt-0.5 shrink-0 animate-spin" /> : <Swords size={16} className="mt-0.5 shrink-0 text-faint" />}
                </button>
              ))}
            </div>
          </div>
          {report ? <ReportCard r={report} onClose={() => setReport(undefined)} /> : (
            <div className="flex items-center justify-center rounded-3xl bg-soft p-10 text-center text-mute">
              Run a scenario to see every attack sent, which were detected and blocked, the time to detect, and that
              benign traffic was left alone.
            </div>
          )}
        </div>
      </Section>

      <div className="grid gap-12 xl:grid-cols-2">
        <Section title="Attacks on the app" sub="Newest first. Each is in the hash-chained audit trail with its CWE, ATT&CK technique and defanged evidence.">
          {s.findings.length === 0 && <div className="rounded-2xl bg-panel-2 p-5 text-mute">No web attacks yet. Run a red-team scenario above.</div>}
          {s.findings.slice(0, 8).map((d) => (
            <Row key={d.id}
                 lead={<ShieldAlert size={18} className={d.decision === 'block' ? 'text-crit' : 'text-high'} />}
                 title={<span className="flex items-center gap-2"><TierPill tier={d.severity as Tier} /> {d.category}</span>}
                 sub={`${d.method} ${d.path} · ${d.cwe} · ${d.attack} ${d.attack_name} · ${d.findings[0]?.evidence ?? ''}`}
                 trail={<span>
                   <span className={`block text-xs font-semibold ${d.decision === 'block' ? 'text-crit' : 'text-high'}`}>{d.decision === 'block' ? 'BLOCKED' : 'flagged'}</span>
                   <span className="block text-xs text-mute">{d.source_ip} · {istTime(d.ts)}</span>
                 </span>} />
          ))}
        </Section>
        <Section title="Attackers" sub="Sources that sent an attack. Block one and the agent drops its traffic inline; unblock to restore.">
          {s.attackers.length === 0 && <div className="rounded-2xl bg-panel-2 p-5 text-mute">No attackers yet.</div>}
          {s.attackers.map((a) => (
            <Row key={a.ip}
                 lead={a.blocked ? <Ban size={18} className="text-crit" /> : <Bug size={18} className="text-high" />}
                 title={<span className="flex items-center gap-2 font-mono">{a.ip} {a.worst && <TierPill tier={a.worst} />}</span>}
                 sub={`${a.attacks} attacks · ${a.families.join(', ')}${a.block_reason ? ` · ${a.block_reason}` : ''}`}
                 trail={<button onClick={() => block(a.ip, a.blocked)}
                                className={`rounded-full px-3.5 py-1.5 text-sm font-semibold ${a.blocked ? 'bg-panel-2 text-text hover:bg-panel-3' : 'bg-crit text-white hover:opacity-85'}`}>
                          {a.blocked ? 'Unblock' : 'Block'}
                        </button>} />
          ))}
        </Section>
      </div>

      <div>
        <Pill onClick={() => onGo('soc', 'cases')}><ShieldIcon size={14} /> A successful web attack opens a SOC incident case — see SOC → Cases</Pill>
      </div>
    </div>
  )
}
