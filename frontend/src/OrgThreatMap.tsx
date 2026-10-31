import { useEffect, useMemo, useState } from 'react'
import { Prov } from './ui'

/* The organisation threat map. Threats recorded against this operator flow from the left (the outside world: attack
   pressure on its ports, scanning of its products, exploited CVEs, phishing look-alikes, suppliers) into its assets,
   laid out by zone from the internet-facing perimeter to the crown jewels; implants call out to C2 on the right.
   Every element is drawn from stored data and carries its provenance; nothing is decorative. */

/* eslint-disable @typescript-eslint/no-explicit-any */
type Map = any

const TIER_FILL: Record<string, string> = {
  Compromise: 'var(--color-comp)', Critical: 'var(--color-crit)', High: 'var(--color-high)', Medium: 'var(--color-med)', Watch: 'var(--color-panel-3)',
}
const EDGE: Record<string, { color: string; dash?: string; label: string }> = {
  attack: { color: 'var(--color-accent)', label: 'attack pressure on this port (REAL, DShield)' },
  scanning: { color: 'var(--color-high)', label: 'scanning of this product on the decoy grid (SIM)' },
  exploited: { color: 'var(--color-crit)', label: 'exploited-in-the-wild CVE on this asset (REAL, CISA KEV)' },
  beacon: { color: 'var(--color-comp)', dash: '6 4', label: 'implant calling out to a known C2 (SIM sighting, REAL indicator)' },
  reach: { color: 'var(--color-faint)', dash: '2 4', label: 'can reach tier-1 systems if compromised (blast radius)' },
  phishing: { color: 'var(--color-high)', dash: '3 3', label: 'look-alike domains in live phishing feeds (REAL)' },
  supplier: { color: 'var(--color-faint)', dash: '3 3', label: 'a supplier this organisation depends on (SIM)' },
}
const W = 1280, H = 600
const COLS: Record<string, number> = { perimeter: 480, dmz: 690, internal: 900, crown: 1100 }
const C2X = 1235

function layout(m: Map) {
  const pos: Record<string, { x: number; y: number }> = {}
  // threats on the left, grouped by kind, in the order they are listed
  const threats = [...m.threats, ...m.suppliers.map((s: any) => ({ ...s, kind: 'supplier' }))]
  const step = Math.min(44, (H - 80) / Math.max(1, threats.length))
  threats.forEach((t: any, i: number) => { pos[t.id] = { x: 150, y: 60 + i * step + step / 2 } })
  for (const col of Object.keys(COLS)) {
    const nodes = m.nodes.filter((n: any) => n.column === col)
    const s = Math.min(42, (H - 90) / Math.max(1, nodes.length))
    nodes.forEach((n: any, i: number) => { pos[n.id] = { x: COLS[col], y: 70 + i * s + s / 2 + (H - 90 - nodes.length * s) / 2 } })
  }
  m.c2.forEach((c: any, i: number) => { pos[c.id] = { x: C2X, y: 110 + i * 60 } })
  pos.org = { x: COLS.perimeter - 40, y: H - 24 }
  pos.crown = { x: COLS.crown, y: 56 }
  return { pos, threats }
}

function curve(a: { x: number; y: number }, b: { x: number; y: number }) {
  const mx = (a.x + b.x) / 2
  return `M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`
}

export function OrgThreatMap({ orgId, onAlert }: { orgId: string; onAlert?: (orgId: string, cveId: string) => void }) {
  const [m, setM] = useState<Map>()
  const [err, setErr] = useState<string>()
  const [hover, setHover] = useState<string>()
  useEffect(() => {
    let alive = true
    const pull = () => fetch(`/api/orgs/${orgId}/threatmap`).then((r) => r.json()).then((d) => alive && setM(d)).catch((e) => setErr(String(e)))
    pull()
    const id = setInterval(pull, 10000)
    return () => { alive = false; clearInterval(id) }
  }, [orgId])
  const L = useMemo(() => (m ? layout(m) : undefined), [m])
  if (err) return <div className="rounded-2xl bg-panel-2 p-5 text-crit">{err}</div>
  if (!m || !L) return <div className="rounded-2xl bg-panel-2 p-5 text-mute">Drawing the threat map from the record…</div>
  const { pos, threats } = L
  const linked = new Set<string>()
  if (hover) for (const e of m.edges) if (e.from === hover || e.to === hover) { linked.add(e.from); linked.add(e.to) }
  const dim = (id: string) => (hover && !linked.has(id) && id !== hover ? 0.25 : 1)
  const node = (id: string) => m.nodes.find((n: any) => n.id === id)
  const hoverNode = hover ? node(hover) : undefined
  const hoverThreat = hover ? threats.find((t: any) => t.id === hover) : undefined
  const hoverC2 = hover ? m.c2.find((c: any) => c.id === hover) : undefined
  const s = m.summary

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-sm">
        <span><b>{s.exposed}</b> <span className="text-mute">internet-facing</span></span>
        <span><b>{s.open_high}</b> <span className="text-mute">High or worse warnings</span></span>
        <span><b>{s.exploited_cves}</b> <span className="text-mute">exploited CVEs</span></span>
        <span><b className={s.beacons ? 'text-comp' : ''}>{s.beacons}</b> <span className="text-mute">implant{s.beacons === 1 ? '' : 's'} calling out</span></span>
        <span><b className={s.elevated_ports ? 'text-crit' : ''}>{s.elevated_ports}</b> <span className="text-mute">ports under elevated attack</span></span>
        <span><b>{s.lookalikes}</b> <span className="text-mute">look-alike domains</span></span>
        <span className="ml-auto text-xs text-mute">{s.shown} of {s.assets} assets drawn · refreshes every 10 s</span>
      </div>
      <div className="overflow-x-auto rounded-3xl bg-soft p-2">
        <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full min-w-[960px]" data-threatmap role="img" aria-label={`Threat map of ${m.org.name}`}
             onMouseLeave={() => setHover(undefined)}>
          <text x={150} y={34} textAnchor="middle" className="fill-text" fontSize={13} fontWeight={700}>Threats recorded against it</text>
          {Object.entries(COLS).map(([k, x]) => (
            <g key={k}>
              <text x={x} y={34} textAnchor="middle" className="fill-text" fontSize={13} fontWeight={700}>{m.columns.find((c: any) => c.id === k)?.label}</text>
              <line x1={x} y1={44} x2={x} y2={H - 44} stroke="var(--color-line)" strokeDasharray="2 6" />
            </g>
          ))}
          {m.c2.length > 0 && <text x={C2X} y={34} textAnchor="middle" className="fill-text" fontSize={13} fontWeight={700}>Calls out</text>}

          {m.edges.map((e: any, i: number) => {
            const a = pos[e.from], b = pos[e.to]
            if (!a || !b) return null
            const st = EDGE[e.kind]
            const w = 0.8 + Math.min(3, e.weight) * 0.9
            return <path key={i} d={curve(a, b)} fill="none" stroke={st.color} strokeWidth={w} strokeDasharray={st.dash}
                         opacity={0.55 * dim(e.from) * dim(e.to)} className={e.kind === 'beacon' ? 'animate-pulse' : ''} />
          })}

          {threats.map((t: any) => {
            const p = pos[t.id]
            const hot = t.elevated || t.kind === 'exploited' || (t.kind === 'scanning' && (t.live_z ?? 0) >= 4)
            return (
              <g key={t.id} transform={`translate(${p.x},${p.y})`} opacity={dim(t.id)} onMouseEnter={() => setHover(t.id)} style={{ cursor: 'default' }}>
                <rect x={-140} y={-15} width={150} height={30} rx={15} fill={hot ? 'var(--color-band)' : 'var(--color-panel)'} stroke="var(--color-line)" />
                <text x={t.kind === 'attack' ? -92 : -65} y={4} textAnchor={t.kind === 'attack' ? 'start' : 'middle'} fontSize={11} fontWeight={600} fill={hot ? '#fff' : 'var(--color-text)'}>
                  {(t.label as string).slice(0, 24)}
                </text>
                {t.kind === 'attack' && t.series?.length > 1 && (
                  <polyline points={t.series.slice(-14).map((v: number, i: number, arr: number[]) => `${-133 + i * 2.8},${9 - (12 * v) / Math.max(1, ...arr)}`).join(' ')}
                            fill="none" stroke={hot ? 'var(--color-high)' : 'var(--color-accent)'} strokeWidth={1.3} />
                )}
              </g>
            )
          })}

          {m.nodes.map((n: any) => {
            const p = pos[n.id]
            const r = n.aggregate ? 14 : n.column === 'crown' ? 13 : n.asset_tier <= 2 ? 11 : 9
            return (
              <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={dim(n.id)} onMouseEnter={() => setHover(n.id)}
                 onClick={() => n.cves?.[0] && onAlert?.(orgId, n.cves[0].cve)} style={{ cursor: n.cves?.length ? 'pointer' : 'default' }}>
                {n.beacon && <circle r={r + 7} fill="none" stroke="var(--color-comp)" strokeWidth={2} className="animate-pulse" />}
                {n.anomaly && <circle r={r + 4} fill="none" stroke="var(--color-high)" strokeWidth={2} strokeDasharray="3 2" />}
                <circle r={r} fill={n.aggregate ? 'var(--color-panel)' : TIER_FILL[n.worst]} stroke={n.aggregate ? 'var(--color-line)' : 'var(--color-panel)'} strokeWidth={2} />
                {n.kev > 0 && !n.aggregate && <text y={4} textAnchor="middle" fontSize={10} fontWeight={700} fill="#fff">{n.kev}</text>}
                {n.aggregate && <text y={4} textAnchor="middle" fontSize={9} fontWeight={700} fill="var(--color-text)">+{n.aggregate}</text>}
                <text x={r + 6} y={4} fontSize={11} fill={n.aggregate ? 'var(--color-text)' : 'var(--color-mute)'} fontWeight={n.aggregate ? 600 : 400}>{n.host}</text>
              </g>
            )
          })}

          {m.c2.map((c: any) => (
            <g key={c.id} transform={`translate(${pos[c.id].x},${pos[c.id].y})`} opacity={dim(c.id)} onMouseEnter={() => setHover(c.id)}>
              <rect x={-24} y={-14} width={48} height={28} rx={6} fill="var(--color-comp)" />
              <text y={4} textAnchor="middle" fontSize={10} fontWeight={700} fill="#fff">C2</text>
            </g>
          ))}
          {m.edges.some((e: any) => e.to === 'org') && (
            <g transform={`translate(${pos.org.x},${pos.org.y})`}>
              <rect x={-70} y={-13} width={140} height={26} rx={13} fill="var(--color-panel)" stroke="var(--color-line)" />
              <text y={4} textAnchor="middle" fontSize={11} fontWeight={600} className="fill-text">the organisation</text>
            </g>
          )}
          {m.edges.some((e: any) => e.to === 'crown') && (
            <g transform={`translate(${pos.crown.x},${pos.crown.y})`}>
              <rect x={-52} y={-9} width={104} height={18} rx={9} fill="var(--color-panel)" stroke="var(--color-line)" />
              <text y={4} textAnchor="middle" fontSize={9} fill="var(--color-mute)">reachable from outside</text>
            </g>
          )}
        </svg>
      </div>

      <div className="mt-3 min-h-[3.5rem] rounded-2xl bg-panel-2 px-5 py-3 text-sm">
        {hoverNode && !hoverNode.aggregate && (
          <div className="flex flex-wrap gap-x-5 gap-y-1">
            <span className="font-semibold">{hoverNode.hostname}</span>
            <span className="text-mute">{hoverNode.label} {hoverNode.version} · {hoverNode.zone} · {hoverNode.role} · tier {hoverNode.asset_tier}</span>
            <span><b>{hoverNode.worst}</b> · {hoverNode.open} open warning{hoverNode.open === 1 ? '' : 's'}{hoverNode.kev ? ` · ${hoverNode.kev} exploited in the wild` : ''}{hoverNode.reach ? ` · reaches ${hoverNode.reach} tier-1 system(s)` : ''}</span>
            {hoverNode.beacon && <span className="font-semibold text-comp">calling C2 {hoverNode.beacon.c2}{hoverNode.beacon.malware ? ` (${hoverNode.beacon.malware})` : ''}</span>}
            {hoverNode.cves.length > 0 && <span className="font-mono text-xs text-mute">{hoverNode.cves.map((c: any) => c.cve).join(' · ')}{hoverNode.cves.length ? ' · click to open' : ''}</span>}
          </div>
        )}
        {hoverNode?.aggregate && <span className="text-mute">{hoverNode.hostname}; drawn as one circle to keep the map readable. The lines into it are the threats against those systems.</span>}
        {hoverThreat && (
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
            <span className="font-semibold">{hoverThreat.label}</span>
            <Prov p={hoverThreat.provenance?.startsWith('REAL') ? 'REAL' : 'SIM'} label={hoverThreat.provenance} />
            <span className="text-mute">{hoverThreat.source}</span>
            {hoverThreat.kind === 'attack' && hoverThreat.ratio != null && <span>{hoverThreat.last7_mean?.toLocaleString('en-IN')} attack records a day from {hoverThreat.sources_last7?.toLocaleString('en-IN')} sources · <b className={hoverThreat.elevated ? 'text-crit' : ''}>{hoverThreat.ratio >= 1 ? '+' : ''}{Math.round((hoverThreat.ratio - 1) * 100)}%</b> vs the 28-day median</span>}
            {hoverThreat.kind === 'scanning' && <span>{hoverThreat.surge ? `surge ${hoverThreat.surge.first} → ${hoverThreat.surge.last}, z ${hoverThreat.surge.z} on ${hoverThreat.surge.sensors} sensors` : 'no surge in the record'}{hoverThreat.live_z != null ? ` · live z ${hoverThreat.live_z}` : ''}</span>}
            {hoverThreat.kind === 'exploited' && <span>on {hoverThreat.assets} asset{hoverThreat.assets === 1 ? '' : 's'} here</span>}
            {hoverThreat.kind === 'phishing' && <span className="font-mono text-xs">{hoverThreat.hosts.join(' · ')}</span>}
            {hoverThreat.kind === 'supplier' && <span>{hoverThreat.service} · runs {hoverThreat.runs.join(', ')} · {hoverThreat.critical_cves} Critical CVE{hoverThreat.critical_cves === 1 ? '' : 's'} on those products</span>}
          </div>
        )}
        {hoverC2 && <span><b className="text-comp">C2 {hoverC2.label}</b> <span className="text-mute">· {hoverC2.malware ?? 'known C2'} · {hoverC2.source} · {hoverC2.provenance}</span></span>}
        {!hover && <span className="text-mute">Hover an asset, a threat or a C2 for the record behind it; click an asset to open its worst warning.</span>}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-mute">
        {Object.entries(EDGE).filter(([k]) => m.edges.some((e: any) => e.kind === k)).map(([k, st]) => (
          <span key={k} className="flex items-center gap-1.5"><svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke={st.color} strokeWidth="2.5" strokeDasharray={st.dash} /></svg>{st.label}</span>
        ))}
        {['Compromise', 'Critical', 'High', 'Medium', 'Watch'].map((t) => (
          <span key={t} className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full" style={{ background: TIER_FILL[t] }} />{t === 'Watch' ? 'no open warning' : t}</span>
        ))}
        <span className="flex items-center gap-1"><span className="flex h-3.5 w-3.5 items-center justify-center rounded-full bg-crit text-[8px] font-bold text-white">n</span>exploited CVEs on the asset</span>
      </div>
    </div>
  )
}
