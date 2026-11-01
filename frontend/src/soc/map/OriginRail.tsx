import { compact, countryName } from '../kit'
import { ATTACK, C2, IPS_LOCATED, snapshotLabel, TAKEN_AT, type Origin } from './data'
import { Flag } from './flags'

/* The ranked origins beside the map (ui-08): one row per origin with its flag, kind, share of reports, IPs and
   reports; hovering or focusing a row draws that origin's attack paths on the map. Under it, the attack sources'
   share of DShield reports as one segmented bar, most reported (red) to least (white). */

const RED = [229, 56, 59], WHITE = [244, 244, 245]
export function shadeAt(t: number): string {
  const c = RED.map((r, i) => Math.round(r + (WHITE[i] - r) * Math.max(0, Math.min(1, t))))
  return `rgb(${c.join(',')})`
}
const pct = (v: number) => (v >= 0.1 ? `${(v * 100).toFixed(0)}%` : v >= 0.01 ? `${(v * 100).toFixed(1)}%` : `${(v * 100).toFixed(2)}%`)

export function OriginRail({ origins, focus, onFocus }: { origins: Origin[]; focus?: string; onFocus: (id?: string) => void }) {
  const ranked = [...origins].sort((a, b) => Number(a.kind === 'c2') - Number(b.kind === 'c2') || b.records - a.records || b.ips - a.ips)
  const attacks = ranked.filter((o) => o.kind === 'attack')
  const totalRec = attacks.reduce((s, o) => s + o.records, 0)
  const shade = new Map(attacks.map((o, i) => [o.id, shadeAt(attacks.length > 1 ? i / (attacks.length - 1) : 0)]))
  const grid = 'grid grid-cols-[22px_minmax(0,1fr)_52px_36px_50px] items-center gap-x-2.5'

  return (
    <div className="flex h-full flex-col p-4">
      <div className="flex items-baseline justify-between gap-3 px-1">
        <h3 className="text-[14px] font-semibold">Top attack origins</h3>
        <span className="text-[12px] text-mute">Snapshot {snapshotLabel()}</span>
      </div>

      {attacks.length > 0 && (
        <div className="mt-3 px-1">
          <div className="flex items-baseline justify-between text-[12px] text-mute">
            <span>Share of DShield reports</span>
            <span className="font-mono text-text">{compact(totalRec)}</span>
          </div>
          <div className="mt-1.5 flex h-2.5 w-full gap-[3px]" role="img"
               aria-label={`Share of DShield reports: ${attacks.map((o) => `${countryName(o.cc)} ${pct(o.share ?? 0)}`).join(', ')}`}>
            {attacks.map((o) => (
              <span key={o.id} onMouseEnter={() => onFocus(o.id)} onMouseLeave={() => onFocus(undefined)}
                    className="h-full rounded-[3px] transition-opacity first:rounded-l-full last:rounded-r-full"
                    style={{ flexGrow: Math.max(0.035, o.share ?? 0), flexBasis: 0, background: shade.get(o.id), opacity: focus && focus !== o.id ? 0.35 : 1 }}
                    title={`${countryName(o.cc)}: ${pct(o.share ?? 0)}`} />
            ))}
          </div>
          <div className="mt-1.5 flex items-center gap-2 text-[11.5px] text-mute">
            <span>most reported</span>
            <span className="h-[3px] flex-1 rounded-full" style={{ background: `linear-gradient(90deg, ${shadeAt(0)}, ${shadeAt(1)})` }} />
            <span>least</span>
          </div>
        </div>
      )}

      <div className={`${grid} mt-4 border-b border-line px-2.5 pb-1.5 text-[11px] font-medium uppercase tracking-wide text-mute`} aria-hidden>
        <span />
        <span>Country</span>
        <span className="text-right">Share</span>
        <span className="text-right">IPs</span>
        <span className="text-right">Reports</span>
      </div>
      <ol className="mt-1 flex-1 space-y-0.5" aria-label="Top attack origins: hover or focus one to draw its attack paths">
        {ranked.map((o) => {
          const on = focus === o.id
          const kind = o.kind === 'attack' ? 'Attack source' : `Botnet C2 · ${o.malware.join(', ')}`
          return (
            <li key={o.id}>
              <button onMouseEnter={() => onFocus(o.id)} onMouseLeave={() => onFocus(undefined)} onFocus={() => onFocus(o.id)} onBlur={() => onFocus(undefined)}
                      aria-label={`${countryName(o.cc)}, ${o.kind === 'attack' ? `attack source, ${pct(o.share ?? 0)} of DShield reports, ${o.ips} of the top ${IPS_LOCATED} IPs, ${o.records.toLocaleString('en-IN')} reports` : `botnet C2, ${o.ips} Feodo Tracker server${o.ips > 1 ? 's' : ''}, ${o.malware.join(', ')}`}. Shows its attack paths on the map.`}
                      className={`${grid} relative w-full rounded-lg px-2.5 py-[7px] text-left transition-colors ${on ? 'bg-panel-3' : 'hover:bg-panel-2'}`}>
                {on && <span className="absolute inset-y-1.5 left-0 w-[2px] rounded-full" style={{ background: o.kind === 'attack' ? ATTACK : C2 }} />}
                <Flag cc={o.cc} className="h-[14px] w-[21px]" />
                <span className="min-w-0">
                  <span className="block truncate text-[13.5px] font-medium leading-tight">{countryName(o.cc)}</span>
                  <span className="mt-0.5 flex items-center gap-1.5 truncate text-[11.5px] leading-tight text-mute">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={o.kind === 'attack' ? { background: ATTACK } : { boxShadow: `inset 0 0 0 1.5px ${C2}` }} />
                    <span className="truncate">{kind}</span>
                  </span>
                </span>
                <span className="text-right font-mono text-[12.5px]">
                  {o.kind === 'attack'
                    ? <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-[2px]" style={{ background: shade.get(o.id) }} />{pct(o.share ?? 0)}</span>
                    : <span className="text-mute">—</span>}
                </span>
                <span className="text-right font-mono text-[12.5px]">{o.ips}</span>
                <span className="text-right font-mono text-[12.5px]">{o.kind === 'attack' ? compact(o.records) : <span className="text-mute">{o.ips} C2</span>}</span>
              </button>
            </li>
          )
        })}
      </ol>
      <p className="mt-3 px-1 text-[12px] leading-snug text-mute">
        SANS ISC DShield top attacking IPs, located by RIPEstat, and abuse.ch Feodo Tracker C2 servers, taken {TAKEN_AT.slice(0, 10)}. Which operator each attack path reaches is simulated.
      </p>
    </div>
  )
}
