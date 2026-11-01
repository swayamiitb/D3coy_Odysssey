import { useCallback, useMemo, useState, type CSSProperties } from 'react'
import type { Soc } from '../api'
import { IndiaMap } from '../IndiaMap'
import { Seg, SocCard } from './kit'
import { originsFromData, routesFor, snapshotLabel, targetsFrom, type OriginFilter } from './map/data'
import { OriginRail } from './map/OriginRail'
import { SiteView } from './map/SiteView'
import { WorldMap } from './map/WorldMap'

/* Threat activity (ui-08): the Now page's signature card. World: a real 2D map (world-atlas countries; India from its
   official outline, by state) with the real attack origins (SANS ISC DShield top attacking IPs located by RIPEstat;
   abuse.ch Feodo Tracker botnet C2s) and the Indian operator states (SIM). Attack paths draw only on intent: hover or
   focus an origin in the list or on the map. Click a target state and the card flies into a 3D site view of the
   government agencies there. India: the state hex map and its ranked list, as before. */

type OrgRow = Soc['orgs'][number]

/** Self-contained dark: the black SOC palette, whatever theme the page around it uses. */
const DARK = {
  '--color-ink': '#000000', '--color-panel': '#0e0e10', '--color-soft': '#060607', '--color-panel-2': '#1a1a1d',
  '--color-panel-3': '#26262a', '--color-panel-4': '#141416', '--color-line': '#222225', '--color-line-2': '#2e2e33',
  '--color-text': '#f4f4f5', '--color-mute': '#a1a1a8', '--color-faint': '#76767d', '--color-accent': '#4f8cf7',
  '--color-crit': '#e5383b', '--color-high': '#ff7a3d', '--color-med': '#f5c242', '--color-comp': '#8a63e8', '--color-ok': '#22b45f',
  '--color-crit-ink': '#ff6b66', '--color-high-ink': '#ff9d6b', '--color-comp-ink': '#b49cff', '--color-ok-ink': '#4fd486',
  '--color-map': '#0e0e10', colorScheme: 'dark', background: '#050506', color: '#f4f4f5', borderRadius: '1rem',
} as CSSProperties

const FILTERS: [OriginFilter, string][] = [['all', 'All origins'], ['attack', 'Attack sources'], ['c2', 'Botnet C2']]

export function ThreatMap({ orgs, onOrg }: { orgs?: OrgRow[]; onOrg: (id: string) => void }) {
  const [mode, setMode] = useState<'world' | 'india'>('world')
  const [paths, setPaths] = useState<'hover' | 'all'>('hover')
  const [filter, setFilter] = useState<OriginFilter>('all')
  const [focus, setFocus] = useState<string>()
  const [site, setSite] = useState<string>()

  const all = useMemo(originsFromData, [])
  const targets = useMemo(() => targetsFrom(orgs ?? []), [orgs])
  const allRoutes = useMemo(() => routesFor(all, targets), [all, targets])
  const origins = useMemo(() => (filter === 'all' ? all : all.filter((o) => o.kind === filter)), [all, filter])
  const routes = useMemo(() => allRoutes.filter((r) => filter === 'all' || r.o.kind === filter), [allRoutes, filter])
  const siteTarget = site ? targets.find((t) => t.state === site) : undefined
  const back = useCallback(() => setSite(undefined), [])
  const open = (state: string) => setSite(state)

  const select = (
    <>
      <label className="relative">
        <span className="sr-only">Show origins</span>
        <select value={filter} onChange={(e) => { setFilter(e.target.value as OriginFilter); setFocus(undefined) }}
                className="h-9 appearance-none rounded-lg border border-line bg-panel/90 pl-3 pr-8 text-[13px] font-medium text-text backdrop-blur hover:bg-panel-2 focus-visible:outline-2 focus-visible:outline-accent">
          {FILTERS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        <svg className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-mute" width="12" height="12" viewBox="0 0 12 12" aria-hidden>
          <path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </label>
      <span className="inline-flex h-9 items-center gap-2 rounded-lg border border-line bg-panel/90 px-3 text-[12.5px] text-mute backdrop-blur">
        <span className="h-1.5 w-1.5 rounded-full bg-ok" />Snapshot {snapshotLabel()}
      </span>
    </>
  )

  return (
    <div className="soc-dark rounded-2xl" style={DARK}>
      <SocCard title="Threat activity" prov={['REAL', 'SIM']} className="!bg-[#0e0e10]"
               sub={site ? `Inside ${site}: the government agencies there, and the real attack origins aimed at them`
                 : mode === 'world' ? 'Where attacks start, and the Indian operators they reach. Hover an origin for its attack paths.'
                   : 'Where the warnings are: states by their operators’ Critical warnings'}
               right={
                 <div className="flex flex-wrap items-center gap-2">
                   {mode === 'world' && !site && (
                     <Seg label="Attack paths" value={paths} onChange={setPaths} items={[['hover', 'Paths on hover'], ['all', 'All paths']]} />
                   )}
                   <Seg label="Map" value={mode} onChange={(m) => { setSite(undefined); setMode(m) }} items={[['world', 'World'], ['india', 'India']]} />
                 </div>
               }
               bodyClass="">
        <div className="grid border-t border-line xl:grid-cols-[minmax(0,1fr)_380px]">
          <div className={`relative min-w-0 overflow-hidden rounded-bl-2xl max-xl:rounded-none ${site ? 'h-[560px] sm:h-[580px]' : mode === 'world' ? 'h-[300px] sm:h-[420px] md:h-[500px]' : 'h-[520px]'} xl:h-full xl:min-h-[600px]`}>
            {mode === 'world' ? (
              <WorldMap origins={origins} targets={targets} routes={routes} focus={focus} showAll={paths === 'all'}
                        onFocus={setFocus} onPick={setSite} paused={!!site} topLeft={select} />
            ) : (
              <div className="h-full">{orgs ? <IndiaMap orgs={orgs} onOrg={onOrg} bare /> : <div className="h-full bg-panel-2" />}</div>
            )}
            {siteTarget && <SiteView key={siteTarget.state} target={siteTarget} origins={origins} focus={focus} onBack={back} onOrg={onOrg} />}
          </div>

          <aside className="min-w-0 border-t border-line xl:border-l xl:border-t-0">
            {mode === 'world' ? (
              <OriginRail origins={origins} focus={focus} onFocus={setFocus} />
            ) : (
              <div className="p-4">
                <div className="flex items-baseline justify-between px-1">
                  <h3 className="text-[14px] font-semibold">States by Critical warnings</h3>
                  <span className="text-[12px] text-mute">Critical</span>
                </div>
                <ol className="mt-2 space-y-0.5">
                  {targets.slice(0, 9).map((t, i) => (
                    <li key={t.state}>
                      <button onClick={() => open(t.state)} aria-label={`${t.state}: ${t.orgs.length} operator${t.orgs.length > 1 ? 's' : ''}, ${t.critical} Critical warnings${t.compromise ? ', suspected compromise' : ''}. Open its 3D site view`}
                              className="flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-left transition-colors hover:bg-panel-2">
                        <span className="w-4 text-right font-mono text-[12px] text-mute">{i + 1}</span>
                        <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${t.compromise ? 'bg-comp' : 'bg-crit'}`} />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-[13.5px] font-medium">{t.state}</span>
                          <span className="block text-[12px] text-mute">{t.orgs.length} operator{t.orgs.length > 1 ? 's' : ''}{t.compromise ? ' · suspected compromise' : ''}</span>
                        </span>
                        <span className="font-mono text-[13px]">{t.critical}</span>
                      </button>
                    </li>
                  ))}
                </ol>
                <p className="mt-3 px-1 text-[12px] leading-snug text-mute">Operators are simulated (SIM); their warnings come from real CVEs. Open a state on the map for its operators, or a row here for its 3D site view.</p>
              </div>
            )}
          </aside>
        </div>
      </SocCard>
    </div>
  )
}
