import { useEffect, useState } from 'react'
import type { Soc } from '../api'

/* The analyst's profile: the sector and the organisation they are responsible for. Everything ranked "for you"
   (the incoming CVE stream, the recommendations) reads it; empty means the national desk. Kept per browser. */

export interface Profile { orgs: string[]; sectors: string[] }
const KEY = 'odyssey.profile'
const EVENT = 'odyssey-profile'

export function getProfile(): Profile {
  try {
    const p = JSON.parse(localStorage.getItem(KEY) || '{}') as Partial<Profile>
    return { orgs: Array.isArray(p.orgs) ? p.orgs : [], sectors: Array.isArray(p.sectors) ? p.sectors : [] }
  } catch { return { orgs: [], sectors: [] } }
}
export function saveProfile(p: Profile) {
  try { localStorage.setItem(KEY, JSON.stringify(p)) } catch { /* private window */ }
  window.dispatchEvent(new CustomEvent(EVENT))
}
export function useProfile(): [Profile, (p: Profile) => void] {
  const [p, setP] = useState<Profile>(getProfile)
  useEffect(() => {
    const on = () => setP(getProfile())
    window.addEventListener(EVENT, on)
    return () => window.removeEventListener(EVENT, on)
  }, [])
  return [p, saveProfile]
}
export const profileQuery = (p: Profile) => `org=${encodeURIComponent(p.orgs.join(','))}&sector=${encodeURIComponent(p.sectors.join(','))}`
export function profileLabel(p: Profile, orgs?: Soc['orgs']): string {
  const org = p.orgs[0] ? orgs?.find((o) => o.id === p.orgs[0])?.name ?? p.orgs[0] : undefined
  return org ? `for ${org}` : p.sectors[0] ? `for ${p.sectors[0]}` : 'for the national desk'
}

const SEL = 'h-9 appearance-none rounded-lg border border-line bg-panel pl-3 pr-8 text-[13px] font-medium text-text hover:bg-panel-2 focus-visible:outline-2 focus-visible:outline-accent'

/** Two small selects: sector, then organisation. "Everything" is the national desk. */
export function ProfilePicker({ orgs }: { orgs?: Soc['orgs'] }) {
  const [p, set] = useProfile()
  const sectors = [...new Set((orgs ?? []).map((o) => o.sector))].sort()
  const inSector = (orgs ?? []).filter((o) => !p.sectors[0] || o.sector === p.sectors[0])
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-[12px] font-medium uppercase tracking-wide text-faint">Ranked for</span>
      <label className="relative">
        <span className="sr-only">Your sector</span>
        <select value={p.sectors[0] ?? ''} onChange={(e) => set({ sectors: e.target.value ? [e.target.value] : [], orgs: [] })} className={SEL}>
          <option value="">Every sector</option>
          {sectors.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </label>
      <label className="relative">
        <span className="sr-only">Your organisation</span>
        <select value={p.orgs[0] ?? ''} onChange={(e) => set({ ...p, orgs: e.target.value ? [e.target.value] : [] })} className={SEL}>
          <option value="">{p.sectors[0] ? `Every ${p.sectors[0]} operator` : 'Every organisation'}</option>
          {inSector.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
        </select>
      </label>
    </div>
  )
}
