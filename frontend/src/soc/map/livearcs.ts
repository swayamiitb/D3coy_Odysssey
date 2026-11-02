import type { Soc } from '../../api'
import feodo from '../../landing/geo/feodo.json'
import { COUNTRY_CENTROID, STATE_CENTROID, stateName } from '../../landing/geo/geo'
import type { LiveArc } from './ThreatGlobe'

/* The live engine's beacon detections as arcs for the maps: the operator's state to the C2's country (abuse.ch Feodo
   Tracker locates the C2; the operator and the sighting are SIM). */

export interface Detection { id: string; ts: string; kind: string; title: string; org_id?: string; asset?: string; c2?: string; drill?: string | null }

const refang = (s: string) => s.replace(/\[\.\]/g, '.').replace(/^hxxp/, 'http')
const C2_COUNTRY = new Map(feodo.entries.map((e) => [e.ip, e.country]))

export function liveArcs(detections: Detection[] | undefined, orgs: Soc['orgs'] | undefined): LiveArc[] {
  if (!detections || !orgs) return []
  const state = new Map(orgs.map((o) => [o.id, stateName(o.state)]))
  const out: LiveArc[] = []
  for (const d of detections) {
    if (d.kind !== 'beacon' || !d.c2 || !d.org_id) continue
    const st = state.get(d.org_id)
    const at = st ? STATE_CENTROID[st] : undefined
    if (!st || !at) continue
    const cc = C2_COUNTRY.get(refang(d.c2))
    const c2at = cc ? COUNTRY_CENTROID[cc] : undefined
    out.push({ id: d.id, state: st, at, c2: d.c2, c2cc: cc, c2at, title: d.title })
    if (out.length >= 6) break
  }
  return out
}
