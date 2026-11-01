/* Site view campuses (ui-08, SIM): each government agency or public-sector body gets a small campus whose buildings
   fit its sector. Sizes are scene units (about a metre each). The internet-facing building (the DMZ) sits on the
   north-west corner, the side most of the real attack origins lie on from India. */

export type Kind = 'tower' | 'ops' | 'dc' | 'edge' | 'design'
export interface BuildingSpec { role: string; kind: Kind; w: number; d: number; h: number; x: number; z: number }

const NW = { x: -21, z: -19 }, NE = { x: 19, z: -17 }, SW = { x: -19, z: 20 }, SE = { x: 20, z: 19 }

export function campusFor(sector: string): BuildingSpec[] {
  switch (sector) {
    case 'Power & Energy':
      return [
        { role: 'Headquarters', kind: 'tower', w: 17, d: 17, h: 54, ...NE },
        { role: 'SCADA control centre', kind: 'ops', w: 28, d: 18, h: 15, ...SW },
        { role: 'Data centre', kind: 'dc', w: 24, d: 20, h: 12, ...SE },
        { role: 'Internet edge (DMZ)', kind: 'edge', w: 15, d: 14, h: 22, ...NW },
      ]
    case 'Transport':
      return [
        { role: 'Headquarters', kind: 'tower', w: 19, d: 16, h: 46, ...NE },
        { role: 'Operations control centre', kind: 'ops', w: 30, d: 19, h: 18, ...SW },
        { role: 'Data centre', kind: 'dc', w: 22, d: 20, h: 12, ...SE },
        { role: 'Internet edge (DMZ)', kind: 'edge', w: 15, d: 14, h: 20, ...NW },
      ]
    case 'Government':
      return [
        { role: 'Directorate', kind: 'tower', w: 24, d: 18, h: 36, ...NE },
        { role: 'State data centre', kind: 'dc', w: 30, d: 22, h: 14, x: -4, z: 20 },
        { role: 'Citizen services portal (DMZ)', kind: 'edge', w: 18, d: 15, h: 24, ...NW },
      ]
    default: // Strategic & Public Enterprises
      return [
        { role: 'Headquarters', kind: 'tower', w: 18, d: 18, h: 48, ...NE },
        { role: 'Secure design centre', kind: 'design', w: 28, d: 20, h: 20, ...SW },
        { role: 'Data centre', kind: 'dc', w: 22, d: 20, h: 12, ...SE },
        { role: 'Internet edge (DMZ)', kind: 'edge', w: 15, d: 14, h: 20, ...NW },
      ]
  }
}

/** Where each agency's campus sits in the scene. */
export function campusSpots(n: number): { x: number; z: number }[] {
  if (n <= 1) return [{ x: 0, z: 0 }]
  if (n === 2) return [{ x: -62, z: 0 }, { x: 62, z: 0 }]
  if (n === 3) return [{ x: -68, z: 26 }, { x: 68, z: 26 }, { x: 0, z: -60 }]
  return Array.from({ length: n }, (_, i) => ({ x: ((i % 2) * 2 - 1) * 64, z: (Math.floor(i / 2) - (Math.ceil(n / 2) - 1) / 2) * 120 }))
}

export const isEdge = (b: BuildingSpec) => b.kind === 'edge'
