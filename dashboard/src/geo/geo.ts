// Reference geography for the landing globe: approximate centroids, [lat, lng] in degrees. Not data, just where to
// draw. Organisations sit at their state's centroid; C2 servers at their country's.
export type LatLng = [number, number]

export const STATE_CENTROID: Record<string, LatLng> = {
  'Andhra Pradesh': [15.9, 79.7], 'Arunachal Pradesh': [28.2, 94.7], Assam: [26.2, 92.9], Bihar: [25.1, 85.3],
  Chhattisgarh: [21.3, 81.9], Goa: [15.3, 74.1], Gujarat: [22.7, 71.6], Haryana: [29.1, 76.1],
  'Himachal Pradesh': [31.9, 77.2], Jharkhand: [23.6, 85.3], Karnataka: [15.3, 75.7], Kerala: [10.5, 76.3],
  'Madhya Pradesh': [23.5, 78.7], Maharashtra: [19.4, 76.1], Manipur: [24.7, 93.9], Meghalaya: [25.5, 91.4],
  Mizoram: [23.2, 92.9], Nagaland: [26.2, 94.6], Odisha: [20.5, 84.4], Punjab: [30.8, 75.3], Rajasthan: [26.6, 73.8],
  Sikkim: [27.5, 88.5], 'Tamil Nadu': [11.0, 78.4], Telangana: [17.9, 79.0], Tripura: [23.7, 91.7],
  'Uttar Pradesh': [26.9, 80.9], Uttarakhand: [30.1, 79.0], 'West Bengal': [23.0, 87.9], Delhi: [28.6, 77.2],
  'Jammu and Kashmir': [33.6, 75.0], Ladakh: [34.2, 77.6], Puducherry: [11.9, 79.8], Chandigarh: [30.7, 76.8],
}

export const COUNTRY_CENTROID: Record<string, LatLng> = {
  US: [39.8, -98.6], CA: [56.1, -106.3], MX: [23.6, -102.5], BR: [-14.2, -51.9], AR: [-38.4, -63.6],
  CL: [-35.7, -71.5], CO: [4.6, -74.3], GB: [54.0, -2.5], IE: [53.4, -8.2], FR: [46.6, 2.2], DE: [51.2, 10.4],
  NL: [52.1, 5.3], BE: [50.5, 4.5], LU: [49.8, 6.1], CH: [46.8, 8.2], AT: [47.5, 14.6], IT: [41.9, 12.6],
  ES: [40.5, -3.7], PT: [39.4, -8.2], SE: [60.1, 18.6], NO: [60.5, 8.5], FI: [61.9, 25.7], DK: [56.3, 9.5],
  PL: [51.9, 19.1], CZ: [49.8, 15.5], RO: [45.9, 25.0], BG: [42.7, 25.5], HU: [47.2, 19.5], UA: [48.4, 31.2],
  MD: [47.4, 28.4], LT: [55.2, 23.9], LV: [56.9, 24.6], EE: [58.6, 25.0], RU: [61.5, 105.3], TR: [39.0, 35.2],
  IL: [31.0, 34.9], IR: [32.4, 53.7], AE: [23.4, 53.8], SA: [23.9, 45.1], EG: [26.8, 30.8], ZA: [-30.6, 22.9],
  NG: [9.1, 8.7], KE: [-0.0, 37.9], IN: [22.0, 79.0], PK: [30.4, 69.3], BD: [23.7, 90.4], CN: [35.9, 104.2],
  HK: [22.3, 114.2], TW: [23.7, 121.0], KR: [35.9, 127.8], JP: [36.2, 138.3], SG: [1.35, 103.8], MY: [4.2, 101.9],
  TH: [15.9, 100.99], VN: [14.1, 108.3], ID: [-0.8, 113.9], PH: [12.9, 121.8], AU: [-25.3, 133.8], NZ: [-40.9, 174.9],
  SC: [-4.7, 55.5], PA: [8.5, -80.8], BZ: [17.2, -88.5], VG: [18.4, -64.6],
}

export const INDIA: LatLng = [22, 79]

const rad = (d: number) => (d * Math.PI) / 180

/** cobe's camera angles that put a location at the centre of the globe (cobe's own "rotate to location" recipe). */
export function anglesFor([lat, lng]: LatLng): { phi: number; theta: number } {
  return { phi: Math.PI - (rad(lng) - Math.PI / 2), theta: rad(lat) }
}

/** Point a fraction t of the way along the great circle from a to b. */
export function slerp(a: LatLng, b: LatLng, t: number): LatLng {
  const v = ([lat, lng]: LatLng) => [Math.cos(rad(lat)) * Math.cos(rad(lng)), Math.cos(rad(lat)) * Math.sin(rad(lng)), Math.sin(rad(lat))]
  const p = v(a), q = v(b)
  const dot = Math.min(1, Math.max(-1, p[0] * q[0] + p[1] * q[1] + p[2] * q[2]))
  const w = Math.acos(dot)
  if (w < 1e-6) return a
  const s = Math.sin(w)
  const k1 = Math.sin((1 - t) * w) / s, k2 = Math.sin(t * w) / s
  const [x, y, z] = [k1 * p[0] + k2 * q[0], k1 * p[1] + k2 * q[1], k1 * p[2] + k2 * q[2]]
  return [(Math.atan2(z, Math.hypot(x, y)) * 180) / Math.PI, (Math.atan2(y, x) * 180) / Math.PI]
}

/** Where to stand to see the great circle a→b side-on: the plane's normal, on whichever side is nearer lng 0. */
export function sideOf(a: LatLng, b: LatLng): LatLng {
  const v = ([lat, lng]: LatLng) => [Math.cos(rad(lat)) * Math.cos(rad(lng)), Math.cos(rad(lat)) * Math.sin(rad(lng)), Math.sin(rad(lat))]
  const p = v(a), q = v(b)
  const n = [p[1] * q[2] - p[2] * q[1], p[2] * q[0] - p[0] * q[2], p[0] * q[1] - p[1] * q[0]]
  const toLatLng = ([x, y, z]: number[]): LatLng => [(Math.atan2(z, Math.hypot(x, y)) * 180) / Math.PI, (Math.atan2(y, x) * 180) / Math.PI]
  const one = toLatLng(n), other = toLatLng(n.map((c) => -c))
  return Math.abs(one[1]) <= Math.abs(other[1]) ? one : other
}

/** Spread several organisations in one state around its centroid so each keeps its own dot. */
export function spread(center: LatLng, i: number, n: number): LatLng {
  if (n <= 1) return center
  const a = (2 * Math.PI * i) / n + 0.6
  return [center[0] + 0.9 * Math.sin(a), center[1] + 0.9 * Math.cos(a)]
}

export const refang = (s: string) => s.replace(/\[\.\]/g, '.')
