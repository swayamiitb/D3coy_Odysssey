import india from '@svg-maps/india'
import { geoGraticule10, geoMercator, geoPath, type GeoPermissibleObjects, type GeoProjection } from 'd3-geo'
import { feature, mesh } from 'topojson-client'
import type { GeometryCollection, Topology } from 'topojson-specification'
import w110 from 'world-atlas/countries-110m.json?url'
import w50 from 'world-atlas/countries-50m.json?url'

/* The 2D world map (ui-08): a real vector map, Mercator. Countries come from world-atlas (Natural Earth, bundled and
   served by Vite, so the demo needs no network) with India's own arcs left out. India itself is drawn from
   @svg-maps/india (the official outline, by state) on top, so the map shows India's boundary as India draws it.

   Calibration of the India drawing (viewBox 0 0 612 696, Mercator): its extreme points sit at x 0 (Gujarat) and
   x 611.86 (Arunachal), y 0 (Jammu and Kashmir) and y 695.70 (Indira Point). Fitting a single Mercator scale through
   two coastline points that world-atlas also has, Kanyakumari (77.518E 8.078N at x 196.035 y 667.766) and Indira
   Point (93.830E 6.748N at x 536.746 y 695.702), gives 1196.76 px per radian and x 0 = 68.1325E; that puts Gujarat's
   west tip at 23.68N (world-atlas: 68.165E 23.86N), Arunachal's east tip at 97.43E 28.04N and the top at 37.16N, all
   within a few hundredths of a degree. Because both are Mercator, the drawing maps onto the map by one scale and one
   translate. */

const IND_K = 1196.7625                // drawing px per radian of longitude
const IND_LON0 = 68.13248              // longitude at x = 0
const merc = (lat: number) => Math.log(Math.tan(Math.PI / 4 + (lat * Math.PI) / 360))
const IND_M0 = merc(8.07825) + 667.766 / IND_K // Mercator y at drawing y = 0
export const rad = (d: number) => (d * Math.PI) / 180

export const LAT_N = 80
export const LAT_S = -56
export const M_N = merc(LAT_N)
export const M_S = merc(LAT_S)
export const mercY = merc
export const imercY = (y: number) => ((2 * Math.atan(Math.exp(y)) - Math.PI / 2) * 180) / Math.PI

export interface WorldLayer { land: GeoPermissibleObjects; borders: GeoPermissibleObjects }

type Countries = Topology<{ countries: GeometryCollection<{ name: string }> }>
const cache = new Map<string, Promise<WorldLayer>>()
function layer(url: string): Promise<WorldLayer> {
  let p = cache.get(url)
  if (!p) {
    p = fetch(url).then((r) => r.json() as Promise<Countries>).then((t) => {
      const fc = feature(t, t.objects.countries)
      return {
        // every country is land (India too, under the official drawing, so no gaps open along its borders)
        land: { type: 'FeatureCollection', features: fc.features.filter((f) => f.id !== '010') } as GeoPermissibleObjects,
        // borders between countries, leaving out every arc India's de-facto outline uses
        borders: mesh(t, t.objects.countries, (a, b) => a !== b && a.id !== '356' && b.id !== '356'),
      }
    })
    cache.set(url, p)
  }
  return p
}
export const loadCoarse = () => layer(w110)
export const loadFine = () => layer(w50)

interface Shape { id: string; name: string; path: string }
const IND = india as unknown as { viewBox: string; locations: Shape[] }
export interface IndiaState { id: string; name: string; path: Path2D }
let STATES: IndiaState[] | undefined
export function indiaStates(): IndiaState[] {
  STATES ??= IND.locations.map((l) => ({ id: l.id, name: l.name, path: new Path2D(l.path) }))
  return STATES
}

/** A view of the map: zoom k (1 = whole world across the box) and the centre in projected units (lambda, Mercator y). */
export interface View { k: number; x: number; y: number }

export function baseScale(W: number, H: number): number {
  // fill the width; a very tall box fits the latitude band instead
  return Math.min(W / (2 * Math.PI), (H * 1.08) / (M_N - M_S))
}

/** The opening view: the band from 78N to 52S fills the box (the poles and the far Pacific are cropped). */
export function homeView(W = 0, H = 0): View {
  const band = merc(78) - merc(-52)
  const k = W && H ? Math.max(1, Math.min(1.6, H / baseScale(W, H) / band)) : 1
  return { k, x: rad(12), y: (merc(78) + merc(-52)) / 2 }
}
export const INDIA_VIEW = { x: rad(81.5), y: merc(22.5) }

/** Keep the view over the map: no panning off the edges of the world. */
export function clampView(v: View, W: number, H: number): View {
  const s = baseScale(W, H) * v.k
  const hw = W / 2 / s, hh = H / 2 / s
  const x = hw >= Math.PI ? 0 : Math.max(-Math.PI + hw, Math.min(Math.PI - hw, v.x))
  const y = hh >= (M_N - M_S) / 2 ? (M_N + M_S) / 2 : Math.max(M_S + hh, Math.min(M_N - hh, v.y))
  return { k: v.k, x, y }
}

export interface Frame { s: number; tx: number; ty: number; proj: GeoProjection }
export function frameFor(v: View, W: number, H: number): Frame {
  const s = baseScale(W, H) * v.k
  const tx = W / 2 - s * v.x, ty = H / 2 + s * v.y
  const proj = geoMercator().scale(s).translate([tx, ty]).clipExtent([[-4, -4], [W + 4, H + 4]])
  return { s, tx, ty, proj }
}

/** Screen position of a [lat, lng] in a frame (plain Mercator maths, no clipping). */
export function toScreen(f: Frame, lat: number, lng: number): [number, number] {
  return [f.tx + f.s * rad(lng), f.ty - f.s * merc(lat)]
}

/** The canvas transform that lays the India drawing onto the map: [scale, translateX, translateY]. */
export function indiaTransform(f: Frame): [number, number, number] {
  const a = f.s / IND_K
  return [a, f.tx + f.s * rad(IND_LON0), f.ty - f.s * IND_M0]
}

export const PAL = {
  ocean: '#050506',
  graticule: 'rgba(255,255,255,0.045)',
  land: '#1c1c21',
  border: '#34343c',
  india: '#2b2b33',
  indiaEdge: '#5a5a66',
  stateLine: 'rgba(255,255,255,0.13)',
}

/** Paint the base map (ocean, graticule, land, borders, India by state) into ctx, already scaled by dpr. */
export function drawBase(ctx: CanvasRenderingContext2D, W: number, H: number, dpr: number, f: Frame, world: WorldLayer | undefined,
  stateFill: Map<string, string>, fine: boolean) {
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.fillStyle = PAL.ocean
  ctx.fillRect(0, 0, W, H)
  const path = geoPath(f.proj, ctx)

  ctx.beginPath()
  path(geoGraticule10())
  ctx.strokeStyle = PAL.graticule
  ctx.lineWidth = 0.6
  ctx.stroke()

  if (world) {
    ctx.beginPath()
    path(world.land)
    ctx.fillStyle = PAL.land
    ctx.fill()
    ctx.beginPath()
    path(world.borders)
    ctx.strokeStyle = PAL.border
    ctx.lineWidth = 0.7
    ctx.stroke()
  }

  // India: a brighter outline under the fills leaves a crisp outer edge; state lines go on top as hairlines.
  const [a, e, g] = indiaTransform(f)
  const states = indiaStates()
  ctx.setTransform(dpr * a, 0, 0, dpr * a, dpr * e, dpr * g)
  ctx.lineJoin = 'round'
  if (fine) {
    ctx.strokeStyle = PAL.indiaEdge
    ctx.lineWidth = 2.2 / a
    for (const st of states) ctx.stroke(st.path)
  }
  for (const st of states) {
    ctx.fillStyle = stateFill.get(st.name) ?? PAL.india
    ctx.fill(st.path)
  }
  ctx.strokeStyle = PAL.stateLine
  ctx.lineWidth = 0.7 / a
  for (const st of states) ctx.stroke(st.path)
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
}
