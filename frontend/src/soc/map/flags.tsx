import {
  AE, AU, BG, BR, BZ, CA, CH, CN, CZ, DE, ES, FR, GB, HK, ID, IL, IN, IR, IT, JP, KR, LT, LU, MD, NL, PA, PK, PL, RO, RU, SC, SE,
  SG, TR, TW, UA, US, VG, VN, ZA,
} from 'country-flag-icons/string/3x2'

/* Country flags as SVG images (country-flag-icons, bundled; never emoji). The set covers every country the snapshot
   names plus the usual attack origins; anything else falls back to its ISO code in a chip. */
const SVG: Record<string, string> = {
  AE, AU, BG, BR, BZ, CA, CH, CN, CZ, DE, ES, FR, GB, HK, ID, IL, IN, IR, IT, JP, KR, LT, LU, MD, NL, PA, PK, PL, RO, RU, SC, SE,
  SG, TR, TW, UA, US, VG, VN, ZA,
}
const URLS = new Map<string, string>()
export function flagUrl(cc: string): string | undefined {
  const svg = SVG[cc]
  if (!svg) return undefined
  let u = URLS.get(cc)
  if (!u) { u = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`; URLS.set(cc, u) }
  return u
}

const IMGS = new Map<string, HTMLImageElement>()
/** A decoded image for drawing a flag on a canvas (undefined until it has loaded). */
export function flagImage(cc: string): HTMLImageElement | undefined {
  const url = flagUrl(cc)
  if (!url) return undefined
  let img = IMGS.get(cc)
  if (!img) { img = new Image(); img.src = url; IMGS.set(cc, img) }
  return img.complete && img.naturalWidth ? img : undefined
}

export function Flag({ cc, className = 'h-[14px] w-[21px]' }: { cc: string; className?: string }) {
  const url = flagUrl(cc)
  if (!url) {
    return <span className={`inline-flex shrink-0 items-center justify-center rounded-[3px] border border-line bg-panel-2 font-mono text-[9px] font-semibold text-mute ${className}`}>{cc}</span>
  }
  return <img src={url} alt="" aria-hidden className={`shrink-0 rounded-[3px] object-cover shadow-[0_0_0_1px_rgba(255,255,255,0.14)] ${className}`} />
}
