/* Odyssey final deck: ten slides on the brief's spine, "Signal Cartography" (see PHILOSOPHY.md).
   Dark instrument ground, hairline rings and ticks, white only where a decision is settled, red only on data.
   Every figure carries its key. Text native, art rasterised from geometry (no text in the art). */
const pptxgen = require('pptxgenjs')
const sharp = require('sharp')
const fs = require('fs')
const path = require('path')
const { applyTheme } = require(process.env.PPTX_SKILL + '/scripts/apply_theme.js')

const OUT = process.argv[2]
const REF = path.join(__dirname, 'shots')
const REPO = path.resolve(__dirname, '../../..')
const IMG = path.join(__dirname, 'img'); fs.mkdirSync(IMG, { recursive: true })

// ---------- palette (the console's) ----------
const K = '000000', W = 'FFFFFF', INKGREY = '1F1F1F', PAPER = 'F3F3F3', RED = 'E11900', GREY = 'A6A6A6', MUTE = '5E5E5E',
      GREEN = '05A357', VIOLET = '9B7BFF', BLUE = '276EF1', PINK = 'F0569A', CYAN = '38BDF8', DIM = '2A2A2A', GRID = '171717'
const THEME = { name: 'Odyssey Signal', headFontFace: 'Arial', bodyFontFace: 'Arial',
  colors: { dk1: K, lt1: W, dk2: INKGREY, lt2: PAPER, accent1: RED, accent2: GREY, accent3: MUTE, accent4: GREEN, accent5: VIOLET, accent6: BLUE, hlink: GREY, folHlink: MUTE } }
const MONO = 'Consolas'
// per-slide ground: every helper reads these at call time
let INK = '#fff', BGC = '#000000', BG = K, FG = W, G2 = GREY, G3 = MUTE, CARDSUB = '3A3A3A', ACC = RED
const SCHEMES = {
  DARK:    { BG: K, FG: W, G2: 'A6A6A6', G3: '5E5E5E', CARDSUB: '3A3A3A', ACC: RED, INK: '#fff', BGC: '#000000' },
  PAPER:   { BG: W, FG: K, G2: '5E5E5E', G3: '8A8A8A', CARDSUB: 'C4C4C4', ACC: RED, INK: '#000', BGC: '#ffffff' },
  NAVY:    { BG: '0B1B33', FG: W, G2: 'B9C3D3', G3: '7A879C', CARDSUB: '3A4A66', ACC: RED, INK: '#fff', BGC: '#0B1B33' },
  SAFFRON: { BG: 'F0962B', FG: K, G2: '3D2A12', G3: '6B4A1E', CARDSUB: 'D9D9D9', ACC: K, INK: '#000', BGC: '#F0962B' },
}
const use = (n) => { const c = SCHEMES[n]; BG = c.BG; FG = c.FG; G2 = c.G2; G3 = c.G3; CARDSUB = c.CARDSUB; ACC = c.ACC; INK = c.INK; BGC = c.BGC; return n }
const DPI = 300

// ---------- art helpers ----------
const px = (inch) => Math.round(inch * DPI)
async function svgPng(name, w, h, body, extraDefs = '') {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${px(w)}" height="${px(h)}" viewBox="0 0 ${w * 100} ${h * 100}">${extraDefs}${body}</svg>`
  const out = path.join(IMG, name + '.png'); await sharp(Buffer.from(svg)).png().toFile(out); return out
}
const ring = (cx, cy, r, { stroke = INK, op = 0.9, w = 0.6, dash = '' } = {}) =>
  `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${stroke}" stroke-opacity="${op}" stroke-width="${w}"${dash ? ` stroke-dasharray="${dash}"` : ''}/>`
const spokes = (cx, cy, r0, r1, n, { op = 0.35, w = 0.45, stroke = INK } = {}) => {
  let s = ''; for (let i = 0; i < n; i++) { const a = (i / n) * Math.PI * 2; s += `<line x1="${cx + Math.cos(a) * r0}" y1="${cy + Math.sin(a) * r0}" x2="${cx + Math.cos(a) * r1}" y2="${cy + Math.sin(a) * r1}" stroke="${stroke}" stroke-opacity="${op}" stroke-width="${w}" stroke-linecap="round"/>` } return s }
const hub = (cx, cy, r, color = '#E11900') => `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${color}"/>`
const hair = (x1, y1, x2, y2, { op = 0.35, w = 0.5, stroke = INK, dash = '' } = {}) =>
  `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" stroke-opacity="${op}" stroke-width="${w}"${dash ? ` stroke-dasharray="${dash}"` : ''}/>`
const chakra = (cx, cy, r, { op = 0.9, hubColor = '#E11900', hubR = r * 0.18, spokeOp = 0.4 } = {}) =>
  ring(cx, cy, r, { op, w: 0.9 }) + spokes(cx, cy, r * 0.3, r * 0.86, 24, { op: spokeOp }) + hub(cx, cy, hubR, hubColor)

// ---------- deck helpers ----------
const pres = new pptxgen()
pres.layout = 'LAYOUT_16x9'           // 10 x 5.625 in
pres.theme = { headFontFace: 'Arial', bodyFontFace: 'Arial' }
pres.author = 'Team Odyssey'; pres.title = 'Odyssey: see the attack coming'; pres.subject = 'D3COY 1.0, PS 01, final round'

const FOOT = 'ODYSSEY  ·  NATIONAL CYBER THREAT EARLY WARNING  ·  D3COY 1.0  ·  PS 01'
for (const [name, c] of Object.entries(SCHEMES)) {
  pres.defineSlideMaster({ title: name, background: { color: c.BG },
    objects: [
      { text: { text: FOOT, options: { x: 0.5, y: 5.27, w: 7, h: 0.22, fontSize: 7, color: c.G3, charSpacing: 1.5, margin: 0, valign: 'middle' } } },
      { placeholder: { options: { name: 'title', type: 'title', x: 0.5, y: 0.36, w: 9, h: 0.62, fontSize: 26, bold: true, color: c.FG, margin: 0, valign: 'middle', align: 'left' } } },
    ],
    slideNumber: { x: 9.0, y: 5.27, w: 0.5, h: 0.22, fontSize: 7, color: c.G3, align: 'right', margin: 0, valign: 'middle' } })
}
pres.defineSlideMaster({ title: 'COVER', background: { color: K }, objects: [] })
const on = (section, scheme) => { use(scheme); return pres.addSlide({ masterName: scheme, sectionTitle: section }) }
let objN = 0
const T = (s, text, o) => s.addText(text, Object.assign({ isTextBox: true, margin: 0, fontSize: 10, color: FG, valign: 'top', objectName: 'text ' + (++objN) }, o))
const title = (s, text) => s.addText(text, { placeholder: 'title' })
const line = (s, x1, y1, x2, y2, color = G3, width = 0.5, dash) => s.addShape(pres.ShapeType.line, { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1), h: Math.abs(y2 - y1), line: Object.assign({ color, width }, dash ? { dashType: dash } : {}), flipV: (x2 - x1) * (y2 - y1) < 0, objectName: 'line ' + (++objN) })
const dot = (s, cx, cy, d, color) => s.addShape(pres.ShapeType.ellipse, { x: cx - d / 2, y: cy - d / 2, w: d, h: d, fill: { color }, objectName: 'dot ' + (++objN) })
const ringS = (s, cx, cy, d, color = FG, width = 0.75, fill = BG, dash) => s.addShape(pres.ShapeType.ellipse, { x: cx - d / 2, y: cy - d / 2, w: d, h: d, fill: { color: fill }, line: Object.assign({ color, width }, dash ? { dashType: dash } : {}), objectName: 'ring ' + (++objN) })
const rect = (s, x, y, w, h, fill, o = {}) => s.addShape(pres.ShapeType.rect, Object.assign({ x, y, w, h, fill: { color: fill }, objectName: 'rect ' + (++objN) }, o))
const chip = (s, x, y, w, h, text, { color = G2, border = G3, size = 8, fill = BG, bold = false } = {}) => {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: h / 2, fill: { color: fill }, line: { color: border, width: 0.5 }, objectName: 'chip ' + (++objN) })
  T(s, text, { x, y, w, h, fontSize: size, color, align: 'center', valign: 'middle', bold })
}
// A figure key. items: { k: 'dot'|'ring'|'hub'|'dash'|'square'|'tri'|'diamond'|'bar'|'none', c: colour, t: label }
function legend(s, x, y, items, { size = 8, color = G2, lead } = {}) {
  let cx = x
  if (lead) { T(s, lead, { x: cx, y: y - 0.09, w: 0.9, h: 0.18, fontSize: size, color: G3, valign: 'middle', bold: true }); cx += 0.34 + lead.length * 0.052 }
  for (const it of items) {
    const c = it.c || G2
    if (it.k === 'dot') dot(s, cx + 0.06, y, 0.1, c)
    else if (it.k === 'ring') ringS(s, cx + 0.06, y, 0.12, c, 0.75)
    else if (it.k === 'hub') { ringS(s, cx + 0.06, y, 0.13, FG, 0.75); dot(s, cx + 0.06, y, 0.05, ACC) }
    else if (it.k === 'dash') line(s, cx, y, cx + 0.16, y, c, 0.75, 'dash')
    else if (it.k === 'bar') line(s, cx, y, cx + 0.16, y, c, 1.5)
    else if (it.k === 'square') rect(s, cx + 0.01, y - 0.05, 0.1, 0.1, c)
    else if (it.k === 'tri') s.addShape(pres.ShapeType.triangle, { x: cx + 0.005, y: y - 0.06, w: 0.12, h: 0.11, fill: { color: c }, objectName: 'tri ' + (++objN) })
    else if (it.k === 'diamond') s.addShape(pres.ShapeType.diamond, { x: cx, y: y - 0.065, w: 0.13, h: 0.13, fill: { color: c }, objectName: 'dia ' + (++objN) })
    const tx = cx + (it.k === 'none' ? 0 : 0.2)
    const tw = it.t.length * (size * 0.0068) + 0.1
    T(s, it.t, { x: tx, y: y - 0.1, w: tw, h: 0.2, fontSize: size, color, valign: 'middle' })
    cx = tx + tw + 0.16
  }
}
const fig = (s, x, y, text, w = 3.5) => T(s, text, { x, y, w, h: 0.16, fontSize: 7, color: G3, fontFace: MONO, charSpacing: 1 })
const big = (s, text, x, y, w, size = 40, color = FG, align = 'left') => T(s, text, { x, y, w, h: size / 60, fontSize: size, bold: true, color, align, valign: 'top', charSpacing: -1 })

async function build() {
  // ---------- pre-rendered art ----------
  // emblem
  const emblem = path.join(IMG, 'emblem.png'); await sharp(path.join(REPO, 'frontend/public/mark-large.svg')).resize(720, 720).png().toFile(emblem)

  use('DARK')
  // 1. cover: the live threat map dimmed under a radar ring system centred on India, dark fade for the title
  {
    const Wp = px(10), Hp = px(5.625)
    const map = await sharp(path.join(REF, 'image-1-1.png')).extract({ left: 0, top: 70, width: 1700, height: 1250 }).resize(Wp, Hp, { fit: 'cover', position: 'centre' }).modulate({ brightness: 0.5, saturation: 0.85 }).toBuffer()
    const cx = 840, cy = 338, rings = []
    for (let i = 1; i <= 7; i++) rings.push(ring(cx, cy, i * 62, { op: i === 4 ? 0.28 : 0.13, w: 0.55 }))
    let ticks = ''; for (let i = 0; i < 72; i++) { const a = (i / 72) * Math.PI * 2, r0 = 434, r1 = i % 6 === 0 ? 448 : 440; ticks += hair(cx + Math.cos(a) * r0, cy + Math.sin(a) * r0, cx + Math.cos(a) * r1, cy + Math.sin(a) * r1, { op: 0.35, w: 0.5 }) }
    const sweep = `<path d="M${cx} ${cy} L${cx + Math.cos(-0.35) * 434} ${cy + Math.sin(-0.35) * 434} A434 434 0 0 0 ${cx + Math.cos(-1.25) * 434} ${cy + Math.sin(-1.25) * 434} Z" fill="url(#sw)"/>`
    const defs = `<defs><linearGradient id="fade" x1="0" x2="1" y1="0" y2="0"><stop offset="0" stop-color="#000" stop-opacity="0.97"/><stop offset="0.42" stop-color="#000" stop-opacity="0.86"/><stop offset="0.72" stop-color="#000" stop-opacity="0.25"/><stop offset="1" stop-color="#000" stop-opacity="0.1"/></linearGradient>
      <linearGradient id="sw" x1="${cx}" y1="${cy}" x2="${cx + 300}" y2="${cy - 300}" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fff" stop-opacity="0.02"/><stop offset="1" stop-color="#fff" stop-opacity="0.16"/></linearGradient>
      <linearGradient id="bot" x1="0" x2="0" y1="0" y2="1"><stop offset="0.7" stop-color="#000" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity="0.9"/></linearGradient></defs>`
    const body = `<rect width="1000" height="562.5" fill="url(#fade)"/><rect width="1000" height="562.5" fill="url(#bot)"/>${rings.join('')}${ticks}${sweep}${hair(cx - 448, cy, cx + 448, cy, { op: 0.12 })}${hair(cx, cy - 448, cx, cy + 448, { op: 0.12 })}`
    const over = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${Wp}" height="${Hp}" viewBox="0 0 1000 562.5">${defs}${body}</svg>`)
    await sharp(map).composite([{ input: await sharp(over).png().toBuffer() }]).png().toFile(path.join(IMG, 'cover.png'))
  }

  use('PAPER')
  // 2. the field of October's CVEs: one mark each, the labelled fifth in white
  {
    const N = 16730, cols = 430, sp = 2.09, r = 0.62, labelled = Math.round(N * 0.21)
    let m = ''; for (let i = 0; i < N; i++) { const c = i % cols, rw = Math.floor(i / cols); m += `<circle cx="${(c + 0.5) * sp}" cy="${(rw + 0.5) * sp}" r="${r}" fill="${i < labelled ? INK : INK}" fill-opacity="${i < labelled ? 1 : 0.3}"/>` }
    await svgPng('field', 9, 0.82, m)
  }

  use('PAPER')
  // 4. thirteen sources converging into one record, then the funnel as nested circles (area by square root)
  {
    const W4 = 7.9, H4 = 2.95, nodes = []
    const groups = [[1, 1, 1, 1], [1, 0, 1, 1], [1, 1, 1, 0, 0]]   // 1 = REAL, 0 = SIM
    let y = 22; groups.forEach((g, gi) => { g.forEach((real) => { nodes.push({ x: 62, y, real }); y += 19.5 }); y += 16 })
    const cx = 395, cy = 147
    let s = ''
    for (const n of nodes) s += `<path d="M${n.x} ${n.y} C ${n.x + 140} ${n.y}, ${cx - 130} ${cy}, ${cx - 42} ${cy}" fill="none" stroke="${INK}" stroke-opacity="${n.real ? 0.3 : 0.18}" stroke-width="0.5"${n.real ? '' : ' stroke-dasharray="3 2.5"'}/>`
    for (const n of nodes) s += n.real ? `<circle cx="${n.x}" cy="${n.y}" r="3.2" fill="${INK}"/>` : `<circle cx="${n.x}" cy="${n.y}" r="3.2" fill="${BGC}" stroke="${INK}" stroke-width="0.8" stroke-dasharray="1.6 1.2"/>`
    s += chakra(cx, cy, 40, { hubR: 5, spokeOp: 0.35 }) + ring(cx, cy, 48, { op: 0.18, w: 0.5 })
    const fx = 632, big = 118, mid = big * Math.sqrt(2277 / 82104), small = big * Math.sqrt(354 / 82104)
    s += `<path d="M${cx + 48} ${cy} C ${cx + 100} ${cy}, ${fx - 160} ${cy}, ${fx - big} ${cy}" fill="none" stroke="${INK}" stroke-opacity="0.45" stroke-width="0.6"/>`
    s += ring(fx, cy, big, { op: 0.55, w: 0.7 }) + ring(fx, cy, mid, { op: 0.9, w: 0.8 }) + `<circle cx="${fx}" cy="${cy}" r="${small}" fill="#E11900"/>`
    // leaders to the labels at the right edge
    s += hair(fx + big, cy, 775, 44, { op: 0.35 }) + hair(fx + mid, cy - mid, 775, 147, { op: 0.35 }) + hair(fx + small, cy + small, 775, 250, { op: 0.6, stroke: '#E11900' })
    s += `<circle cx="775" cy="44" r="1.6" fill="${INK}"/><circle cx="775" cy="147" r="1.6" fill="${INK}"/><circle cx="775" cy="250" r="1.6" fill="#E11900"/>`
    await svgPng('converge', W4, H4, s)
  }

  use('SAFFRON')
  // 5. five rings on a line (chakra motif), the last with the red hub where a person decides
  {
    let s = hair(90, 60, 810, 60, { op: 0.35, w: 0.7 })
    ;[90, 270, 450, 630, 810].forEach((x, i) => { s += `<circle cx="${x}" cy="60" r="44" fill="${BGC}"/>` + ring(x, 60, 44, { op: 0.95, w: 1 }) + spokes(x, 60, 30, 40, 24, { op: 0.35, w: 0.5 }) })
    await svgPng('steps', 9, 1.2, s)
  }

  use('NAVY')
  // 8. the burn-down curve and the deadline dials
  {
    const W8 = 3.0, H8 = 2.4, L = 36, R = 290, Tt = 14, B = 212
    const X = (t) => L + (t / 344) * (R - L), Y = (p) => B - (p / 100) * (B - Tt)
    const pts = [[0, 0], [60, 38], [93, 50], [150, 68], [205, 80], [280, 92], [344, 100]].map(([t, p]) => [X(t), Y(p)])
    let d = `M${pts[0][0]} ${pts[0][1]}`
    for (let i = 0; i < pts.length - 1; i++) { const p0 = pts[Math.max(i - 1, 0)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(i + 2, pts.length - 1)]
      d += ` C ${p1[0] + (p2[0] - p0[0]) / 6} ${p1[1] + (p2[1] - p0[1]) / 6}, ${p2[0] - (p3[0] - p1[0]) / 6} ${p2[1] - (p3[1] - p1[1]) / 6}, ${p2[0]} ${p2[1]}` }
    let s = `<path d="${d} L${R} ${B} L${L} ${B} Z" fill="${INK}" fill-opacity="0.06"/><path d="${d}" fill="none" stroke="${INK}" stroke-width="1.1"/>`
    s += hair(L, B, R, B, { op: 0.5 }) + hair(L, Tt, L, B, { op: 0.5 })
    for (const p of [25, 50, 75, 100]) s += hair(L - 3, Y(p), L, Y(p), { op: 0.6 }) + hair(L, Y(p), R, Y(p), { op: 0.08, dash: '2 3' })
    for (const t of [93, 205, 344]) s += hair(X(t), B, X(t), B + 3, { op: 0.6 })
    for (const [t, p] of [[93, 50], [205, 80]]) s += hair(X(t), Y(p), X(t), B, { op: 0.4, stroke: '#E11900', dash: '2 2' }) + `<circle cx="${X(t)}" cy="${Y(p)}" r="6" fill="${BGC}" stroke="${INK}" stroke-width="1"/>` + hub(X(t), Y(p), 2.4)
    await svgPng('burndown', W8, H8, s)
    // dials: each deadline as an arc on a 120-hour face
    let dl = ''
    const H = [6, 12, 24, 72, 120]
    H.forEach((h, i) => { const cx = 26, cy = 24 + i * 46, r = 17, a = (h / 120) * Math.PI * 2 - Math.PI / 2
      dl += ring(cx, cy, r, { op: 0.18, w: 3.2 })
      const ex = cx + Math.cos(a) * r, ey = cy + Math.sin(a) * r, large = h / 120 > 0.5 ? 1 : 0
      dl += h === 120 ? ring(cx, cy, r, { op: 0.95, w: 3.2, stroke: INK }) : `<path d="M${cx} ${cy - r} A${r} ${r} 0 ${large} 1 ${ex} ${ey}" fill="none" stroke="${i === 0 ? '#E11900' : INK}" stroke-width="3.2" stroke-linecap="butt"/>`
      dl += hair(cx, cy - r - 4, cx, cy - r - 1, { op: 0.6 }) + hub(cx, cy, 1.8, i === 0 ? '#E11900' : INK) })
    await svgPng('dials', 0.6, 2.4, dl)
  }

  use('NAVY')
  // 3. the two lanes
  {
    const xs = [160, 390, 620, 850]
    let s = ''
    s += hair(60, 70, 880, 70, { op: 0.3, w: 0.8 }) + hair(60, 212, 880, 212, { op: 0.75, w: 0.9 })
    xs.forEach((x, i) => { s += `<circle cx="${x}" cy="70" r="9" fill="${BGC}"/>` + ring(x, 70, 9, { op: 0.5, w: 0.9 }) + (i === 2 ? hub(x, 70, 3, '#E11900') : `<circle cx="${x}" cy="70" r="2.4" fill="${INK}" fill-opacity="0.5"/>`) })
    xs.forEach((x, i) => { s += `<circle cx="${x}" cy="212" r="10" fill="${BGC}"/>` + ring(x, 212, 10, { op: 0.95, w: 1, dash: i === 0 ? '2.2 2' : '' }) + spokes(x, 212, 5, 8.5, 12, { op: 0.45 }) + (i === 2 ? hub(x, 212, 3.2) : `<circle cx="${x}" cy="212" r="2.4" fill="${INK}"/>`) })
    // where action starts: a red line on each lane, and the arrow that moves it left
    s += hair(xs[2], 48, xs[2], 92, { op: 0.9, stroke: '#E11900', w: 1.2 }) + hair(xs[0], 188, xs[0], 236, { op: 0.9, stroke: '#E11900', w: 1.2 })
    s += `<path d="M${xs[2]} 92 L${xs[2]} 165 L${xs[0] + 14} 165" fill="none" stroke="#E11900" stroke-width="1" stroke-opacity="0.85"/><path d="M${xs[0] + 16} 160 L${xs[0] + 4} 165 L${xs[0] + 16} 170 Z" fill="#E11900"/>` + hair(xs[0], 165, xs[0], 188, { op: 0.85, stroke: '#E11900', w: 1 })
    await svgPng('lanes', 9, 2.9, s)
  }

  use('PAPER')
  // 2. the C-Edge line
  {
    const x0 = 40, x1 = 860, X = (d) => x0 + d * (x1 - x0)
    const disc = X(0.0), breach = X(0.776), listed = X(0.846)
    let s = hair(x0, 40, x1, 40, { op: 0.45, w: 0.8 })
    for (let m = 0; m <= 9; m++) s += hair(X(m / 9), 40, X(m / 9), 45, { op: 0.4 })
    s += `<rect x="${disc}" y="37.5" width="${breach - disc}" height="5" fill="#E11900" fill-opacity="0.85"/>`
    ;[disc, breach, listed].forEach((x, i) => { s += `<circle cx="${x}" cy="40" r="8" fill="${BGC}"/>` + ring(x, 40, 8, { op: 0.95, w: 1 }) + (i === 1 ? hub(x, 40, 2.8) : `<circle cx="${x}" cy="40" r="2.2" fill="${INK}"/>`) })
    s += hair(disc, 48, disc, 62, { op: 0.5 }) + hair(breach, 32, breach, 14, { op: 0.5 }) + hair(listed, 48, listed, 62, { op: 0.5 })
    await svgPng('cedge', 9, 0.8, s)
  }

  // screenshots for slide 9 and 4, resized for size (contain into black cells)
  const shots = {}
  for (const [key, file, maxW] of [['now', 'image-9-1.png', 1800], ['heat', 'image-9-2.png', 1800], ['world', 'image-9-3.png', 1800], ['india', 'image-9-4.png', 1800], ['site', 'image-9-5.png', 1800], ['feeds', 'image-4-1.png', 2400], ['graph', 'image-6-1.png', 1600]]) {
    const out = path.join(IMG, key + '.png'); const m = await sharp(path.join(REF, file)).metadata()
    await sharp(path.join(REF, file)).resize(Math.min(maxW, m.width)).png({ compressionLevel: 9 }).toFile(out); shots[key] = { path: out, ratio: m.width / m.height }
  }
  await sharp(path.join(REF, 'image-6-1.png')).extract({ left: 0, top: 0, width: 1840, height: 1540 }).resize(1600).png({ compressionLevel: 9 }).toFile(shots.graph.path); shots.graph.ratio = 1840 / 1540
  const fitImg = (s, key, x, y, w, h, alt) => { const r = shots[key].ratio; let iw = w, ih = w / r; if (ih > h) { ih = h; iw = h * r } s.addImage({ path: shots[key].path, x: x + (w - iw) / 2, y: y + (h - ih) / 2, w: iw, h: ih, altText: alt, objectName: 'image ' + (++objN) }); return { x: x + (w - iw) / 2, y: y + (h - ih) / 2, w: iw, h: ih } }

const GROUND = { 'Open': 'DARK', 'The problem': 'PAPER', 'The idea': 'NAVY', 'The record': 'PAPER', 'The path': 'SAFFRON', 'The analysis': 'DARK', 'The score': 'PAPER', 'The action': 'NAVY', 'The console': 'PAPER', 'Close': 'DARK' }
  // =====================================================================================
  // SLIDE 1 · cover
  pres.addSection({ title: 'Open' })
  {
    use('DARK'); const s = pres.addSlide({ masterName: 'COVER', sectionTitle: 'Open' })
    s.addImage({ path: path.join(IMG, 'cover.png'), x: 0, y: 0, w: 10, h: 5.625, altText: 'The live threat map from the console, dimmed, under a radar ring centred on India', objectName: 'cover art' })
    s.addImage({ path: emblem, x: 0.5, y: 0.42, w: 0.7, h: 0.7, altText: 'Odyssey emblem', objectName: 'emblem' })
    T(s, 'ODYSSEY', { x: 1.32, y: 0.47, w: 3, h: 0.3, fontSize: 12, bold: true, color: FG, charSpacing: 4, valign: 'middle' })
    T(s, 'National cyber threat early warning', { x: 1.32, y: 0.76, w: 4, h: 0.3, fontSize: 10, color: G2, valign: 'middle' })
    T(s, 'See the attack coming.', { x: 0.5, y: 1.85, w: 7.6, h: 0.8, fontSize: 40, bold: true, color: FG, charSpacing: -1.5, valign: 'top' })
    T(s, 'Public threat intelligence in. For every Indian organisation: which systems are at risk, how sure we are, what to do, and by when. On one laptop, with no cloud.', { x: 0.5, y: 2.78, w: 4.9, h: 0.9, fontSize: 12, color: 'D9D9D9', lineSpacingMultiple: 1.25 })
    fig(s, 0.5, 4.22, 'FIG 1 · THE LIVE THREAT MAP, AS THE CONSOLE DRAWS IT · 1 NOV 2026', 6.5)
    legend(s, 0.5, 4.52, [{ k: 'dot', c: PINK, t: 'attack source (SANS ISC DShield, REAL)' }, { k: 'ring', c: CYAN, t: 'botnet C2 (Feodo Tracker, REAL)' }, { k: 'dot', c: FG, t: 'operator state (SIM)' }, { k: 'dot', c: VIOLET, t: 'suspected compromise' }])
    T(s, 'FINAL ROUND  ·  D3COY 1.0  ·  DJS ISACA  ·  PROBLEM STATEMENT 01  ·  1 NOV 2026', { x: 0.5, y: 5.12, w: 7, h: 0.22, fontSize: 7.5, color: G2, charSpacing: 1.5, valign: 'middle' })
    s.addNotes('Open on the line. Behind it is the live map from the console: real attack origins from the last snapshot, each origin labelled real, each operator labelled simulated. Then two sentences: in July 2024 one supplier\'s unpatched server took about 300 Indian banks offline. The flaw had been public for six months. Odyssey exists so that the decision is never late again.')
  }

  // SLIDE 2 · the problem
  pres.addSection({ title: 'The problem' })
  {
    const s = on('The problem', GROUND['The problem']); title(s, 'The warning was public. The decision was late.')
    s.addImage({ path: path.join(IMG, 'field.png'), x: 0.5, y: 1.12, w: 9, h: 0.82, altText: 'A field of 16,730 marks, one per CVE published in October 2026; the fifth that say which product and version they affect are drawn bright', objectName: 'field art' })
    fig(s, 0.5, 1.99, 'FIG 2.1 · ONE MARK PER CVE PUBLISHED IN OCTOBER 2026 · CVE PROGRAM, NVD', 6)
    legend(s, 5.75, 2.07, [{ k: 'dot', c: FG, t: 'says which product and version (21%)' }, { k: 'dot', c: 'BDBDBD', t: 'does not (79%)' }])
    // three figures
    const cols = [[0.5, '16,730', 'new CVEs in October 2026 alone, from dozens of feeds, each needing a decision'], [3.5, '72% → 21%', 'of new CVEs say which product and version they affect, January against now'], [6.5, '29%', 'of the CVEs exploited in 2026 were attacked on or before the day they were announced']]
    for (const [x, n, t] of cols) { big(s, n, x, 2.38, 2.8, 34); T(s, t, { x, y: 3.0, w: 2.7, h: 0.5, fontSize: 9.5, color: G2, lineSpacingMultiple: 1.15 }) }
    // the C-Edge line
    T(s, 'C-Edge, 2024', { x: 0.5, y: 3.5, w: 3, h: 0.22, fontSize: 10, bold: true, color: FG })
    T(s, 'the Indian case the brief is written against', { x: 1.5, y: 3.5, w: 4, h: 0.22, fontSize: 9, color: G3 })
    s.addImage({ path: path.join(IMG, 'cedge.png'), x: 0.5, y: 3.8, w: 9, h: 0.8, altText: 'Timeline from January to August 2024: disclosure, the breach of 31 July, the CISA listing of 19 August; the red span is the half year the warning sat public', objectName: 'cedge art' })
    const X = (d) => 0.5 + 0.4 + d * 8.2
    T(s, [{ text: 'Jan 2024  ', options: { bold: true, color: FG } }, { text: 'Jenkins flaw disclosed; exploit public within days', options: { color: G2 } }], { x: X(0), y: 4.45, w: 3.4, h: 0.2, fontSize: 8.5 })
    T(s, [{ text: '31 Jul 2024  ', options: { bold: true, color: FG } }, { text: 'ransomware through the supplier; about 300 banks lose UPI and ATM', options: { color: G2 } }], { x: X(0.776) - 5.4, y: 3.74, w: 5.4, h: 0.2, fontSize: 8.5, align: 'right' })
    T(s, [{ text: '19 Aug 2024  ', options: { bold: true, color: FG } }, { text: 'CISA lists the flaw, 19 days after the banks went down', options: { color: G2 } }], { x: 4.6, y: 4.45, w: 4.9, h: 0.2, fontSize: 8.5, align: 'right' })
    legend(s, 0.5, 4.95, [{ k: 'bar', c: RED, t: 'the warning was public and nothing connected it to who was exposed (six months)' }, { k: 'ring', c: FG, t: 'event' }, { k: 'hub', t: 'the breach' }])
    s.addNotes('The problem is not a shortage of intelligence. It is volume, missing labels, and attackers who move on day zero. The field at the top is October alone, one mark per CVE; only a fifth say what they affect. The C-Edge case is the Indian example: six months of public warning, then 300 banks offline, then the national list catching up 19 days later. Sources: CVE Program, NVD, CISA KEV, NPCI statement of 31 July 2024.')
  }

  // SLIDE 3 · move the line left
  pres.addSection({ title: 'The idea' })
  {
    const s = on('The idea', GROUND['The idea']); title(s, 'Move the line left')
    s.addImage({ path: path.join(IMG, 'lanes.png'), x: 0.5, y: 1.1, w: 9, h: 2.9, altText: 'Two lanes: the reactive sequence above, Odyssey below; a red line marks where action starts on each, and an arrow carries it from the breach back to the first signal', objectName: 'lanes art' })
    T(s, 'THEN · REACT AFTER THE BREACH', { x: 0.5, y: 1.15, w: 4, h: 0.2, fontSize: 8, color: G3, charSpacing: 1.5, bold: true })
    T(s, 'NOW · ACT ON THE SIGNAL', { x: 0.5, y: 2.98, w: 4, h: 0.2, fontSize: 8, color: FG, charSpacing: 1.5, bold: true })
    const xs = [1.6, 3.9, 6.2, 8.5]
    const top = [['Flaw disclosed', 'public record, exploit code soon after'], ['Nothing connects it', 'to who runs the product'], ['Breach', 'the warning signs were public for months'], ['Listed', 'the national list catches up weeks later']]
    const bot = [['12 days before', 'a scanning surge on the decoy grid (SIM) raises a pre-disclosure warning'], ['Day 0', 'the CVE is matched to installed versions within seconds; a day-0 forecast flags the likely-exploited'], ['Warning', 'tier, confidence, a countdown, a notice in the operator\'s language; a person approves'], ['+20.5 days', 'median before CISA lists it, on real signals; up to 42']]
    top.forEach(([h, t], i) => { T(s, h, { x: xs[i] - 1.05, y: 2.0, w: 2.1, h: 0.2, fontSize: 10, bold: true, color: 'C9D1DE', align: 'center' }); T(s, t, { x: xs[i] - 1.05, y: 2.2, w: 2.1, h: 0.4, fontSize: 8.5, color: G3, align: 'center', lineSpacingMultiple: 1.1 }) })
    bot.forEach(([h, t], i) => { T(s, h, { x: xs[i] - 1.05, y: 3.42, w: 2.1, h: 0.22, fontSize: 11, bold: true, color: i === 3 ? ACC : FG, align: 'center' }); T(s, t, { x: xs[i] - 1.05, y: 3.66, w: 2.1, h: 0.62, fontSize: 8.5, color: G2, align: 'center', lineSpacingMultiple: 1.1 }) })
    T(s, 'Every number is recomputed live on the Proof page. Leads from simulated sensors are reported apart from leads on real signals.', { x: 0.5, y: 4.4, w: 9, h: 0.3, fontSize: 9, color: G2 })
    legend(s, 0.5, 4.95, [{ k: 'bar', c: RED, t: 'where action starts' }, { k: 'ring', c: '8A96AA', t: 'reactive step' }, { k: 'ring', c: FG, t: 'Odyssey step' }, { k: 'dash', c: FG, t: 'simulated signal (SIM)' }, { k: 'hub', t: 'a person decides' }])
    s.addNotes('Top lane is how it usually goes. Bottom lane is Odyssey: the decoy grid sees scanning before disclosure (simulated, labelled); on day zero a new CVE is matched to the inventory in seconds and the forecast flags the ones likely to be exploited; the warning goes out with its tier, confidence and clock; and CISA\'s list follows, a median 20.5 days later on real signals. Reactive systems start at the breach. We start at the signal. The red arrow is the whole pitch: the same line, moved left.')
  }

  // SLIDE 4 · every source, one record
  pres.addSection({ title: 'The record' })
  {
    const s = on('The record', GROUND['The record']); title(s, 'Every source, one record')
    s.addImage({ path: path.join(IMG, 'converge.png'), x: 0.5, y: 1.1, w: 7.9, h: 2.95, altText: 'Thirteen sources converge into one record, then nested circles show 82,104 CVEs narrowing to 2,277 relevant and 354 Critical warnings', objectName: 'converge art' })
    const names = [['NVD 2021 to 2026', 1], ['CISA KEV', 1], ['CISA SSVC', 1], ['FIRST EPSS', 1], ['CISA ICS and alerts', 1], ['CERT-In style advisories (SIM)', 0], ['MITRE ATT&CK', 1], ['NDMA SACHET', 1], ['SANS ISC DShield honeypots', 1], ['Feodo Tracker C2', 1], ['OpenPhish', 1], ['National decoy grid (SIM)', 0], ['Firewall flows (SIM)', 0]]
    const gh = ['VULNERABILITY DATABASES', 'ADVISORIES AND CONTEXT', 'TELEMETRY, INDICATORS, LOGS']
    let y = 1.1 + 0.22; let gi = 0; const starts = [0, 4, 8]
    names.forEach(([n, real], i) => { if (starts.includes(i) && i > 0) y += 0.16; if (starts.includes(i)) { T(s, gh[gi++], { x: 1.26, y: y - 0.21, w: 2.6, h: 0.12, fontSize: 6.5, color: G3, charSpacing: 1.2, bold: true }) }
      T(s, n, { x: 1.26, y: y - 0.085, w: 2.6, h: 0.17, fontSize: 8.5, color: real ? FG : G2, valign: 'middle' }); y += 0.195 })
    T(s, 'ONE RECORD', { x: 3.75, y: 2.1, w: 1.4, h: 0.16, fontSize: 6.5, color: G2, charSpacing: 1.5, bold: true, align: 'center' })
    T(s, 'hash-chained, provenance on every line', { x: 3.35, y: 3.08, w: 2.2, h: 0.18, fontSize: 7.5, color: G3, align: 'center' })
    big(s, '82,104', 8.5, 1.4, 1.0, 16, FG); T(s, 'CVEs published in 2026', { x: 8.5, y: 1.67, w: 1.0, h: 0.3, fontSize: 7.5, color: G2 })
    big(s, '2,277', 8.5, 2.43, 1.0, 16, FG); T(s, 'name a product an operator runs', { x: 8.5, y: 2.7, w: 1.0, h: 0.3, fontSize: 7.5, color: G2 })
    big(s, '354', 8.5, 3.46, 1.0, 16, RED); T(s, 'Critical warnings, each to a named operator', { x: 8.5, y: 3.73, w: 1.0, h: 0.4, fontSize: 7.5, color: G2 })
    fig(s, 0.5, 4.08, 'FIG 4 · 13 SOURCES, 10 REAL, 3 SIMULATED · AREA OF EACH CIRCLE BY SQUARE ROOT OF THE COUNT', 6.5)
    legend(s, 0.5, 4.3, [{ k: 'dot', c: FG, t: 'real public source' }, { k: 'ring', c: FG, t: 'simulated, labelled SIM' }, { k: 'hub', t: 'the record' }, { k: 'ring', c: G2, t: 'count, area by square root' }, { k: 'dot', c: RED, t: 'warnings' }])
    // the bundled real feeds, as the console shows them
    const r = fitImg(s, 'feeds', 0.5, 4.5, 6.9, 0.72, 'Console strip of bundled real feeds: ransomware in India, data breaches, ICS/OT advisories, supply-chain advisories, criminal networks')
    T(s, 'In and out in the formats a SOC already runs: STIX 2.1, TAXII 2.1, CSV. A partner\'s indicators are matched against the record in seconds. Also bundled, real: Exploit-DB, ransomware.live, Have I Been Pwned, GitHub advisories, Tor, Spamhaus DROP, Emerging Threats.', { x: 7.55, y: 4.48, w: 1.95, h: 0.78, fontSize: 7, color: G2, lineSpacingMultiple: 1.1 })
    s.addNotes('Thirteen sources, grouped as the brief lists them: vulnerability databases, public advisories, attack telemetry and indicators, and simulated logs, each labelled. The circles are the point: 82,000 CVEs this year become 2,277 that name something an operator runs, and 354 Critical warnings addressed to a named operator. The record goes in and out as STIX, TAXII and CSV; the strip at the bottom is the console\'s own real-feed row.')
  }

  // SLIDE 5 · one advisory, start to finish
  pres.addSection({ title: 'The path' })
  {
    const s = on('The path', GROUND['The path']); title(s, 'One advisory, start to finish')
    s.addImage({ path: path.join(IMG, 'steps.png'), x: 0.5, y: 1.22, w: 9, h: 1.2, altText: 'Five rings on one line; the fifth has a red hub where a person decides', objectName: 'steps art' })
    const xs = [1.4, 3.2, 5.0, 6.8, 8.6]
    const steps = [['A real advisory arrives', 'CISA\'s ICS advisory for Siemens WinCC, read by the security LLM. It works even when the advisory carries no CVE id.'], ['Versions parsed', 'Machine-readable ranges lifted from the text: vers:intdot/<8.0.0.11 and vers:all/*.'], ['Exposure found', '13 WinCC assets at 7 operators, checked against the inventory version by version. Patched hosts are marked safe.'], ['Risk assigned', 'A score with its working, an SSVC tier, a CERT-In deadline. Patch where a fix exists, mitigation where none does.'], ['People decide', 'A notice proposed to each operator in its own language. An analyst approves. Every step lands in the audit trail.']]
    steps.forEach(([h, t], i) => { T(s, String(i + 1), { x: xs[i] - 0.3, y: 1.62, w: 0.6, h: 0.4, fontSize: 16, bold: true, color: i === 4 ? ACC : FG, align: 'center', valign: 'middle' })
      T(s, h, { x: xs[i] - 0.85, y: 2.55, w: 1.7, h: 0.24, fontSize: 10.5, bold: true, color: FG, align: 'center' })
      T(s, t, { x: xs[i] - 0.85, y: 2.82, w: 1.7, h: 1.05, fontSize: 8.5, color: G2, align: 'center', lineSpacingMultiple: 1.12 }) })
    T(s, 'The same path runs for every input', { x: 0.5, y: 3.95, w: 3.2, h: 0.24, fontSize: 10.5, bold: true, color: FG })
    const chips = ['a KEV entry', 'a new CVE from NVD', 'a scanning surge on the decoys', 'a partner\'s indicator list', 'a disaster alert from SACHET']
    let cx = 0.5; chips.forEach((c) => { const w = c.length * 0.052 + 0.28; chip(s, cx, 4.24, w, 0.26, c, { color: FG }); cx += w + 0.1 })
    T(s, 'each is matched to who is exposed, scored, and turned into something a person can approve.', { x: 0.5, y: 4.57, w: 9, h: 0.22, fontSize: 9, color: G2 })
    fig(s, 0.5, 4.8, 'FIG 5 · THE EXAMPLE USE CASE, RUN ON THE REAL CISA ADVISORY FOR SIEMENS WINCC', 6)
    legend(s, 0.5, 5.03, [{ k: 'ring', c: FG, t: 'automated step, written to the audit trail' }, { k: 'dot', c: ACC, t: 'a person decides' }, { k: 'none', t: 'the rings carry the chakra of the emblem: 24 spokes, one record' }])
    s.addNotes('This is the walk-through in the demo. A real CISA advisory for Siemens WinCC comes in. The model reads it, the version ranges are parsed, thirteen assets at seven operators are found exposed, each gets a risk with its working and a deadline, and the notices are proposed in Marathi, Gujarati and Hindi for a person to approve. Then: the same path for every input.')
  }

  // SLIDE 6 · patterns, not noise
  pres.addSection({ title: 'The analysis' })
  {
    const s = on('The analysis', GROUND['The analysis']); title(s, 'Patterns, not noise')
    const r = fitImg(s, 'graph', 0.5, 1.08, 4.3, 3.82, 'The intelligence graph in the console: 115 entities, 447 links, laid out by community')
    fig(s, 0.5, 4.93, 'FIG 6 · INTEL › GRAPH · 115 NODES · 447 LINKS · 146 PUBLIC', 4.4)
    legend(s, 0.5, 5.13, [{ k: 'dot', c: BLUE, t: 'colour: community' }, { k: 'dot', c: FG, t: 'size: links' }, { k: 'diamond', c: FG, t: 'threat group (overlap, not attribution)' }, { k: 'tri', c: FG, t: 'live signal' }], { size: 7 })
    const blocks = [['Reads', 'A security LLM (MiST-8B) reads advisories and writes every brief. 22 of 23 briefs passed the fact validator; a sentence that fails is withheld, never shown.'], ['Relates', 'SecureBERT 2.0 links entities and related threats; a clustering model groups campaigns (12 active). Threat groups come from the ATT&CK record as overlap, never attribution.'], ['Detects', 'Scanning surges, C2 beacons and flow anomalies, every 5 seconds. A hostile advisory with hidden instructions is caught by the injection guard, 5 of 5, and still scored by the rules.']]
    blocks.forEach(([h, t], i) => { const y = 1.12 + i * 0.98
      ringS(s, 5.33, y + 0.14, 0.3, FG, 0.75); T(s, String(i + 1), { x: 5.18, y: y + 0.01, w: 0.3, h: 0.26, fontSize: 9, bold: true, color: FG, align: 'center', valign: 'middle' })
      T(s, h, { x: 5.62, y, w: 3.9, h: 0.28, fontSize: 13, bold: true, color: FG, valign: 'middle' })
      T(s, t, { x: 5.62, y: y + 0.32, w: 3.9, h: 0.6, fontSize: 9, color: G2, lineSpacingMultiple: 1.15 }) })
    rect(s, 5.18, 4.1, 4.32, 0.95, FG)
    T(s, 'AI explains. Rules decide.', { x: 5.38, y: 4.17, w: 4, h: 0.32, fontSize: 15, bold: true, color: BG, valign: 'middle' })
    T(s, 'No model sets a score, a tier or a deadline. All of it runs on one RTX 4070 laptop, 0 cloud calls; each job\'s model is set in a config file and was chosen by measurement on 2026 CVEs.', { x: 5.38, y: 4.5, w: 3.95, h: 0.5, fontSize: 8, color: CARDSUB, lineSpacingMultiple: 1.12 })
    s.addNotes('Three jobs for the models: read, relate, detect. Read: the security LLM reads advisories and writes the brief, and the brief is fact-checked line by line. Relate: entities, related threats, campaigns, and the graph on the left, every entity in the record and how they connect, coloured by community. Detect: surges, beacons and anomalies every five seconds, plus the guard that catches a poisoned advisory. The rule we never break: AI explains, rules decide. And it all runs here, offline.')
  }

  // SLIDE 7 · what goes first
  pres.addSection({ title: 'The score' })
  {
    const s = on('The score', GROUND['The score']); title(s, 'What goes first')
    T(s, [{ text: 'Risk = 100 × Relevance × Importance × (', options: { color: FG } }, { text: '0.55', options: { color: RED, bold: true } }, { text: ' Likelihood + ', options: { color: FG } }, { text: '0.30', options: { color: RED, bold: true } }, { text: ' Severity + ', options: { color: FG } }, { text: '0.15', options: { color: RED, bold: true } }, { text: ' Evidence)', options: { color: FG } }], { x: 0.5, y: 1.0, w: 9, h: 0.3, fontSize: 11, fontFace: MONO, valign: 'middle' })
    T(s, 'LIKELIHOOD, FROM EVIDENCE, IN RANK ORDER', { x: 0.5, y: 1.48, w: 4.5, h: 0.18, fontSize: 7.5, color: G3, charSpacing: 1.5, bold: true })
    const ladder = [['On CISA KEV  ·  SSVC says active  ·  exploit seen on 2+ decoys', 1.0, 'ev'], ['The vendor says exploited in the wild', 0.8, 'ev'], ['A public proof of concept', 0.5, 'ev'], ['A scanning surge on the decoy grid, decays with age', 0.4, 'ev'], ['EPSS ≥ 0.5  ·  CVSS ≥ 9  ·  automatable', 0, 'co'], ['The day-0 forecast', 0, 'pr']]
    const bx = 0.5, bw = 2.3, ly = 1.75
    ladder.forEach(([t, v, kind], i) => { const y = ly + i * 0.47
      T(s, t, { x: bx, y, w: 4.5, h: 0.2, fontSize: 9, color: kind === 'ev' ? FG : G2, valign: 'middle' })
      if (kind === 'ev') { rect(s, bx, y + 0.24, bw * v, 0.12, i === 0 ? ACC : FG); T(s, v.toFixed(1), { x: bx + bw * v + 0.08, y: y + 0.2, w: 0.5, h: 0.2, fontSize: 9, bold: true, color: FG, valign: 'middle', fontFace: MONO }) }
      else if (kind === 'co') { rect(s, bx, y + 0.24, 0.12, 0.12, G3); T(s, 'corroborate', { x: bx + 0.2, y: y + 0.2, w: 1.5, h: 0.2, fontSize: 8.5, color: G2, valign: 'middle', fontFace: MONO }) }
      else { s.addShape(pres.ShapeType.rect, { x: bx, y: y + 0.24, w: 0.8, h: 0.12, fill: { color: BG }, line: { color: G2, width: 0.75, dashType: 'dash' }, objectName: 'ladder dash' }); T(s, 'prediction, not evidence', { x: bx + 0.9, y: y + 0.2, w: 2, h: 0.2, fontSize: 8.5, color: G2, valign: 'middle', fontFace: MONO }) } })
    legend(s, 0.5, 5.05, [{ k: 'bar', c: FG, t: 'floor set by the rule' }, { k: 'bar', c: RED, t: 'certain' }, { k: 'square', c: G3, t: 'corroborates' }, { k: 'dash', c: G2, t: 'prediction' }], { size: 7 })
    T(s, 'Importance: criticality tier 5 to 2, internet-facing ×1.2, blast radius up to ×1.3.  Relevance: the installed version checked against NVD, the vendor and the advisory.  Confidence is scored apart, from A to F source grades.', { x: 0.5, y: 4.54, w: 4.6, h: 0.36, fontSize: 6.8, color: G3, lineSpacingMultiple: 1.1 })
    // the receipt: a white card, the one place a decision is settled
    const rx = 5.4, ry = 1.46, rw = 4.1, rh = 3.7
    rect(s, rx, ry, rw, rh, FG)
    const M = (text, x, y, w, o = {}) => T(s, text, Object.assign({ x, y, w, h: 0.18, fontSize: 8, fontFace: MONO, color: BG, valign: 'middle' }, o))
    M('WARNING RECEIPT', rx + 0.2, ry + 0.14, 2.5, { bold: true, charSpacing: 1 }); M('build 1 Nov 2026 · REAL CVE', rx + rw - 2.4, ry + 0.14, 2.2, { align: 'right', color: CARDSUB })
    T(s, 'Tapti Thermal Energy  ·  Ivanti Connect Secure 22.8R2.4', { x: rx + 0.2, y: ry + 0.4, w: rw - 0.4, h: 0.22, fontSize: 10, bold: true, color: BG, valign: 'middle' })
    M('CVE-2026-111357 · VPN gateway · internet-facing · tier 1', rx + 0.2, ry + 0.63, rw - 0.4, { color: CARDSUB })
    line(s, rx + 0.2, ry + 0.9, rx + rw - 0.2, ry + 0.9, CARDSUB, 0.5)
    const rows = [['Likelihood', '0.55 × 1.0', '45.8', 'KEV 30 Oct · SSVC active · vendor: in the wild'], ['Severity', '0.30 × 1.0', '25.0', 'SSVC technical impact: total'], ['Evidence', '0.15 × 1.0', '12.5', 'CISA (A), NVD (A), vendor (B) agree'], ['Relevance', '× 1.0', '', 'NVD and the vendor both list 22.8R2.4 as affected'], ['Importance', '× 0.83', '', 'tier 1 · internet-facing ×1.2 · blast radius']]
    rows.forEach(([a, b, c, d], i) => { const y = ry + 0.98 + i * 0.4
      M(a, rx + 0.2, y, 1.2, { bold: true }); M(b, rx + 1.35, y, 1.2); if (c) M(c, rx + rw - 1.2, y, 1.0, { align: 'right', bold: true })
      M(d, rx + 0.2, y + 0.18, rw - 0.4, { color: CARDSUB, fontSize: 7.5 }) })
    line(s, rx + 0.2, ry + 3.0, rx + rw - 0.2, ry + 3.0, CARDSUB, 0.5)
    M('RISK', rx + 0.2, ry + 3.1, 1, { bold: true, fontSize: 10 }); T(s, '83.3', { x: rx + rw - 1.4, y: ry + 3.03, w: 1.2, h: 0.3, fontSize: 18, bold: true, color: RED, align: 'right', fontFace: MONO, valign: 'middle' })
    M('Critical · SSVC: Act · 12 h to patch or mitigate · P(compromise) 18%, no beacon seen', rx + 0.2, ry + 3.36, rw - 0.4, { color: CARDSUB, fontSize: 7, h: 0.3, valign: 'top' })
    fig(s, 5.4, 1.3, 'FIG 7 · ONE REAL WARNING FROM THIS BUILD, FACTOR BY FACTOR', 4.1)
    s.addNotes('The score is a formula anyone can check. Likelihood comes from evidence in rank order, and the ladder shows what counts and how much: a KEV listing or an active SSVC verdict is 1.0, a vendor claim 0.8, proof of concept 0.5, a decoy surge 0.4 and decaying, while EPSS and CVSS only corroborate and the forecast is a prediction, not evidence. The receipt on the right is one real warning from this build: 83.3, Critical, Act, twelve hours. The tier follows CISA\'s SSVC decision method; confidence is scored separately from risk.')
  }

  // SLIDE 8 · what to do, and by when
  pres.addSection({ title: 'The action' })
  {
    const s = on('The action', GROUND['The action']); title(s, 'What to do, and by when')
    T(s, 'ON EVERY WARNING', { x: 0.5, y: 1.05, w: 3, h: 0.18, fontSize: 7.5, color: G3, charSpacing: 1.5, bold: true })
    const acts = [['Patch', 'to a named fixed release, never a downgrade (22.8R2.5, 25.1.3.0 for the Ivanti case)'], ['Block', 'the indicators: STIX 2.1 export, risk lists for the firewall, C2 addresses refanged'], ['Investigate', 'a hunt playbook, ATT&CK mitigations, forensic triage where CISA asks for it'], ['Report', 'the CERT-In 6-hour report pre-drafted; RBI, SEBI, DPDP and NCIIPC clocks shown'], ['Notify', 'a notice in the operator\'s own language; a person approves before it goes']]
    acts.forEach(([h, t], i) => { const y = 1.32 + i * 0.56
      ringS(s, 0.66, y + 0.13, 0.28, FG, 0.75); if (i === 4) dot(s, 0.66, y + 0.13, 0.07, RED); else T(s, String(i + 1), { x: 0.52, y: y + 0.01, w: 0.28, h: 0.24, fontSize: 8, bold: true, color: FG, align: 'center', valign: 'middle' })
      T(s, [{ text: h + '  ', options: { bold: true, color: FG } }, { text: t, options: { color: G2 } }], { x: 0.92, y, w: 2.7, h: 0.5, fontSize: 8.5, lineSpacingMultiple: 1.12 }) })
    // burn-down
    T(s, 'RISK PLAN · FEWEST CHANGES, MOST RISK REMOVED', { x: 3.75, y: 1.05, w: 3.4, h: 0.18, fontSize: 7.5, color: G3, charSpacing: 1.5, bold: true })
    s.addImage({ path: path.join(IMG, 'burndown.png'), x: 3.7, y: 1.3, w: 3.0, h: 2.4, altText: 'Burn-down curve: share of national risk removed against change tickets in plan order, with rings at 93 tickets (50%) and 205 (80%)', objectName: 'burndown art' })
    big(s, '93', 5.15, 2.42, 0.8, 18); T(s, 'changes remove half the national risk', { x: 5.78, y: 2.44, w: 1.1, h: 0.3, fontSize: 7.5, color: G2, lineSpacingMultiple: 1.05 })
    big(s, '205', 5.15, 2.9, 0.8, 18); T(s, 'remove 80%, of 344 change tickets', { x: 5.78, y: 2.92, w: 1.1, h: 0.3, fontSize: 7.5, color: G2, lineSpacingMultiple: 1.05 })
    T(s, '100%', { x: 3.7, y: 1.36, w: 0.34, h: 0.14, fontSize: 6, color: G2, align: 'right' }); T(s, '0', { x: 3.7, y: 3.33, w: 0.34, h: 0.14, fontSize: 6, color: G2, align: 'right' })
    T(s, 'share of national risk removed', { x: 3.7, y: 3.5, w: 1.5, h: 0.16, fontSize: 6.5, color: G3 }); T(s, 'change tickets, in plan order →', { x: 5.2, y: 3.5, w: 1.5, h: 0.16, fontSize: 6.5, color: G3, align: 'right' })
    // dials
    T(s, 'BY WHEN · CERT-IN BLUEPRINT', { x: 7.3, y: 1.05, w: 2.2, h: 0.18, fontSize: 7.5, color: G3, charSpacing: 1.5, bold: true })
    s.addImage({ path: path.join(IMG, 'dials.png'), x: 7.3, y: 1.3, w: 0.6, h: 2.4, altText: 'Five dials: 6, 12, 24, 72 and 120 hours as arcs on a 120-hour face', objectName: 'dials art' })
    const dl = [['6 h', 'suspected compromise', RED], ['12 h', 'known-exploited, internet-facing', FG], ['24 h', 'Critical', FG], ['72 h', 'High', FG], ['120 h', 'Medium', FG]]
    dl.forEach(([h, t, c], i) => { const y = 1.3 + 0.24 + i * 0.46 - 0.2; T(s, h, { x: 7.95, y, w: 1.5, h: 0.2, fontSize: 10, bold: true, color: c, valign: 'middle' }); T(s, t, { x: 7.95, y: y + 0.19, w: 1.6, h: 0.18, fontSize: 7.5, color: G2, valign: 'middle' }) })
    // the workflow
    T(s, 'ONE WORKFLOW PER WARNING', { x: 0.5, y: 3.98, w: 3, h: 0.18, fontSize: 7.5, color: G3, charSpacing: 1.5, bold: true })
    const wf = ['Issued', 'Acknowledged', 'Mitigating', 'Verifying', 'Closed'], wx = [0.66, 1.95, 3.24, 4.53, 5.82]
    line(s, 0.66, 4.4, 5.82, 4.4, G3, 0.5)
    wf.forEach((n, i) => { ringS(s, wx[i], 4.4, 0.2, FG, 0.75); dot(s, wx[i], 4.4, 0.06, i === 0 ? ACC : FG); T(s, n, { x: wx[i] - 0.6, y: 4.56, w: 1.2, h: 0.18, fontSize: 8.5, color: i === 0 ? FG : G2, align: 'center' }) })
    T(s, 'Odyssey proposes; a person approves anything consequential. Evidence-based notices, digests and hunts run on their own. Every action is in a hash-chained audit trail.', { x: 6.45, y: 4.0, w: 3.05, h: 0.75, fontSize: 8, color: G2, lineSpacingMultiple: 1.15 })
    legend(s, 0.5, 5.02, [{ k: 'hub', t: 'a person decides' }, { k: 'bar', c: FG, t: 'curve = risk removed in plan order' }, { k: 'dash', c: RED, t: 'milestone' }, { k: 'ring', c: FG, t: 'dial = deadline on a 120-hour face' }, { k: 'bar', c: RED, t: 'the 6-hour incident clock' }], { size: 7.5 })
    s.addNotes('Every warning ends in something a team can do: patch to a named release, block the indicators, hunt, report, notify. Nationally, the risk plan orders the fewest changes that remove the most risk: the curve. Each warning moves through one workflow, with a real countdown from the CERT-In timelines, the dials, and a person approves anything consequential.')
  }

  // SLIDE 9 · one screen per question
  pres.addSection({ title: 'The console' })
  {
    const s = on('The console', GROUND['The console']); title(s, 'One screen per question')
    const cw = 2.9, ch = 1.52, gx = 0.15, xs = [0.5, 0.5 + cw + gx, 0.5 + 2 * (cw + gx)], ys = [1.08, 1.08 + ch + 0.5]
    const cells = [['now', 'Now: what needs me; the brief and the score a click away', 'SIM operators · REAL CVEs'], ['world', 'Where attacks start, and the operators they reach', 'origins REAL · landing points SIM'], ['india', 'India by Critical warnings; compromise in violet', 'operators SIM · warnings from REAL CVEs'], ['heat', 'Intel: real attacks by port and day; threats by technology', 'DShield, REAL'], ['site', 'A state in 3D: its agencies and the attack origins', 'buildings SIM · origins REAL']]
    cells.forEach(([k, cap, prov], i) => { const x = xs[i % 3], y = ys[Math.floor(i / 3)]
      rect(s, x, y, cw, ch, BG === K ? '0B0B0B' : 'EDEDED'); fitImg(s, k, x + 0.04, y + 0.04, cw - 0.08, ch - 0.08, cap)
      T(s, cap, { x, y: y + ch + 0.05, w: cw, h: 0.3, fontSize: 7.5, color: FG, lineSpacingMultiple: 1.05 })
      T(s, prov, { x, y: y + ch + 0.36, w: cw, h: 0.12, fontSize: 6.5, color: G3, fontFace: MONO }) })
    // sixth cell: the six destinations
    const x6 = xs[2], y6 = ys[1]
    rect(s, x6, y6, cw, ch, FG)
    const dest = [['Now', 'what needs me'], ['Live', 'what is happening, shield included'], ['SOC', 'the cases'], ['Intel', 'what is under attack, the graph, indicators'], ['Organisations', 'one operator at a time'], ['Proof', 'the numbers, recomputed on stage']]
    dest.forEach(([n, t], i) => { const y = y6 + 0.1 + i * 0.22; T(s, [{ text: n + '  ', options: { bold: true, color: BG } }, { text: t, options: { color: CARDSUB } }], { x: x6 + 0.18, y, w: cw - 0.3, h: 0.22, fontSize: 8, valign: 'middle' }) })
    T(s, 'Every panel says REAL or SIM. Feeds are bundled, so nothing waits on the network. A night-shift mode for the room.', { x: x6, y: y6 + ch + 0.05, w: cw, h: 0.3, fontSize: 7.5, color: FG, lineSpacingMultiple: 1.05 })
    T(s, 'six screens · one question each', { x: x6, y: y6 + ch + 0.36, w: cw, h: 0.12, fontSize: 6.5, color: G3, fontFace: MONO })
    s.addNotes('Six screens, one question each. Now: what needs me. Live: what is happening, including real attacks on a real app behind the shield. SOC: the cases. Intel: what is under attack, which technologies, the graph, indicators. Organisations: one operator at a time. Proof: the numbers, recomputed on stage. The threat map and the India view are drawn from real feeds bundled into the console; each screenshot carries its own key.')
  }

  // SLIDE 10 · it runs here, offline
  pres.addSection({ title: 'Close' })
  {
    const s = on('Close', GROUND['Close']); title(s, 'It runs here. Offline.')
    const stats = [['0', 'internet or cloud AI calls, ever; the feeds are snapshot-backed'], ['1', 'laptop: an RTX 4070 with 8 GB, every model under 8B parameters'], ['85 s', 'to re-score the nation: 15 operators, 612 systems, 2,277 flaws'], ['221', 'engine tests green; 26 of 26 product flows; 25 of 26 browser steps']]
    stats.forEach(([n, t], i) => { const x = 0.5 + i * 2.3; big(s, n, x, 1.05, 2.1, 40, i === 0 ? ACC : FG); T(s, t, { x, y: 1.78, w: 2.05, h: 0.5, fontSize: 8.5, color: G2, lineSpacingMultiple: 1.12 }) })
    // the backtest, native
    T(s, 'SHARE OF 110 EXPLOITED CVES (KEV, AUG–OCT 2026) EACH RULE FLAGS', { x: 0.5, y: 2.5, w: 5.0, h: 0.18, fontSize: 7, color: G3, charSpacing: 1.2, bold: true })
    s.addChart(pres.ChartType.bar, [{ name: 'Flagged', labels: ['EPSS ≥ 0.1 alone', 'CVSS 9 or higher alone', 'Odyssey evidence rules'], values: [51, 47, 100] }],
      { x: 0.45, y: 2.68, w: 4.7, h: 1.55, barDir: 'bar', chartColors: ['6E6E6E', '6E6E6E', RED], barGapWidthPct: 45, showValue: true, dataLabelPosition: 'outEnd', dataLabelColor: W, dataLabelFontSize: 8, dataLabelFontFace: '+mn-lt', dataLabelFormatCode: '0"%"',
        catAxisLabelColor: W, catAxisLabelFontSize: 8, catAxisLabelFontFace: '+mn-lt', catAxisLineShow: false, valAxisHidden: true, valAxisMaxVal: 118, valAxisMinVal: 0, valGridLine: { style: 'none' }, catGridLine: { style: 'none' }, showLegend: false, showTitle: false, plotArea: { fill: { color: BG } }, chartArea: { fill: { color: BG } }, objectName: 'backtest chart' })
    legend(s, 0.5, 4.36, [{ k: 'square', c: '6E6E6E', t: 'a single public score, on its own' }, { k: 'square', c: RED, t: 'Odyssey\'s evidence rules' }], { size: 7.5 })
    T(s, [{ text: 'KEV is one of our inputs, so 110 of 110 is by design. The honest test is out of time: ', options: { color: FG, bold: true } }, { text: 'the day-0 forecast, frozen in July, caught 61.1% of the CVEs later exploited in August to October while flagging 2%. CVSS ≥ 9 at the same budget caught 16.7%.', options: { color: G2 } }], { x: 0.5, y: 4.54, w: 4.7, h: 0.6, fontSize: 8.5, lineSpacingMultiple: 1.15 })
    // right column: what is real, what is simulated, what was proven on the wire
    const rc = [['Real, public', 'CVEs, KEV, SSVC, EPSS, CISA advisories, DShield, Feodo, OpenPhish, SACHET, Exploit-DB, ransomware.live, breach and network lists.', GREEN], ['Simulated, labelled', 'the 15 operators and their inventory, the decoy grid, the firewall logs.', G2], ['Proven on the wire', '45 of 45 real web attacks detected and blocked inline, 0 false positives, about 15 ms each. Models, scoring and workflow are explained on the Proof page; the test bench is a click away.', FG]]
    rc.forEach(([h, t, c], i) => { const y = 2.5 + i * 0.66; dot(s, 5.63, y + 0.1, 0.1, c); T(s, h, { x: 5.8, y, w: 3.7, h: 0.2, fontSize: 9.5, bold: true, color: FG, valign: 'middle' }); T(s, t, { x: 5.8, y: y + 0.22, w: 3.7, h: 0.48, fontSize: 8, color: G2, lineSpacingMultiple: 1.12 }) })
    rect(s, 5.58, 4.66, 3.92, 0.47, FG)
    T(s, 'Real data. Measured claims. A human in the loop. Zero cloud calls.', { x: 5.72, y: 4.66, w: 3.7, h: 0.47, fontSize: 10.5, bold: true, color: BG, valign: 'middle' })
    s.addNotes('Close on what is in the room: a working prototype on this laptop, no cloud, every model under 8B. Eighty-five seconds to re-score the nation. The chart is the backtest on 110 real exploited CVEs; say that 110 of 110 is by design because KEV is one of our inputs, and that the honest test is the forecast. Then the line: real data, measured claims, a human in the loop, zero cloud calls.')
  }

  await pres.writeFile({ fileName: OUT })
  await applyTheme(OUT, THEME)
  console.log('wrote', OUT)
}
build().catch((e) => { console.error(e); process.exit(1) })
