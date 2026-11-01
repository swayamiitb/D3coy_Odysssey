// Odyssey, the one final deck: the best page of each of the three versions, on one theme.
// Deep navy on every slide, bone text, saffron as the only accent, red kept for threat; bone cards where a decision is made.
// Fonts are Windows-native (the demo laptop): Georgia titles, Bahnschrift condensed numerals, Segoe UI text, Consolas markers.
// NODE_PATH=./node_modules node build_one.js <out.pptx>
const path = require('path')
const pptxgen = require('pptxgenjs')
const { applyTheme } = require('C:/Users/swaya/.claude/skills/synced/eecf8b7f-cbb3-4da8-92a1-45b413afe457_99f417d6-3507-456f-9f1a-9428dc374a93/pptx/scripts/apply_theme.js')

const OUT = process.argv[2] || 'odyssey-one.pptx'
const IMG = (n) => path.join(__dirname, 'img', n)

// palette
const NAVY = '0F1A33', CARD = '16243F', HAIR = '2C3D66', BONE = 'F5F2EA', MUTE = '9FB0D6', DIM = '6F80A8'
const SAFF = 'EF7F33', RED = 'FF4B3A', INK = '0C0C0E', INKMUTE = '5C5C60', PAPERHAIR = 'D6D1C6', VIOLET = '9B7BFF'
const NUM = 'Bahnschrift SemiBold Condensed', SERIF = 'Georgia', SANS = 'Segoe UI', MONO = 'Consolas'

const THEME = {
  name: 'Odyssey',
  headFontFace: SERIF,
  bodyFontFace: SANS,
  colors: { dk1: INK, lt1: BONE, dk2: NAVY, lt2: CARD, accent1: SAFF, accent2: RED, accent3: MUTE, accent4: DIM, accent5: VIOLET, accent6: HAIR, hlink: SAFF, folHlink: DIM },
}

const pres = new pptxgen()
pres.layout = 'LAYOUT_16x9'            // 10 x 5.625 in
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace }
pres.author = 'Team Odyssey'
pres.title = 'Odyssey, final round'
pres.subject = 'D3COY 1.0, PS-01: AI-Based National Cyber Threat Early Warning System'

pres.defineSlideMaster({
  title: 'MAIN',
  background: { color: NAVY },
  objects: [
    { placeholder: { options: { name: 'title', type: 'title', x: 0.5, y: 0.56, w: 9, h: 0.6, fontFace: SERIF, fontSize: 30, bold: true, color: BONE, margin: 0, valign: 'top', align: 'left' }, text: '' } },
  ],
})
pres.defineSlideMaster({ title: 'COVER', background: { color: NAVY }, objects: [] })

// helpers ---------------------------------------------------------------------------------------------------------
const T = (slide, text, o) => slide.addText(text, { isTextBox: true, margin: 0, valign: 'top', fontFace: SANS, ...o })
const mono = (slide, text, o) => T(slide, text, { fontFace: MONO, fontSize: 8, color: MUTE, charSpacing: 1.5, ...o })
const card = (slide, x, y, w, h, fill, name, line) => slide.addShape(pres.ShapeType.roundRect, { x, y, w, h, fill: { color: fill }, rectRadius: 0.08, line: line ? { color: line, width: 0.75 } : { color: fill, width: 0 }, objectName: name })
const hair = (slide, x, y, w, name, color = HAIR, width = 0.75) => slide.addShape(pres.ShapeType.line, { x, y, w, h: 0, line: { color, width }, objectName: name })
const vhair = (slide, x, y, h, name, color = HAIR) => slide.addShape(pres.ShapeType.line, { x, y, w: 0, h, line: { color, width: 0.75 }, objectName: name })
const dot = (slide, cx, cy, r, color, name, o = {}) => slide.addShape(pres.ShapeType.ellipse, { x: cx - r, y: cy - r, w: 2 * r, h: 2 * r, fill: o.hollow ? { color: o.bg ?? NAVY } : { color }, line: { color, width: o.hollow ? 1.25 : 0 }, objectName: name })
const ring = (slide, x, y, label, size, o = {}) => {
  const stroke = o.stroke ?? BONE, fill = o.fill ?? NAVY, text = o.text ?? BONE
  slide.addShape(pres.ShapeType.ellipse, { x, y, w: size, h: size, fill: { color: fill }, line: { color: stroke, width: 1.25 }, objectName: `ring ${label}` })
  T(slide, String(label), { x, y, w: size, h: size, fontFace: MONO, fontSize: o.size ?? 9, bold: true, color: text, align: 'center', valign: 'middle', objectName: `ring ${label} text` })
}
const eyebrow = (slide, text, o = {}) => mono(slide, text, { x: 0.5, y: 0.34, w: 7.5, h: 0.2, color: SAFF, charSpacing: 2.5, ...o })
const chip = (slide, text, o = {}) => {
  const w = o.w ?? Math.min(4.2, 0.25 + text.length * 0.068)
  const x = o.x ?? 9.5 - w, y = o.y ?? 0.27
  slide.addShape(pres.ShapeType.roundRect, { x, y, w, h: 0.3, fill: { color: o.fill ?? NAVY }, rectRadius: 0.04, line: { color: o.stroke ?? BONE, width: 0.75 }, objectName: `${text} chip` })
  T(slide, text, { x, y, w, h: 0.3, fontFace: MONO, fontSize: o.size ?? 7.5, color: o.color ?? BONE, align: 'center', valign: 'middle', charSpacing: 1, objectName: `${text} chip text` })
}
const foot = (slide, left, n) => {
  mono(slide, left, { x: 0.5, y: 5.22, w: 8.2, h: 0.2, fontSize: 7.5, color: DIM, charSpacing: 0.8 })
  mono(slide, `${String(n).padStart(2, '0')} / 10`, { x: 8.7, y: 5.22, w: 0.8, h: 0.2, fontSize: 7.5, color: DIM, align: 'right' })
}
// a legend row: items {m: dot|ring|rect|diamond|tri|line|none, c, t}; widths estimated for Segoe UI
const legend = (slide, x, y, items, o = {}) => {
  const fs = o.size ?? 8, color = o.color ?? MUTE, cw = fs * 0.0072, gapItem = o.gap ?? 0.22
  let cx = x
  items.forEach((it, i) => {
    const m = it.m ?? 'dot', mc = it.c ?? BONE, ms = 0.1
    if (m !== 'none') {
      const my = y + 0.1 - ms / 2
      if (m === 'dot') dot(slide, cx + ms / 2, y + 0.1, ms / 2, mc, `legend ${i} marker`)
      else if (m === 'ring') dot(slide, cx + ms / 2, y + 0.1, ms / 2, mc, `legend ${i} marker`, { hollow: true, bg: o.bg ?? NAVY })
      else if (m === 'rect') slide.addShape(pres.ShapeType.rect, { x: cx, y: my, w: ms, h: ms, fill: { color: mc }, line: { color: mc, width: 0 }, objectName: `legend ${i} marker` })
      else if (m === 'diamond') slide.addShape(pres.ShapeType.diamond, { x: cx, y: my, w: ms, h: ms, fill: { color: mc }, line: { color: mc, width: 0 }, objectName: `legend ${i} marker` })
      else if (m === 'tri') slide.addShape(pres.ShapeType.triangle, { x: cx, y: my, w: ms, h: ms, fill: { color: mc }, line: { color: mc, width: 0 }, objectName: `legend ${i} marker` })
      else if (m === 'line') hair(slide, cx - 0.04, y + 0.1, ms + 0.08, `legend ${i} marker`, mc, 2)
      else if (m === 'arrow') slide.addShape(pres.ShapeType.rightArrow, { x: cx - 0.03, y: my + 0.015, w: ms + 0.1, h: ms - 0.03, fill: { color: mc }, line: { color: mc, width: 0 }, objectName: `legend ${i} marker` })
      cx += ms + 0.07 + (m === 'arrow' ? 0.1 : 0)
    }
    const tw = it.t.length * cw + 0.05
    T(slide, it.t, { x: cx, y, w: tw, h: 0.2, fontSize: fs, color: it.tc ?? color, valign: 'middle', objectName: `legend ${i} text` })
    cx += tw + gapItem
  })
  return cx
}
const big = (slide, num, x, y, w, o = {}) => T(slide, num, { x, y, w, h: o.h ?? 0.8, fontFace: NUM, fontSize: o.size ?? 54, bold: true, color: o.color ?? BONE, valign: 'bottom', align: o.align ?? 'left', charSpacing: o.cs ?? 0, objectName: `${num} figure` })
const shot = (slide, file, x, y, w, h, name, o = {}) => {
  slide.addShape(pres.ShapeType.rect, { x: x - 0.02, y: y - 0.02, w: w + 0.04, h: h + 0.04, fill: { color: o.bg ?? CARD }, line: { color: o.stroke ?? HAIR, width: 0.75 }, objectName: `${name} frame` })
  slide.addImage({ path: IMG(file), x, y, w, h, sizing: { type: 'cover', w, h }, objectName: name })
}

// 1. cover ---------------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Opening' })
{
  const s = pres.addSlide({ masterName: 'COVER', sectionTitle: 'Opening' })
  s.addImage({ path: IMG('map-backdrop.png'), x: 0, y: 0, w: 10, h: 5.625, sizing: { type: 'cover', w: 10, h: 5.625 }, transparency: 74, objectName: 'Backdrop: the live threat map, dimmed' })
  s.addShape(pres.ShapeType.rect, { x: 0, y: 0, w: 6.3, h: 5.625, fill: { color: NAVY, transparency: 30 }, line: { color: NAVY, width: 0 }, objectName: 'backdrop shade' })
  s.addShape(pres.ShapeType.rect, { x: 0, y: 4.3, w: 10, h: 1.325, fill: { color: NAVY, transparency: 30 }, line: { color: NAVY, width: 0 }, objectName: 'backdrop shade bottom' })
  s.addImage({ path: IMG('plates/chakra.png'), x: 6.15, y: 0.3, w: 3.5, h: 3.5, transparency: 12, objectName: 'The emblem chakra drawn as a radar ring with a sweep' })
  s.addImage({ path: IMG('emblem.png'), x: 0.5, y: 0.48, w: 0.7, h: 0.7, objectName: 'Odyssey emblem' })
  T(s, 'Odyssey', { x: 1.3, y: 0.5, w: 3, h: 0.36, fontFace: SERIF, fontSize: 19, bold: true, color: BONE, objectName: 'wordmark' })
  mono(s, 'NATIONAL CYBER THREAT EARLY WARNING', { x: 1.3, y: 0.88, w: 4, h: 0.2, charSpacing: 2.5 })
  mono(s, 'FINAL ROUND  ·  D3COY 1.0  ·  DJS ISACA  ·  PROBLEM STATEMENT 01', { x: 0.5, y: 1.9, w: 7, h: 0.2, color: SAFF, charSpacing: 2 })
  s.addText([
    { text: 'See the ', options: { color: BONE } },
    { text: 'attack', options: { color: SAFF, italic: true } },
    { text: ' coming.', options: { color: BONE } },
  ], { x: 0.5, y: 2.1, w: 6.4, h: 1.5, fontFace: SERIF, fontSize: 52, bold: true, lineSpacingMultiple: 0.92, charSpacing: -1, isTextBox: true, margin: 0, valign: 'top', objectName: 'headline' })
  T(s, 'Public threat intelligence in. For every Indian organisation: which systems are at risk, how sure we are, what to do, and by when. On one laptop, with no cloud.', { x: 0.5, y: 3.78, w: 5.5, h: 0.72, fontSize: 12, color: BONE, lineSpacingMultiple: 1.15, objectName: 'claim' })
  // the seven asks, one strip
  mono(s, 'SEVEN ASKS · ONE SYSTEM', { x: 0.5, y: 4.68, w: 2.2, h: 0.22, charSpacing: 1.5 })
  let cx = 2.6
  ;[['1', 'Collect'], ['2', 'Analyse'], ['3', 'Warn'], ['4', 'Prioritise'], ['5', 'Recommend'], ['6', 'Show'], ['D', 'Explain']].forEach(([n, l]) => {
    const last = n === 'D'
    ring(s, cx, 4.68, n, 0.22, { stroke: last ? SAFF : BONE, fill: last ? SAFF : NAVY, text: last ? INK : BONE, size: 7.5 })
    const w = l.length * 0.064 + 0.06
    T(s, l, { x: cx + 0.28, y: 4.68, w, h: 0.22, fontFace: MONO, fontSize: 8.5, color: BONE, valign: 'middle', objectName: `ask ${l}` })
    cx += 0.28 + w + 0.2
  })
  mono(s, 'BEHIND: THE LIVE THREAT MAP, AS THE CONSOLE DRAWS IT  ·  RED = ATTACK SOURCE (DSHIELD, REAL)  ·  VIOLET = COMPROMISE', { x: 0.5, y: 5.22, w: 8.2, h: 0.2, fontSize: 7.5, color: DIM, charSpacing: 0.8 })
  mono(s, '01 / 10', { x: 8.7, y: 5.22, w: 0.8, h: 0.2, fontSize: 7.5, color: DIM, align: 'right' })
  s.addNotes('Open on the line. Behind it is the live map from the console, real attack origins from the last snapshot; the ring is the chakra from our emblem drawn as a radar. Then two sentences: in July 2024 one supplier\'s unpatched server took about 300 Indian banks offline. The flaw had been public for six months. Odyssey exists so that the decision is never late again. The strip at the bottom is the talk: seven asks, one system.')
}

// 2. the problem --------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Problem' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'Problem' })
  eyebrow(s, '02  ·  THE PROBLEM')
  s.addText([{ text: 'The warning was public.', options: { breakLine: true } }, { text: 'The decision was ' }, { text: 'late.', options: { italic: true, color: SAFF } }], { placeholder: 'title', h: 0.95, lineSpacingMultiple: 0.95 })
  big(s, '16,730', 0.5, 1.6, 4.3, { size: 100, h: 1.4, cs: -2 })
  T(s, 'new CVEs published in October 2026 alone, from dozens of feeds. Every one needs a decision: does it touch us, how badly, how soon.', { x: 0.5, y: 3.06, w: 4.0, h: 0.6, fontSize: 10.5, color: MUTE, lineSpacingMultiple: 1.15, objectName: '16730 caption' })
  vhair(s, 4.85, 1.65, 2.3, 'problem divider')
  // the plates
  s.addImage({ path: IMG('plates/dots72_navy.png'), x: 5.1, y: 1.6, w: 0.9, h: 0.9, objectName: 'A hundred dots, 72 lit' })
  s.addShape(pres.ShapeType.rightArrow, { x: 6.06, y: 1.97, w: 0.28, h: 0.15, fill: { color: SAFF }, line: { color: SAFF, width: 0 }, objectName: 'then to now arrow' })
  s.addImage({ path: IMG('plates/dots21_navy.png'), x: 6.4, y: 1.6, w: 0.9, h: 0.9, objectName: 'A hundred dots, 21 lit' })
  big(s, '72% → 21%', 7.45, 1.55, 2.05, { size: 32, h: 0.52 })
  T(s, 'of new CVEs say which product and version they affect, January against now', { x: 7.45, y: 2.1, w: 2.05, h: 0.5, fontSize: 8.5, color: MUTE, objectName: 'labels caption' })
  s.addImage({ path: IMG('plates/dots29_navy.png'), x: 5.1, y: 2.66, w: 0.9, h: 0.9, objectName: 'A hundred dots, 29 red' })
  big(s, '29%', 6.15, 2.61, 1.4, { size: 32, h: 0.52, color: RED })
  T(s, 'of the CVEs exploited in 2026 were attacked on or before the day they were announced', { x: 6.15, y: 3.16, w: 3.35, h: 0.42, fontSize: 8.5, color: MUTE, objectName: 'day zero caption' })
  legend(s, 5.1, 3.72, [{ m: 'dot', c: HAIR, t: 'one of 100 CVEs' }, { m: 'dot', c: BONE, t: 'labelled with product and version' }, { m: 'dot', c: RED, t: 'attacked by day 0' }])
  mono(s, 'REAL  ·  CVE PROGRAM  ·  NVD  ·  CISA KEV', { x: 5.1, y: 3.94, w: 4.4, h: 0.2, fontSize: 7.5 })
  // C-Edge, as a timeline with the red span
  mono(s, 'C-EDGE  ·  2024  ·  THE INDIAN CASE', { x: 6.5, y: 4.2, w: 3.0, h: 0.2, color: SAFF, charSpacing: 1.5, align: 'right' })
  hair(s, 0.7, 4.5, 8.6, 'C-Edge line', HAIR, 1)
  hair(s, 0.7, 4.5, 5.4, 'C-Edge span', RED, 2.25)
  dot(s, 0.7, 4.5, 0.065, MUTE, 'C-Edge Jan', { hollow: true })
  dot(s, 6.1, 4.5, 0.075, RED, 'C-Edge breach')
  dot(s, 6.6, 4.5, 0.065, MUTE, 'C-Edge listed', { hollow: true })
  s.addText([{ text: 'Jan 2024  ', options: { bold: true, color: BONE } }, { text: 'Jenkins flaw disclosed; exploit public within days', options: { color: MUTE } }], { x: 0.7, y: 4.6, w: 3.6, h: 0.26, fontSize: 8.5, isTextBox: true, margin: 0, objectName: 'C-Edge Jan label' })
  s.addText([{ text: '31 Jul 2024  ', options: { bold: true, color: RED } }, { text: 'ransomware via the supplier; about 300 banks lose UPI and ATM', options: { color: MUTE } }], { x: 1.6, y: 4.2, w: 4.55, h: 0.26, fontSize: 8.5, align: 'right', isTextBox: true, margin: 0, objectName: 'C-Edge Jul label' })
  s.addText([{ text: '19 Aug 2024  ', options: { bold: true, color: BONE } }, { text: 'CISA lists the flaw, 19 days later', options: { color: MUTE } }], { x: 6.72, y: 4.6, w: 2.78, h: 0.26, fontSize: 8.5, isTextBox: true, margin: 0, objectName: 'C-Edge Aug label' })
  legend(s, 0.7, 4.92, [{ m: 'line', c: RED, t: 'six months of public warning, nothing connecting it to who was exposed' }, { m: 'ring', c: MUTE, t: 'event' }, { m: 'dot', c: RED, t: 'the breach' }])
  foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  SOURCES: CVE PROGRAM, NVD, CISA KEV, NPCI 31 JUL 2024', 2)
  s.addNotes('The problem is not a shortage of intelligence. It is volume, missing labels, and attackers who move on day zero. Each dot plate is a hundred CVEs: the lit ones say what they break, and that share fell from 72 to 21 in a year; the red ones were attacked by the day they were announced. C-Edge is the Indian case: six months of public warning, then 300 banks offline, then the national list catching up 19 days later.')
}

// 3. the loop ------------------------------------------------------------------------------------------------------
pres.addSection({ title: 'The loop' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'The loop' })
  eyebrow(s, '03  ·  THE LOOP  ·  THE BRIEF\'S OWN EXAMPLE, RUN FOR REAL')
  s.addText([{ text: 'One advisory, start to ' }, { text: 'finish', options: { italic: true, color: SAFF } }], { placeholder: 'title' })
  chip(s, 'SIEMENS WINCC  ·  CISA ICS ADVISORY  ·  REAL')
  const steps = [
    ['Advisory arrives', 'CISA\'s ICS advisory for Siemens WinCC, read by the security LLM. No CVE id needed.'],
    ['Versions parsed', 'Machine-readable ranges lifted from the text: below 8.0.0.11, and all versions.'],
    ['Exposure found', '13 WinCC assets at 7 operators, checked against the inventory version by version.'],
    ['Risk assigned', 'A score with its working, an SSVC tier, a CERT-In clock. Patch, or mitigate where no fix exists.'],
    ['People decide', 'A notice to each operator in its own language. An analyst approves. Every step audited.'],
  ]
  hair(s, 0.9, 1.62, 8.2, 'station line')
  steps.forEach(([h, b], i) => {
    const x = 0.5 + i * 1.84
    const score = i === 3, person = i === 4
    ring(s, x + 0.08, 1.45, i + 1, 0.34, { stroke: score ? SAFF : BONE, fill: score ? SAFF : person ? BONE : NAVY, text: score || person ? INK : BONE, size: 10 })
    T(s, h, { x, y: 1.96, w: 1.7, h: 0.3, fontFace: SERIF, fontSize: 12.5, bold: true, color: BONE, objectName: `${h} head` })
    T(s, b, { x, y: 2.3, w: 1.68, h: 0.95, fontSize: 9.5, color: MUTE, lineSpacingMultiple: 1.15, objectName: `${h} body` })
  })
  card(s, 0.5, 3.5, 9, 1.32, CARD, 'same path card')
  mono(s, 'THE SAME PATH FOR EVERY INPUT', { x: 0.75, y: 3.64, w: 4, h: 0.2, color: SAFF, charSpacing: 2 })
  let cx = 0.75
  ;['a KEV entry', 'a new CVE from NVD', 'a decoy-grid surge', 'a partner\'s indicators', 'a SACHET alert'].forEach((t) => {
    const w = 0.3 + t.length * 0.07
    chip(s, t, { x: cx, y: 3.92, w, size: 8, stroke: DIM, fill: CARD })
    cx += w + 0.12
  })
  T(s, 'Each is matched to who is exposed, scored, and turned into something a person can approve.', { x: 0.75, y: 4.36, w: 8.5, h: 0.3, fontSize: 10.5, color: BONE, objectName: 'same path line' })
  legend(s, 0.5, 4.95, [{ m: 'ring', c: BONE, t: 'automated, written to the audit trail' }, { m: 'dot', c: SAFF, t: 'the score' }, { m: 'dot', c: BONE, t: 'a person decides' }])
  foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  DJS ISACA  ·  PS-01', 3)
  s.addNotes('This is the walk-through in the demo and the brief\'s own example. A real CISA advisory for Siemens WinCC comes in. The model reads it, the version ranges are parsed, thirteen assets at seven operators are found exposed, each gets a risk with its working and a deadline, and the notices are proposed in Marathi, Gujarati and Hindi for a person to approve. The saffron station is the score; the bone one is the person. Then: the same path for every input.')
}

// 4. collect -------------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Collect' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'Collect' })
  eyebrow(s, '04  ·  1 COLLECT')
  s.addText([{ text: 'Every source, ' }, { text: 'one', options: { italic: true, color: SAFF } }, { text: ' record' }], { placeholder: 'title' })
  chip(s, '13 SOURCES  ·  10 REAL  ·  3 SIM')
  mono(s, 'MANIFEST', { x: 0.5, y: 1.3, w: 1.5, h: 0.2 })
  mono(s, 'SOURCE', { x: 2.3, y: 1.3, w: 1.2, h: 0.2, align: 'right' })
  hair(s, 0.5, 1.52, 3.0, 'manifest head rule', BONE, 1)
  const rows = [['NVD 2021 to 2026', 'REAL'], ['CISA KEV', 'REAL'], ['CISA SSVC', 'REAL'], ['FIRST EPSS', 'REAL'], ['CISA ICS and alerts', 'REAL'], ['MITRE ATT&CK', 'REAL'], ['NDMA SACHET', 'REAL'], ['DShield honeypots', 'REAL'], ['Feodo C2', 'REAL'], ['OpenPhish', 'REAL'], ['CERT-In style advisories', 'SIM'], ['Decoy grid, 24 sensors', 'SIM'], ['Firewall flows', 'SIM']]
  rows.forEach(([n, t], i) => {
    const y = 1.56 + i * 0.235, sim = t === 'SIM'
    T(s, n, { x: 0.5, y, w: 2.2, h: 0.22, fontSize: 9.5, color: sim ? MUTE : BONE, valign: 'middle', objectName: `${n} row` })
    T(s, t, { x: 2.5, y, w: 1.0, h: 0.22, fontFace: MONO, fontSize: 8.5, bold: !sim, color: sim ? DIM : SAFF, align: 'right', valign: 'middle', charSpacing: 1.5, objectName: `${n} tag` })
    hair(s, 0.5, y + 0.235, 3.0, `${n} rule`)
  })
  s.addImage({ path: IMG('plates/funnel_navy.png'), x: 3.95, y: 1.3, w: 2.55, h: 2.55, objectName: '821 dots, one per hundred CVEs; 23 lit, 4 red' })
  legend(s, 3.95, 3.98, [{ m: 'dot', c: HAIR, t: 'one dot = 100 CVEs published in 2026' }])
  legend(s, 3.95, 4.22, [{ m: 'dot', c: BONE, t: 'names a product an operator runs' }])
  legend(s, 3.95, 4.46, [{ m: 'dot', c: RED, t: 'a Critical warning to a named operator' }])
  big(s, '82,104', 6.9, 1.22, 2.6, { size: 52, h: 0.72, cs: -1 })
  mono(s, 'CVES PUBLISHED  ·  2026', { x: 6.9, y: 1.96, w: 2.6, h: 0.2 })
  big(s, '2,277', 6.9, 2.27, 2.6, { size: 52, h: 0.72, cs: -1 })
  mono(s, 'NAME A PRODUCT WE RUN', { x: 6.9, y: 3.01, w: 2.6, h: 0.2 })
  big(s, '354', 6.9, 3.32, 2.6, { size: 52, h: 0.72, cs: -1, color: RED })
  mono(s, 'CRITICAL, EACH TO A NAMED OPERATOR', { x: 6.9, y: 4.06, w: 2.6, h: 0.2, charSpacing: 1 })
  T(s, 'In and out as STIX 2.1, TAXII 2.1 and CSV. A partner\'s indicators are matched against the record in seconds.', { x: 6.9, y: 4.36, w: 2.6, h: 0.55, fontSize: 9, color: MUTE, lineSpacingMultiple: 1.15, objectName: 'formats line' })
  foot(s, 'ALSO BUNDLED, REAL: EXPLOIT-DB · RANSOMWARE.LIVE · HIBP · GITHUB ADVISORIES · TOR · SPAMHAUS DROP · ET', 4)
  s.addNotes('Thirteen sources, in a manifest with the provenance of each: vulnerability databases, public advisories, attack telemetry and indicators, and the simulated layer, labelled. The plate in the middle is the whole year: every dot is a hundred CVEs, the lit ones name something an operator actually runs, the red ones are Critical warnings addressed to a named operator. The record goes in and out as STIX, TAXII and CSV.')
}

// 5. analyse -------------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Analyse' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'Analyse' })
  eyebrow(s, '05  ·  2 ANALYSE')
  s.addText([{ text: 'AI explains. ' }, { text: 'Rules', options: { italic: true, color: SAFF } }, { text: ' decide.' }], { placeholder: 'title' })
  chip(s, '9 MODELS  ·  ONE RTX 4070  ·  0 CLOUD CALLS')
  s.addShape(pres.ShapeType.ellipse, { x: 0.47, y: 1.27, w: 2.96, h: 2.96, fill: { color: CARD }, line: { color: HAIR, width: 0.75 }, objectName: 'graph frame' })
  s.addImage({ path: IMG('graph-sq.png'), x: 0.5, y: 1.3, w: 2.9, h: 2.9, rounding: true, objectName: 'The intelligence graph: 115 entities, 447 links, in a dense circle coloured by cluster' })
  mono(s, 'INTEL › GRAPH  ·  115 NODES  ·  447 LINKS', { x: 0.5, y: 4.32, w: 3.2, h: 0.2, fontSize: 7.5 })
  legend(s, 0.5, 4.55, [{ m: 'dot', c: '276EF1', t: '' }, { m: 'dot', c: SAFF, t: '' }, { m: 'dot', c: '05A357', t: 'colour = technology family' }, { m: 'dot', c: VIOLET, t: 'compromise' }], { size: 7.5, gap: 0.1 })
  legend(s, 0.5, 4.78, [{ m: 'diamond', c: BONE, t: 'threat group, overlap not attribution' }, { m: 'tri', c: BONE, t: 'live signal' }], { size: 7.5, gap: 0.14 })
  const rows = [
    ['22/23', 'Reads', 'MiST 8B, a security LLM, reads every advisory and writes every brief. 22 of 23 briefs pass the fact validator; a failing sentence is withheld, never shown.'],
    ['12', 'Relates', 'SecureBERT 2.0 links entities and threats; a clustering model groups 12 active campaigns. Threat groups are ATT&CK overlap, never attribution.'],
    ['5/5', 'Detects', 'Surges, C2 beacons and flow anomalies, every 5 seconds. A poisoned advisory with hidden instructions: caught by the DeBERTa guard, 5 of 5.'],
  ]
  rows.forEach(([n, h, b], i) => {
    const y = 1.28 + i * 0.95
    big(s, n, 3.8, y, 1.2, { size: 40, h: 0.6, color: SAFF })
    T(s, h, { x: 5.1, y: y + 0.02, w: 4.4, h: 0.28, fontFace: SERIF, fontSize: 14, bold: true, color: BONE, objectName: `${h} head` })
    T(s, b, { x: 5.1, y: y + 0.32, w: 4.4, h: 0.5, fontSize: 9, color: MUTE, lineSpacingMultiple: 1.12, objectName: `${h} body` })
    if (i < 2) hair(s, 3.8, y + 0.88, 5.7, `${h} rule`)
  })
  mono(s, 'MIST 8B  ·  FOUNDATION-SEC 8B  ·  SECUREBERT 2.0  ·  TF-IDF CLASSIFIERS  ·  DAY-0 FORECAST  ·  BAYES  ·  LIVE DETECTORS  ·  DEBERTA GUARD  ·  INDICTRANS2, 22 LANGUAGES', { x: 3.8, y: 4.1, w: 5.7, h: 0.32, fontSize: 6.5, color: DIM, charSpacing: 1 })
  card(s, 3.8, 4.5, 5.7, 0.55, BONE, 'rule card')
  s.addText([{ text: 'No model sets a score, a tier or a deadline. ', options: { bold: true, color: INK } }, { text: 'One model per job, fixed in config, chosen by measurement on 2026 CVEs, newer than any model\'s training data.', options: { color: INKMUTE } }], { x: 3.98, y: 4.5, w: 5.35, h: 0.55, fontSize: 9, valign: 'middle', isTextBox: true, margin: 0, objectName: 'rule text' })
  foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  DOCS/MODEL_CARD.MD  ·  MEASURED 31 OCT 2026 ON THE DEMO LAPTOP', 5)
  s.addNotes('Three jobs for the models: read, relate, detect. Read: the security LLM reads advisories and writes the brief, and the brief is fact-checked line by line. Relate: entities, related threats, campaigns, and the graph on the left, where colour is the technology family, violet a suspected compromise, a diamond a threat group stated as overlap and never attribution, a triangle a live signal. Detect: surges, beacons and anomalies every five seconds, plus the guard that catches a poisoned advisory. Nine models, each chosen by measurement, none of them deciding.')
}

// 6. warn ----------------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Warn' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'Warn' })
  eyebrow(s, '06  ·  3 WARN')
  s.addText([{ text: 'Move the line ' }, { text: 'left', options: { italic: true, color: SAFF } }], { placeholder: 'title' })
  big(s, '+20.5 days', 5.3, 0.3, 4.2, { size: 50, h: 0.72, color: SAFF, align: 'right' })
  mono(s, 'MEDIAN LEAD OVER CISA KEV  ·  REAL SIGNALS  ·  UP TO 42.4', { x: 5.3, y: 1.04, w: 4.2, h: 0.2, fontSize: 7.5, align: 'right', charSpacing: 1 })
  const lane = (label, y, bright, above, pts) => {
    mono(s, label, { x: 0.5, y: above ? y - 0.86 : y - 0.36, w: 3.4, h: 0.2, color: bright ? BONE : MUTE, charSpacing: 2 })
    hair(s, 0.9, y, 8.2, `${label} line`, bright ? BONE : HAIR, 1)
    pts.forEach(([x, head, body, kind], i) => {
      if (kind === 'breach') dot(s, x, y, 0.08, RED, `${label} dot ${i}`)
      else if (kind === 'saff') dot(s, x, y, 0.08, SAFF, `${label} dot ${i}`)
      else if (bright) dot(s, x, y, 0.07, BONE, `${label} dot ${i}`)
      else dot(s, x, y, 0.07, MUTE, `${label} dot ${i}`, { hollow: true })
      const hy = above ? y - 0.62 : y + 0.12, by = above ? y - 0.42 : y + 0.34
      T(s, head, { x: x - 0.95, y: hy, w: 1.9, h: 0.22, fontSize: 10, bold: true, color: kind === 'breach' ? RED : kind === 'saff' ? SAFF : BONE, align: 'center', objectName: `${label} head ${i}` })
      T(s, body, { x: x - 0.95, y: by, w: 1.9, h: 0.32, fontSize: 8.5, color: MUTE, align: 'center', lineSpacingMultiple: 1.05, valign: above ? 'bottom' : 'top', objectName: `${label} body ${i}` })
    })
  }
  lane('THEN  ·  REACT AFTER THE BREACH', 2.0, false, true, [
    [1.6, 'Flaw disclosed', 'public record; exploit code soon after'],
    [3.7, 'Nothing connects it', 'to who actually runs the product'],
    [5.8, 'Breach', 'the warning signs were public for months', 'breach'],
    [7.9, 'Listed', 'the national list catches up weeks later'],
  ])
  lane('NOW  ·  ACT ON THE SIGNAL', 3.02, true, false, [
    [1.6, '12 days before', 'a decoy-grid surge (SIM) raises a warning'],
    [3.7, 'Day 0', 'matched to installed versions in seconds'],
    [5.8, 'Warning', 'tier, confidence, clock; a person approves'],
    [7.9, '+20.5 days', 'median before CISA lists it, on real signals', 'saff'],
  ])
  // the arrow that moves the decision left
  s.addShape(pres.ShapeType.custGeom, { x: 1.78, y: 2.1, w: 4.02, h: 0.82, points: [{ x: 4.02, y: 0 }, { x: 3.7, y: 0.22 }, { x: 3.2, y: 0.42 }, { x: 2.5, y: 0.58 }, { x: 1.7, y: 0.7 }, { x: 0.9, y: 0.78 }, { x: 0.1, y: 0.82 }], fill: { type: 'none' }, line: { color: SAFF, width: 2, endArrowType: 'triangle' }, objectName: 'the decision, moved left' })
  const stats = [['61%', 'of later-exploited CVEs flagged on day 0 at a 2% alert budget; CVSS ≥ 9 catches 17% at the same budget'], ['1 tick', 'one 5-second tick to catch a scanning surge or an implant beacon in the drills; 0 alerts on clean traffic'], ['15 min', 'between feed reads; a new NVD CVE naming our products is matched, scored and forecast within seconds']]
  stats.forEach(([n, l], i) => {
    const x = 0.5 + i * 3.05
    big(s, n, x, 3.9, 2.8, { size: 34, h: 0.52 })
    T(s, l, { x, y: 4.44, w: 2.8, h: 0.45, fontSize: 8.5, color: MUTE, lineSpacingMultiple: 1.1, objectName: `${n} label` })
  })
  legend(s, 0.5, 4.98, [{ m: 'ring', c: MUTE, t: 'reactive step' }, { m: 'dot', c: BONE, t: 'Odyssey step' }, { m: 'dot', c: RED, t: 'the breach' }, { m: 'line', c: SAFF, t: 'the decision, moved before it' }, { m: 'none', t: 'SIM = simulated sensor, labelled · numbers recomputed live on the Proof page' }])
  foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  DJS ISACA  ·  PS-01', 6)
  s.addNotes('Top lane is how it usually goes. Bottom lane is Odyssey: the decoy grid sees scanning before disclosure (simulated, labelled); on day zero a new CVE is matched to the inventory in seconds and the forecast flags the ones likely to be exploited; the warning goes out with its tier, confidence and clock; and CISA\'s list follows, a median 20.5 days later on real signals. The saffron arrow is the whole pitch: reactive systems start at the breach, we start at the signal.')
}

// 7. prioritise ----------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Prioritise' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'Prioritise' })
  eyebrow(s, '07  ·  4 PRIORITISE')
  s.addText([{ text: 'A score you can check ' }, { text: 'by hand', options: { italic: true, color: SAFF } }], { placeholder: 'title' })
  chip(s, 'SCORING.JSON  ·  HASHED INTO EVERY ALERT')
  T(s, 'Risk', { x: 0.5, y: 1.3, w: 0.95, h: 0.45, fontFace: SERIF, fontSize: 24, bold: true, italic: true, color: BONE, objectName: 'risk word' })
  mono(s, '= 100 ×', { x: 0.5, y: 1.78, w: 0.95, h: 0.2, fontSize: 9, color: BONE })
  const tiles = [['RELEVANCE ×', '0 → 1', 'this exact version affected?', BONE], ['IMPORTANCE ×', '0.4 → 1.3', 'criticality · exposure · blast radius', BONE], ['LIKELIHOOD', '55%', 'from evidence, in rank order', SAFF], ['SEVERITY', '30%', 'SSVC technical impact', SAFF], ['EVIDENCE', '15%', 'Admiralty-graded sources', SAFF]]
  tiles.forEach(([k, v, l, c], i) => {
    const x = 1.5 + i * 1.62
    card(s, x, 1.28, 1.52, 1.0, CARD, `${k} tile`, HAIR)
    mono(s, k, { x: x + 0.12, y: 1.36, w: 1.3, h: 0.18, fontSize: 7, color: MUTE })
    big(s, v, x + 0.12, 1.5, 1.3, { size: 28, h: 0.44, color: c })
    T(s, l, { x: x + 0.12, y: 1.95, w: 1.3, h: 0.3, fontSize: 7.5, color: MUTE, objectName: `${k} tile label` })
  })
  mono(s, 'LIKELIHOOD  ·  FROM EVIDENCE  ·  IN RANK ORDER', { x: 0.5, y: 2.5, w: 4.5, h: 0.2, charSpacing: 2 })
  hair(s, 0.5, 2.72, 4.5, 'ladder head rule', BONE, 1)
  const ladder = [['On CISA KEV · SSVC says active · exploit seen on 2+ decoys', '1.0', BONE], ['The vendor says exploited in the wild', '0.8', BONE], ['A public proof of concept', '0.5', BONE], ['A scanning surge on the decoy grid, decaying with age', '0.4', BONE], ['EPSS ≥ 0.5 · CVSS ≥ 9 · automatable', 'corroborate', MUTE], ['The day-0 forecast', 'prediction', MUTE]]
  ladder.forEach(([t, v, c], i) => {
    const y = 2.76 + i * 0.265
    T(s, t, { x: 0.5, y, w: 3.4, h: 0.24, fontSize: 9, color: c, valign: 'middle', objectName: `ladder ${i}` })
    T(s, v, { x: 3.9, y, w: 1.1, h: 0.24, fontFace: MONO, fontSize: 8.5, bold: c === BONE, color: c === BONE ? BONE : MUTE, align: 'right', valign: 'middle', objectName: `ladder ${i} value` })
    hair(s, 0.5, y + 0.265, 4.5, `ladder rule ${i}`)
  })
  s.addText([
    { text: 'Tier ', options: { bold: true, color: BONE } }, { text: 'by CISA\'s SSVC decision path: Act, Attend, Track.  ', options: { color: MUTE } },
    { text: 'Confidence ', options: { bold: true, color: BONE } }, { text: 'scored apart: A to F source grades; agreement between independent sources raises it.  ', options: { color: MUTE } },
    { text: 'Relevance ', options: { bold: true, color: BONE } }, { text: 'checked against NVD, the vendor and the advisory: 0 false "affected" on the Ivanti case.', options: { color: MUTE } },
  ], { x: 0.5, y: 4.42, w: 4.5, h: 0.62, fontSize: 8.5, lineSpacingMultiple: 1.12, isTextBox: true, margin: 0, objectName: 'other factors' })
  // the receipt
  card(s, 5.3, 2.5, 4.2, 2.55, BONE, 'receipt card')
  mono(s, 'ONE REAL WARNING  ·  TAPTI THERMAL  ·  IVANTI CS 22.8R2.4', { x: 5.48, y: 2.6, w: 3.9, h: 0.2, fontSize: 7, color: INKMUTE, charSpacing: 1 })
  const rec = [['Likelihood  0.55 × 1.0', 'KEV 30 Oct · SSVC active · vendor: in the wild', '45.8'], ['Severity  0.30 × 1.0', 'SSVC technical impact: total', '25.0'], ['Evidence  0.15 × 1.0', 'CISA (A), NVD (A), vendor (B) agree', '12.5'], ['Relevance × 1.0  ·  Importance × 0.83', 'affected version · VPN gateway, internet-facing, tier 1', '']]
  rec.forEach(([k, e, v], i) => {
    const y = 2.86 + i * 0.4
    hair(s, 5.48, y, 3.85, `receipt rule ${i}`, PAPERHAIR, 0.75)
    T(s, k, { x: 5.48, y: y + 0.04, w: 3.0, h: 0.18, fontFace: MONO, fontSize: 8.5, bold: true, color: INK, objectName: `receipt ${i} key` })
    T(s, e, { x: 5.48, y: y + 0.22, w: 3.0, h: 0.17, fontSize: 7.5, color: INKMUTE, objectName: `receipt ${i} evidence` })
    if (v) big(s, v, 8.5, y + 0.02, 0.83, { size: 20, h: 0.36, color: INK, align: 'right' })
  })
  hair(s, 5.48, 4.47, 3.85, 'receipt total rule', INK, 1.5)
  T(s, 'RISK', { x: 5.48, y: 4.52, w: 1.5, h: 0.22, fontFace: MONO, fontSize: 10, bold: true, color: INK, objectName: 'receipt total key' })
  T(s, 'Critical · Act · 12 h to patch · P(compromise) 18%', { x: 5.48, y: 4.74, w: 2.6, h: 0.26, fontSize: 7.5, color: INKMUTE, objectName: 'receipt verdict' })
  big(s, '83.3', 7.9, 4.46, 1.43, { size: 34, h: 0.52, color: 'E11900', align: 'right' })
  foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  DJS ISACA  ·  PS-01  ·  ONE REAL WARNING FROM THIS BUILD, FACTOR BY FACTOR', 7)
  s.addNotes('The score is a formula anyone can check: the five tiles are its five factors. Likelihood comes from evidence in rank order, and the ladder shows what counts and how much: a KEV listing or an active SSVC verdict is 1.0, a vendor claim 0.8, proof of concept 0.5, a decoy surge 0.4 and decaying, while EPSS and CVSS only corroborate and the forecast is a prediction, not evidence. The receipt on the right is one real warning from this build: 83.3, Critical, Act, twelve hours. The tier follows CISA\'s SSVC decision method; confidence is scored separately from risk.')
}

// 8. recommend -----------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Recommend' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'Recommend' })
  eyebrow(s, '08  ·  5 RECOMMEND')
  s.addText([{ text: 'What to do, and ' }, { text: 'by when', options: { italic: true, color: SAFF } }], { placeholder: 'title' })
  chip(s, 'A PERSON APPROVES ANYTHING CONSEQUENTIAL')
  mono(s, 'ON EVERY WARNING', { x: 0.5, y: 1.3, w: 3.9, h: 0.2, charSpacing: 2 })
  const acts = [['Patch', 'to a named fixed release, never a downgrade'], ['Block', 'the indicators: STIX 2.1 export, risk lists for the firewall, C2 refanged'], ['Investigate', 'a hunt playbook, ATT&CK mitigations, forensic triage where CISA asks'], ['Report', 'the CERT-In 6-hour report pre-drafted; RBI, SEBI, DPDP and NCIIPC clocks shown'], ['Notify', 'a notice in the operator\'s own language; a person approves before it goes']]
  acts.forEach(([h, b], i) => {
    const y = 1.58 + i * 0.5, last = i === 4
    ring(s, 0.5, y + 0.02, String(i + 1).padStart(2, '0'), 0.3, { stroke: SAFF, fill: last ? SAFF : NAVY, text: last ? INK : SAFF, size: 8 })
    s.addText([{ text: h + '  ', options: { bold: true, color: BONE } }, { text: b, options: { color: MUTE } }], { x: 0.9, y, w: 3.5, h: 0.42, fontSize: 9.5, lineSpacingMultiple: 1.12, valign: 'middle', isTextBox: true, margin: 0, objectName: `action ${i + 1}` })
  })
  T(s, 'Odyssey proposes; a person approves anything consequential. Every action is in a hash-chained audit trail.', { x: 0.5, y: 4.15, w: 3.9, h: 0.45, fontSize: 8.5, color: DIM, lineSpacingMultiple: 1.12, objectName: 'human line' })
  // the risk plan curve
  mono(s, 'THE RISK PLAN', { x: 4.75, y: 1.3, w: 1.6, h: 0.2, charSpacing: 2 })
  const cx0 = 4.95, cy0 = 1.62, cw = 2.45, ch = 1.85
  const f = (c) => c <= 93 ? 50 * (1 - Math.pow(1 - c / 93, 1.6)) : c <= 205 ? 50 + 30 * (1 - Math.pow(1 - (c - 93) / 112, 1.4)) : 80 + 20 * (1 - Math.pow(1 - (c - 205) / 139, 1.3))
  const pts = []
  for (let c = 0; c <= 344; c += 8) pts.push({ x: cw * c / 344, y: ch * (1 - f(c) / 100) })
  pts.push({ x: cw, y: 0 })
  s.addShape(pres.ShapeType.custGeom, { x: cx0, y: cy0, w: cw, h: ch, points: [...pts, { x: cw, y: ch }, { x: 0, y: ch, close: true }], fill: { color: SAFF, transparency: 86 }, line: { color: SAFF, width: 0, transparency: 100 }, objectName: 'risk removed area' })
  s.addShape(pres.ShapeType.custGeom, { x: cx0, y: cy0, w: cw, h: ch, points: pts, fill: { type: 'none' }, line: { color: SAFF, width: 2 }, objectName: 'risk removed curve' })
  hair(s, cx0, cy0 + ch, cw, 'plan x axis', HAIR, 1)
  vhair(s, cx0, cy0, ch, 'plan y axis')
  mono(s, '100%', { x: 4.5, y: cy0 - 0.08, w: 0.4, h: 0.18, fontSize: 7, align: 'right' })
  mono(s, '0', { x: 4.5, y: cy0 + ch - 0.12, w: 0.4, h: 0.18, fontSize: 7, align: 'right' })
  const px = (c) => cx0 + cw * c / 344, py = (c) => cy0 + ch * (1 - f(c) / 100)
  vhair(s, px(93), py(93), cy0 + ch - py(93), 'cut 93 guide', HAIR)
  vhair(s, px(205), py(205), cy0 + ch - py(205), 'cut 205 guide', HAIR)
  dot(s, px(93), py(93), 0.06, BONE, 'cut 93')
  dot(s, px(205), py(205), 0.06, BONE, 'cut 205')
  s.addText([{ text: '93 changes', options: { bold: true, color: BONE, breakLine: true } }, { text: 'half the risk', options: { color: MUTE } }], { x: px(93) + 0.1, y: py(93) + 0.06, w: 1.1, h: 0.36, fontFace: MONO, fontSize: 7.5, isTextBox: true, margin: 0, objectName: 'cut 93 label' })
  s.addText([{ text: '205 changes', options: { bold: true, color: BONE, breakLine: true } }, { text: '80% of it', options: { color: MUTE } }], { x: px(205) + 0.1, y: py(205) + 0.06, w: 1.0, h: 0.36, fontFace: MONO, fontSize: 7.5, isTextBox: true, margin: 0, objectName: 'cut 205 label' })
  mono(s, '344 TICKETS IN ALL', { x: cx0 + cw - 1.7, y: cy0 - 0.2, w: 1.7, h: 0.18, fontSize: 7, align: 'right' })
  mono(s, 'CHANGES, IN PRIORITY ORDER →', { x: cx0, y: cy0 + ch + 0.05, w: cw, h: 0.18, fontSize: 7, align: 'right' })
  legend(s, 4.75, 3.8, [{ m: 'line', c: SAFF, t: 'national risk removed, cumulative' }], { size: 7.5 })
  legend(s, 4.75, 4.02, [{ m: 'dot', c: BONE, t: 'the two cuts the plan proposes, of 344 change tickets' }], { size: 7.5 })
  // the deadline dials
  mono(s, 'BY WHEN  ·  CERT-IN', { x: 7.75, y: 1.3, w: 1.75, h: 0.2, charSpacing: 2 })
  const dials = [['6 h', 'suspected compromise', 6, RED], ['12 h', 'known-exploited, internet', 12, SAFF], ['24 h', 'Critical', 24, SAFF], ['72 h', 'High', 72, SAFF], ['120 h', 'Medium', 120, SAFF]]
  dials.forEach(([n, l, hrs, c], i) => {
    const y = 1.6 + i * 0.52, d = 0.38
    s.addShape(pres.ShapeType.ellipse, { x: 7.75, y, w: d, h: d, fill: { type: 'none' }, line: { color: HAIR, width: 2 }, objectName: `${n} dial face` })
    if (hrs >= 120) s.addShape(pres.ShapeType.ellipse, { x: 7.75, y, w: d, h: d, fill: { type: 'none' }, line: { color: c, width: 2 }, objectName: `${n} dial arc` })
    else s.addShape(pres.ShapeType.arc, { x: 7.75, y, w: d, h: d, angleRange: [270, 270 + 360 * hrs / 120], fill: { type: 'none' }, line: { color: c, width: 2 }, objectName: `${n} dial arc` })
    dot(s, 7.75 + d / 2, y + d / 2, 0.025, c, `${n} dial hub`)
    big(s, n, 8.25, y - 0.06, 1.25, { size: 16, h: 0.3, color: c })
    T(s, l, { x: 8.25, y: y + 0.22, w: 1.3, h: 0.2, fontSize: 7.5, color: MUTE, objectName: `${n} dial label` })
  })
  mono(s, 'DIAL = DEADLINE ON A 120-HOUR FACE', { x: 7.75, y: 4.25, w: 1.75, h: 0.3, fontSize: 6.5 })
  legend(s, 0.5, 4.82, [{ m: 'ring', c: SAFF, t: 'runs on its own, audited' }, { m: 'dot', c: SAFF, t: 'a person decides' }, { m: 'none', t: 'one workflow per warning: issued → acknowledged → mitigating → verifying → closed' }])
  foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  DJS ISACA  ·  PS-01', 8)
  s.addNotes('Every warning ends in something a team can do: patch to a named release, block the indicators, hunt, report, notify. The hollow rings run on their own and are audited; the filled ring is the person. Nationally, the risk plan is the curve: 93 changes remove half the risk, 205 remove 80 percent, of 344 tickets in all. The dials are India\'s clocks from the CERT-In Blueprint, and the countdown runs on the warning itself.')
}

// 9. show ----------------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Show' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'Show' })
  eyebrow(s, '09  ·  6 SHOW')
  s.addText([{ text: 'One screen per ' }, { text: 'question', options: { italic: true, color: SAFF } }], { placeholder: 'title' })
  chip(s, 'NOW  ·  LIVE  ·  SOC  ·  INTEL  ·  ORGANISATIONS  ·  PROOF')
  const figs = [
    ['now-hero.png', 'FIG 9A  ·  NOW  ·  WHAT NEEDS ME', [[{ m: 'dot', c: RED, t: 'chip = compromise' }, { m: 'none', t: 'clock = CERT-In deadline' }], [{ m: 'none', t: 'black button = the one action · operators SIM' }]]],
    ['threats-heat.png', 'FIG 9B  ·  INTEL  ·  WHAT IS UNDER ATTACK', [[{ m: 'rect', c: 'DBE6FB', t: '' }, { m: 'rect', c: '276EF1', t: 'cell = attacks on a port that day, quiet → busy' }], [{ m: 'none', t: 'DShield, REAL · rows = the services operators expose' }]]],
    ['graph-c.png', 'FIG 9C  ·  INTEL  ·  THE GRAPH', [[{ m: 'dot', c: '276EF1', t: 'colour = technology family' }, { m: 'dot', c: VIOLET, t: 'compromise' }], [{ m: 'diamond', c: BONE, t: 'threat group (overlap)' }, { m: 'tri', c: BONE, t: 'live signal' }]]],
    ['map-world-c.png', 'FIG 9D  ·  NOW  ·  WHERE ATTACKS START', [[{ m: 'dot', c: RED, t: 'attack source, REAL' }, { m: 'ring', c: BONE, t: 'botnet C2, REAL' }], [{ m: 'dot', c: MUTE, t: 'operator state, SIM' }, { m: 'dot', c: VIOLET, t: 'compromise' }]]],
    ['map-india-c.png', 'FIG 9E  ·  INDIA BY WARNINGS', [[{ m: 'dot', c: 'C9834F', t: '' }, { m: 'dot', c: RED, t: 'Critical warnings per state, few → many' }], [{ m: 'dot', c: VIOLET, t: 'compromise' }, { m: 'none', t: 'operators SIM, warnings from REAL CVEs' }]]],
    ['site-c.png', 'FIG 9F  ·  A STATE, IN 3D', [[{ m: 'rect', c: MUTE, t: 'agency site, SIM' }, { m: 'arrow', c: RED, t: 'attack from a real origin' }], [{ m: 'none', t: 'origins REAL · buildings SIM' }]]],
  ]
  figs.forEach(([file, cap, leg], i) => {
    const x = 0.5 + (i % 3) * 3.05, y = 1.3 + Math.floor(i / 3) * 1.9
    shot(s, file, x, y, 2.9, 1.25, cap)
    mono(s, cap, { x, y: y + 1.3, w: 2.9, h: 0.18, fontSize: 7, color: SAFF, charSpacing: 1 })
    legend(s, x, y + 1.47, leg[0], { size: 7, gap: 0.12 })
    legend(s, x, y + 1.64, leg[1], { size: 7, gap: 0.12 })
  })
  foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  REAL OR SIM ON EVERY PANEL  ·  FEEDS BUNDLED, NOTHING WAITS ON THE NETWORK', 9)
  s.addNotes('Six screens, one question each. Now: what needs me. Live: what is happening, including real attacks on a real app behind the shield. SOC: the cases. Intel: what is under attack, which technologies, the graph, indicators. Organisations: one operator at a time. Proof: the numbers, recomputed on stage. Each figure carries its legend; the threat map and the India view are drawn from real feeds bundled into the console, and every panel says REAL or SIM.')
}

// 10. explain ------------------------------------------------------------------------------------------------------
pres.addSection({ title: 'Explain' })
{
  const s = pres.addSlide({ masterName: 'MAIN', sectionTitle: 'Explain' })
  s.addImage({ path: IMG('plates/chakra.png'), x: 6.3, y: 1.9, w: 3.4, h: 3.4, transparency: 86, objectName: 'the chakra ring, faint' })
  eyebrow(s, '10  ·  D EXPLAIN  ·  THE MODEL, THE SCORING, THE WORKFLOW')
  s.addText([{ text: 'It runs here. ' }, { text: 'Offline.', options: { italic: true, color: SAFF } }], { placeholder: 'title' })
  chip(s, 'EVERY NUMBER RECOMPUTED LIVE ON THE PROOF PAGE')
  const nums = [['0', 'cloud or internet AI calls, ever', SAFF, 1.5], ['1', 'laptop, an RTX 4070 with 8 GB; every model under 8B', BONE, 1.9], ['85 s', 'to re-score the nation: 15 operators, 612 systems, 2,277 flaws', BONE, 2.3], ['221', 'engine tests green; 26 of 26 product flows; 25 of 26 browser steps', BONE, 2.6]]
  let nx = 0.5
  nums.forEach(([n, l, c, w]) => {
    big(s, n, nx, 1.22, w, { size: 60, h: 0.82, color: c, cs: -1 })
    T(s, l, { x: nx, y: 2.08, w: w - 0.2, h: 0.5, fontSize: 8.5, color: MUTE, lineSpacingMultiple: 1.12, objectName: `${n} label` })
    nx += w + 0.2
  })
  s.addChart(pres.ChartType.bar, [{ name: 'Flagged', labels: ['EPSS ≥ 0.1 alone', 'CVSS 9 or higher alone', 'Odyssey evidence rules'], values: [51, 47, 100] }], {
    x: 0.5, y: 2.75, w: 4.9, h: 1.65, barDir: 'bar', barGapWidthPct: 50,
    chartColors: [DIM, DIM, SAFF],
    showTitle: true, title: '110 real exploited CVEs (CISA KEV, Aug to Oct 2026): share each rule would have flagged', titleColor: MUTE, titleFontSize: 8, titleFontFace: '+mn-lt', titleAlign: 'left',
    showValue: true, dataLabelPosition: 'outEnd', dataLabelFormatCode: '0"%"', dataLabelColor: BONE, dataLabelFontSize: 9, dataLabelFontFace: '+mn-lt', dataLabelFontBold: true,
    catAxisLabelColor: BONE, catAxisLabelFontSize: 8.5, catAxisLabelFontFace: '+mn-lt', catAxisOrientation: 'maxMin', catGridLine: { style: 'none' }, catAxisLineShow: false,
    valAxisHidden: true, valAxisMaxVal: 115, valAxisMinVal: 0, valGridLine: { style: 'none' },
    showLegend: false, plotArea: { fill: { color: NAVY } }, chartArea: { fill: { color: NAVY } },
    objectName: 'KEV backtest bar chart',
  })
  T(s, 'KEV is one of our inputs, so 110 of 110 is by design. The honest test is out of time: the day-0 forecast, frozen in July, caught 61.1% of the CVEs exploited from August to October while flagging 2%; CVSS ≥ 9 at the same budget caught 16.7%.', { x: 0.5, y: 4.45, w: 4.9, h: 0.6, fontSize: 8, color: DIM, lineSpacingMultiple: 1.12, objectName: 'chart note' })
  const facts = [['Real, public', 'CVEs, KEV, SSVC, EPSS, CISA advisories, DShield, Feodo, OpenPhish, SACHET, Exploit-DB, ransomware.live, breach and network lists.', SAFF], ['Simulated, labelled', 'the 15 operators and their inventory, the decoy grid, the firewall logs.', MUTE], ['Proven on the wire', '45 of 45 real web attacks detected and blocked inline, 0 false positives, about 15 ms each.', BONE]]
  facts.forEach(([h, b, c], i) => {
    const y = 2.78 + i * 0.58
    dot(s, 5.75, y + 0.1, 0.05, c, `${h} marker`)
    T(s, h, { x: 5.9, y, w: 3.6, h: 0.2, fontSize: 10, bold: true, color: BONE, objectName: `${h} head` })
    T(s, b, { x: 5.9, y: y + 0.21, w: 3.6, h: 0.36, fontSize: 8, color: MUTE, lineSpacingMultiple: 1.1, objectName: `${h} body` })
  })
  s.addText([{ text: 'Real data. Measured claims. A human in the loop. ', options: { color: BONE } }, { text: 'Zero cloud calls.', options: { italic: true, color: SAFF } }], { x: 5.7, y: 4.55, w: 3.8, h: 0.55, fontFace: SERIF, fontSize: 14, bold: true, lineSpacingMultiple: 1.05, isTextBox: true, margin: 0, valign: 'bottom', objectName: 'closing line' })
  foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  DJS ISACA  ·  PS-01', 10)
  s.addNotes('Close on what is in the room: a working prototype on this laptop, no cloud, every model under 8B. Eighty-five seconds to re-score the nation. The chart is the backtest on 110 real exploited CVEs; say that 110 of 110 is by design because KEV is one of our inputs, and that the honest test is the forecast. Then the line: real data, measured claims, a human in the loop, zero cloud calls.')
}

;(async () => {
  await pres.writeFile({ fileName: OUT })
  await applyTheme(OUT, THEME)
  console.log('wrote', OUT)
})().catch((e) => { console.error(e); process.exit(1) })
