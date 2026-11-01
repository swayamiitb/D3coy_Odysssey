// Odyssey pitch deck v2: image with text on every slide, tricolour India as the design language. Local pptxgenjs build.
const pptxgen = require('pptxgenjs')
const fs = require('fs')
const path = require('path')
const { legendFor } = require('./legend')

const SHOTS = 'D:/DECOY/data/.tmp/shots', ART = 'D:/DECOY/data/.tmp/deck-build/art'
const OUT = 'D:/DECOY/docs/pitch/odyssey-pitch.pptx'
const has = (p) => { try { return fs.statSync(p).size > 1000 } catch { return false } }
const shot = (n) => path.join(SHOTS, n + '.png')
const art = (n) => path.join(ART, n + '.png')

const NAVY = '0F1B3D', NAVY2 = '17264F', NAVY3 = '12335A', WHITE = 'FFFFFF', OFF = 'F4F4F2', LINE = 'E3E3E0'
const SAFFRON = 'F28C28', GREEN = '15843A', GREEN_L = '4FC46F', RED = 'E5383B', INK = '1C2440', MUTE = '525C78', MUTE_D = 'C9D1E3', FAINT = '8A95B3'
const HEAD = 'Cambria', BODY = 'Calibri'

const pres = new pptxgen()
pres.layout = 'LAYOUT_WIDE'
pres.author = 'Team Odyssey'
pres.title = 'Odyssey · D3COY 1.0 · PS-01'
pres.theme = { headFontFace: HEAD, bodyFontFace: BODY }

let page = 0
const SLIDES = []
function base(dark, section, opts = {}) {
  const s = pres.addSlide({ sectionTitle: section })
  page += 1
  const bg = dark ? art('wash_dark') : art('wash_light')
  s.background = has(bg) ? { path: bg } : { color: dark ? NAVY : WHITE }
  const texts = []
  const origText = s.addText.bind(s), origTable = s.addTable.bind(s)
  s.addText = (t, o) => { texts.push(Array.isArray(t) ? t.map((r) => r.text).join('') : String(t)); return origText(t, o) }
  s.addTable = (rows, o) => { rows.forEach((r) => r.forEach((c) => texts.push(typeof c === 'string' ? c : String(c.text)))); return origTable(rows, o) }
  SLIDES.push({ s, texts, dark })
  if (!opts.bare) {
    const y = 7.15
    s.addShape(pres.ShapeType.ellipse, { x: 0.6, y, w: 0.14, h: 0.14, fill: { color: SAFFRON }, line: { color: SAFFRON } })
    s.addShape(pres.ShapeType.ellipse, { x: 0.8, y, w: 0.14, h: 0.14, fill: { color: WHITE }, line: { color: dark ? WHITE : 'B9B9B9', width: 0.75 } })
    s.addShape(pres.ShapeType.ellipse, { x: 1.0, y, w: 0.14, h: 0.14, fill: { color: GREEN }, line: { color: GREEN } })
    s.addText('Odyssey · D3COY 1.0 · PS-01 · AI-Based National Cyber Threat Early Warning System', { x: 1.25, y: 7.1, w: 9.5, h: 0.25, fontSize: 9, color: dark ? FAINT : '8A8A8A', fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(String(page), { x: 12.2, y: 7.1, w: 0.55, h: 0.25, fontSize: 9, color: dark ? FAINT : '8A8A8A', fontFace: BODY, align: 'right', isTextBox: true, margin: 0 })
  }
  return s
}
function head(s, eyebrow, title, dark, titleSize = 28, w = 12.1) {
  s.addText(eyebrow.toUpperCase(), { x: 0.6, y: 0.42, w, h: 0.3, fontSize: 11, bold: true, charSpacing: 3, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText(title, { x: 0.6, y: 0.74, w, h: 0.95, fontSize: titleSize, bold: true, color: dark ? WHITE : INK, fontFace: HEAD, valign: 'top', isTextBox: true, margin: 0 })
}
/** A framed screenshot: navy device frame with a soft shadow; crop = [iw, ih, cx, cy, cw, ch] in source pixels. */
function frame(s, img, x, y, w, opts = {}) {
  const p = shot(img)
  const crop = opts.crop
  const aspect = crop ? crop[4] / crop[5] : 1600 / 1000
  const pad = 0.07
  const iw = w - 2 * pad, ih = iw / aspect
  const h = ih + 2 * pad
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.1, fill: { color: opts.dark ? '070B18' : NAVY }, line: { color: opts.dark ? '2A3B6E' : NAVY, width: 0.75 }, shadow: { type: 'outer', color: '000000', blur: 8, offset: 3, angle: 90, opacity: 0.28 } })
  if (has(p)) {
    if (crop) {
      const [IW, IH, cx, cy, cw] = crop
      const scale = iw / cw
      s.addImage({ path: p, x: x + pad, y: y + pad, w: IW * scale, h: IH * scale, sizing: { type: 'crop', x: cx * scale, y: cy * scale, w: iw, h: ih } })
    } else {
      s.addImage({ path: p, x: x + pad, y: y + pad, w: iw, h: ih })
    }
  } else {
    s.addText('screenshot: ' + img, { x, y, w, h, fontSize: 12, color: MUTE_D, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true })
  }
  if (opts.caption) s.addText(opts.caption, { x, y: y + h + 0.08, w, h: 0.5, fontSize: 10.5, color: opts.dark ? MUTE_D : MUTE, fontFace: BODY, valign: 'top', isTextBox: true, margin: 0 })
  return h
}
function card(s, x, y, w, h, o) {
  const dark = !!o.dark
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.12, fill: { color: o.fill || (dark ? NAVY2 : WHITE), transparency: o.glass ? 6 : 0 }, line: { color: o.border || (dark ? '2A3B6E' : LINE), width: 0.75 }, shadow: dark ? undefined : { type: 'outer', color: '000000', blur: 5, offset: 1.5, angle: 90, opacity: 0.08 } })
  let ty = y + 0.18
  if (o.num != null) {
    s.addShape(pres.ShapeType.ellipse, { x: x + 0.22, y: ty, w: 0.34, h: 0.34, fill: { color: o.numColor || SAFFRON }, line: { color: o.numColor || SAFFRON } })
    s.addText(String(o.num), { x: x + 0.22, y: ty, w: 0.34, h: 0.34, fontSize: 12, bold: true, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 })
  }
  if (o.dot) s.addShape(pres.ShapeType.ellipse, { x: x + w - 0.5, y: ty + 0.04, w: 0.26, h: 0.26, fill: { color: o.dot }, line: { color: o.dot } })
  if (o.head) {
    s.addText(o.head, { x: x + (o.num != null ? 0.66 : 0.22), y: ty - 0.02, w: o.headW || (w - (o.num != null ? 0.88 : 0.44) - (o.dot ? 0.4 : 0)), h: o.headH || 0.42, fontSize: o.headSize || 15, bold: true, color: o.headColor || (dark ? WHITE : INK), fontFace: BODY, valign: 'middle', isTextBox: true, margin: 0 })
    ty += (o.headH || 0.42) + 0.06
  }
  if (o.big) {
    s.addText(o.big, { x: x + 0.22, y: ty, w: w - 0.44, h: 0.72, fontSize: 40, bold: true, color: o.bigColor || SAFFRON, fontFace: HEAD, isTextBox: true, margin: 0, valign: 'middle' })
    ty += 0.76
  }
  if (o.body) s.addText(o.body, { x: x + 0.22, y: ty, w: w - 0.44, h: y + h - ty - 0.14, fontSize: o.bodySize || 12.5, color: o.bodyColor || (dark ? MUTE_D : MUTE), fontFace: BODY, valign: 'top', isTextBox: true, margin: 0, paraSpaceAfter: 4 })
}
function arrowR(s, x, y, color) { s.addShape(pres.ShapeType.rightArrow, { x, y, w: 0.3, h: 0.26, fill: { color }, line: { color } }) }
function stat(s, x, y, w, big, label, sub, color, dark) {
  s.addText(big, { x, y, w, h: 0.7, fontSize: 38, bold: true, color, fontFace: HEAD, isTextBox: true, margin: 0 })
  s.addText(label, { x, y: y + 0.7, w, h: 0.3, fontSize: 13.5, bold: true, color: dark ? WHITE : INK, fontFace: BODY, isTextBox: true, margin: 0 })
  if (sub) s.addText(sub, { x, y: y + 1.0, w, h: 0.75, fontSize: 11.5, color: dark ? MUTE_D : MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
}
function note(s, t) { s.addNotes(t) }
const mapImg = (dark) => art(dark ? 'india_dark' : 'india_light')

// ================================================================ 1 cover
pres.addSection({ title: 'Why' })
{
  const s = base(true, 'Why', { bare: true })
  if (has(mapImg(true))) s.addImage({ path: mapImg(true), x: 7.45, y: 0.55, w: 5.5, h: 5.5 * 1392 / 1224 })
  s.addText('D3COY 1.0 · DJS ISACA WITH C-DAC · PS-01', { x: 0.6, y: 1.05, w: 6.6, h: 0.3, fontSize: 12, bold: true, charSpacing: 3, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Odyssey', { x: 0.6, y: 1.4, w: 6.6, h: 1.5, fontSize: 88, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  s.addText('National cyber threat early warning, running entirely on one laptop.', { x: 0.6, y: 2.95, w: 6.6, h: 1.2, fontSize: 27, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  s.addText('It reads the public threat record and its own sensors, finds what threatens India’s critical operators across six sectors and twelve states, and warns each in its own language, hours to weeks before the incident.', { x: 0.6, y: 4.25, w: 6.4, h: 1.15, fontSize: 14.5, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText([
    { text: '0', options: { color: SAFFRON, bold: true } }, { text: ' cloud calls    ', options: { color: WHITE } },
    { text: '13', options: { color: WHITE, bold: true } }, { text: ' intelligence sources    ', options: { color: WHITE } },
    { text: '22', options: { color: GREEN_L, bold: true } }, { text: ' Indian languages', options: { color: WHITE } },
  ], { x: 0.6, y: 5.6, w: 6.6, h: 0.4, fontSize: 16, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Team Odyssey · 1 November 2026', { x: 0.6, y: 6.1, w: 6.6, h: 0.35, fontSize: 13, color: FAINT, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('On the map: the 15 operators we protect (simulated, labelled SIM), by state; the red one is the suspected compromise open right now.', { x: 7.45, y: 6.85, w: 5.5, h: 0.4, fontSize: 9.5, color: FAINT, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Open with one sentence: Odyssey is a national cyber threat early warning system that runs entirely on this laptop, with zero cloud calls. Everything shown today is live on the machine in front of you.')
}

// ================================================================ 2 problem
{
  const s = base(false, 'Why')
  head(s, 'Problem statement · PS-01', 'Security teams see the attack after it has happened.', false, 28, 6.6)
  const rows = [
    ['Threats evolve faster than teams', 'Newly discovered vulnerabilities, phishing campaigns, malware and attacks on digital infrastructure, every day.', SAFFRON],
    ['Many sources, no single picture', 'Intelligence arrives from many feeds, so it is hard to spot what is emerging, correlate incidents and decide which systems come first.', NAVY],
    ['Reaction, not anticipation', 'Traditional approaches react once suspicious activity has occurred. The brief asks for a proactive system that warns before threats become incidents.', GREEN],
  ]
  rows.forEach(([h, b, c], i) => card(s, 0.6, 1.9 + i * 1.42, 6.6, 1.3, { head: h, body: b, headSize: 15, headH: 0.36, bodySize: 12.5, dot: c }))
  frame(s, 'live_tall', 7.55, 1.9, 5.2, { crop: [1600, 2700, 100, 1215, 1130, 700], caption: 'Real attack origins this week: SANS ISC DShield’s top 1,997 attacking IPs located by RIPEstat, reaching India’s operators.' })
  s.addText('“A need for an intelligent, proactive system that can analyse available cyber threat intelligence, identify emerging attack patterns, and generate early warnings before threats develop into major security incidents.” — the brief', { x: 0.6, y: 6.08, w: 12.1, h: 0.45, fontSize: 10.5, italic: true, color: MUTE, fontFace: HEAD, isTextBox: true, margin: 0 })
  note(s, 'The problem is not a shortage of threat information but the opposite: teams drown in feeds and still react late.')
}

// ================================================================ 3 challenge
{
  const s = base(false, 'Why')
  head(s, 'The challenge', 'Turn raw threat information into three answers an analyst can act on.', false, 28, 6.6)
  const qs = [['1', 'What is happening?', 'Suspicious patterns, emerging campaigns and the systems they touch, correlated across every source.'], ['2', 'Which assets are at risk?', 'A new advisory, matched against the inventory: who runs the affected software, in which version, reachable from where.'], ['3', 'What to do first?', 'A prioritised risk score, an early warning that explains itself, and the preventive measure to take now.']]
  qs.forEach(([n, h, b], i) => {
    const y = 1.9 + i * 1.42
    s.addShape(pres.ShapeType.roundRect, { x: 0.6, y, w: 6.6, h: 1.3, rectRadius: 0.12, fill: { color: NAVY }, line: { color: NAVY } })
    s.addText(n, { x: 0.85, y: y + 0.2, w: 0.6, h: 0.9, fontSize: 40, bold: true, color: SAFFRON, fontFace: HEAD, isTextBox: true, margin: 0, valign: 'middle' })
    s.addText(h, { x: 1.6, y: y + 0.18, w: 5.4, h: 0.42, fontSize: 19, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
    s.addText(b, { x: 1.6, y: y + 0.62, w: 5.4, h: 0.6, fontSize: 12.5, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  frame(s, 'warning', 7.55, 1.9, 5.2, { caption: 'One warning answers all three: what it is and how urgent, which assets and versions, and what to do, with the clocks that apply.' })
  s.addText([{ text: 'Expected solution: ', options: { bold: true, color: INK } }, { text: 'a dashboard of incoming intelligence, an AI-generated threat summary, a prioritised risk score and an early warning that explains why. Odyssey ships all four, measured.', options: { color: MUTE } }], { x: 0.6, y: 6.15, w: 12.1, h: 0.35, fontSize: 12, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'We read the challenge as three questions an analyst must answer in under a minute. Every screen in Odyssey is built around one of them.')
}

// ================================================================ 4 divider: what we built
pres.addSection({ title: 'What' })
{
  const s = base(true, 'What', { bare: true })
  if (has(mapImg(true))) s.addImage({ path: mapImg(true), x: 7.6, y: 0.5, w: 5.3, h: 5.3 * 1392 / 1224 })
  s.addText('WHAT WE BUILT', { x: 0.6, y: 2.0, w: 6.6, h: 0.3, fontSize: 12, bold: true, charSpacing: 3, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('One early-warning loop for the nation’s critical operators.', { x: 0.6, y: 2.4, w: 6.6, h: 1.9, fontSize: 40, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  const stats = [['15', 'operators, SIM', SAFFRON], ['6', 'NCIIPC sectors', WHITE], ['13', 'intelligence sources', GREEN_L], ['12', 'states', SAFFRON]]
  stats.forEach(([b, l, c], i) => { s.addText(b, { x: 0.6 + i * 1.65, y: 4.6, w: 1.6, h: 0.7, fontSize: 40, bold: true, color: c, fontFace: HEAD, isTextBox: true, margin: 0 }); s.addText(l, { x: 0.6 + i * 1.65, y: 5.3, w: 1.6, h: 0.5, fontSize: 12, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 }) })
  s.addText('Power, banking, telecom, transport, government and strategic enterprises, each operator warned in its own language.', { x: 0.6, y: 5.95, w: 6.6, h: 0.6, fontSize: 13, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Section divider. The map shows the simulated constituency: fifteen operators across twelve states; the red marker is the suspected compromise.')
}

// ================================================================ 5 solution loop
{
  const s = base(true, 'What')
  head(s, 'Our solution', 'Odyssey closes the loop: six objectives, one pipeline, one audit trail.', true)
  const steps = [['Aggregate', '13 sources, snapshot-backed and re-read live', SAFFRON], ['Analyse', 'Security LLMs, SecureBERT, forecast, Bayes, detectors', SAFFRON], ['Warn', 'NVD every 2 min, surges, day-0 flags, 22 languages', WHITE], ['Prioritise', 'Risk = 100·R·K·(0.55L + 0.30S + 0.15V), SSVC, clocks', WHITE], ['Act', 'Fixed release, block, hunt, risk plan, decide step by step', GREEN_L], ['See', 'Duty desk, satellite map, SOC, graph, organisations, proof', GREEN_L]]
  const w = 1.78, gap = 0.284
  steps.forEach(([h, b, c], i) => {
    const x = 0.6 + i * (w + gap)
    card(s, x, 1.85, w, 1.75, { dark: true, num: i + 1, numColor: c === WHITE ? '3A4A7A' : c, head: h, headSize: 15, body: b, bodySize: 11 })
    if (i < 5) arrowR(s, x + w, 2.1, c)
  })
  const imgs = [['now', 'Now: the duty desk'], ['live_tall', 'Live: the satellite threat map'], ['graph_tall', 'Intel: the intelligence graph']]
  imgs.forEach(([img, cap], i) => {
    const crop = img === 'live_tall' ? [1600, 2700, 100, 1215, 1400, 875] : img === 'graph_tall' ? [1600, 2200, 100, 1080, 1400, 875] : null
    frame(s, img, 0.6 + i * 4.275, 3.72, 3.55, { crop, dark: true, caption: cap })
  })
  note(s, 'Six steps, in the order the brief lists its key objectives, and the three screens where the loop is visible.')
}

// ================================================================ 6 objectives + map
{
  const s = base(false, 'What')
  head(s, 'The six key objectives', 'Each objective has a home in the product, and the screen says so.', false, 28, 8.4)
  const obj = [['Threat Intelligence Aggregation', 'Intel › Overview, Live › Real feeds, Indicators in and out (STIX, TAXII)'], ['AI-Based Threat Analysis', 'The AI brief on every warning, advisory analysis, the intelligence graph, the day-0 forecast'], ['Early Warning Generation', 'The duty desk, the Live page (NVD intake, detectors, drills), SOC › Warnings'], ['Risk Prioritisation', 'Why this score on every warning, the ranked warning list, Intel › Risk plan, Organisations'], ['Actionable Recommendations', 'What to do on every warning, SOC cases with playbooks, change tickets, step-by-step decision support'], ['Threat Intelligence Dashboard', 'Now, SOC › Overview, Intel › Overview, Organisations, the satellite threat map']]
  obj.forEach(([h, where], i) => {
    const y = 1.85 + i * 0.74
    s.addShape(pres.ShapeType.ellipse, { x: 0.6, y: y + 0.05, w: 0.4, h: 0.4, fill: { color: i < 2 ? SAFFRON : i < 4 ? NAVY : GREEN }, line: { color: i < 2 ? SAFFRON : i < 4 ? NAVY : GREEN } })
    s.addText(String(i + 1), { x: 0.6, y: y + 0.05, w: 0.4, h: 0.4, fontSize: 13, bold: true, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(h, { x: 1.15, y, w: 6.9, h: 0.3, fontSize: 15, bold: true, color: INK, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText([{ text: 'In Odyssey: ', options: { bold: true, color: GREEN } }, { text: where, options: { color: MUTE } }], { x: 1.15, y: y + 0.3, w: 6.9, h: 0.4, fontSize: 11.5, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  if (has(mapImg(false))) s.addImage({ path: mapImg(false), x: 8.6, y: 1.55, w: 4.1, h: 4.1 * 1392 / 1224 })
  s.addText('Every page, tab and warning sheet carries the pill of the objective it answers.', { x: 0.6, y: 6.25, w: 7.6, h: 0.3, fontSize: 11.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Operators by state (SIM); red: the suspected compromise', { x: 8.6, y: 6.25, w: 4.1, h: 0.3, fontSize: 9.5, color: MUTE, fontFace: BODY, align: 'center', isTextBox: true, margin: 0 })
  note(s, 'This is the traceability table from our plan, made visible in the product itself.')
}

// ================================================================ 7 use case
{
  const s = base(false, 'What')
  head(s, 'The brief’s example use case, live', 'A new advisory arrives. Within seconds, every exposed operator has a warning.', false, 26, 6.6)
  const steps = [['Arrive', 'A real CISA ICS advisory for Siemens WinCC, or a CVE from NVD read every two minutes.'], ['Correlate', 'Version ranges parsed and checked against installed versions: 13 WinCC assets at 7 operators.'], ['Score', 'Risk out of 100, an SSVC tier, the CERT-In deadline and a day-0 exploitation forecast.'], ['Warn', 'A validated AI brief, the named fixed release, indicators to block, the hunt steps.'], ['Decide', 'Notices go out in each operator’s language once an analyst approves; every step is in the audit trail.']]
  steps.forEach(([h, b], i) => {
    const y = 1.85 + i * 0.86
    s.addShape(pres.ShapeType.ellipse, { x: 0.6, y: y + 0.04, w: 0.42, h: 0.42, fill: { color: i === 4 ? GREEN : NAVY }, line: { color: i === 4 ? GREEN : NAVY } })
    s.addText(String(i + 1), { x: 0.6, y: y + 0.04, w: 0.42, h: 0.42, fontSize: 13, bold: true, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 })
    if (i < 4) s.addShape(pres.ShapeType.line, { x: 0.81, y: y + 0.5, w: 0, h: 0.36, line: { color: 'B9B9B9', width: 1.25 } })
    s.addText(h, { x: 1.2, y, w: 6.0, h: 0.3, fontSize: 15, bold: true, color: INK, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(b, { x: 1.2, y: y + 0.3, w: 6.0, h: 0.52, fontSize: 11.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  frame(s, 'advisories', 7.55, 1.85, 5.2, { caption: 'Intel › Advisories: the real CISA advisories matched to the inventory; the WinCC one touches 13 assets at 7 operators and proposes notices in their languages.' })
  s.addText([{ text: 'Evidence-based warnings go out on their own; ', options: { bold: true, color: GREEN } }, { text: 'predictions and escalations wait for a person. ', options: { bold: true, color: SAFFRON } }, { text: 'The time from publication to warning is a ledger event, shown on the Live page.', options: { color: MUTE } }], { x: 0.6, y: 6.2, w: 12.1, h: 0.32, fontSize: 12, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'This is the brief’s own example, run live on real data.')
}

// ================================================================ 8 dashboard
function screen(section, eyebrow, title, img, crop, caption, dark, chips) {
  const s = base(dark, section)
  head(s, eyebrow, title, dark, 26)
  const aspect = crop ? crop[4] / crop[5] : 1.6
  const maxH = 4.4
  const w = chips ? Math.min(9.0, (maxH - 0.14) * aspect + 0.14) : Math.min(12.1, (maxH - 0.14) * aspect + 0.14)
  const h = frame(s, img, 0.6, 1.72, w, { crop, dark })
  if (chips) {
    const cx = 0.6 + w + 0.3, cw = 12.7 - cx
    chips.forEach(([big, l], i) => {
      const y = 1.72 + i * 1.12
      s.addShape(pres.ShapeType.roundRect, { x: cx, y, w: cw, h: 1.0, rectRadius: 0.1, fill: { color: dark ? NAVY2 : WHITE }, line: { color: dark ? '2A3B6E' : LINE, width: 0.75 } })
      s.addText(big, { x: cx + 0.2, y: y + 0.08, w: cw - 0.4, h: 0.5, fontSize: 24, bold: true, color: i % 3 === 0 ? SAFFRON : i % 3 === 1 ? (dark ? WHITE : NAVY) : GREEN, fontFace: HEAD, isTextBox: true, margin: 0 })
      s.addText(l, { x: cx + 0.2, y: y + 0.56, w: cw - 0.4, h: 0.4, fontSize: 10.5, color: dark ? MUTE_D : MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
    })
  }
  s.addText(caption, { x: 0.6, y: Math.min(1.72 + h + 0.1, 6.15), w: 12.1, h: 0.34, fontSize: 10.5, color: dark ? MUTE_D : MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  return s
}
{
  const s = screen('What', 'Objective 6 · Threat intelligence dashboard', 'The duty desk: what needs a person right now, with its clock and its evidence.', 'now', null,
    'Now page: the suspected compromise with CERT-In’s 6-hour clock, the decisions waiting, the risk plan and the noise reduction, every figure live from the engine.', false,
    [['47×', 'less noise: 16,730 CVEs this month → 356 warnings'], ['6 h', 'CERT-In clock on the suspected compromise'], ['26', 'decisions waiting for a person'], ['205', 'changes remove 80% of the risk']])
  note(s, 'The hero card is one warning, one countdown, one action: acknowledge, why this warning, decide step by step.')
}
// ================================================================ 9 satellite map
{
  const s = screen('What', 'Objectives 3 and 6 · Early warning on a satellite map', 'Where attacks start, whom they reach, and the live beacons as they are detected.', 'live_tall', [1600, 2700, 90, 950, 1510, 1040],
    'Live page: a flat satellite world (CesiumJS; Sentinel-2 or Bing via Cesium ion, bundled tiles offline) with DShield’s top attacking countries, Feodo C2s, the operators’ states and attack paths as comet trails.', true,
    [['60', 'attacking countries, REAL (DShield, RIPEstat)'], ['1,997', 'of the top 2,000 attacking IPs located'], ['5', 'botnet C2 servers, Feodo Tracker'], ['2 min', 'between NVD reads: every new CVE, ranked']])
  note(s, 'Origins are real; the operators and the landing points are simulated and say so.')
}
// ================================================================ 10 montage
{
  const s = base(false, 'What')
  head(s, 'The console, end to end', 'Six destinations, one question each; details slide in as sheets.', false)
  const tiles = [['soc', 'SOC › Overview: cases, SLAs, decisions'], ['intel', 'Intel › Overview: sources and real feeds'], ['orgs', 'Organisations: one operator’s picture'], ['cases', 'SOC › Cases: playbooks, MTTA, MTTR'], ['risk', 'Intel › Risk plan: fewest changes, most risk'], ['proof', 'Proof › How it works: models and scoring']]
  tiles.forEach(([img, cap], i) => {
    const col = i % 3, row = Math.floor(i / 3)
    frame(s, img, 0.6 + col * 4.5, 1.72 + row * 2.42, 3.1, { caption: cap })
  })
  note(s, 'Each page keeps one question: Now, Live, SOC, Intel, Organisations, Proof.')
}

// ================================================================ 11 divider: how it works
pres.addSection({ title: 'How' })
{
  const s = base(true, 'How', { bare: true })
  if (has(art('chakra_saffron'))) s.addImage({ path: art('chakra_saffron'), x: 8.1, y: 1.15, w: 4.4, h: 4.4, transparency: 15 })
  s.addText('HOW IT WORKS', { x: 0.6, y: 2.0, w: 6.8, h: 0.3, fontSize: 12, bold: true, charSpacing: 3, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Four innovations, every one measured on this laptop.', { x: 0.6, y: 2.4, w: 6.8, h: 1.9, fontSize: 40, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  const items = ['Risk prioritisation you can recompute', 'Early warning before the incident', 'Human in the loop, by construction', 'Sovereign and offline']
  items.forEach((t, i) => { s.addShape(pres.ShapeType.ellipse, { x: 0.6, y: 4.55 + i * 0.42, w: 0.16, h: 0.16, fill: { color: [SAFFRON, WHITE, GREEN_L, SAFFRON][i] }, line: { color: [SAFFRON, WHITE, GREEN_L, SAFFRON][i] } }); s.addText(t, { x: 0.9, y: 4.45 + i * 0.42, w: 6.4, h: 0.36, fontSize: 16, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 }) })
  note(s, 'Section divider.')
}

// ================================================================ 12 scoring
{
  const s = base(true, 'How')
  head(s, 'Innovation 1 · Risk prioritisation', 'One transparent score, recomputable from the evidence, with India’s clocks attached.', true, 26)
  s.addShape(pres.ShapeType.roundRect, { x: 0.6, y: 1.8, w: 7.2, h: 4.5, rectRadius: 0.12, fill: { color: NAVY2 }, line: { color: '2A3B6E', width: 0.75 } })
  s.addText('Risk = 100 · R · K · (0.55 L + 0.30 S + 0.15 V)', { x: 0.85, y: 1.95, w: 6.8, h: 0.55, fontSize: 23, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  const rows = [['Term', 'Meaning', 'Where it comes from'], ['L', 'Exploitability', 'Likelihood rules with floors: CISA KEV, SSVC active, decoy exploit hits, vendor “exploited” text, EPSS, the forecast'], ['S', 'Potential impact', 'SSVC technical impact, OT safety minimum, CVSS'], ['V', 'Evidence', 'Admiralty-graded sources, independent origins, decay with age'], ['K', 'Asset context', 'Criticality tier, internet exposure, blast radius to crown jewels'], ['R', 'Relevance', 'Installed version against NVD, the CNA record and advisory text; disputes go to an analyst']]
  s.addTable(rows.map((r, i) => r.map((c, j) => ({ text: c, options: { bold: i === 0 || j === 0, color: i === 0 ? SAFFRON : WHITE, fontSize: 11, fontFace: BODY, fill: { color: NAVY2 }, border: { type: 'solid', color: '2A3B6E', pt: 0.5 } } }))), { x: 0.85, y: 2.62, w: 6.7, colW: [0.65, 1.65, 4.4], rowH: 0.5 })
  s.addText('An SSVC decision sets the tier; a Bayesian P(compromise) orders a hunt at 20% and declares a suspected compromise at 50%, starting CERT-In’s 6-hour clock. Every warning stores the hash of the scoring config, so any score can be recomputed.', { x: 0.85, y: 5.65, w: 6.7, h: 0.6, fontSize: 11, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  stat(s, 8.2, 1.75, 4.5, '47× less noise', 'measured this morning', '16,730 CVEs published this month became 356 warnings that matter, 2 of them suspected compromises.', SAFFRON, true)
  frame(s, 'evidence', 8.35, 3.45, 4.2, { dark: true, caption: 'Proof › Evidence: every claim as a card, with its measurement.' })
  note(s, 'The formula is deliberately simple and fully visible on every warning’s Why this score tab.')
}

// ================================================================ 13 proactive
{
  const s = base(false, 'How')
  head(s, 'Innovation 2 · Early warning, before the incident', 'Four ways Odyssey gets ahead of the attacker, each one measured.', false, 26, 7.2)
  const items = [['Live intake, every two minutes', 'Every CVE NVD publishes or changes is read, matched to installed versions, scored and ranked for the analyst with its reasons; an exposed match gets a notice within seconds.', SAFFRON], ['Day-0 exploitation forecast', 'Logistic regression, trained 2021 to 2025 and frozen 31 July 2026. Out of sample it flags 2.0% of new CVEs and catches 61.1% of those later exploited; CVSS ≥ 9 catches 16.7%. ROC AUC 0.926.', NAVY], ['Pre-disclosure scanning surges', 'A national decoy grid (24 sensors, SIM, calibrated to published honeypot patterns) raises a robust-z surge per product; the Ivanti surge came 12 days before disclosure.', GREEN], ['Three live detectors, re-tuned by analysts', 'Surge, C2 beacon periodicity and an IsolationForest flow anomaly every five seconds; a beacon re-scores every warning on that host at once. Thresholds re-derive from the analysts’ own decisions.', RED]]
  items.forEach(([h, b, c], i) => card(s, 0.6, 1.8 + i * 1.12, 7.0, 1.02, { head: h, body: b, headSize: 13.5, headH: 0.32, bodySize: 11, dot: c }))
  frame(s, 'live_tall2', 7.95, 1.8, 4.8, { crop: [1600, 3600, 100, 2300, 1400, 1180], caption: 'Live page: the incoming CVE stream, ranked for the analyst with the reasons for each rank, NVD read every two minutes.' })
  s.addText('Forecast precision is about 5% (exploitation is rare, base rate 0.16%), so forecasts are proposals for a person.', { x: 0.6, y: 6.3, w: 7.0, h: 0.25, fontSize: 10, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'The forecast numbers come from docs/eval_exploit_forecast.json; the Proof page recomputes them live.')
}

// ================================================================ 14 human in the loop
{
  const s = base(true, 'How')
  head(s, 'Innovation 3 · Human in the loop, by construction', 'Odyssey acts on evidence, proposes on prediction, and never acts alone on anything consequential.', true, 26)
  card(s, 0.6, 1.8, 3.45, 2.3, { dark: true, head: 'Runs on its own', headColor: GREEN_L, headSize: 13, headH: 0.32, body: '•  Notices on confirmed exploitation of an affected version\n•  Daily digests and threat hunts\n•  CERT-In report drafts, pre-filled', bodySize: 12, bodyColor: WHITE })
  card(s, 4.15, 1.8, 3.45, 2.3, { dark: true, head: 'Waits for a person', headColor: SAFFRON, headSize: 13, headH: 0.32, body: '•  Day-0 predictions and sensor-only warnings\n•  Escalations to CERT-In, NCIIPC, sector CSIRTs\n•  Every rejection is recorded for calibration', bodySize: 12, bodyColor: WHITE })
  s.addText('A SOC on top: cases with owners and SLAs, playbooks, shift handover, MTTA and MTTR measured from what analysts actually did. A profile (sector, organisation) re-ranks the incoming stream and the recommendations for this analyst. Alerts reach Slack, Teams, Discord, e-mail or any webhook, one card per event, audited.', { x: 0.6, y: 4.3, w: 7.0, h: 1.9, fontSize: 13, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  frame(s, 'cases', 7.95, 1.8, 4.8, { dark: true, caption: 'SOC › Cases: the incident case opened by the detector, its playbook, owner and SLA; every step and note is a hash-chained ledger event.' })
  note(s, 'Graduated autonomy was the mentors’ round-one ask.')
}

// ================================================================ 15 decision support
{
  const s = base(false, 'How')
  head(s, 'Objective 5 · Actionable recommendations, step by step', 'From evidence to an audited decision in four steps, on every warning.', false, 26, 6.6)
  const steps = [['Evidence', 'Tier, risk, the rules that fired with their sources, exposure votes, the clocks that apply, live detections on the host.'], ['Options', 'Patch, mitigate, hunt, escalate, verify, accept: each with its steps and effects, and Odyssey’s recommendation with the reason.'], ['Confirm', 'Who to escalate to (CERT-In, the sector CSIRT, NCIIPC), a notice to the operator in its own language, a note for the audit trail.'], ['Done', 'Workflow moved, case opened or advanced with its playbook, escalation card to the channels, every step returned with its ledger reference.']]
  steps.forEach(([h, b], i) => {
    const y = 1.85 + i * 1.08
    s.addShape(pres.ShapeType.ellipse, { x: 0.6, y: y + 0.04, w: 0.42, h: 0.42, fill: { color: [SAFFRON, NAVY, NAVY, GREEN][i] }, line: { color: [SAFFRON, NAVY, NAVY, GREEN][i] } })
    s.addText(String(i + 1), { x: 0.6, y: y + 0.04, w: 0.42, h: 0.42, fontSize: 13, bold: true, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(h, { x: 1.2, y, w: 6.0, h: 0.3, fontSize: 15, bold: true, color: INK, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(b, { x: 1.2, y: y + 0.3, w: 6.0, h: 0.72, fontSize: 11.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  frame(s, 'warning', 7.55, 1.85, 5.2, { caption: 'The warning sheet: tier, risk, clocks, the validated AI brief, the named fixed release, indicators to block, hunt steps, and “Decide, step by step”.' })
  s.addText('Nothing runs until the analyst presses the last button, and then only through mechanisms that already existed and were tested: workflow, cases, channels, ledger.', { x: 0.6, y: 6.22, w: 12.1, h: 0.3, fontSize: 11, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Show the Decide button on the hero card.')
}

// ================================================================ 16 graph
{
  const s = screen('How', 'Objective 2 · AI-based threat analysis', 'The intelligence graph relates everything Odyssey knows, breathing with fresh evidence.', 'graph_tall', [1600, 2200, 90, 900, 1510, 1080],
    'Intel › Graph: organisations, assets, technologies, CVEs, campaigns, ATT&CK techniques, malware, threat groups (overlap, never attribution), indicators and live signals; replay and watchlists.', false,
    [['116', 'entities in the record, every edge with provenance'], ['9', 'earlier instants the record can be replayed at'], ['Top 5', 'threat groups by ATT&CK overlap, recommended with reasons'], ['15 s', 'between watchlist evaluations']])
  note(s, 'Threat groups are stated as overlap with the ATT&CK record, never attribution.')
}

// ================================================================ 17 offline
{
  const s = base(false, 'How')
  head(s, 'Innovation 4 · Sovereign and offline', 'Everything runs on one laptop. Nothing leaves it unless an analyst routes it.', false, 26, 7.2)
  const stats = [['0', 'cloud calls', 'Every model, score and brief is computed here.', SAFFRON], ['8 GB', 'of laptop GPU', 'One 8B security LLM resident; encoders and ML on the CPU.', NAVY], ['13', 'sources, snapshot-backed', 'Re-read live when online, written through to the snapshot.', GREEN], ['22', 'scheduled languages', 'IndicTrans2 locally; 127 of 132 sentences validated.', SAFFRON]]
  stats.forEach(([b, l, sub, c], i) => { const col = i % 2, row = Math.floor(i / 2); stat(s, 0.6 + col * 3.55, 1.85 + row * 1.95, 3.4, b, l, sub, c, false) })
  s.addText('LIVE re-reads NVD every two minutes, KEV, Feodo, OpenPhish and SACHET every fifteen, DShield and CISA advisories hourly; DEMO serves the same screens from the snapshot. Every feed read, model output and click is a hash-chained ledger event.', { x: 0.6, y: 5.75, w: 7.0, h: 0.75, fontSize: 11.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  frame(s, 'system', 7.95, 1.85, 4.8, { caption: 'SOC › System: the laptop’s live vital signs, the models resident on the GPU, every AI job timed, the audit trail growing.' })
  note(s, 'For a national system, data residency is the precondition.')
}

// ================================================================ 18 models
{
  const s = base(false, 'How')
  head(s, 'The model stack · all local, all measured', 'Security-tuned models explain; a deterministic engine decides.', false, 26, 9.0)
  const rows = [['Job', 'Model', 'Measured on 2026 data'], ['Extract, classify, narrate', 'MiST 8B, security-tuned, Apache-2.0 (GPU)', '79.9% vendor accuracy on every 2026 KEV CVE; best LLM on CWE'], ['Deep reasoning on Critical alerts', 'Foundation-Sec 8B Reasoning, Cisco (GPU)', 'Security reasoning traces, in batches'], ['Entities and related threats', 'SecureBERT 2.0 NER and bi-encoder (CPU)', 'Advisory entities; related-threat retrieval'], ['Prompt-injection guard', 'DeBERTa-v3 prompt-injection v2 plus rules (CPU)', 'A hostile advisory is blocked on stage'], ['22 Indian languages', 'IndicTrans2 en-indic 200M, AI4Bharat (CPU)', '127 of 132 sentences validated'], ['CWE and CVSS prediction', 'TF-IDF, LinearSVC and logistic heads (CPU)', 'CWE 77.5% (top-3 87.5%); CVSS metrics 80 to 98%'], ['Day-0 exploitation forecast', 'Logistic regression, leak-free KEV history (CPU)', 'Flags 2.0%, catches 61.1%; ROC AUC 0.926'], ['Live detection and decision', 'Robust-z, RITA-style beacon, IsolationForest, Bayes (CPU)', '0 alerts in 240 quiet sensor-hours; drills caught']]
  s.addTable(rows.map((r, i) => r.map((c) => ({ text: c, options: { bold: i === 0, color: i === 0 ? WHITE : INK, fontSize: 10.5, fontFace: BODY, fill: { color: i === 0 ? NAVY : (i % 2 ? WHITE : OFF) }, border: { type: 'solid', color: LINE, pt: 0.5 } } }))), { x: 0.6, y: 1.78, w: 8.6, colW: [2.2, 3.1, 3.3], rowH: 0.45 })
  if (has(art('chakra_navy'))) s.addImage({ path: art('chakra_navy'), x: 10.35, y: 1.75, w: 1.6, h: 1.6, transparency: 70 })
  const chips = [['8B', 'the largest model, security-tuned, fits an 8 GB GPU'], ['1 per role', 'chosen by local benchmarks, swappable by config'], ['0', 'general LLMs in the running system: baselines only']]
  chips.forEach(([b, l], i) => { const y = 3.55 + i * 0.95; s.addText(b, { x: 9.55, y, w: 3.2, h: 0.45, fontSize: 22, bold: true, color: [SAFFRON, NAVY, GREEN][i], fontFace: HEAD, isTextBox: true, margin: 0 }); s.addText(l, { x: 9.55, y: y + 0.45, w: 3.2, h: 0.45, fontSize: 10.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 }) })
  s.addText('Every brief is checked against the record before it is shown: a number the source never stated is caught, not published.', { x: 0.6, y: 6.0, w: 8.6, h: 0.4, fontSize: 11, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Figures are from docs/MODEL_CARD.md; the Proof page shows the same tables live.')
}

// ================================================================ 19 architecture
{
  const s = base(true, 'How')
  head(s, 'Architecture and tech stack', 'From thirteen sources to one audited decision, on one machine.', true, 26)
  const label = (t, y, c) => s.addText(t.toUpperCase(), { x: 0.6, y, w: 1.2, h: 0.3, fontSize: 10.5, bold: true, charSpacing: 2, color: c, fontFace: BODY, isTextBox: true, margin: 0 })
  label('Sources', 1.64, SAFFRON)
  const srcs = ['NVD', 'CISA KEV · SSVC', 'FIRST EPSS', 'CISA advisories', 'SANS ISC DShield', 'Feodo Tracker', 'OpenPhish', 'MITRE ATT&CK', 'NDMA SACHET', 'Decoy grid · SIM', 'Firewall logs · SIM', 'HTTP shield agents']
  let px = 1.9, py = 1.6
  srcs.forEach((t) => { const w = 0.16 + t.length * 0.083; if (px + w > 12.75) { px = 1.9; py += 0.42 }; const sim = t.includes('SIM'); s.addShape(pres.ShapeType.roundRect, { x: px, y: py, w, h: 0.34, rectRadius: 0.17, fill: { color: NAVY2 }, line: { color: sim ? SAFFRON : '2A3B6E', width: 0.75 } }); s.addText(t, { x: px, y: py, w, h: 0.34, fontSize: 10.5, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 }); px += w + 0.1 })
  s.addShape(pres.ShapeType.downArrow, { x: 6.5, y: 2.46, w: 0.3, h: 0.3, fill: { color: SAFFRON }, line: { color: SAFFRON } })
  label('Engine', 3.02, WHITE)
  const eng = [['Connectors', 'snapshot, live refresh, write-through'], ['Exposure', 'CPE, CNA and text vs installed versions'], ['Scoring', 'risk, SSVC tier, Bayes, India’s clocks'], ['Live engine', 'detectors every 5 s, NVD every 2 min'], ['Autopilot', 'acts on evidence, proposes on prediction'], ['Ledger', 'hash-chained SQLite audit trail']]
  const ew = 1.66
  eng.forEach(([h, b], i) => { const x = 1.9 + i * (ew + 0.1); s.addShape(pres.ShapeType.roundRect, { x, y: 2.85, w: ew, h: 0.95, rectRadius: 0.08, fill: { color: NAVY2 }, line: { color: i === 5 ? SAFFRON : '2A3B6E', width: 0.75 } }); s.addText(h, { x: x + 0.1, y: 2.9, w: ew - 0.2, h: 0.3, fontSize: 12.5, bold: true, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 }); s.addText(b, { x: x + 0.1, y: 3.2, w: ew - 0.2, h: 0.58, fontSize: 10, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 }) })
  label('Local AI', 4.1, GREEN_L)
  const ai = [['Ollama, 8 GB GPU', 'MiST 8B · Foundation-Sec 8B Reasoning, through one llm_client adapter'], ['CPU models', 'SecureBERT 2.0 · DeBERTa guard · IndicTrans2 · forecast · classifiers · IsolationForest']]
  ai.forEach(([h, b], i) => { const x = 1.9 + i * 5.45; s.addShape(pres.ShapeType.roundRect, { x, y: 3.92, w: 5.35, h: 0.8, rectRadius: 0.08, fill: { color: NAVY3 }, line: { color: NAVY3 } }); s.addText(h, { x: x + 0.15, y: 3.97, w: 5.0, h: 0.3, fontSize: 12.5, bold: true, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 }); s.addText(b, { x: x + 0.15, y: 4.27, w: 5.0, h: 0.4, fontSize: 10.5, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 }) })
  s.addShape(pres.ShapeType.downArrow, { x: 6.5, y: 4.82, w: 0.3, h: 0.3, fill: { color: GREEN }, line: { color: GREEN } })
  label('Out', 5.35, GREEN_L)
  const out = [['Console', 'React 19 · Vite · Tailwind · CesiumJS satellite map · three.js site view · live SSE', 3.1], ['Channels', 'Slack · Teams · Discord · e-mail · webhook', 2.35], ['Exchange', 'STIX 2.1 · TAXII 2.1 · CSV risk lists', 2.35], ['India', 'CERT-In report draft · SACHET-compatible CAP 1.2 · 22 languages', 2.75]]
  let ox = 1.9
  out.forEach(([h, b, w]) => { s.addShape(pres.ShapeType.roundRect, { x: ox, y: 5.2, w, h: 0.95, rectRadius: 0.08, fill: { color: NAVY2 }, line: { color: GREEN, width: 0.75 } }); s.addText(h, { x: ox + 0.12, y: 5.25, w: w - 0.24, h: 0.3, fontSize: 12.5, bold: true, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 }); s.addText(b, { x: ox + 0.12, y: 5.55, w: w - 0.24, h: 0.58, fontSize: 10, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 }); ox += w + 0.1 })
  s.addText('FastAPI 0.162 · Python 3.15 · SQLite · scikit-learn · PyTorch CPU · Ollama · pinned versions · one command starts the whole stack', { x: 0.6, y: 6.22, w: 12.1, h: 0.26, fontSize: 10.5, color: FAINT, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Top to bottom: the sources, the deterministic engine, the local AI beside it, and the ways out.')
}

// ================================================================ 20 deliverables
pres.addSection({ title: 'Proof' })
{
  const s = base(false, 'Proof')
  head(s, 'Expected deliverables', 'All four deliverables, each with its proof a click away.', false, 26, 7.2)
  const items = [['A functional prototype', 'Offline on an 8 GB laptop GPU. About 140 engine tests, 26 product flows through the API, a 25-step browser audit, a test bench of 135 checks the judges can re-run.'], ['A dashboard of threats, risk levels and alerts', 'Six destinations; every warning with its tier, risk, clocks and evidence; every page names the objective it serves.'], ['A demonstration on public intelligence and a controlled dataset', 'REAL: CVEs, KEV, SSVC, EPSS, advisories, DShield, Feodo, phishing, SACHET. SIM: 15 operators, the decoy grid, firewall logs. Every item labelled.'], ['An explanation of the AI, the scoring and the mitigation workflow', 'Proof › How it works walks the pipeline, the model roster, the formula on a live example and the workflow; model card and coverage documents in the repository.']]
  items.forEach(([h, b], i) => card(s, 0.6, 1.8 + i * 1.08, 7.0, 1.0, { head: h, body: b, headSize: 13, headH: 0.32, bodySize: 10.5, dot: GREEN, headW: 6.2 }))
  frame(s, 'proof', 7.95, 1.8, 4.8, { caption: 'Proof › How it works: from signal to act in six steps, the models with measured results, the scoring on a live example.' })
  s.addShape(pres.ShapeType.roundRect, { x: 0.6, y: 6.08, w: 7.0, h: 0.44, rectRadius: 0.1, fill: { color: NAVY }, line: { color: NAVY } })
  s.addText('Red-teamed: 45 real web attacks at the lab app, 45 detected and blocked, 0 false positives; 10 hostile CAP messages, 10 refused, no leak.', { x: 0.75, y: 6.08, w: 6.75, h: 0.44, fontSize: 10, color: WHITE, fontFace: BODY, valign: 'middle', isTextBox: true, margin: 0 })
  note(s, 'Each deliverable maps to something the judges can click.')
}

// ================================================================ 21 honesty
{
  const s = base(false, 'Proof')
  head(s, 'What we say before you ask', 'Honest limits, stated on the screens themselves.', false, 26, 8.4)
  const items = [['Sensors are simulated', 'The decoy grid and firewall flows are SIM, labelled, accelerated; the feeds beside them are real and live.'], ['Forecast precision is low', 'About 5%, because exploitation is rare (base rate 0.16%); forecasts are proposals for a person.'], ['Lead time has two origins', 'Real signals and the simulated decoy grid; the Proof page attributes each lead to one of them.'], ['Groups are overlap, not attribution', 'A threat group appears only as overlap with its public ATT&CK record. Odyssey never attributes activity.'], ['Translation is checked, not assumed', '127 of 132 sentences validated across 22 languages; Santali is weakest; withheld lines fall back to English.'], ['CERT-In has no machine-readable feed', 'Its advisories are style-matched samples, labelled SIM; the real national feed we read is NDMA’s SACHET.']]
  items.forEach(([h, b], i) => { const col = i % 2, row = Math.floor(i / 2); card(s, 0.6 + col * 4.1, 1.8 + row * 1.45, 3.95, 1.35, { head: h, headSize: 13, headH: 0.32, body: b, bodySize: 10.5 }) })
  if (has(mapImg(false))) s.addImage({ path: mapImg(false), x: 9.1, y: 1.6, w: 3.6, h: 3.6 * 1392 / 1224 })
  s.addText('Every fact on screen is labelled REAL or SIM; every claim on the Proof page is measured on this laptop and can be re-run.', { x: 0.6, y: 6.2, w: 8.0, h: 0.3, fontSize: 11.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Judges reward candour. These are the limits a careful reviewer would find; we show them first.')
}

// ================================================================ 22 close
{
  const s = base(true, 'Proof', { bare: true })
  frame(s, 'landing', 6.9, 1.2, 5.9, { dark: true })
  s.addText('JOIN THE HUNT', { x: 0.6, y: 1.3, w: 6.0, h: 0.3, fontSize: 12, bold: true, charSpacing: 3, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Early warning for the nation, from one laptop.', { x: 0.6, y: 1.7, w: 6.0, h: 1.8, fontSize: 40, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  s.addText('Live demo on this machine: the duty desk, the satellite threat map, a real CVE taken in from NVD, a red-team against the shield, and one decision taken step by step.', { x: 0.6, y: 3.7, w: 5.9, h: 1.2, fontSize: 15, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Aggregate · Analyse · Warn · Prioritise · Act · See', { x: 0.6, y: 5.0, w: 6.0, h: 0.4, fontSize: 15, bold: true, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Team Odyssey · D3COY 1.0 · PS-01 · Thank you', { x: 0.6, y: 5.6, w: 6.0, h: 0.4, fontSize: 14, color: FAINT, fontFace: BODY, isTextBox: true, margin: 0 })
  const y = 7.05
  s.addShape(pres.ShapeType.ellipse, { x: 0.6, y, w: 0.14, h: 0.14, fill: { color: SAFFRON }, line: { color: SAFFRON } })
  s.addShape(pres.ShapeType.ellipse, { x: 0.8, y, w: 0.14, h: 0.14, fill: { color: WHITE }, line: { color: WHITE } })
  s.addShape(pres.ShapeType.ellipse, { x: 1.0, y, w: 0.14, h: 0.14, fill: { color: GREEN }, line: { color: GREEN } })
  note(s, 'Close on the six verbs, then open the console for the live demo.')
}

for (const { s, texts, dark } of SLIDES) {
  const items = legendFor(texts.join('\n'))
  if (!items.length) continue
  s.addText([{ text: 'Legend  ', options: { bold: true } }, { text: items.join('  ·  ') }],
    { x: 0.6, y: 6.55, w: 12.1, h: 0.52, fontSize: 8, color: dark ? FAINT : '7A7A7A', fontFace: BODY, valign: 'top', isTextBox: true, margin: 0 })
}
pres.writeFile({ fileName: OUT }).then((f) => console.log('wrote', f, 'slides', page))
