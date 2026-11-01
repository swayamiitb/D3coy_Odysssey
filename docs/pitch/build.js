// Odyssey pitch deck for D3COY 1.0 PS-01, built locally with pptxgenjs. Tri-colour theme: saffron, white, green on navy.
const pptxgen = require('pptxgenjs')
const { legendFor } = require('./legend')
const SLIDES = []
const fs = require('fs')
const path = require('path')

const SHOTS = 'D:/DECOY/data/.tmp/shots'
const OUT = 'D:/DECOY/docs/pitch/odyssey-pitch.pptx'
const has = (n) => { try { return fs.statSync(path.join(SHOTS, n + '.png')).size > 1000 } catch { return false } }
const shot = (n) => path.join(SHOTS, n + '.png')

const NAVY = '0F1B3D', NAVY2 = '17264F', NAVY3 = '12335A', WHITE = 'FFFFFF', OFF = 'F4F4F2', LINE = 'E3E3E0'
const SAFFRON = 'F28C28', GREEN = '15843A', GREEN_L = '4FC46F', RED = 'E5383B', INK = '1C2440', MUTE = '525C78', MUTE_D = 'C9D1E3', FAINT = '8A95B3'
const HEAD = 'Cambria', BODY = 'Calibri'

const pres = new pptxgen()
pres.layout = 'LAYOUT_WIDE' // 13.333 x 7.5
pres.author = 'Team Odyssey'
pres.title = 'Odyssey · D3COY 1.0 · PS-01'
pres.theme = { headFontFace: HEAD, bodyFontFace: BODY }

let page = 0
function base(dark, section) {
  const s = pres.addSlide({ sectionTitle: section })
  page += 1
  s.background = { color: dark ? NAVY : WHITE }
  const texts = []
  const origText = s.addText.bind(s), origTable = s.addTable.bind(s)
  s.addText = (t, o) => { texts.push(Array.isArray(t) ? t.map((r) => r.text).join('') : String(t)); return origText(t, o) }
  s.addTable = (rows, o) => { rows.forEach((r) => r.forEach((c) => texts.push(typeof c === 'string' ? c : String(c.text)))); return origTable(rows, o) }
  SLIDES.push({ s, texts, dark })
  // the tri-colour mark: three small discs, the motif of the deck
  const y = 7.15
  s.addShape(pres.ShapeType.ellipse, { x: 0.6, y, w: 0.14, h: 0.14, fill: { color: SAFFRON }, line: { color: SAFFRON } })
  s.addShape(pres.ShapeType.ellipse, { x: 0.8, y, w: 0.14, h: 0.14, fill: { color: dark ? WHITE : WHITE }, line: { color: dark ? WHITE : 'B9B9B9', width: 0.75 } })
  s.addShape(pres.ShapeType.ellipse, { x: 1.0, y, w: 0.14, h: 0.14, fill: { color: GREEN }, line: { color: GREEN } })
  s.addText('Odyssey · D3COY 1.0 · PS-01 · AI-Based National Cyber Threat Early Warning System', { x: 1.25, y: 7.1, w: 9.5, h: 0.25, fontSize: 9, color: dark ? FAINT : '8A8A8A', fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText(String(page), { x: 12.2, y: 7.1, w: 0.55, h: 0.25, fontSize: 9, color: dark ? FAINT : '8A8A8A', fontFace: BODY, align: 'right', isTextBox: true, margin: 0 })
  return s
}
function head(s, eyebrow, title, dark, titleSize = 30) {
  s.addText(eyebrow.toUpperCase(), { x: 0.6, y: 0.42, w: 12.1, h: 0.3, fontSize: 11, bold: true, charSpacing: 3, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText(title, { x: 0.6, y: 0.74, w: 12.1, h: 1.0, fontSize: titleSize, bold: true, color: dark ? WHITE : INK, fontFace: HEAD, valign: 'top', isTextBox: true, margin: 0 })
}
function card(s, x, y, w, h, o) {
  const dark = !!o.dark
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.12, fill: { color: o.fill || (dark ? NAVY2 : WHITE) }, line: { color: o.border || (dark ? NAVY2 : LINE), width: 0.75 }, shadow: dark ? undefined : { type: 'outer', color: '000000', blur: 4, offset: 1, angle: 90, opacity: 0.08 } })
  let ty = y + 0.18
  if (o.num != null) {
    s.addShape(pres.ShapeType.ellipse, { x: x + 0.22, y: ty, w: 0.34, h: 0.34, fill: { color: o.numColor || SAFFRON }, line: { color: o.numColor || SAFFRON } })
    s.addText(String(o.num), { x: x + 0.22, y: ty, w: 0.34, h: 0.34, fontSize: 12, bold: true, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 })
  }
  if (o.head) {
    s.addText(o.head, { x: x + (o.num != null ? 0.66 : 0.22), y: ty - 0.02, w: o.headW || (w - (o.num != null ? 0.88 : 0.44)), h: o.headH || 0.42, fontSize: o.headSize || 15, bold: true, color: o.headColor || (dark ? WHITE : INK), fontFace: BODY, valign: 'middle', isTextBox: true, margin: 0 })
    ty += (o.headH || 0.42) + 0.06
  }
  if (o.big) {
    s.addText(o.big, { x: x + 0.22, y: ty, w: w - 0.44, h: 0.72, fontSize: 40, bold: true, color: o.bigColor || SAFFRON, fontFace: HEAD, isTextBox: true, margin: 0, valign: 'middle' })
    ty += 0.76
  }
  if (o.body) {
    s.addText(o.body, { x: x + 0.22, y: ty, w: w - 0.44, h: y + h - ty - 0.14, fontSize: o.bodySize || 12.5, color: o.bodyColor || (dark ? MUTE_D : MUTE), fontFace: BODY, valign: 'top', isTextBox: true, margin: 0, paraSpaceAfter: 4 })
  }
}
function arrowR(s, x, y, color) {
  s.addShape(pres.ShapeType.rightArrow, { x, y, w: 0.3, h: 0.26, fill: { color }, line: { color } })
}
function note(s, t) { s.addNotes(t) }

// ---------------------------------------------------------------- 1 cover
pres.addSection({ title: 'Why' })
{
  const s = base(true, 'Why')
  // chakra: ring + 24 spokes + hub
  const cx = 10.35, cy = 3.45, r = 1.85
  s.addShape(pres.ShapeType.ellipse, { x: cx - r, y: cy - r, w: 2 * r, h: 2 * r, fill: { type: 'none' }, line: { color: '2A3B6E', width: 1 } })
  s.addShape(pres.ShapeType.ellipse, { x: cx - r * 0.86, y: cy - r * 0.86, w: 2 * r * 0.86, h: 2 * r * 0.86, fill: { type: 'none' }, line: { color: SAFFRON, width: 4 } })
  for (let i = 0; i < 24; i++) {
    const a = (i * 15 * Math.PI) / 180, r1 = r * 0.5, r2 = r * 0.84
    s.addShape(pres.ShapeType.line, { x: cx + Math.cos(a) * r1, y: cy + Math.sin(a) * r1, w: Math.cos(a) * (r2 - r1), h: Math.sin(a) * (r2 - r1), line: { color: WHITE, width: 1.25 }, flipH: false })
  }
  s.addShape(pres.ShapeType.ellipse, { x: cx - r * 0.5, y: cy - r * 0.5, w: r, h: r, fill: { color: NAVY }, line: { color: WHITE, width: 1.5 } })
  s.addShape(pres.ShapeType.ellipse, { x: cx - 0.22, y: cy - 0.22, w: 0.44, h: 0.44, fill: { color: RED }, line: { color: RED } })
  s.addShape(pres.ShapeType.ellipse, { x: cx - 0.42, y: cy - 0.42, w: 0.84, h: 0.84, fill: { type: 'none' }, line: { color: RED, width: 1, transparency: 50 } })
  s.addShape(pres.ShapeType.ellipse, { x: cx - r * 0.86, y: cy - r * 0.86, w: 2 * r * 0.86, h: 2 * r * 0.86, fill: { type: 'none' }, line: { color: GREEN, width: 4, dashType: 'lgDash' }, rotate: 150 })

  s.addText('D3COY 1.0 · DJS ISACA WITH C-DAC · PS-01', { x: 0.6, y: 1.1, w: 7.4, h: 0.3, fontSize: 12, bold: true, charSpacing: 3, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Odyssey', { x: 0.6, y: 1.45, w: 7.4, h: 1.5, fontSize: 88, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  s.addText('National cyber threat early warning, running entirely on one laptop.', { x: 0.6, y: 3.0, w: 7.4, h: 1.2, fontSize: 28, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  s.addText('It reads the public threat record and its own sensors, finds what threatens India’s critical operators, and warns each in its own language, hours to weeks before the incident.', { x: 0.6, y: 4.3, w: 7.2, h: 1.1, fontSize: 15, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText([
    { text: '0', options: { color: SAFFRON, bold: true } }, { text: ' cloud calls   ', options: { color: WHITE } },
    { text: '13', options: { color: SAFFRON, bold: true } }, { text: ' intelligence sources   ', options: { color: WHITE } },
    { text: '22', options: { color: SAFFRON, bold: true } }, { text: ' Indian languages', options: { color: WHITE } },
  ], { x: 0.6, y: 5.75, w: 8, h: 0.4, fontSize: 16, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Team Odyssey · 1 November 2026', { x: 0.6, y: 6.2, w: 7, h: 0.35, fontSize: 13, color: FAINT, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Open with one sentence: Odyssey is a national cyber threat early warning system that runs entirely on this laptop, with zero cloud calls. Everything shown today is live on the machine in front of you.')
}

// ---------------------------------------------------------------- 2 problem
{
  const s = base(false, 'Why')
  head(s, 'Problem statement · PS-01', 'Security teams see the attack after it has happened.', false)
  const cols = [
    ['Threats evolve faster than teams', 'Newly discovered vulnerabilities, phishing campaigns, malware and attacks on digital infrastructure, every day.', SAFFRON],
    ['Many sources, no single picture', 'Intelligence arrives from multiple feeds, so it is hard to spot what is emerging, correlate related incidents and decide which systems need attention first.', NAVY],
    ['Reaction, not anticipation', 'Traditional approaches react once suspicious activity has occurred. The brief asks for a proactive system that warns before threats become major incidents.', GREEN],
  ]
  cols.forEach(([h, b, c], i) => {
    const x = 0.6 + i * 4.1
    card(s, x, 1.95, 3.9, 2.5, { head: h, body: b, headSize: 17, headH: 0.7, bodySize: 14, headW: 2.95 })
    s.addShape(pres.ShapeType.ellipse, { x: x + 3.3, y: 2.12, w: 0.36, h: 0.36, fill: { color: c }, line: { color: c } })
  })
  s.addShape(pres.ShapeType.roundRect, { x: 0.6, y: 4.7, w: 12.1, h: 1.45, rectRadius: 0.12, fill: { color: OFF }, line: { color: OFF } })
  s.addText('“There is a need for an intelligent, proactive system that can analyse available cyber threat intelligence, identify emerging attack patterns, and generate early warnings before threats develop into major security incidents.”  —  the D3COY 1.0 brief', { x: 0.85, y: 4.8, w: 11.6, h: 1.25, fontSize: 15, italic: true, color: INK, fontFace: HEAD, valign: 'middle', isTextBox: true, margin: 0 })
  note(s, 'The problem is not a shortage of threat information but the opposite: teams drown in feeds and still react late. Odyssey turns that flood into a short list of what to do today.')
}

// ---------------------------------------------------------------- 3 challenge
{
  const s = base(false, 'Why')
  head(s, 'The challenge', 'Turn raw threat information into three answers an analyst can act on.', false)
  const qs = [
    ['Answer 1', 'What is happening?', 'Suspicious patterns, emerging attack campaigns and the systems they touch, correlated across every source.'],
    ['Answer 2', 'Which assets are at risk?', 'A new advisory, matched against the inventory: who runs the affected software, in which version, reachable from where.'],
    ['Answer 3', 'What to do first?', 'A prioritised risk score, an early warning that explains itself, and the preventive measure to take now.'],
  ]
  qs.forEach(([e, h, b], i) => {
    const x = 0.6 + i * 4.1
    s.addShape(pres.ShapeType.roundRect, { x, y: 1.95, w: 3.9, h: 2.7, rectRadius: 0.12, fill: { color: NAVY }, line: { color: NAVY } })
    s.addText(e.toUpperCase(), { x: x + 0.3, y: 2.15, w: 3.3, h: 0.3, fontSize: 11, bold: true, charSpacing: 2, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(h, { x: x + 0.3, y: 2.5, w: 3.3, h: 0.8, fontSize: 24, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
    s.addText(b, { x: x + 0.3, y: 3.35, w: 3.3, h: 1.35, fontSize: 14, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  s.addShape(pres.ShapeType.roundRect, { x: 0.6, y: 4.9, w: 12.1, h: 1.3, rectRadius: 0.12, fill: { color: WHITE }, line: { color: LINE, width: 0.75 } })
  s.addShape(pres.ShapeType.ellipse, { x: 0.9, y: 5.32, w: 0.46, h: 0.46, fill: { color: GREEN }, line: { color: GREEN } })
  s.addText('✓', { x: 0.9, y: 5.32, w: 0.46, h: 0.46, fontSize: 16, bold: true, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText([{ text: 'Expected solution: ', options: { bold: true, color: INK } }, { text: 'a working prototype with a dashboard of incoming intelligence, an AI-generated threat summary, a prioritised risk score and an early warning explaining why a threat deserves attention. Odyssey ships all four, measured.', options: { color: MUTE } }], { x: 1.55, y: 5.0, w: 10.9, h: 1.1, fontSize: 15, fontFace: BODY, valign: 'middle', isTextBox: true, margin: 0 })
  note(s, 'We read the challenge as three questions an analyst must answer in under a minute. Every screen in Odyssey is built around one of them.')
}

// ---------------------------------------------------------------- 4 solution loop
pres.addSection({ title: 'What' })
{
  const s = base(true, 'What')
  head(s, 'Our solution', 'Odyssey closes the loop: six objectives, one pipeline, one audit trail.', true)
  const steps = [
    ['Aggregate', '13 sources: NVD, KEV, EPSS, SSVC, CISA, DShield, Feodo, OpenPhish, ATT&CK, SACHET, decoy grid, logs', SAFFRON],
    ['Analyse', 'Security LLMs, SecureBERT, a day-0 forecast, a Bayesian compromise model, three live detectors', SAFFRON],
    ['Warn', 'NVD intake every two minutes, pre-disclosure surges, day-0 flags, notices in 22 languages', WHITE],
    ['Prioritise', 'Risk = 100·R·K·(0.55L + 0.30S + 0.15V), SSVC tier, India’s reporting clocks', WHITE],
    ['Act', 'Named fixed release, indicators to block, hunt playbooks, a risk plan, step-by-step decision support', GREEN_L],
    ['See', 'Duty desk, satellite threat map, SOC, intelligence graph, organisations, proof', GREEN_L],
  ]
  const w = 1.78, gap = 0.284
  steps.forEach(([h, b, c], i) => {
    const x = 0.6 + i * (w + gap)
    card(s, x, 2.0, w, 2.55, { dark: true, num: i + 1, numColor: c === WHITE ? '3A4A7A' : c, head: h, headSize: 15, body: b, bodySize: 11.5 })
    if (i < 5) arrowR(s, x + w + 0.0, 2.3, c)
  })
  const lines = [
    ['Proactive by design.', 'It warns, forecasts and notifies on its own, and asks a person before anything consequential.', SAFFRON],
    ['Honest by construction.', 'Every fact is labelled REAL or SIM, every number on screen is measured, every action is in a hash-chained audit trail.', WHITE],
    ['Sovereign by default.', 'Zero cloud calls. Every model runs on an 8 GB laptop GPU; the demo never depends on the network.', GREEN_L],
  ]
  lines.forEach(([h, b, c], i) => {
    s.addText([{ text: h + ' ', options: { bold: true, color: c } }, { text: b, options: { color: MUTE_D } }], { x: 0.6 + i * 4.1, y: 4.75, w: 3.9, h: 1.5, fontSize: 13.5, fontFace: BODY, valign: 'top', isTextBox: true, margin: 0 })
  })
  note(s, 'Six steps, in the order the brief lists its key objectives. The three lines underneath are the promises we keep on every screen: proactive, honest, sovereign.')
}

// ---------------------------------------------------------------- 5 objectives
{
  const s = base(false, 'What')
  head(s, 'The six key objectives', 'Each objective has a home in the product, and the screen says so.', false)
  const obj = [
    ['Threat Intelligence Aggregation', 'Trusted feeds, public advisories, vulnerability databases and simulated security logs, consolidated.', 'Intel › Overview, Live › Real feeds, Indicators in and out (STIX, TAXII).'],
    ['AI-Based Threat Analysis', 'ML and NLP to find suspicious indicators, recurring patterns and relationships between threats.', 'The AI brief on every warning, advisory analysis, the intelligence graph, the day-0 forecast.'],
    ['Early Warning Generation', 'Timely alerts on emerging threats, by severity, confidence and relevance.', 'The duty desk, the Live page (NVD intake, detectors, drills), SOC › Warnings.'],
    ['Risk Prioritisation', 'Rank by exploitability, asset criticality, potential impact and available evidence.', 'Why this score on every warning, the ranked warning list, Intel › Risk plan, Organisations.'],
    ['Actionable Recommendations', 'Patch vulnerable systems, block malicious indicators, investigate suspicious activity.', 'What to do on every warning, SOC cases with playbooks, change tickets, step-by-step decision support.'],
    ['Threat Intelligence Dashboard', 'Active threats, affected technologies, risk levels and alerts, on one screen.', 'Now, SOC › Overview, Intel › Overview, Organisations, the satellite threat map.'],
  ]
  obj.forEach(([h, what, where], i) => {
    const col = i % 3, row = Math.floor(i / 3)
    const x = 0.6 + col * 4.1, y = 1.95 + row * 2.2
    card(s, x, y, 3.9, 2.05, { num: i + 1, numColor: NAVY, head: h, headSize: 15, headH: 0.4 })
    s.addText(what, { x: x + 0.22, y: y + 0.68, w: 3.46, h: 0.62, fontSize: 12.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText([{ text: 'In Odyssey: ', options: { bold: true, color: GREEN } }, { text: where, options: { color: GREEN } }], { x: x + 0.22, y: y + 1.32, w: 3.46, h: 0.7, fontSize: 12, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  s.addText('Every page, tab and warning sheet carries the numbered pill of the objective it answers; the console footer lists all six with a jump to each.', { x: 0.6, y: 6.2, w: 12.1, h: 0.28, fontSize: 12, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'This is the traceability table from our plan, made visible in the product itself. Judges can walk the six objectives by clicking the pills.')
}

// ---------------------------------------------------------------- 6 use case
{
  const s = base(false, 'What')
  head(s, 'The brief’s example use case, live', 'A new advisory arrives. Within seconds, every exposed operator has a warning.', false)
  const steps = [
    ['Step 1 · Arrive', 'Advisory published', 'A real CISA ICS advisory for Siemens WinCC, or a CVE from NVD read every two minutes.'],
    ['Step 2 · Correlate', 'Matched to inventory', 'Version ranges parsed and checked against installed versions: 13 WinCC assets at 7 operators.'],
    ['Step 3 · Score', 'Exposure and risk', 'Risk out of 100, an SSVC tier, the CERT-In deadline and a day-0 exploitation forecast.'],
    ['Step 4 · Warn', 'Alert that explains itself', 'A validated AI brief, the named fixed release, indicators to block, the hunt steps.'],
    ['Step 5 · Decide', 'A person approves', 'Notices go out in each operator’s language once an analyst approves; every step is in the audit trail.'],
  ]
  const w = 2.2, gap = 0.275
  steps.forEach(([e, h, b], i) => {
    const x = 0.6 + i * (w + gap), dark = i === 4
    s.addShape(pres.ShapeType.roundRect, { x, y: 1.95, w, h: 2.45, rectRadius: 0.12, fill: { color: dark ? NAVY : WHITE }, line: { color: dark ? NAVY : LINE, width: 0.75 } })
    s.addText(e.toUpperCase(), { x: x + 0.2, y: 2.1, w: w - 0.4, h: 0.28, fontSize: 10.5, bold: true, charSpacing: 1.5, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(h, { x: x + 0.2, y: 2.4, w: w - 0.4, h: 0.65, fontSize: 15, bold: true, color: dark ? WHITE : INK, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(b, { x: x + 0.2, y: 3.05, w: w - 0.4, h: 1.3, fontSize: 12, color: dark ? MUTE_D : MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
    if (i < 4) arrowR(s, x + w - 0.02, 2.95, NAVY)
  })
  const rows = [
    ['Evidence-based warnings', 'Go out on their own: known exploitation of an affected installed version.', GREEN],
    ['Predictions and escalations', 'Wait for a person: forecasts, sensor-only surges, reports to regulators.', SAFFRON],
    ['Measured on this laptop', 'Time from publication to warning is a ledger event, shown on the Live page.', NAVY],
  ]
  rows.forEach(([h, b, c], i) => {
    const x = 0.6 + i * 4.1
    card(s, x, 4.6, 3.9, 1.5, { head: h, headSize: 14, headH: 0.36, body: b, bodySize: 13, headW: 3.05 })
    s.addShape(pres.ShapeType.ellipse, { x: x + 3.4, y: 4.77, w: 0.24, h: 0.24, fill: { color: c }, line: { color: c } })
  })
  note(s, 'This is the brief’s own example, run live on real data: the CISA WinCC advisory on Intel › Advisories, or the drill that publishes a new CVE on the Live page and shows the time to warning.')
}

// ---------------------------------------------------------------- 7 dashboard screenshot
function shotSlide(section, eyebrow, title, img, crop, caption, dark) {
  const s = base(dark, section)
  head(s, eyebrow, title, dark, 26)
  const boxX = 0.6, boxY = 1.72, boxW = 12.1, boxH = 4.5
  s.addShape(pres.ShapeType.roundRect, { x: boxX, y: boxY, w: boxW, h: boxH, rectRadius: 0.1, fill: { color: dark ? '070B18' : OFF }, line: { color: dark ? '2A3B6E' : LINE, width: 0.75 } })
  if (img && has(img)) {
    const o = { path: shot(img) }
    if (crop) {
      // the image's natural size, then the window we keep, both in inches of the full image laid out at `w`
      const [iw, ih, cx, cy, cw, ch] = crop
      const aspect = cw / ch
      let dw = boxW - 0.3, dh = dw / aspect
      if (dh > boxH - 0.3) { dh = boxH - 0.3; dw = dh * aspect }
      const scale = dw / cw
      Object.assign(o, { x: boxX + (boxW - dw) / 2, y: boxY + (boxH - dh) / 2, w: iw * scale, h: ih * scale,
        sizing: { type: 'crop', x: cx * scale, y: cy * scale, w: dw, h: dh } })
    } else {
      const aspect = 1600 / 1000
      let dw = boxW - 0.3, dh = dw / aspect
      if (dh > boxH - 0.3) { dh = boxH - 0.3; dw = dh * aspect }
      Object.assign(o, { x: boxX + (boxW - dw) / 2, y: boxY + (boxH - dh) / 2, w: dw, h: dh })
    }
    s.addImage(o)
  } else {
    s.addText('Screenshot: ' + img, { x: boxX, y: boxY, w: boxW, h: boxH, fontSize: 16, color: MUTE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true })
  }
  s.addText(caption, { x: 0.6, y: 6.25, w: 12.1, h: 0.26, fontSize: 10.5, color: dark ? MUTE_D : MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  return s
}
{
  const s = shotSlide('What', 'Objective 6 · Threat intelligence dashboard', 'The duty desk: what needs a person right now, with its clock and its evidence.', 'now', null,
    'Now page: the suspected compromise with CERT-In’s 6-hour clock, the decisions waiting, the risk plan and the 47× noise reduction, every figure live from the engine.', false)
  note(s, 'The hero card is one warning, one countdown, one action, in the style of a ride app: acknowledge, why this warning, decide step by step.')
}
// ---------------------------------------------------------------- 8 satellite map
{
  const s = shotSlide('What', 'Objectives 3 and 6 · Early warning on a satellite map', 'Where attacks start, whom they reach, and the live beacons as they are detected.', 'live_tall', [1600, 2700, 90, 950, 1510, 1040],
    'Live page: a flat satellite world (CesiumJS; Sentinel-2 or Bing via Cesium ion, bundled tiles offline) with DShield’s top attacking countries, Feodo C2s, the operators’ states and attack paths as comet trails.', true)
  note(s, 'Origins are real: DShield’s top 2,000 attacking IPs located by RIPEstat, 60 countries. The operators and the landing points are simulated and say so.')
}
// ---------------------------------------------------------------- 9 console end to end montage
{
  const s = base(false, 'What')
  head(s, 'The console, end to end', 'Six destinations, one question each; details slide in as sheets.', false)
  const tiles = [
    ['soc', 'SOC › Overview: cases, owners, SLAs, the decision queue'],
    ['intel', 'Intel › Overview: 13 sources, real-feed strips, what is under attack'],
    ['orgs', 'Organisations: one operator’s threat map, exposure, fixes, inbox'],
    ['cases', 'SOC › Cases: playbooks, notes, MTTA and MTTR from real clicks'],
    ['risk', 'Intel › Risk plan: the fewest changes that remove the most risk'],
    ['proof', 'Proof › How it works: pipeline, models, scoring on a live example'],
  ]
  tiles.forEach(([img, cap], i) => {
    const col = i % 3, row = Math.floor(i / 3)
    const x = 0.6 + col * 4.1, y = 1.78 + row * 2.32
    s.addShape(pres.ShapeType.roundRect, { x, y, w: 3.9, h: 2.22, rectRadius: 0.08, fill: { color: OFF }, line: { color: LINE, width: 0.75 } })
    if (has(img)) s.addImage({ path: shot(img), x: x + 0.45, y: y + 0.08, w: 3.0, h: 1.875 })
    s.addText(cap, { x: x + 0.1, y: y + 1.96, w: 3.7, h: 0.24, fontSize: 10, color: MUTE, fontFace: BODY, valign: 'middle', isTextBox: true, margin: 0 })
  })
  s.addText('Also on the console: the landing story on a 3D globe, the intelligence graph, indicator import with TAXII out, the HTTP shield red-team, the SACHET panel, the channels.', { x: 0.6, y: 6.25, w: 12.1, h: 0.24, fontSize: 10.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Each page keeps one question: Now (what needs me), Live (is it running), SOC (how we operate), Intel (what is happening), Organisations (who is at risk), Proof (why trust it).')
}

// ---------------------------------------------------------------- 10 scoring
pres.addSection({ title: 'How' })
{
  const s = base(true, 'How')
  head(s, 'Innovation 1 · Risk prioritisation', 'One transparent score, recomputable from the evidence, with India’s clocks attached.', true)
  s.addShape(pres.ShapeType.roundRect, { x: 0.6, y: 1.95, w: 7.3, h: 4.45, rectRadius: 0.12, fill: { color: NAVY2 }, line: { color: NAVY2 } })
  s.addText('Risk = 100 · R · K · (0.55 L + 0.30 S + 0.15 V)', { x: 0.85, y: 2.1, w: 6.8, h: 0.6, fontSize: 24, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  const rows = [
    ['Term', 'Meaning', 'Where it comes from'],
    ['L', 'Exploitability', 'Likelihood rules with floors: CISA KEV, SSVC active, decoy exploit hits, vendor “exploited” text, EPSS, the forecast'],
    ['S', 'Potential impact', 'SSVC technical impact, OT safety minimum, CVSS'],
    ['V', 'Evidence', 'Admiralty-graded sources, independent origins, decay with age'],
    ['K', 'Asset context', 'Criticality tier, internet exposure, blast radius to crown jewels'],
    ['R', 'Relevance', 'Installed version against NVD, the CNA record and advisory text; disputes go to an analyst'],
  ]
  s.addTable(rows.map((r, i) => r.map((c, j) => ({ text: c, options: { bold: i === 0 || j === 0, color: i === 0 ? SAFFRON : WHITE, fontSize: 11.5, fontFace: BODY, fill: { color: NAVY2 }, border: { type: 'solid', color: '2A3B6E', pt: 0.5 } } }))), { x: 0.85, y: 2.85, w: 6.8, colW: [0.7, 1.7, 4.4], rowH: 0.52 })
  const right = [
    ['Measured this morning', '47× less noise', '16,730 CVEs published this month became 356 warnings that matter, 2 of them suspected compromises.', SAFFRON],
    ['Decision, not just a number', null, 'An SSVC decision sets the tier; a Bayesian P(compromise) orders a hunt at 20% and declares a suspected compromise at 50%, starting CERT-In’s 6-hour clock.', WHITE],
    ['Auditable', null, 'Every warning stores the hash of the scoring config, so any score can be recomputed; deadlines follow CERT-In, RBI, SEBI, DPDP and NCIIPC rules.', GREEN_L],
  ]
  let y = 1.95
  right.forEach(([h, big, b, c]) => {
    const hh = big ? 1.8 : 1.2
    card(s, 8.2, y, 4.5, hh, { dark: true, head: h, headSize: 12, headH: 0.3, headColor: MUTE_D, big, bigColor: c, body: b, bodySize: 12 })
    y += hh + 0.1
  })
  note(s, 'The formula is deliberately simple and fully visible on every warning’s Why this score tab. The weights live in a config file, hashed into each warning, so a judge can change them and recompute.')
}

// ---------------------------------------------------------------- 11 proactive
{
  const s = base(false, 'How')
  head(s, 'Innovation 2 · Early warning, before the incident', 'Four ways Odyssey gets ahead of the attacker, each one measured.', false)
  const items = [
    ['Live intake, every two minutes', 'Every CVE NVD publishes or changes is read, matched to installed versions, scored and ranked for the analyst with its reasons; an exposed match gets a notice within seconds. Publication-to-warning time is a ledger event.', SAFFRON],
    ['Day-0 exploitation forecast', 'Logistic regression on text, CVSS, CWE and vendor, trained 2021 to 2025, frozen 31 July 2026. Out of sample it flags 2.0% of new CVEs and catches 61.1% of those later confirmed exploited; CVSS ≥ 9 at the same budget catches 16.7%. ROC AUC 0.926.', NAVY],
    ['Pre-disclosure scanning surges', 'A national decoy grid (24 sensors, simulated and labelled SIM, calibrated to published honeypot patterns) raises a robust-z surge per product. In the record the Ivanti surge came 12 days before disclosure; one surge with no CVE is kept as the false positive it is.', GREEN],
    ['Three live detectors, re-tuned by analysts', 'Scanning surge, C2 beacon periodicity and an IsolationForest flow anomaly run every five seconds; a beacon re-scores every warning on that host to suspected compromise at once. Thresholds re-derive each minute from the analysts’ own decisions.', RED],
  ]
  items.forEach(([h, b, c], i) => {
    const col = i % 2, row = Math.floor(i / 2)
    const x = 0.6 + col * 6.15, y = 1.95 + row * 2.1
    card(s, x, y, 5.95, 1.98, { head: h, headSize: 15, headH: 0.4, body: b, bodySize: 12.5, headW: 5.0 })
    s.addShape(pres.ShapeType.ellipse, { x: x + 5.45, y: y + 0.22, w: 0.26, h: 0.26, fill: { color: c }, line: { color: c } })
  })
  s.addText('Forecast precision is low (about 5%) because exploitation is rare (base rate 0.16%); that is exactly why forecasts are proposals for a person, never automatic notices.', { x: 0.6, y: 6.15, w: 12.1, h: 0.3, fontSize: 12, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'The forecast numbers come from docs/eval_exploit_forecast.json; the Proof page recomputes them live. We say the precision is low before a judge asks.')
}

// ---------------------------------------------------------------- 12 human in the loop
{
  const s = base(true, 'How')
  head(s, 'Innovation 3 · Human in the loop, by construction', 'Odyssey acts on evidence, proposes on prediction, and walks the analyst to a decision.', true)
  card(s, 0.6, 1.95, 3.2, 2.75, { dark: true, head: 'Runs on its own', headColor: GREEN_L, headSize: 13, headH: 0.34, body: '•  Notices on confirmed exploitation of an affected version\n•  Daily digests and threat hunts\n•  CERT-In report drafts, pre-filled', bodySize: 13, bodyColor: WHITE })
  card(s, 3.95, 1.95, 3.2, 2.75, { dark: true, head: 'Waits for a person', headColor: SAFFRON, headSize: 13, headH: 0.34, body: '•  Day-0 predictions and sensor-only warnings\n•  Escalations to CERT-In, NCIIPC, sector CSIRTs\n•  Every rejection is recorded for calibration', bodySize: 13, bodyColor: WHITE })
  card(s, 7.3, 1.95, 5.4, 2.75, { fill: WHITE, border: WHITE, head: 'Decide, step by step', headColor: NAVY, headSize: 13, headH: 0.34,
    body: '1  Evidence: tier, rules fired, exposure votes, clocks, live detections\n2  Options: patch, mitigate, hunt, escalate, verify, accept, with Odyssey’s recommendation and why\n3  Confirm: who to escalate to, a notice in the operator’s language, a note\n4  Done: workflow moved, case opened with its playbook, cards to the channels, every step audited', bodySize: 12.5, bodyColor: INK })
  s.addText('A SOC on top: cases with owners and SLAs, playbooks, shift handover, MTTA and MTTR measured from what analysts actually did. A profile (sector, organisation) re-ranks the incoming stream and the recommendations for this analyst.', { x: 0.6, y: 4.85, w: 5.9, h: 1.4, fontSize: 13, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Alerts reach the apps a team already uses: Slack, Teams, Discord, e-mail or any webhook, one card per event, audited. Analyst escalations and notices travel the same way.', { x: 6.8, y: 4.85, w: 5.9, h: 1.4, fontSize: 13, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Graduated autonomy was the mentors’ round-one ask. The decision support never runs until the analyst presses the last button, and then only uses mechanisms that already existed and were tested.')
}
// ---------------------------------------------------------------- 13 decide screenshot
{
  const s = base(false, 'How')
  head(s, 'Objective 5 · Actionable recommendations, in the product', 'A warning explains itself, then walks the analyst from evidence to an audited decision.', false, 26)
  const place = (img, x, cap) => {
    s.addShape(pres.ShapeType.roundRect, { x, y: 1.78, w: 5.95, h: 4.15, rectRadius: 0.1, fill: { color: OFF }, line: { color: LINE, width: 0.75 } })
    if (has(img)) s.addImage({ path: shot(img), x: x + 0.22, y: 1.9, w: 5.5, h: 5.5 / 1.6 })
    s.addText(cap, { x: x + 0.12, y: 5.38, w: 5.7, h: 0.5, fontSize: 10.5, color: MUTE, fontFace: BODY, valign: 'top', isTextBox: true, margin: 0 })
  }
  place('warning', 0.6, 'The warning sheet: tier, risk, clocks, the validated AI brief, named fixed release, indicators to block, hunt steps, and Decide, step by step.')
  place('cases', 6.75, 'SOC › Cases: the incident case opened by the detector, its playbook, owner and SLA; every step and note is a hash-chained ledger event.')
  s.addText('Executing a decision moves the workflow, opens or advances the case, records the escalation, routes a card to the channels and writes a notice in the operator’s language. Verified end to end on a copy of the record.', { x: 0.6, y: 6.05, w: 12.1, h: 0.4, fontSize: 11.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Show the Decide button on the hero card: evidence, options with the recommendation, confirm with escalation targets, done with ledger references.')
}
// ---------------------------------------------------------------- 14 graph screenshot
{
  const s = shotSlide('How', 'Objective 2 · AI-based threat analysis', 'The intelligence graph relates everything Odyssey knows, breathing with fresh evidence.', 'graph_tall', [1600, 2200, 90, 900, 1510, 1080],
    'Intel › Graph: organisations, assets, technologies, CVEs, campaigns, ATT&CK techniques, malware, threat groups (overlap, never attribution), indicators and live signals; replay and watchlists.', false)
  note(s, 'Threat groups are stated as overlap with the ATT&CK record, never attribution. The Most concerning now strip under the graph ranks organisations, actors, malware and technologies with reasons.')
}

// ---------------------------------------------------------------- 15 offline
{
  const s = base(false, 'How')
  head(s, 'Innovation 4 · Sovereign and offline', 'Everything runs on one laptop. Nothing leaves it unless an analyst routes it.', false)
  const stats = [['0', 'cloud calls', 'Every model, every score, every brief is computed here.', SAFFRON], ['8 GB', 'of laptop GPU', 'One 8B security LLM resident; encoders and classic ML on the CPU.', WHITE], ['13', 'sources, snapshot-backed', 'Re-read live when the network is up, written through to the snapshot; the demo never depends on it.', GREEN_L], ['22', 'scheduled languages', 'IndicTrans2 locally; 127 of 132 test sentences validated; withheld lines fall back to English.', SAFFRON]]
  stats.forEach(([big, l, b, c], i) => {
    const x = 0.6 + i * 3.05
    s.addShape(pres.ShapeType.roundRect, { x, y: 1.95, w: 2.9, h: 2.25, rectRadius: 0.12, fill: { color: NAVY }, line: { color: NAVY } })
    s.addText(big, { x: x + 0.25, y: 2.08, w: 2.4, h: 0.75, fontSize: 40, bold: true, color: c, fontFace: HEAD, isTextBox: true, margin: 0 })
    s.addText(l, { x: x + 0.25, y: 2.85, w: 2.4, h: 0.32, fontSize: 14, bold: true, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(b, { x: x + 0.25, y: 3.2, w: 2.4, h: 0.92, fontSize: 11.5, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  const cards = [
    ['Two modes, one codebase', 'LIVE re-reads NVD every two minutes, KEV, Feodo, OpenPhish and SACHET every fifteen, DShield and CISA advisories hourly. DEMO serves the same screens from the offline snapshot with pre-generated AI outputs.'],
    ['A satellite map that works offline', 'Sentinel-2 or Bing imagery through Cesium ion when online, with token rotation; bundled Natural Earth tiles when not; the 2D map if the GPU is missing.'],
    ['Tamper-evident record', 'Every feed read, model output, autopilot action and analyst click is a hash-chained ledger event; editing any past entry breaks the chain, and the console shows it.'],
  ]
  cards.forEach(([h, b], i) => card(s, 0.6 + i * 4.1, 4.35, 3.9, 2.05, { head: h, headSize: 14.5, headH: 0.38, body: b, bodySize: 12.5 }))
  note(s, 'For a national system, data residency is the precondition. The whole stack runs on the laptop in front of the judges, and the Proof page shows the zero-cloud claim as a measured fact.')
}

// ---------------------------------------------------------------- 16 models
{
  const s = base(false, 'How')
  head(s, 'The model stack · all local, all measured', 'Security-tuned models explain; a deterministic engine decides.', false)
  const rows = [
    ['Job', 'Model', 'Runs on', 'Measured on 2026 data, newer than any training set'],
    ['Extract, classify, narrate', 'MiST 8B (security-tuned, Apache-2.0)', 'GPU, Ollama', 'Best security LLM on product extraction: 79.9% vendor accuracy on every 2026 KEV CVE; best LLM on CWE (62.5%)'],
    ['Deep reasoning on Critical alerts', 'Foundation-Sec 8B Reasoning (Cisco)', 'GPU, Ollama', 'Security reasoning traces, run in batches; free text only'],
    ['Entities and related threats', 'SecureBERT 2.0 NER and bi-encoder (Cisco)', 'CPU', 'Advisory entities and indicators; related-threat retrieval over local embeddings'],
    ['Prompt-injection guard', 'DeBERTa-v3 prompt-injection v2 (ProtectAI) plus rules', 'CPU', 'A hostile advisory in the inbox is blocked on stage'],
    ['22 Indian languages', 'IndicTrans2 en-indic 200M (AI4Bharat, MIT)', 'CPU', '127 of 132 sentences validated; withheld lines fall back to English'],
    ['CWE and CVSS prediction', 'TF-IDF with LinearSVC and logistic heads', 'CPU', 'CWE 77.5% (top-3 87.5%); CVSS metrics 80 to 98% each; the LLM adjudicates among candidates'],
    ['Day-0 exploitation forecast', 'Logistic regression, leak-free KEV history', 'CPU', 'Out of sample: flags 2.0%, catches 61.1%; ROC AUC 0.926; calibrated'],
    ['Live detection and decision', 'Robust-z surge, RITA-style beacon, IsolationForest, Bayesian P(compromise)', 'CPU, every 5 s', '0 alerts in 240 quiet sensor-hours; drills caught; thresholds re-learned from analysts'],
  ]
  s.addTable(rows.map((r, i) => r.map((c) => ({ text: c, options: { bold: i === 0, color: i === 0 ? WHITE : INK, fontSize: 11, fontFace: BODY, fill: { color: i === 0 ? NAVY : (i % 2 ? WHITE : OFF) }, border: { type: 'solid', color: LINE, pt: 0.5 } } }))), { x: 0.6, y: 1.8, w: 12.1, colW: [2.5, 3.4, 1.4, 4.8], rowH: 0.46 })
  s.addText('One model per role, chosen by local benchmarks and swappable by config; general models appear only as baselines. Every brief is checked against the record before it is shown: a number the source never stated is caught, not published.', { x: 0.6, y: 6.0, w: 12.1, h: 0.42, fontSize: 11.5, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Figures are from docs/MODEL_CARD.md and the eval JSON files; the Proof page shows the same tables live. MiST hallucinated a CVSS score once in testing, which is why the fact validator is mandatory.')
}

// ---------------------------------------------------------------- 17 architecture
{
  const s = base(true, 'How')
  head(s, 'Architecture and tech stack', 'From thirteen sources to one audited decision, on one machine.', true, 26)
  const label = (t, y, c) => s.addText(t.toUpperCase(), { x: 0.6, y, w: 1.2, h: 0.3, fontSize: 10.5, bold: true, charSpacing: 2, color: c, fontFace: BODY, isTextBox: true, margin: 0 })
  // sources row: pills
  label('Sources', 1.64, SAFFRON)
  const srcs = ['NVD', 'CISA KEV · SSVC', 'FIRST EPSS', 'CISA advisories', 'SANS ISC DShield', 'Feodo Tracker', 'OpenPhish', 'MITRE ATT&CK', 'NDMA SACHET', 'Decoy grid · SIM', 'Firewall logs · SIM', 'HTTP shield agents']
  let px = 1.9, py = 1.6
  srcs.forEach((t) => {
    const w = 0.16 + t.length * 0.083
    if (px + w > 12.75) { px = 1.9; py += 0.42 }
    const sim = t.includes('SIM')
    s.addShape(pres.ShapeType.roundRect, { x: px, y: py, w, h: 0.34, rectRadius: 0.17, fill: { color: NAVY2 }, line: { color: sim ? SAFFRON : '2A3B6E', width: 0.75 } })
    s.addText(t, { x: px, y: py, w, h: 0.34, fontSize: 10.5, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 })
    px += w + 0.1
  })
  s.addShape(pres.ShapeType.downArrow, { x: 6.5, y: 2.46, w: 0.3, h: 0.3, fill: { color: SAFFRON }, line: { color: SAFFRON } })
  // engine row
  label('Engine', 3.02, WHITE)
  const eng = [['Connectors', 'snapshot, live refresh, write-through'], ['Exposure', 'CPE, CNA and text vs installed versions'], ['Scoring', 'risk, SSVC tier, Bayes, India’s clocks'], ['Live engine', 'detectors every 5 s, NVD every 2 min'], ['Autopilot', 'acts on evidence, proposes on prediction'], ['Ledger', 'hash-chained SQLite audit trail']]
  const ew = 1.66, eg = 0.1
  eng.forEach(([h, b], i) => {
    const x = 1.9 + i * (ew + eg)
    s.addShape(pres.ShapeType.roundRect, { x, y: 2.85, w: ew, h: 0.95, rectRadius: 0.08, fill: { color: NAVY2 }, line: { color: i === 5 ? SAFFRON : '2A3B6E', width: 0.75 } })
    s.addText(h, { x: x + 0.1, y: 2.9, w: ew - 0.2, h: 0.3, fontSize: 12.5, bold: true, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(b, { x: x + 0.1, y: 3.2, w: ew - 0.2, h: 0.58, fontSize: 10, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  // local AI row
  label('Local AI', 4.1, GREEN_L)
  const ai = [['Ollama, 8 GB GPU', 'MiST 8B · Foundation-Sec 8B Reasoning, through one llm_client adapter'], ['CPU models', 'SecureBERT 2.0 · DeBERTa guard · IndicTrans2 · forecast · classifiers · IsolationForest']]
  ai.forEach(([h, b], i) => {
    const x = 1.9 + i * 5.45
    s.addShape(pres.ShapeType.roundRect, { x, y: 3.92, w: 5.35, h: 0.8, rectRadius: 0.08, fill: { color: NAVY3 }, line: { color: NAVY3 } })
    s.addText(h, { x: x + 0.15, y: 3.97, w: 5.0, h: 0.3, fontSize: 12.5, bold: true, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(b, { x: x + 0.15, y: 4.27, w: 5.0, h: 0.4, fontSize: 10.5, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  })
  s.addShape(pres.ShapeType.downArrow, { x: 6.5, y: 4.82, w: 0.3, h: 0.3, fill: { color: GREEN }, line: { color: GREEN } })
  // out row
  label('Out', 5.35, GREEN_L)
  const out = [['Console', 'React 19 · Vite · Tailwind · CesiumJS satellite map · three.js site view · live SSE', 3.1], ['Channels', 'Slack · Teams · Discord · e-mail · webhook', 2.35], ['Exchange', 'STIX 2.1 · TAXII 2.1 · CSV risk lists', 2.35], ['India', 'CERT-In report draft · SACHET-compatible CAP 1.2 · 22 languages', 2.75]]
  let ox = 1.9
  out.forEach(([h, b, w]) => {
    s.addShape(pres.ShapeType.roundRect, { x: ox, y: 5.2, w, h: 0.95, rectRadius: 0.08, fill: { color: NAVY2 }, line: { color: GREEN, width: 0.75 } })
    s.addText(h, { x: ox + 0.12, y: 5.25, w: w - 0.24, h: 0.3, fontSize: 12.5, bold: true, color: WHITE, fontFace: BODY, isTextBox: true, margin: 0 })
    s.addText(b, { x: ox + 0.12, y: 5.55, w: w - 0.24, h: 0.58, fontSize: 10, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
    ox += w + 0.1
  })
  s.addText('FastAPI 0.162 · Python 3.15 · SQLite · scikit-learn · PyTorch CPU · Ollama · pinned versions · one command to start the whole stack', { x: 0.6, y: 6.22, w: 12.1, h: 0.26, fontSize: 10.5, color: FAINT, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Top to bottom: the sources, the deterministic engine, the local AI beside it, and the ways out. The ledger sits at the end of the engine row because every other box writes to it.')
}

// ---------------------------------------------------------------- 18 deliverables
pres.addSection({ title: 'Proof' })
{
  const s = base(false, 'Proof')
  head(s, 'Expected deliverables', 'All four deliverables, each with its proof a click away.', false)
  const items = [
    ['A functional prototype', 'Runs offline on an 8 GB laptop GPU. About 140 engine tests, 26 product flows driven through the API, a 25-step browser audit, and a test bench of 135 checks the judges can re-run from the Proof page.'],
    ['A dashboard of threats, risk levels and alerts', 'Six destinations: Now, Live, SOC, Intel, Organisations, Proof. Every warning carries its tier, risk, clocks and evidence; every page names the objective it serves.'],
    ['A demonstration on public intelligence plus a controlled dataset', 'REAL: CVEs, KEV, SSVC, EPSS, advisories, DShield, Feodo, phishing, SACHET. SIM: 15 fictional operators across six NCIIPC sectors, the decoy grid, firewall logs. Every item labelled.'],
    ['An explanation of the AI, the scoring and the mitigation workflow', 'Proof › How it works walks the pipeline, the model roster with measured results, the formula on a live example and the three-lane workflow; the model card and coverage documents are in the repository.'],
  ]
  items.forEach(([h, b], i) => {
    const col = i % 2, row = Math.floor(i / 2)
    const x = 0.6 + col * 6.15, y = 1.95 + row * 1.95
    card(s, x, y, 5.95, 1.85, { head: h, headSize: 14, headH: 0.6, body: b, bodySize: 12, headW: 4.95 })
    s.addShape(pres.ShapeType.ellipse, { x: x + 5.4, y: y + 0.2, w: 0.3, h: 0.3, fill: { color: GREEN }, line: { color: GREEN } })
    s.addText('✓', { x: x + 5.4, y: y + 0.2, w: 0.3, h: 0.3, fontSize: 11, bold: true, color: WHITE, align: 'center', valign: 'middle', fontFace: BODY, isTextBox: true, margin: 0 })
  })
  s.addShape(pres.ShapeType.roundRect, { x: 0.6, y: 5.85, w: 12.1, h: 0.55, rectRadius: 0.12, fill: { color: NAVY }, line: { color: NAVY } })
  s.addText('Red-teamed, not just tested: 45 real web attacks over the wire against the protected lab app, 45 detected and blocked inline with no false positive on the benign controls; 10 hostile CAP messages at the SACHET ingest, 10 refused, no leak.', { x: 0.85, y: 5.88, w: 11.6, h: 0.5, fontSize: 11.5, color: WHITE, fontFace: BODY, valign: 'middle', isTextBox: true, margin: 0 })
  note(s, 'Each deliverable maps to something the judges can click: the test bench, the six pages, the REAL/SIM labels, the How it works page. The red-team figures are from the model card.')
}

// ---------------------------------------------------------------- 19 honesty
{
  const s = base(false, 'Proof')
  head(s, 'What we say before you ask', 'Honest limits, stated on the screens themselves.', false)
  const items = [
    ['Sensors are simulated', 'The decoy grid and firewall flows are SIM, labelled, accelerated: one 5-second tick is one sensor-hour. The feeds they sit beside are real and live.'],
    ['Forecast precision is low', 'About 5%, because exploitation is rare (base rate 0.16%). Forecasts are proposals for a person, never automatic notices.'],
    ['Lead time has two origins', 'Real signals (CISA SSVC, vendor text, the forecast) and the simulated decoy grid; the Proof page attributes each lead to one of them.'],
    ['Groups are overlap, not attribution', 'A threat group appears only as overlap between its public ATT&CK record and what we observe. Odyssey never attributes activity.'],
    ['Translation is checked, not assumed', '127 of 132 sentences validated across 22 languages; Santali is weakest and withheld lines fall back to English.'],
    ['CERT-In has no machine-readable feed', 'Its advisories are represented by style-matched samples, labelled SIM; the real national feed we read is NDMA’s SACHET.'],
  ]
  items.forEach(([h, b], i) => {
    const col = i % 3, row = Math.floor(i / 3)
    card(s, 0.6 + col * 4.1, 1.95 + row * 2.15, 3.9, 2.05, { head: h, headSize: 14.5, headH: 0.42, body: b, bodySize: 12.5 })
  })
  s.addText('Every fact on screen is labelled REAL or SIM; every claim on the Proof page is measured on this laptop and can be re-run.', { x: 0.6, y: 6.2, w: 12.1, h: 0.26, fontSize: 12, color: MUTE, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Judges reward candour. These are the limits a careful reviewer would find; we show them first.')
}

// ---------------------------------------------------------------- 20 close
{
  const s = base(true, 'Proof')
  if (has('landing')) s.addImage({ path: shot('landing'), x: 7.0, y: 1.3, w: 5.7, h: 5.7 / 1.6, transparency: 10 })
  s.addText('JOIN THE HUNT', { x: 0.6, y: 1.3, w: 6.2, h: 0.3, fontSize: 12, bold: true, charSpacing: 3, color: SAFFRON, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Early warning for the nation, from one laptop.', { x: 0.6, y: 1.7, w: 6.2, h: 1.8, fontSize: 40, bold: true, color: WHITE, fontFace: HEAD, isTextBox: true, margin: 0 })
  s.addText('Live demo on this machine: the duty desk, the satellite threat map, a real CVE taken in from NVD, a red-team against the shield, and one decision taken step by step.', { x: 0.6, y: 3.7, w: 6.0, h: 1.2, fontSize: 15, color: MUTE_D, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText([
    { text: 'Aggregate · Analyse · Warn · Prioritise · Act · See', options: { color: WHITE, bold: true } },
  ], { x: 0.6, y: 5.0, w: 6.2, h: 0.4, fontSize: 15, fontFace: BODY, isTextBox: true, margin: 0 })
  s.addText('Team Odyssey · D3COY 1.0 · PS-01 · Thank you', { x: 0.6, y: 5.6, w: 6.2, h: 0.4, fontSize: 14, color: FAINT, fontFace: BODY, isTextBox: true, margin: 0 })
  note(s, 'Close on the six verbs, then open the console for the live demo.')
}

for (const { s, texts, dark } of SLIDES) {
  const items = legendFor(texts.join('\n'))
  if (!items.length) continue
  s.addText([{ text: 'Legend  ', options: { bold: true } }, { text: items.join('  ·  ') }],
    { x: 0.6, y: 6.52, w: 12.1, h: 0.56, fontSize: 8, color: dark ? FAINT : '7A7A7A', fontFace: BODY, valign: 'top', isTextBox: true, margin: 0 })
}
pres.writeFile({ fileName: OUT }).then((f) => console.log('wrote', f, 'slides', page))
