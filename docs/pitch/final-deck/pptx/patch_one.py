import sys
p = sys.argv[1]; s = open(p, encoding='utf-8').read(); n0 = len(s)
def rep(a, b):
    global s
    assert s.count(a) == 1, 'not found once: ' + a[:90]
    s = s.replace(a, b)
# global: chips sit on the eyebrow row, titles take the full width, footers are tighter
rep("const x = o.x ?? 9.5 - w, y = o.y ?? 0.6", "const x = o.x ?? 9.5 - w, y = o.y ?? 0.27")
rep("x: 0.5, y: 0.56, w: 6.6, h: 0.6, fontFace: SERIF, fontSize: 30", "x: 0.5, y: 0.56, w: 9, h: 0.6, fontFace: SERIF, fontSize: 30")
rep("  mono(slide, left, { x: 0.5, y: 5.22, w: 8.2, h: 0.2, fontSize: 7.5, color: DIM })", "  mono(slide, left, { x: 0.5, y: 5.22, w: 8.2, h: 0.2, fontSize: 7.5, color: DIM, charSpacing: 0.8 })")
# cover
rep("mono(s, 'FINAL ROUND  ·  D3COY 1.0  ·  DJS ISACA  ·  PROBLEM STATEMENT 01', { x: 0.5, y: 1.98, w: 6, h: 0.2, color: SAFF, charSpacing: 2.5 })",
    "mono(s, 'FINAL ROUND  ·  D3COY 1.0  ·  DJS ISACA  ·  PROBLEM STATEMENT 01', { x: 0.5, y: 1.9, w: 7, h: 0.2, color: SAFF, charSpacing: 2 })")
rep("], { x: 0.5, y: 2.2, w: 6.4, h: 1.55, fontFace: SERIF, fontSize: 56, bold: true, lineSpacingMultiple: 0.95, charSpacing: -1, isTextBox: true, margin: 0, valign: 'top', objectName: 'headline' })",
    "], { x: 0.5, y: 2.1, w: 6.4, h: 1.5, fontFace: SERIF, fontSize: 52, bold: true, lineSpacingMultiple: 0.92, charSpacing: -1, isTextBox: true, margin: 0, valign: 'top', objectName: 'headline' })")
rep("{ x: 0.5, y: 3.82, w: 5.5, h: 0.72, fontSize: 12.5, color: BONE, lineSpacingMultiple: 1.15, objectName: 'claim' }", "{ x: 0.5, y: 3.78, w: 5.5, h: 0.72, fontSize: 12, color: BONE, lineSpacingMultiple: 1.15, objectName: 'claim' }")
rep("mono(s, 'SEVEN ASKS · ONE SYSTEM', { x: 0.5, y: 4.68, w: 1.9, h: 0.22, charSpacing: 2 })\n  let cx = 2.45", "mono(s, 'SEVEN ASKS · ONE SYSTEM', { x: 0.5, y: 4.68, w: 2.2, h: 0.22, charSpacing: 1.5 })\n  let cx = 2.6")
rep("mono(s, 'BEHIND: THE LIVE THREAT MAP, AS THE CONSOLE DRAWS IT  ·  RED = ATTACK SOURCE (DSHIELD, REAL)  ·  VIOLET = SUSPECTED COMPROMISE', { x: 0.5, y: 5.22, w: 8.2, h: 0.2, fontSize: 7.5, color: DIM })",
    "mono(s, 'BEHIND: THE LIVE THREAT MAP, AS THE CONSOLE DRAWS IT  ·  RED = ATTACK SOURCE (DSHIELD, REAL)  ·  VIOLET = COMPROMISE', { x: 0.5, y: 5.22, w: 8.2, h: 0.2, fontSize: 7.5, color: DIM, charSpacing: 0.8 })")
# problem: a one-line title, wider figure boxes, an untangled C-Edge timeline
rep("{ text: 'late.', options: { italic: true, color: SAFF } }], { placeholder: 'title', w: 9 })", "{ text: 'late.', options: { italic: true, color: SAFF } }], { placeholder: 'title', fontSize: 24 })")
rep("s.addImage({ path: IMG('plates/dots72_navy.png'), x: 5.1, y: 1.3, w: 1.0, h: 1.0, objectName: 'A hundred dots, 72 lit' })", "s.addImage({ path: IMG('plates/dots72_navy.png'), x: 5.1, y: 1.3, w: 0.9, h: 0.9, objectName: 'A hundred dots, 72 lit' })")
rep("{ x: 6.18, y: 1.72, w: 0.32, h: 0.16, fill: { color: SAFF }", "{ x: 6.06, y: 1.67, w: 0.28, h: 0.15, fill: { color: SAFF }")
rep("s.addImage({ path: IMG('plates/dots21_navy.png'), x: 6.58, y: 1.3, w: 1.0, h: 1.0, objectName: 'A hundred dots, 21 lit' })", "s.addImage({ path: IMG('plates/dots21_navy.png'), x: 6.4, y: 1.3, w: 0.9, h: 0.9, objectName: 'A hundred dots, 21 lit' })")
rep("big(s, '72% → 21%', 7.72, 1.25, 1.8, { size: 36, h: 0.55 })", "big(s, '72% → 21%', 7.45, 1.25, 2.05, { size: 32, h: 0.52 })")
rep("{ x: 7.72, y: 1.84, w: 1.78, h: 0.5, fontSize: 8.5, color: MUTE, objectName: 'labels caption' }", "{ x: 7.45, y: 1.8, w: 2.05, h: 0.5, fontSize: 8.5, color: MUTE, objectName: 'labels caption' }")
rep("s.addImage({ path: IMG('plates/dots29_navy.png'), x: 5.1, y: 2.48, w: 1.0, h: 1.0, objectName: 'A hundred dots, 29 red' })", "s.addImage({ path: IMG('plates/dots29_navy.png'), x: 5.1, y: 2.42, w: 0.9, h: 0.9, objectName: 'A hundred dots, 29 red' })")
rep("big(s, '29%', 6.25, 2.43, 1.4, { size: 36, h: 0.55, color: RED })", "big(s, '29%', 6.15, 2.37, 1.4, { size: 32, h: 0.52, color: RED })")
rep("{ x: 6.25, y: 3.02, w: 3.25, h: 0.42, fontSize: 8.5, color: MUTE, objectName: 'day zero caption' }", "{ x: 6.15, y: 2.92, w: 3.35, h: 0.42, fontSize: 8.5, color: MUTE, objectName: 'day zero caption' }")
rep("mono(s, 'C-EDGE  ·  2024  ·  THE INDIAN CASE', { x: 0.5, y: 4.0, w: 4, h: 0.2, color: SAFF, charSpacing: 2 })", "mono(s, 'C-EDGE  ·  2024  ·  THE INDIAN CASE', { x: 0.5, y: 3.95, w: 2.2, h: 0.2, color: SAFF, charSpacing: 1.5 })")
rep("hair(s, 0.7, 4.42, 8.6, 'C-Edge line', HAIR, 1)\n  hair(s, 0.7, 4.42, 5.4, 'C-Edge span', RED, 2.25)\n  dot(s, 0.7, 4.42, 0.065, MUTE, 'C-Edge Jan', { hollow: true })\n  dot(s, 6.1, 4.42, 0.075, RED, 'C-Edge breach')\n  dot(s, 6.6, 4.42, 0.065, MUTE, 'C-Edge listed', { hollow: true })",
    "hair(s, 0.7, 4.45, 8.6, 'C-Edge line', HAIR, 1)\n  hair(s, 0.7, 4.45, 5.4, 'C-Edge span', RED, 2.25)\n  dot(s, 0.7, 4.45, 0.065, MUTE, 'C-Edge Jan', { hollow: true })\n  dot(s, 6.1, 4.45, 0.075, RED, 'C-Edge breach')\n  dot(s, 6.6, 4.45, 0.065, MUTE, 'C-Edge listed', { hollow: true })")
rep("{ text: 'Jenkins flaw disclosed; exploit public within days', options: { color: MUTE } }], { x: 0.7, y: 4.52, w: 3.4, h: 0.26,", "{ text: 'flaw disclosed; exploit public within days', options: { color: MUTE } }], { x: 0.7, y: 4.55, w: 3.2, h: 0.26,")
rep("{ text: 'ransomware through the supplier; about 300 banks lose UPI and ATM', options: { color: MUTE } }], { x: 2.3, y: 4.52, w: 3.85, h: 0.26, fontSize: 8.5, align: 'right',", "{ text: 'ransomware via the supplier; about 300 banks lose UPI and ATM', options: { color: MUTE } }], { x: 2.25, y: 4.17, w: 3.9, h: 0.26, fontSize: 8.5, align: 'right',")
rep("{ text: 'CISA lists the flaw, 19 days after the banks went down', options: { color: MUTE } }], { x: 6.72, y: 4.1, w: 2.78, h: 0.26,", "{ text: 'CISA lists the flaw, 19 days later', options: { color: MUTE } }], { x: 6.72, y: 4.55, w: 2.78, h: 0.26,")
rep("legend(s, 0.7, 4.84, [{ m: 'line', c: RED, t: 'six months of public warning, nothing connecting it to who was exposed' }", "legend(s, 0.7, 4.88, [{ m: 'line', c: RED, t: 'six months of public warning, nothing connecting it to who was exposed' }")
# the loop: shorter heads and chips
rep("['A real advisory arrives', 'CISA\\'s ICS advisory for Siemens WinCC, read by the security LLM. No CVE id needed.']", "['Advisory arrives', 'CISA\\'s ICS advisory for Siemens WinCC, read by the security LLM. No CVE id needed.']")
rep(";['a KEV entry', 'a new CVE from NVD', 'a scanning surge on the decoys', 'a partner\\'s indicator list', 'a disaster alert from SACHET'].forEach((t) => {\n    const w = 0.28 + t.length * 0.062",
    ";['a KEV entry', 'a new CVE from NVD', 'a decoy-grid surge', 'a partner\\'s indicators', 'a SACHET alert'].forEach((t) => {\n    const w = 0.3 + t.length * 0.07")
# collect: footer
rep("foot(s, 'ALSO BUNDLED, REAL: EXPLOIT-DB  ·  RANSOMWARE.LIVE  ·  HAVE I BEEN PWNED  ·  GITHUB ADVISORIES  ·  TOR  ·  SPAMHAUS DROP  ·  EMERGING THREATS', 4)", "foot(s, 'ALSO BUNDLED, REAL: EXPLOIT-DB  ·  RANSOMWARE.LIVE  ·  HAVE I BEEN PWNED  ·  GITHUB ADVISORIES  ·  TOR  ·  SPAMHAUS DROP  ·  ET', 4)")
# analyse: legend and roster
rep("legend(s, 0.5, 4.78, [{ m: 'diamond', c: BONE, t: 'threat group, ATT&CK overlap not attribution' }, { m: 'tri', c: BONE, t: 'live signal' }], { gap: 0.18 })", "legend(s, 0.5, 4.78, [{ m: 'diamond', c: BONE, t: 'threat group, overlap not attribution' }, { m: 'tri', c: BONE, t: 'live signal' }], { size: 7.5, gap: 0.14 })")
rep("legend(s, 0.5, 4.55, [{ m: 'dot', c: '276EF1', t: '' }, { m: 'dot', c: SAFF, t: '' }, { m: 'dot', c: '05A357', t: 'colour = technology family' }, { m: 'dot', c: VIOLET, t: 'compromise' }], { gap: 0.1 })", "legend(s, 0.5, 4.55, [{ m: 'dot', c: '276EF1', t: '' }, { m: 'dot', c: SAFF, t: '' }, { m: 'dot', c: '05A357', t: 'colour = technology family' }, { m: 'dot', c: VIOLET, t: 'compromise' }], { size: 7.5, gap: 0.1 })")
rep("{ x: 3.8, y: 4.14, w: 5.7, h: 0.32, fontSize: 7, color: DIM })", "{ x: 3.8, y: 4.1, w: 5.7, h: 0.32, fontSize: 6.5, color: DIM, charSpacing: 1 })")
# warn: lane-1 labels above the line, lane-2 below, the arrow in the clear
rep("mono(s, 'MEDIAN LEAD OVER CISA KEV  ·  REAL SIGNALS  ·  UP TO 42.4 DAYS', { x: 5.3, y: 1.04, w: 4.2, h: 0.2, fontSize: 7.5, align: 'right' })", "mono(s, 'MEDIAN LEAD OVER CISA KEV  ·  REAL SIGNALS  ·  UP TO 42.4', { x: 5.3, y: 1.04, w: 4.2, h: 0.2, fontSize: 7.5, align: 'right', charSpacing: 1 })")
rep("""  const lane = (label, y, bright, pts) => {
    mono(s, label, { x: 0.5, y: y - 0.33, w: 4, h: 0.2, color: bright ? BONE : MUTE, charSpacing: 2 })
    hair(s, 0.9, y, 8.2, `${label} line`, bright ? BONE : HAIR, 1)
    pts.forEach(([x, head, body, kind], i) => {
      if (kind === 'breach') dot(s, x, y, 0.08, RED, `${label} dot ${i}`)
      else if (kind === 'saff') dot(s, x, y, 0.08, SAFF, `${label} dot ${i}`)
      else if (bright) dot(s, x, y, 0.07, BONE, `${label} dot ${i}`)
      else dot(s, x, y, 0.07, MUTE, `${label} dot ${i}`, { hollow: true })
      T(s, head, { x: x - 0.95, y: y + 0.12, w: 1.9, h: 0.22, fontSize: 10, bold: true, color: kind === 'breach' ? RED : kind === 'saff' ? SAFF : BONE, align: 'center', objectName: `${label} head ${i}` })
      T(s, body, { x: x - 0.95, y: y + 0.34, w: 1.9, h: 0.42, fontSize: 8.5, color: MUTE, align: 'center', lineSpacingMultiple: 1.1, objectName: `${label} body ${i}` })
    })
  }
  lane('THEN  ·  REACT AFTER THE BREACH', 1.72, false, [""",
"""  const lane = (label, y, bright, above, pts) => {
    mono(s, label, { x: 0.5, y: above ? y - 0.86 : y - 0.36, w: 2.6, h: 0.2, color: bright ? BONE : MUTE, charSpacing: 2 })
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
  lane('THEN  ·  REACT AFTER THE BREACH', 2.0, false, true, [""")
rep("lane('NOW  ·  ACT ON THE SIGNAL', 2.98, true, [", "lane('NOW  ·  ACT ON THE SIGNAL', 3.02, true, false, [")
rep("s.addShape(pres.ShapeType.custGeom, { x: 1.7, y: 1.85, w: 4.1, h: 1.05, points: [{ x: 4.1, y: 0 }, { x: 3.6, y: 0.3 }, { x: 3.0, y: 0.55 }, { x: 2.3, y: 0.75 }, { x: 1.5, y: 0.9 }, { x: 0.7, y: 1.0 }, { x: 0.1, y: 1.05 }], fill: { type: 'none' }, line: { color: SAFF, width: 2, endArrowType: 'triangle' }, objectName: 'the decision, moved left' })",
    "s.addShape(pres.ShapeType.custGeom, { x: 1.78, y: 2.1, w: 4.02, h: 0.82, points: [{ x: 4.02, y: 0 }, { x: 3.7, y: 0.22 }, { x: 3.2, y: 0.42 }, { x: 2.5, y: 0.58 }, { x: 1.7, y: 0.7 }, { x: 0.9, y: 0.78 }, { x: 0.1, y: 0.82 }], fill: { type: 'none' }, line: { color: SAFF, width: 2, endArrowType: 'triangle' }, objectName: 'the decision, moved left' })")
rep("""    big(s, n, x, 3.85, 2.8, { size: 38, h: 0.58 })
    T(s, l, { x, y: 4.45, w: 2.8, h: 0.45, fontSize: 8.5, color: MUTE, lineSpacingMultiple: 1.1, objectName: `${n} label` })""",
"""    big(s, n, x, 3.9, 2.8, { size: 34, h: 0.52 })
    T(s, l, { x, y: 4.44, w: 2.8, h: 0.45, fontSize: 8.5, color: MUTE, lineSpacingMultiple: 1.1, objectName: `${n} label` })""")
rep("legend(s, 0.5, 4.96, [{ m: 'ring', c: MUTE, t: 'reactive step' }", "legend(s, 0.5, 4.98, [{ m: 'ring', c: MUTE, t: 'reactive step' }")
# prioritise: receipt header and verdict
rep("mono(s, 'ONE REAL WARNING  ·  TAPTI THERMAL  ·  IVANTI CS 22.8R2.4  ·  CVE-2026-111357', { x: 5.48, y: 2.6, w: 3.9, h: 0.2, fontSize: 7, color: INKMUTE })", "mono(s, 'ONE REAL WARNING  ·  TAPTI THERMAL  ·  IVANTI CS 22.8R2.4', { x: 5.48, y: 2.6, w: 3.9, h: 0.2, fontSize: 7, color: INKMUTE, charSpacing: 1 })")
rep("T(s, 'Critical · SSVC: Act · 12 h to patch or mitigate · P(compromise) 18%', { x: 5.48, y: 4.74, w: 2.9, h: 0.26,", "T(s, 'Critical · Act · 12 h to patch or mitigate · P(compromise) 18%', { x: 5.48, y: 4.74, w: 2.6, h: 0.26,")
# recommend: labels that fit
rep("mono(s, 'NATIONALLY  ·  THE RISK PLAN', { x: 4.75, y: 1.3, w: 2.7, h: 0.2, charSpacing: 2 })", "mono(s, 'THE RISK PLAN', { x: 4.75, y: 1.3, w: 1.6, h: 0.2, charSpacing: 2 })")
rep("mono(s, '344 TICKETS', { x: cx0 + cw - 0.9, y: cy0 + 0.02, w: 0.9, h: 0.18, fontSize: 7, align: 'right' })", "mono(s, '344 TICKETS IN ALL', { x: cx0 + cw - 1.3, y: cy0 - 0.2, w: 1.3, h: 0.18, fontSize: 7, align: 'right' })")
rep("mono(s, 'BY WHEN  ·  CERT-IN BLUEPRINT', { x: 7.75, y: 1.3, w: 1.75, h: 0.2, charSpacing: 2 })", "mono(s, 'BY WHEN  ·  CERT-IN', { x: 7.75, y: 1.3, w: 1.75, h: 0.2, charSpacing: 2 })")
rep("['12 h', 'known-exploited, internet-facing', 12, SAFF]", "['12 h', 'known-exploited, internet', 12, SAFF]")
rep("{ m: 'none', t: 'one workflow per warning: issued → acknowledged → mitigating → verifying → closed; the countdown runs in real time on the warning' }", "{ m: 'none', t: 'one workflow per warning: issued → acknowledged → mitigating → verifying → closed' }")
# show: two short legend rows per figure, unspaced captions
rep("""    ['now-hero.png', 'FIG 9A  ·  NOW  ·  WHAT NEEDS ME', [{ m: 'dot', c: RED, t: 'chip = suspected compromise' }, { m: 'none', t: 'clock = CERT-In deadline · black button = the one action' }]],
    ['threats-heat.png', 'FIG 9B  ·  INTEL  ·  WHAT IS UNDER ATTACK', [{ m: 'rect', c: 'DBE6FB', t: '' }, { m: 'rect', c: '276EF1', t: 'cell = attacks on a port that day, quiet → busy' }, { m: 'none', t: 'DShield, REAL' }]],
    ['graph-c.png', 'FIG 9C  ·  INTEL  ·  THE GRAPH', [{ m: 'dot', c: '276EF1', t: 'colour = technology family' }, { m: 'dot', c: VIOLET, t: 'compromise' }, { m: 'diamond', c: BONE, t: 'threat group' }, { m: 'tri', c: BONE, t: 'signal' }]],
    ['map-world-c.png', 'FIG 9D  ·  NOW  ·  WHERE ATTACKS START', [{ m: 'dot', c: RED, t: 'attack source, REAL' }, { m: 'ring', c: BONE, t: 'C2, REAL' }, { m: 'dot', c: MUTE, t: 'operator, SIM' }, { m: 'dot', c: VIOLET, t: 'compromise' }]],
    ['map-india-c.png', 'FIG 9E  ·  INDIA BY WARNINGS', [{ m: 'dot', c: 'C9834F', t: '' }, { m: 'dot', c: RED, t: 'Critical warnings per state, few → many' }, { m: 'dot', c: VIOLET, t: 'compromise' }, { m: 'none', t: 'operators SIM' }]],
    ['site-c.png', 'FIG 9F  ·  A STATE, IN 3D', [{ m: 'rect', c: MUTE, t: 'agency site, SIM' }, { m: 'arrow', c: RED, t: 'attack from a real origin' }]],""",
"""    ['now-hero.png', 'FIG 9A  ·  NOW  ·  WHAT NEEDS ME', [[{ m: 'dot', c: RED, t: 'chip = compromise' }, { m: 'none', t: 'clock = CERT-In deadline' }], [{ m: 'none', t: 'black button = the one action · operators SIM, CVEs REAL' }]]],
    ['threats-heat.png', 'FIG 9B  ·  INTEL  ·  WHAT IS UNDER ATTACK', [[{ m: 'rect', c: 'DBE6FB', t: '' }, { m: 'rect', c: '276EF1', t: 'cell = attacks on a port that day, quiet → busy' }], [{ m: 'none', t: 'DShield, REAL · rows = the services operators expose' }]]],
    ['graph-c.png', 'FIG 9C  ·  INTEL  ·  THE GRAPH', [[{ m: 'dot', c: '276EF1', t: 'colour = technology family' }, { m: 'dot', c: VIOLET, t: 'compromise' }], [{ m: 'diamond', c: BONE, t: 'threat group, overlap not attribution' }, { m: 'tri', c: BONE, t: 'live signal' }]]],
    ['map-world-c.png', 'FIG 9D  ·  NOW  ·  WHERE ATTACKS START', [[{ m: 'dot', c: RED, t: 'attack source, REAL' }, { m: 'ring', c: BONE, t: 'botnet C2, REAL' }], [{ m: 'dot', c: MUTE, t: 'operator state, SIM' }, { m: 'dot', c: VIOLET, t: 'compromise' }]]],
    ['map-india-c.png', 'FIG 9E  ·  INDIA BY WARNINGS', [[{ m: 'dot', c: 'C9834F', t: '' }, { m: 'dot', c: RED, t: 'Critical warnings per state, few → many' }], [{ m: 'dot', c: VIOLET, t: 'compromise' }, { m: 'none', t: 'operators SIM, warnings from REAL CVEs' }]]],
    ['site-c.png', 'FIG 9F  ·  A STATE, IN 3D', [[{ m: 'rect', c: MUTE, t: 'agency site, SIM' }, { m: 'arrow', c: RED, t: 'attack from a real origin' }], [{ m: 'none', t: 'origins REAL · buildings SIM' }]]],""")
rep("""    mono(s, cap, { x, y: y + 1.35, w: 2.9, h: 0.18, fontSize: 7, color: SAFF })
    const row1 = leg.slice(0, 2), row2 = leg.slice(2)
    legend(s, x, y + 1.53, row1, { size: 7, gap: 0.12 })
    if (row2.length) legend(s, x, y + 1.7, row2, { size: 7, gap: 0.12 })""",
"""    mono(s, cap, { x, y: y + 1.35, w: 2.9, h: 0.18, fontSize: 7, color: SAFF, charSpacing: 1 })
    legend(s, x, y + 1.53, leg[0], { size: 7, gap: 0.12 })
    legend(s, x, y + 1.7, leg[1], { size: 7, gap: 0.12 })""")
rep("foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  REAL OR SIM ON EVERY PANEL  ·  FEEDS BUNDLED, NOTHING WAITS ON THE NETWORK  ·  A NIGHT-SHIFT MODE FOR THE ROOM', 9)", "foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  REAL OR SIM ON EVERY PANEL  ·  FEEDS BUNDLED, NOTHING WAITS ON THE NETWORK', 9)")
# explain: shorter numeral labels
rep("['0', 'cloud or internet AI calls, ever; the feeds are snapshot-backed', SAFF, 1.5], ['1', 'laptop: an RTX 4070 with 8 GB; every model under 8B parameters', BONE, 1.9]", "['0', 'cloud or internet AI calls, ever', SAFF, 1.5], ['1', 'laptop, an RTX 4070 with 8 GB; every model under 8B', BONE, 1.9]")
open(p, 'w', encoding='utf-8', newline='\n').write(s); print('patched', n0, '->', len(s))
