import sys
p = sys.argv[1]; s = open(p, encoding='utf-8').read(); n0 = len(s)
def rep(a, b):
    global s
    assert s.count(a) == 1, 'not found once: ' + a[:90]
    s = s.replace(a, b)
# problem: a deliberate two-line title, everything below shifted down and untangled
rep("{ text: 'late.', options: { italic: true, color: SAFF } }], { placeholder: 'title', fontSize: 24 })",
    "{ text: 'late.', options: { italic: true, color: SAFF } }], { placeholder: 'title', h: 0.95, lineSpacingMultiple: 0.95 })")
rep("s.addText([{ text: 'The warning was public. The decision was ' }, { text: 'late.'", "s.addText([{ text: 'The warning was public.', options: { breakLine: true } }, { text: 'The decision was ' }, { text: 'late.'")
rep("big(s, '16,730', 0.5, 1.25, 4.3, { size: 112, h: 1.55, cs: -2 })", "big(s, '16,730', 0.5, 1.6, 4.3, { size: 100, h: 1.4, cs: -2 })")
rep("{ x: 0.5, y: 2.88, w: 4.0, h: 0.6, fontSize: 10.5, color: MUTE, lineSpacingMultiple: 1.15, objectName: '16730 caption' }", "{ x: 0.5, y: 3.06, w: 4.0, h: 0.6, fontSize: 10.5, color: MUTE, lineSpacingMultiple: 1.15, objectName: '16730 caption' }")
rep("vhair(s, 4.85, 1.35, 2.5, 'problem divider')", "vhair(s, 4.85, 1.65, 2.3, 'problem divider')")
rep("x: 5.1, y: 1.3, w: 0.9, h: 0.9, objectName: 'A hundred dots, 72 lit' })", "x: 5.1, y: 1.6, w: 0.9, h: 0.9, objectName: 'A hundred dots, 72 lit' })")
rep("{ x: 6.06, y: 1.67, w: 0.28, h: 0.15, fill: { color: SAFF }", "{ x: 6.06, y: 1.97, w: 0.28, h: 0.15, fill: { color: SAFF }")
rep("x: 6.4, y: 1.3, w: 0.9, h: 0.9, objectName: 'A hundred dots, 21 lit' })", "x: 6.4, y: 1.6, w: 0.9, h: 0.9, objectName: 'A hundred dots, 21 lit' })")
rep("big(s, '72% → 21%', 7.45, 1.25, 2.05, { size: 32, h: 0.52 })", "big(s, '72% → 21%', 7.45, 1.55, 2.05, { size: 32, h: 0.52 })")
rep("{ x: 7.45, y: 1.8, w: 2.05, h: 0.5, fontSize: 8.5, color: MUTE, objectName: 'labels caption' }", "{ x: 7.45, y: 2.1, w: 2.05, h: 0.5, fontSize: 8.5, color: MUTE, objectName: 'labels caption' }")
rep("x: 5.1, y: 2.42, w: 0.9, h: 0.9, objectName: 'A hundred dots, 29 red' })", "x: 5.1, y: 2.66, w: 0.9, h: 0.9, objectName: 'A hundred dots, 29 red' })")
rep("big(s, '29%', 6.15, 2.37, 1.4, { size: 32, h: 0.52, color: RED })", "big(s, '29%', 6.15, 2.61, 1.4, { size: 32, h: 0.52, color: RED })")
rep("{ x: 6.15, y: 2.92, w: 3.35, h: 0.42, fontSize: 8.5, color: MUTE, objectName: 'day zero caption' }", "{ x: 6.15, y: 3.16, w: 3.35, h: 0.42, fontSize: 8.5, color: MUTE, objectName: 'day zero caption' }")
rep("legend(s, 5.1, 3.62, [{ m: 'dot', c: HAIR, t: 'one of 100 CVEs' }", "legend(s, 5.1, 3.72, [{ m: 'dot', c: HAIR, t: 'one of 100 CVEs' }")
rep("mono(s, 'REAL  ·  CVE PROGRAM  ·  NVD  ·  CISA KEV', { x: 5.1, y: 3.86, w: 4.4, h: 0.2, fontSize: 7.5 })", "mono(s, 'REAL  ·  CVE PROGRAM  ·  NVD  ·  CISA KEV', { x: 5.1, y: 3.94, w: 4.4, h: 0.2, fontSize: 7.5 })")
rep("mono(s, 'C-EDGE  ·  2024  ·  THE INDIAN CASE', { x: 0.5, y: 3.95, w: 2.2, h: 0.2, color: SAFF, charSpacing: 1.5 })", "mono(s, 'C-EDGE  ·  2024  ·  THE INDIAN CASE', { x: 6.5, y: 4.2, w: 3.0, h: 0.2, color: SAFF, charSpacing: 1.5, align: 'right' })")
rep("hair(s, 0.7, 4.45, 8.6, 'C-Edge line', HAIR, 1)\n  hair(s, 0.7, 4.45, 5.4, 'C-Edge span', RED, 2.25)\n  dot(s, 0.7, 4.45, 0.065, MUTE, 'C-Edge Jan', { hollow: true })\n  dot(s, 6.1, 4.45, 0.075, RED, 'C-Edge breach')\n  dot(s, 6.6, 4.45, 0.065, MUTE, 'C-Edge listed', { hollow: true })",
    "hair(s, 0.7, 4.5, 8.6, 'C-Edge line', HAIR, 1)\n  hair(s, 0.7, 4.5, 5.4, 'C-Edge span', RED, 2.25)\n  dot(s, 0.7, 4.5, 0.065, MUTE, 'C-Edge Jan', { hollow: true })\n  dot(s, 6.1, 4.5, 0.075, RED, 'C-Edge breach')\n  dot(s, 6.6, 4.5, 0.065, MUTE, 'C-Edge listed', { hollow: true })")
rep("{ text: 'flaw disclosed; exploit public within days', options: { color: MUTE } }], { x: 0.7, y: 4.55, w: 3.2, h: 0.26,", "{ text: 'Jenkins flaw disclosed; exploit public within days', options: { color: MUTE } }], { x: 0.7, y: 4.6, w: 3.6, h: 0.26,")
rep("{ text: 'ransomware via the supplier; about 300 banks lose UPI and ATM', options: { color: MUTE } }], { x: 2.25, y: 4.17, w: 3.9, h: 0.26, fontSize: 8.5, align: 'right',", "{ text: 'ransomware via the supplier; about 300 banks lose UPI and ATM', options: { color: MUTE } }], { x: 1.6, y: 4.2, w: 4.55, h: 0.26, fontSize: 8.5, align: 'right',")
rep("{ text: 'CISA lists the flaw, 19 days later', options: { color: MUTE } }], { x: 6.72, y: 4.55, w: 2.78, h: 0.26,", "{ text: 'CISA lists the flaw, 19 days later', options: { color: MUTE } }], { x: 6.72, y: 4.6, w: 2.78, h: 0.26,")
rep("legend(s, 0.7, 4.88, [{ m: 'line', c: RED, t: 'six months of public warning, nothing connecting it to who was exposed' }", "legend(s, 0.7, 4.92, [{ m: 'line', c: RED, t: 'six months of public warning, nothing connecting it to who was exposed' }")
# collect: footer
rep("foot(s, 'ALSO BUNDLED, REAL: EXPLOIT-DB  ·  RANSOMWARE.LIVE  ·  HAVE I BEEN PWNED  ·  GITHUB ADVISORIES  ·  TOR  ·  SPAMHAUS DROP  ·  ET', 4)", "foot(s, 'ALSO BUNDLED, REAL: EXPLOIT-DB  ·  RANSOMWARE.LIVE  ·  HIBP  ·  GITHUB ADVISORIES  ·  TOR  ·  SPAMHAUS DROP  ·  EMERGING THREATS', 4)")
# analyse: a caption that fits
rep("mono(s, 'INTEL › GRAPH  ·  115 NODES  ·  447 LINKS  ·  146 FROM PUBLIC DATA', { x: 0.5, y: 4.32, w: 3.2, h: 0.2, fontSize: 7.5 })", "mono(s, 'INTEL › GRAPH  ·  115 NODES  ·  447 LINKS', { x: 0.5, y: 4.32, w: 3.2, h: 0.2, fontSize: 7.5 })")
# warn: lane label width
rep("mono(s, label, { x: 0.5, y: above ? y - 0.86 : y - 0.36, w: 2.6, h: 0.2, color: bright ? BONE : MUTE, charSpacing: 2 })", "mono(s, label, { x: 0.5, y: above ? y - 0.86 : y - 0.36, w: 3.4, h: 0.2, color: bright ? BONE : MUTE, charSpacing: 2 })")
# prioritise: verdict on one line
rep("T(s, 'Critical · Act · 12 h to patch or mitigate · P(compromise) 18%', { x: 5.48, y: 4.74, w: 2.6, h: 0.26,", "T(s, 'Critical · Act · 12 h to patch · P(compromise) 18%', { x: 5.48, y: 4.74, w: 2.6, h: 0.26,")
# show: shorter images, shorter legends, a wider advance after the arrow marker
rep("      else if (m === 'arrow') slide.addShape(pres.ShapeType.rightArrow, { x: cx - 0.03, y: my + 0.015, w: ms + 0.1, h: ms - 0.03, fill: { color: mc }, line: { color: mc, width: 0 }, objectName: `legend ${i} marker` })\n      cx += ms + 0.07",
    "      else if (m === 'arrow') slide.addShape(pres.ShapeType.rightArrow, { x: cx - 0.03, y: my + 0.015, w: ms + 0.1, h: ms - 0.03, fill: { color: mc }, line: { color: mc, width: 0 }, objectName: `legend ${i} marker` })\n      cx += ms + 0.07 + (m === 'arrow' ? 0.1 : 0)")
rep("[{ m: 'none', t: 'black button = the one action · operators SIM, CVEs REAL' }]", "[{ m: 'none', t: 'black button = the one action · operators SIM' }]")
rep("[{ m: 'diamond', c: BONE, t: 'threat group, overlap not attribution' }, { m: 'tri', c: BONE, t: 'live signal' }]]],", "[{ m: 'diamond', c: BONE, t: 'threat group (overlap)' }, { m: 'tri', c: BONE, t: 'live signal' }]]],")
rep("""    const x = 0.5 + (i % 3) * 3.05, y = 1.3 + Math.floor(i / 3) * 1.9
    shot(s, file, x, y, 2.9, 1.3, cap)
    mono(s, cap, { x, y: y + 1.35, w: 2.9, h: 0.18, fontSize: 7, color: SAFF, charSpacing: 1 })
    legend(s, x, y + 1.53, leg[0], { size: 7, gap: 0.12 })
    legend(s, x, y + 1.7, leg[1], { size: 7, gap: 0.12 })""",
"""    const x = 0.5 + (i % 3) * 3.05, y = 1.3 + Math.floor(i / 3) * 1.9
    shot(s, file, x, y, 2.9, 1.25, cap)
    mono(s, cap, { x, y: y + 1.3, w: 2.9, h: 0.18, fontSize: 7, color: SAFF, charSpacing: 1 })
    legend(s, x, y + 1.47, leg[0], { size: 7, gap: 0.12 })
    legend(s, x, y + 1.64, leg[1], { size: 7, gap: 0.12 })""")
open(p, 'w', encoding='utf-8', newline='\n').write(s); print('patched', n0, '->', len(s))
