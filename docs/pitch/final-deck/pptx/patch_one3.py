import sys
p = sys.argv[1]; s = open(p, encoding='utf-8').read(); n0 = len(s)
def rep(a, b):
    global s
    assert s.count(a) == 1, 'not found once: ' + a[:90]
    s = s.replace(a, b)
rep("foot(s, 'ALSO BUNDLED, REAL: EXPLOIT-DB  ·  RANSOMWARE.LIVE  ·  HIBP  ·  GITHUB ADVISORIES  ·  TOR  ·  SPAMHAUS DROP  ·  EMERGING THREATS', 4)", "foot(s, 'ALSO BUNDLED, REAL: EXPLOIT-DB  ·  RANSOMWARE.LIVE  ·  HAVE I BEEN PWNED  ·  GITHUB ADVISORIES  ·  TOR  ·  SPAMHAUS  ·  ET', 4)")
rep("mono(s, 'CRITICAL WARNINGS  ·  NAMED OPERATORS', { x: 6.9, y: 4.06, w: 2.6, h: 0.2 })", "mono(s, 'CRITICAL, EACH TO A NAMED OPERATOR', { x: 6.9, y: 4.06, w: 2.6, h: 0.2, charSpacing: 1 })")
rep("mono(s, '344 TICKETS IN ALL', { x: cx0 + cw - 1.3, y: cy0 - 0.2, w: 1.3, h: 0.18, fontSize: 7, align: 'right' })", "mono(s, '344 TICKETS IN ALL', { x: cx0 + cw - 1.7, y: cy0 - 0.2, w: 1.7, h: 0.18, fontSize: 7, align: 'right' })")
open(p, 'w', encoding='utf-8', newline='\n').write(s); print('patched', n0, '->', len(s))
