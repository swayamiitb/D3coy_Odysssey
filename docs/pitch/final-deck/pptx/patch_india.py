import sys
p = sys.argv[1]; s = open(p, encoding='utf-8').read()
def rep(a, b):
    global s
    assert s.count(a) == 1, 'not found once: ' + a[:80]
    s = s.replace(a, b)
rep("legend(s, 1.5, 2.32, [{ m: 'rect', c: G.CARD, t: '× multiplies the whole score' }, { m: 'rect', c: G.PANEL, t: '% is a weight inside the bracket; the three sum to 100%' }], { size: 7.5, gap: 0.18 })",
    "legend(s, 1.5, 2.32, [{ m: 'ring', c: G.TXT, t: 'white tile, ×: multiplies the whole score' }, { m: 'rect', c: G.PANEL, t: 'black tile, %: a weight inside the bracket; the three sum to 100%' }], { size: 7.5, gap: 0.18 })")
rep("foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  DJS ISACA  ·  PS-01  ·  GREEN = REAL AND PUBLIC  ·  GREY = SIMULATED  ·  SAFFRON = MEASURED ON THE WIRE', 10)",
    "foot(s, 'ODYSSEY  ·  D3COY 1.0  ·  DJS ISACA  ·  PS-01', 10)")
open(p, 'w', encoding='utf-8', newline='\n').write(s); print('patched')
