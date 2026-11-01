"""Specimen plates for the deck: a chakra radar ring, dot fields, a sweep. Rendered at 2x with supersampling."""
import math, random
from PIL import Image, ImageDraw
OUT = r"C:/Users/swaya/AppData/Local/Temp/claude/d--d3coy--hackathon/9122ef18-2e15-4ea7-b361-4333d0a93d39/scratchpad/deck/img/plates/"
WHITE = (12, 12, 14); GREY = (214, 209, 198); DIM = (214, 209, 198); RED = (225, 25, 0)

def chakra(size=1600, ss=3):
    S = size * ss; im = Image.new("RGBA", (S, S), (0, 0, 0, 0)); d = ImageDraw.Draw(im)
    c = S / 2; R = 0.475 * S
    # the sweep: 90 wedges fading from red to nothing, clockwise behind the rings
    for i in range(90):
        a0 = -90 + i * 0.8; a1 = a0 + 0.9
        alpha = int(150 * (1 - i / 90) ** 1.6)
        d.pieslice([c - R * 0.985, c - R * 0.985, c + R * 0.985, c + R * 0.985], a0 - 72, a1 - 72, fill=(225, 25, 0, alpha))
    # rings
    for r, w, a in ((R, 7, 190), (R * 0.79, 3, 90), (R * 0.58, 3, 80), (R * 0.37, 3, 70), (R * 0.16, 4, 140)):
        d.ellipse([c - r, c - r, c + r, c + r], outline=(245, 245, 245, a), width=w * ss)
    # 24 spokes
    for k in range(24):
        a = math.radians(k * 15 - 90)
        x0, y0 = c + R * 0.17 * math.cos(a), c + R * 0.17 * math.sin(a)
        x1, y1 = c + R * 0.975 * math.cos(a), c + R * 0.975 * math.sin(a)
        d.line([x0, y0, x1, y1], fill=(245, 245, 245, 110), width=3 * ss)
    # 72 ticks on the rim, every fifth longer
    for k in range(72):
        a = math.radians(k * 5 - 90); L = R * (0.06 if k % 6 == 0 else 0.03)
        x0, y0 = c + (R - L) * math.cos(a), c + (R - L) * math.sin(a)
        x1, y1 = c + R * 0.995 * math.cos(a), c + R * 0.995 * math.sin(a)
        d.line([x0, y0, x1, y1], fill=(245, 245, 245, 200), width=(4 if k % 6 == 0 else 2) * ss)
    # hub
    r = R * 0.055; d.ellipse([c - r, c - r, c + r, c + r], fill=(225, 25, 0, 255))
    r2 = R * 0.085; d.ellipse([c - r2, c - r2, c + r2, c + r2], outline=(245, 245, 245, 220), width=3 * ss)
    im = im.resize((size, size), Image.LANCZOS); im.save(OUT + "chakra.png"); print("chakra", im.size)

def dots(name, cols, rows, count, lit, lit_color, cell=40, r=11, ss=3, red=0, order="random", seed=7):
    W, H = cols * cell, rows * cell
    im = Image.new("RGBA", (W * ss, H * ss), (0, 0, 0, 0)); d = ImageDraw.Draw(im)
    idx = list(range(count))
    rnd = random.Random(seed)
    if order == "random":
        pick = rnd.sample(idx, lit + red); lit_set = set(pick[:lit]); red_set = set(pick[lit:])
    else:
        lit_set = set(idx[:lit]); red_set = set(idx[lit:lit + red])
    for i in idx:
        x = (i % cols) * cell + cell / 2; y = (i // cols) * cell + cell / 2
        col = lit_color if i in lit_set else (RED if i in red_set else GREY)
        rr = r * (1.25 if (i in lit_set or i in red_set) else 1)
        d.ellipse([(x - rr) * ss, (y - rr) * ss, (x + rr) * ss, (y + rr) * ss], fill=col + (255,))
    im = im.resize((W, H), Image.LANCZOS); im.save(OUT + name); print(name, im.size)

# the funnel: 1 dot = 100 CVEs. 821 of them; 23 name an operator's product (white); 4 are Critical warnings (red)
dots("funnel_light.png", 29, 29, 821, 23, WHITE, red=4, cell=40, r=10)
# 72 of 100 labelled, then 21 of 100
dots("dots72_light.png", 10, 10, 100, 72, WHITE, cell=52, r=15, order="fill")
dots("dots21_light.png", 10, 10, 100, 21, WHITE, cell=52, r=15, order="fill")
# 29 of 100 attacked on or before day 0, in red
dots("dots29_light.png", 10, 10, 100, 0, WHITE, cell=52, r=15, red=29, order="fill")
# a long, thin tick strip: 110 real exploited CVEs; 56 would be flagged by EPSS alone (51%), 52 by CVSS (47%), 110 by rules
def strip(name, n, lit, color, cell=28):
    im = Image.new("RGBA", (n * cell * 3, 60 * 3), (0, 0, 0, 0)); d = ImageDraw.Draw(im)
    for i in range(n):
        x = i * cell + cell / 2; col = color if i < lit else DIM
        d.rounded_rectangle([(x - 8) * 3, 6 * 3, (x + 8) * 3, 54 * 3], radius=9, fill=col + (255,))
    im = im.resize((n * cell, 60), Image.LANCZOS); im.save(OUT + name); print(name, im.size)
