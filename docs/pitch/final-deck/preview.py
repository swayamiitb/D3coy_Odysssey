"""Render the artifact slide files locally, so arrangement can be checked before publishing.
Usage: python preview.py <slides_dir> <out_dir>   (writes slide-<id>.png and sheet.png)"""
import json, re, sys
from pathlib import Path
from playwright.sync_api import sync_playwright
from PIL import Image

SL = Path(sys.argv[1]); OUT = Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)
IMG = Path(r"C:/Users/swaya/AppData/Local/Temp/claude/d--d3coy--hackathon/9122ef18-2e15-4ea7-b361-4333d0a93d39/scratchpad/deck/img")
FONT = Path(r"C:/Users/swaya/.claude/skills/synced/eecf8b7f-cbb3-4da8-92a1-45b413afe457_99f417d6-3507-456f-9f1a-9428dc374a93/canvas-design/canvas-fonts")
BLOBS = json.loads((Path(__file__).parent / "blobs.json").read_text())   # id -> relative path under img/ (or an absolute path)
order = json.loads((SL.parent / "deck.json").read_text(encoding="utf-8"))["order"]

CSS = """
*{box-sizing:border-box} html,body{margin:0;background:#222}
section{position:relative;width:1920px;height:1080px;overflow:hidden;display:block}
h1,h2,h3,p,ul,ol{margin:0} h1{font-size:96px;font-weight:600;line-height:1.1} h2{font-size:64px;font-weight:600;line-height:1.15}
h3{font-size:44px;font-weight:600;line-height:1.2} p,li{font-size:32px;line-height:1.4} img{display:block}
x-shape{display:block;flex:none} x-shape[kind=ellipse]{border-radius:50%} x-shape[kind=diamond]{transform:rotate(45deg)}
x-shape[kind=arrow-right]{clip-path:polygon(0 30%,60% 30%,60% 0,100% 50%,60% 100%,60% 70%,0 70%)}
x-shape[kind=arrow-left]{clip-path:polygon(100% 30%,40% 30%,40% 0,0 50%,40% 100%,40% 70%,100% 70%)}
x-shape[kind=arrow-up]{clip-path:polygon(50% 0,100% 100%,0 100%)} x-shape[kind=rounded]{border-radius:8px}
aside{display:none} svg{display:block}
section > *:not([style*="position:absolute"]){position:relative}
"""
def blob(m):
    p = BLOBS.get(m.group(1))
    if not p: return m.group(0)
    p = Path(p) if Path(p).is_absolute() else IMG / p
    return "file:///" + str(p).replace("\\", "/")

with sync_playwright() as pw:
    b = pw.chromium.launch(headless=True, channel="msedge")
    pg = b.new_page(viewport={"width": 1920, "height": 1080})
    files = []
    for sid in order:
        html = (SL / f"{sid}.html").read_text(encoding="utf-8")
        html = re.sub(r"/_blob/([0-9a-f]{32})", blob, html)
        doc = f"""<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400..700&family=JetBrains+Mono:wght@400;700&family=Inter+Tight:wght@500..800&family=Inter:wght@400..700&family=Space+Grotesk:wght@400..700&family=Fraunces:opsz,wght@9..144,400..900&family=Archivo+Black&family=Bricolage+Grotesque:opsz,wght@12..96,400..800&display=swap">
<style>@font-face{{font-family:'Big Shoulders';src:url('file:///{str(FONT / 'BigShoulders-Bold.ttf').replace(chr(92), '/')}')}}{CSS}</style></head><body>{html}</body></html>"""
        tmp = OUT / f"_{sid}.html"; tmp.write_text(doc, encoding="utf-8"); pg.goto("file:///" + str(tmp).replace(chr(92), "/"), wait_until="load"); pg.wait_for_timeout(1200)
        f = OUT / f"slide-{sid}.png"; pg.locator("section").first.screenshot(path=str(f)); files.append(f)
    b.close()
# contact sheet: 2 columns
W, H = 960, 540
sheet = Image.new("RGB", (W * 2 + 30, (H + 10) * ((len(files) + 1) // 2) + 10), (34, 34, 34))
for i, f in enumerate(files):
    im = Image.open(f).resize((W, H), Image.LANCZOS)
    sheet.paste(im, (10 + (i % 2) * (W + 10), 10 + (i // 2) * (H + 10)))
sheet.save(OUT / "sheet.png"); print("rendered", len(files), "slides ->", OUT / "sheet.png")
