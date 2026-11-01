"""Render odyssey-one.pdf to PNGs and a contact sheet. Usage: python render_one.py [pdf] [prefix]"""
import sys, glob, os
import pymupdf
from PIL import Image
pdf = sys.argv[1] if len(sys.argv) > 1 else 'odyssey-one.pdf'
prefix = sys.argv[2] if len(sys.argv) > 2 else 'one'
for f in glob.glob(f'{prefix}-*.png'): os.remove(f)
doc = pymupdf.open(pdf); files = []
for i, page in enumerate(doc):
    f = f'{prefix}-{i+1:02d}.png'; page.get_pixmap(dpi=120).save(f); files.append(f)
W, H = 960, 540
sheet = Image.new('RGB', (W * 2 + 30, (H + 10) * ((len(files) + 1) // 2) + 10), (34, 34, 34))
for i, f in enumerate(files):
    im = Image.open(f).resize((W, H), Image.LANCZOS); sheet.paste(im, (10 + (i % 2) * (W + 10), 10 + (i // 2) * (H + 10)))
sheet.save(f'{prefix}-sheet.png'); print('pages', len(doc))
