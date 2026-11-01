#!/usr/bin/env bash
# build the deck, validate, convert to PDF with LibreOffice, render every page to qa-NN.png
set -e
cd "$(dirname "$0")"
export PPTX_SKILL="C:/Users/swaya/.claude/skills/synced/eecf8b7f-cbb3-4da8-92a1-45b413afe457_99f417d6-3507-456f-9f1a-9428dc374a93/pptx"
export NODE_PATH="$PWD/node_modules"
node build.js "$PWD/Odyssey_final.pptx" 2>&1 | tail -3
python "$PPTX_SKILL/scripts/office/validate.py" Odyssey_final.pptx 2>&1 | tail -1
rm -f Odyssey_final.pdf
"/c/Program Files/LibreOffice/program/soffice.exe" --headless --norestore --convert-to pdf --outdir "$PWD" "$PWD/Odyssey_final.pptx" >/dev/null 2>&1 || true
for i in $(seq 1 90); do [ -f Odyssey_final.pdf ] && break; sleep 1; done
ls -la Odyssey_final.pdf
rm -f qa-*.png
python -c "
import pymupdf
d = pymupdf.open('Odyssey_final.pdf')
for i, p in enumerate(d): p.get_pixmap(dpi=110).save(f'qa-{i+1:02d}.png')
print(len(d), 'pages rendered')"
