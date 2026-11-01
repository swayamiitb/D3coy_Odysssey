# Odyssey_FINAL_ONE.pptx, how it is built

The one deck to present: `docs/pitch/Odyssey_FINAL_ONE.pptx` (PDF beside it). Ten slides, one theme throughout: deep
navy, bone text, saffron as the only accent, red kept for threat; bone cards where a decision is made (the warning
receipt, the rule card). The best page of each earlier version, redrawn: the cover and dot plates from the artifact
edition, the C-Edge timeline and the deadline dials from v2, the five-station loop, the manifest, the two-lane
timeline with the saffron arrow, the score tiles and receipt, the burn-down curve, six figures with legends, the
native backtest chart. Every plate, chart and map carries its legend and says REAL or SIM.

Fonts are the demo laptop's own (Windows): Georgia for titles, Bahnschrift SemiBold Condensed for numerals, Segoe UI
for text, Consolas for markers. On a Mac they substitute; present from the Windows laptop or use the PDF.

Rebuild: `NODE_PATH=<folder with pptxgenjs> node build_one.js Odyssey_FINAL_ONE.pptx` from a folder that holds `img/`
(the console screenshots and `img/plates/`, rendered by `plates_navy.py`). The three `patch_one*.py` files are the
layout fixes applied after the first render, already folded into `build_one.js`; `render_one.py` renders the PDF to
PNGs and a contact sheet (`contact-sheet.png` is the final one).
