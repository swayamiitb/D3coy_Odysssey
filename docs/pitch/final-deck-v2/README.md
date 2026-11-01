# Final deck, PowerPoint edition (v2)

`docs/pitch/Odyssey_final_v2.pptx` (and the PDF beside it): ten slides on the problem statement's spine, in the
"Signal Cartography" register described in `PHILOSOPHY.md`. Four grounds alternate: ink black (cover, analysis,
close), paper white (problem, sources, score, screens), deep navy (timeline, action) and one saffron statement slide
(the use case). Every figure carries its key; red is used only on data; the settled card on each slide is the inverse
of its ground. All text is native (Arial, Consolas for the receipt and markers); the art is geometry rasterised with
sharp; the screenshots in `shots/` are the console's own.

Rebuild: `npm install pptxgenjs@3.12.0 sharp@0.33.5` next to `build.js`, set `PPTX_SKILL` to the pptx skill folder
(for `apply_theme.js`) and `NODE_PATH` to that `node_modules`, then `bash render.sh` (LibreOffice renders the PDF
and PyMuPDF the QA pages).
