# Final deck, artifact edition

The ten slides as published to the claude.ai Slides artifact (https://claude.ai/artifact/9tcQLSrCVaroPX1ocrATRC): one
`slides/<id>.html` per slide in the artifact's slide format (a 1920x1080 section, inline styles), the `deck.json` index
(order, sections, typefaces), the design philosophy the look grew from (`DESIGN_PHILOSOPHY.md`, "Sovereign Signal"), now carried across four
backgrounds (ink black, bone white, deep navy, saffron) with Fraunces for titles, Big Shoulders for numerals, Space
Grotesk for text and JetBrains Mono for markers,
and the specimen plates (`plates/`, rendered by `plates.py` with Pillow: the chakra radar ring, the dot fields, the tick
strips). Image references in the slides (`/_blob/...`) point at the artifact's asset store: the console screenshots and
these plates. The PowerPoint in `../Odyssey_final.pptx` is the offline fallback and carries the same content.

Every plate carries its legend on the slide: what a dot, a colour, a ring or a tick means, and whether the source is
REAL or SIM.

`preview.py` renders the slide files locally with Playwright (`python preview.py slides out/`; `blobs.json` maps the
artifact's image ids to the files in the scratchpad) and writes a contact sheet; `contact-sheet.png` is the last one.
