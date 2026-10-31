# Design System — Odyssey SOC

Two surfaces share one token set: the analyst console (`#/overview` and every other route) and the landing story
(`#/`). The landing re-points the same token names inside `.landing`, so every utility follows. Written with the
interface-design skill (soc-skill-pack); the landing follows taste-skill's page rules, the console its app-screen rules.

## Direction

**Personality:** Precision & Density (console) · Boldness & Clarity (landing)
**Foundation:** neutral near-black greys (console), pure black (landing, the team's Uber style)
**Depth:** surface-colour steps, no shadows (console) · flat, elevation by lightness only (landing)

- **Who:** a CERT-In / sector-CSIRT analyst on a night shift deciding what to escalate before a reporting deadline;
  and a judge who watches five minutes of it on a projector.
- **Task:** console: acknowledge, escalate, approve or reject, close as false positive. Landing: understand in four
  scrolls why this matters, then open the incident or the console.
- **Feel:** console: a dispatch board at night, dense and calm, colour only where something is at risk. Landing: black,
  white and grey until a warning lands; every warm colour is a real tier.
- **Signature:** the beacon from a (simulated) Maharashtra VPN gateway to a real QakBot server, drawn as the one arc on
  the globe, with REAL / SIM named at both ends.
- **Focal pattern:** one finding per screen. Console: the answer KPI or the top queue row. Landing: one beat at a time,
  its headline, then one figure (the Critical count, then the report clock).
- **Rejected defaults:** Matrix green and neon "cyber" · KPI tiles with tinted icon circles · an attack map full of arcs
  (one arc, and it is evidence) · glows, gradients and glass · numbered eyebrows and middle-dot strings.

## Tokens

### Spacing
Base 4px. Scale 4, 8, 12, 16, 20, 24, 32, 40, 48.
Console: panel padding 20 · table cells 12 vertical, 20 at row ends · 16 between panels · sidebar 232.
Landing: 40px side margins from md (20 / 32 below) · header 56 · caption column `--cap: min(520px, 41vw)`.
Layers: z-10 tooltips · z-20 console top bar (phones) · z-30 landing header and console sheet.

### Colors
```
/* Console (@theme, src/index.css) */
--color-ground: #0f0f10  --color-panel: #161617  --color-raised: #1f1f21  --color-line: #29292c
--color-text: #ededed    --color-mute: #a1a1a1   --color-faint: #8a8a8a
/* Tiers: one hue each, identical on marks, map dots, bars and words. Never decoration. */
--color-compromise: #ff453a  --color-critical: #ff9f0a  --color-high: #ffd60a  --color-medium: #bdbdbd
--color-watch: #6e6e73 (marks only)  --color-ok: #30d158 (live status dot only)
--color-accent: #276ef1  Uber blue: links, focus, selection. Never on data. Text only at 15px+ on black.
--color-c2: #64d2ff      a botnet command server on the globe: identity, not a tier, never on controls

/* Landing (.landing re-points) */
--color-ground: #000  --color-raised: #1f1f1f  --color-line: #333  --color-text: #fff
--color-mute: #afafaf (9.6:1 on black)  --color-faint: #8a8a8a
/* India map: one cool family, neighbours apart in lightness; -lit = the state has watched operators */
--map-1 oklch(0.28 0.080 254) / lit 0.32 0.096 · --map-2 oklch(0.29 0.048 222) / lit 0.33 0.058
--map-3 oklch(0.38 0.058 206) / lit 0.42 0.070 · --map-4 oklch(0.36 0.072 238) / lit 0.40 0.088
--map-5 oklch(0.35 0.098 254) / lit 0.39 0.114 · --map-hot oklch(0.32 0.090 28) (oxblood: suspected compromise)
White labels read at 8:1 or better on every fill; every tier dot is brighter than every fill.
```

### Radius
2px tier mark · 4px loading bars · 6px console buttons, nav, inputs · 8px panels, tooltips · 999px landing pills,
globe labels, CVE chips.

### Typography
Inter Variable with its optical-size axis (`@fontsource-variable/inter/opsz.css`, bundled, offline). Optical sizing
is on in `.landing` (display cut for large type) and off in the console (renders as before).
Figures: `.num` (tabular) in the console; `.fig` (tabular, slashed zero) on the landing. No system monospace on the
landing; CVE IDs and IPs inside map and globe fragments may be mono.
Console scale: 12 · 13 · 14 (base) · 15 · 26 · 34. Landing scale: 12 map labels · 15 UI lines · 17/18 body ·
h2 clamp(34–60) · h1 and the clock clamp(44–80). Weights 400 / 500 / 600. Tracking −0.035em h2, −0.04em h1.
Minimum 12px for anything a person must read.

### Motion
Console: no entrance animation; feedback only (hover, press, a sheet opening). Landing: native scroll drives
everything, smoothed (110ms time constant); captions enter 400ms after 120ms and leave in 200–240ms (opacity and
translate only); the map's wave plays once (≤ ~830ms); CVE chips enter 300ms staggered 60ms by rank and leave in
150ms; the compromise ring plays twice; the world turns for 5s then holds. Easing `--ease-out: cubic-bezier(0.23, 1,
0.32, 1)`; never ease-in. Reduced motion, no WebGL, phones and short screens get the stacked still page.

## Patterns

### Panel (console)
- Background panel, no border or shadow, radius 8 · header 16 top / 12 bottom / 20 sides · title 15/600 · meta 13 mute

### Button (console)
- 36px (md) / 28px (sm) · padding 0 14 / 0 10 · radius 6 · 14/500 · primary: text fill, ground text · secondary: raised

### Pill (landing; `@utility pill`, `pill-sm`, `pill-primary`, `pill-secondary`)
- 44px (sm 40px; 44px on coarse pointers) · padding 0 20 / 0 16 · radius 999 · 15/500 · press scale 0.97
- One white pill per screen: the header's "Open the console" turns secondary on the last beat

### Landing header
- Fixed, 56px, black · wordmark 18/600 + "National cyber early warning" (lg) · data state: Live / Snapshot with date /
  Sample, not real / Backend not answering

### Caption (landing)
- "N of 4" count (15px mute) · headline (two lines at most, no full stop) · white body · 15px mute lines for figures
  and provenance ("Real: … / Simulated: …", on every beat, sample mode says so)

### Globe (landing)
- cobe 2.0.1, square, centred on the India map's box so the dive lands on the map; DPR 2 (1.5 above 800px)
- Ocean as a grey tone step, white land, no glow · C2 cyan (online larger) · operators orange, sized by √Critical ·
  compromised red · one arc (the beacon), gone before India returns
- Labels: solid black plates on cobe CSS anchors; the compromised operator as a solid red pill with black text

### India map (landing)
- @svg-maps/india 2.0.0 (MapSVG, CC BY 4.0, credited in the footer), boundaries as 1.5px black gaps
- Dot per operator, r = 2.4 + 4.6·√(Critical/max), black ring · labels: white name, count at 85% white, 12px
- States with operators are buttons (focus and tap open the card) · card: solid raised, provenance line last
- Always with the ranked list beside it

### State list
- "Critical warnings by state", 6 rows (4 below sm), grey bars without a track, the compromised row's bar red,
  rows are buttons sharing hover/focus with the map, "See all N operators"

### Hero clock
- Inter tabular slashed-zero at the h1 size, HH:MM:SS, red only when overdue, its meaning and due time underneath,
  role="timer"

### States
- Loading keeps the line's shape (flat bars) · errors say what failed and offer "Try again" · zero prints 0,
  missing prints an em dash · no compromise reads as calm text, not red

## Decisions

| Decision | Rationale | Date |
|----------|-----------|------|
| Landing is its own page at `#/`; the console moved to `#/overview` and its Overview is unchanged | Playbook: a public page is not a working screen; no globe in the console | 2026-11-01 |
| Landing dark, in the team's Uber style, although the playbook keeps public sites light | User's choice; projector demo; matches the dark console behind it | 2026-11-01 |
| Keep the globe, with exactly one arc, which is evidence; it turns 5s then holds | User asked for it; playbook bans the decorative "globe with arcs"; WCAG 2.2.2 | 2026-11-01 |
| No glows, gradients or glass on the landing; the sphere separates by a tone step | taste-skill house rules; the user asked for the globe to stand out from the black | 2026-11-01 |
| India map in one cool family with an oxblood compromise state | User: "dull/dusty" but "not rainbow"; taste-skill colour rules; tiers keep the warm hues | 2026-11-01 |
| Critical counts exclude the compromise tier on the map and list | One variable everywhere: the list adds up to the headline (354) | 2026-11-01 |
| Every map carries a ranked list; REAL / SIM on every beat | Playbook; CLAUDE.md rule 17 | 2026-11-01 |
| The CERT-In clock is the last beat's hero, in Inter tabular (not system mono) | Playbook "clocks are the hero"; taste-skill: no monospace on a page; same on every machine | 2026-11-01 |
| Stacked still page for reduced motion, no WebGL, phones and short screens | ux-guidelines #99; impeccable harden; break-ui | 2026-11-01 |
| cobe + plain SVG, no new chart or map library | pick-ui-library; offline; SVG fits under 1,000 regions | 2026-11-01 |
