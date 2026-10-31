# Odyssey SOC console

An analyst-first SOC website on top of the lead's **Odyssey** backend (`swayamiitb/D3coy_Odysssey`). It covers the triage queue, the incident page, the human-in-the-loop decisions, the audit log and the intelligence views.

## Run

```bash
cd dashboard
npm ci          # first time only; versions are pinned
npm run dev     # http://localhost:5174  (the landing story; the console is at #/overview)
```

At start-up the app picks one data mode and shows it (landing header, and the bottom of the console sidebar):

| Mode | When | Actions (acknowledge, approve…) |
|---|---|---|
| **Live** | The Odyssey backend answers on `http://127.0.0.1:8000`. Set `ODYSSEY_API=http://host:port` to use another address, e.g. a Live Share forwarded port | Recorded in Odyssey's hash-chained ledger |
| **Snapshot** | No backend, but `public/demo/` holds a saved snapshot | Read-only |
| **Sample data** | Neither of the above | Read-only. A banner says the numbers are layout filler |

## Offline demo snapshot (rule 14)

Run this with the backend running. It saves every screen's real API responses into `public/demo/`, so the demo needs no network and no model:

```bash
npm run snapshot                          # backend on 127.0.0.1:8000
node scripts/snapshot.mjs http://HOST:8000
```

Commit `public/demo/` after a good run. The committed snapshot was taken on 1 Nov at 03:22 IST; re-run it after the backend's final build so the counts and the CERT-In clock match the demo. AI briefs are missing from it until the local model is installed (the backend answers 500 for them).

## Live defence (`#/live`, `#/shield`)

Two console screens for the lead's live system: **Live grid** (the simulated decoy grid and firewall flows, surge detection, and drills you can start) and **HTTP Shield** (a real demo portal behind the Odyssey agent: detections, attackers, the block list, Monitor/Block mode and red-team runs). Start the portal from the backend folder; on this laptop it runs on 8088 because 8080 is taken:

```powershell
$env:TARGET_PORT='8088'; $env:TARGET_MODE='enforce'; .venv\Scripts\python -m uvicorn target.portal:app --host 127.0.0.1 --port 8088
```

The portal registers as "enforce", which the Shield treats as Monitor: press **Block** on the Shield screen before a demo so attacks are dropped.

## Landing story (`#/`)

The site opens on a full-screen scroll story, outside the console (`src/screens/Landing.tsx`): real botnet command servers on a 3D globe (`cobe`) → the globe dives into a flat India state map with the operators, their Critical warnings and a ranked list (`src/geo/IndiaMap.tsx`) → the beacon arc from the compromised gateway to its C2 → the map again with each top state's worst real CVE, the CERT-In clock and the decisions waiting. "Open the console" (header and last step) goes to `#/overview`; Back returns to the same step.

Hover, focus or tap a state for its card. Reduced motion, no WebGL, phones and short screens get the stacked version: the four steps one under another, each with a still picture. Labels on the globe need CSS anchor positioning (Chrome or Edge); present in one of those. Design decisions live in `.interface-design/system.md`.

State boundaries: MapSVG via [`@svg-maps/india`](https://www.npmjs.com/package/@svg-maps/india), CC BY 4.0 (credited in the page footer). They are pre-2019 divisions: Ladakh is drawn inside Jammu and Kashmir.

The C2 layer comes from abuse.ch Feodo Tracker, bundled in `src/geo/feodo.json` because the Odyssey API does not return C2 countries. Refresh it before a demo:

```bash
node scripts/feodo.mjs                                   # download the public list
node scripts/feodo.mjs D:\D3coy_Odysssey\data\raw\feodo_ipblocklist.json   # or reuse the backend's saved feed
```
