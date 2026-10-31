# Odyssey SOC console

An analyst-first SOC website on top of the lead's **Odyssey** backend (`swayamiitb/D3coy_Odysssey`). It covers the triage queue, the incident page, the human-in-the-loop decisions, the audit log and the intelligence views.

## Run

```bash
cd dashboard
npm ci          # first time only; versions are pinned
npm run dev     # http://localhost:5174
```

At start-up the console picks one data mode and shows it at the bottom of the sidebar:

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

Commit `public/demo/` after a good run.

## Landing story and globe

The Overview opens with a four-step scroll story (`src/screens/Landing.tsx`): real botnet C2 servers on a 3D globe (`cobe`) → the globe dives into a flat India state map with the operators and their Critical counts (`src/geo/IndiaMap.tsx`) → the beacon arc from the compromised gateway to its C2 → the India map again, with each top state's worst real CVE. Hover a state for details. Visitors with "reduce motion" on get a still version.

State boundaries: MapSVG via [`@svg-maps/india`](https://www.npmjs.com/package/@svg-maps/india), CC BY 4.0 (credited on the map). They are pre-2019 divisions: Ladakh is drawn inside Jammu and Kashmir.

The C2 layer comes from abuse.ch Feodo Tracker, bundled in `src/geo/feodo.json` because the Odyssey API does not return C2 countries. Refresh it before a demo:

```bash
node scripts/feodo.mjs                                   # download the public list
node scripts/feodo.mjs D:\D3coy_Odysssey\data\raw\feodo_ipblocklist.json   # or reuse the backend's saved feed
```
