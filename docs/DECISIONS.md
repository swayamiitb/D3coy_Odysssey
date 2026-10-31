# Decisions Log

Append-only. Add entries only to your part's section, to avoid merge conflicts (rule 22).
Format: `ID | When | What | Why | Who`

## Team-wide (core)

| ID | When | What | Why | Who |
|---|---|---|---|---|
| D-001 | Sat 31 Oct 14:30 | Adopted the 24-rule team rulebook (`CLAUDE.md`) | One shared process across 3 laptops and 3 Claude sessions | Team (approved) |
| D-002 | Sat 31 Oct 14:30 | Local git with feature branches; push to a shared remote later | Separate laptops, separate parts, merge at fixed windows | Team |
| D-003 | Sat 31 Oct 14:30 | Backups = git checkpoint tags `cp/<part>-<NN>-<name>` before every feature | Instant, lossless rewind of any mistake | Team |
| D-004 | Sat 31 Oct 14:30 | AI = local LLM under 8B params, behind one `llm_client` adapter (model TBD) | Team constraint; the adapter makes swapping the model a config change | Team |
| D-005 | Sat 31 Oct 14:30 | Deadline fixed as Sun 1 Nov 12:00 IST; merge windows 21:00 / 02:00 / 06:00; freeze 09:00; code freeze 11:00 | Leaves time for integration and rehearsal before submission | Team |
| D-006 | Sat 31 Oct 14:30 | Kept the folder name `d3coy _hackathon` (with the space) on this laptop | Renaming an open workspace breaks the running VS Code/Claude session. The folder name isn't stored in git, so teammates can clone into any name | Claude (user OK'd either way) |
| D-007 | Sat 31 Oct evening | Mentor deck built as a claude.ai Slides artifact (14 slides, ride-app look: black/white, Inter Tight + Inter, one red accent used only on data); source files in `docs/pitch/mentor-deck/` | User asked for a minimal, Uber-style deck from the team lead's project brief, using the taste-skill design rules; artifact versions + git tags give rewind | Claude (user asked) |
| D-008 | Sat 31 Oct evening | Synced the mentor deck with the lead's repo (`swayamiitb/D3coy_Odysssey` @ 59928e1): product name Odyssey, measured-models slide, 40 tests, 22 Indian languages, Bayesian compromise check, injection guard, ATT&CK mapping, new Built/Next lists; backtest slide now says 110/110 is by design (KEV is one of our rules), as the lead's Proof page does | Deck must match what the demo shows; the circular 110/110 claim would not survive a mentor question | Claude (user asked) |

## Ingestion (ingest)

| ID | When | What | Why | Who |
|---|---|---|---|---|

## AI engine (ai)

| ID | When | What | Why | Who |
|---|---|---|---|---|

## Dashboard (ui)

| ID | When | What | Why | Who |
|---|---|---|---|---|
