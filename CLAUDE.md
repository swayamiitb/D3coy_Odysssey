# CLAUDE.md — D3COY 1.0 Team Rulebook

Every Claude Code session in this repo (on every teammate's laptop) must follow this file.
Rules were approved by the team on Sat 31 Oct 2026. Change them only with the team lead's approval.

## Project

- **Event:** D3COY 1.0 (DJS ISACA), 24-hour offline hackathon. Judged by **live demo + PPT pitch**.
- **Problem:** PS 01 — AI-Based National Cyber Threat Early Warning System.
- **Goal:** aggregate threat intel (feeds, advisories, vulnerability DBs, simulated logs) → AI analysis (indicators, patterns, relationships) → early warnings (severity, confidence, relevance) → risk prioritisation (exploitability, asset criticality, impact, evidence) → actionable mitigations → dashboard.
- **Deadline:** **Sun 1 Nov 2026, 12:00 IST** (submission).
- **Team:** 3 people, separate laptops, one part each (team lead assigns owners).
- **AI:** local LLM under 8B parameters (model chosen by the team). Always called through the `llm_client` adapter.
- **Plan:** [docs/PLAN.md](docs/PLAN.md) · **Decisions:** [docs/DECISIONS.md](docs/DECISIONS.md)

## Rules

### A. Approval & explanation
1. **No new implementation without an approved Feature Brief** (template below). This covers any file, feature, library or config. The owner of that part must say "go".
2. **Research before proposing.** Verify external APIs and libraries against official docs. Never guess.
3. **No scope creep.** Build only what the brief approved. Anything extra needs a new brief.

### B. Backup & rewind
4. **Before each feature:** clean commit + annotated tag `cp/<part>-<NN>-<name>`. **After it works:** commit + tag `done/<part>-<NN>-<name>`.
   Part keys: `core`, `ingest`, `ai`, `ui`. The part key keeps tags unique when the three laptops merge.
5. **Rewind non-destructively:** `git switch -c rescue/<name> <tag>`.
   `git reset --hard`, force-push, and deleting branches or tags all need explicit OK from the part owner.

### C. Team & merging (separate laptops)
6. **One folder per part. Edit only your own folder.** Shared files (`shared/`, `CLAUDE.md`, `README.md`, `docs/PLAN.md`) change only with the team lead's approval.

   | Folder | Part | Key |
   |---|---|---|
   | `ingestion/` | Data collection + backend API | `ingest` |
   | `ai_engine/` | AI analysis + risk scoring | `ai` |
   | `dashboard/` | Frontend dashboard | `ui` |
   | `shared/contracts/` | JSON schemas + API contract | `core` |
   | `data/` | Simulated datasets, demo cache (`data/demo/`) | `core` |
   | `docs/` | Plan, decisions, pitch material | `core` |

7. **Contracts first.** The JSON shapes (Threat, Asset, Alert, RiskScore) and the API endpoints live in `shared/contracts/` and are agreed before anyone codes. Everyone builds against mock data in those shapes. Changing a contract needs agreement from every owner.
8. **Branches:** `feat/<part>-<thing>`, `fix/<part>-<thing>`. `main` must always run the demo. Merging into `main` needs the owner plus one teammate review.
9. **Merge windows:** Sat 21:00 · Sun 02:00 · Sun 06:00. Never leave integration to the end.
10. **Small commits with conventional messages:** `feat(ai): ...`, `fix(ui): ...`, `docs: ...`, `chore: ...`.

### D. Time discipline
11. **Thin slice first.** One CVE → matched to an asset → risk score → AI explanation → shown on the dashboard, working end to end before any extra feature.
12. **50% overrun rule.** If a task runs 50% over its timebox: stop, report, cut scope.
13. **Sun 06:00** one person starts the PPT. **Sun 09:00** feature freeze (fixes, polish, rehearsal only). **Sun 11:00** code freeze, tag `demo-final`. **Sun 12:00** submit.

### E. Live-demo safety
14. **Two modes.** LIVE (real feeds) and DEMO (cached feeds + pre-generated AI outputs, committed under `data/demo/`). The demo must never depend on the network or on model latency.
15. **One scripted demo story**, rehearsed at least 3 times.
16. **Every feature maps to a PS objective** (traceability table in `docs/PLAN.md`). If it doesn't, cut it.
17. **Every AI output shows its evidence and confidence** (score breakdown, sources).

### F. Code hygiene
18. **Pin dependency versions** (`requirements.txt` with `==`, commit `package-lock.json`). The README keeps a one-command way to run the full stack.
19. **All LLM calls go through the single `llm_client` adapter.** The model name and endpoint come from config.
20. **Never commit secrets.** Use `.env` (gitignored) plus a committed `.env.example`.

### G. Docs & AI coordination
21. **This file is the rulebook.** Every Claude session follows it.
22. **Log every decision** in `docs/DECISIONS.md` (what, why, who, when). Append only to your part's section.
23. **`docs/PLAN.md` holds the task board** (owner, status, timebox).
24. **Plans from another teammate's AI go into `docs/` as files** and get a written review (agree / concerns). No silent overrides.

## Feature Brief template

```
### Feature Brief <part>-<NN>: <title>
- What:
- Why (PS objective):
- Files touched:
- How it works:
- Risks:
- Checkpoint tag: cp/<part>-<NN>-<name>
- Rollback: git switch -c rescue/<name> cp/<part>-<NN>-<name>
```

Keep it to 10–20 lines, so the owner can approve it in a minute.

## Session checklist for Claude

1. At session start, read `docs/PLAN.md` and `docs/DECISIONS.md`.
2. Before building: post the brief → wait for "go" → `git status` must be clean → commit → `git tag -a cp/...`.
3. Build only inside your part's folder.
4. After building: run or test it, and report honestly what was verified and what wasn't. Then commit, `git tag -a done/...`, and log the decision.

## Git quick reference

```
git tag -l "cp/*"                                          # list checkpoints
git tag -a cp/ai-03-risk-engine -m "before risk engine"    # create a checkpoint
git switch -c rescue/risk cp/ai-03-risk-engine             # non-destructive rewind
git log --oneline --decorate -15                           # recent history with tags
```
