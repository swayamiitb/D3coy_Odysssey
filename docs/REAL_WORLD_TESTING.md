# Odyssey in real action: pairing with a live target and the SACHET feed

Written for the Odyssey team. This is the approach for testing Odyssey against real, running software and real traffic
rather than only the in-tool synthetic drills, and the boundary we hold while doing it.

## The idea

A national early-warning system is only convincing if it works on real inputs and real attacks, not just a replay of
canned data. Odyssey is paired with two real things:

1. **A live, protected web application.** Odyssey's HTTP shield sits in front of a real running web app through a
   drop-in agent. A person (or a separate red-team session) fires real HTTP attacks at that app over the wire, and
   Odyssey detects them, opens a case, re-scores the host and reports, within milliseconds. This is genuine network
   traffic through a genuine WAF/IDS, not a function call inside the tool.
2. **India's SACHET alert feed.** Odyssey reads NDMA's public-domain SACHET CAP 1.2 feed read-only, matches each
   disaster alert to the operators in that state, and writes its own cyber warnings in the same CAP format. Inbound
   CAP is validated before it is trusted.

## The boundary (non-negotiable)

- **We never attack a real third-party system, and never a real government service.** Not SACHET, not NDMA, not any
  site we do not own. Red-teaming only ever targets an application running on this laptop or a private lab network;
  the red-team runner refuses any target that is not a loopback or RFC-1918 private address.
- **We never impersonate a real agency.** The lab target is a *fictional* government operator from Odyssey's
  simulated constituency, with a visible SIMULATION banner, holding no real data.
- **Odyssey reads SACHET; it does not sit inside it.** Odyssey consumes SACHET's public feed. It has no sensor in
  NDMA's infrastructure and makes no claim to detect an attack on SACHET's own servers. What it detects is attacks on
  the application *we* put behind its shield.
- **Red-teaming is person-triggered.** A person starts each run (the Live page button, or a separate session posting
  to the API). There is no unattended attack loop in the product.

## The live target: Lokseva Citizen Alert Portal (SIMULATED)

`target/gov_portal.py` is a fictional government alert portal ("Lokseva Digital Services Directorate", org `GOV-01`),
modelled on the CityPower portal (`target/portal.py`). It is a real FastAPI web service on `:8081` behind the Odyssey
agent (`agent/odyssey_asgi`). It looks like a citizen alert portal (search, active CAP-style alerts, an officer
sign-in, a CAP feed, a submit form) and exposes the endpoints attackers probe. It reflects input so a real XSS payload
would render, but holds no database, shell, secret or citizen data: detection happens at the HTTP layer in the shield.
A submitted CAP alert is forwarded to Odyssey's ingest guard, so CAP-level attacks are exercised too.

It carries a banner on every page: **"SIMULATED LAB TARGET - a fictional agency for security testing. Not a real
government service; holds no real data."**

It also runs a **self-contained mock OAuth 2.0** authorization-code flow (`/login`, `/oauth/authorize`, `/oauth/token`,
a protected `/dashboard`), so the shield has a realistic authentication surface to watch (open-redirect on
`redirect_uri`, missing `state`/CSRF, SQLi in the token/login, a forged bearer token, a login brute force). The OAuth
server is entirely local and fictional: the only account is a demo one printed on the login page (`officer` /
`demo123`), no real identity provider is contacted, and no real credential is ever collected.

## The red-team agent

`scripts/redteam_agent.py` is a standalone attacker - a separate process from Odyssey, the "red-team entity" - that
exercises the lab target over the wire so the shield can prove it detects. It runs the standard web-attack families
(through Odyssey's own loopback-guarded red-team runner) plus the OAuth/auth-specific cases, in a number of waves you
choose, then prints what the shield caught. Odyssey detects its traffic independently and opens the case.

**Its hard safety rule, enforced in code:** it resolves the target host and refuses anything that is not loopback or an
RFC-1918 private address before sending a single byte, so it can never be pointed at a real or third-party service.
Every request is labelled an exercise (`x-odyssey-redteam` header) in the audit trail. It is person-run and the number
of waves is an argument you pass; it is not an unattended endless loop.

```
.venv\Scripts\python scripts\redteam_agent.py                      # one wave at http://127.0.0.1:8081
.venv\Scripts\python scripts\redteam_agent.py --waves 5 --delay 20 # five waves, 20 s apart
```

It refuses a public target outright, e.g. `--target http://example.com` ->
"refusing: example.com resolves to a public address. This agent only attacks a local lab target you own."

## The full loop, end to end

1. Start the stack (`scripts\start_all.ps1`), then the target (`scripts\start_gov_target.ps1`). The portal registers
   with the shield as `lokseva-alert-portal` (org GOV-01).
2. A person red-teams it on loopback: Live -> *Red-team the shield* against `http://127.0.0.1:8081`, or
   `POST /api/redteam/run {"target":"http://127.0.0.1:8081"}`. Real SQLi, XSS, traversal, command injection, SSTI,
   SSRF, Log4Shell, a scanner sweep and a login brute force go over the wire.
3. Odyssey detects every attack at the HTTP layer, in about 15 ms each, and in block mode drops each one inline with a
   403 (set with `POST /api/shield/apps/lokseva-alert-portal/mode?mode=block`; `mode=monitor` to only detect).
4. Odyssey opens a SOC case ("Web attack on Lokseva Citizen Alert Portal (SIM)", severity Compromise), re-scores the
   host, and the alerts leave the laptop through the channels (Slack / Discord / Teams / webhook / the Ops Console).
5. For the CAP side, a separate session sends CAP messages to `POST /api/sensor/cap` with an `x-odyssey-redteam`
   header; the guard refuses forged senders, replays, stale, oversize and XXE messages, each an audited decision shown
   live on Intel -> Threats -> *Disaster alerts (SACHET)*.

## Measured (1 Nov 2026, on this laptop)

- Red-team against the Lokseva portal: 45 attacks sent, **45 detected (100%)**, **45 blocked inline** in enforce mode,
  precision 1.0, 0 false positives, mean time-to-detect about 15 ms, a Compromise case opened, alerts delivered to the
  channels.
- SACHET feed: 100 alerts in the read, 81 matched to operators by state with a stated basis; the CAP guard holding
  across its eight-step ladder.

## If a legitimate request gets a 403

After a red-team run the attacker IPs (including `127.0.0.1`) are on the shield's block list, so normal browsing of the
target is dropped. Clear it with `POST /api/shield/unblock/127.0.0.1` (and any other IP), and set the app back to
`mode=monitor` for normal browsing. This is the block list working, not a fault.

## What stays simulated, and labelled

The operators, the inventory, the decoy grid and the Lokseva portal are SIM. The CVEs, advisories, attack telemetry,
C2 and phishing indicators, the SACHET feed and the HTTP attacks over the wire are real. Every screen labels REAL or
SIM. Bhashini (cloud translation) is deliberately not used; translation stays local (IndicTrans2).
