# SACHET + Bhashini — integration plan for Odyssey (two independent connectors)

**Status: PLAN ONLY. Nothing here is built yet.** Execute in a fresh thread **after** the Odyssey codebase is
complete and merged. These are **two separate website connectors** and **two separate "Odyssey in action" test
examples** — keep them independently toggleable; do not fuse them into one pipeline.

Recon for this plan was done on **1 Nov 2026** against the live services; verified facts and saved snapshots are in §1.

### Honesty legend
- ✅ **EXISTS** — already in the Odyssey codebase (verified this session).
- 🌐 **VERIFIED LIVE** — fetched and confirmed this session.
- 🔧 **BUILD** — to be written by the executing thread.
- ❓ **UNVERIFIED** — must be checked (key/endpoint/availability) before being relied on.

---

## 0. Preconditions & house rules (read before writing a line)

- **Run only after the codebase is complete.** `git pull` first. Assumes the HTTP shield, channels (`notify.py`),
  live engine, Intel→Graph/Watch/Indicators/Brand/Attack-surface, hash-chained ledger and the translate service are all
  present and green.
- **Hard rules to preserve (project memory):**
  - **0 cloud calls.** Reading SACHET's *public* feed read-only is fine — it is a passive public feed exactly like NVD
    / KEV / Feodo. **Bhashini is the one exception** and must stay off-by-default (see §3).
  - **Stdlib / offline, no new pip dependency.** Verified this session: **`defusedxml` is NOT installed** → use the
    dependency-free XXE defense in §2 (do **not** add a package; do **not** `pip install`).
  - **SIM/REAL labels** on every fact; **hash-chained ledger** for every action; **Uber "Oreo" UI** (black
    nav/hero/footer, white body, no dark mode, screenshot-checked).
  - **Any attack testing targets loopback/private only**; indicators **defanged**; red-team/drill CAP is **`status=Exercise`**.
  - **C: drive is nearly full (~1 GB).** All test scratch goes under `data/.tmp` / `data/.pytest-tmp` (already wired).
- **Coordination / collision.** Wiring touches shared files — `backend/app/main.py` (startup + endpoints), the
  frontend, `scripts/start_all.ps1`, `scripts/e2e_check.py`, `scripts/ui_audit.py`, and the docs. The main "decoy-cf"
  thread edits these too. Claim them or sequence after it reports done. **Verification runs sequentially** (pytest →
  e2e → ui_audit; `ui_audit` needs system Python with Playwright).
- **End-to-end rule.** Every capability ships in the UI with a working button — a backend-only module is not done.

---

## 1. Verified facts & saved snapshots (so the next thread doesn't re-fetch blind)

### SACHET 🌐
- **RSS feed:** `https://sachet.ndma.gov.in/cap_public_website/rss/rss_india.xml` → HTTP 200, `application/xml`,
  **100 items**, `copyright = public domain`. **Snapshot saved: `data/raw/sachet_rss.xml`** (gitignored).
- **RSS item fields:** `title` (event + district/region text), `description` (often empty), `category` (e.g. `Met`),
  `link` (`…/FetchXMLFile?identifier=<id>` → the full CAP XML), `author` (e.g. `controlroom@ndma.gov.in (IMD Chennai)`),
  `guid` (numeric identifier), `pubDate` (RFC-822).
- **CAP detail:** each `link` returns a **CAP 1.2** message, namespace `urn:oasis:names:tc:emergency:cap:1.2`.
  **Sample saved: `data/raw/sachet_cap_sample.xml`** — `identifier=IN-…`, `sender=IMD-Chennai`, `sent` ISO-8601 with
  `+05:30`, `status=Actual`, `msgType=Alert`, `scope=Public`; `<info>` with `language`, `category`, `event`, `urgency`,
  `severity`, `certainty`, `area/areaDesc`. Multilingual alerts carry **one `<info>` block per language** (a sampled
  Andhra Pradesh lightning alert had English + Telugu).
- **State-matching reality:** most titles/areas are **district-level**; only some name a state outright (seen in the
  100-item snapshot: *Andhra Pradesh* ×2, *Odisha* ×4). So match operators **by state-name mention** in the
  title/area, and optionally **lazily fetch one alert's CAP `areaDesc`** for precision. **Do not fetch all 100 CAP
  messages per poll** (rude to the gov server, slow).
- **Operator states present in the SIM inventory** (match targets): Andhra Pradesh, Delhi, Gujarat, Karnataka, Kerala,
  Maharashtra, Odisha, Rajasthan, Tamil Nadu, Telangana, Uttar Pradesh, West Bengal.

### Bhashini ❓
- **Not verified this session** (no key, no endpoint tested). Treat every Bhashini specific as UNVERIFIED.

### Already in Odyssey ✅ (reuse, don't rebuild)
- Local translation, offline, 22 languages: IndicTrans2 at `:8010`; `GET /api/languages`;
  `GET /api/alerts/{org_id}/{cve_id}/brief/translate?lang=` (validated, cached, protected spans).
- Engine pattern to copy: `backend/app/shield.py` / `live.py` — a class built with `connect()`, a module-level
  `ENGINE` singleton, `status()`, ledger events, started in `main.py` `@app.on_event("startup")` behind an env flag.
- Channels: `backend/app/notify.py` routes selected ledger kinds to Slack/Discord/Teams/webhook/email;
  `config/notify.json` is the policy. Red-team runner: `backend/app/engine/redteam.py` (loopback/private guard).

---

## 2. Connector A — SACHET (input + CAP format + untrusted ingest) — REAL, honest, high value

Three parts. A1 is the easy win; A3 is the distinctive security angle (an early-warning system must defend *its own
inputs*).

### A1. Inbound reader 🔧
- **Mirror the live feed-watch** (`live.py::_check_feeds`): poll every **900 s**, snapshot-backed, `status` one of
  `fresh` / `snapshot` / `offline`, provenance **REAL**.
- `read_feed(live=True)` → `{source:"REAL", status, fetched_at, count, matched, alerts:[{identifier,title,category,
  sender,link,published,states,orgs,org_names}]}`; `match_orgs(states, orgs)` by state.
- **Why it matters (say this):** it answers *"is this outage the weather, or an attack?"* — weight a natural cause when
  an operator's state has an active disaster alert; **escalate** an attack that lands *during* a disaster.
- **UI:** a **"Disaster alerts (SACHET)"** panel on **Now** and/or **Intel**, labelled **REAL**, using the existing
  `Section`/`Row` idiom; one row per alert with its states and the operators it touches.

### A2. Outbound CAP writer ("SACHET-compatible", **not** connected) 🔧
- `write_cap(alert, infos_per_language, status="Exercise")` → CAP 1.2 XML in the `cap:1.2` namespace, **one `<info>`
  per language**, all text **escaped**. Odyssey tier → CAP severity:
  `Compromise→Extreme, Critical→Severe, High→Moderate, Medium→Minor, Watch→Minor`.
- Expose via `GET /api/warnings/{org_id}/{cve_id}/cap` (assemble from `alert_detail` + the translate layer). Optional:
  a standing RSS/CAP feed endpoint (see §8 open question).
- **`status=Exercise`** for drills/red-team; **`Actual`** only for a real detection routed via CERT-In.
- **Honesty:** never NDMA/SACHET branding; label it **"SACHET-compatible"**. Line for judges: *"Odyssey reads India's
  national SACHET feed live and writes its cyber warnings in the same CAP format SACHET publishes — so routing them
  through an authorised agency like CERT-In is configuration, not redevelopment."* Do **not** say "connected to
  SACHET" or "sends alerts to SACHET".

### A3. Untrusted-ingest guard 🔧 — `POST /api/sensor/cap` ("validate, don't trust")
Every inbound alert is hostile until proven otherwise. Each decision is an auditable ledger event
(`cap.ingest.accepted` / `cap.ingest.refused`, defanged). Guards:

| Threat | Defense | Refusal reason |
|---|---|---|
| **XXE / billion-laughs** | `safe_parse`: reject any document containing `<!DOCTYPE`/`<!ENTITY`, cap size, then stdlib parse | `xxe` / `oversize` |
| **Forged / spoofed sender** | allow-list of authorised agencies (ids + trusted domains + prefixes) | `untrusted_sender` |
| **Replay** | refuse an `identifier` already seen | `replay` |
| **Stale / cancellation-replay** | refuse if `<expires>` is in the past | `stale` |
| **Flood / DoS of ingest** | rate cap per 60 s window | `rate_limited` |
| **Malformed** | not well-formed, or not a CAP `<alert>`, or missing `identifier`/`sender`/`sent` | `malformed` |

**Why not `defusedxml`:** it is not installed, adding it is a new dependency + a network install against the offline
rule, and rejecting DTDs/entities outright is OWASP's "disable DTDs" guidance and fully sufficient for CAP (which never
carries a DTD); stdlib `expat` does not fetch external entities on its own. Prove it with a test that plants a secret in
a local file and asserts it never appears in the result.

Allow-list that passes the real feed but refuses spoofs: trusted **domains** `ndma.gov.in, imd.gov.in,
mausam.imd.gov.in, cwc.gov.in, incois.gov.in, cert-in.org.in`; **prefixes** `IMD- CWC- INCOIS- SDMA- NDMA`; plus
Odyssey's own id `odyssey@ncew.local`. Real `IMD-Chennai` and `controlroom@ndma.gov.in` pass; bare `IMD` and `EVIL`
are refused.

Surface refusals like shield detections, and (optional, see §8) route `cap.ingest.refused` through the channels at the
High floor so a forged/XXE alert reaches Slack/console.

### A4. Red-team CAP cases 🔧 (loopback only, labelled Exercise)
Extend `engine/redteam.py` (or a small sibling) to fire XXE / forged-sender / replay / flood at
`POST /api/sensor/cap` on `127.0.0.1` only, and measure the refusals. Reuse the existing loopback/private guard; never
a third party.

### A5. Reference module shapes (validated against the real feed today)

```python
# backend/app/sachet.py  (stdlib only)
CAP_NS = "urn:oasis:names:tc:emergency:cap:1.2"
SEVERITY = {"Compromise": "Extreme", "Critical": "Severe", "High": "Moderate", "Medium": "Minor", "Watch": "Minor"}
MAX_XML_BYTES = 2 * 1024 * 1024

def safe_parse(data: bytes) -> "ET.Element":
    """XXE defense, dependency-free: refuse DTD/DOCTYPE/ENTITY and oversize, then parse with stdlib."""
    raw = data if isinstance(data, bytes) else data.encode()
    if len(raw) > MAX_XML_BYTES:
        raise ValueError("XML too large")
    low = raw.lower()
    if b"<!doctype" in low or b"<!entity" in low:
        raise ValueError("DTD/DOCTYPE refused (XXE / entity-expansion defense)")
    import xml.etree.ElementTree as ET
    return ET.fromstring(raw)

def write_cap(alert: dict, infos: list[dict], *, status="Exercise", sender="odyssey@ncew.local",
              scope="Restricted") -> str:
    # build <alert xmlns=cap:1.2> with identifier/sender/sent(now IST, +05:30)/status/msgType=Alert/scope,
    # then one <info> per language: language, category=Security, event, urgency, severity(SEVERITY[tier]),
    # certainty, headline, instruction, area/areaDesc.  Escape every text node.  Return with an XML declaration.

# ingest decision ladder (order matters): rate/flood -> safe_parse (xxe/oversize/malformed) ->
#   required fields -> sender_allowed -> replay (seen identifier) -> stale (<expires> past) -> accepted.
# class CapGuard(connect): read_feed(), fetch_cap(url) [https sachet.ndma.gov.in or loopback only],
#   ingest(data, source_ip=None, redteam=None) -> {accepted, reason, detail, identifier}, status().
# ENGINE: CapGuard | None = None ; start in main.py startup behind ODYSSEY_SACHET != "0".
```

### A6. Test plan (`tests/test_sachet.py`)
Parse the real RSS snapshot (skip if absent) and match a state; parse the real CAP sample; org-match by state;
**XXE + billion-laughs refused without expanding a planted secret**; oversize refused; forged sender refused /
authorised accepted; replay refused; stale refused; flood capped at the window max; malformed refused; `write_cap`
round-trips through `safe_parse` with two languages, severity mapped, namespace present; an XSS payload quoted in a
warning is **escaped, not emitted raw**; every ingest decision is audited and the chain stays intact (use a temp copy
of `data/ews.db`, assert **deltas** not absolute counts — the live DB keeps changing).

---

## 3. Connector B — Bhashini (optional language backend) — UNVERIFIED, cloud

### B1. What it is / adds / does **not** add
MeitY platform for translation + text-to-speech + speech-to-text in the 22 scheduled languages. **Adds:** an official
government language badge and optional **voice** alerts (TTS). **Does not add** basic translation — IndicTrans2 already
does that locally and offline.

### B2. The decision (keep "0 cloud calls" honest)
Bhashini is a **cloud API**: it needs registration + a key, needs internet, and **breaks the "0 cloud calls" promise**
that appears in the footer, on the Proof page and in the pitch. Therefore:
- **Default stays IndicTrans2 local.** Bhashini is **optional and OFF by default**, selected by env
  (`ODYSSEY_TRANSLATE_BACKEND=bhashini` + `ODYSSEY_BHASHINI_KEY`).
- When enabled: **cache** results, **badge** outputs as Bhashini, and **condition the on-screen "0 cloud calls" claim**
  (e.g. "0 cloud calls — local translation; optional Bhashini cloud translation is **off**", flipping when it's on).
  **Never silently break the promise.**

### B3. Where it plugs in (pluggable backend behind the existing seam)
Define one interface and give it two implementations; the `/brief/translate` endpoint and the CAP writer's per-language
`<info>` blocks call the selected backend:

```python
# ai/translate_backend.py
class TranslateBackend:
    def translate(self, texts: list[str], lang: str, protect: list[str]) -> dict:
        """-> {model, seconds, rtl, results: [{text, status}]}"""
# IndicTrans2Backend (existing :8010 call, default) ; BhashiniBackend (new, cloud, off unless keyed)
```

### B4. UNVERIFIED checklist — do **before** relying on it ❓
Register on the Bhashini / MeitY developer portal; confirm the ULCA **pipeline-config** + **inference** endpoint URLs;
the **auth header / key** scheme; the exact **request/response JSON** (including TTS audio encoding); whether any
**offline / on-prem** option exists (likely not); **rate limits** and **ToS**; **data residency / PII** (alerts may name
assets and organisations). If any of these fails → keep Bhashini **off** and ship IndicTrans2-only.

### B5. Honesty lines
Say: *"22 languages run locally and offline by default (IndicTrans2); Bhashini is supported as an optional official
government backend, off unless you provide a key."* Do **not** say "powered by Bhashini" unless it is actually enabled
and verified.

---

## 4. How the two relate — but stay separate
One CAP warning (Connector A) can carry `<info>` blocks produced by **either** translation backend. SACHET is
**input + output format**; Bhashini is **an alternative translator**. Independent toggles (`ODYSSEY_SACHET`,
`ODYSSEY_TRANSLATE_BACKEND`); the demo can show either on its own.

---

## 5. Build order & file touchpoints

| # | Work | New / modified | Endpoints / config | Collision-sensitive | New dep |
|---|---|---|---|---|---|
| 0 | Codebase complete; `git pull` | — | — | — | — |
| 1 | SACHET reader + snapshot + panel | **new** `backend/app/sachet.py`; mod `main.py` (startup + `GET /api/sachet`), new frontend panel + `api.ts` type; `start_all.ps1` (optional, in-process so maybe nothing) | `GET /api/sachet` | `main.py`, frontend, `start_all.ps1` | No |
| 2 | CAP writer + export | `sachet.py`; `main.py` | `GET /api/warnings/{org}/{cve}/cap` | `main.py` | No |
| 3 | CAP ingest + guards + audit | `sachet.py`; `main.py`; (optional) `config/notify.json` kind `cap.ingest.refused` | `POST /api/sensor/cap` | `main.py` | No |
| 4 | Red-team CAP cases (loopback) | `engine/redteam.py` or sibling; `main.py` default target | reuse `POST /api/redteam/run` | `main.py`, `redteam.py` | No |
| 5 | Tests | **new** `tests/test_sachet.py` | — | — | No |
| 6 | **Bhashini backend (optional)** | new `ai/translate_backend.py`; mod the translate seam; env + badge + **Proof wording** | env only | `ai/*`, Proof UI | **Yes (cloud + key, UNVERIFIED)** |
| 7 | Docs & counts | `README.md`, `docs/PS_COVERAGE.md`, `docs/PITCH.md`, `docs/MODEL_CARD.md`, `docs/THREAD_CONTEXT.md` | — | docs (coordinate) | No |

---

## 6. Safety & honesty summary (restate to judges)
Passive public feed read-only (SACHET in); every attack test loopback/private only; indicators defanged; SIM/REAL
labels; outbound CAP `status=Exercise` for drills; **never** NDMA/SACHET branding ("SACHET-compatible"); the "0 cloud
calls" promise is preserved unless the user turns Bhashini on, and then it is stated on screen; no new dependency;
offline snapshots so the demo survives no network. Design principle: **"Odyssey treats every inbound alert as
untrusted — validate, don't trust."**

---

## 7. Demo arc (all local, ~2 min)
1. Odyssey shows SACHET's **real** live feed (read-only). 🌐
2. `curl.exe` a **forged** CAP at `POST /api/sensor/cap` → refused (untrusted sender), logged, shown.
3. Send an **XXE** CAP → refused; show it would have tried to read a local file and was blocked **before parsing**.
4. **Tamper** a stored alert → the audit chain shows **BROKEN** (✅ existing ledger).
5. A legitimate detection → Odyssey emits a **CAP warning** in English + Hindi (local translation; optional Bhashini
   badge). → **detect → prevent → verify → warn**, the full PS-01 chain, nothing external touched.

> Windows note: PowerShell `curl` is not real curl — use **`curl.exe`** or `Invoke-RestMethod`.

---

## 8. Open questions for the user (decide before/at execution)
1. **Bhashini key & the 0-cloud caveat** — is there a developer key, and is the on-screen "0 cloud calls" caveat
   acceptable when it's on? If not → ship IndicTrans2-only, present Bhashini as "supported, off".
2. **CAP outbound shape** — per-warning export only (`GET …/cap`), or also a standing RSS/CAP **feed** endpoint?
3. **Route `cap.ingest.refused` to the channels?** (Slack/console alert on a forged/XXE inbound alert, like a shield
   detection.) Default suggestion: yes, at the High floor.

---

*Appendix — snapshots already on disk (gitignored, reuse for offline build/tests): `data/raw/sachet_rss.xml` (100
items), `data/raw/sachet_cap_sample.xml` (one real CAP 1.2 message). Re-fetch to refresh; both are public domain.*
