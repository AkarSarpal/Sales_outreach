# Pipeline Build Report — Security Outbound V1

---

## Session 4 — 6 July 2026

### Account switch + full writeback run

Switched to a new Lemlist account. New campaign: **Security Outbound V1** (`cam_YvrCNaEq7FojNNH3r`), 51 leads.

**Bug fixed: `pipeline.py` was not loading `.env`**

`pipeline.py` was using `os.getenv()` without ever calling `load_dotenv()`, so it relied on environment variables being pre-exported in the shell. Fixed by adding:

```python
from dotenv import load_dotenv
load_dotenv()
```

`python-dotenv` (v1.2.2) was already installed. Without this fix, the pipeline exited immediately with `LEMLIST_API_KEY is not set` when run directly via `python pipeline.py`.

**Run results (6 July 2026):**

| Metric | Value |
|---|---|
| Leads loaded | 51 |
| `has_cve` | 39 |
| `no_findings` (no domain) | 12 |
| Live scans (Shodan InternetDB) | 8 |
| CISA KEV — actively exploited | 0 |
| Writeback | 39/51 variables pushed |

**Notable findings:**
- Akabank (`akabank.de`) — 75 CVEs on IP from Shodan InternetDB
- Gemakom (`gemakom.de`) — 6 version-accurate CVEs from InternetDB
- Adeus (`adeus.com`) — 34 CVEs from InternetDB including 2026-dated entries

**Writeback discovery:** Lemlist stores custom variables on the lead object (`GET /api/leads/{email}`), not the contact object (`GET /api/contacts/{id}`). The PATCH to `campaigns/{id}/leads/{email}` with flat JSON keys works — variables confirmed present on lead after writeback.

**Cleanup needed before campaign activation:**
- Remove "Example / example.com" placeholder lead from Lemlist
- 12 leads with no domain get empty variables — review or remove before activating

**`.env.example` corrected:** Real API keys were present in the committed template (regression from prior session). Replaced with placeholder values. Fixed typo `VIRUSTOTAL_API_KE` → `VIRUSTOTAL_API_KEY`.

---

## Session 3 — 29 June 2026

### What Was Added — Free Reliability Upgrades (no new API keys)

Three new data sources added to `pipeline.py` to improve CVE accuracy and signal strength without requiring paid or new API keys:

**1. Shodan InternetDB** (`internetdb.shodan.io/{ip}`) — free, no auth
- Resolves domain → IP via `socket.getaddrinfo`, queries InternetDB for that IP
- Returns: open ports, version-accurate CVE IDs (Shodan fingerprint-matched), CPE strings, tags
- When InternetDB has data: switches `data_source` to `live_scan` and looks up the top CVE in NVD by ID (much more accurate than keyword search)
- CDN detection: if `cloudflare` appears in tags, falls back to keyword search (CDN IP data is useless for target)
- Impact: for any lead whose IP InternetDB has indexed, CVEs go from "keyword-matched generic" to "version-accurate"

**2. Direct HTTP fingerprinting** (`fingerprint_http()`) — free, no auth
- `GET https://domain` (fallback to `http://`), 8s timeout, parses `Server:`, `X-Powered-By:`, `X-Generator:`, `via:` headers and first 4KB of HTML
- Detects: Apache, nginx, IIS, ASP.NET, WordPress, Drupal, Joomla, PHP, Node.js, Cloudflare, Tomcat, OpenSSL
- Priority 1 in tech stack — more current than VirusTotal passive cache (VT now fallback-only)
- Impact: better tech stack → better keyword CVE matches for the inferred path

**3. CISA KEV cross-reference** (`load_cisa_kev()`) — free, no auth
- Downloads CISA Known Exploited Vulnerabilities catalog once per run, caches in memory
- ~1,100+ CVE IDs that are being actively exploited in the wild
- After CVE lookup, checks if `top_cve["id"]` is in KEV set
- Adds `exploited_in_wild = "Yes — CISA KEV"` as a new Lemlist variable
- Report: adds ⚠ KEV column to lead table, "CISA KEV — actively exploited" badge in lead details
- Impact: strongest possible signal for outreach — "this CVE is being actively exploited right now"

### New Lemlist variable

`{{exploited_in_wild}}` = `"Yes — CISA KEV"` or `""` (empty)

Use in Step 3 message variant for extra urgency:
> "Found CVE {{key_cve}} (CVSS {{cvss_score}}) — and it's on CISA's actively exploited list. This one isn't theoretical."

### Other changes this session

- **README.md** — complete rewrite with full product documentation (all 5 phases, CLI flags, variable reference, message templates, API keys, data sources, intel quality, MVP thresholds, roadmap)
- **context.md** — pipeline state table and data sources updated to reflect 3 new sources; challenges section updated

---

## Session 2 — 24 June 2026

### What Was Added

Based on reviewer feedback (WhatsApp, 24 June): "why only 4 technologies for CVE, some features are disabled"

- **SSL Labs integration** — `query_ssl_labs(domain)`: pulls SSL grade (A/B/C/F) and cert expiry from SSL Labs cache. No API key required. Uses `fromCache=on&maxAge=48` — never triggers a new scan.
- **Whois integration** — `query_whois(domain)`: shells to system `whois`, parses creation date across 5 formats (handles EU `.de`/`.nl`/`.fr`/`.es`/`.com`). Returns domain age in days and registrar.
- **Tech limit raised 4 → 6** — `tech[:4]` → `tech[:6]`. Covers more of the detected stack when VirusTotal returns multiple signals.
- **Two new Lemlist variables** — `{{ssl_grade}}` and `{{domain_age}}` added to writeback and report.
- **Report updated** — Lead table now has SSL and Domain Age columns. Lead details show `SSL grade B (expires 2026-09-14) | domain age 8y via GoDaddy`.

**VirusTotal key status:** configured in `.env` (session 2). Pipeline now uses real passive HTTP headers for tech stack — no longer falling back to generic defaults for most leads.

---

## Session 1 — 22 June 2026
Based on: challenges.pdf (18 June 2026 report)

---

## What Was Built (Session 1)

A Python pipeline (`pipeline.py`) that:
- Reads all 23 leads from the Lemlist campaign via API (no CSV, no manual prompts)
- Resolves company domains from work email addresses (accurate, no guessing)
- Queries NVD for HIGH/CRITICAL CVEs published in the last 3 years
- Checks HIBP for domain breaches (when API key is provided)
- Tags each lead: `has_cve`, `has_breach`, or `no_findings`
- Generates `intel_report.md` with per-lead variable preview
- Optionally writes all variables back to Lemlist with `--writeback`

**Current pipeline state: operational in inferred mode. Live scanning not yet active.**

---

## Challenges from the June 18 Report — Resolution Status

### 01 — No Shodan API key
**Original status:** HIGH blocker — no live port/service scanning
**Session 1–2 resolution:** Attempted replacement with Censys free tier. Censys removed free programmatic API access entirely in June 2026. Pipeline ran in inferred mode with VirusTotal passive headers as tech stack source.
**Session 3 resolution:** ✅ **Shodan InternetDB** — `internetdb.shodan.io/{ip}` is completely free with no API key. Resolves domain → IP via `socket.getaddrinfo`, returns open ports, version-accurate CVE IDs, CPE strings. For leads where InternetDB has data, `data_source` becomes `live_scan` and CVEs are version-accurate.
**Remaining gap:** Hosts behind Cloudflare/CDN show CDN IP data — pipeline detects this and falls back to keyword search. Shodan paid ($69/mo) reaches origin servers through CDN for full coverage.

---

### 02 — NVD rate limit without API key
**Original status:** MEDIUM — 5 req/30s, ~7min runtime for 20 companies
**Resolution:** ✅ Fixed. Pipeline auto-detects `NVD_API_KEY` and switches sleep: 6.5s without key, 0.7s with free key. Added retry logic for 503/timeout errors (3 attempts, 15s backoff). Also added `cvssV3Severity=HIGH` and `pubStartDate` (3 years) filters so only recent High/Critical CVEs are returned.
**Remaining action:** Get free NVD key at nvd.nist.gov (5 min) → add to `.env` as `NVD_API_KEY`. Cuts runtime from ~7min to ~40sec.

---

### 03 — Domain names not stored in Lemlist leads
**Original status:** HIGH blocker — company name → domain inference wrong ~30–60% of time
**Resolution:** ✅ Fixed. The Lemlist contacts API returns the lead's work email (e.g. `erikjan.davids@bureauveritas.com`). Pipeline extracts the domain directly from the email — no inference needed. `bureauveritas.com`, `prescan.nl`, `minddoc.de` all resolved correctly in testing. The heuristic `infer_domain()` function is still present as fallback for leads with personal email addresses but is rarely invoked.

---

### 04 — Campaign in Draft — zero messages sent
**Original status:** HIGH — all intel gathered but unused
**Resolution:** Pipeline is ready. The `--writeback` flag pushes all 8 variables to each Lemlist lead. Campaign needs to be **activated manually** in Lemlist UI first (assign sender → activate), then run `python pipeline.py --writeback`.
**Remaining action:** Activate campaign in Lemlist UI. This is the single biggest unlock — without it, no outreach happens.

---

### 05 — CVE lookups imprecise without software versions
**Original status:** MEDIUM — keyword search returns broad/irrelevant CVEs
**Session 1–2 resolution:** Added HIGH/CRITICAL filters and 3-year recency window to NVD. VirusTotal passive headers narrowed tech stack for most leads.
**Session 3 resolution:** ✅ Three-layer fix: (1) direct HTTP probe reads `Server:`/`X-Powered-By:` directly (most current), (2) Shodan InternetDB returns CPE strings + CVE IDs matched to the actual IP's fingerprint (version-accurate for indexed hosts), (3) NVD lookup by specific CVE ID when InternetDB has them — much more accurate than keyword search.
**Remaining gap:** CDN-fronted sites and IPs not in InternetDB still use keyword search. BuiltWith API gives framework versions for sharper CPE-based lookups (paid, post-MVP).

---

### 06 — Claude synthesis knowledge-based, not live-scan-based
**Original status:** MEDIUM — unverified risk assessments
**Resolution:** ✅ Implemented. Every result carries `data_source: inferred` or `live_scan`. With Censys unavailable, all current results are `inferred`. The intel report makes this visible per lead. Users can treat inferred findings as conversation starters, not audit-grade claims.

---

### 07 — European companies produce wrong `.com` domain guesses
**Original status:** MEDIUM — ~60% of EU leads fail DNS resolution
**Resolution:** ✅ Superseded. Domain comes from work email, which is inherently correct regardless of TLD. `prescan.nl`, `minddoc.de`, `mediaire.de` all resolved without any TLD logic. The EU TLD problem was only a problem with name-based inference — moot now.

---

### 08 — No automated re-run trigger
**Original status:** LOW
**Resolution:** Not implemented yet — out of scope for MVP.
**Path:** GitHub Actions `schedule: cron` trigger, weekly. Diff against previous `intel_report.md`, alert on new High/Critical CVEs. Write updated scores to Lemlist automatically.

---

### 09 — Anthropic API key in browser artifact
**Original status:** LOW
**Resolution:** ✅ Handled by design. `pipeline.py` is server-side Python. All API keys live in `.env` (blocked by `.gitignore`). No browser-side key exposure.

---

## Challenge: Censys API Removed (not in June 18 report)

**Discovered:** 22 June 2026, during implementation
**Impact:** HIGH — originally planned as the Shodan replacement
**Details:** Censys migrated entirely to `platform.censys.io`. All classic API credentials (ID + Secret) are gone. Free programmatic access to Censys search is no longer available.
**Session 1–2 workaround:** VirusTotal free tier added as lightweight tech stack enrichment. Pipeline ran in inferred mode.
**Session 3 resolution:** ✅ **Shodan InternetDB** (`internetdb.shodan.io/{ip}`) — completely free, no API key, returns live ports + CVE IDs + CPEs. Provides real live scan data for most internet-facing hosts. `scan_censys()` remains in the codebase but is superseded by `query_shodan_internetdb()`.
**Remaining gap:** Shodan paid ($69/mo) gives deeper service fingerprinting and reaches CDN-protected origins. Worth it post-MVP.

---

## Intel Quality Assessment — Current State (updated 29 June 2026)

**What works:**
- Domain resolution: 100% accurate (from email)
- Shodan InternetDB: live ports + version-accurate CVE IDs for indexed IPs (free, no key)
- Direct HTTP fingerprinting: tech stack from `Server:`/`X-Powered-By:`/HTML (free, no key)
- CISA KEV cross-reference: actively-exploited flag per CVE (free, no key)
- NVD CVE lookup: operational, retry logic, HIGH/CRITICAL only, last 3 years
- VirusTotal tech stack: active, used as fallback
- SSL Labs + Whois: active
- Lead tagging: `has_cve` / `has_breach` / `no_findings` working
- Lemlist variable writeback: 11 variables including `{{exploited_in_wild}}`

**What needs attention:**

| Issue | Impact | Fix |
|---|---|---|
| No breach data | Medium — `breach_date` / `compliance_flag` always empty | HIBP API key (~$4/mo) |
| NVD slow without API key | Low — ~7min runtime | Free NVD key, 5 min to get |
| CDN-fronted hosts | Low — InternetDB returns CDN data, falls back to keyword search | Shodan paid ($69/mo) post-MVP |
| Campaign not activated | Blocking — no outreach sent yet | Activate in Lemlist UI |

---

## What Can Be Improved — Prioritised

### Now (free, < 30 min each)

**1. Get free NVD API key**
→ nvd.nist.gov → "Request an API Key"
→ Add to `.env` as `NVD_API_KEY`
→ Runtime drops from ~7min to ~40sec, rate limit raised from 5 to 50 req/30s

**2. Activate Lemlist campaign**
→ Open Lemlist UI → Security Outbound V1 → assign sender → activate
→ Then run: `python pipeline.py --writeback`
→ This is the blocker for any outreach to happen

**3. ~~Get free VirusTotal API key~~ ✓ Done (24 June 2026)**
→ Key configured in `.env`. Now used as fallback only — HTTP fingerprinting runs first.

**4. ~~SSL Labs integration~~ ✓ Done (24 June 2026)**
→ `query_ssl_labs()` added. Pulls SSL grade + cert expiry from cache. No key needed.

**5. ~~Whois integration~~ ✓ Done (24 June 2026)**
→ `query_whois()` added. Domain age + registrar via system CLI. Handles EU TLDs.

**6. ~~Shodan InternetDB~~ ✓ Done (29 June 2026)**
→ `query_shodan_internetdb()` added. Free, no key. Live ports + CVE IDs for indexed IPs.

**7. ~~Direct HTTP fingerprinting~~ ✓ Done (29 June 2026)**
→ `fingerprint_http()` added. Parses `Server:`/`X-Powered-By:`/HTML directly. Priority 1 tech source.

**8. ~~CISA KEV cross-reference~~ ✓ Done (29 June 2026)**
→ `load_cisa_kev()` added. Flags CVEs on CISA's actively-exploited list. New `{{exploited_in_wild}}` variable.

### Soon (paid or ~1hr effort)

**9. HIBP API key (~$4/mo)**
→ haveibeenpwned.com/API/Key
→ Unlocks `breach_date` and `compliance_flag` variables for GDPR angle messages
→ Enables `has_breach` tagging and the second message angle

**10. Shodan paid ($69/mo)**
→ Deeper live scanning — version-accurate banners for CDN-fronted and less-common hosts
→ Worth it post-MVP once message angles are validated

### Later (2hrs+ effort)

**9. GitHub Actions weekly cron**
→ `.github/workflows/sec-intel.yml` with `schedule: cron: '0 9 * * 1'`
→ Run `pipeline.py --writeback` weekly
→ JSON diff against previous run → Slack/email alert on new Critical/High CVEs
→ Lemlist always has the latest intel without manual runs

**10. BuiltWith API for tech stack**
→ Full tech stack per domain including framework versions
→ Feeds directly into CPE-based NVD lookups
→ Free tier: 1 lookup/domain, paid from $295/mo — evaluate post-MVP

**11. Lead scoring model**
→ Priority score = CVSS_score × recency_weight + breach_recency + regulated_industry_flag
→ Re-order Lemlist leads by score before activating sequence
→ Highest-signal leads get contacted first

---

## Files in This Project

| File | Purpose |
|---|---|
| `pipeline.py` | Main enrichment script — run this |
| `.env` | API keys (never commit) |
| `.env.example` | Template for keys — safe to commit |
| `.gitignore` | Blocks `.env` and `intel_report.md` from git |
| `intel_report.md` | Generated per run — per-lead CVE/breach data and Lemlist variables |
| `context.md` | Live project context and architecture |
| `sales_draft_1.md` | Blueprint v3 — phases, templates, success criteria |
| `pipeline_report.md` | This file — challenge resolution log |

---

## To Run Right Now

```bash
# 1. Dry run on 3 leads (no changes to Lemlist)
LEMLIST_API_KEY=<your_key> python pipeline.py --limit 3 -v

# 2. Full run on all 23 leads
LEMLIST_API_KEY=<your_key> python pipeline.py

# 3. Full run + push variables to Lemlist (after activating campaign)
LEMLIST_API_KEY=<your_key> python pipeline.py --writeback
```

Or set `LEMLIST_API_KEY` in `.env` and run without the prefix.
