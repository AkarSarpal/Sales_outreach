# Cyberdebunk — Project Context

## What This Is

A security-enriched LinkedIn outbound system. The core idea: use real, public security and compliance data (CVEs, breaches, GDPR fines) to personalize cold outreach at the lead level. Lemlist handles delivery; a Python pipeline + Claude handles enrichment.

## Current Campaign State (as of 29 June 2026)

- **Campaign:** Security Outbound V1 (`cam_D4cKonCgWRYoNiEDR`)
- **Status:** Draft — 0 messages sent
- **Leads:** 23 leads across 20 unique companies
- **Pipeline runs completed:** 2 sessions (18 June, 24 June 2026)
- **Blockers resolved:** 3 of 4 high-priority blockers have workarounds in place
- **Remaining hard blocker:** Campaign not yet activated (no outreach sent)

## Architecture

1. **ICP Sourcing** — Find leads via AI prompt, import to Lemlist campaign
2. **Security Intel Pipeline** — Per-company data pull via Python script (`pipeline.py`)
3. **Enrichment Injection** — Findings pushed into Lemlist as custom variables
4. **Sequence (manual in Lemlist UI)** — 4-step LinkedIn sequence using enriched templates
5. **Monitoring** — Weekly stats pull via agent, manual copy iteration

## Pipeline State

| Component | Status |
|---|---|
| Lemlist lead read | Fully operational |
| Domain resolution (from work email) | Fully operational |
| Direct HTTP fingerprinting | **Active — free, no key** (new) |
| Shodan InternetDB (ports + CVEs per IP) | **Active — free, no key** (new) |
| CISA KEV cross-reference | **Active — free, no key** (new) |
| VirusTotal tech stack hints | Active — key configured, 500 req/day (fallback) |
| SSL Labs grade + cert expiry | Active — cached lookup, no key required |
| Whois domain age + registrar | Active — system CLI |
| NVD CVE lookup | Operational — rate-limited without API key |
| HIBP breach lookup | Disabled — key not configured |
| Lemlist write-back (custom variables) | Operational |
| Censys port/service scanning | Unavailable — free API removed June 2026 |
| Shodan (full) live scanning | Unavailable — requires $69/mo paid key |

## Data Sources

| Type | Sources |
|---|---|
| CVE / vulnerability | Shodan InternetDB (version-accurate CVE IDs, free) → NVD (CVSS + details). Fallback: NVD keyword search |
| Actively exploited CVEs | CISA KEV feed — free, ~1,100 CVEs being exploited in the wild |
| Tech stack | Direct HTTP fingerprint (Server/X-Powered-By headers + HTML) → VirusTotal passive cache → CPEs from InternetDB |
| Live ports | Shodan InternetDB (free, IP-based) |
| SSL / cert intel | SSL Labs (ssllabs.com) — cached grade + cert expiry, no key required |
| Domain intel | Whois CLI — domain age, registrar |
| Compliance / breach | HIBP API (key not configured), GDPR registries |
| Full live scanning | Censys free API removed June 2026. Shodan $69/mo — not active |

## Lemlist Custom Variables (injected per lead)

`{{cvss_score}}`, `{{key_cve}}`, `{{key_risk}}`, `{{exposed_service}}`, `{{exposed_ports}}`, `{{ssl_grade}}`, `{{domain_age}}`, `{{breach_date}}`, `{{compliance_flag}}`, `{{exploited_in_wild}}`, `{{lemlistTag}}`

`{{exploited_in_wild}}` = `"Yes — CISA KEV"` when the top CVE is on CISA's actively-exploited list. This is the strongest signal for outreach copy — use it to add urgency to the CVE angle message.

Each enrichment entry also carries a `data_source` field (`live_scan` vs `inferred`) so downstream users know which findings are version-accurate vs keyword-matched.

## Known Challenges & Current Solutions

### HIGH — Campaign in Draft, 0 messages sent
- **Impact:** All security intel gathered is unused until campaign is activated
- **Action:** Activate in Lemlist UI (assign sender → activate), then run `python pipeline.py --writeback`

### PARTIALLY RESOLVED — CVEs matched to generic tech defaults (inferred mode)
- **Previous state:** CVEs matched to generic Apache/nginx/IIS defaults
- **Now:** Three-layer tech stack detection: (1) direct HTTP fingerprinting of domain headers + HTML, (2) Shodan InternetDB returns CPE strings with version info, (3) VirusTotal passive cache as fallback. When InternetDB has CVE data for the IP, CVE IDs are version-accurate (Shodan fingerprint) rather than keyword-matched.
- **Remaining gap:** Domains behind Cloudflare/CDN hide origin server — InternetDB returns CDN data. Shodan paid ($69/mo) gives deeper version-accurate service banners.

### MEDIUM — NVD rate limit without API key
- **Impact:** 5 req/30s cap → ~7 min runtime for 23 leads
- **Solution:** Auto-detects `NVD_API_KEY` and adjusts sleep. Get free key at nvd.nist.gov → add `NVD_API_KEY` to `.env` → cuts runtime to ~40sec

### MEDIUM — No breach data
- **Impact:** `breach_date` and `compliance_flag` always empty — GDPR angle unavailable
- **Action:** HIBP API key (~$4/mo at haveibeenpwned.com/API/Key) → add `HIBP_API_KEY` to `.env`

### RESOLVED — Domain resolution
- ✓ Domains extracted from work email (e.g. `erikjan@bureauveritas.com` → `bureauveritas.com`). EU TLDs resolve correctly.

### RESOLVED — Censys free API + live scanning gap
- ✓ Replaced with **Shodan InternetDB** (free, no key). Resolves domain → IP, returns real ports and version-accurate CVE IDs from Shodan's fingerprint database. For hosts not in InternetDB or behind CDN, falls back to HTTP fingerprinting + VirusTotal + NVD keyword search.

### LOW — No automated re-run trigger
- **Solution path:** GitHub Actions weekly cron + JSON diff alert on new Critical/High CVEs → Lemlist write-back

## Message Angle Logic

| Lead tag | Message angle |
|---|---|
| `has_cve` | Reference specific CVE + CVSS score + exposed service |
| `has_breach` | Reference breach date + GDPR enforcement climate |
| `no_findings` | Generic ICP-pain message or deprioritize |

## Key Constraints

- Lemlist sequence config is done **manually in the UI** — pipeline is enrichment only, not sequence automation (MVP phase)
- Claude synthesis is **knowledge-based fallback** when live scan fails — label findings accordingly
- AI-generated copy using CVE data needs **human review** before going live
- Lemlist API exposes campaign-level stats but not A/B test results in structured form

## Prioritized Next Steps

| Priority | Action | Effort | Status |
|---|---|---|---|
| **Now** | Activate campaign in Lemlist UI → run `python pipeline.py --writeback` | 15 min | Blocking |
| **Now** | Get free NVD API key (nvd.nist.gov) → add `NVD_API_KEY` to `.env` | 5 min | Not done |
| **Soon** | HIBP API key (~$4/mo) → unlocks `breach_date`, `compliance_flag`, `has_breach` tag | 10 min | Not done |
| **Later** | Shodan paid ($69/mo) — deeper live scanning for hosts behind CDN or not in InternetDB | — | Post-MVP |
| **Later** | GitHub Actions weekly cron — auto re-run + diff alert on new Critical/High CVEs | 2 hrs | Post-MVP |

## MVP Thresholds (before expanding)

- Connection acceptance ≥ 30%
- Step 3 reply rate ≥ 5%
- Security intel returning usable findings for ≥ 60% of leads
- No LinkedIn account warnings
- ≥ 3 replies referencing the CVE/compliance angle

## Post-MVP Roadmap

- MCP automation for sequence updates (once angles are validated)
- BuiltWith API for tech stack detection → better CVE targeting
- Lead scoring model: high CVSS + recent breach + regulated industry = priority
- Evaluate replacing Lemlist with a lighter delivery layer at volume
- Wappalyzer fingerprints for version-accurate CPE-based CVE lookups
- GitHub Actions weekly cron for pipeline re-runs + diff alerting

## Tooling

- **Python script:** `pipeline.py` — runs enrichment, supports `--writeback` flag
- **Shodan InternetDB** — `internetdb.shodan.io/{ip}` — free, no key — live ports + CVE IDs per IP
- **Direct HTTP fingerprinting** — `GET domain`, parses headers + HTML — free, no key
- **CISA KEV catalog** — `cisa.gov/feeds/known_exploited_vulnerabilities.json` — free, no key
- **NVD REST API v2** — CVE lookup with adaptive rate limiting
- **VirusTotal free tier** — passive HTTP headers for tech stack (fallback only, key configured)
- **SSL Labs** — cached SSL grade + cert expiry per domain (free, no key)
- **Whois CLI** — domain age and registrar (system tool, no setup)
- **HIBP** — domain breach lookup (key not yet configured, ~$4/mo)
- **Claude Desktop + Lemlist MCP** — agent interface for ICP sourcing and monitoring
- **Lemlist** — campaign delivery and sequence execution
- **Config:** API keys in `.env` (never commit); `.env` in `.gitignore`
