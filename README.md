# Cyberdebunk — Security Intelligence Pipeline

Enriches Lemlist leads with real public security data (CVEs, SSL grades, domain age, breach history) and pushes personalised variables back to Lemlist for cold outreach at scale.

---

## Architecture

```
ICP Sourcing  (Claude Desktop + Lemlist MCP)
      ↓
pipeline.py  ←  Shodan InternetDB  — live ports + version-accurate CVE IDs (free, no key)
             ←  Direct HTTP probe  — tech stack from headers + HTML (free, no key)
             ←  CISA KEV catalog   — actively exploited CVE flag (free, no key)
             ←  NVD REST API       — CVE details + CVSS scores
             ←  VirusTotal         — passive tech hints (fallback, 500/day free)
             ←  SSL Labs           — cached SSL grade (free, no key)
             ←  Whois CLI          — domain age (free, no key)
             ←  HIBP               — breach history (optional, ~$4/mo)
      ↓
--writeback  →  Lemlist custom variables per lead
      ↓
Lemlist LinkedIn sequence  (configured manually in UI)
      ↓
Monitor replies → iterate copy
```

---

## Quick Start

```bash
# 1. Install dependency
pip install requests

# 2. Copy and fill in env file
cp .env.example .env
# Required: LEMLIST_API_KEY
# Recommended: NVD_API_KEY (cuts runtime 7min → 40sec)

# 3. Dry run — generates intel_report.md, no changes to Lemlist
python pipeline.py

# 4. Test on 3 leads first
python pipeline.py --limit 3 -v

# 5. Push all variables to Lemlist
python pipeline.py --writeback
```

---

## Setup

### Prerequisites

- Python 3.10+
- `requests` library (`pip install requests`)
- `whois` CLI available on system (pre-installed on macOS/Linux)
- A Lemlist account with at least one campaign containing leads

### Environment variables

Copy `.env.example` to `.env` and fill in the values.

```
LEMLIST_API_KEY=          # required — Lemlist › Settings › Integrations
LEMLIST_CAMPAIGN_ID=      # optional — overrides the default campaign ID hardcoded in pipeline.py
NVD_API_KEY=              # recommended free key — nvd.nist.gov/developers/request-an-api-key
VIRUSTOTAL_API_KEY=       # free (500 req/day) — virustotal.com/gui/join-us
HIBP_API_KEY=             # optional paid (~$4/mo) — haveibeenpwned.com/API/Key
CENSYS_API_ID=            # deprecated — free API removed June 2026, leave blank
CENSYS_API_SECRET=        # deprecated — leave blank
ANTHROPIC_API_KEY=        # optional — for future Claude synthesis features
```

---

## Running the Pipeline

### All command-line options

```
python pipeline.py [OPTIONS]

Options:
  --writeback           Push enriched variables to Lemlist after enrichment
  --limit N             Process only the first N leads (useful for testing)
  --campaign <id>       Override the campaign ID from .env / hardcoded default
  --hibp-key <key>      Pass HIBP key directly (alternative to env var)
  --output <file>       Path for the generated report (default: intel_report.md)
  -v, --verbose         Print per-lead tech stack, CVE counts, SSL grade, domain age
```

### Common usage patterns

```bash
# Dry run — read Lemlist, enrich, write intel_report.md (no Lemlist changes)
python pipeline.py

# Verbose dry run on first 3 leads — shows SSL grade, domain age, CVE counts
python pipeline.py --limit 3 -v

# Full dry run on all leads, verbose
python pipeline.py -v

# Enrich and push variables to Lemlist (activate campaign in Lemlist UI first)
python pipeline.py --writeback

# Override campaign ID inline
python pipeline.py --campaign cam_ABC123 --writeback

# Custom report output path
python pipeline.py --output reports/june_run.md

# Pass HIBP key directly without setting env var
python pipeline.py --hibp-key <your_key> --writeback
```

---

## What the Pipeline Does Per Lead

1. **Fetch leads from Lemlist** — reads all leads and their full contact records from the campaign via the Lemlist REST API.
2. **Resolve company domain** — extracts the domain directly from the lead's work email (e.g. `john@bureauveritas.com` → `bureauveritas.com`). Personal email domains (gmail, outlook, etc.) are skipped.
3. **Extract company name** — parsed from the LinkedIn tagline (`"CISO at MindDoc"` → `MindDoc`). Falls back to title-casing the domain root.
4. **Direct HTTP fingerprinting** — fetches the domain (`https://` then `http://` fallback) and parses `Server:`, `X-Powered-By:`, `X-Generator:` headers and HTML source. Free, no key, more current than any passive cache.
5. **Shodan InternetDB** — resolves the domain to an IP and queries `internetdb.shodan.io/{ip}`. Returns real open ports, version-accurate CVE IDs, CPE strings, and tags. Free, no API key. Falls back gracefully when IP is behind a CDN or has no data.
6. **VirusTotal tech stack** — only called when HTTP fingerprinting returned nothing and InternetDB has no data. Queries VT passive HTTP cache as a last resort for tech stack hints.
7. **SSL Labs grade** — fetches a cached scan from SSL Labs (`fromCache=on`). Returns SSL grade (A–F) and certificate expiry. Never triggers a new scan; no key required.
8. **Whois domain age** — shells to system `whois`, parses creation date across multiple formats. Returns domain age and registrar. Handles EU TLDs (`.de`, `.nl`, `.fr`, `.es`).
9. **CVE lookup** — if InternetDB returned CVE IDs (live path): looks up the top CVE in NVD by ID for CVSS score and description. If no InternetDB data (fallback path): keyword searches NVD across up to 6 detected tech stack items.
10. **CISA KEV cross-reference** — checks every found CVE against CISA's Known Exploited Vulnerabilities feed. A KEV hit means the CVE is being actively exploited in the wild — sets `exploited_in_wild = "Yes — CISA KEV"`.
11. **HIBP breach check** — queries Have I Been Pwned for domain breaches in the last 24 months. Requires a paid API key (~$4/mo). Skipped silently if key is absent.
12. **Tag the lead** — assigns one of three tags: `has_cve`, `has_breach`, or `no_findings`.
13. **Write back to Lemlist** — with `--writeback`, patches all enriched variables to each Lemlist lead by email address.

---

## Lemlist Variables Injected

These are available as `{{variable}}` tokens in Lemlist message templates after `--writeback`.

| Variable | Example | What it is |
|---|---|---|
| `{{cvss_score}}` | `8.8` | CVSS base score of the highest-severity CVE found |
| `{{key_cve}}` | `CVE-2024-38475` | CVE ID of the top finding |
| `{{key_risk}}` | `HIGH` | Severity label of the top CVE |
| `{{exposed_service}}` | `Apache HTTP Server` | Primary service associated with the CVE |
| `{{exposed_ports}}` | `80,443,8080` | Detected open ports (live scan only; `unknown` in inferred mode) |
| `{{ssl_grade}}` | `B` | SSL Labs grade for the company domain |
| `{{domain_age}}` | `12y` | Age of the company domain |
| `{{breach_date}}` | `2024-03-15` | Date of most recent domain breach (HIBP, requires key) |
| `{{compliance_flag}}` | `GDPR breach flagged` | Set when a breach is found (empty otherwise) |
| `{{exploited_in_wild}}` | `Yes — CISA KEV` | Set when the CVE is on CISA's actively-exploited list (empty otherwise) |
| `{{lemlistTag}}` | `has_cve` | Lead classification tag — drives which message variant is sent |

---

## Output: intel_report.md

Generated on every run. Gitignored — never committed.

Sections:
- **Run Summary** — total leads, breakdown by tag, usable intel rate vs 60% MVP threshold, writeback status
- **Lead Table** — one row per lead: company, domain, tag, CVE ID, CVSS score, SSL grade, domain age, breach date
- **Lead Details** — per-lead: tech stack detected, full CVE details with NVD link, SSL grade and cert expiry, domain age and registrar, breach info, and a preview of every Lemlist variable value

To save a run snapshot:
```bash
python pipeline.py --output reports/$(date +%Y-%m-%d).md
```

---

## Phase 1: Lemlist MCP Setup (optional — for lead sourcing via Claude)

Connect Lemlist to Claude Desktop to source and manage leads without leaving the chat.

1. Add the Lemlist MCP server to `~/Library/Application Support/Claude/claude_desktop_config.json`
2. Restart Claude Desktop and authenticate via OAuth
3. Verify: *"List my active Lemlist campaigns"*

The MCP is used for ICP sourcing, campaign creation, and monitoring. Enrichment is handled by `pipeline.py` — the MCP is not needed for the pipeline itself.

---

## Phase 2: ICP Sourcing

Use this prompt in Claude Desktop with the Lemlist MCP connected:

> "Find 50 [Job Title]s at [Industry] companies in [Geography] with [X–Y] employees. Deduplicate against my existing contacts. Create a campaign called 'Security Outbound V1' in Lemlist and import the leads."

Start with 50 leads. Validate enrichment quality before scaling.

---

## Phase 3: Security Intel Pipeline

The pipeline from Phase 3 onwards is the `pipeline.py` script. Run as described above.

Recommended first run:
```bash
python pipeline.py --limit 3 -v    # inspect 3 leads before processing all
python pipeline.py                 # full dry run — verify intel_report.md looks good
python pipeline.py --writeback     # push to Lemlist once satisfied
```

---

## Phase 4: Configure Sequence in Lemlist UI

Do this manually — no code needed. Recommended 4-step LinkedIn sequence:

| Step | Timing | Type | Action |
|---|---|---|---|
| Step 1 | Day 1 | LinkedIn | Profile visit |
| Step 2 | Day 1 +2h | LinkedIn | Connection request — no note |
| Step 3 | Day 3 | LinkedIn | Opening message — security angle |
| Step 4 | Day 7 | LinkedIn | Follow-up if no reply |

### Message templates

**Step 3 — CVE angle** (leads tagged `has_cve`):
> "Hey {{firstName}} — did some research on {{companyName}} before reaching out. Found an active CVE ({{key_cve}}, CVSS {{cvss_score}}) affecting {{exposed_service}} that's still showing up in public scans. Teams in [industry] are often surprised how long these stay unpatched. Worth 15 min to show you what we found?"

**Step 3 — Breach angle** (leads tagged `has_breach`):
> "Hey {{firstName}} — {{companyName}} showed up in a breach dataset from {{breach_date}}. Given how actively GDPR enforcement is moving right now, a lot of [industry] teams are quietly auditing their exposure. Thought this might be timely."

**Step 3 — Generic fallback** (leads tagged `no_findings`):
> "Hey {{firstName}} — we work with a lot of [industry] teams on reducing their external attack surface before it becomes an incident. Would it make sense to show you what we typically find in a 20-minute scan?"

**Step 4 — Follow-up:**
> "Didn't want this to get lost, {{firstName}}. If the timing's off, just say the word — otherwise I'm happy to share the full report."

### Tag-based routing in Lemlist

Set up tag conditions in the sequence before activating:
- `lemlistTag = has_cve` → CVE-angle message
- `lemlistTag = has_breach` → compliance-angle message
- `lemlistTag = no_findings` → generic ICP pain message

---

## Phase 5: Monitor and Iterate

### Weekly stats pull (via Claude Desktop + Lemlist MCP)

> "Pull stats for 'Security Outbound V1': connection acceptance rate, Step 3 reply rate, Step 4 reply rate. Flag anything below: acceptance < 30%, Step 3 reply rate < 5%."

### If reply rate is below target

> "Rewrite the Step 3 message for `has_cve` leads — make the opening more specific to what we found, less generic. Show me the new copy before I update Lemlist."

Always review AI-generated copy that references real CVE data before it goes live. Confirm the CVE is recent and the description is accurate.

### Re-run pipeline for fresh intel

```bash
python pipeline.py --writeback
```

Run weekly or when new leads are added. Updated scores overwrite the previous values in Lemlist automatically.

---

## API Keys

| Key | Required | Cost | Where to get | Impact without it |
|---|---|---|---|---|
| `LEMLIST_API_KEY` | **Yes** | Free | Lemlist › Settings › Integrations | Pipeline cannot run |
| `NVD_API_KEY` | Recommended | Free | nvd.nist.gov/developers/request-an-api-key | Runtime ~7min instead of ~40sec |
| `VIRUSTOTAL_API_KEY` | Recommended | Free (500/day) | virustotal.com/gui/join-us | Tech stack defaults to Apache/nginx/IIS; CVEs less targeted |
| `HIBP_API_KEY` | Optional | ~$4/mo | haveibeenpwned.com/API/Key | `breach_date` and `compliance_flag` always empty; `has_breach` tag never set |
| `CENSYS_API_ID/SECRET` | Not available | — | Removed June 2026 | No live port scanning (pipeline works fine without it) |

---

## Data Sources

| Source | What it provides | Cost | Notes |
|---|---|---|---|
| **Shodan InternetDB** | Live ports, version-accurate CVE IDs, CPE strings per IP | **Free, no key** | New — replaces Censys |
| **Direct HTTP fingerprint** | Tech stack from `Server:`, `X-Powered-By:`, HTML | **Free, no key** | New — more current than VT cache |
| **CISA KEV** | 1,000+ CVEs being actively exploited in the wild | **Free, no key** | New — strongest outreach signal |
| NVD (nvd.nist.gov) | CVE details and CVSS scores | Free | Key optional — speeds up rate limit |
| VirusTotal | Passive tech stack from cached HTTP headers | Free (500/day) | Fallback when HTTP fingerprint fails |
| SSL Labs | SSL grade (A–F) + cert expiry | Free, no key | Cached only — no new scan |
| Whois CLI | Domain age + registrar | Free | System CLI; no setup |
| HIBP | Domain breach history | ~$4/mo | Paid key required |
| Shodan (full) | Live port scanning, version banners | $69/mo | Post-MVP upgrade path |
| Censys | Live port/service scanning | Free API removed June 2026 | Unavailable |

---

## Intel Quality

Every result is labelled `data_source: inferred` or `live_scan`.

**With Shodan InternetDB:** when InternetDB has data for a domain's IP, the result is `live_scan` — ports are real, and CVE IDs are version-accurate matches from Shodan's fingerprint database. InternetDB has coverage on most internet-facing IPs.

**Without InternetDB data:** falls back to `inferred` — CVEs matched against tech stack detected from HTTP headers or VirusTotal cache. Real CVEs, but not version-specific.

**CDN caveat:** if the domain is behind Cloudflare or a similar CDN, InternetDB returns the CDN's IP data, not the origin server's. The pipeline detects this and falls back to keyword search. Flagged in the report.

| Finding type | Accuracy | How it's obtained |
|---|---|---|
| CVE IDs (InternetDB path) | High — version-accurate from Shodan | Shodan InternetDB → NVD by ID |
| CVE IDs (fallback path) | Medium — keyword match to tech stack | NVD keyword search |
| CISA KEV flag | High — directly from CISA feed | Cross-reference against KEV catalog |
| Tech stack | High — direct HTTP headers | `GET domain`, parse `Server:`/`X-Powered-By:`/HTML |
| Exposed ports | High when InternetDB has data | Shodan InternetDB (live) |
| Breach data | High when HIBP key set | HIBP API |
| SSL grade | High — SSL Labs cache | SSL Labs |
| Domain age | High — direct from Whois | System `whois` CLI |

---

## MVP Thresholds

Validate these before expanding or automating:

- [ ] Connection acceptance rate ≥ 30%
- [ ] Step 3 reply rate ≥ 5%
- [ ] Pipeline returning usable intel for ≥ 60% of leads (`has_cve` or `has_breach`)
- [ ] No LinkedIn account warnings
- [ ] ≥ 3 replies referencing the CVE or breach angle specifically

---

## Post-MVP Roadmap

| Priority | Action | Effort | Impact |
|---|---|---|---|
| Soon | HIBP API key (~$4/mo) | 10 min | Unlocks breach angle and GDPR messaging |
| Soon | NVD free API key | 5 min | Cuts runtime 7min → 40sec |
| Soon | ZoomEye free tier (10 searches/day) | 30 min | Shodan alternative for fingerprinting |
| Later | Shodan paid ($69/mo) | — | Live port scanning + version-accurate CVE matching |
| Later | BuiltWith API | Paid from $295/mo | Full tech stack per domain, sharper CVE targeting |
| Later | GitHub Actions weekly cron | 2 hrs | Auto re-run + diff alert on new Critical/High CVEs |
| Later | Lead scoring model | 1 day | Prioritise leads by CVSS × recency × regulated industry |
| Later | MCP sequence automation | 1 day | Auto tag-based message selection once angles validated |

---

## Project Files

| File | Purpose |
|---|---|
| `pipeline.py` | Main enrichment script — run this |
| `.env` | API keys — never commit |
| `.env.example` | Key template — safe to commit |
| `intel_report.md` | Generated per run — per-lead intel preview (gitignored) |
| `context.md` | Live project state — architecture, blockers, pipeline status |
| `sales_draft_1.md` | Blueprint v3 — phases, message templates, success criteria |
| `pipeline_report.md` | Dev log — challenge resolutions and session history |
