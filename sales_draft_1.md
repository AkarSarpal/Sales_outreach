# Security-Enriched LinkedIn Outbound — Blueprint v4

## What Changed from v3

v3 replaced manual Claude prompts with `pipeline.py` but still relied on VirusTotal passive cache as the primary tech stack source, giving keyword-matched CVEs rather than version-accurate ones. v4 adds three free upgrades that require no new API keys:

- **Shodan InternetDB** — resolves each domain to an IP and queries Shodan's free public endpoint. Returns real open ports and version-accurate CVE IDs matched to that specific IP. Replaces the need for Censys (removed June 2026) or Shodan paid for most leads.
- **Direct HTTP fingerprinting** — `GET`s the domain and reads `Server:`/`X-Powered-By:`/HTML for tech stack. More current than any passive cache. VirusTotal is now fallback-only.
- **CISA KEV cross-reference** — downloads CISA's Known Exploited Vulnerabilities catalog (free) and flags CVEs being actively exploited in the wild. Adds `{{exploited_in_wild}}` as a new Lemlist variable — strongest possible outreach signal.

---

## Core Architecture

```
ICP Sourcing (Claude Desktop + Lemlist MCP)
     ↓
pipeline.py  ←  Shodan InternetDB  — live ports + CVE IDs per IP (free, no key)
             ←  Direct HTTP probe  — tech stack from headers + HTML (free, no key)
             ←  CISA KEV catalog   — actively exploited CVE flag (free, no key)
             ←  NVD REST API       — CVE details + CVSS scores
             ←  VirusTotal         — passive tech hints (fallback only)
             ←  SSL Labs           — cached SSL grade (free, no key)
             ←  Whois CLI          — domain age (free, no key)
             ←  HIBP               — breach history (optional, ~$4/mo)
     ↓
--writeback  →  Lemlist custom variables per lead
     ↓
Lemlist sequence (configured manually in UI)
     ↓
Monitor replies → iterate
```

---

## Phase 1: MCP Setup

Connect Lemlist to Claude Desktop.

1. Add the Lemlist MCP server to `~/Library/Application Support/Claude/claude_desktop_config.json`
2. Restart Claude Desktop and authenticate via OAuth (no API keys needed)
3. Verify: *"List my active Lemlist campaigns"*

The MCP is used for lead sourcing and monitoring. Enrichment is handled by `pipeline.py` directly — the MCP is not required to run the pipeline.

---

## Phase 2: ICP Sourcing

**Prompt:**
> "Find 50 [Job Title]s at [Industry] companies in [Geography] with [X–Y] employees. Deduplicate against my existing contacts. Create a campaign called 'Security Outbound V1' in Lemlist and import the leads."

Start at 50 leads. Run the pipeline on a sample before scaling.

---

## Phase 3: Security Intel Pipeline

Phase 3 is a single command. No manual prompting needed.

### Setup (one-time)

```bash
pip install requests
cp .env.example .env
# Required:  LEMLIST_API_KEY
# Optional:  NVD_API_KEY      (free, 5min — cuts runtime 7min → 40sec)
#            VIRUSTOTAL_API_KEY (free — used as fallback if HTTP probe fails)
#            HIBP_API_KEY      (~$4/mo — enables breach angle and GDPR messaging)
# No key needed for: Shodan InternetDB, CISA KEV, direct HTTP probe, SSL Labs, Whois
```

### Run

```bash
# Dry run — generates intel_report.md, no changes to Lemlist
python pipeline.py

# Push variables to Lemlist leads (activate campaign in UI first)
python pipeline.py --writeback

# Test on 3 leads first, verbose output
python pipeline.py --limit 3 -v
```

### What the pipeline does per lead

1. **Fetch from Lemlist** — reads all leads + contacts from the campaign via API
2. **Resolve domain** — from lead's work email (`john@bureauveritas.com` → `bureauveritas.com`). No guessing.
3. **Direct HTTP fingerprint** — `GET https://domain`, parses `Server:`, `X-Powered-By:`, `X-Generator:` and HTML. Free, no key.
4. **Shodan InternetDB** — resolves domain → IP, queries `internetdb.shodan.io/{ip}`. Returns open ports + version-accurate CVE IDs. Free, no key. Detects CDN and falls back gracefully.
5. **VirusTotal** — fallback tech stack from passive HTTP headers when HTTP probe returns nothing.
6. **SSL Labs** — cached SSL grade (A–F) and cert expiry. Free, no key.
7. **Whois** — domain age and registrar. System CLI, no key.
8. **CVE lookup** — if InternetDB has CVE IDs (live path): looks up top CVE in NVD by ID. If not (fallback): keyword searches NVD against detected tech stack.
9. **CISA KEV** — cross-references found CVEs against CISA's actively-exploited list. Free, no key.
10. **HIBP** — breach check per domain. Requires paid key.
11. **Tag lead** — `has_cve`, `has_breach`, or `no_findings`
12. **Write back** — with `--writeback`, patches variables to each Lemlist lead

### Lemlist variables injected

| Variable | Example | Source |
|---|---|---|
| `{{cvss_score}}` | `8.8` | NVD CVSS score |
| `{{key_cve}}` | `CVE-2024-38475` | Top CVE ID |
| `{{key_risk}}` | `HIGH` | CVE severity label |
| `{{exposed_service}}` | `Apache HTTP Server` | Tech stack / InternetDB |
| `{{exposed_ports}}` | `80,443,8080` | Shodan InternetDB (live) or `unknown` |
| `{{ssl_grade}}` | `B` | SSL Labs cached scan |
| `{{domain_age}}` | `12y` | Whois creation date |
| `{{breach_date}}` | `2024-03-15` | HIBP (requires key) |
| `{{compliance_flag}}` | `GDPR breach flagged` | Set when breach found |
| `{{exploited_in_wild}}` | `Yes — CISA KEV` | Set when CVE is on CISA's KEV list |
| `{{lemlistTag}}` | `has_cve` | Lead classification — drives message variant |

Each finding carries `data_source: live_scan` (InternetDB had data) or `inferred` (keyword-matched fallback).

### Data sources

| Source | What it gives | Cost | Status |
|---|---|---|---|
| Shodan InternetDB | Live ports + version-accurate CVE IDs | Free, no key | ✓ Active |
| Direct HTTP probe | Tech stack from headers + HTML | Free, no key | ✓ Active |
| CISA KEV catalog | Actively exploited CVE flag | Free, no key | ✓ Active |
| NVD (nvd.nist.gov) | CVE CVSS scores + descriptions | Free (key speeds up) | ✓ Active |
| VirusTotal | Passive tech hints (fallback) | Free (500/day) | ✓ Active — key configured |
| SSL Labs | SSL grade (A–F) + cert expiry | Free, no key | ✓ Active |
| Whois | Domain age + registrar | Free, CLI | ✓ Active |
| HIBP | Domain breach history | ~$4/mo | Optional — key not configured |
| Shodan (full) | Deep live port/service scanning | $69/mo | Not used — post-MVP |
| Censys | Live port/service scanning | Free API removed June 2026 | Not available |

---

## Phase 4: Configure Sequence in Lemlist UI

**Do this manually — no code needed.**

Recommended 4-step structure:

- **Step 1 (Day 1):** LinkedIn Profile Visit
- **Step 2 (Day 1, +2h):** Connection Request — no note
- **Step 3 (Day 3):** Opening message (security angle)
- **Step 4 (Day 7):** Follow-up if no reply

### Message Templates

**Step 3 — CVE angle + CISA KEV** (use when `lemlistTag = has_cve` and `exploited_in_wild` is set):

> "Hey {{firstName}} — did some research on {{companyName}} before reaching out. Found CVE {{key_cve}} (CVSS {{cvss_score}}) affecting {{exposed_service}} — and it's on CISA's list of vulnerabilities being actively exploited right now. Teams in [industry] are often surprised how long these stay unpatched. Worth 15 min to show you what we found?"

**Step 3 — CVE angle** (use when `lemlistTag = has_cve`, no KEV flag):

> "Hey {{firstName}} — did some research on {{companyName}} before reaching out. Found an active CVE ({{key_cve}}, CVSS {{cvss_score}}) affecting {{exposed_service}} that's still showing up in public scans. Teams in [industry] are often surprised how long these stay unpatched. Worth 15 min to show you what we found?"

**Step 3 — Breach angle** (use when `lemlistTag = has_breach`):

> "Hey {{firstName}} — {{companyName}} showed up in a breach dataset from {{breach_date}}. Given how actively GDPR enforcement is moving right now, a lot of [industry] teams are quietly auditing their exposure. Thought this might be timely."

**Step 3 — Generic fallback** (use when `lemlistTag = no_findings`):

> "Hey {{firstName}} — we work with a lot of [industry] teams on reducing their external attack surface before it becomes an incident. Would it make sense to show you what we typically find in a 20-minute scan?"

**Step 4 — Follow-up:**

> "Didn't want this to get lost, {{firstName}}. If the timing's off, just say the word — otherwise I'm happy to share the full report."

### Tag logic

Set these conditions in Lemlist before activating the sequence:
- `lemlistTag = has_cve` + `exploited_in_wild` set → KEV-angle message (strongest)
- `lemlistTag = has_cve` → CVE-angle message
- `lemlistTag = has_breach` → compliance-angle message
- `lemlistTag = no_findings` → generic ICP pain or deprioritize

---

## Phase 5: Monitor and Iterate

### Weekly stats pull (via Claude Desktop + Lemlist MCP):
> "Pull stats for 'Security Outbound V1': connection acceptance rate, Step 3 reply rate, Step 4 reply rate. Flag anything below: acceptance < 30%, Step 3 reply < 5%."

### If reply rate < 5%:
> "Rewrite the Step 3 message for `has_cve` leads — make the opening more specific to what we found, less generic. Show me the new copy before I update Lemlist."

Always review AI-generated copy that references real CVE data before it goes live — check the CVE is recent and the description is accurate.

### Re-run pipeline for fresh intel:
```bash
python pipeline.py --writeback
```

Run weekly or when new leads are added. Updated scores overwrite the previous values in Lemlist automatically.

---

## MVP Success Criteria

Before expanding or automating:

- [ ] Connection acceptance rate ≥ 30%
- [ ] Step 3 reply rate ≥ 5%
- [ ] Pipeline returning usable findings for ≥ 60% of leads
- [ ] No LinkedIn account warnings
- [ ] ≥ 3 replies referencing the CVE or breach angle specifically

---

## What Comes After the MVP

- **HIBP key (~$4/mo)** — unlocks breach angle, GDPR messaging, `has_breach` tag
- **NVD free key** — cuts runtime 7min → 40sec
- **Shodan paid ($69/mo)** — deeper live scanning, version-accurate banners for all hosts
- **BuiltWith API** — full tech stack per domain including framework versions → sharper CVE targeting
- **Lead scoring model** — weight by: CVSS score + CISA KEV flag + breach recency + regulated industry
- **GitHub Actions cron** — weekly pipeline re-run + diff alert on new Critical/High CVEs
- **MCP sequence automation** — automate tag-based message selection once angles are validated
