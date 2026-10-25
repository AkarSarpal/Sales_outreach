# Cyberdebunk — Claude Code Instructions

## ⚠ CRITICAL RULES — READ FIRST

1. **Never delete any file, variable, function, or data without explicit confirmation from the user first.** If a change would remove something, ask before proceeding — even if it looks unused or redundant.
2. **Never commit `.env`** — it contains real API keys. It is gitignored. `.env.example` is the committed template and must never contain real key values.
3. **Never push to remote** unless the user explicitly asks.
4. **Never modify `intel_report.md`** — it is a generated output file, gitignored, overwritten on each pipeline run.

---

## What This Project Is

A security-enriched LinkedIn outbound system. `pipeline.py` pulls leads from a Lemlist campaign, enriches each company with real security data (CVEs, SSL grade, domain age, breach history), and writes personalised variables back to Lemlist for cold outreach.

**Current campaign:** Security Outbound V1 (`cam_D4cKonCgWRYoNiEDR`) — 23 leads, Draft status (not yet activated).

---

## Key Commands

```bash
# Dry run — enriches all leads, writes intel_report.md, no Lemlist changes
python pipeline.py

# Test on first 3 leads with verbose output
python pipeline.py --limit 3 -v

# Push enriched variables to Lemlist (activate campaign in UI first)
python pipeline.py --writeback

# Override campaign or output path
python pipeline.py --campaign cam_XYZ --output reports/2026-07-01.md
```

---

## Project Files

| File | Purpose | Edit? |
|---|---|---|
| `pipeline.py` | Main enrichment script | Yes |
| `.env` | Real API keys — never commit | Yes (local only) |
| `.env.example` | Key template — committed, no real values | Yes |
| `CLAUDE.md` | This file — project instructions for Claude | Yes |
| `README.md` | Full product documentation | Yes |
| `context.md` | Live project state, pipeline status, next steps | Yes |
| `sales_draft_1.md` | Blueprint v5 — phases, templates, success criteria | Yes |
| `pipeline_report.md` | Dev log — challenge resolutions, session history | Append only |
| `intel_report.md` | Generated output per run — gitignored | Never |
| `required_templates.md` | Lemlist message templates | Yes |
| `challenges.pdf` | Original June 18 challenges report | Read only |

---

## Pipeline Architecture

```
pipeline.py per lead:
  1. Fetch lead from Lemlist API
  2. Resolve domain from work email
  3. Direct HTTP fingerprint  →  tech stack (free, no key)
  4. Shodan InternetDB         →  live ports + CVE IDs + risky-port flag (free, no key)
  5. VirusTotal                →  tech stack fallback (500/day free key)
  6. SSL Labs                  →  SSL grade + cert expiry (free, no key)
  7. Whois CLI                 →  domain age + registrar (free, no key)
  8. NVD REST API              →  CVE details + CVSS (up to 5 IDs/lead, KEV first)
  9. CISA KEV catalog          →  actively-exploited flag on every CVE (free, no key)
 10. HIBP                      →  breach history (optional, ~$4/mo key)
 11. Tag: has_cve / has_breach / no_findings
 12. Write 12 variables to Lemlist via --writeback
```

---

## Lemlist Variables (12 total)

`{{cvss_score}}` `{{key_cve}}` `{{key_risk}}` `{{exposed_service}}` `{{exposed_ports}}` `{{risky_ports}}` `{{ssl_grade}}` `{{domain_age}}` `{{breach_date}}` `{{compliance_flag}}` `{{exploited_in_wild}}` `{{lemlistTag}}`

`{{exploited_in_wild}}` = `"Yes — CISA KEV"` when the CVE is on CISA's actively-exploited list.
`{{risky_ports}}` = high-risk ports exposed to the internet, e.g. `"3306 (MySQL)"` — empty if none or CDN-fronted.
Top CVE selection: KEV-listed first, then highest CVSS (not InternetDB list order).
`{{lemlistTag}}` drives message variant: `has_cve`, `has_breach`, or `no_findings`.

---

## API Keys (current state)

| Key | Status | Impact |
|---|---|---|
| `LEMLIST_API_KEY` | ✅ Configured | Required to run |
| `VIRUSTOTAL_API_KEY` | ✅ Configured | Tech stack fallback |
| `NVD_API_KEY` | ❌ Not set | Pipeline runs in slow mode (~7min). Free key: nvd.nist.gov |
| `HIBP_API_KEY` | ❌ Not set | Breach angle disabled. ~$4/mo: haveibeenpwned.com/API/Key |

**Free sources that need no key at all:** Shodan InternetDB, CISA KEV, direct HTTP probe, SSL Labs, Whois CLI.

---

## Constraints

- Lemlist sequence config is done **manually in the UI** — `pipeline.py` is enrichment only
- CVE copy that references real vulnerability data **must be reviewed by a human** before going live
- `data_source: live_scan` = InternetDB had indexed data for that IP (version-accurate)
- `data_source: inferred` = keyword-matched fallback (real CVEs, not version-specific)
- CDN-fronted domains (Cloudflare etc.) are detected and fall back to inferred mode

---

## What To Do Next

1. **Activate campaign** in Lemlist UI (assign sender → activate)
2. Run `python pipeline.py --writeback`
3. Get free NVD key at nvd.nist.gov → add `NVD_API_KEY` to `.env`
4. Get HIBP key (~$4/mo) → add `HIBP_API_KEY` to `.env` for breach angle

---

## When Updating Files

- **`pipeline_report.md`** — append new sessions, never rewrite history
- **`context.md`** — keep the "as of" date current, update pipeline state and blockers
- **`sales_draft_1.md`** — bump version number when architecture changes
- **`README.md`** — keep in sync with `pipeline.py` — variables, flags, data sources
- Always update all docs together when `pipeline.py` changes
