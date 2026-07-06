# Test Run Report: Security Outbound V1 (Sourcing + Enrichment)

**Date:** July 6, 2026
**Scope:** Two connected test runs — (1) sourcing 50 new German security-exec leads, (2) running the security intelligence pipeline across the full, merged campaign.

---

## Part 1 — Lead Sourcing

**Objective:** Source 50 security executives at German SMBs and load them into the Security Outbound V1 campaign.

### Target criteria

| Criteria | Definition used |
|---|---|
| Roles | CISO, Chief Information Security Officer, Security Manager, IT Security Manager, Head of Security, Head of Information Security, Security Director, Information Security Officer, IT Security Officer |
| Seniority | Executive Leadership, Department Leadership, Ownership/Firm Leadership |
| Geography | Company headquartered in Germany |
| Company size | 11–500 employees (SMB, above the requested 20-employee floor) |
| Active/engaged accounts | Not filterable — see Known Issues |

### What was done

- Searched Lemlist's People Database (650M+ B2B contact index).
  - Broad search (incl. generic "CEO" title): 48,479 matches — too broad.
  - Narrowed to security-specific titles only: 548 matches — workable pool.
- Pulled and reviewed the top 100 highest-relevance profiles.
- Deduplicated against existing Lemlist contacts — **0 existing contacts found**, every lead net-new.
- Removed 1 exact duplicate, capped at 50 final leads.
- Saved all 50 leads to Lemlist Contacts (CRM) and imported into "Security Outbound V1."

### Result

| Step | Outcome |
|---|---|
| Leads sourced | 50 / 50 requested |
| Existing-contact duplicates found | 0 |
| Leads pushed to Contacts (CRM) | 50 / 50 succeeded |
| Campaign created | ✅ "Security Outbound V1" |
| Leads added to campaign | 50 / 50 added, 0 failed |
| Sequence/messaging | Not built (out of scope for this run) |

### Data quality notes

- 44 of 50 leads have a usable email address; 6 have LinkedIn URLs only (no verified email found).
- 1 lead (Ameen, Qorix) had a malformed scraped email (`ameen.@qorix.ai`) — email field excluded to avoid a bounce; LinkedIn URL retained.

### Known issues from sourcing

- **Stray test lead:** while diagnosing the malformed email above, a placeholder lead (`test.lead@example.com`) was added to isolate the problem. It is still sitting in the campaign — confirmed still present in today's pipeline run (see "Example / example.com" row, Part 2) — and needs to be removed manually in the Lemlist UI; no API tool was available to delete it programmatically.
- **"Active / regularly interacting" filter:** Lemlist's People Database has no field for LinkedIn activity or posting frequency, so this criterion could not be applied directly. Titles/seniority were used as the closest available proxy.

---

## Part 2 — Security Intelligence Pipeline Run

**Objective:** Run `pipeline.py` across the full, merged lead list (original 23 + newly sourced batch) to enrich every lead with CVE, SSL, domain-age, and breach data, and write results back to Lemlist.

### Run summary

| Metric | Value |
|---|---|
| Total leads processed | 51 |
| `has_cve` | 39 |
| `has_breach` | 0 |
| `no_findings` | 12 |
| Usable intel rate | 76% — above the 60% MVP threshold |
| Live scans (Shodan InternetDB) | 8 / 51 |
| CISA KEV — actively exploited | 0 |
| Writeback to Lemlist | Yes |

Of the 12 `no_findings` leads, most have no company/domain on file yet (personal-email or LinkedIn-only contacts from the new sourcing batch) — there's nothing for the pipeline to scan against.

### CVE / vulnerability findings

39 of 51 leads returned a matched CVE. Highlights:

- **Highest severity:** several leads matched CVE-2004-0646 and CVE-2006-4028 at CVSS **10.0** (CRITICAL) — these are old, generic Apache/IIS-era CVEs, not version-specific matches. Treat as conversation starters, not audit-grade findings (see data-source note below).
- **Most current CVE:** CVE-2025-58048 (CVSS 9.9) matched for Diu, Orbem, Aignostics, and the stray Example/test lead.
- **Notably specific:** Akabank matched CVE-2026-29168 (CVSS 7.3) via a live Shodan scan — a recent, version-accurate finding.
- **CISA KEV:** 0 of the 39 matched CVEs are on CISA's actively-exploited list this run — no leads currently carry the "exploited in the wild" urgency signal.
- **No breach data:** `has_breach` = 0 across all 51 leads — HIBP key still not configured, so this angle is fully unavailable (see Known Issues).

### Data source quality — live scan vs. inferred

Only **8 of 51 leads (16%)** got a version-accurate finding via Shodan InternetDB live scan: `adeus.com`, `akabank.de`, `gemakom.de`, `ipb.de`, `luecker.com`, `np4.net`, `perbit.com`, `wk-it.com`.

The remaining 31 CVE-tagged leads are on `inferred` (keyword-matched) data — real CVEs, but not confirmed against the actual running software version. This is the expected pattern for domains behind CDN/Cloudflare or hosts not indexed by Shodan InternetDB, per the known architecture gap.

### SSL / domain age

SSL grades and domain age resolved for the majority of leads with a known domain (mostly the original 23). SSL grades ranged from **A+** (e.g. Basalt, Continum, Np4, Talentsconnect) down to **T** (Twt Gmbh, Atd — indicates a trust/chain issue in the SSL Labs scan). Domain ages skewed old across the original 23-lead cohort (12–41 years), consistent with established SMBs rather than startups.

---

## Known Issues Found During This Session

1. **Stray test lead still in campaign** (carried over from sourcing run — see Part 1). Confirmed present in today's pipeline output as "Example / example.com." Needs manual removal in Lemlist UI.
2. **`.env.example` contained real API key values** (Lemlist + VirusTotal) in the working tree, in violation of project policy that this file must only ever hold placeholders. Found and reverted during this session — restored to placeholder values, and fixed a typo (`VIRUSTOTAL_API_KE` → `VIRUSTOTAL_API_KEY`) that would otherwise have silently broken VirusTotal lookups if copied into a real `.env`. Verified the actual local `.env` already uses the correct key name, so the pipeline itself was unaffected. Nothing was pushed to remote.
3. **HIBP key still not configured** — breach angle remains fully disabled (0/51 `has_breach`), same gap noted in prior sessions.
4. **NVD key still not configured** — pipeline ran in slow mode again this run.

---

## Combined Results Snapshot

| Metric | Value |
|---|---|
| Total leads in campaign | 51 (23 original + 50 sourced, minus 1 dedup, minus stray test lead not yet removed) |
| Leads with usable security intel | 39 (76%) |
| Leads with live, version-accurate CVE data | 8 (16%) |
| Leads flagged as actively exploited (CISA KEV) | 0 |
| Leads with breach data | 0 (HIBP not configured) |
| Campaign status | Draft — writeback completed, no outreach sent |

---

## Suggested Next Steps

1. Remove the stray `test.lead@example.com` lead from "Security Outbound V1" (Lemlist UI — no API path available).
2. Design the outreach sequence (email/LinkedIn steps, timing, breakup email) and copy — 39 leads now have CVE-specific angles ready to use.
3. Get a free NVD API key (nvd.nist.gov) — cuts pipeline runtime and raises rate limits for future re-runs.
4. Get an HIBP key (~$4/mo) to unlock the breach/GDPR angle — currently 0 leads have this data.
5. Consider enriching the 6 email-less leads from the sourcing run (costs credits) before launch.
6. Re-verify `.env.example` stays placeholder-only before any future commit — this slipped once this session.
7. Activate the campaign in the Lemlist UI once messaging is ready, then re-run `python pipeline.py --writeback`.
