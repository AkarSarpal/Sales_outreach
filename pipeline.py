#!/usr/bin/env python3
"""
Cyberdebunk Security Intelligence Pipeline

Fetches leads from a Lemlist campaign, enriches each company with
CVE and breach data, and optionally writes results back as Lemlist
custom variables.

Data sources (all free, no additional keys required):
  - Shodan InternetDB  — live ports + CVE IDs per IP (no key)
  - Direct HTTP        — tech stack from response headers + HTML
  - CISA KEV           — actively exploited CVE cross-reference (no key)
  - NVD                — CVE details and CVSS scores
  - VirusTotal         — passive tech hints from cached headers
  - SSL Labs           — cached SSL grade (no key)
  - Whois              — domain age (system CLI)
  - HIBP               — breach history (key optional)

Usage:
    python pipeline.py                      # dry run, generates report
    python pipeline.py --writeback          # push variables to Lemlist
    python pipeline.py --limit 5            # test with first 5 leads
    python pipeline.py --campaign <id>      # override campaign ID
"""

import os
import re
import sys
import time
import json
import socket
import argparse
import subprocess
import requests
from datetime import datetime, timedelta
from pathlib import Path
from base64 import b64encode


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CAMPAIGN_ID = os.getenv("LEMLIST_CAMPAIGN_ID", "cam_D4cKonCgWRYoNiEDR")

NVD_BASE        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HIBP_BASE       = "https://haveibeenpwned.com/api/v3"
CENSYS_BASE     = "https://search.censys.io/api/v2"
LEMLIST_BASE    = "https://api.lemlist.com/api"
INTERNETDB_BASE = "https://internetdb.shodan.io"
CISA_KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

TECH_STACK_DEFAULTS = [
    "Apache HTTP Server", "nginx", "Microsoft IIS",
    "OpenSSL", "WordPress", "Apache Tomcat",
]

VT_BASE       = "https://www.virustotal.com/api/v3"
SSL_LABS_BASE = "https://api.ssllabs.com/api/v3"

_WHOIS_DATE_PATS = [
    re.compile(r"creation date:\s*(\S+)", re.I),
    re.compile(r"created:\s*(\S+)", re.I),
    re.compile(r"registered:\s*(\S+)", re.I),
]
_WHOIS_DATE_FMTS = [
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d", "%d-%b-%Y", "%d/%m/%Y",
]

PERSONAL_EMAIL_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com"}

# Module-level cache for CISA KEV — loaded once per run
_KEV_CACHE: set | None = None


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _lemlist_auth() -> dict:
    key = os.getenv("LEMLIST_API_KEY", "")
    if not key:
        raise EnvironmentError("LEMLIST_API_KEY not set")
    token = b64encode(f":{key}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


def _censys_auth():
    uid    = os.getenv("CENSYS_API_ID", "")
    secret = os.getenv("CENSYS_API_SECRET", "")
    return (uid, secret) if uid and secret else None


def _nvd_sleep() -> float:
    return 0.7 if os.getenv("NVD_API_KEY") else 6.5


def _nvd_headers() -> dict:
    h = {"User-Agent": "CyberdebunkIntel/1.0"}
    key = os.getenv("NVD_API_KEY", "")
    if key:
        h["apiKey"] = key
    return h


# ---------------------------------------------------------------------------
# Lead parsing
# ---------------------------------------------------------------------------

def extract_company(tagline: str, domain: str) -> str:
    """
    Pull company name from a LinkedIn tagline like 'CTO at MindDoc'
    or 'CISO @ Mediaire'. Falls back to title-casing the domain root.
    """
    if tagline:
        m = re.search(r'(?:^|\s)(?:at|@)\s+(.+?)(?:\s*[|·•–].*)?$', tagline, re.IGNORECASE)
        if m:
            name = m.group(1).strip()
            name = re.split(r'\s*[|·•–]\s*', name)[0].strip()
            if len(name) > 2:
                return name
    root = domain.split(".")[0] if domain else "Unknown"
    return root.replace("-", " ").title()


def email_domain(email: str) -> str | None:
    """Extract company domain from work email. Returns None for personal domains."""
    if "@" not in email:
        return None
    dom = email.split("@")[1].lower()
    return None if dom in PERSONAL_EMAIL_DOMAINS else dom


# ---------------------------------------------------------------------------
# Lemlist API
# ---------------------------------------------------------------------------

def fetch_leads(campaign_id: str) -> list[dict]:
    """
    Returns fully enriched leads by joining the campaign leads list
    with each contact record. Each item has:
      email, domain, company, full_name, tagline, linkedin_url,
      contact_id, lead_id
    """
    headers = _lemlist_auth()

    resp = requests.get(
        f"{LEMLIST_BASE}/campaigns/{campaign_id}/leads",
        headers=headers, timeout=30,
    )
    resp.raise_for_status()
    stubs = resp.json()
    if not isinstance(stubs, list):
        stubs = stubs.get("leads", stubs.get("data", []))

    leads = []
    for stub in stubs:
        contact_id = stub.get("contactId")
        if not contact_id:
            continue
        cr = requests.get(
            f"{LEMLIST_BASE}/contacts/{contact_id}",
            headers=headers, timeout=15,
        )
        if cr.status_code != 200:
            continue
        c = cr.json()
        fields  = c.get("fields", {})
        email   = c.get("email", "")
        dom     = email_domain(email)
        tagline = fields.get("tagline", "")
        company = extract_company(tagline, dom or "")
        leads.append({
            "lead_id":     stub.get("_id", ""),
            "contact_id":  contact_id,
            "email":       email,
            "domain":      dom,
            "company":     company,
            "full_name":   c.get("fullName", ""),
            "tagline":     tagline,
            "linkedin_url": c.get("linkedinUrl", ""),
            "location":    fields.get("location", ""),
            "job_title":   fields.get("jobTitle", ""),
        })

    return leads


def writeback_lead(campaign_id: str, email: str, variables: dict) -> bool:
    """Push custom variables to a Lemlist lead (by email address)."""
    resp = requests.patch(
        f"{LEMLIST_BASE}/campaigns/{campaign_id}/leads/{email}",
        headers=_lemlist_auth(),
        json=variables,
        timeout=30,
    )
    return resp.status_code in (200, 201, 204)


# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities — free, no key
# ---------------------------------------------------------------------------

def load_cisa_kev() -> set:
    """
    Return the set of CVE IDs on CISA's Known Exploited Vulnerabilities list.
    Downloaded once per run and cached. A CVE in this list is being actively
    exploited in the wild — stronger outreach signal than CVSS score alone.
    """
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE
    try:
        resp = requests.get(
            CISA_KEV_URL,
            timeout=20,
            headers={"User-Agent": "CyberdebunkIntel/1.0"},
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        _KEV_CACHE = {v["cveID"] for v in vulns if "cveID" in v}
        return _KEV_CACHE
    except Exception as e:
        print(f"  [KEV] could not load CISA KEV list: {e}")
        _KEV_CACHE = set()
        return _KEV_CACHE


# ---------------------------------------------------------------------------
# Shodan InternetDB — free, no API key required
# ---------------------------------------------------------------------------

def query_shodan_internetdb(domain: str) -> dict:
    """
    Query Shodan InternetDB for the IP behind a domain.
    Returns open ports, CVE IDs (version-accurate), CPE strings, and tags.
    Completely free — no API key required.

    Limitation: if the domain is behind Cloudflare or another CDN, the data
    reflects the CDN's IP, not the origin server. Check 'cloudflare' in tags.
    """
    try:
        ip = socket.getaddrinfo(domain, None, socket.AF_INET)[0][4][0]
    except Exception:
        return _no_scan()
    # Skip RFC-1918 and loopback — not routable on the internet
    if ip.startswith(("10.", "172.16.", "192.168.", "127.")):
        return _no_scan()
    try:
        resp = requests.get(
            f"{INTERNETDB_BASE}/{ip}",
            timeout=10,
            headers={"User-Agent": "CyberdebunkIntel/1.0"},
        )
        if resp.status_code == 404:
            return _no_scan()
        if resp.status_code != 200:
            return _no_scan()
        data = resp.json()
        cves  = [v for v in data.get("vulns", []) if v.startswith("CVE-")]
        ports = data.get("ports", [])
        return {
            "ip":          ip,
            "ports":       ports,
            "cves":        cves,
            "cpes":        data.get("cpes", []),
            "tags":        data.get("tags", []),
            "hostnames":   data.get("hostnames", []),
            "services":    [],
            "banners":     {},
            "data_source": "live_scan" if (cves or ports) else "inferred",
        }
    except Exception as e:
        print(f"    [InternetDB] error for {domain}: {e}")
        return _no_scan()


def _no_scan() -> dict:
    return {"ip": "", "ports": [], "cves": [], "cpes": [], "tags": [],
            "hostnames": [], "services": [], "banners": {}, "data_source": "inferred"}


# ---------------------------------------------------------------------------
# Direct HTTP fingerprinting — free, no key
# ---------------------------------------------------------------------------

def fingerprint_http(domain: str) -> list[str]:
    """
    Detect tech stack by fetching the domain directly and parsing
    response headers (Server, X-Powered-By, X-Generator) and HTML source.
    More current than VirusTotal passive cache.
    """
    signals = {
        "Apache HTTP Server": ["apache"],
        "nginx":              ["nginx"],
        "Microsoft IIS":      ["iis", "microsoft-iis"],
        "ASP.NET":            ["asp.net"],
        "WordPress":          ["wordpress", "wp-content", "wp-json"],
        "Drupal":             ["drupal"],
        "Joomla":             ["joomla"],
        "PHP":                ["php"],
        "Node.js / Express":  ["node.js", "express"],
        "Cloudflare":         ["cloudflare"],
        "OpenSSL":            ["openssl"],
        "Apache Tomcat":      ["tomcat", "catalina"],
    }
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; CyberdebunkIntel/1.0)"},
            )
            combined = " ".join([
                resp.headers.get("server", ""),
                resp.headers.get("x-powered-by", ""),
                resp.headers.get("x-generator", ""),
                resp.headers.get("via", ""),
                resp.text[:4000],
            ]).lower()
            found = [t for t, terms in signals.items() if any(s in combined for s in terms)]
            if found:
                return found
            # Got a response but no signals — stop trying schemes
            return []
        except requests.exceptions.SSLError:
            continue  # try http://
        except Exception:
            return []
    return []


# ---------------------------------------------------------------------------
# VirusTotal — passive tech stack hints (free, 500 req/day)
# ---------------------------------------------------------------------------

def query_virustotal(domain: str) -> list[str]:
    """Return tech stack clues from VT passive DNS / HTTP response headers."""
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        return []
    try:
        resp = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers={"x-apikey": key},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        data  = resp.json().get("data", {}).get("attributes", {})
        headers = data.get("last_http_response_headers", {})
        server  = headers.get("server", "") + " " + headers.get("x-powered-by", "")
        cats    = " ".join(data.get("categories", {}).values())
        combined = (server + " " + cats).lower()
        signals = {
            "Apache HTTP Server": ["apache"],
            "nginx":              ["nginx"],
            "Microsoft IIS":      ["iis", "microsoft-iis"],
            "ASP.NET":            ["asp.net"],
            "WordPress":          ["wordpress"],
            "Drupal":             ["drupal"],
            "OpenSSL":            ["openssl"],
            "PHP":                ["php"],
            "Node.js / Express":  ["node.js", "express"],
            "Cloudflare":         ["cloudflare"],
        }
        return [t for t, terms in signals.items() if any(s in combined for s in terms)]
    except Exception as e:
        print(f"    [VT] error for {domain}: {e}")
        return []


# ---------------------------------------------------------------------------
# SSL Labs — SSL grade from cached scan (free, no key, no new scan triggered)
# ---------------------------------------------------------------------------

def query_ssl_labs(domain: str) -> dict:
    """Return SSL grade and cert expiry from SSL Labs cache. Empty dict on cache miss."""
    try:
        resp = requests.get(
            f"{SSL_LABS_BASE}/analyze",
            params={"host": domain, "fromCache": "on", "maxAge": "48"},
            headers={"User-Agent": "CyberdebunkIntel/1.0"},
            timeout=20,
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        if data.get("status") != "READY":
            return {}
        endpoints = data.get("endpoints", [])
        grade = endpoints[0].get("grade", "") if endpoints else ""
        certs = data.get("certs", [])
        expiry = ""
        if certs:
            ts = certs[0].get("notAfter", 0)
            if ts:
                expiry = datetime.utcfromtimestamp(ts / 1000).strftime("%Y-%m-%d")
        return {"grade": grade, "cert_expiry": expiry}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Whois — domain age and registrar via CLI
# ---------------------------------------------------------------------------

def query_whois(domain: str) -> dict:
    """Return domain age in days and registrar from whois CLI."""
    try:
        out = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        ).stdout
        age_days, registrar = None, ""
        for line in out.splitlines():
            if not age_days:
                for pat in _WHOIS_DATE_PATS:
                    m = pat.search(line)
                    if m:
                        ds = m.group(1)[:19]
                        for fmt in _WHOIS_DATE_FMTS:
                            try:
                                age_days = (datetime.now() - datetime.strptime(ds, fmt)).days
                                break
                            except ValueError:
                                pass
                        if age_days:
                            break
            if not registrar and re.match(r"registrar:", line, re.I):
                registrar = line.split(":", 1)[1].strip()[:60]
        return {"age_days": age_days, "registrar": registrar}
    except Exception:
        return {"age_days": None, "registrar": ""}


# ---------------------------------------------------------------------------
# Censys scanning (free programmatic access removed June 2026 — inferred only)
# Kept for reference; replaced in practice by query_shodan_internetdb()
# ---------------------------------------------------------------------------

def scan_censys(domain: str) -> dict:
    auth = _censys_auth()
    if not auth:
        return _no_scan()
    try:
        resp = requests.get(
            f"{CENSYS_BASE}/hosts/search",
            auth=auth,
            params={"q": domain, "per_page": 1},
            timeout=20,
        )
        if resp.status_code == 429:
            print(f"    [Censys] rate-limited on {domain}")
            return _no_scan()
        if resp.status_code != 200:
            return _no_scan()
        hits = resp.json().get("result", {}).get("hits", [])
        if not hits:
            return _no_scan()
        services = hits[0].get("services", [])
        ports    = [s.get("port") for s in services if s.get("port")]
        names    = list({s.get("service_name", "") for s in services if s.get("service_name")})
        banners  = {s["port"]: s["banner"] for s in services if s.get("banner")}
        return {"ports": ports, "services": names, "banners": banners, "data_source": "live_scan"}
    except Exception as e:
        print(f"    [Censys] error: {e}")
        return _no_scan()


# ---------------------------------------------------------------------------
# NVD CVE lookup
# ---------------------------------------------------------------------------

def query_nvd(keyword: str, max_results: int = 50) -> list[dict]:
    time.sleep(_nvd_sleep())
    cutoff = datetime.now() - timedelta(days=3 * 365)
    key = os.getenv("NVD_API_KEY", "")
    params = {
        "keywordSearch":  keyword,
        "resultsPerPage": max_results,
    }
    if key:
        params["apiKey"]       = key
        params["pubStartDate"] = cutoff.strftime("%Y-%m-%dT00:00:00.000")
        params["sortBy"]       = "published"
        params["sortOrder"]    = "dsc"
    try:
        for attempt in range(3):
            try:
                resp = requests.get(NVD_BASE, params=params, headers=_nvd_headers(), timeout=30)
            except requests.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(10 * (attempt + 1))
                    continue
                return []
            if resp.status_code == 403:
                print(f"    [NVD] rate-limited on '{keyword}' — sleeping 35s")
                time.sleep(35)
                continue
            if resp.status_code in (503, 502, 500):
                wait = 15 * (attempt + 1)
                print(f"    [NVD] {resp.status_code} on '{keyword}' — retry in {wait}s")
                time.sleep(wait)
                continue
            break
        resp.raise_for_status()
        results = []
        for v in resp.json().get("vulnerabilities", []):
            cve   = v.get("cve", {})
            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            score, severity = _extract_cvss(cve.get("metrics", {}))
            if score is not None and score < 7.0:
                continue
            if key:
                pub = cve.get("published", "")
                if pub and pub < cutoff.strftime("%Y-%m-%d"):
                    continue
            results.append({
                "id":          cve.get("id", ""),
                "description": desc[:300],
                "cvss_score":  score,
                "severity":    severity,
                "keyword":     keyword,
            })
        return results
    except Exception as e:
        print(f"    [NVD] error for '{keyword}': {e}")
        return []


def query_nvd_by_id(cve_id: str) -> dict | None:
    """Look up a specific CVE by ID. Returns None if not found or not HIGH/CRITICAL."""
    time.sleep(_nvd_sleep())
    params = {"cveId": cve_id}
    key = os.getenv("NVD_API_KEY", "")
    if key:
        params["apiKey"] = key
    try:
        resp = requests.get(NVD_BASE, params=params, headers=_nvd_headers(), timeout=20)
        if resp.status_code != 200:
            return None
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return None
        cve   = vulns[0].get("cve", {})
        descs = cve.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        score, severity = _extract_cvss(cve.get("metrics", {}))
        return {
            "id":          cve.get("id", cve_id),
            "description": desc[:300],
            "cvss_score":  score,
            "severity":    severity or "HIGH",
            "keyword":     cve_id,
        }
    except Exception as e:
        print(f"    [NVD] error for '{cve_id}': {e}")
        return None


def _extract_cvss(metrics: dict) -> tuple:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            d = entries[0].get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity", "")
    return None, ""


def get_top_cve(cves: list[dict]) -> dict | None:
    scored = [c for c in cves if c.get("cvss_score") is not None]
    return max(scored, key=lambda c: c["cvss_score"]) if scored else (cves[0] if cves else None)


# ---------------------------------------------------------------------------
# HIBP breach lookup
# ---------------------------------------------------------------------------

def query_hibp(domain: str, hibp_key: str = "", months: int = 24) -> list[dict]:
    if not hibp_key:
        return []
    try:
        resp = requests.get(
            f"{HIBP_BASE}/breaches",
            params={"domain": domain},
            headers={"hibp-api-key": hibp_key, "User-Agent": "CyberdebunkIntel/1.0"},
            timeout=20,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        cutoff  = datetime.now() - timedelta(days=months * 30)
        recent  = []
        for b in resp.json():
            try:
                if datetime.strptime(b.get("BreachDate", ""), "%Y-%m-%d") >= cutoff:
                    recent.append({
                        "name":      b.get("Name", ""),
                        "date":      b.get("BreachDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                    })
            except ValueError:
                pass
        return recent
    except Exception as e:
        print(f"    [HIBP] error for {domain}: {e}")
        return []


# ---------------------------------------------------------------------------
# Tech stack helpers
# ---------------------------------------------------------------------------

def detect_tech(scan: dict) -> list[str]:
    """Extract tech from Censys-style service/banner data (legacy, rarely used now)."""
    combined = (
        " ".join(s.lower() for s in scan.get("services", []))
        + " "
        + " ".join(str(v).lower() for v in scan.get("banners", {}).values())
    )
    signals = {
        "Apache HTTP Server": ["apache", "httpd"],
        "nginx":              ["nginx"],
        "Microsoft IIS":      ["iis", "microsoft-iis"],
        "ASP.NET":            ["asp.net"],
        "WordPress":          ["wordpress", "wp-content"],
        "Drupal":             ["drupal"],
        "Apache Tomcat":      ["tomcat", "catalina"],
        "OpenSSL":            ["openssl"],
        "PHP":                ["php"],
        "Node.js / Express":  ["node.js", "express"],
    }
    found = [tech for tech, terms in signals.items() if any(t in combined for t in terms)]
    return found or TECH_STACK_DEFAULTS[:3]


def _tech_from_cpes(cpes: list[str]) -> list[str]:
    """Extract human-readable tech names from Shodan CPE strings."""
    cpe_map = {
        "apache:http_server": "Apache HTTP Server",
        "nginx:nginx":        "nginx",
        "microsoft:iis":      "Microsoft IIS",
        "wordpress":          "WordPress",
        "php:php":            "PHP",
        "openssl:openssl":    "OpenSSL",
        "apache:tomcat":      "Apache Tomcat",
        "drupal:drupal":      "Drupal",
    }
    found, seen = [], set()
    for cpe in cpes:
        cpe_l = cpe.lower()
        for key, name in cpe_map.items():
            if key in cpe_l and name not in seen:
                found.append(name)
                seen.add(name)
    return found


# ---------------------------------------------------------------------------
# Lead enrichment
# ---------------------------------------------------------------------------

def analyze_lead(lead: dict, hibp_key: str = "", verbose: bool = False) -> dict:
    company = lead["company"]
    domain  = lead.get("domain") or ""

    print(f"\n  [{company}]  {domain}")

    if not domain:
        print(f"    no domain — skipping scan")
        tag       = "no_findings"
        variables = _empty_variables(tag)
        return {**lead, "tech_stack": [], "top_cve": None, "cve_count": 0,
                "breaches": [], "tag": tag, "data_source": "inferred",
                "exploited_in_wild": False, "variables": variables}

    # 1. Direct HTTP fingerprinting (free, no key — fastest and most current)
    http_tech = fingerprint_http(domain)
    if http_tech and verbose:
        print(f"    http tech: {http_tech}")

    # 2. Shodan InternetDB (free, no key — real ports + CVE IDs per IP)
    internetdb = query_shodan_internetdb(domain)
    is_cdn = "cloudflare" in internetdb.get("tags", []) or "Cloudflare" in (http_tech or [])
    print(f"    internetdb: {internetdb['data_source']}", end="")
    if internetdb["data_source"] == "live_scan":
        cdn_note = " [CDN — origin hidden]" if is_cdn else ""
        print(f" — {internetdb.get('ip')} "
              f"ports {internetdb['ports'][:5]} "
              f"CVEs {len(internetdb['cves'])}{cdn_note}")
    else:
        print()

    # 3. VirusTotal — supplement tech stack when live scan is absent and http gave nothing
    vt_tech = []
    if not http_tech and internetdb["data_source"] == "inferred":
        vt_tech = query_virustotal(domain)
        if vt_tech and verbose:
            print(f"    vt tech: {vt_tech}")

    # 4. SSL Labs — cached grade, no new scan triggered
    ssl = query_ssl_labs(domain)
    if ssl.get("grade") and verbose:
        print(f"    ssl grade: {ssl['grade']}  (cert expires {ssl.get('cert_expiry', '?')})")

    # 5. Whois — domain age and registrar
    whois = query_whois(domain)
    if whois.get("age_days") and verbose:
        print(f"    domain age: {whois['age_days'] // 365}y  ({whois.get('registrar', '')})")

    # 6. Tech stack — priority: direct HTTP > VirusTotal > CPE strings > defaults
    cpe_tech = _tech_from_cpes(internetdb.get("cpes", []))
    tech = http_tech or vt_tech or cpe_tech or TECH_STACK_DEFAULTS[:3]

    # 7. CVEs — live IDs from InternetDB (version-accurate) or keyword search (fallback)
    all_cves = []
    if internetdb.get("cves") and not is_cdn:
        # Have real CVE IDs matched to a specific IP — look up the top one in NVD for details
        cve_ids = internetdb["cves"][:10]
        if verbose:
            print(f"    internetdb CVEs: {cve_ids[:5]}")
        top_detail = query_nvd_by_id(cve_ids[0])
        if top_detail:
            all_cves.append(top_detail)
        # Add remaining as stubs (real IDs, CVSS unknown until looked up)
        for cid in cve_ids[1:]:
            all_cves.append({
                "id": cid, "cvss_score": None,
                "severity": "HIGH", "keyword": cid, "description": "",
            })
        data_source = "live_scan"
    else:
        # Fall back to NVD keyword search against detected tech stack
        for t in tech[:6]:
            cves = query_nvd(t)
            all_cves.extend(cves)
            if verbose and cves:
                print(f"    nvd '{t}': {len(cves)} CVEs")
        data_source = "inferred"

    top_cve = get_top_cve(all_cves)

    # 8. CISA KEV cross-reference — flags actively exploited CVEs
    kev = load_cisa_kev()
    exploited = bool(top_cve and top_cve.get("id") in kev)
    if exploited:
        print(f"    CISA KEV: {top_cve['id']} is actively exploited in the wild")

    # 9. HIBP breach lookup
    breaches = query_hibp(domain, hibp_key)
    breach   = breaches[0] if breaches else None

    # 10. Tag
    if top_cve:
        tag = "has_cve"
    elif breach:
        tag = "has_breach"
    else:
        tag = "no_findings"

    ports_str   = ",".join(str(p) for p in internetdb["ports"][:5]) or "unknown"
    service_str = (internetdb.get("services") or tech or ["unknown"])[0]

    variables = {
        "cvss_score":        str(top_cve["cvss_score"]) if top_cve and top_cve.get("cvss_score") else "",
        "key_risk":          top_cve["severity"]        if top_cve and top_cve.get("severity")   else "",
        "exposed_ports":     ports_str,
        "top_cve":           top_cve["id"]              if top_cve else "",
        "key_cve":           top_cve["id"]              if top_cve else "",
        "exposed_service":   service_str,
        "breach_date":       breach["date"]             if breach  else "",
        "compliance_flag":   "GDPR breach flagged"      if breach  else "",
        "ssl_grade":         ssl.get("grade", ""),
        "domain_age":        f"{whois['age_days'] // 365}y" if whois.get("age_days") else "",
        "exploited_in_wild": "Yes — CISA KEV"           if exploited else "",
        "lemlistTag":        tag,
    }

    print(f"    tag: {tag}", end="")
    if top_cve and top_cve.get("cvss_score"):
        print(f"  |  {top_cve['id']} CVSS {top_cve['cvss_score']}", end="")
    elif top_cve:
        print(f"  |  {top_cve['id']}", end="")
    if exploited:
        print(f"  |  CISA KEV (actively exploited)", end="")
    if breach:
        print(f"  |  breach {breach['date']}", end="")
    print()

    return {
        **lead,
        "tech_stack":        tech,
        "top_cve":           top_cve,
        "cve_count":         len(all_cves),
        "breaches":          breaches,
        "tag":               tag,
        "data_source":       data_source,
        "ssl_grade":         ssl.get("grade", ""),
        "cert_expiry":       ssl.get("cert_expiry", ""),
        "domain_age":        whois.get("age_days"),
        "registrar":         whois.get("registrar", ""),
        "internetdb_ip":     internetdb.get("ip", ""),
        "internetdb_cves":   internetdb.get("cves", []),
        "exploited_in_wild": exploited,
        "variables":         variables,
    }


def _empty_variables(tag: str) -> dict:
    return {
        "cvss_score": "", "key_risk": "", "exposed_ports": "unknown",
        "top_cve": "", "key_cve": "", "exposed_service": "unknown",
        "breach_date": "", "compliance_flag": "",
        "ssl_grade": "", "domain_age": "",
        "exploited_in_wild": "", "lemlistTag": tag,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def generate_report(results: list[dict], writeback: bool = False) -> str:
    now      = datetime.now().strftime("%Y-%m-%d %H:%M")
    total    = len(results)
    n_cve    = sum(1 for r in results if r["tag"] == "has_cve")
    n_breach = sum(1 for r in results if r["tag"] == "has_breach")
    n_none   = sum(1 for r in results if r["tag"] == "no_findings")
    usable   = n_cve + n_breach
    rate     = usable / total if total else 0
    live     = sum(1 for r in results if r.get("data_source") == "live_scan")
    n_kev    = sum(1 for r in results if r.get("exploited_in_wild"))
    mark     = "✓ above" if rate >= 0.60 else "✗ below"

    lines = [
        "# Security Intelligence Report",
        f"Generated: {now}",
        "",
        "## Run Summary",
        "| Metric | Value |",
        "|---|---|",
        f"| Total leads | {total} |",
        f"| `has_cve` | {n_cve} |",
        f"| `has_breach` | {n_breach} |",
        f"| `no_findings` | {n_none} |",
        f"| Usable intel rate | {rate:.0%} — {mark} MVP threshold (60%) |",
        f"| Live scans (Shodan InternetDB) | {live}/{total} |",
        f"| CISA KEV — actively exploited | {n_kev} |",
        f"| Writeback | {'yes' if writeback else 'dry run'} |",
        "",
        "## Lead Table",
        "| Company | Domain | Tag | CVE | CVSS | KEV | SSL | Domain Age | Breach |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        cve_id    = r["top_cve"]["id"]              if r.get("top_cve") else "—"
        cvss      = str(r["top_cve"]["cvss_score"]) if r.get("top_cve") and r["top_cve"].get("cvss_score") else "—"
        kev_flag  = "⚠ KEV"                         if r.get("exploited_in_wild") else "—"
        ssl_grade = r.get("ssl_grade") or "—"
        age       = f"{r['domain_age'] // 365}y"    if r.get("domain_age") else "—"
        breach    = r["variables"].get("breach_date") or "—"
        lines.append(
            f"| {r['company']} | {r.get('domain','—')} | `{r['tag']}` "
            f"| {cve_id} | {cvss} | {kev_flag} | {ssl_grade} | {age} | {breach} |"
        )

    lines += ["", "---", "", "## Lead Details"]
    for r in results:
        v = r["variables"]
        lines += [
            f"### {r['company']}  ({r.get('full_name', '')})",
            f"**Domain:** `{r.get('domain', 'unknown')}` | "
            f"**Data source:** `{r.get('data_source', 'inferred')}`",
            f"**Role:** {r.get('job_title', '')} — {r.get('tagline', '')[:80]}",
            f"**Tag:** `{r['tag']}`",
        ]
        tech = r.get("tech_stack", [])
        if tech:
            lines.append(f"**Tech stack:** {', '.join(tech[:6])}")

        # InternetDB live scan info
        if r.get("internetdb_ip"):
            idb_cves = r.get("internetdb_cves", [])
            idb_note = f"IP `{r['internetdb_ip']}`"
            if idb_cves:
                idb_note += f" — {len(idb_cves)} CVEs from Shodan: {', '.join(idb_cves[:5])}"
            lines.append(f"**InternetDB:** {idb_note}")

        meta_parts = []
        if r.get("ssl_grade"):
            expiry = f" (expires {r['cert_expiry']})" if r.get("cert_expiry") else ""
            meta_parts.append(f"SSL grade **{r['ssl_grade']}**{expiry}")
        if r.get("domain_age"):
            reg = f" via {r['registrar']}" if r.get("registrar") else ""
            meta_parts.append(f"domain age **{r['domain_age'] // 365}y**{reg}")
        if meta_parts:
            lines.append("**Recon:** " + "  |  ".join(meta_parts))

        if r.get("top_cve"):
            c = r["top_cve"]
            kev_badge = " 🚨 **CISA KEV — actively exploited**" if r.get("exploited_in_wild") else ""
            cvss_str  = f"CVSS **{c['cvss_score']}** ({c.get('severity', '?')})" if c.get("cvss_score") else f"({c.get('severity', 'HIGH')})"
            lines += [
                f"**CVE:** [{c['id']}](https://nvd.nist.gov/vuln/detail/{c['id']}) "
                f"— {cvss_str}{kev_badge}",
            ]
            if c.get("description"):
                lines.append(f"> {c['description'][:250]}")

        if v.get("breach_date"):
            lines.append(f"**Breach:** {v['breach_date']} — {v.get('compliance_flag', '')}")

        lines += [
            "",
            "**Lemlist variables:**",
            f"  `{{{{cvss_score}}}}` = {v['cvss_score'] or '(empty)'}",
            f"  `{{{{key_cve}}}}` = {v['key_cve'] or '(empty)'}",
            f"  `{{{{key_risk}}}}` = {v['key_risk'] or '(empty)'}",
            f"  `{{{{exposed_service}}}}` = {v['exposed_service']}",
            f"  `{{{{exposed_ports}}}}` = {v['exposed_ports']}",
            f"  `{{{{ssl_grade}}}}` = {v['ssl_grade'] or '(empty)'}",
            f"  `{{{{domain_age}}}}` = {v['domain_age'] or '(empty)'}",
            f"  `{{{{breach_date}}}}` = {v['breach_date'] or '(empty)'}",
            f"  `{{{{compliance_flag}}}}` = {v['compliance_flag'] or '(empty)'}",
            f"  `{{{{exploited_in_wild}}}}` = {v['exploited_in_wild'] or '(empty)'}",
            "",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Cyberdebunk Security Intel Pipeline")
    parser.add_argument("--campaign",  default=CAMPAIGN_ID)
    parser.add_argument("--writeback", action="store_true", help="Push variables to Lemlist")
    parser.add_argument("--hibp-key",  default=os.getenv("HIBP_API_KEY", ""))
    parser.add_argument("--output",    default="intel_report.md")
    parser.add_argument("--limit",     type=int, default=0, help="Max leads (0 = all)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not os.getenv("LEMLIST_API_KEY"):
        print("Error: LEMLIST_API_KEY is not set. Copy .env.example → .env")
        sys.exit(1)

    if not os.getenv("NVD_API_KEY"):
        print("Note: NVD_API_KEY not set — slow mode (~7min). Free key: nvd.nist.gov\n")
    if not os.getenv("VIRUSTOTAL_API_KEY"):
        print("Note: VIRUSTOTAL_API_KEY not set — VT tech hints disabled (HTTP fingerprinting still runs)\n")

    # Pre-load CISA KEV catalog (cached for the run)
    print("Loading CISA Known Exploited Vulnerabilities catalog...", end=" ", flush=True)
    kev = load_cisa_kev()
    print(f"{len(kev)} entries" if kev else "failed (continuing without KEV)")

    print(f"\nFetching leads from campaign {args.campaign}...")
    leads = fetch_leads(args.campaign)
    if args.limit:
        leads = leads[:args.limit]
    print(f"{len(leads)} leads loaded\n")

    print("Running enrichment...")
    results = [
        analyze_lead(lead, hibp_key=args.hibp_key, verbose=args.verbose)
        for lead in leads
    ]

    if args.writeback:
        print("\nWriting back to Lemlist...")
        ok = 0
        for r in results:
            if r["email"]:
                if writeback_lead(args.campaign, r["email"], r["variables"]):
                    ok += 1
                    if args.verbose:
                        print(f"  ✓ {r['company']}")
                else:
                    print(f"  ✗ {r['company']} ({r['email']})")
        print(f"Writeback: {ok}/{len(results)} updated")

    report = generate_report(results, writeback=args.writeback)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"\nReport → {args.output}")

    n_cve    = sum(1 for r in results if r["tag"] == "has_cve")
    n_breach = sum(1 for r in results if r["tag"] == "has_breach")
    n_none   = sum(1 for r in results if r["tag"] == "no_findings")
    n_live   = sum(1 for r in results if r.get("data_source") == "live_scan")
    n_kev    = sum(1 for r in results if r.get("exploited_in_wild"))
    print(f"Summary: {n_cve} CVE  |  {n_breach} breach  |  {n_none} no findings  "
          f"|  {n_live} live scans  |  {n_kev} CISA KEV")


if __name__ == "__main__":
    main()
