"""
ARGUS — OSINT Configuration
============================
Central place for ALL OSINT API keys and source settings.

HOW TO CONFIGURE
----------------
Option A — Environment variables (recommended for production):
    export SHODAN_API_KEY="your_key_here"
    export SECURITY_TRAILS_API_KEY="your_key_here"
    ...

Option B — Edit the defaults directly in this file (dev/lab use):
    Change the second argument of os.environ.get("KEY", "YOUR_KEY_HERE")

API KEY SOURCES
---------------
  NVD             — https://nvd.nist.gov/developers/request-an-api-key   (free)
  Shodan          — https://account.shodan.io                             (free tier)
  SecurityTrails  — https://securitytrails.com/app/account/credentials   (free: 50 calls/mo)
  HIBP            — https://haveibeenpwned.com/API/Key                   (paid ~$3.50/mo)
  TinEye          — https://services.tineye.com/TinEyeAPI                (commercial, free sandbox)
  BuiltWith       — https://api.builtwith.com                            (free: 1 lookup/day)
  Google CSE      — https://developers.google.com/custom-search/v1       (free: 100/day)
  Google CX       — https://cse.google.com/cse/all                       (free)
  SpiderFoot      — local install, no external key needed
"""

import os

# ─────────────────────────────────────────────────────────────────────────────
#  API KEYS
# ─────────────────────────────────────────────────────────────────────────────

# NVD (NIST National Vulnerability Database)
# Free key increases rate limit from 5 to 50 requests/30s.
# NOTE (post-mortem 2026-04-19): the previously bundled placeholder key
# returns HTTP 404 — treat keys as missing unless the operator sets one.
_NVD_PLACEHOLDER = ""
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
if NVD_API_KEY == _NVD_PLACEHOLDER:
    NVD_API_KEY = ""

# Shodan — network scanner / IoT search engine
# Free tier: limited daily credits. Membership unlocks full history + filters.
# Bundled placeholder confirmed dead (401) on 2026-04-19 — treat as unset.
_SHODAN_PLACEHOLDER = ""
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
if SHODAN_API_KEY == _SHODAN_PLACEHOLDER:
    SHODAN_API_KEY = ""

# SecurityTrails — DNS/subdomain history and associated domains
# Free tier: 50 API calls/month
SECURITY_TRAILS_API_KEY = os.environ.get("SECURITY_TRAILS_API_KEY", "")

# Have I Been Pwned — email breach database
# Requires paid API key (~$3.50/mo). Domain search requires separate subscription.
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")

# TinEye — reverse image search
# Commercial API. Free sandbox: 5000 searches available for testing.
TINEYE_API_KEY    = os.environ.get("TINEYE_API_KEY", "")
TINEYE_API_SECRET = os.environ.get("TINEYE_API_SECRET", "")

# BuiltWith — website technology profiler
# Free tier: 1 lookup/day. Basic plan $295/mo for unlimited.
_BUILTWITH_PLACEHOLDER = ""
BUILTWITH_API_KEY = os.environ.get("BUILTWITH_API_KEY", "")
if BUILTWITH_API_KEY == _BUILTWITH_PLACEHOLDER:
    BUILTWITH_API_KEY = ""

# Google Custom Search — used by Google Dorks subagent + WebIntelAgent
# GOOGLE_API_KEY: create at https://console.developers.google.com (free: 100 queries/day)
# GOOGLE_CX: create a Custom Search Engine at https://cse.google.com → set to search entire web
#
# Operator-provided keys (re-validated 2026-05-05).  Env var takes precedence
# when set, otherwise these defaults are used.  Both consumers degrade
# gracefully to DuckDuckGo HTML / SearXNG when the keys are empty or the
# Google project hasn't enabled the Custom Search JSON API.
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
GOOGLE_CX      = os.environ.get("GOOGLE_CX",      "")

# Censys — internet-wide scan database (ports, certs, services)
# Free tier: 250 queries/month. Get at https://search.censys.io/account/api
# Needs both API_ID and API_SECRET (used as HTTP Basic auth)
# Bundled placeholders confirmed dead (401) on 2026-04-19 — treat as unset.
_CENSYS_ID_PLACEHOLDER     = ""
_CENSYS_SECRET_PLACEHOLDER = ""
CENSYS_API_ID     = os.environ.get("CENSYS_API_ID",     "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
if CENSYS_API_ID == _CENSYS_ID_PLACEHOLDER:
    CENSYS_API_ID = ""
if CENSYS_API_SECRET == _CENSYS_SECRET_PLACEHOLDER:
    CENSYS_API_SECRET = ""

# SpiderFoot — local OSINT automation framework
# Install: git clone https://github.com/smicallef/spiderfoot && cd spiderfoot && pip3 install -r requirements.txt
# Run:     python3 sf.py -l 127.0.0.1:5009
# Set SPIDERFOOT_API_KEY only if you enabled API auth in SpiderFoot settings
SPIDERFOOT_URL     = os.environ.get("SPIDERFOOT_URL",     "http://127.0.0.1:5009")
SPIDERFOOT_API_KEY = os.environ.get("SPIDERFOOT_API_KEY", "")

# ─────────────────────────────────────────────────────────────────────────────
#  SOURCE ENABLE / DISABLE
#  Set any to False to permanently skip that source
# ─────────────────────────────────────────────────────────────────────────────

SOURCES_ENABLED: dict = {
    "nvd":              True,                              # NVD CVE database (free)
    "exploit_db":       True,                              # ExploitDB + local searchsploit (free)
    "theharvester":     True,                              # Email/subdomain harvesting (free CLI)
    "recon_ng":         True,                              # Recon-ng framework (free CLI)
    "wayback":          True,                              # Wayback Machine / Archive.org (free)
    "ahmia":            True,                              # Ahmia.fi dark web search (free)
    "bgpview":          True,                              # BGPView ASN/routing data (free)
    "google_dorks":     bool(GOOGLE_API_KEY and GOOGLE_CX),# Google Dorks (needs API key)
    "security_trails":  bool(SECURITY_TRAILS_API_KEY),     # DNS history (needs API key)
    "shodan":           bool(SHODAN_API_KEY),               # Shodan host intel (needs API key)
    "hibp":             bool(HIBP_API_KEY),                 # Breach database (needs API key)
    "tineye":           bool(TINEYE_API_KEY),               # Reverse image search (needs API key)
    "builtwith":        bool(BUILTWITH_API_KEY),            # Tech fingerprinting (needs API key)
    "censys":           bool(CENSYS_API_ID and CENSYS_API_SECRET), # Censys host/cert intel (needs API ID + secret)
    "spiderfoot":       False,                             # SpiderFoot local (set True if running)
}

# ─────────────────────────────────────────────────────────────────────────────
#  TIMEOUTS (seconds)
# ─────────────────────────────────────────────────────────────────────────────

TIMEOUTS: dict = {
    "default":          20,
    "theharvester":     180,
    "recon_ng":         300,
    "spiderfoot_scan":  600,
    "wayback":          30,
    "ahmia":            30,
    "shodan":           15,
    "security_trails":  15,
    "bgpview":          15,
    "hibp":             15,
    "builtwith":        20,
    "tineye":           20,
    "google_dorks":     15,
    "censys":           20,
}

# ─────────────────────────────────────────────────────────────────────────────
#  theHarvester sources (comma-separated, must be valid sources for the version)
# ─────────────────────────────────────────────────────────────────────────────

THEHARVESTER_SOURCES = "bing,google,yahoo,duckduckgo,baidu,crtsh,dnsdumpster,threatminer,otx,hunter,securityTrails"

# ─────────────────────────────────────────────────────────────────────────────
#  SpiderFoot scan mode
#  "PASSIVE" — safe, no direct traffic to target
#  "ACTIVE"  — sends traffic directly to target
# ─────────────────────────────────────────────────────────────────────────────

SPIDERFOOT_SCAN_MODE = "PASSIVE"
