"""
opsec_profiles.py - operational-security profiles for tool execution.

Why this exists
---------------
ARGUS runs tools with default flags that scream "automated scanner":
  nmap -T4 --min-rate 3000 -sS -sV -sC
  gobuster -t 40 with default User-Agent "Mozilla/5.0 (gobuster)"
  whatweb -a 3 (aggressive mode)

On a real engagement this gets the source IP blocked at the perimeter
within 10 minutes and gives the blue team a clean attribution chain.
The platform needs a single dial that swaps default flags for
stealthier alternatives.

What ships
----------
A central OpsecProfile object that other modules consult when building
tool invocations.  Profiles range from FAST (default, current behavior
- noisy but quick) through QUIET, STEALTH, to PARANOID.  Each profile
defines:
  - rate / parallelism caps
  - per-tool flag overrides (e.g. nmap timing, gobuster -t, gobuster -A)
  - User-Agent rotation pool
  - optional proxy chain (proxychains4 prefix)
  - request jitter (random pre-call delay)

Usage from a tool runner
------------------------
    from utils.opsec_profiles import get_profile, apply_to_argv

    prof = get_profile()                            # whichever env says
    argv = apply_to_argv("nmap", argv, prof)        # mutates flags
    argv = prof.wrap_with_proxy(argv)               # prepends proxychains if set
    await asyncio.sleep(prof.jitter_sec())          # pre-call jitter
"""
from __future__ import annotations

import logging
import os
import random
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Tunables (env-overridable) ───────────────────────────────────────────
OPSEC_PROFILE         = os.environ.get("ARGUS_OPSEC", "fast").lower()
PROXYCHAINS_BIN       = os.environ.get("PROXYCHAINS_BIN", "proxychains4")
PROXYCHAINS_CONFIG    = os.environ.get("PROXYCHAINS_CONFIG", "")   # path to .conf if non-default
EXTRA_UA_FILE         = os.environ.get("ARGUS_UA_FILE", "")
JITTER_MAX_SEC        = float(os.environ.get("ARGUS_JITTER_MAX_SEC", "0"))   # FAST=0 by default


# Curated UA pool - modern + diverse so a single scan doesn't look like
# 5,000 requests from one browser.
_BUILTIN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
]


def _load_extra_uas() -> List[str]:
    if not EXTRA_UA_FILE or not os.path.isfile(EXTRA_UA_FILE):
        return []
    try:
        with open(EXTRA_UA_FILE, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception:
        return []


_UA_POOL: List[str] = _BUILTIN_UAS + _load_extra_uas()


# ── Profile model ────────────────────────────────────────────────────────

@dataclass
class OpsecProfile:
    name:               str
    # Per-tool flag overrides.  Maps tool name -> list of "kill flags" to
    # strip from the operator/LLM-provided argv, and "add flags" to inject.
    nmap_timing:        str           = "-T4"
    nmap_min_rate:      Optional[str] = None
    nmap_max_rate:      Optional[str] = None
    nmap_extras:        List[str]     = field(default_factory=list)
    gobuster_threads:   int           = 40
    ffuf_threads:       int           = 40
    ffuf_rate:          int           = 0          # 0 = unlimited
    whatweb_aggression: int           = 3
    user_agent:         Optional[str] = None        # None = rotate from pool
    rotate_user_agent:  bool          = False
    jitter_max_sec:     float         = 0.0
    proxychains:        bool          = False

    def pick_ua(self) -> str:
        if self.user_agent and not self.rotate_user_agent:
            return self.user_agent
        return random.choice(_UA_POOL)

    def jitter_sec(self) -> float:
        if self.jitter_max_sec <= 0:
            return 0.0
        return random.uniform(0, self.jitter_max_sec)

    def wrap_with_proxy(self, argv: List[str]) -> List[str]:
        """Prepend proxychains if the profile asks for it AND the binary exists."""
        if not self.proxychains:
            return argv
        binpath = shutil.which(PROXYCHAINS_BIN)
        if not binpath:
            logger.warning("[opsec] proxychains requested but %s not on PATH", PROXYCHAINS_BIN)
            return argv
        wrap = [binpath, "-q"]
        if PROXYCHAINS_CONFIG and os.path.isfile(PROXYCHAINS_CONFIG):
            wrap += ["-f", PROXYCHAINS_CONFIG]
        return wrap + argv


# ── Canonical profiles ──────────────────────────────────────────────────

PROFILES: Dict[str, OpsecProfile] = {
    "fast": OpsecProfile(
        name="fast",
        nmap_timing="-T4",
        nmap_min_rate="3000",
        gobuster_threads=40,
        ffuf_threads=40,
        whatweb_aggression=3,
        jitter_max_sec=0.0,
        proxychains=False,
        rotate_user_agent=False,
    ),
    "quiet": OpsecProfile(
        name="quiet",
        nmap_timing="-T3",
        nmap_min_rate=None,
        nmap_max_rate="500",
        nmap_extras=["--randomize-hosts"],
        gobuster_threads=15,
        ffuf_threads=15,
        ffuf_rate=20,
        whatweb_aggression=2,
        jitter_max_sec=0.5,
        proxychains=False,
        rotate_user_agent=True,
    ),
    "stealth": OpsecProfile(
        name="stealth",
        nmap_timing="-T2",
        nmap_min_rate=None,
        nmap_max_rate="50",
        nmap_extras=["--randomize-hosts", "-f"],   # fragmented packets
        gobuster_threads=5,
        ffuf_threads=5,
        ffuf_rate=10,
        whatweb_aggression=1,
        jitter_max_sec=2.0,
        proxychains=True,
        rotate_user_agent=True,
    ),
    "paranoid": OpsecProfile(
        name="paranoid",
        nmap_timing="-T1",
        nmap_min_rate=None,
        nmap_max_rate="10",
        nmap_extras=["--randomize-hosts", "-f", "--data-length", "24"],
        gobuster_threads=2,
        ffuf_threads=2,
        ffuf_rate=2,
        whatweb_aggression=1,
        jitter_max_sec=8.0,
        proxychains=True,
        rotate_user_agent=True,
    ),
}


def get_profile(name: Optional[str] = None) -> OpsecProfile:
    n = (name or OPSEC_PROFILE or "fast").lower()
    return PROFILES.get(n, PROFILES["fast"])


# ── Flag rewriting ──────────────────────────────────────────────────────

# Set of "noisy default" flags we strip when a quiet+ profile is active.
# Keyed by tool name, mapped to list of single-token flags to drop.
_STRIP_FLAGS: Dict[str, set] = {
    "nmap":     {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
                 "--min-rate", "--max-rate"},
    "gobuster": {"-t", "--threads"},
    "ffuf":     {"-t", "-rate"},
    "whatweb":  {"-a", "--aggression"},
}


def _strip_paired_flags(argv: List[str], tool: str) -> List[str]:
    """Drop noisy flags from argv.  Handles "-t 40" (paired) AND "-T4" (joined)."""
    flags = _STRIP_FLAGS.get(tool.lower(), set())
    out: List[str] = []
    skip_next = False
    for tok in argv:
        if skip_next:
            skip_next = False
            continue
        # Joined-form  -T4 / -t40
        joined_match = False
        for f in flags:
            if tok == f or (tok.startswith(f) and len(tok) > len(f) and f.startswith("-") and not f.startswith("--")):
                joined_match = True
                # If it's the paired form ("-t" plus next token), skip both
                if tok == f:
                    skip_next = True
                break
        if joined_match:
            continue
        # Long-form pair "--threads 40"
        if tok in flags:
            skip_next = True
            continue
        out.append(tok)
    return out


def apply_to_argv(tool: str, argv: List[str], profile: OpsecProfile) -> List[str]:
    """Rewrite argv to match the active profile.

    - nmap: replace timing + rate, append --randomize-hosts / -f if set
    - gobuster/ffuf: cap thread count
    - whatweb: cap aggression
    - any HTTP-using tool: append user-agent if not present
    Returns a NEW list; doesn't mutate the input.
    """
    t = (tool or "").lower()
    argv = _strip_paired_flags(list(argv), t)

    if t == "nmap":
        argv.append(profile.nmap_timing)
        if profile.nmap_min_rate:
            argv += ["--min-rate", profile.nmap_min_rate]
        if profile.nmap_max_rate:
            argv += ["--max-rate", profile.nmap_max_rate]
        for x in profile.nmap_extras:
            if x not in argv:
                argv.append(x)
    elif t in ("gobuster", "feroxbuster", "dirsearch"):
        argv += ["-t", str(profile.gobuster_threads)]
        if profile.rotate_user_agent or profile.user_agent:
            argv += ["-a", profile.pick_ua()]
    elif t == "ffuf":
        argv += ["-t", str(profile.ffuf_threads)]
        if profile.ffuf_rate > 0:
            argv += ["-rate", str(profile.ffuf_rate)]
        if profile.rotate_user_agent or profile.user_agent:
            argv += ["-H", f"User-Agent: {profile.pick_ua()}"]
    elif t == "whatweb":
        argv += [f"-a", str(profile.whatweb_aggression)]
        if profile.rotate_user_agent or profile.user_agent:
            argv += [f"--user-agent={profile.pick_ua()}"]
    elif t == "curl":
        # Add UA only if not already in argv
        ua_present = any("user-agent" in tok.lower() for tok in argv)
        if not ua_present and (profile.rotate_user_agent or profile.user_agent):
            argv += ["-A", profile.pick_ua()]
    elif t == "wget":
        ua_present = any("user-agent" in tok.lower() or tok in ("-U", "--user-agent") for tok in argv)
        if not ua_present and (profile.rotate_user_agent or profile.user_agent):
            argv += [f"--user-agent={profile.pick_ua()}"]
    return argv


__all__ = [
    "OpsecProfile", "PROFILES", "get_profile", "apply_to_argv",
]
