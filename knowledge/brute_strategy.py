"""knowledge/brute_strategy.py — smart, adaptive brute-forcing strategy.

ARGUS must NOT blindly run one huge wordlist with a timeout.  It ESCALATES: a fast
high-yield list first, then progressively larger lists, then a technique change
(password-spray to dodge lockout, AS-REP-roast / Kerberoast for AD, and OFFLINE
hash-cracking with rules + rainbow tables) — using the wordlists already on the Kali
host.  Pure + data-driven so it is consistent and unit-testable; the operator (LLM) is
handed this ladder as guidance and the background-brute runner auto-suggests the next
rung when a run finds nothing.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# ── Tiered wordlists (fast → deep), as the paths SecLists / Kali ship them ─────
_USER_LADDER: List[Dict[str, str]] = [
    {"tier": "fast",  "path": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt", "note": "~17 ubiquitous accounts"},
    {"tier": "names", "path": "/usr/share/seclists/Usernames/Names/names.txt",             "note": "common first names"},
    {"tier": "deep",  "path": "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt", "note": "10M real usernames"},
]
_PASS_LADDER: List[Dict[str, str]] = [
    {"tier": "defaults", "path": "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt", "note": "vendor/default creds — try FIRST"},
    {"tier": "fast",     "path": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt", "note": "top 100"},
    {"tier": "common",   "path": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt", "note": "top 10k"},
    {"tier": "rockyou",  "path": "/usr/share/wordlists/rockyou.txt", "note": "rockyou (~14M)"},
    {"tier": "deep",     "path": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt", "note": "top 1M"},
]

# ── Offline cracking: the RIGHT mode + rules / rainbow tables per hash type ────
_CRACK: Dict[str, str] = {
    "ntlm":        "hashcat -m 1000 <hashes> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule  (or NTLM rainbow tables: rcracki_mt / ophcrack tables)",
    "lm":          "ophcrack with the XP-free-fast rainbow tables, or hashcat -m 3000",
    "netntlmv2":   "hashcat -m 5600 <hashes> rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
    "kerberos_tgs":"hashcat -m 13100 (Kerberoast TGS-REP) rockyou.txt -r OneRuleToRuleThemAll.rule",
    "asrep":       "hashcat -m 18200 (AS-REP) rockyou.txt -r best64.rule",
    "md5":         "hashcat -m 0 rockyou.txt -r best64.rule  (or an MD5 rainbow table)",
    "sha1":        "hashcat -m 100 rockyou.txt -r best64.rule",
    "sha512crypt": "hashcat -m 1800 — SLOW; use a targeted list + rules, not full rockyou",
    "bcrypt":      "hashcat -m 3200 — VERY slow; targeted/short list + rules only",
    "mysql":       "hashcat -m 300 rockyou.txt",
}

# Services where ONLINE brute is the wrong first move (spray / roast first).
_AD_SERVICES = ("kerberos", "ldap", "smb", "winrm", "ad", "active directory",
                "389", "445", "88", "636", "5985")


def wordlist_ladder(kind: str = "password") -> List[Dict[str, str]]:
    """The escalation ladder of wordlists (fast → deep) for 'password' or 'username'."""
    return [dict(x) for x in (_USER_LADDER if str(kind).lower().startswith("user") else _PASS_LADDER)]


def next_wordlist(kind: str, tried_paths: Optional[List[str]]) -> Optional[Dict[str, str]]:
    """The NEXT untried rung on the ladder (so a no-hit run escalates), or None when
    the deepest list has already been tried (time to switch technique / crack offline)."""
    tried = set(tried_paths or [])
    for rung in wordlist_ladder(kind):
        if rung["path"] not in tried:
            return rung
    return None


def technique_plan(service: str = "") -> List[str]:
    """The ordered technique escalation for a service — smarter than per-user brute."""
    s = (service or "").lower()
    if any(k in s for k in _AD_SERVICES):
        return [
            "AS-REP roast (impacket GetNPUsers) — grabs crackable hashes for users with no "
            "pre-auth, NO password needed",
            "Kerberoast (GetUserSPNs) any SPN account → crack the TGS-REP offline",
            "PASSWORD-SPRAY one common password across ALL users (e.g. Season+Year, Welcome1) "
            "to avoid account lockout — never per-user brute on AD first",
            "only then a small-list per-user brute on a confirmed valid user",
            "crack every captured hash OFFLINE with hashcat + rules / NTLM rainbow tables",
        ]
    return [
        "try DEFAULT / vendor credentials first",
        "fast small list (top-100) before any big list",
        "escalate the wordlist tier ONLY on a no-hit",
        "if you capture password HASHES, stop online-brute and crack them OFFLINE with "
        "hashcat + rules / rainbow tables (far faster, no lockout, no network noise)",
    ]


def crack_guidance(hash_type: str = "") -> str:
    h = (hash_type or "").lower().replace("-", "").replace(" ", "")
    for key, guide in _CRACK.items():
        if key.replace("_", "") in h:
            return guide
    return _CRACK["ntlm"]


def advisory(service: str = "", kind: str = "password",
             tried_paths: Optional[List[str]] = None, found: bool = False) -> str:
    """A compact escalation advisory for the operator so brute-forcing is SMART +
    ADAPTIVE (different wordlists, spray, rainbow tables) — never one fixed run.
    ``found`` short-circuits to a 'use the creds' nudge."""
    if found:
        return ("[brute strategy] Credentials recovered — STOP brute-forcing this service and "
                "USE the creds (auth, dump, pivot). Spray them across other hosts/services too.")
    nxt = next_wordlist(kind, tried_paths)
    lines = ["[brute strategy] No hit yet — do NOT just retry the same list. ESCALATE / ADAPT:"]
    if nxt:
        lines.append(f"  • next wordlist: {nxt['path']}  ({nxt['tier']} — {nxt['note']})")
    else:
        lines.append("  • wordlists exhausted → switch TECHNIQUE (below) or crack hashes offline.")
    for i, step in enumerate(technique_plan(service), 1):
        lines.append(f"  {i}. {step}")
    lines.append("  • captured hashes → " + crack_guidance(""))
    return "\n".join(lines)
