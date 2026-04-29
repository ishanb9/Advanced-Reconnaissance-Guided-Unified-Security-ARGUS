"""Output-grounded confidence — Issue Validator hard gate (Improvement #14).

Without this gate, the reasoning loop's ``_validate`` step happily flips
a hypothesis to **validated=True** based on either a coarse string
heuristic (``"shell" in stdout``) or — worse — the LLM judge's vibe.
That is how SQLi, RCE, and credential-discovery findings end up in the
report when the underlying tool actually crashed, returned empty
output, or printed a generic banner.

The Issue Validator is a *hard gate*: before a hypothesis is allowed
to validate, the raw tool output must contain at least one **concrete
evidence pattern** matching the hypothesis class.  Hypothesis classes
are inferred from MITRE technique, statement keywords, and tool family.
Each class has a small table of regexes; a match yields one or more
``evidence_quotes``.  If nothing matches, ``grounded=False`` and the
caller is expected to keep the hypothesis at "suspected" and downgrade
confidence rather than confirm.

The validator is deliberately conservative: false negatives (a true
finding gets stuck at suspected) just mean another iteration; false
positives (an unconfirmed finding ships to the report) are the loud
failure mode we are trying to eliminate.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


__all__ = [
    "IssueValidation", "validate_grounding", "infer_class",
    "EVIDENCE_PATTERNS", "FAILURE_PATTERNS",
]


# ── Hypothesis-class taxonomy ──────────────────────────────────────────
# Each class label maps to a list of (label, compiled_regex, weight).
# Weight 2 = strong tell, 1 = soft tell.  Multiple matches across a class
# stack additively, so a SQLi hypothesis grounded by both an error string
# AND a column-count tell scores higher than one grounded by only one.

EVIDENCE_PATTERNS: Dict[str, List[Tuple[str, "re.Pattern[str]", int]]] = {
    # ── Shell / RCE ────────────────────────────────────────────────
    "shell_obtained": [
        ("interactive prompt",       re.compile(r"(?:^|\n)\s*(?:[a-z0-9_.\-]+@[a-z0-9_.\-]+:[^\n]*[#$])\s*$", re.I | re.M), 2),
        ("uid line",                 re.compile(r"\buid=\d+\([^)]+\)\s+gid=\d+", re.I), 2),
        ("whoami output",            re.compile(r"(?:^|\n)(?:nt authority\\\\\w+|root|administrator|[a-z][a-z0-9_-]{0,30})\s*\r?$", re.I | re.M), 1),
        ("meterpreter banner",       re.compile(r"\bmeterpreter\s*>\s*", re.I), 2),
        ("windows cmd banner",       re.compile(r"microsoft windows \[version", re.I), 2),
        ("flag captured",            re.compile(r"\b(?:flag|HTB|THM|picoCTF)\{[^}]+\}", re.I), 2),
    ],

    "rce": [
        ("command echo round-trip",  re.compile(r"\buname\s+-a\b|\bsystem\s*\(\s*['\"][^'\"]+['\"]\s*\)", re.I), 2),
        ("kernel/release banner",    re.compile(r"\b(?:Linux\s+\S+\s+\d+\.\d+\.\d+|Darwin\s+\S+\s+\d+\.\d+)", re.I), 2),
        ("PATH var leak",            re.compile(r"PATH=/[a-z/:]+", re.I), 1),
        ("etc passwd echo",          re.compile(r"^\s*root:[^:]*:0:0:", re.M), 2),
    ],

    # ── Credentials / hashes ──────────────────────────────────────
    "credentials_found": [
        ("user:pass cleartext",      re.compile(r"\b[a-z][a-z0-9._-]{1,30}:[^\s:]{4,}\b"), 1),
        ("ntlm hash",                re.compile(r"\b[a-f0-9]{32}:[a-f0-9]{32}\b", re.I), 2),
        ("md5 hash",                 re.compile(r"\b[a-f0-9]{32}\b", re.I), 1),
        ("sha1 hash",                re.compile(r"\b[a-f0-9]{40}\b", re.I), 1),
        ("kerberos krb5tgs",         re.compile(r"\$krb5tgs\$\d+\$", re.I), 2),
        ("kerberos krb5asrep",       re.compile(r"\$krb5asrep\$\d+\$", re.I), 2),
        ("hashcat success",          re.compile(r"Status\.+:\s*Cracked|Recovered\.+:\s*\d+/\d+\s*\(", re.I), 2),
        ("hydra valid login",        re.compile(r"\[\d+\]\[\S+\]\s+host:.*\s+login:\s+\S+\s+password:\s+\S+", re.I), 2),
        ("smb success",              re.compile(r"\[\+\]\s+\S+\s+\\\\?\S+:\S+\s+\(Pwn3d!\)?", re.I), 2),
    ],

    # ── SQL injection ─────────────────────────────────────────────
    "sql_injection": [
        ("sqlmap injectable banner", re.compile(r"\bparameter\s+'\S+'\s+is\s+vulnerable\b|\bsqlmap identified the following injection point", re.I), 2),
        ("dbms fingerprint",         re.compile(r"\bback-end DBMS:\s+\w+|\bcurrent database:\s+'\S+'", re.I), 2),
        ("error-based oracle",       re.compile(r"(?:You have an error in your SQL syntax|Warning:\s+mysql_|ORA-\d+:|Microsoft OLE DB Provider for SQL Server|PostgreSQL.*ERROR)", re.I), 2),
        ("union column count",       re.compile(r"\bUNION\s+SELECT.*--", re.I), 1),
        ("table dump rows",          re.compile(r"^\|\s*\d+\s*\|\s*[^|]+\s*\|", re.M), 2),
    ],

    # ── XSS ───────────────────────────────────────────────────────
    "xss": [
        ("dalfox triaged poc",       re.compile(r"\[V\]|\bPOC:\s*\S+\?.*=\s*<", re.I), 2),
        ("reflected payload",        re.compile(r"<script[^>]*>(?:alert|prompt|confirm)\(", re.I), 2),
        ("xsstrike vulnerable",      re.compile(r"\bvulnerable\s+to\s+XSS\b|\breflection found", re.I), 2),
    ],

    # ── LFI / path traversal ──────────────────────────────────────
    "lfi": [
        ("etc passwd content",       re.compile(r"^\s*root:[^:]*:0:0:", re.M), 2),
        ("win32.ini content",        re.compile(r"\[boot loader\]|\[fonts\]\s*\n", re.I), 2),
        ("php source disclosure",    re.compile(r"<\?php\s+", re.I), 1),
    ],

    # ── SSRF ──────────────────────────────────────────────────────
    "ssrf": [
        ("internal metadata",        re.compile(r"169\.254\.169\.254|/computeMetadata/v1/|instance-identity/", re.I), 2),
        ("oast callback",            re.compile(r"\.(?:interact\.sh|burpcollaborator\.net|oast\.\w+)\b", re.I), 2),
    ],

    # ── Open ports / services ─────────────────────────────────────
    "service_discovered": [
        ("nmap open line",           re.compile(r"^\s*\d{1,5}/(?:tcp|udp)\s+open\s+\S+", re.M), 2),
        ("masscan open",             re.compile(r"Discovered\s+open\s+port\s+\d+", re.I), 2),
    ],

    # ── CVE / vuln confirmation ───────────────────────────────────
    "cve_confirmed": [
        ("nuclei matched",           re.compile(r"\[(?:critical|high|medium|low|info)\][^\n]*\bCVE-\d{4}-\d+\b", re.I), 2),
        ("metasploit check vuln",    re.compile(r"\bThe target (?:is|appears to be)\s+vulnerable\b", re.I), 2),
        ("smb-vuln-ms17-010",        re.compile(r"VULNERABLE:\s*Remote Code Execution vulnerability in Microsoft SMBv1|\bMS17-010\b", re.I), 2),
        ("eternal blue check",       re.compile(r"\beternalblue.*\bvulnerable\b", re.I), 2),
        ("apache 2.4.49 traversal",  re.compile(r"%2e%2e/%2e%2e/etc/passwd|/cgi-bin/.*?\.\./", re.I), 2),
    ],

    # ── Web paths / login ─────────────────────────────────────────
    "web_path_found": [
        ("gobuster/feroxbuster hit", re.compile(r"^\s*(?:/\S+)\s+(?:\(Status:\s*\d+\)|\d{3}\s+\d+l)\b", re.M | re.I), 2),
        ("ffuf json hit",            re.compile(r'"status":\s*200\b.*?"url":', re.I), 1),
    ],

    # ── Privilege escalation ──────────────────────────────────────
    "privesc": [
        ("linpeas critical",         re.compile(r"\b95%\s+PE\b|\[\+\]\s+\[CVE-\d{4}-\d+\]\s+\[", re.I), 2),
        ("suid binary tell",         re.compile(r"-rws[r-][\sx]+root\s+root\s+\S+", re.I), 2),
        ("sudo nopasswd",            re.compile(r"\bNOPASSWD:\s*ALL\b|\(root\)\s+NOPASSWD:", re.I), 2),
        ("kernel exploit poc",       re.compile(r"\bCVE-\d{4}-\d+.*\b(?:dirtycow|dirtypipe|pwnkit|polkit)\b", re.I), 2),
    ],
}


# Patterns that indicate the action FAILED outright — used to short-circuit
# grounding (no point searching for evidence in a hard error).
FAILURE_PATTERNS: List["re.Pattern[str]"] = [
    re.compile(r"\bconnection refused\b|\bno route to host\b|\bnetwork is unreachable\b", re.I),
    re.compile(r"\b(?:command|module)\s+not\s+found\b", re.I),
    re.compile(r"\bpermission denied\b", re.I),
    re.compile(r"\bsegmentation fault\b|\btraceback \(most recent call last\)", re.I),
    re.compile(r"\bexploit failed\b|\bexploit completed, but no session was created\b", re.I),
    re.compile(r"\bauth(?:entication)? failed\b|\b401\s+unauthorized\b|\b403\s+forbidden\b\s*$", re.I),
    re.compile(r"\bno such file or directory\b", re.I),
]


# Class-inference keywords (lowercase substring match against statement / mitre).
_CLASS_KEYWORDS: List[Tuple[str, Tuple[str, ...]]] = [
    ("shell_obtained",      ("shell", "rce-to-shell", "interactive shell", "meterpreter")),
    ("rce",                 ("rce", "remote code execution", "command injection", "execute commands")),
    ("credentials_found",   ("credential", "password", "hash", "kerberoast", "asreproast", "ntlm")),
    ("sql_injection",       ("sql injection", "sqli", "sqlmap")),
    ("xss",                 ("xss", "cross-site scripting")),
    ("lfi",                 ("lfi", "local file inclusion", "path traversal", "directory traversal")),
    ("ssrf",                ("ssrf", "server-side request forgery")),
    ("cve_confirmed",       ("cve-", "ms17-010", "eternalblue", "log4shell", "shellshock", "heartbleed", "proxylogon")),
    ("privesc",             ("privesc", "privilege escalation", "suid", "sudo", "kernel exploit", "dirtypipe", "pwnkit")),
    ("service_discovered",  ("port scan", "service enumeration", "open port")),
    ("web_path_found",      ("directory bust", "content discovery", "hidden endpoint", "admin panel")),
]


# MITRE technique → class hints (covers most ATT&CK families we use).
_MITRE_HINTS: Dict[str, str] = {
    "T1190": "rce",
    "T1059": "rce",
    "T1110": "credentials_found",
    "T1003": "credentials_found",
    "T1558": "credentials_found",
    "T1548": "privesc",
    "T1068": "privesc",
    "T1078": "credentials_found",
    "T1505": "shell_obtained",
    "T1046": "service_discovered",
    "T1595": "service_discovered",
    "T1566": "credentials_found",
}


# ── Verdict object ─────────────────────────────────────────────────────

@dataclass
class IssueValidation:
    grounded:        bool   = False
    score:           float  = 0.0
    issue_class:     str    = ""
    evidence_quotes: List[str] = field(default_factory=list)
    missing_signals: List[str] = field(default_factory=list)
    failure_signal:  str    = ""
    reason:          str    = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grounded":        self.grounded,
            "score":           round(self.score, 3),
            "issue_class":     self.issue_class,
            "evidence_quotes": list(self.evidence_quotes[:5]),
            "missing_signals": list(self.missing_signals[:6]),
            "failure_signal":  self.failure_signal,
            "reason":          self.reason,
        }


# ── Public API ─────────────────────────────────────────────────────────

def infer_class(*, statement: str = "", mitre: str = "",
                tool: str = "") -> str:
    """Best-effort inference of the issue class from hypothesis fields."""
    statement_low = (statement or "").lower()
    tool_low      = (tool or "").lower()
    mitre_up      = (mitre or "").upper().split(".")[0]

    # 1. Tool family — single-purpose tools are the strongest, most
    # unambiguous signal (sqlmap is always SQLi; nuclei always CVE).
    if tool_low in {"sqlmap", "xsstrike", "dalfox", "commix"}:
        return {"sqlmap": "sql_injection", "xsstrike": "xss",
                "dalfox": "xss", "commix": "rce"}[tool_low]
    if tool_low in {"hydra", "medusa", "patator", "kerbrute",
                    "impacket-getuserspns", "impacket-getnpusers",
                    "impacket-secretsdump"}:
        return "credentials_found"
    if tool_low in {"nmap", "masscan", "rustscan", "naabu"}:
        return "service_discovered"
    if tool_low in {"gobuster", "ffuf", "feroxbuster", "dirb", "wfuzz"}:
        return "web_path_found"
    if tool_low in {"linpeas", "winpeas"}:
        return "privesc"
    if tool_low.startswith("nuclei"):
        return "cve_confirmed"

    # 2. MITRE technique fallback.
    if mitre_up in _MITRE_HINTS:
        return _MITRE_HINTS[mitre_up]

    # 3. Statement keyword scan.
    for cls, kws in _CLASS_KEYWORDS:
        if any(k in statement_low for k in kws):
            return cls

    return "generic"


def _check_failure(stdout: str) -> str:
    for pat in FAILURE_PATTERNS:
        m = pat.search(stdout or "")
        if m:
            return m.group(0)[:120]
    return ""


def validate_grounding(
    *, statement: str = "",
    mitre:        str = "",
    tool:         str = "",
    stdout:       str = "",
    exit_code:    int = 0,
    issue_class:  Optional[str] = None,
) -> IssueValidation:
    """Hard-gate validator — returns ``IssueValidation`` with grounding=True
    iff ``stdout`` contains a concrete evidence pattern for the inferred
    issue class.

    Caller MUST refuse to flip the hypothesis to validated=True unless
    ``grounded`` is True.  When grounded is False the caller should
    still ingest any partial evidence but keep the hypothesis at
    "suspected" / unvalidated.
    """
    cls = issue_class or infer_class(statement=statement, mitre=mitre, tool=tool)
    iv = IssueValidation(issue_class=cls)

    blob = (stdout or "")[:8000]   # cap to keep regex bounded

    # Short-circuit: hard failure trumps everything.
    fail = _check_failure(blob)
    if fail:
        iv.grounded       = False
        iv.failure_signal = fail
        iv.reason         = f"hard failure detected: '{fail}'"
        return iv

    patterns = EVIDENCE_PATTERNS.get(cls) or []
    if not patterns:
        # Generic / unknown class → fall back to exit-code heuristic but
        # mark grounded=False so callers know not to elevate confidence.
        iv.grounded = False
        iv.reason   = (f"no evidence patterns for class '{cls}' — "
                       f"exit_code={exit_code}, refuse to elevate")
        return iv

    matched_total: List[str] = []
    weight_sum = 0
    for label, pat, weight in patterns:
        m = pat.search(blob)
        if not m:
            continue
        snippet = m.group(0)[:160].replace("\n", " ").strip()
        matched_total.append(f"[{label}] {snippet}")
        weight_sum += weight

    if matched_total:
        iv.grounded = True
        iv.evidence_quotes = matched_total
        # Score: weight_sum normalised by max possible weight in this class
        max_weight = sum(w for _, _, w in patterns)
        iv.score   = min(1.0, weight_sum / max(1, max_weight) + 0.25)
        iv.reason  = (f"{len(matched_total)} evidence pattern(s) matched "
                      f"for class '{cls}' (weight={weight_sum}/{max_weight})")
    else:
        iv.grounded = False
        iv.missing_signals = [label for label, _, _ in patterns[:5]]
        iv.reason = (f"no evidence patterns matched for class '{cls}' "
                     f"in {len(blob)} chars of output")

    return iv
