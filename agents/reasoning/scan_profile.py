"""Hypothesis-conditioned scan profile builder.

Improvement #7 — without conditioning, every recon / vuln-id / web phase
runs the full default playbook (e.g. ``nmap --script vuln`` against all
ports, full nuclei templates, full directory wordlists).  Once we have
high-confidence hypotheses about *what* the target probably is, scanning
should bias toward those services, ports, CVEs and tech, both for speed
and to avoid drowning the LLM context in irrelevant output.

This module distills the live ``Hypothesis`` list into a compact
:class:`ScanProfile`.  The profile is dropped onto ``intel["scan_profile"]``
and rendered into ``_intel_summary``, so every existing LLM phase planner
that already reads ``_intel_summary`` automatically picks up the bias —
no change to the planners themselves required.

The extraction is regex/keyword-based and intentionally cheap: this runs
once per reasoning iteration on a list rarely exceeding ~10 hypotheses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set


__all__ = ["ScanProfile", "build_scan_profile"]


# ── Regex patterns for evidence-mining ────────────────────────────────────
_RE_PORT     = re.compile(r"\b(?:port[s]?\s*[:=]?\s*|:)?(\d{2,5})\b")
_RE_CVE      = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_RE_PATH     = re.compile(r"(?:^|\s)(/[A-Za-z0-9_\-./?=&]+)")
_RE_HOST     = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:\.[a-z]{2,})?)\b",
    re.IGNORECASE,
)

# Service / tech keywords we recognise inside hypothesis text
_SERVICE_KEYWORDS = {
    "http": "http", "https": "https", "ssh": "ssh", "ftp": "ftp",
    "smb": "smb", "smbv1": "smb", "rdp": "rdp", "telnet": "telnet",
    "mysql": "mysql", "mssql": "mssql", "postgres": "postgresql",
    "postgresql": "postgresql", "mongodb": "mongodb", "redis": "redis",
    "ldap": "ldap", "kerberos": "kerberos", "dns": "dns",
    "snmp": "snmp", "rpc": "rpc", "nfs": "nfs", "vnc": "vnc",
    "winrm": "winrm", "wmi": "wmi", "ntp": "ntp",
    "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
    "apache": "http", "nginx": "http", "iis": "http", "tomcat": "http",
    "jenkins": "http", "gitlab": "http", "phpmyadmin": "http",
}

# Common service → default port mapping (helps fill priority_ports when
# only a service name appears in the statement)
_SERVICE_DEFAULT_PORTS = {
    "http": [80, 8080, 8000, 8888],
    "https": [443, 8443],
    "ssh": [22],
    "ftp": [21],
    "smb": [445, 139],
    "rdp": [3389],
    "telnet": [23],
    "mysql": [3306],
    "mssql": [1433],
    "postgresql": [5432],
    "mongodb": [27017],
    "redis": [6379],
    "ldap": [389, 636],
    "kerberos": [88],
    "dns": [53],
    "snmp": [161],
    "nfs": [2049],
    "vnc": [5900],
    "winrm": [5985, 5986],
}

# Ports we ignore when extracting from free-text (years, CVE numbers, etc.)
_PORT_BLACKLIST = {19, 20, 21, 80, 443}  # only blacklisted if seen alone w/o context


@dataclass
class ScanProfile:
    """Compact, hypothesis-derived bias for upcoming scans."""

    priority_ports:    List[int]      = field(default_factory=list)
    priority_services: List[str]      = field(default_factory=list)
    priority_cves:     List[str]      = field(default_factory=list)
    priority_paths:    List[str]      = field(default_factory=list)
    priority_hosts:    List[str]      = field(default_factory=list)
    hypothesis_ids:    List[str]      = field(default_factory=list)
    top_statement:     str            = ""
    iteration:         int            = 0
    generated_at:      str            = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "priority_ports":    list(self.priority_ports),
            "priority_services": list(self.priority_services),
            "priority_cves":     list(self.priority_cves),
            "priority_paths":    list(self.priority_paths),
            "priority_hosts":    list(self.priority_hosts),
            "hypothesis_ids":    list(self.hypothesis_ids),
            "top_statement":     self.top_statement,
            "iteration":         self.iteration,
            "generated_at":      self.generated_at,
        }

    def is_empty(self) -> bool:
        return not (self.priority_ports or self.priority_services
                    or self.priority_cves or self.priority_paths
                    or self.priority_hosts)

    def render_for_prompt(self) -> str:
        """Compact multi-line block injected into LLM phase planners."""
        if self.is_empty():
            return ""
        lines = ["=== HYPOTHESIS-CONDITIONED SCAN PROFILE ==="]
        if self.top_statement:
            lines.append(f"Top hypothesis : {self.top_statement[:160]}")
        if self.priority_services:
            lines.append(f"Priority svcs  : {', '.join(self.priority_services[:8])}")
        if self.priority_ports:
            lines.append(f"Priority ports : {', '.join(str(p) for p in self.priority_ports[:12])}")
        if self.priority_cves:
            lines.append(f"Priority CVEs  : {', '.join(self.priority_cves[:8])}")
        if self.priority_paths:
            lines.append(f"Priority paths : {', '.join(self.priority_paths[:8])}")
        if self.priority_hosts:
            lines.append(f"Priority hosts : {', '.join(self.priority_hosts[:6])}")
        lines.append(
            "Bias scans toward these — drop the catch-all defaults unless "
            "the priorities are exhausted."
        )
        return "\n".join(lines)


def _extract_ports(text: str, intel_ports: Set[int]) -> List[int]:
    """Pull port numbers from text, keeping only those that look like real
    ports — i.e. either currently open on the target, or *explicitly* tagged
    by a "port" keyword.  Strips CVE identifiers and version strings first
    so trailing digits don't get mistaken for ports."""
    if not text:
        return []
    # Strip CVE identifiers and dotted version numbers so their digits
    # don't pollute the port match.
    cleaned = _RE_CVE.sub(" ", text)
    cleaned = re.sub(r"\d+(?:\.\d+){1,}", " ", cleaned)
    out: List[int] = []
    # Trusted ports = those explicitly preceded by "port" / "ports" / ":"
    for m in re.finditer(r"\bports?\s*[:=]?\s*(\d{1,5})", cleaned, re.IGNORECASE):
        try:
            p = int(m.group(1))
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535:
            out.append(p)
    # Also trust intel-confirmed open ports if they happen to appear
    for m in re.finditer(r"\b(\d{2,5})\b", cleaned):
        try:
            p = int(m.group(1))
        except (TypeError, ValueError):
            continue
        if p in intel_ports:
            out.append(p)
    return out


def _extract_services(text: str) -> List[str]:
    out: List[str] = []
    low = (text or "").lower()
    for kw, canonical in _SERVICE_KEYWORDS.items():
        if re.search(rf"\b{re.escape(kw)}\b", low):
            out.append(canonical)
    return out


def _extract_cves(text: str) -> List[str]:
    return [m.group(0).upper() for m in _RE_CVE.finditer(text or "")]


def _extract_paths(text: str) -> List[str]:
    paths: List[str] = []
    for m in _RE_PATH.finditer(text or ""):
        p = m.group(1).strip(".,;:)")
        # filter file-path noise like /usr/bin or version strings like /1.18
        if len(p) > 1 and not p.startswith("/usr") and not p.startswith("/etc"):
            paths.append(p)
    return paths


def _extract_hosts(text: str) -> List[str]:
    hosts: List[str] = []
    for m in _RE_HOST.finditer(text or ""):
        h = m.group(1)
        # strip false positives that are really CVE-2021-x or version "2.4.49"
        if re.fullmatch(r"\d+(?:\.\d+){2,}", h):
            continue
        hosts.append(h.lower())
    return hosts


def _dedupe_keep_order(items: Iterable) -> List:
    seen = set()
    out  = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def build_scan_profile(
    hypotheses: List[Any],
    intel: Dict[str, Any],
    *,
    top_n: int = 5,
    iteration: int = 0,
) -> ScanProfile:
    """Build a ``ScanProfile`` biased by the top-N highest-confidence,
    not-yet-invalidated hypotheses.

    Parameters
    ----------
    hypotheses:
        Live hypothesis list (objects with ``confidence``, ``statement``,
        ``required_evidence``, ``recommended_next_actions``,
        ``invalidated``, ``hypothesis_id``).  Untyped on purpose so we
        don't import ``HypothesisEngine`` here (avoids a cycle).
    intel:
        Current intel dict; we read ``open_ports`` to validate port
        extractions.
    top_n:
        How many hypotheses to consider.
    iteration:
        Current reasoning iteration (recorded on the profile).
    """
    # Filter + sort — copy so we don't mutate caller's list
    live = [h for h in (hypotheses or [])
            if not getattr(h, "invalidated", False)]
    live.sort(key=lambda h: float(getattr(h, "confidence", 0.0) or 0.0),
              reverse=True)
    live = live[:top_n]

    intel_ports: Set[int] = set()
    for p in (intel or {}).get("open_ports", []) or []:
        try:
            intel_ports.add(int(p))
        except (TypeError, ValueError):
            continue

    ports:    List[int] = []
    services: List[str] = []
    cves:     List[str] = []
    paths:    List[str] = []
    hosts:    List[str] = []
    h_ids:    List[str] = []

    for h in live:
        statement = str(getattr(h, "statement", "") or "")
        evidence  = list(getattr(h, "required_evidence", []) or [])
        actions   = list(getattr(h, "recommended_next_actions", []) or [])
        # Flatten action dicts into searchable text
        action_text = " ".join(
            str(a.get("target", "")) + " " + str(a.get("tool", "")) + " " + str(a.get("rationale", ""))
            if isinstance(a, dict) else str(a)
            for a in actions
        )
        blob = " ".join([statement, " ".join(str(e) for e in evidence), action_text])

        ports.extend(_extract_ports(blob, intel_ports))
        services.extend(_extract_services(blob))
        cves.extend(_extract_cves(blob))
        paths.extend(_extract_paths(blob))
        hosts.extend(_extract_hosts(blob))
        h_id = getattr(h, "hypothesis_id", None)
        if h_id:
            h_ids.append(h_id)

    # Augment ports with default ports for any priority service that has no
    # explicit port (so `priority_services=["smb"]` implies ports 445/139).
    services_dedup = _dedupe_keep_order(services)
    for svc in services_dedup:
        for default_port in _SERVICE_DEFAULT_PORTS.get(svc, []):
            if default_port in intel_ports and default_port not in ports:
                ports.append(default_port)

    top_stmt = str(getattr(live[0], "statement", "")) if live else ""

    return ScanProfile(
        priority_ports    = _dedupe_keep_order(ports),
        priority_services = services_dedup,
        priority_cves     = _dedupe_keep_order(cves),
        priority_paths    = _dedupe_keep_order(paths),
        priority_hosts    = _dedupe_keep_order(hosts),
        hypothesis_ids    = h_ids,
        top_statement     = top_stmt,
        iteration         = iteration,
    )
