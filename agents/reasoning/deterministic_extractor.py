"""
agents/reasoning/deterministic_extractor.py

Layer 1 of the 3-layer Question Engine pipeline.
Extracts answers from intel + raw tool output using pure regex/heuristics.
No LLM calls — fast, reliable, deterministic.

Also provides a Discovery Pass for Mode 2 (real pentest) that surfaces
noteworthy facts from tool outputs as findings without requiring a hypothesis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ExtractorResult:
    answer:     Optional[str]
    evidence:   str
    confidence: float          # 0.0 – 1.0


@dataclass
class DiscoveryFinding:
    title:        str
    description:  str
    evidence:     str
    finding_type: str   # "version" | "cve" | "credential" | "flag" | "path" | "config"
    severity:     str   # "critical" | "high" | "medium" | "low" | "info"


# ─────────────────────────────────────────────────────────────────────────────
# Main extractor
# ─────────────────────────────────────────────────────────────────────────────

class DeterministicExtractor:
    """
    Pure regex / heuristic extractor.  No network calls, no LLM.

    Two surfaces:
      extract(question, intel, raw_output) → ExtractorResult
          For question-answering: try to answer a specific question.

      discover(raw_output, phase, tool) → List[DiscoveryFinding]
          For discovery mode: scan output for noteworthy facts.
    """

    # ── Flag patterns ─────────────────────────────────────────────────────────
    _FLAG_RE = re.compile(
        r'(?:'
        r'flag\{[^}]+\}'
        r'|FLAG\{[^}]+\}'
        r'|HTB\{[^}]+\}'
        r'|THM\{[^}]+\}'
        r'|ctf\{[^}]+\}'
        r'|picoCTF\{[^}]+\}'
        r'|DUCTF\{[^}]+\}'
        r'|ROOT\{[^}]+\}'
        r'|USER\{[^}]+\}'
        r')',
        re.IGNORECASE,
    )

    # ── Version patterns — (regex, friendly_name) ────────────────────────────
    _VERSION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r'Apache[/ ]([\d]+\.[\d]+\.[\d]+)', re.I),   'Apache'),
        (re.compile(r'nginx[/ ]([\d]+\.[\d]+\.[\d]+)', re.I),    'nginx'),
        (re.compile(r'OpenSSH[_ ]([\d]+\.[\d]+[\w.]*)', re.I),   'OpenSSH'),
        (re.compile(r'vsftpd ([\d]+\.[\d]+\.[\d]+)', re.I),      'vsftpd'),
        (re.compile(r'Samba[/ ]([\d]+\.[\d]+\.[\d]+)', re.I),    'Samba'),
        (re.compile(r'ProFTPD ([\d]+\.[\d]+\.[\d]+)', re.I),     'ProFTPD'),
        (re.compile(r'Microsoft-IIS[/ ]([\d]+\.[\d]+)', re.I),   'IIS'),
        (re.compile(r'PHP[/ ]([\d]+\.[\d]+\.[\d]+)', re.I),      'PHP'),
        (re.compile(r'MySQL[/ ]([\d]+\.[\d]+\.[\d]+)', re.I),    'MySQL'),
        (re.compile(r'PostgreSQL ([\d]+\.[\d]+)', re.I),          'PostgreSQL'),
        (re.compile(r'OpenSSL[/ ]([\d]+\.[\d]+\.[\d]+\w*)', re.I), 'OpenSSL'),
        (re.compile(r'Tomcat[/ ]([\d]+\.[\d]+\.[\d]+)', re.I),   'Tomcat'),
        (re.compile(r'WordPress ([\d]+\.[\d]+\.?[\d]*)', re.I),  'WordPress'),
        (re.compile(r'Drupal ([\d]+\.[\d]+\.?[\d]*)', re.I),     'Drupal'),
    ]

    # ── CVE pattern ───────────────────────────────────────────────────────────
    _CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)

    # ── Interesting paths ──────────────────────────────────────────────────────
    _SENSITIVE_PATH_RE = re.compile(
        r'(?:'
        r'\.git(?:/|$)'
        r'|\.env(?:/|$|\b)'
        r'|/admin(?:/|$)'
        r'|/backup(?:/|$)'
        r'|/config(?:/|$)'
        r'|\.htpasswd'
        r'|wp-config'
        r'|/etc/passwd'
        r'|/etc/shadow'
        r'|/root/'
        r'|/\.ssh/'
        r'|id_rsa'
        r'|\.pem(?:\b|$)'
        r'|\.key(?:\b|$)'
        r')',
        re.I,
    )

    # ── Credential patterns ───────────────────────────────────────────────────
    _CRED_RE = re.compile(
        r'(?:'
        r'(?:password|passwd|secret|pwd)[:\s=]+([^\s\n"\'<>]{4,64})'
        r')',
        re.I,
    )

    # ── Port line pattern (nmap-style) ────────────────────────────────────────
    _PORT_LINE_RE = re.compile(r'(\d{1,5})/(?:tcp|udp)\s+open', re.I)

    # ── IP address ────────────────────────────────────────────────────────────
    _IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    # ── Question keyword groups ───────────────────────────────────────────────
    _Q_PORT      = frozenset(['how many', 'number of', 'count', 'open port', 'ports open'])
    _Q_FLAG      = frozenset(['flag', 'flag{', 'capture the flag', 'user flag', 'root flag', 'get the flag'])
    _Q_OS        = frozenset(['operating system', 'os ', 'what os', 'which os', 'linux', 'windows'])
    _Q_VERSION   = frozenset(['version', 'running', 'what server', 'which server', 'web server',
                              'ftp server', 'ssh version', 'http server'])
    _Q_IP        = frozenset(['ip address', 'hostname', 'host name', 'what is the ip', 'ip of'])
    _Q_SHELL     = frozenset(['shell', 'foothold', 'rce', 'command execution', 'have access', 'got shell'])
    _Q_CRED      = frozenset(['credential', 'password', 'username', 'login', 'cred', 'passwd'])
    _Q_TECH      = frozenset(['technology', 'framework', 'stack', 'cms', 'built with', 'what technology'])
    _Q_PATH      = frozenset(['directory', 'web path', 'endpoint', 'url', 'route', 'page found'])
    _Q_DOMAIN    = frozenset(['domain', 'active directory', ' ad ', 'domain controller', ' dc '])
    _Q_CVE       = frozenset(['cve', 'vulnerability', 'vuln'])

    # ─────────────────────────────────────────────────────────────────────────
    # Public: extract
    # ─────────────────────────────────────────────────────────────────────────

    def extract(
        self,
        question:   str,
        intel:      dict,
        raw_output: str = "",
    ) -> ExtractorResult:
        """
        Try to answer *question* using intel dict + raw_output.
        Returns ExtractorResult with answer=None if nothing found.
        """
        q = question.lower().strip()

        # ── Port count ────────────────────────────────────────────────────────
        if self._matches(q, self._Q_PORT):
            return self._extract_port_count(intel, raw_output)

        # ── Flag ──────────────────────────────────────────────────────────────
        if self._matches(q, self._Q_FLAG):
            return self._extract_flag(q, intel, raw_output)

        # ── IP / hostname ─────────────────────────────────────────────────────
        if self._matches(q, self._Q_IP):
            target = intel.get('target', '')
            if target:
                return ExtractorResult(answer=target,
                                       evidence=f"Target from session: {target}",
                                       confidence=1.0)

        # ── OS ────────────────────────────────────────────────────────────────
        if self._matches(q, self._Q_OS):
            os_guess = intel.get('os_guess', '')
            if os_guess:
                return ExtractorResult(answer=os_guess,
                                       evidence=f"OS detected during recon: {os_guess}",
                                       confidence=0.9)

        # ── Service / version ─────────────────────────────────────────────────
        if self._matches(q, self._Q_VERSION):
            return self._extract_version(q, intel, raw_output)

        # ── CVE ───────────────────────────────────────────────────────────────
        if self._matches(q, self._Q_CVE):
            return self._extract_cve(intel, raw_output)

        # ── Credentials ───────────────────────────────────────────────────────
        if self._matches(q, self._Q_CRED):
            return self._extract_creds(intel)

        # ── Technologies ──────────────────────────────────────────────────────
        if self._matches(q, self._Q_TECH):
            techs = intel.get('technologies', [])
            if techs:
                return ExtractorResult(
                    answer=', '.join(str(t) for t in techs[:10]),
                    evidence="Technologies from web fingerprinting",
                    confidence=0.9,
                )

        # ── Web paths ─────────────────────────────────────────────────────────
        if self._matches(q, self._Q_PATH):
            return self._extract_paths(intel)

        # ── Shell / access ────────────────────────────────────────────────────
        if self._matches(q, self._Q_SHELL):
            if intel.get('shell_access'):
                user = intel.get('current_user', 'unknown')
                return ExtractorResult(
                    answer=f"Yes — shell obtained as {user}",
                    evidence="Shell session active in intel",
                    confidence=1.0,
                )

        # ── Domain / AD ───────────────────────────────────────────────────────
        if self._matches(q, self._Q_DOMAIN):
            domain_info = intel.get('domain_info', {})
            if isinstance(domain_info, dict) and domain_info.get('domain'):
                return ExtractorResult(
                    answer=domain_info['domain'],
                    evidence=str(domain_info),
                    confidence=0.9,
                )

        # ── Last resort: scan raw_output for flag patterns ─────────────────────
        if raw_output:
            m = self._FLAG_RE.search(raw_output)
            if m:
                return ExtractorResult(answer=m.group(0),
                                       evidence=f"Flag found in output",
                                       confidence=0.85)

        return ExtractorResult(answer=None, evidence="", confidence=0.0)

    # ─────────────────────────────────────────────────────────────────────────
    # Public: discover
    # ─────────────────────────────────────────────────────────────────────────

    def discover(
        self,
        raw_output: str,
        phase:      str = "",
        tool:       str = "",
    ) -> List[DiscoveryFinding]:
        """
        Scan raw tool output for noteworthy facts (Mode 2 — Discovery Pass).
        Returns a deduplicated list of DiscoveryFindings.
        """
        findings: List[DiscoveryFinding] = []
        if not raw_output:
            return findings

        seen_titles: set = set()

        def _add(f: DiscoveryFinding) -> None:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                findings.append(f)

        # ── Flags ─────────────────────────────────────────────────────────────
        for m in self._FLAG_RE.finditer(raw_output):
            _add(DiscoveryFinding(
                title       = f"Flag pattern detected: {m.group(0)}",
                description = "A CTF-style flag was found in tool output",
                evidence    = m.group(0),
                finding_type= "flag",
                severity    = "critical",
            ))

        # ── Service versions ──────────────────────────────────────────────────
        for pattern, name in self._VERSION_PATTERNS:
            m = pattern.search(raw_output)
            if m:
                ver = m.group(1)
                _add(DiscoveryFinding(
                    title       = f"Service version: {name} {ver}",
                    description = f"{name} version {ver} identified during {phase or 'scan'}",
                    evidence    = m.group(0),
                    finding_type= "version",
                    severity    = "info",
                ))

        # ── CVEs ──────────────────────────────────────────────────────────────
        for cve in set(self._CVE_RE.findall(raw_output))[:5]:
            _add(DiscoveryFinding(
                title       = f"CVE reference detected: {cve}",
                description = f"{cve} referenced in output — verify exploitability",
                evidence    = cve,
                finding_type= "cve",
                severity    = "high",
            ))

        # ── Sensitive paths ───────────────────────────────────────────────────
        for m in self._SENSITIVE_PATH_RE.finditer(raw_output):
            _add(DiscoveryFinding(
                title       = f"Sensitive path found: {m.group(0)}",
                description = f"Potentially sensitive resource: {m.group(0)}",
                evidence    = m.group(0),
                finding_type= "path",
                severity    = "medium",
            ))

        # ── Credential patterns ───────────────────────────────────────────────
        m = self._CRED_RE.search(raw_output)
        if m:
            _add(DiscoveryFinding(
                title       = "Possible credential in output",
                description = "A credential-like pattern was found in tool output",
                evidence    = m.group(0)[:120],
                finding_type= "credential",
                severity    = "high",
            ))

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _matches(question_lower: str, keyword_set: frozenset) -> bool:
        return any(kw in question_lower for kw in keyword_set)

    def _extract_port_count(self, intel: dict, raw_output: str) -> ExtractorResult:
        """Count open ports from intel first, then raw output."""
        ports = intel.get("open_ports", [])
        if ports:
            port_nums = []
            for p in ports[:20]:
                if isinstance(p, dict):
                    port_nums.append(str(p.get('port', '')))
                else:
                    port_nums.append(str(p))
            evidence = f"Open ports in session intel: {', '.join(port_nums)}"
            return ExtractorResult(answer=str(len(ports)), evidence=evidence, confidence=1.0)

        # Fall back to counting from nmap output
        if raw_output:
            matches = self._PORT_LINE_RE.findall(raw_output)
            if matches:
                unique = list(dict.fromkeys(matches))
                return ExtractorResult(
                    answer   = str(len(unique)),
                    evidence = f"Counted from nmap output: {', '.join(unique[:20])}",
                    confidence = 0.95,
                )
        return ExtractorResult(answer=None, evidence="", confidence=0.0)

    def _extract_flag(self, question_lower: str, intel: dict, raw_output: str) -> ExtractorResult:
        # Check intel store first
        if 'user flag' in question_lower or 'user.txt' in question_lower:
            if intel.get('user_flag'):
                return ExtractorResult(answer=intel['user_flag'],
                                       evidence="Stored in session intel (user_flag)",
                                       confidence=1.0)
        if 'root flag' in question_lower or 'root.txt' in question_lower:
            if intel.get('root_flag'):
                return ExtractorResult(answer=intel['root_flag'],
                                       evidence="Stored in session intel (root_flag)",
                                       confidence=1.0)
        # Scan flags collection in intel
        flags = intel.get('flags', [])
        if flags:
            f = flags[0]
            val = f.get('value', str(f)) if isinstance(f, dict) else str(f)
            return ExtractorResult(answer=val, evidence="From captured flags in intel", confidence=1.0)

        # Scan raw output
        m = self._FLAG_RE.search(raw_output)
        if m:
            return ExtractorResult(answer=m.group(0),
                                   evidence=f"Found in tool output: {m.group(0)}",
                                   confidence=0.95)
        return ExtractorResult(answer=None, evidence="", confidence=0.0)

    def _extract_version(self, question_lower: str, intel: dict, raw_output: str) -> ExtractorResult:
        services_raw = intel.get('services', {}) or {}
        # Normalise services into iterable of dict-or-string entries.
        # Intel stores services as {port: {service, version, ...}} OR list.
        if isinstance(services_raw, dict):
            services = []
            for _p, _s in services_raw.items():
                if isinstance(_s, dict):
                    _entry = dict(_s)
                    _entry.setdefault('port', _p)
                    services.append(_entry)
                else:
                    services.append({'port': _p, 'service': str(_s)})
        elif isinstance(services_raw, list):
            services = services_raw
        else:
            services = []

        # Match specific service keyword
        for name_kw in ['apache', 'nginx', 'iis', 'openssh', 'vsftpd', 'samba',
                         'mysql', 'postgres', 'php', 'tomcat', 'wordpress']:
            if name_kw in question_lower:
                # Check services in intel
                for svc in services:
                    if isinstance(svc, dict):
                        svc_str = (
                            f"{svc.get('service','')} {svc.get('version','')} "
                            f"{svc.get('product','')} {svc.get('banner','')}"
                        ).lower()
                    else:
                        svc_str = str(svc).lower()
                    if name_kw in svc_str:
                        ver_m = re.search(r'[\d]+\.[\d]+[\d.]*', svc_str)
                        if ver_m:
                            return ExtractorResult(
                                answer   = f"{name_kw.capitalize()} {ver_m.group(0)}",
                                evidence = str(svc)[:200],
                                confidence = 0.9,
                            )
                # Check raw output with named patterns
                for pattern, pname in self._VERSION_PATTERNS:
                    if pname.lower() == name_kw:
                        m = pattern.search(raw_output)
                        if m:
                            return ExtractorResult(
                                answer   = f"{pname} {m.group(1)}",
                                evidence = m.group(0),
                                confidence = 0.9,
                            )

        # Generic: return first version string found in raw output
        for pattern, pname in self._VERSION_PATTERNS:
            m = pattern.search(raw_output)
            if m:
                return ExtractorResult(
                    answer   = f"{pname} {m.group(1)}",
                    evidence = m.group(0),
                    confidence = 0.8,
                )

        # Technologies array
        techs = intel.get('technologies', [])
        if techs:
            return ExtractorResult(
                answer   = str(techs[0]),
                evidence = f"Technologies: {', '.join(str(t) for t in techs[:5])}",
                confidence = 0.7,
            )

        return ExtractorResult(answer=None, evidence="", confidence=0.0)

    def _extract_cve(self, intel: dict, raw_output: str) -> ExtractorResult:
        cves = intel.get('cves', [])
        if cves:
            return ExtractorResult(
                answer   = ', '.join(str(c) for c in cves[:5]),
                evidence = "CVEs from vulnerability scan",
                confidence = 0.95,
            )
        found = list(set(self._CVE_RE.findall(raw_output)))[:5]
        if found:
            return ExtractorResult(
                answer   = ', '.join(found),
                evidence = "CVEs from tool output",
                confidence = 0.9,
            )
        return ExtractorResult(answer=None, evidence="", confidence=0.0)

    def _extract_creds(self, intel: dict) -> ExtractorResult:
        creds = intel.get('credentials', [])
        if not creds:
            return ExtractorResult(answer=None, evidence="", confidence=0.0)
        parts = []
        for c in creds[:5]:
            if isinstance(c, dict):
                parts.append(f"{c.get('user', '?')}:{c.get('secret', '***')} ({c.get('service', '')})")
            else:
                parts.append(str(c))
        return ExtractorResult(
            answer   = '; '.join(parts),
            evidence = "Credentials harvested during session",
            confidence = 0.95,
        )

    def _extract_paths(self, intel: dict) -> ExtractorResult:
        web_paths = intel.get('web_paths', [])
        if not web_paths:
            return ExtractorResult(answer=None, evidence="", confidence=0.0)
        parts = []
        for p in web_paths[:10]:
            if isinstance(p, dict):
                parts.append(f"{p.get('path', '')} [{p.get('status', '')}]")
            else:
                parts.append(str(p))
        return ExtractorResult(
            answer   = ', '.join(parts),
            evidence = "Web paths from directory enumeration",
            confidence = 0.85,
        )
