"""
web_vuln_scan_subagent.py — General web vulnerability scanning via nikto and nuclei.

Methodology:
  1. nikto -h target  — broad web vulnerability check (CGI, misconfigs, old software)
  2. nuclei -u target — template-based CVE/misconfiguration detection
  3. Parse nikto findings by OSVDB/CVE reference and severity keywords
  4. Parse nuclei output: template name, severity, CVE, matcher
  5. Map findings to Finding objects with proper severity
  6. Emit "web_vuln_scan_complete" with summary
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Nikto line parsers
# ---------------------------------------------------------------------------
# Example: + OSVDB-637: /~root: Allowed to browse root's home directory.
# Example: + /admin/: This might be interesting.
_NIKTO_FINDING_RE = re.compile(
    r"^\+\s+(?:(OSVDB-\d+|CVE-[\d-]+):\s+)?(.+)",
    re.IGNORECASE,
)

_NIKTO_SEVERITY_KEYWORDS = {
    "CRITICAL": [
        "remote code execution", "rce", "command injection", "arbitrary command",
        "shell", "shellshock", "log4j",
    ],
    "HIGH": [
        "sql injection", "sqli", "auth bypass", "authentication bypass",
        "directory traversal", "path traversal", "file inclusion", "xxe",
        "ssrf", "default password", "default credential", "admin interface",
        "exposed admin", "anonymous", "unauthenticated",
    ],
    "MEDIUM": [
        "xss", "cross-site scripting", "csrf", "clickjacking",
        "information disclosure", "directory listing", "server version",
        "x-powered-by", "outdated", "deprecated", "phpinfo", "debug",
        "test page", "backup file", "config file",
    ],
    "LOW": [
        "missing header", "cookie", "secure flag", "httponly", "hsts",
        "banner", "comment", "internal ip", "email address",
    ],
}

# nuclei output line
# [template-id] [protocol] [severity] url [matcher-name]
_NUCLEI_LINE_RE = re.compile(
    r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)(?:\s+\[([^\]]+)\])?",
    re.IGNORECASE,
)

_NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "unknown":  "INFO",
}

# CVE extractor
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class WebVulnScanSubagent(BaseSubagent):
    """
    General web vulnerability scanning: nikto for broad checks, nuclei for
    template-based CVE/misconfiguration detection.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "web_vuln_scan"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Run nikto + nuclei against all web targets.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            List of URL dicts. Falls back to http://{target} if not provided.

        Returns
        -------
        SubagentResult
            parsed_data["nikto_findings"]  — list of nikto finding dicts
            parsed_data["nuclei_findings"] — list of nuclei finding dicts
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {
            "nikto_findings":  [],
            "nuclei_findings": [],
        }
        wall_start = time.monotonic()

        urls: list[str] = []
        if web_targets:
            urls = [wt["url"] for wt in web_targets if isinstance(wt, dict) and "url" in wt]
        if not urls:
            urls = [f"http://{target}"]

        nikto_findings:  list[dict] = []
        nuclei_findings: list[dict] = []

        for url in urls:
            port = _port_from_url(url)

            # ── nikto ────────────────────────────────────────────────────
            logger.info("[web_vuln_scan] nikto on %s", url)
            try:
                nikto_out = await self.collect_tool(
                    "nikto",
                    target,
                    {
                        "options": (
                            f"-h {url} -C all -timeout 10 "
                            f"-nointeractive -Format txt"
                        )
                    },
                )
                self._tool_outputs[f"nikto_{url}"] = nikto_out
                parsed = _parse_nikto_output(nikto_out)
                nikto_findings.extend(parsed)

                for nf in parsed:
                    sev = nf.get("severity", "INFO")
                    if sev == "INFO":
                        continue  # skip pure-info nikto noise
                    cve = nf.get("cve")
                    await self.store_finding(Finding(
                        title=f"Nikto: {nf['title']}",
                        description=nf["description"],
                        severity=sev,
                        evidence=nf.get("raw", "")[:500],
                        tool="nikto",
                        host=target,
                        port=port,
                        cve=cve,
                        mitre_technique="T1190",
                        exploit_suggestion=_nikto_exploit_hint(nf),
                    ))

            except Exception as exc:
                logger.warning("[web_vuln_scan] nikto error for %s: %s", url, exc)

            # ── nuclei ───────────────────────────────────────────────────
            logger.info("[web_vuln_scan] nuclei on %s", url)
            try:
                nuclei_out = await self.collect_tool(
                    "nuclei",
                    target,
                    {
                        "options": (
                            f"-u {url} -severity critical,high,medium "
                            f"-silent -no-interactsh "
                            f"-timeout 10 -retries 1"
                        )
                    },
                )
                self._tool_outputs[f"nuclei_{url}"] = nuclei_out
                parsed_n = _parse_nuclei_output(nuclei_out, url)
                nuclei_findings.extend(parsed_n)

                for nuc in parsed_n:
                    sev = nuc.get("severity", "INFO")
                    cve = nuc.get("cve")
                    await self.store_finding(Finding(
                        title=f"Nuclei [{nuc['template_id']}]: {nuc.get('matcher', '')}",
                        description=(
                            f"Nuclei template {nuc['template_id']} matched on {nuc['url']}. "
                            f"Protocol: {nuc.get('protocol', 'http')}. "
                            f"Matcher: {nuc.get('matcher', 'unknown')}."
                        ),
                        severity=sev,
                        evidence=nuc.get("raw", "")[:600],
                        tool="nuclei",
                        host=target,
                        port=port,
                        cve=cve,
                        mitre_technique="T1190",
                        exploit_suggestion=_nuclei_exploit_hint(nuc),
                    ))

            except Exception as exc:
                logger.warning("[web_vuln_scan] nuclei error for %s: %s", url, exc)

        result.parsed_data["nikto_findings"]  = nikto_findings
        result.parsed_data["nuclei_findings"] = nuclei_findings
        result.findings                        = self._findings
        result.tool_outputs                    = self._tool_outputs
        result.duration_seconds                = time.monotonic() - wall_start

        await self._emit(
            "web_vuln_scan_complete",
            {
                "target":           target,
                "nikto_count":      len(nikto_findings),
                "nuclei_count":     len(nuclei_findings),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[web_vuln_scan] complete — %d nikto, %d nuclei, %d findings, %.1fs",
            len(nikto_findings), len(nuclei_findings),
            len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_nikto_output(output: str) -> list[dict]:
    """Parse nikto plain-text output into finding dicts."""
    findings: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("Nikto"):
            continue
        m = _NIKTO_FINDING_RE.match(line)
        if not m:
            continue

        ref  = m.group(1) or ""
        desc = m.group(2).strip()
        if not desc or len(desc) < 10:
            continue

        cve = None
        cve_m = _CVE_RE.search(ref + " " + desc)
        if cve_m:
            cve = cve_m.group(0).upper()

        severity = _infer_nikto_severity(desc)
        title_words = desc.split()[:8]
        title = " ".join(title_words)
        if len(desc) > len(title):
            title += "..."

        findings.append({
            "title":       title,
            "description": desc,
            "severity":    severity,
            "cve":         cve,
            "ref":         ref,
            "raw":         line,
        })
    return findings


def _infer_nikto_severity(text: str) -> str:
    """Map nikto finding text to severity."""
    lower = text.lower()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        for kw in _NIKTO_SEVERITY_KEYWORDS.get(level, []):
            if kw in lower:
                return level
    return "INFO"


def _parse_nuclei_output(output: str, base_url: str) -> list[dict]:
    """Parse nuclei -silent output into finding dicts."""
    findings: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _NUCLEI_LINE_RE.match(line)
        if not m:
            continue

        template_id = m.group(1).strip()
        protocol    = m.group(2).strip()
        severity    = _NUCLEI_SEVERITY_MAP.get(m.group(3).strip().lower(), "INFO")
        url         = m.group(4).strip()
        matcher     = m.group(5).strip() if m.group(5) else ""

        cve = None
        cve_m = _CVE_RE.search(template_id + " " + line)
        if cve_m:
            cve = cve_m.group(0).upper()

        findings.append({
            "template_id": template_id,
            "protocol":    protocol,
            "severity":    severity,
            "url":         url,
            "matcher":     matcher,
            "cve":         cve,
            "raw":         line,
        })
    return findings


def _nikto_exploit_hint(finding: dict) -> str:
    sev  = finding.get("severity", "INFO")
    desc = finding.get("description", "").lower()
    if "sql" in desc:
        return "Test parameter injection with sqlmap -u <url> --batch --level=3"
    if "directory listing" in desc or "directory traversal" in desc:
        return "Enumerate directory contents manually or with gobuster."
    if "default" in desc and ("password" in desc or "credential" in desc):
        return "Try vendor default credentials. Check exploit-db for device-specific defaults."
    if sev == "CRITICAL":
        return "Exploit immediately — check Metasploit and exploit-db for PoC."
    if sev == "HIGH":
        return "Research CVE and test with relevant exploit tooling."
    return "Investigate finding manually to confirm exploitability."


def _nuclei_exploit_hint(finding: dict) -> str:
    tid = finding.get("template_id", "").lower()
    sev = finding.get("severity", "INFO")
    if "sqli" in tid or "sql-injection" in tid:
        return "Run sqlmap: sqlmap -u <url> --batch --level=3 --risk=2"
    if "xss" in tid:
        return "Exploit XSS with dalfox or manually craft payload for session hijacking."
    if "rce" in tid or "code-execution" in tid:
        return "Attempt RCE with targeted payload. Verify OOB via interactsh."
    if "ssrf" in tid:
        return "Chain SSRF to reach internal services. Test cloud metadata endpoints."
    if "lfi" in tid:
        return "Try LFI for /etc/passwd, then escalate to RCE via log poisoning."
    if sev == "CRITICAL":
        return "Critical severity — immediate exploitation attempt recommended."
    return "Investigate and manually verify the nuclei finding."


def _port_from_url(url: str) -> int | None:
    m = re.search(r":(\d+)(?:/|$)", url)
    if m:
        return int(m.group(1))
    if url.startswith("https://"):
        return 443
    if url.startswith("http://"):
        return 80
    return None
