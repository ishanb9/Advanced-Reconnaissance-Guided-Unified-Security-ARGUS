"""
cve_lookup_subagent.py — CVE and exploit lookup for discovered services.

Methodology:
  1. Accept services_list kwarg (list of {port, service, version} dicts)
  2. For each service with a version, run searchsploit to find known exploits
  3. Run nmap --script=vulners against discovered services
  4. Run nmap --script=vulscan if available
  5. Parse CVE IDs, CVSS scores, exploit availability
  6. Severity: CRITICAL if public exploit + CVSS>=9; HIGH CVSS>=7; MEDIUM CVSS>=4
  7. Include exploit_suggestion with metasploit module or exploit-db URL
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CVSS_RE = re.compile(r"(?:cvss|score)[:\s]+(\d+(?:\.\d+)?)", re.IGNORECASE)
_EDB_RE = re.compile(r"EDB-ID[:\s#]+(\d+)", re.IGNORECASE)
_MSF_MODULE_RE = re.compile(
    r"(exploit/[a-z0-9_/]+|auxiliary/[a-z0-9_/]+)", re.IGNORECASE
)

# Known high-value metasploit modules keyed by CVE
_CVE_TO_MSF: dict[str, str] = {
    "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2017-0145": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    "CVE-2020-0796": "exploit/windows/smb/smb_ghost_auth_bypass",
    "CVE-2021-44228": "exploit/multi/misc/log4shell_header_injection",
    "CVE-2017-5638":  "exploit/multi/http/struts2_content_type_ognl",
    "CVE-2014-6271":  "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "CVE-2021-41773": "exploit/multi/http/apache_normalize_path_rce",
    "CVE-2021-42013": "exploit/multi/http/apache_normalize_path_rce",
    "CVE-2022-22965": "exploit/multi/http/spring4shell",
    "CVE-2021-21985": "exploit/linux/http/vmware_vcenter_vsan_health_rce",
}


def _score_to_severity(score: float, has_public_exploit: bool) -> str:
    """Map a CVSS score to a severity level, escalating if exploit is public."""
    if has_public_exploit and score >= 9.0:
        return "CRITICAL"
    if has_public_exploit and score >= 7.0:
        return "CRITICAL"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_searchsploit(output: str) -> list[dict]:
    """Parse searchsploit tabular output into structured exploit dicts."""
    exploits: list[dict] = []
    # Lines look like: Title                                       | Path
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("Title"):
            continue
        parts = line.split("|", 1)
        if len(parts) < 2:
            continue
        title = parts[0].strip()
        path = parts[1].strip()
        cve_matches = _CVE_RE.findall(title + " " + path)
        edb_m = _EDB_RE.search(path)
        edb_id = edb_m.group(1) if edb_m else None
        exploits.append({
            "title": title,
            "path": path,
            "cves": [c.upper() for c in cve_matches],
            "edb_id": edb_id,
            "edb_url": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else None,
        })
    return exploits


def _parse_vulners_output(output: str) -> list[dict]:
    """Parse nmap vulners script output into CVE/CVSS dicts."""
    results: list[dict] = []
    current_port: str = ""
    port_re = re.compile(r"^(\d+)/(?:tcp|udp)\s+open", re.IGNORECASE)
    cve_line_re = re.compile(
        r"(CVE-\d{4}-\d{4,7})\s+([\d.]+)\s+(https?://\S+)?",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        pm = port_re.match(line.strip())
        if pm:
            current_port = pm.group(1)
            continue
        cm = cve_line_re.search(line)
        if cm:
            cve = cm.group(1).upper()
            try:
                score = float(cm.group(2))
            except (ValueError, TypeError):
                score = 0.0
            url = cm.group(3) or ""
            results.append({
                "cve": cve,
                "cvss": score,
                "url": url,
                "port": current_port,
            })

    return results


class CveLookupSubagent(BaseSubagent):
    """
    CVE and exploit database lookup for discovered services.

    Runs searchsploit, nmap vulners, and nmap vulscan to correlate
    service versions with known CVEs and public exploit code.
    """

    AGENT_NAME    = "vuln"
    SUBAGENT_NAME = "cve_lookup"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:  # noqa: C901
        """
        Execute CVE lookup against all services with version strings.

        Parameters
        ----------
        target:
            IP address or hostname of the target.
        services_list:
            List of dicts, each with keys: port (int), service (str),
            version (str). Services without a version are skipped.

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        wall_start = time.monotonic()

        services_list: list[dict] = kwargs.get("services_list", [])

        # Collect ports that have version strings for targeted nmap scan
        versioned_services = [
            s for s in services_list
            if s.get("version") and str(s.get("version")).strip()
        ]

        # If no versioned services, emit a diagnostic finding so the user
        # knows why no CVE findings appeared (instead of silent nothing).
        if not versioned_services:
            await self.store_finding(Finding(
                title="CVE lookup skipped — no versioned services",
                description=(
                    f"CveLookupSubagent received {len(services_list)} services but none had "
                    "a version string. Ensure recon ran `nmap -sV` and the service parser "
                    "populated the `version` field."
                ),
                severity="INFO",
                evidence=f"services_list={services_list[:5]}",
                tool="cve_lookup",
                host=target,
            ))

        # ── Step 1: searchsploit per service ─────────────────────────────
        for svc in versioned_services:
            port    = svc.get("port", "")
            service = svc.get("service", "")
            version = svc.get("version", "")
            query   = f"{service} {version}".strip()
            if not query:
                continue

            logger.info("[cve_lookup] searchsploit: %s", query)
            try:
                ss_out = await self.collect_tool(
                    "searchsploit",
                    target,
                    {"options": f'--colour {query}'},
                )
                exploits = _parse_searchsploit(ss_out)
                for exp in exploits:
                    cves_str = ", ".join(exp["cves"]) if exp["cves"] else "N/A"
                    # Determine metasploit module suggestion
                    msf_module = None
                    for cve in exp["cves"]:
                        msf_module = _CVE_TO_MSF.get(cve.upper())
                        if msf_module:
                            break
                    exploit_suggestion = (
                        f"MSF: {msf_module}" if msf_module
                        else (f"ExploitDB: {exp['edb_url']}" if exp["edb_url"]
                              else f"Manual: {exp['path']}")
                    )
                    # Public exploit escalates severity
                    severity = "HIGH"
                    if any(
                        kw in exp["title"].lower()
                        for kw in ("remote", "rce", "code exec", "buffer overflow",
                                   "command inject")
                    ):
                        severity = "CRITICAL"

                    finding = Finding(
                        title=f"Public Exploit: {exp['title'][:80]}",
                        description=(
                            f"searchsploit found a public exploit for {service} {version} "
                            f"on port {port}. CVEs: {cves_str}. "
                            f"Exploit path: {exp['path']}"
                        ),
                        severity=severity,
                        evidence=ss_out[:2000],
                        tool="searchsploit",
                        host=target,
                        port=int(port) if port else None,
                        cve=exp["cves"][0] if exp["cves"] else None,
                        mitre_technique="T1190",
                        exploit_suggestion=exploit_suggestion,
                    )
                    await self.store_finding(finding)
            except Exception as exc:
                logger.warning("[cve_lookup] searchsploit error for %s: %s", query, exc)
                # Emit a visible diagnostic so the UI shows the missing tool,
                # rather than silently producing zero CVE findings.
                _msg = str(exc).lower()
                if "not found" in _msg or "enoent" in _msg or "no such" in _msg:
                    await self.store_finding(Finding(
                        title="searchsploit unavailable — CVE lookup degraded",
                        description=(
                            "The MCP server could not execute `searchsploit` "
                            f"(error: {exc}). Install exploitdb on the MCP host "
                            "to enable ExploitDB correlation."
                        ),
                        severity="INFO",
                        evidence=str(exc)[:500],
                        tool="searchsploit",
                        host=target,
                    ))
                    break   # no point retrying for every versioned service

        # ── Step 2: nmap --script=vulners ────────────────────────────────
        if versioned_services:
            ports_csv = ",".join(
                str(s["port"]) for s in versioned_services if s.get("port")
            )
            logger.info("[cve_lookup] nmap vulners on ports: %s", ports_csv)
            try:
                vulners_out = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"--script=vulners -sV -p {ports_csv} {target}"},
                )
                cve_entries = _parse_vulners_output(vulners_out)
                seen_cves: set[str] = set()

                for entry in cve_entries:
                    cve   = entry["cve"]
                    score = entry["cvss"]
                    port  = entry.get("port", "")

                    if cve in seen_cves:
                        continue
                    seen_cves.add(cve)

                    has_exploit = cve.upper() in _CVE_TO_MSF
                    severity    = _score_to_severity(score, has_exploit)

                    msf_module  = _CVE_TO_MSF.get(cve.upper())
                    exploit_suggestion = (
                        f"MSF: {msf_module}" if msf_module
                        else f"Search ExploitDB for {cve}"
                    )

                    finding = Finding(
                        title=f"{cve} (CVSS {score}) on port {port}",
                        description=(
                            f"nmap vulners script identified {cve} with CVSS score {score} "
                            f"on port {port} of {target}."
                            + (" Public exploit available." if has_exploit else "")
                        ),
                        severity=severity,
                        evidence=vulners_out[:3000],
                        tool="nmap_vulners",
                        host=target,
                        port=int(port) if port else None,
                        cve=cve,
                        mitre_technique="T1190",
                        exploit_suggestion=exploit_suggestion,
                    )
                    await self.store_finding(finding)
            except Exception as exc:
                logger.warning("[cve_lookup] vulners scan error: %s", exc)

        # ── Step 3: nmap --script=vulscan (if available) ─────────────────
        if versioned_services:
            ports_csv = ",".join(
                str(s["port"]) for s in versioned_services if s.get("port")
            )
            logger.info("[cve_lookup] nmap vulscan on ports: %s", ports_csv)
            try:
                vulscan_out = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"--script=vulscan --script-args vulscandb=exploitdb.csv -sV -p {ports_csv} {target}"},
                )
                # vulscan output: "| ID   | Title"
                vulscan_cves = _CVE_RE.findall(vulscan_out)
                vulscan_scores = _CVSS_RE.findall(vulscan_out)

                if vulscan_cves:
                    # Create an aggregated finding for vulscan results
                    top_score = max(
                        (float(s) for s in vulscan_scores), default=5.0
                    )
                    severity = _score_to_severity(top_score, has_public_exploit=False)
                    finding = Finding(
                        title=f"vulscan found {len(set(vulscan_cves))} CVEs on {target}",
                        description=(
                            f"nmap vulscan identified {len(set(vulscan_cves))} CVE references "
                            f"across services on {target}. Highest CVSS: {top_score}."
                        ),
                        severity=severity,
                        evidence=vulscan_out[:3000],
                        tool="nmap_vulscan",
                        host=target,
                        cve=", ".join(sorted(set(vulscan_cves))[:10]),
                        mitre_technique="T1190",
                        exploit_suggestion="Review vulscan output and cross-reference with searchsploit.",
                    )
                    await self.store_finding(finding)
            except Exception as exc:
                logger.info(
                    "[cve_lookup] vulscan not available or error (non-fatal): %s", exc
                )

        # ── Step 4: nmap NSE `vuln` category (always available) ───────────
        # This runs whether or not vulners/vulscan scripts are installed —
        # it uses built-in NSE vuln scripts shipped with nmap.
        if versioned_services:
            ports_csv = ",".join(
                str(s["port"]) for s in versioned_services if s.get("port")
            )
            logger.info("[cve_lookup] nmap --script vuln on ports: %s", ports_csv)
            try:
                vuln_out = await self.collect_tool(
                    "nmap",
                    target,
                    {"options": f"--script vuln -sV -p {ports_csv} {target}"},
                )
                # Extract every CVE + the preceding line as evidence
                nse_cves = set(_CVE_RE.findall(vuln_out))
                if nse_cves:
                    # Emit one aggregated finding so user sees built-in NSE results
                    top_score = max(
                        (float(s) for s in _CVSS_RE.findall(vuln_out)),
                        default=7.0,
                    )
                    await self.store_finding(Finding(
                        title=f"NSE vuln scripts: {len(nse_cves)} CVEs on {target}",
                        description=(
                            f"nmap --script vuln flagged {len(nse_cves)} CVE references. "
                            f"Top CVSS: {top_score}. Review evidence for specific scripts "
                            "(e.g. smb-vuln-*, http-vuln-*, ssl-*)."
                        ),
                        severity=_score_to_severity(top_score, has_public_exploit=False),
                        evidence=vuln_out[:3000],
                        tool="nmap_nse_vuln",
                        host=target,
                        cve=", ".join(sorted(nse_cves)[:10]),
                        mitre_technique="T1190",
                        exploit_suggestion="Cross-reference CVEs with Metasploit/ExploitDB.",
                    ))
                # Also surface any "VULNERABLE:" banners (scripts like
                # smb-vuln-ms17-010, http-shellshock) even if no CVE present.
                for _m in re.finditer(
                    r"VULNERABLE:\s*\n(.+?)(?:\n\n|\n\|_)", vuln_out, re.DOTALL
                ):
                    banner = _m.group(1).strip()[:500]
                    title_line = banner.splitlines()[0][:80] if banner else "NSE reported VULNERABLE"
                    await self.store_finding(Finding(
                        title=f"NSE: {title_line}",
                        description=f"nmap NSE script reported VULNERABLE on {target}.",
                        severity="HIGH",
                        evidence=banner,
                        tool="nmap_nse_vuln",
                        host=target,
                        mitre_technique="T1190",
                    ))
            except Exception as exc:
                logger.warning("[cve_lookup] NSE vuln scripts error: %s", exc)

        # ── Finalise result ───────────────────────────────────────────────
        result.findings      = self._findings
        result.tool_outputs  = self._tool_outputs
        result.duration_seconds = time.monotonic() - wall_start

        await self._emit(
            "cve_lookup_complete",
            {
                "target": target,
                "services_checked": len(versioned_services),
                "findings": len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )
        logger.info(
            "[cve_lookup] complete — %d services checked, %d findings, %.1fs",
            len(versioned_services), len(self._findings), result.duration_seconds,
        )
        return result
