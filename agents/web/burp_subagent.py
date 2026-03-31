"""
burp_subagent.py — Burp Suite integration supporting both Pro and Community editions.

AGENT_NAME  : "web"
SUBAGENT_NAME: "burp"

Edition detection order
-----------------------
1. Burp Suite Pro REST API (http://localhost:1337/v0.1)
   → Full automated crawl + active scan via REST API.

2. Burp Suite Pro binary (API not yet running)
   → Attempt to start Pro with REST API enabled, then fall through to (1).

3. Burp Suite Community binary
   → Launch Community as a passive proxy (via xvfb-run on Linux).
   → Spider the target through the proxy so the passive scanner sees traffic.
   → Parse passive findings from Burp stdout/stderr.
   → Supplement with Nikto for active detection (Community has no active scanner).

4. Nikto fallback
   → No Burp binary found at all — run Nikto only.

Community limitations noted
---------------------------
- Community edition has no active scanner and no REST API.
- Automation relies on the built-in proxy/passive scanner + traffic spidering.
- Active vulnerability checks are delegated to Nikto.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Optional, Tuple

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BURP_SEVERITY_MAP = {
    "high":        "HIGH",
    "medium":      "MEDIUM",
    "low":         "LOW",
    "info":        "INFO",
    "information": "INFO",
    "critical":    "CRITICAL",
}

_BURP_PRO_API_BASE = "http://localhost:1337/v0.1"

# Community proxy default port — 8080, fallback 8081
_COMMUNITY_PROXY_PORT = 8080
_COMMUNITY_PROXY_PORT_FALLBACK = 8081

# Paths to check for Burp binaries (Linux / Kali first, then generic)
_BURP_PRO_PATHS = [
    "/opt/BurpSuitePro/BurpSuitePro",
    "/usr/local/BurpSuitePro/BurpSuitePro",
    "/opt/burpsuitepro/burpsuitepro",
]
_BURP_COMMUNITY_PATHS = [
    "/opt/BurpSuiteCommunity/BurpSuiteCommunity",
    "/usr/local/BurpSuiteCommunity/BurpSuiteCommunity",
    "/opt/burpsuitecommunity/burpsuitecommunity",
]
# Generic 'burpsuite' binary on Kali (could be Community or Pro)
_BURP_GENERIC_BINARY = "burpsuite"

# Patterns that betray a passive-finding line in Burp console output
_PASSIVE_FINDING_RE = re.compile(
    r"(Issue|Finding|Alert|Passive)\s*[:\-]\s*(.+)",
    re.IGNORECASE,
)
_ISSUE_RE = re.compile(
    r"Issue:\s*(.+?)\s*Severity:\s*(High|Medium|Low|Info|Critical)\s*Confidence:\s*(\w+)",
    re.IGNORECASE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# Helper: Burp Community JSON config written to a temp file
# ---------------------------------------------------------------------------

def _build_community_config(target: str, proxy_port: int) -> dict:
    """Return a Burp config dict that enables passive scanning and spider."""
    return {
        "project_options": {
            "connections": {
                "upstream_proxy": {"use_user_options": False},
                "socks_proxy": {"use_socks_proxy": False},
            }
        },
        "target": {
            "scope": {
                "advanced_mode": False,
                "exclude": [],
                "include": [
                    {
                        "enabled": True,
                        "host": re.sub(r"https?://", "", target.rstrip("/")),
                        "protocol": "any",
                        "file": "/.*",
                    }
                ],
            }
        },
        "proxy": {
            "request_listeners": [
                {
                    "certificate_mode": "per_host",
                    "listen_mode": "all_interfaces",
                    "listener_port": proxy_port,
                    "running": True,
                }
            ]
        },
        "scanner": {
            "live_scanning": {
                "live_passive_scanning": {"enabled": True},
                "live_active_scanning": {"enabled": False},
            }
        },
    }


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class BurpSubagent(BaseSubagent):
    """Run Burp Suite scans, supporting both Pro (REST API) and Community editions."""

    AGENT_NAME: str = "web"
    SUBAGENT_NAME: str = "burp"

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        target: str,
        burp_api_url: str = _BURP_PRO_API_BASE,
        scan_config: str = "Crawl and Audit - Balanced",
        timeout_minutes: int = 30,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Run Burp Suite against *target*, automatically selecting the best available
        edition/method.

        Parameters
        ----------
        target:
            Target URL (e.g. http://192.168.1.10 or https://target.example.com).
        burp_api_url:
            Burp Pro REST API base URL (default: http://localhost:1337/v0.1).
        scan_config:
            Burp Pro scan configuration name.
        timeout_minutes:
            Maximum wait time for scan completion (default: 30 min).
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        # ── Step 1: Try Pro REST API ──────────────────────────────────────
        api_available = await self._check_pro_api(burp_api_url)

        if api_available:
            await self._pro_api_scan(target, burp_api_url, scan_config, timeout_minutes)
            result.findings = list(self._findings)
            result.tool_outputs = dict(self._tool_outputs)
            return result

        # ── Step 2: Detect Burp binary ───────────────────────────────────
        edition, burp_path = await self._detect_burp_binary()

        if edition == "pro":
            # Pro binary exists but API is not running — advise user + try community flow
            await self.store_finding(Finding(
                title="Burp Suite Pro Detected — REST API Not Running",
                description=(
                    f"Burp Suite Pro binary found at '{burp_path}' but the REST API is not "
                    f"reachable on {burp_api_url}. To enable the REST API: open Burp → "
                    "User options → Misc → REST API → tick 'Service running'. "
                    "Falling back to Community-style passive proxy scan."
                ),
                severity="INFO",
                evidence=f"Binary: {burp_path}\nAPI URL: {burp_api_url}",
                tool="burp",
                host=target,
                mitre_technique="T1595.003",
            ))
            # Run community-style scan even though binary is Pro (API disabled)
            await self._community_scan(target, burp_path)

        elif edition == "community":
            await self.store_finding(Finding(
                title="Burp Suite Community Edition Detected",
                description=(
                    f"Burp Suite Community binary found at '{burp_path}'. "
                    "Community edition does not include an active scanner or REST API. "
                    "Running passive proxy scan: the target will be spidered through the "
                    "Burp proxy so the passive scanner can detect issues. "
                    "Nikto will be run in parallel for active vulnerability checks."
                ),
                severity="INFO",
                evidence=f"Binary: {burp_path}",
                tool="burp",
                host=target,
                mitre_technique="T1595.003",
            ))
            await self._community_scan(target, burp_path)

        else:
            # No Burp binary found at all
            logger.info("[burp] No Burp binary detected — falling back to Nikto")
            await self.store_finding(Finding(
                title="Burp Suite Not Found — Running Nikto Fallback",
                description=(
                    "Neither Burp Suite Pro REST API nor any Burp binary was found. "
                    "Falling back to Nikto web server scanner. "
                    "Install Burp Suite (any edition) for richer web vulnerability coverage."
                ),
                severity="INFO",
                evidence=f"Target: {target}",
                tool="nikto",
                host=target,
                mitre_technique="T1595.003",
            ))
            await self._nikto_scan(target)

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    async def _check_pro_api(self, api_url: str) -> bool:
        """Return True if the Burp Pro REST API responds on *api_url*."""
        check = await self.collect_tool(
            "curl",
            "",
            {"options": f"-s --connect-timeout 5 {api_url}/ 2>&1"},
        )
        return (
            "burp" in check.lower()
            or '"version"' in check.lower()
            or check.strip().startswith("{")
        )

    async def _detect_burp_binary(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect available Burp binary.

        Returns
        -------
        (edition, path)  where edition is 'pro', 'community', or None.
        """
        # 1. Explicit env override
        env_path = os.environ.get("BURP_PATH", "")
        if env_path and os.path.isfile(env_path):
            edition = "community" if "community" in env_path.lower() else "pro"
            return edition, env_path

        # 2. Check known Pro paths
        for p in _BURP_PRO_PATHS:
            if os.path.isfile(p):
                return "pro", p

        # 3. Check known Community paths
        for p in _BURP_COMMUNITY_PATHS:
            if os.path.isfile(p):
                return "community", p

        # 4. Generic 'burpsuite' binary (common on Kali)
        which_out = await self.collect_tool(
            "bash",
            "",
            {"command": f"which {_BURP_GENERIC_BINARY} 2>/dev/null || echo ''"},
        )
        binary_path = which_out.strip().splitlines()[0].strip() if which_out.strip() else ""

        if binary_path and os.path.isfile(binary_path):
            # Distinguish Pro vs Community by path or by running with --version
            version_out = await self.collect_tool(
                "bash",
                "",
                {"command": f"timeout 10 {binary_path} --version 2>&1 || echo ''"},
            )
            edition = "community" if "community" in (binary_path + version_out).lower() else "pro"
            return edition, binary_path

        return None, None

    # ------------------------------------------------------------------
    # Pro REST API scan (full automated)
    # ------------------------------------------------------------------

    async def _pro_api_scan(
        self,
        target: str,
        api_url: str,
        scan_config: str,
        timeout_minutes: int,
    ) -> None:
        """Create and poll a Burp Pro REST API scan, storing all findings."""

        scan_payload = json.dumps({
            "scan_configurations": [{"type": "NamedConfiguration", "name": scan_config}],
            "urls": [target],
            "scope": {"type": "SimpleScope", "include": [{"rule": target}]},
        })

        scan_create = await self.collect_tool(
            "curl",
            "",
            {"options": (
                f"-s -X POST {api_url}/scan "
                f"-H 'Content-Type: application/json' "
                f"-d '{scan_payload}' "
                f"--connect-timeout 10 2>&1"
            )},
        )

        # Extract scan ID
        scan_id_match = (
            re.search(r'"task_id"\s*:\s*(\d+)', scan_create)
            or re.search(r'/scan/(\d+)', scan_create)
        )

        if not scan_id_match:
            await self.store_finding(Finding(
                title="Burp Pro API: Scan Creation Failed",
                description=(
                    "Burp REST API is reachable but scan creation returned an unexpected "
                    "response. The scan may require authentication or a specific API key."
                ),
                severity="INFO",
                evidence=scan_create[:500],
                tool="burp_pro",
                host=target,
                mitre_technique="T1595.003",
            ))
            await self._nikto_scan(target)
            return

        scan_id = scan_id_match.group(1)
        logger.info("[burp_pro] Scan started — task_id=%s", scan_id)

        await self.store_finding(Finding(
            title=f"Burp Suite Pro: Scan Started — Task ID {scan_id}",
            description=(
                f"Burp Suite Pro automated scan initiated for {target}. "
                f"Config: '{scan_config}'. Task ID: {scan_id}. "
                f"Waiting up to {timeout_minutes} minutes for completion."
            ),
            severity="INFO",
            evidence=scan_create[:300],
            tool="burp_pro",
            host=target,
            mitre_technique="T1595.003",
        ))

        # Poll for completion
        deadline = time.monotonic() + (timeout_minutes * 60)
        scan_status = "running"

        while time.monotonic() < deadline and scan_status not in ("succeeded", "failed"):
            await asyncio.sleep(30)
            status_out = await self.collect_tool(
                "curl", "",
                {"options": f"-s {api_url}/scan/{scan_id} --connect-timeout 10 2>&1"},
            )
            m = re.search(r'"status"\s*:\s*"([^"]+)"', status_out)
            if m:
                scan_status = m.group(1).lower()

        # Retrieve issues
        issues_out = await self.collect_tool(
            "curl", "",
            {"options": f"-s {api_url}/scan/{scan_id}/issues --connect-timeout 10 2>&1"},
        )

        try:
            issues_data = json.loads(issues_out)
            issues = issues_data if isinstance(issues_data, list) else issues_data.get("issues", [])
        except json.JSONDecodeError:
            issues = []

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for issue in issues:
            if not isinstance(issue, dict):
                continue
            issue_name = issue.get("issue_name", issue.get("name", "Unknown Issue"))
            mapped_sev = _BURP_SEVERITY_MAP.get(issue.get("severity", "info").lower(), "INFO")
            confidence = issue.get("confidence", "tentative")
            issue_url = issue.get("origin", target)
            path = issue.get("path", "")
            remediation = issue.get("remediation_background", "")
            detail = issue.get("description", issue.get("issue_detail", ""))
            severity_counts[mapped_sev] += 1

            await self.store_finding(Finding(
                title=f"Burp Pro: [{mapped_sev}] {issue_name}",
                description=(
                    f"{issue_name} at {issue_url}{path}. "
                    f"Confidence: {confidence}. "
                    f"{detail[:300] if detail else ''}"
                ),
                severity=mapped_sev,
                evidence=(
                    f"URL: {issue_url}{path}\n"
                    f"Confidence: {confidence}\n"
                    f"Detail: {detail[:500]}\n"
                    f"Remediation: {remediation[:200]}"
                ),
                tool="burp_pro",
                host=target,
                mitre_technique="T1595.003",
                exploit_suggestion=remediation[:300] if remediation else None,
            ))

        await self.store_finding(Finding(
            title=f"Burp Pro: Scan Complete — {len(issues)} Issues Found",
            description=(
                f"Burp Suite Pro scan of {target} finished (status: {scan_status}). "
                f"CRITICAL={severity_counts['CRITICAL']}, HIGH={severity_counts['HIGH']}, "
                f"MEDIUM={severity_counts['MEDIUM']}, LOW={severity_counts['LOW']}, "
                f"INFO={severity_counts['INFO']}."
            ),
            severity=(
                "CRITICAL" if severity_counts["CRITICAL"] else
                "HIGH" if severity_counts["HIGH"] else
                "MEDIUM" if severity_counts["MEDIUM"] else "INFO"
            ),
            evidence=f"Scan ID: {scan_id}\nStatus: {scan_status}\nTotal issues: {len(issues)}",
            tool="burp_pro",
            host=target,
            mitre_technique="T1595.003",
        ))

    # ------------------------------------------------------------------
    # Community / Pro-without-API passive scan
    # ------------------------------------------------------------------

    async def _community_scan(self, target: str, burp_path: str) -> None:
        """
        Run Burp (Community or Pro with no API) as a passive proxy.

        Strategy:
          1. Write a Burp JSON config that starts the proxy listener.
          2. Launch Burp via xvfb-run (headless X server on Linux).
          3. Wait for the proxy to come up.
          4. Spider the target through the proxy so passive scanner sees traffic.
          5. Wait briefly for passive scan processing.
          6. Kill Burp process.
          7. Parse any findings from Burp stdout/stderr.
          8. Run Nikto in parallel for active vuln detection.
        """
        session_tag = self.session_id[:8]
        config_path  = f"/tmp/burp_cfg_{session_tag}.json"
        project_path = f"/tmp/burp_prj_{session_tag}.burp"
        log_path     = f"/tmp/burp_log_{session_tag}.txt"

        # Determine proxy port (try 8080 first, then 8081)
        port_check = await self.collect_tool(
            "bash", "",
            {"command": f"nc -z localhost {_COMMUNITY_PROXY_PORT} 2>&1 && echo IN_USE || echo FREE"},
        )
        proxy_port = (
            _COMMUNITY_PROXY_PORT_FALLBACK
            if "IN_USE" in port_check
            else _COMMUNITY_PROXY_PORT
        )

        # Write config file
        cfg = _build_community_config(target, proxy_port)
        await self.collect_tool(
            "bash", "",
            {"command": (
                f"cat > {config_path} << 'BURPCFG'\n"
                f"{json.dumps(cfg, indent=2)}\n"
                f"BURPCFG"
            )},
        )

        # Launch Burp via xvfb-run (background, capture output to log)
        launch_cmd = (
            f"xvfb-run -a --server-args='-screen 0 1024x768x24' "
            f"{burp_path} "
            f"--project-file={project_path} "
            f"--config-file={config_path} "
            f"> {log_path} 2>&1 & echo $!"
        )
        pid_out = await self.collect_tool("bash", "", {"command": launch_cmd})
        burp_pid = pid_out.strip().splitlines()[-1].strip()
        logger.info("[burp_community] Launched PID=%s proxy_port=%d", burp_pid, proxy_port)

        # Wait up to 20 s for the proxy port to open
        proxy_up = False
        for _ in range(10):
            await asyncio.sleep(2)
            up_check = await self.collect_tool(
                "bash", "",
                {"command": f"nc -z localhost {proxy_port} 2>&1 && echo UP || echo DOWN"},
            )
            if "UP" in up_check:
                proxy_up = True
                break

        if not proxy_up:
            logger.warning("[burp_community] Proxy port %d never opened — skipping spider", proxy_port)
            await self.store_finding(Finding(
                title="Burp Community: Proxy Did Not Start",
                description=(
                    f"Burp Community was launched but the proxy port {proxy_port} did not open "
                    "within 20 seconds. xvfb-run may be unavailable or Burp needs a license "
                    "acceptance step. Supplementing with Nikto active scan."
                ),
                severity="INFO",
                evidence=f"PID: {burp_pid}\nProxy port: {proxy_port}",
                tool="burp_community",
                host=target,
                mitre_technique="T1595.003",
            ))
        else:
            await self.store_finding(Finding(
                title=f"Burp Community: Proxy Running on Port {proxy_port}",
                description=(
                    f"Burp Suite Community proxy started on localhost:{proxy_port}. "
                    f"Spidering {target} through the proxy to feed the passive scanner."
                ),
                severity="INFO",
                evidence=f"PID: {burp_pid}\nProxy: localhost:{proxy_port}",
                tool="burp_community",
                host=target,
                mitre_technique="T1595.003",
            ))

            # Spider target through Burp proxy to feed passive scanner
            await self.collect_tool(
                "bash", "",
                {"command": (
                    f"wget -q -r -l 3 --no-check-certificate "
                    f"--timeout=15 --tries=1 "
                    f"-e 'http_proxy=http://localhost:{proxy_port}' "
                    f"-e 'https_proxy=http://localhost:{proxy_port}' "
                    f"--header='User-Agent: BurpPassiveSpider/1.0' "
                    f"{target} -P /tmp/burp_crawl_{session_tag}/ 2>&1 | head -100"
                )},
            )

            # Also spider with curl for JS-heavy pages
            await self.collect_tool(
                "bash", "",
                {"command": (
                    f"curl -s -L --max-redirs 5 "
                    f"--proxy http://localhost:{proxy_port} "
                    f"--insecure --max-time 30 "
                    f"{target} -o /dev/null 2>&1"
                )},
            )

            # Give passive scanner time to process captured traffic
            await asyncio.sleep(20)

            # Read Burp log for passive findings
            log_content = await self.collect_tool(
                "bash", "", {"command": f"cat {log_path} 2>/dev/null | head -200"},
            )
            self._parse_community_log(log_content, target)

        # Kill Burp process
        if burp_pid.isdigit():
            await self.collect_tool(
                "bash", "", {"command": f"kill {burp_pid} 2>/dev/null; sleep 1; kill -9 {burp_pid} 2>/dev/null || true"},
            )

        # Clean up temp files
        await self.collect_tool(
            "bash", "",
            {"command": (
                f"rm -f {config_path} {project_path} {log_path} "
                f"2>/dev/null; rm -rf /tmp/burp_crawl_{session_tag}/ 2>/dev/null || true"
            )},
        )

        # Always supplement with Nikto (Community has no active scanner)
        await self.store_finding(Finding(
            title="Burp Community: Running Nikto for Active Vulnerability Detection",
            description=(
                "Burp Suite Community passive scanner has no active scanning capability. "
                "Running Nikto to complement with active vulnerability checks."
            ),
            severity="INFO",
            evidence=f"Target: {target}",
            tool="nikto",
            host=target,
            mitre_technique="T1595.003",
        ))
        await self._nikto_scan(target)

    def _parse_community_log(self, log_content: str, target: str) -> None:
        """Extract passive findings from Burp console log output."""
        if not log_content.strip():
            return

        seen: set[str] = set()
        for line in log_content.splitlines():
            m = _PASSIVE_FINDING_RE.search(line)
            if m:
                text = m.group(2).strip()[:200]
                if text in seen:
                    continue
                seen.add(text)
                sev = self.parse_severity(line)
                # store_finding is sync-incompatible here — queue for later or use _findings directly
                from agents.base_subagent import Finding as _F
                self._findings.append(_F(
                    title=f"Burp Community (Passive): {text[:80]}",
                    description=f"Passive finding detected from Burp Community log: {text}",
                    severity=sev,
                    evidence=line.strip(),
                    tool="burp_community",
                    host=target,
                    mitre_technique="T1595.003",
                ))

    # ------------------------------------------------------------------
    # Nikto active scan (used as active supplement for Community + hard fallback)
    # ------------------------------------------------------------------

    async def _nikto_scan(self, target: str) -> None:
        """Run Nikto and store findings."""
        nikto_output = await self.collect_tool(
            "nikto",
            target,
            {"options": f"-h {target} -Format txt -Tuning 1234789 -timeout 30 2>&1"},
        )

        vuln_lines = [
            ln for ln in nikto_output.splitlines()
            if ln.startswith("+") and not ln.startswith("+ Server") and len(ln) > 20
        ]

        for vuln_line in vuln_lines[:25]:
            sev = self.parse_severity(vuln_line)
            await self.store_finding(Finding(
                title=f"Nikto: {vuln_line[2:60].strip()}",
                description=vuln_line[2:],
                severity=sev,
                evidence=vuln_line,
                tool="nikto",
                host=target,
                mitre_technique="T1595.003",
            ))

        if not vuln_lines:
            await self.store_finding(Finding(
                title="Nikto: Scan Complete — No Notable Issues",
                description=f"Nikto scan of {target} completed without flagging any notable vulnerabilities.",
                severity="INFO",
                evidence=nikto_output[:300] if nikto_output else "No output",
                tool="nikto",
                host=target,
                mitre_technique="T1595.003",
            ))
