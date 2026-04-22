"""
burp_subagent.py — Enhanced Burp Suite Community + Pro integration.

AGENT_NAME   : "web"
SUBAGENT_NAME: "burp"

Edition detection + execution strategy
---------------------------------------
1. Burp Suite Pro REST API (http://localhost:1337/v0.1)
   → Full automated crawl + active scan via REST API.
   → Polls /scan/{id}/issues until Done.

2. Burp Suite Pro binary (API not yet running)
   → Start Pro with --headless=true and REST API flags.
   → Fall through to REST API flow once up.

3. Burp Suite Community binary (any Kali install)
   → EULA pre-accepted via UserConfig JSON.
   → Launch with --headless=true (Burp 2022.9+) or xvfb-run fallback.
   → Start proxy listener on an available port.
   → Route ALL active scanning tools through the proxy simultaneously:
       curl, httpx, gobuster, ffuf, nikto, dalfox, sqlmap, wafw00f
   → Passive scanner processes every request/response seen through proxy.
   → After scan: parse Burp XML state + log for passive findings.
   → Kill Burp cleanly; cleanup temp files.

4. No binary found
   → Comprehensive Nikto + dalfox + gobuster active scan fallback.

Community note
--------------
Burp Community has no REST API and no active scanner.
The key insight: route EVERY active tool through the Burp proxy.
This maximises the traffic the passive scanner processes, surfacing
issues like reflected content, insecure cookies, missing headers,
server errors, and information disclosure across all endpoints.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BURP_PRO_API_BASE      = "http://localhost:1337/v0.1"
_PROXY_PORT_CANDIDATES  = [8080, 8081, 8082, 8083, 18080]

# Known binary locations on Kali / Debian / generic Linux
_BURP_BINARY_HINTS: List[str] = [
    # env override (highest priority)
    os.environ.get("BURP_PATH", ""),
    # Kali default wrapper
    "/usr/bin/burpsuite",
    # Installer paths (Community)
    "/opt/BurpSuiteCommunity/BurpSuiteCommunity",
    "/opt/BurpSuiteCommunity/burpsuitecommunity",
    "/usr/local/BurpSuiteCommunity/BurpSuiteCommunity",
    # Installer paths (Pro)
    "/opt/BurpSuitePro/BurpSuitePro",
    "/opt/BurpSuitePro/burpsuitepro",
    "/usr/local/BurpSuitePro/BurpSuitePro",
    # Generic names
    "/usr/local/bin/burpsuite",
    "/opt/burpsuite/burpsuite",
]

# Jar locations for java -jar launch
_BURP_JAR_HINTS: List[str] = [
    "/opt/BurpSuiteCommunity/BurpSuiteCommunity.jar",
    "/opt/BurpSuitePro/BurpSuitePro.jar",
    "/opt/burpsuite/burpsuite*.jar",
    "/usr/share/burpsuite/burpsuite*.jar",
]

_BURP_SEVERITY_MAP = {
    "high":        "HIGH",
    "medium":      "MEDIUM",
    "low":         "LOW",
    "info":        "INFO",
    "information": "INFO",
    "critical":    "CRITICAL",
}

# Passive-finding patterns in Burp log output
_PASSIVE_RE = re.compile(
    r"(?:Issue|Finding|Alert|Passive|Scanner|Vulnerability)\s*[:\-]\s*(.+)",
    re.IGNORECASE,
)
_SEVERITY_RE = re.compile(
    r"Severity\s*[:\-]\s*(High|Medium|Low|Info(?:rmation(?:al)?)?|Critical)",
    re.IGNORECASE,
)

# Tools to run through proxy for maximum passive coverage
_PROXY_SCAN_TIMEOUT = 300   # per tool
_SPIDER_TIMEOUT     = 120   # crawl timeout


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_burp_config(target: str, proxy_port: int) -> dict:
    """
    JSON config for headless Burp launch.
    Sets proxy listener, live passive scanning, target scope.
    Disables update checks and first-run dialogs.
    """
    host = re.sub(r"https?://", "", target.rstrip("/")).split("/")[0].split(":")[0]
    return {
        "project_options": {
            "connections": {
                "upstream_proxy":   {"use_user_options": False},
                "socks_proxy":      {"use_socks_proxy": False},
                "platform_auth":    {"use_user_options": False},
                "timeout_monitor":  {"enabled": True},
            },
            "http": {
                "redirections": {"follow_redirections": "always"},
                "ssl_negotiation": {
                    "enforce_ssl_negotiation": False,
                    "tls_negotiation_overrides": [],
                },
            },
        },
        "target": {
            "scope": {
                "advanced_mode": False,
                "exclude": [],
                "include": [
                    {
                        "enabled":  True,
                        "host":     host,
                        "protocol": "any",
                        "file":     "/.*",
                    }
                ],
            }
        },
        "proxy": {
            "intercept_client_requests": {
                "do_intercept": False,
            },
            "intercept_server_responses": {
                "do_intercept": False,
            },
            "request_listeners": [
                {
                    "certificate_mode":  "per_host",
                    "listen_mode":       "all_interfaces",
                    "listener_port":     proxy_port,
                    "running":           True,
                    "support_invisible_proxying": True,
                }
            ],
        },
        "scanner": {
            "live_scanning": {
                "live_passive_scanning": {"enabled": True},
                "live_active_scanning":  {"enabled": False},
            }
        },
    }


def _build_user_options() -> dict:
    """
    UserConfig JSON: suppress all first-run dialogs / EULA screens
    so headless launch doesn't hang waiting for user interaction.
    """
    return {
        "user_options": {
            "display": {
                "show_start_screen":        False,
                "look_and_feel":            {"look_and_feel": "cross_platform"},
            },
            "misc": {
                "show_learn_tab":           False,
                "show_update_prompts":      False,
                "auto_update":              {"do_auto_update": False},
            },
            "connections": {
                "platform_auth": {
                    "do_platform_auth": False,
                }
            },
        }
    }


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class BurpSubagent(BaseSubagent):
    """
    Enhanced Burp Suite integration — Community and Pro editions.
    Community: routes all active tools through Burp proxy for maximum passive coverage.
    Pro:       uses REST API for full automated crawl + active scan.
    """

    AGENT_NAME:    str = "web"
    SUBAGENT_NAME: str = "burp"

    # ──────────────────────────────────────────────────────────────────────
    # Main entry point
    # ──────────────────────────────────────────────────────────────────────

    async def run(
        self,
        target:          str,
        burp_api_url:    str = _BURP_PRO_API_BASE,
        scan_config:     str = "Crawl and Audit - Balanced",
        timeout_minutes: int = 40,
        extra_urls:      Optional[List[str]] = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Scan *target* with the best available Burp edition.

        Parameters
        ----------
        target          : Primary target URL.
        burp_api_url    : Burp Pro REST API base URL.
        scan_config     : Burp Pro scan configuration name.
        timeout_minutes : Max wait for scan completion.
        extra_urls      : Additional URLs to include in scope.
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        # ── 1. Try Pro REST API ────────────────────────────────────────────
        if await self._check_pro_api(burp_api_url):
            logger.info("[burp] Pro REST API detected — running full automated scan")
            await self._pro_api_scan(target, burp_api_url, scan_config,
                                     timeout_minutes, extra_urls or [])
            result.findings     = list(self._findings)
            result.tool_outputs = dict(self._tool_outputs)
            return result

        # ── 2. Detect binary / jar ─────────────────────────────────────────
        edition, burp_path = await self._detect_burp_binary()
        logger.info("[burp] edition=%s path=%s", edition, burp_path)

        if edition == "pro":
            # Pro binary but API not running — start it then retry API
            await self._start_pro_with_api(burp_path, burp_api_url)
            if await self._check_pro_api(burp_api_url):
                await self._pro_api_scan(target, burp_api_url, scan_config,
                                         timeout_minutes, extra_urls or [])
                result.findings     = list(self._findings)
                result.tool_outputs = dict(self._tool_outputs)
                return result
            # API still not available — fall through to community-style scan
            logger.warning("[burp] Pro API still unreachable after start — using proxy scan")

        if burp_path:
            await self._community_scan(target, burp_path, extra_urls or [])
        else:
            logger.info("[burp] No Burp binary found — running active fallback tools")
            await self.store_finding(Finding(
                title="Burp Suite Not Found — Running Active Fallback Scanners",
                description=(
                    "No Burp Suite binary detected. Running Nikto + gobuster + dalfox "
                    "as active fallback web scanners. "
                    "Install Burp Suite Community (free) for passive scanner coverage: "
                    "sudo apt install burpsuite"
                ),
                severity="INFO",
                evidence=f"Target: {target}",
                tool="nikto",
                host=target,
                mitre_technique="T1595.003",
            ))
            await self._active_fallback_scan(target)

        result.findings     = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ──────────────────────────────────────────────────────────────────────
    # Detection
    # ──────────────────────────────────────────────────────────────────────

    async def _check_pro_api(self, api_url: str) -> bool:
        """Return True if Burp Pro REST API is live at api_url."""
        out = await self.collect_tool(
            "bash", "",
            {"command": f"curl -sf --connect-timeout 4 {api_url}/ 2>/dev/null || echo NOAPI"},
        )
        return (
            "NOAPI" not in out and
            ('"version"' in out.lower() or "burp" in out.lower() or out.strip().startswith("{"))
        )

    async def _detect_burp_binary(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Locate the Burp Suite binary or jar.
        Returns (edition, path) where edition is 'pro', 'community', or None.
        """
        # Check all known paths
        for raw_path in _BURP_BINARY_HINTS:
            path = raw_path.strip()
            if not path:
                continue
            exists = await self.collect_tool(
                "bash", "",
                {"command": f"test -f '{path}' && echo EXISTS || echo MISSING"},
            )
            if "EXISTS" in exists:
                edition = "community" if "community" in path.lower() else "pro"
                return edition, path

        # Try 'which burpsuite' / 'which burp'
        which_out = await self.collect_tool(
            "bash", "",
            {"command": "which burpsuite 2>/dev/null || which burp 2>/dev/null || echo ''"},
        )
        path = which_out.strip().splitlines()[0].strip()
        if path and path != "''":
            # Identify edition
            ver_out = await self.collect_tool(
                "bash", "",
                {"command": f"timeout 5 '{path}' --version 2>&1 | head -3 || echo ''"},
            )
            edition = (
                "community"
                if "community" in (path + ver_out).lower()
                else "pro"
            )
            return edition, path

        # Check for jar files
        jar_search = await self.collect_tool(
            "bash", "",
            {"command": (
                "find /opt /usr/share /usr/local /home -maxdepth 4 "
                "-name 'burpsuite*.jar' -o -name 'BurpSuite*.jar' 2>/dev/null | head -3"
            )},
        )
        for jar_path in jar_search.strip().splitlines():
            jar_path = jar_path.strip()
            if jar_path:
                # Verify java is available
                java_check = await self.collect_tool(
                    "bash", "",
                    {"command": "which java 2>/dev/null && echo JAVA_OK || echo JAVA_MISSING"},
                )
                if "JAVA_OK" in java_check:
                    edition = "community" if "community" in jar_path.lower() else "pro"
                    return edition, jar_path

        return None, None

    async def _find_free_proxy_port(self) -> int:
        """Return the first TCP port in _PROXY_PORT_CANDIDATES that is not in use."""
        for port in _PROXY_PORT_CANDIDATES:
            check = await self.collect_tool(
                "bash", "",
                {"command": f"nc -z 127.0.0.1 {port} 2>/dev/null && echo IN_USE || echo FREE"},
            )
            if "FREE" in check:
                return port
        return 18080   # last-resort

    # ──────────────────────────────────────────────────────────────────────
    # Pro: start binary with REST API flags
    # ──────────────────────────────────────────────────────────────────────

    async def _start_pro_with_api(self, burp_path: str, api_url: str) -> None:
        """Start Burp Pro with REST API enabled and wait up to 60 s."""
        api_port = re.search(r":(\d+)", api_url)
        port     = api_port.group(1) if api_port else "1337"
        launch = (
            f"nohup '{burp_path}' "
            f"--headless=true "
            f"--config-file=/dev/null "
            f"--unpause-spider-and-scanner "
            f"-Djava.awt.headless=true "
            f"> /tmp/burp_pro_api.log 2>&1 & echo BURP_PRO_PID:$!"
        )
        await self.collect_tool("bash", "", {"command": launch})
        # Poll for API readiness (up to 60 s)
        for _ in range(20):
            await asyncio.sleep(3)
            if await self._check_pro_api(api_url):
                return

    # ──────────────────────────────────────────────────────────────────────
    # Pro: REST API full scan
    # ──────────────────────────────────────────────────────────────────────

    async def _pro_api_scan(
        self,
        target:          str,
        api_url:         str,
        scan_config:     str,
        timeout_minutes: int,
        extra_urls:      List[str],
    ) -> None:
        """Create a Burp Pro REST API scan, poll to completion, store all issues."""
        all_urls = [target] + [u for u in extra_urls if u != target]
        payload  = json.dumps({
            "scan_configurations": [{"type": "NamedConfiguration", "name": scan_config}],
            "urls":   all_urls,
            "scope": {
                "type":    "SimpleScope",
                "include": [{"rule": u} for u in all_urls],
            },
        })
        create_out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"curl -sf -X POST '{api_url}/scan' "
                f"-H 'Content-Type: application/json' "
                f"-d '{payload}' --connect-timeout 10 2>&1"
            )},
        )
        scan_id_m = (
            re.search(r'"task_id"\s*:\s*(\d+)', create_out) or
            re.search(r'/scan/(\d+)', create_out)
        )
        if not scan_id_m:
            await self.store_finding(Finding(
                title="Burp Pro API: Scan Creation Failed",
                description=(
                    f"REST API is reachable but scan creation returned an unexpected response. "
                    f"Check that the API key is not required or that the scan config name "
                    f"'{scan_config}' is correct."
                ),
                severity="INFO",
                evidence=create_out[:600],
                tool="burp_pro",
                host=target,
                mitre_technique="T1595.003",
            ))
            # Supplement with active tools even if API scan fails
            await self._active_fallback_scan(target)
            return

        scan_id = scan_id_m.group(1)
        await self.store_finding(Finding(
            title=f"Burp Pro: Scan Started (task {scan_id})",
            description=(
                f"Burp Suite Pro automated scan initiated for {', '.join(all_urls)}. "
                f"Config: '{scan_config}'. Polling every 30 s (max {timeout_minutes} min)."
            ),
            severity="INFO",
            evidence=create_out[:300],
            tool="burp_pro",
            host=target,
            mitre_technique="T1595.003",
        ))

        # Poll until Done
        deadline    = time.monotonic() + timeout_minutes * 60
        scan_status = "running"
        while time.monotonic() < deadline and scan_status not in ("succeeded", "failed"):
            await asyncio.sleep(30)
            status_out = await self.collect_tool(
                "bash", "",
                {"command": f"curl -sf '{api_url}/scan/{scan_id}' --connect-timeout 10 2>&1"},
            )
            m = re.search(r'"status"\s*:\s*"([^"]+)"', status_out)
            if m:
                scan_status = m.group(1).lower()
                logger.info("[burp_pro] scan %s status=%s", scan_id, scan_status)

        # Retrieve issues
        issues_raw = await self.collect_tool(
            "bash", "",
            {"command": f"curl -sf '{api_url}/scan/{scan_id}/issues' --connect-timeout 10 2>&1"},
        )
        try:
            data   = json.loads(issues_raw)
            issues = data if isinstance(data, list) else data.get("issues", [])
        except json.JSONDecodeError:
            issues = []

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            name        = issue.get("issue_name") or issue.get("name") or "Unknown"
            sev         = _BURP_SEVERITY_MAP.get(
                (issue.get("severity") or "info").lower(), "INFO"
            )
            confidence  = issue.get("confidence", "tentative")
            issue_url   = issue.get("origin", target)
            path        = issue.get("path", "")
            detail      = issue.get("description") or issue.get("issue_detail") or ""
            remediation = issue.get("remediation_background") or ""
            counts[sev] += 1

            await self.store_finding(Finding(
                title=f"[Burp Pro] [{sev}] {name}",
                description=(
                    f"{name} at {issue_url}{path}\n"
                    f"Confidence: {confidence}\n"
                    f"{detail[:400]}"
                ),
                severity=sev,
                evidence=(
                    f"URL       : {issue_url}{path}\n"
                    f"Confidence: {confidence}\n"
                    f"Detail    : {detail[:500]}\n"
                    f"Fix       : {remediation[:200]}"
                ),
                tool="burp_pro",
                host=target,
                mitre_technique="T1595.003",
                exploit_suggestion=remediation[:300] or None,
            ))

        overall_sev = next(
            (s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s] > 0),
            "INFO"
        )
        await self.store_finding(Finding(
            title=(
                f"Burp Pro: Scan Complete — "
                f"{sum(counts.values())} issue(s)  "
                f"[C={counts['CRITICAL']} H={counts['HIGH']} "
                f"M={counts['MEDIUM']} L={counts['LOW']}]"
            ),
            description=(
                f"Scan of {target} finished. Status: {scan_status}. "
                f"Total issues: {len(issues)}."
            ),
            severity=overall_sev,
            evidence=f"Scan ID: {scan_id} | Status: {scan_status}",
            tool="burp_pro",
            host=target,
            mitre_technique="T1595.003",
        ))

    # ──────────────────────────────────────────────────────────────────────
    # Community: proxy-hub passive scan
    # ──────────────────────────────────────────────────────────────────────

    async def _community_scan(
        self,
        target:     str,
        burp_path:  str,
        extra_urls: List[str],
    ) -> None:
        """
        Full Community Edition workflow:
        1. Pre-accept EULA via UserConfig.
        2. Launch Burp headlessly (--headless flag or xvfb-run fallback).
        3. Wait for proxy port.
        4. Route all active scanning tools through the proxy IN PARALLEL.
        5. Give passive scanner time to process.
        6. Parse findings from log + XML state.
        7. Kill Burp + cleanup.
        """
        tag          = (self.session_id or "argus")[:10]
        proxy_port   = await self._find_free_proxy_port()
        cfg_path     = f"/tmp/burp_cfg_{tag}.json"
        prj_path     = f"/tmp/burp_prj_{tag}.burp"
        log_path     = f"/tmp/burp_log_{tag}.txt"
        user_cfg     = f"/tmp/burp_user_{tag}.json"
        crawl_dir    = f"/tmp/burp_crawl_{tag}"
        jar_mode     = burp_path.endswith(".jar")

        # ── Step 1: Write configs ─────────────────────────────────────────
        await self.collect_tool(
            "bash", "",
            {"command": (
                f"mkdir -p {crawl_dir} ~/.BurpSuite && "
                f"cat > '{cfg_path}' << 'BEOF'\n"
                f"{json.dumps(_build_burp_config(target, proxy_port), indent=2)}\n"
                f"BEOF\n"
                f"cat > '{user_cfg}' << 'UEOF'\n"
                f"{json.dumps(_build_user_options(), indent=2)}\n"
                f"UEOF\n"
                # Also write to the default Burp user config so EULA is pre-accepted
                f"cp '{user_cfg}' ~/.BurpSuite/UserConfigCommunity.json 2>/dev/null || true; "
                f"cp '{user_cfg}' ~/.BurpSuite/UserConfigPro.json        2>/dev/null || true"
            )},
        )

        # ── Step 2: Launch Burp headlessly ───────────────────────────────
        burp_pid = await self._launch_burp_headless(
            burp_path, jar_mode, prj_path, cfg_path, user_cfg, log_path
        )

        await self.store_finding(Finding(
            title=f"Burp Community: Launched (proxy localhost:{proxy_port})",
            description=(
                f"Burp Suite Community started headlessly (PID {burp_pid}). "
                f"Proxy listener on localhost:{proxy_port}. "
                f"Routing active tools through proxy to maximise passive scanner coverage."
            ),
            severity="INFO",
            evidence=f"Binary: {burp_path}\nProxy: localhost:{proxy_port}\nPID: {burp_pid}",
            tool="burp_community",
            host=target,
            mitre_technique="T1595.003",
        ))

        # ── Step 3: Wait for proxy ────────────────────────────────────────
        proxy_up = await self._wait_for_proxy(proxy_port, timeout_sec=45)

        if not proxy_up:
            await self.store_finding(Finding(
                title=f"Burp Community: Proxy Port {proxy_port} Did Not Open",
                description=(
                    f"Burp proxy on port {proxy_port} never came up within 45 s. "
                    "Possible reasons: xvfb-run unavailable, EULA dialog blocking, "
                    "or Burp version too old for --headless. "
                    "Running active fallback scanners instead."
                ),
                severity="INFO",
                evidence=f"PID: {burp_pid}",
                tool="burp_community",
                host=target,
                mitre_technique="T1595.003",
            ))
            await self._kill_burp(burp_pid, prj_path, cfg_path, log_path,
                                  user_cfg, crawl_dir)
            await self._active_fallback_scan(target)
            return

        # ── Step 4: Route all tools through proxy ────────────────────────
        all_targets = [target] + [u for u in extra_urls if u != target]
        proxy_env   = f"http_proxy=http://localhost:{proxy_port} https_proxy=http://localhost:{proxy_port}"
        proxy_curl  = f"--proxy http://localhost:{proxy_port} --insecure"
        proxy_java  = f"-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort={proxy_port}"

        await self.store_finding(Finding(
            title="Burp Community: Routing Active Tools Through Proxy",
            description=(
                f"Routing curl, gobuster, ffuf, nikto, dalfox, sqlmap through "
                f"Burp proxy at localhost:{proxy_port}. "
                "Every request/response is processed by the passive scanner."
            ),
            severity="INFO",
            evidence=f"Proxy: localhost:{proxy_port} | Targets: {all_targets}",
            tool="burp_community",
            host=target,
            mitre_technique="T1595.003",
        ))

        # Run all proxy-routed scans in parallel
        scan_coros = []
        for url in all_targets[:3]:
            scan_coros += [
                self._proxy_crawl(url,  proxy_port, crawl_dir),
                self._proxy_gobuster(url, proxy_port),
                self._proxy_ffuf(url,    proxy_port),
                self._proxy_nikto(url,   proxy_port),
                self._proxy_dalfox(url,  proxy_port),
                self._proxy_sqlmap(url,  proxy_port),
                self._proxy_header_check(url, proxy_port),
            ]

        await asyncio.gather(*scan_coros, return_exceptions=True)

        # Give passive scanner extra time to process the captured traffic
        logger.info("[burp_community] Waiting 20 s for passive scanner to process traffic")
        await asyncio.sleep(20)

        # ── Step 5: Parse passive findings ───────────────────────────────
        log_content = await self.collect_tool(
            "bash", "", {"command": f"cat '{log_path}' 2>/dev/null | head -500 || echo ''"},
        )
        self._parse_community_log(log_content, target)

        # Also try to parse the Burp project state XML if exported
        xml_out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"find /tmp -name 'burp_prj_{tag}*' -newer /tmp/burp_cfg_{tag}.json "
                f"2>/dev/null | head -2"
            )},
        )
        for state_file in xml_out.strip().splitlines():
            await self._parse_burp_state_xml(state_file.strip(), target)

        # ── Step 6: Kill Burp + cleanup ───────────────────────────────────
        await self._kill_burp(burp_pid, prj_path, cfg_path, log_path, user_cfg, crawl_dir)

    # ── Headless launch ────────────────────────────────────────────────────

    async def _launch_burp_headless(
        self,
        burp_path: str,
        jar_mode:  bool,
        prj_path:  str,
        cfg_path:  str,
        user_cfg:  str,
        log_path:  str,
    ) -> str:
        """
        Try three launch strategies in order of preference:
          1. --headless=true  (Burp 2022.9+, recommended)
          2. -Djava.awt.headless=true  (older versions via java)
          3. xvfb-run  (legacy fallback)
        Returns the PID string.
        """
        base_flags = (
            f"--project-file='{prj_path}' "
            f"--config-file='{cfg_path}' "
            f"--user-config-file='{user_cfg}'"
        )
        if jar_mode:
            java_cmd = (
                f"java -Djava.awt.headless=true "
                f"-Xmx512m "
                f"-jar '{burp_path}' "
                f"--headless=true {base_flags}"
            )
            launch_cmd = f"nohup {java_cmd} > '{log_path}' 2>&1 & echo $!"
        else:
            # Strategy 1: native --headless (preferred)
            launch_cmd = (
                f"nohup '{burp_path}' --headless=true {base_flags} "
                f"> '{log_path}' 2>&1 & echo $!"
            )

        pid_out = await self.collect_tool("bash", "", {"command": launch_cmd})
        pid     = pid_out.strip().splitlines()[-1].strip()

        # Confirm the process is actually alive after 3 s
        await asyncio.sleep(3)
        alive = await self.collect_tool(
            "bash", "",
            {"command": f"kill -0 {pid} 2>/dev/null && echo ALIVE || echo DEAD"},
        )
        if "DEAD" in alive and not jar_mode:
            # Strategy 2: xvfb-run fallback
            logger.info("[burp] --headless launch failed — falling back to xvfb-run")
            launch_cmd = (
                f"nohup xvfb-run -a --server-args='-screen 0 1280x800x24' "
                f"'{burp_path}' {base_flags} "
                f"> '{log_path}' 2>&1 & echo $!"
            )
            pid_out = await self.collect_tool("bash", "", {"command": launch_cmd})
            pid     = pid_out.strip().splitlines()[-1].strip()

        return pid

    async def _wait_for_proxy(self, proxy_port: int, timeout_sec: int = 45) -> bool:
        """Poll until the proxy TCP port is open. Returns True if up."""
        for _ in range(timeout_sec // 3):
            await asyncio.sleep(3)
            check = await self.collect_tool(
                "bash", "",
                {"command": f"nc -z 127.0.0.1 {proxy_port} 2>/dev/null && echo UP || echo DOWN"},
            )
            if "UP" in check:
                return True
        return False

    async def _kill_burp(
        self,
        pid: str,
        prj_path: str,
        cfg_path: str,
        log_path: str,
        user_cfg: str,
        crawl_dir: str,
    ) -> None:
        """Gracefully stop Burp and remove temp files."""
        if pid and pid.isdigit():
            await self.collect_tool(
                "bash", "",
                {"command": (
                    f"kill {pid} 2>/dev/null; sleep 2; "
                    f"kill -9 {pid} 2>/dev/null || true"
                )},
            )
        await self.collect_tool(
            "bash", "",
            {"command": (
                f"rm -f '{prj_path}' '{cfg_path}' '{log_path}' '{user_cfg}' 2>/dev/null; "
                f"rm -rf '{crawl_dir}' 2>/dev/null || true"
            )},
        )

    # ── Proxy-routed active tools ──────────────────────────────────────────

    async def _proxy_crawl(self, url: str, proxy_port: int, crawl_dir: str) -> None:
        """Multi-tool crawl through the proxy — feeds passive scanner with rich request data."""
        pfx = f"--proxy http://localhost:{proxy_port} --insecure"
        env = f"http_proxy=http://localhost:{proxy_port} https_proxy=http://localhost:{proxy_port}"

        # Deep curl crawl (follow redirects, parse links)
        await self.collect_tool(
            "bash", "",
            {"command": (
                f"curl -sfL --max-redirs 10 --max-time 30 {pfx} "
                f"'{url}' -o /tmp/burp_index.html 2>/dev/null; "
                # Extract all links and fetch them
                f"grep -oE 'href=\"[^\"]+\"' /tmp/burp_index.html 2>/dev/null | "
                f"grep -oE '\"[^\"]+\"' | tr -d '\"' | head -30 | "
                f"while read link; do "
                f"  [[ \"$link\" == http* ]] || link='{url}$link'; "
                f"  curl -sf --max-time 10 {pfx} \"$link\" -o /dev/null 2>/dev/null & "
                f"done; wait"
            )},
        )

        # wget recursive crawl through proxy
        await self.collect_tool(
            "bash", "",
            {"command": (
                f"{env} wget -q -r -l 3 --no-check-certificate "
                f"--timeout=15 --tries=1 --wait=0 "
                f"-e 'use_proxy=yes' "
                f"-e 'http_proxy=http://localhost:{proxy_port}' "
                f"--user-agent='Mozilla/5.0 BurpSuite-Spider' "
                f"'{url}' -P '{crawl_dir}/' 2>&1 | head -50"
            )},
        )

        # httpx enumeration through proxy (if available)
        await self.collect_tool(
            "bash", "",
            {"command": (
                f"echo '{url}' | {env} httpx -silent -follow-redirects "
                f"-status-code -title -tech-detect "
                f"-H 'User-Agent: Mozilla/5.0' 2>/dev/null | head -20 || true"
            )},
        )

    async def _proxy_gobuster(self, url: str, proxy_port: int) -> None:
        """Directory bruteforce through Burp proxy — finds hidden endpoints."""
        wordlist = (
            "/usr/share/wordlists/dirb/common.txt"
            if os.path.isfile("/usr/share/wordlists/dirb/common.txt")
            else "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        )
        out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"gobuster dir -u '{url}' -w '{wordlist}' "
                f"--proxy http://localhost:{proxy_port} "
                f"-k -q -t 20 --timeout 10s "
                f"-x php,asp,aspx,jsp,html,txt,json,xml,bak,old,zip,conf "
                f"--no-error 2>/dev/null | head -80"
            )},
        )
        # Store significant finds
        for line in out.splitlines():
            if re.match(r"^/", line):
                status = re.search(r"\(Status:\s*(\d+)\)", line)
                code   = int(status.group(1)) if status else 200
                if code not in (404, 301) and code < 500:
                    await self.store_finding(Finding(
                        title=f"[Burp/gobuster] Path Found: {line[:80].strip()}",
                        description=f"gobuster (via Burp proxy) found: {line.strip()}",
                        severity="LOW" if code == 200 else "INFO",
                        evidence=line.strip(),
                        tool="gobuster",
                        host=url,
                        mitre_technique="T1595.003",
                    ))

    async def _proxy_ffuf(self, url: str, proxy_port: int) -> None:
        """Parameter and path fuzzing via Burp proxy."""
        wordlist = "/usr/share/wordlists/dirb/big.txt"
        if not os.path.isfile(wordlist):
            return
        await self.collect_tool(
            "bash", "",
            {"command": (
                f"ffuf -u '{url.rstrip('/')}/FUZZ' "
                f"-w '{wordlist}' "
                f"-x http://localhost:{proxy_port} "
                f"-mc 200,204,301,302,307,401,403,405 "
                f"-t 20 -timeout 10 -s 2>/dev/null | head -60"
            )},
        )

    async def _proxy_nikto(self, url: str, proxy_port: int) -> None:
        """Nikto active scanner routing through Burp — feeds passive scanner + finds active vulns."""
        proxy_flag = f"-useproxy http://localhost:{proxy_port} " if proxy_port else ""
        out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"nikto -h '{url}' "
                f"{proxy_flag}"
                f"-C all -maxtime 4m "
                f"-Tuning 123456789abc "
                f"-nointeractive 2>/dev/null | head -150"
            )},
        )
        for line in out.splitlines():
            if not line.startswith("+"):
                continue
            text = line.lstrip("+ ").strip()
            if len(text) < 15 or "Nikto" in text or "Target" in text:
                continue
            sev = self.parse_severity(text)
            await self.store_finding(Finding(
                title=f"[Burp/Nikto] {text[:80]}",
                description=text,
                severity=sev,
                evidence=line.strip(),
                tool="nikto",
                host=url,
                mitre_technique="T1595.003",
            ))

    async def _proxy_dalfox(self, url: str, proxy_port: int) -> None:
        """XSS scanning via Burp proxy — all payloads visible to passive scanner."""
        out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"dalfox url '{url}' "
                f"--proxy http://localhost:{proxy_port} "
                f"--silence --no-color --timeout 60 "
                f"--skip-bav 2>/dev/null | head -60"
            )},
        )
        for line in out.splitlines():
            if "[V]" in line or "VULN" in line.upper() or "XSS" in line:
                await self.store_finding(Finding(
                    title=f"[Burp/dalfox] XSS: {line[:80].strip()}",
                    description=f"dalfox found XSS (via Burp proxy): {line.strip()}",
                    severity="HIGH",
                    evidence=line.strip(),
                    tool="dalfox",
                    host=url,
                    mitre_technique="T1059.007",
                ))

    async def _proxy_sqlmap(self, url: str, proxy_port: int) -> None:
        """SQLMap injection testing via Burp proxy — all SQLi payloads visible to passive scanner."""
        out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"sqlmap -u '{url}' "
                f"--proxy=http://localhost:{proxy_port} "
                f"--crawl=2 --forms --level=2 --risk=2 --batch "
                f"--random-agent --technique=BEUSTQ "
                f"--timeout=10 --retries=1 "
                f"--answers='follow=Y' "
                f"--flush-session --output-dir=/tmp/sqlmap_burp "
                f"2>/dev/null | head -80"
            )},
        )
        if "identified the following injection" in out or "is vulnerable" in out.lower():
            db = re.search(r"back-end DBMS:\s*(.+)", out)
            await self.store_finding(Finding(
                title=f"[Burp/SQLMap] SQL Injection Confirmed at {url}",
                description=(
                    f"SQLMap confirmed SQLi via Burp proxy.\n"
                    f"Database: {db.group(1).strip() if db else 'Unknown'}"
                ),
                severity="CRITICAL",
                evidence=out[:1500],
                tool="sqlmap",
                host=url,
                mitre_technique="T1190",
                exploit_suggestion="Use --dump to extract data. Consider --os-shell for RCE.",
            ))

    async def _proxy_header_check(self, url: str, proxy_port: int) -> None:
        """Check security headers via Burp proxy (feeds passive scanner with header data)."""
        proxy_flag = f"--proxy http://localhost:{proxy_port} " if proxy_port else ""
        out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"curl -sfI --max-time 15 "
                f"{proxy_flag}--insecure "
                f"--user-agent 'Mozilla/5.0' "
                f"'{url}' 2>/dev/null"
            )},
        )
        missing = []
        headers_lower = out.lower()
        for hdr in (
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
        ):
            if hdr not in headers_lower:
                missing.append(hdr)
        if missing:
            await self.store_finding(Finding(
                title=f"[Burp] Missing Security Headers ({len(missing)}): {url}",
                description=f"Missing: {', '.join(missing)}",
                severity="LOW",
                evidence=out[:800],
                tool="curl",
                host=url,
                mitre_technique="T1595.003",
            ))
        # Check for interesting response headers (server version, etc.)
        for line in out.splitlines():
            if re.match(r"(?i)server:|x-powered-by:|x-aspnet-version:", line):
                await self.store_finding(Finding(
                    title=f"[Burp] Server Disclosure: {line.strip()[:80]}",
                    description=f"Response header discloses server/technology info: {line.strip()}",
                    severity="LOW",
                    evidence=line.strip(),
                    tool="curl",
                    host=url,
                    mitre_technique="T1082",
                ))

    # ── Finding parsers ────────────────────────────────────────────────────

    def _parse_community_log(self, log_content: str, target: str) -> None:
        """Extract passive scanner issues from Burp console log."""
        if not log_content.strip():
            return
        seen: set = set()
        for line in log_content.splitlines():
            m = _PASSIVE_RE.search(line)
            if not m:
                continue
            text = m.group(1).strip()[:200]
            if not text or text in seen:
                continue
            seen.add(text)

            # Try to extract severity from the same line or nearby context
            sev_m = _SEVERITY_RE.search(line)
            sev   = (
                _BURP_SEVERITY_MAP.get(sev_m.group(1).lower(), "MEDIUM")
                if sev_m
                else self.parse_severity(line)
            )
            self._findings.append(Finding(
                title=f"[Burp Passive] {text[:80]}",
                description=f"Burp Community passive finding: {text}",
                severity=sev,
                evidence=line.strip()[:500],
                tool="burp_community",
                host=target,
                mitre_technique="T1595.003",
            ))

    async def _parse_burp_state_xml(self, state_file: str, target: str) -> None:
        """Parse a Burp project state/export XML file for issues."""
        if not state_file:
            return
        xml_raw = await self.collect_tool(
            "bash", "",
            {"command": f"strings '{state_file}' 2>/dev/null | head -1000 || echo ''"},
        )
        # Extract issue blocks from XML
        for m in re.finditer(
            r"<issue>.*?</issue>", xml_raw, re.DOTALL | re.IGNORECASE
        ):
            block   = m.group(0)
            name_m  = re.search(r"<name>([^<]+)</name>", block)
            sev_m   = re.search(r"<severity>([^<]+)</severity>", block, re.IGNORECASE)
            detail_m= re.search(r"<issueDetail>([^<]+)</issueDetail>", block, re.IGNORECASE)
            host_m  = re.search(r"<host[^>]*>([^<]+)</host>", block)
            path_m  = re.search(r"<path>([^<]+)</path>", block)
            if not name_m:
                continue
            name = name_m.group(1).strip()
            sev  = _BURP_SEVERITY_MAP.get(
                (sev_m.group(1).strip().lower() if sev_m else "info"), "INFO"
            )
            detail = detail_m.group(1).strip() if detail_m else ""
            url    = (
                (host_m.group(1).strip() if host_m else target) +
                (path_m.group(1).strip() if path_m else "")
            )
            await self.store_finding(Finding(
                title=f"[Burp State] {name[:80]}",
                description=f"{name}\n{detail[:400]}",
                severity=sev,
                evidence=f"URL: {url}\n{detail[:300]}",
                tool="burp_community",
                host=target,
                mitre_technique="T1595.003",
            ))

    # ──────────────────────────────────────────────────────────────────────
    # Fallback: no Burp binary
    # ──────────────────────────────────────────────────────────────────────

    async def _active_fallback_scan(self, target: str) -> None:
        """
        Comprehensive active web scan when Burp is unavailable.
        Runs nikto + gobuster + dalfox + header check in parallel.
        """
        await asyncio.gather(
            self._proxy_nikto(target, proxy_port=0),     # no proxy
            self._active_gobuster(target),
            self._active_dalfox(target),
            self._proxy_header_check(target, proxy_port=0),
            return_exceptions=True,
        )

    async def _active_gobuster(self, url: str) -> None:
        """Gobuster without proxy — direct fallback scan."""
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.isfile(wordlist):
            return
        out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"gobuster dir -u '{url}' -w '{wordlist}' "
                f"-k -q -t 20 --timeout 10s --no-error "
                f"-x php,asp,aspx,jsp,html,txt,bak 2>/dev/null | head -60"
            )},
        )
        for line in out.splitlines():
            if re.match(r"^/", line):
                await self.store_finding(Finding(
                    title=f"[gobuster] Path Found: {line[:80].strip()}",
                    description=f"gobuster found: {line.strip()}",
                    severity="LOW",
                    evidence=line.strip(),
                    tool="gobuster",
                    host=url,
                    mitre_technique="T1595.003",
                ))

    async def _active_dalfox(self, url: str) -> None:
        """dalfox without proxy — direct XSS scan."""
        out = await self.collect_tool(
            "bash", "",
            {"command": (
                f"dalfox url '{url}' --silence --no-color "
                f"--timeout 60 --skip-bav 2>/dev/null | head -40"
            )},
        )
        for line in out.splitlines():
            if "[V]" in line or "VULN" in line.upper():
                await self.store_finding(Finding(
                    title=f"[dalfox] XSS: {line[:80].strip()}",
                    description=f"dalfox XSS finding: {line.strip()}",
                    severity="HIGH",
                    evidence=line.strip(),
                    tool="dalfox",
                    host=url,
                    mitre_technique="T1059.007",
                ))
