"""
web_fingerprint_subagent.py — Web technology fingerprinting and WAF detection.

Methodology:
  1. httpx probe     — status, title, content-length, tech-detect for all ports
  2. whatweb         — deep CMS/framework/server fingerprinting per live URL
  3. wafw00f         — WAF presence detection
  4. eyewitness/gowitness screenshot (optional, non-blocking, 30s timeout)
  5. Severity grading:
       CRITICAL — admin panel exposed without auth prompt
       HIGH     — login page + default-credential indicators detected
       MEDIUM   — version disclosure, sensitive tech stack revealed
       INFO     — general technology discovery
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default web ports probed if caller provides none
# ---------------------------------------------------------------------------
DEFAULT_WEB_PORTS: list[int] = [80, 443, 8080, 8443, 8000, 8888]

# ---------------------------------------------------------------------------
# Technology fingerprint patterns (service → CMS/Framework classification)
# ---------------------------------------------------------------------------
_CMS_PATTERNS: dict[str, re.Pattern] = {
    "WordPress":  re.compile(r"wp-content|wp-login|wordpress", re.IGNORECASE),
    "Drupal":     re.compile(r"drupal|sites/default|misc/drupal", re.IGNORECASE),
    "Joomla":     re.compile(r"joomla|com_content|administrator/index\.php", re.IGNORECASE),
    "Magento":    re.compile(r"magento|skin/frontend|mage/", re.IGNORECASE),
    "PrestaShop": re.compile(r"prestashop|ps_categoryproducts", re.IGNORECASE),
    "Typo3":      re.compile(r"typo3|typolink", re.IGNORECASE),
    "Shopify":    re.compile(r"shopify|cdn\.shopify", re.IGNORECASE),
    "Laravel":    re.compile(r"laravel|_token.*XSRF|laravel_session", re.IGNORECASE),
    "Django":     re.compile(r"django|csrfmiddlewaretoken", re.IGNORECASE),
    "Spring":     re.compile(r"spring|springframework|Whitelabel Error Page", re.IGNORECASE),
    "Rails":      re.compile(r"ruby on rails|rails|authenticity_token", re.IGNORECASE),
    "Express":    re.compile(r"express|x-powered-by.*express", re.IGNORECASE),
    "Flask":      re.compile(r"werkzeug|flask|jinja2", re.IGNORECASE),
    "ASP.NET":    re.compile(r"asp\.net|__viewstate|aspxauth", re.IGNORECASE),
    "JSP":        re.compile(r"\.jsp|jsessionid", re.IGNORECASE),
    "PHP":        re.compile(r"x-powered-by.*php|\.php", re.IGNORECASE),
    "Node.js":    re.compile(r"x-powered-by.*node|express", re.IGNORECASE),
}

_SERVER_PATTERN = re.compile(r"(?:^|\n)server:\s*(.+)", re.IGNORECASE)
_TITLE_PATTERN  = re.compile(r"<title[^>]*>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
_STATUS_PATTERN = re.compile(r"HTTP/[\d\.]+\s+(\d{3})")
_XPOWERED_PATTERN = re.compile(r"x-powered-by:\s*(.+)", re.IGNORECASE)

# Admin panel path patterns
_ADMIN_PATHS = re.compile(
    r"(?:^|[\s'\"/])(/(?:admin|administrator|wp-admin|manager|console|dashboard|"
    r"cpanel|phpmyadmin|webadmin|controlpanel|backend|cms)[/\w]*)",
    re.IGNORECASE,
)

# Login page indicators
_LOGIN_INDICATORS = re.compile(
    r"(?:login|sign.?in|log.?in|password|passwd|credentials|username|email).*"
    r"(?:form|input|field|submit|button)",
    re.IGNORECASE | re.DOTALL,
)

# Default credential page indicators
_DEFAULT_CRED_INDICATORS = re.compile(
    r"(?:default|initial|factory)\s+(?:password|credential|login|username)",
    re.IGNORECASE,
)

# WAF vendor names from wafw00f
_WAF_PATTERN = re.compile(
    r"(?:is behind|detected|identified|found)\s+(.+?)(?:\s+WAF|\s+\(|$)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_httpx_json_line(line: str) -> dict | None:
    """Parse a single JSON line from httpx -json output."""
    import json
    try:
        return json.loads(line.strip())
    except Exception:
        return None


def _parse_whatweb_line(line: str) -> dict:
    """
    Parse a WhatWeb output line.

    WhatWeb lines look like:
      http://10.0.0.1 [200 OK] Apache[2.4.49], PHP[7.4.26], Title[My Site]
    Returns a dict of {technology: version_or_detail}.
    """
    result: dict = {}
    # Extract status code
    sc_m = re.search(r"\[(\d{3})\s", line)
    if sc_m:
        result["status_code"] = int(sc_m.group(1))
    # Extract tech[version] pairs
    for m in re.finditer(r"([\w\-\.]+)\[([^\]]+)\]", line):
        key = m.group(1)
        val = m.group(2)
        if key.lower() not in ("http", "https", "ip", "country", "status"):
            result[key] = val
    return result


def _extract_technologies(combined_output: str) -> list[str]:
    """Extract normalized technology names from combined tool output."""
    found: list[str] = []
    for tech_name, pattern in _CMS_PATTERNS.items():
        if pattern.search(combined_output):
            found.append(tech_name)
    # Server header
    sm = _SERVER_PATTERN.search(combined_output)
    if sm:
        found.append(f"Server:{sm.group(1).strip()}")
    # X-Powered-By
    xm = _XPOWERED_PATTERN.search(combined_output)
    if xm:
        found.append(f"X-Powered-By:{xm.group(1).strip()}")
    return list(dict.fromkeys(found))  # deduplicate preserving order


def _assess_severity(url: str, combined_output: str, technologies: list[str]) -> tuple[str, str]:
    """
    Return (severity, reason) based on what was discovered.

    CRITICAL: admin panel accessible with no auth
    HIGH:     login page + default credential hints
    MEDIUM:   version disclosure, interesting tech
    INFO:     general discovery
    """
    # Admin panel exposed
    admin_m = _ADMIN_PATHS.search(combined_output)
    if admin_m:
        # Check if a login form is present on the admin path
        if _LOGIN_INDICATORS.search(combined_output):
            return "CRITICAL", f"Admin panel exposed at {admin_m.group(1)}"
        return "HIGH", f"Admin path accessible: {admin_m.group(1)}"

    # Login + default credential page
    if _LOGIN_INDICATORS.search(combined_output) and _DEFAULT_CRED_INDICATORS.search(combined_output):
        return "HIGH", "Login page with default credential references detected"

    # Version disclosure in Server/X-Powered-By
    version_tech = [t for t in technologies if re.search(r"\d+\.\d+", t)]
    if version_tech:
        return "MEDIUM", f"Version disclosure: {', '.join(version_tech[:3])}"

    # CMS detected
    cms_found = [t for t in technologies if t in _CMS_PATTERNS]
    if cms_found:
        return "MEDIUM", f"CMS detected: {', '.join(cms_found)}"

    return "INFO", "Web service fingerprinted"


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class WebFingerprintSubagent(BaseSubagent):
    """
    Web technology fingerprinting, WAF detection, and screenshot capture.

    For each candidate URL (target × web_ports) probes liveness with httpx,
    runs whatweb for deep fingerprinting, checks for WAFs with wafw00f, and
    attempts a screenshot with eyewitness or gowitness.
    """

    AGENT_NAME    = "recon"
    SUBAGENT_NAME = "web_fingerprint"

    async def run(  # noqa: C901
        self,
        target: str,
        web_ports: list[int] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Fingerprint all web services on *target*.

        Parameters
        ----------
        target:
            IP or hostname to probe.
        web_ports:
            List of TCP ports to probe. Defaults to [80, 443, 8080, 8443, 8000, 8888].

        Returns
        -------
        SubagentResult
            parsed_data["web_targets"] — list of per-URL fingerprint dicts
        """
        if web_ports is None:
            web_ports = DEFAULT_WEB_PORTS

        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"web_targets": []}
        wall_start = time.monotonic()

        # ── Step 1: Build URL list and probe with httpx ────────────────────
        urls: list[str] = []
        for port in web_ports:
            scheme = "https" if port in (443, 8443) else "http"
            urls.append(f"{scheme}://{target}:{port}")

        logger.info("[web_fingerprint] probing %d URLs on %s", len(urls), target)

        # httpx multi-probe (one tool call with -l flag simulation via options)
        # We call httpx per URL because the MCP tool wraps CLI calls
        live_urls: list[dict] = []
        for url in urls:
            try:
                httpx_out = await self.collect_tool(
                    "httpx",
                    target,
                    {
                        "options": (
                            f"-u {url} -title -tech-detect -status-code "
                            f"-content-length -follow-redirects -timeout 10 -silent"
                        )
                    },
                )
                self._tool_outputs[f"httpx_{url}"] = httpx_out

                if not httpx_out.strip():
                    continue  # No response — port not listening

                # Try JSON parse first (httpx -json)
                entry: dict = {
                    "url": url,
                    "status_code": None,
                    "title": "",
                    "server": "",
                    "content_length": None,
                    "technologies": [],
                    "waf": None,
                    "raw_httpx": httpx_out,
                }

                # Parse httpx -json line if present
                for raw_line in httpx_out.splitlines():
                    parsed_json = _parse_httpx_json_line(raw_line)
                    if parsed_json:
                        entry["status_code"]    = parsed_json.get("status-code") or parsed_json.get("status_code")
                        entry["title"]          = parsed_json.get("title", "")
                        entry["content_length"] = parsed_json.get("content-length")
                        techs = parsed_json.get("technologies") or parsed_json.get("tech") or []
                        entry["technologies"]   = techs if isinstance(techs, list) else [techs]
                        entry["server"]         = parsed_json.get("webserver", "")
                        break
                else:
                    # Fallback: parse plain-text httpx output
                    sc_m = _STATUS_PATTERN.search(httpx_out)
                    if sc_m:
                        entry["status_code"] = int(sc_m.group(1))
                    title_m = _TITLE_PATTERN.search(httpx_out)
                    if title_m:
                        entry["title"] = title_m.group(1)[:120]
                    server_m = _SERVER_PATTERN.search(httpx_out)
                    if server_m:
                        entry["server"] = server_m.group(1).strip()

                # Only include HTTP 200/30x/401/403 as "live" (skip 000 / connection refused)
                if entry["status_code"] and entry["status_code"] < 500:
                    live_urls.append(entry)
                    logger.info(
                        "[web_fingerprint] live: %s status=%s title=%s",
                        url, entry["status_code"], entry["title"][:40],
                    )

            except Exception as exc:
                logger.warning("[web_fingerprint] httpx error for %s: %s", url, exc)

        if not live_urls:
            logger.info("[web_fingerprint] no live web services found on %s", target)
            result.duration_seconds = time.monotonic() - wall_start
            await self._emit(
                "web_fingerprint_complete",
                {"target": target, "live_count": 0, "web_targets": []},
            )
            return result

        # ── Step 2: WhatWeb deep fingerprint ──────────────────────────────
        for entry in live_urls:
            url = entry["url"]
            logger.info("[web_fingerprint] whatweb: %s", url)
            try:
                ww_out = await self.collect_tool(
                    "whatweb",
                    target,
                    {"options": f"-a 3 --no-errors --log-brief=- {url}"},
                )
                self._tool_outputs[f"whatweb_{url}"] = ww_out
                entry["raw_whatweb"] = ww_out

                ww_parsed = _parse_whatweb_line(ww_out)
                # Merge whatweb status if httpx did not find it
                if entry["status_code"] is None and "status_code" in ww_parsed:
                    entry["status_code"] = ww_parsed.pop("status_code")
                else:
                    ww_parsed.pop("status_code", None)

                # Add whatweb-found technologies
                for k, v in ww_parsed.items():
                    tech_str = f"{k}[{v}]" if v else k
                    if tech_str not in entry["technologies"]:
                        entry["technologies"].append(tech_str)

                # Extract server from WhatWeb if not already set
                if not entry["server"] and "Apache" in ww_parsed:
                    entry["server"] = f"Apache[{ww_parsed['Apache']}]"
                elif not entry["server"] and "Nginx" in ww_parsed:
                    entry["server"] = f"Nginx[{ww_parsed['Nginx']}]"
                elif not entry["server"] and "IIS" in ww_parsed:
                    entry["server"] = f"IIS[{ww_parsed['IIS']}]"

                # Deep tech detection from combined output
                combined = "\n".join([
                    entry.get("raw_httpx", ""),
                    entry.get("raw_whatweb", ""),
                ])
                extra_techs = _extract_technologies(combined)
                for t in extra_techs:
                    if t not in entry["technologies"]:
                        entry["technologies"].append(t)

            except Exception as exc:
                logger.warning("[web_fingerprint] whatweb error for %s: %s", url, exc)

        # ── Step 3: WAF detection with wafw00f ────────────────────────────
        # Run once per base host (wafw00f auto-tries common paths)
        base_url = live_urls[0]["url"] if live_urls else f"http://{target}"
        logger.info("[web_fingerprint] wafw00f: %s", base_url)
        waf_name: str | None = None
        try:
            wafw_out = await self.collect_tool(
                "wafw00f",
                target,
                {"options": f"-a {base_url}"},
            )
            self._tool_outputs["wafw00f"] = wafw_out
            wm = _WAF_PATTERN.search(wafw_out)
            if wm:
                waf_name = wm.group(1).strip()
            elif re.search(r"no waf detected|not protected", wafw_out, re.IGNORECASE):
                waf_name = None
            elif re.search(r"is behind", wafw_out, re.IGNORECASE):
                waf_name = "Unknown WAF"

            # Propagate WAF to all entries
            for entry in live_urls:
                entry["waf"] = waf_name

            if waf_name:
                await self.store_finding(Finding(
                    title=f"WAF Detected: {waf_name}",
                    description=(
                        f"A Web Application Firewall ({waf_name}) was detected in front of "
                        f"{target}. This may affect exploit delivery and scan accuracy."
                    ),
                    severity="MEDIUM",
                    evidence=wafw_out[:500],
                    tool="wafw00f",
                    host=target,
                    exploit_suggestion=(
                        "Research WAF bypass techniques for the identified vendor. "
                        "Consider HTTP parameter pollution, encoding variations, or "
                        "IP-based direct access."
                    ),
                ))
        except Exception as exc:
            logger.warning("[web_fingerprint] wafw00f error: %s", exc)

        # ── Step 4: Screenshots (non-blocking, 30s timeout) ───────────────
        screenshot_tool: str | None = None
        for tool_candidate in ("gowitness", "eyewitness"):
            # We attempt but do not fail if unavailable
            screenshot_tool = tool_candidate
            break  # prefer gowitness

        if screenshot_tool:
            screenshot_targets = " ".join(e["url"] for e in live_urls[:5])
            logger.info("[web_fingerprint] screenshot with %s", screenshot_tool)
            try:
                if screenshot_tool == "gowitness":
                    ss_options = f"scan file --targets - --timeout 30 --disable-db"
                else:
                    ss_options = f"--web --prepend-https --timeout 30"

                async with asyncio.timeout(35):
                    ss_out = await self.collect_tool(
                        screenshot_tool,
                        target,
                        {"options": ss_options, "urls": screenshot_targets},
                    )
                self._tool_outputs[f"screenshot_{screenshot_tool}"] = ss_out
                logger.info("[web_fingerprint] screenshots completed")
            except (asyncio.TimeoutError, Exception) as exc:
                logger.info(
                    "[web_fingerprint] screenshot skipped (non-critical): %s", exc
                )

        # ── Step 5: Classify findings and store ───────────────────────────
        for entry in live_urls:
            combined_text = "\n".join([
                entry.get("raw_httpx", ""),
                entry.get("raw_whatweb", ""),
            ])
            severity, reason = _assess_severity(
                entry["url"], combined_text, entry["technologies"]
            )

            tech_str = ", ".join(entry["technologies"][:10]) if entry["technologies"] else "unknown"
            evidence_parts = [
                f"URL: {entry['url']}",
                f"Status: {entry.get('status_code', '?')}",
                f"Title: {entry.get('title', '')}",
                f"Server: {entry.get('server', '')}",
                f"Technologies: {tech_str}",
            ]
            if entry.get("waf"):
                evidence_parts.append(f"WAF: {entry['waf']}")

            await self.store_finding(Finding(
                title=(
                    f"Web Service: {entry['url']} "
                    f"[{entry.get('status_code', '?')}] "
                    f"{entry.get('title', '')[:40]}"
                ),
                description=(
                    f"Web service at {entry['url']} returned HTTP {entry.get('status_code')}. "
                    f"Server: {entry.get('server', 'unknown')}. "
                    f"Technologies: {tech_str}. "
                    f"WAF: {entry.get('waf') or 'none detected'}. "
                    f"Reason for {severity}: {reason}."
                ),
                severity=severity,
                evidence="\n".join(evidence_parts),
                tool="httpx/whatweb",
                host=target,
                port=_port_from_url(entry["url"]),
                exploit_suggestion=_web_exploit_hint(severity, entry["technologies"]),
            ))

        # ── Step 6: Assemble final result ─────────────────────────────────
        web_targets_out = [
            {
                "url":            e["url"],
                "status_code":    e.get("status_code"),
                "title":          e.get("title", ""),
                "server":         e.get("server", ""),
                "technologies":   e.get("technologies", []),
                "waf":            e.get("waf"),
                "content_length": e.get("content_length"),
            }
            for e in live_urls
        ]

        result.parsed_data["web_targets"] = web_targets_out
        result.findings                   = self._findings
        result.tool_outputs               = self._tool_outputs
        result.duration_seconds           = time.monotonic() - wall_start

        # ── Step 7: Emit completion event ─────────────────────────────────
        await self._emit(
            "web_fingerprint_complete",
            {
                "target":      target,
                "live_count":  len(live_urls),
                "waf":         waf_name,
                "web_targets": web_targets_out,
                "finding_count": len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[web_fingerprint] complete — %d live URLs, %d findings, %.1fs",
            len(live_urls), len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _port_from_url(url: str) -> int | None:
    """Extract port number from URL string."""
    m = re.search(r":(\d+)(?:/|$)", url)
    if m:
        return int(m.group(1))
    if url.startswith("https://"):
        return 443
    if url.startswith("http://"):
        return 80
    return None


def _web_exploit_hint(severity: str, technologies: list[str]) -> str:
    """Return a contextual exploitation hint."""
    tech_lower = " ".join(technologies).lower()
    if "wordpress" in tech_lower:
        return (
            "WordPress detected — run wpscan for plugin/theme CVEs and "
            "weak credentials: wpscan --url <target> --enumerate vp,vt,u"
        )
    if "joomla" in tech_lower:
        return "Joomla detected — run joomscan for known vulnerabilities."
    if "drupal" in tech_lower:
        return "Drupal detected — check Drupalgeddon (SA-CORE-2018-002) and similar."
    if severity == "CRITICAL":
        return (
            "Admin panel exposed. Test for default credentials "
            "(admin:admin, admin:password) and authentication bypass."
        )
    if severity == "HIGH":
        return (
            "Login page found. Run credential brute-force with hydra/medusa. "
            "Check for SQLi on login fields."
        )
    if severity == "MEDIUM":
        return (
            "Version information disclosed. Cross-reference with CVE databases "
            "and searchsploit for known exploits."
        )
    return "Enumerate further with gobuster/ffuf for hidden paths and backup files."
