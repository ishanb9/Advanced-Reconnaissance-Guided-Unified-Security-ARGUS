"""
crypto_failures_subagent.py — OWASP A04:2025 Cryptographic Failures detection.

Methodology:
  1. SSL/TLS configuration test using sslscan
  2. HTTP → HTTPS redirect check (missing redirect = finding)
  3. Security headers check: HSTS, CSP, X-Frame-Options, X-Content-Type-Options via curl -I
  4. Weak cipher and protocol detection (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
  5. Classify findings:
       HIGH     — SSLv2/SSLv3 enabled, no HTTPS redirect, missing HSTS on HTTPS
       MEDIUM   — TLS 1.0/1.1 enabled, missing CSP/X-Frame-Options headers
       LOW      — Missing X-Content-Type-Options, informational header issues
  6. Emit "crypto_failures_complete" with finding count
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_SSLV2_RE     = re.compile(r"SSLv2\s+enabled|Accepted\s+SSLv2", re.IGNORECASE)
_SSLV3_RE     = re.compile(r"SSLv3\s+enabled|Accepted\s+SSLv3", re.IGNORECASE)
_TLS10_RE     = re.compile(r"TLSv1\.0\s+enabled|Accepted\s+TLSv1\.0|TLS 1\.0 enabled", re.IGNORECASE)
_TLS11_RE     = re.compile(r"TLSv1\.1\s+enabled|Accepted\s+TLSv1\.1|TLS 1\.1 enabled", re.IGNORECASE)
_WEAK_CIPHER_RE = re.compile(
    r"RC4|DES\b|3DES|NULL cipher|EXPORT|anon|ADH|AECDH|LOW\b|MEDIUM\b",
    re.IGNORECASE,
)
_CERT_EXPIRED_RE   = re.compile(r"certificate.*expir|NOT after.*\d{4}", re.IGNORECASE)
_SELF_SIGNED_RE    = re.compile(r"self.signed|self_signed|unable to get local issuer", re.IGNORECASE)

_HSTS_RE              = re.compile(r"strict-transport-security", re.IGNORECASE)
_CSP_RE               = re.compile(r"content-security-policy", re.IGNORECASE)
_XFRAME_RE            = re.compile(r"x-frame-options", re.IGNORECASE)
_XCONTENT_RE          = re.compile(r"x-content-type-options", re.IGNORECASE)
_LOCATION_HTTPS_RE    = re.compile(r"location:\s*https://", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------


class CryptoFailuresSubagent(BaseSubagent):
    """
    Cryptographic failures detection via sslscan and HTTP header analysis.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "crypto_failures"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Test for cryptographic failures on all web targets.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            List of URL dicts from web_fingerprint parsed_data["web_targets"].

        Returns
        -------
        SubagentResult
            parsed_data["crypto_issues"] — list of detected issue dicts
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"crypto_issues": []}
        wall_start = time.monotonic()

        # RAG lookup for relevant techniques
        await self._kb_search(
            f"cryptographic failures TLS SSL weak cipher HSTS {target}", top_k=3
        )

        # Build URL list
        urls: list[str] = []
        if web_targets:
            urls = [wt["url"] for wt in web_targets if isinstance(wt, dict) and "url" in wt]
        if not urls:
            urls = [f"http://{target}", f"https://{target}"]

        issues: list[dict] = []
        scanned_hosts: set[str] = set()

        for url in urls:
            base = url.rstrip("/")
            is_https = url.startswith("https://")
            host_port = _host_port_from_url(url)

            # ── Test 1: SSL/TLS scan via sslscan (HTTPS only, once per host) ──
            if is_https and host_port not in scanned_hosts:
                scanned_hosts.add(host_port)
                logger.info("[crypto_failures] sslscan on %s", host_port)
                try:
                    ssl_out = await self.collect_tool(
                        "sslscan",
                        target,
                        {
                            "options": f"--no-colour {host_port}"
                        },
                    )
                    self._tool_outputs[f"sslscan_{host_port}"] = ssl_out

                    if _SSLV2_RE.search(ssl_out):
                        issues.append({"type": "sslv2_enabled", "host": host_port})
                        await self.store_finding(Finding(
                            title=f"SSLv2 Enabled: {host_port}",
                            description=(
                                f"The server at {host_port} accepts SSLv2 connections. "
                                f"SSLv2 is critically broken and allows trivial decryption attacks."
                            ),
                            severity="HIGH",
                            evidence=ssl_out[:600],
                            tool="sslscan",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1557",
                            exploit_suggestion=(
                                "Use openssl s_client -ssl2 to confirm. "
                                "Disable SSLv2 immediately in server TLS configuration."
                            ),
                        ))

                    if _SSLV3_RE.search(ssl_out):
                        issues.append({"type": "sslv3_enabled", "host": host_port})
                        await self.store_finding(Finding(
                            title=f"SSLv3 Enabled (POODLE): {host_port}",
                            description=(
                                f"The server at {host_port} accepts SSLv3 connections. "
                                f"SSLv3 is vulnerable to the POODLE attack (CVE-2014-3566)."
                            ),
                            severity="HIGH",
                            evidence=ssl_out[:600],
                            tool="sslscan",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1557",
                            exploit_suggestion=(
                                "openssl s_client -ssl3 -connect {host_port} to confirm POODLE. "
                                "Disable SSLv3 in server configuration."
                            ),
                        ))

                    if _TLS10_RE.search(ssl_out):
                        issues.append({"type": "tls10_enabled", "host": host_port})
                        await self.store_finding(Finding(
                            title=f"TLS 1.0 Enabled (Legacy): {host_port}",
                            description=(
                                f"The server at {host_port} accepts TLS 1.0 connections. "
                                f"TLS 1.0 is deprecated and vulnerable to BEAST and POODLE attacks."
                            ),
                            severity="MEDIUM",
                            evidence=ssl_out[:600],
                            tool="sslscan",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1557",
                            exploit_suggestion=(
                                "Upgrade server to require TLS 1.2 minimum. "
                                "Configure: ssl_protocols TLSv1.2 TLSv1.3;"
                            ),
                        ))

                    if _TLS11_RE.search(ssl_out):
                        issues.append({"type": "tls11_enabled", "host": host_port})
                        await self.store_finding(Finding(
                            title=f"TLS 1.1 Enabled (Deprecated): {host_port}",
                            description=(
                                f"The server at {host_port} accepts TLS 1.1 connections. "
                                f"TLS 1.1 is deprecated as of RFC 8996 (March 2021)."
                            ),
                            severity="MEDIUM",
                            evidence=ssl_out[:600],
                            tool="sslscan",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1557",
                            exploit_suggestion=(
                                "Disable TLS 1.1 in server configuration. "
                                "Require TLS 1.2+ with strong cipher suites."
                            ),
                        ))

                    if _WEAK_CIPHER_RE.search(ssl_out):
                        issues.append({"type": "weak_cipher", "host": host_port})
                        await self.store_finding(Finding(
                            title=f"Weak Cipher Suites Accepted: {host_port}",
                            description=(
                                f"The server at {host_port} accepts weak cipher suites "
                                f"(RC4, DES, 3DES, NULL, EXPORT, or anonymous ciphers)."
                            ),
                            severity="MEDIUM",
                            evidence=ssl_out[:600],
                            tool="sslscan",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1557",
                            exploit_suggestion=(
                                "Configure server cipher suite to: "
                                "ECDHE+AESGCM:ECDHE+CHACHA20:!RC4:!DES:!3DES:!NULL:!EXPORT"
                            ),
                        ))

                    if _SELF_SIGNED_RE.search(ssl_out):
                        issues.append({"type": "self_signed_cert", "host": host_port})
                        await self.store_finding(Finding(
                            title=f"Self-Signed Certificate: {host_port}",
                            description=(
                                f"The server at {host_port} presents a self-signed certificate. "
                                f"This allows trivial MitM attacks as clients cannot verify identity."
                            ),
                            severity="MEDIUM",
                            evidence=ssl_out[:400],
                            tool="sslscan",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1557",
                            exploit_suggestion=(
                                "Install a CA-signed certificate (e.g., Let's Encrypt). "
                                "Use mitmproxy to intercept traffic during testing."
                            ),
                        ))

                except Exception as exc:
                    logger.warning("[crypto_failures] sslscan error for %s: %s", host_port, exc)

            # ── Test 2: HTTP → HTTPS redirect check ───────────────────────
            if not is_https:
                logger.info("[crypto_failures] HTTPS redirect check for %s", url)
                http_base = base
                try:
                    redir_out = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -o /dev/null -w '%{{http_code}} %{{redirect_url}}' "
                                f"-m 10 --max-redirs 0 \"{http_base}/\""
                            )
                        },
                    )
                    self._tool_outputs[f"https_redirect_{base[-20:]}"] = redir_out

                    redirects_to_https = _LOCATION_HTTPS_RE.search(redir_out) or (
                        "https://" in redir_out.lower()
                    )
                    parts = redir_out.strip().split()
                    code = int(parts[0]) if parts and parts[0].isdigit() else 0

                    if not redirects_to_https and code == 200:
                        issues.append({"type": "no_https_redirect", "url": http_base})
                        await self.store_finding(Finding(
                            title=f"No HTTPS Redirect: {http_base}",
                            description=(
                                f"The server at {http_base} does not redirect HTTP traffic to HTTPS. "
                                f"Credentials and session tokens may be transmitted in cleartext."
                            ),
                            severity="HIGH",
                            evidence=f"HTTP {code} with no HTTPS redirect on {http_base}",
                            tool="curl",
                            host=target,
                            port=80,
                            mitre_technique="T1557",
                            exploit_suggestion=(
                                "Use mitmproxy/Wireshark to capture plaintext traffic. "
                                "Add server redirect: return 301 https://$host$request_uri;"
                            ),
                        ))

                except Exception as exc:
                    logger.warning("[crypto_failures] redirect check error for %s: %s", url, exc)

            # ── Test 3: Security headers check ────────────────────────────
            logger.info("[crypto_failures] security headers check for %s", url)
            try:
                headers_out = await self.collect_tool(
                    "curl",
                    target,
                    {
                        "options": (
                            f"-s -I -m 10 "
                            f"-H 'User-Agent: Mozilla/5.0' "
                            f"\"{base}/\""
                        )
                    },
                )
                self._tool_outputs[f"headers_{base[-20:]}"] = headers_out

                # HSTS check (required for HTTPS sites)
                if is_https and not _HSTS_RE.search(headers_out):
                    issues.append({"type": "missing_hsts", "url": base})
                    await self.store_finding(Finding(
                        title=f"Missing HSTS Header: {base}",
                        description=(
                            f"The HTTPS site at {base} does not set the "
                            f"Strict-Transport-Security header. Browsers may "
                            f"allow HTTP downgrade attacks."
                        ),
                        severity="HIGH",
                        evidence=headers_out[:500],
                        tool="curl",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1557",
                        exploit_suggestion=(
                            "Add header: Strict-Transport-Security: "
                            "max-age=31536000; includeSubDomains; preload"
                        ),
                    ))

                # CSP check
                if not _CSP_RE.search(headers_out):
                    issues.append({"type": "missing_csp", "url": base})
                    await self.store_finding(Finding(
                        title=f"Missing Content-Security-Policy: {base}",
                        description=(
                            f"The site at {base} does not set a Content-Security-Policy header. "
                            f"This increases exposure to XSS and data injection attacks."
                        ),
                        severity="MEDIUM",
                        evidence=headers_out[:500],
                        tool="curl",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1059",
                        exploit_suggestion=(
                            "Add header: Content-Security-Policy: default-src 'self'; "
                            "script-src 'self'; object-src 'none'"
                        ),
                    ))

                # X-Frame-Options check
                if not _XFRAME_RE.search(headers_out):
                    issues.append({"type": "missing_xframe", "url": base})
                    await self.store_finding(Finding(
                        title=f"Missing X-Frame-Options: {base}",
                        description=(
                            f"The site at {base} does not set X-Frame-Options. "
                            f"This allows clickjacking attacks via iframes."
                        ),
                        severity="MEDIUM",
                        evidence=headers_out[:500],
                        tool="curl",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1059",
                        exploit_suggestion=(
                            "Add header: X-Frame-Options: DENY  or "
                            "Content-Security-Policy: frame-ancestors 'none'"
                        ),
                    ))

                # X-Content-Type-Options check
                if not _XCONTENT_RE.search(headers_out):
                    issues.append({"type": "missing_xcontent_type", "url": base})
                    await self.store_finding(Finding(
                        title=f"Missing X-Content-Type-Options: {base}",
                        description=(
                            f"The site at {base} does not set X-Content-Type-Options: nosniff. "
                            f"Browsers may MIME-sniff responses leading to XSS via file uploads."
                        ),
                        severity="LOW",
                        evidence=headers_out[:500],
                        tool="curl",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1059",
                        exploit_suggestion=(
                            "Add header: X-Content-Type-Options: nosniff"
                        ),
                    ))

            except Exception as exc:
                logger.warning("[crypto_failures] headers check error for %s: %s", url, exc)

        result.parsed_data["crypto_issues"] = issues
        result.findings                      = self._findings
        result.tool_outputs                  = self._tool_outputs
        result.duration_seconds              = time.monotonic() - wall_start

        await self._emit(
            "crypto_failures_complete",
            {
                "target":           target,
                "issue_count":      len(issues),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[crypto_failures] complete — %d issues, %d findings, %.1fs",
            len(issues), len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _host_port_from_url(url: str) -> str:
    """Extract host:port string for sslscan."""
    m = re.match(r"https?://([^/]+)", url)
    if not m:
        return url
    hp = m.group(1)
    if ":" not in hp:
        hp += ":443" if url.startswith("https://") else ":80"
    return hp


def _port_from_url(url: str) -> int | None:
    m = re.search(r":(\d+)(?:/|$)", url)
    if m:
        return int(m.group(1))
    if url.startswith("https://"):
        return 443
    if url.startswith("http://"):
        return 80
    return None
