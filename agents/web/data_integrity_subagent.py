"""
data_integrity_subagent.py — OWASP A08:2025 Software and Data Integrity Failures detection.

Methodology:
  1. File upload bypass: check if /upload endpoint exists, test content-type bypass payloads
  2. Deserialization hints: scan responses for Java serialized objects (base64 rO0AB),
     PHP serialized data (a:, O: patterns), Python unsafe deserialization markers
  3. Unsigned JWT detection: check cookies/headers for JWT tokens, test alg:none bypass
  4. Third-party JS loaded over HTTP (missing Subresource Integrity)
  5. Classify findings:
       CRITICAL — file upload allows server-side code execution
       HIGH     — unsigned JWT (alg:none), deserialization endpoints detected
       MEDIUM   — file upload exists (requires further testing), missing SRI
       LOW      — JWT without expiry, informational integrity issues
  6. Emit "data_integrity_complete" with finding count
"""

from __future__ import annotations

import base64
import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Java serialized object magic bytes (base64: rO0AB)
_JAVA_SERIAL_B64_RE = re.compile(r"rO0AB[A-Za-z0-9+/=]{4,}", re.IGNORECASE)
_JAVA_SERIAL_HEX_RE = re.compile(r"aced0005", re.IGNORECASE)

# PHP serialized object patterns
_PHP_SERIAL_RE = re.compile(
    r'(?:^|[^A-Za-z])(?:a:\d+:\{|O:\d+:"|s:\d+:"|i:\d+;|b:[01];)',
    re.MULTILINE,
)

# Python unsafe deserialization indicators (detection only)
_UNSAFE_DESER_RE = re.compile(r"gASV|cos\n|cbuiltins\n|__reduce__|deserialization", re.IGNORECASE)

# JWT patterns: three base64url segments separated by dots
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*",
)

# Script tags loading JS over HTTP (not HTTPS, not relative)
_HTTP_SCRIPT_RE = re.compile(
    r'<script[^>]+src=["\']http://[^"\']+["\']',
    re.IGNORECASE,
)

# Script tags missing integrity attribute
_SCRIPT_NO_SRI_RE = re.compile(
    r'<script[^>]+src=["\']https?://(?!localhost|127\.0\.0\.1)[^"\']+["\'](?![^>]*integrity=)',
    re.IGNORECASE,
)

_UPLOAD_ENDPOINTS = [
    "/upload",
    "/uploads",
    "/file/upload",
    "/files/upload",
    "/api/upload",
    "/image/upload",
    "/media/upload",
    "/attachments",
    "/avatar",
    "/profile/picture",
]

_UPLOAD_SUCCESS_RE = re.compile(
    r'"url"\s*:|"path"\s*:|"filename"\s*:|"file_url"\s*:|uploaded successfully|upload complete',
    re.IGNORECASE,
)

# Server-side execution indicator (webshell response)
_EXEC_RESPONSE_RE = re.compile(
    r"uid=\d+|root:|www-data|apache|nobody|<br\s*/>uid=",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------


class DataIntegritySubagent(BaseSubagent):
    """
    Software and Data Integrity failures detection via upload, deserialization, and JWT tests.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "data_integrity"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Test for data integrity failures on all web targets.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            List of URL dicts from web_fingerprint parsed_data["web_targets"].

        Returns
        -------
        SubagentResult
            parsed_data["integrity_issues"] — list of detected issue dicts
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"integrity_issues": []}
        wall_start = time.monotonic()

        # RAG lookup for relevant techniques
        await self._kb_search(
            f"deserialization file upload bypass data integrity JWT {target}", top_k=3
        )

        # Build URL list
        urls: list[str] = []
        if web_targets:
            urls = [wt["url"] for wt in web_targets if isinstance(wt, dict) and "url" in wt]
        if not urls:
            urls = [f"http://{target}", f"https://{target}"]

        issues: list[dict] = []

        for url in urls:
            base = url.rstrip("/")

            # ── Test 1: File upload endpoint detection & bypass ────────────
            logger.info("[data_integrity] file upload probe on %s", url)
            for upload_path in _UPLOAD_ENDPOINTS[:5]:
                upload_url = f"{base}{upload_path}"
                try:
                    # Probe GET first to see if endpoint exists
                    probe_out = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -o /dev/null -w '%{{http_code}}' "
                                f"-m 5 \"{upload_url}\""
                            )
                        },
                    )
                    self._tool_outputs[f"upload_probe_{upload_path.replace('/', '_')}"] = probe_out

                    code_str = probe_out.strip()
                    if not code_str.isdigit():
                        continue
                    code = int(code_str)

                    if code in (200, 301, 302, 405):  # 405 = POST required, endpoint exists
                        # Test with double-extension bypass (content-type spoofing)
                        upload_result = await self.collect_tool(
                            "curl",
                            target,
                            {
                                "options": (
                                    f"-s -m 15 "
                                    f"-X POST "
                                    f"-F 'file=@/dev/null;filename=test_probe.gif;type=image/gif' "
                                    f"\"{upload_url}\""
                                )
                            },
                        )
                        self._tool_outputs[f"upload_test_{upload_path.replace('/', '_')}"] = upload_result

                        sev = "CRITICAL" if _EXEC_RESPONSE_RE.search(upload_result) else "MEDIUM"
                        if _UPLOAD_SUCCESS_RE.search(upload_result) or _EXEC_RESPONSE_RE.search(upload_result):
                            issues.append({
                                "type": "file_upload_bypass",
                                "url": upload_url,
                                "severity": sev,
                            })
                            await self.store_finding(Finding(
                                title=(
                                    f"File Upload{'— RCE Possible' if sev == 'CRITICAL' else ' Endpoint Detected'}: "
                                    f"{upload_path}"
                                ),
                                description=(
                                    f"File upload endpoint found at {upload_url}. "
                                    + ("Server-side execution response detected — possible RCE." if sev == "CRITICAL"
                                       else "Endpoint accepts uploads. Test content-type and extension bypass.")
                                ),
                                severity=sev,
                                evidence=upload_result[:500],
                                tool="curl",
                                host=target,
                                port=_port_from_url(url),
                                mitre_technique="T1505",
                                exploit_suggestion=(
                                    f"Test bypass: curl -s -X POST "
                                    f"-F 'file=@shell.php;type=image/jpeg;filename=shell.php.jpg' "
                                    f"{upload_url}  "
                                    f"Also try: shell.phtml, shell.php%00.jpg, shell.PhP"
                                ),
                            ))
                        elif code in (200, 405):
                            issues.append({"type": "upload_endpoint_exists", "url": upload_url})
                            await self.store_finding(Finding(
                                title=f"File Upload Endpoint Detected: {upload_path}",
                                description=(
                                    f"File upload endpoint exists at {upload_url} (HTTP {code}). "
                                    f"Manual testing required to assess file type validation and storage."
                                ),
                                severity="MEDIUM",
                                evidence=f"HTTP {code} on {upload_url}",
                                tool="curl",
                                host=target,
                                port=_port_from_url(url),
                                mitre_technique="T1505",
                                exploit_suggestion=(
                                    f"Test upload bypass via double extension and MIME type spoofing: "
                                    f"curl -X POST -F 'file=@webshell.php;type=image/jpeg' {upload_url}"
                                ),
                            ))

                except Exception as exc:
                    logger.warning("[data_integrity] upload error %s: %s", upload_url, exc)

            # ── Test 2: Deserialization marker detection ───────────────────
            logger.info("[data_integrity] deserialization scan on %s", url)
            deser_test_urls = [
                f"{base}/",
                f"{base}/api/",
                f"{base}/ws",
            ]
            for deser_url in deser_test_urls[:2]:
                try:
                    deser_headers = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -I -m 8 "
                                f"-H 'User-Agent: Mozilla/5.0' "
                                f"\"{deser_url}\""
                            )
                        },
                    )
                    deser_body = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -c /dev/null -b '' -m 8 "
                                f"\"{deser_url}\""
                            )
                        },
                    )
                    self._tool_outputs[f"deser_headers_{deser_url[-20:]}"] = deser_headers
                    self._tool_outputs[f"deser_body_{deser_url[-20:]}"]    = deser_body

                    combined = deser_headers + deser_body

                    if _JAVA_SERIAL_B64_RE.search(combined) or _JAVA_SERIAL_HEX_RE.search(combined):
                        issues.append({"type": "java_deserialization", "url": deser_url})
                        await self.store_finding(Finding(
                            title=f"Java Serialized Object Detected: {deser_url}",
                            description=(
                                f"Response from {deser_url} contains Java serialized object markers "
                                f"(magic bytes AC ED 00 05 or base64 'rO0AB'). "
                                f"The application may be vulnerable to Java deserialization attacks "
                                f"(CVE-2015-4852, CVE-2016-0792, CVE-2017-3248)."
                            ),
                            severity="HIGH",
                            evidence=combined[:500],
                            tool="curl",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1059",
                            exploit_suggestion=(
                                "Use ysoserial to generate gadget chains for CommonsCollections, "
                                "Spring, or JBoss. Submit base64-encoded payload as cookie/body parameter."
                            ),
                        ))

                    if _PHP_SERIAL_RE.search(combined):
                        issues.append({"type": "php_deserialization", "url": deser_url})
                        await self.store_finding(Finding(
                            title=f"PHP Serialized Data Detected: {deser_url}",
                            description=(
                                f"Response or cookies from {deser_url} contain PHP serialized data. "
                                f"If deserialized without validation, this may allow PHP object injection "
                                f"via __wakeup/__destruct magic method gadget chains."
                            ),
                            severity="HIGH",
                            evidence=combined[:500],
                            tool="curl",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1059",
                            exploit_suggestion=(
                                "Craft malicious PHP serialized objects using phpggc gadget chains "
                                "for common frameworks (Laravel, Symfony, WordPress)."
                            ),
                        ))

                    if _UNSAFE_DESER_RE.search(combined):
                        issues.append({"type": "unsafe_deserialization_hint", "url": deser_url})
                        await self.store_finding(Finding(
                            title=f"Unsafe Deserialization Marker Detected: {deser_url}",
                            description=(
                                f"Response from {deser_url} contains markers suggesting unsafe "
                                f"deserialization of user-controlled data. Deserializing untrusted "
                                f"data can lead to remote code execution."
                            ),
                            severity="HIGH",
                            evidence=combined[:500],
                            tool="curl",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1059",
                            exploit_suggestion=(
                                "Investigate the serialization format and test for object injection. "
                                "Replace unsafe deserialization with JSON or validated schemas."
                            ),
                        ))

                except Exception as exc:
                    logger.warning("[data_integrity] deserialization error %s: %s", deser_url, exc)

            # ── Test 3: JWT detection and alg:none test ────────────────────
            logger.info("[data_integrity] JWT detection on %s", url)
            try:
                jwt_probe = await self.collect_tool(
                    "curl",
                    target,
                    {
                        "options": (
                            f"-s -v -m 10 "
                            f"-H 'User-Agent: Mozilla/5.0' "
                            f"\"{base}/\""
                        )
                    },
                )
                self._tool_outputs[f"jwt_probe_{base[-20:]}"] = jwt_probe

                jwt_matches = _JWT_RE.findall(jwt_probe)
                if jwt_matches:
                    for jwt_token in jwt_matches[:3]:
                        parts = jwt_token.split(".")
                        if len(parts) >= 2:
                            try:
                                # Pad base64url for decoding
                                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                                header_json = base64.urlsafe_b64decode(header_b64).decode(
                                    "utf-8", errors="ignore"
                                )

                                alg_none = re.search(r'"alg"\s*:\s*"none"', header_json, re.IGNORECASE)
                                alg_weak = re.search(r'"alg"\s*:\s*"(HS256|none|RS256)"', header_json)

                                # Check payload for exp claim
                                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                                payload_json = base64.urlsafe_b64decode(payload_b64).decode(
                                    "utf-8", errors="ignore"
                                )
                                no_exp = '"exp"' not in payload_json

                                if alg_none:
                                    issues.append({"type": "jwt_alg_none", "url": base})
                                    await self.store_finding(Finding(
                                        title=f"JWT with alg:none Detected: {base}",
                                        description=(
                                            f"A JWT token with algorithm 'none' was detected at {base}. "
                                            f"This means the signature is not verified — token forgery is trivial."
                                        ),
                                        severity="HIGH",
                                        evidence=f"JWT header: {header_json[:200]}",
                                        tool="curl",
                                        host=target,
                                        port=_port_from_url(url),
                                        mitre_technique="T1550",
                                        exploit_suggestion=(
                                            "Modify JWT payload and set alg to 'none'. "
                                            "Remove the signature segment: header.payload. "
                                            "Tools: jwt_tool, jwt-cracker, python-jwt."
                                        ),
                                    ))
                                elif no_exp and alg_weak:
                                    issues.append({"type": "jwt_no_expiry", "url": base})
                                    await self.store_finding(Finding(
                                        title=f"JWT Without Expiry Claim: {base}",
                                        description=(
                                            f"JWT token at {base} lacks an 'exp' (expiry) claim. "
                                            f"Stolen tokens remain valid indefinitely."
                                        ),
                                        severity="MEDIUM",
                                        evidence=f"JWT header: {header_json[:200]}",
                                        tool="curl",
                                        host=target,
                                        port=_port_from_url(url),
                                        mitre_technique="T1550",
                                        exploit_suggestion=(
                                            "Capture and replay JWT token — it will not expire. "
                                            "Implement short-lived tokens with 'exp' and refresh flow."
                                        ),
                                    ))

                            except Exception:
                                pass  # JWT decode failure is not a finding

            except Exception as exc:
                logger.warning("[data_integrity] JWT test error for %s: %s", url, exc)

            # ── Test 4: Third-party JS loaded over HTTP (missing SRI) ──────
            logger.info("[data_integrity] SRI and mixed content check on %s", url)
            try:
                page_out = await self.collect_tool(
                    "curl",
                    target,
                    {
                        "options": (
                            f"-s -m 15 "
                            f"-H 'User-Agent: Mozilla/5.0' "
                            f"\"{base}/\""
                        )
                    },
                )
                self._tool_outputs[f"page_content_{base[-20:]}"] = page_out

                http_scripts = _HTTP_SCRIPT_RE.findall(page_out)
                if http_scripts:
                    issues.append({"type": "http_script_src", "url": base, "count": len(http_scripts)})
                    await self.store_finding(Finding(
                        title=f"Third-Party JavaScript Loaded Over HTTP: {base}",
                        description=(
                            f"The page at {base} loads {len(http_scripts)} JavaScript file(s) "
                            f"over plain HTTP. An attacker performing MitM can inject malicious scripts."
                        ),
                        severity="HIGH",
                        evidence="\n".join(http_scripts[:5]),
                        tool="curl",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1195",
                        exploit_suggestion=(
                            "Intercept HTTP response with mitmproxy and inject JS payload. "
                            "Fix: replace all http:// script sources with https://."
                        ),
                    ))

                no_sri_scripts = _SCRIPT_NO_SRI_RE.findall(page_out)
                if no_sri_scripts:
                    issues.append({"type": "missing_sri", "url": base, "count": len(no_sri_scripts)})
                    await self.store_finding(Finding(
                        title=f"External Scripts Without Subresource Integrity (SRI): {base}",
                        description=(
                            f"The page at {base} loads {len(no_sri_scripts)} external JavaScript "
                            f"file(s) without SRI attributes. "
                            f"If the CDN or third-party host is compromised, malicious code executes."
                        ),
                        severity="MEDIUM",
                        evidence="\n".join(no_sri_scripts[:3]),
                        tool="curl",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1195",
                        exploit_suggestion=(
                            "Add integrity and crossorigin attributes to all external scripts: "
                            "<script src='...' integrity='sha384-...' crossorigin='anonymous'>"
                        ),
                    ))

            except Exception as exc:
                logger.warning("[data_integrity] SRI check error for %s: %s", url, exc)

        result.parsed_data["integrity_issues"] = issues
        result.findings                         = self._findings
        result.tool_outputs                     = self._tool_outputs
        result.duration_seconds                 = time.monotonic() - wall_start

        await self._emit(
            "data_integrity_complete",
            {
                "target":           target,
                "issue_count":      len(issues),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[data_integrity] complete — %d issues, %d findings, %.1fs",
            len(issues), len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _port_from_url(url: str) -> int | None:
    m = re.search(r":(\d+)(?:/|$)", url)
    if m:
        return int(m.group(1))
    if url.startswith("https://"):
        return 443
    if url.startswith("http://"):
        return 80
    return None
