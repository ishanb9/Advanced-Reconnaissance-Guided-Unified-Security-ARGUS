"""
insecure_design_subagent.py — OWASP A06:2025 Insecure Design detection.

Methodology:
  1. Rate limiting test: rapidly send 20 login attempts and check if blocked
  2. Username enumeration: check if login returns different errors for valid vs invalid users
  3. Password reset flow: check if /forgot-password, /reset-password endpoints exist and leak info
  4. Verbose error messages: send malformed requests and check for stack traces/debug info
  5. Classify findings:
       HIGH     — no rate limiting on login, username enumeration confirmed
       MEDIUM   — verbose errors, reset endpoint info disclosure
       LOW      — missing security controls that suggest insecure design
  6. Emit "insecure_design_complete" with finding count
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

_STACK_TRACE_RE = re.compile(
    r"Traceback \(most recent|at \w+\.\w+\(.*\.java:\d+\)"
    r"|System\.Web\.HttpException|NullReferenceException"
    r"|Fatal error:.*on line \d+"
    r"|Warning:.*in .* on line \d+"
    r"|DebugKit|stacktrace|stack_trace"
    r"|Exception in thread|org\.springframework",
    re.IGNORECASE,
)

_DEBUG_INFO_RE = re.compile(
    r"DEBUG|DEVELOPMENT|<b>Fatal error</b>|<b>Warning</b>"
    r"|phpinfo\(\)|Server Software|X-Powered-By|X-Generator"
    r"|application_error|error_log|debug_mode",
    re.IGNORECASE,
)

_RESET_ENDPOINTS = [
    "/forgot-password",
    "/forgot_password",
    "/reset-password",
    "/reset_password",
    "/password-reset",
    "/password/reset",
    "/account/recover",
    "/recover",
    "/auth/reset",
]

_LOGIN_ENDPOINTS = [
    "/login",
    "/signin",
    "/auth/login",
    "/api/login",
    "/user/login",
    "/account/login",
]

_USER_ENUM_INDICATORS = [
    "user not found",
    "no account",
    "email not registered",
    "username does not exist",
    "invalid username",
    "account not found",
]

_RATE_LIMIT_INDICATORS = re.compile(
    r"too many|rate limit|throttl|blocked|locked|429|slow down|try again later",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------


class InsecureDesignSubagent(BaseSubagent):
    """
    Insecure design detection via rate limiting, enumeration, and error disclosure tests.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "insecure_design"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Test for insecure design patterns on all web targets.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            List of URL dicts from web_fingerprint parsed_data["web_targets"].

        Returns
        -------
        SubagentResult
            parsed_data["design_issues"] — list of detected issue dicts
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"design_issues": []}
        wall_start = time.monotonic()

        # RAG lookup for relevant techniques
        await self._kb_search(
            f"insecure design rate limiting account lockout security controls {target}", top_k=3
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

            # ── Test 1: Rate limiting on login endpoints ───────────────────
            logger.info("[insecure_design] rate limit test on %s", url)
            for login_path in _LOGIN_ENDPOINTS[:3]:
                login_url = f"{base}{login_path}"
                try:
                    # Send rapid burst of 20 POST requests with bogus credentials
                    # Use parallel curl with --parallel flag
                    rate_cmds = " ".join(
                        [f"\"{login_url}\""] * 20
                    )
                    rate_out = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -o /dev/null -w '%{{http_code}}\n' "
                                f"-X POST "
                                # NOTE: literal probe value. This first request
                                # previously interpolated the burst-loop counter,
                                # which is not defined until the loop below — the
                                # resulting NameError was silently swallowed and
                                # killed this whole rate-limit check.
                                f"-d 'username=admin&password=wrongpassword0' "
                                f"-m 5 \"{login_url}\""
                            )
                        },
                    )
                    self._tool_outputs[f"rate_limit_{login_path.replace('/', '_')}"] = rate_out

                    code_str = rate_out.strip()
                    if code_str.isdigit() and int(code_str) in (200, 401, 403):
                        # Endpoint exists — now test rapid-fire for rate limit
                        burst_results = []
                        for i in range(10):
                            try:
                                burst_out = await self.collect_tool(
                                    "curl",
                                    target,
                                    {
                                        "options": (
                                            f"-s -w '%{{http_code}}' "
                                            f"-X POST "
                                            f"-d 'username=testuser&password=wrongpwd{i}' "
                                            f"-m 3 \"{login_url}\""
                                        )
                                    },
                                )
                                burst_results.append(burst_out)
                            except Exception:
                                pass

                        full_burst = "\n".join(burst_results)
                        has_rate_limit = bool(_RATE_LIMIT_INDICATORS.search(full_burst))
                        status_codes = [
                            int(x) for x in re.findall(r"\b(\d{3})\b", full_burst)
                            if x.isdigit()
                        ]
                        has_429 = 429 in status_codes

                        if not has_rate_limit and not has_429 and len(burst_results) >= 5:
                            issues.append({
                                "type": "no_rate_limiting",
                                "url": login_url,
                            })
                            await self.store_finding(Finding(
                                title=f"No Rate Limiting on Login: {login_path}",
                                description=(
                                    f"The login endpoint {login_url} does not enforce rate limiting. "
                                    f"10 rapid authentication attempts completed without throttling or "
                                    f"lockout, enabling brute-force attacks."
                                ),
                                severity="HIGH",
                                evidence=f"10 rapid POST requests to {login_url} — no 429 or lockout detected",
                                tool="curl",
                                host=target,
                                port=_port_from_url(url),
                                mitre_technique="T1110",
                                exploit_suggestion=(
                                    f"hydra -l admin -P /usr/share/wordlists/rockyou.txt "
                                    f"{target} http-post-form '{login_path}:username=^USER^&password=^PASS^:F=invalid'"
                                ),
                            ))
                            break  # one finding per URL

                except Exception as exc:
                    logger.warning("[insecure_design] rate limit test error %s: %s", login_url, exc)

            # ── Test 2: Username enumeration ───────────────────────────────
            logger.info("[insecure_design] username enumeration on %s", url)
            for login_path in _LOGIN_ENDPOINTS[:3]:
                login_url = f"{base}{login_path}"
                try:
                    # Test with likely-valid username vs definitely-invalid one
                    resp_valid = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -m 8 "
                                f"-X POST "
                                f"-d 'username=admin&password=wrongpassword_xyz_123' "
                                f"\"{login_url}\""
                            )
                        },
                    )
                    resp_invalid = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -m 8 "
                                f"-X POST "
                                f"-d 'username=zz_nonexistent_user_abc&password=wrongpassword_xyz_123' "
                                f"\"{login_url}\""
                            )
                        },
                    )
                    self._tool_outputs[f"enum_valid_{login_path.replace('/', '_')}"] = resp_valid
                    self._tool_outputs[f"enum_invalid_{login_path.replace('/', '_')}"] = resp_invalid

                    # Check if responses are meaningfully different
                    for indicator in _USER_ENUM_INDICATORS:
                        if indicator.lower() in resp_invalid.lower() and indicator.lower() not in resp_valid.lower():
                            issues.append({
                                "type": "username_enumeration",
                                "url": login_url,
                                "indicator": indicator,
                            })
                            await self.store_finding(Finding(
                                title=f"Username Enumeration: {login_path}",
                                description=(
                                    f"The login endpoint {login_url} returns different error messages "
                                    f"for valid vs invalid usernames. "
                                    f"Indicator found: '{indicator}'. "
                                    f"Attackers can enumerate valid accounts."
                                ),
                                severity="HIGH",
                                evidence=(
                                    f"Valid user response snippet: {resp_valid[:200]}\n"
                                    f"Invalid user response snippet: {resp_invalid[:200]}"
                                ),
                                tool="curl",
                                host=target,
                                port=_port_from_url(url),
                                mitre_technique="T1589",
                                exploit_suggestion=(
                                    f"ffuf -w /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt "
                                    f"-u {login_url} -X POST "
                                    f"-d 'username=FUZZ&password=wrong' -fr '{indicator}'"
                                ),
                            ))
                            break

                except Exception as exc:
                    logger.warning("[insecure_design] enum test error %s: %s", login_url, exc)

            # ── Test 3: Password reset endpoint info disclosure ────────────
            logger.info("[insecure_design] password reset probe on %s", url)
            for reset_path in _RESET_ENDPOINTS:
                reset_url = f"{base}{reset_path}"
                try:
                    reset_out = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -o /dev/null -w '%{{http_code}}' "
                                f"-m 5 \"{reset_url}\""
                            )
                        },
                    )
                    self._tool_outputs[f"reset_{reset_path.replace('/', '_')}"] = reset_out

                    code_str = reset_out.strip()
                    if code_str.isdigit() and int(code_str) in (200, 301, 302):
                        # Endpoint exists — check for info disclosure on POST
                        reset_post = await self.collect_tool(
                            "curl",
                            target,
                            {
                                "options": (
                                    f"-s -m 8 "
                                    f"-X POST "
                                    f"-d 'email=nonexistent_user_xyz@example.com' "
                                    f"\"{reset_url}\""
                                )
                            },
                        )
                        self._tool_outputs[f"reset_post_{reset_path.replace('/', '_')}"] = reset_post

                        for indicator in _USER_ENUM_INDICATORS:
                            if indicator.lower() in reset_post.lower():
                                issues.append({
                                    "type": "reset_info_disclosure",
                                    "url": reset_url,
                                    "indicator": indicator,
                                })
                                await self.store_finding(Finding(
                                    title=f"Password Reset Info Disclosure: {reset_path}",
                                    description=(
                                        f"The password reset endpoint {reset_url} reveals account existence. "
                                        f"Response indicates: '{indicator}' for unknown accounts, "
                                        f"allowing attacker to enumerate registered users."
                                    ),
                                    severity="MEDIUM",
                                    evidence=reset_post[:400],
                                    tool="curl",
                                    host=target,
                                    port=_port_from_url(url),
                                    mitre_technique="T1589",
                                    exploit_suggestion=(
                                        f"Enumerate emails: ffuf -w emails.txt -u {reset_url} "
                                        f"-X POST -d 'email=FUZZ' -fr 'not found'"
                                    ),
                                ))
                                break

                except Exception as exc:
                    logger.warning("[insecure_design] reset probe error %s: %s", reset_url, exc)

            # ── Test 4: Verbose error messages / debug info ────────────────
            logger.info("[insecure_design] verbose error check on %s", url)
            error_payloads = [
                f"{base}/nonexistent_path_xyz_abc_123",
                f"{base}/?id=1'",
                f"{base}/?debug=1",
                f"{base}/?test=<script>",
            ]
            for err_url in error_payloads[:3]:
                try:
                    err_out = await self.collect_tool(
                        "curl",
                        target,
                        {
                            "options": (
                                f"-s -m 8 "
                                f"-H 'User-Agent: Mozilla/5.0' "
                                f"\"{err_url}\""
                            )
                        },
                    )
                    self._tool_outputs[f"error_{err_url[-20:].replace('/', '_')}"] = err_out

                    if _STACK_TRACE_RE.search(err_out):
                        issues.append({"type": "stack_trace_disclosure", "url": err_url})
                        await self.store_finding(Finding(
                            title=f"Stack Trace / Debug Info Disclosure: {err_url}",
                            description=(
                                f"The application at {err_url} returns stack traces or verbose "
                                f"debug information in error responses. This reveals internal "
                                f"file paths, technology stack, and code structure to attackers."
                            ),
                            severity="MEDIUM",
                            evidence=err_out[:600],
                            tool="curl",
                            host=target,
                            port=_port_from_url(url),
                            mitre_technique="T1082",
                            exploit_suggestion=(
                                "Disable debug mode in production. Set DEBUG=False. "
                                "Configure custom error pages. Review error_reporting settings."
                            ),
                        ))
                        break  # one finding per URL

                except Exception as exc:
                    logger.warning("[insecure_design] error check error %s: %s", err_url, exc)

        result.parsed_data["design_issues"] = issues
        result.findings                      = self._findings
        result.tool_outputs                  = self._tool_outputs
        result.duration_seconds              = time.monotonic() - wall_start

        await self._emit(
            "insecure_design_complete",
            {
                "target":           target,
                "issue_count":      len(issues),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[insecure_design] complete — %d issues, %d findings, %.1fs",
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
