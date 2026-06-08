"""
owasp2025_native_probes.py — dependency-free OWASP Top 10:2025 web probes.

Why this module exists
----------------------
Two structural gaps in ARGUS's web pipeline (found in the OWASP-2025 coverage
audit):

  1. **"Documented but not implemented" phases.**  The WSTG orchestrator SENT
     probes (a CORS pre-flight, a cookie request, error payloads) but never
     PARSED the responses, so CORS / CSRF / cookie-flag / verbose-error
     detection were effectively absent despite the phase comments claiming them.

  2. **Single-tool fragility.**  SSTI relied on `tplmap`, NoSQLi on `nosqlmap`,
     XSS on `dalfox` — abandoned / frequently-missing binaries.  When the binary
     was absent the whole vector silently produced nothing, with no fallback.

This module fixes both: it performs **native, tool-independent** detection using
only `curl`, and all detection logic lives in **pure functions** that are unit-
testable offline (no live target, no base-agent infra).  It is additive — it
complements (does not replace) sqlmap/dalfox/commix where those run.

Coverage (detection / first-pass oracle):
  • A01 — CORS misconfiguration (reflected origin, null origin, `*`+credentials)
  • A01 — CSRF (state-changing form without anti-CSRF token / weak SameSite)
  • A05 — SSTI polyglot (`{{1337*1337}}`, `${...}`, `#{...}`, `<%= ... %>`)
  • A05 — CRLF / HTTP response-header injection (`%0d%0a`)
  • A05 — LDAP / XPath injection (error-based)
  • A05 / A02 / A10 — verbose error / stack-trace / SQL-error disclosure
  • A04 — cookie security flags (Secure / HttpOnly / SameSite)
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Optional, Awaitable

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ── Distinctive SSTI sentinel.  1337*1337 = 1787569; wrapped in a unique
#    marker so a literal echo of the payload is NOT mistaken for evaluation. ──
SSTI_SENTINEL: str = "qXq"
SSTI_PRODUCT:  str = "1787569"
SSTI_EVALUATED: str = f"{SSTI_SENTINEL}{SSTI_PRODUCT}{SSTI_SENTINEL}"
SSTI_PAYLOADS = (
    f"{SSTI_SENTINEL}{{{{1337*1337}}}}{SSTI_SENTINEL}",   # Jinja2 / Twig / Nunjucks
    f"{SSTI_SENTINEL}${{1337*1337}}{SSTI_SENTINEL}",       # FreeMarker / JSP-EL / Thymeleaf
    f"{SSTI_SENTINEL}#{{1337*1337}}{SSTI_SENTINEL}",       # Ruby (Slim/ERB) / Thymeleaf
    f"{SSTI_SENTINEL}<%= 1337*1337 %>{SSTI_SENTINEL}",     # ERB / EJS
)

CRLF_MARKER_HEADER: str = "x-argus-crlf"
CRLF_MARKER_VALUE:  str = "injected"

# ── Detection patterns ──────────────────────────────────────────────────────
_STACK_TRACE_PATTERNS = [
    ("php",    re.compile(r"<b>\s*(Fatal error|Warning|Notice|Parse error)\s*</b>|"
                          r"\bon line \d+|Stack trace:|Call Stack", re.I)),
    ("java",   re.compile(r"\bjava\.[a-z]+\.[A-Za-z.]+Exception|\bat (com|org|java)\."
                          r"[\w.$]+\([\w.]+:\d+\)|Exception in thread", re.I)),
    ("spring", re.compile(r"org\.springframework\.[\w.]+|Whitelabel Error Page", re.I)),
    ("dotnet", re.compile(r"\bSystem\.[A-Za-z.]+Exception|at System\.[\w.]+|"
                          r"\[\w*Exception:|Microsoft\.[\w.]+", re.I)),
    ("python", re.compile(r"Traceback \(most recent call last\)|"
                          r'File ".+?", line \d+|Werkzeug Debugger', re.I)),
    ("node",   re.compile(r"\bat Object\.<anonymous>|/node_modules/|"
                          r"\b(ReferenceError|TypeError|SyntaxError):.+\n\s+at ", re.I)),
    ("ruby",   re.compile(r"\.rb:\d+:in `|ActionController::|RAILS_ENV", re.I)),
    ("go",     re.compile(r"goroutine \d+ \[|panic: .+\n\n", re.I)),
]

_SQL_ERROR_PATTERNS = [
    ("mysql",      re.compile(r"You have an error in your SQL syntax|"
                              r"\bMySQL server version|\bmysql_fetch|"
                              r"\bWarning.*\bmysqli?_", re.I)),
    ("postgres",   re.compile(r"PostgreSQL.*ERROR|\bpg_query\(\)|"
                              r"unterminated quoted string", re.I)),
    ("mssql",      re.compile(r"Microsoft OLE DB Provider|ODBC SQL Server Driver|"
                              r"Unclosed quotation mark after the character", re.I)),
    ("oracle",     re.compile(r"\bORA-\d{5}|Oracle error|quoted string not properly terminated", re.I)),
    ("sqlite",     re.compile(r"SQLite3?::|SQLite/JDBCDriver|unrecognized token", re.I)),
]

_LDAP_ERROR_PATTERNS = re.compile(
    r"Invalid DN syntax|javax\.naming\.directory|LDAP:\s*error|"
    r"com\.sun\.jndi\.ldap|Bad search filter|supplied argument is not a valid ldap",
    re.I,
)
_XPATH_ERROR_PATTERNS = re.compile(
    r"XPathException|xmlXPathEval|Invalid (expression|predicate)|"
    r"SimpleXMLElement|Unfinished qualified name|MS\.Internal\.Xml",
    re.I,
)


# ── Pure detection functions (unit-testable, no I/O) ─────────────────────────

def analyze_cors(origin_sent: str, headers_text: str) -> Optional[dict]:
    """Inspect a CORS pre-flight/response.  Returns a finding dict or None.

    Vulnerable when the server REFLECTS an arbitrary origin (optionally with
    credentials), echoes a ``null`` origin, or pairs ``*`` with credentials.
    """
    h = headers_text or ""
    m = re.search(r"access-control-allow-origin:\s*([^\r\n]+)", h, re.I)
    if not m:
        return None
    acao = m.group(1).strip()
    acac = bool(re.search(r"access-control-allow-credentials:\s*true", h, re.I))
    origin = (origin_sent or "").strip()

    if origin and acao == origin:
        if acac:
            return {"severity": "CRITICAL", "acao": acao, "credentials": True,
                    "detail": "Server reflects an arbitrary Origin AND allows credentials — "
                              "cross-origin theft of authenticated data."}
        return {"severity": "HIGH", "acao": acao, "credentials": False,
                "detail": "Server reflects an arbitrary Origin in Access-Control-Allow-Origin."}
    if acao.lower() == "null":
        return {"severity": "HIGH", "acao": acao, "credentials": acac,
                "detail": "Server trusts the 'null' Origin (exploitable via sandboxed iframe)."}
    if acao == "*" and acac:
        return {"severity": "MEDIUM", "acao": acao, "credentials": True,
                "detail": "Wildcard ACAO combined with Allow-Credentials (misconfiguration)."}
    return None


def ssti_evaluated(body: str) -> bool:
    """True when the SSTI sentinel was evaluated server-side (1337*1337=1787569)."""
    return SSTI_EVALUATED in (body or "")


def detect_crlf(headers_text: str) -> bool:
    """True when our injected CRLF header is reflected into the response headers."""
    h = (headers_text or "").lower()
    return bool(re.search(rf"{CRLF_MARKER_HEADER}:\s*{CRLF_MARKER_VALUE}", h))


def detect_stack_trace(body: str) -> Optional[str]:
    """Return the language/framework whose stack trace / debug page leaked, or None."""
    b = body or ""
    for name, pat in _STACK_TRACE_PATTERNS:
        if pat.search(b):
            return name
    return None


def detect_sql_error(body: str) -> Optional[str]:
    """Return the DBMS whose error leaked (error-based SQLi oracle), or None."""
    b = body or ""
    for name, pat in _SQL_ERROR_PATTERNS:
        if pat.search(b):
            return name
    return None


def detect_ldap_error(body: str) -> bool:
    return bool(_LDAP_ERROR_PATTERNS.search(body or ""))


def detect_xpath_error(body: str) -> bool:
    return bool(_XPATH_ERROR_PATTERNS.search(body or ""))


def analyze_cookies(set_cookie_lines: list[str], is_https: bool) -> list[dict]:
    """Per-cookie Secure / HttpOnly / SameSite assessment.  Returns missing-flag findings."""
    out: list[dict] = []
    for line in (set_cookie_lines or []):
        ln = (line or "").strip()
        if not ln:
            continue
        low = ln.lower()
        name = ln.split("=", 1)[0].strip()
        if not name:
            continue
        session_like = any(k in name.lower() for k in
                            ("sess", "sid", "auth", "token", "jwt", "login", "csrf"))
        missing: list[str] = []
        if is_https and "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        elif re.search(r"samesite\s*=\s*none", low) and "secure" not in low:
            missing.append("SameSite=None-without-Secure")
        if missing:
            sev = "MEDIUM" if (session_like and ("HttpOnly" in missing or
                                                 any("SameSite" in m for m in missing))) else "LOW"
            out.append({"cookie": name, "missing": missing, "severity": sev,
                        "session_like": session_like})
    return out


def analyze_csrf(body: str, set_cookie_lines: list[str]) -> Optional[dict]:
    """Detect a state-changing form lacking an anti-CSRF token.  Returns finding or None."""
    b = body or ""
    # Find <form ... method=post ...> blocks (case-insensitive, attrs in any order)
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", b, re.I | re.S)
    open_tags = re.findall(r"<form\b[^>]*>", b, re.I)
    has_post = any(re.search(r"method\s*=\s*['\"]?post", t, re.I) for t in open_tags)
    if not has_post:
        return None
    token_re = re.compile(r"name\s*=\s*['\"]?[^'\">]*"
                          r"(csrf|xsrf|_token|authenticity_token|nonce|__requestverification)",
                          re.I)
    for inner, tag in zip(forms or [""] * len(open_tags), open_tags):
        if not re.search(r"method\s*=\s*['\"]?post", tag, re.I):
            continue
        if not token_re.search(inner) and not token_re.search(tag):
            # SameSite on session cookies partially mitigates CSRF
            samesite_strict = any(re.search(r"samesite\s*=\s*(strict|lax)", (c or "").lower())
                                  for c in (set_cookie_lines or []))
            return {"severity": "LOW" if samesite_strict else "MEDIUM",
                    "detail": "POST form without an anti-CSRF token field"
                              + ("" if samesite_strict else " (and no SameSite cookie protection)")}
    return None


def split_headers_body(raw: str) -> tuple[str, str]:
    """Split a `curl -i` response into (headers, body)."""
    raw = raw or ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw:
            head, _, body = raw.partition(sep)
            return head, body
    return raw, ""


def parse_set_cookies(headers_text: str) -> list[str]:
    """Extract Set-Cookie values from a header blob."""
    return re.findall(r"^\s*set-cookie:\s*([^\r\n]+)", headers_text or "", re.I | re.M)


# ── Subagent ─────────────────────────────────────────────────────────────────

class OWASP2025NativeProbesSubagent(BaseSubagent):
    """Native, dependency-free OWASP-2025 web probes (curl-only)."""

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "owasp2025_native_probes"

    async def run(
        self,
        target: str,
        url: Optional[str] = None,
        web_targets: Optional[list] = None,
        tool_runner: Optional[Callable[[str, str, dict], Awaitable[str]]] = None,
        **kwargs: Any,
    ) -> SubagentResult:
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data = {"native_probe_findings": []}
        t0 = time.monotonic()

        # Resolve the base URL list — honour the single `url=` the orchestrator
        # passes (works around the generic url-plumbing gap), then web_targets,
        # then a sane default.
        urls: list[str] = []
        if url:
            urls = [url]
        elif web_targets:
            urls = [wt.get("url") for wt in web_targets
                    if isinstance(wt, dict) and wt.get("url")]
        if not urls:
            urls = [f"http://{target}"]

        run_tool = tool_runner or (lambda tool, tgt, opts: self.collect_tool(tool, tgt, opts))

        for raw_url in urls[:2]:
            base = (raw_url or "").rstrip("/")
            if not base:
                continue
            is_https = base.startswith("https://")
            findings = result.parsed_data["native_probe_findings"]

            # ── A01: CORS reflection ──
            try:
                out = await run_tool("curl", target, {"options":
                    f"-s -k -D - -o /dev/null -m 8 -H 'Origin: https://argus-evil.test' '{base}/'"})
                cors = analyze_cors("https://argus-evil.test", out)
                if cors:
                    findings.append({"vector": "cors", **cors})
                    await self.store_finding(Finding(
                        title=f"CORS Misconfiguration ({cors['severity']}): {base}",
                        description=cors["detail"],
                        severity=cors["severity"], tool="curl", host=target,
                        mitre_technique="T1190",
                        exploit_suggestion="Host a cross-origin fetch() from a malicious page with "
                                           "credentials:'include' to read authenticated responses.",
                    ))
            except Exception as exc:
                logger.debug("[native_probes] cors error: %s", exc)

            # ── A05: CRLF / header injection ──
            try:
                out = await run_tool("curl", target, {"options":
                    f"-s -k -D - -o /dev/null -m 8 "
                    f"'{base}/?x=1%0d%0a{CRLF_MARKER_HEADER}:{CRLF_MARKER_VALUE}'"})
                if detect_crlf(out):
                    findings.append({"vector": "crlf", "severity": "HIGH"})
                    await self.store_finding(Finding(
                        title=f"CRLF / HTTP Response-Header Injection: {base}",
                        description="A CRLF-encoded payload was reflected into the response headers, "
                                    "enabling header injection / response splitting / cache poisoning.",
                        severity="HIGH", tool="curl", host=target, mitre_technique="T1190",
                        exploit_suggestion="Inject Set-Cookie / Location headers or split the response "
                                           "to poison caches.",
                    ))
            except Exception as exc:
                logger.debug("[native_probes] crlf error: %s", exc)

            # ── A05 / A02 / A10: verbose errors, SQL/LDAP/XPath error oracles ──
            try:
                out = await run_tool("curl", target, {"options":
                    f"-s -k -m 8 \"{base}/?id=1%27%22%5C%29%28&q=%2A%29%28uid%3D%2A&debug=1\""})
                lang = detect_stack_trace(out)
                if lang:
                    findings.append({"vector": "verbose_error", "lang": lang, "severity": "MEDIUM"})
                    await self.store_finding(Finding(
                        title=f"Verbose Error / Stack-Trace Disclosure ({lang}): {base}",
                        description=f"A malformed request elicited a {lang} stack trace / debug page, "
                                    "leaking framework, versions and code paths (CWE-209/550).",
                        severity="MEDIUM", tool="curl", host=target, mitre_technique="T1592",
                    ))
                dbms = detect_sql_error(out)
                if dbms:
                    findings.append({"vector": "sql_error", "dbms": dbms, "severity": "HIGH"})
                    await self.store_finding(Finding(
                        title=f"Error-based SQL Injection oracle ({dbms}): {base}",
                        description=f"A single-quote payload triggered a {dbms} SQL error — strong "
                                    "indicator of SQL injection. Confirm/dump with sqlmap.",
                        severity="HIGH", tool="curl", host=target, mitre_technique="T1190",
                        exploit_suggestion=f"sqlmap -u '{base}/?id=1' --batch --dbs",
                    ))
                if detect_ldap_error(out):
                    findings.append({"vector": "ldap_injection", "severity": "HIGH"})
                    await self.store_finding(Finding(
                        title=f"LDAP Injection oracle: {base}",
                        description="An LDAP filter metacharacter payload triggered an LDAP error.",
                        severity="HIGH", tool="curl", host=target, mitre_technique="T1190"))
                if detect_xpath_error(out):
                    findings.append({"vector": "xpath_injection", "severity": "HIGH"})
                    await self.store_finding(Finding(
                        title=f"XPath Injection oracle: {base}",
                        description="An XPath metacharacter payload triggered an XPath error.",
                        severity="HIGH", tool="curl", host=target, mitre_technique="T1190"))
            except Exception as exc:
                logger.debug("[native_probes] error-oracle error: %s", exc)

            # ── A05: SSTI polyglot ──
            try:
                opts = "-s -k -G -m 8 "
                for i, pl in enumerate(SSTI_PAYLOADS):
                    opts += f"--data-urlencode 'q{i}={pl}' "
                opts += f"'{base}/'"
                out = await run_tool("curl", target, {"options": opts})
                if ssti_evaluated(out):
                    findings.append({"vector": "ssti", "severity": "CRITICAL"})
                    await self.store_finding(Finding(
                        title=f"Server-Side Template Injection (RCE-capable): {base}",
                        description="A template expression (1337*1337) was evaluated server-side "
                                    f"(found '{SSTI_EVALUATED}') — SSTI, frequently escalates to RCE.",
                        severity="CRITICAL", tool="curl", host=target, mitre_technique="T1190",
                        exploit_suggestion="Confirm engine, then escalate to RCE "
                                           "(sstimap, or engine-specific payloads).",
                    ))
            except Exception as exc:
                logger.debug("[native_probes] ssti error: %s", exc)

            # ── A04 + A01: cookie flags + CSRF (single -i fetch) ──
            try:
                out = await run_tool("curl", target, {"options": f"-s -k -i -m 8 '{base}/'"})
                headers, body = split_headers_body(out)
                cookies = parse_set_cookies(headers)
                for c in analyze_cookies(cookies, is_https):
                    findings.append({"vector": "cookie_flags", **c})
                    await self.store_finding(Finding(
                        title=f"Insecure Cookie '{c['cookie']}' (missing {', '.join(c['missing'])}): {base}",
                        description=f"Cookie '{c['cookie']}' is missing: {', '.join(c['missing'])} "
                                    "(A04 — session/credential exposure).",
                        severity=c["severity"], tool="curl", host=target))
                csrf = analyze_csrf(body, cookies)
                if csrf:
                    findings.append({"vector": "csrf", **csrf})
                    await self.store_finding(Finding(
                        title=f"Potential CSRF ({csrf['severity']}): {base}",
                        description=csrf["detail"], severity=csrf["severity"],
                        tool="curl", host=target, mitre_technique="T1190"))
            except Exception as exc:
                logger.debug("[native_probes] cookie/csrf error: %s", exc)

        try:
            await self._emit("owasp2025_native_probes_complete", {
                "target": target,
                "findings": len(result.parsed_data["native_probe_findings"]),
                "elapsed_sec": round(time.monotonic() - t0, 1),
            })
        except Exception:
            pass
        return result
