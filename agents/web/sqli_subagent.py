"""
sqli_subagent.py — SQL injection detection via sqlmap.

Methodology:
  1. For each web_target URL: sqlmap -u URL --batch --level=3 --risk=2 --forms
  2. For each form in forms_list kwarg: sqlmap against form action+params
  3. Parse injectable parameters, database type, table names
  4. Severity:
       CRITICAL — SQLi found with DB dump capability (--dump feasible)
       HIGH     — Blind SQLi (time/boolean-based)
       MEDIUM   — Error-based SQLi (info disclosure but limited impact)
  5. Emit "sqli_complete" event
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# sqlmap output patterns
# ---------------------------------------------------------------------------
_INJECTABLE_RE   = re.compile(
    r"Parameter:\s+(.+?)\s+\((?:GET|POST|Cookie|URI|Header|User-Agent)\)",
    re.IGNORECASE,
)
_DB_TYPE_RE      = re.compile(r"back-end DBMS:\s+(.+)", re.IGNORECASE)
_DB_NAMES_RE     = re.compile(r"available databases.*?:\n((?:\[\*\]\s+\S+\n?)+)", re.DOTALL | re.IGNORECASE)
_TABLE_RE        = re.compile(r"Database:\s+(\S+).*?(\d+) tables?", re.IGNORECASE | re.DOTALL)
_DUMP_CAPABLE_RE = re.compile(r"sqlmap identified the following injection point|fetching tables|fetching columns|dumping", re.IGNORECASE)
_BLIND_TIME_RE   = re.compile(r"time-based blind|stacked queries", re.IGNORECASE)
_BLIND_BOOL_RE   = re.compile(r"boolean-based blind", re.IGNORECASE)
_ERROR_BASED_RE  = re.compile(r"error-based", re.IGNORECASE)
_UNION_BASED_RE  = re.compile(r"UNION query", re.IGNORECASE)
_NOT_VULN_RE     = re.compile(r"does not seem to be injectable|no parameter\(s\) found|not vulnerable", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class SqliSubagent(BaseSubagent):
    """
    SQL injection detection using sqlmap against web targets and discovered forms.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "sqli"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        forms_list:  list[dict] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Run sqlmap against all provided URLs and forms.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            List of URL dicts from web_fingerprint.
        forms_list:
            List of form dicts from crawl_subagent:
            [{"action": str, "method": str, "inputs": [{"name": str, "type": str}]}]

        Returns
        -------
        SubagentResult
            parsed_data["injections"] — list of injection result dicts
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"injections": []}
        wall_start = time.monotonic()

        urls: list[str] = []
        if web_targets:
            urls = [wt["url"] for wt in web_targets if isinstance(wt, dict) and "url" in wt]
        if not urls:
            urls = [f"http://{target}"]

        injections: list[dict] = []

        # ── Phase 1: URL-based sqlmap ──────────────────────────────────────
        for url in urls:
            logger.info("[sqli] sqlmap on %s", url)
            try:
                sm_out = await self.collect_tool(
                    "sqlmap",
                    target,
                    {
                        "options": (
                            f"-u \"{url}\" --batch --level=3 --risk=2 "
                            f"--forms --crawl=2 --threads=4 "
                            f"--output-dir=/tmp/sqlmap_output "
                            f"--timeout=30"
                        )
                    },
                )
                self._tool_outputs[f"sqlmap_{url}"] = sm_out

                if _NOT_VULN_RE.search(sm_out):
                    logger.info("[sqli] %s not injectable", url)
                    continue

                inj_result = _parse_sqlmap_output(sm_out, url)
                if inj_result["injectable"]:
                    injections.append(inj_result)
                    severity = _determine_severity(inj_result)
                    await self.store_finding(Finding(
                        title=f"SQL Injection: {inj_result.get('parameter', 'unknown param')} @ {url}",
                        description=_injection_description(inj_result, url),
                        severity=severity,
                        evidence=sm_out[:800],
                        tool="sqlmap",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1190",
                        exploit_suggestion=_sqli_exploit_hint(inj_result, url),
                    ))

            except Exception as exc:
                logger.warning("[sqli] sqlmap error for %s: %s", url, exc)

        # ── Phase 2: Form-based sqlmap ─────────────────────────────────────
        if forms_list:
            for form in forms_list[:20]:  # cap form count
                action  = form.get("action", "")
                method  = form.get("method", "POST").upper()
                inputs  = form.get("inputs", [])

                if not action:
                    continue

                form_url = action if action.startswith("http") else f"http://{target}{action}"
                data_parts = "&".join(
                    f"{inp.get('name', 'param')}=FUZZ"
                    for inp in inputs
                    if inp.get("type", "text") not in ("submit", "hidden", "button")
                )

                logger.info("[sqli] sqlmap form: %s [%s]", form_url, method)
                try:
                    flags = f"-u \"{form_url}\" --batch --level=3 --risk=2 --threads=4 --timeout=30"
                    if method == "POST" and data_parts:
                        flags += f" --data=\"{data_parts}\""
                    elif method == "GET":
                        flags += " --forms"

                    sm_out = await self.collect_tool(
                        "sqlmap",
                        target,
                        {"options": flags},
                    )
                    self._tool_outputs[f"sqlmap_form_{action[:40]}"] = sm_out

                    if _NOT_VULN_RE.search(sm_out):
                        continue

                    inj_result = _parse_sqlmap_output(sm_out, form_url)
                    if inj_result["injectable"]:
                        injections.append(inj_result)
                        severity = _determine_severity(inj_result)
                        await self.store_finding(Finding(
                            title=f"SQL Injection (Form): {inj_result.get('parameter', 'unknown')} @ {form_url}",
                            description=_injection_description(inj_result, form_url),
                            severity=severity,
                            evidence=sm_out[:800],
                            tool="sqlmap",
                            host=target,
                            port=_port_from_url(form_url),
                            mitre_technique="T1190",
                            exploit_suggestion=_sqli_exploit_hint(inj_result, form_url),
                        ))

                except Exception as exc:
                    logger.warning("[sqli] sqlmap form error for %s: %s", form_url, exc)

        result.parsed_data["injections"] = injections
        result.findings                  = self._findings
        result.tool_outputs              = self._tool_outputs
        result.duration_seconds          = time.monotonic() - wall_start

        await self._emit(
            "sqli_complete",
            {
                "target":           target,
                "injection_count":  len(injections),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[sqli] complete — %d injections, %d findings, %.1fs",
            len(injections), len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_sqlmap_output(output: str, url: str) -> dict:
    """Extract injection details from sqlmap output."""
    injectable = bool(
        _INJECTABLE_RE.search(output) or
        _DUMP_CAPABLE_RE.search(output) or
        _BLIND_TIME_RE.search(output) or
        _BLIND_BOOL_RE.search(output) or
        _ERROR_BASED_RE.search(output)
    )

    param_m  = _INJECTABLE_RE.search(output)
    db_m     = _DB_TYPE_RE.search(output)
    db_names = re.findall(r"\[\*\]\s+(\S+)", output)

    injection_types: list[str] = []
    if _UNION_BASED_RE.search(output):
        injection_types.append("UNION-based")
    if _ERROR_BASED_RE.search(output):
        injection_types.append("error-based")
    if _BLIND_BOOL_RE.search(output):
        injection_types.append("boolean-blind")
    if _BLIND_TIME_RE.search(output):
        injection_types.append("time-blind")

    return {
        "url":             url,
        "injectable":      injectable,
        "parameter":       param_m.group(1).strip() if param_m else "",
        "db_type":         db_m.group(1).strip() if db_m else "",
        "databases":       db_names,
        "injection_types": injection_types,
        "dump_capable":    bool(_DUMP_CAPABLE_RE.search(output)),
    }


def _determine_severity(inj: dict) -> str:
    if inj.get("dump_capable") or "UNION-based" in inj.get("injection_types", []):
        return "CRITICAL"
    if any(bt in inj.get("injection_types", []) for bt in ("boolean-blind", "time-blind")):
        return "HIGH"
    if "error-based" in inj.get("injection_types", []):
        return "MEDIUM"
    return "HIGH"


def _injection_description(inj: dict, url: str) -> str:
    db_type = inj.get("db_type", "unknown DB")
    param   = inj.get("parameter", "unknown parameter")
    types   = ", ".join(inj.get("injection_types", ["unknown"])) or "unknown"
    dbs     = ", ".join(inj.get("databases", [])[:5])

    return (
        f"SQL injection found in parameter '{param}' at {url}. "
        f"Backend DBMS: {db_type}. Injection types: {types}. "
        + (f"Accessible databases: {dbs}. " if dbs else "")
        + ("Full DB dump possible. " if inj.get("dump_capable") else "")
    )


def _sqli_exploit_hint(inj: dict, url: str) -> str:
    db_type = inj.get("db_type", "").lower()
    param   = inj.get("parameter", "param")
    base    = f"sqlmap -u \"{url}\" -p \"{param}\" --batch --level=5 --risk=3"

    if "mysql" in db_type or "maria" in db_type:
        return base + " --dump-all --dbs --os-shell"
    if "mssql" in db_type or "microsoft" in db_type:
        return base + " --dump-all --dbs --os-shell --technique=U"
    if "postgresql" in db_type:
        return base + " --dump-all --dbs"
    if "oracle" in db_type:
        return base + " --dump-all --dbs --technique=U"
    return base + " --dump-all --dbs"


def _port_from_url(url: str) -> int | None:
    m = re.search(r":(\d+)(?:/|$)", url)
    if m:
        return int(m.group(1))
    if url.startswith("https://"):
        return 443
    if url.startswith("http://"):
        return 80
    return None
