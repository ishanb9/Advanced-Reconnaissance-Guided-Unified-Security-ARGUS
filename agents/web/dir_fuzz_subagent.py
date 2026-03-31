"""
dir_fuzz_subagent.py — Directory and file fuzzing via gobuster and feroxbuster.

Methodology:
  1. gobuster dir — fast wordlist-based directory discovery per web target
  2. feroxbuster  — recursive fuzzing on discovered interesting directories
  3. Parse status codes: 200 (accessible), 301/302 (redirect), 403 (forbidden)
  4. Classify findings:
       HIGH     — admin panels, backup/config files found
       MEDIUM   — hidden directories, 403-protected interesting paths
       INFO     — general discovered paths
  5. Emit "dir_fuzz_complete" with full path list
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wordlists (Kali standard paths)
# ---------------------------------------------------------------------------
_WORDLIST_DIR   = "/usr/share/wordlists/dirb/common.txt"
_WORDLIST_LARGE = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

# ---------------------------------------------------------------------------
# Admin panel patterns
# ---------------------------------------------------------------------------
_ADMIN_PATH_RE = re.compile(
    r"/(admin|administrator|wp-admin|wp-login|dashboard|manager|console|"
    r"cpanel|phpmyadmin|webadmin|controlpanel|backend|cms|portal|panel|"
    r"manage|management|moderator|superuser|sysadmin)(/|$|\?)",
    re.IGNORECASE,
)

# Backup / config file patterns
_BACKUP_FILE_RE = re.compile(
    r"\.(bak|backup|old|orig|save|swp|tmp|temp|sql|dump|tar|gz|zip|rar|7z|"
    r"config|conf|cfg|env|ini|log|db|sqlite|mdb|key|pem|crt|csr|p12|pfx)$",
    re.IGNORECASE,
)

# Interesting but non-admin paths (MEDIUM)
_INTERESTING_PATH_RE = re.compile(
    r"/(upload|uploads|files|file|backup|backups|data|db|database|config|"
    r"conf|settings|setup|install|test|dev|staging|api|v1|v2|internal|"
    r"private|secret|hidden|old|archive|tmp|temp|cache|logs?|debug)(/|$|\?)",
    re.IGNORECASE,
)

# gobuster / feroxbuster output line
_GOBUSTER_RE = re.compile(
    r"((?:/[^\s]+))\s+\(Status:\s*(\d+)\)",
    re.IGNORECASE,
)
_FEROX_RE = re.compile(
    r"(\d{3})\s+\w+\s+\w+\s+(https?://[^\s]+)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class DirFuzzSubagent(BaseSubagent):
    """
    Directory and file brute-forcing with gobuster + feroxbuster.

    Iterates over all web_targets, runs gobuster with a common wordlist,
    then recurses with feroxbuster on admin/interesting directories found.
    """

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "dir_fuzz"

    async def run(  # noqa: C901
        self,
        target: str,
        web_targets: list[dict] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Fuzz directories on all web targets.

        Parameters
        ----------
        target:
            Base host/IP.
        web_targets:
            List of URL dicts (from web_fingerprint parsed_data["web_targets"]).
            Falls back to http/https on target:80/443 if not provided.

        Returns
        -------
        SubagentResult
            parsed_data["paths"] — list of {url, path, status, interesting, admin}
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"paths": []}
        wall_start = time.monotonic()

        # Build URL list
        urls: list[str] = []
        if web_targets:
            urls = [wt["url"] for wt in web_targets if isinstance(wt, dict) and "url" in wt]
        if not urls:
            urls = [f"http://{target}", f"https://{target}"]

        logger.info("[dir_fuzz] fuzzing %d URLs on %s", len(urls), target)

        all_paths: list[dict] = []

        for url in urls:
            # ── gobuster dir ──────────────────────────────────────────────
            logger.info("[dir_fuzz] gobuster on %s", url)
            interesting_dirs: list[str] = []
            try:
                gb_out = await self.collect_tool(
                    "gobuster",
                    target,
                    {
                        "options": (
                            f"dir -u {url} -w {_WORDLIST_DIR} "
                            f"-t 40 -q --no-error -x php,html,txt,bak,sql,zip,conf,cfg,env "
                            f"--timeout 10s"
                        )
                    },
                )
                self._tool_outputs[f"gobuster_{url}"] = gb_out
                gb_paths = _parse_gobuster(gb_out, url)

                for entry in gb_paths:
                    entry["source"] = "gobuster"
                    all_paths.append(entry)
                    if entry["admin"]:
                        interesting_dirs.append(entry["full_url"])
                    elif entry["interesting"]:
                        interesting_dirs.append(entry["full_url"])

            except Exception as exc:
                logger.warning("[dir_fuzz] gobuster error for %s: %s", url, exc)

            # ── feroxbuster recursive on interesting dirs ──────────────────
            if interesting_dirs:
                logger.info(
                    "[dir_fuzz] feroxbuster recursive on %d interesting dirs",
                    len(interesting_dirs)
                )
                for idir in interesting_dirs[:5]:  # cap recursion targets
                    try:
                        ferox_out = await self.collect_tool(
                            "feroxbuster",
                            target,
                            {
                                "options": (
                                    f"--url {idir} -w {_WORDLIST_DIR} "
                                    f"--depth 3 --threads 30 --quiet "
                                    f"--extensions php,html,txt,bak,sql,json,conf "
                                    f"--timeout 10"
                                )
                            },
                        )
                        self._tool_outputs[f"feroxbuster_{idir}"] = ferox_out
                        ferox_paths = _parse_feroxbuster(ferox_out)
                        for entry in ferox_paths:
                            entry["source"] = "feroxbuster"
                            all_paths.append(entry)
                    except Exception as exc:
                        logger.warning("[dir_fuzz] feroxbuster error for %s: %s", idir, exc)

        # ── Emit findings ─────────────────────────────────────────────────
        for entry in all_paths:
            severity = _classify_path_severity(entry)
            if severity == "INFO" and entry.get("status") not in (200, 301, 302, 403):
                continue  # skip uninteresting non-hits

            await self.store_finding(Finding(
                title=_path_finding_title(entry),
                description=_path_finding_description(entry),
                severity=severity,
                evidence=f"URL: {entry.get('full_url', '')} | Status: {entry.get('status', '?')}",
                tool=entry.get("source", "gobuster"),
                host=target,
                port=_port_from_url(entry.get("full_url", "")),
                mitre_technique="T1083" if not entry.get("admin") else "T1078",
                exploit_suggestion=_path_exploit_hint(entry),
            ))

        result.parsed_data["paths"] = all_paths
        result.findings             = self._findings
        result.tool_outputs         = self._tool_outputs
        result.duration_seconds     = time.monotonic() - wall_start

        await self._emit(
            "dir_fuzz_complete",
            {
                "target":           target,
                "path_count":       len(all_paths),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[dir_fuzz] complete — %d paths, %d findings, %.1fs",
            len(all_paths), len(self._findings), result.duration_seconds,
        )
        return result


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_gobuster(output: str, base_url: str) -> list[dict]:
    """Parse gobuster dir output lines into path dicts."""
    paths: list[dict] = []
    for line in output.splitlines():
        m = _GOBUSTER_RE.search(line)
        if m:
            path = m.group(1)
            status = int(m.group(2))
            full_url = base_url.rstrip("/") + path
            paths.append({
                "path":     path,
                "full_url": full_url,
                "status":   status,
                "admin":    bool(_ADMIN_PATH_RE.search(path)),
                "backup":   bool(_BACKUP_FILE_RE.search(path)),
                "interesting": bool(_INTERESTING_PATH_RE.search(path)),
            })
    return paths


def _parse_feroxbuster(output: str) -> list[dict]:
    """Parse feroxbuster output lines into path dicts."""
    paths: list[dict] = []
    for line in output.splitlines():
        m = _FEROX_RE.search(line)
        if m:
            status   = int(m.group(1))
            full_url = m.group(2).strip()
            path_m   = re.search(r"https?://[^/]+(/.+)", full_url)
            path     = path_m.group(1) if path_m else full_url
            paths.append({
                "path":     path,
                "full_url": full_url,
                "status":   status,
                "admin":    bool(_ADMIN_PATH_RE.search(path)),
                "backup":   bool(_BACKUP_FILE_RE.search(path)),
                "interesting": bool(_INTERESTING_PATH_RE.search(path)),
            })
    return paths


# ---------------------------------------------------------------------------
# Severity / description helpers
# ---------------------------------------------------------------------------

def _classify_path_severity(entry: dict) -> str:
    if entry.get("admin"):
        return "HIGH"
    if entry.get("backup"):
        return "HIGH"
    if entry.get("interesting") and entry.get("status") == 200:
        return "MEDIUM"
    if entry.get("interesting"):
        return "MEDIUM"
    if entry.get("status") in (200, 301, 302):
        return "INFO"
    if entry.get("status") == 403:
        return "LOW"
    return "INFO"


def _path_finding_title(entry: dict) -> str:
    path = entry.get("path", "/")
    status = entry.get("status", "?")
    if entry.get("admin"):
        return f"Admin Panel Found: {path} [{status}]"
    if entry.get("backup"):
        return f"Backup/Config File Found: {path} [{status}]"
    if entry.get("interesting"):
        return f"Interesting Path Discovered: {path} [{status}]"
    return f"Path Discovered: {path} [{status}]"


def _path_finding_description(entry: dict) -> str:
    full_url = entry.get("full_url", "")
    status   = entry.get("status", "?")
    path     = entry.get("path", "/")

    desc = f"Path {path} returned HTTP {status} at {full_url}."
    if entry.get("admin"):
        desc += " This appears to be an administrative interface."
    if entry.get("backup"):
        desc += " This file may contain sensitive data, database dumps, or credentials."
    return desc


def _path_exploit_hint(entry: dict) -> str:
    if entry.get("admin"):
        return (
            "Test for default credentials (admin:admin, admin:password). "
            "Try SQL injection on login form. Check for authentication bypass."
        )
    if entry.get("backup"):
        return (
            "Download and inspect file for credentials, DB schemas, API keys, "
            "and configuration secrets."
        )
    if entry.get("interesting"):
        return "Enumerate further. Look for file upload, directory listing, or sensitive data exposure."
    return "Probe path for parameter injection, file inclusion, and information disclosure."


def _port_from_url(url: str) -> int | None:
    m = re.search(r":(\d+)(?:/|$)", url)
    if m:
        return int(m.group(1))
    if url.startswith("https://"):
        return 443
    if url.startswith("http://"):
        return 80
    return None
