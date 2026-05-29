"""
github_poc_subagent.py — Find runnable PoCs on GitHub for the discovered stack.

WHAT IT DOES
============
The old OSINT pipeline returned ExploitDB titles like "OpenSSH 1.2 -
'.scp' File Create/Overwrite" — which doesn't apply to OpenSSH 7.6.
What an actual pentester does next: search GitHub for the CVE ID +
'exploit' / 'poc' to find a real runnable script.  This subagent
automates that step.

Queries:
  1. Every critical/high CVE discovered by NVD → search
     "CVE-XXXX-YYYY exploit" + "CVE-XXXX-YYYY poc" on the
     GitHub code-search API (which doesn't require auth for
     low-volume queries).
  2. Every product+version detected by recon →
     "<product> <version> exploit" and "<product> <version> rce".
  3. Surface high-star / recently-updated repos so the platform
     picks well-tested PoCs over abandoned ones.

The subagent does NOT clone or execute anything — it just builds an
intelligence record (repo URL + description + stars + last commit)
that the OSINT synthesis prompt can include in its context.

Anti-rate-limit
---------------
GitHub's unauthenticated search API allows ~10 requests/min.  We
keep a 2-second gap between calls and cap total queries to 12.
"""
from __future__ import annotations

import asyncio
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity


GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
GITHUB_API_TIMEOUT = 15
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")    # optional


class GitHubPoCSubagent(OsintSubagentBase):
    """Find runnable PoCs on GitHub for CVEs + discovered services."""

    SOURCE_NAME  = "github_poc"
    DISPLAY_NAME = "GitHub PoC"

    MAX_QUERIES_PER_RUN = int(os.environ.get("GITHUB_POC_MAX_QUERIES", "12"))
    INTER_QUERY_DELAY   = float(os.environ.get("GITHUB_POC_DELAY", "2.0"))

    # Repos with these names are almost always garbage — generic
    # exploit catalogs that don't run.  Skip when we see them.
    _NAME_BLACKLIST = re.compile(
        r"(?i)\b(cve-?database|all-?cves|cve-?list|awesome-?cve|cve-?monitor)\b"
    )

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("github_poc", True):
            return []
        queries = self._build_queries()
        if not queries:
            return []
        await self._emit("osint_status", {
            "message": f"GitHub PoC: searching {len(queries)} queries"
        })
        for q, label, sev in queries[: self.MAX_QUERIES_PER_RUN]:
            if self._stopped:
                break
            await self._search_one(q, label, sev)
            await asyncio.sleep(self.INTER_QUERY_DELAY)
        return self._results

    # ── Query construction ──────────────────────────────────────────

    def _build_queries(self) -> List[Tuple[str, str, FindingSeverity]]:
        """Return list of (query, human_label, severity)."""
        out: List[Tuple[str, str, FindingSeverity]] = []
        seen_cves: set = set()

        # CVE queries — every critical / high CVE we've discovered
        cves_with_score = self._disco("cves_with_score") or []
        cves_flat       = self._disco("critical_cves") or []
        cves_combined: List[Tuple[str, float]] = []
        for entry in cves_with_score:
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                cves_combined.append((str(entry[0]), float(entry[1] or 0)))
            elif isinstance(entry, dict) and entry.get("cve_id"):
                cves_combined.append(
                    (entry["cve_id"], float(entry.get("cvss_score", 0) or 0))
                )
        for c in cves_flat:
            if isinstance(c, str):
                cves_combined.append((c, 9.0))    # assume critical when flat
        # Sort by CVSS descending so we burn budget on high-impact CVEs first
        cves_combined.sort(key=lambda t: t[1], reverse=True)
        for cve_id, score in cves_combined[:6]:
            if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id, re.IGNORECASE):
                continue
            if cve_id.upper() in seen_cves:
                continue
            seen_cves.add(cve_id.upper())
            # Two patterns per CVE — "exploit" and "poc" — cover both
            # naming conventions used by PoC authors.
            sev = (FindingSeverity.CRITICAL if score >= 9.0
                   else FindingSeverity.HIGH if score >= 7.0
                   else FindingSeverity.MEDIUM)
            out.append((
                f'"{cve_id}" exploit',
                f"PoC for {cve_id} (CVSS {score:.1f})",
                sev,
            ))
            out.append((
                f'"{cve_id}" poc',
                f"PoC for {cve_id} (alt search)",
                sev,
            ))

        # Product+version queries — for high-value stacks observed
        products = self._disco("product_versions") or []
        for pv in products[:4]:
            if not pv or len(pv) < 4:
                continue
            out.append((
                f'"{pv}" exploit',
                f"Exploit code for {pv}",
                FindingSeverity.HIGH,
            ))

        return out

    # ── GitHub API call ─────────────────────────────────────────────

    async def _search_one(self, query: str, label: str,
                              severity: FindingSeverity) -> None:
        headers = {
            "Accept":     "application/vnd.github.v3+json",
            "User-Agent": "ARGUS-pentest/1.0",
        }
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        params = {
            "q":          query,
            "sort":       "stars",
            "order":      "desc",
            "per_page":   5,
        }
        try:
            async with httpx.AsyncClient(timeout=GITHUB_API_TIMEOUT) as client:
                resp = await client.get(GITHUB_SEARCH_URL,
                                            params=params, headers=headers)
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"GitHub PoC: query error: {exc}"
            })
            return
        if resp.status_code == 403:
            # Rate-limited — abandon the rest of the batch
            await self._emit("osint_warning", {
                "message": (
                    "GitHub PoC: HTTP 403 — unauthenticated rate limit "
                    "exhausted.  Set GITHUB_TOKEN env to lift the cap."
                )
            })
            return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return
        items = data.get("items") or []
        if not items:
            return
        kept = []
        for it in items[:5]:
            name  = it.get("full_name", "")
            if self._NAME_BLACKLIST.search(name):
                continue
            desc  = (it.get("description") or "")[:200]
            url   = it.get("html_url") or ""
            stars = int(it.get("stargazers_count") or 0)
            kept.append({
                "name":  name,
                "desc":  desc,
                "url":   url,
                "stars": stars,
                "lang":  it.get("language") or "",
                "updated": (it.get("updated_at") or "")[:10],
            })
        if not kept:
            return
        # Relevance = stars-weighted, with floor for ≥1-star repos
        max_stars = max(k["stars"] for k in kept) if kept else 0
        relevance = 0.65 if max_stars < 10 else 0.85 if max_stars < 100 else 0.95
        summary_lines = [f"• {k['name']} ★{k['stars']} ({k['lang']}, {k['updated']})\n  {k['url']}\n  {k['desc']}"
                            for k in kept[:5]]
        await self._store(
            query     = query,
            title     = f"GitHub: {label} — {len(kept)} repo(s)",
            summary   = f"Top GitHub PoC search results for `{query}`:\n\n"
                          + "\n\n".join(summary_lines),
            url       = f"https://github.com/search?q={query.replace(' ', '+')}&type=repositories",
            severity  = severity,
            relevance = relevance,
            raw       = {
                "query":       query,
                "label":       label,
                "repos":       kept,
                "data_type":   "github_poc",
            },
        )


__all__ = ["GitHubPoCSubagent"]
