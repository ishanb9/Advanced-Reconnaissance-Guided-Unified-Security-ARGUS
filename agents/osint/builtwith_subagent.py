"""
builtwith_subagent.py — BuiltWith website technology profiler.

BuiltWith identifies the technology stack of any website:
  - Web servers, frameworks, CMSs
  - Analytics and tracking tools
  - CDN and hosting providers
  - JavaScript libraries and versions
  - Security products (WAF, DDoS protection)
  - E-commerce platforms

Why it matters for pentest:
  - Identifies CMSs with known CVEs (WordPress, Drupal, Joomla, etc.)
  - Reveals server-side frameworks (PHP, ASP.NET, Ruby on Rails, etc.)
  - Uncovers third-party integrations that may have their own vulns

API docs: https://api.builtwith.com
Free tier: 1 domain lookup per day
Set env:   BUILTWITH_API_KEY
"""

from __future__ import annotations

from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import BUILTWITH_API_KEY, SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

BASE_URL = "https://api.builtwith.com/v21/api.json"

# Technologies that may indicate known-vulnerable platforms
RISKY_TECH_KEYWORDS = [
    "wordpress", "drupal", "joomla", "magento", "prestashop",
    "opencart", "phpbb", "mediawiki", "moodle", "typo3",
    "php", "asp.net", "coldfusion", "struts", "spring",
    "jquery", "angular", "react",   # older versions may be vuln
    "adobe experience manager", "sitecore", "episerver",
    "weblogic", "jboss", "websphere",
]


class BuiltWithSubagent(OsintSubagentBase):
    SOURCE_NAME  = "builtwith"
    DISPLAY_NAME = "BuiltWith"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("builtwith") or not BUILTWITH_API_KEY:
            return []
        if self._is_ip(self._target):
            return []   # BuiltWith is domain-focused

        target = self._target
        await self._emit("osint_status", {
            "message": f"BuiltWith: profiling technology stack for {target}"
        })

        resp = await self._get(
            BASE_URL,
            params={"KEY": BUILTWITH_API_KEY, "LOOKUP": target},
            timeout=TIMEOUTS.get("builtwith", 20),
        )

        if not resp or resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except Exception:
            return []

        await self._parse_and_store(target, data)
        return self._results

    # ── Response parser ───────────────────────────────────────────

    async def _parse_and_store(self, target: str, data: Dict):
        categories: Dict[str, List[str]] = {}
        all_techs:  List[str]            = []

        for result in data.get("Results", []):
            for path in result.get("Result", {}).get("Paths", []):
                for tech in path.get("Technologies", []):
                    name = tech.get("Name", "").strip()
                    if not name:
                        continue
                    cats = tech.get("Categories") or ["Other"]
                    cat  = cats[0] if cats else "Other"
                    all_techs.append(name)
                    categories.setdefault(cat, []).append(name)

        if not all_techs:
            return

        # Detect potentially risky technologies
        risky = [
            t for t in all_techs
            if any(k in t.lower() for k in RISKY_TECH_KEYWORDS)
        ]

        summary_lines = [
            f"{cat}: {', '.join(dict.fromkeys(techs))[:120]}"
            for cat, techs in list(categories.items())[:18]
        ]

        await self._store(
            query     = target,
            title     = f"BuiltWith: {len(all_techs)} technologies on {target}",
            summary   = "\n".join(summary_lines),
            url       = f"https://builtwith.com/{target}",
            severity  = FindingSeverity.MEDIUM if risky else FindingSeverity.INFO,
            relevance = 0.75,
            raw       = {
                "technologies": list(dict.fromkeys(all_techs))[:100],
                "categories":   {k: list(dict.fromkeys(v))[:10]
                                 for k, v in list(categories.items())[:25]},
                "risky_tech":   risky[:20],
                "data_type":    "tech_profile",
            },
        )

        # Individual findings for risky tech (max 5 to avoid flooding)
        for tech in list(dict.fromkeys(risky))[:5]:
            await self._store(
                query     = target,
                title     = f"Technology: {tech} detected on {target}",
                summary   = (
                    f"{tech} is running on {target}.\n"
                    "This platform may have known CVEs — check NVD and ExploitDB."
                ),
                severity  = FindingSeverity.MEDIUM,
                relevance = 0.65,
                raw       = {"technology": tech, "data_type": "risky_tech"},
            )
