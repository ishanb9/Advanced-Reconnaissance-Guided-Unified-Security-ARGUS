"""
tineye_subagent.py — TinEye reverse image search.

TinEye finds where images from the target website appear on the web.
Useful for:
  - Attribution / copyright tracking
  - Finding reused profile photos (social engineering leads)
  - Discovering mirror / phishing sites using the same assets
  - Identifying stolen branding

Requires TinEye API key and secret:
  Sign up: https://services.tineye.com/TinEyeAPI
  Free sandbox: 5,000 searches available for trial

Set env vars: TINEYE_API_KEY, TINEYE_API_SECRET
"""

from __future__ import annotations

import re
from typing import Dict, List

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import TINEYE_API_KEY, SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

TINEYE_API_BASE = "https://api.tineye.com/rest"


class TinEyeSubagent(OsintSubagentBase):
    SOURCE_NAME  = "tineye"
    DISPLAY_NAME = "TinEye"

    async def run(self, image_urls: List[str] = None) -> List[Dict]:
        if not SOURCES_ENABLED.get("tineye") or not TINEYE_API_KEY:
            return []

        target = self._target
        await self._emit("osint_status", {
            "message": f"TinEye: reverse image search for {target}"
        })

        # Auto-discover images from homepage if none supplied
        if not image_urls:
            image_urls = await self._discover_images(target)

        if not image_urls:
            return []

        for img_url in image_urls[:5]:  # Limit to 5 to conserve API quota
            if self._stopped:
                break
            await self._search_image(img_url)

        return self._results

    # ── Image discovery ────────────────────────────────────────────

    async def _discover_images(self, target: str) -> List[str]:
        """Crawl target homepage and extract absolute image URLs."""
        homepage = target if target.startswith("http") else f"https://{target}"
        resp = await self._get(homepage, timeout=15)
        if not resp or resp.status_code != 200:
            return []

        imgs = re.findall(
            r'<img[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE
        )
        result = []
        for img in imgs[:20]:
            if img.startswith("http"):
                result.append(img)
            elif img.startswith("/"):
                result.append(f"https://{target}{img}")
        # Deduplicate, skip tiny icons
        result = [u for u in dict.fromkeys(result) if not any(
            x in u.lower() for x in ["favicon", "icon", ".svg", "1x1", "pixel"]
        )]
        return result[:10]

    # ── TinEye search ──────────────────────────────────────────────

    async def _search_image(self, image_url: str):
        resp = await self._get(
            f"{TINEYE_API_BASE}/search/",
            params={"api_key": TINEYE_API_KEY, "image_url": image_url},
            timeout=TIMEOUTS.get("tineye", 20),
        )
        if not resp or resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        results_block = data.get("results", {})
        total         = results_block.get("total_results", 0)

        if total == 0:
            return

        matches  = results_block.get("matches", [])
        domains  = list(dict.fromkeys(m.get("domain", "") for m in matches if m.get("domain")))
        crawled  = [m.get("crawl_date", "") for m in matches[:5]]

        await self._store(
            query     = image_url,
            title     = f"TinEye: image from {self._target} found on {total} site(s)",
            summary   = (
                f"Image URL: {image_url}\n"
                f"Matches  : {total}\n"
                f"Domains  : {', '.join(domains[:10])}"
            ),
            url       = f"https://tineye.com/search?url={image_url}",
            severity  = FindingSeverity.INFO,
            relevance = 0.45,
            raw       = {
                "image_url":   image_url,
                "match_count": total,
                "domains":     domains[:20],
                "crawl_dates": crawled,
                "data_type":   "image_usage",
            },
        )
