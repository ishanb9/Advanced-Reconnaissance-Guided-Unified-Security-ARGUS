"""
cisa_kev_subagent.py — CISA Known Exploited Vulnerabilities catalog.

WHY IT MATTERS
==============
CISA (US Cybersecurity and Infrastructure Security Agency) publishes a
free, no-auth JSON feed of every CVE that has been observed being
actively exploited in the wild.  KEV-listed CVEs are by definition
higher-value targets than ones that are merely "high CVSS" — there's a
documented working exploit and an attacker community using it.

A discovered CVE that is also KEV-listed is essentially a guaranteed
foothold path.  Surfacing this signal lets the OSINT synthesis say
"prioritise this CVE — it's actively exploited" instead of treating
all CVEs as equally promising.

How it works
------------
1. Downloads the catalog ONCE per engagement (cached in memory).
2. For every CVE discovered by NVD / vuln-scan / OSINT, checks
   inclusion in KEV.
3. Each KEV hit is stored as a CRITICAL OSINT result with the
   "knownExploitedVuln" / "requiredAction" / "dueDate" fields.
4. KEV-listed CVE IDs are surfaced into ``discovery["kev_cves"]``
   so the synthesis prompt + master agent see them.

URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx

from agents.osint.base_osint_subagent import OsintSubagentBase
from agents.osint.osint_config import SOURCES_ENABLED, TIMEOUTS
from db.schemas import FindingSeverity

logger = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Module-level cache — the catalog is ~50KB and changes daily.  One
# download per process is plenty.
_KEV_CACHE: Optional[Dict[str, Dict[str, Any]]] = None
_KEV_CACHE_LOCK = asyncio.Lock()


async def _load_kev_catalog() -> Dict[str, Dict[str, Any]]:
    """Lazy-load the KEV catalog.  Returns {cve_id: entry}."""
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE
    async with _KEV_CACHE_LOCK:
        if _KEV_CACHE is not None:
            return _KEV_CACHE
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    CISA_KEV_URL,
                    headers={"User-Agent": "ARGUS-pentest/1.0",
                              "Accept":     "application/json"},
                )
            if resp.status_code != 200:
                logger.warning("[cisa_kev] HTTP %d", resp.status_code)
                _KEV_CACHE = {}
                return _KEV_CACHE
            data = resp.json()
        except Exception as exc:
            logger.warning("[cisa_kev] catalog fetch failed: %s", exc)
            _KEV_CACHE = {}
            return _KEV_CACHE
        catalog: Dict[str, Dict[str, Any]] = {}
        for entry in (data.get("vulnerabilities") or []):
            cid = (entry.get("cveID") or "").upper()
            if cid:
                catalog[cid] = entry
        _KEV_CACHE = catalog
        logger.info("[cisa_kev] catalog loaded — %d entries", len(catalog))
        return catalog


def is_kev(cve_id: str) -> bool:
    """Synchronous KEV check.  Returns False if catalog not yet loaded."""
    if _KEV_CACHE is None:
        return False
    return cve_id.upper() in _KEV_CACHE


def kev_entry(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return the full KEV entry for a CVE, or None."""
    if _KEV_CACHE is None:
        return None
    return _KEV_CACHE.get(cve_id.upper())


class CisaKevSubagent(OsintSubagentBase):
    """Check every discovered CVE against the CISA KEV catalog."""

    SOURCE_NAME  = "cisa_kev"
    DISPLAY_NAME = "CISA KEV"

    async def run(self) -> List[Dict]:
        if not SOURCES_ENABLED.get("cisa_kev", True):
            return []

        # Pull discovered CVEs from the discovery context (filled by
        # the master OSINT agent after NVD finishes).
        cves_with_score: List[tuple] = []
        for entry in (self._disco("cves_with_score") or []):
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                cves_with_score.append((str(entry[0]).upper(),
                                          float(entry[1] or 0)))
            elif isinstance(entry, dict) and entry.get("cve_id"):
                cves_with_score.append((entry["cve_id"].upper(),
                                          float(entry.get("cvss_score", 0) or 0)))
        flat = [str(c).upper() for c in (self._disco("critical_cves") or [])
                 if isinstance(c, str)]
        all_cves = set(c for c, _ in cves_with_score) | set(flat)
        if not all_cves:
            await self._emit("osint_status", {
                "message": "CISA KEV: no CVEs discovered yet — skipping"
            })
            return []

        await self._emit("osint_status", {
            "message": f"CISA KEV: checking {len(all_cves)} CVEs "
                         "against actively-exploited catalog",
        })
        catalog = await _load_kev_catalog()
        if not catalog:
            return []

        kev_hits: List[str] = []
        for cve_id in sorted(all_cves):
            entry = catalog.get(cve_id)
            if not entry:
                continue
            kev_hits.append(cve_id)
            await self._store_kev_hit(cve_id, entry)

        if kev_hits:
            # Surface to discovery for downstream consumers (synthesis,
            # entry-point detector, master prompt)
            existing = list(self._discovery.get("kev_cves") or [])
            self._discovery["kev_cves"] = list(dict.fromkeys(existing + kev_hits))
            await self._emit("osint_status", {
                "message": (
                    f"CISA KEV: 🔥 {len(kev_hits)} of your CVEs are "
                    "ACTIVELY EXPLOITED in the wild: "
                    + ", ".join(kev_hits[:5])
                    + (" …" if len(kev_hits) > 5 else "")
                )
            })
        else:
            await self._emit("osint_status", {
                "message": (
                    f"CISA KEV: none of the {len(all_cves)} discovered CVEs "
                    "appear in CISA's actively-exploited catalog"
                )
            })
        return self._results

    async def _store_kev_hit(self, cve_id: str, entry: Dict[str, Any]) -> None:
        product = entry.get("product") or "?"
        vendor  = entry.get("vendorProject") or "?"
        name    = entry.get("vulnerabilityName") or "?"
        desc    = entry.get("shortDescription") or ""
        action  = entry.get("requiredAction") or ""
        due     = entry.get("dueDate") or ""
        date_added = entry.get("dateAdded") or ""
        ransom  = entry.get("knownRansomwareCampaignUse") or "Unknown"
        notes   = entry.get("notes") or ""
        cwes    = entry.get("cwes") or []

        title = f"🔥 KEV: {cve_id} — {vendor} {product} — ACTIVELY EXPLOITED"
        summary = (
            f"CVE: {cve_id}\n"
            f"Vendor/Product: {vendor} / {product}\n"
            f"Vuln Name: {name}\n"
            f"Description: {desc[:400]}\n"
            f"CWEs: {', '.join(cwes) if cwes else '(none)'}\n"
            f"Known Ransomware Use: {ransom}\n"
            f"Added to KEV: {date_added}\n"
            f"CISA Required Action: {action[:400]}\n"
            f"CISA Due Date: {due}\n"
            + (f"Notes: {notes[:300]}\n" if notes else "")
        )
        await self._store(
            query     = cve_id,
            title     = title,
            summary   = summary,
            url       = f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            cves      = [cve_id],
            severity  = FindingSeverity.CRITICAL,
            relevance = 1.0,    # KEV inclusion is the strongest possible signal
            raw       = {
                "data_type": "kev",
                "cve_id":    cve_id,
                "vendor":    vendor,
                "product":   product,
                "vulnerability_name": name,
                "description":        desc,
                "date_added":         date_added,
                "due_date":           due,
                "required_action":    action,
                "known_ransomware":   ransom,
                "cwes":               cwes,
            },
        )


__all__ = [
    "CisaKevSubagent", "is_kev", "kev_entry",
    "_load_kev_catalog", "CISA_KEV_URL",
]
