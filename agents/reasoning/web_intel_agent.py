"""agents/reasoning/web_intel_agent.py

Web-Intelligence Pivot Agent — fires when the reasoning loop is stuck.

Problem this solves
====================
When the LLM-driven reasoning loop runs out of ideas and the deterministic
primer chains have all completed without producing a foothold, the platform
historically just exits with "No more actions available".  But there's
huge unused potential: every service version / CVE / banner / framework
hint we've already collected can be looked up on the web — exploit-DB,
HackTricks, GitHub PoCs, vendor advisories — to find the canonical
exploitation technique that the LLM didn't propose on its own.

This module implements that pivot.  When invoked it:

  1. Builds 1-3 high-precision web search queries from observed intel
     (service+version, CVE IDs, AD-specific tech, web framework + version).
  2. Searches the web (Google Custom Search → DuckDuckGo HTML → SearXNG
     fallback so the agent works even without API keys).
  3. Fetches the top results and strips them to clean text (safe fetch:
     follows redirects but bounded size, timeout, no auth headers).
  4. Asks the LLM to extract concrete, runnable exploitation steps —
     with strict grounding rules: only commands referencing tools we
     have, services we've observed, and CVEs we can map to artefacts.
  5. Validates each extracted command (re-uses B6 pseudo-code rejection
     and the MCP tool catalog) and converts the survivors into
     ``Hypothesis`` objects with populated ``recommended_next_actions``
     so the next iteration of the reasoning loop has fresh, evidence-
     backed material to work with.

Results are cached on (query) so the same lookup isn't repeated within
the engagement.  Per-engagement budget caps prevent runaway API spend.

Authoritative-source bias
-------------------------
Sources are scored — exploit-db.com / hacktricks / github advisories
outrank random blogs.  The LLM is told the source rank so it weights
extraction accordingly.

Wiring
------
Reasoning loop calls ``web_intel.run(intel, hypotheses)`` from the
``action is None`` branch BEFORE giving up.  If ``run()`` injected any
new hypotheses, the loop continues.  Otherwise it ends as before.
"""

from __future__ import annotations

import asyncio
import hashlib
import html as _html
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx


logger = logging.getLogger(__name__)


__all__ = ["WebIntelAgent", "ExploitHint", "WebSearchResult"]


# ════════════════════════════════════════════════════════════════════
# Data classes
# ════════════════════════════════════════════════════════════════════

@dataclass
class WebSearchResult:
    title:    str
    url:      str
    snippet:  str
    source:   str            # "google" / "ddg" / "searxng" / "manual"
    rank:     int    = 0     # 0-based result position from the search engine
    authority: float = 0.5   # 0..1 — bumped for exploit-db / hacktricks / github

    def to_dict(self) -> dict:
        return {
            "title": self.title, "url": self.url,
            "snippet": self.snippet[:300] if self.snippet else "",
            "source": self.source, "rank": self.rank,
            "authority": self.authority,
        }


@dataclass
class ExploitHint:
    """A single extracted, validated exploitation step."""
    tool:        str          # tool name (must be runnable)
    args:        str          # full arg string with target placeholder filled
    description: str          # 1-line explanation
    cve:         Optional[str] = None
    mitre:       Optional[str] = None
    confidence:  float        = 0.55     # 0..1 from extractor LLM grading
    source_url:  Optional[str] = None
    raw_quote:   Optional[str] = None    # ≤200 chars verbatim from page

    def to_dict(self) -> dict:
        return {
            "tool":        self.tool,
            "args":        self.args,
            "description": self.description[:300],
            "cve":         self.cve,
            "mitre":       self.mitre,
            "confidence":  self.confidence,
            "source_url":  self.source_url,
            "raw_quote":   (self.raw_quote or "")[:200],
        }


# ════════════════════════════════════════════════════════════════════
# WebIntelAgent
# ════════════════════════════════════════════════════════════════════

# Source-authority table — when a result URL contains one of these
# substrings, the authority score is boosted.  Used to bias the LLM's
# extraction toward verified exploitation sources rather than blog posts.
_AUTHORITY_BOOSTS = (
    ("exploit-db.com",       0.95),
    ("exploitdb.com",        0.95),
    ("hacktricks.xyz",       0.92),
    ("hacktricks.boitatech", 0.92),
    ("attackerkb.com",       0.90),
    ("nvd.nist.gov",         0.90),
    ("cve.mitre.org",        0.88),
    ("github.com",           0.78),       # PoCs vary in quality
    ("rapid7.com",           0.85),
    ("metasploit.com",       0.88),
    ("snyk.io/vuln",         0.85),
    ("vulners.com",          0.82),
    ("packetstormsecurity",  0.80),
    ("offensive-security",   0.85),
    ("portswigger.net",      0.85),
    ("microsoft.com/security",0.85),
    ("oracle.com/security",  0.80),
    ("cisa.gov",             0.85),
)


class WebIntelAgent:
    """Per-session web-intelligence pivot.  Owned by ReasoningLoop."""

    # Caps to prevent runaway resource use across an engagement
    MAX_QUERIES_PER_INVOCATION = 3
    MAX_RESULTS_PER_QUERY      = 5
    MAX_FETCH_PER_INVOCATION   = 4
    MAX_INVOCATIONS_PER_RUN    = 6
    PAGE_FETCH_TIMEOUT_S       = 12
    PAGE_SIZE_LIMIT            = 256_000   # bytes — bounded snippet harvest

    def __init__(
        self,
        *, master_agent: Any,
        session_id:     str,
        target:         str,
        broadcast:      Optional[Callable[..., Any]] = None,
    ) -> None:
        self._master    = master_agent
        self._session   = session_id
        self._target    = target
        self._broadcast = broadcast or getattr(master_agent, "_broadcast_raw", None)

        # In-memory query → results cache so consecutive stuck events with
        # the same intel snapshot don't re-fetch.
        self._query_cache:  Dict[str, List[WebSearchResult]] = {}
        self._page_cache:   Dict[str, str] = {}
        self._invocations:  int = 0

        # Surface which search-engine path is wired up so operators can
        # immediately tell whether the Google CSE credentials are picked
        # up properly vs falling back to DuckDuckGo HTML scraping.
        try:
            gkey, gcx = self._resolve_google_creds()
            sx = os.environ.get("SEARXNG_URL", "")
            if gkey and gcx:
                primary = f"google_cse (cx={gcx[:6]}…)"
            elif sx:
                primary = f"searxng ({sx})"
            else:
                primary = "duckduckgo_html (no API keys configured)"
            logger.info(
                "[web_intel] WebIntelAgent ready — primary=%s, fallback=ddg, "
                "session=%s target=%s",
                primary, session_id, target,
            )
        except Exception:
            pass

    # ── Public entrypoint ────────────────────────────────────────────
    async def run(
        self,
        intel:      dict,
        hypotheses: list,
    ) -> int:
        """Run a single web-intel pivot pass.

        Returns the number of new hypotheses injected.  When 0 is returned
        the caller (reasoning loop) should treat the loop as exhausted and
        terminate.
        """
        if self._invocations >= self.MAX_INVOCATIONS_PER_RUN:
            await self._emit("Web intel pivot — invocation cap reached this run")
            return 0
        self._invocations += 1

        if not self.should_invoke(intel, hypotheses):
            return 0

        await self._emit(
            "Web intel pivot — building queries from observed intel"
        )

        queries = self.build_queries(intel)
        if not queries:
            await self._emit(
                "Web intel pivot — nothing concrete to query (no service+version "
                "/ CVE / framework intel observed yet)"
            )
            return 0

        all_results: List[WebSearchResult] = []
        for q in queries[: self.MAX_QUERIES_PER_INVOCATION]:
            await self._emit(f"Web intel: searching for {q!r}")
            results = await self.search(q)
            if results:
                all_results.extend(results)

        if not all_results:
            await self._emit("Web intel pivot — no search results returned")
            return 0

        # Dedup by URL, sort by authority desc, cap to MAX_FETCH
        seen: set = set()
        ranked: List[WebSearchResult] = []
        for r in sorted(all_results, key=lambda x: x.authority, reverse=True):
            if r.url in seen:
                continue
            seen.add(r.url)
            ranked.append(r)

        ranked = ranked[: self.MAX_FETCH_PER_INVOCATION]

        # Fetch page bodies (best-effort, bounded)
        pages: List[Tuple[WebSearchResult, str]] = []
        for r in ranked:
            text = await self.fetch_page(r.url)
            if text:
                pages.append((r, text))

        if not pages:
            await self._emit("Web intel pivot — pages unfetchable; stopping")
            return 0

        # Ask the LLM to extract usable exploit hints
        hints = await self.extract_hints(pages, intel)

        if not hints:
            await self._emit(
                f"Web intel pivot — fetched {len(pages)} pages but extracted "
                f"no concrete commands"
            )
            return 0

        # Inject as hypotheses
        injected = await self.inject_hypotheses(intel, hypotheses, hints)

        await self._emit(
            f"Web intel pivot — injected {injected} new hypotheses with "
            f"{sum(len((h.recommended_next_actions or [])) for h in hypotheses[-injected:])} "
            f"actions from {len(pages)} authoritative sources"
        )
        return injected

    # ── Stuck-state detector ─────────────────────────────────────────
    def should_invoke(self, intel: dict, hypotheses: list) -> bool:
        """Heuristic: do we have enough intel to ask intelligent questions
        AND no productive path forward?"""
        # If we've already obtained a foothold, leave the platform alone —
        # post-foothold and lateral primers should drive next.
        if intel.get("shell_access"):
            return False

        # Don't invoke if we've never even completed RECON — wait for
        # services to be observed first.
        services = intel.get("services") or {}
        ports    = intel.get("open_ports") or []
        if not ports:
            return False

        # If every hypothesis is invalidated AND no fresh leads, it's stuck.
        active = [
            h for h in (hypotheses or [])
            if not getattr(h, "invalidated", False)
        ]
        # Also stuck when active hypotheses have no recommended_next_actions
        # left after primer + LLM dedup
        actionable = [
            h for h in active
            if (getattr(h, "recommended_next_actions", None) or [])
        ]
        if actionable:
            return False
        return True

    # ── Query builder ────────────────────────────────────────────────
    def build_queries(self, intel: dict) -> List[str]:
        """Produce up to 3 high-precision search queries from intel.

        Priority order:
          1. CVEs (if any) — they're already specific exploit targets
          2. Service+version pairs (with vendor when known)
          3. Web framework / CMS + version
          4. AD-specific path: domain + DC version
        """
        queries: List[str] = []

        # 1. CVEs — most specific
        cves = intel.get("cves") or []
        for c in (cves or [])[:2]:
            cv = str(c).strip().upper()
            if not cv.startswith("CVE-"):
                continue
            queries.append(f"{cv} exploit poc github metasploit")

        # 2. Service banners with versions
        services = intel.get("services") or {}
        if isinstance(services, dict):
            services_iter = list(services.items())[:8]
        else:
            services_iter = []
        seen_svc = set()
        for port, svc in services_iter:
            if isinstance(svc, dict):
                name    = (svc.get("service") or svc.get("name") or "").strip().lower()
                version = (svc.get("version") or "").strip()    # version ONLY — don't fall back to product
                product = (svc.get("product") or "").strip()
            else:
                name, version, product = str(svc).lower(), "", ""
            if not name or name in {"unknown", "tcpwrapped", "tcp"}:
                continue
            sig = (name, version)
            if sig in seen_svc:
                continue
            seen_svc.add(sig)
            # Build a search-friendly product+name without duplication
            label_parts: list = []
            if product and product.lower() not in name:
                label_parts.append(product)
            label_parts.append(name)
            label = " ".join(label_parts).strip()
            if version:
                queries.append(f"{label} {version} exploit known vulnerabilities")
            elif product:
                queries.append(f"{label} known cves exploit")

        # 3. Web tech / framework
        web_tech = intel.get("web_tech_tags") or intel.get("web_tech") or []
        if isinstance(web_tech, list) and web_tech:
            tech_str = " ".join(str(t) for t in web_tech[:3])
            queries.append(f"{tech_str} exploitation techniques web pentest")

        # 4. AD-specific lookup
        domain = (intel.get("domain") or "").strip()
        if domain and any(p in self._port_set(intel) for p in ("88", "389", "445")):
            queries.append(
                f"active directory exploitation {domain} kerberos NTLM relay AS-REP roast"
            )

        # Deduplicate / cap
        out: List[str] = []
        seen: set = set()
        for q in queries:
            qn = q.strip().lower()
            if qn and qn not in seen:
                seen.add(qn)
                out.append(q)
            if len(out) >= self.MAX_QUERIES_PER_INVOCATION:
                break
        return out

    @staticmethod
    def _port_set(intel: dict) -> set:
        out: set = set()
        for p in (intel.get("open_ports") or []):
            if isinstance(p, dict):
                pp = p.get("port")
                if pp is not None:
                    out.add(str(pp))
            else:
                out.add(str(p).split("/")[0])
        return out

    # ── Web search (Google → DuckDuckGo → SearXNG) ───────────────────
    async def search(self, query: str) -> List[WebSearchResult]:
        """Search the web for ``query``.  Cached.  Fallback chain:
        Google CSE → DuckDuckGo HTML → SearXNG (when configured).
        """
        cached = self._query_cache.get(query)
        if cached is not None:
            return cached

        results: List[WebSearchResult] = []

        # 1. Google Custom Search — best when API key is present.
        # Read from osint_config so the platform-wide defaults
        # (set via env vars OR baked into osint_config.py) flow through;
        # env var still takes precedence at osint_config-load time.
        gkey, gcx = self._resolve_google_creds()
        if gkey and gcx:
            try:
                results = await self._search_google(query, gkey, gcx)
                if not results:
                    logger.info(
                        "[web_intel] Google CSE returned 0 results for %r — "
                        "falling back to DDG", query[:60],
                    )
            except Exception as exc:
                logger.warning("[web_intel] Google search failed: %s", exc)

        # 2. DuckDuckGo HTML fallback
        if not results:
            try:
                results = await self._search_ddg(query)
            except Exception as exc:
                logger.warning("[web_intel] DuckDuckGo search failed: %s", exc)

        # 3. SearXNG (operator-deployed, optional)
        if not results:
            sx = os.environ.get("SEARXNG_URL", "")
            if sx:
                try:
                    results = await self._search_searxng(query, sx)
                except Exception as exc:
                    logger.warning("[web_intel] SearXNG failed: %s", exc)

        # Score authority
        for r in results:
            r.authority = self._score_authority(r.url)

        self._query_cache[query] = results
        return results

    # Per-session Google CSE health cache so we don't spam 403s.
    # Keyed by (api_key prefix) — a "dead" key stays dead for the
    # rest of the engagement when the failure mode is structural
    # (accessNotConfigured, forbidden), or for 30 minutes when it
    # is transient (rate limit / quota).
    _CSE_DEAD: Dict[str, float] = {}

    @classmethod
    def _cse_is_dead(cls, key: str) -> bool:
        import time as _t
        dead_until = cls._CSE_DEAD.get(key[:16])
        return dead_until is not None and _t.time() < dead_until

    @classmethod
    def _cse_mark_dead(cls, key: str, *, permanent: bool) -> None:
        import time as _t
        # Permanent failures stay marked for 24h (engagement-scoped);
        # transient failures clear after 30 minutes
        ttl = 86400.0 if permanent else 1800.0
        cls._CSE_DEAD[key[:16]] = _t.time() + ttl

    async def _search_google(self, q: str, key: str, cx: str) -> List[WebSearchResult]:
        """Call Google Custom Search JSON API.  Surfaces the server-side
        error reason on 403/429 so the operator can fix project setup.

        Common 403 reasons:
          • PERMISSION_DENIED / accessNotConfigured — Custom Search
            JSON API not enabled on the project that owns the API key.
            We mark the key DEAD permanently for the engagement so
            subsequent calls go straight to DDG with no per-query
            403 noise.  Enable at:
            https://console.cloud.google.com/apis/library/customsearch.googleapis.com
          • dailyLimitExceeded — free-tier 100 queries/day exhausted
            — DEAD for 30 minutes.
          • rateLimitExceeded — transient — DEAD for 30 minutes.
        """
        # Skip the API call entirely if the key is already known dead
        if self._cse_is_dead(key):
            return []

        url = "https://www.googleapis.com/customsearch/v1"
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(url, params={
                "key": key, "cx": cx, "q": q,
                "num": self.MAX_RESULTS_PER_QUERY,
            })
        if resp.status_code != 200:
            try:
                err = resp.json().get("error", {})
                reason  = ""
                msg     = err.get("message", "(no message)")
                errs    = err.get("errors") or []
                if errs and isinstance(errs[0], dict):
                    reason = errs[0].get("reason", "")
                # Mark dead so future queries skip the API call
                permanent = reason in (
                    "accessNotConfigured", "PERMISSION_DENIED",
                    "forbidden", "keyInvalid",
                )
                self._cse_mark_dead(key, permanent=permanent)
                logger.warning(
                    "[web_intel] Google CSE %d (%s): %s — marking key %s; "
                    "falling back to DDG.  Enable Custom Search JSON API at "
                    "console.cloud.google.com/apis/library/customsearch.googleapis.com",
                    resp.status_code, reason or "unknown", msg[:200],
                    "permanently dead" if permanent else "dead for 30 minutes",
                )
            except Exception:
                self._cse_mark_dead(key, permanent=False)
                logger.warning(
                    "[web_intel] Google CSE HTTP %d (body unparseable) — falling back to DDG",
                    resp.status_code,
                )
            return []
        try:
            data = resp.json()
        except Exception:
            return []
        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            logger.warning(
                "[web_intel] Google CSE inline error: %s — falling back to DDG",
                err.get("message", str(err))[:200],
            )
            return []
        items = data.get("items") or []
        out: List[WebSearchResult] = []
        for i, it in enumerate(items[: self.MAX_RESULTS_PER_QUERY]):
            out.append(WebSearchResult(
                title    = it.get("title") or "",
                url      = it.get("link") or "",
                snippet  = it.get("snippet") or "",
                source   = "google",
                rank     = i,
            ))
        return out

    async def _search_ddg(self, q: str) -> List[WebSearchResult]:
        """DuckDuckGo HTML scrape — works without an API key."""
        url = "https://html.duckduckgo.com/html/"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ARGUS-WebIntel/1.0",
        }
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            resp = await client.post(url, data={"q": q}, headers=headers)
        if resp.status_code != 200:
            return []
        text = resp.text
        # Result cards have:  class="result__a" href="<URL>">title</a>
        # and class="result__snippet">snippet</a>
        result_re = re.compile(
            r'class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>'
            r'(?:.*?class="result__snippet"[^>]*>(.*?)</a>)?',
            re.DOTALL | re.IGNORECASE,
        )
        out: List[WebSearchResult] = []
        for i, m in enumerate(result_re.finditer(text)):
            if i >= self.MAX_RESULTS_PER_QUERY:
                break
            raw_url = _html.unescape(m.group(1) or "")
            # DDG sometimes wraps URLs in /l/?uddg=<url>
            if raw_url.startswith("/l/?"):
                inner = re.search(r"uddg=([^&]+)", raw_url)
                if inner:
                    from urllib.parse import unquote
                    raw_url = unquote(inner.group(1))
            title   = re.sub(r"<[^>]+>", "", m.group(2) or "").strip()
            snippet = re.sub(r"<[^>]+>", "", (m.group(3) or "")).strip()
            if raw_url.startswith("http"):
                out.append(WebSearchResult(
                    title=_html.unescape(title),
                    url=raw_url,
                    snippet=_html.unescape(snippet),
                    source="ddg",
                    rank=i,
                ))
        return out

    async def _search_searxng(self, q: str, base: str) -> List[WebSearchResult]:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(
                base.rstrip("/") + "/search",
                params={"q": q, "format": "json"},
            )
        if resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except Exception:
            return []
        out: List[WebSearchResult] = []
        for i, it in enumerate((data.get("results") or [])[: self.MAX_RESULTS_PER_QUERY]):
            out.append(WebSearchResult(
                title=it.get("title") or "",
                url=it.get("url") or "",
                snippet=it.get("content") or "",
                source="searxng",
                rank=i,
            ))
        return out

    @staticmethod
    def _score_authority(url: str) -> float:
        u = (url or "").lower()
        for needle, score in _AUTHORITY_BOOSTS:
            if needle in u:
                return score
        return 0.55

    @staticmethod
    def _resolve_google_creds() -> Tuple[str, str]:
        """Resolve (GOOGLE_API_KEY, GOOGLE_CX) honouring this priority:
          1. Explicit env vars at runtime (operator override)
          2. osint_config.GOOGLE_API_KEY / GOOGLE_CX (platform-wide defaults)
          3. Empty strings → caller falls back to DuckDuckGo HTML

        Centralising the lookup means both Google Dorks subagent and the
        WebIntelAgent see the SAME keys and don't drift apart.
        """
        # 1. Live env override
        env_key = os.environ.get("GOOGLE_API_KEY", "")
        env_cx  = os.environ.get("GOOGLE_CX", "")
        if env_key and env_cx:
            return env_key, env_cx

        # 2. osint_config defaults
        try:
            from agents.osint.osint_config import GOOGLE_API_KEY, GOOGLE_CX
            if GOOGLE_API_KEY and GOOGLE_CX:
                return GOOGLE_API_KEY, GOOGLE_CX
        except Exception:
            pass

        # 3. Partial env vars (one set, one not) — return what we have so the
        # caller can decide; Google CSE itself will reject incomplete creds
        # which we treat as "fall through to DDG"
        return env_key, env_cx

    # ── Page fetcher ─────────────────────────────────────────────────
    async def fetch_page(self, url: str) -> str:
        """Fetch a URL, return text-only stripped content.  Cached."""
        if url in self._page_cache:
            return self._page_cache[url]

        try:
            async with httpx.AsyncClient(
                timeout=self.PAGE_FETCH_TIMEOUT_S,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=4),
                headers={"User-Agent": "Mozilla/5.0 ARGUS-WebIntel/1.0"},
            ) as client:
                resp = await client.get(url)
        except Exception as exc:
            logger.debug("[web_intel] fetch failed %s: %s", url[:60], exc)
            self._page_cache[url] = ""
            return ""

        if resp.status_code != 200:
            self._page_cache[url] = ""
            return ""

        # Strip to text — drop scripts, styles, then collapse tags.
        body = resp.text[: self.PAGE_SIZE_LIMIT]
        body = re.sub(r"<script\b[^>]*>.*?</script>", " ", body,
                      flags=re.DOTALL | re.IGNORECASE)
        body = re.sub(r"<style\b[^>]*>.*?</style>", " ", body,
                      flags=re.DOTALL | re.IGNORECASE)
        body = re.sub(r"<!--.*?-->", " ", body, flags=re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", body)
        text = _html.unescape(text)
        text = re.sub(r"\s+", " ", text).strip()
        # Cap to keep LLM prompt reasonable
        text = text[:8000]
        self._page_cache[url] = text
        return text

    # ── LLM-based hint extractor ────────────────────────────────────
    async def extract_hints(
        self,
        pages: List[Tuple[WebSearchResult, str]],
        intel: dict,
    ) -> List[ExploitHint]:
        """Ask the LLM to extract concrete, runnable exploit commands
        from the fetched page text — with strict grounding rules."""
        # Build a compact intel snapshot for the LLM
        services_summary = []
        for port, svc in (intel.get("services") or {}).items():
            if isinstance(svc, dict):
                name = svc.get("service") or svc.get("name") or ""
                ver  = svc.get("version") or svc.get("product") or ""
                services_summary.append(f"{port}/{name} {ver}".strip())
            else:
                services_summary.append(f"{port}/{svc}")
        ports_str = ", ".join(sorted(self._port_set(intel))[:30])

        # Tool catalog the LLM is allowed to choose from
        catalog: list = []
        try:
            catalog = list((self._master and self._master._tool_catalog or {}).keys())
        except Exception:
            catalog = []
        catalog_hint = (
            "AVAILABLE TOOLS (only choose from this list — others will be rejected):\n  "
            + ", ".join(sorted(catalog)[:120])
            if catalog else
            "AVAILABLE TOOLS: (catalog unloaded — use common Kali tool names: "
            "nmap, nuclei, sqlmap, hydra, crackmapexec, evil-winrm, impacket-*, "
            "metasploit, etc.)"
        )

        creds_str = ""
        creds = intel.get("credentials") or []
        if creds:
            sample = creds[0] if isinstance(creds[0], dict) else {}
            if sample.get("user"):
                creds_str = (
                    f"\nCREDENTIALS AVAILABLE: user={sample.get('user')} "
                    f"domain={sample.get('domain','')} "
                    f"(password redacted but available — use as `$PASS` in commands "
                    f"and the dispatcher will substitute)"
                )

        # Compose the page evidence — title + URL + first 2000 chars of body
        sources_block: list = []
        for i, (sr, body) in enumerate(pages):
            sources_block.append(
                f"[SOURCE {i+1}] (authority={sr.authority:.2f}) {sr.title}\n"
                f"URL: {sr.url}\n"
                f"--- excerpt ---\n{body[:2000]}\n--- end ---"
            )
        sources_text = "\n\n".join(sources_block)

        system = (
            "You are an expert penetration-testing LLM extracting exploit "
            "intelligence from web search results.\n\n"
            "STRICT RULES (violating any rule invalidates the response):\n"
            "1. Output VALID JSON only — no prose, no markdown fences.\n"
            "2. Each `command` MUST be a single shell tool invocation; the "
            "first whitespace-delimited token MUST be a tool name from the "
            "AVAILABLE TOOLS list.\n"
            "3. The action must reference a service/port that actually appears "
            "in TARGET INTEL.  If a source describes an exploit for a service "
            "we have NOT observed, do not include it.\n"
            "4. Replace the target hostname / IP with the literal string {TARGET} "
            "in every command — the dispatcher substitutes it.\n"
            "5. If creds are available, use the literal `$USER` / `$PASS` / "
            "`$DOMAIN` placeholders — the dispatcher substitutes from intel.\n"
            "6. Only include actions you can justify with a quote from the "
            "source (≤30 words verbatim).\n"
            "7. confidence: 0.6-0.95 — calibrate to source authority + how "
            "directly the source claims the exploit works.\n"
            "8. Skip social-engineering / phishing / DDoS / illegal-only paths.\n"
            "9. Maximum 5 hints in the response."
        )

        user = (
            f"TARGET INTEL\n"
            f"  target: {self._target}\n"
            f"  open_ports: {ports_str}\n"
            f"  services: {'; '.join(services_summary[:30])}\n"
            f"  cves: {', '.join((intel.get('cves') or [])[:8])}\n"
            f"  domain: {intel.get('domain','') or '(none)'}\n"
            f"  current_user: {intel.get('current_user','') or '(none)'}\n"
            f"{creds_str}\n\n"
            f"{catalog_hint}\n\n"
            f"WEB SEARCH SOURCES\n\n{sources_text}\n\n"
            "TASK: Extract concrete, runnable exploit commands relevant to "
            "the TARGET INTEL above.  Return ONLY this JSON shape:\n"
            "{\n"
            '  "hints": [\n'
            "    {\n"
            '      "tool": "sqlmap",\n'
            '      "args": "-u http://{TARGET}/login.php --batch --crawl=2 --dbs",\n'
            '      "description": "Brief why-this-applies",\n'
            '      "cve": "CVE-2023-XXXX or null",\n'
            '      "mitre": "T1190 or null",\n'
            '      "confidence": 0.75,\n'
            '      "source_url": "https://...",\n'
            '      "raw_quote": "≤30 word verbatim quote"\n'
            "    }\n"
            "  ]\n"
            "}\n"
        )

        # Call the master's think_json (already wired with circuit breaker
        # backoff from B1).  Fail gracefully on any error.
        try:
            think_json = getattr(self._master, "think_json", None) \
                       or getattr(self._master, "_think_json", None)
            if not callable(think_json):
                return []
            raw = await think_json(user, system_context=system)
        except Exception as exc:
            logger.warning("[web_intel] LLM extract call failed: %s", exc)
            return []

        if not isinstance(raw, dict):
            return []
        hints_raw = raw.get("hints") or []
        if not isinstance(hints_raw, list):
            return []

        # Validate / coerce each hint
        out: List[ExploitHint] = []
        for h in hints_raw[:5]:
            if not isinstance(h, dict):
                continue
            tool = (h.get("tool") or "").strip()
            args = (h.get("args") or "").strip()
            if not tool or not args:
                continue
            # Apply B6 pseudo-code rejection
            if not re.match(r"^[A-Za-z][A-Za-z0-9._+/-]*$", tool):
                logger.debug("[web_intel] rejecting hint with bad tool=%r", tool)
                continue
            # If catalog is loaded, require the tool to be in it
            if catalog and tool not in catalog:
                # Allow approximate matches — the LLM commonly emits
                # "impacket-getuserspns" but catalog has "impacket-GetUserSPNs"
                lower_catalog = {c.lower(): c for c in catalog}
                cand = lower_catalog.get(tool.lower())
                if cand is None:
                    logger.debug("[web_intel] tool %r not in catalog — skipping", tool)
                    continue
                tool = cand
            # Substitute {TARGET} placeholder
            args_filled = args.replace("{TARGET}", self._target)
            # creds substitution — if intel has them
            if "$USER" in args_filled or "$PASS" in args_filled or "$DOMAIN" in args_filled:
                cuser, cpass, cdom = self._creds_for_subst(intel)
                if not cuser or not cpass:
                    logger.debug(
                        "[web_intel] hint needs creds but none available — skipping"
                    )
                    continue
                args_filled = (args_filled
                               .replace("$USER", cuser)
                               .replace("$PASS", cpass)
                               .replace("$DOMAIN", cdom or ""))

            out.append(ExploitHint(
                tool        = tool,
                args        = args_filled,
                description = (h.get("description") or "")[:300],
                cve         = (h.get("cve") or None) if h.get("cve") not in ("", "null", None) else None,
                mitre       = (h.get("mitre") or None) if h.get("mitre") not in ("", "null", None) else None,
                confidence  = float(h.get("confidence") or 0.6),
                source_url  = h.get("source_url") or None,
                raw_quote   = (h.get("raw_quote") or "")[:200],
            ))
        return out

    @staticmethod
    def _creds_for_subst(intel: dict) -> Tuple[str, str, str]:
        creds = intel.get("credentials") or []
        for c in creds:
            if isinstance(c, dict) and (c.get("user") or "") and (c.get("password") or c.get("pass")):
                return (
                    c.get("user", ""),
                    c.get("password") or c.get("pass") or "",
                    c.get("domain") or "",
                )
        ad = intel.get("ad") or {}
        if isinstance(ad, dict) and ad.get("user") and ad.get("password"):
            return (ad.get("user",""), ad.get("password",""), ad.get("dns_domain") or "")
        return ("", "", "")

    # ── Hypothesis injection ─────────────────────────────────────────
    async def inject_hypotheses(
        self,
        intel:      dict,
        hypotheses: list,
        hints:      List[ExploitHint],
    ) -> int:
        """Convert validated ExploitHints into Hypothesis objects and add
        them to the running ``hypotheses`` list.  Returns the number of
        hypotheses successfully injected."""
        if not hints:
            return 0
        try:
            from agents.reasoning.hypothesis_engine import Hypothesis
        except Exception as exc:
            logger.warning("[web_intel] cannot import Hypothesis class: %s", exc)
            return 0

        injected = 0
        # Group hints by (tool, source_url) — one hypothesis per cluster
        for hint in hints:
            statement = (
                f"Web-intel-derived exploit path: {hint.description or hint.tool} "
                f"({hint.tool})"
            )[:240]
            evidence = []
            if hint.source_url:
                evidence.append(f"Source: {hint.source_url}")
            if hint.raw_quote:
                evidence.append(f"Quote: {hint.raw_quote[:200]}")
            if hint.cve:
                evidence.append(f"CVE: {hint.cve}")

            # NB: Hypothesis dataclass has no evidence_against field — only
            # evidence_supporting / required_evidence.  Pass exactly the
            # fields the dataclass declares (see hypothesis_engine.py:38).
            hyp = Hypothesis(
                hypothesis_id            = f"webintel-{uuid.uuid4().hex[:10]}",
                statement                = statement,
                confidence               = max(0.4, min(0.9, hint.confidence)),
                evidence_supporting      = evidence,
                required_evidence        = [
                    f"Successful execution of {hint.tool} produces shell, "
                    f"credential, or vulnerability confirmation"
                ],
                recommended_next_actions = [f"{hint.tool} {hint.args}"],
                attack_phase             = "exploit",
                mitre_technique          = hint.mitre or None,
            )
            hypotheses.append(hyp)
            injected += 1

        # Also stash the raw hints on intel so the report generator can
        # include them in the engagement narrative.
        intel.setdefault("web_intel_hints", []).extend(h.to_dict() for h in hints)
        return injected

    # ── Internals ────────────────────────────────────────────────────
    async def _emit(self, message: str) -> None:
        try:
            if callable(self._broadcast):
                await self._broadcast({
                    "type":       "reasoning_decision",
                    "session_id": self._session,
                    "agent":      "master",
                    "data":       {"message": message, "component": "web_intel"},
                })
        except Exception:
            pass
        try:
            from utils.scan_logger import log_reasoning as _log_reasoning
            _log_reasoning(
                self._session,
                step       = "web_intel",
                reasoning  = "",
                decision   = message[:600],
                next_action= "",
            )
        except Exception:
            pass
        try:
            logger.info("[web_intel] %s", message)
        except Exception:
            pass
