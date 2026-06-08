"""
cve_lookup.py — self-contained "product (+version) -> known CVEs + public PoCs".

The single most basic pentest reflex ARGUS was missing.  On the ReactorWatch box
ARGUS detected "Next.js" and the operator *talked about* a 2025 CVE 21 times, yet
it never pinned the version, never looked up the actual CVE, and never fetched the
public exploit — so it failed a box whose foothold was a KNOWN public CVE
(CVE-2025-55182, "React2Shell") with a GitHub PoC.

This module gives the operator a real, multi-source lookup it can call directly
and synchronously, with NO coupling to the OSINT agent's internals:

  • NVD 2.0 REST API        — official CVE records for a keyword/product+version
  • GitHub repository search — the fastest path to a PUBLIC PoC/exploit repo
                               (this is what surfaces fresh CVEs NVD lags on)
  • searchsploit (local)     — Exploit-DB offline copy, if installed

Everything is best-effort and never raises: a lookup that can't reach the
network simply returns fewer results.  Auth tokens (NVD_API_KEY / GITHUB_TOKEN)
are honoured for higher rate limits but are optional.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

try:
    import httpx
except Exception:   # pragma: no cover
    httpx = None

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GH_REPO_URL = "https://api.github.com/search/repositories"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


async def lookup(product: str, version: str = "", *,
                 limit: int = 8, timeout: int = 25) -> Dict[str, Any]:
    """Return {query, cves:[...], pocs:[...], searchsploit:[...]} for a product.

    `version` is optional but sharpens results.  Always returns a dict; on any
    failure the corresponding list is simply empty.
    """
    product = (product or "").strip()
    if not product:
        return {"query": "", "cves": [], "pocs": [], "searchsploit": []}

    cves = await _nvd(product, version, limit=limit, timeout=timeout)
    pocs = await _github(product, version, cves, limit=limit, timeout=timeout)
    sploits = _searchsploit(product, version)
    return {
        "query": f"{product} {version}".strip(),
        "cves": cves,
        "pocs": pocs,
        "searchsploit": sploits,
    }


def _relevance(text: str, cve_id: str, product: str, version: str) -> float:
    t = (text or "").lower()
    score = 0.0
    if version and version.lower() in t:
        score += 5.0
    # Recent CVEs are far more likely to be the intended foothold on a CTF box.
    m = re.match(r"cve-(\d{4})-", (cve_id or "").lower())
    if m:
        try:
            yr = int(m.group(1))
            score += max(0, (yr - 2018)) * 0.5
        except Exception:
            pass
    for kw in ("remote code execution", "rce", "deserial", "command injection",
               "unauthenticated", "arbitrary code", "ssrf", "path traversal"):
        if kw in t:
            score += 1.0
    return score


async def _nvd(product: str, version: str, *, limit: int, timeout: int) -> List[Dict[str, Any]]:
    if httpx is None:
        return []
    kw = f"{product} {version}".strip()
    headers = {}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    out: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(NVD_URL,
                            params={"keywordSearch": kw, "resultsPerPage": 40},
                            headers=headers)
            if r.status_code != 200:
                return []
            data = r.json()
        for item in (data.get("vulnerabilities") or []):
            cve = item.get("cve") or {}
            cid = cve.get("id", "")
            descs = cve.get("descriptions") or []
            desc = next((d.get("value", "") for d in descs
                         if d.get("lang") == "en"), "")
            sev = ""
            metrics = cve.get("metrics") or {}
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(mk) or []
                if arr:
                    cd = arr[0].get("cvssData", {}) or {}
                    sev = cd.get("baseSeverity", "") or str(cd.get("baseScore", ""))
                    break
            out.append({
                "cve": cid, "severity": sev, "summary": desc[:300],
                "_score": _relevance(desc, cid, product, version),
            })
        out.sort(key=lambda x: -x["_score"])
        for o in out:
            o.pop("_score", None)
        return out[:limit]
    except Exception:
        return []


async def _github(product: str, version: str, cves: List[Dict[str, Any]], *,
                  limit: int, timeout: int) -> List[Dict[str, Any]]:
    if httpx is None:
        return []
    queries: List[str] = []
    if version:
        queries.append(f"{product} {version} RCE")
    queries += [f"{product} RCE exploit", f"{product} CVE PoC"]
    for cv in cves[:3]:
        if cv.get("cve"):
            queries.append(cv["cve"])
    headers = {"Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    seen = set()
    out: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            for q in queries[:6]:
                try:
                    r = await c.get(GH_REPO_URL,
                                    params={"q": q, "sort": "stars",
                                            "order": "desc", "per_page": 5},
                                    headers=headers)
                    if r.status_code != 200:
                        continue
                    for it in (r.json().get("items") or []):
                        url = it.get("html_url", "")
                        if not url or url in seen:
                            continue
                        seen.add(url)
                        desc = it.get("description") or ""
                        out.append({
                            "repo": it.get("full_name", ""),
                            "url": url,
                            "stars": it.get("stargazers_count", 0),
                            "desc": desc[:160],
                            "cves": sorted(set(m.upper() for m in
                                               _CVE_RE.findall(it.get("full_name", "") + " " + desc))),
                        })
                except Exception:
                    continue
        out.sort(key=lambda x: -x.get("stars", 0))
        return out[:limit]
    except Exception:
        return []


def _searchsploit(product: str, version: str) -> List[Dict[str, str]]:
    if not shutil.which("searchsploit"):
        return []
    term = f"{product} {version}".strip()
    try:
        r = subprocess.run(["searchsploit", "--json", term],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout or "{}")
        out = []
        for e in (data.get("RESULTS_EXPLOIT") or [])[:8]:
            out.append({"title": e.get("Title", ""), "path": e.get("Path", "")})
        return out
    except Exception:
        return []


def _poc_rce_rank(poc: Dict[str, Any]) -> float:
    """Rank a PoC repo: RCE/exploit-named + CVE-tagged + stars float to the top.

    The operator on the Reactor box was handed an RCE PoC but got buried under
    low-severity SSRF/DoS NVD noise; this makes the weaponisable repo win."""
    blob = (str(poc.get("repo", "")) + " " + str(poc.get("desc", ""))).lower()
    # Weaponisability must DOMINATE raw stars — a 30-star RCE PoC beats a
    # 2000-star "awesome-nextjs" list.  Stars are only a tiebreaker.
    score = 0.0
    if any(k in blob for k in ("rce", "shell", "exec", "deserial", "command")):
        score += 1000
    if poc.get("cves"):
        score += 500
    score += min(float(poc.get("stars", 0)), 500) * 0.1
    return score


def format_result(res: Dict[str, Any]) -> str:
    """Operator-readable rendering, biased to ACT on a public exploit.

    Leads with an imperative when a PoC exists, ranks RCE PoCs first, and DROPS
    low-severity NVD noise when a real exploit repo is available — so the
    operator commits to running the PoC instead of wandering across SSRF/DoS
    CVEs (the exact failure on the Reactor box)."""
    if not res or not (res.get("cves") or res.get("pocs") or res.get("searchsploit")):
        return (f"cve_lookup('{res.get('query','')}'): no CVEs/PoCs found. "
                "Pin a more exact product+version, or the service may have no "
                "known public exploit (pivot to manual testing).")
    lines = [f"cve_lookup: {res.get('query','')}"]
    pocs = sorted(res.get("pocs") or [], key=_poc_rce_rank, reverse=True)
    if pocs:
        top = pocs[0]
        cvet = (" (" + ",".join(top["cves"]) + ")") if top.get("cves") else ""
        lines.append(
            "→ ACTION: a PUBLIC EXPLOIT exists for this stack. Your next steps: "
            f"`git clone {top.get('url','')}`{cvet}, read it, then RUN it against "
            "the target (adapt LHOST/URL). Do this BEFORE more enumeration, and "
            "do NOT hand-roll the exploit — use the public PoC.")
        lines.append("PUBLIC PoC / exploit repos (most weaponisable first):")
        for p in pocs[:6]:
            cvetag = (" " + ",".join(p["cves"])) if p.get("cves") else ""
            lines.append(f"  ★{p.get('stars',0)} {p.get('url','')}{cvetag}"
                         f"  — {p.get('desc','')}")
    # NVD list: when a PoC exists, drop LOW-severity noise and cap hard so the
    # weaponisable lead is not diluted by DoS/info-disclosure CVEs.
    cves = res.get("cves") or []
    if pocs:
        cves = [c for c in cves if str(c.get("severity", "")).upper()
                not in ("LOW", "NONE", "")][:4]
    if cves:
        lines.append("NVD CVEs (context):")
        for c in cves[:6]:
            lines.append(f"  {c.get('cve','')} [{c.get('severity','')}] {c.get('summary','')[:160]}")
    if res.get("searchsploit"):
        lines.append("searchsploit (Exploit-DB local):")
        for s in res["searchsploit"][:6]:
            lines.append(f"  {s.get('title','')}  ({s.get('path','')})")
    return "\n".join(lines)
