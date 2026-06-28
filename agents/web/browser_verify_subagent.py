"""agents/web/browser_verify_subagent.py — headless-browser verification (Gap #2).

Confirms web findings that curl CANNOT prove — IDOR, auth-bypass, business-logic,
DOM/reflected-XSS — by driving a real headless Chromium (Playwright), attaches a
PoC artifact, and lets the finding pipeline gate on the result.

Design constraints (founder mandate: make ARGUS better, never break it):
  * ADDITIVE + BEST-EFFORT.  The browser engine is an OPTIONAL dependency: if
    Playwright/Chromium is not installed the whole module degrades to a no-op
    (``is_browser_available()`` → False; ``verify`` → verified=None) and the
    finding keeps its original severity with an honest note.  Nothing here can
    block, gate, or crash the engagement.
  * The decision/credential/classification logic is PURE so it is unit-testable
    without a browser; only ``verify`` touches Playwright (lazy-imported).

Verdict shape: {verified: True|False|None, method, confidence, artifacts:[...],
reason}.  verified True = proven; False = tried and could not prove (downgrade);
None = not attempted (no browser / no creds for this class) → no penalty.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("argus.browser_verify")

# Per-finding wall-clock cap so a slow/JS-heavy app can never stall the pipeline.
_VERIFY_TIMEOUT = int(os.environ.get("ARGUS_BROWSER_VERIFY_TIMEOUT", "60"))
# Master on/off (default on).  Absent Playwright is itself a no-op regardless.
_ENABLED = os.environ.get("ARGUS_BROWSER_VERIFY", "1") != "0"

# ── Classification: which finding classes a browser can actually verify ───────
_CLASS_PATTERNS = [
    ("idor",           re.compile(r"\bidor\b|insecure direct object|broken access|"
                                  r"bola|object reference", re.I)),
    ("auth_bypass",    re.compile(r"auth(entication)?[ -]?bypass|access control|"
                                  r"forced browsing|privilege escal|unauthenti", re.I)),
    ("xss",            re.compile(r"\bxss\b|cross[ -]?site script", re.I)),
    ("business_logic", re.compile(r"business logic|workflow|race condition|"
                                  r"price manipulat|quantity", re.I)),
]


def verifiable_class(finding: Dict[str, Any]) -> Optional[str]:
    """Return the verification recipe key for a finding, or None if a browser
    cannot meaningfully verify it.  Pure."""
    hay = " ".join(str(finding.get(k) or "") for k in
                   ("title", "name", "description", "tags", "cwe", "category")).lower()
    for key, rx in _CLASS_PATTERNS:
        if rx.search(hay):
            return key
    return None


def is_browser_available() -> bool:
    """True only if Playwright is importable (Chromium presence is checked at
    launch).  False on any dev box without the optional dependency."""
    if not _ENABLED:
        return False
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


# ── Credentials: degrade gracefully by how many accounts we have ──────────────
def collect_verify_creds(intel: Dict[str, Any],
                         config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Merge ARGUS-discovered creds + optional operator verification accounts.

    Returns {accounts:[{user,password,...}], mode}: 'cross_user' (>=2),
    'auth_unauth' (==1), or 'unauth' (0).  Pure."""
    accounts: List[Dict[str, Any]] = []
    seen = set()

    def _add(u, p, **extra):
        u = (u or "").strip()
        if not u or u in seen:
            return
        seen.add(u)
        accounts.append({"user": u, "password": (p or ""), **extra})

    # Operator-provided test accounts take priority (most reliable).
    for a in ((config or {}).get("verification_accounts") or []):
        if isinstance(a, dict):
            _add(a.get("user") or a.get("username"), a.get("password") or a.get("pass"),
                 login_url=a.get("login_url"))
    # ARGUS-discovered credentials.
    for c in (intel.get("credentials") or []):
        if isinstance(c, dict):
            _add(c.get("user") or c.get("username") or c.get("login"),
                 c.get("password") or c.get("pass") or c.get("secret"))
        elif isinstance(c, (list, tuple)) and len(c) >= 2:
            _add(c[0], c[1])

    mode = ("cross_user" if len(accounts) >= 2
            else "auth_unauth" if len(accounts) == 1 else "unauth")
    return {"accounts": accounts, "mode": mode}


# ── Verdict application: the gate decision (pure) ─────────────────────────────
def apply_verdict(finding: Dict[str, Any], verdict: Dict[str, Any], *,
                  browser_available: bool, creds_present: bool) -> Dict[str, Any]:
    """Apply a verification verdict to a finding dict (mutates + returns it).

    verified True  → mark verified, attach PoC, add confirmed/directly_exploitable
                     signals so the operational severity policy tags it
                     DEMONSTRATED/CONFIRMED; severity is kept/raised by the policy.
    verified False → downgrade to the 'unverified' report section (never dropped).
    verified None  → not attempted; leave severity untouched, add an honest note.
    Pure — does not touch the browser or DB."""
    if not isinstance(finding.get("extra"), dict):
        finding["extra"] = {}
    extra = finding["extra"]
    v = verdict.get("verified") if isinstance(verdict, dict) else None
    method = (verdict or {}).get("method", "")
    arts   = (verdict or {}).get("artifacts", []) or []
    reason = (verdict or {}).get("reason", "")

    if v is True:
        extra["browser_verified"]   = True
        extra["verification_method"] = method
        if arts:
            extra["poc_artifacts"] = arts
        # Feed the operational severity policy: a browser-confirmed web bug is a
        # CONFIRMED, directly-exploitable weakness (DEMONSTRATED if it yielded data).
        if not isinstance(finding.get("signals"), dict):
            finding["signals"] = {}
        sig = finding["signals"]
        sig["confirmed"] = True
        sig["directly_exploitable"] = True
    elif v is False:
        extra["browser_verified"] = False
        extra["report_section"]   = "unverified"
        extra["unverified_reason"] = reason or "browser verification could not prove this finding"
        # Downgrade: an unproven web claim should not sit at high severity.
        finding["severity"] = "LOW" if str(finding.get("severity", "")).isupper() else "low"
    else:
        extra["browser_verified"] = None
        if not browser_available:
            extra["unverified_reason"] = "headless browser unavailable (install playwright)"
        elif not creds_present:
            extra["unverified_reason"] = reason or "no credentials available for cross-user verification"
        else:
            extra["unverified_reason"] = reason or "not attempted"
    return finding


# ── The browser engine (isolated; lazy Playwright import) ─────────────────────
def _host_match(a: str, b: str) -> bool:
    """Exact host or proper sub-domain match — NEVER an arbitrary substring
    ('admin' must not match 'admin.evil.com', and 'evil.com' must not match
    'notevil.com')."""
    a, b = (a or "").lower().strip(), (b or "").lower().strip()
    return bool(a) and bool(b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def _in_scope(host: str, intel: Dict[str, Any]) -> bool:
    if not host:
        return False
    scope = [str(s).lower() for s in (intel.get("target_scope") or []) if s]
    tgt = str(intel.get("target_host") or intel.get("target") or "").lower()
    if scope:
        return any(_host_match(host, s) for s in scope)
    # No explicit scope list → must match the engagement target (or, in the
    # subagent path where only the finding's own host is known, that host is the
    # target by construction).
    return _host_match(host, tgt) or not tgt


def _url_of(finding: Dict[str, Any], intel: Dict[str, Any]) -> str:
    u = (finding.get("url") or finding.get("endpoint") or finding.get("evidence") or "")
    m = re.search(r"https?://[^\s'\"]+", str(u))
    if m:
        return m.group(0)
    host = finding.get("host") or intel.get("target_host") or intel.get("target") or ""
    port = finding.get("port")
    scheme = "https" if str(port) in ("443", "8443") else "http"
    return f"{scheme}://{host}" + (f":{port}" if port and str(port) not in ("80", "443") else "")


async def verify(finding: Dict[str, Any], intel: Dict[str, Any],
                 config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Drive a headless browser to confirm a finding.  Import-safe + best-effort:
    returns verified=None (never raises) when the browser is unavailable, the
    target is out of scope, or anything goes wrong.  Real recipes run on Kali."""
    cls = verifiable_class(finding)
    if cls is None:
        return {"verified": None, "reason": "not a browser-verifiable class"}
    if not is_browser_available():
        return {"verified": None, "reason": "headless browser unavailable"}
    url = _url_of(finding, intel)
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
    if not _in_scope(host, intel):
        return {"verified": None, "reason": f"target {host} out of scope"}
    # Skip launching a browser for cross-user IDOR when we lack two accounts.
    if cls == "idor" and collect_verify_creds(intel, config or {}).get("mode") != "cross_user":
        return {"verified": None, "method": "idor-cross-user",
                "reason": "need >=2 accounts for cross-user IDOR proof"}
    try:
        return await asyncio.wait_for(
            _run_recipe(cls, finding, url, intel, config or {}), timeout=_VERIFY_TIMEOUT)
    except asyncio.TimeoutError:
        return {"verified": None, "reason": f"verification timed out ({_VERIFY_TIMEOUT}s)"}
    except Exception as exc:                                  # pragma: no cover
        logger.debug("browser verify failed: %s", exc)
        return {"verified": None, "reason": f"browser error: {type(exc).__name__}"}


async def _run_recipe(cls: str, finding: Dict[str, Any], url: str,
                      intel: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Per-class Playwright recipe.  Lazy-imports Playwright so the module loads
    without it.  Captures PoC artifacts (screenshots) on a proven finding."""
    from playwright.async_api import async_playwright   # lazy

    creds = collect_verify_creds(intel, config)
    artifacts: List[Dict[str, Any]] = []
    art_dir = _artifact_dir(intel)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            if cls == "xss":
                return await _verify_xss(browser, url, art_dir, artifacts)
            if cls == "auth_bypass":
                return await _verify_auth_bypass(browser, url, creds, art_dir, artifacts)
            if cls == "idor":
                return await _verify_idor(browser, url, finding, creds, art_dir, artifacts)
            # business_logic: best-effort, not auto-provable yet
            return {"verified": None, "reason": "business-logic recipe needs a manual flow",
                    "method": "business_logic"}
        finally:
            await browser.close()


async def _new_ctx(browser):
    return await browser.new_context(ignore_https_errors=True)


async def _shot(page, art_dir, artifacts, name):
    try:
        path = os.path.join(art_dir, name) if art_dir else None
        if path:
            await page.screenshot(path=path, full_page=False)
            artifacts.append({"type": "screenshot", "path": path})
    except Exception:
        pass


async def _verify_xss(browser, url, art_dir, artifacts) -> Dict[str, Any]:
    ctx = await _new_ctx(browser)
    page = await ctx.new_page()
    fired = {"hit": False}
    page.on("dialog", lambda d: (fired.__setitem__("hit", True), asyncio.ensure_future(d.dismiss())))
    try:
        await page.goto(url, wait_until="load", timeout=20000)
        await _shot(page, art_dir, artifacts, "xss.png")
        # Proof of execution = the payload actually FIRED a dialog.  Mere presence
        # of a <script> tag on the page is NOT proof (every site has scripts).
        if fired["hit"]:
            return {"verified": True, "method": "dom-xss-dialog", "confidence": 0.9,
                    "artifacts": artifacts, "reason": "payload executed (dialog fired)"}
        return {"verified": False, "method": "dom-xss", "confidence": 0.5,
                "artifacts": artifacts, "reason": "payload did not execute in the DOM"}
    finally:
        await ctx.close()


async def _verify_auth_bypass(browser, url, creds, art_dir, artifacts) -> Dict[str, Any]:
    ctx = await _new_ctx(browser)
    page = await ctx.new_page()
    try:
        resp = await page.goto(url, wait_until="load", timeout=20000)
        status = resp.status if resp else 0
        body = (await page.content()).lower()
        await _shot(page, art_dir, artifacts, "auth_bypass.png")
        is_login = any(k in body for k in ("login", "sign in", "password", "unauthorized", "forbidden"))
        if status == 200 and not is_login:
            return {"verified": True, "method": "unauth-protected-access", "confidence": 0.75,
                    "artifacts": artifacts,
                    "reason": "protected resource returned content without auth"}
        return {"verified": False, "method": "unauth-protected-access", "confidence": 0.6,
                "artifacts": artifacts, "reason": f"got status {status} / login surface"}
    finally:
        await ctx.close()


async def _verify_idor(browser, url, finding, creds, art_dir, artifacts) -> Dict[str, Any]:
    if creds.get("mode") != "cross_user":
        return {"verified": None, "method": "idor-cross-user",
                "reason": "need >=2 accounts for cross-user IDOR proof"}
    a, b = creds["accounts"][0], creds["accounts"][1]
    body_a = await _fetch_as(browser, url, a, art_dir, artifacts, "idor_a.png")
    body_b = await _fetch_as(browser, url, b, art_dir, artifacts, "idor_b.png")
    if body_a is None or body_b is None:
        return {"verified": None, "method": "idor-cross-user",
                "reason": "could not establish both sessions"}
    # If user B can read the SAME resource content user A sees, it is IDOR.
    overlap = _content_overlap(body_a, body_b)
    if overlap > 0.6 and len(body_b) > 80:
        return {"verified": True, "method": "idor-cross-user", "confidence": 0.85,
                "artifacts": artifacts,
                "reason": f"user B read user A's resource (overlap {overlap:.0%})"}
    return {"verified": False, "method": "idor-cross-user", "confidence": 0.6,
            "artifacts": artifacts, "reason": "user B did not get user A's content"}


async def _fetch_as(browser, url, account, art_dir, artifacts, shot) -> Optional[str]:
    ctx = await _new_ctx(browser)
    page = await ctx.new_page()
    try:
        login_url = account.get("login_url")
        if login_url:
            await page.goto(login_url, wait_until="load", timeout=20000)
            try:
                await page.fill("input[type=text], input[name*=user], input[name*=email]",
                                account["user"], timeout=4000)
                await page.fill("input[type=password], input[name*=pass]",
                                account.get("password", ""), timeout=4000)
                await page.click("button[type=submit], input[type=submit], button", timeout=4000)
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
            # Confirm the session is actually authenticated; otherwise a cross-user
            # IDOR "match" would just be two identical login/error pages (a false
            # positive).  If still on a password form / error and no authed marker,
            # treat login as failed and skip this account.
            _lb = (await page.content()).lower()
            _authed = any(k in _lb for k in ("logout", "sign out", "log out",
                                             "dashboard", "my account", "profile"))
            _stuck = any(k in _lb for k in ('type="password"', 'name="password"',
                                            "invalid", "incorrect", "try again"))
            if _stuck and not _authed:
                return None
        resp = await page.goto(url, wait_until="load", timeout=20000)
        await _shot(page, art_dir, artifacts, shot)
        return (await page.content()) if resp else None
    except Exception:
        return None
    finally:
        await ctx.close()


def _content_overlap(a: str, b: str) -> float:
    """Crude token-overlap ratio between two response bodies."""
    ta = set(re.findall(r"\w{4,}", (a or "").lower())[:2000])
    tb = set(re.findall(r"\w{4,}", (b or "").lower())[:2000])
    if not ta:
        return 0.0
    return len(ta & tb) / float(len(ta))


def _artifact_dir(intel: Dict[str, Any]) -> str:
    try:
        sid = str(intel.get("session_id") or intel.get("scan_id") or "default")
        base = os.environ.get("ARGUS_ARTIFACT_DIR", os.path.join("logs", "poc_artifacts"))
        d = os.path.join(base, sid)
        os.makedirs(d, exist_ok=True)
        return d
    except Exception:
        return ""
