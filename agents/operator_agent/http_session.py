"""
http_session.py — stateful HTTP session for the operator core.

This is the single biggest capability ARGUS lacked.  The legacy pipeline ran
one-shot tools (a fresh `curl` per call) that could not carry a cookie, a CSRF
token, or an auth header from one request to the next — so it could never do
the register → login → authenticated-exploration → exploit flow that every
modern web box (and the SmartHire loss) requires.

HttpSession wraps ONE persistent httpx.AsyncClient so cookies and connection
state accumulate across requests, exactly like a browser / a human tester with
a cookie jar.  It adds the small amount of HTML smarts an operator needs:
form discovery, CSRF-token extraction, link/title extraction, and a compact
text summary suitable for dropping straight into the operator's transcript.

Pure helpers (extract_forms / extract_csrf / extract_title / extract_links)
are module-level and dependency-free (regex only) so they are unit-testable
without a live target.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    import httpx
except Exception:   # pragma: no cover - httpx is a hard dep elsewhere
    httpx = None


# ── Pure HTML helpers (regex; no bs4 dependency) ────────────────────────────

_FORM_RE  = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*>", re.I)
_ATTR_RE  = re.compile(r"""(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s">]+))""")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_LINK_RE  = re.compile(r"""<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s">]+))""", re.I)
_CSRF_HINT = ("csrf", "authenticity_token", "_token", "xsrf", "nonce", "__requestverificationtoken")


def _attrs(tag: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag or ""):
        key = (m.group(1) or "").lower()
        val = m.group(2) or m.group(3) or m.group(4) or ""
        out[key] = val
    return out


def extract_forms(html: str) -> List[Dict[str, Any]]:
    """Return every <form> as {action, method, inputs:{name:value}, ...}.

    This is what lets the operator see "there is a login form posting to
    /login with fields username, password, csrf_token" and fill it correctly.
    """
    forms: List[Dict[str, Any]] = []
    if not html:
        return forms
    # Re-scan for the opening <form ...> tag attrs separately from the body,
    # since _FORM_RE captures only the inner body.
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.I | re.S):
        head_attrs = _attrs("<form " + (fm.group(1) or "") + ">")
        body = fm.group(2) or ""
        inputs: Dict[str, str] = {}
        input_meta: List[Dict[str, str]] = []
        for tag in _INPUT_RE.findall(body):
            a = _attrs(tag)
            name = a.get("name") or a.get("id") or ""
            if not name:
                continue
            inputs[name] = a.get("value", "")
            input_meta.append({
                "name": name,
                "type": a.get("type", "text"),
                "value": a.get("value", ""),
            })
        forms.append({
            "action": head_attrs.get("action", ""),
            "method": (head_attrs.get("method", "get") or "get").lower(),
            "id":     head_attrs.get("id", ""),
            "inputs": inputs,
            "input_meta": input_meta,
        })
    return forms


def extract_csrf(html: str) -> Optional[Dict[str, str]]:
    """Find the most likely CSRF/anti-forgery hidden field as {name: value}."""
    if not html:
        return None
    for tag in _INPUT_RE.findall(html):
        a = _attrs(tag)
        name = (a.get("name") or "").lower()
        if any(h in name for h in _CSRF_HINT):
            return {"name": a.get("name", ""), "value": a.get("value", "")}
    # Also catch <meta name="csrf-token" content="...">
    m = re.search(
        r"""<meta\b[^>]*name\s*=\s*['"]?csrf-token['"]?[^>]*content\s*=\s*['"]([^'"]+)['"]""",
        html, re.I)
    if m:
        return {"name": "csrf-token", "value": m.group(1)}
    return None


def extract_title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    return re.sub(r"\s+", " ", (m.group(1) if m else "")).strip()[:200]


def extract_links(html: str, base_url: str = "") -> List[str]:
    links: List[str] = []
    seen = set()
    for m in _LINK_RE.finditer(html or ""):
        href = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        full = urljoin(base_url, href) if base_url else href
        if full not in seen:
            seen.add(full)
            links.append(full)
    return links[:80]


# ── The stateful session ────────────────────────────────────────────────────

class HttpSession:
    """One persistent client whose cookies/auth survive across requests.

    Optional vhost routing: when ``target_ip`` is set and a request carries a
    ``host`` (or an explicit Host header), the connection is made to the IP
    while the Host header is sent as given — so models.smarthire.htb can be
    reached even without an /etc/hosts entry, over plain HTTP.  (For HTTPS the
    operator should add the hosts entry via the shell tool; SNI makes IP-rewrite
    unreliable, so we leave the URL untouched there.)
    """

    def __init__(self, *, target_ip: Optional[str] = None, verify: bool = False,
                 timeout: float = 20.0, follow_redirects: bool = True,
                 user_agent: str = "Mozilla/5.0 (ARGUS-Operator)"):
        if httpx is None:
            raise RuntimeError("httpx is required for HttpSession")
        self._client = httpx.AsyncClient(
            verify=verify,
            timeout=httpx.Timeout(timeout),
            follow_redirects=follow_redirects,
            headers={"User-Agent": user_agent},
        )
        self._target_ip = target_ip
        self.history: List[Dict[str, Any]] = []
        self.auth_state: Dict[str, Any] = {"logged_in": False, "user": None}

    # -- core ----------------------------------------------------------------
    async def request(self, method: str, url: str, *,
                      headers: Optional[Dict[str, str]] = None,
                      data: Any = None, json: Any = None,
                      params: Any = None, host: Optional[str] = None,
                      follow_redirects: Optional[bool] = None) -> Dict[str, Any]:
        method = (method or "GET").upper()
        req_headers = dict(headers or {})
        connect_url = url

        # vhost routing over plain HTTP: connect to IP, send Host header.
        host_hdr = host or req_headers.get("Host") or req_headers.get("host")
        if host_hdr and self._target_ip and url.lower().startswith("http://"):
            parts = urlsplit(url)
            netloc_host = parts.hostname or host_hdr
            if netloc_host != self._target_ip:
                new_netloc = self._target_ip + (f":{parts.port}" if parts.port else "")
                connect_url = urlunsplit((parts.scheme, new_netloc, parts.path,
                                          parts.query, parts.fragment))
                req_headers["Host"] = host_hdr

        try:
            resp = await self._client.request(
                method, connect_url, headers=req_headers or None,
                data=data, json=json, params=params,
                follow_redirects=(self.follow_default
                                  if follow_redirects is None else follow_redirects),
            )
        except Exception as exc:   # noqa: BLE001
            err = {"error": f"{type(exc).__name__}: {exc}", "url": url,
                   "method": method, "status": 0, "body": "", "forms": [],
                   "cookies": self.cookies}
            self.history.append({"method": method, "url": url, "status": 0,
                                 "error": err["error"]})
            return err

        result = self._build_result(resp, requested_url=url)
        self.history.append({"method": method, "url": result["url"],
                             "status": result["status"], "len": result["length"]})
        return result

    @property
    def follow_default(self) -> bool:
        return self._client.follow_redirects

    async def get(self, url: str, **kw) -> Dict[str, Any]:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Dict[str, Any]:
        return await self.request("POST", url, **kw)

    # -- convenience flows ---------------------------------------------------
    async def submit_form(self, page_url: str, *, action: Optional[str] = None,
                          fields: Optional[Dict[str, str]] = None,
                          method: str = "POST", host: Optional[str] = None,
                          fetch_first: bool = True) -> Dict[str, Any]:
        """Fetch a page, merge any discovered form defaults + CSRF token with
        the caller's fields, and submit.  This is the register/login primitive.
        """
        merged: Dict[str, str] = {}
        target_action = action or page_url
        if fetch_first:
            page = await self.get(page_url, host=host)
            forms = page.get("forms") or []
            if forms:
                merged.update(forms[0].get("inputs") or {})
                if not action and forms[0].get("action"):
                    target_action = urljoin(page.get("url") or page_url,
                                            forms[0]["action"])
            csrf = extract_csrf(page.get("body") or "")
            if csrf and csrf.get("name"):
                merged[csrf["name"]] = csrf["value"]
        if fields:
            merged.update(fields)
        return await self.request(method, target_action, data=merged, host=host)

    def mark_logged_in(self, user: Optional[str]) -> None:
        self.auth_state = {"logged_in": True, "user": user}

    # -- introspection -------------------------------------------------------
    @property
    def cookies(self) -> Dict[str, str]:
        try:
            return {c.name: c.value for c in self._client.cookies.jar}
        except Exception:
            return dict(self._client.cookies)

    def _build_result(self, resp, *, requested_url: str) -> Dict[str, Any]:
        try:
            body = resp.text
        except Exception:
            body = ""
        return {
            "status":      resp.status_code,
            "url":         str(resp.url),
            "requested":   requested_url,
            "headers":     {k: v for k, v in resp.headers.items()},
            "set_cookie":  resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [],
            "cookies":     self.cookies,
            "title":       extract_title(body),
            "forms":       extract_forms(body),
            "csrf":        extract_csrf(body),
            "links":       extract_links(body, str(resp.url)),
            "length":      len(body),
            "body":        body,
            "body_excerpt": body[:4000],
        }

    def summarize(self, result: Dict[str, Any], *, body_chars: int = 1500) -> str:
        """Compact text rendering of a response for the operator transcript."""
        if result.get("error"):
            return f"HTTP ERROR {result.get('method','')} {result.get('url','')}: {result['error']}"
        lines = [
            f"HTTP {result['status']}  {result['url']}  ({result['length']} bytes)",
        ]
        if result.get("title"):
            lines.append(f"title: {result['title']}")
        ct = result.get("headers", {}).get("content-type", "")
        if ct:
            lines.append(f"content-type: {ct}")
        loc = result.get("headers", {}).get("location", "")
        if loc:
            lines.append(f"redirect -> {loc}")
        if result.get("cookies"):
            lines.append("cookies: " + ", ".join(result["cookies"].keys()))
        forms = result.get("forms") or []
        for i, f in enumerate(forms[:4]):
            names = ",".join((f.get("inputs") or {}).keys())
            lines.append(f"form[{i}] {f.get('method','get').upper()} "
                         f"{f.get('action','') or '(self)'} fields=[{names}]")
        if result.get("csrf"):
            lines.append(f"csrf field: {result['csrf'].get('name')}")
        body = result.get("body") or ""
        if body:
            lines.append("body:")
            lines.append(body[:body_chars])
        return "\n".join(lines)

    async def close(self) -> None:
        try:
            await self._client.aclose()
        except Exception:
            pass
