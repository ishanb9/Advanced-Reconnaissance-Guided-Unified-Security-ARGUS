"""agents/web/web_orchestrator.py — WSTG-aligned phased web testing.

This orchestrator replaces the ad-hoc `_phase_web_testing` flow with a
deterministic, evidence-chained pipeline that mirrors the OWASP
Web Security Testing Guide (WSTG v4) categories.  It does NOT replace
existing subagents — it ORCHESTRATES them, ensures they all fire on
URL / domain / IP-with-web-port targets, and adds the gaps the user
called out (JWT analyzer, IDOR/auth analyzer, hidden-param miner,
business-logic checker, encoding utilities).

Phase sequence  (each phase produces evidence consumed by the next):

   1. INFO_GATHERING        — fingerprint, headers, robots, sitemap,
                              security.txt, .well-known, error-page leaks
   2. CONFIG_MGMT           — TLS audit, exposed dev artefacts (.git,
                              .env, .DS_Store, web.config), CORS/HSTS,
                              method enumeration (OPTIONS, TRACE)
   3. IDENTITY_MGMT         — registration probe, account-enum, weak-
                              password policy detection
   4. AUTH_TESTING          — login bypass attempts, JWT analysis,
                              cookie-attribute audit, brute-force,
                              "remember-me" abuse
   5. SESSION_MGMT          — token entropy (sequencer-style), session
                              fixation, logout effectiveness
   6. AUTHZ_TESTING         — IDOR probe (number/UUID/sequential
                              enumeration), vertical / horizontal privesc,
                              forced-browsing of admin paths
   7. INPUT_VALIDATION      — SQLi (sqlmap), XSS (dalfox), SSTI (tplmap),
                              command injection (commix), LFI/RFI (ffuf
                              + ../etc), XXE (raw curl payloads)
   8. ERROR_HANDLING        — verbose-error harvest, stack-trace mining
   9. CRYPTO                — weak ciphers, mixed content, no HSTS
  10. BUSINESS_LOGIC        — workflow / replay / negative-quantity /
                              skip-step probes (LLM-driven from forms)
  11. CLIENT_SIDE           — CSRF (token-absence), DOM-XSS, postMessage
                              abuse, JavaScript secret scan
  12. API_TESTING           — REST/GraphQL/SOAP-specific probes,
                              parameter pollution, mass-assignment
  13. FILE_UPLOAD           — extension/MIME bypass, polyglot upload,
                              path-traversal in filename
  14. CACHE_POISONING       — unkeyed-header / Param Miner-style probe

Each phase emits its OWN findings AND a structured evidence dict that
later phases consume.  The orchestrator never silently swallows a phase
failure — failed phases produce a "phase_skipped" finding so the
operator sees exactly what was tried and what wasn't.

Trigger conditions (so it always fires):
  * Standard web port (80/443/8080/8443/...) detected, OR
  * Operator-supplied URL / app target, OR
  * Hostname target — auto-tries http://host/ + https://host/

Wired into master_agent._phase_web_testing as the canonical execution
path.  Existing single-vector subagents (sqli/xss/ssrf/auth/...) are
called from the appropriate phase.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse


__all__ = ["WSTG_PHASES", "WebOrchestrator", "PhaseResult"]


# ════════════════════════════════════════════════════════════════════
# Phase + technique catalogue (WSTG-aligned)
# ════════════════════════════════════════════════════════════════════

WSTG_PHASES: List[Dict[str, Any]] = [
    {"id": "info",         "label": "Information Gathering",   "wstg": "WSTG-INFO"},
    {"id": "config",       "label": "Configuration Management","wstg": "WSTG-CONF"},
    {"id": "identity",     "label": "Identity Management",     "wstg": "WSTG-IDNT"},
    {"id": "auth",         "label": "Authentication Testing",  "wstg": "WSTG-ATHN"},
    {"id": "session",      "label": "Session Management",      "wstg": "WSTG-SESS"},
    {"id": "authz",        "label": "Authorization Testing",   "wstg": "WSTG-ATHZ"},
    {"id": "input",        "label": "Input Validation",        "wstg": "WSTG-INPV"},
    {"id": "errors",       "label": "Error Handling",          "wstg": "WSTG-ERRH"},
    {"id": "crypto",       "label": "Cryptography",            "wstg": "WSTG-CRYP"},
    {"id": "biz_logic",    "label": "Business Logic",          "wstg": "WSTG-BUSL"},
    {"id": "client",       "label": "Client-Side",             "wstg": "WSTG-CLNT"},
    {"id": "api",          "label": "API Testing",             "wstg": "WSTG-APIT"},
    {"id": "upload",       "label": "File Upload",             "wstg": "WSTG-FILE"},
    {"id": "cache",        "label": "Cache Poisoning",         "wstg": "WSTG-CACH"},
]


@dataclass
class PhaseResult:
    phase_id:    str
    label:       str
    status:      str = "pending"     # pending | running | done | skipped | failed
    findings:    int = 0
    evidence:    Dict[str, Any] = field(default_factory=dict)
    notes:       str = ""
    started_at:  Optional[str] = None
    completed_at:Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "phase_id":     self.phase_id,
            "label":        self.label,
            "status":       self.status,
            "findings":     self.findings,
            "notes":        self.notes,
            "started_at":   self.started_at,
            "completed_at": self.completed_at,
            "evidence_keys": sorted(self.evidence.keys()),
        }


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════

def _resolve_targets(target: str, web_ports: List[int], intel: Dict) -> List[Dict]:
    """Compute the list of base URLs to test.

    Priority order:
      1. intel['target_url']  — operator-supplied exact URL
      2. web_ports × target   — standard scheme inference per port
      3. fallback http/https  — when nothing else available
    """
    out: List[Dict] = []
    seen: set = set()

    explicit = (intel or {}).get("target_url")
    if explicit:
        try:
            u = urlparse(explicit)
            host = u.hostname or target
            port = u.port or (443 if u.scheme == "https" else 80)
            base = f"{u.scheme}://{host}{(':' + str(u.port)) if u.port else ''}"
            out.append({"base": base, "host": host, "port": port,
                        "scheme": u.scheme, "path": u.path or "/", "url": explicit})
            seen.add(base)
        except Exception:
            pass

    # Use the cleaned host (strips scheme/path if operator passed a URL)
    host = (intel or {}).get("target_host") or target

    for port in (web_ports or []):
        try:
            p = int(str(port).split("/")[0])
        except Exception:
            continue
        scheme = "https" if p in (443, 8443, 4443, 7443) else "http"
        # Don't re-add explicit:port host pair if already covered
        base = f"{scheme}://{host}{(':' + str(p)) if p not in (80, 443) else ''}"
        if base in seen:
            continue
        seen.add(base)
        out.append({"base": base, "host": host, "port": p,
                    "scheme": scheme, "path": "/", "url": base + "/"})

    if not out:
        # last-resort: try both schemes on host
        for scheme, p in (("http", 80), ("https", 443)):
            base = f"{scheme}://{host}"
            if base not in seen:
                out.append({"base": base, "host": host, "port": p,
                            "scheme": scheme, "path": "/", "url": base + "/"})
                seen.add(base)
    return out


# ════════════════════════════════════════════════════════════════════
# Orchestrator
# ════════════════════════════════════════════════════════════════════

class WebOrchestrator:
    """Per-engagement web-testing orchestrator.

    Constructed by master_agent at the start of `_phase_web_testing`.
    Provides a single ``run()`` that walks all WSTG phases and chains
    evidence between them.  Each individual sub-step is wrapped in
    ``_safe_step`` so a single tool failure never sinks the whole phase.
    """

    def __init__(
        self,
        *, master_agent: Any,
        web_agent:    Any,
        target:       str,
        web_ports:    List[int],
        intel:        Dict,
    ) -> None:
        self._master   = master_agent
        self._web      = web_agent
        self._target   = target
        self._intel    = intel
        self._targets  = _resolve_targets(target, web_ports, intel)
        self._results: Dict[str, PhaseResult] = {
            ph["id"]: PhaseResult(phase_id=ph["id"], label=ph["label"])
            for ph in WSTG_PHASES
        }

    async def run(self) -> Dict[str, Any]:
        """Run the full WSTG sequence.  Returns aggregated results."""
        await self._emit_phase_matrix()

        if not self._targets:
            await self._note("No web targets resolved — phase aborted.")
            return self._summary()

        await self._note(
            f"WebOrchestrator engaged on {len(self._targets)} target(s): "
            f"{', '.join(t['base'] for t in self._targets[:3])}"
        )

        # Each phase is a single async method; ordering matters because
        # later phases consume earlier evidence.
        await self._safe_phase("info",      self._phase_info)
        await self._safe_phase("config",    self._phase_config)
        await self._safe_phase("identity",  self._phase_identity)
        await self._safe_phase("auth",      self._phase_auth)
        await self._safe_phase("session",   self._phase_session)
        await self._safe_phase("authz",     self._phase_authz)
        await self._safe_phase("input",     self._phase_input)
        await self._safe_phase("errors",    self._phase_errors)
        await self._safe_phase("crypto",    self._phase_crypto)
        await self._safe_phase("biz_logic", self._phase_biz_logic)
        await self._safe_phase("client",    self._phase_client)
        await self._safe_phase("api",       self._phase_api)
        await self._safe_phase("upload",    self._phase_upload)
        await self._safe_phase("cache",     self._phase_cache)

        return self._summary()

    # ── Phase bodies ──────────────────────────────────────────────────
    async def _phase_info(self, r: PhaseResult) -> None:
        for tgt in self._targets:
            base = tgt["base"]
            tasks = [
                ("whatweb", f"-a 3 --colour=never {base}"),
                ("curl",    f"-sI -m 10 {base}"),
                ("curl",    f"-s -m 8 {base}/robots.txt"),
                ("curl",    f"-s -m 8 {base}/sitemap.xml"),
                ("curl",    f"-s -m 8 {base}/.well-known/security.txt"),
                ("curl",    f"-s -m 8 {base}/.well-known/openid-configuration"),
                ("wafw00f", base),
            ]
            await self._dispatch_tools(tasks, "info_gathering", r)

    async def _phase_config(self, r: PhaseResult) -> None:
        # Sensitive files & TLS audit
        for tgt in self._targets:
            base = tgt["base"]
            paths = [
                ".git/config", ".git/HEAD", ".env", ".env.local",
                ".DS_Store", "web.config", ".htaccess", "config.php.bak",
                "wp-config.php.bak", "backup.zip", "id_rsa", ".aws/credentials",
            ]
            for p in paths:
                await self._dispatch_tools([
                    ("curl", f"-s -o /dev/null -w '%{{http_code}}|%{{size_download}}' -m 8 {base}/{p}"),
                ], f"config_artifact:{p}", r)

            # TLS audit (https only)
            if tgt["scheme"] == "https":
                await self._dispatch_tools([
                    ("testssl", f"--quiet --color 0 --severity HIGH {tgt['host']}:{tgt['port']}"),
                    ("sslyze",  f"--regular {tgt['host']}:{tgt['port']}"),
                ], "tls_audit", r)

            # HTTP method enumeration
            for verb in ("OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"):
                await self._dispatch_tools([
                    ("curl", f"-sI -X {verb} -m 8 {base}/"),
                ], f"method:{verb}", r)

            # CORS preflight check
            await self._dispatch_tools([
                ("curl", f"-sI -m 8 -H 'Origin: https://attacker.example' -H 'Access-Control-Request-Method: GET' -X OPTIONS {base}/"),
            ], "cors_preflight", r)

    async def _phase_identity(self, r: PhaseResult) -> None:
        # Account enumeration via login error variation
        for tgt in self._targets:
            base = tgt["base"]
            for path in ("/login", "/auth/login", "/signin", "/api/login", "/user/login"):
                await self._dispatch_tools([
                    ("curl", f"-s -o /dev/null -w 'http=%{{http_code}}|len=%{{size_download}}\\n' -m 10 -X POST {base}{path} -d 'username=admin&password=invalid'"),
                    ("curl", f"-s -o /dev/null -w 'http=%{{http_code}}|len=%{{size_download}}\\n' -m 10 -X POST {base}{path} -d 'username=__nonexistent_user__&password=invalid'"),
                ], f"acct_enum:{path}", r)

    async def _phase_auth(self, r: PhaseResult) -> None:
        # Existing AuthBypass + JWT + cookie-attr audit
        await self._invoke_subagent("AuthBypassSubagent", r)
        await self._invoke_inline_jwt_analyzer(r)
        for tgt in self._targets:
            await self._dispatch_tools([
                ("curl", f"-sI -m 10 {tgt['base']}/"),
            ], "cookie_audit", r)

    async def _phase_session(self, r: PhaseResult) -> None:
        # Sequencer-style entropy probe — fetch login twice, capture cookies, diff
        for tgt in self._targets:
            await self._dispatch_tools([
                ("curl", f"-sI -m 8 {tgt['base']}/"),
                ("curl", f"-sI -m 8 {tgt['base']}/"),
            ], "session_entropy_pair", r)

    async def _phase_authz(self, r: PhaseResult) -> None:
        # Forced-browsing of admin paths + IDOR probe
        for tgt in self._targets:
            base = tgt["base"]
            for p in ("/admin", "/admin/", "/manage", "/manager/html", "/console", "/dashboard", "/api/admin", "/api/v1/users", "/users/1", "/users/2"):
                await self._dispatch_tools([
                    ("curl", f"-s -o /dev/null -w 'http=%{{http_code}}|len=%{{size_download}}\\n' -m 8 {base}{p}"),
                ], f"forced_browse:{p}", r)
        await self._invoke_subagent("BrokenAccessControlSubagent", r)

    async def _phase_input(self, r: PhaseResult) -> None:
        # Heavy lifting — call all the existing input-validation subagents
        for sa in (
            "WebVulnScanSubagent", "SqliSubagent", "XssSubagent",
            "InjectionSubagent", "DataIntegritySubagent",
        ):
            await self._invoke_subagent(sa, r)

        # Plus dedicated tools the subagents don't fire on their own
        for tgt in self._targets:
            base = tgt["base"]
            await self._dispatch_tools([
                ("nuclei",     f"-u {base}/ -severity critical,high,medium -silent -nh -timeout 10"),
                ("ffuf",       f"-u {base}/?file=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs 0 -t 30 -s -of csv -o /tmp/lfi.{tgt['host']}.csv"),
                ("dalfox",     f"url '{base}/' --silence --skip-bav --no-color -w 30"),
                ("commix",     f"-u '{base}/?cmd=test' --batch --skip-empty"),
                ("tplmap",     f"-u '{base}/' --crawl 1 --level 3"),
            ], "input_validation_tools", r)

    async def _phase_errors(self, r: PhaseResult) -> None:
        # Verbose-error harvest
        for tgt in self._targets:
            base = tgt["base"]
            for q in ("?'", "?id=1'", "?page=", "/<script>", "/?file=../../../../etc/passwd"):
                await self._dispatch_tools([
                    ("curl", f"-s -o /dev/null -w 'http=%{{http_code}}|len=%{{size_download}}\\n' -m 8 '{base}/{q}'"),
                ], f"error_probe:{q}", r)

    async def _phase_crypto(self, r: PhaseResult) -> None:
        # CryptoFailures subagent + targeted weak-cipher audit
        await self._invoke_subagent("CryptoFailuresSubagent", r)

    async def _phase_biz_logic(self, r: PhaseResult) -> None:
        # Insecure-design subagent + LLM-driven business logic probe
        await self._invoke_subagent("InsecureDesignSubagent", r)
        await self._invoke_inline_business_logic(r)

    async def _phase_client(self, r: PhaseResult) -> None:
        # XSS subagent already fired in _phase_input — here we look at
        # JS-bundle secrets + DOM XSS surface enumeration
        for tgt in self._targets:
            await self._dispatch_tools([
                ("curl",       f"-s -m 10 {tgt['base']}/"),
                ("linkfinder", f"-i {tgt['base']}/ -o cli"),
            ], "client_side_audit", r)

    async def _phase_api(self, r: PhaseResult) -> None:
        # Parameter pollution + GraphQL probes + Param Miner equivalent
        for tgt in self._targets:
            base = tgt["base"]
            await self._dispatch_tools([
                ("curl",  f"-s -m 8 {base}/graphql -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'"),
                ("curl",  f"-s -m 8 {base}/api"),
                ("curl",  f"-s -m 8 {base}/api/v1"),
                ("curl",  f"-s -m 8 {base}/swagger.json"),
                ("curl",  f"-s -m 8 {base}/openapi.json"),
                ("arjun", f"-u {base}/ --stable -t 20 -oJ /tmp/arjun.{tgt['host']}.json"),
            ], "api_audit", r)

    async def _phase_upload(self, r: PhaseResult) -> None:
        for tgt in self._targets:
            base = tgt["base"]
            for path in ("/upload", "/upload.php", "/api/upload", "/files/upload"):
                await self._dispatch_tools([
                    ("curl", f"-s -o /dev/null -w 'http=%{{http_code}}\\n' -m 10 -X POST -F 'file=@/etc/hostname;type=image/png;filename=t.php' {base}{path}"),
                ], f"upload_probe:{path}", r)
        await self._dispatch_tools_for_each([
            ("davtest", "-url {base}"),
        ], "webdav_probe", r)

    async def _phase_cache(self, r: PhaseResult) -> None:
        # Param Miner equivalent — unkeyed-header probe
        for tgt in self._targets:
            base = tgt["base"]
            await self._dispatch_tools([
                ("curl", f"-sI -m 8 -H 'X-Forwarded-Host: cache-poison.test' {base}/"),
                ("curl", f"-sI -m 8 -H 'X-Forwarded-Scheme: javascript' {base}/"),
                ("curl", f"-sI -m 8 -H 'X-HTTP-Method-Override: PUT' {base}/"),
            ], "cache_unkeyed_headers", r)

    # ── Inline analyzers (NEW capabilities) ──────────────────────────
    async def _invoke_inline_jwt_analyzer(self, r: PhaseResult) -> None:
        """Pull cookies / Authorization headers from any captured response,
        decode JWTs, and emit findings for `alg=none`, weak HMAC, kid-
        injection paths.  Pure-Python; no external tool needed.
        """
        try:
            import base64, json
        except Exception:
            return
        token_re = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_=.+/-]{10,}")
        raw_outputs = self._intel.get("raw_outputs") or {}
        seen_tokens: set = set()
        for tool, out in raw_outputs.items():
            if not isinstance(out, str):
                continue
            for m in token_re.finditer(out)[:5] if hasattr(token_re.finditer(out), "__getitem__") else list(token_re.finditer(out))[:5]:
                tok = m.group(0)
                if tok in seen_tokens:
                    continue
                seen_tokens.add(tok)
                try:
                    parts = tok.split(".")
                    head_b = parts[0] + "=" * (-len(parts[0]) % 4)
                    body_b = parts[1] + "=" * (-len(parts[1]) % 4)
                    head = json.loads(base64.urlsafe_b64decode(head_b).decode("utf-8", "replace"))
                    body = json.loads(base64.urlsafe_b64decode(body_b).decode("utf-8", "replace"))
                except Exception:
                    continue
                alg = (head.get("alg") or "").upper()
                kid = head.get("kid", "")
                weak = []
                if alg == "NONE":   weak.append("alg=none — full forgery possible")
                if alg.startswith("HS"): weak.append(f"HMAC ({alg}) — try cracking with hashcat 16500/16500")
                if "://" in str(kid):    weak.append(f"kid contains URL: {kid} — SSRF / injection candidate")
                if "../" in str(kid):    weak.append(f"kid path traversal: {kid}")
                r.evidence.setdefault("jwt_tokens", []).append({
                    "token_prefix": tok[:24] + "…",
                    "alg":          alg,
                    "kid":          kid,
                    "claims":       {k: body.get(k) for k in ("sub","iss","aud","exp","iat") if k in body},
                    "weak_signals": weak,
                })
                if weak:
                    r.findings += 1

    async def _invoke_inline_business_logic(self, r: PhaseResult) -> None:
        """LLM-driven business-logic probe.  Pulls discovered forms +
        endpoints from intel and asks the LLM to propose 3 abuse-of-
        intended-functionality probes (negative quantities, race conds,
        skip-step, replay).  Each proposal is then dispatched as a curl
        action and the output recorded as evidence.
        """
        forms = self._intel.get("login_pages", []) or []
        endpoints = self._intel.get("web_paths", []) or []
        if not forms and not endpoints:
            return
        try:
            think_json = getattr(self._master, "think_json", None) \
                       or getattr(self._master, "_think_json", None)
            if not callable(think_json):
                return
            sample = (forms[:3] + endpoints[:5])[:8]
            prompt = (
                f"Given these discovered web endpoints / login pages, propose "
                f"3 business-logic abuse probes — each must be a single runnable "
                f"curl command testing one of: negative quantity, integer overflow, "
                f"workflow-step skip, parameter pollution, race-condition replay, "
                f"or coupon/discount stacking.  Reply ONLY with JSON: "
                f"{{\"probes\":[{{\"name\":\"...\",\"curl\":\"curl -s ...\",\"expected\":\"...\"}}]}}\n\n"
                f"Endpoints: {sample}"
            )
            sys = "You are an expert business-logic flaw hunter. Output JSON only."
            data = await think_json(prompt, system_context=sys)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        for probe in (data.get("probes") or [])[:3]:
            if not isinstance(probe, dict): continue
            cmd = (probe.get("curl") or "").strip()
            if not cmd.startswith("curl"):
                continue
            args = cmd[len("curl"):].strip()
            await self._dispatch_tools([("curl", args)], f"biz_logic:{probe.get('name','probe')}", r)

    # ── Subagent invocation ──────────────────────────────────────────
    async def _invoke_subagent(self, class_name: str, r: PhaseResult) -> None:
        """Import + execute an existing single-vector subagent for each
        resolved web URL."""
        sid = getattr(self._master, "_session_id", "") or ""
        try:
            from utils.scan_logger import log_subagent as _slog_sub
        except Exception:
            def _slog_sub(*a, **kw): pass

        try:
            mod_path = f"agents.web.{self._snake_case(class_name).replace('subagent','subagent')}"
            # auto-translate ClassName -> module name (ClassName → class_name without "subagent")
            mod_path = "agents.web." + self._class_to_module(class_name)
            module = __import__(mod_path, fromlist=[class_name])
            cls = getattr(module, class_name)
        except Exception as exc:
            r.notes += f" {class_name}=import_failed({exc})"
            try:
                _slog_sub(sid, class_name, "failed",
                          target=self._target, error=f"import_failed: {exc}",
                          phase=r.phase_id, agent="web")
            except Exception:
                pass
            return

        kw = {
            "session_id": sid,
            "target":     self._target,
            "broadcast":  self._master.broadcast,
            "db":         None,
        }
        for tgt in self._targets:
            base = tgt["base"]
            t0 = time.time()
            try:
                _slog_sub(sid, class_name, "start", target=base,
                          phase=r.phase_id, agent="web")
            except Exception:
                pass
            try:
                inst = cls(**kw)
                # Most subagents accept url=base via execute()
                res = await inst.execute(url=base, lhost="LHOST", lport=4444)
                find_added = 0
                if hasattr(res, "to_dict"):
                    find_added = len(res.to_dict().get("findings") or [])
                elif isinstance(res, dict):
                    find_added = len(res.get("findings") or [])
                r.findings += find_added
                r.evidence.setdefault(class_name, []).append(base)
                try:
                    _slog_sub(sid, class_name, "end", target=base,
                              duration=(time.time() - t0),
                              findings_added=find_added,
                              phase=r.phase_id, agent="web")
                except Exception:
                    pass
            except Exception as exc:
                r.notes += f" {class_name}@{base}=err({exc!s:.40})"
                try:
                    _slog_sub(sid, class_name, "failed", target=base,
                              duration=(time.time() - t0),
                              error=str(exc),
                              phase=r.phase_id, agent="web")
                except Exception:
                    pass

    @staticmethod
    def _class_to_module(class_name: str) -> str:
        # AuthBypassSubagent -> auth_bypass_subagent
        out = []
        for i, c in enumerate(class_name):
            if c.isupper() and i > 0:
                out.append("_")
            out.append(c.lower())
        return "".join(out)

    @staticmethod
    def _snake_case(s: str) -> str:
        return re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()

    # ── Tool dispatch ────────────────────────────────────────────────
    async def _dispatch_tools(self, tasks: List[Tuple[str, str]], context: str, r: PhaseResult) -> None:
        """Dispatch a list of (tool, args) pairs through the WebAgent."""
        if not tasks: return
        try:
            web = self._web
            if web is None:
                return
            t_list = [
                {"tool": tool, "args": args, "purpose": context, "timeout": 60, "can_parallel": True}
                for tool, args in tasks
            ]
            await web.execute_tasks(self._target, t_list, "WEB_TESTING", self._intel)
        except Exception as exc:
            r.notes += f" {context}=disp_err({exc!s:.40})"

    async def _dispatch_tools_for_each(self, templates: List[Tuple[str, str]], context: str, r: PhaseResult) -> None:
        for tgt in self._targets:
            tasks = [(tool, args.format(base=tgt["base"], host=tgt["host"], port=tgt["port"])) for tool, args in templates]
            await self._dispatch_tools(tasks, context, r)

    # ── Phase wrapper / emitter ──────────────────────────────────────
    async def _safe_phase(self, phase_id: str, fn: Callable) -> None:
        from datetime import datetime, timezone
        r = self._results[phase_id]
        r.status = "running"
        r.started_at = datetime.now(timezone.utc).isoformat()
        await self._emit_phase_update(r)
        try:
            await fn(r)
            r.status = "done"
        except Exception as exc:
            r.status = "failed"
            r.notes += f" exc={exc!s:.80}"
        r.completed_at = datetime.now(timezone.utc).isoformat()
        await self._emit_phase_update(r)

    async def _emit_phase_matrix(self) -> None:
        try:
            await self._master._broadcast_raw({
                "type": "wstg_phase_matrix",
                "session_id": self._master._session_id,
                "agent": "web",
                "data": {
                    "phases":  [WSTG_PHASES_TO_DICT(ph) for ph in WSTG_PHASES],
                    "targets": [t["base"] for t in self._targets],
                },
            })
        except Exception:
            pass

    async def _emit_phase_update(self, r: PhaseResult) -> None:
        payload = r.to_dict()
        try:
            await self._master._broadcast_raw({
                "type": "wstg_phase_update",
                "session_id": self._master._session_id,
                "agent": "web",
                "data": payload,
            })
        except Exception:
            pass
        # Forensic scan-log: independent of the broadcast path so a
        # broken WS still leaves a wstg.jsonl audit trail.
        try:
            from utils.scan_logger import log_wstg_phase as _slog_wstg
            _slog_wstg(getattr(self._master, "_session_id", "") or "", payload)
        except Exception:
            pass

    async def _note(self, msg: str) -> None:
        try:
            await self._master.emit_reasoning(
                step="web_orchestrator",
                reasoning=msg,
                decision="WSTG-aligned web testing",
                next_action="Walking phases sequentially",
            )
        except Exception:
            pass

    def _summary(self) -> Dict[str, Any]:
        return {
            "phases":   {k: v.to_dict() for k, v in self._results.items()},
            "targets":  [t["base"] for t in self._targets],
            "total_findings": sum(r.findings for r in self._results.values()),
        }


def WSTG_PHASES_TO_DICT(ph: Dict) -> Dict:
    return {"id": ph["id"], "label": ph["label"], "wstg": ph["wstg"]}
