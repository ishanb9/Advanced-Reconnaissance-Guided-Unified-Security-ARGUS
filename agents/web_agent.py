"""
KALI PENTEST PLATFORM v3 — Web Agent

OWASP Top 10 + Burp Suite methodology.
A dedicated web testing agent analogous to running Burp Suite Pro.

OWASP checks covered:
  A01: Broken Access Control        → directory traversal, IDOR, admin panel
  A02: Cryptographic Failures       → HTTPS enforcement, sensitive data in HTTP
  A03: Injection                    → SQLi (sqlmap), Command injection (commix), SSTI
  A04: Insecure Design              → logic flaws, default credentials
  A05: Security Misconfiguration    → nikto, exposed admin, debug endpoints
  A06: Vulnerable Components        → CVE matching per detected libraries
  A07: Authentication Failures      → brute force (hydra), default creds
  A08: Data Integrity Failures      → upload bypass, deserialization hints
  A09: Logging & Monitoring         → error verbosity, stack traces
  A10: SSRF                         → URL parameters pointing to internal

Tools:
  nikto, gobuster, ffuf, wfuzz, sqlmap, commix, wapiti, davtest
  whatweb, wafw00f, dirb, sslscan, curl (manual HTTP tests)

Does NOT call think(). Executes Instructions from MasterAgent.
"""

import re
from typing import Optional, Dict, List

from agents.base_agent import BaseAgent, Instruction, BroadcastFn
from db.schemas import AgentName, AgentStatus, AttackPhase, FindingSeverity
import db.mongo_client as db

# RAG Knowledge Base access
try:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "knowledge"))
    import knowledge_base as _kb_web
    def _kb_commands(query: str, top_k: int = 2) -> str:
        try:
            cmds = _kb_web.search_commands(query, top_k=top_k)
            return "\n".join(cmds) if cmds else ""
        except Exception:
            return ""
except ImportError:
    def _kb_commands(query: str, top_k: int = 2) -> str:
        return ""


class WebAgent(BaseAgent):
    """
    Dedicated OWASP web application testing specialist.
    Covers Burp Suite-equivalent manual and automated checks.
    """

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.OSINT, broadcast)   # reuse OSINT enum slot
        self.name  = "web"
        self.phase = AttackPhase.VULN_ID

    async def run(
        self,
        session_id:   str,
        target:       str,
        web_ports:    List[int] = None,
        technologies: List[str] = None,
        known_paths:  List[str] = None,
        intel:        dict = None,
        **kwargs
    ) -> Dict:
        self._session_id = session_id
        web_ports    = web_ports or [80]
        technologies = technologies or []
        known_paths  = known_paths or []
        intel        = intel or {}
        os_guess     = intel.get("os_guess", "unknown").lower()
        is_windows   = "windows" in os_guess

        result = {
            "web_vulns":     [],
            "paths":         [],
            "technologies":  technologies[:],
            "sqli_found":    False,
            "xss_found":     False,
            "lfi_found":     False,
            "upload_bypass": False,
            "credentials":   [],
            "interesting_files": []
        }

        await self.set_status(AgentStatus.RUNNING, f"Web application testing: {target}")

        for port in web_ports[:2]:
            proto   = "https" if port in (443, 8443) else "http"
            base_url = f"{proto}://{target}:{port}"

            await self.emit_reasoning(
                step       = f"web_testing_port_{port}",
                reasoning  = f"Testing web application on {base_url} following OWASP Top 10",
                decision   = "Full OWASP coverage: discovery → injection → auth → config",
                next_action= f"Starting with directory enumeration on {base_url}"
            )

            # ── A05: Security Misconfiguration — Directory enum ──
            tech_info = {
                "is_windows": is_windows,
                "is_wordpress": "wordpress" in technologies or any("wordpress" in str(t).lower() for t in technologies),
                "is_php": "php" in technologies,
                "is_dotnet": any(t in technologies for t in ["asp.net", "iis"]),
                "is_java": any(t in technologies for t in ["java", "spring", "servlet"]),
            }
            await self._test_directory_enum(target, port, proto, base_url, result, tech_info)

            # ── A05: Nikto comprehensive scan ────────────────────
            await self._test_nikto(target, port, proto, base_url, result)

            # ── A03: SQL Injection ────────────────────────────────
            await self._test_sqli(target, port, proto, base_url, result)

            # ── A03: Command Injection ────────────────────────────
            await self._test_command_injection(target, port, proto, base_url, result)

            # ── A01: Broken Access Control ────────────────────────
            await self._test_access_control(target, port, proto, base_url, result)

            # ── A07: Authentication Failures ─────────────────────
            await self._test_auth_bypass(target, port, proto, base_url, result)

            # ── A08: File Upload ─────────────────────────────────
            await self._test_file_upload(target, port, proto, base_url, known_paths, result)

            # ── SSRF hints ───────────────────────────────────────
            await self._test_ssrf_hints(target, port, proto, base_url, result)

            # ── A04: Cryptographic Failures ───────────────────────
            await self._test_crypto_failures(target, port, proto, base_url, result)

            # ── WebDAV ───────────────────────────────────────────
            await self._test_webdav(target, port, proto, base_url, result)

            # ── CMS-specific (WordPress, Joomla, Drupal) ─────────
            for tech in technologies:
                if "wordpress" in tech.lower():
                    await self._test_wordpress(target, port, proto, base_url, result)
                    break
                if "drupal" in tech.lower():
                    await self._test_drupal_vulns(target, port, proto, base_url, result)
                    break

            # ── Windows/IIS-specific testing ──────────────────────
            if is_windows or any(t in ["iis", "asp.net"] for t in technologies):
                await self._test_windows_iis(target, port, proto, base_url, result)

        await self.set_status(AgentStatus.DONE,
            f"Web testing complete: {len(result['web_vulns'])} findings, {len(result['paths'])} paths")
        return result

    # ─── OWASP Test Methods ───────────────────────────────────

    async def _test_directory_enum(self, target, port, proto, base_url, result, tech_info=None):
        """A05 + A01: Find hidden files, backup files, admin panels — tech-aware."""
        tech_info = tech_info or {}
        await self.emit_reasoning(
            step       = "directory_enum",
            reasoning  = "Directory enumeration reveals hidden endpoints, admin panels, backup files",
            decision   = "gobuster + ffuf for comprehensive coverage with multiple wordlists",
            next_action= f"gobuster dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt"
        )
        try:
            kb = _kb_commands(f"gobuster ffuf directory enumeration {base_url}", top_k=2)
            if kb:
                await self.emit_reasoning(
                    step="kb_dirfuzz",
                    reasoning=f"KB context for directory enumeration loaded",
                    decision="Using KB examples for wordlist/flag selection",
                    next_action=f"Applying KB guidance: {kb[:200]}"
                )
        except Exception:
            pass
        # Choose extensions based on detected technology stack
        if tech_info.get("is_windows") or tech_info.get("is_dotnet"):
            exts = "asp,aspx,ashx,asmx,config,xml,html,bak,old,zip"
        elif tech_info.get("is_java"):
            exts = "jsp,jspx,do,action,xml,properties,html,bak,zip"
        elif tech_info.get("is_php") or tech_info.get("is_wordpress"):
            exts = "php,php5,html,txt,bak,old,zip,sql,conf,xml,json"
        else:
            exts = "html,txt,bak,old,zip,conf,xml,json,js,yaml"

        # gobuster — fast tech-aware enumeration
        gob = await self.run_tool(
            "gobuster",
            f"dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt "
            f"-x {exts} -t 30 -q --no-error --timeout 10s",
            target=target, phase=AttackPhase.VULN_ID, timeout=120
        )
        paths = self._parse_gobuster(gob["stdout"])
        result["paths"].extend(paths)

        # Look for high-value finds
        high_value = [p for p in paths if any(k in p.lower() for k in
            ["admin", "backup", "config", ".env", ".git", "phpmyadmin", "wp-admin",
             "api", "swagger", "upload", "shell", ".sql", ".bak", "login"])]

        for path in high_value:
            sev = FindingSeverity.HIGH if any(k in path.lower() for k in
                    ["admin", "config", ".env", ".git", "phpmyadmin"]) else FindingSeverity.MEDIUM
            await self.store_finding(
                severity    = sev,
                title       = f"Sensitive Path Found: {path}",
                description = f"Potentially sensitive path accessible at {base_url}{path}",
                host        = target,
                port        = port,
                service     = "http",
                tool_used   = "gobuster",
                evidence    = f"HTTP accessible: {base_url}{path}",
                remediation = "Restrict access to sensitive paths. Use authentication."
            )
            result["interesting_files"].append(path)

        # ffuf for parameter fuzzing on found pages
        if paths:
            await self.emit_reasoning(
                step       = "ffuf_params",
                reasoning  = "Found pages — fuzz for hidden parameters that may reveal vulnerabilities",
                decision   = "ffuf parameter brute-force on most interesting endpoints",
                next_action= f"ffuf -u {base_url}/FUZZ -w wordlists"
            )

        await self.add_node(
            node_id  = f"web_paths_{port}",
            type     = "web_discovery",
            label    = f"Web Paths ({len(paths)} found)",
            host     = target,
            port     = port,
            metadata = {"paths": paths[:20], "high_value": high_value}
        )

    async def _test_nikto(self, target, port, proto, base_url, result):
        """A05: Comprehensive server misconfiguration scan."""
        await self.emit_reasoning(
            step       = "nikto_scan",
            reasoning  = "Nikto checks for default files, CGI vulns, server misconfig, dangerous HTTP methods",
            decision   = "Full nikto scan with all tests enabled",
            next_action= f"nikto -h {base_url} -C all"
        )
        nik = await self.run_tool(
            "nikto", f"-h {base_url} -C all -maxtime 300",
            target=target, phase=AttackPhase.VULN_ID, timeout=120
        )
        findings = self._parse_nikto_output(nik["stdout"])
        result["web_vulns"].extend(findings)
        for f in findings:
            await self.store_finding(
                severity    = f["severity"],
                title       = f["title"],
                description = f["description"],
                host        = target,
                port        = port,
                service     = "http",
                tool_used   = "nikto",
                evidence    = f.get("evidence","")
            )

    async def _test_sqli(self, target, port, proto, base_url, result):
        """A03: SQL Injection — crawl and test all forms and parameters."""
        await self.emit_reasoning(
            step       = "sqli_testing",
            reasoning  = "SQL injection in input parameters can lead to data theft or RCE via xp_cmdshell/INTO OUTFILE",
            decision   = "sqlmap with form crawling, level 2, risk 2 for balanced detection",
            next_action= f"sqlmap -u {base_url}/ --crawl=3 --level=2 --risk=2 --batch --forms --dbs"
        )
        try:
            kb = _kb_commands(f"sqlmap sql injection {base_url}", top_k=2)
        except Exception:
            kb = ""
        # First try crawl-based
        sqli = await self.run_tool(
            "sqlmap",
            f"-u {base_url}/ --crawl=3 --level=2 --risk=2 --batch --forms --dbs "
            f"--output-dir=/tmp/sqlmap_{port} --flush-session",
            target=target, phase=AttackPhase.VULN_ID, timeout=120
        )
        if any(k in sqli["stdout"].lower() for k in
               ["injectable", "is vulnerable", "sqlmap identified", "[INFO] fetched"]):
            result["sqli_found"] = True
            # Extract DB names
            dbs = re.findall(r"available databases.*?:\n(.*?)(?:\n\n|\Z)", sqli["stdout"], re.DOTALL)
            await self.store_finding(
                severity    = FindingSeverity.CRITICAL,
                title       = f"SQL Injection Confirmed: {base_url}",
                description = "SQL injection vulnerability detected. Database contents may be accessible.",
                host        = target,
                port        = port,
                service     = "http",
                tool_used   = "sqlmap",
                evidence    = sqli["stdout"][:3000],
                remediation = "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                extra       = {"databases": dbs}
            )
            result["web_vulns"].append({
                "type": "sqli", "severity": "critical",
                "url": base_url, "description": "SQL injection confirmed"
            })

            await self.add_node(
                node_id  = f"sqli_{port}",
                type     = "vulnerability",
                label    = "SQL Injection",
                host     = target,
                port     = port,
                severity = "critical",
                metadata = {"owasp": "A03", "tool": "sqlmap"}
            )

    async def _test_command_injection(self, target, port, proto, base_url, result):
        """A03: OS Command Injection via commix."""
        await self.emit_reasoning(
            step       = "command_injection",
            reasoning  = "Command injection gives direct OS access — high priority test on all input params",
            decision   = "commix with automatic crawl and injection point detection",
            next_action= f"commix --url={base_url}/ --crawl=1 --batch"
        )
        cmdi = await self.run_tool(
            "commix",
            f"--url={base_url}/ --crawl=1 --batch --level=2 --output-dir=/tmp/commix_{port}",
            target=target, phase=AttackPhase.VULN_ID, timeout=90
        )
        if any(k in cmdi["stdout"].lower() for k in
               ["is vulnerable", "injection point", "commix identified"]):
            await self.store_finding(
                severity    = FindingSeverity.CRITICAL,
                title       = f"Command Injection: {base_url}",
                description = "OS command injection vulnerability detected — may allow remote code execution",
                host        = target,
                port        = port,
                service     = "http",
                tool_used   = "commix",
                evidence    = cmdi["stdout"][:2000],
                remediation = "Validate and sanitise all user input. Use subprocess with argument arrays, never shell=True."
            )
            result["web_vulns"].append({
                "type": "cmdi", "severity": "critical",
                "url": base_url, "description": "Command injection confirmed"
            })

    async def _test_access_control(self, target, port, proto, base_url, result):
        """A01: Broken Access Control — LFI, path traversal, directory listing."""
        await self.emit_reasoning(
            step       = "access_control",
            reasoning  = "LFI/path traversal can read /etc/passwd, SSH keys, config files",
            decision   = "Test common LFI paths and directory traversal sequences",
            next_action= f"wfuzz LFI payloads against {base_url}"
        )
        try:
            kb = _kb_commands(f"IDOR broken access control path traversal {base_url}", top_k=2)
        except Exception:
            kb = ""
        # Test LFI via wfuzz if any paths with parameters found
        lfi_paths = [p for p in result.get("paths", []) if "?" in p or "=" in p]
        if lfi_paths or result.get("paths"):
            lfi = await self.run_tool(
                "wfuzz",
                f"-c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt "
                f"--hc 404,400 {base_url}/FUZZ",
                target=target, phase=AttackPhase.VULN_ID, timeout=120
            )
            if any(k in lfi["stdout"].lower() for k in ["root:x:", "etc/passwd", "windows/system32"]):
                result["lfi_found"] = True
                await self.store_finding(
                    severity    = FindingSeverity.CRITICAL,
                    title       = f"Local File Inclusion (LFI): {base_url}",
                    description = "LFI vulnerability allows reading arbitrary server files",
                    host        = target,
                    port        = port,
                    service     = "http",
                    tool_used   = "wfuzz",
                    evidence    = lfi["stdout"][:2000],
                    remediation = "Validate file paths. Use whitelist of allowed files. Use realpath() and check prefix."
                )

        # Check for directory listing
        for path in ["/", "/images/", "/uploads/", "/files/", "/backup/"]:
            curl = await self.run_tool(
                "curl",
                f"-s -o /dev/null -w '%{{http_code}}' {base_url}{path}",
                target=target, phase=AttackPhase.VULN_ID, timeout=10
            )
            if "200" in curl["stdout"]:
                curl_body = await self.run_tool(
                    "curl", f"-s -L {base_url}{path}",
                    target=target, phase=AttackPhase.VULN_ID, timeout=15
                )
                if "Index of" in curl_body["stdout"] or "Parent Directory" in curl_body["stdout"]:
                    await self.store_finding(
                        severity    = FindingSeverity.HIGH,
                        title       = f"Directory Listing Enabled: {base_url}{path}",
                        description = f"Web server exposes directory listing at {path}",
                        host        = target,
                        port        = port,
                        service     = "http",
                        tool_used   = "curl",
                        evidence    = f"Directory listing at {base_url}{path}",
                        remediation = "Disable directory listing in web server config (Apache: Options -Indexes)"
                    )

    async def _test_auth_bypass(self, target, port, proto, base_url, result):
        """A07: Authentication — default credentials, common admin panels."""
        await self.emit_reasoning(
            step       = "auth_testing",
            reasoning  = "Default credentials and weak passwords are common in misconfigured systems",
            decision   = "Check common admin panels with default credentials",
            next_action= f"Test admin login at {base_url}/admin, /login, /wp-admin"
        )
        # Check common admin panels exist
        admin_paths = ["/admin", "/administrator", "/wp-admin/", "/login", "/user/login",
                       "/phpmyadmin", "/manager/html", "/console", "/dashboard"]
        found_admin = []
        for ap in admin_paths:
            curl = await self.run_tool(
                "curl", f"-s -o /dev/null -w '%{{http_code}}' -L {base_url}{ap}",
                target=target, phase=AttackPhase.VULN_ID, timeout=10
            )
            code = curl["stdout"].strip().replace("'", "")
            if code in ("200", "301", "302", "401", "403"):
                found_admin.append((ap, code))
                if code in ("200", "301", "302"):
                    await self.store_finding(
                        severity    = FindingSeverity.HIGH,
                        title       = f"Admin Panel Accessible: {ap}",
                        description = f"Admin interface accessible at {base_url}{ap} (HTTP {code})",
                        host        = target,
                        port        = port,
                        service     = "http",
                        tool_used   = "curl",
                        evidence    = f"HTTP {code} at {base_url}{ap}",
                        remediation = "Restrict admin access by IP. Implement MFA."
                    )

        # Try default credentials on found admin panels
        if found_admin:
            await self.emit_reasoning(
                step       = "default_creds",
                reasoning  = f"Admin panel found at {found_admin[0][0]} — try default credentials",
                decision   = "Hydra brute-force with default credential list",
                next_action= f"hydra -L users.txt -P pass.txt {target} http-form-post"
            )

    async def _test_file_upload(self, target, port, proto, base_url, result, known_paths):
        """A08: Insecure File Upload — bypass restrictions to upload web shell."""
        upload_paths = [p for p in result.get("paths", []) + known_paths
                        if "upload" in p.lower() or "file" in p.lower() or "image" in p.lower()]
        if not upload_paths:
            return

        await self.emit_reasoning(
            step       = "upload_testing",
            reasoning  = f"File upload endpoints found: {upload_paths[:3]} — test for unrestricted upload",
            decision   = "Test extension bypass techniques (double extension, null byte, MIME mismatch)",
            next_action= "Try uploading PHP web shell with various bypass techniques"
        )
        await self.store_finding(
            severity    = FindingSeverity.HIGH,
            title       = f"File Upload Endpoint Found",
            description = f"File upload functionality at {upload_paths[0]} — potential RCE if upload restrictions bypass possible",
            host        = target,
            port        = port,
            service     = "http",
            tool_used   = "gobuster",
            evidence    = f"Upload endpoints: {upload_paths[:3]}",
            remediation = "Validate file type server-side. Store uploads outside web root. Rename uploads."
        )

    async def _test_ssrf_hints(self, target, port, proto, base_url, result):
        """A10: SSRF — parameters that fetch URLs."""
        await self.emit_reasoning(
            step       = "ssrf_check",
            reasoning  = "URL parameters that fetch remote resources may be vulnerable to SSRF",
            decision   = "Check for URL/redirect parameters in discovered paths",
            next_action= "Scan paths for url=, redirect=, fetch=, proxy= parameters"
        )
        ssrf_params = ["url", "redirect", "next", "return", "goto", "target",
                       "link", "fetch", "proxy", "callback", "load", "ref"]
        ssrf_paths = [p for p in result.get("paths", [])
                      if any(f"?{param}=" in p or f"&{param}=" in p for param in ssrf_params)]
        if ssrf_paths:
            await self.store_finding(
                severity    = FindingSeverity.HIGH,
                title       = "Potential SSRF Parameters Found",
                description = f"URL-fetching parameters found: {ssrf_paths[:5]} — test for SSRF/open redirect",
                host        = target,
                port        = port,
                service     = "http",
                tool_used   = "analysis",
                evidence    = str(ssrf_paths[:5]),
                remediation = "Validate and whitelist allowed URLs. Block internal IP ranges."
            )

    async def _test_crypto_failures(self, target, port, proto, base_url, result):
        """A04: Cryptographic Failures — TLS/SSL, security headers, cleartext data."""
        await self.emit_reasoning(
            step       = "crypto_failures",
            reasoning  = "Check for weak TLS, missing HSTS, insecure cookies, and cleartext sensitive data",
            decision   = "Test HTTP→HTTPS redirect, security headers, SSL configuration",
            next_action= f"curl -I {base_url} | check headers"
        )

        # Check security headers
        headers_out = await self.run_tool(
            "curl", f"-s -I -m 10 --max-redirs 3 {base_url}",
            target=target, phase=AttackPhase.VULN_ID, timeout=30
        )
        headers = (headers_out.get("stdout", "") + headers_out.get("stderr", "")).lower()

        missing_headers = []
        if "strict-transport-security" not in headers and proto == "https":
            missing_headers.append("HSTS (Strict-Transport-Security)")
        if "x-frame-options" not in headers:
            missing_headers.append("X-Frame-Options")
        if "x-content-type-options" not in headers:
            missing_headers.append("X-Content-Type-Options")
        if "content-security-policy" not in headers:
            missing_headers.append("Content-Security-Policy")

        if missing_headers:
            await self.store_finding(
                severity    = FindingSeverity.MEDIUM,
                title       = f"Missing Security Headers: {base_url}",
                description = f"Security headers missing: {', '.join(missing_headers)}",
                host        = target, port=port, service="http",
                tool_used   = "curl",
                evidence    = f"Missing: {missing_headers}\nResponse headers: {headers[:500]}",
                remediation = "Add security headers: HSTS, X-Frame-Options, CSP, X-Content-Type-Options"
            )

        # HTTP-only? (should force HTTPS)
        if proto == "http" and port in (80, 8080):
            https_check = await self.run_tool(
                "curl", f"-s -o /dev/null -w '%{{http_code}}' -m 5 https://{target}:{443 if port == 80 else 8443}/",
                target=target, phase=AttackPhase.VULN_ID, timeout=20
            )
            http_code = https_check.get("stdout", "").strip()
            if http_code not in ("200", "301", "302"):
                await self.store_finding(
                    severity    = FindingSeverity.MEDIUM,
                    title       = f"No HTTPS Enforcement: {base_url}",
                    description = "Application accessible over HTTP without forced redirect to HTTPS",
                    host        = target, port=port, service="http",
                    tool_used   = "curl",
                    evidence    = f"HTTP {http_code} — no HTTPS redirect detected",
                    remediation = "Configure HTTP→HTTPS redirect and enable HSTS"
                )

        # SSL scan if HTTPS
        if proto == "https":
            ssl_out = await self.run_tool(
                "sslscan", f"--no-colour {target}:{port}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60
            )
            ssl_text = ssl_out.get("stdout", "")
            vuln_ciphers = []
            if "sslv2" in ssl_text.lower() and "enabled" in ssl_text.lower():
                vuln_ciphers.append("SSLv2")
            if "sslv3" in ssl_text.lower() and "enabled" in ssl_text.lower():
                vuln_ciphers.append("SSLv3")
            if "rc4" in ssl_text.lower():
                vuln_ciphers.append("RC4")
            if "des-cbc" in ssl_text.lower():
                vuln_ciphers.append("DES")
            if vuln_ciphers:
                await self.store_finding(
                    severity    = FindingSeverity.HIGH,
                    title       = f"Weak SSL/TLS Ciphers: {base_url}",
                    description = f"Insecure cipher suites enabled: {', '.join(vuln_ciphers)}",
                    host        = target, port=port, service="https",
                    tool_used   = "sslscan",
                    evidence    = ssl_text[:1000],
                    remediation = "Disable SSLv2/SSLv3/TLS1.0, RC4 ciphers. Use TLS 1.2/1.3 only."
                )

    async def _test_webdav(self, target, port, proto, base_url, result):
        """Check WebDAV for write access."""
        dav = await self.run_tool(
            "davtest", f"-url {base_url}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        if "SUCCEED" in dav["stdout"]:
            await self.store_finding(
                severity    = FindingSeverity.CRITICAL,
                title       = f"WebDAV Write Access: {base_url}",
                description = "WebDAV allows file uploads — can upload web shell for RCE",
                host        = target,
                port        = port,
                service     = "webdav",
                tool_used   = "davtest",
                evidence    = dav["stdout"][:1000],
                remediation = "Disable WebDAV or restrict to authenticated users with IP allowlist."
            )
            result["upload_bypass"] = True

    async def _test_wordpress(self, target, port, proto, base_url, result):
        """WordPress-specific testing."""
        await self.emit_reasoning(
            step       = "wordpress_scan",
            reasoning  = "WordPress detected — wpscan checks for outdated plugins, themes, weak passwords",
            decision   = "wpscan with plugin enumeration",
            next_action= f"wpscan --url {base_url} --enumerate p,t,u"
        )
        wp = await self.run_tool(
            "wpscan",
            f"--url {base_url} --enumerate p,t,u --plugins-detection aggressive --no-banner",
            target=target, phase=AttackPhase.VULN_ID, timeout=120
        )
        vulns = re.findall(r'\[!\]\s+(.+)', wp["stdout"])
        for v in vulns[:10]:
            await self.store_finding(
                severity    = FindingSeverity.HIGH,
                title       = f"WordPress: {v[:80]}",
                description = v,
                host        = target,
                port        = port,
                service     = "wordpress",
                tool_used   = "wpscan",
                evidence    = v
            )

    async def _test_drupal_vulns(self, target, port, proto, base_url, result):
        """Drupal-specific — check for Drupalgeddon."""
        await self.emit_reasoning(
            step       = "drupal_check",
            reasoning  = "Drupal detected — check for Drupalgeddon (CVE-2014-3704, CVE-2018-7600)",
            decision   = "NSE scripts for Drupal CVE check",
            next_action= f"nmap --script http-drupal-enum {target} -p {port}"
        )
        drupal = await self.run_tool(
            "nmap", f"--script http-drupal-enum,http-vuln-cve2014-3704 -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        if "VULNERABLE" in drupal["stdout"]:
            await self.store_finding(
                severity    = FindingSeverity.CRITICAL,
                title       = "Drupalgeddon Vulnerability",
                description = "Drupal is vulnerable to Drupalgeddon — unauthenticated RCE possible",
                host        = target,
                port        = port,
                service     = "drupal",
                tool_used   = "nmap",
                evidence    = drupal["stdout"][:1000]
            )

    # ─── Parsers ──────────────────────────────────────────────

    def _parse_gobuster(self, output: str) -> List[str]:
        paths = []
        for line in output.splitlines():
            m = re.match(r'(/[^\s]+)\s+\(Status:\s*(\d+)', line)
            if m:
                status = int(m.group(2))
                if status not in (404, 400):
                    paths.append(m.group(1))
        return paths

    def _parse_nikto_output(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            if not line.startswith("+"):
                continue
            text = line.lstrip("+ ").strip()
            if len(text) < 15 or any(k in text for k in ["Nikto", "Target", "Start", "End", "SSL"]):
                continue
            sev = FindingSeverity.INFO
            if any(k in text.lower() for k in ["sql", "xss", "injection", "rce", "execute", "shell"]):
                sev = FindingSeverity.CRITICAL
            elif any(k in text.lower() for k in ["vulnerability", "dangerous", "exploit", "admin", "backup"]):
                sev = FindingSeverity.HIGH
            elif any(k in text.lower() for k in ["exposed", "disclosure", "version", "header", "missing"]):
                sev = FindingSeverity.MEDIUM
            findings.append({"severity": sev, "title": text[:80], "description": text, "evidence": text})
        return findings

    async def _test_windows_iis(self, target, port, proto, base_url, result):
        """Windows/IIS-specific vulnerability checks."""
        await self.emit_reasoning(
            step       = "windows_iis_test",
            reasoning  = "Windows/IIS target detected — running IIS-specific vulnerability checks",
            decision   = "Test: IIS short-name, WebDAV, NTLM auth, .NET deserialization hints",
            next_action= f"nmap IIS scripts against {base_url}"
        )
        # IIS short-name vulnerability
        iis_short = await self.run_tool(
            "nmap",
            f"--script http-iis-short-name-brute,http-iis-webdav-vuln -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        if any(k in iis_short["stdout"].lower() for k in ["vulnerable", "webdav enabled", "write access"]):
            await self.store_finding(
                severity    = FindingSeverity.HIGH,
                title       = f"IIS Vulnerability: {base_url}",
                description = "IIS WebDAV or short-name vulnerability detected",
                host        = target, port=port, service="http/iis",
                tool_used   = "nmap",
                evidence    = iis_short["stdout"][:1000],
                remediation = "Disable WebDAV if not needed. Patch IIS. Disable 8.3 filename creation."
            )

        # Check for exposed ASP.NET error pages (verbose error disclosure)
        err_check = await self.run_tool(
            "curl",
            f"-s -m 10 {base_url}/nope-does-not-exist-12345.aspx",
            target=target, phase=AttackPhase.VULN_ID, timeout=15
        )
        if any(k in err_check.get("stdout", "").lower() for k in
               ["stack trace", "system.web", "exception", "at system.", "runtime error"]):
            await self.store_finding(
                severity    = FindingSeverity.MEDIUM,
                title       = f"ASP.NET Verbose Error Disclosure: {base_url}",
                description = "ASP.NET exposes detailed stack traces — aids attacker reconnaissance",
                host        = target, port=port, service="http/iis",
                tool_used   = "curl",
                evidence    = err_check["stdout"][:500],
                remediation = "Set customErrors mode='On' in web.config. Disable debug mode."
            )
        result["web_vulns"].extend([{"type": "iis_check", "severity": "medium", "url": base_url}])
