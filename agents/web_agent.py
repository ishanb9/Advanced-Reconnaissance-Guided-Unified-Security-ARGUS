"""
KALI PENTEST PLATFORM v3 — Web Agent (Enhanced)

OWASP Top 10 + comprehensive Kali web toolkit.

Key improvements over v2:
  - Parallel test execution (OWASP checks run concurrently)
  - nuclei integration for template-based web CVE detection
  - Aggressive sqlmap (level 5, risk 3) with all HTTP methods
  - wapiti for comprehensive web vulnerability scanning
  - XSS-specific testing (dalfox/reflected XSS probes)
  - arjun for hidden parameter discovery
  - CMS detection and CMS-specific scanning (wpscan, droopescan, joomscan)
  - Expanded port coverage (all HTTP ports, not just 80/443)

Tools: nikto, gobuster, ffuf, wfuzz, sqlmap, commix, wapiti, davtest,
       nuclei, dalfox, arjun, whatweb, wafw00f, wpscan, droopescan,
       joomscan, sslscan, curl, hydra
"""

import asyncio
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


_HTTPS_PORTS = {443, 8443, 4443, 9443}


class WebAgent(BaseAgent):
    """
    Comprehensive OWASP web application testing specialist.
    Runs tests in parallel where possible for speed.
    """

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.OSINT, broadcast)   # reuse OSINT enum slot
        self.name  = "web"
        self.phase = AttackPhase.VULN_ID
        # BaseAgent registered this instance under ``str(AgentName.OSINT)`` in
        # its super().__init__. After the rename above, the "web" identity is
        # what the watchdog emits to the frontend ("subagent": "web"), so the
        # frontend's stop/extend button sends back "web". Re-register under
        # that key as well so the direct lookup in agent_server resolves
        # without needing the fallback-by-name scan.
        try:
            from agents.base_agent import _AGENT_REGISTRY as _AR
            _AR[self.name] = self
        except Exception:
            pass

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
            "interesting_files": [],
            "raw_output":    "",
        }

        await self.set_status(AgentStatus.RUNNING, f"Web application testing: {target}")

        for port in web_ports[:4]:  # test up to 4 web ports
            proto    = "https" if port in _HTTPS_PORTS else "http"
            base_url = f"{proto}://{target}:{port}"

            tech_info = {
                "is_windows":   is_windows,
                "is_wordpress": any("wordpress" in str(t).lower() for t in technologies),
                "is_php":       any("php" in str(t).lower() for t in technologies),
                "is_dotnet":    any(t.lower() in ("asp.net", "iis", "aspx") for t in technologies),
                "is_java":      any(t.lower() in ("java", "spring", "tomcat", "servlet", "jsp") for t in technologies),
                "is_drupal":    any("drupal" in str(t).lower() for t in technologies),
                "is_joomla":    any("joomla" in str(t).lower() for t in technologies),
                "is_node":      any(t.lower() in ("node", "express", "next.js", "react") for t in technologies),
            }

            await self.emit_reasoning(
                step       = f"web_testing_port_{port}",
                reasoning  = f"Testing web application on {base_url} — OWASP Top 10 + full Kali toolkit",
                decision   = "Phase 1: fingerprint+discover in parallel → Phase 2: injection+vuln tests in parallel",
                next_action= f"Starting comprehensive web assessment on {base_url}"
            )

            # ── PHASE 1: Fingerprint + Discovery (parallel) ─────
            phase1_tasks = [
                ("CMS/Tech Detection", self._detect_cms_tech(target, port, proto, base_url, result, technologies)),
                ("Directory Enumeration", self._test_directory_enum(target, port, proto, base_url, result, tech_info)),
                ("WAF Detection", self._detect_waf(target, port, proto, base_url, result)),
            ]
            await self._run_parallel(phase1_tasks, f"Phase 1 — Discovery ({base_url})")

            # ── PHASE 2: Vulnerability testing (parallel) ───────
            phase2_tasks = [
                ("Nikto Scan",          self._test_nikto(target, port, proto, base_url, result)),
                ("Nuclei Web Scan",     self._test_nuclei_web(target, port, proto, base_url, result)),
                ("SQL Injection",       self._test_sqli(target, port, proto, base_url, result)),
                ("Command Injection",   self._test_command_injection(target, port, proto, base_url, result)),
                ("XSS Testing",         self._test_xss(target, port, proto, base_url, result)),
                ("LFI/Access Control",  self._test_access_control(target, port, proto, base_url, result)),
                ("SSRF Detection",      self._test_ssrf_hints(target, port, proto, base_url, result)),
                ("Security Headers",    self._test_crypto_failures(target, port, proto, base_url, result)),
            ]

            # Add conditional tests
            if result.get("paths"):
                phase2_tasks.append(("Parameter Discovery", self._test_param_discovery(target, port, proto, base_url, result)))
            phase2_tasks.append(("Auth Testing", self._test_auth_bypass(target, port, proto, base_url, result)))
            phase2_tasks.append(("File Upload",  self._test_file_upload(target, port, proto, base_url, known_paths, result)))
            phase2_tasks.append(("WebDAV Check", self._test_webdav(target, port, proto, base_url, result)))

            await self._run_parallel(phase2_tasks, f"Phase 2 — Vulnerability Testing ({base_url})")

            # ── PHASE 3: CMS-specific (if detected) ────────────
            cms_tasks = []
            if tech_info["is_wordpress"]:
                cms_tasks.append(("WordPress Scan", self._test_wordpress(target, port, proto, base_url, result)))
            if tech_info["is_drupal"]:
                cms_tasks.append(("Drupal Scan", self._test_drupal_vulns(target, port, proto, base_url, result)))
            if tech_info["is_joomla"]:
                cms_tasks.append(("Joomla Scan", self._test_joomla(target, port, proto, base_url, result)))
            if is_windows or tech_info["is_dotnet"]:
                cms_tasks.append(("IIS/ASP.NET", self._test_windows_iis(target, port, proto, base_url, result)))
            if tech_info["is_java"]:
                cms_tasks.append(("Java/Tomcat", self._test_java_vulns(target, port, proto, base_url, result)))

            if cms_tasks:
                await self._run_parallel(cms_tasks, f"Phase 3 — CMS/Platform-Specific ({base_url})")

        await self.set_status(AgentStatus.DONE,
            f"Web testing complete: {len(result['web_vulns'])} vulns, {len(result['paths'])} paths")
        return result

    # ═══════════════════════════════════════════════════════════════
    #  EXECUTE_TASKS interface (called by _dispatch_to_agent)
    # ═══════════════════════════════════════════════════════════════

    async def execute_tasks(self, target, tasks, phase_name, intel):
        """Compatibility interface for master_agent._dispatch_to_agent."""
        web_ports = intel.get("web_ports") or [80]
        technologies = intel.get("technologies") or []
        known_paths  = intel.get("web_paths") or []
        return await self.run(
            session_id   = getattr(self, "_session_id", ""),
            target       = target,
            web_ports    = web_ports,
            technologies = technologies,
            known_paths  = known_paths,
            intel        = intel,
        )

    # ═══════════════════════════════════════════════════════════════
    #  PARALLEL RUNNER
    # ═══════════════════════════════════════════════════════════════

    async def _run_parallel(self, tasks: list, description: str):
        labels = [l for l, _ in tasks]
        await self.emit_reasoning(
            step="parallel", reasoning=f"{description}: {len(tasks)} tests",
            decision=f"Running: {', '.join(labels[:10])}",
            next_action=f"Parallel: {', '.join(labels[:6])}"
        )
        results = await asyncio.gather(
            *[coro for _, coro in tasks], return_exceptions=True
        )
        for (label, _), res in zip(tasks, results):
            if isinstance(res, Exception):
                pass  # non-fatal

    # ═══════════════════════════════════════════════════════════════
    #  PHASE 1: FINGERPRINT + DISCOVERY
    # ═══════════════════════════════════════════════════════════════

    async def _detect_cms_tech(self, target, port, proto, base_url, result, technologies):
        """CMS and technology detection via whatweb."""
        out = await self.run_tool(
            "whatweb", f"-a 3 --color=never {base_url}",
            target=target, phase=AttackPhase.VULN_ID, timeout=30
        )
        stdout = out.get("stdout", "")
        result["raw_output"] += "\n" + stdout

        # Extract technologies from whatweb output
        techs_found = re.findall(r'\[([^\]]+)\]', stdout)
        for t in techs_found:
            t_clean = t.strip().lower()
            if t_clean and t_clean not in [x.lower() for x in result["technologies"]]:
                result["technologies"].append(t_clean)
                # Auto-detect CMS
                if "wordpress" in t_clean:
                    technologies.append("wordpress")
                elif "drupal" in t_clean:
                    technologies.append("drupal")
                elif "joomla" in t_clean:
                    technologies.append("joomla")

    async def _detect_waf(self, target, port, proto, base_url, result):
        """WAF detection via wafw00f."""
        out = await self.run_tool(
            "wafw00f", f"{base_url}",
            target=target, phase=AttackPhase.VULN_ID, timeout=30
        )
        stdout = out.get("stdout", "")
        result["raw_output"] += "\n" + stdout
        if "is behind" in stdout.lower():
            waf_name = re.search(r'is behind\s+(.+)', stdout)
            waf = waf_name.group(1).strip() if waf_name else "Unknown WAF"
            await self.store_finding(
                severity=FindingSeverity.INFO,
                title=f"WAF Detected: {waf}",
                description=f"Web Application Firewall detected: {waf}. Testing may require evasion techniques.",
                host=target, port=port, service="http",
                tool_used="wafw00f", evidence=stdout[:500]
            )

    async def _test_directory_enum(self, target, port, proto, base_url, result, tech_info=None):
        """Directory enumeration with gobuster + ffuf."""
        tech_info = tech_info or {}

        # Choose extensions based on tech stack
        if tech_info.get("is_windows") or tech_info.get("is_dotnet"):
            exts = "asp,aspx,ashx,asmx,config,xml,html,bak,old,zip"
        elif tech_info.get("is_java"):
            exts = "jsp,jspx,do,action,xml,properties,html,bak,zip,war"
        elif tech_info.get("is_php") or tech_info.get("is_wordpress"):
            exts = "php,php5,html,txt,bak,old,zip,sql,conf,xml,json"
        elif tech_info.get("is_node"):
            exts = "js,json,html,md,env,yaml,yml,config"
        else:
            exts = "html,txt,bak,old,zip,conf,xml,json,js,yaml,php"

        # gobuster with common wordlist
        gob = await self.run_tool(
            "gobuster",
            f"dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt "
            f"-x {exts} -t 40 -q --no-error --timeout 10s",
            target=target, phase=AttackPhase.VULN_ID, timeout=180
        )
        paths = self._parse_gobuster(gob["stdout"])
        result["paths"].extend(paths)
        result["raw_output"] += "\n" + gob.get("stdout", "")

        # ffuf with medium wordlist for deeper coverage
        ffuf = await self.run_tool(
            "ffuf",
            f"-u {base_url}/FUZZ -w /usr/share/wordlists/dirb/big.txt "
            f"-mc 200,204,301,302,307,401,403,405,500 -t 40 -timeout 10 -s",
            target=target, phase=AttackPhase.VULN_ID, timeout=180
        )
        ffuf_paths = [l.strip() for l in ffuf["stdout"].splitlines() if l.strip() and l.strip().startswith("/")]
        for fp in ffuf_paths:
            if fp not in paths:
                result["paths"].append(fp)
        result["raw_output"] += "\n" + ffuf.get("stdout", "")

        # Report high-value paths
        high_value_keywords = [
            "admin", "backup", "config", ".env", ".git", "phpmyadmin",
            "wp-admin", "api", "swagger", "upload", "shell", ".sql", ".bak",
            "login", "debug", "console", "actuator", "graphql", ".DS_Store",
            "robots.txt", "sitemap", ".htaccess", "web.config", "server-status",
        ]
        high_value = [p for p in result["paths"] if any(k in p.lower() for k in high_value_keywords)]
        for path in high_value[:15]:
            sev = FindingSeverity.HIGH if any(k in path.lower() for k in
                    ["admin", "config", ".env", ".git", "backup", ".sql", "debug", "console"]) else FindingSeverity.MEDIUM
            await self.store_finding(
                severity=sev, title=f"Sensitive Path: {path}",
                description=f"Potentially sensitive path at {base_url}{path}",
                host=target, port=port, service="http", tool_used="gobuster",
                evidence=f"HTTP accessible: {base_url}{path}",
                remediation="Restrict access. Use authentication. Remove from production."
            )
            result["interesting_files"].append(path)

    # ═══════════════════════════════════════════════════════════════
    #  PHASE 2: VULNERABILITY TESTING
    # ═══════════════════════════════════════════════════════════════

    async def _test_nikto(self, target, port, proto, base_url, result):
        """Nikto comprehensive scan with all tuning options."""
        nik = await self.run_tool(
            "nikto", f"-h {base_url} -C all -maxtime 300 -Tuning 123456789abc",
            target=target, phase=AttackPhase.VULN_ID, timeout=360
        )
        findings = self._parse_nikto_output(nik["stdout"])
        result["web_vulns"].extend(findings)
        result["raw_output"] += "\n" + nik.get("stdout", "")
        for f in findings:
            await self.store_finding(
                severity=f["severity"], title=f["title"],
                description=f["description"], host=target,
                port=port, service="http", tool_used="nikto",
                evidence=f.get("evidence", "")
            )

    async def _test_nuclei_web(self, target, port, proto, base_url, result):
        """Nuclei web-specific templates: CVEs, misconfigs, exposures, default logins."""
        out = await self.run_tool(
            "nuclei",
            f"-u {base_url} -severity critical,high,medium -silent -nc "
            f"-timeout 10 -rate-limit 100 -concurrency 15 -stats -si 30 "
            f"-tags cve,misconfig,exposure,default-login,xss,sqli,lfi,rce,ssrf",
            target=target, phase=AttackPhase.VULN_ID, timeout=300
        )
        result["raw_output"] += "\n" + out.get("stdout", "")
        sev_map = {"critical": FindingSeverity.CRITICAL, "high": FindingSeverity.HIGH,
                   "medium": FindingSeverity.MEDIUM, "low": FindingSeverity.LOW}
        for line in out["stdout"].splitlines():
            line = line.strip()
            m = re.match(r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)(.*)', line)
            if m:
                template_id = m.group(1).strip()
                severity_s  = m.group(3).strip().lower()
                url         = m.group(4).strip()
                sev = sev_map.get(severity_s, FindingSeverity.MEDIUM)
                await self.store_finding(
                    severity=sev, title=f"[Nuclei] {template_id}",
                    description=f"Nuclei template match: {template_id} on {url}",
                    host=target, port=port, service="http",
                    tool_used="nuclei", evidence=line[:500]
                )
                result["web_vulns"].append({
                    "type": "nuclei", "severity": severity_s,
                    "url": url, "description": template_id
                })

    async def _test_sqli(self, target, port, proto, base_url, result):
        """SQL injection with aggressive sqlmap settings."""
        # Level 5, Risk 3 = thorough testing (all techniques, time-based, stacked queries)
        sqli = await self.run_tool(
            "sqlmap",
            f"-u {base_url}/ --crawl=3 --level=5 --risk=3 --batch --forms --dbs "
            f"--random-agent --tamper=space2comment "
            f"--output-dir=/tmp/sqlmap_{port} --flush-session --threads=4",
            target=target, phase=AttackPhase.VULN_ID, timeout=300
        )
        stdout = sqli["stdout"]
        result["raw_output"] += "\n" + stdout
        if any(k in stdout.lower() for k in
               ["injectable", "is vulnerable", "sqlmap identified", "[INFO] fetched"]):
            result["sqli_found"] = True
            dbs = re.findall(r"available databases.*?:\n(.*?)(?:\n\n|\Z)", stdout, re.DOTALL)
            await self.store_finding(
                severity=FindingSeverity.CRITICAL,
                title=f"SQL Injection Confirmed: {base_url}",
                description="SQL injection vulnerability detected. Database contents accessible.\n" +
                           (f"Databases found: {dbs[0][:200]}" if dbs else ""),
                host=target, port=port, service="http", tool_used="sqlmap",
                evidence=stdout[:3000],
                remediation="Use parameterised queries. Never concatenate user input into SQL."
            )
            result["web_vulns"].append({
                "type": "sqli", "severity": "critical",
                "url": base_url, "description": "SQL injection confirmed"
            })

    async def _test_command_injection(self, target, port, proto, base_url, result):
        """OS command injection via commix — aggressive mode."""
        cmdi = await self.run_tool(
            "commix",
            f"--url={base_url}/ --crawl=2 --batch --level=3 "
            f"--output-dir=/tmp/commix_{port} --random-agent",
            target=target, phase=AttackPhase.VULN_ID, timeout=120
        )
        stdout = cmdi["stdout"]
        result["raw_output"] += "\n" + stdout
        if any(k in stdout.lower() for k in
               ["is vulnerable", "injection point", "commix identified"]):
            await self.store_finding(
                severity=FindingSeverity.CRITICAL,
                title=f"Command Injection: {base_url}",
                description="OS command injection — remote code execution possible",
                host=target, port=port, service="http", tool_used="commix",
                evidence=stdout[:2000],
                remediation="Validate all user input. Use subprocess with argument arrays."
            )
            result["web_vulns"].append({
                "type": "cmdi", "severity": "critical",
                "url": base_url, "description": "Command injection confirmed"
            })

    async def _test_xss(self, target, port, proto, base_url, result):
        """XSS testing via dalfox + reflected XSS probes."""
        # dalfox: modern XSS scanner with DOM, reflected, and stored detection
        out = await self.run_tool(
            "dalfox", f"url {base_url}/ --crawl --silence --no-color --timeout 10",
            target=target, phase=AttackPhase.VULN_ID, timeout=120
        )
        stdout = out.get("stdout", "")
        result["raw_output"] += "\n" + stdout
        if "POC" in stdout or "Vulnerable" in stdout or "[V]" in stdout:
            result["xss_found"] = True
            await self.store_finding(
                severity=FindingSeverity.HIGH,
                title=f"XSS Vulnerability: {base_url}",
                description="Cross-site scripting (XSS) detected — session hijacking / phishing possible",
                host=target, port=port, service="http", tool_used="dalfox",
                evidence=stdout[:2000],
                remediation="Encode all output. Use Content-Security-Policy. Sanitise user input."
            )
            result["web_vulns"].append({
                "type": "xss", "severity": "high",
                "url": base_url, "description": "XSS confirmed"
            })

    async def _test_access_control(self, target, port, proto, base_url, result):
        """LFI, path traversal, directory listing."""
        # wfuzz for LFI
        lfi = await self.run_tool(
            "wfuzz",
            f"-c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt "
            f"--hc 404,400 -t 20 {base_url}/FUZZ",
            target=target, phase=AttackPhase.VULN_ID, timeout=120
        )
        stdout = lfi.get("stdout", "")
        result["raw_output"] += "\n" + stdout
        if any(k in stdout.lower() for k in ["root:x:", "etc/passwd", "windows/system32"]):
            result["lfi_found"] = True
            await self.store_finding(
                severity=FindingSeverity.CRITICAL,
                title=f"Local File Inclusion (LFI): {base_url}",
                description="LFI allows reading arbitrary server files — credential theft, source code exposure",
                host=target, port=port, service="http", tool_used="wfuzz",
                evidence=stdout[:2000],
                remediation="Validate file paths. Whitelist allowed files. Use realpath() with prefix check."
            )

        # Directory listing check
        for path in ["/", "/images/", "/uploads/", "/files/", "/backup/", "/static/", "/media/"]:
            curl = await self.run_tool(
                "curl", f"-s -L -m 5 {base_url}{path}",
                target=target, phase=AttackPhase.VULN_ID, timeout=10
            )
            body = curl.get("stdout", "")
            if "Index of" in body or "Parent Directory" in body:
                await self.store_finding(
                    severity=FindingSeverity.HIGH,
                    title=f"Directory Listing: {base_url}{path}",
                    description=f"Web server exposes directory listing at {path}",
                    host=target, port=port, service="http", tool_used="curl",
                    evidence=f"Directory listing at {base_url}{path}",
                    remediation="Disable directory listing (Apache: Options -Indexes)"
                )

    async def _test_ssrf_hints(self, target, port, proto, base_url, result):
        """SSRF parameter detection."""
        ssrf_params = ["url", "redirect", "next", "return", "goto", "target",
                       "link", "fetch", "proxy", "callback", "load", "ref", "path", "file"]
        ssrf_paths = [p for p in result.get("paths", [])
                      if any(f"{param}=" in p.lower() for param in ssrf_params)]
        if ssrf_paths:
            await self.store_finding(
                severity=FindingSeverity.HIGH,
                title="Potential SSRF Parameters Found",
                description=f"URL-fetching parameters: {ssrf_paths[:5]} — test for SSRF/open redirect",
                host=target, port=port, service="http", tool_used="analysis",
                evidence=str(ssrf_paths[:5]),
                remediation="Validate/whitelist URLs. Block internal IP ranges."
            )

    async def _test_param_discovery(self, target, port, proto, base_url, result):
        """Hidden parameter discovery via arjun."""
        # Test top 3 interesting paths
        test_urls = []
        for p in result.get("paths", [])[:5]:
            if not p.startswith("/"):
                p = "/" + p
            test_urls.append(f"{base_url}{p}")

        if not test_urls:
            test_urls = [f"{base_url}/"]

        for url in test_urls[:3]:
            out = await self.run_tool(
                "arjun", f"-u {url} --stable -t 10 -q",
                target=target, phase=AttackPhase.VULN_ID, timeout=60
            )
            stdout = out.get("stdout", "")
            result["raw_output"] += "\n" + stdout
            # arjun outputs: [url] [param1, param2, ...]
            params = re.findall(r'\[([^\]]+)\]', stdout)
            if params and len(params) > 1:
                await self.store_finding(
                    severity=FindingSeverity.MEDIUM,
                    title=f"Hidden Parameters: {url}",
                    description=f"arjun discovered hidden parameters: {', '.join(params[1:])}",
                    host=target, port=port, service="http", tool_used="arjun",
                    evidence=stdout[:500],
                    remediation="Review hidden parameters for injection points."
                )

    async def _test_crypto_failures(self, target, port, proto, base_url, result):
        """Security headers and SSL/TLS checks."""
        headers_out = await self.run_tool(
            "curl", f"-s -I -m 10 --max-redirs 3 {base_url}",
            target=target, phase=AttackPhase.VULN_ID, timeout=15
        )
        headers = headers_out.get("stdout", "").lower()
        result["raw_output"] += "\n" + headers_out.get("stdout", "")

        missing = []
        if "strict-transport-security" not in headers and proto == "https":
            missing.append("HSTS")
        if "x-frame-options" not in headers:
            missing.append("X-Frame-Options")
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")
        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")
        if "x-xss-protection" not in headers:
            missing.append("X-XSS-Protection")

        if missing:
            await self.store_finding(
                severity=FindingSeverity.MEDIUM,
                title=f"Missing Security Headers ({len(missing)})",
                description=f"Missing: {', '.join(missing)}",
                host=target, port=port, service="http", tool_used="curl",
                evidence=f"Missing headers: {missing}",
                remediation="Add security headers: HSTS, X-Frame-Options, CSP, X-Content-Type-Options"
            )

        # SSL scan if HTTPS
        if proto == "https":
            ssl_out = await self.run_tool(
                "sslscan", f"--no-colour {target}:{port}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60
            )
            ssl_text = ssl_out.get("stdout", "").lower()
            result["raw_output"] += "\n" + ssl_out.get("stdout", "")
            weak = []
            for kw in ["sslv2", "sslv3", "rc4", "des-cbc"]:
                if kw in ssl_text:
                    weak.append(kw.upper())
            if weak:
                await self.store_finding(
                    severity=FindingSeverity.HIGH,
                    title=f"Weak SSL/TLS: {', '.join(weak)}",
                    description=f"Insecure cipher suites: {', '.join(weak)}",
                    host=target, port=port, service="https", tool_used="sslscan",
                    evidence=ssl_out.get("stdout", "")[:1000],
                    remediation="Disable SSLv2/SSLv3, RC4, DES. Use TLS 1.2/1.3 only."
                )

    async def _test_auth_bypass(self, target, port, proto, base_url, result):
        """Admin panel discovery + default credential testing."""
        admin_paths = ["/admin", "/administrator", "/wp-admin/", "/login", "/user/login",
                       "/phpmyadmin", "/manager/html", "/console", "/dashboard", "/admin.php",
                       "/wp-login.php", "/xmlrpc.php", "/api/v1", "/swagger", "/graphql"]
        found_admin = []
        for ap in admin_paths:
            curl = await self.run_tool(
                "curl", f"-s -o /dev/null -w '%{{http_code}}' -L -m 5 {base_url}{ap}",
                target=target, phase=AttackPhase.VULN_ID, timeout=10
            )
            code = curl["stdout"].strip().replace("'", "")
            if code in ("200", "301", "302", "401"):
                found_admin.append((ap, code))
                sev = FindingSeverity.HIGH if code in ("200", "302") else FindingSeverity.MEDIUM
                await self.store_finding(
                    severity=sev, title=f"Admin Panel: {ap} (HTTP {code})",
                    description=f"Admin interface at {base_url}{ap}",
                    host=target, port=port, service="http", tool_used="curl",
                    evidence=f"HTTP {code} at {base_url}{ap}",
                    remediation="Restrict admin access by IP. Implement MFA."
                )

    async def _test_file_upload(self, target, port, proto, base_url, known_paths, result):
        """File upload endpoint detection."""
        upload_paths = [p for p in result.get("paths", []) + known_paths
                        if any(k in p.lower() for k in ["upload", "file", "image", "attach", "media"])]
        if upload_paths:
            await self.store_finding(
                severity=FindingSeverity.HIGH,
                title="File Upload Endpoints Found",
                description=f"Upload endpoints: {upload_paths[:5]} — test for unrestricted upload / web shell",
                host=target, port=port, service="http", tool_used="gobuster",
                evidence=f"Upload endpoints: {upload_paths[:5]}",
                remediation="Validate file type server-side. Store outside web root. Rename uploads."
            )

    async def _test_webdav(self, target, port, proto, base_url, result):
        """WebDAV write access check."""
        dav = await self.run_tool(
            "davtest", f"-url {base_url}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        if "SUCCEED" in dav.get("stdout", ""):
            result["upload_bypass"] = True
            await self.store_finding(
                severity=FindingSeverity.CRITICAL,
                title=f"WebDAV Write Access: {base_url}",
                description="WebDAV allows file uploads — web shell RCE possible",
                host=target, port=port, service="webdav", tool_used="davtest",
                evidence=dav["stdout"][:1000],
                remediation="Disable WebDAV or restrict to authenticated users."
            )

    # ═══════════════════════════════════════════════════════════════
    #  PHASE 3: CMS/PLATFORM-SPECIFIC
    # ═══════════════════════════════════════════════════════════════

    async def _test_wordpress(self, target, port, proto, base_url, result):
        """WordPress: wpscan with aggressive plugin/theme/user enumeration."""
        wp = await self.run_tool(
            "wpscan",
            f"--url {base_url} --enumerate ap,at,u,dbe "
            f"--plugins-detection aggressive --no-banner --random-user-agent",
            target=target, phase=AttackPhase.VULN_ID, timeout=180
        )
        stdout = wp["stdout"]
        result["raw_output"] += "\n" + stdout
        vulns = re.findall(r'\[!\]\s+(.+)', stdout)
        for v in vulns[:15]:
            sev = FindingSeverity.CRITICAL if "rce" in v.lower() or "sqli" in v.lower() else FindingSeverity.HIGH
            await self.store_finding(
                severity=sev, title=f"WordPress: {v[:80]}",
                description=v, host=target, port=port,
                service="wordpress", tool_used="wpscan", evidence=v
            )
        # Extract usernames
        users = re.findall(r'\|\s+(\w+)\s+\|', stdout)
        if users:
            await self.store_finding(
                severity=FindingSeverity.MEDIUM,
                title=f"WordPress Users Enumerated: {', '.join(users[:10])}",
                description=f"WordPress user enumeration revealed: {', '.join(users[:10])}",
                host=target, port=port, service="wordpress", tool_used="wpscan",
                evidence=f"Users: {users[:10]}"
            )

    async def _test_drupal_vulns(self, target, port, proto, base_url, result):
        """Drupal: Drupalgeddon + droopescan."""
        tasks = [
            self.run_tool("nmap",
                f"--script http-drupal-enum,http-vuln-cve2014-3704 -p {port} {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60),
            self.run_tool("droopescan",
                f"scan drupal -u {base_url} -t 8",
                target=target, phase=AttackPhase.VULN_ID, timeout=120),
        ]
        results_out = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_out:
            if isinstance(r, Exception):
                continue
            stdout = r.get("stdout", "")
            result["raw_output"] += "\n" + stdout
            if "VULNERABLE" in stdout or "drupalgeddon" in stdout.lower():
                await self.store_finding(
                    severity=FindingSeverity.CRITICAL,
                    title="Drupalgeddon Vulnerability",
                    description="Drupal is vulnerable to Drupalgeddon — unauthenticated RCE",
                    host=target, port=port, service="drupal",
                    tool_used="nmap", evidence=stdout[:1000]
                )

    async def _test_joomla(self, target, port, proto, base_url, result):
        """Joomla scanning via joomscan."""
        out = await self.run_tool(
            "joomscan", f"-u {base_url} --enumerate-components",
            target=target, phase=AttackPhase.VULN_ID, timeout=120
        )
        stdout = out.get("stdout", "")
        result["raw_output"] += "\n" + stdout
        vulns = re.findall(r'\[!\]\s+(.+)', stdout)
        for v in vulns[:10]:
            await self.store_finding(
                severity=FindingSeverity.HIGH,
                title=f"Joomla: {v[:80]}",
                description=v, host=target, port=port,
                service="joomla", tool_used="joomscan", evidence=v
            )

    async def _test_java_vulns(self, target, port, proto, base_url, result):
        """Java/Tomcat-specific: manager brute, deserialization, Spring4Shell."""
        tasks = [
            # Tomcat manager default creds
            self.run_tool("nmap",
                f"--script http-tomcat-manager-default-creds -p {port} {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60),
            # Spring4Shell check via nuclei
            self.run_tool("nuclei",
                f"-u {base_url} -tags spring,springboot,tomcat -severity critical,high -silent -nc",
                target=target, phase=AttackPhase.VULN_ID, timeout=120),
            # Java deserialization check
            self.run_tool("curl",
                f"-s -o /dev/null -w '%{{http_code}}' -m 5 {base_url}/actuator/env",
                target=target, phase=AttackPhase.VULN_ID, timeout=10),
        ]
        results_out = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_out:
            if isinstance(r, Exception):
                continue
            stdout = r.get("stdout", "")
            result["raw_output"] += "\n" + stdout
            if "default credentials" in stdout.lower() or "tomcat:tomcat" in stdout.lower():
                await self.store_finding(
                    severity=FindingSeverity.CRITICAL,
                    title="Tomcat Manager Default Credentials",
                    description="Tomcat manager accessible with default credentials — deploy WAR for RCE",
                    host=target, port=port, service="tomcat", tool_used="nmap",
                    evidence=stdout[:500],
                    remediation="Change default Tomcat manager credentials. Restrict by IP."
                )

    async def _test_windows_iis(self, target, port, proto, base_url, result):
        """Windows/IIS-specific vulnerability checks."""
        tasks = [
            self.run_tool("nmap",
                f"--script http-iis-short-name-brute,http-iis-webdav-vuln -p {port} {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60),
            self.run_tool("curl",
                f"-s -m 10 {base_url}/nope-does-not-exist-12345.aspx",
                target=target, phase=AttackPhase.VULN_ID, timeout=15),
        ]
        results_out = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_out:
            if isinstance(r, Exception):
                continue
            stdout = r.get("stdout", "")
            result["raw_output"] += "\n" + stdout
            if any(k in stdout.lower() for k in ["vulnerable", "webdav enabled", "write access"]):
                await self.store_finding(
                    severity=FindingSeverity.HIGH,
                    title=f"IIS Vulnerability: {base_url}",
                    description="IIS WebDAV or short-name vulnerability detected",
                    host=target, port=port, service="http/iis", tool_used="nmap",
                    evidence=stdout[:1000],
                    remediation="Disable WebDAV. Patch IIS. Disable 8.3 filename creation."
                )
            if any(k in stdout.lower() for k in ["stack trace", "system.web", "runtime error"]):
                await self.store_finding(
                    severity=FindingSeverity.MEDIUM,
                    title="ASP.NET Verbose Error Disclosure",
                    description="ASP.NET exposes stack traces — aids attacker reconnaissance",
                    host=target, port=port, service="http/iis", tool_used="curl",
                    evidence=stdout[:500],
                    remediation="Set customErrors mode='On'. Disable debug mode."
                )

    # ═══════════════════════════════════════════════════════════════
    #  PARSERS
    # ═══════════════════════════════════════════════════════════════

    def _parse_gobuster(self, output: str) -> List[str]:
        paths = []
        for line in output.splitlines():
            m = re.match(r'(/[^\s]+)\s+\(Status:\s*(\d+)', line)
            if m and int(m.group(2)) not in (404, 400):
                paths.append(m.group(1))
        return paths

    def _parse_nikto_output(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            if not line.startswith("+"):
                continue
            text = line.lstrip("+ ").strip()
            if len(text) < 15 or any(k in text for k in ["Nikto", "Target", "Start", "End"]):
                continue
            sev = FindingSeverity.INFO
            if any(k in text.lower() for k in ["sql", "xss", "injection", "rce", "execute", "shell", "remote code"]):
                sev = FindingSeverity.CRITICAL
            elif any(k in text.lower() for k in ["vulnerability", "dangerous", "exploit", "admin", "backup", "password"]):
                sev = FindingSeverity.HIGH
            elif any(k in text.lower() for k in ["exposed", "disclosure", "version", "header", "missing", "cookie"]):
                sev = FindingSeverity.MEDIUM
            findings.append({"severity": sev, "title": text[:80], "description": text, "evidence": text})
        return findings
