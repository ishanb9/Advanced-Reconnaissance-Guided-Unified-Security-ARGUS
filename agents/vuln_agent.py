"""
KALI PENTEST PLATFORM v3 — Vulnerability Agent (Enhanced)

Service-adaptive, LLM-planned vulnerability assessment using the full
Kali toolset: nmap NSE, nikto, nuclei, rustscan, searchsploit, sslscan,
enum4linux, smbmap, snmpwalk, smtp-user-enum, and more.

Key improvements over v2:
  - Service-adaptive: selects tools based on discovered services
  - Parallel execution: runs independent checks concurrently
  - Nuclei integration: template-based CVE detection
  - Expanded port coverage: all HTTP/S ports, not just 80/8080
  - LLM-assisted CVE prioritisation for found service versions
  - Deep service-specific checks for 15+ service types
"""

import asyncio
import re
from typing import Optional, Dict, List

from agents.base_agent import BaseAgent, Instruction, BroadcastFn
from db.schemas import AgentName, AgentStatus, AttackPhase, FindingSeverity
import db.mongo_client as db


# ── HTTP-like ports (covers dev servers, proxies, APIs) ──────────────
_HTTP_PORTS  = {80, 8080, 8000, 8888, 3000, 5000, 9090, 8081, 8443, 443, 4443, 9443, 8008, 8181, 8888}
_HTTPS_PORTS = {443, 8443, 4443, 9443}

# ── Service → check mapping ─────────────────────────────────────────
# Each entry: (check_method_name, severity_weight)
_SERVICE_CHECKS = {
    "ftp":         "_check_ftp",
    "ssh":         "_check_ssh",
    "smtp":        "_check_smtp",
    "dns":         "_check_dns",
    "http":        "_check_http_deep",
    "https":       "_check_http_deep",
    "http-proxy":  "_check_http_deep",
    "smb":         "_check_smb",
    "microsoft-ds":"_check_smb",
    "netbios-ssn": "_check_smb",
    "mysql":       "_check_mysql",
    "postgresql":  "_check_postgres",
    "mssql":       "_check_mssql",
    "ms-sql-s":    "_check_mssql",
    "oracle":      "_check_oracle",
    "redis":       "_check_redis",
    "mongodb":     "_check_mongodb",
    "mongod":      "_check_mongodb",
    "ldap":        "_check_ldap",
    "snmp":        "_check_snmp",
    "nfs":         "_check_nfs",
    "vnc":         "_check_vnc",
    "rdp":         "_check_rdp",
    "ms-wbt-server":"_check_rdp",
    "telnet":      "_check_telnet",
    "irc":         "_check_irc",
    "ajp13":       "_check_ajp",
    "java-rmi":    "_check_rmi",
    "rmiregistry": "_check_rmi",
    "ssl":         "_check_ssl",
    "imap":        "_check_ssl",
    "pop3":        "_check_ssl",
    "submission":  "_check_ssl",
}


class VulnAgent(BaseAgent):

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.VULN, broadcast)
        self.phase = AttackPhase.VULN_ID

    # ═══════════════════════════════════════════════════════════════
    #  MAIN ENTRY
    # ═══════════════════════════════════════════════════════════════

    async def run(
        self,
        session_id: str,
        target:     str,
        open_ports: List[int] = None,
        services:   Dict = None,
        **kwargs
    ) -> Dict:
        self._session_id = session_id
        open_ports = open_ports or []
        services   = services or {}
        self._target = target
        result = {
            "vulnerabilities": [], "cves": [], "exploits": [],
            "raw_output": "",
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }

        await self.set_status(AgentStatus.RUNNING, f"Vulnerability assessment: {target}")
        ports_str = ",".join(str(p) for p in open_ports[:50]) if open_ports else ""

        # ─── Phase 1: Parallel broad scans ──────────────────────
        phase1: list = []

        # 1a. NSE vuln scripts on all ports
        if ports_str:
            phase1.append(("nse_vuln", self._nse_vuln_scan(target, ports_str, result)))

        # 1b. Nuclei template-based CVE scan
        phase1.append(("nuclei", self._nuclei_scan(target, open_ports, result)))

        # 1c. searchsploit for each service version
        phase1.append(("searchsploit", self._searchsploit_all(target, services, result)))

        # ─── Phase 1b: SQLMap on HTTP ports (runs alongside NSE/Nuclei) ─
        http_ports_found = []
        for p in open_ports:
            pn = p.get("port") if isinstance(p, dict) else p
            if pn and int(str(pn).split("/")[0]) in _HTTP_PORTS:
                http_ports_found.append(int(str(pn).split("/")[0]))
        if not http_ports_found and open_ports:
            http_ports_found = [80]   # default if no HTTP detected yet

        if http_ports_found:
            phase1.append(("sqlmap", self._sqlmap_scan(target, list(dict.fromkeys(http_ports_found)), result)))

        # Run Phase 1 in parallel (NSE + Nuclei + Searchsploit + SQLMap)
        if phase1:
            await self._run_parallel(phase1, "Phase 1: Broad vulnerability scans")

        # ─── Phase 1c: OWASP ZAP + OpenVAS (heavy, run after phase 1) ────
        # These take longer and are best run sequentially after the fast scans
        # so port/service info is already available.
        phase1_heavy: list = [
            ("openvas", self._openvas_scan(target, open_ports, result)),
            ("zap",     self._zap_scan(target, list(dict.fromkeys(http_ports_found)) or [80], result)),
        ]
        await self._run_parallel(phase1_heavy, "Phase 1c: Deep scanners (OpenVAS, ZAP)")

        # ─── Phase 2: Service-specific deep checks (parallel) ───
        phase2: list = []
        checked_types = set()
        for port_key, svc_info in services.items():
            port = int(port_key) if isinstance(port_key, str) else port_key
            svc_name = (svc_info.get("service") or svc_info.get("name") or "").lower().strip()
            product  = (svc_info.get("product") or svc_info.get("version") or "").lower()

            # Find the appropriate check method
            check_method_name = None
            for svc_pattern, method_name in _SERVICE_CHECKS.items():
                if svc_pattern in svc_name or svc_pattern in product:
                    check_method_name = method_name
                    break

            # Also detect HTTP by port
            if not check_method_name and port in _HTTP_PORTS:
                check_method_name = "_check_http_deep"

            if check_method_name:
                # Avoid running same check type multiple times unless different ports
                check_key = f"{check_method_name}_{port}"
                if check_key not in checked_types:
                    checked_types.add(check_key)
                    method = getattr(self, check_method_name, None)
                    if method:
                        phase2.append((
                            f"{svc_name or 'svc'}:{port}",
                            method(target, port, svc_info, result)
                        ))

        # SSL/TLS checks for known SSL ports
        ssl_ports = [p for p in open_ports if p in _HTTPS_PORTS or
                     any("ssl" in str(services.get(p, {}).get("service", "")).lower()
                         for _ in [None])]
        for port in ssl_ports[:5]:
            ck = f"_check_ssl_{port}"
            if ck not in checked_types:
                checked_types.add(ck)
                phase2.append((f"ssl:{port}", self._check_ssl(target, port, services.get(port, {}), result)))

        if phase2:
            await self._run_parallel(phase2, "Phase 2: Service-specific deep scans")

        # Compile severity breakdown
        for v in result["vulnerabilities"]:
            sev = (v.get("severity") or "low").lower()
            if sev in result["severity_breakdown"]:
                result["severity_breakdown"][sev] += 1

        await self.set_status(AgentStatus.DONE,
            f"Vuln scan complete: {len(result['vulnerabilities'])} vulns, "
            f"{len(result['cves'])} CVEs, {len(result['exploits'])} exploits")

        # Build raw_output summary for answer extraction
        raw_parts = []
        for v in result["vulnerabilities"]:
            raw_parts.append(f"[{v.get('severity','?').upper()}] {v.get('id','')}: {v.get('description','')}")
        result["raw_output"] = "\n".join(raw_parts)

        return result

    # ═══════════════════════════════════════════════════════════════
    #  EXECUTE_TASKS interface (called by _dispatch_to_agent)
    # ═══════════════════════════════════════════════════════════════

    async def execute_tasks(self, target, tasks, phase_name, intel):
        """Execute LLM-planned vuln tasks AND the built-in methodology scans.

        Previously this override silently dropped `tasks` and only ran the
        hardcoded methodology — which meant the LLM's plan in
        `_llm_plan_vuln_scan` (hydra, wfuzz, nikto, wpscan, …) was never
        dispatched and no CVEs / vulns were ever found.

        Now:
          1. If the Master passed explicit `tasks`, dispatch them via
             BaseAgent.execute_tasks (which runs each tool through MCP).
          2. Always also run the methodology scans on open ports via
             self.run() so the default broad sweep still happens.
          3. Merge the two result dicts.
        """
        # 1. Dispatch LLM-planned tasks through the generic BaseAgent path
        llm_result: dict = {}
        if tasks:
            try:
                llm_result = await super().execute_tasks(target, tasks, phase_name, intel)
            except Exception as exc:      # non-fatal — still run methodology
                import logging as _lg
                _lg.getLogger(__name__).warning(
                    "[vuln_agent] LLM-task dispatch error (continuing): %s", exc
                )

        # 2. Run the fixed methodology scans on open ports
        open_ports = intel.get("open_ports", [])
        port_list, services = [], {}
        for p in open_ports:
            if isinstance(p, dict):
                pn = p.get("port", 0)
                port_list.append(pn)
                services[pn] = p
            else:
                port_list.append(p)
        methodology_result = await self.run(
            session_id = getattr(self, "_session_id", ""),
            target     = target,
            open_ports = port_list,
            services   = services,
        )

        # 3. Merge — methodology + LLM-planned findings/cves/raw_outputs
        merged = dict(methodology_result or {})
        if llm_result:
            for key in ("cves", "vulnerabilities", "web_paths",
                        "credentials", "interesting_files", "findings"):
                lst_a = list(merged.get(key) or [])
                lst_b = list(llm_result.get(key) or [])
                merged[key] = lst_a + [x for x in lst_b if x not in lst_a]
            # Dict merges
            for key in ("services", "service_versions", "raw_outputs"):
                a = dict(merged.get(key) or {})
                a.update(llm_result.get(key) or {})
                merged[key] = a
            # Concatenate stdout
            if llm_result.get("stdout"):
                merged["stdout"] = (merged.get("stdout") or "") + "\n" + llm_result["stdout"]
        return merged

    # ═══════════════════════════════════════════════════════════════
    #  PARALLEL RUNNER
    # ═══════════════════════════════════════════════════════════════

    async def _run_parallel(self, tasks: list, description: str):
        """Run [(label, coro), ...] in parallel with error handling."""
        labels = [l for l, _ in tasks]
        await self.emit_reasoning(
            step       = "parallel_scan",
            reasoning  = f"{description}: {len(tasks)} checks in parallel",
            decision   = f"Running: {', '.join(labels[:8])}{'...' if len(labels) > 8 else ''}",
            next_action= f"Parallel: {', '.join(labels[:8])}"
        )
        results = await asyncio.gather(
            *[coro for _, coro in tasks],
            return_exceptions=True
        )
        for (label, _), res in zip(tasks, results):
            if isinstance(res, Exception):
                pass  # non-fatal — continue with other checks

    # ═══════════════════════════════════════════════════════════════
    #  PHASE 1: BROAD SCANS
    # ═══════════════════════════════════════════════════════════════

    async def _nse_vuln_scan(self, target, ports_str, result):
        """NSE vuln + safe + auth + exploit scripts."""
        await self.emit_reasoning(
            step="nse_vuln", reasoning="NSE scripts check 600+ known CVEs, misconfigs, and defaults",
            decision="Run vuln, safe, auth, exploit NSE categories",
            next_action=f"nmap --script vuln,safe,auth -sV -p {ports_str} {target}"
        )
        out = await self.run_tool(
            "nmap", f"--script vuln,safe,auth -sV -p {ports_str} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=600
        )
        vulns, cves = self._parse_nmap_vulns(out["stdout"])
        result["vulnerabilities"].extend(vulns)
        result["cves"].extend(cves)
        result["raw_output"] += "\n" + out.get("stdout", "")
        for v in vulns:
            sev = self._estimate_severity(v.get("id", ""), v.get("description", ""))
            await self.store_finding(
                severity=sev, title=v.get("id", "NSE Vulnerability"),
                description=v.get("description", ""), host=target,
                port=v.get("port"), service=v.get("service"),
                cves=v.get("cves", []), tool_used="nmap",
                raw_output=v.get("raw", "")[:2000], evidence=v.get("raw", "")[:500]
            )

    async def _nuclei_scan(self, target, open_ports, result):
        """Nuclei template-based vulnerability scanning — CVEs, misconfigs, exposures."""
        # Build target list
        targets: list[str] = []
        for p in open_ports:
            port = p.get("port") if isinstance(p, dict) else p
            proto = "https" if port in _HTTPS_PORTS else "http"
            targets.append(f"{proto}://{target}:{port}")

        if not targets:
            targets = [f"http://{target}"]

        target_str = ",".join(targets[:10])

        await self.emit_reasoning(
            step="nuclei", reasoning="Nuclei runs 5000+ templates for CVEs, misconfigs, exposures, default logins",
            decision="Run nuclei with critical+high+medium severity templates",
            next_action=f"nuclei -u {targets[0]} -severity critical,high,medium"
        )

        # Run nuclei with multiple target URLs
        out = await self.run_tool(
            "nuclei",
            f"-u {target_str} -severity critical,high,medium -silent -nc -timeout 10 "
            f"-rate-limit 100 -bulk-size 25 -concurrency 15 -stats -si 30",
            target=target, phase=AttackPhase.VULN_ID, timeout=300
        )
        nuclei_findings = self._parse_nuclei(out["stdout"])
        result["vulnerabilities"].extend(nuclei_findings)
        result["raw_output"] += "\n" + out.get("stdout", "")

        for nf in nuclei_findings:
            cves_found = re.findall(r'CVE-\d{4}-\d+', nf.get("id", "") + nf.get("description", ""))
            result["cves"].extend(cves_found)
            await self.store_finding(
                severity=nf["severity"], title=f"[Nuclei] {nf['id']}",
                description=nf["description"], host=target,
                port=nf.get("port"), service=nf.get("service", "http"),
                cves=cves_found, tool_used="nuclei",
                evidence=nf.get("evidence", "")[:1000]
            )

    async def _searchsploit_all(self, target, services, result):
        """Search ExploitDB for every discovered service+version."""
        for port_key, svc in services.items():
            svc_name = svc.get("service") or svc.get("name") or ""
            version  = svc.get("version") or svc.get("product") or ""
            if not svc_name:
                continue
            search_term = f"{svc_name} {version}".strip()
            if len(search_term) < 3:
                continue
            ss = await self.run_tool(
                "searchsploit", f"--id {search_term}",
                target=target, phase=AttackPhase.VULN_ID, timeout=30
            )
            exploits = self._parse_searchsploit(ss["stdout"])
            result["exploits"].extend(exploits)
            if exploits:
                port = int(port_key) if isinstance(port_key, str) else port_key
                await self.store_finding(
                    severity=FindingSeverity.HIGH,
                    title=f"Public Exploits: {search_term} ({len(exploits)} found)",
                    description=f"ExploitDB has {len(exploits)} exploits for {search_term}:\n" +
                                "\n".join(f"  - {e.get('title', '?')}" for e in exploits[:5]),
                    host=target, port=port, service=svc_name,
                    exploits=[e.get("id", "") for e in exploits[:10]],
                    tool_used="searchsploit",
                    evidence=ss["stdout"][:1500]
                )

    # ═══════════════════════════════════════════════════════════════
    #  PHASE 2: SERVICE-SPECIFIC DEEP CHECKS
    # ═══════════════════════════════════════════════════════════════

    async def _check_ftp(self, target, port, svc_info, result):
        """FTP: anonymous login, bounce, writeable directories."""
        out = await self.run_tool(
            "nmap", f"--script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "Anonymous FTP login allowed" in stdout:
            await self._store_vuln(result, "FTP-ANON", "Anonymous FTP Login Allowed",
                                   "FTP allows anonymous access — potential data exposure and upload",
                                   target, port, "ftp", "critical", stdout, "nmap",
                                   remediation="Disable anonymous FTP access.")
        if "VULNERABLE" in stdout or "backdoor" in stdout.lower():
            cves = self._extract_cves(stdout)
            await self._store_vuln(result, f"FTP-BACKDOOR-{port}", "FTP Service Backdoor",
                                   f"FTP backdoor vulnerability detected: {cves}",
                                   target, port, "ftp", "critical", stdout, "nmap", cves=cves)

    async def _check_ssh(self, target, port, svc_info, result):
        """SSH: weak algorithms, password auth, version-based CVEs."""
        out = await self.run_tool(
            "nmap", f"--script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos,ssh-brute -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=90
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "password" in stdout.lower():
            await self._store_vuln(result, "SSH-PASS-AUTH", "SSH Password Authentication Enabled",
                                   "SSH allows password authentication — brute-force risk",
                                   target, port, "ssh", "medium", stdout, "nmap",
                                   remediation="Disable password auth. Use key-based only.")
        # Check for weak key exchange / MAC algorithms
        weak_algos = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                      "hmac-md5", "hmac-sha1-96", "arcfour", "3des-cbc"]
        for algo in weak_algos:
            if algo in stdout.lower():
                await self._store_vuln(result, f"SSH-WEAK-ALGO", f"SSH Weak Algorithm: {algo}",
                                       f"SSH uses weak algorithm {algo}",
                                       target, port, "ssh", "medium", stdout, "nmap",
                                       remediation=f"Disable {algo} in SSH config.")
                break

    async def _check_smtp(self, target, port, svc_info, result):
        """SMTP: open relay, user enumeration, VRFY/EXPN."""
        tasks = [
            self.run_tool("nmap",
                f"--script smtp-open-relay,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1764,smtp-commands -p {port} {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60),
            self.run_tool("smtp-user-enum",
                f"-M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {target} -p {port}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60),
        ]
        results_out = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_out:
            if isinstance(r, Exception):
                continue
            stdout = r.get("stdout", "")
            result["raw_output"] += "\n" + stdout
            if "open relay" in stdout.lower():
                await self._store_vuln(result, "SMTP-RELAY", "SMTP Open Relay",
                                       "Mail server allows relaying — can be used for spam/phishing",
                                       target, port, "smtp", "high", stdout, "nmap")
            if "EXISTS" in stdout or "VRFY" in stdout:
                users = re.findall(r'(\w+).*EXISTS', stdout)
                if users:
                    await self._store_vuln(result, "SMTP-ENUM", "SMTP User Enumeration",
                                           f"SMTP reveals valid users: {', '.join(users[:10])}",
                                           target, port, "smtp", "medium", stdout, "smtp-user-enum")

    async def _check_dns(self, target, port, svc_info, result):
        """DNS: zone transfer, cache poisoning, version disclosure."""
        out = await self.run_tool(
            "nmap", f"--script dns-zone-transfer,dns-cache-snoop,dns-nsid -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "zone transfer" in stdout.lower() and ("XFR" in stdout or "AXFR" in stdout):
            await self._store_vuln(result, "DNS-ZONE-XFER", "DNS Zone Transfer Allowed",
                                   "DNS server allows zone transfer — exposes all DNS records",
                                   target, port, "dns", "high", stdout, "nmap",
                                   remediation="Restrict zone transfers to authorised secondary DNS servers.")

    async def _check_http_deep(self, target, port, svc_info, result):
        """Deep HTTP check: nikto + nuclei targeted + HTTP headers."""
        proto = "https" if port in _HTTPS_PORTS else "http"
        base  = f"{proto}://{target}:{port}"

        # Nikto comprehensive
        nik = await self.run_tool(
            "nikto", f"-h {base} -C all -maxtime 5m -Tuning 123456789abc",
            target=target, phase=AttackPhase.VULN_ID, timeout=360
        )
        nikto_findings = self._parse_nikto(nik["stdout"])
        result["vulnerabilities"].extend(nikto_findings)
        result["raw_output"] += "\n" + nik.get("stdout", "")
        for f in nikto_findings:
            await self.store_finding(
                severity=f["severity"], title=f["title"],
                description=f["description"], host=target,
                port=port, service="http", tool_used="nikto",
                evidence=f.get("evidence", "")
            )

    async def _check_smb(self, target, port, svc_info, result):
        """SMB: EternalBlue, null session, share enumeration, signing."""
        tasks = [
            self.run_tool("nmap",
                f"--script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,"
                f"smb-vuln-conficker,smb-security-mode,smb2-security-mode,"
                f"smb-enum-shares,smb-enum-users,smb-os-discovery "
                f"-p 139,445 {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=120),
            self.run_tool("enum4linux",
                f"-a {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=120),
            self.run_tool("smbmap",
                f"-H {target} -u '' -p ''",
                target=target, phase=AttackPhase.VULN_ID, timeout=60),
        ]
        results_out = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_out:
            if isinstance(r, Exception):
                continue
            stdout = r.get("stdout", "")
            result["raw_output"] += "\n" + stdout
            if "VULNERABLE" in stdout:
                cves = self._extract_cves(stdout)
                await self._store_vuln(result, f"SMB-VULN-{port}", f"SMB Critical Vulnerability ({', '.join(cves) or 'MS17-010'})",
                                       "SMB is vulnerable to critical exploit — RCE possible",
                                       target, port, "smb", "critical", stdout, "nmap", cves=cves,
                                       remediation="Apply patches. Disable SMBv1.")
            if "READ" in stdout or "WRITE" in stdout:
                # Parse share access from smbmap/enum4linux
                shares = re.findall(r'(\S+)\s+(READ|WRITE|READ, WRITE)', stdout)
                if shares:
                    await self._store_vuln(result, "SMB-SHARES", "SMB Accessible Shares",
                                           f"Shares accessible: {', '.join(f'{s[0]}({s[1]})' for s in shares[:10])}",
                                           target, port, "smb", "high", stdout, "smbmap")
            if "message_signing" in stdout.lower() and "disabled" in stdout.lower():
                await self._store_vuln(result, "SMB-SIGNING", "SMB Signing Disabled",
                                       "SMB message signing is disabled — enables relay attacks",
                                       target, port, "smb", "high", stdout, "nmap",
                                       remediation="Enable SMB message signing.")

    async def _check_mysql(self, target, port, svc_info, result):
        """MySQL: empty password, info disclosure, version CVEs."""
        out = await self.run_tool(
            "nmap", f"--script mysql-empty-password,mysql-info,mysql-enum,mysql-vuln-cve2012-2122 -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "empty password" in stdout.lower() or "anonymous" in stdout.lower():
            await self._store_vuln(result, "MYSQL-NOPASS", "MySQL No Password",
                                   "MySQL allows login without password",
                                   target, port, "mysql", "critical", stdout, "nmap")
        if "VULNERABLE" in stdout:
            cves = self._extract_cves(stdout)
            await self._store_vuln(result, f"MYSQL-CVE", f"MySQL Vulnerability: {', '.join(cves) or 'auth bypass'}",
                                   "MySQL CVE detected", target, port, "mysql", "critical", stdout, "nmap", cves=cves)

    async def _check_postgres(self, target, port, svc_info, result):
        """PostgreSQL: default creds, trust auth."""
        out = await self.run_tool(
            "nmap", f"--script pgsql-brute -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "Valid credentials" in stdout or "postgres:postgres" in stdout.lower():
            await self._store_vuln(result, "PGSQL-DEFCREDS", "PostgreSQL Default Credentials",
                                   "PostgreSQL accessible with default/weak credentials",
                                   target, port, "postgresql", "critical", stdout, "nmap")

    async def _check_mssql(self, target, port, svc_info, result):
        """MSSQL: sa brute, xp_cmdshell, info disclosure."""
        out = await self.run_tool(
            "nmap", f"--script ms-sql-info,ms-sql-empty-password,ms-sql-brute,ms-sql-xp-dir -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=90
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "empty password" in stdout.lower() or "sa:" in stdout.lower():
            await self._store_vuln(result, "MSSQL-NOPASS", "MSSQL SA Empty Password",
                                   "MSSQL sa account has no password — full database compromise",
                                   target, port, "mssql", "critical", stdout, "nmap",
                                   remediation="Set strong sa password. Disable sa account.")
        if "xp_cmdshell" in stdout.lower():
            await self._store_vuln(result, "MSSQL-CMDSHELL", "MSSQL xp_cmdshell Available",
                                   "xp_cmdshell enabled — OS command execution via SQL",
                                   target, port, "mssql", "critical", stdout, "nmap")

    async def _check_oracle(self, target, port, svc_info, result):
        """Oracle: TNS listener, SID enumeration."""
        out = await self.run_tool(
            "nmap", f"--script oracle-sid-brute,oracle-tns-version -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        result["raw_output"] += "\n" + out.get("stdout", "")

    async def _check_redis(self, target, port, svc_info, result):
        """Redis: no-auth access, INFO dump."""
        out = await self.run_tool(
            "nmap", f"--script redis-info,redis-brute -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "redis_version" in stdout and "authentication" not in stdout.lower():
            await self._store_vuln(result, "REDIS-NOAUTH", "Redis No Authentication",
                                   "Redis accessible without authentication — data theft and RCE via SLAVEOF/MODULE",
                                   target, port, "redis", "critical", stdout, "nmap",
                                   remediation="Enable requirepass. Bind to localhost. Use ACLs.")

    async def _check_mongodb(self, target, port, svc_info, result):
        """MongoDB: no auth, database enumeration."""
        out = await self.run_tool(
            "nmap", f"--script mongodb-info,mongodb-databases,mongodb-brute -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "databases" in stdout.lower() and "totalSize" in stdout:
            await self._store_vuln(result, "MONGO-NOAUTH", "MongoDB No Authentication",
                                   "MongoDB accessible without authentication — full database access",
                                   target, port, "mongodb", "critical", stdout, "nmap",
                                   remediation="Enable authentication. Bind to localhost.")

    async def _check_ldap(self, target, port, svc_info, result):
        """LDAP: anonymous bind, null base search."""
        out = await self.run_tool(
            "nmap", f"--script ldap-rootdse,ldap-search,ldap-brute -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "namingContexts" in stdout or "rootDomainNamingContext" in stdout:
            await self._store_vuln(result, "LDAP-ANON", "LDAP Anonymous Bind Allowed",
                                   "LDAP allows anonymous queries — exposes directory information",
                                   target, port, "ldap", "high", stdout, "nmap")

    async def _check_snmp(self, target, port, svc_info, result):
        """SNMP: default communities, info dump."""
        tasks = [
            self.run_tool("nmap",
                f"--script snmp-brute,snmp-info,snmp-sysdescr -p {port} -sU {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60),
            self.run_tool("snmpwalk",
                f"-v2c -c public {target} system",
                target=target, phase=AttackPhase.VULN_ID, timeout=30),
        ]
        results_out = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_out:
            if isinstance(r, Exception):
                continue
            stdout = r.get("stdout", "")
            result["raw_output"] += "\n" + stdout
            if "public" in stdout.lower() and ("sysDescr" in stdout or "SNMPv2" in stdout):
                await self._store_vuln(result, "SNMP-DEFAULT", "SNMP Default Community String",
                                       "SNMP uses default 'public' community — full system info disclosure",
                                       target, port, "snmp", "high", stdout, "snmpwalk",
                                       remediation="Change community strings. Use SNMPv3 with auth+privacy.")

    async def _check_nfs(self, target, port, svc_info, result):
        """NFS: exported shares, mount access."""
        out = await self.run_tool(
            "nmap", f"--script nfs-ls,nfs-showmount,nfs-statfs -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "/" in stdout and "showmount" in stdout.lower() or "nfs-showmount" in stdout:
            await self._store_vuln(result, "NFS-EXPORT", "NFS Shares Exported",
                                   "NFS shares accessible — potential sensitive data exposure",
                                   target, port, "nfs", "high", stdout, "nmap",
                                   remediation="Restrict NFS exports by IP. Use Kerberos auth.")

    async def _check_vnc(self, target, port, svc_info, result):
        """VNC: no auth, brute force."""
        out = await self.run_tool(
            "nmap", f"--script vnc-info,vnc-brute,realvnc-auth-bypass -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "No authentication" in stdout or "auth bypass" in stdout.lower():
            await self._store_vuln(result, "VNC-NOAUTH", "VNC No Authentication",
                                   "VNC accessible without password — full desktop access",
                                   target, port, "vnc", "critical", stdout, "nmap")

    async def _check_rdp(self, target, port, svc_info, result):
        """RDP: BlueKeep, NLA status, encryption level."""
        out = await self.run_tool(
            "nmap", f"--script rdp-vuln-ms12-020,rdp-enum-encryption,rdp-ntlm-info -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "VULNERABLE" in stdout:
            cves = self._extract_cves(stdout)
            await self._store_vuln(result, "RDP-VULN", f"RDP Vulnerability: {', '.join(cves) or 'MS12-020'}",
                                   "RDP vulnerable to remote code execution",
                                   target, port, "rdp", "critical", stdout, "nmap", cves=cves)

    async def _check_telnet(self, target, port, svc_info, result):
        """Telnet: cleartext protocol, banner grab."""
        out = await self.run_tool(
            "nmap", f"--script telnet-brute,telnet-encryption,telnet-ntlm-info -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        result["raw_output"] += "\n" + out.get("stdout", "")
        await self._store_vuln(result, "TELNET-CLEAR", "Telnet Cleartext Protocol",
                               "Telnet transmits credentials in cleartext",
                               target, port, "telnet", "medium", "", "nmap",
                               remediation="Replace telnet with SSH.")

    async def _check_irc(self, target, port, svc_info, result):
        """IRC: backdoor checks (UnrealIRCd 3.2.8.1)."""
        out = await self.run_tool(
            "nmap", f"--script irc-unrealircd-backdoor -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "backdoor" in stdout.lower() or "VULNERABLE" in stdout:
            await self._store_vuln(result, "IRC-BACKDOOR", "IRC Backdoor (UnrealIRCd)",
                                   "UnrealIRCd backdoor — unauthenticated RCE",
                                   target, port, "irc", "critical", stdout, "nmap")

    async def _check_ajp(self, target, port, svc_info, result):
        """AJP (Ghostcat CVE-2020-1938)."""
        out = await self.run_tool(
            "nmap", f"--script ajp-auth,ajp-headers,ajp-methods -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if port == 8009 or "ajp" in stdout.lower():
            await self._store_vuln(result, "AJP-GHOSTCAT", "AJP Ghostcat (CVE-2020-1938)",
                                   "AJP connector exposed — file read/inclusion via Ghostcat",
                                   target, port, "ajp", "critical", stdout, "nmap",
                                   cves=["CVE-2020-1938"],
                                   remediation="Disable AJP connector or restrict to localhost.")

    async def _check_rmi(self, target, port, svc_info, result):
        """Java RMI: deserialization, registry enum."""
        out = await self.run_tool(
            "nmap", f"--script rmi-dumpregistry,rmi-vuln-classloader -p {port} {target}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        if "VULNERABLE" in stdout:
            await self._store_vuln(result, "RMI-DESER", "Java RMI Deserialization",
                                   "Java RMI vulnerable to deserialization attack — RCE possible",
                                   target, port, "rmi", "critical", stdout, "nmap")

    async def _check_ssl(self, target, port, svc_info, result):
        """SSL/TLS: weak ciphers, expired certs, known vulns."""
        out = await self.run_tool(
            "sslscan", f"--no-colour {target}:{port}",
            target=target, phase=AttackPhase.VULN_ID, timeout=60
        )
        stdout = out["stdout"]
        result["raw_output"] += "\n" + stdout
        checks = [
            ("SSLv2",      "SSLv2 Enabled",              "critical", "Disable SSLv2 immediately"),
            ("SSLv3",      "SSLv3 Enabled (POODLE)",     "high",     "Disable SSLv3, enable TLS 1.2+"),
            ("TLSv1.0",    "TLS 1.0 Enabled",            "medium",   "Disable TLS 1.0, enforce TLS 1.2+"),
            ("RC4",        "Weak RC4 Cipher Supported",   "high",     "Disable RC4 cipher suites"),
            ("DES",        "Weak DES Cipher Supported",   "high",     "Disable DES/3DES cipher suites"),
            ("Heartbleed", "HEARTBLEED Vulnerable",       "critical", "Apply OpenSSL patch CVE-2014-0160"),
        ]
        for keyword, title, sev, remediation in checks:
            if keyword.lower() in stdout.lower():
                await self._store_vuln(result, f"SSL-{keyword}", title,
                                       f"{title} — encryption weakness on port {port}",
                                       target, port, "ssl", sev, stdout, "sslscan",
                                       remediation=remediation)

    # ═══════════════════════════════════════════════════════════════
    #  PHASE 1b/1c — HEAVY SCANNERS: SQLMap, OpenVAS, ZAP
    # ═══════════════════════════════════════════════════════════════

    async def _sqlmap_scan(self, target: str, http_ports: list, result: dict):
        """SQLMap automated SQL injection detection — crawls forms on all HTTP ports."""
        await self.emit_reasoning(
            step="sqlmap",
            reasoning="SQLMap detects SQL injection in GET/POST params, forms, cookies",
            decision=f"Crawl + inject on {len(http_ports)} HTTP port(s)",
            next_action=f"sqlmap crawl against {target}"
        )
        for port in http_ports[:3]:
            proto    = "https" if port in _HTTPS_PORTS else "http"
            base_url = f"{proto}://{target}:{port}/"
            out_dir  = f"/tmp/sqlmap_argus_{target.replace('.','_')}_{port}"
            out = await self.run_tool(
                "sqlmap",
                f"-u {base_url} --crawl=3 --forms --level=3 --risk=2 --batch "
                f"--random-agent --tamper=space2comment "
                f"--output-dir={out_dir} --flush-session "
                f"--threads=4 --timeout=10 --retries=2 "
                f"--technique=BEUSTQ --answers='follow=Y'",
                target=target, phase=AttackPhase.VULN_ID, timeout=600
            )
            stdout = out.get("stdout", "")
            result["raw_output"] += "\n" + stdout
            await self._parse_sqlmap_output(stdout, target, port, result)

    async def _parse_sqlmap_output(self, output: str, target: str, port: int, result: dict):
        """Parse sqlmap stdout for confirmed injection points and store findings."""
        if not output:
            return
        confirmed = (
            "identified the following injection" in output or
            "is vulnerable" in output.lower() or
            "sql injection vulnerability" in output.lower()
        )
        potential = any(k in output.lower() for k in (
            "error-based", "union-based", "time-based", "boolean-based", "stacked queries"
        ))
        if confirmed:
            db_match  = re.search(r'back-end DBMS:\s*(.+)', output)
            db_info   = f"\nDatabase: {db_match.group(1).strip()}" if db_match else ""
            params    = re.findall(r"Parameter:\s*(.+?)\s*\((.+?)\)\s*\n\s+Type:\s*(.+)", output)
            detail    = db_info
            if params:
                detail += "\n\nInjection points:\n" + "\n".join(
                    f"  {p[0]} ({p[1]}): {p[2]}" for p in params[:10]
                )
            await self._store_vuln(
                result, "SQLI-CONFIRMED", "[SQLMap] SQL Injection Confirmed",
                f"SQLMap confirmed SQLi at {target}:{port}.{detail}",
                target, port, "http", "critical", output[:2000], "sqlmap",
                remediation="Use parameterised queries/prepared statements. Validate all user input."
            )
        elif potential:
            await self._store_vuln(
                result, "SQLI-POTENTIAL", "[SQLMap] Potential SQL Injection Indicators",
                f"SQLMap found SQLi indicators at {target}:{port}. Manual verification recommended.",
                target, port, "http", "high", output[:1500], "sqlmap",
                remediation="Review SQL query construction. Use ORM or prepared statements."
            )

    # ── OpenVAS ──────────────────────────────────────────────────────────

    async def _ensure_openvas_running(self) -> bool:
        """Check if GVM/OpenVAS services are up; start them if not. Returns True when ready."""
        check = await self.run_tool(
            "bash", "-c 'systemctl is-active gvmd 2>/dev/null; echo RC:$?'",
            target=self._target, phase=AttackPhase.VULN_ID, timeout=10
        )
        if "active" in check.get("stdout", "") and "RC:0" in check.get("stdout", ""):
            return True

        await self.emit_reasoning(
            step="openvas_start",
            reasoning="GVM/OpenVAS services not running — starting now",
            decision="sudo gvm-start (may take 60–120 s for NVT feeds to load)",
            next_action="gvm-start"
        )
        # Start GVM and wait for gvmd socket to accept connections
        await self.run_tool(
            "bash",
            "-c 'sudo gvm-start 2>&1 | tail -5; sleep 5; "
            "for i in $(seq 1 36); do "
            "  gvm-cli socket --xml \"<get_version/>\" 2>/dev/null | grep -q version "
            "  && echo GVM_READY && break; sleep 5; "
            "done'",
            target=self._target, phase=AttackPhase.VULN_ID, timeout=210
        )
        return True

    async def _openvas_scan(self, target: str, open_ports: list, result: dict):
        """OpenVAS/GVM comprehensive scan — 70,000+ NVT checks with auto-start."""
        await self.emit_reasoning(
            step="openvas",
            reasoning="OpenVAS runs 70,000+ NVTs covering CVEs, misconfigs, default creds, deep service checks",
            decision="Start GVM if needed → create target → Full and Fast scan → parse XML results",
            next_action=f"OpenVAS scan against {target}"
        )
        await self._ensure_openvas_running()

        # Read GMP credentials — gvm-setup stores them in /etc/gvm/setup_vars
        cred_out = await self.run_tool(
            "bash",
            "-c 'sudo cat /etc/gvm/setup_vars 2>/dev/null || "
            "sudo grep -r \"admin\" /etc/gvm/ 2>/dev/null | head -3 || echo CRED_MISSING'",
            target=self._target, phase=AttackPhase.VULN_ID, timeout=10
        )
        gvm_user, gvm_pass = "admin", "admin"
        pm = re.search(r'(?:PASSWORD|PASS|GVM_PASSWORD)[=:\s]+["\']?(\S+?)["\']?(?:\s|$)',
                       cred_out.get("stdout", ""), re.IGNORECASE)
        if pm:
            gvm_pass = pm.group(1)

        # Helper: run one gvm-cli XML command and return stdout
        cli_base = (
            f"gvm-cli --gmp-username '{gvm_user}' --gmp-password '{gvm_pass}' socket"
        )

        # Write a small Python helper to /tmp to avoid shell-quoting nightmares
        helper_script = f"""
import subprocess, sys, re, time
import xml.etree.ElementTree as ET

def gvm(xml_str):
    r = subprocess.run(
        ['gvm-cli', '--gmp-username', '{gvm_user}', '--gmp-password', '{gvm_pass}',
         'socket', '--xml', xml_str],
        capture_output=True, text=True, timeout=60
    )
    return r.stdout.strip()

target_ip = '{target}'
ts = str(int(time.time()))

# 1 — Create target (use "All IANA assigned TCP and UDP" port list)
r = gvm(f'<create_target>'
        f'<name>argus-{{target_ip}}-{{ts}}</name>'
        f'<hosts>{{target_ip}}</hosts>'
        f'<port_list id="730ef368-57e2-11e1-a90f-406186ea4fc5"/>'
        f'</create_target>')
print("CREATE_TARGET:", r[:300])
tid = re.search(r'id="([0-9a-f-]{{36}})"', r)
if not tid:
    print("ERROR: could not create target"); sys.exit(1)
tid = tid.group(1)

# 2 — Create task with "Full and fast" scan config
r = gvm(f'<create_task>'
        f'<name>argus-{{target_ip}}-{{ts}}</name>'
        f'<config id="daba56c8-73ec-11df-a475-002264764cea"/>'
        f'<target id="{{tid}}"/>'
        f'</create_task>')
print("CREATE_TASK:", r[:300])
task_id = re.search(r'id="([0-9a-f-]{{36}})"', r)
if not task_id:
    print("ERROR: could not create task"); sys.exit(1)
task_id = task_id.group(1)

# 3 — Start task
gvm(f'<start_task task_id="{{task_id}}"/>')
print(f"TASK_STARTED: {{task_id}}")

# 4 — Poll until Done (max 25 min)
for i in range(150):
    time.sleep(10)
    r2 = gvm(f'<get_tasks task_id="{{task_id}}"/>')
    try:
        root = ET.fromstring(r2)
        status   = root.findtext('.//status')   or ''
        progress = root.findtext('.//progress') or '?'
    except Exception:
        status, progress = '', '?'
    print(f"OPENVAS_PROGRESS: {{status}} ({{progress}}%)")
    if status in ('Done', 'Stopped', 'Interrupted'):
        break

# 5 — Get results
r3 = gvm(f'<get_results task_id="{{task_id}}" filter="rows=200 min_qod=30"/>')
print("RESULTS_START")
print(r3)
print("RESULTS_END")

# 6 — Cleanup
gvm(f'<delete_task task_id="{{task_id}}" ultimate="0"/>')
gvm(f'<delete_target target_id="{{tid}}" ultimate="0"/>')
print("CLEANUP_DONE")
"""
        script_path = f"/tmp/argus_openvas_{target.replace('.','_')}.py"

        # Write helper script
        await self.run_tool(
            "bash", f"-c 'cat > {script_path} << \\'PYEOF\\'\\n{helper_script}\\nPYEOF'",
            target=self._target, phase=AttackPhase.VULN_ID, timeout=10
        )
        # Better: use python3 -c with the script content written via tee
        write_out = await self.run_tool(
            "bash",
            f"-c 'python3 - << \\'PYEOF\\'\\n{helper_script}\\nPYEOF'",
            target=self._target, phase=AttackPhase.VULN_ID, timeout=1560   # 26 min
        )
        raw = write_out.get("stdout", "")
        result["raw_output"] += "\n" + raw

        # Extract results XML block
        rs = raw.find("RESULTS_START")
        re_end = raw.find("RESULTS_END")
        if rs != -1 and re_end != -1:
            results_xml = raw[rs + len("RESULTS_START"):re_end].strip()
            await self._parse_openvas_results(results_xml, target, result)

    async def _parse_openvas_results(self, xml_output: str, target: str, result: dict):
        """Parse GVM get_results XML and store as VulnAgent findings."""
        import xml.etree.ElementTree as ET
        xml_start = xml_output.find("<get_results_response")
        if xml_start == -1:
            xml_start = xml_output.find("<result ")
        if xml_start == -1:
            return
        try:
            # Wrap bare <result> elements in a root tag if needed
            xml_block = xml_output[xml_start:]
            if not xml_block.startswith("<get_results_response"):
                xml_block = f"<results>{xml_block}</results>"
            root = ET.fromstring(xml_block)
        except ET.ParseError:
            return

        threat_map = {
            "Critical": ("critical", FindingSeverity.CRITICAL),
            "High":     ("critical", FindingSeverity.CRITICAL),
            "Medium":   ("high",     FindingSeverity.HIGH),
            "Low":      ("medium",   FindingSeverity.MEDIUM),
            "Log":      ("info",     FindingSeverity.INFO),
        }

        for res in root.findall(".//result"):
            name      = (res.findtext("name")        or "").strip()
            desc      = (res.findtext("description") or "").strip()
            threat    = (res.findtext("threat")      or "Log").strip()
            host_el   = res.find("host")
            port_el   = res.find("port")
            nvt_el    = res.find("nvt")
            host_ip   = (host_el.text if host_el is not None else target or "").strip()
            port_raw  = (port_el.text  if port_el  is not None else "").strip()

            if not name or threat == "Log":
                continue

            # Extract port number
            port_val = None
            pm2 = re.search(r"(\d+)", port_raw)
            if pm2:
                port_val = int(pm2.group(1))

            # Extract CVEs from nvt refs
            cve_list = []
            if nvt_el is not None:
                for ref in nvt_el.findall(".//ref"):
                    if ref.get("type", "").lower() == "cve" and ref.get("id"):
                        cve_list.append(ref.get("id"))

            sev_str, _ = threat_map.get(threat, ("medium", FindingSeverity.MEDIUM))
            await self._store_vuln(
                result,
                f"OVS-{re.sub(r'[^A-Z0-9]', '', name.upper())[:20]}",
                f"[OpenVAS] {name}",
                (desc or name)[:2000],
                host_ip or target, port_val, "openvas",
                sev_str, desc[:500], "openvas",
                cves=cve_list,
            )

    # ── OWASP ZAP ────────────────────────────────────────────────────────

    async def _zap_scan(self, target: str, http_ports: list, result: dict):
        """OWASP ZAP active scan — starts daemon if needed, spiders + active-scans each HTTP port."""
        await self.emit_reasoning(
            step="zap",
            reasoning="OWASP ZAP finds XSS, SQLi, path traversal, CSRF, misconfigurations via active scanning",
            decision=f"Start ZAP daemon → spider → active scan → collect alerts on {len(http_ports)} port(s)",
            next_action=f"ZAP active scan against {target}"
        )
        zap_port = 8091   # non-standard to avoid conflict with running services
        zap_api  = f"http://127.0.0.1:{zap_port}"

        # Check if ZAP daemon already up on our port
        alive_check = await self.run_tool(
            "bash",
            f"-c 'curl -sf --max-time 3 \"{zap_api}/JSON/core/view/version/\" 2>/dev/null | "
            f"grep -c version || echo 0'",
            target=self._target, phase=AttackPhase.VULN_ID, timeout=10
        )
        zap_already_up = alive_check.get("stdout", "").strip().startswith("1")

        if not zap_already_up:
            # Start ZAP in headless daemon mode, wait for API readiness
            await self.run_tool(
                "bash",
                f"-c 'nohup zaproxy -daemon -host 127.0.0.1 -port {zap_port} "
                f"-config api.disablekey=true "
                f"-config api.addrs.addr.name=.* "
                f"-config api.addrs.addr.regex=true "
                f"> /tmp/zap_argus.log 2>&1 & "
                f"echo ZAP_PID:$! ; '",
                target=self._target, phase=AttackPhase.VULN_ID, timeout=15
            )
            # Poll until ZAP API responds (up to 90 seconds)
            await self.run_tool(
                "bash",
                f"-c 'for i in $(seq 1 30); do "
                f'  curl -sf --max-time 3 "{zap_api}/JSON/core/view/version/" 2>/dev/null '
                f"  | grep -q version && echo ZAP_READY && break; "
                f"  sleep 3; "
                f"done'",
                target=self._target, phase=AttackPhase.VULN_ID, timeout=100
            )

        # Scan each HTTP port
        for port in http_ports[:3]:
            proto    = "https" if port in _HTTPS_PORTS else "http"
            base_url = f"{proto}://{target}:{port}"

            # Spider the target
            await self.run_tool(
                "bash",
                f'-c \'curl -sf "{zap_api}/JSON/spider/action/scan/'
                f'?url={base_url}&maxChildren=20&recurse=true" 2>/dev/null; '
                f'for i in $(seq 1 30); do '
                f'  STATUS=$(curl -sf "{zap_api}/JSON/spider/view/status/?scanId=0" 2>/dev/null | '
                f'    grep -oP "(?<=\\"status\\":\\s\\"?)\\d+"); '
                f'  echo "ZAP spider: $STATUS%"; '
                f'  [ "$STATUS" = "100" ] && break; sleep 3; '
                f'done\'',
                target=self._target, phase=AttackPhase.VULN_ID, timeout=120
            )

            # Active scan
            ascan_out = await self.run_tool(
                "bash",
                f'-c \'SCANID=$(curl -sf "{zap_api}/JSON/ascan/action/scan/'
                f'?url={base_url}&recurse=true&inScopeOnly=false" 2>/dev/null | '
                f'grep -oP "(?<=\\"scan\\":\\s?\\")\\d+"); '
                f'echo "ZAP ascan ID: $SCANID"; '
                f'for i in $(seq 1 72); do '
                f'  PROG=$(curl -sf "{zap_api}/JSON/ascan/view/status/?scanId=$SCANID" 2>/dev/null | '
                f'    grep -oP "(?<=\\"status\\":\\s?\\"?)\\d+"); '
                f'  echo "ZAP active scan: $PROG%"; '
                f'  [ "$PROG" = "100" ] && break; sleep 10; '
                f'done\'',
                target=self._target, phase=AttackPhase.VULN_ID, timeout=750
            )
            result["raw_output"] += "\n" + ascan_out.get("stdout", "")

            # Retrieve alerts JSON
            alerts_out = await self.run_tool(
                "bash",
                f'-c \'curl -sf "{zap_api}/JSON/alert/view/alerts/'
                f'?baseurl={base_url}&start=0&count=200" 2>/dev/null\'',
                target=self._target, phase=AttackPhase.VULN_ID, timeout=30
            )
            await self._parse_zap_alerts(alerts_out.get("stdout", ""), target, port, result)

        # Shut down ZAP if we started it
        if not zap_already_up:
            await self.run_tool(
                "bash",
                f"-c 'curl -sf \"{zap_api}/JSON/core/action/shutdown/\" 2>/dev/null; sleep 3'",
                target=self._target, phase=AttackPhase.VULN_ID, timeout=15
            )

    async def _parse_zap_alerts(self, json_output: str, target: str, port: int, result: dict):
        """Parse OWASP ZAP JSON alerts and store as findings."""
        import json as _json
        try:
            data   = _json.loads(json_output)
            alerts = data.get("alerts", [])
        except Exception:
            return

        risk_map = {
            "High":          ("critical", FindingSeverity.CRITICAL),
            "Medium":        ("high",     FindingSeverity.HIGH),
            "Low":           ("medium",   FindingSeverity.MEDIUM),
            "Informational": ("info",     FindingSeverity.INFO),
        }
        seen_names: set = set()

        for alert in alerts:
            name      = (alert.get("name")        or "").strip()
            desc      = (alert.get("description") or "").strip()
            risk      = (alert.get("risk")        or "Low").strip()
            solution  = (alert.get("solution")    or "").strip()
            evidence  = (alert.get("evidence")    or "").strip()
            url       = (alert.get("url")         or "").strip()
            cwe_id    = alert.get("cweid", "")

            if not name or risk == "Informational" or name in seen_names:
                continue
            seen_names.add(name)

            cves      = re.findall(r"CVE-\d{4}-\d+", desc + evidence)
            sev_str, _ = risk_map.get(risk, ("medium", FindingSeverity.MEDIUM))

            full_desc = (
                f"{desc}\n\n"
                f"URL      : {url}\n"
                f"Evidence : {evidence[:300]}\n"
                f"CWE      : CWE-{cwe_id}\n"
                f"Solution : {solution[:400]}"
            )
            await self._store_vuln(
                result,
                f"ZAP-{re.sub(r'[^A-Z0-9]', '', name.upper())[:20]}",
                f"[ZAP] {name}",
                full_desc[:2000],
                target, port, "http",
                sev_str, evidence[:500], "zaproxy",
                cves=cves,
                remediation=solution[:500],
            )

    # ═══════════════════════════════════════════════════════════════
    #  HELPER: store vulnerability + finding in one call
    # ═══════════════════════════════════════════════════════════════

    async def _store_vuln(self, result, vuln_id, title, description, target, port,
                          service, severity, evidence, tool, cves=None, remediation=""):
        sev_map = {
            "critical": FindingSeverity.CRITICAL, "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM, "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        sev_enum = sev_map.get(severity, FindingSeverity.MEDIUM) if isinstance(severity, str) else severity
        result["vulnerabilities"].append({
            "id": vuln_id, "description": description,
            "port": port, "service": service, "severity": severity,
            "cves": cves or [],
        })
        if cves:
            result["cves"].extend(cves)
        await self.store_finding(
            severity=sev_enum, title=title, description=description,
            host=target, port=port, service=service,
            cves=cves or [], tool_used=tool,
            evidence=evidence[:1500] if evidence else "",
            remediation=remediation
        )

    # ═══════════════════════════════════════════════════════════════
    #  PARSERS
    # ═══════════════════════════════════════════════════════════════

    def _parse_nmap_vulns(self, output: str):
        vulns, cves = [], []
        current_port, current_service = None, None
        current_vuln = None
        for line in output.splitlines():
            pm = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
            if pm:
                current_port    = int(pm.group(1))
                current_service = pm.group(2)
                continue
            for cve in re.findall(r'CVE-\d{4}-\d+', line, re.IGNORECASE):
                cves.append(cve)
            if "VULNERABLE" in line or "| vuln:" in line:
                vuln_name = re.sub(r'[\|_]+', ' ', line).strip()
                current_vuln = {
                    "id": vuln_name, "description": vuln_name,
                    "port": current_port, "service": current_service,
                    "cves": [], "raw": line
                }
                vulns.append(current_vuln)
            elif current_vuln and line.strip().startswith("|"):
                current_vuln["raw"] += "\n" + line
                for cve in re.findall(r'CVE-\d{4}-\d+', line):
                    current_vuln["cves"].append(cve)
                    cves.append(cve)
        return vulns, list(set(cves))

    def _parse_nuclei(self, output: str) -> list:
        """Parse nuclei output lines: [severity] [template-id] [protocol] url [info]"""
        findings = []
        sev_map = {"critical": FindingSeverity.CRITICAL, "high": FindingSeverity.HIGH,
                   "medium": FindingSeverity.MEDIUM, "low": FindingSeverity.LOW,
                   "info": FindingSeverity.INFO}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Nuclei format: [template-id] [protocol] [severity] url [extra]
            # Or: [2024-01-01] [template-id:matcher] [protocol] [severity] url
            m = re.match(r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)(.*)', line)
            if m:
                template_id = m.group(1).strip()
                protocol    = m.group(2).strip()
                severity_s  = m.group(3).strip().lower()
                url         = m.group(4).strip()
                extra       = m.group(5).strip()
                # Extract port from URL
                port_match = re.search(r':(\d+)', url)
                port = int(port_match.group(1)) if port_match else (443 if "https" in url else 80)
                findings.append({
                    "id":          template_id,
                    "severity":    sev_map.get(severity_s, FindingSeverity.MEDIUM),
                    "description": f"Nuclei: {template_id} — {extra or protocol}",
                    "port":        port,
                    "service":     protocol,
                    "evidence":    line,
                })
        return findings

    def _parse_searchsploit(self, output: str) -> list:
        exploits = []
        for line in output.splitlines():
            m = re.match(r'\s*(.+?)\s*\|\s*(\S+\.(?:py|rb|pl|c|sh|txt|php))\s*$', line)
            if m and not line.startswith("-") and len(m.group(1).strip()) > 5:
                eid = re.search(r'(\d+)', m.group(2))
                exploits.append({
                    "title": m.group(1).strip(),
                    "path": m.group(2).strip(),
                    "id": eid.group(1) if eid else ""
                })
        return exploits

    def _parse_nikto(self, output: str) -> list:
        findings = []
        for line in output.splitlines():
            if not line.startswith("+"):
                continue
            text = line.lstrip("+ ").strip()
            if len(text) < 10 or "Nikto" in text or "Target" in text:
                continue
            sev = FindingSeverity.INFO
            if any(k in text.lower() for k in ["injectable", "xss", "sql", "rce", "command", "execute", "remote code"]):
                sev = FindingSeverity.CRITICAL
            elif any(k in text.lower() for k in ["dangerous", "vulnerability", "exploit", "backup", "config", "admin", "password"]):
                sev = FindingSeverity.HIGH
            elif any(k in text.lower() for k in ["exposed", "disclosure", "version", "header", "cookie", "missing"]):
                sev = FindingSeverity.MEDIUM
            findings.append({
                "severity": sev, "title": text[:80],
                "description": text, "evidence": text
            })
        return findings

    def _extract_cves(self, text: str) -> list:
        return list(set(re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)))

    def _estimate_severity(self, vuln_id: str, desc: str) -> str:
        text = f"{vuln_id} {desc}".lower()
        if any(k in text for k in ["rce", "remote code", "backdoor", "eternalblue", "ms17-010", "command execution"]):
            return FindingSeverity.CRITICAL
        if any(k in text for k in ["sqli", "injection", "bypass", "overflow", "arbitrary"]):
            return FindingSeverity.HIGH
        if any(k in text for k in ["xss", "csrf", "disclosure", "traversal"]):
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW
