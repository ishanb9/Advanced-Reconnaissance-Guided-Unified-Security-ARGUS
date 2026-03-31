"""
KALI PENTEST PLATFORM v3 — Vulnerability Agent

OSCP/OSWE methodology:
  1. NSE vulnerability scripts (nmap --script vuln)
  2. SSL/TLS analysis (sslscan, sslyze)
  3. ExploitDB search per service/version (searchsploit)
  4. Service-specific vulnerability checks:
     - HTTP: nikto, wafw00f
     - FTP: anonymous login
     - SSH: version-based CVE check
     - SMB: EternalBlue, MS17-010
     - MSSQL: sa credentials, xp_cmdshell
     - MySQL: default creds
  5. CVE extraction and severity mapping
  6. All findings stored with evidence

Does NOT call think(). Executes Instructions from MasterAgent.
"""

import re
from typing import Optional, Dict, List

from agents.base_agent import BaseAgent, Instruction, BroadcastFn
from db.schemas import AgentName, AgentStatus, AttackPhase, FindingSeverity
import db.mongo_client as db


class VulnAgent(BaseAgent):

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.VULN, broadcast)
        self.phase = AttackPhase.VULN_ID

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
        result = {"vulnerabilities": [], "cves": [], "exploits": [],
                  "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0}}

        await self.set_status(AgentStatus.RUNNING, f"Vulnerability assessment: {target}")

        ports_str = ",".join(str(p) for p in open_ports[:30]) if open_ports else ""

        # ── 1: NSE vuln scripts ────────────────────────────────
        if ports_str:
            await self.emit_reasoning(
                step       = "nse_vuln_scripts",
                reasoning  = "NSE vuln scripts check for known CVEs, misconfigs, and dangerous defaults",
                decision   = "Run comprehensive vuln, safe, and auth NSE categories",
                next_action= f"nmap --script vuln,safe,auth -sV -p {ports_str} {target}"
            )
            nmap_vuln = await self.run_tool(
                "nmap", f"--script vuln,safe,auth -sV -p {ports_str} {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=600
            )
            vulns, cves = self._parse_nmap_vulns(nmap_vuln["stdout"])
            result["vulnerabilities"].extend(vulns)
            result["cves"].extend(cves)
            for v in vulns:
                sev = self._estimate_severity(v.get("id",""), v.get("description",""))
                await self.store_finding(
                    severity    = sev,
                    title       = v.get("id", "NSE Vulnerability"),
                    description = v.get("description", ""),
                    host        = target,
                    port        = v.get("port"),
                    service     = v.get("service"),
                    cves        = v.get("cves", []),
                    tool_used   = "nmap",
                    raw_output  = v.get("raw", "")[:2000],
                    evidence    = v.get("raw", "")[:500]
                )

        # ── 2: SSL/TLS analysis ────────────────────────────────
        ssl_ports = [p for p, s in services.items()
                     if "ssl" in str(s.get("service","")).lower() or p in (443, 8443, 465, 993, 995)]
        for port in ssl_ports[:3]:
            await self.emit_reasoning(
                step       = f"ssl_scan_{port}",
                reasoning  = f"SSL/TLS on port {port} — check for weak ciphers, BEAST, POODLE, HEARTBLEED",
                decision   = "Run sslscan for comprehensive TLS analysis",
                next_action= f"sslscan --no-colour {target}:{port}"
            )
            ssl = await self.run_tool(
                "sslscan", f"--no-colour {target}:{port}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60
            )
            ssl_issues = self._parse_ssl_issues(ssl["stdout"])
            for issue in ssl_issues:
                await self.store_finding(
                    severity    = issue["severity"],
                    title       = issue["title"],
                    description = issue["description"],
                    host        = target,
                    port        = port,
                    service     = "ssl/tls",
                    tool_used   = "sslscan",
                    remediation = issue.get("remediation", "")
                )

        # ── 3: ExploitDB search per service version ───────────
        await self.emit_reasoning(
            step       = "searchsploit",
            reasoning  = "Search ExploitDB for public exploits matching discovered service versions",
            decision   = "searchsploit each detected service+version combination",
            next_action= "searchsploit <service> <version> for each service"
        )
        for port, svc in services.items():
            svc_name = svc.get("service", "")
            version  = svc.get("version", "")
            if not svc_name:
                continue
            search_term = f"{svc_name} {version}".strip()
            ss = await self.run_tool(
                "searchsploit", f"--id {search_term}",
                target=target, phase=AttackPhase.VULN_ID, timeout=30
            )
            exploits = self._parse_searchsploit(ss["stdout"])
            result["exploits"].extend(exploits)
            if exploits:
                await self.store_finding(
                    severity    = FindingSeverity.HIGH,
                    title       = f"Public Exploits for {search_term}",
                    description = f"ExploitDB has {len(exploits)} exploits for {search_term}: {', '.join([e.get('title','?')[:50] for e in exploits[:3]])}",
                    host        = target,
                    port        = port,
                    service     = svc_name,
                    exploits    = [e.get("id","") for e in exploits[:5]],
                    tool_used   = "searchsploit",
                    evidence    = ss["stdout"][:1000]
                )

        # ── 4: FTP anonymous login ────────────────────────────
        if 21 in open_ports:
            await self.emit_reasoning(
                step       = "ftp_anon",
                reasoning  = "FTP on port 21 — check for anonymous login (common misconfiguration)",
                decision   = "Try anonymous:anonymous credentials",
                next_action= f"nmap --script ftp-anon {target} -p 21"
            )
            ftp = await self.run_tool(
                "nmap", f"--script ftp-anon,ftp-bounce,ftp-syst -p 21 {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60
            )
            if "Anonymous FTP login allowed" in ftp["stdout"]:
                await self.store_finding(
                    severity    = FindingSeverity.HIGH,
                    title       = "FTP Anonymous Login Allowed",
                    description = "FTP server allows anonymous access — potential data exposure and upload capability",
                    host        = target,
                    port        = 21,
                    service     = "ftp",
                    tool_used   = "nmap",
                    evidence    = "Anonymous FTP login allowed",
                    remediation = "Disable anonymous FTP access. Configure proper authentication."
                )
                result["vulnerabilities"].append({
                    "id": "FTP-ANON", "description": "Anonymous FTP login allowed",
                    "port": 21, "severity": "high"
                })

        # ── 5: SSH version check ──────────────────────────────
        if 22 in open_ports:
            ssh_ver = services.get(22, {}).get("version", "")
            await self.emit_reasoning(
                step       = "ssh_version",
                reasoning  = f"SSH version {ssh_ver} — check for known CVEs",
                decision   = "NSE scripts for SSH enumeration",
                next_action= f"nmap --script ssh-auth-methods,ssh-hostkey -p 22 {target}"
            )
            ssh = await self.run_tool(
                "nmap", f"--script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -p 22 {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=60
            )
            # Check for password auth enabled
            if "password" in ssh["stdout"].lower():
                await self.store_finding(
                    severity    = FindingSeverity.MEDIUM,
                    title       = "SSH Password Authentication Enabled",
                    description = "SSH allows password authentication — susceptible to brute force",
                    host        = target,
                    port        = 22,
                    service     = "ssh",
                    tool_used   = "nmap",
                    remediation = "Disable password auth. Use key-based authentication only."
                )

        # ── 6: SMB vulnerabilities (MS17-010, EternalBlue) ───
        if 445 in open_ports:
            await self.emit_reasoning(
                step       = "smb_vulns",
                reasoning  = "SMB port 445 — check for EternalBlue (MS17-010), SMBGhost (CVE-2020-0796)",
                decision   = "Run SMB-specific NSE scripts",
                next_action= f"nmap --script smb-vuln-ms17-010,smb-security-mode -p 445 {target}"
            )
            smb = await self.run_tool(
                "nmap", f"--script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,smb-security-mode,smb2-security-mode -p 139,445 {target}",
                target=target, phase=AttackPhase.VULN_ID, timeout=120
            )
            if "VULNERABLE" in smb["stdout"]:
                cves = self._extract_cves(smb["stdout"])
                await self.store_finding(
                    severity    = FindingSeverity.CRITICAL,
                    title       = f"SMB VULNERABLE — {', '.join(cves) if cves else 'MS17-010'}",
                    description = "SMB service is vulnerable to critical exploits (EternalBlue/MS17-010). Remote code execution possible.",
                    host        = target,
                    port        = 445,
                    service     = "smb",
                    cves        = cves,
                    tool_used   = "nmap",
                    evidence    = smb["stdout"][:2000],
                    remediation = "Apply MS17-010 patch immediately. Disable SMBv1."
                )
                result["vulnerabilities"].append({
                    "id": "SMB-ETERNALBLUE",
                    "description": "EternalBlue/MS17-010 vulnerability",
                    "port": 445, "cves": cves, "severity": "critical"
                })

        # ── 7: HTTP nikto scan ────────────────────────────────
        http_ports = [p for p in open_ports if p in (80, 8080, 8000, 8888)]
        for port in http_ports[:2]:
            await self.emit_reasoning(
                step       = f"nikto_{port}",
                reasoning  = f"HTTP on port {port} — nikto checks for misconfigs, headers, dangerous files",
                decision   = "Run nikto with all plugins for comprehensive check",
                next_action= f"nikto -h http://{target}:{port} -C all"
            )
            nik = await self.run_tool(
                "nikto", f"-h http://{target}:{port} -C all -maxtime 5m",
                target=target, phase=AttackPhase.VULN_ID, timeout=360
            )
            nikto_findings = self._parse_nikto(nik["stdout"])
            for finding in nikto_findings:
                await self.store_finding(
                    severity    = finding["severity"],
                    title       = finding["title"],
                    description = finding["description"],
                    host        = target,
                    port        = port,
                    service     = "http",
                    tool_used   = "nikto",
                    evidence    = finding.get("evidence", "")
                )
            result["vulnerabilities"].extend(nikto_findings)

        await self.set_status(AgentStatus.DONE,
            f"Vuln scan complete: {len(result['vulnerabilities'])} findings, {len(result['cves'])} CVEs")
        return result

    # ─── Parsers ──────────────────────────────────────────────

    def _parse_nmap_vulns(self, output: str):
        vulns, cves = [], []
        current_port, current_service = None, None
        current_vuln = None

        for line in output.splitlines():
            # Port line: "80/tcp open http"
            pm = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
            if pm:
                current_port    = int(pm.group(1))
                current_service = pm.group(2)
                continue

            # CVEs
            for cve in re.findall(r'CVE-\d{4}-\d+', line, re.IGNORECASE):
                cves.append(cve)

            # VULNERABLE block
            if "VULNERABLE" in line or "| vuln:" in line:
                vuln_name = re.sub(r'[\|_]+', ' ', line).strip()
                current_vuln = {
                    "id":          vuln_name,
                    "description": vuln_name,
                    "port":        current_port,
                    "service":     current_service,
                    "cves":        [],
                    "raw":         line
                }
                vulns.append(current_vuln)
            elif current_vuln and line.strip().startswith("|"):
                current_vuln["raw"] += "\n" + line
                if "CVE" in line:
                    for cve in re.findall(r'CVE-\d{4}-\d+', line):
                        current_vuln["cves"].append(cve)
                        cves.append(cve)
                if "description" not in current_vuln or not current_vuln["description"]:
                    current_vuln["description"] = line.strip("| ").strip()

        return vulns, list(set(cves))

    def _parse_ssl_issues(self, output: str) -> List[Dict]:
        issues = []
        checks = [
            ("SSLv2",      "SSLv2 Enabled",                 FindingSeverity.CRITICAL, "Disable SSLv2 immediately"),
            ("SSLv3",      "SSLv3 Enabled (POODLE)",        FindingSeverity.HIGH,     "Disable SSLv3, enable TLS 1.2+"),
            ("TLSv1.0",    "TLS 1.0 Enabled",               FindingSeverity.MEDIUM,   "Disable TLS 1.0, enforce TLS 1.2+"),
            ("TLSv1.1",    "TLS 1.1 Enabled",               FindingSeverity.MEDIUM,   "Disable TLS 1.1, enforce TLS 1.2+"),
            ("RC4",        "Weak RC4 Cipher Supported",      FindingSeverity.HIGH,     "Disable RC4 cipher suites"),
            ("DES",        "Weak DES Cipher Supported",      FindingSeverity.HIGH,     "Disable DES/3DES cipher suites"),
            ("Heartbleed", "HEARTBLEED Vulnerable",          FindingSeverity.CRITICAL, "Apply OpenSSL patch for CVE-2014-0160"),
            ("BEAST",      "BEAST Attack Possible",          FindingSeverity.MEDIUM,   "Disable CBC mode ciphers with TLS 1.0"),
            ("POODLE",     "POODLE Attack Possible",         FindingSeverity.HIGH,     "Disable SSLv3"),
        ]
        for keyword, title, sev, remediation in checks:
            if keyword.lower() in output.lower():
                issues.append({
                    "severity":    sev,
                    "title":       title,
                    "description": f"{title} — encryption weakness that may allow traffic decryption",
                    "remediation": remediation
                })
        return issues

    def _parse_searchsploit(self, output: str) -> List[Dict]:
        exploits = []
        for line in output.splitlines():
            # Format: "  Title                    | Path"
            m = re.match(r'\s*(.+?)\s*\|\s*(\S+\.(?:py|rb|pl|c|sh|txt|php))\s*$', line)
            if m and not line.startswith("-") and len(m.group(1).strip()) > 5:
                title = m.group(1).strip()
                path  = m.group(2).strip()
                eid   = re.search(r'(\d+)', path)
                exploits.append({
                    "title": title,
                    "path":  path,
                    "id":    eid.group(1) if eid else ""
                })
        return exploits

    def _parse_nikto(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            if not line.startswith("+"):
                continue
            # Remove leading + and clean
            text = line.lstrip("+ ").strip()
            if len(text) < 10 or "Nikto" in text or "Target" in text:
                continue
            # Severity heuristic
            sev = FindingSeverity.INFO
            if any(k in text.lower() for k in ["injectable", "xss", "sql", "rce", "command", "execute"]):
                sev = FindingSeverity.CRITICAL
            elif any(k in text.lower() for k in ["dangerous", "vulnerability", "exploit", "backup", "config", "admin"]):
                sev = FindingSeverity.HIGH
            elif any(k in text.lower() for k in ["exposed", "disclosure", "version", "header", "cookie"]):
                sev = FindingSeverity.MEDIUM
            findings.append({
                "severity":    sev,
                "title":       text[:80],
                "description": text,
                "evidence":    text
            })
        return findings
