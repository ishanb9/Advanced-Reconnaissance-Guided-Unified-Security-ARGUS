"""
KALI PENTEST PLATFORM v3 — Recon Agent

OSCP-style reconnaissance methodology:
  Phase 1: Host Discovery (is it alive?)
  Phase 2: Fast port scan (what ports are open?)
  Phase 3: Full port scan (did we miss anything?)
  Phase 4: Service/version detection (what is running?)
  Phase 5: OS fingerprinting
  Phase 6: Web technology detection (if HTTP found)
  Phase 7: Subdomain/DNS enumeration (if domain target)
  Phase 8: SMB/NetBIOS enumeration (if 139/445 found)
  Phase 9: SNMP enumeration (if 161 found)
  Phase 10: Report structured findings

IMPORTANT: This agent does NOT call think(). It only executes
Instructions issued by MasterAgent via execute_instruction().
"""

import asyncio
import re
from typing import Optional, Dict, List

from agents.base_agent import BaseAgent, Instruction, BroadcastFn
from db.schemas import AgentName, AgentStatus, AttackPhase, FindingSeverity
import db.mongo_client as db


class ReconAgent(BaseAgent):
    """
    Reconnaissance specialist.
    Executes instructions from MasterAgent — does NOT call LLM.
    Parses all tool output into structured intel and stores to DB.
    """

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__(AgentName.RECON, broadcast)
        self.phase = AttackPhase.RECON

    async def run(self, session_id: str, target: str, **kwargs) -> Dict:
        """
        Standalone run — used only if ReconAgent is invoked directly.
        Normally MasterAgent issues Instructions via execute_instruction().
        """
        self._session_id = session_id
        result = {
            "open_ports":  [],
            "services":    {},
            "os_guess":    "unknown",
            "web_paths":   [],
            "subdomains":  [],
            "technologies": [],
            "raw_hosts":   []
        }

        await self.set_status(AgentStatus.RUNNING, f"Starting recon on {target}")

        # Target node in attack graph
        target_node = f"target_{target.replace('.', '_').replace('/', '_')}"
        await self.add_node(
            node_id  = target_node,
            type     = "host",
            label    = target,
            host     = target,
            metadata = {"role": "target"}
        )

        # ── Phase 1: Host is alive? ───────────────────────────
        await self.emit_reasoning(
            step       = "host_discovery",
            reasoning  = f"Verify {target} is reachable before scanning",
            decision   = "Ping sweep first to avoid wasting time on dead hosts",
            next_action= f"fping -a -g {target}"
        )

        ping = await self.run_tool("fping", f"-a -q {target}", target=target,
                                    phase=AttackPhase.RECON, timeout=15)
        if ping["exit_code"] != 0 and not self._extract_ips(ping["stdout"]):
            # Try ICMP manually
            ping2 = await self.run_tool("nmap", f"-sn -PE {target}", target=target,
                                         phase=AttackPhase.RECON, timeout=30)
            if "Host is up" not in ping2["stdout"]:
                await self.emit_reasoning(
                    step       = "host_unreachable",
                    reasoning  = f"{target} did not respond to ping",
                    decision   = "Continue scanning anyway — ICMP may be blocked",
                    next_action= "Proceed with port scan"
                )

        # ── Phase 2: Fast port scan (top 1000) ───────────────
        await self.emit_reasoning(
            step       = "fast_scan",
            reasoning  = "Quick scan top 1000 ports to get initial picture",
            decision   = "nmap -F for speed, then full scan later",
            next_action= f"nmap -F -T4 --open {target}"
        )
        fast = await self.run_tool(
            "nmap", f"-F -T4 --open {target}",
            target=target, phase=AttackPhase.RECON, timeout=120
        )
        quick_ports = self._extract_ports(fast["stdout"])
        result["open_ports"] = quick_ports

        if quick_ports:
            await self.emit_reasoning(
                step       = "fast_scan_result",
                reasoning  = f"Found {len(quick_ports)} open ports in fast scan",
                decision   = "Run full port scan and service detection on discovered ports",
                next_action= f"nmap -sV -sC on ports {quick_ports[:10]}",
                data       = {"ports": quick_ports}
            )
            await self.store_finding(
                severity    = FindingSeverity.INFO,
                title       = f"Open Ports: {target}",
                description = f"Fast scan discovered {len(quick_ports)} open ports: {quick_ports}",
                host        = target,
                tool_used   = "nmap"
            )

        # ── Phase 3: Full port scan (all 65535) ───────────────
        await self.emit_reasoning(
            step       = "full_scan",
            reasoning  = "Fast scan may miss uncommon ports — scan all 65535",
            decision   = "Full TCP scan with rate limiting to avoid detection",
            next_action= f"nmap -p- --min-rate 3000 {target}"
        )
        full = await self.run_tool(
            "nmap", f"-p- --min-rate 3000 -T4 --open {target}",
            target=target, phase=AttackPhase.RECON, timeout=600
        )
        all_ports = self._extract_ports(full["stdout"])
        # Merge with quick scan
        result["open_ports"] = sorted(list(set(result["open_ports"] + all_ports)))
        new_ports = [p for p in all_ports if p not in quick_ports]
        if new_ports:
            await self.emit_reasoning(
                step       = "additional_ports",
                reasoning  = f"Full scan found {len(new_ports)} additional ports not in fast scan",
                decision   = "Include all ports in service detection",
                next_action= "Service detection on all discovered ports",
                data       = {"new_ports": new_ports}
            )

        # ── Phase 4: Service/version detection ───────────────
        if result["open_ports"]:
            ports_str = ",".join(str(p) for p in result["open_ports"][:50])
            await self.emit_reasoning(
                step       = "service_detection",
                reasoning  = "Identify exact services and versions for vulnerability matching",
                decision   = "nmap -sV -sC with default scripts + OS detection",
                next_action= f"nmap -sV -sC -O -p {ports_str} {target}"
            )
            svc = await self.run_tool(
                "nmap", f"-sV -sC -O -p {ports_str} {target}",
                target=target, phase=AttackPhase.RECON, timeout=300
            )
            services = self._extract_services(svc["stdout"])
            result["services"] = services

            # OS detection
            os_match = re.search(r'OS details: (.+)', svc["stdout"])
            if os_match:
                result["os_guess"] = os_match.group(1).strip()
            elif re.search(r'linux', svc["stdout"], re.IGNORECASE):
                result["os_guess"] = "Linux"
            elif re.search(r'windows', svc["stdout"], re.IGNORECASE):
                result["os_guess"] = "Windows"

            # Store service findings and attack graph nodes
            for port, svc_info in services.items():
                svc_name = svc_info.get("service", "unknown")
                version  = svc_info.get("version", "")
                await self.add_node(
                    node_id  = f"svc_{port}_{svc_name}",
                    type     = "service",
                    label    = f"{svc_name}:{port}" + (f" ({version[:30]})" if version else ""),
                    host     = target,
                    port     = port,
                    metadata = svc_info
                )
                await self.add_edge(
                    source = target_node,
                    target = f"svc_{port}_{svc_name}",
                    label  = "exposes",
                    tool   = "nmap"
                )
                await self.store_finding(
                    severity    = FindingSeverity.INFO,
                    title       = f"Service: {svc_name} on port {port}",
                    description = f"Port {port}: {svc_name} {version}",
                    host        = target,
                    port        = port,
                    service     = svc_name,
                    tool_used   = "nmap"
                )

        # ── Phase 5: Web detection (HTTP ports) ───────────────
        http_ports = [p for p, s in result["services"].items()
                      if s.get("service", "").lower() in ("http", "https", "http-alt", "http-proxy",
                                                           "ssl/http", "ssl/https", "8080", "8443")]
        # Also check common web ports
        for p in [80, 443, 8080, 8443, 8000, 8888]:
            if p in result["open_ports"] and p not in http_ports:
                http_ports.append(p)

        if http_ports:
            await self.emit_reasoning(
                step       = "web_detection",
                reasoning  = f"HTTP services found on {http_ports} — fingerprint web technologies",
                decision   = "Run whatweb for technology detection",
                next_action= f"whatweb http://{target}"
            )
            for port in http_ports[:3]:
                proto = "https" if port in (443, 8443) else "http"
                ww = await self.run_tool(
                    "whatweb", f"-a 3 {proto}://{target}:{port}",
                    target=target, phase=AttackPhase.RECON, timeout=60
                )
                techs = self._parse_whatweb(ww["stdout"])
                result["technologies"].extend(techs)

                await self.store_finding(
                    severity    = FindingSeverity.INFO,
                    title       = f"Web Technologies on port {port}",
                    description = f"Detected: {', '.join(techs[:10])}",
                    host        = target,
                    port        = port,
                    service     = "http",
                    tool_used   = "whatweb"
                )

            # WAF detection
            wafw = await self.run_tool(
                "wafw00f", f"http://{target}",
                target=target, phase=AttackPhase.RECON, timeout=30
            )
            if "is behind" in wafw["stdout"].lower():
                waf_match = re.search(r'is behind (.+)', wafw["stdout"])
                if waf_match:
                    await self.store_finding(
                        severity    = FindingSeverity.MEDIUM,
                        title       = f"WAF Detected: {waf_match.group(1).strip()}",
                        description = f"Web Application Firewall detected — may affect exploitation",
                        host        = target,
                        tool_used   = "wafw00f"
                    )

        # ── Phase 6: DNS/Subdomain (if domain) ────────────────
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            # Target looks like a domain name
            await self.emit_reasoning(
                step       = "dns_enum",
                reasoning  = f"{target} appears to be a domain — enumerate subdomains",
                decision   = "DNS recon with dnsrecon and amass",
                next_action= f"dnsrecon -d {target}"
            )
            dns = await self.run_tool(
                "dnsrecon", f"-d {target} -t std,brt,axfr",
                target=target, phase=AttackPhase.RECON, timeout=120
            )
            subdomains = re.findall(r'(?:A|AAAA|CNAME)\s+(\S+\.' + re.escape(target) + r')', dns["stdout"])
            result["subdomains"] = list(set(subdomains))
            if result["subdomains"]:
                await self.store_finding(
                    severity    = FindingSeverity.INFO,
                    title       = f"Subdomains: {target}",
                    description = f"Found {len(result['subdomains'])} subdomains: {result['subdomains'][:5]}",
                    host        = target,
                    tool_used   = "dnsrecon"
                )

        # ── Phase 7: SMB enumeration (139/445) ───────────────
        if 445 in result["open_ports"] or 139 in result["open_ports"]:
            await self.emit_reasoning(
                step       = "smb_enum",
                reasoning  = "SMB ports open — enumerate shares, users, domain info",
                decision   = "Run enum4linux for comprehensive SMB enumeration",
                next_action= f"enum4linux -a {target}"
            )
            smb = await self.run_tool(
                "enum4linux", f"-a {target}",
                target=target, phase=AttackPhase.RECON, timeout=120
            )
            if smb["exit_code"] == 0 and smb["stdout"]:
                await self.store_finding(
                    severity    = FindingSeverity.MEDIUM,
                    title       = f"SMB Enumeration: {target}",
                    description = f"SMB services accessible on {target}",
                    host        = target,
                    port        = 445,
                    service     = "smb",
                    tool_used   = "enum4linux",
                    raw_output  = smb["stdout"][:3000]
                )
            # Also try smbmap
            smbm = await self.run_tool(
                "smbmap", f"-H {target}",
                target=target, phase=AttackPhase.RECON, timeout=60
            )
            if "READ" in smbm["stdout"] or "WRITE" in smbm["stdout"]:
                await self.store_finding(
                    severity    = FindingSeverity.HIGH,
                    title       = f"SMB Share Access: {target}",
                    description = f"Accessible SMB shares found — potential data exposure",
                    host        = target,
                    port        = 445,
                    service     = "smb",
                    tool_used   = "smbmap",
                    raw_output  = smbm["stdout"][:2000]
                )

        # ── Phase 8: SNMP (port 161) ──────────────────────────
        if 161 in result["open_ports"]:
            await self.emit_reasoning(
                step       = "snmp_enum",
                reasoning  = "SNMP port 161 open — often reveals system info with default community strings",
                decision   = "Try common community strings: public, private, manager",
                next_action= f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt {target}"
            )
            snmp = await self.run_tool(
                "onesixtyone", f"-c /usr/share/doc/onesixtyone/dict.txt {target}",
                target=target, phase=AttackPhase.RECON, timeout=30
            )
            if "[" in snmp["stdout"]:
                # Community string found — do full walk
                community = re.search(r'\[(\w+)\]', snmp["stdout"])
                if community:
                    snmpwalk = await self.run_tool(
                        "snmpwalk", f"-v2c -c {community.group(1)} {target}",
                        target=target, phase=AttackPhase.RECON, timeout=60
                    )
                    await self.store_finding(
                        severity    = FindingSeverity.HIGH,
                        title       = f"SNMP Community String: {community.group(1)}",
                        description = f"Default SNMP community string accessible — information disclosure",
                        host        = target,
                        port        = 161,
                        service     = "snmp",
                        tool_used   = "snmpwalk",
                        raw_output  = snmpwalk["stdout"][:3000]
                    )

        await self.set_status(AgentStatus.DONE, f"Recon complete: {len(result['open_ports'])} ports, {len(result['services'])} services")
        return result

    # ─── Parsers ──────────────────────────────────────────────

    def _parse_whatweb(self, output: str) -> List[str]:
        """Extract technology names from whatweb output."""
        techs = []
        # WhatWeb format: [200 OK] Apache[2.4.41], PHP[7.4], WordPress[5.8]
        for m in re.finditer(r'(\w[\w\s\-\.]+)\[([^\]]+)\]', output):
            name = m.group(1).strip()
            if name and len(name) > 2 and name not in ("Status", "Country", "IP"):
                techs.append(f"{name}[{m.group(2)}]")
        return techs
