"""
service_banner_subagent.py — Per-service banner grabbing and protocol enumeration.

Protocol-specific probing:
  SMTP  (25/587) — EHLO banner, VRFY admin
  FTP   (21)     — anonymous login, banner grab
  SSH   (22)     — version banner parse (old versions → HIGH)
  HTTP  (80/443/8080) — curl -I for Server header, X-Powered-By
  SNMP  (161)    — snmpwalk -c public -v1 community string test
  SMB   (445/139) — enum4linux-ng -A (null session)
  RDP   (3389)   — nmap --script rdp-enum-encryption
  LDAP  (389)    — ldapsearch -x anonymous bind test
  MySQL (3306)   — version + empty-password via nmap scripts
  Redis (6379)   — INFO SERVER (no-auth detection)
  MongoDB (27017) — auth-required check via nmap scripts
  Generic         — nmap -sV --script=banner

Severity model:
  CRITICAL — Redis/MongoDB no-auth, anonymous FTP + write, cleartext protocols (telnet/rsh)
  HIGH     — anonymous LDAP bind, SMB null session, old SSH (<7.4), anon FTP read
  MEDIUM   — SMTP VRFY/open relay, SNMP community string, RDP weak enc, HTTP version disclosure
  INFO     — banners with only version info
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Port → protocol routing table
# ---------------------------------------------------------------------------

PROTOCOL_PORTS: dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    80:    "http",
    110:   "pop3",
    139:   "smb",
    143:   "imap",
    161:   "snmp",
    389:   "ldap",
    443:   "http",
    445:   "smb",
    512:   "rexec",
    513:   "rsh",
    514:   "rsh",
    587:   "smtp",
    636:   "ldap",
    993:   "imap",
    995:   "pop3",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    5900:  "vnc",
    6379:  "redis",
    8080:  "http",
    8443:  "http",
    8888:  "http",
    27017: "mongodb",
}

# Cleartext protocols — always CRITICAL if found
_CLEARTEXT_PORTS: frozenset[int] = frozenset({23, 512, 513, 514})

# SSH version detection — old = major < 7 OR (major==7 AND minor < 4)
_SSH_VERSION_RE = re.compile(r"OpenSSH[_\s](\d+)\.(\d+)", re.IGNORECASE)

# Weak SSH algorithm patterns
_WEAK_SSH_ALGO_RE = re.compile(
    r"diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1"
    r"|arcfour|blowfish-cbc|3des-cbc|cast128-cbc",
    re.IGNORECASE,
)

# FTP
_FTP_ANON_RE  = re.compile(r"230[- ]|Anonymous FTP login allowed", re.IGNORECASE)
_FTP_WRITE_RE = re.compile(r"WRITE|STOR|MKD|DELE", re.IGNORECASE)

# LDAP anonymous bind success
_LDAP_ANON_RE = re.compile(r"numEntries:|result: 0 Success|dn:", re.IGNORECASE)

# SMB null session indicators
_SMB_NULL_RE  = re.compile(r"Null session|Anonymous login|null session|\bIPC\$\b", re.IGNORECASE)

# Redis no-auth
_REDIS_DATA_RE   = re.compile(r"redis_version:|tcp_port:|Server\b", re.IGNORECASE)
_REDIS_NOAUTH_RE = re.compile(r"NOAUTH|Authentication required", re.IGNORECASE)

# MongoDB
_MONGO_DATA_RE = re.compile(r'"ok"\s*:\s*1|"version"\s*:', re.IGNORECASE)
_MONGO_AUTH_RE = re.compile(r"Unauthorized|Authentication|errmsg", re.IGNORECASE)

# Server header
_SERVER_HDR_RE = re.compile(r"(?:^|\n)server:\s*(.+)", re.IGNORECASE)
_XPOWERED_RE   = re.compile(r"x-powered-by:\s*(.+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ssh_is_old(major: int, minor: int) -> bool:
    return major < 7 or (major == 7 and minor < 4)


# ---------------------------------------------------------------------------
# Subagent
# ---------------------------------------------------------------------------

class ServiceBannerSubagent(BaseSubagent):
    """
    Per-port banner grabbing and protocol-level enumeration.

    Accepts a list of open ports and optional service name hints, runs
    protocol-specific probing for each concurrently, and stores
    severity-graded findings.
    """

    AGENT_NAME    = "recon"
    SUBAGENT_NAME = "service_banner"

    async def run(  # noqa: C901
        self,
        target: str,
        ports: list[int] | None = None,
        services: dict[int, str] | None = None,
        **kwargs: Any,
    ) -> SubagentResult:
        """
        Enumerate banners for every open port on *target*.

        Parameters
        ----------
        target:
            IP address or hostname.
        ports:
            Open TCP port numbers to probe. Defaults to common service ports.
        services:
            Optional dict of port → service-name hints (from prior nmap scan).

        Returns
        -------
        SubagentResult
            parsed_data["banners"] — dict[int, banner_dict] per probed port
        """
        if ports is None:
            ports = []
        if services is None:
            services = {}
        if not ports:
            ports = list(PROTOCOL_PORTS.keys())

        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        result.parsed_data: dict = {"banners": {}}
        wall_start = time.monotonic()

        logger.info(
            "[service_banner] probing %d ports on %s", len(ports), target
        )

        banner_map: dict[int, dict] = {}
        sem = asyncio.Semaphore(6)

        async def _probe_one(port: int) -> None:
            # services dict values may be dicts (full nmap info) or plain strings — normalise to str
            raw_svc = services.get(port, PROTOCOL_PORTS.get(port, "generic"))
            if isinstance(raw_svc, dict):
                raw_svc = raw_svc.get("service") or raw_svc.get("name") or "generic"
            svc_hint = str(raw_svc).lower() if raw_svc else "generic"
            async with sem:
                try:
                    entry = await self._dispatch(target, port, svc_hint)
                    banner_map[port] = entry
                    await self._maybe_find(target, port, svc_hint, entry)
                except Exception as exc:
                    logger.warning(
                        "[service_banner] port %d probe error: %s", port, exc
                    )
                    banner_map[port] = {
                        "port": port, "service": svc_hint,
                        "banner": "", "error": str(exc),
                    }

        await asyncio.gather(*(_probe_one(p) for p in ports))

        # MongoDB requires string keys — convert integer port keys to strings
        result.parsed_data["banners"] = {str(k): v for k, v in banner_map.items()}
        result.findings               = self._findings
        result.tool_outputs           = self._tool_outputs
        result.duration_seconds       = time.monotonic() - wall_start

        await self._emit(
            "service_banner_complete",
            {
                "target":           target,
                "ports_probed":     len(ports),
                "banners_grabbed":  len(banner_map),
                "finding_count":    len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )

        logger.info(
            "[service_banner] complete — %d ports, %d findings, %.1fs",
            len(ports), len(self._findings), result.duration_seconds,
        )
        return result

    # ------------------------------------------------------------------
    # Protocol dispatch
    # ------------------------------------------------------------------

    async def _dispatch(self, target: str, port: int, svc: str) -> dict:
        """Route to the protocol-specific probe based on port or service hint."""
        s = svc.lower()

        if port in _CLEARTEXT_PORTS or s in ("telnet", "rsh", "rexec", "rlogin"):
            return await self._probe_cleartext(target, port, svc)
        if port == 21 or "ftp" in s:
            return await self._probe_ftp(target, port)
        if port == 22 or "ssh" in s:
            return await self._probe_ssh(target, port)
        if port in (25, 587) or "smtp" in s:
            return await self._probe_smtp(target, port)
        if port in (80, 443, 8080, 8443, 8000, 8888) or "http" in s:
            return await self._probe_http(target, port)
        if port == 161 or "snmp" in s:
            return await self._probe_snmp(target, port)
        if port in (139, 445) or any(k in s for k in ("smb", "netbios", "microsoft-ds")):
            return await self._probe_smb(target, port)
        if port == 3389 or any(k in s for k in ("rdp", "ms-wbt")):
            return await self._probe_rdp(target, port)
        if port in (389, 636) or "ldap" in s:
            return await self._probe_ldap(target, port)
        if port == 3306 or "mysql" in s:
            return await self._probe_mysql(target, port)
        if port == 6379 or "redis" in s:
            return await self._probe_redis(target, port)
        if port == 27017 or "mongo" in s:
            return await self._probe_mongodb(target, port)
        return await self._probe_generic(target, port, svc)

    # ------------------------------------------------------------------
    # Individual protocol probes
    # ------------------------------------------------------------------

    async def _probe_cleartext(self, target: str, port: int, svc: str) -> dict:
        """Telnet/rsh/rexec — cleartext, always CRITICAL."""
        out = await self.collect_tool(
            "nmap",
            target,
            {"options": f"-sV -p {port} {target}"},
        )
        self._tool_outputs[f"nmap_cleartext_{port}"] = out
        banner = ""
        for line in out.splitlines():
            if f"{port}/tcp" in line and "open" in line.lower():
                banner = line.strip()
                break
        return {"port": port, "service": svc, "banner": banner, "raw": out[:600]}

    async def _probe_ftp(self, target: str, port: int) -> dict:
        """FTP banner, anonymous login, write access."""
        out = await self.collect_tool(
            "nmap",
            target,
            {"options": f"-sV --script=ftp-anon,ftp-syst,ftp-bounce -p {port} {target}"},
        )
        self._tool_outputs[f"nmap_ftp_{port}"] = out

        anon_ok = bool(_FTP_ANON_RE.search(out))
        write   = bool(_FTP_WRITE_RE.search(out)) and "WRITE" in out.upper()

        banner = ""
        for line in out.splitlines():
            ls = line.strip()
            if f"{port}/tcp" in ls and "ftp" in ls.lower():
                banner = ls
                break
        if not banner:
            m = re.search(r"220[- ](.+)", out)
            if m:
                banner = m.group(0).strip()

        return {
            "port": port, "service": "ftp", "banner": banner,
            "anon_allowed": anon_ok, "write_access": write,
            "raw": out[:1000],
        }

    async def _probe_ssh(self, target: str, port: int) -> dict:
        """SSH version banner and algorithm enumeration."""
        out = await self.collect_tool(
            "nmap",
            target,
            {"options": f"-sV --script=ssh-hostkey,ssh2-enum-algos -p {port} {target}"},
        )
        self._tool_outputs[f"nmap_ssh_{port}"] = out

        vm = _SSH_VERSION_RE.search(out)
        old_ssh    = False
        version_str = ""
        if vm:
            major, minor = int(vm.group(1)), int(vm.group(2))
            version_str  = f"OpenSSH {major}.{minor}"
            old_ssh      = _ssh_is_old(major, minor)

        weak_algos = bool(_WEAK_SSH_ALGO_RE.search(out))
        algos      = [
            line.strip() for line in out.splitlines()
            if any(k in line.lower() for k in ("kex_algo", "encryption_algo"))
        ][:4]

        return {
            "port": port, "service": "ssh", "banner": version_str or out[:100],
            "old_version": old_ssh, "weak_algos": weak_algos, "algorithms": algos,
            "raw": out[:1000],
        }

    async def _probe_smtp(self, target: str, port: int) -> dict:
        """SMTP EHLO banner, VRFY, and open relay check."""
        out = await self.collect_tool(
            "nmap",
            target,
            {
                "options": (
                    f"-sV --script=smtp-commands,smtp-open-relay,"
                    f"smtp-enum-users --script-args smtp-enum-users.methods=VRFY "
                    f"-p {port} {target}"
                )
            },
        )
        self._tool_outputs[f"nmap_smtp_{port}"] = out

        ehlo        = ""
        vrfy_on     = False
        open_relay  = False

        for line in out.splitlines():
            ls = line.strip()
            if (ls.startswith("220") or "ESMTP" in ls) and not ehlo:
                ehlo = ls
            if "VRFY" in ls.upper() and re.search(r"250|valid", ls, re.IGNORECASE):
                vrfy_on = True
            if re.search(r"open relay|relay access allowed", ls, re.IGNORECASE):
                open_relay = True

        return {
            "port": port, "service": "smtp", "banner": ehlo or out[:100],
            "vrfy_enabled": vrfy_on, "open_relay": open_relay,
            "raw": out[:1000],
        }

    async def _probe_http(self, target: str, port: int) -> dict:
        """HTTP HEAD — grab Server and X-Powered-By headers."""
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target}:{port}"
        out = await self.collect_tool(
            "curl",
            target,
            {"options": f"-I -m 10 -sk --max-redirs 3 {url}"},
        )
        self._tool_outputs[f"curl_{port}"] = out

        server = powered = ""
        status = None
        for line in out.splitlines():
            ls = line.strip()
            hm = re.match(r"HTTP/[\d.]+ (\d{3})", ls)
            if hm:
                status = int(hm.group(1))
            elif ls.lower().startswith("server:"):
                server = ls.split(":", 1)[1].strip()
            elif ls.lower().startswith("x-powered-by:"):
                powered = ls.split(":", 1)[1].strip()

        missing_headers = [
            hdr for hdr in (
                "Strict-Transport-Security", "X-Frame-Options",
                "X-Content-Type-Options", "Content-Security-Policy",
            )
            if not re.search(re.escape(hdr), out, re.IGNORECASE)
        ]

        return {
            "port": port, "service": "http", "url": url,
            "banner": f"Server: {server}" if server else out[:100],
            "server": server, "powered_by": powered, "status_code": status,
            "missing_headers": missing_headers,
            "raw": out[:600],
        }

    async def _probe_snmp(self, target: str, port: int) -> dict:
        """SNMP: test community strings public/private/manager."""
        community_list = ["public", "private", "manager", "community", "default"]
        found_comm: str | None = None
        walk_out   = ""

        for comm in community_list:
            try:
                snmp_out = await self.collect_tool(
                    "snmpwalk",
                    target,
                    {"options": f"-c {comm} -v1 -t 5 -r 1 {target} sysDescr.0"},
                )
                self._tool_outputs[f"snmpwalk_{comm}"] = snmp_out
                if re.search(r"STRING:|OID:|iso\.", snmp_out, re.IGNORECASE):
                    found_comm = comm
                    walk_out   = snmp_out
                    break
            except Exception as exc:
                logger.debug("[service_banner] snmpwalk %s: %s", comm, exc)

        return {
            "port": port, "service": "snmp",
            "banner":           walk_out[:200] or "no community string found",
            "community_string": found_comm,
            "community_found":  found_comm is not None,
            "raw":              walk_out[:800],
        }

    async def _probe_smb(self, target: str, port: int) -> dict:
        """SMB: enum4linux-ng null session + smbmap share enumeration."""
        e4l_out = await self.collect_tool(
            "enum4linux-ng",
            target,
            {"options": f"-A {target}"},
        )
        self._tool_outputs[f"enum4linux_{port}"] = e4l_out

        null_session = bool(_SMB_NULL_RE.search(e4l_out))
        write_shares: list[str] = []
        read_shares:  list[str] = []

        for line in e4l_out.splitlines():
            sm = re.search(r"\\\\[^\\]+\\(\S+)", line)
            if sm:
                share = sm.group(1)
                if "WRITE" in line.upper():
                    write_shares.append(share)
                elif "READ" in line.upper() or "OK" in line.upper():
                    read_shares.append(share)

        # Supplement with smbmap
        smbmap_out = ""
        try:
            smbmap_out = await self.collect_tool(
                "smbmap",
                target,
                {"options": f"-H {target} --no-banner"},
            )
            self._tool_outputs[f"smbmap_{port}"] = smbmap_out
            for line in smbmap_out.splitlines():
                if "WRITE" in line.upper():
                    m = re.match(r"\s*(\S+)\s+(?:READ,\s*)?WRITE", line, re.IGNORECASE)
                    if m and m.group(1) not in write_shares:
                        write_shares.append(m.group(1))
        except Exception as exc:
            logger.debug("[service_banner] smbmap: %s", exc)

        return {
            "port": port, "service": "smb",
            "banner":       e4l_out[:200],
            "null_session": null_session,
            "read_shares":  list(dict.fromkeys(read_shares))[:10],
            "write_shares": list(dict.fromkeys(write_shares))[:10],
            "raw":          (e4l_out + "\n" + smbmap_out)[:1500],
        }

    async def _probe_rdp(self, target: str, port: int) -> dict:
        """RDP: check encryption level and NLA with nmap scripts."""
        out = await self.collect_tool(
            "nmap",
            target,
            {"options": f"--script=rdp-enum-encryption -p {port} {target}"},
        )
        self._tool_outputs[f"nmap_rdp_{port}"] = out

        nla_enabled = bool(re.search(r"CredSSP|NLA", out))
        enc_level   = ""
        protocols: list[str] = []

        for line in out.splitlines():
            ls = line.strip()
            if "encryption level" in ls.lower():
                enc_level = ls
            if any(p in ls for p in ("TLS", "SSL", "HYBRID", "CLASSIC", "CredSSP", "RDP")):
                protocols.append(ls)

        return {
            "port": port, "service": "rdp",
            "banner":           enc_level or out[:100],
            "nla_enabled":      nla_enabled,
            "encryption_level": enc_level,
            "protocols":        protocols[:5],
            "raw":              out[:800],
        }

    async def _probe_ldap(self, target: str, port: int) -> dict:
        """LDAP: test anonymous bind with ldapsearch."""
        out = await self.collect_tool(
            "ldapsearch",
            target,
            {"options": f"-x -H ldap://{target}:{port} -b '' -s base '(objectclass=*)'"},
        )
        self._tool_outputs[f"ldapsearch_{port}"] = out

        anon_bind = bool(_LDAP_ANON_RE.search(out))
        base_dn   = ""
        bm = re.search(r"namingContexts:\s*(.+)", out)
        if bm:
            base_dn = bm.group(1).strip()

        return {
            "port": port, "service": "ldap",
            "banner":    f"BaseDN: {base_dn}" if base_dn else out[:100],
            "anon_bind": anon_bind,
            "base_dn":   base_dn,
            "raw":       out[:800],
        }

    async def _probe_mysql(self, target: str, port: int) -> dict:
        """MySQL: grab version and test empty/anonymous password."""
        out = await self.collect_tool(
            "nmap",
            target,
            {"options": f"-sV --script=mysql-info,mysql-empty-password -p {port} {target}"},
        )
        self._tool_outputs[f"nmap_mysql_{port}"] = out

        version      = ""
        anon_allowed = False

        for line in out.splitlines():
            ls = line.strip()
            vm = re.search(r"(\d+\.\d+[\.\d]*)", ls)
            if vm and "mysql" in ls.lower() and not version:
                version = vm.group(1)
            if re.search(r"empty.password|root.*valid|anonymous.*login", ls, re.IGNORECASE):
                anon_allowed = True

        return {
            "port": port, "service": "mysql",
            "banner":       f"MySQL {version}" if version else out[:100],
            "version":      version,
            "anon_allowed": anon_allowed,
            "raw":          out[:800],
        }

    async def _probe_redis(self, target: str, port: int) -> dict:
        """Redis: INFO SERVER — detect whether auth is required."""
        out = await self.collect_tool(
            "nmap",
            target,
            {"options": f"--script=redis-info -p {port} {target}"},
        )
        self._tool_outputs[f"nmap_redis_{port}"] = out

        has_data  = bool(_REDIS_DATA_RE.search(out))
        needs_auth = bool(_REDIS_NOAUTH_RE.search(out))
        no_auth   = has_data and not needs_auth
        version   = ""

        vm = re.search(r"redis_version:\s*([\d.]+)", out, re.IGNORECASE)
        if vm:
            version = vm.group(1)

        return {
            "port": port, "service": "redis",
            "banner":        f"Redis {version}" if version else out[:100],
            "version":       version,
            "no_auth":       no_auth,
            "auth_required": needs_auth,
            "raw":           out[:800],
        }

    async def _probe_mongodb(self, target: str, port: int) -> dict:
        """MongoDB: check if auth is required via nmap scripts."""
        out = await self.collect_tool(
            "nmap",
            target,
            {"options": f"--script=mongodb-info,mongodb-databases -p {port} {target}"},
        )
        self._tool_outputs[f"nmap_mongodb_{port}"] = out

        has_data = bool(_MONGO_DATA_RE.search(out))
        req_auth = bool(_MONGO_AUTH_RE.search(out))
        no_auth  = has_data and not req_auth
        version  = ""

        vm = re.search(r'"version"\s*:\s*"([\d.]+)"', out)
        if vm:
            version = vm.group(1)

        return {
            "port": port, "service": "mongodb",
            "banner":        f"MongoDB {version}" if version else out[:100],
            "version":       version,
            "no_auth":       no_auth,
            "auth_required": req_auth,
            "raw":           out[:800],
        }

    async def _probe_generic(self, target: str, port: int, svc: str) -> dict:
        """Generic nmap banner script for unrecognised services."""
        out = await self.collect_tool(
            "nmap",
            target,
            {"options": f"-sV --script=banner -p {port} {target}"},
        )
        self._tool_outputs[f"nmap_generic_{port}"] = out

        banner = ""
        for line in out.splitlines():
            ls = line.strip()
            if f"{port}/tcp" in ls and "open" in ls.lower():
                banner = ls
                break
            if "|_banner" in ls.lower():
                banner = ls

        return {
            "port": port, "service": svc or "unknown",
            "banner": banner or out[:150],
            "raw":    out[:600],
        }

    # ------------------------------------------------------------------
    # Finding storage
    # ------------------------------------------------------------------

    async def _maybe_find(  # noqa: C901
        self,
        target: str,
        port: int,
        svc: str,
        banner: dict,
    ) -> None:
        """Evaluate banner dict and store a severity-graded Finding if warranted."""

        # ── Cleartext protocol ────────────────────────────────────────────
        if port in _CLEARTEXT_PORTS or svc in ("telnet", "rsh", "rexec", "rlogin"):
            await self.store_finding(Finding(
                title=f"Cleartext Protocol on port {port}: {svc.upper()}",
                description=(
                    f"{svc.upper()} at {target}:{port} is a cleartext protocol. "
                    f"Credentials and session data are transmitted in plaintext and "
                    f"can be captured by a network sniffer."
                ),
                severity="CRITICAL",
                evidence=banner.get("raw", "")[:400],
                tool="nmap",
                host=target,
                port=port,
                mitre_technique="T1040",
                exploit_suggestion=(
                    f"Capture credentials with tcpdump/Wireshark. "
                    f"Connect: {svc} {target}. Disable in favor of SSH."
                ),
            ))
            return

        # ── Redis — no auth ───────────────────────────────────────────────
        if svc == "redis" and banner.get("no_auth"):
            ver = banner.get("version", "")
            await self.store_finding(Finding(
                title=f"Redis {port} — Unauthenticated Access",
                description=(
                    f"Redis {ver} at {target}:{port} responded to INFO without auth. "
                    f"Full key-value store is readable/writable. "
                    f"Attackable for RCE via CONFIG SET / slave replication."
                ),
                severity="CRITICAL",
                evidence=banner.get("raw", "")[:500],
                tool="nmap",
                host=target,
                port=port,
                mitre_technique="T1190",
                exploit_suggestion=(
                    f"redis-cli -h {target} -p {port} INFO server; "
                    "CONFIG SET dir /root/.ssh && CONFIG SET dbfilename authorized_keys"
                    " && SET pwn '<ssh_pubkey>' && SAVE"
                ),
            ))
            return

        # ── MongoDB — no auth ─────────────────────────────────────────────
        if svc == "mongodb" and banner.get("no_auth"):
            await self.store_finding(Finding(
                title=f"MongoDB {port} — Unauthenticated Access",
                description=(
                    f"MongoDB at {target}:{port} exposes all databases without auth. "
                    f"Data is fully readable and writable."
                ),
                severity="CRITICAL",
                evidence=banner.get("raw", "")[:500],
                tool="nmap",
                host=target,
                port=port,
                mitre_technique="T1190",
                exploit_suggestion=(
                    f"mongo {target}:{port} --eval \"db.adminCommand({{listDatabases:1}})\""
                ),
            ))
            return

        # ── FTP — anon + write ────────────────────────────────────────────
        if svc == "ftp" and banner.get("anon_allowed") and banner.get("write_access"):
            await self.store_finding(Finding(
                title=f"FTP {port} — Anonymous Login with Write Access",
                description=(
                    f"FTP at {target}:{port} allows anonymous login with write access. "
                    f"Attacker can upload files (webshells, SSH keys) → potential RCE."
                ),
                severity="CRITICAL",
                evidence=banner.get("raw", "")[:500],
                tool="nmap",
                host=target,
                port=port,
                mitre_technique="T1190",
                exploit_suggestion=(
                    f"ftp {target} [user=anonymous pass=anonymous] → put webshell or authorized_keys"
                ),
            ))
            return

        # ── FTP — anon (read only) ────────────────────────────────────────
        if svc == "ftp" and banner.get("anon_allowed"):
            await self.store_finding(Finding(
                title=f"FTP {port} — Anonymous Login Allowed",
                description=(
                    f"FTP at {target}:{port} permits anonymous login. "
                    f"Unauthenticated users can list and download accessible files."
                ),
                severity="HIGH",
                evidence=banner.get("raw", "")[:500],
                tool="nmap",
                host=target,
                port=port,
                mitre_technique="T1078",
                exploit_suggestion=f"ftp {target} [anonymous:anonymous] → ls -la, get <files>",
            ))
            return

        # ── LDAP — anonymous bind ─────────────────────────────────────────
        if svc == "ldap" and banner.get("anon_bind"):
            base_dn = banner.get("base_dn", "dc=domain,dc=com")
            await self.store_finding(Finding(
                title=f"LDAP {port} — Anonymous Bind Allowed",
                description=(
                    f"LDAP at {target}:{port} accepts unauthenticated binds. "
                    f"Directory objects (users, groups, OUs) may be enumerable. "
                    + (f"Base DN: {base_dn}." if base_dn else "")
                ),
                severity="HIGH",
                evidence=banner.get("raw", "")[:500],
                tool="ldapsearch",
                host=target,
                port=port,
                mitre_technique="T1087.002",
                exploit_suggestion=(
                    f"ldapsearch -x -H ldap://{target}:{port} "
                    f"-b '{base_dn}' '(objectclass=user)' sAMAccountName"
                ),
            ))
            return

        # ── SMB — null session ────────────────────────────────────────────
        if svc == "smb" and banner.get("null_session"):
            write_shares = banner.get("write_shares", [])
            read_shares  = banner.get("read_shares", [])
            sev = "CRITICAL" if write_shares else "HIGH"
            await self.store_finding(Finding(
                title=(
                    f"SMB {port} — Null Session"
                    + (f" + Writable Shares {write_shares}" if write_shares else "")
                ),
                description=(
                    f"SMB at {target}:{port} allows null (unauthenticated) sessions. "
                    + (f"Writable shares: {write_shares}. " if write_shares else "")
                    + (f"Readable shares: {read_shares}. " if read_shares else "")
                ),
                severity=sev,
                evidence=banner.get("raw", "")[:600],
                tool="enum4linux-ng",
                host=target,
                port=port,
                mitre_technique="T1135",
                exploit_suggestion=(
                    f"smbclient -L //{target} -N → smbclient //{target}/<share> -N. "
                    "NTLM relay: ntlmrelayx.py -tf targets.txt -smb2support"
                ),
            ))
            return

        # ── SSH — old version ─────────────────────────────────────────────
        if svc == "ssh" and banner.get("old_version"):
            ver = banner.get("banner", "OpenSSH (old)")
            await self.store_finding(Finding(
                title=f"SSH {port} — Outdated Version: {ver}",
                description=(
                    f"SSH at {target}:{port} runs {ver}, below secure minimum (7.4+). "
                    f"May be vulnerable to CVE-2018-15473 (user enum) and others."
                ),
                severity="HIGH",
                evidence=banner.get("raw", "")[:400],
                tool="nmap",
                host=target,
                port=port,
                cve="CVE-2018-15473",
                mitre_technique="T1190",
                exploit_suggestion=(
                    f"searchsploit openssh {ver.split()[-1]}. "
                    f"python3 ssh-user-enum.py -t {target} -p {port} -U /usr/share/wordlists/metasploit/unix_users.txt"
                ),
            ))

        # Weak SSH algorithms (supplemental, not early return)
        if svc == "ssh" and banner.get("weak_algos"):
            await self.store_finding(Finding(
                title=f"SSH {port} — Weak Algorithms Advertised",
                description=(
                    f"SSH at {target}:{port} advertises deprecated algorithms "
                    f"(DH-group1-SHA1, arcfour, 3DES-CBC, etc.)."
                ),
                severity="MEDIUM",
                evidence=banner.get("raw", "")[:400],
                tool="nmap",
                host=target,
                port=port,
                mitre_technique="T1557",
                exploit_suggestion="Downgrade attacks may be possible. Brute-force if password auth enabled.",
            ))
            return

        # ── SNMP — community string ───────────────────────────────────────
        if svc == "snmp" and banner.get("community_found"):
            comm = banner["community_string"]
            await self.store_finding(Finding(
                title=f"SNMP {port} — Community String '{comm}' Accepted",
                description=(
                    f"SNMP at {target}:{port} accepts '{comm}'. "
                    f"System info, routing tables, processes, and installed software are readable."
                ),
                severity="MEDIUM",
                evidence=banner.get("raw", "")[:500],
                tool="snmpwalk",
                host=target,
                port=port,
                mitre_technique="T1046",
                exploit_suggestion=(
                    f"snmpwalk -v1 -c {comm} {target}  (full MIB). "
                    f"snmp-check -c {comm} {target}  (formatted summary)."
                ),
            ))
            return

        # ── SMTP — VRFY enabled ───────────────────────────────────────────
        if svc == "smtp" and banner.get("vrfy_enabled"):
            await self.store_finding(Finding(
                title=f"SMTP {port} — VRFY Command Enabled",
                description=(
                    f"SMTP at {target}:{port} responds to VRFY, enabling user enumeration."
                ),
                severity="MEDIUM",
                evidence=banner.get("raw", "")[:400],
                tool="nmap",
                host=target,
                port=port,
                mitre_technique="T1589.002",
                exploit_suggestion=(
                    "smtp-user-enum -M VRFY "
                    f"-U /usr/share/wordlists/metasploit/unix_users.txt -t {target} -p {port}"
                ),
            ))

        # ── SMTP — open relay ─────────────────────────────────────────────
        if svc == "smtp" and banner.get("open_relay"):
            await self.store_finding(Finding(
                title=f"SMTP {port} — Open Relay Detected",
                description=(
                    f"SMTP at {target}:{port} is an open relay — unauthenticated relay "
                    f"to arbitrary destinations allowed."
                ),
                severity="HIGH",
                evidence=banner.get("raw", "")[:400],
                tool="nmap",
                host=target,
                port=port,
                mitre_technique="T1048",
                exploit_suggestion=(
                    f"swaks --to victim@external.com --from nobody@internal "
                    f"--server {target}:{port}"
                ),
            ))
            return

        # ── RDP — no NLA / weak encryption ───────────────────────────────
        if svc == "rdp":
            nla = banner.get("nla_enabled", True)
            enc = banner.get("encryption_level", "").lower()
            if not nla or "classic" in enc or "low" in enc:
                await self.store_finding(Finding(
                    title=f"RDP {port} — No NLA / Weak Encryption",
                    description=(
                        f"RDP at {target}:{port} lacks NLA or uses weak encryption. "
                        f"Pre-auth traffic may be capturable; credential brute-force is easier."
                    ),
                    severity="MEDIUM",
                    evidence=banner.get("raw", "")[:400],
                    tool="nmap",
                    host=target,
                    port=port,
                    mitre_technique="T1021.001",
                    exploit_suggestion=(
                        "Capture NTLMv2 with Responder. "
                        f"Brute-force: hydra -l Administrator -P rockyou.txt rdp://{target}:{port}"
                    ),
                ))
            return

        # ── HTTP — server/version disclosure ─────────────────────────────
        if svc == "http":
            server  = banner.get("server", "")
            powered = banner.get("powered_by", "")
            missing = banner.get("missing_headers", [])
            info    = " | ".join(filter(None, [server, powered]))
            if info:
                has_ver = bool(re.search(r"\d+\.\d+", info))
                await self.store_finding(Finding(
                    title=f"HTTP {port} — Server Disclosure: {info[:60]}",
                    description=(
                        f"HTTP at {target}:{port} discloses: {info}. "
                        f"Version info aids targeted attack selection."
                    ),
                    severity="MEDIUM" if has_ver else "LOW",
                    evidence=banner.get("raw", "")[:300],
                    tool="curl",
                    host=target,
                    port=port,
                    exploit_suggestion="searchsploit the version string; check NVD for CVEs.",
                ))
            if missing:
                await self.store_finding(Finding(
                    title=f"HTTP {port} — Missing Security Headers",
                    description=(
                        f"HTTP at {target}:{port} is missing: {', '.join(missing)}."
                    ),
                    severity="LOW",
                    evidence=banner.get("raw", "")[:300],
                    tool="curl",
                    host=target,
                    port=port,
                ))
            return

        # B9 — Generic banner data is no longer stored as a finding.  These
        # INFO entries previously made up ~74% of the findings list, which
        # buried the actual actionable findings (LDAP anon bind, kerberoast
        # available, etc.) in noise.  The banner data still flows into
        # intel['banners'] / intel['service_versions'] for the planner via
        # the parsed_data merge at the recon phase.  Operators wanting the
        # banners back in findings can set ARGUS_INCLUDE_BANNER_FINDINGS=1.
        import os as _os
        banner_text = banner.get("banner", "")
        if banner_text and len(banner_text) > 8 and _os.environ.get("ARGUS_INCLUDE_BANNER_FINDINGS"):
            await self.store_finding(Finding(
                title=f"Port {port} Banner ({banner.get('service', 'unknown')})",
                description=(
                    f"Banner from {target}:{port} "
                    f"({banner.get('service', 'unknown')}): {banner_text[:150]}"
                ),
                severity="INFO",
                evidence=banner_text[:400],
                tool="nmap",
                host=target,
                port=port,
            ))
