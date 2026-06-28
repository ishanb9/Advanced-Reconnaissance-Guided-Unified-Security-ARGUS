"""knowledge/safety_governor.py — unified execution-boundary governor (Gap #5).

ONE pure decision point for "may ARGUS run this tool invocation, as-is?", replacing
scattered, reactive guards with a single, testable policy that has real teeth:

  • SCOPE       — the target host must be inside the authorised scope.  Hitting an
                  out-of-scope host is a legal/safety boundary, so this DENIES.
  • DESTRUCTIVE — host-damaging ops (wipe/format a disk, overwrite system files,
                  shutdown/reboot, fork-bomb) are REWRITTEN to a no-op so any chained
                  recon still runs, instead of trashing the box or ARGUS itself.
  • OT / LIFE   — intrusive actions against an OT / life-safety target need explicit
                  authorization; safe-by-default otherwise (reuses the skill gate).
  • INTRUSIVE   — the action's intrusiveness vs the human-selected ceiling.  Advisory
                  at run_tool (the dispatch layer enforces auto-run); callers may opt
                  into hard enforcement via ``enforce``.

``evaluate`` returns a Verdict dict; ``decision`` ∈ {allow, rewrite, deny,
require_approval}.  It is pure and never raises on normal input, so the run_tool
caller can wrap it best-effort and the governor can never break a legitimate run.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

# Reuse the OT/intrusiveness ceiling gate rather than re-deriving it.
try:                                    # pragma: no cover - import shape only
    from knowledge.skill_registry import allowed as _ceiling_allows
except Exception:                       # pragma: no cover
    def _ceiling_allows(action_safety: str, ceiling: str, domain: str = "IT",
                        life_safety: bool = False, authorized: bool = False) -> bool:
        return True

# ── Intrusiveness classification ──────────────────────────────────────────────
# Weaponisation / exploitation / brute / DoS-ish tools are "intrusive"; active but
# non-exploit probes are "light"; passive recon is "safe".  Unknown → "light".
_INTRUSIVE_TOOLS = {
    "metasploit", "msfconsole", "msfvenom", "sqlmap", "hydra", "medusa", "patator",
    "john", "hashcat", "responder", "crackmapexec", "impacket", "exploit", "searchsploit",
    "commix", "beef", "setoolkit", "wpscan",
}
_INTRUSIVE_HINTS = ("exploit", "--rce", "reverse-shell", "payload", "bruteforce",
                    "--brute", "shell_exec", "weaponize")
_LIGHT_TOOLS = {
    "nmap", "rustscan", "masscan", "nikto", "nuclei", "ffuf", "gobuster", "feroxbuster",
    "dirb", "wfuzz", "httpx", "whatweb", "wafw00f", "enum4linux", "smbclient", "curl",
}
_SAFE_TOOLS = {
    "whois", "dig", "host", "nslookup", "theharvester", "amass", "subfinder", "sublist3r",
    "dnsrecon", "crt", "shodan", "sslscan", "openssl", "ping", "traceroute",
}


def classify_intrusiveness(tool_name: str, args: str = "") -> str:
    """Return 'safe' | 'light' | 'intrusive' for a tool invocation."""
    t = str(tool_name or "").lower().strip()
    a = str(args or "").lower()
    if t in _INTRUSIVE_TOOLS or any(h in t or h in a for h in _INTRUSIVE_HINTS):
        return "intrusive"
    if t in _SAFE_TOOLS:
        return "safe"
    if t in _LIGHT_TOOLS:
        return "light"
    return "light"


# ── Destructive-op detection / rewrite ────────────────────────────────────────
# A destructive op must be EXECUTED, which means it sits in COMMAND POSITION — at the
# start of a command or right after a shell separator — not embedded as an argument,
# filename, URL path, grep pattern, or echo'd string.  We therefore split the args
# into command segments and inspect each segment's COMMAND, so `grep -r shutdown
# /var/log` and `curl http://t/api/shutdown/` are never mistaken for a host shutdown.

# Shells where these ops are dangerous (argv-style tool invocations are not shells).
_SHELLS = {"bash", "sh", "zsh", "shell_exec", "cmd", "powershell", "system"}

# Two tiers of roots.  CRITICAL: ANY recursive delete (incl. sub-paths) is host damage.
# BARE: only deleting the root ITSELF is damage — sub-paths are legit workdirs
# (e.g. rm -rf /home/kali/scan is fine; rm -rf /home wipes every user).
_CRITICAL_ROOTS = ("/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/lib64",
                   "/sys", "/proc", "/dev", "/root")
_BARE_ROOTS = ("/", "~", "$home", "/home", "/var", "/opt", "/srv")

_SEP_RE = re.compile(r"&&|\|\||[;&|\n]")
#: Bare command wrappers that prefix the REAL command without positional args, so the
#: real command's basename is what matters (env rm -rf /, nohup shutdown, doas mkfs …).
_WRAPPERS = {"sudo", "doas", "env", "nohup", "setsid", "exec", "command",
             "builtin", "time", "then", "do"}
_FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
_DD_DISK_RE = re.compile(r"\bof=/dev/(?:sd|nvme|vd|hd|mmcblk)", re.I)
_REDIR_DISK_RE = re.compile(r">\s*/dev/(?:sd|nvme|vd|hd|mmcblk)\w*", re.I)


def _norm_path(p: str) -> str:
    p = str(p or "").strip().strip("'\"")
    return (p.rstrip("/") or "/").lower()


def _path_is_dangerous(operand: str) -> bool:
    """True if a recursive delete of ``operand`` damages the host."""
    p = _norm_path(operand)
    if p in _BARE_ROOTS:                       # the bare root itself
        return True
    for r in _CRITICAL_ROOTS:                  # the root or any path under it
        if p == r or p.startswith(r + "/"):
            return True
    return False


def _flags_recursive_force(flags: List[str]):
    """Parse rm/chmod/chown flag tokens (any order, short clusters or long flags)."""
    low = [f.lower() for f in flags]
    short = [f for f in low if f.startswith("-") and not f.startswith("--")]
    recursive = any("r" in f for f in short) or any(f in ("--recursive", "--recurse") for f in low)
    force = any("f" in f for f in short) or ("--force" in low)
    return recursive, force


def _segments(args: str):
    """Yield (command_basename, operand_tokens, raw_segment) for each shell segment,
    stripping a leading ``sudo`` and ``VAR=val`` env assignments."""
    for raw in _SEP_RE.split(args or ""):
        seg = raw.strip()
        if not seg:
            continue
        toks = seg.split()
        i = 0
        # Strip leading wrappers (sudo/env/nohup/…) and VAR=val env assignments so the
        # REAL command surfaces: `env rm -rf /` and `nohup shutdown` are not disguised.
        while i < len(toks) and (toks[i].rsplit("/", 1)[-1].lower() in _WRAPPERS
                                 or re.match(r"^\w+=", toks[i])):
            i += 1
        if i >= len(toks):
            continue
        cmd = toks[i].rsplit("/", 1)[-1].lower()   # basename: /sbin/shutdown → shutdown
        yield cmd, toks[i + 1:], seg


def _is_net_disrupt(cmd: str, rest: List[str], seg: str) -> bool:
    """True if the command tears down or restarts the LOCAL network / VPN tunnel the
    engagement runs over (e.g. the operator 'fixing' connectivity by restarting
    OpenVPN mid-scan) — self-sabotage that drops the MCP server, Mongo, and the
    target route.  The human operator owns the tunnel; ARGUS must not touch it."""
    low = seg.lower()
    if cmd in ("pkill", "killall", "kill") and re.search(r"open ?vpn|wireguard|\bwg\b|networkmanager", low):
        return True
    if cmd == "openvpn":                                  # (re)starting a VPN daemon
        return True
    if cmd in ("wg-quick", "ifdown"):
        return True
    if cmd in ("systemctl", "service") and re.search(r"\b(stop|restart|disable)\b", low) \
            and re.search(r"openvpn|network|wg", low):
        return True
    if cmd == "ifconfig" and any(t.lower() == "down" for t in rest):
        return True
    if cmd == "ip" and "link" in low and "down" in low:
        return True
    if cmd == "nmcli" and re.search(r"\b(down|disconnect|off)\b", low):
        return True
    return False


def destructive_match(tool_name: str, args: str) -> Optional[str]:
    """Return a short label for a host-damaging op in COMMAND POSITION, else None.
    Only shell-style tools are inspected (argv tools cannot run a shell command)."""
    if str(tool_name or "").lower() not in _SHELLS:
        return None
    a = str(args or "")
    if _FORK_BOMB_RE.search(a):
        return "fork bomb"
    for cmd, rest, seg in _segments(a):
        if _is_net_disrupt(cmd, rest, seg):
            return "network/VPN self-disruption (engagement connectivity)"
        if cmd == "rm":
            recursive, force = _flags_recursive_force([t for t in rest if t.startswith("-")])
            if recursive and force:
                for op in (t for t in rest if not t.startswith("-")):
                    if _path_is_dangerous(op):
                        return f"rm -rf {op}"
        elif cmd in ("shutdown", "reboot", "poweroff", "halt"):
            return cmd                                   # the command itself
        elif cmd == "init" and rest and rest[0] in ("0", "6"):
            return f"init {rest[0]}"
        elif cmd.startswith("mkfs") or cmd in ("wipefs", "shred"):
            return cmd
        elif cmd == "dd" and _DD_DISK_RE.search(seg):
            return "dd of=/dev/<disk>"
        elif cmd in ("chmod", "chown"):
            recursive, _ = _flags_recursive_force([t for t in rest if t.startswith("-")])
            if recursive and any(_path_is_dangerous(t) for t in rest if not t.startswith("-")):
                return f"{cmd} -R on a system path"
    if _REDIR_DISK_RE.search(a):                        # cat x > /dev/sda
        return "redirect to /dev/<disk>"
    return None


# ── Scope matching ────────────────────────────────────────────────────────────
def _norm_host(h: str) -> str:
    h = str(h or "").strip().lower()
    h = re.sub(r"^\w+://", "", h)          # strip scheme
    h = h.split("/")[0].split("@")[-1]     # strip path + creds
    h = h.split(":")[0]                    # strip port
    return h.strip("[]")


def host_in_scope(host: str, scope_hosts: Iterable[str]) -> bool:
    """Exact host, IP, or proper sub-domain of a scope entry.  Empty scope ⇒ unknown
    (treated as in-scope — the governor only DENIES when scope is explicitly set)."""
    scope = [_norm_host(s) for s in (scope_hosts or []) if str(s).strip()]
    if not scope:
        return True
    h = _norm_host(host)
    if not h:
        return True
    for s in scope:
        # In scope iff host IS a scope entry or a SUB-domain of one — NOT the reverse:
        # authorising app.example.com must NOT put the parent example.com in scope.
        if h == s or h.endswith("." + s):
            return True
    return False


# ── The governor ──────────────────────────────────────────────────────────────
_DEFAULT_ENFORCE = ("scope", "destructive", "ot_life_safety")


def evaluate(invocation: Dict[str, Any],
             enforce: Iterable[str] = _DEFAULT_ENFORCE) -> Dict[str, Any]:
    """Decide whether a tool invocation may run as-is.  ``invocation`` keys:
        tool_name, args, target_host, scope_hosts, ceiling, domain,
        life_safety (bool), authorized (bool).
    Returns {decision, reason, rewritten_args, checks}.  Pure."""
    inv = invocation or {}
    tool = str(inv.get("tool_name") or "")
    args = str(inv.get("args") or "")
    enforce = set(enforce or ())

    intr = classify_intrusiveness(tool, args)
    in_scope = host_in_scope(inv.get("target_host") or "", inv.get("scope_hosts") or [])
    domain = str(inv.get("domain") or "IT").upper()
    life_safety = bool(inv.get("life_safety"))
    authorized = bool(inv.get("authorized"))
    ceiling = str(inv.get("ceiling") or "intrusive")
    destructive = destructive_match(tool, args)

    checks = {"intrusiveness": intr, "in_scope": in_scope, "destructive": destructive,
              "domain": domain, "life_safety": life_safety}

    def verdict(decision: str, reason: str, rewritten: Optional[str] = None) -> Dict[str, Any]:
        return {"decision": decision, "reason": reason,
                "rewritten_args": rewritten, "checks": checks}

    # 1) SCOPE — out-of-scope target is a hard boundary.
    if "scope" in enforce and not in_scope:
        return verdict("deny", f"target '{inv.get('target_host')}' is OUT OF SCOPE "
                               f"(authorised scope: {list(inv.get('scope_hosts') or [])})")

    # 2) DESTRUCTIVE — rewrite host-damaging ops to a no-op so the loop continues.
    if "destructive" in enforce and destructive:
        return verdict("rewrite",
                       f"neutralised host-destructive operation: {destructive!r}",
                       rewritten="true")

    # 3) OT / LIFE-SAFETY — intrusive action on OT or a life-safety asset needs auth.
    if "ot_life_safety" in enforce and intr == "intrusive" and not authorized:
        if domain == "OT" or life_safety:
            return verdict("deny",
                           f"intrusive action on a {'life-safety' if life_safety else 'OT'} "
                           "target requires explicit authorization (safe-by-default)")

    # 4) INTRUSIVENESS ceiling — hard only when the caller opts in; else advisory.
    if "intrusiveness" in enforce and not _ceiling_allows(intr, ceiling, domain,
                                                          life_safety, authorized):
        return verdict("require_approval",
                       f"action intrusiveness '{intr}' exceeds the '{ceiling}' ceiling")

    return verdict("allow", "within scope, non-destructive, within ceiling")
