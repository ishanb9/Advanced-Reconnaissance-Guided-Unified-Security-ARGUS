# -*- coding: utf-8 -*-
"""ARGUS-driven data layer for the vendored dark/light report design.

The vendored builder (``build_report.py``) reads its data model through
``import data as D`` and consumes these 15 module-level names:

    ENGAGEMENT SEVERITY_ORDER SEVERITY_COUNTS TOTAL_FINDINGS HOSTS HOST_NO_DATA
    F ATTACK_SURFACE KILL_CHAIN KILL_CHAIN_PHASES MITRE DETECTION REMEDIATION
    CVSS_BANDS METHODOLOGY

Two guarantees:

1.  Every name below is declared with a SAFE, SHAPE-CORRECT default, so a bare
    ``import data`` never raises and ``build_report.build(...)`` renders an
    empty-but-valid report even if :func:`apply` is never called.
2.  :func:`apply` re-populates every name from a live ARGUS
    ``ReportGenerator._build_context`` dict.  It is fully defensive — every
    access is guarded and the function never raises; on any per-section failure
    it leaves that section at its safe default.

Nothing here mutates the builder; it only supplies the data the builder reads.
"""

import re

# --------------------------------------------------------------------------- #
#  Canonical constants (also the safe defaults for the constant-shaped names)
# --------------------------------------------------------------------------- #

# hot -> cool; canonical key set used to index every counts dict and drive order
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# builder SEV_CLASS / sev_rank domain — F.sev, HOSTS counts keys, CVSS_BANDS.sev
# must all be members of this set.
_SEV_KEYS = ("Critical", "High", "Medium", "Low", "Info")

_SEV_CANON = {
    "critical": "Critical", "crit": "Critical",
    "high": "High",
    "medium": "Medium", "med": "Medium", "moderate": "Medium",
    "low": "Low",
    "info": "Info", "informational": "Info", "information": "Info",
    "none": "Info", "unknown": "Info", "": "Info",
}

# ARGUS final_rating slug -> gauge-safe capitalized level (charts.risk_gauge only
# accepts Info/Low/Medium/High/Critical; 'none' would crash order.index()).
_RATING_TO_RISK = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "none": "Info", "info": "Info", "": "Info",
}

_RISK_BY_SEV = {"Critical": "high", "High": "high", "Medium": "med",
                "Low": "low", "Info": "info"}
_RISK_RANK = {"high": 3, "med": 2, "low": 1, "info": 0}

# small ATT&CK id -> name table for when only finding.mitre (no mappings) exists
_MITRE_NAMES = {
    "T1595": "Active Scanning", "T1592": "Gather Victim Host Information",
    "T1046": "Network Service Discovery", "T1190": "Exploit Public-Facing Application",
    "T1059": "Command & Scripting Interpreter", "T1059.007": "JavaScript",
    "T1203": "Exploitation for Client Execution", "T1068": "Exploitation for Privilege Escalation",
    "T1210": "Exploitation of Remote Services", "T1212": "Exploitation for Credential Access",
    "T1040": "Network Sniffing", "T1557": "Adversary-in-the-Middle",
    "T1552": "Unsecured Credentials", "T1110": "Brute Force", "T1078": "Valid Accounts",
    "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares", "T1071": "Application Layer Protocol",
    "T1505": "Server Software Component", "T1083": "File and Directory Discovery",
    "T1005": "Data from Local System", "T1213": "Data from Information Repositories",
}


def _default_cvss_bands():
    return [
        {"band": "9.0 – 10.0", "sev": "Critical", "desc": "Demonstrated compromise / catastrophic impact"},
        {"band": "7.0 – 8.9", "sev": "High", "desc": "Public exploit or confirmed direct exploitability"},
        {"band": "4.0 – 6.9", "sev": "Medium", "desc": "Confirmed, chainable weakness"},
        {"band": "0.1 – 3.9", "sev": "Low", "desc": "Minor issue / information leak"},
        {"band": "0.0", "sev": "Info", "desc": "Detection / attack surface"},
    ]


def _default_methodology():
    return [
        {"step": "Plan",
         "body": "ARGUS builds a hypothesis tree of testable attack paths from reconnaissance, "
                 "activating nodes as evidence accrues."},
        {"step": "Execute",
         "body": "Ordered tool dispatch against each hypothesis; every action is logged with its "
                 "command, raw output and MITRE ATT&CK annotation. Non-exploitable paths are "
                 "retained as coverage evidence."},
        {"step": "Validate",
         "body": "A finding is published only when it passes the Issue-Validator gate — grounded in "
                 "concrete tool output, accurately CVSS-scored, with reproduction recorded. "
                 "Unsubstantiated claims are demoted, not shipped."},
    ]


def _default_engagement():
    return {
        "platform": "ARGUS",
        "platform_tagline": "Autonomous Offensive Security",
        "doc_type": "Autonomous Penetration Test · Engagement Report",
        "engagement_name": "Authorized Assessment",
        "scope_cidr": "N/A",
        "targets": [],
        "hosts_with_findings": 0,
        "engagement_type": "Penetration Test",
        "started": "—",
        "completed": "—",
        "duration": "—",
        "generated": "—",
        "overall_risk": "Info",
        "overall_risk_note": "No findings published",
        "access_achieved": "None",
        "findings_gate": "ARGUS Issue-Validator (evidence-grounded, severity-scaled)",
        "classification": "CONFIDENTIAL",
        "frameworks": ["MITRE ATT&CK Enterprise", "OWASP Top 10", "CVSS v3.1", "PTES"],
    }


def _empty_counts():
    return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}


def _placeholder_host():
    """A single neutral host so ``dashboard()``'s ``max(h['total'] ...)`` never
    hits an empty sequence when there are no findings."""
    return {
        "ip": "—", "label": "No hosts with findings", "os": "Unknown",
        "counts": _empty_counts(), "total": 0,
        "note": "No published findings for this engagement.",
    }


# --------------------------------------------------------------------------- #
#  Module-level names — SAFE DEFAULTS (a builder run with no data still renders)
# --------------------------------------------------------------------------- #

ENGAGEMENT = _default_engagement()
SEVERITY_COUNTS = _empty_counts()
TOTAL_FINDINGS = 0
HOSTS = [_placeholder_host()]          # never empty (dashboard() calls max())
HOST_NO_DATA = "—"
F = []
ATTACK_SURFACE = []
KILL_CHAIN = []
KILL_CHAIN_PHASES = ["Recon", "Exploit / Foothold", "Privilege Esc",
                     "Post-exploit / Loot", "Persistence", "Lateral"]
MITRE = []
DETECTION = []
REMEDIATION = []
CVSS_BANDS = _default_cvss_bands()
METHODOLOGY = _default_methodology()

# --- extended ARGUS data types (every one has an empty-safe default) ---------
COMPROMISE_EVIDENCE = {}            # basis-of-compromise / proof-of-access receipts
CREDS_SUMMARY = []                  # recovered logins & harvested secrets (redacted)
LOOT_ENTRIES = []                   # harvested data-of-interest, archived by SHA-256
LOOT_SUMMARY = {}                   # category -> count
FLAGS = []                          # captured user/root flags & high-value tokens
AI_SECURITY = {}                    # AI/LLM red-team results (AIVSS/ASR/OWASP-LLM/ATLAS)
COVERAGE_TESTS = []                 # every probe run incl. negative results
COVERAGE_COUNTS = {}               # outcome -> count
OBJECTIVES = []                     # engagement question set with answers
OBJECTIVES_DONE = 0
OBJECTIVES_TOTAL = 0
MISSION_BRIEF = {}                  # objective / scope / budgets / blast radius
WIN_CONDITIONS = {}                 # win-condition tracker snapshot
AUTONOMY = ""                       # session autonomy level
EXPLOIT_MODULES = []                # exploits & public PoCs considered / selected
REASONING_JOURNAL = []              # per-iteration decision trail (strings)
JOURNAL_TRUNCATED = False
JOURNAL_TOTAL = 0
WEB_INTEL_HINTS = []                # exploit techniques mined from web sources
DISCOVERED_ISSUES = []              # observed-but-not-promoted issues storyline
PRIMER_ROWS = []                    # platform capability map (tool availability)
ATTACK_PATH = []                    # chronological foothold/pivot/privesc timeline
ENGAGEMENT_TIMELINE = []            # chronological milestones
TOOLS_USED = []                     # sorted unique tool names
PHASES_COMPLETED = []               # pentest phases that actually ran
ALL_PHASES = ["recon", "scan", "vuln_id", "osint", "exploit", "post_exploit",
              "privesc", "persistence", "lateral", "wireless", "iot", "reporting"]
OBSERVABILITY = {}                  # token usage + tool-invocation counters


# --------------------------------------------------------------------------- #
#  Small guarded helpers
# --------------------------------------------------------------------------- #

_CIDR_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _s(v):
    """Safe string: None -> '' (never raises)."""
    if v is None:
        return ""
    try:
        return v if isinstance(v, str) else str(v)
    except Exception:
        return ""


def _norm_sev(v):
    try:
        return _SEV_CANON.get(_s(v).strip().lower(), "Info")
    except Exception:
        return "Info"


def _cvss_str(cb):
    """extra.cvss_base (float|int|str|None) -> display string ('' when absent)."""
    try:
        if cb is None or cb == "":
            return ""
        if isinstance(cb, bool):
            return ""
        if isinstance(cb, (int, float)):
            return "%.1f" % float(cb)
        return _s(cb).strip()
    except Exception:
        return ""


def _mitre_str(v):
    """Coerce a finding's mitre field (str|list|dict|None) to a single id/''."""
    try:
        if v is None:
            return ""
        if isinstance(v, str):
            return v.strip()
        if isinstance(v, (list, tuple)):
            for x in v:
                sx = _s(x).strip()
                if sx:
                    return sx
            return ""
        if isinstance(v, dict):
            for k in ("technique_id", "id", "technique"):
                sx = _s(v.get(k)).strip()
                if sx:
                    return sx
            return ""
        return _s(v).strip()
    except Exception:
        return ""


def _humanize(v):
    s = _s(v).strip()
    if not s or s.lower() in ("auto", "unknown", "default", "none", "null"):
        return "Penetration Test"
    return " ".join(w.capitalize() for w in re.split(r"[\s_\-]+", s) if w)


def _ip_key(x):
    xs = _s(x)
    if _IPV4_RE.match(xs):
        try:
            return (0, tuple(int(g) for g in xs.split(".")))
        except Exception:
            return (1, xs)
    return (1, xs)


def _infer_cidr(targets):
    ipv4s = [t for t in targets if _IPV4_RE.match(_s(t))]
    if not ipv4s:
        return None
    prefixes = {".".join(_s(ip).split(".")[:3]) for ip in ipv4s}
    if len(prefixes) == 1:
        return next(iter(prefixes)) + ".0/24"
    return None


def _safe(fn, *args, **kw):
    """Call ``fn(*args)`` and swallow any exception, returning ``kw['default']``."""
    default = kw.get("default")
    try:
        return fn(*args)
    except Exception:
        return default


# --------------------------------------------------------------------------- #
#  Section builders (each pure + guarded; return safe fallbacks)
# --------------------------------------------------------------------------- #

def _build_findings(ctx):
    """ARGUS enriched findings -> F register rows (all values strings)."""
    src = ctx.get("findings")
    if not isinstance(src, list):
        return []
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    rows = []
    for i, f in enumerate(src):
        if not isinstance(f, dict):
            continue
        extra = f.get("extra") if isinstance(f.get("extra"), dict) else {}
        sev = _norm_sev(f.get("severity"))
        host = _s(f.get("host")).strip() or "unspecified"
        port_v = f.get("port")
        if isinstance(port_v, bool):
            port = ""
        elif isinstance(port_v, int):
            port = str(port_v)
        elif isinstance(port_v, str) and port_v.strip():
            port = port_v.strip()
        else:
            port = ""
        proto = (_s(f.get("protocol")).strip() or _s(f.get("service")).strip()
                 or _s(f.get("phase")).strip() or "finding")
        cvss = _cvss_str(extra.get("cvss_base") if extra else None)
        if not cvss:
            cvss = _cvss_str(f.get("cvss"))
        mitre = (_mitre_str(f.get("mitre")) or _mitre_str(f.get("mitre_technique"))
                 or _mitre_str(extra.get("mitre") if extra else None))
        title = _s(f.get("title")).strip() or "Finding"
        desc = _s(f.get("description")).strip() or title
        evidence = _s(f.get("evidence")).strip() or _s(f.get("raw_output")).strip()
        basis = (_s(f.get("basis_note")).strip() or _s(f.get("severity_rationale")).strip()
                 or _s(f.get("evidence_tag")).strip()
                 or "Severity %s as assessed by ARGUS from the collected tool evidence." % sev)
        # [S12/S84] render the STORED per-finding remediation — real remediation persisted on
        # finalized findings lives in extra.remediation and was being discarded in favour of
        # the blanket placeholder, so all 80 findings shared one string.
        fix = (_s(f.get("remediation")).strip()
               or _s(extra.get("remediation") if extra else "").strip()
               or _s(f.get("fix")).strip() or _s(f.get("recommendation")).strip()
               or "No specific remediation recorded; review the evidence and apply vendor/base-line guidance.")
        cat = (_s(extra.get("category") if extra else "").strip().lower()
               or _s(f.get("phase")).strip().lower() or "general")
        rows.append({
            "_i": i,
            "id": "", "sev": sev, "cvss": cvss, "host": host, "port": port,
            "proto": proto, "cat": cat, "mitre": mitre, "title": title,
            "raw": _s(f.get("raw_output")), "desc": desc, "basis": basis,
            "evidence": evidence, "fix": fix,
        })
    # stable severity sort, then stamp sequential F-NN ids
    rows.sort(key=lambda r: (rank.get(r["sev"], 4), r["_i"]))
    for n, r in enumerate(rows, 1):
        r["id"] = "F-%02d" % n
        r.pop("_i", None)
    return rows


def _counts_from_findings(f_list):
    c = _empty_counts()
    for f in (f_list or []):
        s = f.get("sev")
        if s in c:
            c[s] += 1
    return c


def _host_os(host, fs, ctx):
    hay = " ".join((f.get("title", "") + " " + f.get("desc", "") + " " + f.get("proto", ""))
                   for f in fs).lower()
    if any(k in hay for k in ("windows", "active directory", " smb", "ms-wbt", "rdp",
                              "netbios", "microsoft-ds")):
        return "Windows"
    if any(k in hay for k in ("linux", "unix", "debian", "ubuntu", "busybox", "embedded")):
        return "Linux"
    intel = ctx.get("intel") if isinstance(ctx.get("intel"), dict) else {}
    og = _s(intel.get("os_guess")).strip()
    if og and og.lower() not in ("unknown", "none", "n/a"):
        return og
    return "Unknown"


def _host_label(host, fs):
    hay = " ".join((f.get("title", "") + " " + f.get("cat", "") + " " + f.get("proto", ""))
                   for f in fs).lower()
    if any(k in hay for k in ("hikvision", "rtsp", "camera", "iot", "embedded")):
        return "IoT / camera"
    if any(k in hay for k in ("active directory", " smb", "netbios", "ldap", "kerberos")):
        return "Windows / AD host"
    if any(k in hay for k in ("mssql", "mysql", "postgres", "mongo", "redis", "database", "oracle")):
        return "Database host"
    if any(k in hay for k in ("http", "web", "xss", "idor", "csp", "header", "tls", "https")):
        return "Web host"
    if any(k in hay for k in ("telnet", "rexec", "rsh", "rlogin", "ssh", "ftp", "rdp")):
        return "Remote-access host"
    return "Host"


def _host_note(fs, counts):
    total = len(fs)
    mix = "%dC / %dH / %dM / %dL / %dI" % (
        counts["Critical"], counts["High"], counts["Medium"], counts["Low"], counts["Info"])
    top = fs[0]["title"] if fs else ""
    if top:
        return "%d finding(s) — %s. Highest-severity: %s" % (total, mix, top)
    return "%d finding(s) — %s." % (total, mix)


def _build_hosts(f_list, ctx):
    groups = {}
    for f in (f_list or []):
        groups.setdefault(f["host"], []).append(f)
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    hosts = []
    for host, fs in groups.items():
        fs.sort(key=lambda x: (rank.get(x["sev"], 4), x["id"]))
        counts = _empty_counts()
        for f in fs:
            if f["sev"] in counts:
                counts[f["sev"]] += 1
        hosts.append({
            "ip": host, "label": _host_label(host, fs), "os": _host_os(host, fs, ctx),
            "counts": counts, "total": len(fs), "note": _host_note(fs, counts),
        })
    hosts.sort(key=lambda h: (h["counts"]["Critical"], h["counts"]["High"],
                              h["counts"]["Medium"], h["counts"]["Low"], h["total"]),
               reverse=True)
    return hosts or [_placeholder_host()]


def _build_targets(hosts, f_list, ctx):
    seen = set()
    order = []

    def add(v):
        t = _s(v).strip()
        if not t:
            return
        if t.lower() in ("unspecified", "—", "-", "none", "null", "multiple",
                         "multiple subnets", "n/a"):
            return
        if t not in seen:
            seen.add(t)
            order.append(t)

    session = ctx.get("session") if isinstance(ctx.get("session"), dict) else {}
    for k in ("target_ip", "target", "target_host", "target_hostname"):
        add(session.get(k))
    dh = session.get("discovered_hosts")
    if isinstance(dh, list):
        for x in dh:
            add(x)
    for h in (hosts or []):
        add(h.get("ip"))
    for f in (f_list or []):
        add(f.get("host"))
    flags = ctx.get("flags")
    if isinstance(flags, list):
        for fl in flags:
            if isinstance(fl, dict):
                add(fl.get("host"))

    targets = sorted(order, key=_ip_key)
    with_findings = {h.get("ip") for h in (hosts or []) if h.get("total", 0) > 0}
    nodata = ""
    for t in targets:
        if t not in with_findings:
            nodata = t
            break
    return targets, (nodata or "—")


def _scope_cidr(session, target_display, targets):
    for cand in (session.get("scope") if isinstance(session, dict) else None, target_display):
        if isinstance(cand, str):
            m = _CIDR_RE.search(cand)
            if m:
                return m.group(0)
    inf = _infer_cidr(targets)
    if inf:
        return inf
    td = _s(target_display).strip()
    if td:
        return td
    if targets:
        return targets[0]
    return "N/A"


def _access_line(outcome, intel):
    o = outcome if isinstance(outcome, dict) else {}
    it = intel if isinstance(intel, dict) else {}
    if o.get("root"):
        return "Full compromise — root / administrator"
    if o.get("compromised") or it.get("shell_access"):
        return "Foothold obtained"
    return "None"


def _build_engagement(ctx, targets, total, hosts):
    session = ctx.get("session") if isinstance(ctx.get("session"), dict) else {}
    outcome = ctx.get("outcome") if isinstance(ctx.get("outcome"), dict) else {}
    intel = ctx.get("intel") if isinstance(ctx.get("intel"), dict) else {}

    et = _humanize(ctx.get("engagement_type") or session.get("target_type"))
    rating = _s(ctx.get("final_rating") or outcome.get("final_rating")).strip().lower()
    overall_risk = _RATING_TO_RISK.get(rating, "Info")
    note = (_s(ctx.get("final_rating_label")).strip()
            or _s(outcome.get("final_rating_label")).strip()
            or {"Critical": "Critical risk", "High": "Significant issues identified",
                "Medium": "Moderate issues identified", "Low": "Minor issues identified",
                "Info": "No significant issues identified"}.get(overall_risk, ""))
    scope_cidr = _scope_cidr(session, ctx.get("target_display"), targets)
    hosts_wf = sum(1 for h in (hosts or []) if h.get("total", 0) > 0)

    frameworks = ["MITRE ATT&CK Enterprise", "OWASP Top 10", "CVSS v3.1", "PTES"]
    ai = ctx.get("ai_security")
    if isinstance(ai, dict) and ai.get("count"):
        frameworks += ["OWASP Top 10 for LLM", "MITRE ATLAS", "AIVSS"]

    e = _default_engagement()
    e.update({
        "doc_type": "Autonomous %s · Engagement Report" % et,
        "engagement_name": _s(ctx.get("target_display")).strip() or scope_cidr or "Authorized Assessment",
        "scope_cidr": scope_cidr,
        "targets": list(targets),
        "hosts_with_findings": hosts_wf,
        "engagement_type": et,
        "started": _s(session.get("started_at")).strip() or "—",
        "completed": _s(session.get("completed_at")).strip() or "—",
        "duration": _s(ctx.get("duration")).strip() or "—",
        "generated": _s(ctx.get("generated_at")).strip() or "—",
        "overall_risk": overall_risk,
        "overall_risk_note": note,
        "access_achieved": _access_line(outcome, intel),
        "frameworks": frameworks,
    })
    return e


def _build_surface(ctx, hosts):
    findings = ctx.get("findings") if isinstance(ctx.get("findings"), list) else []
    intel = ctx.get("intel") if isinstance(ctx.get("intel"), dict) else {}
    os_by = {h.get("ip"): h.get("os", "Unknown") for h in (hosts or [])}
    host_order = [h.get("ip") for h in (hosts or []) if h.get("ip") not in ("—", None)]

    by_host = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        host = _s(f.get("host")).strip() or "unspecified"
        pv = f.get("port")
        if isinstance(pv, bool):
            continue
        if isinstance(pv, int):
            port = str(pv)
        elif isinstance(pv, str) and pv.strip().isdigit():
            port = pv.strip()
        else:
            continue
        svc = _s(f.get("service")).strip() or _s(f.get("protocol")).strip() or "service"
        proto = _s(f.get("protocol")).strip() or "tcp"
        risk = _RISK_BY_SEV.get(_norm_sev(f.get("severity")), "info")
        product = _s(f.get("title")).strip()[:90] or svc
        d = by_host.setdefault(host, {})
        cur = d.get(port)
        if cur is None or _RISK_RANK.get(risk, 0) > _RISK_RANK.get(cur["risk"], 0):
            d[port] = {"port": port, "proto": proto, "service": svc,
                       "product": product, "risk": risk}

    # intel is parent/best-effort only — attribute to the single primary host
    primary = host_order[0] if len(host_order) == 1 else None
    if primary is not None:
        svcs = intel.get("services")
        if isinstance(svcs, dict):
            for pk, meta in svcs.items():
                p = _s(pk).strip()
                if not p.isdigit():
                    continue
                d = by_host.setdefault(primary, {})
                if p not in d:
                    m = meta if isinstance(meta, dict) else {}
                    d[p] = {"port": p,
                            "proto": _s(m.get("protocol")).strip() or "tcp",
                            "service": _s(m.get("service")).strip() or "service",
                            "product": _s(m.get("version")).strip() or "Observed service",
                            "risk": "info"}
        ops = intel.get("open_ports")
        if isinstance(ops, list):
            for pv in ops:
                p = _s(pv).strip()
                if not p.isdigit():
                    continue
                d = by_host.setdefault(primary, {})
                if p not in d:
                    d[p] = {"port": p, "proto": "tcp", "service": "open port",
                            "product": "Open port (recon)", "risk": "info"}

    out, done = [], set()

    def emit(host):
        if host in done or host is None:
            return
        done.add(host)
        d = by_host.get(host, {})
        if not d:
            return
        keys = sorted(d, key=lambda x: int(x) if x.isdigit() else (1 << 30))
        out.append({"ip": host, "os": os_by.get(host, "Unknown"),
                    "services": [d[k] for k in keys]})

    for host in host_order:
        emit(host)
    for host in list(by_host):
        emit(host)
    return out


def _phase_of(it):
    p = _s(it.get("phase")).strip()
    if p:
        return p
    txt = (_s(it.get("label")) + " " + _s(it.get("result")) + " "
           + _s(it.get("technique")) + " " + _s(it.get("detail"))).lower()
    if any(k in txt for k in ("exploit", "foothold", "rce", "shell")):
        return "Exploit / Foothold"
    if any(k in txt for k in ("privesc", "privilege")):
        return "Privilege Esc"
    if any(k in txt for k in ("loot", "exfil", "post-ex", "post exploit")):
        return "Post-exploit / Loot"
    if "persist" in txt:
        return "Persistence"
    if any(k in txt for k in ("lateral", "pivot")):
        return "Lateral"
    return "Recon"


def _build_killchain(ctx):
    ap = ctx.get("attack_path")
    tl = ctx.get("engagement_timeline")
    src = ap if (isinstance(ap, list) and ap) else (tl if isinstance(tl, list) else [])
    steps = []
    n = 0
    for it in src[:40]:
        if not isinstance(it, dict):
            continue
        n += 1
        label = (_s(it.get("label")).strip() or _s(it.get("technique")).strip()
                 or _s(it.get("result")).strip() or _s(it.get("source")).strip()
                 or _s(it.get("detail")).strip() or "Step %d" % n)
        detail = (_s(it.get("detail")).strip() or _s(it.get("description")).strip()
                  or _s(it.get("result")).strip() or _s(it.get("note")).strip()
                  or _s(it.get("ts") or it.get("timestamp")).strip())
        steps.append({"n": n, "phase": _phase_of(it),
                      "label": label[:180], "detail": detail[:280]})
    return steps


def _build_mitre(f_list, ctx):
    fid_host = {f["id"]: f.get("host", "") for f in (f_list or [])}
    tech = {}

    def entry(tid):
        return tech.setdefault(tid, {"id": tid, "name": "", "tactic": "",
                                     "findings": set(), "details": []})

    mm = ctx.get("mitre_mappings")
    if isinstance(mm, list):
        for m in mm:
            if not isinstance(m, dict):
                continue
            tid = _s(m.get("technique_id") or m.get("id")).strip()
            if not tid:
                continue
            e = entry(tid)
            name = _s(m.get("technique_name") or m.get("name")).strip()
            tac = _s(m.get("tactic")).strip()
            if name and not e["name"]:
                e["name"] = name
            if tac and not e["tactic"]:
                e["tactic"] = tac
            det = _s(m.get("outcome") or m.get("result") or m.get("tool_used")
                     or m.get("tool")).strip()
            if det:
                e["details"].append(det)

    # fold in finding references (and derive techniques if no mappings existed)
    for f in (f_list or []):
        mt = f.get("mitre")
        if mt:
            entry(mt)["findings"].add(f["id"])

    result = []
    for tid, e in tech.items():
        findings = sorted(e["findings"])
        hosts = sorted({fid_host.get(x, "") for x in findings if fid_host.get(x)})
        count = len(findings) if findings else 1
        name = e["name"] or _MITRE_NAMES.get(tid, "") or tid
        detail = "; ".join(dict.fromkeys(e["details"]))[:240]
        if not detail:
            if hosts:
                detail = "Referenced by %d finding(s) on %s." % (len(findings), ", ".join(hosts[:4]))
            elif findings:
                detail = "Referenced by %d finding(s)." % len(findings)
            else:
                detail = "Mapped ATT&CK technique."
        result.append({"id": tid, "name": name, "tactic": e["tactic"] or "—",
                       "count": count, "findings": findings, "detail": detail})
    result.sort(key=lambda m: m["count"], reverse=True)
    return result


def _build_detection(f_list, ctx):
    rows, seen = [], set()
    for f in (f_list or []):
        key = (f.get("title", ""), f.get("mitre", ""), f.get("host", ""))
        if key in seen:
            continue
        seen.add(key)
        rows.append({"finding": _s(f.get("title"))[:90] or "—",
                     "tech": f.get("mitre") or "—",
                     "host": f.get("host") or "—"})
        if len(rows) >= 40:
            break
    return rows


_REMED_BUCKETS = [
    dict(key="exploit",
         title="Investigate & contain exploitable code-execution flaws",
         priority="Immediate", impact="High", effort="Medium", owner="AppSec + Host owner",
         kws=["inject", "rce", "remote code", "command exec", "command injection", "sql injection",
              "sqli", "deserial", "upload", "travers", "ssrf", "xxe", "lfi", "rfi", "webshell",
              " shell", "foothold", "exploit", "arbitrary code", "arbitrary command"],
         summary="Highest-potential-impact issues: confirmed or indicated code execution / injection. "
                 "Verify exploitability, contain affected hosts, remove unsafe input handling and "
                 "deploy interim virtual patches while permanent fixes are developed."),
    dict(key="authz",
         title="Remediate broken access control (IDOR / BOLA / auth bypass)",
         priority="Immediate", impact="High", effort="Medium", owner="Application teams",
         kws=["idor", "bola", "broken object", "broken access", "access control", "authoriz",
              "authorisation", "privilege", "unauthor", "auth bypass", "insecure direct", "bypass"],
         summary="Enforce deny-by-default, per-request object-level authorization across the affected "
                 "applications; adopt unguessable identifiers and validate every access decision "
                 "server-side."),
    dict(key="generic_high",
         title="Remediate remaining high-severity findings",
         priority="Immediate", impact="High", effort="Medium", owner="Security team",
         kws=[],
         summary="High-severity findings requiring prompt remediation. Prioritise by exploitability and "
                 "exposure, and track each to closure with a retest."),
    dict(key="cleartext",
         title="Eliminate cleartext & weak remote-access protocols",
         priority="High", impact="High", effort="Low", owner="Infrastructure / Sysadmins",
         kws=["cleartext", "clear text", "telnet", "rexec", "rlogin", " rsh", "r-service", "ftp",
              "plaintext", "plain text", "rdp", "nla", "weak encryption", "weak cipher", "smbv1",
              "smb signing", "sslv", "protocol expose", "network sniff", "downgrade"],
         summary="Disable cleartext and legacy remote-access services (Telnet, r-services, FTP) and "
                 "weakly-configured RDP/TLS. Move administration to hardened, encrypted channels and "
                 "restrict to jump hosts / VPN. Low effort, high risk reduction."),
    dict(key="headers",
         title="Deploy a baseline HTTP security-header standard",
         priority="High", impact="Medium", effort="Low", owner="Platform / Web ops",
         kws=["header", "content-security", "csp", "hsts", "strict-transport", "x-frame",
              "x-content-type", "referrer-policy", "permissions-policy", "cookie", "clickjack",
              "mime", "x-xss"],
         summary="Standardise CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and "
                 "Permissions-Policy at the web/proxy tier and validate in CI. A single control "
                 "delivers broad coverage across endpoints."),
    dict(key="surface",
         title="Harden exposed management, IoT & data services",
         priority="Medium", impact="Medium", effort="Medium", owner="Infrastructure / Device owners",
         kws=["open port", "disclosure", "banner", "server header", "active directory", " smb",
              "database", "mssql", "mysql", "postgres", "mongo", "redis", "rtsp", "camera",
              "hikvision", "fingerprint", "service detected", "iot", "exposed"],
         summary="Segment and restrict exposed management interfaces, IoT/camera stacks, directory and "
                 "database services to trusted networks. Change default credentials, enforce "
                 "authentication and confirm firmware/patch levels."),
    dict(key="generic_med",
         title="Address medium-severity weaknesses",
         priority="Medium", impact="Medium", effort="Medium", owner="System owners",
         kws=[],
         summary="Medium-severity weaknesses that are chainable or increase blast radius. Schedule "
                 "remediation within the normal maintenance cycle and retest."),
    dict(key="coverage",
         title="Close low-risk & coverage items",
         priority="Low", impact="Low", effort="Low", owner="IT operations",
         kws=[],
         summary="Informational, recon and coverage-only observations plus low-risk hygiene items. "
                 "Confirm availability where probes failed, then re-test to close coverage gaps. "
                 "No urgent action required."),
]


def _remed_bucket_key(f):
    hay = (_s(f.get("title")) + " " + _s(f.get("cat")) + " " + _s(f.get("desc"))).lower()
    for b in _REMED_BUCKETS:
        if b["kws"] and any(k in hay for k in b["kws"]):
            return b["key"]
    sev = f.get("sev")
    if sev in ("Critical", "High"):
        return "generic_high"
    if sev == "Medium":
        return "generic_med"
    return "coverage"


def _build_remediation(f_list):
    if not f_list:
        return []
    grouped = {}
    for f in f_list:
        grouped.setdefault(_remed_bucket_key(f), []).append(f)
    out = []
    n = 0
    for b in _REMED_BUCKETS:
        fs = grouped.get(b["key"])
        if not fs:
            continue
        n += 1
        cats = list(dict.fromkeys(_s(f.get("cat")).strip() for f in fs if _s(f.get("cat")).strip()))
        out.append({
            "rank": "P%d" % n, "title": b["title"], "priority": b["priority"],
            "impact": b["impact"], "effort": b["effort"], "owner": b["owner"],
            "findings": [f["id"] for f in fs], "summary": b["summary"],
            "cats": cats,
        })
    return out


def _normalize_invariants():
    """Final guard: repair anything that could make the builder KeyError/crash."""
    global SEVERITY_COUNTS, HOSTS, ENGAGEMENT, TOTAL_FINDINGS, HOST_NO_DATA
    if not isinstance(SEVERITY_COUNTS, dict):
        SEVERITY_COUNTS = _empty_counts()
    else:
        for k in _SEV_KEYS:
            try:
                SEVERITY_COUNTS[k] = int(SEVERITY_COUNTS.get(k, 0) or 0)
            except Exception:
                SEVERITY_COUNTS[k] = 0

    if not isinstance(HOSTS, list) or not HOSTS:
        HOSTS = [_placeholder_host()]
    else:
        for h in HOSTS:
            if not isinstance(h, dict):
                continue
            c = h.get("counts")
            if not isinstance(c, dict):
                h["counts"] = _empty_counts()
            else:
                for k in _SEV_KEYS:
                    try:
                        c[k] = int(c.get(k, 0) or 0)
                    except Exception:
                        c[k] = 0
            try:
                h["total"] = int(h.get("total", 0) or 0)
            except Exception:
                h["total"] = 0

    if not isinstance(TOTAL_FINDINGS, int):
        try:
            TOTAL_FINDINGS = int(TOTAL_FINDINGS)
        except Exception:
            TOTAL_FINDINGS = 0

    if not isinstance(HOST_NO_DATA, str) or not HOST_NO_DATA:
        HOST_NO_DATA = "—"

    if not isinstance(ENGAGEMENT, dict):
        ENGAGEMENT = _default_engagement()
    else:
        base = _default_engagement()
        for k, v in base.items():
            ENGAGEMENT.setdefault(k, v)
        # gauge-safe overall_risk (charts.risk_gauge only knows the 5 canon levels)
        if ENGAGEMENT.get("overall_risk") not in _SEV_KEYS:
            ENGAGEMENT["overall_risk"] = _RATING_TO_RISK.get(
                _s(ENGAGEMENT.get("overall_risk")).strip().lower(), "Info")
        if not isinstance(ENGAGEMENT.get("targets"), list):
            ENGAGEMENT["targets"] = []
        if not isinstance(ENGAGEMENT.get("frameworks"), list):
            ENGAGEMENT["frameworks"] = base["frameworks"]


# --------------------------------------------------------------------------- #
#  Extended data-type builders (each pure + guarded)
# --------------------------------------------------------------------------- #

def _num(v, d=0):
    try:
        if isinstance(v, bool):
            return d
        if isinstance(v, (int, float)):
            return v
        s = _s(v).strip()
        return float(s) if s else d
    except Exception:
        return d


def _slist(v, limit=None, lower=False):
    """List of non-empty stripped strings from any iterable-ish value."""
    if not isinstance(v, (list, tuple)):
        return []
    out = []
    for x in v:
        sx = _s(x).strip()
        if not sx:
            continue
        out.append(sx.lower() if lower else sx)
        if limit and len(out) >= limit:
            break
    return out


def _build_compromise(ctx):
    ce = ctx.get("compromise_evidence")
    if not isinstance(ce, dict) or not ce.get("claimed"):
        return {}
    return {
        "claimed": True,
        "proven": bool(ce.get("proven")),
        "level": _s(ce.get("level")).strip() or "foothold",
        "basis": _s(ce.get("basis")).strip(),
        "proof_items": _slist(ce.get("proof_items"), limit=12),
        "method_steps": _slist(ce.get("method_steps"), limit=14),
        "no_artifact_reason": _s(ce.get("no_artifact_reason")).strip(),
    }


def _build_creds(ctx):
    src = ctx.get("creds_summary")
    if not isinstance(src, list):
        return []
    out = []
    for r in src[:300]:
        if not isinstance(r, dict):
            continue
        out.append({
            "user": _s(r.get("user")).strip() or "—",
            "domain": _s(r.get("domain")).strip(),
            "password": _s(r.get("password")).strip() or "—",
            "source": _s(r.get("source")).strip() or "—",
            "note": _s(r.get("note")).strip(),
        })
    return out


def _build_loot(ctx):
    entries = []
    src = ctx.get("loot_entries")
    if isinstance(src, list):
        for e in src[:300]:
            if not isinstance(e, dict):
                continue
            entries.append({
                "severity": _norm_sev(e.get("severity")),
                "doi_id": _s(e.get("doi_id")).strip(),
                "doi_label": (_s(e.get("doi_label")).strip()
                              or _s(e.get("doi_id")).strip() or "—"),
                "source": _s(e.get("source")).strip() or "—",
                "target": _s(e.get("target")).strip() or "—",
                "size_bytes": int(_num(e.get("size_bytes"), 0)),
                "sha256": _s(e.get("sha256")).strip(),
            })
    summary = {}
    summ = ctx.get("loot_summary")
    if isinstance(summ, dict):
        for k, v in summ.items():
            ks = _s(k).strip()
            if ks:
                summary[ks] = int(_num(v, 0))
    return entries, summary


def _build_flags(ctx):
    src = ctx.get("flags")
    if not isinstance(src, list):
        return []
    out = []
    for r in src[:100]:
        if not isinstance(r, dict):
            continue
        out.append({
            "flag_type": _s(r.get("flag_type")).strip() or "flag",
            "value": _s(r.get("value")).strip(),
            "location": _s(r.get("location")).strip(),
            "found_by": _s(r.get("found_by")).strip(),
            "host": _s(r.get("host")).strip(),
        })
    return out


def _build_ai_security(ctx):
    ai = ctx.get("ai_security")
    if not isinstance(ai, dict) or not ai.get("count"):
        return {}
    findings = []
    for f in (ai.get("findings") if isinstance(ai.get("findings"), list) else [])[:100]:
        if not isinstance(f, dict):
            continue
        findings.append({
            "title": _s(f.get("title")).strip() or "AI finding",
            "sev": _norm_sev(f.get("severity")),
            "aivss": _num(f.get("aivss"), 0),
            "cvss": _num(f.get("cvss"), 0),
            "asr": int(_num(f.get("asr"), 0)),
            "owasp_llm": _s(f.get("owasp_llm")).strip(),
            "atlas": _s(f.get("atlas")).strip(),
        })
    return {
        "count": int(_num(ai.get("count"), len(findings))),
        "max_aivss": _num(ai.get("max_aivss"), 0),
        "avg_asr": int(_num(ai.get("avg_asr"), 0)),
        "owasp_classes": _slist(ai.get("owasp_classes")),
        "findings": findings,
    }


def _build_coverage(ctx):
    tests = []
    src = ctx.get("coverage_tests")
    if isinstance(src, list):
        for t in src[:200]:
            if not isinstance(t, dict):
                continue
            tests.append({
                "tool": _s(t.get("tool")).strip() or "—",
                "target": _s(t.get("target")).strip() or "—",
                "command": _s(t.get("command")).strip(),
                "outcome": _s(t.get("outcome")).strip().lower() or "—",
                "note": _s(t.get("note")).strip(),
            })
    counts = {}
    cc = ctx.get("coverage_counts")
    if isinstance(cc, dict):
        for k, v in cc.items():
            ks = _s(k).strip().lower()
            if ks:
                counts[ks] = int(_num(v, 0))
    if not counts and tests:
        for t in tests:
            counts[t["outcome"]] = counts.get(t["outcome"], 0) + 1
    return tests, counts


def _build_objectives(ctx):
    src = ctx.get("objectives")
    if not isinstance(src, list):
        return [], 0, 0
    out = []
    for o in src[:200]:
        if not isinstance(o, dict):
            continue
        idx = o.get("index")
        out.append({
            "index": int(idx) if isinstance(idx, int) and not isinstance(idx, bool) else len(out) + 1,
            "question": _s(o.get("question")).strip() or "—",
            "section": _s(o.get("section")).strip(),
            "answer": _s(o.get("answer")).strip(),
            "tool": _s(o.get("tool")).strip(),
            "answered": bool(o.get("answered")),
        })
    done = sum(1 for o in out if o["answered"])
    return out, done, len(out)


def _build_mission(ctx):
    mb0 = ctx.get("mission_brief") if isinstance(ctx.get("mission_brief"), dict) else {}
    mb = {}
    if mb0:
        mb = {
            "objective": _s(mb0.get("objective")).strip(),
            "win_conditions": _slist(mb0.get("win_conditions")),
            "scope_in": _slist(mb0.get("scope_in")),
            "scope_out": _slist(mb0.get("scope_out")),
            "time_budget_min": int(_num(mb0.get("time_budget_min"), 0)),
            "noise_budget": int(_num(mb0.get("noise_budget"), 0)),
            "blast_radius": _s(mb0.get("blast_radius")).strip(),
            "notes": _s(mb0.get("notes")).strip(),
        }
    wc0 = ctx.get("win_conditions") if isinstance(ctx.get("win_conditions"), dict) else {}
    conditions = []
    for c in (wc0.get("conditions") if isinstance(wc0.get("conditions"), list) else []):
        if not isinstance(c, dict):
            continue
        conditions.append({
            "name": _s(c.get("name")).strip() or "—",
            "achieved": bool(c.get("achieved")),
            "evidence": _s(c.get("evidence")).strip(),
        })
    wc = {}
    if conditions:
        wc = {
            "conditions": conditions,
            "achieved_count": int(_num(wc0.get("achieved_count"),
                                       sum(1 for c in conditions if c["achieved"]))),
            "total": int(_num(wc0.get("total"), len(conditions))),
            "progress_pct": int(_num(wc0.get("progress_pct"), 0)),
        }
    session = ctx.get("session") if isinstance(ctx.get("session"), dict) else {}
    autonomy = _s(session.get("autonomy")).strip()
    return mb, wc, autonomy


def _build_exploit_modules(ctx):
    src = ctx.get("exploit_modules")
    if not isinstance(src, list):
        return []
    out = []
    for e in src[:25]:
        if isinstance(e, dict):
            cv = e.get("cves")
            cves = _slist(cv) if isinstance(cv, (list, tuple)) else (
                [_s(cv).strip()] if _s(cv).strip() else [])
            out.append({
                "cves": cves,
                "product": _s(e.get("product")).strip(),
                "title": _s(e.get("title")).strip(),
                "type": _s(e.get("type")).strip(),
                "url": _s(e.get("url")).strip(),
                "path": _s(e.get("path")).strip(),
                "used": bool(e.get("used") or e.get("selected")),
            })
        else:
            s = _s(e).strip()
            if not s:
                continue
            is_url = s.lower().startswith("http")
            out.append({
                "cves": [], "product": "", "title": s, "type": "",
                "url": s if is_url else "", "path": "" if is_url else s, "used": False,
            })
    return out


def _build_journal(ctx):
    src = ctx.get("reasoning_journal")
    if not isinstance(src, list):
        return [], False, 0
    items = _slist(src, limit=60)
    trunc = bool(ctx.get("journal_truncated"))
    jt = ctx.get("journal_total")
    total = int(jt) if isinstance(jt, int) and not isinstance(jt, bool) else len(items)
    return items, trunc, total


def _build_web_intel(ctx):
    src = ctx.get("web_intel_hints")
    if not isinstance(src, list):
        return []
    out = []
    for h in src[:60]:
        if not isinstance(h, dict):
            continue
        out.append({
            "confidence": _num(h.get("confidence"), 0),
            "tool": _s(h.get("tool")).strip(),
            "cve": _s(h.get("cve")).strip(),
            "mitre": _s(h.get("mitre")).strip(),
            "description": _s(h.get("description")).strip(),
            "source_url": _s(h.get("source_url")).strip(),
        })
    return out


def _build_discovered(ctx):
    src = ctx.get("discovered_issues")
    if not isinstance(src, list):
        return []
    out = []
    for d in src[:120]:
        if not isinstance(d, dict):
            continue
        out.append({
            "title": _s(d.get("title")).strip() or "—",
            "sev": _norm_sev(d.get("severity")),
            "tool": _s(d.get("tool")).strip(),
            "status": _s(d.get("status")).strip() or "observed",
            "host": _s(d.get("host")).strip(),
        })
    return out


def _build_primer(ctx):
    src = ctx.get("primer_rows")
    if not isinstance(src, list):
        return []
    out = []
    for r in src[:80]:
        if not isinstance(r, dict):
            continue
        out.append({
            "chain": _s(r.get("chain")).strip() or "—",
            "present": int(_num(r.get("present"), 0)),
            "total": int(_num(r.get("total"), 0)),
            "missing": _s(r.get("missing")).strip() or "—",
            "coverage": int(_num(r.get("coverage"), 0)),
            "status": _s(r.get("status")).strip().upper() or "OK",
        })
    return out


def _build_attack_path(ctx):
    src = ctx.get("attack_path")
    if not isinstance(src, list):
        return []
    out = []
    for i, s in enumerate(src[:60], 1):
        if not isinstance(s, dict):
            continue
        step = s.get("__step")
        result = (_s(s.get("result")).strip() or _s(s.get("description")).strip()
                  or _s(s.get("note")).strip() or _s(s.get("technique")).strip() or "—")
        out.append({
            "step": int(step) if isinstance(step, int) and not isinstance(step, bool) else i,
            "phase": _s(s.get("phase")).strip() or "—",
            "result": result[:220],
            "source": _s(s.get("source")).strip(),
            "ts": _s(s.get("ts") or s.get("timestamp")).strip(),
        })
    return out


def _build_timeline(ctx):
    src = ctx.get("engagement_timeline")
    if not isinstance(src, list):
        return []
    out = []
    for t in src[:60]:
        if not isinstance(t, dict):
            continue
        ts = _s(t.get("ts")).strip()
        if not ts:
            continue
        out.append({
            "ts": ts,
            "label": _s(t.get("label")).strip() or "—",
            "detail": _s(t.get("detail")).strip()[:160],
        })
    return out


def _build_tools(ctx):
    tu = ctx.get("tools_used")
    if isinstance(tu, list) and tu:
        return sorted({s for s in (_s(x).strip() for x in tu) if s})
    ct = ctx.get("coverage_tests")
    if isinstance(ct, list):
        return sorted({s for s in (_s(t.get("tool")).strip()
                                   for t in ct if isinstance(t, dict)) if s})
    return []


def _build_phases(ctx):
    session = ctx.get("session") if isinstance(ctx.get("session"), dict) else {}
    pc = session.get("phases_completed")
    if not isinstance(pc, list):
        pc = ctx.get("phases_completed")
    return _slist(pc, lower=True) if isinstance(pc, list) else []


def _build_observability(ctx):
    o = ctx.get("observability")
    if not isinstance(o, dict):
        return {}
    tt = int(_num(o.get("total_tokens"), 0))
    inv = int(_num(o.get("total_invocations"), 0))
    if not tt and not inv:
        return {}
    per = {}
    src = o.get("invocations_per_tool")
    if isinstance(src, dict):
        for k, v in src.items():
            ks = _s(k).strip()
            if ks:
                per[ks] = int(_num(v, 0))
    return {
        "total_tokens": tt,
        "prompt_tokens": int(_num(o.get("prompt_tokens"), 0)),
        "completion_tokens": int(_num(o.get("completion_tokens"), 0)),
        "tokens_estimated": bool(o.get("tokens_estimated")),
        "total_invocations": inv,
        "invocations_per_tool": per,
    }


# --------------------------------------------------------------------------- #
#  Public entry point
# --------------------------------------------------------------------------- #

def apply(ctx):
    """Re-populate every module-level name from a live ARGUS ``_build_context``
    dict.  Never raises; on any per-section failure that section keeps its safe
    default."""
    global ENGAGEMENT, SEVERITY_ORDER, SEVERITY_COUNTS, TOTAL_FINDINGS, HOSTS
    global HOST_NO_DATA, F, ATTACK_SURFACE, KILL_CHAIN, KILL_CHAIN_PHASES
    global MITRE, DETECTION, REMEDIATION, CVSS_BANDS, METHODOLOGY
    global COMPROMISE_EVIDENCE, CREDS_SUMMARY, LOOT_ENTRIES, LOOT_SUMMARY, FLAGS
    global AI_SECURITY, COVERAGE_TESTS, COVERAGE_COUNTS, OBJECTIVES, OBJECTIVES_DONE
    global OBJECTIVES_TOTAL, MISSION_BRIEF, WIN_CONDITIONS, AUTONOMY, EXPLOIT_MODULES
    global REASONING_JOURNAL, JOURNAL_TRUNCATED, JOURNAL_TOTAL, WEB_INTEL_HINTS
    global DISCOVERED_ISSUES, PRIMER_ROWS, ATTACK_PATH, ENGAGEMENT_TIMELINE
    global TOOLS_USED, PHASES_COMPLETED, ALL_PHASES, OBSERVABILITY

    if not isinstance(ctx, dict):
        ctx = {}

    # constant-shaped names — restore canonical values (idempotent)
    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
    KILL_CHAIN_PHASES = ["Recon", "Exploit / Foothold", "Privilege Esc",
                         "Post-exploit / Loot", "Persistence", "Lateral"]
    CVSS_BANDS = _default_cvss_bands()
    METHODOLOGY = _default_methodology()

    # data-driven names
    f_list = _safe(_build_findings, ctx, default=[]) or []
    F = f_list
    SEVERITY_COUNTS = _safe(_counts_from_findings, F, default=_empty_counts()) or _empty_counts()
    TOTAL_FINDINGS = len(F)

    hosts = _safe(_build_hosts, F, ctx, default=None)
    HOSTS = hosts if (isinstance(hosts, list) and hosts) else [_placeholder_host()]

    tg = _safe(_build_targets, HOSTS, F, ctx, default=([], "—")) or ([], "—")
    try:
        targets, HOST_NO_DATA = tg
    except Exception:
        targets, HOST_NO_DATA = [], "—"

    ENGAGEMENT = _safe(_build_engagement, ctx, targets, TOTAL_FINDINGS, HOSTS,
                       default=_default_engagement()) or _default_engagement()
    ATTACK_SURFACE = _safe(_build_surface, ctx, HOSTS, default=[]) or []
    KILL_CHAIN = _safe(_build_killchain, ctx, default=[]) or []
    MITRE = _safe(_build_mitre, F, ctx, default=[]) or []
    DETECTION = _safe(_build_detection, F, ctx, default=[]) or []
    REMEDIATION = _safe(_build_remediation, F, default=[]) or []

    # ---- extended ARGUS data types (all empty-safe on absence/failure) ----
    ALL_PHASES = ["recon", "scan", "vuln_id", "osint", "exploit", "post_exploit",
                  "privesc", "persistence", "lateral", "wireless", "iot", "reporting"]

    COMPROMISE_EVIDENCE = _safe(_build_compromise, ctx, default={}) or {}
    CREDS_SUMMARY = _safe(_build_creds, ctx, default=[]) or []

    _loot = _safe(_build_loot, ctx, default=([], {})) or ([], {})
    try:
        LOOT_ENTRIES, LOOT_SUMMARY = _loot
    except Exception:
        LOOT_ENTRIES, LOOT_SUMMARY = [], {}

    FLAGS = _safe(_build_flags, ctx, default=[]) or []
    AI_SECURITY = _safe(_build_ai_security, ctx, default={}) or {}

    _cov = _safe(_build_coverage, ctx, default=([], {})) or ([], {})
    try:
        COVERAGE_TESTS, COVERAGE_COUNTS = _cov
    except Exception:
        COVERAGE_TESTS, COVERAGE_COUNTS = [], {}

    _obj = _safe(_build_objectives, ctx, default=([], 0, 0)) or ([], 0, 0)
    try:
        OBJECTIVES, OBJECTIVES_DONE, OBJECTIVES_TOTAL = _obj
    except Exception:
        OBJECTIVES, OBJECTIVES_DONE, OBJECTIVES_TOTAL = [], 0, 0

    _mis = _safe(_build_mission, ctx, default=({}, {}, "")) or ({}, {}, "")
    try:
        MISSION_BRIEF, WIN_CONDITIONS, AUTONOMY = _mis
    except Exception:
        MISSION_BRIEF, WIN_CONDITIONS, AUTONOMY = {}, {}, ""

    EXPLOIT_MODULES = _safe(_build_exploit_modules, ctx, default=[]) or []

    _jr = _safe(_build_journal, ctx, default=([], False, 0)) or ([], False, 0)
    try:
        REASONING_JOURNAL, JOURNAL_TRUNCATED, JOURNAL_TOTAL = _jr
    except Exception:
        REASONING_JOURNAL, JOURNAL_TRUNCATED, JOURNAL_TOTAL = [], False, 0

    WEB_INTEL_HINTS = _safe(_build_web_intel, ctx, default=[]) or []
    DISCOVERED_ISSUES = _safe(_build_discovered, ctx, default=[]) or []
    PRIMER_ROWS = _safe(_build_primer, ctx, default=[]) or []
    ATTACK_PATH = _safe(_build_attack_path, ctx, default=[]) or []
    ENGAGEMENT_TIMELINE = _safe(_build_timeline, ctx, default=[]) or []
    TOOLS_USED = _safe(_build_tools, ctx, default=[]) or []
    PHASES_COMPLETED = _safe(_build_phases, ctx, default=[]) or []
    OBSERVABILITY = _safe(_build_observability, ctx, default={}) or {}

    try:
        _normalize_invariants()
    except Exception:
        pass
