"""knowledge/severity_policy.py — the single source of truth for finding severity.

ARGUS grades a finding by what it OPERATIONALLY demonstrated or assessed (the
red-team convention), not by a raw CVSS number.  This module is a pure,
dependency-free policy so severity is consistent run-to-run and testable in
isolation.  CVSS is computed elsewhere and kept only as a reference score; it
never drives the headline severity.

The rubric (top-down, first match wins — a finding lands at the HIGHEST tier its
evidence justifies):

  CRITICAL  ARGUS demonstrated COMPROMISE — root/admin or domain-admin — OR an
            equivalent catastrophic demonstrated impact: full unauthenticated
            data exfiltration (total_data) or control of an OT/safety system
            (ot_control).
  HIGH      A public exploit is available for a CONFIRMED product+version (run or
            not), OR a demonstrated partial / non-root foothold, OR a confirmed
            DIRECTLY-exploitable weakness (no public exploit needed) that is not
            catastrophic.  Definite risk, high chaining probability.
  MEDIUM    A confirmed weakness with NO applicable public exploit and not
            directly exploitable alone, but CHAINABLE with other vulns/misconfigs.
            (Also: a public exploit exists but the vulnerable version is
            unconfirmed — we do not inflate on guesswork.)
  LOW       A confirmed minor issue / information leak — not directly exploitable,
            weak/remote chaining value, useful mainly for recon.
  INFO      Bare detection / harmless information — attack surface, not
            exploitable.  (inherent_risk metadata still drives prioritisation.)

`grade(signals)` returns {severity, rationale, evidence_tag, factors}.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Ordered severity ladder (low → high) for comparisons / monotonic re-grade.
SEVERITY_ORDER: List[str] = ["info", "low", "medium", "high", "critical"]

# Compromise ladder (none → strongest).  The last four are CRITICAL-class
# outcomes (demonstrated full compromise or catastrophic impact); foothold /
# user_rce are partial (HIGH-class).
COMPROMISE_ORDER: List[str] = [
    "none", "foothold", "user_rce",
    "root_admin", "domain_admin", "total_data", "ot_control",
]
_CRITICAL_COMPROMISE = {"root_admin", "domain_admin", "total_data", "ot_control"}
_PARTIAL_COMPROMISE  = {"foothold", "user_rce"}

# Evidence tags — replace the misleading blanket "VERIFIED" badge with an honest
# statement of WHAT was established.
TAG_DEMONSTRATED = "DEMONSTRATED"   # compromise / impact actually achieved
TAG_PUBLIC_EXPLOIT = "PUBLIC-EXPLOIT"  # applicable public exploit exists
TAG_CONFIRMED = "CONFIRMED"         # weakness proven by a probe
TAG_OBSERVED  = "OBSERVED"          # detection / information only


def _sev_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(str(sev).lower())
    except ValueError:
        return 0


def _compromise_rank(level: str) -> int:
    try:
        return COMPROMISE_ORDER.index(str(level or "none").lower())
    except ValueError:
        return 0


def _b(signals: Dict[str, Any], key: str, default: bool = False) -> bool:
    v = signals.get(key, default)
    return bool(v)


def grade(signals: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the operational severity for a finding from its evidence signals.

    See the module docstring for the rubric.  Pure + deterministic: the same
    signals always yield the same verdict.
    """
    s = signals or {}
    compromise = str(s.get("compromise", "none") or "none").lower()
    factors: List[str] = []

    def verdict(sev: str, rationale: str, tag: str) -> Dict[str, Any]:
        return {"severity": sev, "rationale": rationale,
                "evidence_tag": tag, "factors": list(factors)}

    # ── CRITICAL — demonstrated compromise or equivalent catastrophic impact ──
    if compromise in _CRITICAL_COMPROMISE:
        factors.append(f"compromise={compromise}")
        _why = {
            "root_admin":   "root/administrator access obtained on the host",
            "domain_admin": "domain-administrator access obtained",
            "total_data":   "full unauthenticated data exfiltration demonstrated",
            "ot_control":   "control of an OT/safety system demonstrated",
        }[compromise]
        return verdict("critical", f"ARGUS compromised the target — {_why}.",
                       TAG_DEMONSTRATED)

    # ── HIGH — partial foothold, applicable public exploit, or directly-exploitable ──
    if compromise in _PARTIAL_COMPROMISE:
        factors.append(f"compromise={compromise}")
        _why = ("an interactive non-root foothold (low-privilege shell)"
                if compromise == "foothold" else "user-level code execution")
        return verdict("high", f"ARGUS demonstrated {_why} — partial compromise, "
                               "privilege escalation likely chains to full control.",
                       TAG_DEMONSTRATED)

    confirmed   = _b(s, "confirmed")
    exploit_avl = _b(s, "exploit_available")
    version_ok  = _b(s, "version_confirmed", True)
    direct      = _b(s, "directly_exploitable")
    chainable   = _b(s, "chainable")

    if exploit_avl and confirmed and version_ok:
        factors.append("exploit_available+version_confirmed")
        return verdict("high", "A public exploit is available for the confirmed "
                               "product/version — definite risk whether or not it was run.",
                       TAG_PUBLIC_EXPLOIT)

    if confirmed and direct:
        factors.append("directly_exploitable")
        return verdict("high", "Confirmed directly-exploitable weakness (no public "
                               "exploit required) — a definite standalone risk.",
                       TAG_CONFIRMED)

    # ── MEDIUM — confirmed + chainable (no applicable public exploit) ──
    if exploit_avl and not version_ok:
        factors.append("exploit_available+version_unconfirmed")
        return verdict("medium", "A public exploit exists for the product, but the "
                                 "vulnerable version could not be confirmed — chainable risk.",
                       TAG_PUBLIC_EXPLOIT)

    if confirmed and chainable:
        factors.append("confirmed+chainable")
        return verdict("medium", "Confirmed weakness with no applicable public exploit, "
                                 "but a high chance of chaining with other issues.",
                       TAG_CONFIRMED)

    # ── LOW — confirmed minor / info-leak, weak chaining, recon value ──
    if _b(s, "info_leak_only") or (confirmed and not _b(s, "detection_only")):
        factors.append("info_leak_or_minor_confirmed")
        return verdict("low", "Not directly exploitable; leaks information useful for "
                              "recon or has only a remote chaining possibility.",
                       TAG_CONFIRMED)

    # ── INFO — bare detection / harmless information ──
    factors.append("detection_only" if _b(s, "detection_only") else "informational")
    return verdict("info", "Attack-surface observation — present but not exploitable "
                          "on its own.", TAG_OBSERVED)


def merge_signals(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Additively merge evidence for a re-grade.  Booleans OR together; the
    compromise level takes the STRONGER of the two; other scalars prefer the new
    value when provided.  Used so a finding escalates as evidence accrues."""
    out = dict(old or {})
    for k, v in (new or {}).items():
        if k == "compromise":
            if _compromise_rank(v) > _compromise_rank(out.get("compromise", "none")):
                out["compromise"] = v
        elif isinstance(v, bool):
            out[k] = bool(out.get(k, False)) or v
        elif v is not None:
            out[k] = v
    return out


def is_escalation(old_sev: str, new_sev: str) -> bool:
    """True if new_sev is strictly higher than old_sev on the severity ladder."""
    return _sev_rank(new_sev) > _sev_rank(old_sev)


# ════════════════════════════════════════════════════════════════════════════
# Report-time normalization — the SINGLE source of truth applied to every finding
# before it is rendered, so a report never inflates severity or shows tool noise.
# Render-only: the DB is never mutated; the autonomous flow is untouched.
# ════════════════════════════════════════════════════════════════════════════
import re as _re   # noqa: E402

# A "finding" that is actually raw tool output, an internal ARGUS diagnostic, or a
# malformed record — these must NEVER reach a client report.  Kept tight (high
# precision) so a real finding is never dropped.
_NOISE_RE = _re.compile(
    r"\[stderr\]|^\s*\[?stderr\b|searchsploit\s*:\s*no exploits found|no exploits found for|"
    r"starting searchsploit|searchsploit\s+-j|--exclude=|^\s*e\.g\.\b|"
    r"exploit attempted\s*[—-]\s*$|operator core unavailable|legacy fallback engaged|"
    r"scan terminated:|host\(s\) tested|multiple index files found|"
    r"\{\s*['\"]cve['\"]\s*:|public exploit:\s*\[stderr\]|public exploit:\s*starting", _re.I)

# NEGATIVE / operational RESULT records ("we tried X and found nothing / did a benign
# op") that some subagents wrongly emit as findings — belong in coverage/logs, not the
# client report.  High-precision phrasings taken from the real producers.
_NEGATIVE_RE = _re.compile(
    r"all targets have smb signing|\bsmb signing (is )?enabled\b|no service accounts found|"
    r"no exploits found|\bexploit attempted\b|endpoint probed \(no|no confirmed webshell|"
    r"adjacent host\(s\) discovered|cached tickets found in credential store|"
    r"via enum4linux(-ng)?\s*$|no (kerberoastable|asrep|vulnerable) .*(found|accounts)", _re.I)

# Malformed title = a severity/label prefix followed by a bare number (an IP split at
# its first octet, e.g. "CRITICAL: 192", "Target 192", "Host 192").
_MALFORMED_TITLE_RE = _re.compile(
    r"^(critical|high|medium|low|info|target|host)\s*:?\s*\d+\s*$", _re.I)

# Bare attack-surface DETECTION (no exploitation) → INFO.
_DETECTION_RE = _re.compile(
    r"\bdetected\b|server disclosure|version disclosure|service / framework version|"
    r"os fingerprint|open port\b|\bbanner\b|appears to be outdated|wildcard dns|"
    r"\bvhost(s)?\b|virtual host|subdomain|web director(y|ies)|hidden vhost|"
    r"access-controlled surface|index files", _re.I)

# Hygiene / information-leak → LOW (still confirmed, just not directly exploitable).
_INFO_LEAK_RE = _re.compile(
    r"missing (security )?header|missing hsts|information disclosure|phpinfo|"
    r"verbose error|directory listing|x-powered-by|strict-transport", _re.I)

# An injection / RCE CLAIM whose proof must be checked before it can be CRITICAL.
_UNPROVEN_RCE_RE = _re.compile(
    r"\brce\b|remote code execution|command injection|\bcmdi\b|sql injection|\bsqli\b|"
    r"\bssrf\b|\bidor\b|\bbola\b|\bxxe\b|deserciali[sz]ation|deserciali|template injection|\bssti\b", _re.I)

_REPRO_PROVEN = {"reproduced", "confirmed", "demonstrated", "verified"}
_REPRO_UNPROVEN = {"", "na", "n/a", "none", "unreproduced", "unverified", "pending", "attempted"}


def _norm_sev(sev: Any) -> str:
    s = str(sev or "").lower().replace("findingseverity.", "").strip()
    return s if s in SEVERITY_ORDER else ("info" if not s else s)


def is_noise(finding: Dict[str, Any]) -> "tuple[bool, str]":
    """True (+reason) when a stored 'finding' is raw tool output / an internal ARGUS
    diagnostic / a malformed record that must not appear as a client-facing finding."""
    f = finding or {}
    title = str(f.get("title") or "")
    low = title.lower()
    if _NOISE_RE.search(title):
        return True, "raw tool output / internal diagnostic — not a security finding"
    if _MALFORMED_TITLE_RE.match(title.strip()):
        return True, "malformed title (label + bare number — an IP split at its first octet)"
    if _NEGATIVE_RE.search(low):
        return True, "negative / operational result (tried X, found nothing) — coverage, not a finding"
    if "operator core unavailable" in low or "legacy fallback" in low:
        return True, "internal ARGUS status message — not a target finding"
    if low.startswith(("public exploit: [stderr]", "public exploit: starting",
                       "searchsploit:", "metasploit: exploit attempted")):
        return True, "tool invocation log line — not a security finding"
    return False, ""


def _has_validated_cve(finding: Dict[str, Any]) -> bool:
    """A real CVE id is attached (so a critical CVE keeps its weight — founder policy)."""
    cves = finding.get("cves") or []
    for c in cves:
        cid = c.get("cve") if isinstance(c, dict) else c
        if cid and _re.match(r"cve-\d{4}-\d+", str(cid), _re.I):
            return True
    return False


# ── Evidence-contradicts-claim detection ─────────────────────────────────────
# A finding whose TITLE asserts a positive result but whose EVIDENCE shows the tool
# FAILED / found nothing is a FALSE POSITIVE (e.g. "Kerberos: Cached Tickets Found"
# with evidence "[EXIT 1] klist: No credentials cache found").  These illogical records
# must never reach a client report.  Kept high-precision: fires only when a positive
# claim meets a clear failure signal AND there is no positive-proof token.
_CLAIM_POSITIVE_RE = _re.compile(
    r"\b(found|obtained|captured|exposed|detected|discovered|successful?|vulnerable|"
    r"compromis\w*|leaked?|readable|writable|accessible|enabled|recovered|cracked|"
    r"dumped|extracted|granted|bypassed|achieved|present in)\b", _re.I)

_EVIDENCE_FAILURE_RE = _re.compile(
    r"\[exit [1-9]\d*\]|\bexit(?:ed| code)?[:=\s]+[1-9]|no credentials cache|"
    r"\bno\b[^.\n]{0,24}\b(found|cache|accounts?|tickets?|results?|entries|hosts?)\b|"
    r"\bnot found\b|\b0 results?\b|connection (refused|timed out|reset)|could not|unable to|"
    r"permission denied|access denied|command not found|no such file|no route to host|"
    # Authentication/authorization DENIED — the probe was rejected, so it proved no access.
    # A finding that claims readable/accessible-without-auth but whose evidence is a 401/403 /
    # 'not authorized' / 'forbidden' is a false positive; treat as a non-grounding failure.
    r"\b40[13]\b|unauthoriz|not authoriz|\bforbidden\b|authentication required|login required|"
    r"\bfailed\b|\btimed out\b|operation not permitted|is unreachable|"
    r"name or service not known|nothing (found|returned)|empty (result|response)", _re.I)

_EVIDENCE_PROOF_RE = _re.compile(
    r"uid=\d+|gid=\d+|\bprincipal:|valid starting|\bflag\{|htb\{|"
    r"\d+\s+(ticket|account|credential|host|record|hash|user|entr)\w*\s+"
    r"(found|retrieved|cracked|obtained)|http/\d(\.\d)?\s+200|\b200 ok\b|"
    r"logged in|authentication succe|session opened|shell obtained", _re.I)

# I1 — evidence that shows the supporting run FAILED, found nothing, or never ran.
# A finding CANNOT reach >=MEDIUM/VERIFIED on this evidence (or on empty evidence):
# "filtered" / "0 hosts up" / "No X vuln" / [CIRCUIT-BREAKER] / [FAIL] / connect-refused
# (curl 7) / timeout (28/124) / TLS failure (35/56/60) / non-zero exit.
_UNSUPPORTED_EVIDENCE_RE = _re.compile(
    r"\[circuit-?breaker\]|circuit-?break|\[fail\]|"
    r"\[exit [1-9]\d*\]|\bexit(?:ed| code)?[:=\s]+[1-9]\d*\b|"
    r"\b0 hosts? up\b|host seems down|\bfiltered\b|"
    r"connection (?:refused|reset|timed out)|connect(?:ion)? failed|\(7\)\s|curl:\s*\(7\)|"
    r"\btimed out\b|\btimeout\b|\(28\)|\(124\)|operation timed out|"
    r"ssl(?:v3)? (?:handshake|alert|routines)|\(35\)|\(56\)|\(60\)|wrong version number|"
    r"no route to host|network is unreachable|name or service not known|"
    r"unable to connect|could not connect|couldn't connect|"
    # Rate-limited / throttled — the tool was blocked and got no real result, so it
    # can never ground a MEDIUM+ finding (generalises the tool-outcome space, not a
    # sample specific).  A bare "429" alone is too collision-prone, so require it with
    # HTTP or a rate-limit phrase.
    r"\b429\b\s*(?:too many requests)?|too many requests|http/\d(?:\.\d)?\s+429|"
    r"rate[-\s]?limit(?:ed|ing)?|\bthrottl(?:ed|ing)\b|retry[-\s]?after|"
    # Unknown / uninstalled / unavailable capability — no evidence was produced.
    r"unknown tool|no such (?:capability|command|tool)|capability (?:missing|unavailable)|"
    r"not installed|tool (?:missing|unavailable)|"
    # Explicitly truncated / incomplete result without a proof token → not grounding.
    r"\btruncated\b|partial (?:read|response|content|result)|incomplete read|unexpected eof|"
    r"no (?:previously reported )?[\w./-]* ?vuln|not vulnerable|"
    r"\bno\b[^.\n]{0,24}\b(found|results?|entries|hosts?|links?|usable links?)\b", _re.I)


def evidence_is_successful(finding: Dict[str, Any]) -> bool:
    """I1: True ONLY when the finding's evidence shows a SUCCESSFUL supporting run —
    non-empty output that does not negate the claim (a hard-proof token always counts).
    Empty evidence, a tool failure, a negative/'found nothing' result, a circuit-breaker
    or [FAIL] message, or a connect/timeout/TLS failure => NOT successful, so the finding
    can never justify >=MEDIUM / VERIFIED.  Pure + deterministic."""
    ev = str((finding or {}).get("evidence") or (finding or {}).get("raw_output") or "").strip()
    if not ev:
        return False
    if _EVIDENCE_PROOF_RE.search(ev) or _proof_re().search(ev):
        return True
    if _UNSUPPORTED_EVIDENCE_RE.search(ev) or _EVIDENCE_FAILURE_RE.search(ev):
        return False
    return True


def evidence_contradicts_claim(finding: Dict[str, Any]) -> "tuple[bool, str]":
    """True (+reason) when the finding's title asserts a POSITIVE result but its evidence
    shows the tool FAILED / found nothing (non-zero exit, 'not found', stderr error) and
    carries no positive-proof token — a claim↔evidence contradiction that is a false
    positive, not a real finding."""
    f = finding or {}
    title = str(f.get("title") or "")
    ev = str(f.get("evidence") or f.get("raw_output") or "")
    if not ev.strip() or not _CLAIM_POSITIVE_RE.search(title):
        return False, ""
    # Symmetric proof escape (same as evidence_is_successful): a genuine access artifact —
    # a hard-proof token from EITHER proof regex (uid=/whoami/NT AUTHORITY/session/flag) —
    # means the claim IS backed even if the evidence also contains a failure/denied string
    # (e.g. "GET /admin -> 403 (WAF)  ...bypassed... whoami -> nt authority\\system").  Only
    # WITHOUT any proof token is a failure string a real claim↔evidence contradiction.
    if (_EVIDENCE_FAILURE_RE.search(ev)
            and not (_EVIDENCE_PROOF_RE.search(ev) or _proof_re().search(ev))):
        return True, ("evidence contradicts the claim — the tool failed or found nothing "
                      "(non-zero exit / 'not found' / error) while the title asserts a positive result")
    return False, ""


# ── Self-authored-evidence gate (I2 / P2) ────────────────────────────────────
# A COMPROMISE-class claim (a shell / credential / flag / domain-admin / RCE) must rest
# on a CAPTURED TOOL ARTIFACT, never on narrative prose.  "I obtained a root shell" /
# "the assistant compromised the host" is self-authored text, not evidence.  This holds
# for every finding type and target — the artifact requirement is universal.
_COMPROMISE_CLAIM_RE = _re.compile(
    r"\b(shell obtained|reverse shell|got a shell|root shell|got root|obtained root|"
    r"gained root|foothold (?:obtained|established|achieved)|command execution achieved|"
    r"rce achieved|compromis\w+|credentials? (?:captured|obtained|dumped|recovered)|"
    r"password (?:captured|cracked|obtained)|flag (?:captured|obtained|read|retrieved)|"
    r"session opened|meterpreter session|domain admin|secretsdump|dumped the hashes)\b",
    _re.I)


# COMPROMISE-proof tokens — a STRICT subset of _EVIDENCE_PROOF_RE.  A bare HTTP 200 / "200
# OK" means the tool got a successful RESPONSE (fine for grounding a detection finding), but
# it is NOT proof of a shell / credential / flag — a WAF, honeypot or wildcard responder
# answers 200 to everything.  So compromise claims require a real access artifact, never a
# 200.  (The OS-banner tokens in _proof_re — uname/cmd.exe-version output — ARE shell proof.)
_COMPROMISE_PROOF_RE = _re.compile(
    r"uid=\d+|gid=\d+|\bprincipal:|valid starting|\bflag\{|htb\{|"
    r"\d+\s+(ticket|account|credential|host|record|hash|user|entr)\w*\s+"
    r"(found|retrieved|cracked|obtained)|"
    r"logged in|authentication succe|session opened|shell obtained", _re.I)


def _has_captured_proof(finding: Dict[str, Any]) -> bool:
    """True when a compromise claim is backed by a CAPTURED ARTIFACT — a compromise-proof
    token in the evidence, a DEMONSTRATED tag, a reproduced status, a committed-exploit
    source, or a validated CVE.  A bare HTTP 200 / OS fingerprint and narrative prose alone
    return False (they do not prove access)."""
    f = finding or {}
    ev = str(f.get("evidence") or f.get("raw_output") or "")
    if ev and (_COMPROMISE_PROOF_RE.search(ev) or _proof_re().search(ev)):
        return True
    if str(f.get("evidence_tag") or "") == TAG_DEMONSTRATED:
        return True
    if str(f.get("reproduce_status") or "").lower() in _REPRO_PROVEN:
        return True
    if str(f.get("source") or "").lower() == "committed_exploit":
        return True
    return _has_validated_cve(f)


def _classify_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """The single source of truth for a finding's REPORT severity.  Returns
    ``{drop, severity, evidence_tag, rationale}``.  Conservative — it only reclassifies
    well-understood classes (tool-noise, detection-only, unproven-injection, demonstrated
    compromise, validated-CVE); anything else keeps its (clamped) producer severity.

    Founder decisions encoded here:
      • a VALIDATED critical CVE stays CRITICAL even if ARGUS did not execute it;
      • an UNPROVEN injection/RCE claim (no CVE, not reproduced) is capped at MEDIUM
        until command execution is demonstrated;
      • bare detection / service-discovery is INFO (LOW for an info-leak);
      • tool-output / internal-diagnostic records are DROPPED from the report.
    """
    f = finding or {}
    raw = _norm_sev(f.get("severity"))

    noise, why = is_noise(f)
    if noise:
        return {"drop": True, "severity": "info", "evidence_tag": TAG_OBSERVED, "rationale": why}

    # False positive: the finding claims a positive result its own evidence refutes.
    contradicted, cwhy = evidence_contradicts_claim(f)
    if contradicted:
        return {"drop": True, "severity": "info", "evidence_tag": TAG_OBSERVED, "rationale": cwhy}

    # Real evidence signals present → the operational policy governs verbatim.
    signals = f.get("signals") if isinstance(f.get("signals"), dict) else None
    if signals:
        v = grade(signals)
        return {"drop": False, "severity": v["severity"],
                "evidence_tag": v["evidence_tag"], "rationale": v["rationale"]}

    blob = (str(f.get("title") or "") + " " + str(f.get("description") or "")).lower()
    repro = str(f.get("reproduce_status") or "").lower()
    src = str(f.get("source") or "").lower()

    # Demonstrated compromise (committed-exploit win, reproduced PoC, captured proof).
    if (str(f.get("evidence_tag") or "") == TAG_DEMONSTRATED or repro in _REPRO_PROVEN
            or src == "committed_exploit"):
        keep = raw if raw in ("critical", "high") else "high"
        return {"drop": False, "severity": keep, "evidence_tag": TAG_DEMONSTRATED,
                "rationale": "ARGUS demonstrated this issue (reproduced / captured proof)."}

    # Validated critical/high CVE with a real CVE id → keep its weight (founder policy).
    if _has_validated_cve(f) and raw in ("critical", "high") and repro not in ("false", "rejected"):
        return {"drop": False, "severity": raw, "evidence_tag": TAG_PUBLIC_EXPLOIT,
                "rationale": "Validated CVE for the confirmed product — public exploit risk."}

    # Unproven injection / RCE claim (no CVE, not reproduced) → cap at MEDIUM pending proof.
    if _UNPROVEN_RCE_RE.search(blob) and not _has_validated_cve(f) and repro in _REPRO_UNPROVEN:
        capped = "medium" if _sev_rank(raw) > _sev_rank("medium") else raw
        return {"drop": False, "severity": capped, "evidence_tag": TAG_OBSERVED,
                "rationale": "Injection signature observed but command execution was NOT "
                             "demonstrated — capped pending proof of exploitation."}

    # Metasploit / generic 'exploit attempted' with no session → INFO.
    if "exploit attempted" in blob and "shell obtained" not in blob and "session opened" not in blob:
        return {"drop": False, "severity": "info", "evidence_tag": TAG_OBSERVED,
                "rationale": "Exploit attempted; no session/shell obtained."}

    # Information / hygiene exposure (missing headers, disclosure, phpinfo) → LOW.
    if _INFO_LEAK_RE.search(blob) and repro in _REPRO_UNPROVEN:
        return {"drop": False, "severity": "low", "evidence_tag": TAG_OBSERVED,
                "rationale": "Information/hygiene exposure — not directly exploitable."}

    # Bare detection / attack-surface observation → INFO.
    if _DETECTION_RE.search(blob) and repro in _REPRO_UNPROVEN:
        return {"drop": False, "severity": "info", "evidence_tag": TAG_OBSERVED,
                "rationale": "Attack-surface detection — present, not exploitable on its own."}

    # Otherwise: no operational-policy signal fired.  Two founder rules apply:
    #   1) a CRITICAL must have a defensible basis — an unsubstantiated one (no validated
    #      CVE, no demonstrated compromise, no reproduction) is provisionally capped to HIGH
    #      so the report never shows "critical" without proof;
    #   2) every rendered finding must carry a STATED basis — never return an empty rationale,
    #      so a client can always see WHY a severity was assigned.
    if raw == "critical":
        return {"drop": False, "severity": "high", "evidence_tag": TAG_OBSERVED,
                "rationale": "Rated CRITICAL by the finding producer but NOT substantiated by "
                             "a validated CVE or demonstrated exploitation — provisionally "
                             "capped to HIGH pending proof of impact."}
    return {"drop": False, "severity": raw, "evidence_tag": str(f.get("evidence_tag") or ""),
            "rationale": f"Severity {raw.upper()} as assessed by the finding producer from "
                         "its collected evidence (no demonstrated compromise or validated CVE "
                         "on file)."}


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """The single source of truth for a finding's REPORT severity + the I1 evidence gate.

    Runs the operational classifier, then applies the ONE hard guarantee (invariant I1):
    NO finding reaches >=MEDIUM / a VERIFIED tag unless a SUCCESSFUL tool run backs it
    (non-empty, non-negating evidence, or a hard-proof token).  A finding whose evidence
    is empty, a tool failure, a circuit-breaker/[FAIL], or a negative result is capped to
    INFO and tagged OBSERVED — regardless of its producer severity, a syntactic CVE id, or
    a 'demonstrated'/'foothold' title.  This is what stops the fabricated-compromise class
    (empty-evidence HIGH/MEDIUM findings) from reaching the client report."""
    res = _classify_finding(finding)
    if (not res.get("drop")) and _sev_rank(res.get("severity", "info")) >= _sev_rank("medium"):
        if not evidence_is_successful(finding):
            _prior = str(res.get("rationale") or "")
            res = {
                "drop": False, "severity": "info", "evidence_tag": TAG_OBSERVED,
                "rationale": ("UNSUPPORTED — no successful tool run backs this claim: the "
                              "evidence is empty, a tool failure, or a negative result, so the "
                              "severity is capped to INFO per the evidence-grounding policy (I1). "
                              + _prior)[:600],
            }
    # I2 / P2 — a compromise-class claim needs a CAPTURED artifact, never narrative prose.
    if (not res.get("drop")) and _sev_rank(res.get("severity", "info")) >= _sev_rank("medium"):
        _f = finding or {}
        _blob = str(_f.get("title") or "") + " " + str(_f.get("description") or "")
        if _COMPROMISE_CLAIM_RE.search(_blob) and not _has_captured_proof(_f):
            res = {
                "drop": False, "severity": "info", "evidence_tag": TAG_OBSERVED,
                "rationale": ("UNSUPPORTED COMPROMISE CLAIM — asserts a shell/credential/flag/"
                              "compromise but no captured tool artifact backs it (no proof token, "
                              "reproduced status, or committed-exploit source); capped to INFO per "
                              "the self-authored-evidence policy (I2)."),
            }
    return res


def compute_final_rating(sev_counts: Dict[str, int], *, root: bool = False,
                         shell: bool = False, has_issues: bool = False) -> "tuple[str, str]":
    """The ONE canonical engagement verdict, derived from the normalized severity counts
    and the compromise state — identical across every report theme.  Returns
    ``(final_rating, final_rating_label)``.  Proven-compromise-first, then critical issues,
    so the headline can never disagree between report types."""
    c = {k: int((sev_counts or {}).get(k, 0) or 0) for k in SEVERITY_ORDER}
    total = sum(c.values())
    if root:
        return "critical", "FULL COMPROMISE — ROOT"
    if shell:
        return "critical", "COMPROMISED — FOOTHOLD"
    if c["critical"] > 0:
        return "critical", "CRITICAL — UNEXPLOITED CRITICAL ISSUES"
    if c["high"] > 0:
        return "high", "HIGH — SIGNIFICANT ISSUES IDENTIFIED"
    if total > 0 or has_issues:
        # highest present severity drives the colour; wording stays the familiar one.
        rating = "medium" if c["medium"] > 0 else ("low" if c["low"] > 0 else "info")
        return rating, "PARTIAL — ISSUES IDENTIFIED"
    return "none", "RECON ONLY"


# ═══════════════════════════════════════════════════════════════════════════
#  Reproducibility + basis-of-claim  (report defensibility)
#
#  A client-facing finding — and ESPECIALLY a "compromised" verdict — must stand
#  on documented, human-reproducible receipts: WHAT was run, on WHAT BASIS the
#  claim rests, and (when no artifact was auto-captured) WHY, plus the EXACT
#  steps a human can rerun to verify.  These are PURE functions over the data
#  ARGUS actually recorded — they NEVER fabricate a command or a proof.
# ═══════════════════════════════════════════════════════════════════════════

# Signatures that constitute hard proof of the claimed access in captured output.
_PROOF_RE = None


def _proof_re():
    """Lazily-compiled proof-signature regex (uid=/whoami/shadow/SID/…)."""
    global _PROOF_RE
    if _PROOF_RE is None:
        import re
        _PROOF_RE = re.compile(
            r"uid=\d+|gid=\d+|\broot:[^:]*:0:0:|\bwhoami\b|"
            r"\bNT AUTHORITY\\|BUILTIN\\Administrators|S-1-5-(?:21|32)|"
            r"Linux \S+ \d+\.\d+|Microsoft Windows \[Version",
            re.I)
    return _PROOF_RE


def _clean_cmds(*vals: Any) -> List[str]:
    """Flatten str / list-of-str command fields into stripped, real command strings."""
    out: List[str] = []
    for v in vals:
        if isinstance(v, str):
            s = v.strip()
            if s:
                out.append(s)
        elif isinstance(v, (list, tuple)):
            for x in v:
                if isinstance(x, dict):
                    x = x.get("command") or x.get("cmd") or ""
                s = str(x or "").strip()
                if s:
                    out.append(s)
    return out


def _finding_commands(f: Dict[str, Any]) -> List[str]:
    """Every EXACT command already recorded on a finding — real data only."""
    f = f or {}
    cmds = _clean_cmds(f.get("command"), f.get("cmd"), f.get("commands"))
    ex = f.get("extra")
    if isinstance(ex, dict):
        cmds += _clean_cmds(ex.get("command"), ex.get("cmd"),
                            ex.get("repro"), ex.get("reproduction"), ex.get("commands"))
    return cmds


def build_reproduction(finding: Dict[str, Any],
                       coverage_tests: "list | None" = None) -> List[str]:
    """Compile the EXACT ordered steps a human can rerun to reproduce a finding,
    strictly from what ARGUS executed.  Returns [] when nothing concrete was
    recorded (the caller then shows the evidence block alone) — it never invents
    a command."""
    steps: List[str] = []
    seen = set()

    def _add(cmd: Any) -> None:
        c = str(cmd or "").strip()
        if len(c) > 1 and c not in seen:
            seen.add(c)
            steps.append(c)

    for c in _finding_commands(finding):
        _add(c)

    host = str((finding or {}).get("host") or (finding or {}).get("target") or "").strip()
    tool = str((finding or {}).get("tool_used") or (finding or {}).get("tool") or "").strip().lower()
    for t in (coverage_tests or []):
        if not isinstance(t, dict):
            continue
        cmd = str(t.get("command") or "").strip()
        if not cmd:
            continue
        t_host = str(t.get("target") or t.get("host") or "").strip()
        t_tool = str(t.get("tool") or "").strip().lower()
        host_ok = bool(host) and bool(t_host) and (host in t_host or t_host in host)
        tool_ok = (not tool) or (tool == t_tool)
        if host_ok and tool_ok:
            _add(cmd)
    return steps[:12]


def finding_basis(finding: Dict[str, Any]) -> "tuple[str, str]":
    """The concrete grounds a finding stands on → (kind, human note).  Real data only.
    kind ∈ {proof, cve, tool, none}."""
    f = finding or {}
    ev = str(f.get("evidence") or f.get("raw_output") or "")
    cves = [str(c) for c in (f.get("cves") or []) if c]
    if ev and _proof_re().search(ev):
        return "proof", ("Command output in the evidence block proves the stated access "
                         "(uid / whoami / hash / SID present).")
    if cves:
        return "cve", ("Grounded in " + ", ".join(cves[:3]) +
                       " matched to the confirmed product/version.")
    if ev.strip():
        # [S5] Non-empty evidence is NOT confirmation when the recorded output is a tool
        # FAILURE or a negating result (filtered / 0 hosts up / EXIT 28 / circuit-breaker /
        # "no X vuln").  Claim the finding is "grounded in the recorded tool output" ONLY
        # when that output actually succeeds — otherwise the basis directly contradicts the
        # evidence block it points at (the audit found 13/14 findings VERIFIED + "grounded"
        # sitting above evidence that read "filtered" / "0 hosts up" / "EXIT 28").
        if evidence_is_successful(f):
            return "tool", "Grounded in the recorded tool output shown in the evidence block."
        return "none", ("The recorded tool output does NOT confirm this — it shows a "
                        "filtered / timed-out / negative result, so the finding is unverified.")
    return "none", ""


def compromise_evidence_state(findings: "list | None", flags: "list | None",
                              intel: "dict | None",
                              coverage_tests: "list | None" = None,
                              loot: "list | None" = None) -> Dict[str, Any]:
    """Transparency receipts for a compromise claim.  Returns {} when no compromise
    is claimed.  Otherwise KEEPS the claim but documents: the BASIS, whether a proof
    artifact was captured, the exact METHOD steps ARGUS ran, and — when no artifact
    was captured — WHY, so a human can manually reproduce and verify.  Real data only."""
    findings = findings or []
    flags = flags or []
    intel = intel or {}
    loot = loot or []

    def _fval(f):
        return str((f or {}).get("value") or "").strip()

    root_flag = any((f or {}).get("flag_type") == "root" and _fval(f) for f in flags)
    user_flag = any((f or {}).get("flag_type") == "user" and _fval(f) for f in flags)
    any_flag_rec = any((f or {}).get("flag_type") in ("user", "root") for f in flags)
    shelled = bool(intel.get("shell_access")) or root_flag or user_flag or any_flag_rec
    if not shelled:
        return {}

    # ── proof artifacts actually captured ──────────────────────────────────
    proof_items: List[str] = []
    for f in flags:
        val = _fval(f)
        if val:
            proof_items.append(
                f"{(f.get('flag_type') or 'flag').upper()} flag captured at "
                f"{f.get('location') or 'target'}: {val[:64]}")
    for f in findings:
        if not isinstance(f, dict):
            continue
        ev = str(f.get("evidence") or f.get("raw_output") or "")
        if ev and _proof_re().search(ev):
            first = next((ln.strip() for ln in ev.splitlines() if ln.strip()), "")
            proof_items.append("Proof-of-access command output recorded: " + first[:90])
        if str(f.get("screenshot") or "").strip():
            proof_items.append("Screenshot artifact: " + str(f.get("screenshot"))[:90])
    for l in loot:
        if isinstance(l, dict) and l.get("sha256"):
            proof_items.append(
                f"Artifact archived (SHA-256 {str(l.get('sha256'))[:16]}…): "
                f"{l.get('name') or l.get('path') or 'evidence'}")

    # dedup, keep order
    _seen = set()
    proof_items = [p for p in proof_items if not (p in _seen or _seen.add(p))][:12]
    proven = bool(proof_items)

    # ── method: the EXACT commands ARGUS ran along the compromise path ──────
    method: List[str] = []
    mseen = set()
    _KW = ("rce", "remote code", "shell", "foothold", "exploit", "upload",
           "proof of access", "flag found", "command execution", "webshell",
           "reverse", "privilege", "privesc")
    for f in findings:
        if not isinstance(f, dict):
            continue
        title = str(f.get("title") or "").lower()
        if any(k in title for k in _KW):
            for c in build_reproduction(f, coverage_tests):
                if c not in mseen:
                    mseen.add(c)
                    method.append(c)
    # backstop: the commands that SUCCEEDED during the engagement (real coverage)
    if len(method) < 3:
        for t in (coverage_tests or []):
            if isinstance(t, dict) and str(t.get("outcome") or "").lower() == "success":
                c = str(t.get("command") or "").strip()
                if c and c not in mseen:
                    mseen.add(c)
                    method.append(c)
    method = method[:14]

    level = "root" if root_flag else ("user" if user_flag else "foothold")
    if proven:
        basis = "; ".join(proof_items)
    elif root_flag:
        basis = "Root-level flag recorded during the engagement"
    elif user_flag:
        basis = "User-level flag recorded during the engagement"
    else:
        basis = ("An interactive session / command execution context was established on the "
                 "target during the engagement")

    no_artifact_reason = ""
    if not proven:
        no_artifact_reason = (
            "ARGUS reached the target's execution context (the basis above), but the automated "
            "evidence sweep did not persist a stored artifact — typically because the session was "
            "non-interactive or closed before the evidence phase, or the proof command returned no "
            "output. The access is real and can be MANUALLY reproduced and verified by a human "
            "operator using the exact steps above/below.")

    return {
        "claimed": True,
        "proven": proven,
        "level": level,
        "basis": basis,
        "proof_items": proof_items,
        "method_steps": method,
        "no_artifact_reason": no_artifact_reason,
    }
