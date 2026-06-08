"""
lesson_distiller.py — continuous learning for ARGUS.

At the END of an engagement this distils the GENUINE, confirmed-working attack
techniques ARGUS used — and ONLY those — into the RAG knowledge base, so every
future scan can pattern-match on hard-won experience.

The cardinal rule (the operator's explicit requirement):
    Store only GENUINE methods of attack — successful ways of compromise,
    confirmed-exploitable vulnerabilities, and real tips/tricks/techniques —
    NEVER every scan finding.

Two quality gates enforce that:
  1. ENGAGEMENT gate (`genuine_success`): the engagement must have PROVEN
     something — a foothold/RCE, a captured flag, a recovered credential, a
     successful privilege escalation, OR a confirmed-exploitable
     vulnerability/auth-bypass.  A scan that merely *found* unconfirmed CVEs,
     open ports, or missing headers contributes NOTHING.
  2. LESSON gate (`_lesson_quality_ok`): each distilled card must describe a
     reusable, confirmed-to-have-worked TECHNIQUE (product/version → weakness →
     exact method) — not a raw finding, a failed attempt, or a one-line restate.

This module is PROCESS only.  The vuln-specific CONTENT (CVE ids, products,
payloads) is produced at runtime by the model from the engagement and written to
the RAG (data) — never hardcoded here.  Everything is best-effort and wrapped so
learning can NEVER crash or slow the engagement.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Tuple

# Generic action verbs that mark a real *technique* (not a static finding).
# These are universal methodology words, never a specific vuln/payload.
_TECHNIQUE_VERBS = (
    "exploit", "bypass", "inject", "escalate", "chain", "leak", "abuse",
    "upload", "traverse", "deserialize", "deserialise", "forge", "crack",
    "pivot", "execute", "overwrite", "poison", "smuggle", "reset", "takeover",
    "take over", "spray", "relay", "tunnel", "decrypt", "extract", "enumerate",
    "brute", "fuzz", "coerce", "impersonate", "hijack", "downgrade",
)
# Phrases that signal a low-value restatement we must NOT learn as a "technique".
_NON_TECHNIQUE = (
    "missing security header", "missing header", "open port", "server disclosure",
    "directory listing", "version disclosure", "informational", "no findings",
    "wildcard dns", "banner",
)


def genuine_success(intel: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """ENGAGEMENT gate.  True when the engagement PROVED a working technique.

    Gate strictness (operator-selected): ANY confirmed-working technique —
    code-execution, a captured flag, a recovered credential, a successful
    privesc, a met win-condition, OR an explicitly confirmed/exploited
    vulnerability.  Unconfirmed CVE *candidates* (auto-seeded exploit modules)
    do NOT count, so a pure recon/scan contributes nothing."""
    it = intel or {}
    reasons: List[str] = []
    if it.get("shell_access") or it.get("rce_confirmed"):
        reasons.append("code-execution / foothold")
    if it.get("user_flag") or it.get("root_flag"):
        reasons.append("flag captured")
    creds = it.get("credentials")
    if isinstance(creds, (list, dict)) and len(creds) > 0:
        reasons.append("credential recovered")
    if str(it.get("privesc_status", "")).lower() in ("success", "complete", "root"):
        reasons.append("privilege escalation")
    wc = it.get("win_conditions") or {}
    if isinstance(wc, dict) and (wc.get("achieved_count") or 0) > 0:
        reasons.append("win condition achieved")
    # A vulnerability EXPLICITLY confirmed/exploited (not an auto-seeded candidate).
    for v in (it.get("vulnerabilities") or []):
        if isinstance(v, dict) and (v.get("confirmed") or v.get("exploited")
                or str(v.get("status", "")).lower() in ("confirmed", "exploited", "verified")):
            reasons.append("confirmed-exploitable vulnerability"); break
    # An exploit module the operator actually USED (not just fetched as a lead).
    for m in (it.get("exploit_modules") or []):
        if isinstance(m, dict) and (m.get("used") or m.get("worked") or m.get("confirmed")):
            reasons.append("working exploit"); break
    return (len(reasons) > 0, reasons)


def _scrub(text: str, target: str) -> str:
    """Remove engagement-specific identifiers that aren't reusable: the target
    IP/host, raw 32-64 hex flag tokens.  Keeps product/version/CVE/method."""
    t = str(text or "")
    if target:
        t = t.replace(target, "the target")
    t = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "the target", t)          # IPs
    t = re.sub(r"\b[0-9a-fA-F]{32,64}\b", "<flag>", t)                   # flag tokens
    return t.strip()


def _lesson_quality_ok(text: str) -> bool:
    """LESSON gate.  Keep only a reusable, confirmed-to-have-worked technique."""
    t = (text or "").strip()
    if len(t) < 40 or len(t) > 1200:
        return False
    low = t.lower()
    if any(p in low for p in _NON_TECHNIQUE) and not any(v in low for v in _TECHNIQUE_VERBS):
        return False
    # Must read like a method: an action verb, OR a CVE id, OR a product+version.
    if any(v in low for v in _TECHNIQUE_VERBS):
        return True
    if re.search(r"cve-\d{4}-\d+", low):
        return True
    if re.search(r"[A-Za-z][A-Za-z0-9.\-]+\s+\d+\.\d+", t):   # product + version
        return True
    return False


def _collect_evidence(intel: Dict[str, Any]) -> str:
    """Compact, redaction-friendly summary of WHAT WORKED, for the distiller."""
    it = intel or {}
    parts: List[str] = []
    ap = it.get("attack_path") or []
    if ap:
        steps = []
        for s in ap:
            if isinstance(s, dict):
                steps.append(f"[{s.get('phase','?')}] {s.get('result') or s.get('detail') or ''}")
        if steps:
            parts.append("ATTACK PATH:\n" + "\n".join(steps[:12]))
    mods = [m for m in (it.get("exploit_modules") or []) if isinstance(m, dict)]
    if mods:
        parts.append("EXPLOITS/PoCs:\n" + "\n".join(
            f"- {','.join(m.get('cves', []) or []) or m.get('product','')} {m.get('url','')}"
            f"{' [USED]' if (m.get('used') or m.get('worked') or m.get('confirmed')) else ''}"
            for m in mods[:12]))
    vulns = [v for v in (it.get("vulnerabilities") or []) if isinstance(v, dict)]
    if vulns:
        parts.append("VULNERABILITIES:\n" + "\n".join(
            f"- {v.get('cve') or v.get('title','')}: {str(v.get('summary') or v.get('description',''))[:160]}"
            for v in vulns[:8]))
    notes = it.get("operator_notes") or []
    if notes:
        flat = [str(n.get("note") if isinstance(n, dict) else n) for n in notes]
        parts.append("OPERATOR NOTES:\n" + "\n".join(f"- {n[:220]}" for n in flat[:10]))
    svcs = it.get("services") or {}
    if isinstance(svcs, dict) and svcs:
        parts.append("SERVICES: " + ", ".join(
            f"{p}/{(s or {}).get('service','?')} {(s or {}).get('version','')}".strip()
            for p, s in list(svcs.items())[:12]))
    return "\n\n".join(parts)[:6000]


_SYSTEM = (
    "You are ARGUS's lessons curator. From a COMPLETED, SUCCESSFUL penetration "
    "test you extract the GENUINE, reusable attack techniques that were CONFIRMED "
    "to work this engagement, so future engagements can reuse them. STRICT rules:\n"
    "  • Only techniques that DEMONSTRABLY worked here (evidence in the data). "
    "Never speculation, never a technique that failed, never a raw finding "
    "(open port / missing header / unconfirmed CVE).\n"
    "  • Generalise: name the PRODUCT + VERSION + WEAKNESS CLASS + the exact "
    "working METHOD (and CVE id / public PoC if used). Make it reusable on a "
    "DIFFERENT host — do not include this target's IP, hostname, or flag values.\n"
    "  • Be concise and concrete: a tester reading the card should be able to "
    "reproduce the technique.\n"
    "Respond with ONLY a JSON array (max 5) of objects: "
    '{"title": str, "category": one of '
    '[recon,web,exploit,privesc,post,lateral,auth,cloud,ad], '
    '"technique": str (2-5 sentences, the reusable method)}. '
    "If nothing genuinely reusable was confirmed, return []."
)


def _parse_lessons(raw: str) -> List[Dict[str, Any]]:
    if not raw:
        return []
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("```")[1] if "```" in s[3:] else s.strip("`")
        s = re.sub(r"^json", "", s.strip(), flags=re.I).strip()
    m = re.search(r"\[.*\]", s, re.S)
    if m:
        s = m.group(0)
    try:
        obj = json.loads(s)
        return [o for o in obj if isinstance(o, dict)] if isinstance(obj, list) else []
    except Exception:
        return []


def _deterministic_lessons(intel: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fallback when no LLM is available: build technique cards straight from the
    USED exploit modules + confirmed vulns (still genuine — they're tied to a
    confirmed-success engagement)."""
    out: List[Dict[str, Any]] = []
    for m in (intel.get("exploit_modules") or []):
        if not (isinstance(m, dict) and (m.get("used") or m.get("worked") or m.get("confirmed"))):
            continue
        cves = ", ".join(m.get("cves", []) or [])
        prod = m.get("product", "")
        url = m.get("url", "")
        if not (cves or url):
            continue
        out.append({
            "title": f"{prod or cves or 'Public PoC'} — confirmed working exploit",
            "category": "exploit",
            "technique": (f"{prod} {cves}: a public PoC ({url}) was run and confirmed "
                          "to work this engagement. Fetch and run it directly against a "
                          "matching version rather than hand-rolling the exploit.").strip(),
        })
    return out[:5]


async def distill_and_store(*, master: Any, intel: Dict[str, Any], session_id: str,
                            target: str, target_type: str = "unknown") -> int:
    """Entry point — distil genuine techniques from this engagement into the RAG.
    Returns the number of lessons stored.  Best-effort: never raises."""
    try:
        ok, reasons = genuine_success(intel)
        if not ok:
            return 0   # nothing genuine was proven — learn NOTHING (not every scan)

        evidence = _collect_evidence(intel)
        lessons: List[Dict[str, Any]] = []

        # Prefer an LLM distillation (richer, generalisable); fall back to a
        # deterministic extraction from the confirmed-working data.
        raw = ""
        try:
            conv = getattr(master, "converse", None)
            if conv is not None and evidence.strip():
                user = (f"Target type: {target_type}. Confirmed success: "
                        f"{', '.join(reasons)}.\n\nENGAGEMENT EVIDENCE:\n{evidence}\n\n"
                        "Extract the genuine, confirmed-working techniques as the JSON "
                        "array defined in your instructions.")
                raw = await conv([{"role": "system", "content": _SYSTEM},
                                  {"role": "user", "content": user}],
                                 tier="bulk", timeout=120)
        except Exception:
            raw = ""
        lessons = _parse_lessons(raw) or _deterministic_lessons(intel)

        try:
            from knowledge import knowledge_base as kb
        except Exception:
            try:
                import knowledge.knowledge_base as kb   # type: ignore
            except Exception:
                return 0

        stored = 0
        for les in lessons[:5]:
            text = str(les.get("technique") or les.get("text") or "").strip()
            title = str(les.get("title") or "").strip()
            full = (f"{title}\n{text}" if title else text).strip()
            full = _scrub(full, target)
            if not _lesson_quality_ok(full):
                continue
            cat = str(les.get("category") or "exploit").strip().lower()
            try:
                added = kb.ingest_tip(
                    text=full, category=cat, source=f"engagement_lesson:{session_id}",
                    extra_metadata={"source_type": "engagement_lesson",
                                    "target_type": target_type,
                                    "outcome": "confirmed"})
                if added:
                    stored += 1
            except Exception:
                continue

        if stored:
            try:
                await master._emit("rag_lesson_learned", {
                    "session_id": session_id, "count": stored,
                    "reasons": reasons})
            except Exception:
                pass
        return stored
    except Exception:
        return 0
