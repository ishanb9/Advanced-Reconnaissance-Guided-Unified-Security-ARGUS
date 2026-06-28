"""skill_registry.py — data-driven technology coverage (sub-project #5).

Loads human-authored skill files (knowledge/skills/<domain>/<tech>.md = Markdown
guidance + YAML front-matter), matches them against recon intel, and feeds the
operator guidance + safety-gated quick-wins.  Adding a technology = adding a .md
file (no code).  Mirrors agents/ai_red_team/discovery (same matcher + FP guard).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

_SKILLS_DIR = Path(__file__).resolve().parent / "skills"

# Code-level FP guard (shared with discovery): a shared web port never fires a
# detection on its own — only a technology-dedicated port match alone suffices.
_SHARED_PORTS = {80, 443, 3000, 3001, 4000, 5000, 5005, 8000, 8001, 8002,
                 8080, 8081, 8082, 8265, 8443, 8888, 9000, 9090, 9099}
_TEXT_KEYS = ("http", "https", "web", "whatweb", "headers", "banners",
              "http_banners", "titles", "server_headers", "web_findings", "tech")
_SAFETY = {"safe": 0, "intrusive": 1, "disruptive": 2}


def _split_front_matter(raw: str):
    """Return (front_matter_dict, body_str) for a Markdown+YAML-front-matter file."""
    import yaml
    if raw.startswith("---"):
        parts = raw.split("---", 2)
        if len(parts) >= 3:
            try:
                fm = yaml.safe_load(parts[1]) or {}
            except Exception:
                fm = {}
            return (fm if isinstance(fm, dict) else {}), parts[2].strip()
    return {}, raw.strip()


def load_skills(root: Optional[str] = None) -> List[Dict[str, Any]]:
    d = Path(root) if root else _SKILLS_DIR
    out: List[Dict[str, Any]] = []
    if not d.exists():
        return out
    for f in sorted(d.rglob("*.md")):
        if f.name.lower() == "readme.md":
            continue
        try:
            fm, body = _split_front_matter(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not (fm.get("id") and fm.get("technology") and isinstance(fm.get("match"), dict)):
            continue
        m = fm["match"]
        out.append({
            "id": str(fm["id"]), "technology": str(fm["technology"]),
            "domain": str(fm.get("domain", "IT")).upper(),
            "safety_class": str(fm.get("safety_class", "safe")).lower(),
            "severity": fm.get("severity"), "life_safety": bool(fm.get("life_safety")),
            "transport": str(fm.get("transport", "ip")).lower(),
            "category": str(fm.get("category", "")).strip().lower(),
            "match": {"ports": m.get("ports") or [], "banners": m.get("banners") or [],
                      "markers": m.get("markers") or []},
            "quick_wins": fm.get("quick_wins") or [],
            "references": fm.get("references") or [], "cpe": fm.get("cpe", ""),
            "mitre": fm.get("mitre", ""), "guidance": body, "_source": str(f),
        })
    return out


def _iter_ports(intel):
    for p in (intel.get("open_ports") or []):
        if isinstance(p, dict):
            try:
                yield int(p.get("port")), str(p.get("service") or ""), str(p.get("version") or "")
            except Exception:
                continue
        else:
            try:
                yield int(p), "", ""
            except Exception:
                continue
    for k, v in (intel.get("services") or {}).items():
        try:
            port = int(v.get("port") if isinstance(v, dict) and v.get("port") else k)
        except Exception:
            continue
        svc = str((v or {}).get("service") or "") if isinstance(v, dict) else ""
        ver = str((v or {}).get("version") or "") if isinstance(v, dict) else ""
        yield port, svc, ver


def _text_blob(intel) -> str:
    parts = [f"{s} {v}" for _p, s, v in _iter_ports(intel)]
    for k in _TEXT_KEYS:
        val = intel.get(k)
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, (list, tuple)):
            parts.extend(str(x) for x in val)
        elif isinstance(val, dict):
            parts.extend(f"{kk} {vv}" for kk, vv in val.items())
    return " \n ".join(parts).lower()


def match_skills(intel: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(intel, dict):
        return []
    skills = load_skills()
    open_ports = {p for p, _s, _v in _iter_ports(intel)}
    blob = _text_blob(intel)
    out: List[Dict[str, Any]] = []
    for s in skills:
        ev: List[str] = []
        hit_ports: List[int] = []
        dedicated = False
        for p in s["match"]["ports"]:
            try:
                pi = int(p)
            except Exception:
                continue
            if pi in open_ports:
                hit_ports.append(pi); ev.append(f"{pi}/tcp")
                if pi not in _SHARED_PORTS:
                    dedicated = True
        banner = any(str(b).lower() in blob for b in s["match"]["banners"] if b)
        marker = any(str(m).lower() in blob for m in s["match"]["markers"] if m)
        if banner:
            ev.append("banner-match")
        if marker:
            ev.append("marker-match")
        if not (dedicated or banner or marker):
            continue
        out.append({
            "id": s["id"], "technology": s["technology"], "domain": s["domain"],
            "safety_class": s["safety_class"], "severity": s["severity"],
            "life_safety": s["life_safety"], "transport": s.get("transport", "ip"),
            "category": s.get("category", ""), "ports": sorted(set(hit_ports)),
            "evidence": "; ".join(dict.fromkeys(ev)), "guidance": s["guidance"][:1200],
            "quick_wins": s["quick_wins"], "references": s["references"],
            "mitre": s["mitre"], "capability": "knowledge/skills",
            "hint": (f"{s['technology']} skill matched — domain {s['domain']}, "
                     f"base class {s['safety_class']}. Safe quick-wins available."),
        })
    return out


def finding_for(detection: Dict[str, Any]) -> Dict[str, Any]:
    tech = detection.get("technology", "technology")
    ev = detection.get("evidence", "")
    refs = ", ".join(str(r) for r in (detection.get("references") or [])[:5])
    ot = detection.get("domain") == "OT"
    transport = str(detection.get("transport", "ip")).lower()
    _bridge = {"rf": "an SDR / radio bridge (HackRF / RTL-SDR / KillerBee / Ubertooth)",
               "can": "a CAN/serial bridge (SocketCAN / HWBridge)",
               "l2": "on-segment Layer-2 capture (raw socket / SPAN)",
               "serial": "an RS-485 / serial bridge (Proxmark / ESPKey / LibOSDP)"}
    transport_note = ("" if transport == "ip"
                      else f" Active testing requires {_bridge.get(transport, 'dedicated hardware')} — "
                           "the matched quick-wins are operator guidance, not auto-executed.")
    return {
        # A bare detection is an OBSERVATION of attack surface → INFO. The skill's
        # inherent-risk class drives PRIORITISATION only (priority_score / rank_matches
        # read it straight off the detection dict, knowledge/skill_registry.py), never
        # the finding severity. Real HIGH/CRITICAL is reserved for a confirmed issue
        # (version-applicable CVE, proven misconfig, or an exploited/foothold finding).
        "severity": "info",
        "inherent_risk": (detection.get("severity") or "info"),
        "title": f"{tech} detected" + (" (OT — fragile)" if ot else ""),
        "description": (f"{tech} was identified on the target ({ev}). "
                        + (detection.get("guidance", "")[:600])
                        + (f" References: {refs}." if refs else "")
                        + (" OT/ICS: reachability can equal control — test read-only first."
                           if ot else "")
                        + transport_note),
        "evidence": ev,
        "remediation": ("Inventory and segment this asset; restrict access to authorized "
                        "management networks; apply vendor advisories"
                        + (f" ({refs})" if refs else "") + "."),
        "tool_used": "skill_registry",
        "mitre": detection.get("mitre", ""),
    }


def allowed(action_safety: str, ceiling: str, domain: str = "IT",
            life_safety: bool = False, authorized: bool = False) -> bool:
    """Safety gate: may an action of class ``action_safety`` auto-run under the
    human-selected ``ceiling`` for a target in ``domain``?  Safe-by-default for OT."""
    a = _SAFETY.get(str(action_safety).lower(), 2)
    c = _SAFETY.get(str(ceiling).lower(), 0)
    if life_safety and a >= _SAFETY["intrusive"] and not authorized:
        return False
    if str(domain).upper() == "OT" and not authorized:
        c = min(c, _SAFETY["safe"])     # OT clamps to safe unless authorized
    return a <= c


def safe_quick_wins(detection, ceiling, domain="IT", authorized=False):
    return [q for q in (detection.get("quick_wins") or [])
            if allowed(q.get("safety", "safe"), ceiling, domain,
                       detection.get("life_safety", False), authorized)]


def ingest_to_rag(skill: Dict[str, Any]) -> bool:
    """Best-effort: push the guidance body into the RAG knowledge base."""
    body = (skill.get("guidance") or "").strip()
    if len(body) < 40:
        return False
    try:
        from knowledge import knowledge_base as kb
        return bool(kb.ingest(
            text=f"# {skill.get('technology','')} (skill)\n{body}",
            source_file=skill.get("_source", f"skill:{skill.get('id','')}"),
            chunk_index=0,
            metadata={"chunk_type": "skill",
                      "ports": [int(p) for p in (skill.get("match", {}).get("ports") or []) if str(p).isdigit()],
                      "cves": [r for r in (skill.get("references") or []) if str(r).upper().startswith("CVE")],
                      "mitre_ttps": [skill["mitre"]] if skill.get("mitre") else [],
                      "section_title": skill.get("technology", "")}))
    except Exception:
        return False


# ── Prioritisation (#2): rank matched skills so the operator focuses ──────────
import re as _re_pri

_SEV_W = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.15}


def _cve_recency(references) -> float:
    """1.0 baseline; newer referenced CVEs raise the score (KEV-style recency)."""
    years = []
    for r in (references or []):
        for y in _re_pri.findall(r"CVE-(\d{4})-", str(r).upper()):
            try:
                years.append(int(y))
            except Exception:
                pass
    if not years:
        return 1.0
    return max(0.8, min(1.6, 1.0 + (max(years) - 2018) / 12.0))


def priority_score(detection: Dict[str, Any]) -> float:
    """severity × exploitability × CVE-recency × learned-weight (from telemetry)."""
    sev = _SEV_W.get(str(detection.get("severity") or "").lower(), 0.15)
    refs = detection.get("references") or []
    qws = detection.get("quick_wins") or []
    has_safe = any(str(q.get("safety", "safe")).lower() == "safe" for q in qws if isinstance(q, dict))
    has_cve = any("CVE-" in str(r).upper() for r in refs)
    exploit = 1.0 + (0.2 if has_safe else 0.0) + (0.25 if has_cve else 0.0)
    recency = _cve_recency(refs)
    try:
        from knowledge import skill_telemetry as _t
        lw = _t.learned_weight(str(detection.get("id", "")))
    except Exception:
        lw = 1.0
    return round(sev * exploit * recency * lw, 4)


def rank_matches(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return the detections highest-priority first, each tagged priority_score."""
    out: List[Dict[str, Any]] = []
    for d in (detections or []):
        d = dict(d)
        d["priority_score"] = priority_score(d)
        out.append(d)
    out.sort(key=lambda x: x.get("priority_score", 0.0), reverse=True)
    return out


def prioritized_guidance(detections: List[Dict[str, Any]], ceiling: str = "safe",
                         domain: str = "IT", authorized: bool = False,
                         top_n: int = 5) -> str:
    """Build a focused operator advisory from the TOP-N ranked matches (so the
    operator doesn't drown), each with its ceiling-allowed SAFE quick-wins."""
    lines: List[str] = []
    for d in rank_matches(detections)[:max(1, top_n)]:
        qws = safe_quick_wins(d, ceiling, d.get("domain", domain), authorized)
        qwt = " | ".join(str(q.get("cmd", "")) for q in qws[:3] if isinstance(q, dict))
        lines.append(f"[{d.get('priority_score', 0):.2f}] {d.get('technology','')} "
                     f"({d.get('evidence','')}) — {d.get('hint','')}"
                     + (f"  SAFE quick-wins: {qwt}" if qwt else ""))
    return "\n".join(lines)


__all__ = ["load_skills", "match_skills", "finding_for", "allowed",
           "safe_quick_wins", "ingest_to_rag",
           "priority_score", "rank_matches", "prioritized_guidance"]
