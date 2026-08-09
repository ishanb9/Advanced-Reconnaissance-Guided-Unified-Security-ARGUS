"""knowledge/fuzz_targeting.py — the "where to fuzz" indicator (pure, advisory).

ARGUS scores each ATTACK SURFACE it has observed for the likelihood that fuzzing
it yields a PREVIOUSLY-UNKNOWN bug, and ranks them so the human operator knows
where to point the (human-controlled) Fuzzing Lab first.

This module is a pure, dependency-free heuristic so the indicator is consistent
run-to-run and testable in isolation.  It is **advisory only** — nothing here runs
fuzzing, gates the engagement, or affects completion.  It is computed on demand
from a snapshot of ``intel``.

Grounded in adversarially-verified deep research:
  USE  — fuzzable surface = structured-input handlers (parsers / file-format /
         protocol state machines / deserialization / upload / API); the NOVELTY
         term is DOMINATED by OSS-vs-proprietary + CVE history; reachability +
         input-controllability are necessary; memory-unsafe language is only a
         WEAK prior; a crash is not a vulnerability.
  AVOID — static call-graph "danger score"; directly-reachable-only; sink-function
         concentration; component/firmware AGE as a 0-day proxy (age tracks known
         N-days, not novel bugs); "old version = more 0-days"; treating generic
         mainstream web apps as high-novelty.  No calibrated formula exists, so
         this is a TRANSPARENT heuristic prior — every score shows its factors.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ── Weights (novelty dominant; surface high; memory-unsafety only a weak prior) ──
_W_NOVELTY = 0.50
_W_SURFACE = 0.35
_W_MEM     = 0.15

_TIER_HIGH = 60.0
_TIER_MED  = 35.0

# Heavily-fuzzed mainstream OSS (OSS-Fuzz roster + hardened daemons) → LOW novelty:
# a 0-day here is much harder because these are continuously fuzzed upstream.
_FUZZED_OSS = {
    "apache", "httpd", "nginx", "openssh", "ssh", "openssl", "libssl", "sqlite",
    "mysql", "mariadb", "postgresql", "postgres", "redis", "mongodb", "bind",
    "named", "dnsmasq", "php", "python", "curl", "libxml2", "haproxy", "memcached",
    "exim", "postfix", "vsftpd", "proftpd", "openvpn", "wolfssl", "libpng",
    "libjpeg", "zlib", "expat", "pcre", "lua", "ffmpeg", "imagemagick", "freetype",
}

# Likely native C/C++ (weak crash-prone prior).  Managed runtimes are down-weighted.
_NATIVE_HINTS = {
    "nginx", "apache", "httpd", "openssh", "ssh", "openssl", "bind", "named",
    "dnsmasq", "vsftpd", "proftpd", "exim", "postfix", "memcached", "redis",
    "sqlite", "modbus", "opcua", "bacnet", "s7", "s7comm", "dnp3", "mqtt", "coap",
    "snmp", "rtsp", "sip", "smb", "rpc", "rdp", "ftp", "telnet", "ntp", "ssdp",
}
_MANAGED_HINTS = {
    "tomcat", "jetty", "java", "node", "nodejs", "express", "gunicorn", "uwsgi",
    "iis", "asp.net", "aspnet", "kestrel", "django", "flask", "rails", "jboss",
    "wildfly", "glassfish", "weblogic", "websphere", "spring",
}

# service-token → (surface_type, input_kind, surface_fuzzability, lab fuzzer_id|None)
# surface_fuzzability: structured-input richness, NOT a memory prior.
_SURFACE_BY_SERVICE: List[tuple] = [
    ("modbus",  ("ot",      "protocol",     0.85, "modbus_enum")),
    ("s7",      ("ot",      "protocol",     0.85, "s7_enum")),
    ("opcua",   ("ot",      "protocol",     0.85, None)),
    ("bacnet",  ("ot",      "protocol",     0.85, None)),
    ("dnp3",    ("ot",      "protocol",     0.85, None)),
    ("mqtt",    ("iot",     "protocol",     0.80, "mqtt_fuzz")),
    ("coap",    ("iot",     "protocol",     0.80, "coap_fuzz")),
    ("rtsp",    ("network", "protocol",     0.80, "nmap_fuzz_scripts")),
    ("sip",     ("network", "protocol",     0.80, "nmap_fuzz_scripts")),
    ("snmp",    ("network", "protocol",     0.70, "nmap_fuzz_scripts")),
    ("smb",     ("network", "protocol",     0.75, "nmap_fuzz_scripts")),
    ("rpc",     ("network", "protocol",     0.75, "nmap_fuzz_scripts")),
    ("rdp",     ("network", "protocol",     0.70, "nmap_fuzz_scripts")),
    ("ftp",     ("network", "protocol",     0.65, "nmap_fuzz_scripts")),
    ("telnet",  ("network", "protocol",     0.55, "nmap_fuzz_scripts")),
    ("https",   ("web",     "http-request", 0.40, "ffuf_content")),
    ("http",    ("web",     "http-request", 0.40, "ffuf_content")),
    ("ssl",     ("network", "protocol",     0.60, "tlsfuzz")),
    ("tls",     ("network", "protocol",     0.60, "tlsfuzz")),
]
# Ports that strongly imply a structured file/media parser (high fuzzability).
_TLS_PORTS = {"443", "8443"}


def _svc_token(service: str, port: str = "") -> str:
    return f"{service or ''} {port or ''}".strip().lower()


def _classify_service(service: str, port: str) -> tuple:
    """Return (surface_type, input_kind, surface_fuzzability, fuzzer_id)."""
    s = (service or "").lower()
    for token, spec in _SURFACE_BY_SERVICE:
        if token in s:
            st, ik, fz, fid = spec
            # TLS web on 8443/443 stays web; bare ssl/tls service → tlsfuzz.
            return st, ik, fz, fid
    # Web-ish by port even if the banner is vague.
    if str(port) in ("80", "8080", "8000", "8888"):
        return "web", "http-request", 0.40, "ffuf_content"
    if str(port) in _TLS_PORTS:
        return "web", "http-request", 0.42, "ffuf_content"
    # Unknown TCP service — protocol fuzzing surface.
    return "network", "protocol", 0.50, "nmap_fuzz_scripts"


def _is_api_path(path: str) -> bool:
    return bool(re.search(r"(^|/)(api|v\d+|graphql|rest|swagger|openapi)(/|$)",
                          str(path or ""), re.IGNORECASE))


def _is_upload_path(path: str) -> bool:
    return "upload" in str(path or "").lower() or "import" in str(path or "").lower()


# ──────────────────────────────────────────────────────────────────────────────
# Novelty — the DOMINANT term: where is a non-public bug actually likely?
# ──────────────────────────────────────────────────────────────────────────────
def novelty_score(service: str, surface_type: str, domain: str = "",
                  *, has_cve: bool = False, in_kev: bool = False) -> float:
    """0..1 estimate of how UNDER-FUZZED / proprietary a surface is.

    Heavily-fuzzed mainstream OSS is low (a 0-day is hard); OT/IoT/embedded and
    unknown/niche/proprietary tech is high (lightly fuzzed).  A public-CVE/KEV
    history nudges DOWN (well-trodden); a complex surface with no CVE history
    nudges UP (under-explored).  Component AGE is deliberately NOT used.
    """
    s = (service or "").lower()
    dom = (domain or "").upper()
    if any(tok in s for tok in _FUZZED_OSS):
        base = 0.15
    elif surface_type in ("ot", "iot") or dom in ("OT", "IOT"):
        base = 0.90
    else:
        # Unknown / niche / proprietary IT service → assume lightly fuzzed.
        base = 0.70
    # CVE/KEV coverage modifier (history of public scrutiny).
    if in_kev or has_cve:
        base -= 0.15
    elif base >= 0.65:
        base += 0.10   # complex + no public CVE history = under-explored
    return max(0.05, min(0.98, base))


def _mem_unsafe_prior(service: str) -> float:
    """WEAK prior: native C/C++ is more crash-prone than a managed runtime.
    Deliberately small weight — a crash is not a vulnerability."""
    s = (service or "").lower()
    if any(tok in s for tok in _MANAGED_HINTS):
        return 0.30
    if any(tok in s for tok in _NATIVE_HINTS):
        return 0.80
    return 0.50


def score_surface(surface: Dict[str, Any], *, has_cve: bool = False,
                  in_kev: bool = False) -> Dict[str, Any]:
    """Transparent heuristic 'fuzz yield' for one surface.

    Returns {score 0..100, tier, factors{…}, rationale}.  ``factors`` is always
    populated so the UI/report can SHOW why — this is an estimate, not a
    calibrated probability.
    """
    st   = surface.get("surface_type", "network")
    svc  = surface.get("service", "")
    dom  = surface.get("domain", "")
    fz   = float(surface.get("surface_fuzzability", 0.5))
    reachable = bool(surface.get("reachable", True))
    controllable = bool(surface.get("input_controllable", True))
    gate = 1.0 if (reachable and controllable) else 0.0

    nov = novelty_score(svc, st, dom, has_cve=has_cve, in_kev=in_kev)
    mem = _mem_unsafe_prior(svc)
    raw = (_W_NOVELTY * nov + _W_SURFACE * fz + _W_MEM * mem)
    score = round(gate * raw * 100.0, 1)
    tier = "none" if gate == 0 else ("high" if score >= _TIER_HIGH
                                     else "medium" if score >= _TIER_MED else "low")

    factors = {
        "novelty":            round(nov, 2),
        "surface_fuzzability": round(fz, 2),
        "mem_unsafe_prior":   round(mem, 2),
        "reachable":          reachable,
        "input_controllable": controllable,
        "has_public_cve":     bool(has_cve),
        "in_kev":             bool(in_kev),
    }
    why = []
    if nov >= 0.7:
        why.append("proprietary / lightly-fuzzed tech (high novelty)")
    elif nov <= 0.2:
        why.append("heavily-fuzzed mainstream OSS (low novelty)")
    if fz >= 0.8:
        why.append("rich structured-input handler (parser/protocol)")
    if mem >= 0.8:
        why.append("likely native C/C++ (weak crash-prone prior)")
    if has_cve or in_kev:
        why.append("has public CVE/exploit history (well-trodden)")
    if not why:
        why.append("moderate fuzz surface")
    rationale = "Estimated fuzz yield (heuristic): " + "; ".join(why) + "."

    return {"score": score, "tier": tier, "factors": factors, "rationale": rationale}


# ──────────────────────────────────────────────────────────────────────────────
# Surface enumeration — derive fuzz surfaces from what ARGUS already observed.
# ──────────────────────────────────────────────────────────────────────────────
def enumerate_surfaces(intel: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build the candidate fuzz-surface list from an intel snapshot.  Defensive:
    unknown shapes yield fewer surfaces, never an exception."""
    out: List[Dict[str, Any]] = []
    if not isinstance(intel, dict):
        return out
    host = str(intel.get("target_host") or intel.get("target") or "").strip()
    services = intel.get("services") or {}
    # Capability/skill detections carry the OT/IoT domain.
    detected_domain: Dict[str, str] = {}
    for det in (intel.get("_capability_detections") or []):
        try:
            for p in (det.get("ports") or []):
                detected_domain[str(p)] = str(det.get("domain", "")).upper()
        except Exception:
            pass

    if isinstance(services, dict):
        for port, svc in services.items():
            if not isinstance(svc, dict):
                continue
            service = svc.get("service") or svc.get("product") or ""
            st, ik, fz, fid = _classify_service(service, str(port))
            dom = detected_domain.get(str(port), "")
            if dom in ("OT", "IOT") and st not in ("ot", "iot"):
                st = dom.lower()
            surf = {
                "host": host, "port": _to_int(port), "service": service,
                "surface_type": st, "input_kind": ik,
                "surface_fuzzability": fz, "fuzzer_id": fid, "domain": dom,
                "evidence": (svc.get("version") or svc.get("banner") or "")[:120],
                "reachable": True, "input_controllable": True,
            }
            out.append(surf)

    # Web upload / API endpoints are high-value structured-input surfaces.
    for path in (intel.get("web_paths") or []):
        p = str(path)
        if _is_upload_path(p):
            out.append(_web_surface(host, p, "web", "file-upload", 0.90, "ffuf_content"))
        elif _is_api_path(p):
            out.append(_web_surface(host, p, "api", "api-grammar", 0.60, "ffuf_api"))

    # OPT-IN sharper gate (default OFF → existing scores byte-identical): refine the
    # reachable / input_controllable defaults from recon evidence so score_surface's gate
    # reflects real attacker-controllability.  Enable with ARGUS_REACH_GATE=1.
    import os as _os
    if _os.environ.get("ARGUS_REACH_GATE"):
        try:
            from knowledge.reach_controllability import controllability_signals as _cs
            for _surf in out:
                _sig = _cs(_surf, intel)
                _surf["input_controllable"] = bool(_sig.get("input_controllable",
                                                            _surf.get("input_controllable", True)))
                _surf["controllability"] = _sig.get("controllability", 0.0)
        except Exception:
            pass
    return out


def _web_surface(host, path, st, ik, fz, fid) -> Dict[str, Any]:
    return {
        "host": host, "port": None, "service": "http", "surface_type": st,
        "input_kind": ik, "surface_fuzzability": fz, "fuzzer_id": fid,
        "domain": "", "evidence": str(path)[:120],
        "reachable": True, "input_controllable": True, "endpoint": str(path),
    }


def _to_int(v) -> Optional[int]:
    try:
        return int(v)
    except Exception:
        return None


def _cve_signals(intel: Dict[str, Any], port: Optional[int]):
    """(has_cve, in_kev) for a port — best-effort from intel + KEV catalog."""
    has_cve = False
    cves = intel.get("cves") or intel.get("critical_cves") or []
    if cves:
        has_cve = True
    in_kev = False
    try:
        from agents.osint.cisa_kev_subagent import is_kev
        for c in (cves or []):
            cid = c[0] if isinstance(c, (list, tuple)) else c
            if isinstance(cid, str) and is_kev(cid):
                in_kev = True
                break
    except Exception:
        pass
    return has_cve, in_kev


def rank_targets(intel: Dict[str, Any]) -> Dict[str, Any]:
    """Score + rank every fuzz surface; also a per-host rollup (its best surface).
    Pure + best-effort: returns {targets:[…], by_host:{…}} (empty on any error)."""
    try:
        surfaces = enumerate_surfaces(intel)
    except Exception:
        return {"targets": [], "by_host": {}}
    scored: List[Dict[str, Any]] = []
    for s in surfaces:
        try:
            has_cve, in_kev = _cve_signals(intel if isinstance(intel, dict) else {}, s.get("port"))
            verdict = score_surface(s, has_cve=has_cve, in_kev=in_kev)
            if verdict["tier"] == "none":
                continue
            scored.append({**s, **verdict})
        except Exception:
            continue
    scored.sort(key=lambda r: r.get("score", 0), reverse=True)
    by_host: Dict[str, float] = {}
    for r in scored:
        h = r.get("host") or "?"
        by_host[h] = max(by_host.get(h, 0.0), r.get("score", 0.0))
    return {"targets": scored, "by_host": by_host,
            "high_count": sum(1 for r in scored if r.get("tier") == "high")}
