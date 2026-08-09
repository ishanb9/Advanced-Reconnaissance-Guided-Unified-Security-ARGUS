"""knowledge/reach_controllability.py — reachability + input-controllability signals.

Slice-2 leaf module.  Derives, from recon evidence ARGUS has ALREADY collected
(open ports, discovered web paths, params/forms, service banners/fingerprints),
whether a fuzz SURFACE is:

  * **reachable** — exposed/listening per recon (an open port, a discovered path,
    a running service), and
  * **input_controllable** — has a CONCRETE attacker-drivable input (a web path
    with a discovered query param / form field, an upload/import endpoint, an API
    endpoint that accepts a body, or a protocol service whose banner/fingerprint
    indicates an accepting handler).

It also emits two 0..1 confidences (``controllability`` / ``sink_proximity``)
scaled by how many concrete signals were found, plus short human ``evidence``
strings naming WHY.

This populates the already-wired (but defaulted-``True``) ``reachable`` /
``input_controllable`` gate in :mod:`knowledge.fuzz_targeting.score_surface`.

Design constraints (NON-NEGOTIABLE):
  * **Pure stdlib, deterministic, never raises.**  No live traffic, no network,
    no optional binaries.  Same input → same output, every run.
  * **Conservative.**  ``input_controllable`` is ``True`` ONLY with concrete
    evidence of a driveable input; a bare static path or a closed/unknown service
    yields ``False``.  ``reachable`` falls back to a conservative default only
    when nothing in the surface proves exposure.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = ["controllability_signals"]

# Keys that, when present and non-empty on a surface/intel record, indicate a
# concrete attacker-drivable input (discovered params, form fields, request body,
# upload sink, or a named endpoint/api).  Grounded in the shapes recon already
# emits (see knowledge/fuzz_targeting.enumerate_surfaces + recon subagents).
_INPUT_KEYS = (
    "params", "parameters", "query", "query_params", "querystring",
    "forms", "form_fields", "fields", "inputs",
    "body", "json_body", "post_data", "request_body",
    "upload", "uploads", "file_upload", "multipart",
    "api", "api_params", "api_body",
    "web_targets", "endpoints",
)

# Path fragments implying an attacker can drive structured input.
_UPLOAD_RE = re.compile(r"(upload|import|attachment|multipart|file)", re.IGNORECASE)
_API_RE = re.compile(
    r"(^|/)(api|v\d+|graphql|rest|rpc|soap|swagger|openapi)(/|$|\?)", re.IGNORECASE
)
_QUERY_RE = re.compile(r"\?[^=\s]+=", re.IGNORECASE)            # a real ?k=v query string
_DYNAMIC_RE = re.compile(r"\.(php|asp|aspx|jsp|cgi|pl|py|rb|do|action)\b", re.IGNORECASE)

# Static-asset extensions: a bare path ending here is NOT input-controllable.
_STATIC_RE = re.compile(
    r"\.(?:html?|htm|css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|txt|pdf|"
    r"webp|mp4|mp3|webm|wasm)(?:$|\?)",
    re.IGNORECASE,
)

# Banner/fingerprint tokens that indicate a service ACCEPTS structured input
# (a handler we could feed) rather than a closed/filtered/empty port.
_HANDLER_TOKENS = (
    "http", "server", "soap", "rest", "api", "json", "xml", "rpc", "graphql",
    "ftp", "smtp", "imap", "pop3", "ssh", "telnet", "smb", "rdp", "snmp", "ldap",
    "mysql", "postgres", "redis", "mongodb", "mssql", "amqp", "mqtt", "coap",
    "modbus", "s7", "s7comm", "opcua", "bacnet", "dnp3", "sip", "rtsp", "ntp",
    "tls", "ssl", "login", "auth", "prompt", "ready", "banner", "welcome",
    "upload", "post", "query",
)
# Tokens that indicate a CLOSED / filtered / non-accepting port — conservative no.
_CLOSED_TOKENS = ("closed", "filtered", "refused", "no-response", "tcpwrapped")

# Input kinds (from fuzz_targeting) that are inherently driveable structured input.
_DRIVEABLE_INPUT_KINDS = {
    "protocol", "http-request", "api-grammar", "file-upload",
}


def _truthy_collection(v: Any) -> bool:
    """A param/form/body signal counts only if it's a non-empty concrete value."""
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (str, bytes)):
        return len(v) > 0
    if isinstance(v, (list, tuple, set, dict)):
        return len(v) > 0
    if isinstance(v, (int, float)):
        return v != 0
    return True


def _gather_strings(*values: Any) -> str:
    """Flatten assorted recon fields into one lowercase haystack for token scans."""
    parts: List[str] = []
    for v in values:
        if v is None:
            continue
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, tuple, set)):
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
        elif isinstance(v, dict):
            for item in v.values():
                if isinstance(item, str):
                    parts.append(item)
    try:
        return " ".join(parts).lower()
    except Exception:
        return ""


def _path_of(surface: Dict[str, Any]) -> str:
    for key in ("endpoint", "path", "web_path", "url", "target", "uri"):
        v = surface.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def _has_open_port(surface: Dict[str, Any], intel: Dict[str, Any]) -> bool:
    """True when recon shows a listening port for this surface."""
    state = str(surface.get("port_state") or surface.get("state") or "").lower()
    if any(tok in state for tok in _CLOSED_TOKENS):
        return False
    if "open" in state:
        return True
    port = surface.get("port")
    if port not in (None, "", 0):
        # A concrete port on a surface enumerated from recon services implies listening.
        return True
    return False


def controllability_signals(surface: Dict[str, Any],
                            intel: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Derive reachability + input-controllability from existing recon evidence.

    NO live traffic.  Pure, deterministic, never raises.

    Args:
        surface: a single fuzz-surface record (as produced by
            :func:`knowledge.fuzz_targeting.enumerate_surfaces` or the lab UI):
            ``service``/``port``/``surface_type``/``input_kind``/``endpoint``/
            ``evidence`` plus any discovered ``params``/``forms``/``body``/etc.
        intel: optional broader recon snapshot for corroborating signals
            (``web_paths``, ``services``, ``web_targets`` …).

    Returns:
        ``{"input_controllable": bool, "reachable": bool,
           "controllability": float(0..1), "sink_proximity": float(0..1),
           "evidence": list[str]}``
    """
    default = {
        "input_controllable": False,
        "reachable": False,
        "controllability": 0.0,
        "sink_proximity": 0.0,
        "evidence": [],
    }
    try:
        if not isinstance(surface, dict):
            return dict(default)
        intel = intel if isinstance(intel, dict) else {}

        evidence: List[str] = []
        input_signals = 0          # count of concrete attacker-input signals
        reach_signals = 0          # count of exposure signals

        surface_type = str(surface.get("surface_type") or "").lower()
        input_kind = str(surface.get("input_kind") or "").lower()
        service = str(surface.get("service") or surface.get("product") or "")
        path = _path_of(surface)

        # An explicitly closed/filtered port_state suppresses every
        # exposure/handler inference below (conservative).
        port_state = str(surface.get("port_state") or surface.get("state") or "").lower()
        port_closed = any(tok in port_state for tok in _CLOSED_TOKENS)

        # ── Reachability: is it exposed/listening per recon? ──────────────────
        reachable = False
        if _has_open_port(surface, intel):
            reachable = True
            reach_signals += 1
            port = surface.get("port")
            evidence.append(
                f"open/listening port {port}" if port not in (None, "", 0)
                else "service reported listening")
        if path:
            reachable = True
            reach_signals += 1
            evidence.append(f"discovered path {path[:80]}")
        if service and not port_closed and not any(
                tok in service.lower() for tok in _CLOSED_TOKENS):
            # A named/fingerprinted running service is itself exposure evidence.
            if not reachable:
                evidence.append(f"running service '{service[:40]}'")
            reachable = True
            reach_signals += 1
        if surface.get("reachable") is True and not reachable:
            # Upstream already asserted reachability and we found no contradiction.
            reachable = True
            reach_signals += 1
            evidence.append("recon marked surface reachable")

        # ── Input-controllability: a CONCRETE attacker-drivable input? ────────
        input_controllable = False

        # (1) Discovered params / form fields / body / upload sink on the surface
        #     (or corroborated in the broader intel snapshot).
        for key in _INPUT_KEYS:
            if _truthy_collection(surface.get(key)) or _truthy_collection(intel.get(key)):
                input_controllable = True
                input_signals += 1
                evidence.append(f"discovered attacker input '{key}'")
                break

        # (2) Path-based concrete inputs: upload/import sink, API w/ body, or a
        #     real query string / dynamic handler — but NEVER a bare static asset.
        if path:
            is_static = bool(_STATIC_RE.search(path)) and not _QUERY_RE.search(path)
            if _UPLOAD_RE.search(path):
                input_controllable = True
                input_signals += 1
                evidence.append("upload/import endpoint (file-driven input)")
            elif _API_RE.search(path):
                input_controllable = True
                input_signals += 1
                evidence.append("API endpoint (accepts request body/params)")
            elif _QUERY_RE.search(path):
                input_controllable = True
                input_signals += 1
                evidence.append("path carries a query parameter")
            elif _DYNAMIC_RE.search(path):
                input_controllable = True
                input_signals += 1
                evidence.append("dynamic server-side handler (driveable input)")
            elif is_static:
                evidence.append("bare static asset (no driveable input)")

        # (3) Declared input_kind that is inherently structured/driveable.
        if input_kind in _DRIVEABLE_INPUT_KINDS:
            input_controllable = True
            input_signals += 1
            evidence.append(f"structured input handler ('{input_kind}')")

        # (4) Protocol service whose banner/fingerprint indicates an ACCEPTING
        #     handler (not a closed/filtered port).
        haystack = _gather_strings(
            surface.get("evidence"), surface.get("banner"),
            surface.get("fingerprint"), surface.get("version"),
            surface.get("product"), service,
        )
        if port_closed or any(tok in haystack for tok in _CLOSED_TOKENS):
            # Explicitly closed/filtered → no accepting handler to drive.
            if not input_controllable:
                evidence.append("service reported closed/filtered (no handler)")
        elif surface_type in ("ot", "iot", "network") or input_kind == "protocol":
            if any(tok in haystack for tok in _HANDLER_TOKENS):
                input_controllable = True
                input_signals += 1
                evidence.append("protocol banner indicates an accepting handler")

        # ── Confidence scaling (0..1) from concrete signal counts ─────────────
        # controllability rides on attacker-input signals; sink_proximity on how
        # directly that input reaches a handler (input + reach corroboration).
        controllability = 0.0
        if input_controllable:
            controllability = min(1.0, 0.5 + 0.25 * input_signals)
        sink_proximity = 0.0
        if input_controllable:
            sink_proximity = min(1.0, 0.4 + 0.2 * (input_signals + min(reach_signals, 2)))
        elif reachable:
            # Reachable but no driveable input found: a weak, non-zero proximity.
            sink_proximity = min(0.3, 0.1 * reach_signals)

        if not evidence:
            evidence.append("no concrete reach/controllability evidence")

        return {
            "input_controllable": bool(input_controllable),
            "reachable": bool(reachable),
            "controllability": round(float(controllability), 3),
            "sink_proximity": round(float(sink_proximity), 3),
            "evidence": evidence,
        }
    except Exception:  # never raise out — log + safe default
        logger.debug("controllability_signals failed; returning safe default",
                     exc_info=True)
        return dict(default)
