"""agents/fuzzing/oracle.py — anomaly detection + dedup (the "find the bug" stage).

Pure, modality-aware classification of a fuzz ``Observation`` (relative to a baseline)
into an ``Anomaly`` worth weaponising, plus deduplication so one bug is developed once.
No network / LLM here — fully unit-testable with fixture observations.

The strongest web signal is a returned MARKER: payloadgen tags each payload with its
intended vuln family + an expected oracle marker (e.g. an SSTI ``{{7*7}}`` should echo
``49``; a command-injection ``;echo <canary>`` should echo the canary).  When that
marker re-appears in the response, the input was evaluated — a high-confidence anomaly.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from agents.fuzzing.engines.base import Anomaly, Observation

# Server-side error fingerprints that indicate an injection / info-leak surface.
_SQL_ERR = re.compile(r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
                      r"SQLite3?::|Unclosed quotation|ODBC SQL", re.I)
_STACK_ERR = re.compile(r"Traceback \(most recent|Exception in thread|"
                        r"\.java:\d+\)|stack trace|Warning: |Fatal error:", re.I)
_TEMPLATE_ERR = re.compile(r"jinja2|TemplateSyntaxError|freemarker|velocity|"
                           r"twig|ognl|Expression .* evaluated", re.I)

# family → the exploit_class the develop loop will weaponise.
_FAMILY_CLASS = {
    "sqli": "sqli_exfil", "ssti": "ssti", "cmd": "cmd_injection",
    "cmdi": "cmd_injection", "rce": "rce", "ssrf": "ssrf",
    "xxe": "ssrf", "deser": "deserialization", "lfi": "lfi",
    "upload": "file_upload_rce", "auth": "auth_bypass", "jwt": "auth_bypass",
    "redos": "redos", "xss": "xss",
}


def _family(obs: Observation) -> str:
    inp = obs.input
    fam = ""
    if isinstance(inp, dict):
        fam = str(inp.get("family") or inp.get("class") or "")
    return fam.lower() or str(obs.signal.get("family") or "").lower()


def _expected_marker(obs: Observation) -> str:
    inp = obs.input
    if isinstance(inp, dict):
        return str(inp.get("marker") or "")
    return ""


def _cls_for(family: str, default: str) -> str:
    return _FAMILY_CLASS.get(family, default)


def classify(modality: str, baseline: Dict[str, Any], obs: Observation) -> Optional[Anomaly]:
    """Return an Anomaly for an interesting observation, else None.  Pure."""
    modality = (modality or "").lower()
    sig = obs.signal or {}
    base = baseline or {}
    body = obs.raw or str(sig.get("body") or "")

    # ── Binary / native crash signals (modality-agnostic but strongest) ──
    if sig.get("asan") or sig.get("sanitizer"):
        return Anomaly(type="asan", exploit_class="memory_corruption", severity_hint="high",
                       evidence=str(sig.get("asan") or sig.get("sanitizer"))[:400],
                       case_id=obs.case_id, signature=f"asan:{sig.get('stack_hash','')}",
                       detail={"stack_hash": sig.get("stack_hash")})
    if sig.get("crash") or str(sig.get("signal_name") or "").upper() in ("SIGSEGV", "SIGABRT", "SIGBUS"):
        return Anomaly(type="crash", exploit_class="memory_corruption", severity_hint="high",
                       evidence=str(sig.get("signal_name") or "crash"),
                       case_id=obs.case_id, signature=f"crash:{sig.get('stack_hash', obs.case_id)}",
                       detail={"stack_hash": sig.get("stack_hash")})

    if modality in ("web", "api"):
        return _classify_web(base, obs, sig, body)
    if modality == "network":
        return _classify_proto(base, obs, sig)
    if modality == "ai":
        if sig.get("leak") or sig.get("policy_bypass"):
            return Anomaly(type="ai_leak", exploit_class="info", severity_hint="high",
                           evidence=str(sig.get("leak") or "policy bypass")[:400],
                           case_id=obs.case_id, signature=f"ai:{_family(obs)}:{obs.case_id[:8]}")
        return None
    return None


def _classify_web(base, obs, sig, body) -> Optional[Anomaly]:
    fam = _family(obs)
    marker = _expected_marker(obs)
    status = sig.get("status")
    b_status = base.get("status")
    b_len = int(base.get("body_len") or 0)
    cur_len = int(sig.get("body_len") or len(body) or 0)

    # 1) Strongest: the expected evaluation marker came back → input was executed.
    if marker and marker in body:
        cls = _cls_for(fam, "rce")
        return Anomaly(type="reflected_eval", exploit_class=cls, severity_hint="high",
                       evidence=f"payload marker {marker!r} reflected/evaluated in response",
                       case_id=obs.case_id, signature=f"eval:{cls}:{marker}")

    # 2) Server error fingerprints → injection / info-leak surface.
    if _SQL_ERR.search(body):
        return Anomaly(type="sql_error", exploit_class="sqli_exfil", severity_hint="high",
                       evidence="SQL error string leaked by the server",
                       case_id=obs.case_id, signature=f"sqlerr:{obs.case_id[:8]}")
    if _TEMPLATE_ERR.search(body):
        return Anomaly(type="template_error", exploit_class="ssti", severity_hint="high",
                       evidence="template-engine error leaked", case_id=obs.case_id,
                       signature=f"tmplerr:{obs.case_id[:8]}")

    # 3) New 5xx that the baseline did not produce → fault triggered by the input.
    if isinstance(status, int) and status >= 500 and not (isinstance(b_status, int) and b_status >= 500):
        cls = _cls_for(fam, "info")
        return Anomaly(type="http_5xx", exploit_class=cls,
                       severity_hint="medium" if cls != "info" else "low",
                       evidence=f"input triggered HTTP {status} (baseline {b_status})",
                       case_id=obs.case_id, signature=f"5xx:{status}:{fam}")

    # 4) Time-based: latency well above baseline → blind injection / ReDoS.
    lat = float(sig.get("latency") or 0.0)
    b_lat = float(base.get("latency") or 0.0)
    if lat and b_lat and lat > max(2.0, b_lat * 5) and lat > 3.0:
        cls = "redos" if fam == "redos" else _cls_for(fam, "info")
        return Anomaly(type="timeout", exploit_class=cls, severity_hint="medium",
                       evidence=f"response latency {lat:.1f}s vs baseline {b_lat:.1f}s",
                       case_id=obs.case_id, signature=f"time:{cls}")

    # 5) Big response-size delta with a known injection family → worth a look.
    if fam in _FAMILY_CLASS and b_len and cur_len > b_len * 3 and cur_len - b_len > 500:
        cls = _cls_for(fam, "info")
        return Anomaly(type="size_delta", exploit_class=cls, severity_hint="low",
                       evidence=f"response grew {b_len}→{cur_len} bytes for a {fam} payload",
                       case_id=obs.case_id, signature=f"size:{cls}")
    if _STACK_ERR.search(body):
        return Anomaly(type="stack_leak", exploit_class="info", severity_hint="low",
                       evidence="application stack trace leaked", case_id=obs.case_id,
                       signature=f"stack:{obs.case_id[:8]}")
    return None


def _classify_proto(base, obs, sig) -> Optional[Anomaly]:
    # A remote service that resets / hangs / desyncs after a mutated message.
    if sig.get("conn_reset") or sig.get("rst"):
        return Anomaly(type="reset", exploit_class="memory_corruption", severity_hint="high",
                       evidence="service reset the connection after a mutated message",
                       case_id=obs.case_id, signature=f"rst:{obs.case_id[:8]}")
    if sig.get("hang") or sig.get("no_response"):
        return Anomaly(type="hang", exploit_class="dos", severity_hint="medium",
                       evidence="service stopped responding after a mutated message",
                       case_id=obs.case_id, signature=f"hang:{obs.case_id[:8]}")
    if sig.get("desync"):
        return Anomaly(type="desync", exploit_class="memory_corruption", severity_hint="high",
                       evidence="protocol desynchronisation observed", case_id=obs.case_id,
                       signature=f"desync:{obs.case_id[:8]}")
    return None


class AnomalyOracle:
    """Stateful wrapper over ``classify`` that dedups anomalies for one campaign."""

    def __init__(self) -> None:
        self._seen: set = set()

    def classify(self, modality: str, baseline: Dict[str, Any],
                 obs: Observation) -> Optional[Anomaly]:
        a = classify(modality, baseline, obs)
        if a is None:
            return None
        if a.signature in self._seen:
            return None
        self._seen.add(a.signature)
        return a

    @property
    def count(self) -> int:
        return len(self._seen)
