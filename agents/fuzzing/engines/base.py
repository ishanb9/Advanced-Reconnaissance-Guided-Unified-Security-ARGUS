"""agents/fuzzing/engines/base.py — shared types + the FuzzEngine interface.

A fuzz CAMPAIGN drives one target/surface through SELECT→GENERATE→FUZZ→TRIAGE→
DEVELOP→GATE→PROVE→RECORD.  Each modality (live-http, live-proto, binary, ai)
implements ``FuzzEngine``: it owns its mutate→send→observe loop and streams a uniform
``Observation`` to a sink the campaign provides.  Everything here is import-light and
free of heavy deps so the spine + oracle + exploit-dev loop are unit-testable.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional


@dataclass
class Observation:
    """One fuzz case's result, uniform across modalities so the oracle reads one shape."""
    case_id: str
    input: Any                                   # the payload/seed/message that produced it
    signal: Dict[str, Any] = field(default_factory=dict)   # status/latency/body_len/stderr/crash/asan/diff
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"case_id": self.case_id, "input": _short(self.input),
                "signal": self.signal, "raw": self.raw[:600]}


@dataclass
class Anomaly:
    """A triaged interesting result worth trying to weaponise."""
    type: str                                    # http_5xx | reflected_diff | timeout | crash | asan | desync | ai_leak …
    exploit_class: str                           # rce | cmd_injection | sqli_exfil | ssrf | ssti | deserialization |
                                                 # auth_bypass | file_upload_rce | memory_corruption | redos | dos | info
    severity_hint: str = "medium"                # info|low|medium|high|critical
    evidence: str = ""
    case_id: str = ""
    signature: str = ""                          # dedup key (stack-hash / response-signature)
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "exploit_class": self.exploit_class,
                "severity_hint": self.severity_hint, "evidence": self.evidence[:400],
                "case_id": self.case_id, "signature": self.signature, "detail": self.detail}


@dataclass
class PoC:
    """A candidate (or confirmed) custom exploit produced by the develop loop."""
    exploit_class: str
    kind: str                                    # "shell" | "python" | "http" | "payload"
    code: str
    iteration: int = 0
    proven: bool = False
    verdict: Optional[Dict[str, Any]] = None
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"exploit_class": self.exploit_class, "kind": self.kind,
                "code": self.code[:4000], "iteration": self.iteration,
                "proven": self.proven, "verdict": self.verdict,
                "explanation": self.explanation[:600]}


@dataclass
class Verdict:
    """Result of running a deterministic success oracle against a PoC's output."""
    proven: bool
    method: str = ""
    reason: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"proven": self.proven, "method": self.method,
                "reason": self.reason, "evidence": self.evidence[:400]}


@dataclass
class CampaignCtx:
    """Everything an engine / generator / exploit-dev loop needs, threaded in so the
    modules never import MasterAgent.  Callables are best-effort + may be stubs in tests."""
    session_id: str
    target: str
    modality: str                                # web | api | network | binary | ai
    surface: Dict[str, Any] = field(default_factory=dict)
    intel: Dict[str, Any] = field(default_factory=dict)
    ceiling: str = "intrusive"                   # human-selected intrusiveness ceiling
    domain: str = "IT"                           # IT | OT
    authorized: bool = False
    canary: str = ""                             # per-campaign unique proof token
    oob_url: str = ""                            # ARGUS-controlled out-of-band callback URL
    scope_hosts: List[str] = field(default_factory=list)
    # True when a LIVE autonomous scan is running alongside this campaign: the campaign
    # then YIELDS LLM/tool capacity to the engagement (scan gets priority).
    throttle: bool = False
    # Optional pre-computed fuzzability/novel-bug-likelihood (0-100) for the surface,
    # surfaced as the campaign's chance-of-success signal.
    fuzzability: int = 0
    # Best-effort callables (async).  Defaults are no-ops so pure tests need no wiring.
    emit: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None
    llm_generate: Optional[Callable[..., Awaitable[str]]] = None   # tiered fallback upstream
    run_poc: Optional[Callable[[PoC], Awaitable[Dict[str, Any]]]] = None
    run_tool: Optional[Callable[..., Awaitable[Dict[str, Any]]]] = None

    async def emit_event(self, event: str, payload: Dict[str, Any]) -> None:
        if self.emit is None:
            return
        try:
            res = self.emit(event, {"session_id": self.session_id, **payload})
            if hasattr(res, "__await__"):
                await res
        except Exception:
            pass


class FuzzEngine(abc.ABC):
    """A modality's fuzz engine.  Owns its own loop; streams Observations to ``sink``."""
    modality: str = "base"

    def is_available(self) -> "tuple[bool, str]":
        """(ok, reason).  Override to report a missing optional binary cleanly."""
        return True, ""

    @abc.abstractmethod
    async def run(self, ctx: CampaignCtx,
                  sink: Callable[[Observation], Awaitable[None]]) -> None:
        """Mutate → send → observe, calling ``await sink(obs)`` per case.  Must honour
        ctx budgets/stop and never raise out (log + return on error)."""
        raise NotImplementedError


def _short(v: Any, n: int = 300) -> Any:
    try:
        s = v if isinstance(v, str) else repr(v)
        return s[:n]
    except Exception:
        return "<unrepr>"
