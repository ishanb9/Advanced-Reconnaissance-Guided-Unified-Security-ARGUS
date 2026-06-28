"""agents/fuzzing/proof.py — deterministic, class-specific success oracles (the proof gate).

The research is unambiguous: never trust an LLM's claim that an exploit works — gate on a
REAL oracle (a returned canary, a spawned-file marker, an OOB callback, an over-threshold
timing).  This module owns:

  • a per-campaign canary token (embedded in payloads, looked for in output),
  • an out-of-band (OOB) callback registry — the target calling ARGUS's URL is undeniable
    proof of SSRF / blind RCE,
  • ``oracle_for(exploit_class)`` → the deterministic checker the develop loop runs,
  • ``confirm`` → an INDEPENDENT re-run of the winning PoC (reusing repro_verifier /
    browser_verify) so a one-off fluke isn't reported as proven.

Pure + dependency-light: ``oracle_for`` checkers are synchronous and unit-testable;
``confirm`` is best-effort and never raises.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Dict, Optional

from agents.fuzzing.engines.base import CampaignCtx, PoC, Verdict

logger = logging.getLogger("argus.fuzz.proof")

# ── Canary + OOB callback registry ────────────────────────────────────────────
_OOB: Dict[str, Dict[str, Any]] = {}     # token -> {"hits": int, "last": meta}


def new_canary() -> str:
    return "ARGUSPWN" + uuid.uuid4().hex[:12]


def new_oob_token() -> str:
    return "oob" + uuid.uuid4().hex[:14]


def oob_url(base: str, token: str) -> str:
    base = (base or "").rstrip("/")
    return f"{base}/{token}" if base else f"http://oob.invalid/{token}"


def arm_oob(token: str) -> None:
    _OOB.setdefault(token, {"hits": 0, "last": None})


def mark_oob_hit(token: str, meta: Optional[Dict[str, Any]] = None) -> bool:
    """Called by the OOB HTTP/DNS endpoint when the TARGET calls back.  Returns True if
    the token was armed (a real, expected callback)."""
    rec = _OOB.get(token)
    if rec is None:
        return False
    rec["hits"] += 1
    rec["last"] = meta or {}
    return True


def oob_fired(token: str) -> bool:
    return bool(token) and _OOB.get(token, {}).get("hits", 0) > 0


# ── Deterministic per-class success oracles ───────────────────────────────────
def _canary_hit(out: Dict[str, Any], ctx: CampaignCtx) -> bool:
    text = _text(out)
    return bool(ctx.canary) and ctx.canary in text


def _oob_or_canary(out: Dict[str, Any], ctx: CampaignCtx) -> bool:
    return _canary_hit(out, ctx) or oob_fired(_oob_token(ctx))


def _oracle_rce(out, ctx) -> Verdict:
    if _canary_hit(out, ctx):
        return Verdict(True, "canary", "command output returned the proof canary",
                       _excerpt(out, ctx.canary))
    if oob_fired(_oob_token(ctx)):
        return Verdict(True, "oob", "target made the expected out-of-band callback")
    return Verdict(False, "", "no canary in output and no OOB callback")


def _oracle_sqli(out, ctx) -> Verdict:
    if _canary_hit(out, ctx):
        return Verdict(True, "exfil", "planted secret value was returned in the response",
                       _excerpt(out, ctx.canary))
    return Verdict(False, "", "planted secret not present in the response")


def _oracle_ssrf(out, ctx) -> Verdict:
    if oob_fired(_oob_token(ctx)):
        return Verdict(True, "oob", "target made an outbound request to ARGUS's OOB URL")
    return Verdict(False, "", "no outbound OOB callback observed")


def _oracle_auth(out, ctx) -> Verdict:
    if _canary_hit(out, ctx):
        return Verdict(True, "authed_marker", "reached an authenticated-only marker",
                       _excerpt(out, ctx.canary))
    return Verdict(False, "", "did not reach the authenticated-only marker")


def _oracle_timing(out, ctx) -> Verdict:
    try:
        elapsed = float(out.get("elapsed") or 0.0)
    except (TypeError, ValueError):
        elapsed = 0.0
    if elapsed >= float(out.get("threshold") or 5.0):
        return Verdict(True, "timing", f"response time {elapsed:.1f}s over threshold")
    return Verdict(False, "", f"response time {elapsed:.1f}s under threshold")


def _oracle_memcorrupt(out, ctx) -> Verdict:
    # Only auto-proven by an undeniable controlled-read/shell canary; otherwise a human
    # confirms (memory-corruption weaponisation is human-gated above the ceiling).
    if _canary_hit(out, ctx):
        return Verdict(True, "canary", "controlled read/shell returned the proof canary",
                       _excerpt(out, ctx.canary))
    return Verdict(False, "", "no controlled-read/shell canary — needs human confirmation")


_ORACLES: Dict[str, Callable[[Dict[str, Any], CampaignCtx], Verdict]] = {
    "rce": _oracle_rce,
    "cmd_injection": _oracle_rce,
    "ssti": _oracle_rce,
    "deserialization": _oracle_rce,
    "file_upload_rce": _oracle_rce,
    "lfi": _oracle_rce,
    "sqli_exfil": _oracle_sqli,
    "ssrf": _oracle_ssrf,
    "auth_bypass": _oracle_auth,
    "redos": _oracle_timing,
    "dos": _oracle_timing,
    "memory_corruption": _oracle_memcorrupt,
}


def oracle_for(exploit_class: str) -> Callable[[Dict[str, Any], CampaignCtx], Verdict]:
    """The deterministic success checker for a class.  Unknown class → canary/OOB."""
    return _ORACLES.get(str(exploit_class or "").lower(), _oracle_default)


def _oracle_default(out, ctx) -> Verdict:
    if _oob_or_canary(out, ctx):
        return Verdict(True, "canary/oob", "proof token observed")
    return Verdict(False, "", "no proof token observed")


def check(exploit_class: str, run_output: Dict[str, Any], ctx: CampaignCtx) -> Verdict:
    """Run the class oracle against a PoC's output.  Pure (no I/O)."""
    try:
        return oracle_for(exploit_class)(run_output or {}, ctx)
    except Exception as exc:   # noqa: BLE001
        return Verdict(False, "", f"oracle error: {type(exc).__name__}: {exc}")


# ── Independent confirmation (re-run the winner once) ──────────────────────────
async def confirm(poc: PoC, ctx: CampaignCtx) -> Verdict:
    """Re-run the winning PoC ONCE on an independent pass and re-check the oracle, so a
    fluke is not reported as proven (the Gap-#1 reproduction principle).  For a web PoC,
    a Gap-#2 browser confirmation is attempted as corroboration.  Never raises."""
    if poc is None or ctx.run_poc is None:
        return Verdict(False, "", "no independent runner available")
    try:
        out = await ctx.run_poc(poc)
    except Exception as exc:   # noqa: BLE001
        logger.debug("confirm re-run failed: %s", exc)
        return Verdict(False, "", f"re-run error: {type(exc).__name__}")
    v = check(poc.exploit_class, out if isinstance(out, dict) else {"stdout": str(out)}, ctx)
    if v.proven:
        v.method = (v.method + "+rerun").strip("+")
        v.reason = "independently reproduced: " + v.reason
    return v


# ── helpers ───────────────────────────────────────────────────────────────────
def _text(out: Dict[str, Any]) -> str:
    if not isinstance(out, dict):
        return str(out or "")
    return " ".join(str(out.get(k) or "") for k in ("stdout", "stderr", "body", "output"))


def _excerpt(out: Dict[str, Any], needle: str, span: int = 80) -> str:
    t = _text(out)
    i = t.find(needle) if needle else -1
    if i < 0:
        return t[:160]
    return t[max(0, i - span // 2): i + len(needle) + span // 2]


def _oob_token(ctx: CampaignCtx) -> str:
    # The OOB URL ends in /<token>; recover it for the registry lookup.
    return (ctx.oob_url or "").rstrip("/").rsplit("/", 1)[-1] if ctx.oob_url else ""
