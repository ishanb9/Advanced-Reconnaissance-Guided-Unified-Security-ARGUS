"""agents/fuzzing/triage.py — the TRIAGE-PLUS sub-stage (modality-general, enrich-only).

After the oracle hands the campaign an ``Anomaly``, this stage enriches the finding
with three *pure, deterministic* signals — no LLM, no network, never blocks or drops:

1. **Dedup.**  A stable ``stack_hash`` (the anomaly's own ``signature``, or a casr stack
   hash of the re-run output when ``casr-cluster``/``casr-san`` is on PATH — best-effort,
   ``shutil.which`` guarded) is recorded in the on-disk :class:`knowledge.crash_ledger.CrashLedger`;
   we learn whether this crash has been ``seen`` before and which ``cluster_id`` it belongs to.

2. **Exploitability band.**  A small, defensible lookup table maps the sanitizer class
   (parsed from the anomaly detail / re-run output) and the higher-level ``exploit_class``
   to one of ``probable | likely | unlikely | unknown`` — a triage hint, never a claim.

3. **Novelty correlation.**  ``knowledge.novelty_check.assess(component, version, exploit_class)``
   correlates against an OFFLINE corpus (ExploitDB / known-CVE / local-NVD) so ARGUS can
   honestly flag a *candidate*-novel bug — it never auto-asserts "0-day".

The result is a :class:`CrashTriage`; the caller merges ``to_dict()`` into the finding as
optional keys.  Every external call is wrapped: on ANY error this returns a default
``CrashTriage`` rather than raising — a triage failure must never lose a real finding.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from agents.fuzzing.engines.base import Anomaly, CampaignCtx

logger = logging.getLogger("argus.fuzz.triage")

# Hard wall-clock ceiling for the optional casr helper so a wedged binary can't hang triage.
_CASR_TIMEOUT = int(os.environ.get("ARGUS_TRIAGE_CASR_SEC", "15"))


# ──────────────────────────────────────────────────────────────────────────────
# Exploitability table — sanitizer class / exploit_class → band.  Defensible,
# conservative hints only; weaponisation stays human-gated upstream.
# ──────────────────────────────────────────────────────────────────────────────
# Memory-safety sanitizer classes (parsed from ASan/QASan/UBSan output).
_SANITIZER_BAND: Dict[str, str] = {
    "heap-buffer-overflow-write": "probable",
    "heap-use-after-free": "probable",
    "double-free": "probable",
    "heap-buffer-overflow-read": "likely",
    "global-buffer-overflow": "likely",
    "stack-buffer-overflow": "likely",
    "segv": "likely",
}

# Non-memory exploit classes (web / proto / logic).
_CLASS_BAND: Dict[str, str] = {
    "rce": "probable",
    "cmd_injection": "probable",
    "sqli_exfil": "likely",
    "deserialization": "likely",
    "file_upload_rce": "likely",
    "ssrf": "likely",
    "ssti": "likely",
    "auth_bypass": "likely",
    "redos": "unlikely",
    "dos": "unlikely",
    "info": "unlikely",
}

# Sanitizer fingerprints → canonical class key.  Order matters: WRITE before the
# generic heap-buffer-overflow so a directional overflow lands in the right band.
_SAN_PATTERNS: List[tuple[str, str]] = [
    ("heap-use-after-free", "heap-use-after-free"),
    ("double-free", "double-free"),
    ("global-buffer-overflow", "global-buffer-overflow"),
    ("stack-buffer-overflow", "stack-buffer-overflow"),
    ("stack-overflow", "stack-buffer-overflow"),
]


@dataclass
class CrashTriage:
    """Enrichment for one anomaly: dedup + exploitability + novelty.  All optional;
    the caller merges :meth:`to_dict` into the finding without ever dropping it."""
    cluster_id: str = ""
    is_duplicate: bool = False
    exploitability: str = "unknown"      # probable | likely | unlikely | unknown
    novelty_label: str = "undetermined"  # known-nday | no-known-public-match | undetermined
    novelty_evidence: str = ""
    component: str = ""
    version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "is_duplicate": self.is_duplicate,
            "exploitability": self.exploitability,
            "novelty_label": self.novelty_label,
            "novelty_evidence": self.novelty_evidence,
            "component": self.component,
            "version": self.version,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Sanitizer-class derivation
# ──────────────────────────────────────────────────────────────────────────────
def _sanitizer_class(anomaly: Anomaly, run_output: str) -> str:
    """Best-effort canonical sanitizer class from the anomaly detail + re-run output.

    Distinguishes heap-buffer-overflow WRITE (probable) from READ (likely) when the
    sanitizer reports the access direction; otherwise falls back to the generic key.
    Returns "" when no memory-safety fingerprint is present.
    """
    parts: List[str] = []
    try:
        detail = anomaly.detail if isinstance(anomaly.detail, dict) else {}
        for v in detail.values():
            if isinstance(v, str):
                parts.append(v)
        parts.append(str(anomaly.type or ""))
        parts.append(str(anomaly.evidence or ""))
    except Exception:   # noqa: BLE001 — defensive: a weird anomaly must not break triage
        pass
    parts.append(run_output or "")
    blob = " ".join(parts).lower()

    for needle, key in _SAN_PATTERNS:
        if needle in blob:
            return key

    if "heap-buffer-overflow" in blob:
        # Directional overflow → READ is likely, WRITE is probable.
        if "write of size" in blob or "wild write" in blob:
            return "heap-buffer-overflow-write"
        if "read of size" in blob:
            return "heap-buffer-overflow-read"
        # Unknown direction: treat as the (more conservative) READ band.
        return "heap-buffer-overflow-read"

    if "sigsegv" in blob or "segv" in blob or "segmentation fault" in blob:
        return "segv"
    return ""


def _exploitability(anomaly: Anomaly, run_output: str) -> str:
    """Map sanitizer class (preferred) then exploit_class to an exploitability band."""
    san = _sanitizer_class(anomaly, run_output)
    if san and san in _SANITIZER_BAND:
        return _SANITIZER_BAND[san]
    cls = str(getattr(anomaly, "exploit_class", "") or "").lower()
    if cls in _CLASS_BAND:
        return _CLASS_BAND[cls]
    return "unknown"


# ──────────────────────────────────────────────────────────────────────────────
# casr stack hash (optional, best-effort, guarded)
# ──────────────────────────────────────────────────────────────────────────────
def _casr_stack_hash(run_output: str) -> str:
    """Derive a casr stack hash from re-run output when casr is on PATH.

    Best-effort: pipes the sanitizer report to ``casr-san``/``casr-cluster`` and pulls a
    cluster/hash token out of its JSON.  Any missing binary / parse error → "" (the
    caller then falls back to the anomaly signature).  Never raises.
    """
    if not run_output:
        return ""
    tool = shutil.which("casr-san") or shutil.which("casr-cluster")
    if not tool:
        return ""
    try:
        proc = subprocess.run(            # noqa: S603 — argv list, no shell
            [tool, "--stdout"],
            input=run_output.encode("utf-8", "replace"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=_CASR_TIMEOUT,
        )
        out = proc.stdout.decode("utf-8", "replace").strip()
        if not out:
            return ""
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                for k in ("ClusterHash", "CrashlineHash", "StackTraceHash",
                          "cluster_hash", "stack_hash", "Hash"):
                    v = data.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()[:24]
        except Exception:   # noqa: BLE001 — non-JSON output: hash the report ourselves
            pass
        # Fallback: a stable digest of casr's normalised report.
        import hashlib
        return "casr:" + hashlib.sha1(out.encode("utf-8", "replace")).hexdigest()[:16]
    except Exception as exc:   # noqa: BLE001
        logger.debug("casr stack hash failed: %s", exc)
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# Component / version derivation from the surface or intel fingerprint
# ──────────────────────────────────────────────────────────────────────────────
def _component_version(ctx: CampaignCtx) -> tuple[str, str]:
    """Resolve (component, version) from ctx.surface, else the intel fingerprint.

    Prefers explicit surface keys; falls back to the target binary basename and any
    fingerprint product/version the recon stage left in ctx.intel.  Best-effort.
    """
    component = ""
    version = ""
    try:
        surface = ctx.surface if isinstance(ctx.surface, dict) else {}
        component = str(surface.get("component") or "").strip()
        version = str(surface.get("version") or "").strip()
        if not component:
            for key in ("binary", "binary_path", "source_path", "target"):
                val = surface.get(key)
                if isinstance(val, str) and val.strip():
                    component = os.path.basename(val.strip().rstrip("/\\"))
                    break
    except Exception:   # noqa: BLE001
        pass

    if not component or not version:
        try:
            intel = ctx.intel if isinstance(ctx.intel, dict) else {}
            fp = intel.get("fingerprint")
            fp = fp if isinstance(fp, dict) else intel
            if isinstance(fp, dict):
                if not component:
                    component = str(fp.get("product") or fp.get("component")
                                    or fp.get("name") or "").strip()
                if not version:
                    version = str(fp.get("version") or fp.get("product_version")
                                  or "").strip()
        except Exception:   # noqa: BLE001
            pass

    if not component:
        try:
            component = os.path.basename(str(ctx.target or "").strip().rstrip("/\\"))
        except Exception:   # noqa: BLE001
            component = ""
    return component, version


# ──────────────────────────────────────────────────────────────────────────────
# Optional-dependency helpers — crash_ledger / novelty_check are sibling slices and
# may be absent; importing them lazily keeps this module pure-additive and safe.
# ──────────────────────────────────────────────────────────────────────────────
def _make_ledger():
    try:
        from knowledge.crash_ledger import CrashLedger
        return CrashLedger()
    except Exception as exc:   # noqa: BLE001
        logger.debug("crash_ledger unavailable: %s", exc)
        return None


def _novelty(component: str, version: str, exploit_class: str) -> tuple[str, str]:
    try:
        from knowledge import novelty_check
        res = novelty_check.assess(component, version, exploit_class)
        if isinstance(res, dict):
            label = str(res.get("label") or "undetermined")
            evidence = str(res.get("evidence") or "")
            return label, evidence
    except Exception as exc:   # noqa: BLE001
        logger.debug("novelty_check unavailable: %s", exc)
    return "undetermined", ""


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────
def triage_crash(anomaly: Anomaly, ctx: CampaignCtx, run_output: str = "",
                 *, ledger=None) -> CrashTriage:
    """Enrich ``anomaly`` with dedup + exploitability + novelty.  Pure/deterministic,
    no LLM, never raises.  Returns a :class:`CrashTriage`; the caller merges
    :meth:`CrashTriage.to_dict` into the finding as optional keys and NEVER drops it.

    Args:
        anomaly: the triaged result from the oracle (``signature`` is the dedup key).
        ctx: the campaign context (``surface`` / ``intel`` supply component/version).
        run_output: best-effort re-run / sanitizer text used for casr + sanitizer class.
        ledger: an injectable :class:`knowledge.crash_ledger.CrashLedger`
            (default: a fresh on-disk ledger).
    """
    try:
        target = str(getattr(ctx, "target", "") or "")

        # (1) Dedup — stable stack hash, then record into the ledger.
        stack_hash = str(getattr(anomaly, "signature", "") or "")
        if not stack_hash:
            stack_hash = _casr_stack_hash(run_output)
        else:
            casr = _casr_stack_hash(run_output)
            if casr:
                stack_hash = casr
        if not stack_hash:
            stack_hash = str(getattr(anomaly, "case_id", "") or "") or "unknown"

        # (2) Exploitability band.
        exploitability = _exploitability(anomaly, run_output)

        # (3) Component / version.
        component, version = _component_version(ctx)

        # (4) Novelty correlation (offline).
        exploit_class = str(getattr(anomaly, "exploit_class", "") or "")
        novelty_label, novelty_evidence = _novelty(component, version, exploit_class)

        # Ledger dedup/record (best-effort; absent ledger → no dedup signal).
        cluster_id = ""
        is_duplicate = False
        led = ledger or _make_ledger()
        if led is not None:
            try:
                is_duplicate = bool(led.seen(target, stack_hash))
            except Exception as exc:   # noqa: BLE001
                logger.debug("ledger.seen failed: %s", exc)
                is_duplicate = False
            try:
                cluster_id = str(led.record(target, stack_hash, {
                    "exploit_class": exploit_class,
                    "exploitability": exploitability,
                    "component": component,
                    "version": version,
                    "type": str(getattr(anomaly, "type", "") or ""),
                }) or "")
            except Exception as exc:   # noqa: BLE001
                logger.debug("ledger.record failed: %s", exc)
                cluster_id = ""

        return CrashTriage(
            cluster_id=cluster_id,
            is_duplicate=is_duplicate,
            exploitability=exploitability,
            novelty_label=novelty_label,
            novelty_evidence=novelty_evidence,
            component=component,
            version=version,
        )
    except Exception as exc:   # noqa: BLE001 — triage must never lose a finding
        logger.debug("triage_crash failed, returning default: %s", exc)
        return CrashTriage()
