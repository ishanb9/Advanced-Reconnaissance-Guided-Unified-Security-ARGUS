"""
resource_governor.py — auto-size ARGUS to the host it runs on.

ARGUS runs on everything from a 2-core / 4 GB Kali VM to a 32-core workstation.
Left un-tuned it uses one set of concurrency defaults everywhere: that OOM-killed
a small VM on a 7-host CIDR run (all hosts triaged at once + the CPU RAG reranker),
while leaving a big box slower than it needs to be.

This module fixes both ends with two cooperating parts:

  1. ``autotune()`` — called ONCE at server boot.  Detects CPU cores, RAM, GPU and
     the LLM backend tier, computes a right-sized profile, and writes the values
     into the EXISTING concurrency env knobs via ``os.environ.setdefault`` (so any
     value the operator set by hand ALWAYS wins).  Small boxes scale DOWN (no OOM);
     big boxes scale UP past the stock defaults (no artificial slowness) — but never
     past what the LLM backend can serve (a single local Ollama serialises, so more
     parallel hosts than it can answer just produces 429s, not speed).

  2. ``MemoryWatchdog`` — a lightweight async task that samples free RAM and, when it
     drops below a floor, CLEARS an admission gate so no NEW host slot is taken until
     memory recovers (hysteresis).  In-flight hosts finish and free memory; new ones
     wait.  This catches load that accumulates unpredictably mid-scan.

Everything is additive and best-effort: if psutil is missing it falls back to
``/proc/meminfo`` and then to a conservative assumption; if detection fails the
stock defaults stand.  Nothing here ever raises into a scan.

Env overrides
-------------
- ``ARGUS_PERF_PROFILE`` = ``auto`` (default) | ``constrained`` | ``balanced`` | ``performance``
- ``ARGUS_LLM_CEILING``  = force the LLM concurrency ceiling (int)
- ``ARGUS_MEM_FLOOR_PCT`` / ``ARGUS_MEM_RELEASE_PCT`` = watchdog thresholds
- any concurrency knob set by hand (``ARGUS_CIDR_TRIAGE_PARALLEL`` etc.) is preserved
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Mirror of cidr_orchestrator.MAX_LIVE_HOSTS — hard ceiling on parallel hosts.
_MAX_HOSTS = 64
# Env knobs the governor sizes (all already consumed elsewhere in the codebase).
_KNOB_TRIAGE   = "ARGUS_CIDR_TRIAGE_PARALLEL"
_KNOB_EXPLOIT  = "ARGUS_CIDR_EXPLOIT_PARALLEL"
_KNOB_HOSTS    = "ARGUS_MAX_PARALLEL_HOSTS"        # governor's recommended default host cap
_KNOB_FUZZDEV  = "ARGUS_FUZZ_MAX_CONCURRENT_DEVELOP"
_KNOB_METAADV  = "ARGUS_META_MAX_ADVISORY"
_KNOB_RERANK   = "KB_RERANK_MODEL"                 # "" disables the cross-encoder reranker

_SNAPSHOT: Dict[str, Any] = {}                     # last autotune result (for /status)


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(v)))


# ──────────────────────────────────────────────────────────────────────────
#  Detection (best-effort, never raises)
# ──────────────────────────────────────────────────────────────────────────

def _cpu_cores() -> int:
    try:
        return max(1, int(os.cpu_count() or 1))
    except Exception:
        return 1


def _mem_gb() -> tuple[float, float, str]:
    """Return (total_gb, available_gb, source).  psutil → /proc/meminfo → assumed."""
    try:
        import psutil  # type: ignore
        vm = psutil.virtual_memory()
        return vm.total / 1e9, vm.available / 1e9, "psutil"
    except Exception:
        pass
    try:
        info: Dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                k, _, rest = line.partition(":")
                info[k.strip()] = int(rest.strip().split()[0])   # value is in kB
        total = info.get("MemTotal", 0) / 1e6                     # kB → GB
        avail = info.get("MemAvailable", info.get("MemFree", 0)) / 1e6
        if total > 0:
            return total, (avail or total * 0.5), "proc"
    except Exception:
        pass
    # Unknown host → assume constrained so we never OOM a box we can't measure.
    return 4.0, 2.0, "assumed"


def _avail_pct() -> Optional[float]:
    """Live available-RAM percentage for the watchdog, or None if unmeasurable."""
    try:
        import psutil  # type: ignore
        vm = psutil.virtual_memory()
        return 100.0 * vm.available / vm.total if vm.total else None
    except Exception:
        pass
    try:
        info: Dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                k, _, rest = line.partition(":")
                info[k.strip()] = int(rest.strip().split()[0])
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        return 100.0 * avail / total if total else None
    except Exception:
        return None


def _gpu_present() -> bool:
    try:
        if shutil.which("nvidia-smi"):
            return True
        if os.path.exists("/proc/driver/nvidia/version"):
            return True
    except Exception:
        pass
    return False


def _llm_ceiling(provider_name: Optional[str]) -> int:
    """Max concurrent hosts/agents the LLM backend can actually serve.

    A single local model (Ollama) serialises requests → a low ceiling (more
    parallel hosts than it can answer just produces 429s).  A hosted API tolerates
    high concurrency.  ``ARGUS_LLM_CEILING`` overrides everything.
    """
    env = os.environ.get("ARGUS_LLM_CEILING")
    if env:
        try:
            return max(1, int(env))
        except Exception:
            pass
    name = (provider_name or os.environ.get("LLM_PROVIDER", "") or "").strip().lower()
    if "ollama" in name or name in ("local", "localhost", "lmstudio", "openai-compat"):
        return 3
    if name in ("anthropic", "claude", "claude-code", "openai", "gemini", "google"):
        return 16
    # auto / unknown — infer from configured hosted keys.
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY") \
            or os.environ.get("GEMINI_API_KEY") or os.environ.get("CLAUDE_CODE"):
        return 16
    return 6


def detect_resources(provider_name: Optional[str] = None) -> Dict[str, Any]:
    total, avail, source = _mem_gb()
    return {
        "cores":        _cpu_cores(),
        "mem_total_gb": round(total, 1),
        "mem_avail_gb": round(avail, 1),
        "mem_source":   source,
        "gpu":          _gpu_present(),
        "llm_ceiling":  _llm_ceiling(provider_name),
        "llm_provider": (provider_name or os.environ.get("LLM_PROVIDER", "") or "unknown"),
    }


# ──────────────────────────────────────────────────────────────────────────
#  Profile computation
# ──────────────────────────────────────────────────────────────────────────

def _label(cores: int, mem: float) -> str:
    if cores <= 2 or mem < 4.0:
        return "constrained"
    if cores >= 8 and mem >= 16.0:
        return "performance"
    return "balanced"


def compute_profile(res: Dict[str, Any], override: Optional[str] = None) -> Dict[str, Any]:
    """Map detected resources → concrete concurrency values.

    ``override`` forces a band (constrained/balanced/performance); ``None`` = auto
    (continuous scaling from cores + RAM).  In ALL cases the host/agent parallelism
    is capped by the LLM backend ceiling so we never out-run the model.
    """
    cores = max(1, int(res.get("cores", 1)))
    mem   = float(res.get("mem_avail_gb") or res.get("mem_total_gb") or 4.0)
    llm   = max(1, int(res.get("llm_ceiling", 6)))
    gpu   = bool(res.get("gpu"))

    if override == "constrained":
        triage, exploit, rerank = 2, 1, False
    elif override == "performance":
        triage, exploit, rerank = min(cores, 16), min(max(1, cores // 2), 12), True
    elif override == "balanced":
        triage, exploit, rerank = min(cores, 6), min(max(1, cores // 2), 4), (mem >= 6.0)
    else:  # auto — scale continuously from hardware
        triage  = min(cores, int(mem // 1.5))
        exploit = min(max(1, cores // 2), int(mem // 3))
        rerank  = (mem >= 6.0) or gpu

    # LLM backend ceiling caps host/agent parallelism regardless of hardware.
    triage  = _clamp(min(triage,  llm), 1, 24)
    exploit = _clamp(min(exploit, llm), 1, 16)
    hosts   = _clamp(min(exploit, llm), 1, 16)

    values = {
        _KNOB_TRIAGE:  triage,
        _KNOB_EXPLOIT: exploit,
        _KNOB_HOSTS:   hosts,
        _KNOB_FUZZDEV: _clamp(min(2, exploit), 1, 4),
        _KNOB_METAADV: _clamp(exploit + 1, 2, 8),
        "rerank_on":   rerank,
    }
    return {
        "label":  override or _label(cores, mem),
        "values": values,
    }


# [48] Knobs the governor auto-set via setdefault (i.e. the human/CI did NOT set
# them).  Consumers can distinguish "governor picked this" from "an operator/CI
# override is present" so a UI slider isn't silently shadowed by the autotune value.
_AUTOSET: set = set()


def was_autoset(knob: str) -> bool:
    """True when `knob` in the environment came from the governor's setdefault
    (not a human/CI export).  Used so an operator slider can override the
    governor's default without a real env override losing."""
    return knob in _AUTOSET


def apply_profile(prof: Dict[str, Any]) -> Dict[str, Any]:
    """Write the profile into env via setdefault — any hand-set value WINS."""
    v = prof.get("values", {})
    for knob in (_KNOB_TRIAGE, _KNOB_EXPLOIT, _KNOB_HOSTS, _KNOB_FUZZDEV, _KNOB_METAADV):
        try:
            if knob not in os.environ:          # governor is about to fill it in
                _AUTOSET.add(knob)
            os.environ.setdefault(knob, str(v[knob]))
        except Exception:
            pass
    # Disable the CPU cross-encoder reranker on constrained boxes (the 64 s/batch hog).
    if not v.get("rerank_on", True):
        os.environ.setdefault(_KNOB_RERANK, "")
    return prof


# ──────────────────────────────────────────────────────────────────────────
#  Public: autotune + snapshot
# ──────────────────────────────────────────────────────────────────────────

def autotune(provider_name: Optional[str] = None) -> Dict[str, Any]:
    """Detect resources, compute + apply a profile.  Idempotent, never raises."""
    global _SNAPSHOT
    try:
        res = detect_resources(provider_name)
        override = (os.environ.get("ARGUS_PERF_PROFILE", "auto") or "auto").strip().lower()
        if override not in ("auto", "constrained", "balanced", "performance"):
            override = "auto"
        prof = compute_profile(res, None if override == "auto" else override)
        apply_profile(prof)
        _SNAPSHOT = {
            "label":     prof["label"],
            "override":  override,
            "resources": res,
            "applied":   {k: os.environ.get(k) for k in
                          (_KNOB_TRIAGE, _KNOB_EXPLOIT, _KNOB_HOSTS, _KNOB_FUZZDEV, _KNOB_METAADV)},
            "reranker":  "on" if prof["values"].get("rerank_on", True)
                         and os.environ.get(_KNOB_RERANK, "x") != "" else "off",
        }
        logger.info(
            "[resource-governor] %s — %sc / %.1fGB avail / llm-cap=%s / gpu=%s → "
            "hosts=%s triage=%s exploit=%s reranker=%s",
            _SNAPSHOT["label"], res["cores"], res["mem_avail_gb"], res["llm_ceiling"],
            res["gpu"], _SNAPSHOT["applied"][_KNOB_HOSTS], _SNAPSHOT["applied"][_KNOB_TRIAGE],
            _SNAPSHOT["applied"][_KNOB_EXPLOIT], _SNAPSHOT["reranker"],
        )
    except Exception as exc:   # noqa: BLE001
        logger.warning("[resource-governor] autotune failed (%s) — stock defaults stand", exc)
    return _SNAPSHOT


def snapshot() -> Dict[str, Any]:
    """Last autotune result — for /status and diagnostics."""
    return dict(_SNAPSHOT)


def recommended_hosts(default: int = 5) -> int:
    """The governor's recommended max_parallel_hosts (from the applied env), for
    agent_server to use as the request default instead of a hardcoded constant."""
    try:
        return max(1, int(os.environ.get(_KNOB_HOSTS, str(default))))
    except Exception:
        return default


# ──────────────────────────────────────────────────────────────────────────
#  Live memory watchdog — pauses NEW host admission under RAM pressure
# ──────────────────────────────────────────────────────────────────────────

_admit: Optional[asyncio.Event] = None
_watchdog: Optional["MemoryWatchdog"] = None
_pressure: bool = False


def _admit_event() -> asyncio.Event:
    global _admit
    if _admit is None:
        _admit = asyncio.Event()
        _admit.set()          # default: admission open
    return _admit


def admit_open() -> bool:
    """True when new host slots may be taken (False while under RAM pressure)."""
    return _admit_event().is_set()


def under_pressure() -> bool:
    return _pressure


async def wait_for_admission(max_wait: float = 120.0) -> None:
    """Block until admission is open (RAM recovered), or ``max_wait`` elapses.

    A no-op when no watchdog is running (the gate defaults to open).  The cap
    guarantees a scan can never hang forever if memory stays low for external
    reasons — after it, we proceed and let the per-host budgets apply.
    """
    ev = _admit_event()
    if ev.is_set():
        return
    try:
        await asyncio.wait_for(ev.wait(), timeout=max(1.0, float(max_wait)))
    except asyncio.TimeoutError:
        logger.warning("[resource-governor] admission still gated after %.0fs — proceeding", max_wait)


class MemoryWatchdog:
    """Samples free RAM; clears the admission gate under pressure (with hysteresis)."""

    def __init__(self, floor_pct: float = 12.0, release_pct: float = 25.0,
                 interval: float = 5.0) -> None:
        self.floor_pct   = float(os.environ.get("ARGUS_MEM_FLOOR_PCT", floor_pct))
        self.release_pct = float(os.environ.get("ARGUS_MEM_RELEASE_PCT", release_pct))
        self.interval    = max(0.02, float(interval))   # default 5s; floor allows fast sampling/tests
        self._stop       = False
        self._task: Optional[asyncio.Task] = None

    async def _loop(self) -> None:
        global _pressure
        ev = _admit_event()
        while not self._stop:
            avail = _avail_pct()
            if avail is not None:
                if ev.is_set() and avail < self.floor_pct:
                    ev.clear(); _pressure = True
                    logger.warning("[resource-governor] RAM pressure — %.0f%% free < %.0f%%; "
                                   "pausing NEW host admission", avail, self.floor_pct)
                elif (not ev.is_set()) and avail >= self.release_pct:
                    ev.set(); _pressure = False
                    logger.info("[resource-governor] RAM recovered — %.0f%% free; resuming host admission",
                                avail)
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break

    def start(self) -> None:
        _admit_event().set()
        if self._task is None:
            self._task = asyncio.ensure_future(self._loop())

    async def stop(self) -> None:
        self._stop = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass
            self._task = None


def start_watchdog() -> None:
    """Start the RAM watchdog (idempotent).  Safe to call at server startup."""
    global _watchdog
    if _watchdog is None:
        _watchdog = MemoryWatchdog()
    try:
        _watchdog.start()
    except Exception as exc:   # noqa: BLE001
        logger.warning("[resource-governor] watchdog start failed: %s", exc)


async def stop_watchdog() -> None:
    global _watchdog
    if _watchdog is not None:
        await _watchdog.stop()
