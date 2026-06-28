"""agents/fuzzing/campaign.py — the Fuzz Campaign spine.

Drives one target/surface through SELECT→GENERATE→FUZZ→TRIAGE→DEVELOP→GATE→PROVE→RECORD
as its own asyncio task (parallel, never blocks the engagement loop).  Each stage emits a
WS event and fails soft: a stage error degrades to recording an UNVERIFIED anomaly, never
a crash.  The ceiling-driven gate auto-proves at/below the human ceiling and asks for an
approval card above it (memory-corruption, destructive, OT/life-safety).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

from agents.fuzzing import exploit_dev as _xdev
from agents.fuzzing import oracle as _oracle
from agents.fuzzing import payloadgen as _payloadgen
from agents.fuzzing import proof as _proof
from agents.fuzzing.engines.base import Anomaly, CampaignCtx, Observation, PoC

logger = logging.getLogger("argus.fuzz.campaign")

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MAX_DEVELOP = int(os.environ.get("ARGUS_FUZZ_MAX_DEVELOP", "3"))   # anomalies to weaponise/run
#: Global ceiling on concurrent exploit-DEVELOP work across ALL campaigns, so several
#: parallel campaigns can't thrash the shared LLM provider.  Lazily bound to the loop.
_MAX_CONCURRENT_DEVELOP = int(os.environ.get("ARGUS_FUZZ_MAX_CONCURRENT_DEVELOP", "2"))
_develop_sem = None


def _develop_semaphore():
    global _develop_sem
    if _develop_sem is None:
        _develop_sem = asyncio.Semaphore(_MAX_CONCURRENT_DEVELOP)
    return _develop_sem


# ── Ceiling-driven gate (the human's decision: auto below, approval above) ─────
#: intrusiveness of weaponising each class, on the skill_registry scale
#: (safe < intrusive < disruptive).  At the default "intrusive" ceiling, the active
#: exploit classes auto-prove; the disruptive ones (could crash the service) need a card.
_CLASS_INTRUSIVENESS = {
    "info": "safe",
    "sqli_exfil": "intrusive", "ssrf": "intrusive", "auth_bypass": "intrusive",
    "redos": "intrusive", "lfi": "intrusive", "ssti": "intrusive",
    "cmd_injection": "intrusive", "rce": "intrusive", "deserialization": "intrusive",
    "file_upload_rce": "intrusive", "xss": "intrusive",
    "dos": "disruptive", "memory_corruption": "disruptive",
}


def needs_approval(exploit_class: str, ctx: CampaignCtx) -> bool:
    """True when PROVING this class must pause for a human approval card."""
    cls = (exploit_class or "").lower()
    if cls == "memory_corruption":
        return True                                  # weaponisation is always human-gated
    if (ctx.domain or "IT").upper() == "OT" and not ctx.authorized:
        return True                                  # safe-by-default for OT
    intr = _CLASS_INTRUSIVENESS.get(cls, "intrusive")
    try:
        from knowledge.skill_registry import allowed
        return not allowed(intr, ctx.ceiling or "intrusive", ctx.domain or "IT",
                           False, ctx.authorized)
    except Exception:
        return intr in ("intrusive", "disruptive") and (ctx.ceiling or "intrusive") == "safe"


def rank_anomalies(anomalies: List[Anomaly]) -> List[Anomaly]:
    """Most-exploitable first: by severity hint, then prefer classes with a clean oracle."""
    def key(a: Anomaly):
        has_oracle = a.exploit_class in (
            "rce", "cmd_injection", "sqli_exfil", "ssrf", "ssti", "auth_bypass",
            "deserialization", "file_upload_rce")
        return (_SEV_RANK.get(a.severity_hint, 0), 1 if has_oracle else 0)
    return sorted(anomalies, key=key, reverse=True)


class FuzzCampaign:
    def __init__(self, *, job_id: str, ctx: CampaignCtx, engine: Any,
                 on_finding: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
                 max_sec: int = 1800) -> None:
        self.job_id = job_id
        self.ctx = ctx
        self.engine = engine
        self._on_finding = on_finding
        self.max_sec = max_sec
        self._stop = False
        self.status = "pending"
        self.started = 0.0
        self.baseline: Dict[str, Any] = {}
        self.anomalies: List[Anomaly] = []
        self.findings: List[Dict[str, Any]] = []
        self._oracle = _oracle.AnomalyOracle()

    def stop(self) -> None:
        self._stop = True

    async def _stage(self, name: str, **extra) -> None:
        await self.ctx.emit_event("fuzz_campaign_stage",
                                  {"job_id": self.job_id, "stage": name, "target": self.ctx.target,
                                   "modality": self.ctx.modality, **extra})

    async def run(self) -> Dict[str, Any]:
        self.started = time.time()
        self.status = "running"
        if not self.ctx.canary:
            self.ctx.canary = _proof.new_canary()
        try:
            ok, why = self.engine.is_available()
            if not ok:
                self.status = "unavailable"
                await self._stage("error", message=f"engine unavailable: {why}")
                return self.snapshot()

            await self._stage("select", surface=self.ctx.surface)
            await self._stage("generate")
            payloads = await _payloadgen.generate(self.ctx)
            self.ctx.surface.setdefault("payloads", payloads)

            await self._stage("fuzz", payloads=len(payloads))
            await self._fuzz(payloads)

            await self._stage("triage", anomalies=len(self.anomalies))
            ranked = rank_anomalies(self.anomalies)[:_MAX_DEVELOP]

            for anomaly in ranked:
                if self._stop or self._expired():
                    break
                await self._develop_and_prove(anomaly)

            self.status = "done"
        except Exception as exc:   # noqa: BLE001
            self.status = "error"
            logger.warning("campaign %s failed: %s", self.job_id, exc)
            await self._stage("error", message=f"{type(exc).__name__}: {exc}")
        await self._stage("record", findings=len(self.findings))
        return self.snapshot()

    async def _fuzz(self, payloads: List[Dict[str, Any]]) -> None:
        async def sink(obs: Observation) -> None:
            if obs.signal.get("baseline"):
                self.baseline = obs.signal
                return
            anomaly = self._oracle.classify(self.ctx.modality, self.baseline, obs)
            if anomaly is not None:
                self.anomalies.append(anomaly)
                await self.ctx.emit_event("fuzz_anomaly",
                                          {"job_id": self.job_id, **anomaly.to_dict()})
        self.ctx.surface["payloads"] = payloads
        try:
            await asyncio.wait_for(self.engine.run(self.ctx, sink),
                                   timeout=max(30, self.max_sec))
        except asyncio.TimeoutError:
            logger.debug("engine run hit the campaign wall-clock for %s", self.job_id)
        except Exception as exc:   # noqa: BLE001
            logger.debug("engine run error for %s: %s", self.job_id, exc)

    async def _develop_and_prove(self, anomaly: Anomaly) -> None:
        await self._stage("develop", exploit_class=anomaly.exploit_class,
                          anomaly_type=anomaly.type)
        poc: Optional[PoC] = None
        try:
            async with _develop_semaphore():          # bound LLM concurrency across campaigns
                poc = await _xdev.develop(anomaly, self.ctx)
        except Exception as exc:   # noqa: BLE001
            logger.debug("develop failed: %s", exc)

        if poc is None:
            # No proven exploit — still record the anomaly honestly (unverified).
            await self._record(anomaly, poc=None, proven=False,
                               note="anomaly detected; no proven exploit developed")
            return

        gate = needs_approval(anomaly.exploit_class, self.ctx)
        await self._stage("gate", exploit_class=anomaly.exploit_class,
                          decision="approval" if gate else "auto")
        if gate:
            await self.ctx.emit_event("fuzz_approval_request", {
                "job_id": self.job_id, "exploit_class": anomaly.exploit_class,
                "target": self.ctx.target, "poc": poc.to_dict(),
                "reason": "weaponisation above the intrusiveness ceiling — human approval required"})
            await self._record(anomaly, poc=poc, proven=False,
                               note="custom PoC developed; PROOF pending human approval "
                                    "(above intrusiveness ceiling)")
            return

        await self._stage("prove", exploit_class=anomaly.exploit_class)
        verdict = await _proof.confirm(poc, self.ctx)
        await self.ctx.emit_event("proof_verdict", {
            "job_id": self.job_id, "exploit_class": anomaly.exploit_class, **verdict.to_dict()})
        poc.proven = bool(verdict.proven)
        await self._record(anomaly, poc=poc, proven=bool(verdict.proven),
                           note=verdict.reason)

    async def _record(self, anomaly: Anomaly, *, poc: Optional[PoC], proven: bool,
                      note: str) -> None:
        sev = "high" if proven else anomaly.severity_hint
        finding = {
            "title": (f"Custom exploit ({anomaly.exploit_class}) PROVEN via fuzzing"
                      if proven else f"Fuzzing anomaly ({anomaly.exploit_class}) on {self.ctx.target}"),
            "description": (f"Fuzz campaign on {self.ctx.target} surfaced a "
                            f"{anomaly.type} anomaly ({anomaly.exploit_class}). {note}"),
            "severity": sev,
            "host": self.ctx.target.split(":")[0].split("/")[0],
            "service": self.ctx.modality,
            "source": "fuzz_campaign",
            "exploit_class": anomaly.exploit_class,
            "evidence": anomaly.evidence,
            "job_id": self.job_id,
            "reproduce_status": "reproduced" if proven else "unreproduced",
            "signals": {"directly_exploitable": proven,
                        "compromise": "user_rce" if (proven and anomaly.exploit_class in
                                                     ("rce", "cmd_injection", "memory_corruption")) else ""},
        }
        if poc is not None:
            finding["poc"] = poc.to_dict()
            finding["evidence_tag"] = "DEMONSTRATED" if proven else "OBSERVED"
        self.findings.append(finding)
        await self.ctx.emit_event("fuzz_finding", {"job_id": self.job_id, **finding})
        if self._on_finding is not None:
            try:
                res = self._on_finding(finding)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as exc:   # noqa: BLE001
                logger.debug("on_finding callback failed: %s", exc)

    def _expired(self) -> bool:
        return (time.time() - self.started) > self.max_sec

    def snapshot(self) -> Dict[str, Any]:
        return {"job_id": self.job_id, "status": self.status, "target": self.ctx.target,
                "modality": self.ctx.modality, "anomalies": len(self.anomalies),
                "findings": len(self.findings),
                "proven": sum(1 for f in self.findings if f.get("reproduce_status") == "reproduced")}


# ── Registry (mirrors fuzz_lab.start_lab) ──────────────────────────────────────
_CAMPAIGNS: Dict[str, FuzzCampaign] = {}


def start_campaign(campaign: FuzzCampaign) -> asyncio.Task:
    _CAMPAIGNS[campaign.job_id] = campaign
    return asyncio.ensure_future(campaign.run())


def get_campaign(job_id: str) -> Optional[FuzzCampaign]:
    return _CAMPAIGNS.get(job_id)


def stop_campaign(job_id: str) -> bool:
    c = _CAMPAIGNS.get(job_id)
    if c is None:
        return False
    c.stop()
    return True


def list_campaigns(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    out = []
    for c in _CAMPAIGNS.values():
        if session_id and c.ctx.session_id != session_id:
            continue
        out.append(c.snapshot())
    return out
