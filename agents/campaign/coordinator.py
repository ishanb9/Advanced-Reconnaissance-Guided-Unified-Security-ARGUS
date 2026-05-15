"""
coordinator.py - wave-based multi-host campaign coordinator.

Why this exists
---------------
ARGUS has a CIDROrchestrator that spawns N MasterAgents in parallel,
each running the FULL recon -> exploit -> privesc loop on its own host.
That works for 2-3 hosts but at 10+ targets:
  - Recon traffic is unnecessarily serialised within each host loop
  - Common vulnerabilities (default creds, weak SMB) re-discovered
    on every host independently
  - Credential found on host A doesn't get sprayed against host B-Z
    until host A's loop crosses post-exploit

A wave-based coordinator runs phases ACROSS hosts:
  Wave 1: recon ALL hosts in parallel
  Wave 2: aggregate findings + dispatch playbooks per matched service
  Wave 3: credential auto-spray across the whole fleet
  Wave 4: per-host targeted exploitation only on hosts that survived
          the playbook wave

This typically halves total scan time and surfaces common credentials
in wave 3 that the per-host loop wouldn't have learned about for hours.

What this is and is NOT
-----------------------
- IS:  A higher-level orchestrator that sits ABOVE the existing
       CIDROrchestrator / MasterAgent.  It calls them as building
       blocks.
- IS NOT:  A replacement for either.  Operators who prefer the existing
           per-host parallel model can keep using it directly; this
           coordinator is an opt-in alternative for engagements with
           5+ targets.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Caller-supplied async per-host operation.  Returns the host's findings.
PerHostOp = Callable[[str, Dict[str, Any]], Awaitable[List[Dict[str, Any]]]]


@dataclass
class HostState:
    host:           str
    services:       List[Dict[str, Any]] = field(default_factory=list)
    findings:       List[Dict[str, Any]] = field(default_factory=list)
    shell_obtained: bool = False
    dead:           bool = False           # marked by tool blacklist signal
    last_phase:     str  = "init"


@dataclass
class CampaignPlan:
    targets:        List[str]
    waves:          List[str] = field(default_factory=lambda: [
        "recon", "playbooks", "credspray", "targeted_exploit",
        "privesc", "lateral", "report",
    ])
    parallel_per_wave: int = 5
    wave_timeout_sec:  int = 1800


class CampaignCoordinator:
    """Wave-based campaign runner."""

    def __init__(self,
                 plan: CampaignPlan,
                 on_event: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None):
        self.plan = plan
        self.on_event = on_event
        self.hosts: Dict[str, HostState] = {h: HostState(host=h) for h in plan.targets}
        self.shared_creds: List[Dict[str, Any]] = []   # vault hits across hosts
        self.start_time: float = 0.0

    async def _emit(self, et: str, data: Dict[str, Any]) -> None:
        if self.on_event is None:
            return
        try:
            await self.on_event(et, data)
        except Exception:
            pass

    # ── Wave dispatcher ─────────────────────────────────────────────────
    async def _run_wave(self, wave: str, op: PerHostOp) -> None:
        live_hosts = [h for h, s in self.hosts.items() if not s.dead]
        if not live_hosts:
            return
        await self._emit("campaign_wave_start", {
            "wave": wave, "hosts": len(live_hosts),
        })
        sem = asyncio.Semaphore(self.plan.parallel_per_wave)

        async def _go(h: str) -> None:
            async with sem:
                try:
                    findings = await asyncio.wait_for(
                        op(h, {"state": self.hosts[h], "shared_creds": self.shared_creds}),
                        timeout=self.plan.wave_timeout_sec,
                    )
                    self.hosts[h].findings.extend(findings or [])
                    self.hosts[h].last_phase = wave
                except asyncio.TimeoutError:
                    logger.warning("[campaign] %s/%s timed out", wave, h)
                    await self._emit("campaign_host_timeout", {
                        "wave": wave, "host": h,
                    })
                except Exception as exc:
                    logger.warning("[campaign] %s/%s error: %s", wave, h, exc)
                    await self._emit("campaign_host_error", {
                        "wave": wave, "host": h, "error": str(exc),
                    })

        await asyncio.gather(*(_go(h) for h in live_hosts), return_exceptions=True)
        await self._emit("campaign_wave_complete", {
            "wave": wave, "hosts": len(live_hosts),
            "total_findings": sum(len(s.findings) for s in self.hosts.values()),
        })

    # ── Convenience: aggregate fleet findings + credentials ────────────
    def aggregate_findings(self) -> List[Dict[str, Any]]:
        out = []
        for s in self.hosts.values():
            out.extend(s.findings)
        return out

    def common_findings(self, min_hosts: int = 2) -> List[Dict[str, Any]]:
        """Findings (by title) seen on >=min_hosts hosts.  Useful for
        prioritisation - a default-cred finding on 8 of 10 hosts is much
        more impactful than one critical on a single host."""
        by_title: Dict[str, List[Dict[str, Any]]] = {}
        for s in self.hosts.values():
            for f in s.findings:
                t = str(f.get("title") or "untitled")
                by_title.setdefault(t, []).append(f)
        out = []
        for title, finds in by_title.items():
            if len(finds) >= min_hosts:
                # Synthesize a "fleet-level" finding
                hosts = sorted({str(f.get("host") or "") for f in finds})
                out.append({
                    "title":    f"FLEET: {title} on {len(hosts)} hosts",
                    "severity": finds[0].get("severity"),
                    "evidence": ", ".join(hosts[:10]),
                    "fleet_hosts": hosts,
                    "fleet_count": len(hosts),
                })
        out.sort(key=lambda f: -f["fleet_count"])
        return out

    # ── Driver ──────────────────────────────────────────────────────────
    async def run(self, op_for_wave: Dict[str, PerHostOp]) -> Dict[str, Any]:
        """Run the campaign.

        Args:
            op_for_wave: caller-supplied PerHostOp for each wave name.
                         Wave names not in this dict are skipped silently.

        Returns:
            Summary dict with per-host outcomes + fleet-level aggregates.
        """
        self.start_time = time.monotonic()
        await self._emit("campaign_start", {
            "targets": self.plan.targets,
            "waves":   self.plan.waves,
        })

        for wave in self.plan.waves:
            op = op_for_wave.get(wave)
            if op is None:
                logger.info("[campaign] wave %s: no op provided; skipping", wave)
                continue
            await self._run_wave(wave, op)

        elapsed = time.monotonic() - self.start_time
        summary = {
            "duration_sec":  elapsed,
            "host_count":    len(self.hosts),
            "shells":        sum(1 for s in self.hosts.values() if s.shell_obtained),
            "total_findings": sum(len(s.findings) for s in self.hosts.values()),
            "fleet_common":  self.common_findings(min_hosts=2),
            "per_host":      {
                h: {
                    "findings":       len(s.findings),
                    "shell_obtained": s.shell_obtained,
                    "last_phase":     s.last_phase,
                    "dead":           s.dead,
                }
                for h, s in self.hosts.items()
            },
        }
        await self._emit("campaign_complete", {
            "duration_sec":  round(elapsed, 1),
            "total_findings": summary["total_findings"],
            "shells":        summary["shells"],
            "fleet_common":  len(summary["fleet_common"]),
        })
        return summary


__all__ = ["CampaignCoordinator", "CampaignPlan", "HostState"]
