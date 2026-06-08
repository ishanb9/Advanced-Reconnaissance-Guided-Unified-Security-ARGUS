"""
domain_recon_orchestrator.py — domain → subdomain hunt → human pick → scan.

When ARGUS is given a DOMAIN (not an IP/CIDR) with subdomain-hunting enabled,
this orchestrator runs the full real-world recon-to-engagement flow:

  1. HUNT   — enumerate subdomains across the public network (passive crt.sh +
              subfinder, active gobuster-dns brute) and resolve + scope-classify
              each (subdomain_hunter.hunt).
  2. PRESENT— stream the candidate list to the GUI (target_selection_request).
  3. GATE   — BLOCK on a mandatory human selection (target_selection.await_selection,
              fail-closed: no pick → attack nothing).
  4. SCAN   — feed the operator's chosen hosts into the existing CIDROrchestrator,
              which spawns one MasterAgent per selected target.

It mirrors the MasterAgent / CIDROrchestrator control surface (pause / resume /
request_stop / _intel) so agent_server can drive it uniformly.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Callable, Coroutine, Dict, List, Optional

import db.mongo_client as _db
from db.schemas import WebSocketMessage
from agents.cidr_orchestrator import CIDROrchestrator
from agents.recon import subdomain_hunter as _hunter
from agents import target_selection as _sel

logger = logging.getLogger(__name__)

# How long the scan blocks waiting for the operator to pick targets.
# Fail-closed on expiry (scan nothing).  Generous by default.
SELECTION_TIMEOUT = int(os.environ.get("TARGET_SELECTION_TIMEOUT", "1800"))


class DomainReconOrchestrator:
    def __init__(
        self,
        session_id:         str,
        domain:             str,
        broadcast:          Callable[[WebSocketMessage], Coroutine[Any, Any, None]],
        session_kwargs:     Dict,
        max_parallel_hosts: int = 5,
        passive:            bool = True,
        active:             bool = True,
    ) -> None:
        self.session_id         = session_id
        self.domain             = (domain or "").strip().lower().strip(".")
        self.broadcast          = broadcast
        self.session_kwargs     = session_kwargs
        self.max_parallel_hosts = max_parallel_hosts
        self.passive            = passive
        self.active             = active
        self._stop              = False
        self._inner:            Optional[CIDROrchestrator] = None
        self._pause_event:      asyncio.Event = asyncio.Event()
        self._pause_event.set()

    # ── Control surface (delegates to the inner orchestrator once scanning) ──

    def request_stop(self) -> None:
        self._stop = True
        try:
            _sel.resolve(self.session_id, [])   # unblock the gate → scan nothing
        except Exception:
            pass
        if self._inner:
            self._inner.request_stop()

    def stop_all_agents(self) -> None:
        self.request_stop()

    async def pause(self) -> str:
        self._pause_event.clear()
        if self._inner:
            return await self._inner.pause()
        return ""

    async def resume(self) -> bool:
        self._pause_event.set()
        if self._inner:
            return await self._inner.resume()
        return False

    def inject_guidance(self, guidance: dict) -> None:
        if self._inner:
            self._inner.inject_guidance(guidance)

    def confirm_action(self, phase: str) -> None:
        if self._inner:
            self._inner.confirm_action(phase)

    @property
    def _intel(self) -> dict:
        return self._inner._intel if self._inner else {}

    # ── Emit helper ──────────────────────────────────────────────────────

    async def _emit(self, mtype: str, data: dict) -> None:
        try:
            await self.broadcast(WebSocketMessage(
                type=mtype, session_id=self.session_id, agent="recon", data=data,
            ))
        except Exception:
            pass

    # ── Main entry point ─────────────────────────────────────────────────

    async def run(self) -> Dict:
        if not self.domain:
            await self._emit("domain_recon_error", {"message": "no domain given"})
            return {"error": "no domain"}

        # ── Step 1: HUNT ──────────────────────────────────────────────
        await self._emit("subdomain_hunt_start", {
            "domain":  self.domain,
            "passive": self.passive,
            "active":  self.active,
            "message": f"Hunting subdomains of {self.domain} (passive + active)…",
        })

        async def _progress(msg: str) -> None:
            await self._emit("subdomain_hunt_progress", {"message": msg})

        try:
            candidates = await _hunter.hunt(
                self.domain, passive=self.passive, active=self.active,
                on_progress=_progress,
            )
        except Exception as exc:                                  # noqa: BLE001
            logger.warning("[domain_recon] hunt failed: %s", exc)
            await self._emit("domain_recon_error", {"message": f"hunt failed: {exc}"})
            return {"error": str(exc)}

        if self._stop:
            return {"stopped": True}

        cand_dicts = [c.to_dict() for c in candidates]
        try:
            await _db.update_session(self.session_id, {"subdomain_candidates": cand_dicts})
        except Exception:
            pass

        # ── Step 2 + 3: PRESENT + blocking GATE ───────────────────────
        allowed = [c.host for c in candidates]
        _sel.create_request(self.session_id, allowed=allowed)
        await self._emit("target_selection_request", {
            "selection_id": self.session_id,
            "domain":       self.domain,
            "candidates":   cand_dicts,
            "count":        len(cand_dicts),
            "in_network":   sum(1 for c in candidates if c.in_apex_network),
            "third_party":  sum(1 for c in candidates if c.third_party),
            "timeout_sec":  SELECTION_TIMEOUT,
            "message": (f"Found {len(cand_dicts)} candidate target(s) for "
                        f"{self.domain}. Select which to engage — nothing is "
                        f"attacked until you choose."),
        })

        selected = await _sel.await_selection(self.session_id, timeout=SELECTION_TIMEOUT)

        if self._stop:
            return {"stopped": True}

        if not selected:
            await self._emit("target_selection_empty", {
                "selection_id": self.session_id,
                "message": ("No targets selected (or selection timed out) — "
                            "attacking nothing. Re-run and pick targets to engage."),
            })
            return {"selected": [], "candidates": cand_dicts}

        await self._emit("target_selection_confirmed", {
            "selection_id": self.session_id,
            "selected":     selected,
            "count":        len(selected),
            "message": f"Engaging {len(selected)} operator-selected target(s).",
        })
        try:
            await _db.update_session(self.session_id, {"selected_targets": selected})
        except Exception:
            pass

        # ── Step 4: SCAN the selected set via the multi-target orchestrator ──
        self._inner = CIDROrchestrator(
            session_id         = self.session_id,
            target_input       = ",".join(selected),
            broadcast          = self.broadcast,
            session_kwargs     = self.session_kwargs,
            max_parallel_hosts = self.max_parallel_hosts,
        )
        if not self._pause_event.is_set():
            await self._inner.pause()
        return await self._inner.run()


__all__ = ["DomainReconOrchestrator", "SELECTION_TIMEOUT"]
