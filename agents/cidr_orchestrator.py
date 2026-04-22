"""
cidr_orchestrator.py — Multi-Target / CIDR Pentest Orchestrator

Accepts a single IP, CIDR range, or comma-separated list and:
  1. Expands the input into individual IP candidates
  2. Runs live-host discovery (nmap -sn) to find alive hosts
  3. Spawns one MasterAgent per live host, bounded by a semaphore
  4. Each MasterAgent gets a host-scoped broadcast closure that injects
     host_id into every WebSocketMessage so the frontend can filter per-IP
  5. Persists discovered_hosts / hosts_completed into the session document

Single-IP pass-through guarantee
---------------------------------
If the input resolves to exactly one host (e.g. "192.168.1.10") the
orchestrator calls MasterAgent.run() directly without any wrapping,
preserving 100% identical behaviour to the pre-multi-target code path.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import signal as _signal
from typing import Any, Callable, Coroutine, Dict, List, Optional

import httpx

import db.mongo_client as _db
from db.schemas import SessionMode, WebSocketMessage
from agents.master_agent import MasterAgent

logger = logging.getLogger(__name__)

# Hard safety caps
MAX_CIDR_ADDRESSES = 1024   # reject /8 etc.
MAX_LIVE_HOSTS     = 64     # cap parallel session size


class CIDROrchestrator:
    """
    Orchestrates parallel MasterAgent instances for multi-host pentests.
    """

    def __init__(
        self,
        session_id:         str,
        target_input:       str,
        broadcast:          Callable[[WebSocketMessage], Coroutine[Any, Any, None]],
        session_kwargs:     Dict,               # forwarded to every MasterAgent.run()
        max_parallel_hosts: int = 5,
    ) -> None:
        self.session_id         = session_id
        self.target_input       = target_input.strip()
        self.broadcast          = broadcast
        self.session_kwargs     = session_kwargs
        self.max_parallel_hosts = max(1, min(max_parallel_hosts, MAX_LIVE_HOSTS))
        self._stop              = False
        self._active_masters:   List[MasterAgent] = []

        # Pause/resume — mirrors the MasterAgent contract so agent_server
        # can call pause()/resume() on either type without isinstance checks.
        self._pause_event: asyncio.Event = asyncio.Event()
        self._pause_event.set()   # start in running state

    def request_stop(self) -> None:
        """Stop the orchestrator and all active child MasterAgents."""
        self._stop = True
        for m in self._active_masters:
            try:
                m.stop_all_agents()
            except Exception:
                pass

    def stop_all_agents(self) -> None:
        """Alias used by agent_server stop endpoint."""
        self.request_stop()

    async def pause(self) -> str:
        """
        Pause the orchestrator: blocks new host slots from being acquired
        and cascades pause() to every in-flight MasterAgent.
        Returns empty string (checkpoint IDs come from each MasterAgent).
        """
        self._pause_event.clear()
        await self._emit("scan_paused", {
            "message": "Multi-host scan pause requested — finishing current hosts",
        })
        for m in list(self._active_masters):
            try:
                await m.pause()
            except Exception:
                pass
        return ""

    async def resume(self) -> bool:
        """
        Resume: unblock the pause event and cascade resume() to every
        in-flight MasterAgent.  Returns True if was paused.
        """
        was_paused = not self._pause_event.is_set()
        self._pause_event.set()
        for m in list(self._active_masters):
            try:
                await m.resume()
            except Exception:
                pass
        if was_paused:
            await self._emit("scan_resumed", {"message": "Multi-host scan resumed"})
        return was_paused

    def inject_guidance(self, guidance: dict) -> None:
        """Forward operator guidance to all active MasterAgents."""
        for m in self._active_masters:
            try:
                m._guidance_queue.put_nowait(guidance)
            except Exception:
                pass

    def confirm_action(self, phase: str) -> None:
        """Forward confirmation to all active MasterAgents."""
        for m in self._active_masters:
            try:
                m.confirm_action(phase)
            except Exception:
                pass

    # Provide a stub _intel so agent_server code that reads active_agents[id]._intel
    # doesn't crash for multi-host sessions.
    @property
    def _intel(self) -> dict:
        # For multi-host, aggregate intel from the first active master (if any)
        if self._active_masters:
            return self._active_masters[0]._intel
        return {}

    # ── Main entry point ───────────────────────────────────────────────────────

    async def run(self) -> Dict:
        """
        Full multi-host orchestration flow.
        Returns a summary dict { host: result, ... }
        """
        # ── Step 1: Expand target ──────────────────────────────
        try:
            candidates = self._expand_target(self.target_input)
        except ValueError as exc:
            await self._emit("cidr_error", {"message": str(exc)})
            return {"error": str(exc)}

        # ── Step 2: Single-IP fast path ────────────────────────
        if len(candidates) == 1:
            # Behave exactly as original agent_server: direct MasterAgent call
            master = MasterAgent(broadcast=self.broadcast)
            self._active_masters.append(master)
            result = await master.run(
                session_id = self.session_id,
                target     = candidates[0],
                **self.session_kwargs,
            )
            self._active_masters.remove(master)
            return {candidates[0]: result}

        # ── Step 3: Multi-host path ────────────────────────────
        await self._emit("cidr_expansion_start", {
            "target_input": self.target_input,
            "candidate_count": len(candidates),
            "message": f"Discovering live hosts in {self.target_input} ({len(candidates)} candidates)...",
        })

        live_hosts = await self._discover_live_hosts(candidates)

        if not live_hosts:
            await self._emit("cidr_error", {
                "message": f"No live hosts found in {self.target_input}",
            })
            return {"live_hosts": []}

        # Cap and persist
        live_hosts = live_hosts[:MAX_LIVE_HOSTS]
        await self._emit("host_discovery_complete", {
            "hosts":   live_hosts,
            "count":   len(live_hosts),
            "message": f"Found {len(live_hosts)} live hosts",
        })
        for host in live_hosts:
            await _db.add_discovered_host(self.session_id, host)

        # Update session mode
        mode = SessionMode.CIDR if "/" in self.target_input else SessionMode.MULTI
        await _db.update_session(self.session_id, {"session_mode": mode.value})

        # ── Resume: skip hosts already finished before a pause ─
        session_doc   = await _db.get_session(self.session_id)
        hosts_done    = set(session_doc.get("hosts_completed", []) if session_doc else [])
        pending_hosts = [h for h in live_hosts if h not in hosts_done]
        if hosts_done:
            await self._emit("cidr_resume", {
                "skipped": list(hosts_done),
                "pending": pending_hosts,
                "message": f"Resuming — skipping {len(hosts_done)} already-completed host(s)",
            })

        # ── Step 4: Bounded parallel execution ────────────────
        semaphore = asyncio.Semaphore(self.max_parallel_hosts)
        tasks     = [self._run_host(host, semaphore) for host in pending_hosts]
        results   = await asyncio.gather(*tasks, return_exceptions=True)
        # Inject placeholder results for already-completed hosts
        for h in hosts_done:
            live_hosts_order = live_hosts  # keep original order for summary
        live_hosts = pending_hosts   # results align with pending_hosts

        summary = {}
        for host, res in zip(live_hosts, results):
            summary[host] = res if not isinstance(res, Exception) else str(res)

        await self._emit("cidr_scan_complete", {
            "hosts_tested": len(live_hosts),
            "message":      f"All {len(live_hosts)} hosts tested",
        })
        return summary

    # ── Per-host runner ────────────────────────────────────────────────────────

    async def _run_host(self, host: str, semaphore: asyncio.Semaphore) -> Any:
        # Wait if paused — block until resume() sets the event
        await self._pause_event.wait()
        async with semaphore:
            if self._stop:
                return "stopped"

            await self._emit("host_scan_start", {
                "host":    host,
                "message": f"Starting pentest on {host}",
            }, host_id=host)

            master = MasterAgent(broadcast=self._make_host_broadcast(host))
            self._active_masters.append(master)
            try:
                result = await master.run(
                    session_id = self.session_id,
                    target     = host,
                    **self.session_kwargs,
                )
            except Exception as exc:
                logger.warning("[CIDROrchestrator] Host %s failed: %s", host, exc)
                result = {"error": str(exc)}
            finally:
                try:
                    self._active_masters.remove(master)
                except ValueError:
                    pass

            await _db.mark_host_complete(self.session_id, host)
            await self._emit("host_scan_complete", {
                "host":    host,
                "message": f"Pentest complete on {host}",
            }, host_id=host)
            return result

    # ── Live host discovery ────────────────────────────────────────────────────

    async def _discover_live_hosts(self, candidates: List[str]) -> List[str]:
        """
        Use nmap -sn (ping scan) to find live hosts.
        Falls back to fping if nmap is unavailable.
        For small candidate lists (≤4), skips discovery and returns all.
        """
        if len(candidates) <= 4:
            # For very small lists, assume all are live (avoids ping-blocked issues)
            return candidates

        target_arg = " ".join(candidates) if len(candidates) <= 32 else self.target_input

        # Try nmap ping scan
        nmap_cmd = f"nmap -sn -T4 --open {target_arg} 2>/dev/null"
        live = await self._run_discovery_cmd(nmap_cmd, r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)")

        if not live:
            # Fallback: fping
            fping_cmd = f"fping -a -q {target_arg} 2>/dev/null"
            live = await self._run_discovery_cmd(fping_cmd, r"(\d+\.\d+\.\d+\.\d+)")

        if not live:
            # Last resort: try all candidates (user may have ICMP blocked)
            logger.warning("[CIDROrchestrator] No live hosts via ping; using all %d candidates", len(candidates))
            live = candidates

        # Emit per-host discovery events
        for host in live:
            await self._emit("host_discovered", {"host": host}, host_id=host)

        return live

    async def _run_discovery_cmd(self, cmd: str, ip_pattern: str) -> List[str]:
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # new process group → killpg kills all children
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                # Kill entire process group so nmap children don't linger
                try:
                    os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                try:
                    proc.kill()
                except Exception:
                    pass
                return []
            output = stdout.decode(errors="replace")
            ips    = re.findall(ip_pattern, output)
            return list(dict.fromkeys(ips))  # deduplicated, order-preserving
        except Exception as exc:
            logger.warning("[CIDROrchestrator] Discovery command failed: %s", exc)
            return []

    # ── Target expansion ───────────────────────────────────────────────────────

    @staticmethod
    def _expand_target(target_input: str) -> List[str]:
        """
        Parse target_input into a list of individual IP strings.
        Supports:
          - Single IP:               "192.168.1.10"
          - CIDR:                    "192.168.1.0/24"
          - Comma-separated IPs:     "10.0.0.1,10.0.0.2"
          - Comma-separated CIDRs:   "10.0.0.0/29,192.168.1.0/30"
          - Hostname (single):       "router.local"  → returned as-is
        """
        parts = [p.strip() for p in target_input.split(",") if p.strip()]
        ips: List[str] = []

        for part in parts:
            if "/" in part:
                try:
                    net = ipaddress.ip_network(part, strict=False)
                except ValueError:
                    raise ValueError(f"Invalid CIDR: {part}")
                if net.num_addresses > MAX_CIDR_ADDRESSES:
                    raise ValueError(
                        f"CIDR {part} contains {net.num_addresses} addresses "
                        f"(max {MAX_CIDR_ADDRESSES}). Use a smaller subnet."
                    )
                ips.extend(str(ip) for ip in net.hosts())
            else:
                # Single IP or hostname — validate if looks like an IP
                try:
                    ipaddress.ip_address(part)
                except ValueError:
                    pass  # hostname — accept as-is
                ips.append(part)

        if not ips:
            raise ValueError(f"Could not parse any targets from: {target_input!r}")

        return list(dict.fromkeys(ips))  # deduplicated

    # ── Host-scoped broadcast ──────────────────────────────────────────────────

    def _make_host_broadcast(
        self, host: str
    ) -> Callable[[Any], Coroutine[Any, Any, None]]:
        """
        Return a broadcast closure that injects host_id into every
        WebSocketMessage before forwarding to the real session broadcast.
        """
        async def _host_broadcast(msg: Any) -> None:
            if isinstance(msg, WebSocketMessage):
                # Rebuild with host_id set
                tagged = WebSocketMessage(
                    type       = msg.type,
                    session_id = msg.session_id,
                    agent      = msg.agent,
                    data       = msg.data,
                    timestamp  = msg.timestamp,
                    host_id    = host,
                )
                await self.broadcast(tagged)
            elif isinstance(msg, dict):
                msg["host_id"] = host
                await self.broadcast(msg)
            else:
                await self.broadcast(msg)

        return _host_broadcast

    # ── Emit helper ────────────────────────────────────────────────────────────

    async def _emit(self, event_type: str, data: dict, host_id: Optional[str] = None) -> None:
        msg = WebSocketMessage(
            type       = event_type,
            session_id = self.session_id,
            agent      = "orchestrator",
            data       = data,
            host_id    = host_id,
        )
        try:
            await self.broadcast(msg)
        except Exception as exc:
            logger.debug("[CIDROrchestrator] broadcast failed: %s", exc)
