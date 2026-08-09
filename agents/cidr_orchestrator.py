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
from utils.scan_logger import register_exercise_dir
from utils.resource_governor import wait_for_admission as _rg_admit
from utils.resource_governor import was_autoset as _rg_was_autoset

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
        presolved:          bool = False,       # targets already discovered + human-approved
        host_authz:         Optional[Dict[str, Dict]] = None,  # host -> per-target authorization
    ) -> None:
        # PER-HOST authorization.  Previously session_kwargs was built ONCE from the
        # HTTP body and every host inherited identical auth/intrusiveness — so a
        # third-party CDN edge in a client's DNS was attacked with exactly the same
        # authority as the client's own web server.  This is the missing channel: one
        # authorization record per host, applied when that host's MasterAgent spawns.
        self.host_authz: Dict[str, Dict] = dict(host_authz or {})
        # ``presolved`` means the caller (DomainReconOrchestrator) already resolved and
        # human-approved this exact host list.  Re-running live-host discovery on it is
        # not just wasted work — it DESTROYS the hostnames: _discover_live_hosts parses
        # `nmap -sn` with a regex whose capture group is the IP, so
        # "Nmap scan report for shop.example.com (93.184.216.34)" collapses to the bare
        # IP.  Picking 5+ subdomains therefore silently scanned 5+ IPs with no vhost
        # name, breaking Host-header/web testing (<=4 picks kept names, so the bug only
        # appeared on larger selections).  Skip discovery for a presolved list.
        self.presolved = bool(presolved)
        self.session_id         = session_id
        self.target_input       = target_input.strip()
        self.broadcast          = broadcast
        self.session_kwargs     = session_kwargs
        self.max_parallel_hosts = max(1, min(max_parallel_hosts, MAX_LIVE_HOSTS))
        self._stop              = False
        # True once host-discovery (nmap -sn / fping) has POSITIVELY proved these hosts
        # live — so per-host runs can skip the redundant scan-start reachability blocker
        # (which would otherwise falsely pause a live host that lacks 80/443/22).  Stays
        # False for the ≤4-candidate "assumed live" path and the last-resort "use all
        # candidates" path, where each host keeps its own (ICMP-aware) reachability gate.
        self._liveness_proven   = False
        self._active_masters:   List[MasterAgent] = []
        # Per-host isolation: each target host runs under its OWN child session (created
        # once, reused across triage + deep) so findings/logs never cross-contaminate and
        # each host gets its own log folder.  host -> child_session_id.
        self._host_sessions:    Dict[str, str] = {}

        # Pause/resume — mirrors the MasterAgent contract so agent_server
        # can call pause()/resume() on either type without isinstance checks.
        self._pause_event: asyncio.Event = asyncio.Event()
        self._pause_event.set()   # start in running state

    async def _child_session_for(self, host: str) -> str:
        """Return (creating once) the per-host CHILD session id for ``host``, linked to
        this orchestrator's PARENT session via ``parent_session_id``.  All of the host's
        findings/intel/logs land under this child, so there is one log folder per host and
        zero cross-target contamination; the report rolls children up via the parent link.
        Degrades to the parent id if child creation fails — never breaks the run."""
        existing = self._host_sessions.get(host)
        if existing:
            return existing
        try:
            from db import mongo_client as _db
            from db.schemas import SessionCreate as _SC
            # [45] Cold resume: after a process restart the in-memory host->child map is
            # empty, so REUSE the child session this host already had under THIS parent.
            # A fresh child id would orphan the host's prior findings, logs and checkpoint
            # (children checkpoint under their own session id) and silently restart it.
            try:
                _prior = await _db.get_child_session_for_host(str(self.session_id), host)
                if _prior:
                    self._host_sessions[host] = _prior
                    return _prior
            except Exception:
                pass
            _scope = (self.session_kwargs.get("scope")
                      if isinstance(self.session_kwargs, dict) else None)
            _child = await _db.create_session(_SC(
                target_ip=host, target_type="unknown", scope=_scope,
                session_mode="single", parent_session_id=str(self.session_id)))
            child_sid = str((_child or {}).get("id") or (_child or {}).get("_id") or "")
            if child_sid:
                self._host_sessions[host] = child_sid
                return child_sid
        except Exception as exc:   # noqa: BLE001
            logger.warning("[CIDR] child-session create for %s failed (%s); using parent id",
                           host, exc)
        self._host_sessions[host] = str(self.session_id)
        return str(self.session_id)

    async def _resume_checkpoint_for(self, host: str) -> Optional[str]:
        """[45] The checkpoint id to resume this host from, or None for a first run.
        Looked up by (parent, host) so a COLD resume finds a half-finished host's
        checkpoint even though the orchestrator no longer knows its child session id.
        A fresh run has no prior checkpoint → None → master.run() behaves exactly as
        before, so a first-time scan is byte-for-byte unchanged."""
        try:
            from db import mongo_client as _db
            cp = await _db.get_latest_child_checkpoint(str(self.session_id), host)
            if cp:
                cid = cp.get("_id") or cp.get("id")
                return str(cid) if cid else None
        except Exception:
            pass
        return None

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
        # ONLY safe when there is no per-host context to lose.  This branch skips
        # everything below it — exercise log dir, host events, child session, and
        # the per-host kwargs the other three master.run() call sites pass — so
        # taking it for a target that HAS per-host context silently discarded that
        # context.  A domain scan where the operator picked exactly one host landed
        # here: the authorization they reviewed at the gate (possibly an explicit
        # "passive only" on a third-party name) was dropped, and MasterAgent
        # re-derived a more permissive grant from scratch.  A host the human
        # deliberately restricted could then be actively probed.
        # Presolved / authorized targets take the full path instead, which is also
        # where they get their per-host log subfolder and UI events.
        if len(candidates) == 1 and not self.presolved and not self.host_authz:
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
        # Create the ONE exercise log folder up front; every per-host child session
        # nests its logs as a SUBfolder of this dir (one folder per exercise).
        try:
            register_exercise_dir(str(self.session_id), target=self.target_input)
        except Exception:
            pass
        await self._emit("cidr_expansion_start", {
            "target_input": self.target_input,
            "candidate_count": len(candidates),
            "message": f"Discovering live hosts in {self.target_input} ({len(candidates)} candidates)...",
        })

        if self.presolved:
            # Human-approved, already-resolved targets: keep them VERBATIM (hostnames
            # intact) and treat liveness as proven so the per-host reachability blocker
            # doesn't re-litigate a host the operator explicitly chose.
            live_hosts = list(candidates)
            self._liveness_proven = True
            logger.info("[CIDR] presolved target list (%d) — skipping live-host "
                        "discovery so hostnames are preserved", len(live_hosts))
            for host in live_hosts:
                await self._emit("host_discovered", {"host": host, "presolved": True},
                                 host_id=host)
        else:
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

        # ── F3 pre-flight: prove the reasoning ENGINE can construct BEFORE spawning N host
        # sessions.  A constructor-contract mismatch (e.g. the stale-`negative_memory.py`
        # `on_record` crash) would otherwise make every one of these hosts silently fail; the
        # smoke surfaces it ONCE, loudly, up front.  ARGUS still proceeds — each host degrades
        # to the working legacy pipeline (never a silent no-op) — but the operator is told the
        # primary engine is broken instead of getting 27 empty "completed" hosts.
        try:
            _pf_ok, _pf_why = await MasterAgent.preflight_reasoning_components()
        except Exception as _pf_exc:   # noqa: BLE001 — a broken smoke must not abort the scan
            _pf_ok, _pf_why = False, f"{type(_pf_exc).__name__}: {_pf_exc}"
        if not _pf_ok:
            logger.error("[CIDR] reasoning pre-flight FAILED before %d-host fan-out: %s",
                         len(pending_hosts), _pf_why)
            await self._emit("reasoning_preflight_failed", {
                "error": _pf_why,
                "hosts": len(pending_hosts),
                "message": (f"Reasoning engine pre-flight FAILED ({_pf_why}). Every host will "
                            "run on the LEGACY fallback pipeline (not a silent no-op). Fix the "
                            "reasoning-component contract to restore the primary engine."),
            })

        # ── Step 4: Execute ───────────────────────────────────
        # Default: two-phase (triage ALL hosts in parallel → exploit in promise
        # order with bounded concurrency + hand-off on no-progress).  Revert to
        # the legacy single-phase semaphore model with ARGUS_CIDR_TWO_PHASE=0.
        two_phase = os.environ.get("ARGUS_CIDR_TWO_PHASE", "1") != "0"
        if two_phase:
            summary = await self._run_two_phase(pending_hosts)
        else:
            summary = await self._run_single_phase(pending_hosts)

        await self._emit("cidr_scan_complete", {
            "hosts_tested": len(summary),
            "message":      f"All {len(summary)} hosts tested",
        })
        return summary

    # ── Per-host runner ────────────────────────────────────────────────────────

    async def _run_host(self, host: str, semaphore: asyncio.Semaphore) -> Any:
        # Wait if paused — block until resume() sets the event
        await self._pause_event.wait()
        async with semaphore:
            if self._stop:
                return "stopped"

            # [49] Re-check admission INSIDE the slot.  Host coroutines are created
            # up-front (asyncio.gather), so every host cleared the RAM gate at t=0
            # and a freed slot then spawned a new MasterAgent even under pressure —
            # the watchdog only barriered the fan-out once.  Gating here means a
            # slot-holder blocks until RAM recovers (wait_for_admission's 120s cap
            # preserves liveness).
            await self._pause_event.wait()
            await _rg_admit()

            await self._emit("host_scan_start", {
                "host":    host,
                "message": f"Starting pentest on {host}",
            }, host_id=host)

            master = MasterAgent(broadcast=self._make_host_broadcast(host))
            self._active_masters.append(master)
            try:
                result = await master.run(
                    session_id = await self._child_session_for(host),
                    target = host,
                    parent_session_id=str(self.session_id),
                    checkpoint_id=await self._resume_checkpoint_for(host),  # [45] resume mid-host
                    reachability_confirmed=self._liveness_proven,           # discovery already proved this host live
                    target_authorization=self.host_authz.get(host),         # per-host authorization
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

    # ── Two-phase triage → prioritized exploit ──────────────────────────────────
    TRIAGE_PHASES = ["recon"]

    async def _triage_host(self, host: str, sem: asyncio.Semaphore) -> dict:
        """Phase A: a LIGHT, recon-only pass on one host (bounded by `sem`), so
        EVERY live host gets covered quickly.  Reuses the recon pipeline via
        master.run(phases=recon).  Returns {host, intel, score}; never raises."""
        await self._pause_event.wait()
        async with sem:
            if self._stop:
                return {"host": host, "intel": {}, "score": 0.0}
            # [49] Re-check admission inside the slot (see _run_host).
            await self._pause_event.wait()
            await _rg_admit()
            timeout = float(os.environ.get("ARGUS_CIDR_TRIAGE_TIMEOUT_SEC", "300"))
            master = MasterAgent(broadcast=self._make_host_broadcast(host))
            self._active_masters.append(master)
            intel: Dict[str, Any] = {}
            try:
                kw = dict(self.session_kwargs)
                kw["phases"] = self.TRIAGE_PHASES
                await asyncio.wait_for(
                    master.run(session_id=await self._child_session_for(host), target=host,
                               parent_session_id=str(self.session_id),
                               reachability_confirmed=self._liveness_proven,
                               target_authorization=self.host_authz.get(host), **kw),
                    timeout=timeout)
                intel = getattr(master, "_intel", {}) or {}
            except asyncio.TimeoutError:
                intel = getattr(master, "_intel", {}) or {}
            except Exception as exc:   # noqa: BLE001
                logger.warning("[CIDR] triage %s failed: %s", host, exc)
                intel = getattr(master, "_intel", {}) or {}
            finally:
                try:
                    self._active_masters.remove(master)
                except ValueError:
                    pass
            score = self._score_host(intel)
            surface = {"open_ports": intel.get("open_ports") or [],
                       "services": list((intel.get("services") or {}).keys())}
            try:
                await _db.set_host_triage(self.session_id, host, score, "triaged", surface)
            except Exception:
                pass
            await self._emit("host_triage_complete", {
                "host": host, "promise_score": score,
                "open_ports": surface["open_ports"], "services": surface["services"],
                "os_guess": intel.get("os_guess", ""),
                "surface_summary": f"{len(surface['open_ports'])} ports, "
                                   f"{len(surface['services'])} services",
            }, host_id=host)
            return {"host": host, "intel": intel, "score": score}

    async def _run_two_phase(self, pending_hosts: List[str]) -> Dict:
        """Phase A: triage ALL hosts in parallel (high concurrency).  Phase B:
        run full engagements on hosts in promise-rank order through a small
        semaphore, each bounded by a per-host depth budget so a stalled host
        releases its slot to the next-ranked host."""
        # Honour the operator's "max parallel hosts" choice from the UI.  The
        # deep-exploit lane USED to be hard-pinned at 3, so raising the slider had
        # no effect and multiple targets appeared to be tested one-at-a-time.  Now
        # the exploit lane defaults to the slider value; triage (cheaper) runs at
        # least as wide.  Env vars still override for fine-tuning / CI.
        _mph             = max(1, int(getattr(self, "max_parallel_hosts", 5) or 5))

        # [48] Honour the slider over the GOVERNOR's default.  The resource governor
        # setdefault()s these two knobs at boot, so os.environ.get() always finds a
        # value and the slider (str(_mph) fallback) was dead — multiple targets ran
        # effectively one-at-a-time.  Use the env value only for a REAL human/CI
        # override (not a governor autoset); otherwise use the slider.  _mph is
        # already capped at recommended_hosts() at session creation, so the slider
        # can never exceed the hardware/LLM ceiling — no OOM regression.
        def _knob(name: str, default: int) -> int:
            raw = os.environ.get(name)
            if raw is not None and not _rg_was_autoset(name):
                try:
                    return int(raw)
                except (TypeError, ValueError):
                    return default
            return default
        exploit_parallel = max(1, _knob("ARGUS_CIDR_EXPLOIT_PARALLEL", _mph))
        triage_parallel  = max(exploit_parallel,
                               _knob("ARGUS_CIDR_TRIAGE_PARALLEL", max(8, _mph)))
        host_sec         = max(0, int(os.environ.get("ARGUS_CIDR_EXPLOIT_HOST_SEC", "1800")))

        # ── Phase A — triage every host ──
        await self._emit("cidr_phase", {
            "phase": "triage", "hosts": len(pending_hosts),
            "message": f"Triaging {len(pending_hosts)} hosts in parallel"})
        tsem = asyncio.Semaphore(triage_parallel)
        triaged = await asyncio.gather(
            *[self._triage_host(h, tsem) for h in pending_hosts],
            return_exceptions=True)
        scored = [r for r in triaged if isinstance(r, dict)]
        # Highest promise first (stable tiebreak on host string).
        scored.sort(key=lambda r: (r.get("score", 0.0), r.get("host", "")), reverse=True)
        ranked_hosts = [r["host"] for r in scored]
        await self._emit("cidr_phase", {
            "phase": "exploit", "hosts": len(ranked_hosts),
            "ranking": [{"host": r["host"], "score": r["score"]} for r in scored],
            "message": f"Exploiting {len(ranked_hosts)} hosts in promise order"})

        # ── Phase B — bounded, ranked deep exploitation with hand-off ──
        esem = asyncio.Semaphore(exploit_parallel)

        async def _deep(host: str) -> Any:
            await self._pause_event.wait()
            async with esem:
                if self._stop:
                    return "stopped"
                # [49] Re-check admission inside the slot (see _run_host).
                await self._pause_event.wait()
                await _rg_admit()
                # Self-heal the data layer before each host: a mid-run server
                # reload / lifespan teardown could have closed Mongo, which would
                # otherwise fail this host's entire exploit phase with
                # "MongoDB not initialized".
                try:
                    from db.mongo_client import ensure_setup
                    await ensure_setup()
                except Exception:
                    pass
                await self._emit("host_scan_start",
                                 {"host": host, "message": f"Exploiting {host}"}, host_id=host)
                master = MasterAgent(broadcast=self._make_host_broadcast(host))
                self._active_masters.append(master)
                try:
                    kw = dict(self.session_kwargs)
                    _hard = 0
                    if host_sec > 0:
                        kw["max_seconds"] = host_sec   # advisory budget for the operator
                        _hard = host_sec + 300         # HARD wall-clock ceiling = budget + 5m grace
                    # The per-host max_seconds above is ADVISORY — OperatorCore disables it the
                    # instant any progress signal exists, which let ONE productive host run
                    # ~2h and starve every other target (the "queues targets but doesn't test
                    # them" bug).  A hard asyncio timeout GUARANTEES each ranked host yields its
                    # slot to the next-ranked host, so all targets get engaged.
                    _coro = master.run(session_id=await self._child_session_for(host), target=host,
                                       parent_session_id=str(self.session_id),
                                       checkpoint_id=await self._resume_checkpoint_for(host),  # [45]
                                       reachability_confirmed=self._liveness_proven,
                                       target_authorization=self.host_authz.get(host),
                                       **kw)
                    result = await (asyncio.wait_for(_coro, timeout=_hard) if _hard > 0 else _coro)
                except asyncio.TimeoutError:
                    logger.warning("[CIDR] host %s hit the hard %ss ceiling — yielding its slot "
                                   "to the next-ranked host", host, _hard)
                    result = {"host": host, "status": "time_capped"}
                except Exception as exc:   # noqa: BLE001
                    logger.warning("[CIDR] exploit %s failed: %s", host, exc)
                    result = {"error": str(exc)}
                finally:
                    try:
                        self._active_masters.remove(master)
                    except ValueError:
                        pass
                # [I7] record HOW this host terminated so the report labels a
                # time-capped/errored host as PARTIAL, never as fully assessed.
                _hstatus = "completed"
                if isinstance(result, dict):
                    if result.get("status") == "time_capped":
                        _hstatus = "time_capped"
                    elif result.get("error"):
                        _hstatus = "error"
                await _db.mark_host_complete(self.session_id, host, _hstatus)
                await self._emit("host_scan_complete",
                                 {"host": host, "message": f"Done {host}"}, host_id=host)
                return result

        results = await asyncio.gather(*[_deep(h) for h in ranked_hosts],
                                       return_exceptions=True)
        return {h: (r if not isinstance(r, Exception) else str(r))
                for h, r in zip(ranked_hosts, results)}

    async def _run_single_phase(self, pending_hosts: List[str]) -> Dict:
        """Legacy model (ARGUS_CIDR_TWO_PHASE=0): bounded full engagements, no
        triage/ranking — preserved verbatim as the revert path."""
        semaphore = asyncio.Semaphore(self.max_parallel_hosts)
        results = await asyncio.gather(
            *[self._run_host(h, semaphore) for h in pending_hosts],
            return_exceptions=True)
        return {h: (r if not isinstance(r, Exception) else str(r))
                for h, r in zip(pending_hosts, results)}

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

        if live:
            # Discovery POSITIVELY answered for these hosts (nmap -sn / fping) → their
            # reachability is proven, so per-host runs can skip the redundant scan-start
            # reachability blocker instead of risking a false "unreachable" pause.
            self._liveness_proven = True
        else:
            # Last resort: try all candidates (user may have ICMP blocked).  Liveness is
            # NOT proven here, so each host keeps its own (ICMP-aware) reachability gate.
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
        # Per-host agents run under an isolated CHILD session, so their events are
        # stamped with the child session_id.  But the browser's WebSocket subscribes
        # to the PARENT (launch) session, and ws_manager.broadcast() routes strictly
        # by message.session_id — so child-stamped events would land on a channel no
        # one is listening to and the live UI (AI Observability feed, Mission Control,
        # etc.) goes dark for MULTI/CIDR scans.  Re-stamp the WS message to the PARENT
        # session for DELIVERY, keeping host_id so the UI attributes it to the right
        # host.  Mongo storage still uses the child session (findings/intel isolation
        # is a separate path and is untouched) — this only fixes live display routing.
        _parent_sid = str(self.session_id)

        async def _host_broadcast(msg: Any) -> None:
            if isinstance(msg, WebSocketMessage):
                tagged = WebSocketMessage(
                    type       = msg.type,
                    session_id = _parent_sid,   # deliver on the parent's WS channel
                    agent      = msg.agent,
                    data       = msg.data,
                    timestamp  = msg.timestamp,
                    host_id    = host,
                )
                await self.broadcast(tagged)
            elif isinstance(msg, dict):
                msg = dict(msg)
                msg["host_id"]    = host
                msg["session_id"] = _parent_sid
                await self.broadcast(msg)
            else:
                await self.broadcast(msg)

        return _host_broadcast

    # ── Triage scoring ──────────────────────────────────────────────────────────
    def _score_host(self, intel: dict) -> float:
        """Content-agnostic 'promise' score for ranking which host to exploit first.

        Derived ONLY from generic surface signals (open-port count, high-value
        service CLASSES, count of version→CVE leads, presence of an auth surface) —
        never from any CVE id / product / payload literal, so the engine stays
        clean against the no-hardcoded-content guard.  Higher = more promising."""
        if not isinstance(intel, dict):
            return 0.0
        ports = intel.get("open_ports") or []
        services = intel.get("services") or {}
        score = 0.0
        score += 1.0 * len(ports) if isinstance(ports, (list, tuple)) else 0.0
        _HIGH_VALUE = ("http", "https", "smb", "ssh", "rdp", "ftp", "mysql",
                       "postgres", "mssql", "mongodb", "redis", "ldap", "vnc", "telnet")
        svc_blob = " ".join(
            str((v.get("service") if isinstance(v, dict) else v) or "").lower()
            for v in (services.values() if isinstance(services, dict) else [])
        )
        for cls in _HIGH_VALUE:
            if cls in svc_blob:
                score += 2.0
        cves = intel.get("cves") or []
        score += 1.5 * len(cves) if isinstance(cves, (list, tuple)) else 0.0
        if intel.get("login_pages") or "login" in svc_blob:
            score += 1.0
        return float(round(score, 2))

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
