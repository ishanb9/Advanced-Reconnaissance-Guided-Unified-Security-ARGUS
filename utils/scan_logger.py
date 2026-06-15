"""
scan_logger.py — Per-session forensic-grade scan logger for ARGUS.

Produces a forensic-quality bundle per pentest session under
``logs/<ts>_<session_id>/``.  Every file is append-only and the writer is
non-raising so a bad log write never kills a pentest.

Files written
-------------
- ``scan.log``            human-readable narrative (filtered: httpx /
                          urllib3 / httpcore noise routed to ``http.log``)
- ``http.log``            httpx / urllib3 / httpcore traffic (own file so
                          it doesn't drown the narrative)
- ``events.jsonl``        structured event stream (phase / reasoning /
                          info / session_start / session_end)
- ``tool_calls.jsonl``    one line per tool invocation (MCP/local/subagent)
                          with args, duration, exit code, stderr/stdout tails
- ``llm_calls.jsonl``     one line per LLM invocation (model, latency,
                          prompt/response sizes, decision summary, raw tail
                          on parse error)
- ``subagents.jsonl``     subagent lifecycle (start/end with status,
                          findings_added, duration, errors)
- ``findings.jsonl``      one line per finding as it is discovered
- ``ws_events.jsonl``     mirror of the WebSocket event stream so we can
                          replay exactly what the GUI saw
- ``wstg.jsonl``          WSTG phase matrix updates from WebOrchestrator
- ``errors.log``          plain-text error list with full tracebacks
- ``intel_final.json``    full intel snapshot at session-end
- ``findings_final.json`` full findings list at session-end (deduped)
- ``summary.json``        counters, durations, top tools, phase history,
                          per-phase budgets

Public API
----------
>>> from utils.scan_logger import start_scan_logger, get_scan_logger, close_scan_logger
>>> slog = start_scan_logger(session_id, target=target, engagement_type="pentest")
>>> slog.log_phase("recon", "start")
>>> slog.log_tool_call("nmap", "-sV -p- 10.0.0.1", duration=42.1, exit_code=0,
...                    stdout_tail="...", stderr_tail="", source="mcp")
>>> slog.log_llm("plan_vuln_scan", prompt_chars=2400, response_chars=800,
...              latency=5.2, model="glm-5")
>>> slog.log_finding("CRITICAL", "RCE on 10.0.0.1:80", "Apache 2.4.49 path traversal")
>>> slog.log_subagent("SqliSubagent", "start", target="http://x/login")
>>> slog.log_ws_event("plan_step_update", {...})
>>> slog.log_wstg_phase({"phase_id":"info","status":"running",...})
>>> slog.snapshot_intel({...})
>>> slog.snapshot_findings([{...}, ...])
>>> close_scan_logger(session_id)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


# ──────────────────────────────────────────────────────────────────────────
#  Paths / registry
# ──────────────────────────────────────────────────────────────────────────

_LOGS_ROOT = Path(
    os.environ.get("ARGUS_LOG_DIR")
    or (Path(__file__).resolve().parents[1] / "logs")
)
_LOGS_ROOT.mkdir(parents=True, exist_ok=True)

_ACTIVE: Dict[str, "ScanLogger"] = {}
_LOCK = threading.Lock()


# WS event types that arrive in such high volume they would drown the
# ws_events.jsonl file.  Their absence is fine — narrative is preserved
# in scan.log + tool_calls.jsonl.
_WS_NOISE_EVENTS = frozenset({
    "tool_output_chunk",
    "subagent_tool_line",
    "subagent_tool_progress",
    "agent_status_tick",
    "session_heartbeat",
    "live_metric",
    "tool_progress",
})


def _safe_id(session_id: str) -> str:
    """Sanitise session id for use as a directory name."""
    return "".join(c for c in str(session_id) if c.isalnum() or c in ("-", "_")) or "unknown"


def _shrink(value: Any, *, max_str: int = 600, max_items: int = 40) -> Any:
    """Recursively cap string lengths and list/dict size for log payloads.

    Keeps the structure intact so JSON stays valid; just prevents 5 MB
    log lines when an event carries a giant raw_outputs blob.
    """
    try:
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value if len(value) <= max_str else (value[: max_str] + "…")
        if isinstance(value, (list, tuple)):
            sliced = list(value)[: max_items]
            extra  = len(value) - len(sliced)
            out = [_shrink(v, max_str=max_str, max_items=max_items) for v in sliced]
            if extra > 0:
                out.append(f"…(+{extra} more)")
            return out
        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for i, (k, v) in enumerate(value.items()):
                if i >= max_items:
                    out["…"] = f"+{len(value) - max_items} more keys"
                    break
                out[str(k)] = _shrink(v, max_str=max_str, max_items=max_items)
            return out
        return str(value)[: max_str]
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────
#  ScanLogger
# ──────────────────────────────────────────────────────────────────────────

class ScanLogger:
    """Per-session multi-file logger.  All methods are no-op safe."""

    def __init__(self, session_id: str, target: str = "", engagement_type: str = "") -> None:
        self.session_id      = session_id
        self.target          = target
        self.engagement_type = engagement_type
        self.started_at      = datetime.now(timezone.utc)
        self._t_monotonic    = time.monotonic()

        # Running counters exposed in the final summary
        self.counters: Dict[str, int] = {
            "tool_calls": 0,
            "tool_errors": 0,
            "llm_calls": 0,
            "findings": 0,
            "errors": 0,
            "phase_changes": 0,
        }
        # Keep the last handful of errors so we can surface them in the footer
        self._recent_errors: list[Dict[str, Any]] = []
        self._tool_names: Dict[str, int] = {}
        self._phase_history: list[Dict[str, Any]] = []

        # Per-phase budget tracking — how much each phase contributes
        # (tool calls, llm calls, findings, errors, duration).
        self._phase_budget: Dict[str, Dict[str, Any]] = {}
        self._current_phase: Optional[str] = None
        self._phase_started_ts: float = self._t_monotonic
        self._phase_start_counters: Dict[str, int] = dict(self.counters)

        ts_dir = self.started_at.strftime("%Y%m%d-%H%M%S")
        self.dir = _LOGS_ROOT / f"{ts_dir}_{_safe_id(session_id)}"
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Fall back to a temp-like location
            self.dir = _LOGS_ROOT
        # Primary text streams
        self.text_path     = self.dir / "scan.log"
        self.http_path     = self.dir / "http.log"
        self.errors_path   = self.dir / "errors.log"
        # Structured streams (JSON Lines)
        self.events_path   = self.dir / "events.jsonl"
        self.tools_path    = self.dir / "tool_calls.jsonl"
        self.llm_path      = self.dir / "llm_calls.jsonl"
        self.subagents_path= self.dir / "subagents.jsonl"
        self.findings_path = self.dir / "findings.jsonl"
        self.ws_path       = self.dir / "ws_events.jsonl"
        self.wstg_path     = self.dir / "wstg.jsonl"
        # End-of-session snapshots
        self.summary_path        = self.dir / "summary.json"
        self.intel_final_path    = self.dir / "intel_final.json"
        self.findings_final_path = self.dir / "findings_final.json"

        # ── Root-logger handlers ───────────────────────────────────────
        # Two FileHandlers are installed for the session's lifetime:
        #   1. main_handler  → scan.log    (filters httpx / urllib3 / httpcore)
        #   2. http_handler  → http.log    (only httpx / urllib3 / httpcore)
        # Without the filter, scan.log is dominated by Ollama POST chatter
        # and the operator can't see the actual phase / tool / finding
        # narrative.  See ARGUS log-rev plan.
        fmt = logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )

        class _NotHTTP(logging.Filter):
            _NOISE = ("httpx", "httpcore", "urllib3", "asyncio", "anyio")
            def filter(self, record: logging.LogRecord) -> bool:
                n = record.name or ""
                return not any(n == p or n.startswith(p + ".") for p in self._NOISE)

        class _OnlyHTTP(logging.Filter):
            _NOISE = ("httpx", "httpcore", "urllib3")
            def filter(self, record: logging.LogRecord) -> bool:
                n = record.name or ""
                return any(n == p or n.startswith(p + ".") for p in self._NOISE)

        self._file_handler = logging.FileHandler(
            self.text_path, mode="a", encoding="utf-8"
        )
        self._file_handler.setLevel(logging.INFO)
        self._file_handler.setFormatter(fmt)
        self._file_handler.addFilter(_NotHTTP())
        logging.getLogger().addHandler(self._file_handler)

        self._http_handler = logging.FileHandler(
            self.http_path, mode="a", encoding="utf-8"
        )
        self._http_handler.setLevel(logging.INFO)
        self._http_handler.setFormatter(fmt)
        self._http_handler.addFilter(_OnlyHTTP())
        logging.getLogger().addHandler(self._http_handler)

        # Ensure root is at least INFO so our handler actually receives records.
        # Don't lower it below the operator's configured level.
        if logging.getLogger().level > logging.INFO or logging.getLogger().level == logging.NOTSET:
            logging.getLogger().setLevel(logging.INFO)

        self._write_header()

    # ── Header / footer ────────────────────────────────────────────────

    def _write_header(self) -> None:
        header = (
            "\n" + "=" * 78 + "\n"
            f"ARGUS scan log — session {self.session_id}\n"
            f"Target:          {self.target}\n"
            f"Engagement type: {self.engagement_type}\n"
            f"Started (UTC):   {self.started_at.isoformat()}\n"
            f"Log directory:   {self.dir}\n"
            + "=" * 78 + "\n"
        )
        self._append_text(header)
        self._write_event("session_start", {
            "target":          self.target,
            "engagement_type": self.engagement_type,
            "log_dir":         str(self.dir),
        })

    def _write_footer(self) -> None:
        ended = datetime.now(timezone.utc)
        dur   = time.monotonic() - self._t_monotonic
        tool_top = sorted(self._tool_names.items(), key=lambda kv: -kv[1])[:10]
        footer = (
            "\n" + "─" * 78 + "\n"
            f"Scan ended (UTC): {ended.isoformat()}\n"
            f"Duration:         {dur:,.1f} s\n"
            f"Counters:         {self.counters}\n"
            f"Top tools:        {tool_top}\n"
            f"Recent errors ({len(self._recent_errors)} kept):\n"
        )
        for e in self._recent_errors[-20:]:
            footer += f"  [{e.get('where','?')}] {e.get('type','Error')}: {e.get('message','')[:200]}\n"
        footer += "=" * 78 + "\n"
        self._append_text(footer)

        try:
            summary = {
                "session_id":      self.session_id,
                "target":          self.target,
                "engagement_type": self.engagement_type,
                "started_at":      self.started_at.isoformat(),
                "ended_at":        ended.isoformat(),
                "duration_sec":    round(dur, 2),
                "counters":        self.counters,
                "top_tools":       tool_top,
                "phase_history":   self._phase_history,
                "phase_budget":    list(self._phase_budget.values()),
                "recent_errors":   self._recent_errors[-50:],
                "files": {
                    "scan_log":        str(self.text_path.name),
                    "http_log":        str(self.http_path.name),
                    "errors_log":      str(self.errors_path.name),
                    "events":          str(self.events_path.name),
                    "tool_calls":      str(self.tools_path.name),
                    "llm_calls":       str(self.llm_path.name),
                    "subagents":       str(self.subagents_path.name),
                    "findings":        str(self.findings_path.name),
                    "ws_events":       str(self.ws_path.name),
                    "wstg":            str(self.wstg_path.name),
                    "intel_final":     str(self.intel_final_path.name),
                    "findings_final":  str(self.findings_final_path.name),
                },
            }
            self.summary_path.write_text(
                json.dumps(summary, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

        self._write_event("session_end", {"duration_sec": round(dur, 2),
                                          "counters":     self.counters})

    # ── Low-level writers (never raise) ────────────────────────────────

    def _append_text(self, line: str) -> None:
        try:
            with self.text_path.open("a", encoding="utf-8") as f:
                f.write(line if line.endswith("\n") else line + "\n")
        except Exception:
            pass

    def _write_json_line(self, path: Path, payload: Dict[str, Any]) -> None:
        try:
            payload = dict(payload)
            payload.setdefault("ts", datetime.now(timezone.utc).isoformat())
            payload.setdefault("elapsed_sec", round(time.monotonic() - self._t_monotonic, 3))
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, default=str, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _write_event(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> None:
        self._write_json_line(self.events_path,
                              {"event": event_type, "session_id": self.session_id, **(data or {})})

    # ── Public helpers ─────────────────────────────────────────────────

    def log_phase(self, phase: str, status: str, detail: str = "", **extra: Any) -> None:
        """Phase transition: status in {"start","done","skip","fail"}.

        Tracks per-phase budgets — when a phase ends we record the delta
        in tool_calls / llm_calls / findings / errors / duration and dump
        it into ``self._phase_budget`` so ``summary.json`` carries it.
        """
        self.counters["phase_changes"] += 1
        rec = {
            "phase":  phase,
            "status": status,
            "detail": detail,
            **extra,
        }
        self._phase_history.append(
            {**rec, "ts": datetime.now(timezone.utc).isoformat()}
        )

        # Phase budget bookkeeping
        if status == "start":
            self._current_phase = phase
            self._phase_started_ts = time.monotonic()
            self._phase_start_counters = dict(self.counters)
        elif status in ("done", "skip", "fail"):
            try:
                dur = time.monotonic() - self._phase_started_ts
                start = self._phase_start_counters or {}
                budget = {
                    "phase":           phase,
                    "status":          status,
                    "duration_sec":    round(dur, 2),
                    "tool_calls":      self.counters["tool_calls"]   - start.get("tool_calls", 0),
                    "tool_errors":     self.counters["tool_errors"]  - start.get("tool_errors", 0),
                    "llm_calls":       self.counters["llm_calls"]    - start.get("llm_calls", 0),
                    "findings":        self.counters["findings"]     - start.get("findings", 0),
                    "errors":          self.counters["errors"]       - start.get("errors", 0),
                    "ts":              datetime.now(timezone.utc).isoformat(),
                }
                # Keep the most recent budget entry per phase id (a phase can
                # be re-run; we keep the latest).
                self._phase_budget[str(phase)] = budget
                # Append delta line to scan.log so the operator sees it inline
                self._append_text(
                    f"[PHASE] {str(phase).upper():<12} {status:<5}  "
                    f"Δ tool={budget['tool_calls']:<3} llm={budget['llm_calls']:<3} "
                    f"find={budget['findings']:<3} err={budget['errors']:<3} "
                    f"in {budget['duration_sec']:>6.1f}s — {detail}"
                )
                self._write_event("phase_done", budget)
            except Exception:
                pass
            self._current_phase = None
            return

        self._append_text(f"[PHASE] {str(phase).upper():<12} {status:<5}  {detail}")
        self._write_event("phase", rec)

    def log_tool_call(
        self,
        tool:        str,
        args:        str = "",
        *,
        duration:    float = 0.0,
        exit_code:   Optional[int] = None,
        stdout_tail: str = "",
        stderr_tail: str = "",
        source:      str = "mcp",     # "mcp" | "local" | "subagent"
        purpose:     str = "",
        target:      str = "",
        phase:       str = "",
        error:       str = "",
    ) -> None:
        """Record a single tool invocation (one line in tool_calls.jsonl)."""
        self.counters["tool_calls"] += 1
        self._tool_names[tool] = self._tool_names.get(tool, 0) + 1
        if error or (exit_code is not None and exit_code not in (0, None)):
            self.counters["tool_errors"] += 1

        # Human-readable line
        status_glyph = "OK " if (exit_code in (0, None) and not error) else "ERR"
        self._append_text(
            f"[TOOL]  {status_glyph} {tool:<18} exit={exit_code!s:<4} "
            f"{duration:>7.2f}s src={source:<8} {phase:<10} "
            f"{(purpose or args)[:110]}"
        )
        if error:
            self._append_text(f"        └─ error: {error[:300]}")
        if stderr_tail and not error:
            first = stderr_tail.strip().splitlines()[-1] if stderr_tail.strip() else ""
            if first:
                self._append_text(f"        └─ stderr: {first[:300]}")

        self._write_json_line(self.tools_path, {
            "tool":        tool,
            "args":        args[:4000],
            "source":      source,
            "target":      target,
            "phase":       phase,
            "purpose":     purpose,
            "duration_sec": round(duration, 3),
            "exit_code":   exit_code,
            "stdout_tail": (stdout_tail or "")[-2000:],
            "stderr_tail": (stderr_tail or "")[-2000:],
            "error":       error or "",
        })

    def log_llm(
        self,
        step:            str,
        *,
        prompt_chars:    int = 0,
        response_chars:  int = 0,
        latency:         float = 0.0,
        model:           str = "",
        decision:        str = "",
        reasoning:       str = "",
        parse_error:     bool = False,
        raw_tail:        str = "",
        prompt_tail:     str = "",
        agent:           str = "",
        prompt_tokens:   int = 0,
        completion_tokens: int = 0,
        total_tokens:    int = 0,
    ) -> None:
        """Record one LLM invocation (planner / extractor / evaluator).

        Writes to both ``llm_calls.jsonl`` (structured, per-call) and
        ``events.jsonl`` (so the unified event stream stays complete).
        On parse-error, persists the raw response tail so we can debug
        what the model actually said.

        ``prompt_tokens`` / ``completion_tokens`` / ``total_tokens`` carry the
        provider's REAL usage when available (e.g. Anthropic's streamed usage
        block) — these are the authoritative token counts.  The ``*_chars``
        fields are retained for backward compatibility / debugging; they are
        CHARACTER counts, NOT tokens, and must never be presented as tokens
        (that conflation was the wrong token count the user observed).  When a
        provider does not expose usage the token fields stay 0 and consumers may
        fall back to an estimate, clearly labelled as such.
        """
        self.counters["llm_calls"] += 1
        # Aggregate real token usage across the session (0 when unavailable).
        if total_tokens or prompt_tokens or completion_tokens:
            self.counters["prompt_tokens"] = (
                self.counters.get("prompt_tokens", 0) + int(prompt_tokens or 0))
            self.counters["completion_tokens"] = (
                self.counters.get("completion_tokens", 0) + int(completion_tokens or 0))
            self.counters["total_tokens"] = (
                self.counters.get("total_tokens", 0)
                + int(total_tokens or (int(prompt_tokens or 0) + int(completion_tokens or 0))))
        err_flag = " !" if parse_error else ""
        _tok_str = (f" tok={total_tokens or (prompt_tokens + completion_tokens)}"
                    if (total_tokens or prompt_tokens or completion_tokens) else "")
        self._append_text(
            f"[LLM]   {step:<24} {latency:>6.2f}s  "
            f"in={prompt_chars}ch out={response_chars}ch{_tok_str} {model}{err_flag}"
            + (f" agent={agent}" if agent else "")
        )
        if decision:
            self._append_text(f"        └─ decision: {decision[:240]}")
        if reasoning and reasoning != decision:
            self._append_text(f"        └─ reasoning: {reasoning[:240]}")
        if parse_error and raw_tail:
            self._append_text(f"        └─ raw[!]:    {raw_tail[:300]}")
        rec = {
            "step":           step,
            "model":          model,
            "agent":          agent,
            "prompt_chars":   prompt_chars,
            "response_chars": response_chars,
            "prompt_tokens":     int(prompt_tokens or 0),
            "completion_tokens": int(completion_tokens or 0),
            "total_tokens":      int(total_tokens or (int(prompt_tokens or 0)
                                                      + int(completion_tokens or 0))),
            "tokens_estimated":  not bool(total_tokens or prompt_tokens or completion_tokens),
            "latency_sec":    round(latency, 3),
            "parse_error":    parse_error,
            "decision":       (decision or "")[:600],
            "reasoning":      (reasoning or "")[:1200],
            "raw_tail":       (raw_tail or "")[-2000:],
            "prompt_tail":    (prompt_tail or "")[-1500:],
            "phase":          self._current_phase or "",
        }
        # Per-call dedicated stream
        self._write_json_line(self.llm_path, rec)
        # Mirrored into the unified event stream
        self._write_event("llm", rec)

    def log_finding(
        self,
        severity: str = "",
        title:    str = "",
        description: str = "",
        **extra: Any,
    ) -> None:
        """Record a discovered finding.

        Writes to ``findings.jsonl`` (per-finding) AND ``events.jsonl``.
        Accepts arbitrary ``**extra`` so callers can attach finding_id,
        agent, subagent, target, phase, evidence, cves, etc.
        """
        self.counters["findings"] += 1
        sev = (severity or extra.get("severity") or "").upper()
        ttl = title or extra.get("title") or ""
        self._append_text(
            f"[FIND]  {sev:<8} {(ttl or '')[:140]}"
            + (f"  ({extra['phase']})" if extra.get("phase") else "")
        )
        rec = {
            "severity":    sev,
            "title":       ttl,
            "description": (description or "")[:1200],
            "phase":       self._current_phase or extra.get("phase", ""),
            **{k: v for k, v in (extra or {}).items()
               if k not in ("severity", "title", "description")},
        }
        self._write_json_line(self.findings_path, rec)
        self._write_event("finding", rec)

    # ── New first-class signals ────────────────────────────────────────

    def log_subagent(
        self,
        name:        str,
        status:      str,                # start | end | failed | skipped
        *,
        target:      str = "",
        duration:    float = 0.0,
        findings_added: int = 0,
        agent:       str = "",
        phase:       str = "",
        notes:       str = "",
        error:       str = "",
    ) -> None:
        """Record a subagent lifecycle event.

        Operators repeatedly ask "did SqliSubagent fire on URL X?" — this
        method makes the answer one ``grep`` away.
        """
        self._append_text(
            f"[SUB]   {status:<7} {name:<28} on={target[:60]:<60} "
            + (f"+{findings_added} find  {duration:>6.1f}s" if status != "start" else "")
            + (f"  err={error[:120]}" if error else "")
        )
        self._write_json_line(self.subagents_path, {
            "name":            name,
            "status":          status,
            "target":          target,
            "duration_sec":    round(duration, 3),
            "findings_added":  findings_added,
            "agent":           agent,
            "phase":           phase or self._current_phase or "",
            "notes":           (notes or "")[:1200],
            "error":           (error or "")[:1200],
        })
        self._write_event("subagent", {
            "name":   name,
            "status": status,
            "target": target,
            "phase":  phase or self._current_phase or "",
        })

    def log_ws_event(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Mirror a WebSocket broadcast so we can replay what the GUI saw.

        High-volume / chunked event types are skipped to keep the file
        legible.
        """
        if event_type in _WS_NOISE_EVENTS:
            return
        try:
            self._write_json_line(self.ws_path, {
                "type": event_type,
                "data": _shrink(data, max_str=600, max_items=40),
            })
        except Exception:
            pass

    def log_wstg_phase(self, payload: Dict[str, Any]) -> None:
        """Mirror a single WSTG phase update from WebOrchestrator.

        ``payload`` is the dict produced by ``PhaseResult.to_dict()`` —
        we keep the full record so the file IS the WSTG audit trail.
        """
        try:
            self._write_json_line(self.wstg_path, dict(payload or {}))
            phase_id = (payload or {}).get("phase_id", "?")
            status   = (payload or {}).get("status",   "?")
            findings = (payload or {}).get("findings", 0)
            self._append_text(
                f"[WSTG]  {phase_id:<10} {status:<7} findings={findings}"
            )
        except Exception:
            pass

    def snapshot_intel(self, intel: Dict[str, Any]) -> None:
        """Persist the full intel dict to ``intel_final.json``.

        Excludes a few high-volume keys (``raw_outputs``) by default — pass
        ``intel`` with those stripped if you want them included.
        """
        try:
            self.intel_final_path.write_text(
                json.dumps(_shrink(intel, max_str=4000, max_items=200),
                           indent=2, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

    def snapshot_findings(self, findings: list) -> None:
        """Persist the full final findings list to ``findings_final.json``."""
        try:
            self.findings_final_path.write_text(
                json.dumps(findings, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

    def log_error(
        self,
        where: str,
        *,
        exc:     Optional[BaseException] = None,
        message: str = "",
        **extra: Any,
    ) -> None:
        self.counters["errors"] += 1
        err_type = type(exc).__name__ if exc is not None else "Error"
        err_msg  = str(exc) if exc is not None else message
        tb       = traceback.format_exc() if exc is not None else ""
        rec = {
            "where":   where,
            "type":    err_type,
            "message": err_msg,
            "phase":   self._current_phase or extra.get("phase", ""),
            **extra,
        }
        self._recent_errors.append(rec)
        self._append_text(f"[ERROR] {where:<24} {err_type}: {err_msg[:400]}")
        if tb and tb.strip() != "NoneType: None":
            for line in tb.splitlines()[-12:]:
                self._append_text(f"        {line}")
        self._write_event("error", {**rec, "traceback": tb[:4000]})

        # Dedicated errors.log so a deep traceback list is reviewable
        # without grepping through the noisy main scan log.
        try:
            with self.errors_path.open("a", encoding="utf-8") as f:
                ts = datetime.now(timezone.utc).isoformat()
                f.write(
                    f"\n{'─' * 78}\n"
                    f"[{ts}]  where={where}  phase={rec['phase']}  type={err_type}\n"
                    f"message: {err_msg}\n"
                )
                if tb and tb.strip() != "NoneType: None":
                    f.write(tb if tb.endswith("\n") else tb + "\n")
        except Exception:
            pass

    def log_reasoning(self, step: str, reasoning: str = "", decision: str = "", next_action: str = "") -> None:
        """Mirror of master_agent.emit_reasoning — human-readable."""
        self._append_text(f"[THINK] {step:<24} → {decision[:200]}")
        if reasoning:
            self._append_text(f"        reason:  {reasoning[:240]}")
        if next_action:
            self._append_text(f"        next:    {next_action[:240]}")
        self._write_event("reasoning", {
            "step":        step,
            "reasoning":   reasoning[:1200],
            "decision":    decision[:600],
            "next_action": next_action[:600],
        })

    def log_info(self, where: str, message: str, **extra: Any) -> None:
        self._append_text(f"[INFO]  {where:<24} {message[:300]}")
        if extra:
            self._write_event("info", {"where": where, "message": message, **extra})

    # ── Teardown ───────────────────────────────────────────────────────

    def close(self) -> None:
        try:
            self._write_footer()
        finally:
            for h in (getattr(self, "_file_handler", None),
                      getattr(self, "_http_handler", None)):
                try:
                    if h is not None:
                        logging.getLogger().removeHandler(h)
                        h.close()
                except Exception:
                    pass


# ──────────────────────────────────────────────────────────────────────────
#  Registry helpers (session-scoped global)
# ──────────────────────────────────────────────────────────────────────────

def start_scan_logger(session_id: str, target: str = "", engagement_type: str = "") -> ScanLogger:
    with _LOCK:
        existing = _ACTIVE.get(session_id)
        if existing is not None:
            return existing
        slog = ScanLogger(session_id, target=target, engagement_type=engagement_type)
        _ACTIVE[session_id] = slog
        return slog


def get_scan_logger(session_id: Optional[str]) -> Optional[ScanLogger]:
    if not session_id:
        return None
    return _ACTIVE.get(session_id)


def close_scan_logger(session_id: str) -> None:
    with _LOCK:
        slog = _ACTIVE.pop(session_id, None)
    if slog is not None:
        slog.close()


# ──────────────────────────────────────────────────────────────────────────
#  Safe proxy — resilient helpers that do nothing if no active logger
# ──────────────────────────────────────────────────────────────────────────

def _proxy(session_id: Optional[str], method: str, *args: Any, **kwargs: Any) -> None:
    if not session_id:
        return
    slog = _ACTIVE.get(session_id)
    if slog is None:
        return
    try:
        getattr(slog, method)(*args, **kwargs)
    except Exception:
        # Never let logging blow up a pentest
        pass


def log_tool_call(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_tool_call", *args, **kwargs)


def log_llm(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_llm", *args, **kwargs)


def log_phase(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_phase", *args, **kwargs)


def log_error(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_error", *args, **kwargs)


def log_finding(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_finding", *args, **kwargs)


def log_info(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_info", *args, **kwargs)


def log_reasoning(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_reasoning", *args, **kwargs)


def log_subagent(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_subagent", *args, **kwargs)


def log_ws_event(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_ws_event", *args, **kwargs)


def log_wstg_phase(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "log_wstg_phase", *args, **kwargs)


def snapshot_intel(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "snapshot_intel", *args, **kwargs)


def snapshot_findings(session_id: Optional[str], *args: Any, **kwargs: Any) -> None:
    _proxy(session_id, "snapshot_findings", *args, **kwargs)
