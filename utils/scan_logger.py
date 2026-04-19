"""
scan_logger.py — Per-session end-to-end scan logger for ARGUS.

Produces three files per pentest session under ``logs/<session_id>/``:

1. ``scan.log``        — human-readable text log.  Captures every
   ``logging.info/warning/error`` from every module (root-logger handler
   installed for the session's lifetime).  Use this when you want to read
   the scan like a story.

2. ``events.jsonl``    — structured JSON-lines event stream.  One line per
   high-value event (phase change, finding, error, LLM decision).  Use
   ``jq`` / Python / grep to filter and analyse.

3. ``tool_calls.jsonl``— one line per tool invocation (MCP or local) with
   the full command, duration, exit code, stderr tail and truncated
   stdout tail.  This is what you send back to the developer when a tool
   "should have found something but didn't".

A summary header is written at session start (target, mode, tool count)
and a summary footer at session end (counts of tools/findings/errors,
duration, top errors).

Usage
-----
>>> from utils.scan_logger import start_scan_logger, get_scan_logger, close_scan_logger
>>> slog = start_scan_logger(session_id, target=target, engagement_type="pentest")
>>> slog.log_phase("recon", "start")
>>> slog.log_tool_call("nmap", "-sV -p- 10.0.0.1", duration=42.1, exit_code=0,
...                    stdout_tail="...", stderr_tail="", source="mcp")
>>> slog.log_llm("plan_vuln_scan", prompt_chars=2400, response_chars=800,
...              latency=5.2, model="glm-5")
>>> slog.log_finding("CRITICAL", "RCE on 10.0.0.1:80", "Apache 2.4.49 path traversal")
>>> slog.log_error("phase_exploit", exc=RuntimeError("msfconsole not found"))
>>> close_scan_logger(session_id)

The logger is designed to never raise — any IO/serialisation error is
swallowed so a bad log write never kills a pentest.
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


def _safe_id(session_id: str) -> str:
    """Sanitise session id for use as a directory name."""
    return "".join(c for c in str(session_id) if c.isalnum() or c in ("-", "_")) or "unknown"


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

        ts_dir = self.started_at.strftime("%Y%m%d-%H%M%S")
        self.dir = _LOGS_ROOT / f"{ts_dir}_{_safe_id(session_id)}"
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Fall back to a temp-like location
            self.dir = _LOGS_ROOT
        self.text_path   = self.dir / "scan.log"
        self.events_path = self.dir / "events.jsonl"
        self.tools_path  = self.dir / "tool_calls.jsonl"
        self.summary_path = self.dir / "summary.json"

        # Root-logger handler so EVERY module's logger.info/warning/error
        # is mirrored into scan.log for the session's lifetime.
        fmt = logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
        self._file_handler = logging.FileHandler(
            self.text_path, mode="a", encoding="utf-8"
        )
        self._file_handler.setLevel(logging.INFO)
        self._file_handler.setFormatter(fmt)
        logging.getLogger().addHandler(self._file_handler)
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
                "recent_errors":   self._recent_errors[-50:],
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
        """Phase transition: status in {"start","done","skip","fail"}."""
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
        self._append_text(f"[PHASE] {phase.upper():<12} {status:<5}  {detail}")
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
    ) -> None:
        """Record one LLM invocation (planner / extractor / evaluator)."""
        self.counters["llm_calls"] += 1
        err_flag = " !" if parse_error else ""
        self._append_text(
            f"[LLM]   {step:<24} {latency:>6.2f}s  "
            f"in={prompt_chars}ch out={response_chars}ch {model}{err_flag}"
        )
        if decision:
            self._append_text(f"        └─ decision: {decision[:240]}")
        if reasoning and reasoning != decision:
            self._append_text(f"        └─ reasoning: {reasoning[:240]}")
        self._write_event("llm", {
            "step":           step,
            "model":          model,
            "prompt_chars":   prompt_chars,
            "response_chars": response_chars,
            "latency_sec":    round(latency, 3),
            "parse_error":    parse_error,
            "decision":       decision[:600],
            "reasoning":      reasoning[:1200],
        })

    def log_finding(
        self,
        severity: str,
        title:    str,
        description: str = "",
        **extra: Any,
    ) -> None:
        self.counters["findings"] += 1
        self._append_text(f"[FIND]  {severity:<8} {title[:140]}")
        self._write_event("finding", {
            "severity":    severity,
            "title":       title,
            "description": description[:800],
            **extra,
        })

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
            **extra,
        }
        self._recent_errors.append(rec)
        self._append_text(f"[ERROR] {where:<24} {err_type}: {err_msg[:400]}")
        if tb and tb.strip() != "NoneType: None":
            for line in tb.splitlines()[-12:]:
                self._append_text(f"        {line}")
        self._write_event("error", {**rec, "traceback": tb[:4000]})

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
            try:
                logging.getLogger().removeHandler(self._file_handler)
                self._file_handler.close()
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
