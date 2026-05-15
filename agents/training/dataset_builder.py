"""
dataset_builder.py - assemble fine-tuning datasets from ARGUS scan transcripts.

Why this exists
---------------
After ARGUS runs N engagements it has accumulated a goldmine of
(prompt, response, outcome) triplets:
  - Master planning prompt -> LLM-generated phase plan -> did the
    plan lead to a finding within 1 hour?
  - Recon LLM "extract findings from this nmap output" -> response ->
    did the extraction match what playbook checks confirmed?
  - Decision-engine action selection -> chosen tool -> did the tool
    yield a useful exit code + output?

This module walks the scan logs, joins LLM calls to their downstream
outcomes, and emits JSONL files suitable for SFT (supervised fine-
tuning) or DPO (direct-preference) training of a future ARGUS-tuned
small model.

The output format is the OpenAI / sharegpt-style chat completion:
  {"messages": [{"role":"system","content":"..."},
                {"role":"user","content":"<prompt>"},
                {"role":"assistant","content":"<response>"}],
   "label": "positive" | "negative" | "neutral",
   "outcome": {...},
   "metadata": {...}}

A future model trained on these triples should learn:
  - Which planning prompts that worked → reproduce
  - Which planning prompts that flopped → avoid
  - The LATENCY profile of effective planning (be terser when speed
    matters)

What this is NOT
----------------
It is NOT a trainer.  It only assembles the dataset.  Operators run
the actual fine-tune externally (axolotl / unsloth / openai-finetune).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class OutcomeLabel(str, Enum):
    POSITIVE = "positive"   # plan led to finding / shell within window
    NEGATIVE = "negative"   # plan led to errors / no progress
    NEUTRAL  = "neutral"    # ambiguous; useful as context, not preference


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_LOG_DIR = REPO_ROOT / "logs"
DEFAULT_OUT_FILE = REPO_ROOT / "agents" / "training" / "dataset.jsonl"


# ── Helpers ─────────────────────────────────────────────────────────────

def _safe_load_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not path.exists():
        return out
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except (OSError, IOError):
        pass
    return out


def _parse_ts(ts: Any) -> Optional[float]:
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return None
    return None


# ── Outcome labelling ───────────────────────────────────────────────────

def _label_for_llm_call(
    call:       Dict[str, Any],
    findings:   List[Dict[str, Any]],
    tool_calls: List[Dict[str, Any]],
    events:     List[Dict[str, Any]],
    window_sec: float = 600.0,
) -> Tuple[OutcomeLabel, Dict[str, Any]]:
    """Decide POSITIVE / NEGATIVE / NEUTRAL for a single LLM call.

    Heuristic:
      Look at what happened in the `window_sec` seconds AFTER this
      LLM call's timestamp.
        POSITIVE if any of:
          - HIGH or CRITICAL finding logged
          - Shell event fired
          - 2+ tool calls returned exit 0 with substantial output
        NEGATIVE if:
          - 3+ tool calls in that window returned exit != 0 AND no
            findings of any severity
        NEUTRAL otherwise.
    """
    call_ts = _parse_ts(call.get("ts"))
    if call_ts is None:
        return OutcomeLabel.NEUTRAL, {"reason": "no_timestamp"}
    end_ts = call_ts + window_sec

    # Slice events / findings / tools to the window
    window_findings = [f for f in findings
                       if call_ts <= (_parse_ts(f.get("ts")) or 0) <= end_ts]
    window_tools = [t for t in tool_calls
                    if call_ts <= (_parse_ts(t.get("ts")) or 0) <= end_ts]
    window_events = [e for e in events
                     if call_ts <= (_parse_ts(e.get("ts")) or 0) <= end_ts]

    high_findings = [f for f in window_findings
                     if str(f.get("severity") or "").upper() in ("CRITICAL", "HIGH")]
    shell = any(e.get("event") in ("shell_obtained",) or
                "shell" in str(e.get("type") or "").lower()
                for e in window_events)
    successful_tools = [t for t in window_tools
                        if (t.get("exit_code") == 0) and
                           len((t.get("stdout_tail") or "")) > 50]
    failed_tools = [t for t in window_tools
                    if t.get("exit_code") not in (None, 0)]

    if shell:
        return OutcomeLabel.POSITIVE, {
            "reason": "shell_in_window",
            "shell_events": sum(1 for e in window_events if "shell" in str(e.get("type") or "").lower()),
        }
    if high_findings:
        return OutcomeLabel.POSITIVE, {
            "reason": "high_findings",
            "count":  len(high_findings),
            "titles": [str(f.get("title") or "")[:80] for f in high_findings[:3]],
        }
    if len(successful_tools) >= 2 and not failed_tools:
        return OutcomeLabel.POSITIVE, {
            "reason": "multiple_successful_tools",
            "count":  len(successful_tools),
        }
    if len(failed_tools) >= 3 and not window_findings:
        return OutcomeLabel.NEGATIVE, {
            "reason": "tool_failures_no_findings",
            "count":  len(failed_tools),
        }
    return OutcomeLabel.NEUTRAL, {"reason": "no_clear_outcome"}


# ── Per-session dataset ────────────────────────────────────────────────

def emit_for_session(
    session_dir: Path,
    label_filter: Optional[Iterable[OutcomeLabel]] = None,
) -> Iterable[Dict[str, Any]]:
    """Yield JSONL records for one session.

    label_filter: only emit records whose label is in this set
                  (default: emit all).
    """
    llm_calls  = _safe_load_jsonl(session_dir / "llm_calls.jsonl")
    findings   = _safe_load_jsonl(session_dir / "findings.jsonl")
    tool_calls = _safe_load_jsonl(session_dir / "tool_calls.jsonl")
    events     = _safe_load_jsonl(session_dir / "events.jsonl")

    if not llm_calls:
        return

    session_id = session_dir.name
    label_filter = set(label_filter) if label_filter else None

    for call in llm_calls:
        prompt = call.get("prompt") or call.get("prompt_tail") or ""
        response = call.get("response") or call.get("raw_tail") or ""
        if not prompt or not response:
            continue
        label, reason = _label_for_llm_call(call, findings, tool_calls, events)
        if label_filter and label not in label_filter:
            continue
        record = {
            "messages": [
                {"role": "system",
                 "content": str(call.get("system") or
                                "You are a penetration-testing AI in ARGUS.")},
                {"role": "user",      "content": str(prompt)[:8000]},
                {"role": "assistant", "content": str(response)[:8000]},
            ],
            "label":  label.value,
            "outcome": reason,
            "metadata": {
                "session_id": session_id,
                "agent":      call.get("agent"),
                "model":      call.get("model"),
                "latency":    call.get("latency_sec"),
                "phase":      call.get("phase"),
                "step":       call.get("step"),
                "parse_error": call.get("parse_error"),
                "ts":         call.get("ts"),
            },
        }
        yield record


# ── Driver ──────────────────────────────────────────────────────────────

def build_training_set(
    log_dir: Path = DEFAULT_LOG_DIR,
    out_file: Path = DEFAULT_OUT_FILE,
    label_filter: Optional[Iterable[OutcomeLabel]] = None,
) -> int:
    """Walk every session in log_dir, emit records to out_file.

    Returns count written.
    """
    if not log_dir.exists():
        logger.error("[training] log dir %s does not exist", log_dir)
        return 0
    out_file.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(out_file, "w", encoding="utf-8") as out:
        for session_dir in sorted(log_dir.iterdir()):
            if not session_dir.is_dir():
                continue
            for rec in emit_for_session(session_dir, label_filter):
                out.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                count += 1
    logger.info("[training] wrote %d records to %s", count, out_file)
    return count


# ── CLI ─────────────────────────────────────────────────────────────────

def _cli() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR))
    p.add_argument("--out",     default=str(DEFAULT_OUT_FILE))
    p.add_argument("--only", choices=("positive", "negative", "neutral"),
                   action="append", default=None,
                   help="Only emit records with these labels (may repeat)")
    args = p.parse_args()

    filt = None
    if args.only:
        filt = [OutcomeLabel(x) for x in args.only]

    n = build_training_set(Path(args.log_dir), Path(args.out), filt)
    print(f"wrote {n} records to {args.out}")
    print()
    print("Next steps for actually training a model:")
    print("  1. Inspect a few records:   head -3 {} | jq .".format(args.out))
    print("  2. Split: ~90% train / 10% eval")
    print("  3. Fine-tune via axolotl / unsloth / openai-finetune")
    print("  4. Drop the new model name into OLLAMA_MODEL and restart")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())


__all__ = ["build_training_set", "emit_for_session", "OutcomeLabel"]
