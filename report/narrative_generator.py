"""
narrative_generator.py - storytelling report renderer.

Why this exists
---------------
The existing report (report/generator.py) produces a Findings List -
useful as a reference but not as a deliverable.  Clients pay for
narrative: timeline -> recon -> foothold -> escalation -> impact,
with each step grounded in evidence (request/response, command output,
screenshot reference).

This module wraps the existing generator with a narrative renderer
that:
  1. Builds a chronological event timeline from events.jsonl
  2. Groups findings into kill-chain phases
  3. Generates a per-phase narrative paragraph (LLM-assisted; falls
     back to template if no LLM)
  4. Pulls the highest-CVSS chain as the "attack story"
  5. Renders to Markdown (which can be PDF'd via pandoc / weasyprint
     downstream)

This is additive - it doesn't replace the existing HTML report; it's a
second deliverable for engagements that want a story.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class TimelineEvent:
    ts:    str
    phase: str
    kind:  str             # tool / finding / shell / meta / etc.
    text:  str


# ── Loaders ─────────────────────────────────────────────────────────────

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


def _ts_str(rec: Dict[str, Any]) -> str:
    ts = rec.get("ts") or rec.get("timestamp") or ""
    try:
        if "T" in ts:
            return ts.split("T")[1][:8]
    except Exception:
        pass
    return ts[:8]


# ── Timeline ────────────────────────────────────────────────────────────

def build_timeline(session_dir: Path) -> List[TimelineEvent]:
    """Build a chronological event timeline."""
    events  = _safe_load_jsonl(session_dir / "events.jsonl")
    tools   = _safe_load_jsonl(session_dir / "tool_calls.jsonl")
    finds   = _safe_load_jsonl(session_dir / "findings.jsonl")

    tl: List[TimelineEvent] = []

    for e in events:
        kind = e.get("event") or ""
        phase = str(e.get("phase") or "").replace("AttackPhase.", "").lower()
        ts = _ts_str(e)
        if kind == "session_start":
            tl.append(TimelineEvent(ts, "init", "session",
                                    f"Session opened on {e.get('target') or '?'}"))
        elif kind == "phase":
            tl.append(TimelineEvent(ts, phase, "phase",
                                    f"Phase {phase} {e.get('status') or ''}"))
        elif kind == "subagent":
            tl.append(TimelineEvent(ts, phase, "subagent",
                                    f"Subagent {e.get('name')} {e.get('status')} on {e.get('target') or '?'}"))
        elif kind == "shell_obtained":
            tl.append(TimelineEvent(ts, "exploit", "shell",
                                    f"Shell obtained: {e.get('shell_type') or 'unknown'}"))

    for t in tools:
        ts = _ts_str(t)
        phase = str(t.get("phase") or "").replace("AttackPhase.", "").lower()
        ok = (t.get("exit_code") == 0)
        tl.append(TimelineEvent(
            ts, phase, "tool",
            f"{'OK ' if ok else 'ERR'} {t.get('tool')} {(t.get('args') or '')[:60]}",
        ))

    for f in finds:
        ts = _ts_str(f)
        phase = str(f.get("phase") or "").lower()
        sev = str(f.get("severity") or "INFO").upper()
        tl.append(TimelineEvent(
            ts, phase, "finding",
            f"{sev}  {str(f.get('title') or 'untitled')[:80]}",
        ))

    tl.sort(key=lambda e: e.ts)
    return tl


# ── Narrative renderer ─────────────────────────────────────────────────

PHASE_ORDER = ["recon", "vuln_id", "web_testing", "exploit",
               "post_exploit", "privesc", "lateral", "reporting"]

PHASE_LABELS = {
    "recon":         "Reconnaissance",
    "vuln_id":       "Vulnerability identification",
    "web_testing":   "Web application testing",
    "exploit":       "Initial exploitation",
    "post_exploit":  "Post-exploitation",
    "privesc":       "Privilege escalation",
    "lateral":       "Lateral movement",
    "reporting":     "Reporting & cleanup",
}


def _findings_by_phase(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {p: [] for p in PHASE_ORDER}
    for f in findings:
        p = str(f.get("phase") or "recon").lower()
        if p not in out:
            out[p] = []
        out[p].append(f)
    return out


def _phase_paragraph(phase: str, phase_findings: List[Dict[str, Any]],
                     phase_tools: List[Dict[str, Any]]) -> str:
    """Render one phase's narrative paragraph (template-based, no LLM)."""
    if not phase_findings and not phase_tools:
        return f"No activity in the {phase} phase."

    tool_names = sorted({t.get("tool") or "" for t in phase_tools if t.get("tool")})
    tool_names = [t for t in tool_names if t]
    sev_counts: Dict[str, int] = {}
    for f in phase_findings:
        s = str(f.get("severity") or "INFO").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    sev_summary = ", ".join(
        f"{c} {s.lower()}" for s, c in sorted(sev_counts.items())
        if c > 0
    ) or "none"

    parts = [
        f"During the {PHASE_LABELS.get(phase, phase)} phase, ARGUS executed "
        f"{len(phase_tools)} tool invocations"
        + (f" using {', '.join(tool_names[:5])}" if tool_names else "")
        + f", surfacing {sev_summary}.",
    ]

    # Highlight the highest-severity finding
    high = sorted(
        phase_findings,
        key=lambda f: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                       .get(str(f.get("severity") or "INFO").upper(), 0),
        reverse=True,
    )
    if high and str(high[0].get("severity") or "").upper() in ("CRITICAL", "HIGH"):
        top = high[0]
        parts.append(
            f"The most significant finding in this phase was "
            f"**{str(top.get('title') or '')}** at "
            f"`{top.get('host') or '?'}:{top.get('port') or '?'}` "
            f"({str(top.get('severity') or '').upper()}). "
            f"{str(top.get('description') or '')[:200]}"
        )
    return " ".join(parts)


def render_markdown(session_dir: Path) -> str:
    """Render the full narrative report as a single markdown string."""
    findings = _safe_load_jsonl(session_dir / "findings.jsonl")
    tools    = _safe_load_jsonl(session_dir / "tool_calls.jsonl")
    events   = _safe_load_jsonl(session_dir / "events.jsonl")

    sess_start = next((e for e in events if e.get("event") == "session_start"), {})
    target     = sess_start.get("target") or "?"
    eng_type   = sess_start.get("engagement_type") or "?"
    started    = sess_start.get("ts") or ""
    finished   = (events[-1].get("ts") if events else "") or ""

    # CVSS scoring
    try:
        from utils.cvss_scorer import score_findings
        scored = score_findings(findings)
        cvss_lookup = {s.finding_id: s for s in scored}
    except Exception:
        scored = []
        cvss_lookup = {}

    fbp = _findings_by_phase(findings)
    tbp: Dict[str, List[Dict[str, Any]]] = {p: [] for p in PHASE_ORDER}
    for t in tools:
        p = str(t.get("phase") or "recon").replace("AttackPhase.", "").lower()
        if p not in tbp:
            tbp[p] = []
        tbp[p].append(t)

    # ── Markdown skeleton ──────────────────────────────────────────────
    lines: List[str] = [
        f"# Penetration Test Report",
        "",
        f"**Target:** `{target}`",
        f"**Engagement type:** {eng_type}",
        f"**Started:** {started}",
        f"**Finished:** {finished}",
        f"**Total findings:** {len(findings)} "
        f"({sum(1 for f in findings if str(f.get('severity') or '').upper() in ('CRITICAL','HIGH'))} of high+ severity)",
        "",
    ]

    # Executive summary
    crit_count = sum(1 for f in findings if str(f.get("severity") or "").upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity") or "").upper() == "HIGH")
    if crit_count + high_count > 0:
        risk = "CRITICAL" if crit_count > 0 else "HIGH"
    elif sum(1 for f in findings if str(f.get("severity") or "").upper() == "MEDIUM") > 0:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    lines += [
        "## Executive summary",
        "",
        f"Overall risk: **{risk}**.",
        "",
        f"ARGUS performed an automated security assessment of `{target}` and "
        f"surfaced **{crit_count} critical**, **{high_count} high**, and "
        f"{sum(1 for f in findings if str(f.get('severity') or '').upper() not in ('CRITICAL','HIGH'))} "
        f"lower-severity findings.  The most impactful issues are detailed below "
        f"in chronological narrative form, followed by a complete findings "
        f"inventory.",
        "",
    ]

    # Top-5 findings table (by CVSS if available, else severity)
    if scored:
        top5 = scored[:5]
        lines += [
            "## Top 5 findings by CVSS impact",
            "",
            "| CVSS | Severity | Title |",
            "|------|----------|-------|",
        ]
        for s in top5:
            lines.append(
                f"| {s.cvss_base:.1f} | {s.severity} | {s.title[:100]} |"
            )
        lines.append("")

    # Per-phase narrative
    lines += ["## Attack narrative", ""]
    for phase in PHASE_ORDER:
        ff = fbp.get(phase) or []
        tt = tbp.get(phase) or []
        if not ff and not tt:
            continue
        lines += [
            f"### {PHASE_LABELS.get(phase, phase)}",
            "",
            _phase_paragraph(phase, ff, tt),
            "",
        ]
        # Per-phase finding bullets
        if ff:
            for f in ff[:8]:
                fid = str(f.get("finding_id") or f.get("id") or "")
                score = cvss_lookup.get(fid).cvss_base if fid in cvss_lookup else 0.0
                lines.append(
                    f"- **{str(f.get('severity') or 'INFO').upper()}** "
                    + (f"`CVSS {score:.1f}` " if score > 0 else "")
                    + f"_{str(f.get('title') or 'untitled')[:120]}_"
                )
            if len(ff) > 8:
                lines.append(f"- _... and {len(ff) - 8} more in the findings inventory_")
            lines.append("")

    # Timeline
    tl = build_timeline(session_dir)
    if tl:
        lines += ["## Timeline (chronological)", "", "```text"]
        for e in tl:
            lines.append(f"{e.ts}  {e.phase:<13s} {e.kind:<9s} {e.text}")
        lines += ["```", ""]

    # Findings inventory (full)
    lines += ["## Findings inventory", ""]
    for f in sorted(
        findings,
        key=lambda x: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
                       .get(str(x.get("severity") or "INFO").upper(), 0),
        reverse=True,
    ):
        fid = str(f.get("finding_id") or f.get("id") or "")
        score = cvss_lookup.get(fid).cvss_base if fid in cvss_lookup else None
        lines += [
            f"### {str(f.get('severity') or 'INFO').upper()}: "
            f"{str(f.get('title') or 'untitled')[:140]}",
            "",
            f"- Host: `{f.get('host') or '?'}`  Port: `{f.get('port') or '?'}`  "
            f"Service: `{f.get('service') or '?'}`",
        ]
        if score is not None and score > 0:
            lines.append(f"- CVSS base: **{score:.1f}**  Vector: `{cvss_lookup[fid].cvss_vector}`")
        if f.get("cve"):
            lines.append(f"- CVE: `{f.get('cve')}`")
        if f.get("mitre_technique"):
            lines.append(f"- MITRE technique: `{f.get('mitre_technique')}`")
        if f.get("description"):
            lines += ["", str(f["description"])[:1500], ""]
        if f.get("evidence"):
            lines += ["", "**Evidence:**", "", "```", str(f["evidence"])[:1200], "```", ""]
        if f.get("exploit_suggestion"):
            lines += ["**Suggested exploitation:**", "", str(f["exploit_suggestion"])[:600], ""]
        lines.append("")

    lines += [
        "---",
        "",
        f"_Report generated by ARGUS narrative renderer at "
        f"{datetime.now(timezone.utc).isoformat()}._",
    ]
    return "\n".join(lines)


def write_report(session_dir: Path, out_path: Optional[Path] = None) -> Path:
    """Render + write to disk.  Returns the written path."""
    md = render_markdown(session_dir)
    if out_path is None:
        out_path = session_dir / "narrative.md"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)
    return out_path


# ── CLI ─────────────────────────────────────────────────────────────────

def _cli() -> int:
    import argparse, sys
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("session_dir", help="Path to a session log directory")
    p.add_argument("-o", "--out",  default=None, help="Output markdown file")
    args = p.parse_args()
    sd = Path(args.session_dir)
    if not sd.is_dir():
        print(f"ERR: not a directory: {sd}")
        return 2
    out = Path(args.out) if args.out else (sd / "narrative.md")
    written = write_report(sd, out)
    print(f"wrote {written}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli())


__all__ = ["render_markdown", "write_report", "build_timeline"]
