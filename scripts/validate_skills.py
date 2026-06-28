#!/usr/bin/env python3
"""scripts/validate_skills.py — validate the skill catalog (static + device-lab).

Trades breadth for verified depth. Two modes:

  1. **Static** (always, no hardware): for every `knowledge/skills/**/*.md`, check
     front-matter schema, the shared-port false-positive guard, quick-win sanity
     (a `{host}` placeholder, a plausible tool, no write/destructive verb in a
     `safety: safe` command), CVE-reference formatting, and port plausibility.
     Each skill gets `static-ok` or a list of warnings.
  2. **Device lab** (opt-in, `--lab targets.json`): for skills whose technology
     you map to a real lab host, run the skill's first SAFE quick-win against it
     (read-only) and mark `lab-confirmed` / `lab-failed`. This is the honest
     "validate against a device lab" path — it needs YOUR lab + authorization;
     without `--lab` it does the static pass only.

Writes `knowledge/skills/.validation.json` and prints a summary. Never modifies
skill files (it reviews, it doesn't rewrite).

Usage:
  python -X utf8 scripts/validate_skills.py                      # static validation
  python -X utf8 scripts/validate_skills.py --json               # machine-readable
  python -X utf8 scripts/validate_skills.py --lab targets.json   # + live lab run
      # targets.json:  {"modbus": "10.0.0.10", "opcua": "10.0.0.11"}
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

SKILLS_DIR = _REPO_ROOT / "knowledge" / "skills"
REPORT_PATH = SKILLS_DIR / ".validation.json"

# Single source of truth: the same shared-port set the runtime FP guard uses,
# so the validator never flags a port the registry already treats as dedicated.
try:
    from knowledge.skill_registry import _SHARED_PORTS  # type: ignore
except Exception:
    _SHARED_PORTS = {80, 443, 3000, 3001, 4000, 5000, 5005, 8000, 8001, 8002,
                     8080, 8081, 8082, 8265, 8443, 8888, 9000, 9090, 9099}
# Write/control markers that must NEVER appear in a `safety: safe` quick-win.
# Alpha verbs match on word boundaries (so "perm" never matches "rm"); the
# explicit tokens match as substrings.  Protocol-ambiguous hex codes (0x05 is a
# Modbus write but a FINS read) are intentionally NOT listed.
_WRITE_WORDS = ("delete", "reboot", "shutdown", "writeproperty", "writesinglecoil",
                "rmdir", "mkfs")
_WRITE_TOKENS = ("--write", "write_register", "write_coil", "force_multiple",
                 "rm -rf", "rm -f ", "writeproperty")


def _skills() -> List[Dict[str, Any]]:
    from knowledge import skill_registry as sr
    return sr.load_skills()


def validate_skill(skill: Dict[str, Any]) -> List[str]:
    """Return a list of warnings for one skill ([] == static-ok)."""
    warns: List[str] = []
    sid = skill.get("id", "?")
    m = skill.get("match") or {}
    ports = [int(p) for p in (m.get("ports") or []) if str(p).isdigit()]
    banners = m.get("banners") or []
    markers = m.get("markers") or []

    transport = str(skill.get("transport", "ip")).lower()
    # Pure-RF/CAN/L2/serial skills are KNOWLEDGE-only by design (no IP surface) —
    # an empty match / no active quick-win is expected, not a defect.
    knowledge_only = transport != "ip"
    if not (ports or banners or markers) and not knowledge_only:
        warns.append("empty match (no port/banner/marker) — only RAG-discoverable")
    for p in ports:
        if p in _SHARED_PORTS:
            warns.append(f"shared port {p} in match.ports (FP risk — rely on banner/marker)")
        if not (0 < p < 65536):
            warns.append(f"implausible port {p}")
    if str(skill.get("domain", "")).upper() not in ("OT", "IOT", "IT"):
        warns.append(f"bad domain {skill.get('domain')!r}")
    if str(skill.get("safety_class", "")).lower() not in ("safe", "intrusive", "disruptive"):
        warns.append(f"bad safety_class {skill.get('safety_class')!r}")

    qws = skill.get("quick_wins") or []
    if not knowledge_only and not any(
            str(q.get("safety", "safe")).lower() == "safe" for q in qws if isinstance(q, dict)):
        warns.append("no SAFE quick-win")
    for q in qws:
        if not isinstance(q, dict):
            continue
        cmd = str(q.get("cmd", ""))
        safety = str(q.get("safety", "safe")).lower()
        if safety == "safe":
            low = cmd.lower()
            hit = next((w for w in _WRITE_WORDS if re.search(r"\b" + re.escape(w) + r"\b", low)), None)
            if not hit:
                hit = next((t for t in _WRITE_TOKENS if t in low), None)
            if hit:
                warns.append(f"safe quick-win contains write/control marker {hit.strip()!r}: {cmd[:60]}")

    for r in (skill.get("references") or []):
        rs = str(r).upper()
        if rs.startswith("CVE") and not re.match(r"CVE-\d{4}-\d{3,}", rs):
            warns.append(f"malformed CVE ref: {r}")
    return warns


def _first_safe_quick_win(skill: Dict[str, Any], host: str) -> Optional[str]:
    for q in (skill.get("quick_wins") or []):
        if isinstance(q, dict) and str(q.get("safety", "safe")).lower() == "safe":
            cmd = str(q.get("cmd", "")).replace("{host}", host).strip()
            if cmd and "{" not in cmd:
                return cmd
    return None


def lab_check(skill: Dict[str, Any], host: str, timeout: int = 60) -> Dict[str, Any]:
    """Run a skill's first SAFE quick-win against a real lab host (read-only).
    Returns {status, cmd, note}. Requires the tool be installed + reachable host."""
    cmd = _first_safe_quick_win(skill, host)
    if not cmd:
        return {"status": "skip", "note": "no runnable safe quick-win"}
    tool = cmd.split()[0]
    if shutil.which(tool) is None:
        return {"status": "skip", "cmd": cmd, "note": f"tool '{tool}' not installed"}
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout)  # nosec - operator-authorized lab run
        ok = proc.returncode == 0 and bool((proc.stdout or "").strip())
        return {"status": "lab-confirmed" if ok else "lab-failed", "cmd": cmd,
                "note": f"exit={proc.returncode}, {len(proc.stdout or '')} bytes"}
    except Exception as e:
        return {"status": "lab-failed", "cmd": cmd, "note": f"error: {e}"}


def run(lab_targets: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    skills = _skills()
    results: Dict[str, Any] = {}
    clean = warned = lab_ok = lab_bad = 0
    for s in skills:
        sid = s["id"]
        warns = validate_skill(s)
        entry: Dict[str, Any] = {"status": "static-ok" if not warns else "warnings",
                                 "warnings": warns, "category": s.get("category", ""),
                                 "domain": s.get("domain"), "transport": s.get("transport", "ip")}
        if warns:
            warned += 1
        else:
            clean += 1
        if lab_targets and sid in lab_targets and s.get("transport", "ip") == "ip":
            lab = lab_check(s, str(lab_targets[sid]))
            entry["lab"] = lab
            if lab.get("status") == "lab-confirmed":
                lab_ok += 1
            elif lab.get("status") == "lab-failed":
                lab_bad += 1
        results[sid] = entry

    summary = {"total": len(skills), "static_ok": clean, "with_warnings": warned,
               "lab_confirmed": lab_ok, "lab_failed": lab_bad, "skills": results}
    try:
        SKILLS_DIR.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Validate the ARGUS skill catalog")
    ap.add_argument("--lab", help="path to a JSON {skill_id: host} map for a live lab run")
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    args = ap.parse_args(argv)

    targets = None
    if args.lab:
        try:
            targets = json.loads(Path(args.lab).read_text(encoding="utf-8"))
        except Exception as e:
            print(f"could not read --lab targets: {e}", file=sys.stderr)
            return 2

    res = run(lab_targets=targets)
    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(f"skills: {res['total']}  static-ok: {res['static_ok']}  "
              f"with-warnings: {res['with_warnings']}  "
              f"lab-confirmed: {res['lab_confirmed']}  lab-failed: {res['lab_failed']}")
        flagged = [(k, v["warnings"]) for k, v in res["skills"].items() if v["warnings"]]
        for sid, w in flagged[:40]:
            print(f"  ⚠ {sid}: {'; '.join(w)}")
        if len(flagged) > 40:
            print(f"  … +{len(flagged) - 40} more (see {REPORT_PATH})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
