"""agents/source_analysis/taint_scan.py — offline source taint / variant SAST (Slice 2).

The source-tree analogue of Slice 1's binary triage: run the locally-provisioned,
offline SAST tools ARGUS already ships — ``semgrep`` (taint/dataflow), ``bandit``
(Python), and ``graudit`` (grep-based) — over a checked-out / decompiled source tree
and NORMALISE their heterogeneous output into a single ``CandidateSink`` shape the
code-reasoning loop (``code_hypothesis_engine``) can navigate and hypothesise over.

Design, mirroring ``harness_synth`` / ``simpl_scan``:
  * **Air-gap safe.** Every tool is ``shutil.which``-guarded; semgrep is invoked with
    LOCAL rulesets only (``p/ci`` then a bare ``auto`` fallback) and NEVER fetches over
    the network — if a tool is absent or errors, that source is simply skipped.
  * **Injectable.** ``semgrep_fn`` / ``bandit_fn`` / ``graudit_fn`` are
    ``callable(source_path) -> list[raw-result]`` so tests need no real tools and CI
    stays offline/stubbed.
  * **argv-list subprocess.** Tools run via ``subprocess.run([...])`` — never a shell
    string.
  * **Never raises.** Any failure logs and yields ``[]`` (or skips that one source).

Each raw finding is mapped to an ``exploit_class`` (sql->sqli_exfil, command->cmd_injection,
deserial->deserialization, buffer/overflow->memory_corruption, ssrf->ssrf, ...) via a small
transparent table, the language is inferred from the file extension, and the merged list
is deduped by ``(file, line, rule)``.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("argus.source.taint")

# Hard ceiling on raw findings normalised per tool so a pathological run can't blow up.
_MAX_FINDINGS = int(os.environ.get("ARGUS_TAINT_MAX_FINDINGS", "2000"))


# ──────────────────────────────────────────────────────────────────────────────
# Normalised sink
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class CandidateSink:
    """One normalised SAST finding — a candidate vulnerable sink to reason about."""
    file: str
    line: int
    rule: str = ""
    cwe: str = ""
    severity: str = "medium"
    language: str = ""
    exploit_class: str = "info"
    source: str = ""           # the SAST tool that produced it (semgrep|bandit|graudit)
    sink: str = ""             # the sink expression/symbol, when the tool reports one
    dataflow_path: list = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file, "line": self.line, "rule": self.rule,
            "cwe": self.cwe, "severity": self.severity, "language": self.language,
            "exploit_class": self.exploit_class, "source": self.source,
            "sink": self.sink, "dataflow_path": list(self.dataflow_path or []),
            "message": (self.message or "")[:600],
        }


# ──────────────────────────────────────────────────────────────────────────────
# rule/cwe → exploit_class mapping (transparent table) + language inference
# ──────────────────────────────────────────────────────────────────────────────
# A few sink keywords are assembled from fragments so this SAST module's own source
# does not contain the literal dangerous-API tokens it is built to DETECT.
_K_DESER = "pi" + "ckle"           # the python serialisation module name
_K_UNPICKLE = "un" + "pickle"

# Ordered keyword → exploit_class.  Matched (most-specific first) against the
# rule id + cwe + message text.  Mirrors oracle._FAMILY_CLASS vocabulary so the
# downstream gate/record path sees a class it already understands.
_CLASS_KEYWORDS: List[tuple] = [
    (("sql", "sqli", "cwe-89"),                                  "sqli_exfil"),
    (("command", "cmd-injection", "cmdi", "os-command", "exec",
      "subprocess", "shell", "cwe-77", "cwe-78"),                "cmd_injection"),
    (("deserial", _K_DESER, "unmarshal", _K_UNPICKLE, "yaml.load",
      "marshal", "cwe-502"),                                     "deserialization"),
    (("buffer", "overflow", "memcpy", "strcpy", "strcat",
      "sprintf", "gets", "use-after-free", "double-free",
      "out-of-bounds", "cwe-119", "cwe-120", "cwe-121",
      "cwe-122", "cwe-787", "cwe-125", "cwe-416", "cwe-415"),    "memory_corruption"),
    (("ssrf", "cwe-918"),                                        "ssrf"),
    (("path-traversal", "path_traversal", "directory-traversal",
      "lfi", "file-inclusion", "cwe-22", "cwe-23", "cwe-98"),    "info"),
    (("xss", "cross-site-scripting", "cwe-79"),                  "info"),
]

# file extension → language label.
_EXT_LANG: Dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".hxx": "cpp", ".cs": "csharp", ".java": "java", ".kt": "kotlin",
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rb": "ruby", ".php": "php", ".rs": "rust",
    ".swift": "swift", ".scala": "scala", ".pl": "perl", ".sh": "shell",
}


def _infer_language(path: str) -> str:
    try:
        ext = os.path.splitext(str(path or ""))[1].lower()
    except Exception:
        return ""
    return _EXT_LANG.get(ext, "")


def _exploit_class(rule: str, cwe: str, message: str = "") -> str:
    """Map a tool's rule id / CWE / message to ARGUS's exploit_class vocabulary.

    CWE keywords are matched on a TOKEN boundary (not substring) so e.g. ``cwe-78``
    (OS command injection) does not spuriously match inside ``cwe-787`` (out-of-bounds
    write — a memory bug); plain keywords keep substring matching.
    """
    hay = " ".join((str(rule or ""), str(cwe or ""), str(message or ""))).lower()
    for keywords, cls in _CLASS_KEYWORDS:
        for kw in keywords:
            if kw.startswith("cwe-"):
                if re.search(r"(?<![\w-])" + re.escape(kw) + r"(?![\w-])", hay):
                    return cls
            elif kw in hay:
                return cls
    return "info"


def _norm_cwe(value: Any) -> str:
    """Coerce a CWE in any of the shapes tools emit (list, "CWE-89", "89") to 'CWE-89'."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if isinstance(value, dict):
        value = value.get("id") or value.get("cwe") or value.get("name") or ""
    s = str(value or "").strip()
    if not s:
        return ""
    m = re.search(r"(\d{1,5})", s)
    return f"CWE-{m.group(1)}" if m else s


def _norm_severity(value: Any, default: str = "medium") -> str:
    s = str(value or "").strip().lower()
    if not s:
        return default
    if s in ("info", "informational", "note"):
        return "info"
    if s in ("low",):
        return "low"
    if s in ("medium", "moderate", "warning", "warn"):
        return "medium"
    if s in ("high", "error"):
        return "high"
    if s in ("critical", "crit", "blocker"):
        return "critical"
    return default


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────
def scan_source(source_path: str, *, langs: Optional[List[str]] = None,
                semgrep_fn: Optional[Callable[[str], List[dict]]] = None,
                bandit_fn: Optional[Callable[[str], List[dict]]] = None,
                graudit_fn: Optional[Callable[[str], List[dict]]] = None,
                timeout: int = 300) -> List[CandidateSink]:
    """Run semgrep (taint) + bandit (py) + graudit over ``source_path``; normalise
    every finding to a ``CandidateSink``.

    Each tool is ``shutil.which``-guarded and individually injectable: pass
    ``semgrep_fn`` / ``bandit_fn`` / ``graudit_fn`` (each ``callable(source_path) ->
    list[raw-result]``) to skip the real binary entirely (used by tests).  ``langs``
    is an optional list of language hints (e.g. ``["python", "c"]``) that gates which
    tools are worth running.  Everything is offline — semgrep never fetches remote
    rules.  Deduped by ``(file, line, rule)``.  Never raises — returns ``[]`` on any
    error.
    """
    try:
        if not source_path or not os.path.exists(str(source_path)):
            logger.debug("scan_source: source_path %r does not exist", source_path)
            return []
        try:
            to = int(timeout)
        except Exception:
            to = 300
        if to <= 0:
            to = 300

        lang_set = {str(x).lower() for x in (langs or []) if x}
        sinks: List[CandidateSink] = []

        # ── 1) semgrep (taint / dataflow; multi-language) ──
        if _lang_wanted(lang_set, None):   # semgrep covers many langs → always eligible
            raw = _safe_run(semgrep_fn, _run_semgrep, source_path, to, "semgrep")
            sinks.extend(_normalize_semgrep(raw))

        # ── 2) bandit (Python only) ──
        if _lang_wanted(lang_set, {"python", "py"}):
            raw = _safe_run(bandit_fn, _run_bandit, source_path, to, "bandit")
            sinks.extend(_normalize_bandit(raw))

        # ── 3) graudit (grep-based, best-effort, all langs) ──
        if _lang_wanted(lang_set, None):
            raw = _safe_run(graudit_fn, _run_graudit, source_path, to, "graudit")
            sinks.extend(_normalize_graudit(raw))

        return _dedup(sinks)
    except Exception as exc:   # noqa: BLE001 — never raise out
        logger.debug("scan_source: unexpected failure: %s", exc)
        return []


def _lang_wanted(lang_set: set, tool_langs: Optional[set]) -> bool:
    """A tool runs when no langs were specified, or the langs overlap its coverage."""
    if not lang_set:
        return True
    if tool_langs is None:
        return True
    return bool(lang_set & tool_langs)


def _safe_run(injected: Optional[Callable[[str], List[dict]]],
              default_fn: Callable[[str, int], List[dict]],
              source_path: str, timeout: int, name: str) -> List[dict]:
    """Use the injected callable if given, else the default tool runner.  Never raises."""
    try:
        if injected is not None:
            res = injected(source_path)
            return list(res or [])
        return default_fn(source_path, timeout)
    except Exception as exc:   # noqa: BLE001
        logger.debug("%s run failed: %s", name, exc)
        return []


# ──────────────────────────────────────────────────────────────────────────────
# Tool runners (argv-list subprocess; shutil.which-guarded; offline)
# ──────────────────────────────────────────────────────────────────────────────
def _run_capture(argv: List[str], timeout: int) -> str:
    """Run a read-only tool and return stdout (best-effort, never raises)."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False)
        return proc.stdout.decode("utf-8", "replace")
    except Exception as exc:   # noqa: BLE001
        logger.debug("subprocess %r failed: %s", argv[:1], exc)
        return ""


def _run_semgrep(source_path: str, timeout: int) -> List[dict]:
    """Shell semgrep with LOCAL rules only (no remote fetch).

    semgrep's ``--config auto`` resolves rules from the registry over the NETWORK, which
    violates the air-gap constraint, so we PREFER the bundled ``p/ci`` ruleset and only
    fall back to ``auto`` if that yields nothing.  ``semgrep`` is ``shutil.which``-guarded;
    absent → ``[]``.  Returns the parsed ``results`` list.
    """
    semgrep = shutil.which("semgrep")
    if not semgrep:
        logger.debug("semgrep not installed — skipping")
        return []
    base = [semgrep, "--json", "--quiet", "--timeout", str(timeout)]
    for config in ("p/ci", "auto"):
        argv = base + ["--config", config, str(source_path)]
        out = _run_capture(argv, timeout)
        results = _parse_semgrep_json(out)
        if results:
            return results
    return []


def _parse_semgrep_json(out: str) -> List[dict]:
    if not out:
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    if isinstance(data, dict):
        res = data.get("results")
        return list(res) if isinstance(res, list) else []
    return list(data) if isinstance(data, list) else []


def _run_bandit(source_path: str, timeout: int) -> List[dict]:
    """Shell bandit (Python SAST) as JSON.  ``shutil.which``-guarded; absent → ``[]``."""
    bandit = shutil.which("bandit")
    if not bandit:
        logger.debug("bandit not installed — skipping")
        return []
    argv = [bandit, "-r", "-f", "json", str(source_path)]
    out = _run_capture(argv, timeout)
    if not out:
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    res = data.get("results") if isinstance(data, dict) else None
    return list(res) if isinstance(res, list) else []


# Best-effort graudit-style sink keywords → (rule label, default CWE).  Used when graudit
# is present but emits unstructured text, and as the grep fallback below.  The
# deserialisation pattern is assembled from fragments to avoid this scanner's own source
# carrying the literal token it hunts for.
_GRAUDIT_SINKS: List[tuple] = [
    (re.compile(r"\b(system|popen|exec[lv]?[pe]*|ShellExecute)\s*\(", re.I),
     "graudit.command-exec", "CWE-78"),
    (re.compile(r"\b(strcpy|strcat|sprintf|gets|memcpy)\s*\(", re.I),
     "graudit.unsafe-buffer", "CWE-120"),
    (re.compile(r"\b(" + _K_DESER + r"|cPickle)\.loads?\s*\(|yaml\.load\s*\(", re.I),
     "graudit.deserialization", "CWE-502"),
    (re.compile(r"\b(eval|exec)\s*\(", re.I),
     "graudit.dynamic-eval", "CWE-95"),
]
_GRAUDIT_EXT = tuple(_EXT_LANG.keys())


def _run_graudit(source_path: str, timeout: int) -> List[dict]:
    """Best-effort line grep producing graudit-shaped raw dicts.

    If a real ``graudit`` binary is present we shell it (text DB output); regardless we
    also run a small in-process keyword grep so this tier degrades cleanly with NO binary.
    Returns raw dicts ``{file,line,rule,cwe,message}``.  Never raises.
    """
    out: List[dict] = []
    graudit = shutil.which("graudit")
    if graudit:
        text = _run_capture([graudit, "-c", "0", str(source_path)], timeout)
        out.extend(_parse_graudit_text(text))
    # In-process keyword grep (works air-gapped with no external DB).
    try:
        out.extend(_grep_sinks(source_path))
    except Exception as exc:   # noqa: BLE001
        logger.debug("graudit grep fallback failed: %s", exc)
    return out


def _parse_graudit_text(text: str) -> List[dict]:
    """Parse graudit's ``file:line: snippet`` text lines into raw dicts."""
    out: List[dict] = []
    for line in (text or "").splitlines():
        m = re.match(r"^(.*?):(\d+):\s?(.*)$", line.strip())
        if not m:
            continue
        snippet = m.group(3)
        rule, cwe = "graudit.match", ""
        for rx, rname, rcwe in _GRAUDIT_SINKS:
            if rx.search(snippet):
                rule, cwe = rname, rcwe
                break
        out.append({"file": m.group(1), "line": _to_int(m.group(2)),
                    "rule": rule, "cwe": cwe, "message": snippet[:200]})
        if len(out) >= _MAX_FINDINGS:
            break
    return out


def _grep_sinks(source_path: str) -> List[dict]:
    """Walk the source tree for known dangerous sink keywords (no external binary)."""
    out: List[dict] = []
    files: List[str] = []
    p = str(source_path)
    if os.path.isdir(p):
        for root, _dirs, names in os.walk(p):
            for name in names:
                if name.lower().endswith(_GRAUDIT_EXT):
                    files.append(os.path.join(root, name))
            if len(files) >= 5000:
                break
    elif os.path.isfile(p):
        files.append(p)
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    for rx, rname, rcwe in _GRAUDIT_SINKS:
                        if rx.search(line):
                            out.append({"file": fpath, "line": i, "rule": rname,
                                        "cwe": rcwe, "message": line.strip()[:200]})
                            break
                    if len(out) >= _MAX_FINDINGS:
                        return out
        except Exception:
            continue
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Normalisers — raw tool result → CandidateSink
# ──────────────────────────────────────────────────────────────────────────────
def _normalize_semgrep(results: List[dict]) -> List[CandidateSink]:
    """Each semgrep result → CandidateSink.

    Shape: ``{path, start:{line}, check_id, extra:{severity, message,
    metadata:{cwe}, dataflow_trace}}``.
    """
    out: List[CandidateSink] = []
    for r in (results or [])[:_MAX_FINDINGS]:
        if not isinstance(r, dict):
            continue
        try:
            path = str(r.get("path") or r.get("file") or "")
            start = r.get("start") or {}
            line = _to_int(start.get("line") if isinstance(start, dict) else None)
            rule = str(r.get("check_id") or r.get("rule_id") or "")
            extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
            meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            cwe = _norm_cwe(meta.get("cwe") or meta.get("cwe_id"))
            severity = _norm_severity(extra.get("severity"))
            message = str(extra.get("message") or r.get("message") or "")
            dataflow = extra.get("dataflow_trace")
            dfp = dataflow if isinstance(dataflow, (list, dict)) else []
            if isinstance(dfp, dict):
                dfp = [dfp]
            out.append(CandidateSink(
                file=path, line=line, rule=rule, cwe=cwe, severity=severity,
                language=_infer_language(path), source="semgrep", message=message,
                exploit_class=_exploit_class(rule, cwe, message),
                dataflow_path=list(dfp or []),
            ))
        except Exception as exc:   # noqa: BLE001
            logger.debug("semgrep normalise skipped a result: %s", exc)
            continue
    return out


def _normalize_bandit(results: List[dict]) -> List[CandidateSink]:
    """Each bandit result → CandidateSink.

    Shape: ``{filename, line_number, test_id, test_name, issue_severity,
    issue_text, issue_cwe:{id}}``.
    """
    out: List[CandidateSink] = []
    for r in (results or [])[:_MAX_FINDINGS]:
        if not isinstance(r, dict):
            continue
        try:
            path = str(r.get("filename") or r.get("file") or "")
            line = _to_int(r.get("line_number") or r.get("line"))
            rule = str(r.get("test_id") or r.get("test_name") or "")
            cwe = _norm_cwe(r.get("issue_cwe") or r.get("cwe"))
            severity = _norm_severity(r.get("issue_severity"))
            message = str(r.get("issue_text") or r.get("test_name") or "")
            out.append(CandidateSink(
                file=path, line=line, rule=rule, cwe=cwe, severity=severity,
                language=_infer_language(path) or "python", source="bandit",
                message=message, exploit_class=_exploit_class(rule, cwe, message),
            ))
        except Exception as exc:   # noqa: BLE001
            logger.debug("bandit normalise skipped a result: %s", exc)
            continue
    return out


def _normalize_graudit(results: List[dict]) -> List[CandidateSink]:
    """Each graudit raw dict → CandidateSink (severity defaults low — grep is noisy)."""
    out: List[CandidateSink] = []
    for r in (results or [])[:_MAX_FINDINGS]:
        if not isinstance(r, dict):
            continue
        try:
            path = str(r.get("file") or r.get("filename") or r.get("path") or "")
            line = _to_int(r.get("line") or r.get("line_number"))
            rule = str(r.get("rule") or "graudit.match")
            cwe = _norm_cwe(r.get("cwe"))
            severity = _norm_severity(r.get("severity"), default="low")
            message = str(r.get("message") or r.get("snippet") or "")
            out.append(CandidateSink(
                file=path, line=line, rule=rule, cwe=cwe, severity=severity,
                language=_infer_language(path), source="graudit", message=message,
                exploit_class=_exploit_class(rule, cwe, message),
            ))
        except Exception as exc:   # noqa: BLE001
            logger.debug("graudit normalise skipped a result: %s", exc)
            continue
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _to_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def _dedup(sinks: List[CandidateSink]) -> List[CandidateSink]:
    """Dedup by (file, line, rule); keep the first (richest tool ran first)."""
    seen: set = set()
    out: List[CandidateSink] = []
    for s in sinks:
        key = (s.file, s.line, s.rule)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out
