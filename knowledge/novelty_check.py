"""knowledge/novelty_check.py — offline novelty correlation for the triage gate.

The honest answer ARGUS is allowed to give about a freshly-found native bug is NOT
"this is a 0-day" — that claim needs a vendor/coordination process no air-gapped tool
can run.  What it CAN do, fully offline, is correlate a (component, version,
exploit_class) tuple against the local public-vulnerability evidence it already ships
with, and report one of three conservative verdicts:

  * ``known-nday``            — a credible local match exists (ExploitDB / known-CVE /
                                local-NVD feed); this is almost certainly a known issue.
  * ``no-known-public-match`` — sources RAN and found nothing; a **CANDIDATE-NOVEL**
                                flag for a human to confirm, never an asserted 0-day.
  * ``undetermined``          — no usable component string (can't correlate at all).

Three best-effort offline sources, each wrapped so a missing/broken source yields ``[]``
rather than an exception:

  1. ExploitDB via ``searchsploit -j`` (guarded by ``shutil.which('searchsploit')``;
     injectable as ``searchsploit_fn`` for tests — never shells out under test).
  2. The local known-CVE set (``utils.model_capability.load_known_cves`` by default),
     filtered to entries that mention the component.
  3. An optional local-NVD JSON feed (``nvd_dir`` arg or ``KB_NVD_DIR`` env) — *.json
     files scanned for the component keyword / a matching CPE string.

Air-gapped, stdlib-only, deterministic, and it NEVER raises: any failure degrades to the
most conservative honest verdict.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("argus.knowledge.novelty")

# Hard cap on the local-NVD scan so a huge feed dir can't stall the triage gate.
_NVD_MAX_FILES = int(os.environ.get("KB_NVD_MAX_FILES", "400"))
# searchsploit can hang on a corrupt DB; keep the offline call bounded.
_SEARCHSPLOIT_TIMEOUT = int(os.environ.get("KB_SEARCHSPLOIT_TIMEOUT", "20"))


def assess(component: str, version: str, exploit_class: str, *,
           searchsploit_fn: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
           known_cves: Optional[Set[str]] = None,
           nvd_dir: Optional[str] = None) -> Dict[str, Any]:
    """Offline novelty correlation for a (component, version, exploit_class) tuple.

    Returns ``{label, evidence, matches}`` where ``label`` is one of
    ``'known-nday' | 'no-known-public-match' | 'undetermined'``.

    ``'no-known-public-match'`` is a CANDIDATE-NOVEL flag for a human to confirm — it is
    NEVER an asserted 0-day.  ``searchsploit_fn`` is injectable for tests (default shells
    the offline ExploitDB via ``searchsploit -j``, guarded by ``shutil.which``).  Pure
    apart from the optional offline source reads; never raises.
    """
    comp = _clean(component)
    ver = _clean(version)
    eclass = _clean(exploit_class) or "unknown"

    # No usable component → we cannot correlate anything honestly.
    if not comp or comp.lower() in ("unknown", "n/a", "none", "null"):
        return {
            "label": "undetermined",
            "evidence": "No component identified; cannot correlate against public sources.",
            "matches": [],
        }

    matches: List[Dict[str, Any]] = []
    # Each source is independently guarded: a failure yields [] and is logged at debug.
    matches.extend(_from_searchsploit(comp, ver, searchsploit_fn))
    matches.extend(_from_known_cves(comp, ver, known_cves))
    matches.extend(_from_local_nvd(comp, ver, nvd_dir))

    matches = _dedup(matches)

    label_parts = " ".join(p for p in (comp, ver) if p)
    if matches:
        srcs = sorted({str(m.get("source") or "?") for m in matches})
        evidence = (f"Found {len(matches)} credible public match(es) for {label_parts} "
                    f"(sources: {', '.join(srcs)}) — likely a known n-day, not novel.")
        return {"label": "known-nday", "evidence": evidence, "matches": matches}

    # Sources ran but found nothing → conservative candidate-novel flag (human-confirm).
    evidence = (f"No known public CVE or ExploitDB entry matches {label_parts or comp} "
                f"for {eclass}")
    return {"label": "no-known-public-match", "evidence": evidence, "matches": []}


# ── source 1: ExploitDB via searchsploit -j ──────────────────────────────────
def _from_searchsploit(component: str, version: str,
                       searchsploit_fn: Optional[Callable[[str], List[Dict[str, Any]]]],
                       ) -> List[Dict[str, Any]]:
    """ExploitDB matches.  ``searchsploit_fn`` overrides the default shell-out (tests)."""
    try:
        rows = (searchsploit_fn(component) if searchsploit_fn is not None
                else _default_searchsploit(component))
    except Exception as exc:   # noqa: BLE001 — a broken source must not break triage
        logger.debug("searchsploit source failed for %r: %s", component, exc)
        return []
    out: List[Dict[str, Any]] = []
    for row in (rows or []):
        if not isinstance(row, dict):
            continue
        title = str(row.get("Title") or row.get("title") or "").strip()
        if not title or not _mentions(title, component):
            continue
        out.append({
            "source": "exploitdb",
            "id": str(row.get("EDB-ID") or row.get("id") or "").strip(),
            "title": title[:200],
            "version_match": _version_in(title, version),
            "ref": str(row.get("Path") or row.get("path") or "").strip()[:200],
        })
    return out


def _default_searchsploit(component: str) -> List[Dict[str, Any]]:
    """Shell the OFFLINE ExploitDB mirror via ``searchsploit -j`` (argv, never a shell
    string).  Returns the parsed ``RESULTS_EXPLOIT`` rows, or [] if the tool is absent."""
    binp = shutil.which("searchsploit")
    if not binp:
        return []
    argv = [binp, "--colour", "-j", component]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=_SEARCHSPLOIT_TIMEOUT, check=False)
    except Exception as exc:   # noqa: BLE001 — timeout / OS error → no matches
        logger.debug("searchsploit subprocess failed: %s", exc)
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return []
    rows = data.get("RESULTS_EXPLOIT") if isinstance(data, dict) else None
    return rows if isinstance(rows, list) else []


# ── source 2: local known-CVE set ────────────────────────────────────────────
def _from_known_cves(component: str, version: str,
                     known_cves: Optional[Set[str]]) -> List[Dict[str, Any]]:
    """Filter the local known-CVE set to entries mentioning the component."""
    try:
        cves = known_cves if known_cves is not None else _load_known_cves()
    except Exception as exc:   # noqa: BLE001
        logger.debug("known-CVE source failed: %s", exc)
        return []
    if not cves:
        return []
    out: List[Dict[str, Any]] = []
    for entry in cves:
        text = str(entry or "")
        # A bare "CVE-YYYY-NNNN" id carries no component context — it can't be a credible
        # component match on its own, so only entries that NAME the component count.
        if not _mentions(text, component) or _looks_like_bare_cve(text):
            continue
        cid_m = re.search(r"CVE-\d{4}-\d{4,7}", text, re.I)
        out.append({
            "source": "known_cve",
            "id": (cid_m.group(0).upper() if cid_m else ""),
            "title": text[:200],
            "version_match": _version_in(text, version),
            "ref": "",
        })
    return out


def _load_known_cves() -> Set[str]:
    """Best-effort default known-CVE loader (kept import-local so a refactor of
    ``utils.model_capability`` can't break import of this leaf module)."""
    try:
        from utils.model_capability import load_known_cves
        loaded = load_known_cves()
        return loaded if isinstance(loaded, set) else set(loaded or [])
    except Exception as exc:   # noqa: BLE001
        logger.debug("load_known_cves unavailable: %s", exc)
        return set()


# ── source 3: optional local-NVD JSON feed ───────────────────────────────────
def _from_local_nvd(component: str, version: str,
                    nvd_dir: Optional[str]) -> List[Dict[str, Any]]:
    """Scan ``*.json`` under ``nvd_dir`` (or ``$KB_NVD_DIR``) for component keyword / CPE
    hits.  Bounded by ``_NVD_MAX_FILES``; every read is individually guarded."""
    root = (nvd_dir or os.environ.get("KB_NVD_DIR") or "").strip()
    if not root or not os.path.isdir(root):
        return []
    needle = component.lower()
    out: List[Dict[str, Any]] = []
    try:
        names = sorted(n for n in os.listdir(root) if n.lower().endswith(".json"))
    except Exception as exc:   # noqa: BLE001
        logger.debug("local-NVD listing failed for %r: %s", root, exc)
        return []
    for name in names[:_NVD_MAX_FILES]:
        path = os.path.join(root, name)
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except Exception:
            continue
        low = text.lower()
        # Match on a plain keyword hit OR a CPE product token (cpe:.../<product>:...).
        cpe_hit = re.search(r"cpe:[^\"'\s]*:" + re.escape(needle) + r"[:\"'\s]", low)
        if needle not in low and not cpe_hit:
            continue
        cid_m = re.search(r"CVE-\d{4}-\d{4,7}", text, re.I)
        out.append({
            "source": "local_nvd",
            "id": (cid_m.group(0).upper() if cid_m else ""),
            "title": (cid_m.group(0).upper() if cid_m else name)[:200],
            "version_match": _version_in(low, version),
            "ref": name,
        })
    return out


# ── helpers ──────────────────────────────────────────────────────────────────
def _clean(v: Any) -> str:
    try:
        return str(v or "").strip()
    except Exception:
        return ""


def _mentions(text: str, component: str) -> bool:
    """Whole-word-ish component mention, case-insensitive (avoids 'cat' ⊂ 'concatenate')."""
    comp = component.strip().lower()
    if not comp:
        return False
    try:
        return re.search(r"(?<![\w-])" + re.escape(comp) + r"(?![\w-])", text.lower()) is not None
    except Exception:
        return comp in text.lower()


def _version_in(text: str, version: str) -> bool:
    if not version:
        return False
    try:
        return re.search(r"(?<![\w.])" + re.escape(version) + r"(?![\w.])", text) is not None
    except Exception:
        return version in text


def _looks_like_bare_cve(text: str) -> bool:
    """True for an entry that is *only* a CVE id (no component context to credit)."""
    return re.fullmatch(r"\s*CVE-\d{4}-\d{4,7}\s*", text, re.I) is not None


def _dedup(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for m in matches:
        key = f"{m.get('source')}:{m.get('id')}:{m.get('title')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(m)
    return out
