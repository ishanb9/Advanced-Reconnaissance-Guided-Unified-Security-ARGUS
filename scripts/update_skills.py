#!/usr/bin/env python3
"""scripts/update_skills.py — weekly skill-catalog updater for ARGUS.

Keep ``knowledge/skills/`` current with global trends.  Two independent,
best-effort passes (both honour ``--dry-run``):

  1. CVE refresh (no LLM, free): pull the CISA KEV catalog and append newly
     known-exploited CVEs to the ``references:`` of any skill whose technology /
     vendor it matches.  Deduplicated; never removes anything.
  2. Trend discovery (LLM): ask the configured LLM for currently-trending
     technologies/products NOT yet covered, per category, and author a new,
     schema-valid, FP-safe skill file for each.  Skips ids that already exist.

Every write is validated against the skill-registry schema (and the shared-port
false-positive guard) before it touches disk, and a JSONL run log is appended to
``knowledge/skills/.update_log.jsonl``.

Run weekly:
  # cron (Linux/Kali) — Mondays 03:00
  0 3 * * 1  cd /path/to/ARGUS && python3 -X utf8 scripts/update_skills.py >> /var/log/argus-skills.log 2>&1
  # Windows Task Scheduler (weekly): program=python, args=-X utf8 scripts\\update_skills.py

Usage:
  python -X utf8 scripts/update_skills.py                 # full weekly run
  python -X utf8 scripts/update_skills.py --dry-run       # show the plan, write nothing
  python -X utf8 scripts/update_skills.py --kev-only      # CVE refresh only (no LLM)
  python -X utf8 scripts/update_skills.py --no-llm        # alias for --kev-only
  python -X utf8 scripts/update_skills.py --category security --max 8
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

SKILLS_DIR = _REPO_ROOT / "knowledge" / "skills"
LOG_PATH = SKILLS_DIR / ".update_log.jsonl"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Genuinely-shared ports a skill must NOT rely on for a port-only match — the
# SAME authoritative set the runtime FP guard uses (service-dedicated ports like
# 3306/22/3389 are intentionally NOT here, so we never strip them).
try:
    from knowledge.skill_registry import _SHARED_PORTS  # type: ignore
except Exception:
    _SHARED_PORTS = {80, 443, 3000, 3001, 4000, 5000, 5005, 8000, 8001, 8002,
                     8080, 8081, 8082, 8265, 8443, 8888, 9000, 9090, 9099}
_CATEGORIES = ("security", "network", "os", "webapp", "scada", "home", "marine", "aviation")
_DOMAINS = {"OT", "IOT", "IT"}
_STOP = {"the", "and", "for", "ip", "server", "service", "system", "systems", "device",
         "devices", "software", "platform", "appliance", "gateway", "controller", "inc",
         "corp", "ltd", "llc", "co", "technologies", "technology", "network", "security"}


# ── helpers ─────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    # Avoid importing datetime.now in a way that breaks deterministic test runs;
    # this is only used for the human-readable log timestamp.
    try:
        import datetime
        return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def load_existing() -> List[Dict[str, Any]]:
    from knowledge import skill_registry as sr
    return sr.load_skills()


def existing_ids(skills: Optional[List[Dict[str, Any]]] = None) -> set:
    return {s["id"] for s in (skills if skills is not None else load_existing())}


def fetch_kev(timeout: int = 25) -> List[Dict[str, Any]]:
    """Fetch the CISA KEV catalog (free, no-auth). Returns its vulnerability list,
    or [] on any failure (offline-safe)."""
    try:
        import urllib.request
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "ARGUS-skill-updater"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec - read-only public feed
            data = json.loads(r.read().decode("utf-8", "replace"))
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        return vulns if isinstance(vulns, list) else []
    except Exception:
        return []


def _skill_keywords(skill: Dict[str, Any]) -> set:
    blob = f"{skill.get('technology','')} {skill.get('id','')}".lower()
    toks = {t for t in re.split(r"[^a-z0-9]+", blob) if len(t) >= 3 and t not in _STOP}
    return toks


def match_kev_to_skill(skill: Dict[str, Any], kev: List[Dict[str, Any]],
                       cap: int = 8) -> List[str]:
    """Return KEV CVE ids whose vendor/product matches the skill's keywords and
    are not already in its references."""
    kws = _skill_keywords(skill)
    if not kws:
        return []
    have = {str(r).upper() for r in (skill.get("references") or [])}
    out: List[str] = []
    for v in kev:
        if not isinstance(v, dict):
            continue
        hay = f"{v.get('vendorProject','')} {v.get('product','')}".lower()
        cve = str(v.get("cveID", "")).upper()
        if not cve or cve in have or cve in out:
            continue
        htoks = {t for t in re.split(r"[^a-z0-9]+", hay) if len(t) >= 3}
        if kws & htoks:
            out.append(cve)
            if len(out) >= cap:
                break
    return out


def _read_front_matter(path: Path) -> Tuple[Dict[str, Any], str]:
    import yaml
    raw = path.read_text(encoding="utf-8")
    if raw.startswith("---"):
        parts = raw.split("---", 2)
        if len(parts) >= 3:
            fm = yaml.safe_load(parts[1]) or {}
            return (fm if isinstance(fm, dict) else {}), parts[2].lstrip("\n")
    return {}, raw


def _write_front_matter(path: Path, fm: Dict[str, Any], body: str) -> None:
    import yaml
    text = "---\n" + yaml.safe_dump(fm, sort_keys=False, allow_unicode=True, width=100) + "---\n\n" + body.strip() + "\n"
    path.write_text(text, encoding="utf-8")


def refresh_references(skills: List[Dict[str, Any]], kev: List[Dict[str, Any]],
                       dry_run: bool = False) -> List[Dict[str, Any]]:
    """Append newly known-exploited CVEs to matching skills' references. Returns
    a list of {id, added:[cve]} changes."""
    changes: List[Dict[str, Any]] = []
    for skill in skills:
        added = match_kev_to_skill(skill, kev)
        if not added:
            continue
        src = skill.get("_source")
        changes.append({"id": skill["id"], "added": added})
        if dry_run or not src:
            continue
        try:
            p = Path(src)
            fm, body = _read_front_matter(p)
            refs = list(fm.get("references") or [])
            have = {str(r).upper() for r in refs}
            for cve in added:
                if cve.upper() not in have:
                    refs.append(cve); have.add(cve.upper())
            fm["references"] = refs
            _write_front_matter(p, fm, body)
        except Exception:
            continue
    return changes


# ── FP / schema validation ───────────────────────────────────────────────────

def fp_clean_match(match: Dict[str, Any]) -> Dict[str, Any]:
    """Drop shared ports from match.ports (they must rely on banners/markers)."""
    ports = [int(p) for p in (match.get("ports") or []) if str(p).isdigit()]
    match = dict(match)
    match["ports"] = [p for p in ports if p not in _SHARED_PORTS]
    match["banners"] = list(match.get("banners") or [])
    match["markers"] = list(match.get("markers") or [])
    return match


def validate_spec(spec: Dict[str, Any]) -> Tuple[bool, str]:
    if not isinstance(spec, dict):
        return False, "not a dict"
    if not spec.get("id") or not re.match(r"^[a-z0-9_]+$", str(spec["id"])):
        return False, "bad id"
    if not spec.get("technology"):
        return False, "no technology"
    m = spec.get("match")
    if not isinstance(m, dict):
        return False, "no match block"
    m = fp_clean_match(m)
    if not (m["ports"] or m["banners"] or m["markers"]):
        return False, "match has no dedicated port / banner / marker"
    if str(spec.get("domain", "IT")).upper() not in _DOMAINS:
        return False, "bad domain"
    return True, "ok"


def spec_to_markdown(spec: Dict[str, Any]) -> str:
    """Render a validated spec dict into a skill .md (front-matter + body)."""
    import yaml
    fm = {
        "id": str(spec["id"]),
        "technology": str(spec["technology"]),
        "domain": str(spec.get("domain", "IT")).upper(),
        "category": str(spec.get("category", "")).lower(),
        "transport": str(spec.get("transport", "ip")).lower(),
        "safety_class": str(spec.get("safety_class", "safe")).lower(),
        "severity": spec.get("severity", "medium"),
        "life_safety": bool(spec.get("life_safety", False)),
        "match": fp_clean_match(spec["match"]),
        "quick_wins": spec.get("quick_wins") or [],
        "references": spec.get("references") or [],
        "mitre": spec.get("mitre", ""),
    }
    body = (spec.get("guidance") or f"{fm['technology']} — added by the weekly skill updater.").strip()
    return ("---\n" + yaml.safe_dump(fm, sort_keys=False, allow_unicode=True, width=100)
            + "---\n\n" + body + "\n")


def author_skill_file(spec: Dict[str, Any], dry_run: bool = False) -> Optional[str]:
    """Validate a spec + write it as knowledge/skills/<category>/<id>.md.
    Returns the path written (or that WOULD be written under --dry-run), or None
    when invalid / already present."""
    ok, _why = validate_spec(spec)
    if not ok:
        return None
    cat = str(spec.get("category", "misc")).lower()
    if cat not in _CATEGORIES:
        cat = "misc"
    out = SKILLS_DIR / cat / f"{spec['id']}.md"
    if out.exists():
        return None
    if dry_run:
        return str(out)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(spec_to_markdown(spec), encoding="utf-8")
        return str(out)
    except Exception:
        return None


# ── LLM trend discovery ───────────────────────────────────────────────────────

def _llm_complete(prompt: str, tier: str = "bulk", timeout: int = 180) -> str:
    """Best-effort single-shot LLM completion via the ARGUS provider chain.
    Returns '' if no provider is configured / reachable."""
    try:
        import asyncio
        from utils import llm_providers as _llm

        async def _run() -> str:
            chunks: List[str] = []
            async for tok in _llm.stream_tiered(
                    [{"role": "user", "content": prompt}], tier=tier, timeout=timeout):
                chunks.append(tok)
            return "".join(chunks)

        return asyncio.run(_run())
    except Exception:
        return ""


def _parse_json_array(text: str) -> List[Dict[str, Any]]:
    if not text:
        return []
    t = text.strip()
    t = re.sub(r"^```(?:json)?", "", t).strip()
    t = re.sub(r"```$", "", t).strip()
    m = re.search(r"\[.*\]", t, re.DOTALL)
    if m:
        t = m.group(0)
    try:
        data = json.loads(t)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def discover_new_technologies(existing: set, category: str, max_new: int = 8) -> List[Dict[str, Any]]:
    """Ask the LLM for trending NEW technologies in a category as skill specs.
    Best-effort; returns [] without an LLM."""
    prompt = (
        "You maintain an authorized-pentest knowledge base. List up to "
        f"{max_new} GLOBALLY-USED or currently-TRENDING technologies/products in the "
        f"'{category}' category that an offensive-security platform should cover, that are "
        f"NOT already in this id list: {', '.join(sorted(existing))[:3000]}.\n\n"
        "Return ONLY a JSON array. Each element:\n"
        '{"id":"<kebab>","technology":"<name>","domain":"OT|IoT|IT","category":"' + category + '",'
        '"transport":"ip|rf|can|l2|serial","safety_class":"safe|intrusive|disruptive",'
        '"severity":"critical|high|medium|low","life_safety":false,'
        '"match":{"ports":[<dedicated ports only, NEVER 80/443/22/8080/etc>],"banners":["..."],"markers":["specific marker"]},'
        '"quick_wins":[{"cmd":"... {host} ...","safety":"safe","note":"read-only"}],'
        '"references":["CVE-...","advisory"],"mitre":"Txxxx","guidance":"2-3 sentences of operator guidance"}\n'
        "Rules: id unique + kebab_case; at least one SAFE quick_win; OT/SCADA/marine/aviation -> safety_class safe + read-only."
    )
    specs = _parse_json_array(_llm_complete(prompt))
    out: List[Dict[str, Any]] = []
    for s in specs:
        if isinstance(s, dict) and s.get("id") and str(s["id"]) not in existing:
            s.setdefault("category", category)
            ok, _ = validate_spec(s)
            if ok:
                out.append(s)
    return out[:max_new]


# ── orchestration ─────────────────────────────────────────────────────────────

def log_run(entry: Dict[str, Any]) -> None:
    try:
        SKILLS_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def run(dry_run: bool = False, kev_only: bool = False, use_llm: bool = True,
        categories: Optional[List[str]] = None, max_new: int = 8) -> Dict[str, Any]:
    skills = load_existing()
    ids = existing_ids(skills)
    cats = categories or list(_CATEGORIES)

    # Pass 1 — CVE refresh (free, no LLM).
    kev = fetch_kev()
    ref_changes = refresh_references(skills, kev, dry_run=dry_run) if kev else []

    # Pass 2 — LLM trend discovery + authoring.
    authored: List[str] = []
    discovered = 0
    if use_llm and not kev_only:
        seen = set(ids)
        for cat in cats:
            specs = discover_new_technologies(seen, cat, max_new=max_new)
            discovered += len(specs)
            for spec in specs:
                path = author_skill_file(spec, dry_run=dry_run)
                if path:
                    authored.append(path)
                    seen.add(str(spec["id"]))

    summary = {
        "ts": _now_iso(), "dry_run": dry_run, "kev_only": kev_only,
        "existing": len(ids), "kev_entries": len(kev),
        "references_updated": len(ref_changes),
        "reference_changes": ref_changes[:50],
        "trends_discovered": discovered, "skills_authored": len(authored),
        "authored": authored[:100],
    }
    log_run(summary)
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Weekly ARGUS skill-catalog updater")
    ap.add_argument("--dry-run", action="store_true", help="show the plan, write nothing")
    ap.add_argument("--kev-only", action="store_true", help="CVE refresh only (no LLM)")
    ap.add_argument("--no-llm", action="store_true", help="alias for --kev-only")
    ap.add_argument("--category", action="append", default=None,
                    help=f"limit trend discovery to a category ({'/'.join(_CATEGORIES)}); repeatable")
    ap.add_argument("--max", type=int, default=8, help="max new technologies per category")
    args = ap.parse_args(argv)

    res = run(dry_run=args.dry_run, kev_only=(args.kev_only or args.no_llm),
              use_llm=not (args.kev_only or args.no_llm),
              categories=args.category, max_new=args.max)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
