# Universal Technology Coverage (Slice 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Give ARGUS a data-driven **skill registry** so any technology (OT/IoT/IT) can be matched + guided from a human-authored skill file, governed by a human-set **scan-intrusiveness ceiling** that is safe-by-default for OT.

**Architecture:** A new `knowledge/skill_registry.py` loads `knowledge/skills/<domain>/<tech>.md` (Markdown + YAML front-matter), matches each skill's signatures against recon intel (reusing the shadow-AI matcher + `_SHARED_PORTS` FP guard), records findings + injects safety-filtered quick-wins into the operator, and auto-ingests guidance bodies into the RAG knowledge base. A pure-function safety gate enforces the GUI-selected ceiling. One read-only code module (`agents/ot/modbus.py`) demonstrates Tier-2 active speaking. Additive; reuses the `_CAPABILITY_MODULES` registry from #4 Slice 2.

**Tech Stack:** Python (pyyaml, asyncio), the ARGUS capability registry / findings / RAG (`knowledge.knowledge_base.ingest`), the `python -X utf8 agents/test_architecture_integration.py` harness, React.createElement frontend.

**Reference spec:** `docs/superpowers/specs/2026-06-20-universal-tech-coverage-design.md`.

**Global rules:** additive; coverage = data (skill files), not engine code; attack content lives in `knowledge/skills` + `agents/<domain>` (never the operator spine — `test_no_hardcoded_attack_content` stays green); safe-by-default for OT; env toggle `ARGUS_SKILL_REGISTRY` (default-on); harness green + new tests registered in `main()`; frontend `node --check` + cache-bust; Windows→Kali manual copy.

---

## Interfaces (locked — used across tasks)

- `skill_registry.load_skills(root=None) -> list[dict]` — each skill: `{id, technology, domain, safety_class, severity, life_safety, match{ports[],banners[],markers[]}, quick_wins[{cmd,safety,note}], references[], cpe, mitre, guidance(str), _source(str)}`. Validates `id`+`technology`+`match`; never raises.
- `skill_registry.match_skills(intel) -> list[dict]` — detections `{id, technology, domain, safety_class, severity, life_safety, ports[], evidence, guidance, quick_wins[], references[], mitre, capability:"knowledge/skills", hint}`.
- `skill_registry.finding_for(detection) -> dict` — store_finding-shaped (only when `severity` truthy).
- `skill_registry.allowed(action_safety, ceiling, domain, life_safety=False, authorized=False) -> bool` — the safety gate (pure).
- `skill_registry.safe_quick_wins(detection, ceiling, domain, authorized=False) -> list[dict]` — quick-wins filtered by the gate.
- `skill_registry.ingest_to_rag(skill) -> bool` — push guidance body to `knowledge.knowledge_base.ingest`.
- `agents.ot.modbus.detect(intel) -> dict|None`; `agents.ot.modbus.finding_for(det) -> dict`.

---

## Task 1: Skill loader + matcher + FP guard

**Files:** Create `knowledge/skill_registry.py`, `knowledge/skills/ot/modbus.md`, `knowledge/skills/README.md`; Test: `agents/test_architecture_integration.py`.

- [ ] **Step 1: Write the failing test** — add to the harness:

```python
def test_skill_registry_load_match():
    _section("Test — skill registry loader + matcher (data-driven tech coverage)")
    from knowledge import skill_registry as sr
    skills = sr.load_skills()
    _assert(isinstance(skills, list) and len(skills) >= 1, "skill files load from knowledge/skills")
    s = next((x for x in skills if x["id"] == "modbus"), None)
    _assert(s and s["technology"] and s["match"].get("ports") and s["guidance"],
            "modbus skill carries technology + match + guidance body")
    # dedicated port 502 → detection
    det = sr.match_skills({"open_ports": [{"port": 502, "service": "unknown"}], "services": {}})
    _assert(any(d["id"] == "modbus" for d in det), "match_skills fires on Modbus port 502")
    # plain host + shared port → NO false positive
    _assert(sr.match_skills({"open_ports": [{"port": 80, "service": "http"}]}) == [],
            "match_skills does not false-positive on a plain web host")
    f = sr.finding_for(next(d for d in det if d["id"] == "modbus"))
    _assert(f.get("severity") and f.get("title") and f.get("remediation"), "finding_for shapes a record")
```

- [ ] **Step 2: Run harness → FAIL** (`No module named knowledge.skill_registry`).
  Run: `python -X utf8 agents/test_architecture_integration.py`

- [ ] **Step 3: Implement `knowledge/skill_registry.py`:**

```python
"""skill_registry.py — data-driven technology coverage (sub-project #5).

Loads human-authored skill files (knowledge/skills/<domain>/<tech>.md = Markdown
guidance + YAML front-matter), matches them against recon intel, and feeds the
operator guidance + safety-gated quick-wins.  Adding a technology = adding a .md
file (no code).  Mirrors agents/ai_red_team/discovery (same matcher + FP guard).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

_SKILLS_DIR = Path(__file__).resolve().parent / "skills"

# Code-level FP guard (shared with discovery): a shared web port never fires a
# detection on its own — only an AI/OT-dedicated port match alone suffices.
_SHARED_PORTS = {80, 443, 3000, 3001, 4000, 5000, 5005, 8000, 8001, 8002,
                 8080, 8081, 8082, 8265, 8443, 8888, 9000, 9090, 9099}
_TEXT_KEYS = ("http", "https", "web", "whatweb", "headers", "banners",
              "http_banners", "titles", "server_headers", "web_findings", "tech")
_SAFETY = {"safe": 0, "intrusive": 1, "disruptive": 2}


def _split_front_matter(raw: str):
    """Return (front_matter_dict, body_str) for a Markdown+YAML-front-matter file."""
    import yaml
    if raw.startswith("---"):
        parts = raw.split("---", 2)
        if len(parts) >= 3:
            try:
                fm = yaml.safe_load(parts[1]) or {}
            except Exception:
                fm = {}
            return (fm if isinstance(fm, dict) else {}), parts[2].strip()
    return {}, raw.strip()


def load_skills(root: Optional[str] = None) -> List[Dict[str, Any]]:
    d = Path(root) if root else _SKILLS_DIR
    out: List[Dict[str, Any]] = []
    if not d.exists():
        return out
    for f in sorted(d.rglob("*.md")):
        if f.name.lower() == "readme.md":
            continue
        try:
            fm, body = _split_front_matter(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not (fm.get("id") and fm.get("technology") and isinstance(fm.get("match"), dict)):
            continue
        m = fm["match"]
        out.append({
            "id": str(fm["id"]), "technology": str(fm["technology"]),
            "domain": str(fm.get("domain", "IT")).upper(),
            "safety_class": str(fm.get("safety_class", "safe")).lower(),
            "severity": fm.get("severity"), "life_safety": bool(fm.get("life_safety")),
            "match": {"ports": m.get("ports") or [], "banners": m.get("banners") or [],
                      "markers": m.get("markers") or []},
            "quick_wins": fm.get("quick_wins") or [],
            "references": fm.get("references") or [], "cpe": fm.get("cpe", ""),
            "mitre": fm.get("mitre", ""), "guidance": body, "_source": str(f),
        })
    return out


def _iter_ports(intel):
    for p in (intel.get("open_ports") or []):
        if isinstance(p, dict):
            try:
                yield int(p.get("port")), str(p.get("service") or ""), str(p.get("version") or "")
            except Exception:
                continue
        else:
            try:
                yield int(p), "", ""
            except Exception:
                continue
    for k, v in (intel.get("services") or {}).items():
        try:
            port = int(v.get("port") if isinstance(v, dict) and v.get("port") else k)
        except Exception:
            continue
        svc = str((v or {}).get("service") or "") if isinstance(v, dict) else ""
        ver = str((v or {}).get("version") or "") if isinstance(v, dict) else ""
        yield port, svc, ver


def _text_blob(intel) -> str:
    parts = [f"{s} {v}" for _p, s, v in _iter_ports(intel)]
    for k in _TEXT_KEYS:
        val = intel.get(k)
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, (list, tuple)):
            parts.extend(str(x) for x in val)
        elif isinstance(val, dict):
            parts.extend(f"{kk} {vv}" for kk, vv in val.items())
    return " \n ".join(parts).lower()


def match_skills(intel: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(intel, dict):
        return []
    skills = load_skills()
    open_ports = {p for p, _s, _v in _iter_ports(intel)}
    blob = _text_blob(intel)
    out: List[Dict[str, Any]] = []
    for s in skills:
        ev: List[str] = []
        hit_ports: List[int] = []
        dedicated = False
        for p in s["match"]["ports"]:
            try:
                pi = int(p)
            except Exception:
                continue
            if pi in open_ports:
                hit_ports.append(pi); ev.append(f"{pi}/tcp")
                if pi not in _SHARED_PORTS:
                    dedicated = True
        banner = any(str(b).lower() in blob for b in s["match"]["banners"] if b)
        marker = any(str(m).lower() in blob for m in s["match"]["markers"] if m)
        if banner:
            ev.append("banner-match")
        if marker:
            ev.append("marker-match")
        if not (dedicated or banner or marker):
            continue
        out.append({
            "id": s["id"], "technology": s["technology"], "domain": s["domain"],
            "safety_class": s["safety_class"], "severity": s["severity"],
            "life_safety": s["life_safety"], "ports": sorted(set(hit_ports)),
            "evidence": "; ".join(dict.fromkeys(ev)), "guidance": s["guidance"][:1200],
            "quick_wins": s["quick_wins"], "references": s["references"],
            "mitre": s["mitre"], "capability": "knowledge/skills",
            "hint": (f"{s['technology']} skill matched — domain {s['domain']}, "
                     f"base class {s['safety_class']}. Safe quick-wins available."),
        })
    return out


def finding_for(detection: Dict[str, Any]) -> Dict[str, Any]:
    tech = detection.get("technology", "technology")
    ev = detection.get("evidence", "")
    refs = ", ".join(str(r) for r in (detection.get("references") or [])[:5])
    ot = detection.get("domain") == "OT"
    return {
        "severity": detection.get("severity") or "info",
        "title": f"{tech} detected" + (" (OT — fragile)" if ot else ""),
        "description": (f"{tech} was identified on the target ({ev}). "
                        + (detection.get("guidance", "")[:600])
                        + (f" References: {refs}." if refs else "")
                        + (" OT/ICS: reachability can equal control — test read-only first."
                           if ot else "")),
        "evidence": ev,
        "remediation": ("Inventory and segment this asset; restrict access to authorized "
                        "management networks; apply vendor advisories"
                        + (f" ({refs})" if refs else "") + "."),
        "tool_used": "skill_registry",
        "mitre": detection.get("mitre", ""),
    }


def allowed(action_safety: str, ceiling: str, domain: str = "IT",
            life_safety: bool = False, authorized: bool = False) -> bool:
    """Safety gate: may an action of class ``action_safety`` auto-run under the
    human-selected ``ceiling`` for a target in ``domain``?  Safe-by-default for OT."""
    a = _SAFETY.get(str(action_safety).lower(), 2)
    c = _SAFETY.get(str(ceiling).lower(), 0)
    if life_safety and a >= _SAFETY["intrusive"] and not authorized:
        return False
    if str(domain).upper() == "OT" and not authorized:
        c = min(c, _SAFETY["safe"])     # OT clamps to safe unless authorized
    return a <= c


def safe_quick_wins(detection, ceiling, domain="IT", authorized=False):
    return [q for q in (detection.get("quick_wins") or [])
            if allowed(q.get("safety", "safe"), ceiling, domain,
                       detection.get("life_safety", False), authorized)]


def ingest_to_rag(skill: Dict[str, Any]) -> bool:
    """Best-effort: push the guidance body into the RAG knowledge base."""
    body = (skill.get("guidance") or "").strip()
    if len(body) < 40:
        return False
    try:
        from knowledge import knowledge_base as kb
        return bool(kb.ingest(
            text=f"# {skill.get('technology','')} (skill)\n{body}",
            source_file=skill.get("_source", f"skill:{skill.get('id','')}"),
            chunk_index=0,
            metadata={"chunk_type": "skill",
                      "ports": [int(p) for p in (skill.get("match", {}).get("ports") or []) if str(p).isdigit()],
                      "cves": [r for r in (skill.get("references") or []) if str(r).upper().startswith("CVE")],
                      "mitre_ttps": [skill["mitre"]] if skill.get("mitre") else [],
                      "section_title": skill.get("technology", "")}))
    except Exception:
        return False
```

- [ ] **Step 4: Create the seed `knowledge/skills/ot/modbus.md`** (front-matter + guidance) matching §3.1 of the spec (id: modbus, domain: OT, safety_class: safe, severity: high, match.ports [502], banners ["modbus"], markers ["mbap"], quick_wins with one safe + one disruptive, references, a 2-3 paragraph guidance body). Task 6's workflow fills the rest of P0.

- [ ] **Step 5: Create `knowledge/skills/README.md`** documenting the front-matter schema + an annotated example + "drop a file here to add coverage; it auto-loads + ingests to RAG".

- [ ] **Step 6: Register `test_skill_registry_load_match` in `main()` `tests=[...]`. Run harness → PASS.**

- [ ] **Step 7: Commit** `feat(skills): data-driven technology skill registry + loader/matcher`.

---

## Task 2: Safety gate + RAG ingest tests

**Files:** Test: `agents/test_architecture_integration.py`.

- [ ] **Step 1: Write the failing test:**

```python
def test_skill_safety_gate_and_rag():
    _section("Test — skill safety-class gate (human intrusiveness ceiling, OT safe-by-default)")
    from knowledge import skill_registry as sr
    _assert(sr.allowed("safe", "safe", "IT") is True, "safe action allowed at safe ceiling")
    _assert(sr.allowed("disruptive", "intrusive", "IT") is False, "disruptive blocked under intrusive ceiling")
    _assert(sr.allowed("intrusive", "disruptive", "IT") is True, "intrusive allowed under disruptive ceiling")
    # OT clamps to safe even at a higher ceiling unless authorized
    _assert(sr.allowed("intrusive", "disruptive", "OT", authorized=False) is False,
            "OT target clamps to safe without authorization")
    _assert(sr.allowed("intrusive", "disruptive", "OT", authorized=True) is True,
            "authorized OT engagement may go intrusive")
    # life-safety never auto-runs intrusive+ without authorization
    _assert(sr.allowed("intrusive", "disruptive", "IT", life_safety=True, authorized=False) is False,
            "life-safety point never auto-actuates")
    # safe_quick_wins filters
    det = {"quick_wins": [{"cmd": "read", "safety": "safe"}, {"cmd": "write", "safety": "disruptive"}],
           "life_safety": False}
    _assert(len(sr.safe_quick_wins(det, "safe", "IT")) == 1, "only the safe quick-win surfaces at safe ceiling")
    _assert(len(sr.safe_quick_wins(det, "disruptive", "IT")) == 2, "both surface at disruptive ceiling")
    # RAG ingest is best-effort + callable
    ok = sr.ingest_to_rag({"id": "x", "technology": "T", "_source": "s",
                           "guidance": "A" * 80, "match": {"ports": [1]}, "references": []})
    _assert(ok in (True, False), "ingest_to_rag returns a bool (best-effort)")
```

- [ ] **Step 2: Run harness → FAIL.** (gate not yet exercised / asserts mismatch)
- [ ] **Step 3:** No new code — `allowed`/`safe_quick_wins`/`ingest_to_rag` already implemented in Task 1. If any assert fails, fix the gate logic to match.
- [ ] **Step 4: Register + run harness → PASS.**
- [ ] **Step 5: Commit** `test(skills): safety-class gate + RAG ingest`.

---

## Task 3: Modbus read-only code-module exemplar

**Files:** Create `agents/ot/__init__.py`, `agents/ot/modbus.py`; Test: harness.

- [ ] **Step 1: Write the failing test:**

```python
def test_ot_modbus_module():
    _section("Test — agents/ot/modbus read-only capability exemplar")
    from agents.ot import modbus
    det = modbus.detect({"open_ports": [{"port": 502, "service": "unknown"}], "services": {}})
    _assert(det and det.get("technology", "").lower().startswith("modbus") and det.get("safety_class") == "safe",
            "modbus.detect fingerprints 502/tcp as a safe (read-only) detection")
    _assert(modbus.detect({"open_ports": [{"port": 80, "service": "http"}]}) is None,
            "modbus.detect does not false-positive on a plain web host")
    f = modbus.finding_for(det)
    _assert(f.get("severity") and "modbus" in f["title"].lower() and f.get("remediation"),
            "modbus.finding_for shapes a store_finding record")
```

- [ ] **Step 2: Run harness → FAIL** (`No module named agents.ot`).
- [ ] **Step 3: Implement** `agents/ot/__init__.py` (empty) + `agents/ot/modbus.py`:

```python
"""agents/ot/modbus.py — read-only Modbus/TCP capability module (Tier-2 exemplar).

Demonstrates an ACTIVE protocol-speaking capability module that is safe-by-default:
detection is a passive 502/tcp fingerprint; the only documented active probe is the
read-only Read-Device-Identification (FC 0x2B / MEI 14). All write function codes are
documented-but-gated (never emitted here). Pattern mirrors agents/avot/recon.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

MODBUS_PORT = 502
SAFETY_CLASS = "safe"

def _ports(intel):
    for p in (intel.get("open_ports") or []):
        try:
            yield (int(p.get("port")) if isinstance(p, dict) else int(p))
        except Exception:
            continue
    for k, v in (intel.get("services") or {}).items():
        try:
            yield int(v.get("port") if isinstance(v, dict) and v.get("port") else k)
        except Exception:
            continue

def detect(intel: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(intel, dict) or MODBUS_PORT not in set(_ports(intel)):
        return None
    return {
        "technology": "Modbus / Modbus-TCP", "domain": "OT", "safety_class": SAFETY_CLASS,
        "ports": [MODBUS_PORT], "evidence": "502/tcp (Modbus MBAP)",
        "capability": "agents/ot/modbus",
        "hint": ("Read-only Modbus enumeration: nmap --script modbus-discover, or FC 0x2B/MEI 14 "
                 "(Read Device ID) — vendor/product/firmware. WRITE FCs 0x05/06/0F/10 are GATED "
                 "(disruptive — actuate the process)."),
    }

def finding_for(detection: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "severity": "high",
        "title": "Modbus/TCP control interface exposed (OT)",
        "description": ("A Modbus/TCP endpoint was detected on 502/tcp (" + detection.get("evidence", "")
                        + "). Modbus has no authentication, encryption, or integrity: any reachable "
                        "client can read process data and (via write function codes) command coils/"
                        "registers. Test read-only by default; writes can shut down a live PLC."),
        "evidence": detection.get("evidence", ""),
        "remediation": ("Isolate OT on a segmented VLAN with no inbound access from IT/user networks; "
                        "front Modbus with an authenticating gateway; disable unused write access; "
                        "monitor 502/tcp; map findings to CISA ICS advisories."),
        "tool_used": "agents.ot.modbus", "mitre": "T0846",
    }
```

- [ ] **Step 4: Register + run harness → PASS.**
- [ ] **Step 5: Commit** `feat(ot): read-only Modbus capability-module exemplar`.

---

## Task 4: Engine wiring — registry runs skills + RAG ingest on start

**Files:** Modify `agents/master_agent.py` (`_CAPABILITY_MODULES` add `agents.ot.modbus`; extend `_avot_capability_scan` to run `skill_registry.match_skills`; add a one-time `_ingest_skills_to_rag`); Test: harness.

- [ ] **Step 1: Write the failing test:**

```python
def test_skill_registry_engine_wiring():
    _section("Test — master runs the skill registry + Modbus module in the capability scan")
    import inspect, pathlib
    import agents.master_agent as ma
    ma_src = (pathlib.Path(__file__).resolve().parent.parent / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("agents.ot.modbus" in ma_src, "Modbus module registered in _CAPABILITY_MODULES")
    scan = inspect.getsource(ma.MasterAgent._avot_capability_scan)
    _assert("match_skills" in scan and "skill_registry" in scan,
            "capability scan also runs the data-driven skill registry")
    _assert("_ingest_skills_to_rag" in ma_src or "ingest_to_rag" in ma_src,
            "master ingests skill guidance into RAG (best-effort)")
```

- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3: Implement** in `agents/master_agent.py`:
  - Add `"agents.ot.modbus"` to `_CAPABILITY_MODULES`.
  - In `_avot_capability_scan`, after the module loop, add:

```python
        # Data-driven skill registry (sub-project #5): match human-authored
        # skill files against intel + record/guide via the same path.
        try:
            from knowledge import skill_registry as _sr
            for _d in _sr.match_skills(self._intel):
                self._record_capability_detection(_sr, _d)
        except Exception:
            pass
```

  - Add a best-effort one-time RAG ingest (call once per run, e.g. guarded by a `self._skills_ingested` flag set in `run()` or lazily in the scan):

```python
    def _ingest_skills_to_rag(self) -> None:
        """Best-effort: ingest skill guidance bodies into RAG once per process."""
        import os as _os
        if _os.environ.get("ARGUS_SKILL_REGISTRY", "1") == "0":
            return
        if getattr(self, "_skills_ingested", False):
            return
        self._skills_ingested = True
        try:
            from knowledge import skill_registry as _sr
            for _s in _sr.load_skills():
                _sr.ingest_to_rag(_s)
        except Exception:
            pass
```

  - Call `self._ingest_skills_to_rag()` at the top of `_avot_capability_scan` (best-effort; the flag makes it idempotent).
  - NOTE: `_record_capability_detection(mod, det)` calls `mod.finding_for(det)` — `skill_registry` exposes `finding_for`, so passing the module object works unchanged.

- [ ] **Step 4: Run harness → PASS.** Also `python -X utf8 -c "import py_compile; py_compile.compile('agents/master_agent.py', doraise=True)"`.
- [ ] **Step 5: Commit** `feat(engine): run skill registry in the capability scan + RAG ingest`.

---

## Task 5: GUI scan-intrusiveness ceiling (schema → server → master → intel)

**Files:** Modify `db/schemas.py` (`StartPentestRequest.scan_intrusiveness`), `agent_server.py` (forward into `master_kwargs`), `agents/master_agent.py` (store `self._intel["scan_intrusiveness"]`), `static/js/pages/TargetConfig.jsx` (selector), `templates/index.html` (cache-bust); Test: harness.

- [ ] **Step 1: Write the failing test:**

```python
def test_scan_intrusiveness_ui_and_plumbing():
    _section("Test — human scan-intrusiveness ceiling (safe|intrusive|disruptive) GUI + plumbing")
    import pathlib, inspect
    root = pathlib.Path(__file__).resolve().parent.parent
    sch = (root / "db" / "schemas.py").read_text(encoding="utf-8")
    _assert("scan_intrusiveness" in sch, "StartPentestRequest carries scan_intrusiveness")
    srv = (root / "agent_server.py").read_text(encoding="utf-8")
    _assert("scan_intrusiveness" in srv, "server forwards scan_intrusiveness into master_kwargs")
    import agents.master_agent as ma
    _assert("scan_intrusiveness" in inspect.getsource(ma.MasterAgent.run), "master.run stores the ceiling in intel")
    tc = (root / "static" / "js" / "pages" / "TargetConfig.jsx").read_text(encoding="utf-8")
    _assert("scan_intrusiveness" in tc and "intrusive" in tc and "disruptive" in tc,
            "TargetConfig exposes a safe|intrusive|disruptive selector")
```

- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3: Implement:**
  - `db/schemas.py` `StartPentestRequest`: add `scan_intrusiveness: str = "safe"`.
  - `agent_server.py` `create_session` `master_kwargs`: add `scan_intrusiveness = getattr(body, "scan_intrusiveness", "safe") or "safe",`.
  - `agents/master_agent.py` `run()`: after the target setup block, add `self._intel["scan_intrusiveness"] = kwargs.get("scan_intrusiveness") or "safe"`.
  - `static/js/pages/TargetConfig.jsx`: add `scan_intrusiveness: 'safe'` to the `form` state; render a selector card (a 3-button group or `<select>`) with `safe` / `intrusive` / `disruptive` (default safe; copy: "safe = read-only/passive · intrusive = active enumeration · disruptive = writes/state-changing (OT-gated)"). It is already in `payload = {...form}`.
  - `templates/index.html`: bump `TargetConfig.jsx?v=9` → `?v=10` (and the two harness cache-bust assertions `TargetConfig.jsx?v=9` → `?v=10`).
- [ ] **Step 4:** `node --check` (copy to temp `.js`), register + run harness → PASS.
- [ ] **Step 5: Commit** `feat(gui): human-set scan-intrusiveness ceiling (safe|intrusive|disruptive)`.

---

## Task 6: Seed P0 coverage as skill files (workflow)

**Files:** Create `knowledge/skills/{ot,iot,it}/*.md` (P0 families); Test: harness breadth assert.

- [ ] **Step 1: Add the breadth assertion** to `test_skill_registry_load_match` (or a new test):

```python
def test_skill_registry_p0_breadth():
    _section("Test — seed P0 technology skill coverage (OT/IoT/IT breadth)")
    from knowledge import skill_registry as sr
    skills = sr.load_skills()
    ids = {s["id"] for s in skills}
    domains = {s["domain"] for s in skills}
    _assert(len(skills) >= 15, f"P0 skill coverage breadth (got {len(skills)})")
    _assert({"OT", "IT"} <= domains, "coverage spans at least OT + IT domains")
    for need in ("modbus", "mqtt"):
        _assert(need in ids, f"seed skill present: {need}")
    # every skill that lists ONLY shared ports must carry a banner or marker (no FP-by-design)
    for s in skills:
        ports = [int(p) for p in s["match"]["ports"] if str(p).isdigit()]
        only_shared = ports and all(p in sr._SHARED_PORTS for p in ports)
        if only_shared:
            _assert(s["match"]["banners"] or s["match"]["markers"],
                    f"{s['id']}: shared-port skill must have a banner/marker (FP-safe)")
```

- [ ] **Step 2: Run harness → FAIL** (breadth < 15).
- [ ] **Step 3: Generate** the P0 skill files via a parallel workflow (one agent per family, writing `knowledge/skills/<domain>/<id>.md`), each with the locked front-matter schema (id, technology, domain, safety_class, severity, life_safety, match{ports/banners/markers}, quick_wins, references, mitre) + a guidance body. FP rule: list a port in `match.ports` only if AI/OT-dedicated; shared ports rely on banners/markers. Families (research §6 P0): OT — opcua, bacnet, modbus(exists), s7comm, ethernetip, iec104, dnp3, niagara_fox; IoT — mqtt, coap, upnp_ssdp, mdns, onvif_rtsp, ipp_pjl; IT — smb_ad, kerberos, ldap, vpn_edge, cloud_imds, kubernetes, docker, graphql, grpc, databases, message_queues. Then an FP-audit pass (mirror the shadow-AI signatures workflow).
- [ ] **Step 4: Register + run harness → PASS.**
- [ ] **Step 5: Commit** `feat(skills): seed P0 OT/IoT/IT technology coverage`.

---

## Task 7: Tool-catalog awareness + final sweep

**Files:** Modify `agents/operator_agent/tool_catalog.py` (mention the skill registry + safe quick-win pattern); Test: harness.

- [ ] **Step 1: Write the failing test:**

```python
def test_skill_registry_toolbelt_awareness():
    _section("Test — operator tool catalog is aware of the skill registry")
    import pathlib
    tc = (pathlib.Path(__file__).resolve().parent.parent / "agents" / "operator_agent" / "tool_catalog.py").read_text(encoding="utf-8")
    _assert("skill" in tc.lower() and ("quick win" in tc.lower() or "quick_win" in tc.lower() or "intrusiveness" in tc.lower()),
            "tool catalog surfaces the skill-registry quick-win / intrusiveness awareness")
```

- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3:** Add a short doc note in `tool_catalog.py`'s `run_tool` documentation: matched-technology skills inject safe quick-wins; the operator should prefer the skill's safe quick-win first and respect the scan-intrusiveness ceiling (intrusive/disruptive quick-wins need authorization, OT safe-by-default). Keep it content-agnostic (no payloads — guard stays green).
- [ ] **Step 4: Final sweep:**
  - `python -X utf8 agents/test_architecture_integration.py` → `RESULT: PASS`; confirm `test_no_hardcoded_attack_content` green.
  - `py_compile` the new/modified Python; `node --check` TargetConfig.
  - Edited-files list for manual Windows→Kali copy.
- [ ] **Step 5: Commit** `feat(operator): skill-registry quick-win awareness + #5 Slice 1 sweep`.

---

## Self-review

**Spec coverage:** §3.1 skill format → T1 (loader) + T6 (seed); §3.2 code module → T3; §3.3 loader/matcher/finding_for/ingest → T1; §3.4 engine wiring + RAG-on-start → T4; §4 safety gate + ceiling → T2 (`allowed`/`safe_quick_wins`); §5 GUI control → T5; §6 seed P0 → T6; §7 findings→report → T1 `finding_for` (reuses existing pipeline); §8 manual extension UX → T1 README; §9 testing → every task; §10 slicing (Slice 1 only) → covered; §11 constraints → global rules + T7 sweep.

**Placeholder scan:** all code steps carry real code; the seed-skill generation is delegated to a workflow with the locked front-matter schema (data, not a code placeholder). No TBD.

**Type consistency:** `load_skills`→skill dicts (T1) consumed by `match_skills`/`ingest_to_rag` (T1) + T4/T6; `match_skills`→detection dicts consumed by `finding_for` + `_record_capability_detection` (T4); `allowed`/`safe_quick_wins` (T1, tested T2); `agents.ot.modbus.detect/finding_for` (T3) registered T4. `_record_capability_detection(mod, det)` already calls `mod.finding_for(det)` — `skill_registry` and `agents.ot.modbus` both expose `finding_for`, so the registry loop is uniform. Consistent.
