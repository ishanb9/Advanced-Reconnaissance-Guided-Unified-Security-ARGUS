# Report Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Ship 5 selectable, print-ready report themes (faithful Jinja2 conversions of the approved HTML, wired to ARGUS's real `_build_context`) with a theme picker, and fix the PDF download so it renders the chosen theme (weasyprint → browser-print fallback, never raw plaintext).

**Architecture:** A `report/themes/` registry holds five Jinja2 templates rendered from the same `_build_context`; `generator.py` selects by key; the report endpoint takes `?theme=`; `ReportPage.jsx` adds a picker + client-side print fallback. weasyprint becomes the primary PDF engine. All additive — the professional/dark templates stay as fallbacks.

**Tech Stack:** Jinja2, weasyprint, FastAPI (`agent_server.py`), React UMD (`React.createElement`), the `python -X utf8 agents/test_architecture_integration.py` harness.

**Reference spec:** `docs/superpowers/specs/2026-06-19-report-overhaul-design.md`. **Source designs:** `docs/superpowers/report-options/option{1..5}-*.html`.

**Global rules:** additive/no-regression; harness stays green (new tests in `main()`); frontend passes `node --check`; cache-bust bumped; `weasyprint` + pango/cairo libs added to requirements + setup scripts; re-grep line numbers before editing.

---

## Context contract (what every theme binds to)

`_build_context(session_id)` already returns (verified by exploration): `session`, `findings[]` (each: `title, severity, host, port, service, description, cves[], evidence, remediation, tool_used, phase, verified, gated_reason, extra.cvss_base, extra.cvss_vector, mitre`), `summary{critical,high,medium,low,info,total}`, `sev`, `outcome`, `target_display`, `flags[]`, `graph`, `intel{os_guess,open_ports[],services{},shell_access}`, `coverage_tests[]{tool,target,command,outcome,note}`, `coverage_counts{}`, `discovered_issues[]`, `engagement_timeline[]{ts,label,detail}`, `mitre_mappings[]{technique_id,tactic,technique_name,tool_used,outcome}`, `objectives[]`, `win_conditions`, `creds_summary[]`, `loot_entries[]{severity,doi_label,source,target,size_bytes,sha256}`, `attack_path[]{__step,phase,result,source,ts}`, `exploit_modules[]`, `web_intel_hints[]`, `executive_summary`, `generated_at`, `engagement_type`, `duration`.
**Added by this plan:** `themes[]` (registry), per-finding `retest_status`, `detection_map[]`.

---

## Task 1: Theme registry

**Files:** Create `report/themes/__init__.py`; Test harness.

- [ ] **Step 1: Failing assertion** (`test_report_theme_registry`):
```python
def test_report_theme_registry():
    from report.themes import THEMES, get_theme, DEFAULT_THEME
    keys = set(THEMES.keys())
    assert {"executive","operator_dark","editorial","compliance","threat_intel"} <= keys
    assert DEFAULT_THEME == "executive"
    assert get_theme("nope") == get_theme(DEFAULT_THEME)   # unknown → default
    print("[PASS] theme registry")
```
- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3: Implement** `report/themes/__init__.py`:
```python
"""Selectable report themes — each is a Jinja2 template file in this package,
rendered from the same ReportGenerator._build_context.  Override-not-delete:
the professional/dark templates in report/ remain the guaranteed fallback."""
import os
from pathlib import Path

_DIR = Path(__file__).resolve().parent

THEMES = {
    "executive":     {"name": "Executive Consultancy", "file": "executive.html.j2",
                      "description": "Light, corporate, board-ready"},
    "operator_dark": {"name": "Operator Dark / SOC",   "file": "operator_dark.html.j2",
                      "description": "Premium dark SOC console (prints light)"},
    "editorial":     {"name": "Editorial Whitepaper",  "file": "editorial.html.j2",
                      "description": "Serif display, research-report typesetting"},
    "compliance":    {"name": "Compliance / Framework","file": "compliance.html.j2",
                      "description": "Audit-grade GRC, MITRE/OWASP/CVSS-forward"},
    "threat_intel":  {"name": "Threat-Intel / Kill-chain","file": "threat_intel.html.j2",
                      "description": "Infographic breach-story, hero kill-chain"},
}
DEFAULT_THEME = os.environ.get("ARGUS_REPORT_THEME", "executive")
if DEFAULT_THEME not in THEMES:
    DEFAULT_THEME = "executive"

def theme_path(key: str) -> Path:
    info = THEMES.get(key) or THEMES[DEFAULT_THEME]
    return _DIR / info["file"]

def get_theme(key: str) -> str:
    """Return the raw Jinja2 template string for a theme key (default on miss)."""
    p = theme_path(key if key in THEMES else DEFAULT_THEME)
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""

def list_themes():
    return [{"key": k, "name": v["name"], "description": v["description"]}
            for k, v in THEMES.items()]
```
- [ ] **Step 4: Run harness → PASS** (the `.j2` files arrive in Task 2; `get_theme` returns "" until then, which the registry test tolerates).

---

## Task 2: The 5 Jinja2 theme templates (workflow-generated, chunked)

**Files:** Create `report/themes/{executive,operator_dark,editorial,compliance,threat_intel}.html.j2`; Test harness.

Convert each approved standalone HTML (`docs/superpowers/report-options/optionN-*.html`) into a Jinja2 template that renders the **context contract** above, replacing every hardcoded sample value with bindings and guarding each section with `{% if %}`. Build each file CHUNKED (skeleton+CSS first, then sections appended before a `<!--MORE-->` anchor via Edit) so no single write exceeds the output cap.

**Binding rules (apply to all 5):**
- Stat tiles ← `summary.critical/high/medium/low/info/total`, access ← `outcome.label`.
- Findings register / cards ← `{% for f in findings %}`: severity `f.severity`, CVSS `f.extra.cvss_base`/`f.extra.cvss_vector`, host `f.host`, MITRE `f.mitre`, retest `f.retest_status` (Task 4), evidence `f.evidence`, remediation `f.remediation`, loot sample where present.
- Attempts log ← `{% for c in coverage_tests %}` (tool/command/outcome/note); "Tested — not exploitable" ← same list filtered `c.outcome in ("negative","blocked","error")`.
- Loot + evidence appendix ← `{% for l in loot_entries %}` (doi_label/source/target/`l.sha256`) + `creds_summary`.
- Attack-path graph ← inline SVG generated from `attack_path`/`graph` nodes (loop over stages).
- Data-viz ← inline SVG bars from `summary` + `coverage_counts`.
- MITRE map ← `mitre_mappings`; timeline ← `engagement_timeline`; scope card ← `intel.services`/`session`; detection ← `detection_map` (Task 4).
- Keep each file's `@page` + `@media print` CSS. Self-contained (inline CSS/SVG, Google Fonts only).

- [ ] **Step 1: Failing assertion** (`test_report_themes_render`):
```python
def test_report_themes_render():
    import pathlib, jinja2
    root = pathlib.Path(__file__).resolve().parent.parent
    tdir = root / "report" / "themes"
    sample = _sample_report_context()   # fixture defined in Task 6
    for key in ("executive","operator_dark","editorial","compliance","threat_intel"):
        f = tdir / f"{key}.html.j2"
        assert f.exists(), f"missing theme {key}"
        src = f.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in src and "@media print" in src, f"{key} not print-ready"
        html = jinja2.Template(src).render(**sample)         # must not raise
        assert "<!--MORE-->" not in html, f"{key} left a build marker"
        assert "<svg" in html, f"{key} missing inline SVG (graph/charts)"
        assert sample["target_display"] in html, f"{key} did not bind target"
    print("[PASS] 5 themes render from sample context")
```
- [ ] **Step 2: Run harness → FAIL** (files absent).
- [ ] **Step 3: Generate the 5 `.j2` files** via the report-template conversion workflow (5 parallel agents, chunked writes, each reads its source HTML + this binding contract and writes one `.j2`).
- [ ] **Step 4: Run harness → PASS** (all 5 render from the sample context, no markers, SVG present, target bound).

---

## Task 3: Generator — theme resolution + PDF cascade reorder

**Files:** Modify `report/generator.py` (`generate_html`, `generate_pdf`, template compile, `list_themes`); Test harness.

- [ ] **Step 1: Failing assertion** (`test_generator_theme_and_pdf_order`):
```python
def test_generator_theme_and_pdf_order():
    import inspect, report.generator as g
    gh = inspect.getsource(g.ReportGenerator.generate_html)
    assert "theme" in gh, "generate_html lacks theme arg"
    gp = inspect.getsource(g.ReportGenerator.generate_pdf)
    assert gp.index("weasyprint") < gp.index("pdf_writer"), "weasyprint must precede plaintext"
    assert "engine" in gp, "plaintext is opt-in via engine flag"
    assert "list_themes" in inspect.getsource(g), "generator exposes list_themes"
    print("[PASS] generator theme + pdf order")
```
- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3: Implement.** In `generate_html(self, session_id, theme=None)`: resolve `from report.themes import get_theme, DEFAULT_THEME`; `tpl = get_theme(theme or DEFAULT_THEME)`; if `tpl`: `from jinja2 import Template; html = Template(tpl).render(**ctx)` else fall back to `self._template.render(**ctx)`. Mirror in `generate_pdf(self, session_id, theme=None, engine=None)`. Reorder `generate_pdf` so weasyprint is attempted FIRST on the themed `html`; wkhtmltopdf second; return `None` if no styled engine (signal). Only call `report.pdf_writer` when `engine == "text"`. Add `def list_themes(self): from report.themes import list_themes as _lt; return _lt()`.
- [ ] **Step 4: Run harness → PASS.**

---

## Task 4: Derived context — retest_status + detection_map

**Files:** Modify `report/generator.py` (`_build_context`); Test harness.

- [ ] **Step 1: Failing assertion** (`test_context_retest_and_detection`):
```python
def test_context_retest_and_detection():
    import inspect, report.generator as g
    bc = inspect.getsource(g.ReportGenerator._build_context)
    assert "retest_status" in bc and "detection_map" in bc, "derived fields missing"
    print("[PASS] retest + detection derived")
```
- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3: Implement** in `_build_context`, after `findings` is finalized:
```python
        # Per-finding retest status (drives the register's Verified/Open/Gated column)
        for _f in (findings or []):
            if isinstance(_f, dict):
                if _f.get("verified") is True:
                    _f["retest_status"] = "Verified"
                elif _f.get("gated_reason"):
                    _f["retest_status"] = "Gated"
                else:
                    _f["retest_status"] = "Open"
        # Best-effort, content-agnostic detection/purple-team hints (per finding):
        # generic telemetry suggestion from the finding's MITRE technique/class —
        # NO hardcoded vuln/payload table.
        detection_map = []
        for _f in (findings or []):
            if not isinstance(_f, dict):
                continue
            _tech = str(_f.get("mitre") or "").strip()
            _host = _f.get("host") or ""
            detection_map.append({
                "finding": _f.get("title", ""),
                "technique": _tech or "—",
                "opportunity": f"Activity on {_host or 'the asset'} consistent with this finding",
                "telemetry": ("Correlate the tool/command that produced it with host telemetry; "
                              "alert on the matching " + (_tech or "ATT&CK") + " behaviour"),
                "caught": "Open",
            })
```
and add `"detection_map": detection_map,` to the returned context dict.
- [ ] **Step 4: Run harness → PASS.**

---

## Task 5: Endpoint — `?theme=` + `/report/themes`

**Files:** Modify `agent_server.py` (report endpoint + new themes route); Test harness.

- [ ] **Step 1: Failing assertion** (`test_report_endpoint_theme`):
```python
def test_report_endpoint_theme():
    srv = open("agent_server.py","r",encoding="utf-8").read()
    assert 'theme' in srv and 'report/themes' in srv, "endpoint missing theme param / themes route"
    print("[PASS] report endpoint theme wiring")
```
- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3: Implement.** In the report endpoint handler, read `theme = request.query_params.get("theme")` (or the existing param plumbing) and pass to `generate_html(session_id, theme=theme)` / `generate_pdf(session_id, theme=theme, engine=request.query_params.get("engine"))`. On `format=pdf` returning `None`, respond with `Response(status_code=503, headers={"X-PDF-Engine":"none"})` (frontend falls back to print). Add `@app.get("/report/themes")` returning `JSONResponse(ReportGenerator(...).list_themes())` (or a module-level `from report.themes import list_themes`).
- [ ] **Step 4: Run harness → PASS.**

---

## Task 6: Dependencies + setup + sample fixture

**Files:** Modify `requirements.txt`, `setup.sh`, `install-kali-tools.sh`; add `_sample_report_context()` to the harness; Test harness.

- [ ] **Step 1: Failing assertion** (`test_pdf_deps_provisioned`):
```python
def test_pdf_deps_provisioned():
    req = open("requirements.txt","r",encoding="utf-8").read().lower()
    assert "weasyprint" in req, "weasyprint not in requirements"
    setup = open("setup.sh","r",encoding="utf-8").read().lower()
    assert "pango" in setup or "weasyprint" in setup, "setup.sh missing weasyprint system libs"
    print("[PASS] pdf deps provisioned")
```
- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3: Implement.** Add `weasyprint>=60` to `requirements.txt`. Add to `setup.sh` + `install-kali-tools.sh` an apt line: `libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 libffi-dev` with a comment "# weasyprint: server-side styled PDF". Add `_sample_report_context()` to the harness returning a realistic dict matching the context contract (findings with cvss/verified/gated_reason/retest_status, coverage_tests, loot_entries with sha256, mitre_mappings, attack_path, summary, outcome, target_display, etc.) for Task 2's render test.
- [ ] **Step 4: Run harness → PASS.**

---

## Task 7: Frontend — theme picker + print fallback

**Files:** Modify `static/js/pages/ReportPage.jsx`, `templates/index.html` (cache-bust); Test harness.

- [ ] **Step 1: Failing assertion** (`test_reportpage_theme_picker`):
```python
def test_reportpage_theme_picker():
    rp = open("static/js/pages/ReportPage.jsx","r",encoding="utf-8").read()
    assert "theme" in rp and "report/themes" in rp, "ReportPage missing theme picker"
    assert "window.print" in rp or "printToPdf" in rp, "ReportPage missing browser-print fallback"
    print("[PASS] ReportPage theme picker + print fallback")
```
- [ ] **Step 2: Run harness → FAIL.**
- [ ] **Step 3: Implement.** In `ReportPage.jsx`: on mount fetch `/report/themes`, render a `<select>` (default executive, persisted in `localStorage` `argus_report_theme`); on change reload the in-page report iframe/preview with `?theme=<key>` and update the HTML/PDF download links to include `&theme=<key>`. Change `downloadPDF()`: request the PDF endpoint with the theme; if the response is 503 / `X-PDF-Engine: none`, open the themed HTML (`?theme=…`) in a new window and call `window.print()` (the user saves as PDF). Keep a visible "Print / Save as PDF" button that always does the client-side print.
- [ ] **Step 4: Cache-bust** — bump `ReportPage.jsx?v=` in `templates/index.html`.
- [ ] **Step 5: `node --check` (as .js)** + **Run harness → PASS.**

---

## Task 8: Final sweep

- [ ] **Step 1:** `python -X utf8 agents/test_architecture_integration.py` → `RESULT: PASS`.
- [ ] **Step 2:** Confirm `test_no_hardcoded_attack_content`, `test_professional_report_template`, `test_report_storyline_sections`, `test_report_pdf_and_ui_population` still PASS (non-regression).
- [ ] **Step 3:** `py_compile` `report/generator.py`, `report/themes/__init__.py`, `agent_server.py`; `node --check` `ReportPage.jsx`.
- [ ] **Step 4:** Open each `report/themes/*.html.j2` rendered (the Task-2 test already does) — confirm 5 distinct, complete.
- [ ] **Step 5:** Produce the edited-files list for manual Windows→Kali copy.

---

## Self-review

**Spec coverage:** themes/registry → T1; 5 templates + bindings → T2; theme selection (generator) → T3; retest+detection derived → T4; endpoint `?theme=` + `/report/themes` → T5; weasyprint dep + setup + sample fixture → T6; PDF cascade reorder → T3; UI picker + print fallback → T7; testing/non-regression → every task + T8. All spec sections mapped.

**Placeholder scan:** new units carry real code; the 5-template conversion is delegated to a workflow with an explicit binding contract (not a placeholder). No TBD/TODO.

**Type consistency:** `get_theme`/`list_themes`/`DEFAULT_THEME`/`THEMES` defined T1, used T3/T5/T7. `retest_status`/`detection_map` defined T4, consumed by T2 templates. `_sample_report_context()` defined T6, used T2. `generate_html(theme=)`/`generate_pdf(theme=,engine=)` defined T3, called T5. Consistent.
