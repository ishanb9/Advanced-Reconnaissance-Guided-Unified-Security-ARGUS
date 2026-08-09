# Report Overhaul — Design Spec

> Sub-project #2 of the 2026-06-19 ARGUS enhancement program (order: 1 Integrity ✅ → **2 Report** → 3 Crestron → 4 AI-engine).
> Status: approved in brainstorming; pending spec review → writing-plans.

## 1. Problem

1. **The PDF download is broken on Kali.** `generator.generate_pdf()` cascades wkhtmltopdf → weasyprint → `report/pdf_writer.py` (a stdlib plaintext writer). Neither weasyprint nor wkhtmltopdf is in `requirements.txt`/`requirements-kali.txt`, so on a stock Kali install the download **always falls to the plaintext writer** — a raw, unstyled report that looks nothing like the HTML the user sees.
2. **The report should be a leader-class deliverable.** The client took ARGUS output and re-rendered it into a far richer document (cover, stat-tile exec summary, system/scope card, attack-path graph, findings register with retest, evidence appendix with hashes, detection/purple-team mapping, data-viz). ARGUS already has a professional light template (`report/report_template.py`) and a rich `_build_context`, but it is one fixed look and missing several rich surfaces (attempts log, captured-loot samples, non-exploitable coverage, retest column, CVSS rubric, evidence appendix, data-viz, attack-path graph).
3. **The user wants choice.** Five distinct visual treatments were produced and approved; all five should ship as **selectable** report themes.

## 2. Goals / Non-goals

**Goals**
- Five **selectable** report themes (executive · operator-dark · editorial · compliance · threat-intel), each a faithful Jinja2 conversion of the approved standalone HTML, all rendering ARGUS's real `_build_context` data.
- A theme **picker** on the Report page + a `theme` endpoint param; the **PDF download renders the selected theme** and matches the HTML.
- **Fix the PDF bug**: weasyprint (renders the exact styled HTML) is the primary engine; if unavailable, the frontend falls back to **browser print-to-PDF** of the styled theme; the plaintext writer drops to absolute-last-resort (never the default styled download).
- Surface the rich detail the client sample had, wired to real data: **attempts log** (exploitable + non-exploitable), **captured loot samples + SHA-256**, attack-path graph, findings register with **Verified/Open/Gated retest**, CVSS rubric + per-finding score, MITRE map, evidence appendix, detection/purple-team mapping (best-effort), data-viz, remediation roadmap, timeline.

**Non-goals**
- AI-security-specific modules (ASR metrics, shadow-AI discovery, responsible-AI harm matrix, EU AI Act compliance mapping) — those are sub-project #4 (the AI engine). The themes adopt the *visual language*; AI content comes later.
- Re-architecting `_build_context` (it already exposes the needed keys; we add only small derived fields).
- Engine/agent changes (this is the report layer + report endpoint + report UI).

## 3. Hard constraints

- **Additive / no regression.** The existing dark template and `report_template.py` remain as guaranteed fallbacks. Default behavior (no theme chosen) renders a valid styled report. Toggle/guarded; reverting is safe.
- **Harness** `python -X utf8 agents/test_architecture_integration.py` stays green; new guard tests registered in `main()`.
- **Frontend** edits pass `node --check` (the report UI uses `React.createElement`, no JSX); bump the relevant `?v=` in `templates/index.html`.
- **Delivery:** edits made on Windows, copied manually to Kali; every response ends with the edited-file list. New dependency (`weasyprint`) + its system libs (pango/cairo/gdk-pixbuf) added to `requirements.txt` and `setup.sh`/`install-kali-tools.sh` so the user can provision them.
- **No hardcoded vuln content in engine modules** (`report/` is the report layer; any derived "detection hint" is generic/content-agnostic, not a CVE/product/payload table).

## 4. Components

### A. Theme registry + 5 Jinja2 templates

- New `report/themes/` package: five Jinja2 template files — `executive.html.j2`, `operator_dark.html.j2`, `editorial.html.j2`, `compliance.html.j2`, `threat_intel.html.j2` — each a faithful conversion of the approved standalone HTML in `docs/superpowers/report-options/`, with hardcoded sample values replaced by Jinja2 bindings over the `_build_context` keys (Section 5). Each is self-contained (inline CSS, inline SVG graph/charts, no external JS; web fonts via Google Fonts only), and keeps its `@page` + `@media print` rules.
- `report/themes/__init__.py` exposes `THEMES` (ordered dict): `{key: {"name", "description", "file"}}` and a `get_theme(key) -> str|Template` loader (Jinja2 `FileSystemLoader` on `report/themes/`). Unknown/empty key → default.
- Default theme key = `"executive"` (env-overridable: `ARGUS_REPORT_THEME`).
- The existing `report_template.py` / dark template remain importable fallbacks if a theme file is missing or fails to render.
- **Graceful degradation:** every template guards each section with `{% if <data> %}` so a sparse engagement (e.g. recon-only) renders cleanly without empty shells.

### B. Theme selection (generator + endpoint + UI)

- `generator.py`: `generate_html(session_id, theme: str|None=None)` and `generate_pdf(session_id, theme: str|None=None)` resolve the theme (arg → `ARGUS_REPORT_THEME` → `"executive"`) and render that template with the same `_build_context`. A `list_themes()` helper returns `THEMES` for the UI.
- `agent_server.py`: the report endpoint accepts `?theme=<key>` (HTML and PDF) and a `GET /report/themes` returns the theme list (key/name/description) for the picker.
- Frontend report page (`static/js/pages/ReportPage.jsx`): a **theme dropdown** (populated from `/report/themes`), defaulting to executive; changing it reloads the in-page preview and updates the HTML/PDF download links with `&theme=`. Selection persisted (localStorage) so it's remembered.

### C. PDF fidelity (the bug)

- `generate_pdf(theme)` order: **weasyprint** (renders the selected theme's HTML → full-fidelity PDF) → wkhtmltopdf (if a binary exists) → return `None` to signal "no server engine." The plaintext `pdf_writer` is used **only** for explicitly headless/API callers (a `?engine=text` opt-in), never as the default styled download.
- Endpoint: on `format=pdf`, if a styled engine produced bytes → serve `application/pdf`. If none available → respond with a small JSON/`X-PDF-Engine: none` so the frontend triggers the **client-side fallback**.
- **Client-side fallback:** the "Download PDF" button, when the server has no styled engine, opens the themed report in a print-optimized view and calls `window.print()` (the user picks "Save as PDF") — zero dependency, pixel-perfect, works on any box. A always-available "Print / Save as PDF" affordance is added regardless.
- **Dependencies:** add `weasyprint>=60` to `requirements.txt`; add the system libs (`libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 libffi-dev`) to `setup.sh` + `install-kali-tools.sh` with a comment that they enable server-side styled PDF.

### D. Rich-data binding (the new surfaces, wired to real context)

All themes render these from existing `_build_context` keys (Section 5); detail the client sample had:
- **Attempts log** — from `coverage_tests` (tool · command · outcome `success|blocked|error|negative` · note), color-coded by outcome; a **"Tested — not exploitable"** subsection filters `outcome in (negative, blocked, error)` so coverage is visible, not just hits.
- **Findings register** — from `findings`: ID · finding · severity (color-coded) · **CVSS** (`cvss_base`/`cvss_vector`) · host · MITRE · **retest status** derived from `verified`/`gated_reason` (`Verified` if `verified` true, `Gated` if `gated_reason` set, else `Open`). Detailed finding cards include description, evidence, remediation.
- **Captured loot + samples** — from `loot_entries`/`creds_summary`: per artifact a redacted sample + **SHA-256** (`sha256`) + source; an **evidence appendix** table (artifact · type · finding · hash). Redaction note rendered.
- **Attack-path graph** — inline SVG kill-chain from `attack_path`/`graph` (stage → stage, MITRE-labelled, severity/tactic-colored).
- **Data-viz** — inline SVG severity-distribution bar (from `summary`) + attempt-outcome breakdown (from `coverage_counts`). No external chart libs.
- **CVSS rubric** — a static rubric/legend section + per-finding score/vector.
- **MITRE map** — from `mitre_mappings`.
- **Detection / purple-team mapping** — a **best-effort, content-agnostic** per-finding section: a small derived `detection_map` in `_build_context` that, for each finding, emits a generic telemetry/rule hint from the finding's MITRE technique/class (no hardcoded vuln table) + a "caught today?" Open default. Renders when findings exist.
- **Remediation roadmap** (P1/P2/P3 from severity), **engagement timeline** (`engagement_timeline`), **system/scope card** (`intel`/`session` services + trust boundary), **exec summary** (`summary`/`outcome`/`executive_summary` + stat tiles).

### E. Severity color system

One palette shared across all themes (each theme restyles it but keeps the semantics): critical / high / medium / low / info, applied to badges, the register, stat tiles, charts, and the graph, with a small legend. Print-safe (dark themes flip to ink-friendly backgrounds under `@media print`).

## 5. Data model / context contract

The themes render the existing `_build_context` keys (no shape change): `session`, `findings` (incl. `cvss_base`/`cvss_vector`/`verified`/`gated_reason`/`evidence`/`remediation`/`host`/`port`/`cves`/`mitre`), `summary`, `sev`, `outcome`, `target_display`, `tools_used`, `flags`, `graph`, `intel`, `coverage_tests`, `coverage_counts`, `discovered_issues`, `engagement_timeline`, `mitre_mappings`, `objectives`, `win_conditions`, `creds_summary`, `loot_entries` (incl. `sha256`), `attack_path`, `exploit_modules`, `web_intel_hints`, `executive_summary`, `generated_at`, `engagement_type`, `duration`.
**Added (small, derived in generator):** `detection_map` (per-finding generic telemetry hint), `themes` (registry for the picker), and a normalized per-finding `retest_status`.

## 6. Testing

New guard tests in `agents/test_architecture_integration.py` (registered in `main()`):
- Theme registry: `THEMES` has the 5 keys; each theme file exists, parses as Jinja2, contains `<!DOCTYPE html>` + `@media print` + the required section markers; default key is `executive`.
- Selection: `generate_html(theme=<each>)` renders without error from a **sample context fixture** and the output contains that theme's signature class/marker; unknown theme falls back; `list_themes()`/`/report/themes` returns 5.
- Rich sections present: rendered sample HTML contains the attempts log + "not exploitable" subsection, the loot/evidence SHA-256 appendix, the retest column, the CVSS rubric, the attack-path `<svg>`, and the data-viz `<svg>`.
- PDF fidelity: `generate_pdf` attempts weasyprint **before** the plaintext writer; the plaintext path is reachable only via the explicit `engine=text` opt-in; `weasyprint` is listed in `requirements.txt`; the pango/cairo libs are in `setup.sh`/`install-kali-tools.sh`.
- Frontend: `ReportPage.jsx` has the theme dropdown + `&theme=` link wiring + the client-side print fallback; `node --check` passes; cache-bust bumped.
- Regression: existing report tests (`test_professional_report_template`, `test_report_storyline_sections`, `test_report_pdf_and_ui_population`) still pass; the dark/professional fallback still renders.

## 7. Files touched (map)

- **Create** `report/themes/__init__.py` + `report/themes/{executive,operator_dark,editorial,compliance,threat_intel}.html.j2` (converted from `docs/superpowers/report-options/*.html`).
- `report/generator.py` — theme resolution in `generate_html`/`generate_pdf`; `list_themes()`; `detection_map` + `retest_status` derivation in `_build_context`; PDF cascade reorder (weasyprint primary, plaintext opt-in only).
- `agent_server.py` — `?theme=` on the report endpoint; `GET /report/themes`.
- `static/js/pages/ReportPage.jsx` — theme dropdown, `&theme=` links, client-side print-to-PDF fallback, persisted selection.
- `templates/index.html` — cache-bust bump for `ReportPage.jsx`.
- `requirements.txt` — `weasyprint>=60`.
- `setup.sh`, `install-kali-tools.sh` — pango/cairo/gdk-pixbuf system libs.
- `agents/test_architecture_integration.py` — guard tests.
- (Untracked reference: `docs/superpowers/report-options/*.html` — the approved source designs.)

## 8. Rollout / revertibility

Default theme = executive; `ARGUS_REPORT_THEME` overrides. If weasyprint isn't installed, the styled PDF still works via the browser-print fallback (no plaintext). The dark/professional template remains the fallback if a theme file is missing. All additive — removing the themes dir/param restores prior behavior.

## 9. Risks

- **weasyprint system deps on Kali** — needs pango/cairo; mitigated by the setup-script additions + the zero-dependency browser-print fallback so a missing lib never reproduces the raw-PDF bug.
- **5-template maintenance** — five faithful templates to keep in sync with the context contract; mitigated by the shared context keys + graceful `{% if %}` guards + the harness sample-context render test per theme.
- **HTML→Jinja2 conversion fidelity** — each large template must bind correctly without breaking layout; mitigated by per-theme render tests against a sample fixture and `node`/Jinja2 parse checks.
- **Detection mapping** — kept generic/content-agnostic to avoid hardcoded vuln content; richer detection is #4.
