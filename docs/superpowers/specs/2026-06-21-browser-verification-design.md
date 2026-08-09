# Headless-Browser Verification of Web Findings (Gap #2) — Design

**Goal:** ARGUS confirms web findings that curl cannot prove (IDOR, auth-bypass, business-logic, DOM/reflected-XSS) by driving a real headless browser, attaches a PoC artifact, and gates the report on the result — delivering the "verified findings" correctness story. Additive, best-effort, never breaks the engagement.

**Status:** approved (brainstorm 2026-06-21). First of the 8-gap correctness program. Prereq for Gap #1.

## Decisions (locked)
- **Engine:** self-contained Python Playwright subagent (`agents/web/browser_verify_subagent.py`), headless Chromium. **Optional dependency** — if Playwright/Chromium is absent, verification is a no-op (finding keeps original severity + honest note); nothing breaks until `pip install playwright && playwright install chromium`.
- **Gate:** auto-verify candidate findings → VERIFIED keeps/raises severity + PoC artifact + DEMONSTRATED/CONFIRMED tag; UNVERIFIED (browser+creds available) → downgraded to a separate **"Unverified — needs manual confirmation"** report section (never dropped); not-tried (no browser / no creds for that class) → original severity + note.
- **Creds:** merge ARGUS-found `intel.credentials` + optional operator `verification_accounts` (user A/B); degrade ≥2→cross-user IDOR, 1→auth-vs-unauth, 0→unauth-only.

## Component — `agents/web/browser_verify_subagent.py` (testable-pure surfaces + isolated browser)
Pure (unit-tested without a browser):
- `verifiable_class(finding) -> 'idor'|'auth_bypass'|'xss'|'business_logic'|None` — classify by title/tags/cwe.
- `collect_verify_creds(intel, config) -> {accounts:[...], mode:'cross_user'|'auth_unauth'|'unauth'}`.
- `apply_verdict(finding, verdict, *, browser_available, creds_present) -> finding'` — the decision:
  - `verified is True` → `extra.browser_verified=True`, `extra.poc_artifacts=[...]`, `extra.verification_method`, severity signals `confirmed=True, directly_exploitable=True` (→ operational policy DEMONSTRATED/CONFIRMED), keep/raise severity.
  - `verified is False` (tried, failed) → `extra.browser_verified=False`, severity → low, `extra.unverified_reason`, `extra.report_section='unverified'`.
  - `verified is None` (not tried) → `extra.browser_verified=None`, `extra.unverified_reason`, original severity unchanged.
- `is_browser_available() -> bool` — Playwright importable.

Isolated (real browser, import-safe via lazy import; runs on Kali):
- `async verify(finding, intel, config) -> verdict` with per-class recipes:
  - **IDOR** (cross_user): login A → fetch resource id → login B → fetch same id → B reads A's data ⇒ verified; diff bodies. Artifacts: 2 screenshots + HAR + DOM diff.
  - **auth_bypass**: fetch protected route unauth / tampered token → returns protected content (not login redirect) ⇒ verified.
  - **xss**: navigate with payload, confirm execution in DOM (marker/dialog) ⇒ verified.
  - **business_logic**: best-effort replay of described steps; else not-tried.
  - Scope-enforced (in-scope host only), 60s/finding cap, all exceptions → `verified=None`.

## Integration — `agents/base_subagent.store_finding`
Best-effort post-hook (gated by env `ARGUS_BROWSER_VERIFY`, default on): for a `verifiable_class` finding, if `is_browser_available()` → `await verify(...)` (capped) → `apply_verdict(...)` before the doc is finalized. Absent browser → instant no-op (current dev default). Fully wrapped; any failure → finding stored as-is.

## Report — `report/generator.py` + executive theme
Findings with `extra.browser_verified==False` (or `extra.report_section=='unverified'`) render in a new **"Unverified Findings — manual confirmation needed"** section, separate from the main register. Verified findings show their PoC-artifact references + the DEMONSTRATED/CONFIRMED evidence tag (already wired).

## Deps
`requirements-kali.txt` += `playwright`; `install-kali-tools.sh` += `playwright install --with-deps chromium`. Kept optional so non-Kali/dev installs are unaffected.

## Testing (no Chromium in dev → test the pure surfaces + degradation)
- `verifiable_class` classification; `collect_verify_creds` degradation (0/1/2 accounts → mode); `apply_verdict` all three branches (verified→tag, unverified+available→downgrade+section, not-tried→unchanged); `is_browser_available()` false-safe; the store_finding hook is a no-op when the browser is unavailable. Harness stays `RESULT: PASS`. A checkpoint self-audit (Workflow) confirms no regression to the existing web/finding pipeline.
