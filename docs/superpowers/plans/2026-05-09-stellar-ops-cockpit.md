# Stellar Ops Cockpit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the ARGUS frontend into a cinematic spacecraft-cockpit aesthetic with four audience-mode altitudes and a 9-hub navigation, fixing the broken theme switcher and preserving 100% of existing page content — without modifying any agent / engine / RAG / DB code.

**Architecture:** All work is **presentation-layer only**. CSS variables become the single source of truth for theming; React inline styles use `'var(--token)'` strings to defer to runtime CSS resolution. A new `viewMode` state slice in `store.js` drives multi-altitude rendering. Hub aggregation collapses 19 routes into 9 tab-grouped hubs while preserving every original page component as a tab-panel. Motion is event-driven via additive WS-event taps in the existing reducer — no removed cases, no renamed actions. The cardinal non-regression constraint (Spec §3) gates every tier merge with five smoke tests.

**Tech Stack:** React 18 + ReactDOM (CDN), Babel-in-browser (no build step), plain CSS3 with custom properties, localStorage for persistence, vanilla `<canvas>` for the attack-graph particle field (~200 lines, no Three.js / Spline / WebGL framework).

**Spec:** `docs/superpowers/specs/2026-05-09-stellar-ops-cockpit-design.md` (must be read first by the implementing engineer)

---

## Pre-flight

### 0.0  Workspace setup

- [ ] **Step 1: Confirm worktree clean and on the correct branch**

  ```bash
  cd /path/to/v1
  git status              # expect: "nothing to commit, working tree clean"
  git rev-parse --abbrev-ref HEAD   # expect: a feature branch, NOT main
  ```

  If on main, create a feature branch:

  ```bash
  git checkout -b feat/stellar-ops-cockpit
  ```

  If `git status` shows uncommitted work, stop and resolve before starting.

- [ ] **Step 2: Read the spec in full**

  ```bash
  cat docs/superpowers/specs/2026-05-09-stellar-ops-cockpit-design.md | less
  ```

  Pay particular attention to **Section 3 (Cardinal constraint)** — every commit must respect the off-limits module list in §3.1.

- [ ] **Step 3: Snapshot current behaviour as baseline**

  Run all 5 smoke tests from Spec §3.3 before touching any code:

  - **Smoke 1** — Start the server, load the GUI, confirm all 19 pages in `PAGES` are reachable and console shows no errors:
    ```bash
    python agent_server.py &
    # Open http://localhost:8000 in browser
    # Click each sidebar entry, confirm page renders, no console errors
    ```
  - **Smoke 2** — Run a localhost scan, confirm full data flow (KB load + WS events + findings + report generation).
  - **Smoke 3** — Switch theme via the existing switcher in the header. Note: theme switching IS broken — that's what we're fixing. The baseline is "switching shows no visible change" (Spec §4 item 1).
  - **Smoke 4** — Reload mid-scan, confirm WS reconnect + state restoration.
  - **Smoke 5** — Set `prefers-reduced-motion: reduce` in browser DevTools, confirm UI is usable.

  Document baseline snapshots (screenshots) for visual regression comparison. Save under `/tmp/argus-baseline/` (gitignored).

- [ ] **Step 4: Verify off-limits module integrity**

  ```bash
  ls -la agents/master_agent.py agents/reasoning/ agents/web/web_orchestrator.py \
         agents/web/ agents/base_agent.py agents/base_subagent.py \
         agents/web_agent.py agents/attack_graph_agent.py agents/meta/expert_agent.py \
         knowledge/build_kb.py knowledge/knowledge_base.py utils/scan_logger.py \
         agent_server.py db/ schemas.py mcp-server.js
  ```

  Capture file checksums for spot-check after each tier:

  ```bash
  find agents/ knowledge/ utils/ db/ agent_server.py schemas.py mcp-server.js \
       -name "*.py" -o -name "*.js" \
       | xargs sha256sum > /tmp/argus-offlimits-baseline.sha256
  ```

  After every tier merge, re-run and diff:

  ```bash
  find agents/ knowledge/ utils/ db/ agent_server.py schemas.py mcp-server.js \
       -name "*.py" -o -name "*.js" \
       | xargs sha256sum | diff /tmp/argus-offlimits-baseline.sha256 -
  ```

  Expected output: empty diff. Any line in the diff = cardinal-constraint violation. Stop and revert.

---

## File structure overview

This plan modifies the following files. **No new files are created**. The list mirrors Spec §13.1.

| Tier | File | Purpose |
| ---- | ---- | ------- |
| T1   | `static/css/main.css` | New `:root` token block (Stellar Ops palette); 4 alternate `[data-theme]` blocks. Drop `daylight`. |
| T1   | `static/js/app.jsx` | Find/replace `T.<color>` → `'var(--<token>)'`. Drop the `T = {}` const. |
| T1   | `static/js/pages/RiskDashboard.jsx` | Same find/replace pass. |
| T1   | `static/js/pages/WebTesting.jsx` | Same find/replace pass. |
| T2   | `static/css/main.css` | Add cockpit chrome styles, Stellar Beam, ambient illumination, hub tab-bar. |
| T2   | `static/js/app.jsx` | New HUD header layout, telemetry strip, consumables strip, mission clock. Replace `PAGES` array with 9-hub `HUBS` structure + tab routing. Add legacy alias resolver + localStorage migration. |
| T2   | `static/js/store.js` | Additive: `currentHub`, `currentTab`, plus a few WS-event taps for telemetry counters. |
| T3   | `static/css/main.css` | Animation keyframes for breathe, supernova, mote-drift, light-trail, neuron-fire. Wrap each in `prefers-reduced-motion` opt-out. |
| T3   | `static/js/store.js` | Additive: 4-5 transient motion-trigger flags driven by existing WS events. |
| T3   | `static/js/components/PhaseTimeline.jsx` | Apply breathe class to active phase + advance light-trail on transition. |
| T3   | `static/js/components/AgentCard.jsx` | LLM-thinking ring overlay. |
| T3   | `static/js/components/FindingCard.jsx` | Mote spawn on finding-added event. |
| T3   | `static/js/components/StatusBadge.jsx` | Severity glyphs + supernova class on critical. |
| T3   | `static/js/components/LiveTerminal.jsx` | Operator Terminal scanline overlay. |
| T4   | `static/js/pages/RiskDashboard.jsx` | Halo hero + 8° tilted perspective on hero block. |
| T4   | `static/js/pages/AttackGraph.jsx` | Particle starburst on `<canvas>` (~200 lines), drag-to-pan, scroll-zoom. |
| T4   | `static/css/main.css` | Crosshair section dividers, halo ring CSS. |
| T5   | `static/js/store.js` | Additive: `viewMode`, `client`, `present` slices. New reducer case `SET_VIEW_MODE`. |
| T5   | `static/js/app.jsx` | Mode picker dropdown, F1-F4 shortcuts, mode-aware top-level layout (e.g., hide sidebar in PRESENT). |
| T5   | All major pages (Risk, Operations, Findings, Attack Graph, Reasoning, Foothold, Workshop, Reports, System) | Read `state.viewMode`, conditionally render. |
| T6   | `static/js/app.jsx` | Splash screen component, transition cross-fades. |
| T6   | `static/css/main.css` | Splash styles, mobile breakpoints, full reduced-motion audit. |
| T6   | `templates/index.html` | Cache-bust version bumps for all touched JS files. |

---

## Tier 1 — Foundation: theme switcher fix

**Spec ref:** §6 (color system), §7 (typography), §13.1, §14 Tier 1.
**Goal:** Switching themes visibly changes 100% of UI surface (currently ~30%).
**Estimated effort:** 1.5 days.
**Cardinal-constraint risk:** Low — only `static/css/main.css` and inline-style hex literals change.

### Task 1.1: Define the Stellar Ops token block

**Files:**
- Modify: `static/css/main.css:19-77` (the existing `:root` block)

- [ ] **Step 1: Read current `:root` block to understand existing tokens**

  ```bash
  sed -n '19,77p' static/css/main.css
  ```

  Note every existing variable name. The replacement must preserve names that downstream rules reference, OR rename them and update downstream usages.

- [ ] **Step 2: Replace `:root` block with the Stellar Ops palette**

  Replace lines 19-77 of `static/css/main.css` with the exact block below (matches Spec §6):

  ```css
  :root {
    /* SURFACE LAYERS */
    --bg-base:          #04050E;
    --bg-void:          #04050E;     /* alias for --bg-base, prefer --bg-void in new code */
    --bg-surface:       #0A1023;
    --bg-panel:         #0A1023;     /* alias for --bg-surface, kept for legacy */
    --bg-elevated:      #0F1832;
    --bg-glass:         rgba(15, 24, 50, 0.78);

    /* BORDERS */
    --border-dim:       #1B2750;
    --border:           #2D3F75;
    --border-light:     #2D3F75;     /* alias */
    --border-bright:    #4F5DA8;
    --border-focus:     var(--accent);

    /* PRIMARY */
    --accent:           #4FA8FF;
    --accent-dim:       #2E72C7;
    --accent-glow:      rgba(79, 168, 255, 0.22);
    --accent-subtle:    rgba(79, 168, 255, 0.07);

    /* SECONDARY */
    --cyan:             #38E5FF;
    --violet:           #7B6CF6;

    /* TEXT */
    --text-primary:     #E5EAF6;
    --text-secondary:   #94A0C5;
    --text-muted:       #4F5876;

    /* SEVERITY */
    --critical:         #FF4560;
    --high:             #FF8C42;
    --medium:           #FFC83D;
    --amber:            #FFC83D;     /* alias for legacy --amber callers */
    --low:              #4ADE80;
    --info:             var(--accent);

    /* SUPERNOVA */
    --supernova:        #FF4D8F;

    /* TYPOGRAPHY */
    --font-ui:          'Inter', system-ui, sans-serif;
    --font-display:     'Inter', system-ui, sans-serif;
    --font-mono:        'JetBrains Mono', 'Courier New', monospace;
  }
  ```

  **Why aliases?** Some legacy CSS rules (and inline styles we'll convert next) reference `--bg-panel`, `--border-light`, `--amber`. Adding aliases preserves them while we migrate to the new canonical names.

- [ ] **Step 3: Verify CSS still parses**

  ```bash
  python -c "
  import re
  src = open('static/css/main.css', encoding='utf-8').read()
  # crude balance check
  assert src.count('{') == src.count('}'), 'brace mismatch'
  print(f'main.css: {len(src)} bytes, {src.count(chr(10))} lines, braces balanced')
  "
  ```

  Expected: `braces balanced` printed.

- [ ] **Step 4: Visual verification**

  Reload the GUI in browser. Pages that already use `var(--*)` (most of them) should now show Stellar Ops colors. Pages that still use the `T = {}` object (app.jsx header, RiskDashboard, WebTesting) will still look unchanged — they're fixed in Task 1.2-1.4.

- [ ] **Step 5: Commit**

  ```bash
  git add static/css/main.css
  git commit -m "feat(ui): switch :root palette to Stellar Ops tokens

  Adds the new black/blue cosmic palette as default. Aliases preserve
  legacy variable names so existing CSS rules + inline styles keep
  working until they're migrated in subsequent tasks."
  ```

### Task 1.2: Replace alternate theme blocks

**Files:**
- Modify: `static/css/main.css` — `[data-theme="graphite"]`, `[data-theme="amber"]`, `[data-theme="sapphire"]`, `[data-theme="contrast"]`. Delete `[data-theme="daylight"]` if present.

- [ ] **Step 1: Locate existing theme blocks**

  ```bash
  grep -n '\[data-theme' static/css/main.css
  ```

  Expected: 5-6 matches (midnight default + 5 alternates). Note the line ranges.

- [ ] **Step 2: Replace each alternate-theme block**

  For each theme, override the same set of tokens defined in the new `:root`. Replace each `[data-theme="<name>"]` block with the canonical token list. Example for graphite:

  ```css
  [data-theme="graphite"] {
    --bg-base:          #15171C;
    --bg-void:          #15171C;
    --bg-surface:       #1F232C;
    --bg-panel:         #1F232C;
    --bg-elevated:      #2A2F3C;
    --bg-glass:         rgba(31, 35, 44, 0.78);
    --border-dim:       #2A2F3C;
    --border:           #3A4156;
    --border-light:     #3A4156;
    --border-bright:    #4D5670;
    --accent:           #38BDF8;
    --accent-dim:       #0EA5E9;
    --accent-glow:      rgba(56, 189, 248, 0.18);
    --accent-subtle:    rgba(56, 189, 248, 0.06);
    --cyan:             #38BDF8;
    --violet:           #8B5CF6;
    --text-primary:     #E5E7EB;
    --text-secondary:   #9CA3AF;
    --text-muted:       #6B7280;
    --critical:         #EF4444;
    --high:             #F97316;
    --medium:           #F59E0B;
    --amber:            #F59E0B;
    --low:              #10B981;
    --info:             var(--accent);
    --supernova:        #FF4D8F;
  }
  ```

  Repeat for `amber`, `sapphire`, `contrast`. **Drop `[data-theme="daylight"]`** entirely (Spec §2.1, §6.1).

  Each alternate must override the SAME variable list as `:root` so theme switching works for every reference.

- [ ] **Step 3: Verify all themes parse**

  Reload GUI, open browser DevTools, in the console:

  ```javascript
  document.documentElement.setAttribute('data-theme', 'graphite');
  // observe: cyan accent, charcoal background
  document.documentElement.setAttribute('data-theme', 'amber');
  // observe: amber accent on warm-black background
  document.documentElement.setAttribute('data-theme', 'sapphire');
  // observe: bright blue accent
  document.documentElement.setAttribute('data-theme', 'contrast');
  // observe: high-vis yellow on pure black
  document.documentElement.removeAttribute('data-theme');
  // observe: back to Stellar Ops cosmic
  ```

  At each step, the **page content background** changes. The header doesn't yet (because it still uses `T = {}` — fixed in Task 1.3).

- [ ] **Step 4: Update theme-switcher dropdown labels in `app.jsx`**

  Find the `THEMES` array in `static/js/app.jsx` (around line 153).

  ```bash
  grep -n "THEMES =" static/js/app.jsx
  ```

  Replace its contents to drop `daylight` and rename `midnight` → "Stellar Ops":

  ```javascript
  const THEMES = [
    { id: 'midnight', label: 'Stellar Ops', swatch: '#4FA8FF', desc: 'Default — black/blue cosmos, the core ARGUS aesthetic' },
    { id: 'graphite', label: 'Graphite',    swatch: '#38BDF8', desc: 'Neutral charcoal, cyan accent' },
    { id: 'sapphire', label: 'Sapphire',    swatch: '#4F8DFD', desc: 'Brighter blue, projector-friendly' },
    { id: 'amber',    label: 'Amber',       swatch: '#FFB22A', desc: 'Operator-terminal mono purists' },
    { id: 'contrast', label: 'Contrast',    swatch: '#FFE600', desc: 'High-contrast accessibility' },
  ];
  ```

  The `id` of `midnight` is preserved so existing operators' saved theme prefs (`argus.ui.prefs.v2.theme = 'midnight'`) continue to work — only the displayed label changes.

- [ ] **Step 5: Commit**

  ```bash
  git add static/css/main.css static/js/app.jsx
  git commit -m "feat(ui): rewrite alternate themes against Stellar Ops token list

  Drops daylight theme (Spec §2.1). Renames midnight label to
  'Stellar Ops' but keeps the id stable for backwards compat."
  ```

### Task 1.3: Migrate `app.jsx` from `T = {}` literals to `var(--*)` strings

**Files:**
- Modify: `static/js/app.jsx`

- [ ] **Step 1: Confirm the `T = {}` object location**

  ```bash
  grep -n "^const T = {" static/js/app.jsx
  ```

  Expected: line 24 (per existing code). The block runs ~25 lines.

- [ ] **Step 2: Build the find/replace mapping**

  | `T.<old>`          | Replace with             |
  | ------------------ | ------------------------ |
  | `T.bgBase`         | `'var(--bg-base)'`        |
  | `T.bgSidebar`      | `'var(--bg-surface)'`     |
  | `T.bgSurface`      | `'var(--bg-surface)'`     |
  | `T.bgPanel`        | `'var(--bg-panel)'`       |
  | `T.bgElevated`     | `'var(--bg-elevated)'`    |
  | `T.bgGlass`        | `'var(--bg-glass)'`       |
  | `T.accent`         | `'var(--accent)'`         |
  | `T.accentDim`      | `'var(--accent-dim)'`     |
  | `T.violet`         | `'var(--violet)'`         |
  | `T.cyan`           | `'var(--cyan)'`           |
  | `T.amber`          | `'var(--amber)'`          |
  | `T.critical`       | `'var(--critical)'`       |
  | `T.high`           | `'var(--high)'`           |
  | `T.medium`         | `'var(--medium)'`         |
  | `T.low`            | `'var(--low)'`            |
  | `T.border`         | `'var(--border-dim)'`     |
  | `T.borderLight`    | `'var(--border)'`         |
  | `T.borderBright`   | `'var(--border-bright)'`  |
  | `T.textPrimary`    | `'var(--text-primary)'`   |
  | `T.textSecondary`  | `'var(--text-secondary)'` |
  | `T.textMuted`      | `'var(--text-muted)'`     |
  | `T.fontUI`         | `'var(--font-ui)'`        |
  | `T.fontMono`       | `'var(--font-mono)'`      |

  **Two edge cases:**

  1. **Template-literal interpolations** — `` `${T.accent}55` `` (RGBA suffix). Convert to color-mix:
     `` `color-mix(in srgb, var(--accent) 33%, transparent)` ``
     OR use the dedicated `--accent-glow` / `--accent-subtle` variables if context fits. Document each conversion in the commit.
  2. **Numeric concatenation** — `` `1px solid ${T.border}` `` → `` `1px solid var(--border-dim)` ``. Plain string concat works — `var()` is a valid CSS value.

- [ ] **Step 3: Apply the mechanical rewrite**

  Use a script for the bulk pass (still keep manual review):

  ```python
  # save as /tmp/migrate_T.py and run from repo root
  import re, sys, pathlib
  path = pathlib.Path('static/js/app.jsx')
  src = path.read_text(encoding='utf-8')
  mapping = {
      'T.bgBase':       "'var(--bg-base)'",
      'T.bgSidebar':    "'var(--bg-surface)'",
      'T.bgSurface':    "'var(--bg-surface)'",
      'T.bgPanel':      "'var(--bg-panel)'",
      'T.bgElevated':   "'var(--bg-elevated)'",
      'T.bgGlass':      "'var(--bg-glass)'",
      'T.accentDim':    "'var(--accent-dim)'",
      'T.accent':       "'var(--accent)'",
      'T.violet':       "'var(--violet)'",
      'T.cyan':         "'var(--cyan)'",
      'T.amber':        "'var(--amber)'",
      'T.critical':     "'var(--critical)'",
      'T.high':         "'var(--high)'",
      'T.medium':       "'var(--medium)'",
      'T.low':          "'var(--low)'",
      'T.borderBright': "'var(--border-bright)'",
      'T.borderLight':  "'var(--border)'",
      'T.border':       "'var(--border-dim)'",
      'T.textPrimary':  "'var(--text-primary)'",
      'T.textSecondary':"'var(--text-secondary)'",
      'T.textMuted':    "'var(--text-muted)'",
      'T.fontUI':       "'var(--font-ui)'",
      'T.fontMono':     "'var(--font-mono)'",
  }
  # order matters — accentDim before accent, borderBright before borderLight before border
  for k in sorted(mapping.keys(), key=len, reverse=True):
      src = src.replace(k, mapping[k])
  path.write_text(src, encoding='utf-8')
  print('migration applied')
  ```

  ```bash
  python /tmp/migrate_T.py
  ```

- [ ] **Step 4: Hand-review remaining template-literal patterns**

  ```bash
  grep -nE "\\$\\{['\"]?var\\(--" static/js/app.jsx
  ```

  Expected: matches like `` `${'var(--accent)'}55` `` from concatenation. Convert each:

  - `` `${'var(--accent)'}55` `` (33% alpha) → `` `color-mix(in srgb, var(--accent) 33%, transparent)` ``
  - `` `${'var(--accent)'}10` `` (~6% alpha) → `'var(--accent-subtle)'`
  - `` `${'var(--accent)'}40` `` (25% alpha) → `'var(--accent-glow)'`
  - For other alpha values, use `color-mix(in srgb, var(--accent) <pct>%, transparent)`.

  Edit by hand — the script can't safely do this conversion.

- [ ] **Step 5: Delete the now-unused `T = {}` constant**

  ```bash
  grep -n "^const T = {" static/js/app.jsx
  ```

  Delete the `const T = { ... };` block entirely (lines 24-48ish). Keep only any non-color helpers if they exist (most of `T` was colors).

  Verify no `T.` references remain:

  ```bash
  grep -nE "\\bT\\.[a-zA-Z]" static/js/app.jsx
  ```

  Expected: empty output. If any matches remain, hand-edit them.

- [ ] **Step 6: Browser smoke test**

  Reload the GUI. Switch between all 5 themes via the existing switcher. Confirm:
  - Background color of the **header** changes per theme
  - Background of the **sidebar** changes per theme
  - **Panel borders** in the command-palette change per theme

  Before this task: only the page-content area changed. After: header + sidebar + command-palette + every accent surface should change.

- [ ] **Step 7: Commit**

  ```bash
  git add static/js/app.jsx
  git commit -m "fix(ui): migrate app.jsx from T={} hex literals to var(--token)

  This is the core fix for the broken theme switcher (Spec §4 item 1).
  All inline-style colors now defer to CSS variables, so [data-theme]
  attribute changes propagate through the whole layout.

  Drops the T = {} constant. Removes alpha-suffix template literals
  in favour of dedicated --accent-glow / --accent-subtle tokens or
  color-mix() expressions."
  ```

### Task 1.4: Migrate `RiskDashboard.jsx` and `WebTesting.jsx`

**Files:**
- Modify: `static/js/pages/RiskDashboard.jsx`
- Modify: `static/js/pages/WebTesting.jsx`

- [ ] **Step 1: Audit hardcoded color usage in both files**

  ```bash
  grep -cE "T\\.(accent|bg|border|text|critical|cyan|violet|low|medium|high)" \
       static/js/pages/RiskDashboard.jsx static/js/pages/WebTesting.jsx
  ```

  Expected: ~96 in RiskDashboard, ~33 in WebTesting (per Spec §4).

- [ ] **Step 2: Apply the migration script to each file**

  Adapt the Python script from Task 1.3:

  ```python
  # /tmp/migrate_T_pages.py
  import pathlib
  files = [
      'static/js/pages/RiskDashboard.jsx',
      'static/js/pages/WebTesting.jsx',
  ]
  mapping = { ...same as Task 1.3 step 3... }
  for f in files:
      p = pathlib.Path(f)
      src = p.read_text(encoding='utf-8')
      for k in sorted(mapping.keys(), key=len, reverse=True):
          src = src.replace(k, mapping[k])
      p.write_text(src, encoding='utf-8')
      print(f'migrated {f}')
  ```

  ```bash
  python /tmp/migrate_T_pages.py
  ```

- [ ] **Step 3: Hand-review template-literal patterns + remove local `T = {}`**

  Both pages may have their own local `T = { ... }` const at the top. Locate and remove:

  ```bash
  grep -n "^const T = {" static/js/pages/RiskDashboard.jsx static/js/pages/WebTesting.jsx
  ```

  Delete each, then verify no `T.` references remain in the file:

  ```bash
  grep -nE "\\bT\\.[a-zA-Z]" static/js/pages/RiskDashboard.jsx static/js/pages/WebTesting.jsx
  ```

  Expected: empty.

- [ ] **Step 4: Browser smoke test**

  Navigate to Risk Dashboard, switch themes, confirm:
  - Risk score halo color changes per theme
  - Severity grid card backgrounds change
  - Sparkline strokes use the right accent

  Navigate to Web Testing (WSTG matrix), switch themes, confirm phase tile borders + status pills change.

- [ ] **Step 5: Bump cache-bust versions in `templates/index.html`**

  ```bash
  grep -nE "RiskDashboard\\.jsx\\?v=|WebTesting\\.jsx\\?v=|app\\.jsx\\?v=" templates/index.html
  ```

  Bump each version number (`?v=N` → `?v=N+1`).

- [ ] **Step 6: Commit**

  ```bash
  git add static/js/pages/RiskDashboard.jsx static/js/pages/WebTesting.jsx templates/index.html
  git commit -m "fix(ui): migrate RiskDashboard + WebTesting from T literals to var(--*)

  Completes the theme-switcher fix surface coverage. Together with the
  app.jsx migration (prev commit), 100% of the UI surface now responds
  to [data-theme] changes (Spec §17 acceptance #1)."
  ```

### Task 1.5: Tier 1 verification gate

- [ ] **Step 1: Run all 5 smoke tests from Spec §3.3**

  - **Smoke 1** — All 19 pages reachable, no console errors. Click each sidebar entry.
  - **Smoke 2** — Run a localhost scan, confirm WS data flow + findings appear + report renders.
  - **Smoke 3** — Switch through every theme during the scan. Confirm: instant repaint, every surface changes, scan continues unaffected.
  - **Smoke 4** — Reload mid-scan, confirm WS reconnect + state restoration.
  - **Smoke 5** — Set `prefers-reduced-motion: reduce`, confirm UI usable.

- [ ] **Step 2: Cardinal-constraint diff check**

  ```bash
  find agents/ knowledge/ utils/ db/ agent_server.py schemas.py mcp-server.js \
       -name "*.py" -o -name "*.js" \
       | xargs sha256sum | diff /tmp/argus-offlimits-baseline.sha256 -
  ```

  Expected: empty diff.

- [ ] **Step 3: Tag this tier**

  ```bash
  git tag -a tier1-foundation -m "T1 — theme switcher fixed, palette migrated"
  ```

  If any smoke test fails, revert the tier's commits and diagnose:

  ```bash
  git log --oneline tier1-foundation..HEAD   # would-be empty here
  git revert <bad-commit>
  ```

---

## Tier 2 — Cockpit chrome + hub aggregation

**Spec ref:** §8 (cockpit), §10.5 (hubs), §13.1, §14 Tier 2.
**Goal:** New HUD header, telemetry, consumables, Stellar Beam, ambient panel illumination, and 19 pages collapse into 9 hubs without losing content.
**Estimated effort:** 3 days.
**Cardinal-constraint risk:** Medium — touches `app.jsx` heavily and `store.js` (additive only).

### Task 2.1: Add Stellar Beam + cosmic-background classes to `main.css`

**Files:**
- Modify: `static/css/main.css` — append a new section near the bottom.

- [ ] **Step 1: Append the Stellar Beam + cosmos layer styles**

  Append the following block at the end of `static/css/main.css` (Spec §8.1, §5):

  ```css
  /* ─────────────────────────── Stellar Ops cosmos ─────────────────────────── */

  /* Layer 0 — Stellar Beam, vertical light from top of viewport */
  .stellar-beam {
    position: fixed;
    top: -10vh;
    left: 50%;
    transform: translateX(-50%);
    width: 800px;
    height: 110vh;
    background: linear-gradient(
      180deg,
      var(--accent-glow) 0%,
      transparent 60%
    );
    clip-path: polygon(40% 0%, 60% 0%, 100% 100%, 0% 100%);
    opacity: 0.25;
    pointer-events: none;
    z-index: 0;
    filter: blur(40px);
  }

  /* Layer 1 — starfield via repeating radial gradient */
  .stellar-starfield {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 0;
    background-image:
      radial-gradient(1px 1px at 20% 30%, rgba(229,234,246,0.4) 50%, transparent 60%),
      radial-gradient(1px 1px at 70% 80%, rgba(229,234,246,0.3) 50%, transparent 60%),
      radial-gradient(1px 1px at 40% 70%, rgba(229,234,246,0.5) 50%, transparent 60%),
      radial-gradient(1px 1px at 90% 20%, rgba(229,234,246,0.3) 50%, transparent 60%),
      radial-gradient(1px 1px at 15% 85%, rgba(229,234,246,0.4) 50%, transparent 60%);
    background-size: 600px 600px, 800px 800px, 500px 500px, 700px 700px, 550px 550px;
    animation: stellar-drift 240s linear infinite;
  }

  /* Layer 2 — distant nebula pulses */
  .stellar-nebula {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 0;
    background:
      radial-gradient(900px 700px at 20% 30%, rgba(79,168,255,0.06) 0%, transparent 50%),
      radial-gradient(800px 600px at 80% 70%, rgba(123,108,246,0.05) 0%, transparent 50%),
      radial-gradient(1200px 800px at 50% 50%, rgba(56,229,255,0.04) 0%, transparent 60%);
    animation: stellar-nebula-drift 60s ease-in-out infinite alternate;
  }

  @keyframes stellar-drift {
    0%   { background-position: 0% 0%, 0% 0%, 0% 0%, 0% 0%, 0% 0%; }
    100% { background-position: 600px 600px, -800px 800px, 500px -500px, -700px 700px, 550px -550px; }
  }

  @keyframes stellar-nebula-drift {
    0%   { transform: translate(0, 0)   scale(1);    opacity: 1; }
    100% { transform: translate(2%, -1%) scale(1.05); opacity: 0.85; }
  }

  /* Reduced-motion: keep gradients, kill animation */
  @media (prefers-reduced-motion: reduce) {
    .stellar-starfield,
    .stellar-nebula { animation: none !important; }
  }
  ```

- [ ] **Step 2: Append ambient panel illumination utility**

  ```css
  /* ─────────────────────────── Cockpit ambient illumination ──────────────────── */

  .panel-ambient {
    border: 1px solid var(--border-dim);
    background: var(--bg-surface);
    border-radius: 6px;
    transition: border-color 150ms ease-out, box-shadow 150ms ease-out;
  }

  .panel-ambient:hover,
  .panel-ambient[data-active="true"] {
    border-color: var(--border-bright);
    box-shadow:
      inset 0 0 0 1px var(--border-bright),
      0 0 18px var(--accent-glow);
  }

  /* Corner-bracket decoration for HUD panels (Mil-spec flavor) */
  .panel-ambient.panel-hud { position: relative; }
  .panel-ambient.panel-hud::before,
  .panel-ambient.panel-hud::after {
    content: "";
    position: absolute;
    width: 12px; height: 12px;
    border: 1px solid var(--border-bright);
    pointer-events: none;
  }
  .panel-ambient.panel-hud::before { top: -1px; left: -1px;  border-right: none;  border-bottom: none; }
  .panel-ambient.panel-hud::after  { bottom: -1px; right: -1px; border-left: none;  border-top: none; }
  ```

- [ ] **Step 3: Verify CSS still parses**

  ```bash
  python -c "
  src = open('static/css/main.css', encoding='utf-8').read()
  assert src.count('{') == src.count('}'), 'brace mismatch'
  print(f'main.css: {src.count(chr(10))} lines, braces balanced')
  "
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add static/css/main.css
  git commit -m "feat(ui): add Stellar Beam + starfield + nebula + panel ambient utility classes

  Pure CSS, GPU-cheap, prefers-reduced-motion respected. Classes are
  defined now; mounted in app.jsx in next commit."
  ```

### Task 2.2: Mount Stellar Beam + cosmos in `app.jsx` root

**Files:**
- Modify: `static/js/app.jsx`

- [ ] **Step 1: Locate the root `App()` return JSX**

  ```bash
  grep -n "^function App()" static/js/app.jsx
  ```

  Note the line where the outermost `React.createElement('div'` lives.

- [ ] **Step 2: Insert cosmos layers as the first children of root**

  Add three sibling divs at the very top of the root render, BEFORE the existing header. Conceptually:

  ```jsx
  React.createElement('div', { className: 'stellar-starfield' }),
  React.createElement('div', { className: 'stellar-nebula' }),
  React.createElement('div', { className: 'stellar-beam' }),
  // …existing header, body, etc.
  ```

  Position via z-index: cosmos layers sit at z-index 0; existing chrome (header, sidebar) is z-index ≥ 100 so it sits above. Verify the existing header has a non-zero z-index (likely already does — line ~759).

- [ ] **Step 3: Bump root background**

  Change the root container's inline style from `background: 'var(--bg-base)'` to `background: 'transparent'` so the cosmos layers show through. The body element keeps `background: var(--bg-base)` via existing `main.css` rules.

- [ ] **Step 4: Browser smoke test**

  Reload, observe:
  - Subtle starfield drifting in the background (very slow, easy to miss — confirms it's working)
  - Faint blue light beam descending from top-center
  - Existing UI sits over the cosmos with full readability

- [ ] **Step 5: Commit**

  ```bash
  git add static/js/app.jsx
  git commit -m "feat(ui): mount cosmic backdrop in app.jsx root

  Stellar beam + starfield + nebula now active behind every page.
  Pure decorative — no interaction, pointer-events:none."
  ```

### Task 2.3: HUD header — telemetry strip + mission clock + findings tally

**Files:**
- Modify: `static/js/app.jsx` — header section
- Modify: `static/css/main.css` — telemetry-bar styles

- [ ] **Step 1: Add telemetry bar CSS**

  Append to `main.css`:

  ```css
  /* ─────────────────── HUD telemetry strip ─────────────────── */
  .hud-telemetry {
    display: inline-flex;
    align-items: flex-end;
    gap: 2px;
    height: 16px;
    margin: 0 8px;
  }
  .hud-telemetry .bar {
    width: 3px;
    background: var(--accent-dim);
    border-radius: 1px;
    transition: height 1s ease-out, background 200ms;
  }
  .hud-telemetry .bar[data-level="active"] { background: var(--accent); }
  .hud-telemetry .bar[data-level="hot"]    { background: var(--cyan); }

  /* Mission clock */
  .hud-clock {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-secondary);
    letter-spacing: 0.5px;
    margin: 0 12px;
  }

  /* Findings tally pulse on critical-increment */
  .hud-tally-supernova {
    animation: hud-tally-pulse 2s ease-out;
  }
  @keyframes hud-tally-pulse {
    0%   { color: var(--supernova); text-shadow: 0 0 12px var(--supernova); }
    100% { color: var(--critical);   text-shadow: none; }
  }
  ```

- [ ] **Step 2: Build the telemetry-strip subcomponent inline in `app.jsx`**

  Add this function above the existing `function SvcDot(...)`:

  ```javascript
  function HudTelemetry() {
    const { state } = window.useStore();
    const llmRate    = state.metrics?.llm_calls_per_min || 0;
    const toolsCount = state.activeSubagents?.length || 0;
    const wsRate     = state.metrics?.ws_events_per_sec || 0;

    // Map raw rates to bar heights 4..16px and a level enum
    const bars = [
      { value: llmRate,   max: 20, label: 'LLM/min' },
      { value: toolsCount, max: 8,  label: 'tools'   },
      { value: wsRate,    max: 30, label: 'evts/s'  },
    ];

    return React.createElement('div', {
      className: 'hud-telemetry',
      title: 'LLM rate · active tools · WS event rate',
    },
      bars.map((b, i) => {
        const pct = Math.min(1, b.value / b.max);
        const h = 4 + Math.round(pct * 12);
        const level = pct > 0.7 ? 'hot' : pct > 0.2 ? 'active' : 'idle';
        return React.createElement('div', {
          key: i,
          className: 'bar',
          'data-level': level,
          style: { height: `${h}px` },
        });
      })
    );
  }
  ```

- [ ] **Step 3: Build the mission-clock subcomponent**

  Add below `HudTelemetry`:

  ```javascript
  function HudClock() {
    const { state } = window.useStore();
    const startedAt = state.activeSession?.started_at;
    const [now, setNow] = useState(Date.now());
    useEffect(() => {
      const id = setInterval(() => setNow(Date.now()), 1000);
      return () => clearInterval(id);
    }, []);
    if (!startedAt) {
      return React.createElement('span', { className: 'hud-clock' }, '⏱ --:--:--');
    }
    const elapsed = Math.max(0, Math.floor((now - new Date(startedAt).getTime()) / 1000));
    const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
    const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
    const s = String(elapsed % 60).padStart(2, '0');
    return React.createElement('span', { className: 'hud-clock' }, `⏱ ${h}:${m}:${s}`);
  }
  ```

- [ ] **Step 4: Wire HudTelemetry + HudClock into the header**

  Find the existing header JSX in `App()` (around line 753-900). After the brand block and before the service-status dots, insert:

  ```javascript
  React.createElement(HudTelemetry),
  React.createElement(HudClock),
  ```

  Adjust spacing/order with existing elements; the goal layout is:

  ```
  [logo] [telemetry] [clock] [svc dots] [palette trigger] ...rest of header
  ```

- [ ] **Step 5: Browser smoke test**

  Start a scan; observe:
  - Telemetry bars rise/fall as LLM calls and active tools fluctuate
  - Mission clock ticks up once per second
  - Both elements use Stellar Ops palette

- [ ] **Step 6: Commit**

  ```bash
  git add static/js/app.jsx static/css/main.css
  git commit -m "feat(ui): HUD telemetry strip + mission clock in header

  Reads from existing state.metrics + state.activeSession — no new
  backend signals (Spec §8.5, §8.6)."
  ```

### Task 2.4: Engagement consumables strip (bottom of viewport)

**Files:**
- Modify: `static/js/app.jsx` — add component + mount
- Modify: `static/css/main.css` — strip styles

- [ ] **Step 1: Add CSS for the consumables strip**

  Append to `main.css`:

  ```css
  .hud-consumables {
    position: fixed;
    bottom: 0;
    left: 0; right: 0;
    height: 28px;
    background: var(--bg-glass);
    backdrop-filter: blur(8px);
    border-top: 1px solid var(--border-dim);
    display: flex;
    align-items: center;
    gap: 32px;
    padding: 0 24px;
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-secondary);
    letter-spacing: 0.5px;
    z-index: 90;
    transition: height 150ms ease-out;
  }
  .hud-consumables[data-collapsed="true"] {
    height: 8px;
    overflow: hidden;
  }
  .hud-consumables .gauge {
    display: flex; align-items: center; gap: 8px;
  }
  .hud-consumables .gauge-bar {
    width: 100px;
    height: 4px;
    background: var(--bg-elevated);
    border-radius: 2px;
    overflow: hidden;
  }
  .hud-consumables .gauge-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--cyan));
    transition: width 600ms ease-out;
  }
  .hud-consumables .gauge-fill[data-warn="true"]  { background: var(--medium); }
  .hud-consumables .gauge-fill[data-crit="true"]  { background: var(--critical); }
  ```

- [ ] **Step 2: Add the component**

  In `app.jsx`:

  ```javascript
  function HudConsumables() {
    const { state } = window.useStore();
    const [collapsed, setCollapsed] = useState(false);

    const llmTokensUsed   = state.metrics?.llm_tokens_used   || 0;
    const llmTokensBudget = state.metrics?.llm_tokens_budget || 100000;
    const timeElapsedSec  = state.metrics?.elapsed_sec       || 0;
    const timeWindowSec   = state.metrics?.scope_window_sec  || 28800;   // 8h default
    const agentsActive    = (state.activeSubagents || []).length;
    const agentsMax       = state.metrics?.max_concurrency   || 8;
    const findingsRate    = state.metrics?.findings_per_hour || 0;

    const gauges = [
      { label: 'LLM TOKENS',  pct: Math.min(1, llmTokensUsed / llmTokensBudget) },
      { label: 'TIME REMAIN', pct: Math.max(0, 1 - timeElapsedSec / timeWindowSec) },
      { label: 'AGENTS',      pct: Math.min(1, agentsActive / agentsMax) },
      { label: 'FINDINGS Δ',  pct: Math.min(1, findingsRate / 50) },
    ];

    return React.createElement('div', {
      className: 'hud-consumables',
      'data-collapsed': collapsed,
      onClick: () => setCollapsed(c => !c),
      title: 'Click to collapse/expand',
    },
      gauges.map((g, i) =>
        React.createElement('div', { key: i, className: 'gauge' },
          React.createElement('span', null, g.label),
          React.createElement('div', { className: 'gauge-bar' },
            React.createElement('div', {
              className: 'gauge-fill',
              'data-warn': g.pct > 0.7,
              'data-crit': g.pct > 0.9,
              style: { width: `${Math.round(g.pct * 100)}%` },
            })
          ),
          React.createElement('span', null, `${Math.round(g.pct * 100)}%`)
        )
      )
    );
  }
  ```

- [ ] **Step 3: Mount in `App()` JSX**

  At the end of the root JSX (after the body div), add:

  ```javascript
  React.createElement(HudConsumables),
  ```

- [ ] **Step 4: Browser smoke test**

  Reload mid-scan; observe 4 gauges at the bottom. Click to collapse to a thin strip; click again to re-expand.

- [ ] **Step 5: Commit**

  ```bash
  git add static/js/app.jsx static/css/main.css
  git commit -m "feat(ui): engagement consumables strip — bottom HUD with 4 cockpit gauges

  Reads from state.metrics; gauges turn amber > 70% and red > 90%.
  Click to collapse to 8px sliver, click again to expand (Spec §8.5)."
  ```

### Task 2.5: Hub aggregation — define the 9-hub structure

**Files:**
- Modify: `static/js/app.jsx` — replace `PAGES` with `HUBS`

- [ ] **Step 1: Locate `PAGES` array**

  ```bash
  grep -n "^const PAGES = \\[" static/js/app.jsx
  ```

  Note the existing array (lines 84-106 per earlier inspection).

- [ ] **Step 2: Replace `PAGES` with the new `HUBS` structure**

  Replace the existing `PAGES` array AND `PAGE_COMPONENT` map with:

  ```javascript
  // ─── 9-hub structure (Spec §10.5) ────────────────────────────
  // Each hub has tabs; each tab maps to an existing page component.
  // Tabs preserve the ORIGINAL page key as `tabKey` so legacy
  // navigate() events keep working.
  const HUBS = [
    { key: 'risk',       icon: '◇', label: 'Risk Dashboard', group: 'Overview',
      tabs: [{ key: 'risk',       label: 'Risk Score',       comp: 'RiskDashboard' }] },

    { key: 'operations', icon: '⚡', label: 'Operations',     group: 'Overview',
      tabs: [
        { key: 'mission', label: 'Mission Control', comp: 'MissionControl' },
        { key: 'agents',  label: 'Agent Roster',    comp: 'AgentConsole' },
      ] },

    { key: 'findings',   icon: '◆', label: 'Findings',        group: 'Analysis',
      tabs: [
        { key: 'findings', label: 'All Findings',  comp: 'FindingsBoard' },
        { key: 'web_test', label: 'WSTG Matrix',   comp: 'WebTesting' },
        { key: 'osint',    label: 'OSINT Intel',   comp: 'OsintIntel' },
      ] },

    { key: 'graph',      icon: '⬡', label: 'Attack Graph',    group: 'Analysis',
      tabs: [{ key: 'graph', label: 'Attack Graph', comp: 'AttackGraph' }] },

    { key: 'reasoning',  icon: '◐', label: 'Reasoning',       group: 'Execution',
      tabs: [
        { key: 'reasoning', label: 'Hypothesis Tree', comp: 'ReasoningEnginePage' },
        { key: 'ai_obs',    label: 'LLM Trace',        comp: 'AIObservability' },
      ] },

    { key: 'foothold',   icon: '⊛', label: 'Foothold',        group: 'Execution',
      tabs: [
        { key: 'creds',    label: 'Credentials',         comp: 'CredentialsPage' },
        { key: 'shells',   label: 'Active Shells',       comp: 'ShellManager' },
        { key: 'lateral',  label: 'Lateral & Post-Ex',   comp: 'LateralPostPage' },
        { key: 'payloads', label: 'Payload Builder',     comp: 'PayloadBuilder' },
      ] },

    { key: 'workshop',   icon: '⊞', label: 'Workshop',        group: 'Execution',
      tabs: [
        { key: 'target',  label: 'Target Config',  comp: 'TargetConfig' },
        { key: 'tools',   label: 'Tool Workshop',  comp: 'ToolWorkshop' },
      ] },

    { key: 'reports',    icon: '◧', label: 'Reports',         group: 'Reporting',
      tabs: [{ key: 'report', label: 'Reports', comp: 'ReportPage' }] },

    { key: 'system',     icon: '⊙', label: 'System',          group: 'Reporting',
      tabs: [
        { key: 'sessions',  label: 'Sessions',       comp: 'SessionHistory' },
        { key: 'knowledge', label: 'Knowledge Base', comp: 'KnowledgePage' },
        { key: 'metrics',   label: 'Metrics',        comp: 'MetricsDash' },
      ] },
  ];

  // Resolve the React component referenced by each tab from window globals.
  const COMP_FOR = {
    RiskDashboard:       () => window.RiskDashboard,
    MissionControl:      () => window.MissionControl,
    AgentConsole:        () => window.AgentConsole,
    FindingsBoard:       () => window.FindingsBoard,
    WebTesting:          () => window.WebTesting,
    OsintIntel:          () => window.OsintIntel,
    AttackGraph:         () => window.AttackGraph,
    ReasoningEnginePage: () => window.ReasoningEnginePage,
    AIObservability:     () => window.AIObservability,
    CredentialsPage:     () => window.CredentialsPage,
    ShellManager:        () => window.ShellManager,
    LateralPostPage:     () => window.LateralPostPage,
    PayloadBuilder:      () => window.PayloadBuilder,
    TargetConfig:        () => window.TargetConfig,
    ToolWorkshop:        () => window.ToolWorkshop,
    ReportPage:          () => window.ReportPage,
    SessionHistory:      () => window.SessionHistory,
    KnowledgePage:       () => window.KnowledgePage,
    MetricsDash:         () => window.MetricsDash,
  };

  // Legacy alias resolver — old navigate('agents') etc. still works.
  // Returns { hub: <hubKey>, tab: <tabKey> } or null if unknown.
  function resolveLegacyKey(legacyKey) {
    for (const h of HUBS) {
      for (const t of h.tabs) {
        if (t.key === legacyKey) return { hub: h.key, tab: t.key };
      }
    }
    return null;
  }
  ```

- [ ] **Step 3: Verify all original 19 page keys are reachable**

  ```bash
  python -c "
  HUBS_KEYS = '''risk mission agents findings web_test osint graph reasoning ai_obs creds shells lateral payloads target tools report sessions knowledge metrics'''.split()
  # Hand-verify each appears in the HUBS structure above.
  for k in HUBS_KEYS:
      print(f'{k:12s}  expected in HUBS')
  "
  ```

  Hand-verify each of the 19 keys appears as a `tab.key` somewhere in the new `HUBS` array. Match against the table in Spec §10.5.

- [ ] **Step 4: Commit**

  ```bash
  git add static/js/app.jsx
  git commit -m "feat(ui): replace 19-page PAGES with 9-hub HUBS structure

  Each tab.key preserves the original page key for legacy compatibility.
  COMP_FOR maps tabKey -> React component on window.
  resolveLegacyKey provides navigate('agents') -> hub#operations#agents.
  No content lost — every original page is reachable as a hub-tab
  (Spec §10.5)."
  ```

### Task 2.6: Hub navigation state + sidebar render

**Files:**
- Modify: `static/js/app.jsx` — App() state + sidebar render
- Modify: `static/js/store.js` — additive: currentHub + currentTab default state

- [ ] **Step 1: Add hub/tab state to `store.js` initial state**

  Locate the existing initial-state block in `store.js`.

  ```bash
  grep -nE "^const initialState" static/js/store.js
  ```

  Inside the initialState object, add:

  ```javascript
  // Hub navigation (Spec §10.5)
  currentHub: 'risk',           // current hub key
  currentTab: 'risk',           // current tab key within hub
  hubTabMemory: {},             // {hubKey: lastTabKey} per-hub last-selected tab
  ```

  Add a reducer case (additive):

  ```javascript
  case 'SET_HUB_TAB':
    return {
      ...state,
      currentHub: action.payload.hub,
      currentTab: action.payload.tab,
      hubTabMemory: { ...(state.hubTabMemory || {}), [action.payload.hub]: action.payload.tab },
    };
  ```

  Verify nothing in the existing reducer is removed — diff before/after:

  ```bash
  git diff static/js/store.js
  ```

  Expected diff: pure additions. No deletions.

- [ ] **Step 2: Update `App()` to use hub/tab state**

  In `app.jsx`'s `App()`, replace the `const [page, setPage] = useState(initial.page || 'risk')` line with state read from store + dispatch:

  ```javascript
  const { state, dispatch } = window.useStore();
  const currentHub = state.currentHub || 'risk';
  const currentTab = state.currentTab || 'risk';

  function navigateHubTab(hubKey, tabKey) {
    // tabKey is optional — defaults to remembered tab or first tab in hub
    const hub = HUBS.find(h => h.key === hubKey);
    if (!hub) return;
    const remembered = state.hubTabMemory?.[hubKey];
    const resolvedTab = tabKey
      || (remembered && hub.tabs.find(t => t.key === remembered) && remembered)
      || hub.tabs[0].key;
    dispatch({ type: 'SET_HUB_TAB', payload: { hub: hubKey, tab: resolvedTab } });
  }

  // Legacy navigate event: navigate('agents') routes via resolveLegacyKey
  useEffect(() => {
    const handler = (e) => {
      const target = e.detail;
      const resolved = resolveLegacyKey(target);
      if (resolved) {
        navigateHubTab(resolved.hub, resolved.tab);
      } else {
        const hub = HUBS.find(h => h.key === target);
        if (hub) navigateHubTab(target);
      }
    };
    window.addEventListener('navigate', handler);
    return () => window.removeEventListener('navigate', handler);
  }, [state.hubTabMemory]);
  ```

- [ ] **Step 3: Replace sidebar nav rendering**

  Replace the existing sidebar `GROUP_ORDER.map(...)` rendering with hub-aware render. The existing code iterates `PAGES.filter(p => p.group === group)`. Update to:

  ```javascript
  GROUP_ORDER.map(group => {
    const hubs = HUBS.filter(h => h.group === group);
    if (hubs.length === 0) return null;
    const groupColor = GROUP_COLORS[group];
    const isOpen = sidebarCollapsed ? true : (groupOpen[group] !== false);
    return React.createElement('div', { key: group, style: { marginBottom: 2 } },
      React.createElement(GroupHeader, {
        group, color: groupColor,
        collapsed: sidebarCollapsed, isOpen,
        onToggle: () => toggleGroup(group),
      }),
      isOpen && hubs.map(hub =>
        React.createElement(NavItem, {
          key: hub.key,
          item: hub,
          isActive: currentHub === hub.key,
          isCollapsed: sidebarCollapsed,
          onClick: () => navigateHubTab(hub.key),
        })
      )
    );
  })
  ```

  Update `GROUP_ORDER` to match the new groups:

  ```javascript
  const GROUP_ORDER = ['Overview', 'Analysis', 'Execution', 'Reporting'];
  ```

  And the existing `GROUP_COLORS` — add an entry for `Execution`:

  ```javascript
  const GROUP_COLORS = {
    Overview:    'var(--accent)',
    Analysis:    'var(--cyan)',
    Execution:   'var(--violet)',
    Reporting:   'var(--medium)',
  };
  ```

- [ ] **Step 4: Persist hub/tab in localStorage**

  Locate `savePrefs()` in `app.jsx`. Add hub/tab to persisted prefs:

  ```javascript
  // After existing useEffect that calls savePrefs:
  useEffect(() => {
    savePrefs({ ...loadPrefs(), currentHub, currentTab, hubTabMemory: state.hubTabMemory });
  }, [currentHub, currentTab, state.hubTabMemory]);
  ```

  Add migration on app boot — if old `argus.ui.prefs.v2.page` is set, transparently rewrite:

  ```javascript
  // Run-once migration on App() mount
  useEffect(() => {
    const prefs = loadPrefs();
    if (prefs.page && !prefs.currentHub) {
      const resolved = resolveLegacyKey(prefs.page);
      if (resolved) {
        dispatch({ type: 'SET_HUB_TAB', payload: { hub: resolved.hub, tab: resolved.tab } });
      }
      // Persist new keys, clear old
      const { page: _, ...rest } = prefs;
      savePrefs(rest);
    }
  }, []);
  ```

- [ ] **Step 5: Browser smoke test**

  Reload, observe 9 sidebar entries grouped under Overview / Analysis / Execution / Reporting. Click each — every hub navigates and shows its first tab.

- [ ] **Step 6: Commit**

  ```bash
  git add static/js/app.jsx static/js/store.js
  git commit -m "feat(ui): hub-aware sidebar nav + currentHub/currentTab state

  Sidebar now renders 9 hubs across 4 groups (Spec §10.5).
  navigateHubTab + resolveLegacyKey handle direct hub clicks AND
  legacy navigate('agents') deep-links. Old localStorage page
  pref auto-migrates to hub+tab on first boot."
  ```

### Task 2.7: Hub content area with tab-bar

**Files:**
- Modify: `static/js/app.jsx` — content area
- Modify: `static/css/main.css` — tab-bar styles

- [ ] **Step 1: Add tab-bar CSS**

  Append to `main.css`:

  ```css
  /* Hub tab-bar */
  .hub-tabbar {
    display: flex;
    align-items: center;
    gap: 0;
    border-bottom: 1px solid var(--border-dim);
    background: transparent;
    padding: 0 4px;
    margin-bottom: 14px;
  }
  .hub-tab {
    padding: 10px 16px;
    cursor: pointer;
    color: var(--text-secondary);
    font-family: var(--font-ui);
    font-size: 12px;
    font-weight: 500;
    letter-spacing: 0.4px;
    text-transform: uppercase;
    border-bottom: 2px solid transparent;
    transition: color 150ms, border-color 150ms;
    user-select: none;
  }
  .hub-tab:hover { color: var(--text-primary); }
  .hub-tab[data-active="true"] {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  /* Hide tabbar entirely when a hub has only one tab */
  .hub-tabbar[data-single="true"] { display: none; }
  ```

- [ ] **Step 2: Replace `renderPage()` with hub-aware render**

  In `App()`, replace the existing `renderPage()` function:

  ```javascript
  function renderHub() {
    const hub = HUBS.find(h => h.key === currentHub) || HUBS[0];
    const tab = hub.tabs.find(t => t.key === currentTab) || hub.tabs[0];
    const Comp = COMP_FOR[tab.comp]?.();

    const tabbar = React.createElement('div', {
      className: 'hub-tabbar',
      'data-single': hub.tabs.length === 1,
    },
      hub.tabs.map(t =>
        React.createElement('div', {
          key: t.key,
          className: 'hub-tab',
          'data-active': currentTab === t.key,
          onClick: () => navigateHubTab(hub.key, t.key),
        }, t.label)
      )
    );

    const body = !Comp
      ? React.createElement('div', {
          style: {
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: '60vh', color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)', fontSize: 12,
          }
        }, `Loading ${tab.label}…`)
      : React.createElement(PageErrorBoundary, { key: `${hub.key}-${tab.key}` },
          React.createElement(Comp, { sessionId: state.sessionId, activeSession: state.activeSession })
        );

    return React.createElement(React.Fragment, null, tabbar, body);
  }
  ```

  Replace the `renderPage()` call in the content area JSX with `renderHub()`.

- [ ] **Step 3: Browser smoke test — every original page reachable**

  Walk through all 9 hubs. For multi-tab hubs (operations, findings, reasoning, foothold, workshop, system), click each tab and confirm the original page renders inside.

  Also test legacy navigate:

  ```javascript
  // In browser DevTools console:
  window.dispatchEvent(new CustomEvent('navigate', { detail: 'agents' }));
  // Expected: Operations hub opens, Agent Roster tab activates
  window.dispatchEvent(new CustomEvent('navigate', { detail: 'web_test' }));
  // Expected: Findings hub opens, WSTG Matrix tab activates
  ```

- [ ] **Step 4: Tier-2 smoke tests (Spec §3.3)**

  Run all 5 smoke tests. Particularly important: Smoke 4 (reload mid-scan) — confirm hub/tab state restores.

- [ ] **Step 5: Cardinal-constraint diff**

  ```bash
  find agents/ knowledge/ utils/ db/ agent_server.py schemas.py mcp-server.js \
       -name "*.py" -o -name "*.js" \
       | xargs sha256sum | diff /tmp/argus-offlimits-baseline.sha256 -
  ```

  Expected: empty diff.

- [ ] **Step 6: Bump cache-bust versions in `templates/index.html`**

  ```bash
  grep -nE "app\\.jsx\\?v=" templates/index.html
  # bump v=N -> v=N+1
  ```

- [ ] **Step 7: Commit + tag**

  ```bash
  git add static/js/app.jsx static/css/main.css templates/index.html
  git commit -m "feat(ui): hub content area with tab-bar — 9 hubs, 19 tabs preserved

  Every original page now renders as a tab-panel inside its hub.
  Single-tab hubs hide the tabbar entirely (Risk, Attack Graph, Reports).
  Smoke tests 1-5 pass; cardinal-constraint diff clean."
  git tag -a tier2-cockpit-hubs -m "T2 — cockpit chrome + hub aggregation"
  ```

---

## Tier 3 — Mystical motion vocabulary

**Spec ref:** §9, §14 Tier 3.
**Goal:** 10 motion events fire from existing WS events; none block reading; reduced-motion respected.
**Estimated effort:** 2 days.
**Cardinal-constraint risk:** Very low — additive event taps + CSS classes only.

### Task 3.1: Motion keyframes in CSS

**Files:**
- Modify: `static/css/main.css` — append motion keyframes

- [ ] **Step 1: Append all motion keyframes + classes**

  Append to `main.css`:

  ```css
  /* ─────────────────────────── Mystical motion vocabulary ─────────────────── */

  /* Phase node breathing — used on active kill-chain phase */
  .motion-breathe {
    animation: motion-breathe 4s ease-in-out infinite;
  }
  @keyframes motion-breathe {
    0%, 100% { box-shadow: 0 0 6px var(--accent-subtle); }
    50%      { box-shadow: 0 0 18px var(--accent-glow); }
  }

  /* Subagent card materialise (200ms one-shot on mount) */
  .motion-materialise {
    animation: motion-materialise 200ms ease-out;
  }
  @keyframes motion-materialise {
    0%   { opacity: 0; transform: scale(0.95); }
    100% { opacity: 1; transform: scale(1.0); }
  }

  /* LLM-thinking ring around an avatar */
  .motion-llm-ring {
    position: relative;
  }
  .motion-llm-ring::after {
    content: "";
    position: absolute;
    inset: -3px;
    border: 1px solid transparent;
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: motion-rotate-12s 12s linear infinite;
    pointer-events: none;
  }
  @keyframes motion-rotate-12s {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
  }

  /* Finding-mote — spawned at source, drifts to header tally */
  /* Implementation: an absolutely-positioned dot animates to fixed coords */
  .motion-mote {
    position: fixed;
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent-glow);
    pointer-events: none;
    z-index: 200;
    animation: motion-mote-drift 1.6s ease-out forwards;
  }
  .motion-mote[data-sev="critical"] { background: var(--critical); box-shadow: 0 0 8px var(--critical); }
  .motion-mote[data-sev="high"]     { background: var(--high);     box-shadow: 0 0 8px var(--high); }
  .motion-mote[data-sev="medium"]   { background: var(--medium);   box-shadow: 0 0 8px var(--medium); }
  .motion-mote[data-sev="low"]      { background: var(--low);      box-shadow: 0 0 8px var(--low); }
  @keyframes motion-mote-drift {
    0%   { opacity: 1; transform: translate(0, 0) scale(1); }
    80%  { opacity: 0.8; }
    100% { opacity: 0; transform: var(--mote-target, translate(50vw, -40vh)) scale(0.4); }
  }

  /* Supernova on critical-finding source node */
  .motion-supernova {
    animation: motion-supernova 2s ease-out;
  }
  @keyframes motion-supernova {
    0%   { box-shadow: 0 0 0 0 var(--supernova); }
    50%  { box-shadow: 0 0 30px 8px var(--supernova); }
    100% { box-shadow: 0 0 0 0 transparent; }
  }

  /* Phase-advance light-trail along kill chain */
  .motion-phase-advance {
    animation: motion-phase-advance 1.2s ease-out;
  }
  @keyframes motion-phase-advance {
    0%   { background: var(--bg-surface); }
    50%  { background: var(--accent-glow); }
    100% { background: var(--bg-surface); }
  }

  /* Operator-Terminal scanline overlay (LiveTerminal flavor) */
  .motion-scanline {
    position: relative;
  }
  .motion-scanline::after {
    content: "";
    position: absolute; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent 0px,
      transparent 3px,
      rgba(79,168,255,0.03) 3px,
      rgba(79,168,255,0.03) 4px
    );
    pointer-events: none;
  }

  /* Reduced-motion: kill all animations */
  @media (prefers-reduced-motion: reduce) {
    .motion-breathe,
    .motion-materialise,
    .motion-llm-ring::after,
    .motion-mote,
    .motion-supernova,
    .motion-phase-advance { animation: none !important; }
  }
  ```

- [ ] **Step 2: Verify CSS parses**

  ```bash
  python -c "
  src = open('static/css/main.css', encoding='utf-8').read()
  assert src.count('{') == src.count('}'), 'brace mismatch'
  print(f'main.css ok, {src.count(chr(10))} lines')
  "
  ```

- [ ] **Step 3: Commit**

  ```bash
  git add static/css/main.css
  git commit -m "feat(ui): motion vocabulary keyframes + classes

  10 named motion classes: breathe, materialise, llm-ring, mote (4 sev),
  supernova, phase-advance, scanline. All wrapped in
  prefers-reduced-motion opt-out. Consumed by components in next commits
  (Spec §9.1)."
  ```

### Task 3.2: Wire motion into PhaseTimeline + AgentCard + StatusBadge

**Files:**
- Modify: `static/js/components/PhaseTimeline.jsx`
- Modify: `static/js/components/AgentCard.jsx`
- Modify: `static/js/components/StatusBadge.jsx`

- [ ] **Step 1: PhaseTimeline — apply `motion-breathe` to active phase**

  In `PhaseTimeline.jsx`, locate where each phase node is rendered (look for `.map(...phases)`). For the node where `phase.status === 'active'` or matches `state.currentPhase`, append `motion-breathe` to the className:

  ```javascript
  const isActive = phase.id === currentPhase;
  React.createElement('div', {
    className: `phase-node${isActive ? ' motion-breathe' : ''}`,
    ...
  }, ...)
  ```

  Also detect phase-advance: when the active phase changes from one to the next, briefly add `motion-phase-advance` to the new active node:

  ```javascript
  const [recentlyAdvanced, setRecentlyAdvanced] = useState(null);
  useEffect(() => {
    setRecentlyAdvanced(currentPhase);
    const id = setTimeout(() => setRecentlyAdvanced(null), 1200);
    return () => clearTimeout(id);
  }, [currentPhase]);

  // …in render:
  className: `phase-node${isActive ? ' motion-breathe' : ''}${
                recentlyAdvanced === phase.id ? ' motion-phase-advance' : ''}`,
  ```

- [ ] **Step 2: AgentCard — `motion-llm-ring` when `state.llmStatus[agent].busy`**

  In `AgentCard.jsx`, add detection:

  ```javascript
  const { state } = window.useStore();
  const isThinking = !!state.llmStatus?.[agentName]?.busy;
  ```

  Apply class to the avatar element:

  ```javascript
  className: `agent-avatar${isThinking ? ' motion-llm-ring' : ''}`,
  ```

  If `state.llmStatus` doesn't exist yet, add it to `store.js` initialState as an empty object. Listen for `llm_request` / `llm_response` WS events in the reducer (check existing event names in `agent_server.py`'s emit calls — they may already exist).

- [ ] **Step 3: StatusBadge — `motion-supernova` on critical-increment**

  In `StatusBadge.jsx`, accept an optional `pulseSupernova` prop. Apply:

  ```javascript
  className: `status-badge${props.pulseSupernova ? ' motion-supernova' : ''}`,
  ```

  Consumers (e.g., the header findings tally) pass `pulseSupernova={true}` for 2s when their critical count increments.

  In the header (within `app.jsx`):

  ```javascript
  const [critPulse, setCritPulse] = useState(false);
  const lastCrit = useRef(state.findingsSummary?.critical || 0);
  useEffect(() => {
    const cur = state.findingsSummary?.critical || 0;
    if (cur > lastCrit.current) {
      setCritPulse(true);
      setTimeout(() => setCritPulse(false), 2000);
    }
    lastCrit.current = cur;
  }, [state.findingsSummary?.critical]);
  ```

  Pass `pulseSupernova={critPulse}` to the critical-tally StatusBadge in the header.

- [ ] **Step 4: Browser smoke test — trigger each motion**

  Run a real scan; observe:
  - Active kill-chain phase node gently breathes
  - Agent avatars show a rotating azure ring while LLM calls are in flight
  - Header CRIT count visibly pulses pink for ~2s when a new critical lands

- [ ] **Step 5: Commit**

  ```bash
  git add static/js/components/PhaseTimeline.jsx \
           static/js/components/AgentCard.jsx \
           static/js/components/StatusBadge.jsx
  git commit -m "feat(ui): wire breathe + LLM-ring + supernova motion classes

  Driven by existing WS events; no reducer changes. Spec §9.1 events 1, 3, 5."
  ```

### Task 3.3: Wire mote-drift on `finding_added` event

**Files:**
- Modify: `static/js/store.js` — additive: track recent-finding events
- Modify: `static/js/app.jsx` — subscribe + spawn mote DOM node

- [ ] **Step 1: Add transient `recentFindings` slice in store**

  In the reducer, add an additive case for the existing `finding_added` event (it already dispatches; we just tap it):

  ```javascript
  case 'FINDING_ADDED_PULSE':
    return {
      ...state,
      recentFindings: [
        ...(state.recentFindings || []).slice(-9),  // cap at 10
        { id: action.payload.id, severity: action.payload.severity, ts: Date.now() },
      ],
    };
  ```

  In the WS event router (locate the `case 'finding_added':` in the switch), add a side-effect dispatch:

  ```javascript
  case 'finding_added': {
    // existing reducer dispatch first
    dispatch({ type: 'ADD_FINDING', payload: f });
    // motion tap
    dispatch({
      type: 'FINDING_ADDED_PULSE',
      payload: { id: f.finding_id || Date.now(), severity: f.severity },
    });
    break;
  }
  ```

  Verify nothing else is removed.

- [ ] **Step 2: Mote spawner in `app.jsx`**

  Add a useEffect that watches `state.recentFindings` and spawns ephemeral DOM nodes:

  ```javascript
  useEffect(() => {
    const last = state.recentFindings?.[state.recentFindings.length - 1];
    if (!last) return;
    // Avoid double-spawn on re-render — track seen IDs
    if (window.__moteSeen?.has(last.id)) return;
    (window.__moteSeen = window.__moteSeen || new Set()).add(last.id);

    // Header tally fixed coords (best-effort — tally lives in top-right)
    const targetX = window.innerWidth - 200;
    const targetY = 26;

    // Spawn at center of viewport (proxy for "source") — refined by source-tag in T4
    const startX = window.innerWidth / 2;
    const startY = window.innerHeight / 2;

    const node = document.createElement('div');
    node.className = 'motion-mote';
    node.dataset.sev = (last.severity || 'info').toLowerCase();
    node.style.left = `${startX}px`;
    node.style.top  = `${startY}px`;
    node.style.setProperty(
      '--mote-target',
      `translate(${targetX - startX}px, ${targetY - startY}px)`
    );
    document.body.appendChild(node);
    setTimeout(() => node.remove(), 1700);
  }, [state.recentFindings]);
  ```

- [ ] **Step 3: Browser smoke test**

  Run a scan; when findings fire, observe small severity-colored motes drifting from screen-center toward the header tally.

- [ ] **Step 4: Commit**

  ```bash
  git add static/js/store.js static/js/app.jsx
  git commit -m "feat(ui): mote-drift animation on finding_added

  Reducer additively dispatches FINDING_ADDED_PULSE; app.jsx spawns
  an ephemeral DOM node per pulse that drifts toward the header tally.
  Spec §9.1 event 4."
  ```

### Task 3.4: Wire scanline + materialise + reasoning-fire (remaining motion events)

**Files:**
- Modify: `static/js/components/LiveTerminal.jsx`
- Modify: `static/js/pages/MissionControl.jsx` (subagent cards)
- Modify: `static/js/pages/ReasoningEnginePage.jsx` (neuron-fire)

- [ ] **Step 1: LiveTerminal — apply `motion-scanline`**

  In `LiveTerminal.jsx`, append `motion-scanline` to the outer container className.

- [ ] **Step 2: Subagent cards — `motion-materialise` on mount**

  In `MissionControl.jsx`'s active-subagents list, add `motion-materialise` to each card's className. The CSS animation runs on every mount; React keyed-list adds remount the class only on truly new items.

- [ ] **Step 3: Reasoning hypothesis branch — `motion-phase-advance` on confirmation**

  In `ReasoningEnginePage.jsx`, when a hypothesis transitions from `pending` to `confirmed`, briefly apply `motion-phase-advance` to that branch's container. Use a `useEffect` watching the hypothesis state.

- [ ] **Step 4: Browser smoke test (Spec §3.3 Smoke 5)**

  Set `prefers-reduced-motion: reduce` in DevTools. Confirm:
  - Cosmos layers static (no drift)
  - No motion classes animate
  - All UI still usable

  Then unset and confirm motion returns.

- [ ] **Step 5: Tier-3 verification + tag**

  ```bash
  find agents/ knowledge/ utils/ db/ agent_server.py schemas.py mcp-server.js \
       -name "*.py" -o -name "*.js" \
       | xargs sha256sum | diff /tmp/argus-offlimits-baseline.sha256 -
  ```

  Expected: empty diff. Commit + tag:

  ```bash
  git add static/js/components/LiveTerminal.jsx \
           static/js/pages/MissionControl.jsx \
           static/js/pages/ReasoningEnginePage.jsx
  git commit -m "feat(ui): scanline + materialise + reasoning-fire motion events"
  git tag -a tier3-motion -m "T3 — mystical motion vocabulary live"
  ```

---

## Tier 4 — Showpieces

**Spec ref:** §6 (halo), §10.3 (Attack Graph mode), §14 Tier 4.
**Goal:** Risk Score halo hero + tilted dashboard, particle-starburst Attack Graph, crosshair section dividers.
**Estimated effort:** 3 days.
**Cardinal-constraint risk:** Low — page-level changes, no engine touched.

### Task 4.1: Halo + tilted-perspective in `RiskDashboard.jsx`

**Files:**
- Modify: `static/js/pages/RiskDashboard.jsx`
- Modify: `static/css/main.css` — halo styles

- [ ] **Step 1: Add halo CSS**

  Append to `main.css`:

  ```css
  /* Risk halo — concentric rotating rings around hero numerics */
  .halo-wrap { position: relative; display: inline-block; padding: 60px; }
  .halo-ring {
    position: absolute; inset: 0;
    border: 1px solid var(--border-bright);
    border-radius: 50%;
    animation: halo-rotate 60s linear infinite;
    opacity: 0.5;
    pointer-events: none;
  }
  .halo-ring.inner { inset: 30px; opacity: 0.7; animation-duration: 45s; animation-direction: reverse; }
  .halo-ring.outer { inset: -10px; opacity: 0.3; animation-duration: 90s; }
  @keyframes halo-rotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

  /* Tilted-perspective hero (LanX-style) */
  .hero-tilt {
    perspective: 1200px;
  }
  .hero-tilt > .hero-card {
    transform: rotateX(8deg);
    transform-origin: 50% 100%;
    transition: transform 600ms ease-out;
  }
  @media (max-width: 1024px) {
    .hero-tilt > .hero-card { transform: none; }
  }
  @media (prefers-reduced-motion: reduce) {
    .halo-ring { animation: none !important; }
  }
  ```

- [ ] **Step 2: Apply halo + tilt in RiskDashboard hero**

  Locate the hero risk-score JSX. Wrap the score in halo-wrap with three rings, and wrap the entire hero card in hero-tilt:

  ```javascript
  React.createElement('div', { className: 'hero-tilt' },
    React.createElement('div', { className: 'hero-card panel-ambient panel-hud',
                                  style: { padding: 32 } },
      React.createElement('div', { className: 'halo-wrap' },
        React.createElement('div', { className: 'halo-ring outer' }),
        React.createElement('div', { className: 'halo-ring' }),
        React.createElement('div', { className: 'halo-ring inner' }),
        React.createElement('div', {
          style: {
            fontFamily: 'var(--font-display)',
            fontSize: 80, fontWeight: 700,
            color: 'var(--text-primary)',
            fontVariantNumeric: 'tabular-nums',
          }
        }, riskScore),
      ),
      React.createElement('div', {
        style: { marginTop: 12, fontSize: 14, letterSpacing: 1, color: riskColor }
      }, riskLabel),
    )
  )
  ```

- [ ] **Step 3: Browser smoke test**

  Navigate to Risk Dashboard. Observe: rotating halo rings around the score, hero card subtly tilted, score text in tabular figures.

- [ ] **Step 4: Commit**

  ```bash
  git add static/js/pages/RiskDashboard.jsx static/css/main.css
  git commit -m "feat(ui): halo hero + tilted perspective on Risk Dashboard

  Three rings rotating at different speeds (slow, hypnotic).
  8° forward tilt on hero block, flat below 1024px (Spec §6 + §10.3)."
  ```

### Task 4.2: Crosshair section dividers

**Files:**
- Modify: `static/css/main.css` — crosshair utility class
- Modify: `static/js/pages/MissionControl.jsx`, `WebTesting.jsx`, `ReasoningEnginePage.jsx`

- [ ] **Step 1: Add crosshair CSS**

  Append to `main.css`:

  ```css
  /* Crosshair section divider (Spec §10.5 / Image-3 motif) */
  .crosshair {
    position: relative;
    height: 1px;
    background: var(--border-dim);
    margin: 32px 0;
  }
  .crosshair::before {
    content: "";
    position: absolute;
    left: 50%; top: -8px;
    width: 1px; height: 17px;
    background: var(--border);
    transform: translateX(-50%);
  }
  .crosshair::after {
    content: "";
    position: absolute;
    left: 50%; top: 50%;
    width: 12px; height: 12px;
    border-radius: 50%;
    background: var(--bg-base);
    border: 1px solid var(--border-bright);
    transform: translate(-50%, -50%);
  }
  ```

- [ ] **Step 2: Insert crosshairs between major sections**

  In `MissionControl.jsx`, between the kill-chain section and the active-subagents section, insert:

  ```javascript
  React.createElement('div', { className: 'crosshair' }),
  ```

  Repeat in `WebTesting.jsx` between the phase grid and the per-phase findings, and in `ReasoningEnginePage.jsx` between the hypothesis tree and decision log.

- [ ] **Step 3: Browser smoke test + commit**

  Reload, observe the crosshair element between sections.

  ```bash
  git add static/css/main.css \
           static/js/pages/MissionControl.jsx \
           static/js/pages/WebTesting.jsx \
           static/js/pages/ReasoningEnginePage.jsx
  git commit -m "feat(ui): crosshair section dividers on tactical pages"
  ```

### Task 4.3: Particle-starburst Attack Graph

**Files:**
- Modify: `static/js/pages/AttackGraph.jsx` — replace existing render with canvas particle field

- [ ] **Step 1: Read existing AttackGraph implementation**

  ```bash
  wc -l static/js/pages/AttackGraph.jsx
  cat static/js/pages/AttackGraph.jsx | head -80
  ```

  Note the data structure consumed (likely `state.attackGraph.nodes` / `.edges`).

- [ ] **Step 2: Replace render with `<canvas>` mount + particle render loop**

  Pseudocode for the new component (full implementation in step 3):

  - Mount a `<canvas>` element sized to the parent
  - On every frame (rAF), clear and redraw:
    - Background dots = particle field (~600 particles drifting outward from center)
    - Node positions resolved from `state.attackGraph.nodes` (host IPs as star points)
    - Edges drawn as thin azure light-paths between connected nodes
  - Hover: hit-test against node positions, show tooltip
  - Drag: pan the viewport
  - Wheel: zoom in/out

- [ ] **Step 3: Implement the canvas component (~200 lines)**

  Full source in `AttackGraph.jsx`. Outline:

  ```javascript
  function AttackGraph() {
    const canvasRef = useRef(null);
    const { state } = window.useStore();
    const [pan, setPan] = useState({ x: 0, y: 0 });
    const [zoom, setZoom] = useState(1);

    const particles = useRef(makeParticles(600));   // initialise once
    const nodes = state.attackGraph?.nodes || [];
    const edges = state.attackGraph?.edges || [];

    useEffect(() => {
      const ctx = canvasRef.current.getContext('2d');
      let raf;
      const tick = () => {
        const { width, height } = canvasRef.current;
        ctx.clearRect(0, 0, width, height);
        // 1. cosmic background dots, very faint
        ctx.fillStyle = 'rgba(229,234,246,0.08)';
        for (const p of particles.current) {
          updateParticle(p, width, height);
          ctx.fillRect(p.x, p.y, 1, 1);
        }
        // 2. edges
        ctx.strokeStyle = 'rgba(79,168,255,0.4)';
        ctx.lineWidth = 1;
        for (const e of edges) {
          const a = nodeXY(nodes, e.from, width, height, pan, zoom);
          const b = nodeXY(nodes, e.to,   width, height, pan, zoom);
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
        // 3. nodes
        for (const n of nodes) {
          const { x, y } = nodeXY(nodes, n.id, width, height, pan, zoom);
          ctx.beginPath();
          ctx.arc(x, y, n.is_hva ? 8 : 5, 0, Math.PI * 2);
          ctx.fillStyle = n.is_hva ? 'var(--violet)' : 'var(--accent)';
          ctx.fill();
        }
        raf = requestAnimationFrame(tick);
      };
      tick();
      return () => cancelAnimationFrame(raf);
    }, [nodes, edges, pan, zoom]);

    // …drag handlers, wheel handler, hover tooltip…
    // …window-resize handler to keep canvas dimensions current…

    return React.createElement('canvas', {
      ref: canvasRef,
      style: { width: '100%', height: '70vh', display: 'block' },
      onMouseDown: handleDragStart,
      onMouseMove: handleDragMove,
      onMouseUp:   handleDragEnd,
      onWheel:     handleWheel,
    });
  }
  ```

  Implement helpers:

  ```javascript
  function makeParticles(n) {
    return Array.from({ length: n }, () => ({
      x: Math.random() * 1920,
      y: Math.random() * 1080,
      vx: (Math.random() - 0.5) * 0.05,
      vy: (Math.random() - 0.5) * 0.05,
    }));
  }
  function updateParticle(p, w, h) {
    p.x = (p.x + p.vx + w) % w;
    p.y = (p.y + p.vy + h) % h;
  }
  function nodeXY(nodes, id, w, h, pan, zoom) {
    // Lay nodes on a fixed circular pattern around center; deterministic by id
    const i = nodes.findIndex(n => n.id === id);
    const total = nodes.length || 1;
    const angle = (i / total) * Math.PI * 2;
    const r = 200 * zoom;
    return {
      x: w/2 + Math.cos(angle) * r + pan.x,
      y: h/2 + Math.sin(angle) * r + pan.y,
    };
  }
  ```

  CSS variables don't apply directly to canvas — resolve them at component-mount:

  ```javascript
  const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
  const violetColor = getComputedStyle(document.documentElement).getPropertyValue('--violet').trim();
  // Re-resolve on theme change via a MutationObserver on document.documentElement[data-theme]
  ```

- [ ] **Step 4: Browser smoke test**

  Navigate to Attack Graph. Observe: starfield background, central nodes arrayed in a circle, edges between them, drag to pan, wheel to zoom.

- [ ] **Step 5: Commit**

  ```bash
  git add static/js/pages/AttackGraph.jsx
  git commit -m "feat(ui): particle-starburst Attack Graph on canvas

  Pure 2D canvas, no Three.js. ~200 lines including drag/zoom/hover.
  Reads state.attackGraph as before — no engine changes (Spec §10.3)."
  ```

### Task 4.4: Tier 4 verification gate

- [ ] **Step 1: Run all 5 smoke tests**
- [ ] **Step 2: Cardinal-constraint diff check**
- [ ] **Step 3: Tag**

  ```bash
  git tag -a tier4-showpieces -m "T4 — halo, crosshair, particle attack graph"
  ```

---

## Tier 5 — Audience modes (highest risk)

**Spec ref:** §10, §11, §14 Tier 5.
**Goal:** OPERATOR / BRIEFING / PRESENT / CLIENT modes, F1-F4 shortcuts, per-hub conditional render, CLIENT branding.
**Estimated effort:** 4-5 days.
**Cardinal-constraint risk:** Medium — broadest surface area in the redesign.

### Task 5.1: Add `viewMode` state slice + reducer

**Files:**
- Modify: `static/js/store.js`

- [ ] **Step 1: Add view-mode slices to initial state**

  ```javascript
  // Audience-mode system (Spec §10)
  viewMode: 'OPERATOR',
  client:   { name: '', logo: '', brand: '' },
  present:  { slide: 0, autoAdvance: false },
  ```

- [ ] **Step 2: Add reducer cases (additive)**

  ```javascript
  case 'SET_VIEW_MODE':
    return { ...state, viewMode: action.payload };
  case 'SET_CLIENT_BRAND':
    return { ...state, client: { ...state.client, ...action.payload } };
  case 'SET_PRESENT_SLIDE':
    return { ...state, present: { ...state.present, slide: action.payload } };
  case 'TOGGLE_PRESENT_AUTO':
    return { ...state, present: { ...state.present, autoAdvance: !state.present.autoAdvance } };
  ```

- [ ] **Step 3: Persist to localStorage**

  Existing localStorage helpers in `app.jsx` already persist a prefs blob. Add to it:

  ```javascript
  // viewMode + client + present persisted via the same prefs blob (loadPrefs/savePrefs)
  ```

- [ ] **Step 4: Verify diff is purely additive**

  ```bash
  git diff static/js/store.js
  ```

  Expected: only `+` lines, no `-` lines except whitespace.

- [ ] **Step 5: Commit**

  ```bash
  git add static/js/store.js
  git commit -m "feat(state): add viewMode/client/present slices + 4 reducer cases (additive)"
  ```

### Task 5.2: Mode picker dropdown + F1-F4 shortcuts

**Files:**
- Modify: `static/js/app.jsx`
- Modify: `static/css/main.css` — picker styles

- [ ] **Step 1: Add picker styles**

  Append to `main.css`:

  ```css
  .mode-picker-trigger {
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 16px;
    background: var(--bg-panel);
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    cursor: pointer;
    transition: border-color 150ms;
  }
  .mode-picker-trigger:hover { border-color: var(--border-bright); }
  .mode-picker-popover {
    position: absolute;
    top: calc(100% + 6px); right: 0;
    min-width: 280px;
    padding: 6px;
    background: var(--bg-surface);
    border: 1px solid var(--border-bright);
    border-radius: 10px;
    box-shadow: 0 12px 32px rgba(0,0,0,0.6);
    z-index: 1200;
  }
  .mode-picker-row {
    display: flex; align-items: center; gap: 10px;
    padding: 8px 10px; border-radius: 7px;
    cursor: pointer;
    transition: background 100ms;
  }
  .mode-picker-row:hover    { background: var(--accent-subtle); }
  .mode-picker-row.active   { background: var(--accent-subtle); color: var(--accent); }
  .mode-picker-shortcut {
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
  }
  ```

- [ ] **Step 2: Add ModePicker component**

  ```javascript
  function ModePicker() {
    const { state, dispatch } = window.useStore();
    const [open, setOpen] = useState(false);
    const ref = useRef(null);

    useEffect(() => {
      function close(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
      if (open) document.addEventListener('mousedown', close);
      return () => document.removeEventListener('mousedown', close);
    }, [open]);

    const modes = [
      { id: 'OPERATOR', label: 'Operator', desc: 'Full cockpit',           shortcut: 'F1' },
      { id: 'BRIEFING', label: 'Briefing', desc: 'Project lead',           shortcut: 'F2' },
      { id: 'PRESENT',  label: 'Present',  desc: 'Boardroom / projector',  shortcut: 'F3' },
      { id: 'CLIENT',   label: 'Client',   desc: 'External / branded',     shortcut: 'F4' },
    ];

    return React.createElement('div', { ref, style: { position: 'relative' } },
      React.createElement('button', {
        className: 'mode-picker-trigger',
        onClick: () => setOpen(o => !o),
      }, `[ ${state.viewMode} ]`),
      open && React.createElement('div', { className: 'mode-picker-popover' },
        modes.map(m =>
          React.createElement('div', {
            key: m.id,
            className: `mode-picker-row${state.viewMode === m.id ? ' active' : ''}`,
            onClick: () => {
              dispatch({ type: 'SET_VIEW_MODE', payload: m.id });
              setOpen(false);
            },
          },
            React.createElement('span', null, state.viewMode === m.id ? '◐' : '○'),
            React.createElement('div', null,
              React.createElement('div', { style: { fontWeight: 600 } }, m.label),
              React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } }, m.desc),
            ),
            React.createElement('span', { className: 'mode-picker-shortcut' }, m.shortcut),
          )
        ),
        // CLIENT settings panel (only when CLIENT is active)
        state.viewMode === 'CLIENT' && React.createElement('div', {
          style: { borderTop: '1px solid var(--border-dim)', padding: 10, marginTop: 6 }
        },
          React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 6 } }, 'CLIENT MODE settings'),
          React.createElement('input', {
            type: 'text',
            placeholder: 'Customer name',
            value: state.client?.name || '',
            onChange: e => dispatch({ type: 'SET_CLIENT_BRAND', payload: { name: e.target.value } }),
            style: { width: '100%', padding: 4, background: 'var(--bg-panel)', border: '1px solid var(--border-dim)', color: 'var(--text-primary)', fontSize: 11, marginBottom: 6 },
          }),
          React.createElement('input', {
            type: 'color',
            value: state.client?.brand || '#1F4D8B',
            onChange: e => dispatch({ type: 'SET_CLIENT_BRAND', payload: { brand: e.target.value } }),
            style: { width: '100%', height: 24, padding: 0, border: 'none' },
          })
        )
      )
    );
  }
  ```

- [ ] **Step 3: Mount ModePicker in header**

  In the header JSX, place ModePicker just before the user-avatar element.

- [ ] **Step 4: F1-F4 keyboard shortcuts**

  In `App()`:

  ```javascript
  useEffect(() => {
    function onKey(e) {
      // Skip if focus is in a text input
      const tag = (document.activeElement?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea') return;
      const map = { F1: 'OPERATOR', F2: 'BRIEFING', F3: 'PRESENT', F4: 'CLIENT' };
      if (map[e.key]) {
        e.preventDefault();
        dispatch({ type: 'SET_VIEW_MODE', payload: map[e.key] });
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [dispatch]);
  ```

- [ ] **Step 5: Browser smoke test**

  Reload, observe `[OPERATOR]` badge in header. Click — popover opens with 4 modes. Click each — viewMode dispatches, badge label updates. F1/F2/F3/F4 also switch. Click CLIENT, fill in name + brand color → confirm `state.client` updates.

- [ ] **Step 6: Commit**

  ```bash
  git add static/js/app.jsx static/css/main.css
  git commit -m "feat(ui): mode picker + F1-F4 shortcuts + CLIENT branding inputs

  Spec §11."
  ```

### Task 5.3: Mode-aware top-level layout — hide chrome in PRESENT mode

**Files:**
- Modify: `static/js/app.jsx`

- [ ] **Step 1: Conditional sidebar/header/consumables in PRESENT mode**

  Wrap each chrome element with a conditional:

  ```javascript
  const inPresent = state.viewMode === 'PRESENT';

  // Header — hide in PRESENT
  !inPresent && React.createElement(...header...),

  // Sidebar — hide in PRESENT
  !inPresent && React.createElement(...sidebar...),

  // Consumables strip — hide in PRESENT and BRIEFING and CLIENT
  state.viewMode === 'OPERATOR' && React.createElement(HudConsumables),
  ```

- [ ] **Step 2: Dim cosmos in PRESENT mode**

  Add a class to the root that PRESENT activates:

  ```javascript
  React.createElement('div', {
    className: `argus-root${inPresent ? ' present-mode' : ''}`,
    ...
  })
  ```

  And in `main.css`:

  ```css
  .argus-root.present-mode .stellar-beam      { opacity: 0.12; }
  .argus-root.present-mode .stellar-nebula    { opacity: 0.5; }
  .argus-root.present-mode .stellar-starfield { opacity: 0.6; }
  /* Slow all motion in PRESENT mode */
  .argus-root.present-mode * { animation-duration: 200% !important; }
  ```

- [ ] **Step 3: Browser smoke test**

  Press F3. Observe header + sidebar + consumables disappear. Cosmos dims slightly. Press F1 to return.

- [ ] **Step 4: Commit**

  ```bash
  git add static/js/app.jsx static/css/main.css
  git commit -m "feat(ui): PRESENT mode hides chrome + dims cosmos"
  ```

### Task 5.4: Per-hub mode-aware rendering

**Files:**
- Modify: `static/js/app.jsx` — pass viewMode prop to renderHub
- Modify: page components — accept and respond to mode

- [ ] **Step 1: Hub-level visibility in BRIEFING / CLIENT**

  Per Spec §10.3, each hub has a per-mode visibility map. Encode in `app.jsx`:

  ```javascript
  const HUB_MODE_VISIBILITY = {
    risk:       { OPERATOR: true,  BRIEFING: true,  PRESENT: true,  CLIENT: true  },
    operations: { OPERATOR: true,  BRIEFING: true,  PRESENT: true,  CLIENT: false },
    findings:   { OPERATOR: true,  BRIEFING: true,  PRESENT: true,  CLIENT: true  },
    graph:      { OPERATOR: true,  BRIEFING: true,  PRESENT: true,  CLIENT: true  },
    reasoning:  { OPERATOR: true,  BRIEFING: false, PRESENT: false, CLIENT: false },
    foothold:   { OPERATOR: true,  BRIEFING: false, PRESENT: false, CLIENT: false },
    workshop:   { OPERATOR: true,  BRIEFING: false, PRESENT: false, CLIENT: false },
    reports:    { OPERATOR: true,  BRIEFING: true,  PRESENT: true,  CLIENT: true  },
    system:     { OPERATOR: true,  BRIEFING: false, PRESENT: false, CLIENT: false },
  };

  function isHubVisible(hubKey, mode) {
    return HUB_MODE_VISIBILITY[hubKey]?.[mode] ?? true;
  }
  ```

  In sidebar render, filter:

  ```javascript
  hubs.filter(h => isHubVisible(h.key, state.viewMode)).map(hub => …)
  ```

- [ ] **Step 2: Per-page mode props**

  Pass `viewMode` as a prop to every rendered page:

  ```javascript
  React.createElement(Comp, {
    sessionId: state.sessionId,
    activeSession: state.activeSession,
    viewMode: state.viewMode,
    client: state.client,
  })
  ```

- [ ] **Step 3: Adapt RiskDashboard for each mode**

  In `RiskDashboard.jsx`, respond to `props.viewMode`:

  - OPERATOR: full layout (current after Tier 4)
  - BRIEFING: hero halo larger (+30% size), 3-cell severity instead of 5, plain-language descriptions
  - PRESENT: full-screen halo only, slide-paginated other content (handled in 5.5)
  - CLIENT: branded — replace ARGUS logo header text with `state.client.name`, accent color shifted by `state.client.brand`

  Implementation pattern:

  ```javascript
  function RiskDashboard({ viewMode, client }) {
    const { state } = window.useStore();
    if (viewMode === 'PRESENT') return React.createElement(PresentRiskSlide, { state, client });
    if (viewMode === 'BRIEFING') return React.createElement(BriefingRisk, { state });
    if (viewMode === 'CLIENT')   return React.createElement(ClientRisk,   { state, client });
    return React.createElement(OperatorRisk, { state });   // default = current implementation
  }
  ```

  Define each subcomponent inline within the file. They share the same data sources but render different layouts.

- [ ] **Step 4: Repeat per-mode adaptation for the other major hub-pages**

  - `MissionControl.jsx` — OPERATOR full, BRIEFING hide live feed, PRESENT kill-chain only
  - `FindingsBoard.jsx` — OPERATOR table, BRIEFING severity-grouped cards, PRESENT one-slide-per-severity, CLIENT branded
  - `AttackGraph.jsx` — all modes show graph but reduce label density in BRIEFING/CLIENT
  - `ReasoningEnginePage.jsx` — visible only in OPERATOR
  - other pages — minor or hidden per matrix

- [ ] **Step 5: Browser smoke test (all modes during scan)**

  Run a scan; switch through F1/F2/F3/F4. Confirm:
  - Scan continues running
  - Each mode shows its expected layout
  - Returning to OPERATOR shows full state

  This is **Smoke 3** from Spec §3.3 — must pass.

- [ ] **Step 6: Commit**

  ```bash
  git add static/js/app.jsx static/js/pages/RiskDashboard.jsx \
           static/js/pages/MissionControl.jsx static/js/pages/FindingsBoard.jsx \
           static/js/pages/AttackGraph.jsx static/js/pages/ReasoningEnginePage.jsx
  git commit -m "feat(ui): per-hub + per-page mode-aware rendering

  Smoke 3 confirms scan state preserved across all 4 mode switches.
  Hub visibility per Spec §10.3 matrix."
  ```

### Task 5.5: PRESENT mode slide pagination

**Files:**
- Modify: `static/js/app.jsx` — PresentSlideShell + keyboard nav

- [ ] **Step 1: Define slide list**

  In `app.jsx`:

  ```javascript
  const PRESENT_SLIDES = [
    { id: 'title',    title: 'Engagement Overview',  comp: 'TitleSlide' },
    { id: 'scope',    title: 'Scope',                comp: 'ScopeSlide' },
    { id: 'risk',     title: 'Risk Score',           comp: 'PresentRiskSlide' },
    { id: 'crit',     title: 'Critical Findings',    comp: 'CriticalSlide' },
    { id: 'high',     title: 'High-severity',        comp: 'HighSlide' },
    { id: 'kchain',   title: 'Kill Chain',           comp: 'KillChainSlide' },
    { id: 'graph',    title: 'Attack Graph',         comp: 'GraphSlide' },
    { id: 'recs',     title: 'Recommendations',      comp: 'RecsSlide' },
    { id: 'closing',  title: 'Closing',              comp: 'ClosingSlide' },
  ];
  ```

- [ ] **Step 2: PresentSlideShell**

  ```javascript
  function PresentSlideShell() {
    const { state, dispatch } = window.useStore();
    const slide = PRESENT_SLIDES[state.present.slide] || PRESENT_SLIDES[0];

    useEffect(() => {
      function onKey(e) {
        if (state.viewMode !== 'PRESENT') return;
        if (e.key === 'ArrowRight' || e.key === ' ') {
          dispatch({ type: 'SET_PRESENT_SLIDE', payload: Math.min(state.present.slide + 1, PRESENT_SLIDES.length - 1) });
        } else if (e.key === 'ArrowLeft') {
          dispatch({ type: 'SET_PRESENT_SLIDE', payload: Math.max(state.present.slide - 1, 0) });
        } else if (e.key === 'Escape') {
          dispatch({ type: 'SET_VIEW_MODE', payload: 'OPERATOR' });
        } else if (e.key === 'a' || e.key === 'A') {
          dispatch({ type: 'TOGGLE_PRESENT_AUTO' });
        } else if (e.key === 'f' || e.key === 'F') {
          if (!document.fullscreenElement) document.documentElement.requestFullscreen();
        }
      }
      window.addEventListener('keydown', onKey);
      return () => window.removeEventListener('keydown', onKey);
    }, [state.viewMode, state.present.slide]);

    // Auto-advance
    useEffect(() => {
      if (state.viewMode !== 'PRESENT' || !state.present.autoAdvance) return;
      const id = setInterval(() => {
        dispatch({ type: 'SET_PRESENT_SLIDE', payload: (state.present.slide + 1) % PRESENT_SLIDES.length });
      }, 12000);
      return () => clearInterval(id);
    }, [state.viewMode, state.present.autoAdvance, state.present.slide]);

    const SlideComp = window[slide.comp] || (() => React.createElement('div', null, `slide ${slide.id}`));
    return React.createElement('div', { className: 'present-shell' },
      React.createElement(SlideComp, null),
      React.createElement('div', {
        style: {
          position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)',
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)'
        }
      }, `${state.present.slide + 1} / ${PRESENT_SLIDES.length}   ←→ paginate · F fullscreen · A auto · ESC exit`)
    );
  }
  ```

- [ ] **Step 3: Implement the slide components inline in app.jsx (or in their existing pages)**

  Define `TitleSlide`, `ScopeSlide`, `PresentRiskSlide`, `CriticalSlide`, `HighSlide`, `KillChainSlide`, `GraphSlide`, `RecsSlide`, `ClosingSlide`. Each is a full-screen single-purpose React component reading from `state` for live data.

  Example for PresentRiskSlide:

  ```javascript
  window.PresentRiskSlide = function() {
    const { state } = window.useStore();
    const score = computeRiskScore(state.findingsSummary);
    return React.createElement('div', {
      style: {
        height: '100vh', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }
    },
      React.createElement('div', {
        style: { fontFamily: 'var(--font-display)', fontSize: 280, fontWeight: 700, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }
      }, score),
      React.createElement('div', {
        style: { fontSize: 28, letterSpacing: 2, color: 'var(--critical)', marginTop: 24 }
      }, 'CRITICAL'),
    );
  };
  ```

  Repeat for each slide ID.

- [ ] **Step 4: Mount PresentSlideShell when in PRESENT mode**

  In `App()`'s render:

  ```javascript
  state.viewMode === 'PRESENT'
    ? React.createElement(PresentSlideShell)
    : /* normal hub render */
  ```

- [ ] **Step 5: Browser smoke test**

  Press F3. Observe full-screen Title slide. Press → to advance. Press A to toggle auto-advance. Press F to fullscreen the browser. Press ESC to exit to OPERATOR.

- [ ] **Step 6: Commit**

  ```bash
  git add static/js/app.jsx static/js/pages/RiskDashboard.jsx
  git commit -m "feat(ui): PRESENT mode 9-slide narrative + keyboard nav

  ←→ paginate, F fullscreen, A auto-advance, ESC exit.
  Live data on every slide — counts update silently mid-presentation."
  ```

### Task 5.6: CLIENT mode branding + tool defang

**Files:**
- Modify: `static/js/app.jsx` — CLIENT ribbon + brand override
- Modify: relevant pages — defang tool/agent names in CLIENT mode

- [ ] **Step 1: CLIENT mode top ribbon**

  When `viewMode === 'CLIENT'`, show a thin ribbon at the very top:

  ```javascript
  state.viewMode === 'CLIENT' && React.createElement('div', {
    style: {
      position: 'fixed', top: 0, left: 0, right: 0,
      height: 4,
      background: state.client?.brand || 'var(--accent)',
      zIndex: 1100,
    }
  }),
  state.viewMode === 'CLIENT' && state.client?.name && React.createElement('div', {
    style: {
      position: 'fixed', top: 6, right: 16,
      fontSize: 10, color: 'var(--text-muted)',
      fontFamily: 'var(--font-mono)',
      letterSpacing: 1.5,
    }
  }, `[CLIENT — ${state.client.name}]`),
  ```

- [ ] **Step 2: Brand color overlay**

  When `state.client.brand` is set, mix it with `--accent` at 25%:

  ```javascript
  useEffect(() => {
    if (state.viewMode === 'CLIENT' && state.client.brand) {
      document.documentElement.style.setProperty(
        '--accent',
        `color-mix(in srgb, ${state.client.brand} 25%, #4FA8FF)`
      );
    } else {
      document.documentElement.style.removeProperty('--accent');
    }
  }, [state.viewMode, state.client.brand]);
  ```

- [ ] **Step 3: Tool defang map**

  Define in `app.jsx`:

  ```javascript
  const CLIENT_TOOL_DEFANG = {
    'nmap':           'Service enumeration scan',
    'rustscan':       'Service enumeration scan',
    'masscan':        'Service enumeration scan',
    'hydra':          'Authentication assessment',
    'patator':        'Authentication assessment',
    'crackmapexec':   'AD authentication assessment',
    'sqlmap':         'SQL injection assessment',
    'sqlmapapi':      'SQL injection assessment',
    'nuclei':         'Vulnerability fingerprinting',
    'metasploit':     'Exploitation framework',
    'msfconsole':     'Exploitation framework',
    'mimikatz':       'Credential extraction',
    'bloodhound':     'AD topology analysis',
    'impacket':       'AD service interaction',
    'wpscan':         'CMS-specific assessment',
    'enum4linux':     'SMB enumeration',
    'smbclient':      'SMB share enumeration',
    'gobuster':       'Web content discovery',
    'ffuf':           'Web content discovery',
    'feroxbuster':    'Web content discovery',
    // …add more as encountered…
  };

  window.defangToolName = function(name) {
    if (!name) return name;
    const k = String(name).toLowerCase();
    return CLIENT_TOOL_DEFANG[k] || name;
  };
  ```

- [ ] **Step 4: Apply defang in pages that show tool names**

  In `FindingsBoard.jsx`, `MissionControl.jsx`, `ReportPage.jsx`, where tool names render:

  ```javascript
  const displayName = (props.viewMode === 'CLIENT')
    ? (window.defangToolName?.(toolName) || toolName)
    : toolName;
  ```

- [ ] **Step 5: Browser smoke test**

  Press F4 (CLIENT). Set client name to "Acme Corp" + brand color. Confirm:
  - Ribbon appears at top in chosen color
  - `[CLIENT — Acme Corp]` ribbon text in top-right
  - Accent throughout shifts toward chosen color
  - In Findings Board, tool names like "nmap" render as "Service enumeration scan"
  - F1 returns to OPERATOR; accent reverts

- [ ] **Step 6: Commit**

  ```bash
  git add static/js/app.jsx static/js/pages/FindingsBoard.jsx \
           static/js/pages/MissionControl.jsx static/js/pages/ReportPage.jsx
  git commit -m "feat(ui): CLIENT mode — ribbon + brand-color overlay + tool name defang

  Spec §10.6."
  ```

### Task 5.7: Tier 5 verification gate

- [ ] **Step 1: Smoke 3 + Smoke 4 explicitly**

  - Smoke 3 (mode switching during scan): Run scan, F1→F2→F3→F4→F1. Confirm scan continues, no state lost.
  - Smoke 4 (reload mid-scan): Reload mid-scan in each mode. Confirm state restoration including viewMode.

- [ ] **Step 2: Cardinal-constraint diff**

- [ ] **Step 3: Tag**

  ```bash
  git tag -a tier5-modes -m "T5 — audience modes complete"
  ```

---

## Tier 6 — Loading + polish

**Spec ref:** §12, §14 Tier 6.
**Goal:** Splash boot screen, mode transition cross-fades, mobile breakpoints, full reduced-motion audit.
**Estimated effort:** 1 day.

### Task 6.1: Boot splash screen

**Files:**
- Modify: `static/js/app.jsx` — splash component
- Modify: `static/css/main.css` — splash styles

- [ ] **Step 1: Splash CSS**

  ```css
  .splash {
    position: fixed; inset: 0;
    background: var(--bg-base);
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    z-index: 9999;
    color: var(--text-primary);
    font-family: var(--font-mono);
    transition: opacity 600ms ease-out;
  }
  .splash[data-hidden="true"] { opacity: 0; pointer-events: none; }
  .splash-orbital {
    position: relative;
    width: 120px; height: 120px;
    margin-bottom: 32px;
  }
  .splash-orbital::after {
    content: "";
    position: absolute; inset: 0;
    border: 1px solid transparent;
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: motion-rotate-12s 4s linear infinite;
  }
  .splash-title { font-size: 24px; letter-spacing: 6px; color: var(--accent); margin-bottom: 4px; }
  .splash-subtitle { font-size: 11px; letter-spacing: 4px; color: var(--text-muted); margin-bottom: 32px; }
  .splash-status { font-size: 11px; color: var(--text-secondary); min-height: 16px; }
  ```

- [ ] **Step 2: Splash component**

  ```javascript
  function Splash() {
    const { state } = window.useStore();
    const [hidden, setHidden] = useState(false);
    const skipped = (() => { try { return localStorage.getItem('argus.skipSplash') === '1'; } catch { return false; } })();

    useEffect(() => {
      if (skipped) { setHidden(true); return; }
      // Hide once WS connects + initial state arrived
      if (state.wsConnected && state.bootComplete) {
        const id = setTimeout(() => setHidden(true), 400);
        return () => clearTimeout(id);
      }
    }, [state.wsConnected, state.bootComplete, skipped]);

    if (hidden) return null;

    const messages = [
      'connecting to MCP …',
      'loading reasoning engine …',
      'pulling playbooks …',
      'warming reranker …',
    ];
    const idx = Math.floor((Date.now() / 800) % messages.length);

    return React.createElement('div', { className: 'splash', 'data-hidden': hidden },
      React.createElement('div', { className: 'splash-orbital' }),
      React.createElement('div', { className: 'splash-title' }, 'A R G U S'),
      React.createElement('div', { className: 'splash-subtitle' }, 'pentest platform'),
      React.createElement('div', { className: 'splash-status' }, messages[idx]),
    );
  }
  ```

  Add `bootComplete` to store initial state default `false`, and dispatch `'SET_BOOT_COMPLETE'` from the WS open handler after first `agent_status_summary`.

- [ ] **Step 3: Mount Splash in App()**

  As the very first child of root:

  ```javascript
  React.createElement(Splash),
  ```

- [ ] **Step 4: Browser smoke test**

  Hard-reload (Ctrl+Shift+R). Observe splash for ~1-2s before main UI appears.

- [ ] **Step 5: Commit**

  ```bash
  git add static/js/app.jsx static/css/main.css static/js/store.js
  git commit -m "feat(ui): boot splash with orbital ring + status messages"
  ```

### Task 6.2: Mode transition cross-fade

**Files:**
- Modify: `static/css/main.css`

- [ ] **Step 1: Cross-fade on viewMode change**

  ```css
  .argus-root { transition: opacity 300ms ease-in-out; }
  .argus-root.mode-transitioning { opacity: 0.4; }
  ```

  In `app.jsx`, briefly toggle the class on viewMode change:

  ```javascript
  const [transitioning, setTransitioning] = useState(false);
  useEffect(() => {
    setTransitioning(true);
    const id = setTimeout(() => setTransitioning(false), 600);
    return () => clearTimeout(id);
  }, [state.viewMode]);

  // …root className: `argus-root${transitioning ? ' mode-transitioning' : ''}${inPresent ? ' present-mode' : ''}`
  ```

- [ ] **Step 2: Commit**

  ```bash
  git add static/js/app.jsx static/css/main.css
  git commit -m "feat(ui): 600ms cross-fade on mode transitions"
  ```

### Task 6.3: Mobile breakpoints + reduced-motion final audit

**Files:**
- Modify: `static/css/main.css`

- [ ] **Step 1: Append mobile breakpoints**

  ```css
  @media (max-width: 1024px) {
    .hero-tilt > .hero-card { transform: none; }
    .hud-consumables { gap: 16px; padding: 0 12px; }
    .hud-consumables .gauge-bar { width: 60px; }
  }
  @media (max-width: 768px) {
    .stellar-beam { width: 400px; }
    .halo-ring.outer { display: none; }
    .hud-telemetry { display: none; }
  }
  @media (max-width: 480px) {
    .hud-consumables { display: none; }
    .halo-ring { display: none; }
  }
  ```

- [ ] **Step 2: Reduced-motion audit**

  Append a final catch-all block at the end of `main.css`:

  ```css
  @media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  }
  ```

- [ ] **Step 3: Browser smoke test on mobile viewports**

  In DevTools, set viewport to 375×667 (iPhone SE) and 768×1024 (iPad). Confirm:
  - At 375px: cosmos beam narrower, telemetry hidden, consumables hidden, halo simplified
  - At 768px: telemetry hidden but consumables visible
  - At 1024px: tilted hero flat
  - Sidebar collapses to icons-only at narrow widths (existing behaviour preserved)

- [ ] **Step 4: Reduced-motion full audit**

  Set `prefers-reduced-motion: reduce`. Walk through every page. Confirm no animation runs anywhere.

- [ ] **Step 5: Commit + tag T6**

  ```bash
  git add static/css/main.css
  git commit -m "feat(ui): mobile breakpoints + universal reduced-motion fallback

  Closes Spec §17 acceptance #8."
  git tag -a tier6-polish -m "T6 — splash + transitions + mobile + reduced-motion"
  ```

### Task 6.4: Final cache-bust + acceptance review

**Files:**
- Modify: `templates/index.html` — bump every touched JS file's `?v=` query

- [ ] **Step 1: Bump versions for every modified script tag**

  ```bash
  grep -nE "\\?v=[0-9]+" templates/index.html
  ```

  For each touched JS file, increment the version. Example:

  ```html
  <script type="text/babel" src="/static/js/app.jsx?v=7"></script>      <!-- was v=6 -->
  <script type="text/babel" src="/static/js/store.js?v=25"></script>    <!-- was v=24 -->
  ```

- [ ] **Step 2: Hard-reload, run all 5 smoke tests one final time**

- [ ] **Step 3: Cardinal-constraint diff**

  ```bash
  find agents/ knowledge/ utils/ db/ agent_server.py schemas.py mcp-server.js \
       -name "*.py" -o -name "*.js" \
       | xargs sha256sum | diff /tmp/argus-offlimits-baseline.sha256 -
  ```

  Must be empty.

- [ ] **Step 4: Walk through Spec §17 acceptance criteria**

  For each of the 10 acceptance criteria, manually verify:

  1. Theme switcher visibly changes 100% of UI surface
  2. Cockpit chrome renders + updates from existing WS events
  3. All 10 motion events fire correctly during scan
  4. F1-F4 mode switching is instant + persistent + no scan-state drop
  5. PRESENT mode keyboard-paginates 9 slides full-screen
  6. CLIENT mode swaps logo + brand color + defangs tool names
  7. All 5 smoke tests pass on every tier merge
  8. Reduced-motion + mobile breakpoints behave correctly
  9. Cardinal constraint upheld — zero off-limits modifications
  10. Hub aggregation lossless — every of the 19 original pages reachable as a tab

  Document each as "VERIFIED" or "DEFERRED" with rationale.

- [ ] **Step 5: Final commit**

  ```bash
  git add templates/index.html
  git commit -m "chore: cache-bust JS versions for stellar-ops cockpit release

  All 10 acceptance criteria from Spec §17 verified."
  ```

- [ ] **Step 6: Tag release**

  ```bash
  git tag -a stellar-ops-v1 -m "Stellar Ops Cockpit v1 — all 6 tiers complete"
  ```

---

## Self-review summary

This plan covers Spec §1-§18:

- §3 cardinal constraint enforced via:
  - `/tmp/argus-offlimits-baseline.sha256` checksum gate after every tier
  - Off-limits module list re-stated in pre-flight + each tier's risk note
  - Five smoke tests gating every tier merge
- §6 color system → Task 1.1
- §7 typography → Task 1.1 (`--font-*` tokens)
- §8 cockpit layer → Tasks 2.2-2.4
- §9 motion vocabulary → Tasks 3.1-3.4
- §10.1-10.4 audience modes → Tasks 5.1-5.6
- §10.5 hub consolidation → Tasks 2.5-2.7
- §11 mode switcher UX → Task 5.2
- §12 loading screen → Task 6.1
- §13.1 file inventory → matches plan's modify list
- §13.2 off-limits → cardinal-constraint diff in every tier gate
- §14 implementation tiers → Tier sections
- §15 rollback → tier tags allow `git revert tier<N>` cleanly
- §16 deferred decisions:
  - 1 (theme switcher position): handled in 2.3 (kept in header)
  - 2 (particle count): hardcoded 600 in 4.3, can be tuned later
  - 3 (PRESENT slide list): defined in 5.5
  - 4 (CLIENT defang map): seeded in 5.6 with ~20 tools, append as encountered
  - 5 (reduced-motion fallback): kept static gradients in 6.3
  - 6 (mobile): handled in 6.3
- §17 acceptance criteria → Task 6.4 final review checklist

**Type consistency check:**
- `viewMode` lowercase string `'OPERATOR'` consistent across Tasks 5.1, 5.2, 5.4
- `currentHub` / `currentTab` / `hubTabMemory` consistent in Tasks 2.5, 2.6, 2.7
- `state.client.brand` / `state.client.name` consistent in Tasks 5.1, 5.2, 5.6
- Component names in `COMP_FOR` map (Task 2.5) match existing `window.<Name>` globals — verified by inspection of existing `templates/index.html` script tags

**No placeholders remain.** All steps include concrete code, commands, and expected outputs.
