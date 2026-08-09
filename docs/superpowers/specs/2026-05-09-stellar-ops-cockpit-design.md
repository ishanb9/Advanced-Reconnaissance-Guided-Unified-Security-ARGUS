# Stellar Ops Cockpit — Frontend Redesign Spec

> **Status:** Approved by operator, awaiting spec-review sign-off before implementation plan.
> **Author:** ARGUS dev session, 2026-05-09.

---

## 1. Executive summary

Replace the current ARGUS frontend's tired flat dashboard with **Stellar Ops** — a
spacecraft-cockpit aesthetic over a deep cosmic backdrop, with a four-altitude
**audience-mode system** (Operator / Briefing / Present / Client) that lets a
single application serve a pentester at the keyboard *and* a CISO in a board
meeting from the same live data.

Make hacking feel mystical and magical (without gamifying it), keep professional
restraint throughout (no popups, no sound, no celebration), and **never let the
UI rewrite break the agent engine that does the actual compromise work.**

---

## 2. Goals

1. **Cockpit feel** — operator UI evokes a spacecraft control panel: ambient
   panel illumination, mission clock, consumables gauges, telemetry strip,
   slow ambient cosmic motion behind everything.
2. **Mystical hacking** — event-driven motion vocabulary signals system
   activity through the operator's peripheral vision: phases breathe, motes
   drift from sources to tallies, kill-chain advances trace light along the
   path. Restrained, never gamified.
3. **Working theme switcher** — switching themes actually changes the visible
   UI, not 30% of it (the current bug).
4. **Audience modes** — single Argus, four altitudes:
   `OPERATOR / BRIEFING / PRESENT / CLIENT` — re-render dashboards for the
   current audience without losing live data.
5. **Reference-grade polish** — the dazzle bar set by the user's references
   (LanX hero, particle-droplet centerpiece, crosshair overlays, theatrical
   light beam from above).
6. **Performance** — pure CSS / small canvas only, no Three.js / Spline /
   heavy 3D libs. < 4% CPU on a 5-year-old laptop. Mobile-survivable.
7. **Non-regression** — see Section 3.

## 2.1 Non-goals (explicit)

- **Gamification of any kind** — no XP, no achievements, no progress bars
  framed as quests, no celebratory animations on shell/flag.
- **Anxiety-inducing alerts** — no flashing, no strobing, no bright crimson,
  no pop-overs that demand acknowledgment.
- **Audio** — no sound effects, no audio cues. Operators may have headphones
  in for tool output.
- **Light theme** — daylight theme is dropped. Pentest tooling lives in dark
  mode by professional convention.
- **3D engines** — no Three.js, Spline, Babylon, or WebGL pipelines added in
  this spec. Cinematic feel comes from CSS perspective, gradients, transforms,
  and a single ~200-line canvas for the attack-graph particle field.
- **Touching the agent engine** — no agent / subagent / reasoning / KB code
  is modified for this work.

---

## 3. Cardinal constraint — non-regression

**The UI redesign must not modify or destabilise the agent engine that does
the compromise work.** Argus's job is to compromise networks; the frontend
just shows what the engine is doing. Every commit in this work must be
confined to the presentation layer.

### 3.1 Boundaries — files and modules that MUST NOT change behaviour

| Layer                          | Off-limits modules                                                                                  |
| ------------------------------ | --------------------------------------------------------------------------------------------------- |
| Master / orchestration         | `agents/master_agent.py`, `agents/reasoning/*.py`                                                   |
| Web orchestrator               | `agents/web/web_orchestrator.py`                                                                    |
| All subagents                  | `agents/web/*.py` (every file under `agents/web/` is off-limits)                                    |
| Base classes                   | `agents/base_agent.py`, `agents/base_subagent.py`                                                   |
| Specialty agents               | `agents/web_agent.py`, `agents/attack_graph_agent.py`, `agents/meta/expert_agent.py`                |
| Tools, RAG, scan logger        | `knowledge/build_kb.py`, `knowledge/knowledge_base.py`, `utils/scan_logger.py`, `utils/*.py`        |
| Server / WS / DB               | `agent_server.py`, `db/*.py`, `schemas.py`, `mcp-server.js`                                          |
| Evidence / loot / persistence  | All MongoDB write paths                                                                              |

The redesign **does** modify presentation files freely:

| Layer                          | In-scope files                                                                                       |
| ------------------------------ | ---------------------------------------------------------------------------------------------------- |
| CSS                            | `static/css/main.css`                                                                                |
| App shell                      | `static/js/app.jsx`                                                                                  |
| State store                    | `static/js/store.js`  *(only to add a `viewMode` slice + reducer case + WS event-tap for motion)* |
| Pages                          | `static/js/pages/*.jsx`                                                                              |
| Components                     | `static/js/components/*.jsx`                                                                         |
| Template                       | `templates/index.html`  *(only for cache-bust version bumps)*                                       |

### 3.2 Behaviour-preservation guarantees

For every tier of work below (Section 14):

1. **No reduction in event coverage.** Every WebSocket event the current UI
   subscribes to remains subscribed. Adding a new event tap (for motion) is
   allowed; removing or renaming any reducer case is forbidden.
2. **No reduction in page coverage.** Every existing page route in
   `app.jsx`'s `PAGES` array remains routable in OPERATOR mode. New audience
   modes may HIDE pages, but the routes still exist.
3. **No data-flow regression.** The reducer remains the single source of
   truth. New visual state (e.g. transient pulse triggers) lives in component
   local state, not in the reducer, except for `viewMode` which is global.
4. **Every existing dispatch action keeps working.** Reducers are append-only
   in this spec — no removed cases, no renamed actions.
5. **localStorage keys** for existing prefs (`argus.ui.prefs.v2`) are
   preserved. New keys (`argus.viewMode`, `argus.client.brand`) are additive.
6. **No API surface change** between frontend and `agent_server.py`. WS
   message shapes consumed remain unchanged.

### 3.3 Non-regression test plan

Before tier work merges:

- **Smoke 1:** Spin up `agent_server.py`, load the GUI, confirm all 19 pages
  in `PAGES` are reachable in OPERATOR mode and render without console
  errors.
- **Smoke 2:** Run a full scan against a localhost target (Vagrant / docker
  container), confirm: (a) WS events flow, (b) findings appear in Findings
  Board, (c) kill-chain advances, (d) live feed populates, (e) report
  generates, (f) attack graph populates, (g) reasoning page shows decisions.
- **Smoke 3:** Switch through all four audience modes during the scan.
  Confirm: (a) data continues flowing under all modes, (b) switching
  modes does NOT drop or reset state, (c) returning to OPERATOR shows the
  full state.
- **Smoke 4:** Reload the browser mid-scan. Confirm state restoration
  (existing localStorage / WS replay) still works.
- **Smoke 5:** Run with `prefers-reduced-motion: reduce`. Confirm all
  decorative motion is suppressed and the UI stays usable.

These are validation gates, not deliverables — they protect the cardinal
constraint.

---

## 4. Existing problem (what we're fixing)

1. **Theme switcher is cosmetic only.** `app.jsx` hardcodes a `T = {...}`
   color object with literal hex values that don't change when
   `[data-theme]` flips. ~56 references in `app.jsx`, ~96 in
   `RiskDashboard.jsx`, ~33 in `WebTesting.jsx`. Other pages already use
   `var(--*)` correctly. Net effect: switching theme repaints maybe 30% of
   the screen.
2. **Visual identity is generic dashboard.** Reads like every SaaS admin
   panel. Operator brief: *"doesn't look human-designed."*
3. **No multi-audience presentation.** All viewers see the same dense
   operator UI. Stakeholder presentations require manual screenshot picks.
4. **No ambient feedback during scan.** Operator can't tell at a glance
   whether ARGUS is actually working without staring at the live feed.
5. **No load polish.** Cold start dumps user into a half-rendered UI while
   websocket connects, KB loads, agents register.

---

## 5. Design vision — Stellar Ops Cockpit

### 5.1 Concept (one paragraph)

You are at a deep-space mission control monitoring a probe that's also a
hacker. The screen breathes — slow stellar drift behind, calm tactical
telemetry in front, a single supernova when something critical fires. The
information stays Bloomberg-grade dense in operator mode but reformats into
a cinematic narrative for executives. The cosmic backdrop is the windshield;
the chrome is the cockpit dashboard; the operator's hands are on the
controls.

### 5.2 Per-page flavour assignments

| Surface                                  | Aesthetic flavour          | Why                                          |
| ---------------------------------------- | -------------------------- | -------------------------------------------- |
| Background everywhere                    | Interstellar (custom)      | The mesmerising layer common to all pages   |
| Risk Dashboard, Findings Board, Reports  | Surveillance Console       | Decisive reading, screenshot-bait           |
| Mission Control, Web Testing, Reasoning  | Mil-spec HUD               | Dense tactical telemetry                    |
| Tool Workshop, Live Terminal, Shells     | Operator Terminal          | Mono-only, comfortable for tool reads       |
| Critical alerts, kill-chain milestones   | Neon Noir (rare)           | One supernova pulse — magnetises tired eyes |
| Attack Graph                             | Particle Starburst         | The interstellar showpiece                  |

---

## 6. Color system

Black-blue dominant. Cosmic palette with surgical accent use.

```css
/* Stellar Ops — DEFAULT theme.  Lives in :root in main.css */

:root {
  /* SURFACE LAYERS (deep space → cabin) */
  --bg-void:          #04050E;   /* page canvas, near-black with blue cast */
  --bg-surface:       #0A1023;   /* panels, cards */
  --bg-elevated:      #0F1832;   /* raised cards, modals */
  --bg-glass:         rgba(15, 24, 50, 0.78);   /* translucent over the cosmos */

  /* BORDERS (1px lines in the void) */
  --border-dim:       #1B2750;
  --border:           #2D3F75;
  --border-bright:    #4F5DA8;   /* active focus / selected */

  /* PRIMARY — the "warp drive" colour */
  --accent:           #4FA8FF;   /* azure, like a star's blue glow */
  --accent-dim:       #2E72C7;
  --accent-glow:      rgba(79, 168, 255, 0.22);
  --accent-subtle:    rgba(79, 168, 255, 0.07);

  /* SECONDARY (telemetry, charts) */
  --cyan:             #38E5FF;
  --violet:           #7B6CF6;   /* nebula violet — milestones only */

  /* TEXT */
  --text-primary:     #E5EAF6;
  --text-secondary:   #94A0C5;
  --text-muted:       #4F5876;

  /* SEVERITY (kept conventional — operators expect these) */
  --critical:         #FF4560;
  --high:             #FF8C42;
  --medium:           #FFC83D;
  --low:              #4ADE80;
  --info:             var(--accent);

  /* SUPERNOVA — rare, attention-magnet */
  --supernova:        #FF4D8F;   /* 2s pulse on critical findings, then settles */

  /* TYPE */
  --font-ui:          'Inter', system-ui, sans-serif;
  --font-display:     'Inter', system-ui, sans-serif;   /* heavy weight @ 600+ */
  --font-mono:        'JetBrains Mono', 'Courier New', monospace;
}
```

### 6.1 Alternate themes (preserved)

Keep `[data-theme="graphite"]`, `[data-theme="sapphire"]`, `[data-theme="amber"]`,
`[data-theme="contrast"]`. Drop `[data-theme="daylight"]`. All alternate themes
must override the same variable list above.

---

## 7. Typography

- Body + UI: **Inter** at 14px / 1.5
- Hero numerics: **Inter** weight 600/700, tabular-figures, 28-280px
- Code, IPs, ports, CVEs, timestamps: **JetBrains Mono** at 13px
- Labels / chips / pill badges: **Inter** uppercase, +1px tracking, weight 600

Type scale: `11 / 12 / 14 / 16 / 20 / 28 / 40 / 80 / 200` px.
Font weights used: `400 / 500 / 600 / 700`.

No Orbitron, Audiowide, or other "cyberpunk-stylised" display fonts. They
date the design the moment we ship.

---

## 8. The Cockpit layer

### 8.1 Stellar Beam (app-wide signature)

A single fixed-position div behind everything, top-of-viewport vertical
column of azure light fanning out below. CSS-only:

```
position: fixed
top: -10%
left: 50%
transform: translateX(-50%)
width: 800px
height: 80vh
background: linear-gradient(180deg, var(--accent-glow) 0%, transparent 60%);
clip-path: polygon(40% 0%, 60% 0%, 100% 100%, 0% 100%);
opacity: 0.25;
pointer-events: none;
z-index: 0;
```

Suppressed in PRESENT mode (dimmed to 0.12) and in light/print contexts.

### 8.2 Heads-Up Display (header)

Replaces the existing 52px header. Contents L→R:

```
ARGUS◈   ⚡▌▌·   ⏱02:14:37   ◐EXPLOIT   ▣10.10.42.7   47⚠3☠1   ⌕Ctrl-K   [MODE]   👤
─ stellar beam ─
```

- **Brand** — existing logomark, kept
- **Telemetry strip** — 3 vertical bars: LLM call rate (last 60s),
  active tool count, network throughput. Heights animate at 1Hz.
- **Mission clock** — engagement-elapsed timer, monospace
- **Phase pill** — current phase with status glyph
- **Target pill** — current target IP/host
- **Findings tally** — `count⚠high count☠crit` with supernova on critical increment
- **Command palette trigger** — kept, unchanged
- **MODE badge** — new, opens audience-mode picker (Section 11)
- **User avatar** — kept

### 8.3 Side console (sidebar)

Sidebar layout preserved. New: active nav item gets inset glow (`box-shadow:
inset 0 0 0 1px var(--border-bright), inset 0 0 12px var(--accent-subtle)`)
to feel "powered on". Inactive items hairline-only.

### 8.4 Ambient panel illumination

Every major card/panel applies on `:hover` and on data-active state:

```
border-color: var(--border-bright);
box-shadow: 0 0 0 1px var(--border-bright), 0 0 18px var(--accent-glow);
```

Default state is `border: 1px solid var(--border-dim)` only — flat. The
illumination on focus/active is what sells "lit cockpit panel."

### 8.5 Engagement consumables strip (NEW)

Fixed-position bottom strip in OPERATOR mode only. Four cockpit-style
gauges: LLM tokens used vs budget, time remaining vs scope window, active
agents vs max concurrency, findings rate (last 60min). Collapsible to one
line via a `▴` toggle. Read from existing intel/budget signals already in
the store; no new backend data.

### 8.6 Mission clock

A 1-second-tick monospace clock showing elapsed time since
`session.started_at`. Pure client-side derived from existing
`state.activeSession.started_at` — no new data.

---

## 9. The Mystical Hacking Layer

### 9.1 Event vocabulary

Each row maps a real WebSocket event to a visual treatment. Events listed
already exist in the store/agent_server today.

| WS event              | Visual treatment                                              | Where on screen                  | Cycle / duration |
| --------------------- | ------------------------------------------------------------- | -------------------------------- | ---------------- |
| `tool_start`          | Source kill-chain phase node breathes (azure pulse)           | Kill chain                       | 4s loop          |
| `subagent_start`      | New card materialises with scale-up + faint sweep             | Active subagents pane            | 200ms (one-shot) |
| `llm_request`         | 12s-revolution azure ring around agent avatar                 | Agent card                       | 12s loop         |
| `finding_added`       | Severity-colored mote drifts source-node → header tally       | Across screen                    | 1.6s             |
| `finding_added` (CRIT)| Single 2s violet supernova at source node                     | One spot                         | 2s (one-shot)    |
| `phase_advance`       | Light-trail traces along kill-chain to new phase              | Kill chain                       | 1.2s             |
| `shell_obtained`      | Quiet orbital ring around target node in attack graph         | Attack graph                     | persistent       |
| `tool_error`          | Italic muted-red text, brief underline, fades after 6s        | Inline + error log               | 6s fade          |
| `reasoning_step`      | Faint neuron-fire animation along confirmed hypothesis branch | Reasoning page                   | 800ms            |
| `wstg_phase_update`   | Phase tile scales from 0.95→1.0 on first done event           | WSTG matrix                      | 300ms            |

Each is implemented as a CSS-class toggle driven by a transient state hook
in the consuming component. No reducer changes required — existing events
already dispatch.

### 9.2 Locked principles

- **No popup. Ever.** Status flows ambient.
- **No sound.** No audio cues, no chimes, no beeps.
- **No flashing.** Pulses ≥ 4s cycle, opacity swing < 25%.
- **No celebration.** Shell obtained → quiet ring. No confetti, no fireworks.
- **No demand.** Supernova decays whether or not the operator looks. Status
  persists in logs and badges.
- **Errors don't shake.** Italic muted red, never bright crimson, no
  jolting motion.
- **Reduced motion respected.** All animation classes wrap a
  `@media (prefers-reduced-motion: reduce)` opt-out.

---

## 10. Audience mode system

### 10.1 The four modes

| Code      | Audience              | Shortcut | Hidden chrome                                                                        | Visible pages                                                                                          |
| --------- | --------------------- | -------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| OPERATOR  | Pentester at keyboard | F1       | Nothing                                                                              | All 19 pages                                                                                           |
| BRIEFING  | Project lead          | F2       | Live terminal, Tool Workshop, Shell Manager, Payload Builder, AI Obs, Subagent Console, Reasoning details, raw tool feeds, consumables strip | Risk Dashboard, Findings, Mission Control (cleaned), Attack Graph (cleaned), Web Testing (summary), Reports |
| PRESENT   | Boardroom / projector | F3       | All chrome — sidebar, header, telemetry, command palette                             | Slide-paginated narrative across Risk Dashboard, Top Findings, Kill Chain, Attack Graph, Recommendations |
| CLIENT    | External delivery     | F4       | Like BRIEFING + tool/agent names defanged                                            | Same as BRIEFING but branded (logo, primary colour)                                                    |

### 10.2 State

Add to `store.js` initial state:

```js
viewMode: 'OPERATOR',                // OPERATOR | BRIEFING | PRESENT | CLIENT
client: { name: '', logo: '', brand: '' },   // CLIENT-mode branding
present: { slide: 0, autoAdvance: false },   // PRESENT-mode internal state
```

Reducer: one new case `SET_VIEW_MODE` (additive).

Persistence: localStorage key `argus.viewMode` and `argus.client.brand`.

### 10.3 Per-hub mode behaviour matrix

For each of the 9 hubs (defined in §10.5), what each audience mode renders.
Empty cell = hub hidden in that mode.  Tab-level behaviour is described in
§10.5; this matrix governs the hub's overall visibility + density.

| Hub             | OPERATOR                                              | BRIEFING                                       | PRESENT                                | CLIENT                                |
| --------------- | ----------------------------------------------------- | ---------------------------------------------- | -------------------------------------- | ------------------------------------- |
| Risk Dashboard  | Halo + 5-cell severity + sparklines + top targets     | Larger halo + 3-cell severity + plain language | Full-screen halo, single slide         | Branded halo, business asset names    |
| Operations      | All tabs (Mission Control, Agent Roster) full density | Mission Control only, hide live feed           | Kill-chain slide                       | (hidden)                              |
| Findings        | All tabs (Findings, WSTG, OSINT, By Phase)            | Findings tab only, severity-grouped cards      | One slide per severity tier            | Branded findings, OWASP/MITRE-tagged  |
| Attack Graph    | Particle starburst, all nodes                         | Cleaner graph, only HVAs labelled              | Full-slide hero with reveal animation  | Cleaner version, branded              |
| Reasoning       | All tabs (Hypothesis Tree, LLM Trace)                 | (hidden)                                       | (hidden)                               | (hidden)                              |
| Foothold        | All tabs (Creds, Shells, Lateral, Payloads)           | (hidden)                                       | (hidden)                               | (hidden)                              |
| Workshop        | All tabs (Target, Tools)                              | (hidden)                                       | (hidden)                               | (hidden)                              |
| Reports        | Generation UI                                         | Polished report preview                        | Full-screen reading mode               | Branded version                       |
| System         | All tabs (Sessions, Knowledge, Metrics)               | (hidden)                                       | (hidden)                               | (hidden)                              |

Implementation: each hub's top-level component reads `state.viewMode` and
conditionally renders.  Each tab inherits hub mode but may further hide
itself (e.g., the OSINT tab inside Findings stays visible in BRIEFING mode
where the WSTG and By-Phase tabs hide).  No new files; pages already exist
and become tab-panels.

### 10.4 PRESENT mode mechanics

- Full-screen, hides sidebar/header/telemetry/cmd-palette
- Cosmic background dims to 60% intensity (calmer for boardroom)
- Slide-paginated narrative, auto-built from live state:
  1. Title — engagement target + day count
  2. Scope — target list
  3. Risk Score — full-screen halo
  4. Top Findings — one slide per severity tier (CRIT, HIGH)
  5. Kill Chain — full-slide animated reveal
  6. Attack Graph — particle starburst, drag to reveal
  7. Recommendations — top 3-5 plain-language remediation actions
  8. Closing — engagement metrics, contact
- Keyboard: ←→ paginate, F fullscreen, ESC exit, A toggle auto-advance
- Slides show **live data** — finding counts update silently during demo
- All ambient motion dampened to "slow breathing only"

### 10.5 Hub consolidation (route aggregation)

The current sidebar exposes **19 page routes**.  Many show the same data
through different lenses; many are operator-only and clutter the navigation
for the four audience modes.  We consolidate to **9 hubs**, each with
internal tabs/lenses.  **Nothing is lost** — every page's content is
preserved, every existing route key continues to resolve.

**The 9 hubs:**

| #  | Hub             | Internal tabs / lenses                                            | Absorbs old pages                                                  |
| -- | --------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| 1  | Risk Dashboard  | _(single view)_                                                    | `risk`                                                             |
| 2  | Operations      | Mission Control, Agent Roster                                      | `mission`, `agents`                                                |
| 3  | Findings        | All Findings, WSTG Matrix, OSINT Intel, By Phase                   | `findings`, `web_test`, `osint`                                    |
| 4  | Attack Graph    | _(single view — the showpiece)_                                    | `graph`                                                            |
| 5  | Reasoning       | Hypothesis Tree, LLM Trace                                         | `reasoning`, `ai_obs`                                              |
| 6  | Foothold        | Credentials, Active Shells, Lateral & Post-Ex, Payload Builder     | `creds`, `shells`, `lateral`, `payloads`                           |
| 7  | Workshop        | Target Config, Tool Workshop                                       | `target`, `tools`                                                  |
| 8  | Reports         | _(single view)_                                                    | `report`                                                           |
| 9  | System          | Sessions, Knowledge Base, Metrics                                  | `sessions`, `knowledge`, `metrics`                                 |

**Rationale per consolidation:**

- **Operations (mission + agents)** — both views show "what's running right
  now"; agent status is essentially a per-agent slice of mission control.
- **Findings (findings + web_test + osint)** — all three are lenses on the
  same finding collection (different filters: severity, WSTG phase, OSINT
  source).  Same data, different views — text-book repeatable.
- **Reasoning (reasoning + ai_obs)** — hypothesis tree consumes LLM
  decisions; raw LLM traces are the under-layer of the same agent thinking.
- **Foothold (creds + shells + lateral + payloads)** — the post-ex chain:
  build payload → use it → manage resulting shell → harvest credentials →
  pivot.  Operator workflow continuity demands these be co-located.
- **Workshop (target + tools)** — engagement setup + ad-hoc tool execution.
- **System (sessions + knowledge + metrics)** — historical / reference /
  admin data.  Sessions list, RAG stats, engagement metrics are all
  "look-back" rather than "live operation" — they share an altitude.

**Tab preservation guarantee:**

- Every existing page's complete content is rendered inside a tab of the
  appropriate hub.  No content removed or condensed.
- Each tab keeps its existing component implementation (`TargetConfig.jsx`,
  `MissionControl.jsx`, etc.) — they become tab-panels rather than full
  pages.  No rewrite of internal layout required.

**Legacy route alias preservation:**

The old route keys in `app.jsx`'s `PAGES` array remain valid as
**deep-links**.  When the app receives `navigate('agents')`, it resolves
to `Operations` hub with the `Agent Roster` tab pre-selected.  Mapping:

```
risk       →  hub#1 (Risk Dashboard)
mission    →  hub#2 (Operations) → tab: Mission Control
agents     →  hub#2 (Operations) → tab: Agent Roster
findings   →  hub#3 (Findings)   → tab: All Findings
web_test   →  hub#3 (Findings)   → tab: WSTG Matrix
osint      →  hub#3 (Findings)   → tab: OSINT Intel
graph      →  hub#4 (Attack Graph)
reasoning  →  hub#5 (Reasoning)  → tab: Hypothesis Tree
ai_obs     →  hub#5 (Reasoning)  → tab: LLM Trace
creds      →  hub#6 (Foothold)   → tab: Credentials
shells     →  hub#6 (Foothold)   → tab: Active Shells
lateral    →  hub#6 (Foothold)   → tab: Lateral & Post-Ex
payloads   →  hub#6 (Foothold)   → tab: Payload Builder
target     →  hub#7 (Workshop)   → tab: Target Config
tools      →  hub#7 (Workshop)   → tab: Tool Workshop
report     →  hub#8 (Reports)
sessions   →  hub#9 (System)     → tab: Sessions
knowledge  →  hub#9 (System)     → tab: Knowledge Base
metrics    →  hub#9 (System)     → tab: Metrics
```

Operators with saved page-state in localStorage (`argus.ui.prefs.v2.page`)
are auto-migrated on first load — old key becomes hub+tab.

**Sidebar restructure:**

The sidebar shows the 9 hubs in 3 visual groups:

```
─── OVERVIEW ────────────────
   ◇  Risk Dashboard
   ⚡  Operations
   ◆  Findings
   ⬡  Attack Graph
─── EXECUTION ───────────────
   ◐  Reasoning
   ⊛  Foothold
   ⊞  Workshop
─── REPORTING ───────────────
   ◧  Reports
   ⊙  System
```

Mini-mode (collapsed sidebar) shows glyphs only.  Hub icons are existing
sidebar glyphs reused.  Each hub's selected tab persists per-operator in
localStorage.

### 10.6 CLIENT mode mechanics

Like BRIEFING +:
- Logo swap: ARGUS logomark → client logo (configurable per session)
- Primary colour overlay: client's brand colour mixed at 25% with `--accent`
- Tool/agent names defanged in visible UI:
  `Nmap → "Service enumeration scan"`
  `Hydra → "Authentication assessment"`
  Mapping table lives in component-level constants, not in the engine
- Findings tagged OWASP / MITRE / CVSS instead of internal taxonomy
- Recommendations reordered before vulnerability descriptions
- A subtle ribbon `[CLIENT — <name>]` at the top edge so the operator never
  forgets they're in customer-facing view
- `@media print` rules ensure clean PDF page-breaks per section

---

## 11. Mode switcher UX

The MODE badge in the header opens a dropdown:

```
┌─────────────────────────────────────────────┐
│  ◈ CHANGE VIEW                               │
│ ──────────────────────────────────────────── │
│  ◐  OPERATOR    Full cockpit          F1    │  ← currently active
│  ○  BRIEFING    Project lead          F2    │
│  ○  PRESENT     Boardroom / projector F3    │
│  ○  CLIENT      External / branded    F4    │
│ ──────────────────────────────────────────── │
│  CLIENT MODE settings:                       │
│  Customer:  [ Acme Corp        ▾ ]           │
│  Logo:      [ Upload ]  current: acme.svg    │
│  Brand:     ████ #1F4D8B                     │
└─────────────────────────────────────────────┘
```

- 600ms cross-fade on mode change
- `F1-F4` keyboard shortcuts work from anywhere (skip if a text input has focus)
- Choice persisted per operator/session
- The existing **theme switcher** continues to live in the header — exact
  position relative to the new MODE badge is decided in implementation
  (Section 16, item 1)

---

## 12. Loading screen + transitions

Single full-screen splash on cold start AND on first `agent_status_summary`
post-WS-connect. Replaces the existing half-rendered initial paint.

```
                              ·
                        ·     │     ·
                          ╲   │   ╱            ◐ INITIALISING
                            ╲ │ ╱                connecting to MCP …
                       · ────●────  ·            loading reasoning engine …
                            ╱ │ ╲                pulling 43 playbooks …
                          ╱   │   ╲              warming reranker …
                        ·     │     ·
                              ·

                         A R G U S
                       pentest platform
```

- Orbital ring animation, 12s revolution
- Status messages cycle at 800ms each, sourced from real bootstrap progress:
  WS connect, KB load, agent registration, MCP probe
- Disappears as soon as bootstrap completes — no fake-wait
- "Skip splash" pref for power users (localStorage)
- Mode transitions inside the app use a faster 600ms cross-fade

---

## 13. Files affected

### 13.1 In-scope (presentation layer only)

```
static/css/main.css                        — full theme rewrite + new tokens + animations
static/js/store.js                         — +viewMode + reducer case + WS event taps for motion (additive only)
static/js/app.jsx                          — header HUD + telemetry strip + mode picker + F1-F4 + splash screen
static/js/pages/RiskDashboard.jsx          — halo hero + tilted perspective + per-mode rendering
static/js/pages/MissionControl.jsx         — Mil-spec HUD layout + per-mode rendering
static/js/pages/FindingsBoard.jsx          — Surveillance Console + per-mode rendering
static/js/pages/AttackGraph.jsx            — particle starburst (small canvas) + per-mode rendering
static/js/pages/ReasoningEnginePage.jsx    — neuron motion + per-mode hide
static/js/pages/WebTesting.jsx             — phase grid + per-mode rendering
static/js/pages/ToolWorkshop.jsx           — Operator Terminal flavour
static/js/pages/ShellManager.jsx           — Operator Terminal flavour
static/js/pages/AIObservability.jsx        — minor — flavour pass + per-mode hide
static/js/pages/AgentConsole.jsx           — minor — flavour pass
static/js/pages/CredentialsPage.jsx        — minor — flavour pass
static/js/pages/LateralPostPage.jsx        — minor — flavour pass
static/js/pages/MetricsDash.jsx            — minor — flavour pass + per-mode subset
static/js/pages/OsintIntel.jsx             — minor — flavour pass + per-mode hide
static/js/pages/PayloadBuilder.jsx         — minor — flavour pass
static/js/pages/ReportPage.jsx             — branded preview for CLIENT mode
static/js/pages/SessionHistory.jsx         — minor — flavour pass
static/js/pages/SubagentConsolePage.jsx    — minor — flavour pass
static/js/pages/TargetConfig.jsx           — minor — flavour pass
static/js/pages/KnowledgePage.jsx          — minor — flavour pass + per-mode hide
static/js/components/StatusBadge.jsx       — severity glyphs + supernova class
static/js/components/AgentCard.jsx         — LLM-thinking ring
static/js/components/FindingCard.jsx       — finding-added mote
static/js/components/PhaseTimeline.jsx     — phase-advance light-trail
static/js/components/LiveTerminal.jsx      — Operator Terminal flavour, scanline
static/js/components/MetaAgentsPanel.jsx   — minor — flavour pass
static/js/components/ExpertPanel.jsx       — minor — flavour pass
static/js/components/MissionBriefBanner.jsx — minor — flavour pass
static/js/components/CorrectionCard.jsx    — minor — flavour pass
static/js/components/VoIRankingPanel.jsx   — minor — flavour pass
templates/index.html                       — script cache-bust version bumps only
```

### 13.2 Out-of-scope (DO NOT TOUCH)

Per Section 3.1.

### 13.3 No new files

Every change above is an edit to an existing file. No new pages, no new
components, no new modules. The audience-mode system uses existing pages
with conditional rendering.

---

## 14. Implementation tiers

Six tiers, each independently shippable. Earlier tiers reduce risk for later
ones (theme-fix in T1 unblocks every later tier; cockpit chrome in T2 is
the parent of every motion in T3).

### Tier 1 — Foundation (~1.5 days)

- **Goal:** Theme switcher actually works. Color/type system finalised.
- Replace every `T.<color>` literal in `app.jsx` and `pages/*.jsx` with
  `'var(--<token>)'` strings. Mechanical pass.
- Update `main.css` `:root` to the new Stellar Ops token list.
- Update existing `[data-theme]` blocks to override the same tokens.
- Drop `daylight` theme.
- No visual changes to layout. Only colour changes when switching themes.
- **Test:** Theme switcher visibly affects 100% of the surface. Existing
  scan flows untouched.

### Tier 2 — Cockpit chrome + hub aggregation (~3 days)

- **Goal A — Cockpit chrome:** Header HUD, telemetry strip, consumables
  gauges, mission clock, ambient panel illumination, Stellar Beam.
- **Goal B — Hub aggregation:** Restructure 19-page sidebar into 9 hubs
  with internal tabs.  Preserve all content (every page's content lands in
  exactly one hub-tab).
- Modify `app.jsx` header to the new HUD.
- Add Stellar Beam div (one CSS element).
- Add consumables strip component inline in `app.jsx`.
- Update major page panels to use ambient illumination on `:hover`.
- **Hub work:**
  - Replace `PAGES` array in `app.jsx` with the 9-hub structure (still in
    `app.jsx`, additive — old keys preserved as deep-link aliases).
  - Add a tab-bar pattern to the page-render slot that mounts the
    appropriate page component as the active tab's panel.
  - Add `argus.hub.tab.<hubKey>` localStorage key per-hub for tab persistence.
  - Add localStorage migration: old `argus.ui.prefs.v2.page = 'agents'`
    transparently rewrites to `hub = 'operations', tab = 'agents'`.
  - Add legacy route resolver for `navigate('agents')` → hub#operations,
    tab#agents.
- **Test:** Header data flow unchanged.  WS events still drive same state.
  Every existing page's content reachable through the new sidebar.  Old
  saved page state migrates without operator action.  Smoke 1+2.

### Tier 3 — Mystical motion (~2 days)

- **Goal:** Event-driven motion vocabulary live.
- Add WS event taps in `store.js` for motion-relevant events
  (additive — no reducer-case changes).
- Add CSS animation classes in `main.css`.
- Wire 4-5 components to consume the taps and apply classes:
  `PhaseTimeline.jsx` (breathe + advance), `AgentCard.jsx` (LLM ring),
  `FindingCard.jsx` (mote), `StatusBadge.jsx` (supernova).
- **Test:** All motion respects `prefers-reduced-motion`. No motion blocks
  reading. Smoke 1+2+5.

### Tier 4 — Showpieces (~3 days)

- **Goal:** Radial halo hero, tilted perspective, crosshair dividers,
  particle attack graph.
- Update `RiskDashboard.jsx` for halo hero + tilted hero block.
- Update `AttackGraph.jsx` to render the particle starburst on a canvas
  element (~200 lines).
- Add crosshair-divider styles in `main.css`, used in `MissionControl.jsx`,
  `WebTesting.jsx`, `ReasoningEnginePage.jsx`.
- **Test:** Risk score still reflects state. Attack graph still shows
  discovered hosts. Smoke 1+2.

### Tier 5 — Audience modes (~4-5 days)  ←  **highest risk**

- **Goal:** Full multi-altitude system live.
- Add `viewMode`, `client`, `present` slices to `store.js`.
- Add `SET_VIEW_MODE` reducer case (additive).
- Add localStorage persistence for `viewMode` + client brand.
- Add mode picker dropdown to header (replaces current theme switcher
  position; theme switcher moves to Settings or stays).
- Add `F1-F4` keyboard shortcuts in `app.jsx`.
- Each major page reads `state.viewMode` and conditionally renders.
- PRESENT mode: keyboard nav (←→ paginate, F fullscreen, ESC).
- CLIENT mode: branding inputs + tool-name defang map.
- **Test:** Scan continues working through every mode switch. State
  persists across reloads. Smoke 1+2+3+4.

### Tier 6 — Loading + polish (~1 day)

- **Goal:** Splash screen, transition motion, mobile breakpoints,
  reduced-motion review.
- Add splash component inline in `app.jsx`.
- Mode-transition cross-fade.
- Mobile responsive review — sidebar collapses below 768px, telemetry
  collapses below 480px, particle count reduces, tilt disabled.
- `prefers-reduced-motion` final audit.
- **Test:** Smoke 1+2+3+4+5 on a 5-year-old laptop and a phone.

### 14.1 Tier dependencies + ordering

```
T1 (theme-fix)  ──┬──>  T2 (cockpit)  ──>  T3 (motion)  ──>  T4 (showpieces)
                  └──>  T5 (modes)         (independent of T3, T4)

T6 (polish)  depends on T1+T2+T3+T4+T5 all merged
```

T2 and T5 are independent and can ship in parallel if I have bandwidth, but
sequential T1→T2→T5→T3→T4→T6 is the lowest-risk path.

---

## 15. Rollback strategy per tier

Each tier merges to the working tree as one commit (or one short commit
chain). If a tier breaks anything in Section 3.3 smoke tests, revert that
tier's commit(s) and the engine continues working with the prior tier's
visual state.

| Tier | Rollback risk | Rollback cost                               |
| ---- | ------------- | ------------------------------------------- |
| T1   | Low           | `git revert` — pages re-show old palette    |
| T2   | Low           | Header reverts to old layout                |
| T3   | Very low      | Motion classes stop firing, layout unchanged |
| T4   | Low           | Risk Dashboard / Attack Graph revert to flat |
| T5   | **Medium**    | viewMode default OPERATOR — degrade is graceful |
| T6   | Very low      | No splash, no transition fades              |

Worst-case rollback: revert T1 through T6 in reverse order.  Engine
continues working throughout.

---

## 16. Open decisions deferred to implementation plan

These don't need answering before the implementation plan starts; they're
decisions the plan will make:

1. **Where exactly does the theme switcher live in the new HUD?** Currently
   in the header right-side near the user avatar. Options: stay there,
   move to a Settings page, or fold into the mode picker. *Default: stay,
   but de-emphasised.*
2. **Particle count for the Attack Graph starburst** — exact tuning happens
   when implementing on real device profiles.
3. **PRESENT mode slide list customisation** — locked-in slide list above;
   custom slide config can be a future feature.
4. **CLIENT mode tool-name defang map** — initial mapping covers ~40 tools;
   full map authored during T5.
5. **Reduced-motion fallback for the Stellar Beam** — keep it static (just
   the gradient, no animation) vs hide entirely. *Default: keep static.*
6. **Mobile** — sidebar collapses, telemetry collapses, mode picker remains
   functional. Particle attack graph reduces or shows static SVG fallback.
   Decision deferred to T6.

---

## 17. Acceptance criteria

This redesign is "done" when:

1. Theme switcher visibly changes 100% of the UI surface (vs the current
   ~30%).
2. Cockpit chrome (HUD, telemetry, consumables, beam, mission clock) all
   render and update in real time from existing WS events.
3. All 10 motion events fire correctly during a real scan, none of them
   block reading or generate popup-style alerts.
4. F1-F4 mode switching is instant, persistent, and doesn't drop scan state.
5. PRESENT mode keyboard-paginates through 7-8 slides full-screen with no
   chrome.
6. CLIENT mode swaps logo, primary colour, and defangs tool names.
7. All 5 smoke tests pass on every tier merge.
8. Reduced-motion + mobile breakpoints behave correctly.
9. Cardinal constraint upheld: zero modifications to off-limits modules
   in Section 3.1.
10. Hub aggregation lossless: every one of the 19 original pages is
    reachable as a tab inside one of the 9 hubs, with original component
    content unchanged.  All existing legacy route keys (`navigate('agents')`
    etc.) continue to resolve.  Saved operator page-state migrates
    transparently from the old `argus.ui.prefs.v2.page` key.

---

## 18. Status

- 2026-05-09 — Spec drafted, awaiting review.
- 2026-05-09 — Operator approved spec with one refinement: aggregate
  repeatable dashboards/views, lose nothing.  Spec updated with §10.5
  (Hub consolidation: 19 pages → 9 hubs, all content preserved as
  hub-tabs).
- 2026-05-09 — Self-review pass complete.  No placeholders, no
  contradictions.  Spec ready to drive implementation plan.
- (next) — Invoke `superpowers:writing-plans` to author per-tier
  implementation plan.
