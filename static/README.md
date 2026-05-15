# ARGUS Frontend

> The operator cockpit · 22 pages, 12 shared components, 18 skins,
> zero build step.

The ARGUS UI is a React 18 single-page app served by the FastAPI backend
at `/`. It runs **without a build pipeline** — Babel-standalone compiles
JSX in the browser on first load, then the result is cached. This trades
a small first-paint cost for a vastly simpler operator-deployment story
(no Node toolchain, no `npm install`, no bundling, no source maps to
manage in production).

```
templates/index.html
   │
   ├─ <link rel="stylesheet" href="/static/css/main.css">
   │   • base tokens, layout, default ("Stellar") skin
   ├─ <link id="argus-skin" rel="stylesheet" href="...">
   │   • runtime-swappable skin overlay — 17 alternatives
   │
   ├─ vendor (React 18 + antd + dayjs + d3 + xterm + babel-standalone)
   ├─ /static/js/api.js          ← thin fetch wrapper, baseURL config
   ├─ /static/js/store.js        ← global state (reducer + provider)
   ├─ /static/js/components/*    ← shared widgets
   ├─ /static/js/pages/*         ← top-level views (hub/tab targets)
   ├─ /static/js/skins/*         ← lazy modules (WebGL Three.js scene)
   └─ /static/js/app.jsx         ← router + AuthBoundary + cockpit shell
```

---

## Contents

1. [Quick mental model](#quick-mental-model)
2. [Folder layout](#folder-layout)
3. [Bootstrap order (why this matters)](#bootstrap-order-why-this-matters)
4. [Pages](#pages)
5. [Components](#components)
6. [State management](#state-management)
7. [Auth integration](#auth-integration)
8. [Skin system](#skin-system)
9. [Audience modes](#audience-modes)
10. [Adding a new page](#adding-a-new-page)
11. [Adding a new component](#adding-a-new-component)
12. [Performance notes](#performance-notes)
13. [Browser support](#browser-support)
14. [Why no build step?](#why-no-build-step)

---

## Quick mental model

```
┌──────────────────────────────────────────────────────────────┐
│ AuthBoundary                                                 │
│   • fetches /auth/me on boot                                 │
│   • if 401 → render <LoginPage>                              │
│   • if 200 → hydrate session_state + render cockpit          │
│   • if 404 → bypass (auth module not installed)              │
│ │                                                            │
│ ▼                                                            │
│ <App> ── header ── sidebar (Hub list) ── content (active Tab)│
│                                                              │
│   Header chips:                                              │
│     [Engagement clock]  [MCP status]  [HUD telemetry]        │
│     [Critical badge]  [ModePicker]  [SkinChooser]            │
│     [ThemeSwitcher]  [UserChip]                              │
│                                                              │
│   Sidebar:                                                   │
│     OVERVIEW   ┐                                             │
│     ANALYSIS   │── 10 hubs · per-mode visibility             │
│     EXECUTION  │   (Risk · Operations · Findings · Graph ·   │
│     REPORTING  │    Reasoning · Foothold · Workshop ·        │
│                │    Reports · System · Users & Access)       │
│     User-pinned engagement card                              │
│                                                              │
│   Content:                                                   │
│     hub-tabbar + active page rendered                        │
└──────────────────────────────────────────────────────────────┘
```

All UI state (skin, audience mode, sidebar collapse, current
hub/tab, hub-tab memory, pinned engagement) is **per-user**, persisted
both to `localStorage` (write-through cache) and to the auth DB
(source of truth). State follows the operator across devices.

---

## Folder layout

```
static/
├── README.md                        ← this file
├── api.js                           ← fetch wrapper
├── app.jsx                          ← bootstrap + AuthBoundary + App shell
├── store.js                         ← global state + reducer + provider
│
├── components/   12 shared widgets
│   ├── AgentCard.jsx                ← live agent activity tile
│   ├── CorrectionCard.jsx           ← operator-correction proposal
│   ├── ExpertPanel.jsx              ← per-domain expert suggestions
│   ├── FindingCard.jsx              ← severity-tinted finding tile
│   ├── LiveTerminal.jsx             ← xterm.js shell PTY view
│   ├── MetaAgentsPanel.jsx          ← meta-agent orchestration panel
│   ├── MfaChallenge.jsx             ← cinematic TOTP / backup-code form
│   ├── MissionBriefBanner.jsx       ← top-of-page engagement context
│   ├── PhaseTimeline.jsx            ← horizontal phase progress bar
│   ├── SkinChooser.jsx              ← family-grouped 18-skin picker
│   ├── StatusBadge.jsx              ← idle/active/error pill
│   └── VoIRankingPanel.jsx          ← value-of-information ranking
│
├── pages/        22 top-level views (mounted via HUBS[] in app.jsx)
│   ├── AIObservability.jsx          ← LLM trace + token / cost view
│   ├── AgentConsole.jsx             ← agent roster + status
│   ├── AttackGraph.jsx              ← interactive attack-path graph
│   ├── CredentialsPage.jsx          ← harvested creds vault
│   ├── FindingsBoard.jsx            ← findings table + severity filters
│   ├── KnowledgePage.jsx            ← RAG query + corpus browser
│   ├── LateralPostPage.jsx          ← lateral movement + post-ex
│   ├── LoginPage.jsx                ← cinematic landing + SSO entry
│   ├── MetricsDash.jsx              ← engagement metrics dashboard
│   ├── MissionControl.jsx           ← live cockpit (default view)
│   ├── OsintIntel.jsx               ← OSINT findings explorer
│   ├── PayloadBuilder.jsx           ← payload + encoder ladder UI
│   ├── ReasoningEnginePage.jsx      ← hypothesis-tree viewer
│   ├── ReportPage.jsx               ← report generation + export
│   ├── RiskDashboard.jsx            ← default landing for managers
│   ├── SessionHistory.jsx           ← past engagement list
│   ├── ShellManager.jsx             ← active reverse-shell tiles
│   ├── SubagentConsolePage.jsx      ← live sub-agent activity
│   ├── TargetConfig.jsx             ← new-engagement wizard
│   ├── ToolWorkshop.jsx             ← manual tool invocation
│   ├── UserAdminPage.jsx            ← users · sessions · audit · IdP · SCIM
│   └── WebTesting.jsx               ← OWASP WSTG matrix view
│
├── skins/        webgl_scene.js (lazy-loaded for Spatial-3D skin)
│
├── css/
│   ├── main.css                     ← tokens + base + Stellar default
│   ├── skins/                       ← 18 runtime-swappable skins
│   │   ├── README.md
│   │   ├── apollo.css      ← Mission Control / NASA terminal
│   │   ├── tactical.css    ← Palantir Gotham / Anduril Lattice
│   │   ├── bloomberg.css   ← Amber terminal / trading floor
│   │   ├── glass.css       ← visionOS hyperreal glass
│   │   ├── editorial.css   ← Stripe Press magazine layout
│   │   ├── webgl.css       ← spatial 3D overlay
│   │   ├── veteran.css     ← greybeard operator
│   │   ├── novice.css      ← junior pentester
│   │   ├── genz.css        ← vaporwave cyberpunk
│   │   ├── redcell.css     ← blood-red offensive ops
│   │   ├── hunter.css      ← bug-bounty $$$
│   │   ├── ctf.css         ← gamified capture-the-flag
│   │   ├── auditor.css     ← read-only evidence
│   │   ├── manager.css     ← PM dashboard
│   │   ├── executive.css   ← C-suite boardroom
│   │   ├── cfo.css         ← finance lens
│   │   └── legal.css       ← compliance + framework strips
│   └── …
│
└── vendor/       prebuilt third-party libraries (no CDN runtime dep)
    ├── react.production.min.js · react-dom.production.min.js
    ├── babel.min.js              ← JSX → JS at runtime
    ├── antd.min.js · antd.reset.min.css
    ├── dayjs.min.js · d3.min.js · icons.umd.js
    └── xterm.min.js · xterm.min.css
```

---

## Bootstrap order (why this matters)

Babel-standalone compiles `<script type="text/babel">` tags **in
DOM order**. Files that expose `window.<X>` (e.g. `window.LoginPage`,
`window.SkinChooser`, `window.StoreProvider`) must load **before**
their first consumer.

The canonical load order in `templates/index.html`:

```
1. vendor/   (React, antd, dayjs, d3, xterm, babel — plain <script>)
2. api.js + store.js                 (no JSX, but conventionally first)
3. components/*                      (each defines window.<Component>)
4. SkinChooser + MfaChallenge        (must precede LoginPage)
5. pages/LoginPage.jsx               (must precede app.jsx)
6. pages/UserAdminPage.jsx
7. pages/RiskDashboard.jsx … pages/* (defined LAZILY via getters in app.jsx)
8. app.jsx                           (LAST — boots the React tree)
```

When you add a page that another component imports (rare), bump its
load position above its consumer.

Every file has a `?v=N` cache buster — bump the version when you change
a file so existing browsers re-fetch.

---

## Pages

Each page is mounted into the routing system via the `HUBS[]` array in
`app.jsx`. A hub is a sidebar entry; a hub has one or more tabs; each
tab renders a page. The router signature:

```js
const HUBS = [
  { key: 'risk', icon: '◇', label: 'Risk Dashboard', group: 'Overview',
    tabs: [{ key: 'risk', label: 'Risk Score', comp: 'RiskDashboard' }] },
  …
];

const COMP_FOR = {
  RiskDashboard: () => window.RiskDashboard,
  …
};
```

`COMP_FOR` is a map from string name to a getter function so pages can
be lazily resolved AFTER their script has loaded (Babel-standalone is
async).

### Per-mode hub visibility

Some hubs are hidden in BRIEFING / PRESENT / CLIENT modes. Configured
in `HUB_MODE_VISIBILITY` in `app.jsx`:

| Hub | OPERATOR | BRIEFING | PRESENT | CLIENT |
|-----|----------|----------|---------|--------|
| Risk Dashboard | ✓ | ✓ | ✓ | ✓ |
| Operations | ✓ | ✓ | ✓ | — |
| Findings | ✓ | ✓ | ✓ | ✓ |
| Attack Graph | ✓ | ✓ | ✓ | ✓ |
| Reasoning | ✓ | — | — | — |
| Foothold | ✓ | — | — | — |
| Workshop | ✓ | — | — | — |
| Reports | ✓ | ✓ | ✓ | ✓ |
| System | ✓ | — | — | — |
| Users & Access | ✓ | — | — | — |

CLIENT mode also routes tool names through `window.defangToolName()`
which replaces "nmap" / "metasploit" / "mimikatz" etc. with outcome
phrasing ("Service enumeration scan", "Exploitation framework",
"Credential extraction").

---

## Components

12 shared, reusable widgets. Conventions:

- Each file defines `window.<ComponentName>` so it works without ES modules.
- No prop-types runtime check (rely on the FastAPI Pydantic contract).
- Tokens come from CSS custom properties — components inherit the
  active skin automatically.
- Touch-friendly: 36px minimum tap target.

Notable ones:

| Component | What it does |
|-----------|--------------|
| `SkinChooser` | Family-grouped 3-tab picker with live thumbnails of all 18 skins. Persists choice to localStorage + `/auth/me/state`. |
| `LiveTerminal` | xterm.js-backed PTY view. WebSocket multiplexes multiple shell streams. Resizes responsively. |
| `MfaChallenge` | Cinematic 6-cell digit input with auto-submit, paste-handling, countdown ring. Switches to single-input mode for backup codes. |
| `FindingCard` | Severity-tinted card; tooltip shows full evidence chain. Click → opens detail modal. |
| `PhaseTimeline` | Horizontal pill row showing 8 pentest phases. Active phase pulses. |
| `AgentCard` | Live agent activity tile with ETA, current tool, and last finding badge. |
| `VoIRankingPanel` | Value-of-information ranking — surfaces "what's the most informative thing to do next". |

---

## State management

Global state lives in `store.js`. A reducer-based pattern (NOT Redux —
just `useReducer` + Context):

```js
const { state, dispatch } = window.useStore();
// state = { sysStatus, activeSession, findingsSummary, currentPhase,
//           recentFindings, wsConnected, viewMode, client, metrics,
//           currentHub, currentTab, hubTabMemory, activeSubagents,
//           bootComplete, present, ... }
```

Actions:

| Action | Effect |
|--------|--------|
| `SET_HUB_TAB` | Navigate; updates `hubTabMemory[hub]` |
| `SET_VIEW_MODE` | OPERATOR / BRIEFING / PRESENT / CLIENT |
| `SET_BOOT_COMPLETE` | Hide splash screen |
| `SET_CLIENT_BRAND` | CLIENT mode customer name + brand color |
| `SET_ACTIVE_SESSION` | Pin / switch engagement |
| `WS_EVENT` | Apply a live WebSocket event |
| `ADD_FINDING` | Update findings summary + recent list |
| `SET_PHASE` | Update current phase + phase timeline |

UI prefs (skin, theme, sidebar collapse, current hub/tab) are stored
in `localStorage.argus.ui.prefs.v2` AND mirrored to the auth DB via
`PATCH /auth/me/state` (debounced 800 ms).

---

## Auth integration

`AuthBoundary` wraps the cockpit:

```js
root.render(
  React.createElement(AuthBoundary, null,
    React.createElement(window.StoreProvider, null,
      React.createElement(App)
    )
  )
);
```

Three phases:

1. **`checking`** — Show an inline orbital spinner while `GET /auth/me` runs.
2. **`login`** — Render `<LoginPage>` (cinematic). On success, reload.
3. **`authed`** | **`bypass`** — Render the cockpit. (`bypass` is when
   `/auth/me` returns 404, i.e. the auth module isn't installed — the
   platform still boots in dev.)

Once authenticated:
- `window.ArgusAuth.me` is set so any component can read the current user.
- `window.ArgusAuth.logout()` is the canonical sign-out.
- The user's persisted session state (`skin`, `audience_mode`,
  `pinned_pentest_session_id`, …) is hydrated from the server.
- If no skin is saved, the role's default skin is applied
  (OPERATOR → redcell · EXECUTIVE → executive · AUDITOR → auditor · …).

CSRF: state-changing API calls must include the `X-CSRF-Token` header
matching the `argus_csrf` cookie (double-submit pattern). The `authFetch`
helper in `UserAdminPage.jsx` is a reference.

---

## Skin system

See **[`css/skins/README.md`](css/skins/README.md)** for the full catalogue,
authoring guide, and design rationale per skin.

Key points:

- 18 skins · 3 families (Aesthetic · Operator · Management)
- Each skin is a single CSS file in `css/skins/`
- Activation is by `<html data-skin="<id>">` + the `<link id="argus-skin">`
  in `templates/index.html` (href swapped at runtime)
- Skins re-theme via CSS custom properties (`--accent`, `--bg-base`, …)
- The WebGL skin lazy-loads its Three.js scene from `js/skins/webgl_scene.js`

---

## Audience modes

The header `ModePicker` exposes 4 audience modes (F1-F4 hotkeys):

| Mode | Use case | Sidebar | HUD | Header |
|------|----------|---------|-----|--------|
| OPERATOR | Day-to-day red-team work | Full | Full | All chips |
| BRIEFING | Project lead / scrum review | Trimmed | Slimmer | All chips |
| PRESENT | Boardroom / projector | Slide deck | Hidden | Minimal |
| CLIENT | External-facing scoped view | Findings + reports only | Hidden | Customer brand |

PRESENT mode replaces the cockpit body with a 9-slide deck
(`PRESENT_SLIDES` in `app.jsx`). CLIENT mode adds a brand ribbon at
the top of the viewport and defangs tool names.

---

## Adding a new page

1. **Create the file**

   `static/js/pages/MyNewPage.jsx` — define `window.MyNewPage`:

   ```js
   (function () {
     const { useState, useEffect } = React;
     function MyNewPage() {
       return React.createElement('div', { className: 'panel' },
         'Hello ARGUS');
     }
     window.MyNewPage = MyNewPage;
   })();
   ```

2. **Register the script** in `templates/index.html` (cache-busted):

   ```html
   <script type="text/babel" src="/static/js/pages/MyNewPage.jsx?v=1"></script>
   ```

3. **Add to `HUBS[]` and `COMP_FOR`** in `static/js/app.jsx`:

   ```js
   { key: 'mynew', icon: '◆', label: 'My New View', group: 'Analysis',
     tabs: [{ key: 'mynew', label: 'Default', comp: 'MyNewPage' }] }

   const COMP_FOR = {
     …
     MyNewPage: () => window.MyNewPage,
   };
   ```

4. **Optionally set mode visibility** in `HUB_MODE_VISIBILITY`.

5. **Bump `app.jsx?v=N`** in `templates/index.html`.

---

## Adding a new component

Same pattern as pages, just live in `static/js/components/`:

```js
(function () {
  function MyChip({ label }) {
    return React.createElement('span', { className: 'badge' }, label);
  }
  window.MyChip = MyChip;
})();
```

Register the script before its first consumer in `templates/index.html`.

---

## Performance notes

- **Babel compile cost** — once per file per browser session
  (~30 ms each). 35 JSX files → ~1 s one-time. Subsequent loads are
  cached.
- **Vendor JS bundle** — ~1.2 MB (React + antd + d3 + xterm). Served
  from `/static/vendor/` so the browser caches aggressively.
- **WebGL skin** — Three.js (~150 kB) is fetched only when the user
  selects the Spatial 3D skin. Other skins pay zero cost for it.
- **Particle field on the login page** — 130 nodes with O(n²)
  connection check; benchmarked at ~3 ms/frame on a 2018 MacBook Pro.
  Falls back to 40 nodes with `prefers-reduced-motion`.

---

## Browser support

| Browser | Status |
|---------|--------|
| Chrome / Edge ≥ 100 | ✅ tier-1 |
| Firefox ≥ 100 | ✅ tier-1 |
| Safari ≥ 16 | ✅ tier-1 (uses `backdrop-filter`, `color-mix`) |
| Safari < 16 / older iOS | ⚠ skins look flat — `color-mix()` unsupported |
| IE 11 | ✗ not supported |

`color-mix()` is heavily used in the skin token system. Browsers without
support degrade to the raw `--accent` value (not transparent or blended).

---

## Why no build step?

Pentest deployments are often air-gapped, ephemeral, or live on a
short-lived ops-network VM. Requiring Node.js, npm, and a webpack
config there is friction. ARGUS trades the ~1 second first-paint cost
of in-browser Babel compilation for:

- **Zero deployment friction** — `git pull && uvicorn agent_server:app`
- **No dependency drift** — every vendor file is committed to `static/vendor/`
- **Editable in-place** — `vi static/js/pages/MyPage.jsx` works on the
  ops VM; refresh the browser and your change is live
- **Smaller attack surface** — no `node_modules`, no transitive supply chain

When ARGUS is deployed at a scale where the first-paint matters (>1000
operators), drop a `static-build` step in front and serve the compiled
output instead. The whole codebase compiles cleanly with `@babel/cli`
or `esbuild`.

---

*See also: [`auth/README.md`](../auth/README.md) ·
[`static/css/skins/README.md`](css/skins/README.md) ·
[`../README.md`](../README.md)*
