# ARGUS Skin System

> 18 runtime-switchable visual treatments grouped by audience. Every
> operator and stakeholder picks the look that fits them. Pure CSS
> overlays — zero touch to agents, findings, or any backend logic.

The skin system lets one person see the cockpit as a NASA mission
control terminal, another as a Bloomberg trading floor, and a third
as a Stripe-Press magazine — all viewing the same engagement data in
real time. The choice is per-user, persisted to the auth DB, and
follows the operator across devices.

---

## Contents

1. [Quick mental model](#quick-mental-model)
2. [The 18 skins](#the-18-skins)
3. [How a skin is structured](#how-a-skin-is-structured)
4. [Authoring a new skin](#authoring-a-new-skin)
5. [Design tokens reference](#design-tokens-reference)
6. [Skin chooser UI](#skin-chooser-ui)
7. [Cinematic login page](#cinematic-login-page)
8. [Lazy WebGL skin](#lazy-webgl-skin)
9. [Reduced-motion support](#reduced-motion-support)
10. [Testing a new skin](#testing-a-new-skin)

---

## Quick mental model

```
<html data-skin="apollo">     ← active skin attribute
<head>
  <link rel="stylesheet" href="/static/css/main.css">
  <link id="argus-skin" rel="stylesheet" href="/static/css/skins/apollo.css">
</head>
```

`main.css` defines the **default** look (the "Stellar" skin — cosmic
blue cockpit) plus the design-token system every skin overrides. A
skin file is a single CSS file containing one rule for the `:root`
custom properties plus targeted overrides scoped to `[data-skin="<id>"]`.

The browser combines the two via the cascade. Switching a skin at
runtime is just:

```js
window.ArgusSkin.apply('bloomberg');
// 1. <link id="argus-skin"> href ← /static/css/skins/bloomberg.css
// 2. <html data-skin="bloomberg">
// 3. localStorage saved + PATCH /auth/me/state queued
```

No reload. No flicker. The CSS variables propagate to every component
in one frame.

---

## The 18 skins

### Aesthetic (7) — role-neutral visual treatments

| ID | Display | Inspiration | Signature element |
|----|---------|-------------|-------------------|
| `stellar` | Stellar Ops | Default ARGUS look | Cosmic blue + violet glow |
| `apollo` | Apollo | NASA / JPL / SpaceX | Phosphor amber + CRT scanlines + bus-bar status strip |
| `tactical` | Tactical | Palantir Gotham · Anduril Lattice | Topographic contour SVG + classified strip + radar sweep |
| `bloomberg` | Trading Floor | Bloomberg Terminal · TradingView | Amber-on-black + scrolling ticker tape + F1-F12 strip |
| `glass` | Hyperreal Glass | Apple visionOS | `backdrop-filter: blur(40px)` + aurora gradient mesh + hue-shifting orb |
| `editorial` | Editorial | Stripe Press · The Browser | Cream paper + Spectral/EB Garamond serifs + drop caps |
| `webgl` | Spatial 3D | Three.js · Bruno Simon | Full-bleed 3D scene (lazy-loaded) + orbital satellites |

### Operator (6) — for red-team / pentest practitioners

| ID | Persona | Signature element |
|----|---------|-------------------|
| `veteran` | Greybeard (10+ yrs OSCP+) | 11px JetBrains Mono · raw MITRE T-codes · vim hints · zero chrome |
| `novice` | Junior pentester / trainee | Big icons · friendly teal · MITRE → plain English translations · "💡 New here?" footer |
| `genz` | Cyberpunk native | Vaporwave + RGB conic-gradient sweep + glitch FX · "BANGER 🔥 / FIRE / MID" severity labels |
| `redcell` | Pure offensive ops | Blood-red on matte black · Russo One stencil display · crosshair watermark · "OP-SEC" footer |
| `hunter` | Bug-bounty researcher | Gold/amber stack · "P1/P2/P3" tiers · "★ PWN ★" badges on confirmed criticals |
| `ctf` | Capture-the-flag player | Press Start 2P pixel font · synthwave sunset · "500PTS / 200PTS" point labels |

### Management (5) — for oversight / leadership / compliance

| ID | Persona | Signature element |
|----|---------|-------------------|
| `auditor` | Third-party assessor | Read-only cursors on action buttons · evidence-source citation footers · SHA-256 hash watermarks · "EVIDENCE PRESERVED" strip |
| `manager` | Team lead / scrum master | PM-blue dashboard · progress bars · ETA-friendly traffic-light status |
| `executive` | CEO / CISO / Board | 120px display numerals · Crimson Pro serif headlines · QoQ trend arrows · HUD hidden · board-deck margins |
| `cfo` | Finance review | Tabular numerics · `$ cost-of-fix` annotations · financial green up / red down |
| `legal` | GRC / counsel | Legal-pad pale yellow rule lines · PCI/HIPAA/SOX/GDPR/ISO27001 strip · citation chain · "NOT LEGAL ADVICE" disclaimer |

---

## How a skin is structured

Every skin CSS file is composed of the same six sections, in order:

```css
/* ════════════════════════════════════════════════════════════════
   1. @import — Google Font + any vendor type
   ════════════════════════════════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=...');

/* ════════════════════════════════════════════════════════════════
   2. :root[data-skin="<id>"] — token overrides
   ════════════════════════════════════════════════════════════════ */
:root[data-skin="apollo"] {
  --bg-base:          #0A0A0A;
  --accent:           #FFB000;
  --font-display:     'IBM Plex Mono', monospace;
  --radius:           0;
  /* … all design tokens … */
}

/* ════════════════════════════════════════════════════════════════
   3. body — background, scan lines, watermark, etc.
   ════════════════════════════════════════════════════════════════ */
[data-skin="apollo"] body { background: …; }

/* ════════════════════════════════════════════════════════════════
   4. Surfaces — header, sidebar, panels, cards
   ════════════════════════════════════════════════════════════════ */
[data-skin="apollo"] .header { … }
[data-skin="apollo"] .panel  { … }

/* ════════════════════════════════════════════════════════════════
   5. Interactive elements — buttons, inputs, badges, pills
   ════════════════════════════════════════════════════════════════ */
[data-skin="apollo"] button  { … }
[data-skin="apollo"] input   { … }

/* ════════════════════════════════════════════════════════════════
   6. Decorative pseudo-elements — bus strips, watermarks
   ════════════════════════════════════════════════════════════════ */
[data-skin="apollo"] body::before { content: 'BUS-7 · NOMINAL'; … }
```

This structure makes diffing skins easy and lets reviewers focus on
the differentiating block (section 6) without wading through tokens.

---

## Authoring a new skin

```bash
# 1. Pick a unique ID (lowercase, snake_case)
SKIN_ID=spectral

# 2. Copy the smallest existing skin as your starting point
cp veteran.css ${SKIN_ID}.css

# 3. Edit the file — overhaul tokens in section 2, then re-paint
#    surfaces in sections 3-6 to match your design language
```

Then register it in **two** places:

### (a) `static/js/components/SkinChooser.jsx`

Append a new entry to the `SKINS` array:

```js
{ id: 'spectral', family: 'aesthetic', label: 'Spectral',
  tagline: 'High-energy laser look',
  mood: 'Synthwave · neon',
  swatches: ['#0A0A0F', '#9B5DE5', '#00BBF9', '#F15BB5'],
  icon: '✺' },
```

The `family` is one of `aesthetic`, `operator`, or `management`.
`swatches` are the 4 dots shown in the popover thumbnail.

### (b) Bump the SkinChooser version

Edit `templates/index.html`:

```html
<script type="text/babel" src="/static/js/components/SkinChooser.jsx?v=3"></script>
```

That's it. No backend change, no rebuild.

### Design checklist (review before merging a new skin)

- [ ] All 5 severity tints (`--critical`, `--high`, `--medium`, `--low`, `--info`) are discernible from each other in the new palette
- [ ] Tap targets are ≥ 36px (especially for `.auth-stage-card` form controls)
- [ ] Form input focus state is clearly visible
- [ ] Sidebar `[data-active="true"]` row is unambiguous
- [ ] Modal/popover backgrounds are opaque enough to obscure cockpit content
- [ ] Color contrast WCAG AA for body text (`--text-primary` on `--bg-base`)
- [ ] Animations respect `prefers-reduced-motion`
- [ ] No external image URLs (use inline SVG `data:` URIs or `@import` Google Fonts only)
- [ ] No CDN-hosted fonts except `fonts.googleapis.com` (works on most corporate networks)
- [ ] Less than 500 lines of CSS (if longer, the skin is doing too much)

---

## Design tokens reference

Every skin overrides this set. Defaults live in `main.css`.

### Surface layers

| Token | Purpose | Typical value |
|-------|---------|---------------|
| `--bg-base` | Page background | `#04050E` (stellar) · `#0A0A0A` (apollo) |
| `--bg-void` | Deepest layer | `#04050E` |
| `--bg-surface` | Cards on the page | `#0A1023` (stellar) · `#FFFFFF` (light skins) |
| `--bg-panel` | Alias for surface, kept for legacy | same as `--bg-surface` |
| `--bg-elevated` | Above-card surfaces (popovers) | `#0F1832` |
| `--bg-glass` | Frosted glass overlays | `rgba(15,24,50,0.78)` |
| `--bg-sidebar` | Left-rail background | `#060A1A` |

### Borders

| Token | Purpose |
|-------|---------|
| `--border-dim` | Hairline between minor surfaces |
| `--border` | Default panel border |
| `--border-light` | Alias for `--border` |
| `--border-bright` | Hover/focus state |
| `--border-focus` | Input focus ring |

### Accent + secondary

| Token | Purpose |
|-------|---------|
| `--accent` | Primary CTA color |
| `--accent-dim` | Pressed state |
| `--accent-glow` | Hover glow (used in `box-shadow`) |
| `--accent-subtle` | Hover background fill |
| `--cyan` | Secondary accent (charts, severity-info) |
| `--violet` | Third accent (milestones, special highlights) |

### Text

| Token | Purpose |
|-------|---------|
| `--text-primary` | Body text |
| `--text-secondary` | Captions, labels |
| `--text-muted` | Disabled / placeholder |

### Severity (the 5 colors that surface in `<FindingCard>` etc.)

| Token | Default |
|-------|---------|
| `--critical` | `#FF4560` |
| `--high` | `#FF8C42` |
| `--medium` | `#FFC83D` |
| `--low` | `#4ADE80` |
| `--info` | `--accent` |

Each has a matching `*-bg` (background fill at low alpha) and `*-bd`
(border at higher alpha).

### Typography

| Token | Purpose | Example |
|-------|---------|---------|
| `--font-ui` | Body / UI text | `'Inter', system-ui` |
| `--font-display` | Hero numerals, headlines | `'Inter Tight'` |
| `--font-mono` | Code, terminals, telemetry | `'JetBrains Mono'` |

### Geometry

| Token | Default | Used in |
|-------|---------|---------|
| `--radius` | `6px` | small chips |
| `--radius-md` | `8px` | inputs, buttons |
| `--radius-lg` | `10px` | cards |
| `--radius-xl` | `14px` | hero cards |

### Shadows

| Token | Purpose |
|-------|---------|
| `--shadow-sm` | Card resting elevation |
| `--shadow-md` | Hover lift |
| `--shadow-lg` | Modal / popover |

### Transitions

| Token | Default |
|-------|---------|
| `--trans` | `150ms ease` |
| `--trans-slow` | `300ms ease` |

---

## Skin chooser UI

`SkinChooser.jsx` mounts in the cockpit header between the audience-
mode picker and the theme switcher. Its popover groups skins into the
3 family tabs (Aesthetic · Operator · Management), shows a 44×44
gradient thumbnail per skin, swatches, mood, and a 1-line tagline.

The selected skin is:
1. Saved to `localStorage.argus.ui.skin.v1` immediately
2. Applied via `data-skin` attr + `<link>` href swap
3. Mirrored to the auth DB via `PATCH /auth/me/state` (debounced ~800 ms)

On cold boot, `AuthBoundary` hydrates `session_state.skin` from
`/auth/me` and applies it before the cockpit renders, so there's no
flash of the wrong skin.

---

## Cinematic login page

The login page (`pages/LoginPage.jsx`) renders inside a `.auth-stage`
container that ALSO re-themes with the active skin. The composition is:

```
Layer 0 — .auth-stage-mesh         (animated radial gradient mesh, 30s)
Layer 1 — <canvas> ParticleField   (130 nodes + connection lines)
Layer 2 — .auth-stage-overlay      (scan lines + film grain)
Layer 3 — .auth-stage-card         (frosted glass card with the form)
        ├── ARGUS wordmark         (chromatic RGB-split animation)
        ├── Typewriter tagline
        ├── Status strip           (MCP / VECTOR DB / TLS / BUILD)
        ├── Tabs                   (Credentials / Single Sign-On)
        ├── Form                   (bottom-border inputs, gradient submit)
        └── Footer                 (secure-badge + contact-admin hint)
```

The login page works in every skin — Apollo turns it phosphor amber,
Bloomberg turns it terminal amber, Editorial gives it cream-paper
serif elegance, etc. The 18 looks are not just for the cockpit; they
extend to the very first impression.

---

## Lazy WebGL skin

The Spatial 3D skin (`webgl.css`) requires Three.js. To keep the
default load time small, the Three.js scene is **lazy-loaded** only
when the user picks this skin. The script `js/skins/webgl_scene.js`:

- Fetched only when `ArgusSkin.apply('webgl')` runs
- Mounts a full-bleed canvas with a wire-frame icosahedron (target host)
- Orbits 8 octahedron "service satellite" sprites
- Renders a 1,400-particle starfield with additive blending
- Cleans up on `ArgusSkin.apply('<anything-else>')` — tears down GPU memory

Operators who never touch the WebGL skin pay zero perf cost.

---

## Reduced-motion support

All animation-heavy skins observe `prefers-reduced-motion: reduce`:

```css
@media (prefers-reduced-motion: reduce) {
  .auth-stage-mesh,
  .auth-wordmark-mark,
  .auth-wordmark-text::before,
  .auth-wordmark-text::after,
  .auth-cursor,
  .auth-stage-card { animation: none !important; }
}
```

The particle field in `LoginPage.jsx` also reduces from 130 nodes to
40 nodes and disables the animation loop when this preference is set.

---

## Testing a new skin

```bash
# 1. Quick CSS-syntax check (brace balance + selector validity)
node -e "
const fs = require('fs');
const src = fs.readFileSync('static/css/skins/spectral.css', 'utf8');
const noC = src.replace(/\\/\\*[\\s\\S]*?\\*\\//g, '');
const opens = (noC.match(/{/g) || []).length;
const closes = (noC.match(/}/g) || []).length;
console.log('balanced:', opens === closes, '(' + opens + '/' + closes + ')');
"

# 2. Confirm SkinChooser registration
node -e "
const fs = require('fs');
const src = fs.readFileSync('static/js/components/SkinChooser.jsx', 'utf8');
console.log('Registered:', /id: 'spectral'/.test(src));
"

# 3. Open the browser, sign in, pick the skin, walk through each hub
#    + each audience mode (F1-F4). Look for:
#    - unreadable text
#    - invisible focus rings
#    - severity badges that look identical
#    - panels that bleed into the page background
#    - hover effects that don't trigger
```

---

*See also:
[`../../js/components/SkinChooser.jsx`](../../js/components/SkinChooser.jsx) ·
[`../main.css`](../main.css) ·
[`../../README.md`](../../README.md)*
