// ═══════════════════════════════════════════════════════════
// ARGUS Pentest Platform — Root App Shell  (v2 UI revamp)
//
// Goals of this revamp (NO functional changes):
//   • Cleaner information architecture: collapsible sidebar with
//     mini/full modes, accordion groups, and a Risk Dashboard as
//     the new default landing page.
//   • Consolidated header — brand + service status + command-palette
//     trigger + critical-pill.  Removes redundancy with the sidebar
//     active-session widget.
//   • Command palette (Ctrl/Cmd-K) for power-user navigation across
//     17 pages without sidebar scrolling.
//   • Toast container hooks for transient notifications fired by the
//     reducer (TOAST_PUSH).
//
// EVERY existing page is still registered (now via HUBS → tabs → COMP_FOR).
// Every dispatch action and WS handler from store.js is untouched.  This is
// a presentation layer refresh only.
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useCallback, useMemo, useRef } = React;

// ─── Error boundary (unchanged behaviour) ─────────────────────
class PageErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(e) { return { error: e }; }
  render() {
    if (this.state.error) {
      return React.createElement('div', {
        style: { padding: 40, color: 'var(--critical)', fontFamily: 'var(--font-mono)', fontSize: 12 }
      },
        React.createElement('div', { style: { fontSize: 15, marginBottom: 12, fontWeight: 700 } }, '⚠ Page Error'),
        React.createElement('pre', {
          style: {
            background: 'var(--bg-panel)', padding: 14, borderRadius: 8,
            border: '1px solid var(--critical-bd)', whiteSpace: 'pre-wrap',
            wordBreak: 'break-word', fontSize: 11, color: 'var(--text-secondary)', margin: 0
          }
        }, this.state.error?.message || String(this.state.error)),
        React.createElement('button', {
          onClick: () => this.setState({ error: null }),
          style: {
            marginTop: 12, padding: '6px 14px', borderRadius: 6, cursor: 'pointer',
            border: '1px solid var(--critical-bd)', background: 'var(--critical-bg)',
            color: 'var(--critical)', fontSize: 11, fontFamily: 'var(--font-ui)'
          }
        }, '↺ Retry')
      );
    }
    return this.props.children;
  }
}

// ─── Hub structure (Spec §10.5) ──────────────────────────────────
// 9 hubs collapse the previous 19 pages.  Each tab.key preserves the
// ORIGINAL page key so legacy navigate() events keep working.  Every
// existing page component continues to render as a tab-panel — no
// content lost.
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
      { key: 'findings', label: 'All Findings', comp: 'FindingsBoard' },
      { key: 'web_test', label: 'WSTG Matrix',  comp: 'WebTesting' },
      { key: 'osint',    label: 'OSINT Intel',  comp: 'OsintIntel' },
    ] },

  { key: 'graph',      icon: '⬡', label: 'Attack Graph',    group: 'Analysis',
    tabs: [{ key: 'graph', label: 'Attack Graph', comp: 'AttackGraph' }] },

  { key: 'reasoning',  icon: '◐', label: 'Reasoning',       group: 'Execution',
    tabs: [
      { key: 'reasoning', label: 'Hypothesis Tree', comp: 'ReasoningEnginePage' },
      { key: 'ai_obs',    label: 'LLM Trace',       comp: 'AIObservability' },
    ] },

  { key: 'foothold',   icon: '⊛', label: 'Foothold',        group: 'Execution',
    tabs: [
      { key: 'creds',    label: 'Credentials',         comp: 'CredentialsPage' },
      { key: 'shells',   label: 'Active Shells',       comp: 'ShellManager' },
      { key: 'exploit_lab', label: 'Exploit Lab',      comp: 'ExploitLabPage' },
      { key: 'fuzz_lab', label: 'Fuzzing Lab',         comp: 'FuzzingLabPage' },
      { key: 'lateral',  label: 'Lateral & Post-Ex',   comp: 'LateralPostPage' },
      { key: 'payloads', label: 'Payload Builder',     comp: 'PayloadBuilder' },
    ] },

  { key: 'workshop',   icon: '⊞', label: 'Workshop',        group: 'Execution',
    tabs: [
      { key: 'target', label: 'Target Config', comp: 'TargetConfig' },
      { key: 'tools',  label: 'Tool Workshop', comp: 'ToolWorkshop' },
    ] },

  { key: 'reports',    icon: '◧', label: 'Reports',         group: 'Reporting',
    tabs: [{ key: 'report', label: 'Reports', comp: 'ReportPage' }] },

  { key: 'system',     icon: '⊙', label: 'System',          group: 'Reporting',
    tabs: [
      { key: 'sessions',  label: 'Sessions',       comp: 'SessionHistory' },
      { key: 'knowledge', label: 'Knowledge Base', comp: 'KnowledgePage' },
      { key: 'metrics',   label: 'Metrics',        comp: 'MetricsDash' },
    ] },

  // ── Enterprise · User & access management ──
  // RBAC-gated by the backend; the FE renders the hub but the tabs
  // pull data through /auth/admin/* which 403s for non-admin users.
  { key: 'users',      icon: '◭', label: 'Users & Access',  group: 'Reporting',
    tabs: [{ key: 'admin', label: 'User Admin', comp: 'UserAdminPage' }] },
];

// Per-mode hub visibility (Spec §10.3)
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
  users:      { OPERATOR: true,  BRIEFING: false, PRESENT: false, CLIENT: false },
};

function isHubVisible(hubKey, mode) {
  return HUB_MODE_VISIBILITY[hubKey]?.[mode] ?? true;
}

// CLIENT-mode tool-name defang: tool jargon → outcome phrasing (Spec §10.6)
const CLIENT_TOOL_DEFANG = {
  'nmap':         'Service enumeration scan',
  'rustscan':     'Service enumeration scan',
  'masscan':      'Service enumeration scan',
  'hydra':        'Authentication assessment',
  'patator':      'Authentication assessment',
  'crackmapexec': 'AD authentication assessment',
  'sqlmap':       'SQL injection assessment',
  'nuclei':       'Vulnerability fingerprinting',
  'metasploit':   'Exploitation framework',
  'msfconsole':   'Exploitation framework',
  'mimikatz':     'Credential extraction',
  'bloodhound':   'AD topology analysis',
  'impacket':     'AD service interaction',
  'wpscan':       'CMS-specific assessment',
  'enum4linux':   'SMB enumeration',
  'smbclient':    'SMB share enumeration',
  'gobuster':     'Web content discovery',
  'ffuf':         'Web content discovery',
  'feroxbuster':  'Web content discovery',
  'whatweb':      'Web fingerprinting',
};

window.defangToolName = function(name) {
  if (!name) return name;
  const k = String(name).toLowerCase();
  return CLIENT_TOOL_DEFANG[k] || name;
};

// PRESENT mode: 9 slides walking the engagement story (Spec §10.4)
const PRESENT_SLIDES = [
  { id: 'title',   title: 'Engagement Overview' },
  { id: 'scope',   title: 'Scope' },
  { id: 'risk',    title: 'Risk Score' },
  { id: 'crit',    title: 'Critical Findings' },
  { id: 'high',    title: 'High-severity Findings' },
  { id: 'kchain',  title: 'Kill Chain' },
  { id: 'graph',   title: 'Attack Graph' },
  { id: 'recs',    title: 'Recommendations' },
  { id: 'closing', title: 'Closing' },
];

// Map component-name strings to lazy window.<Name> getters.
const COMP_FOR = {
  UserAdminPage:       () => window.UserAdminPage,
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
  ExploitLabPage:      () => window.ExploitLabPage,
  FuzzingLabPage:      () => window.FuzzingLabPage,
  LateralPostPage:     () => window.LateralPostPage,
  PayloadBuilder:      () => window.PayloadBuilder,
  TargetConfig:        () => window.TargetConfig,
  ToolWorkshop:        () => window.ToolWorkshop,
  ReportPage:          () => window.ReportPage,
  SessionHistory:      () => window.SessionHistory,
  KnowledgePage:       () => window.KnowledgePage,
  MetricsDash:         () => window.MetricsDash,
};

// Legacy alias resolver — old navigate('agents') still resolves.
// Returns {hub, tab} or null.
function resolveLegacyKey(legacyKey) {
  for (const h of HUBS) {
    for (const t of h.tabs) {
      if (t.key === legacyKey) return { hub: h.key, tab: t.key };
    }
  }
  return null;
}

const GROUP_ORDER = ['Overview', 'Analysis', 'Execution', 'Reporting'];

const GROUP_COLORS = {
  Overview:  'var(--accent)',
  Analysis:  'var(--cyan)',
  Execution: 'var(--violet)',
  Reporting: 'var(--medium)',
};

// ─── Persistent UI prefs ─────────────────────────────────────
const PREFS_KEY = 'argus.ui.prefs.v2';
function loadPrefs() {
  try { return JSON.parse(localStorage.getItem(PREFS_KEY)) || {}; }
  catch { return {}; }
}
function savePrefs(p) {
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(p)); } catch {}
}

// ─── Themes ─────────────────────────────────────────────────
// Each theme name maps to a `[data-theme="<name>"]` block in main.css.
// `midnight` is the default (no data-attribute).  Users pick from a
// dropdown in the header; the choice is persisted in localStorage.
const THEMES = [
  { id: 'midnight', label: 'Stellar Ops', swatch: '#4FA8FF', desc: 'Default — black/blue cosmos, the core ARGUS aesthetic' },
  { id: 'graphite', label: 'Graphite',    swatch: '#38BDF8', desc: 'Neutral charcoal, cyan accent' },
  { id: 'sapphire', label: 'Sapphire',    swatch: '#4F8DFD', desc: 'Brighter blue, projector-friendly' },
  { id: 'amber',    label: 'Amber',       swatch: '#FFB22A', desc: 'Operator-terminal mono purists' },
  { id: 'contrast', label: 'Contrast',    swatch: '#FFE600', desc: 'High-contrast accessibility' },
];
function applyTheme(id) {
  if (!id || id === 'midnight') {
    document.documentElement.removeAttribute('data-theme');
  } else {
    document.documentElement.setAttribute('data-theme', id);
  }
}

function ThemeSwitcher({ current, onPick }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    function close(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
    if (open) document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);
  const meta = THEMES.find(t => t.id === current) || THEMES[0];
  return React.createElement('div', { ref, style: { position: 'relative' } },
    React.createElement('button', {
      onClick: () => setOpen(o => !o),
      title: 'Switch color theme',
      style: {
        display: 'flex', alignItems: 'center', gap: 7,
        padding: '4px 10px', borderRadius: 18, cursor: 'pointer',
        background: 'var(--bg-panel)', border: `1px solid ${'var(--border-dim)'}`,
        color: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-ui)',
        transition: 'border-color 0.15s, color 0.15s',
      },
      onMouseEnter: e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-primary)'; },
      onMouseLeave: e => { e.currentTarget.style.borderColor = 'var(--border-dim)'; e.currentTarget.style.color = 'var(--text-secondary)'; },
    },
      React.createElement('span', {
        style: {
          width: 10, height: 10, borderRadius: '50%',
          background: meta.swatch, flexShrink: 0,
          boxShadow: `0 0 5px ${meta.swatch}66`,
        }
      }),
      meta.label,
      React.createElement('span', { style: { fontSize: 9, opacity: 0.5 } }, '▾')
    ),
    open && React.createElement('div', {
      style: {
        position: 'absolute', top: 'calc(100% + 6px)', right: 0, zIndex: 1200,
        minWidth: 220, padding: 6, borderRadius: 10,
        background: 'var(--bg-surface)', border: `1px solid ${'var(--border-bright)'}`,
        boxShadow: '0 12px 32px rgba(0,0,0,0.6)',
      }
    },
      React.createElement('div', {
        style: { fontSize: 9, color: 'var(--text-muted)', padding: '6px 10px 8px',
                 letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 700 }
      }, 'Color Theme'),
      THEMES.map(t => {
        const active = t.id === current;
        return React.createElement('div', {
          key: t.id,
          onClick: () => { onPick(t.id); setOpen(false); },
          style: {
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '7px 10px', borderRadius: 7, cursor: 'pointer',
            background: active ? `${t.swatch}15` : 'transparent',
            transition: 'background 0.1s',
          },
          onMouseEnter: e => { if (!active) e.currentTarget.style.background = 'color-mix(in srgb, var(--text-primary) 3%, transparent)'; },
          onMouseLeave: e => { if (!active) e.currentTarget.style.background = 'transparent'; },
        },
          React.createElement('span', {
            style: {
              width: 12, height: 12, borderRadius: '50%',
              background: t.swatch, flexShrink: 0,
              boxShadow: active ? `0 0 8px ${t.swatch}` : 'none',
              border: `1px solid ${t.swatch}80`,
            }
          }),
          React.createElement('div', { style: { flex: 1, minWidth: 0 } },
            React.createElement('div', {
              style: { fontSize: 12, fontWeight: 600, color: active ? t.swatch : 'var(--text-primary)' }
            }, t.label),
            React.createElement('div', {
              style: { fontSize: 10, color: 'var(--text-muted)',
                       overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
            }, t.desc)
          ),
          active && React.createElement('span', {
            style: { color: t.swatch, fontSize: 12 }
          }, '✓')
        );
      })
    )
  );
}

// ─── Audience-mode picker (T5) ──────────────────────────────────
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
    { id: 'OPERATOR', label: 'Operator', desc: 'Full cockpit',          shortcut: 'F1' },
    { id: 'BRIEFING', label: 'Briefing', desc: 'Project lead',          shortcut: 'F2' },
    { id: 'PRESENT',  label: 'Present',  desc: 'Boardroom / projector', shortcut: 'F3' },
    { id: 'CLIENT',   label: 'Client',   desc: 'External / branded',    shortcut: 'F4' },
  ];

  return React.createElement('div', { ref, style: { position: 'relative' } },
    React.createElement('button', {
      className: 'mode-picker-trigger',
      onClick: () => setOpen(o => !o),
    }, `[ ${state.viewMode || 'OPERATOR'} ]`),

    open && React.createElement('div', { className: 'mode-picker-popover' },
      modes.map(m =>
        React.createElement('div', {
          key: m.id,
          className: `mode-picker-row${state.viewMode === m.id ? ' active' : ''}`,
          onClick: () => {
            dispatch({ type: 'SET_VIEW_MODE', payload: m.id });
            if (m.id !== 'CLIENT') setOpen(false);
          },
        },
          React.createElement('span', null, state.viewMode === m.id ? '◐' : '○'),
          React.createElement('div', { style: { flex: 1 } },
            React.createElement('div', { style: { fontWeight: 600 } }, m.label),
            React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } }, m.desc),
          ),
          React.createElement('span', { className: 'mode-picker-shortcut' }, m.shortcut),
        )
      ),

      // CLIENT settings panel — only shown when CLIENT is the current mode
      state.viewMode === 'CLIENT' && React.createElement('div', {
        style: { borderTop: '1px solid var(--border-dim)', padding: 10, marginTop: 6 }
      },
        React.createElement('div', {
          style: { fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: 1 }
        }, 'CLIENT MODE SETTINGS'),
        React.createElement('input', {
          type: 'text',
          className: 'mode-picker-input',
          placeholder: 'Customer name',
          value: state.client?.name || '',
          onChange: e => dispatch({ type: 'SET_CLIENT_BRAND', payload: { name: e.target.value } }),
        }),
        React.createElement('input', {
          type: 'color',
          value: state.client?.brand || '#1F4D8B',
          onChange: e => dispatch({ type: 'SET_CLIENT_BRAND', payload: { brand: e.target.value } }),
          style: { width: '100%', height: 28, padding: 0, border: 'none', cursor: 'pointer' },
        })
      )
    )
  );
}

// ─── HUD telemetry strip ────────────────────────────────────────
// 3 vertical bars: LLM call rate (per-min), active subagent count,
// WS event rate.  Heights animate at 1Hz using transition.  Reads
// defensively from state.metrics — works even when metrics absent.
function HudTelemetry() {
  const { state } = window.useStore();
  const llmRate    = state.metrics?.llm_calls_per_min || 0;
  const toolsCount = (state.activeSubagents || []).length;
  const wsRate     = state.metrics?.ws_events_per_sec || 0;

  const bars = [
    { value: llmRate,    max: 20, label: 'LLM/min' },
    { value: toolsCount, max: 8,  label: 'tools'   },
    { value: wsRate,     max: 30, label: 'evts/s'  },
  ];

  return React.createElement('div', {
    className: 'hud-telemetry',
    title: `LLM ${llmRate}/min · ${toolsCount} active tools · ${wsRate} evt/s`,
  },
    bars.map((b, i) => {
      const pct = Math.min(1, (b.value || 0) / b.max);
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

// ─── Mission clock ──────────────────────────────────────────────
// Pure client-side derived from state.activeSession.started_at.
// Ticks once per second.  Shows "--:--:--" when no session active.
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

// ─── Engagement consumables strip ────────────────────────────────
// 4 cockpit-style gauges at the bottom of the viewport.  Computes
// live values from existing state when the backend isn't emitting
// dedicated `metrics` events yet — so the strip always shows real
// numbers instead of staring at 0% / 100% forever.
//
// Per-gauge danger direction:
//   `asc`  (default): higher pct = worse (LLM tokens, agents, findings rate)
//   `desc`         : lower  pct = worse (TIME REMAIN — 0% = out of time)
function HudConsumables() {
  const { state } = window.useStore();
  const [collapsed, setCollapsed] = useState(false);
  const [now, setNow] = useState(Date.now());

  // 1Hz tick keeps the elapsed/time-remaining gauge live during scans
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const m = state.metrics || {};

  // ── Elapsed time ── derive from activeSession.started_at when the
  // backend hasn't pushed a dedicated metrics event.
  let timeElapsedSec = m.elapsed_sec || 0;
  const startedAt = state.activeSession?.started_at;
  if (!timeElapsedSec && startedAt) {
    timeElapsedSec = Math.max(0, Math.floor((now - new Date(startedAt).getTime()) / 1000));
  }
  const timeWindowSec = m.scope_window_sec
    || state.activeSession?.scope_window_sec
    || 28800;  // 8h default

  // ── LLM tokens — backend should populate, fall back to a rough
  // estimate from comm history if not set.
  let llmTokensUsed = m.llm_tokens_used || 0;
  if (!llmTokensUsed && state.agentComms) {
    // rough estimate: 4 chars ≈ 1 token across all stored LLM comms
    try {
      const totalChars = Object.values(state.agentComms || {})
        .flat()
        .filter(c => c && c.type === 'llm')
        .reduce((sum, c) => sum + ((c.prompt || '').length + (c.response || '').length), 0);
      llmTokensUsed = Math.round(totalChars / 4);
    } catch {}
  }
  const llmTokensBudget = m.llm_tokens_budget || 100000;

  // ── Agents ── live from state.activeSubagents
  const agentsActive = (state.activeSubagents || []).length;
  const agentsMax    = m.max_concurrency || 8;

  // ── Findings rate ── findings per hour
  let findingsRate = m.findings_per_hour || 0;
  if (!findingsRate && timeElapsedSec > 60 && state.findingsSummary) {
    const total = (state.findingsSummary.critical || 0)
                + (state.findingsSummary.high || 0)
                + (state.findingsSummary.medium || 0)
                + (state.findingsSummary.low || 0)
                + (state.findingsSummary.info || 0);
    findingsRate = total / (timeElapsedSec / 3600);
  }

  const gauges = [
    { label: 'LLM TOKENS',  pct: Math.min(1, llmTokensUsed / Math.max(1, llmTokensBudget)),
      direction: 'asc',
      detail: `${formatCompact(llmTokensUsed)} / ${formatCompact(llmTokensBudget)}` },
    { label: 'TIME REMAIN', pct: Math.max(0, 1 - timeElapsedSec / Math.max(1, timeWindowSec)),
      direction: 'desc',
      detail: formatDuration(Math.max(0, timeWindowSec - timeElapsedSec)) },
    { label: 'AGENTS',      pct: Math.min(1, agentsActive / Math.max(1, agentsMax)),
      direction: 'asc',
      detail: `${agentsActive} / ${agentsMax}` },
    { label: 'FINDINGS/h',  pct: Math.min(1, findingsRate / 50),
      direction: 'asc',
      detail: findingsRate ? findingsRate.toFixed(1) : '0' },
  ];

  return React.createElement('div', {
    className: 'hud-consumables',
    'data-collapsed': collapsed,
    onClick: () => setCollapsed(c => !c),
    title: 'Click to collapse/expand engagement consumables',
  },
    gauges.map((g, i) => {
      // danger direction: invert pct for the "desc" semantic so a
      // low % (= bad) lights up the warn/crit colours, not a high one
      const dangerPct = g.direction === 'desc' ? 1 - g.pct : g.pct;
      return React.createElement('div', { key: i, className: 'gauge' },
        React.createElement('span', null, g.label),
        React.createElement('div', { className: 'gauge-bar',
          title: g.detail,
        },
          React.createElement('div', {
            className: 'gauge-fill',
            'data-warn': dangerPct > 0.7,
            'data-crit': dangerPct > 0.9,
            style: { width: `${Math.round(g.pct * 100)}%` },
          })
        ),
        React.createElement('span', { title: g.detail }, g.detail)
      );
    })
  );
}

// ─── Compact formatters used by HudConsumables ──────────────────
function formatCompact(n) {
  if (!n) return '0';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
  return String(n);
}
function formatDuration(sec) {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return m ? `${h}h ${m}m` : `${h}h`;
}

// ─── Service status dot ──────────────────────────────────────
function SvcDot({ label, status, mini = false }) {
  const color = status === 'online' ? 'var(--low)'
    : status === 'offline'          ? 'var(--critical)'
    : 'var(--medium)';
  const isOnline = status === 'online';
  const title = `${label}: ${status || 'unknown'}`;
  if (mini) {
    return React.createElement('span', {
      title,
      style: {
        width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0,
        boxShadow: isOnline ? `0 0 6px ${color}` : 'none',
      }
    });
  }
  return React.createElement('div', {
    title,
    style: {
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '3px 9px', borderRadius: 16,
      background: `${color}10`,
      border: `1px solid ${color}33`,
      fontSize: 10, fontWeight: 600, color,
      fontFamily: 'var(--font-ui)', letterSpacing: 0.4,
      cursor: 'default',
    }
  },
    React.createElement('span', {
      style: {
        width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0,
        boxShadow: isOnline ? `0 0 5px ${color}` : 'none',
      }
    }),
    label
  );
}

// ─── Nav item ────────────────────────────────────────────────
function NavItem({ item, isActive, isCollapsed, onClick }) {
  const [hovered, setHovered] = useState(false);
  const accent = GROUP_COLORS[item.group] || 'var(--accent)';

  return React.createElement('div', {
    onClick,
    onMouseEnter: () => setHovered(true),
    onMouseLeave: () => setHovered(false),
    title: isCollapsed ? `${item.label}${item.desc ? ' — ' + item.desc : ''}` : (item.desc || item.label),
    style: {
      display: 'flex', alignItems: 'center',
      gap: isCollapsed ? 0 : 10,
      margin: '1px 6px',
      padding: isCollapsed ? '8px 0' : '8px 11px',
      justifyContent: isCollapsed ? 'center' : 'flex-start',
      borderRadius: 8, cursor: 'pointer',
      fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: isActive ? 600 : 450,
      letterSpacing: 0.1,
      color: isActive ? accent : hovered ? 'var(--text-primary)' : 'var(--text-secondary)',
      background: isActive
        ? `${accent}14`
        : hovered ? 'color-mix(in srgb, var(--text-primary) 3%, transparent)' : 'transparent',
      borderLeft: isCollapsed
        ? 'none'
        : `2px solid ${isActive ? accent : 'transparent'}`,
      transition: 'all 0.12s ease',
      userSelect: 'none',
      position: 'relative',
    }
  },
    isCollapsed && isActive && React.createElement('span', {
      style: {
        position: 'absolute', left: 0, top: 6, bottom: 6, width: 2,
        background: accent, borderRadius: '0 2px 2px 0',
      }
    }),
    React.createElement('span', {
      style: {
        width: isCollapsed ? 24 : 18, textAlign: 'center', flexShrink: 0,
        fontSize: isCollapsed ? 16 : 13,
        opacity: isActive ? 1 : 0.7,
      }
    }, item.icon),
    !isCollapsed && React.createElement('span', {
      style: { flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
    }, item.label)
  );
}

// ─── Group header ────────────────────────────────────────────
function GroupHeader({ group, color, collapsed, isOpen, onToggle }) {
  if (collapsed) {
    return React.createElement('div', {
      style: {
        height: 1, background: 'var(--border-dim)', margin: '6px 14px',
      }
    });
  }
  return React.createElement('div', {
    onClick: onToggle,
    style: {
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '10px 14px 5px',
      fontSize: 9, letterSpacing: 1.6,
      color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700,
      fontFamily: 'var(--font-ui)', cursor: 'pointer', userSelect: 'none',
    }
  },
    React.createElement('span', {
      style: {
        width: 5, height: 5, borderRadius: '50%',
        background: color, flexShrink: 0,
        boxShadow: `0 0 4px ${color}80`
      }
    }),
    React.createElement('span', { style: { flex: 1 } }, group),
    React.createElement('span', {
      style: {
        fontSize: 10, color: 'var(--text-muted)',
        transform: isOpen ? 'rotate(0deg)' : 'rotate(-90deg)',
        transition: 'transform 0.15s ease',
      }
    }, '▾')
  );
}

// ─── Tool Timeout Modal ──────────────────────────────────────
function ToolTimeoutModal() {
  const { state, dispatch, sendWS } = window.useStore();
  const warn = state.toolTimeoutWarning;

  if (!warn) return null;

  function fmtElapsed(sec) {
    if (!sec || sec < 0) return '0s';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }
  function extend(extraSec) {
    sendWS({ type: 'tool_extend', subagent: warn.subagent, extra_sec: extraSec });
    dispatch({ type: 'TOOL_TIMEOUT_CLEAR' });
  }
  function stopTool() {
    sendWS({ type: 'tool_stop', subagent: warn.subagent });
    dispatch({ type: 'TOOL_TIMEOUT_CLEAR' });
  }

  return React.createElement('div', {
    style: {
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0,0,0,0.68)', backdropFilter: 'blur(5px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }
  },
    React.createElement('div', {
      style: {
        background: 'var(--bg-surface)', border: `1px solid ${'var(--critical)'}`,
        borderRadius: 14, padding: '26px 30px', minWidth: 430, maxWidth: 530,
        boxShadow: '0 0 60px color-mix(in srgb, var(--critical) 19%, transparent), 0 12px 40px rgba(0,0,0,0.65)',
        fontFamily: 'var(--font-ui)',
      }
    },
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 18 }
      },
        React.createElement('div', {
          style: {
            width: 36, height: 36, borderRadius: 8, flexShrink: 0,
            background: 'var(--critical-bg)', border: '1px solid color-mix(in srgb, var(--critical) 31%, transparent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
          }
        }, '⏱'),
        React.createElement('div', null,
          React.createElement('div', {
            style: { fontSize: 15, fontWeight: 700, color: 'var(--critical)', letterSpacing: 0.2, marginBottom: 3 }
          }, 'Tool Running Too Long'),
          React.createElement('div', {
            style: { fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5 }
          }, 'This tool has exceeded its time limit. Choose to extend or stop it.')
        )
      ),

      React.createElement('div', {
        style: {
          background: 'var(--bg-panel)', borderRadius: 8, padding: '10px 14px',
          border: `1px solid ${'var(--border-dim)'}`, marginBottom: 20,
        }
      },
        ['Tool', 'Subagent', 'Running for'].map((lbl, i) => {
          const val = i === 0 ? (warn.tool || 'unknown')
                    : i === 1 ? (warn.subagent || 'unknown')
                              : fmtElapsed(warn.elapsed_sec || 0);
          const color = i === 0 ? 'var(--cyan)' : i === 1 ? 'var(--text-primary)' : 'var(--medium)';
          return React.createElement('div', {
            key: lbl,
            style: {
              display: 'flex', justifyContent: 'space-between', padding: '5px 0',
              borderBottom: i < 2 ? '1px solid color-mix(in srgb, var(--border-dim) 33%, transparent)' : 'none',
            }
          },
            React.createElement('span', {
              style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase',
                       letterSpacing: 1, fontFamily: 'var(--font-mono)' }
            }, lbl),
            React.createElement('span', {
              style: { fontSize: 11, fontFamily: 'var(--font-mono)', color, fontWeight: i === 0 || i === 2 ? 700 : 500 }
            }, val)
          );
        })
      ),

      React.createElement('div', {
        style: { fontSize: 10, color: 'var(--text-secondary)', marginBottom: 10, letterSpacing: 0.3 }
      }, 'Extend the time limit or stop this tool:'),

      React.createElement('div', {
        style: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 8, marginBottom: 10 }
      },
        [{label:'+10 min',sec:600},{label:'+20 min',sec:1200},{label:'+30 min',sec:1800},{label:'+60 min',sec:3600}].map(({label, sec}) =>
          React.createElement('button', {
            key: label,
            onClick: () => extend(sec),
            style: {
              padding: '9px 0', borderRadius: 7, cursor: 'pointer',
              border: '1px solid color-mix(in srgb, var(--accent) 31%, transparent)', background: 'var(--accent-subtle)',
              color: 'var(--accent)', fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)',
            }
          }, label)
        )
      ),

      React.createElement('button', {
        onClick: stopTool,
        style: {
          width: '100%', padding: '10px 0', borderRadius: 7, cursor: 'pointer',
          border: '1px solid var(--critical-bd)', background: 'var(--critical-bg)',
          color: 'var(--critical)', fontSize: 12, fontWeight: 700,
          fontFamily: 'var(--font-mono)', letterSpacing: 0.5,
        }
      }, '■  Stop This Tool')
    )
  );
}

// ─── Connectivity Blocker Modal ──────────────────────────────
// The target became unreachable (e.g. the VPN/route went down). ARGUS PAUSED
// instead of spinning doomed scans, and asks the human to restore connectivity
// and RESUME, or ABORT the target (which finalizes honestly — no false
// "0 findings — complete"). Always mounted; renders only when blocked.
function BlockerModal() {
  const { state, dispatch, sendWS } = window.useStore();
  const p = state.blockerPrompt;
  if (!p) return null;
  function resume() {
    sendWS({ type: 'blocker_resume', target: p.target || '' });
    dispatch({ type: 'BLOCKER_CLEAR' });
  }
  function abort() {
    sendWS({ type: 'blocker_abort', target: p.target || '' });
    dispatch({ type: 'BLOCKER_CLEAR' });
  }
  return React.createElement('div', {
    style: {
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0,0,0,0.68)', backdropFilter: 'blur(5px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }
  },
    React.createElement('div', {
      style: {
        background: 'var(--bg-surface)', border: '1px solid var(--high)',
        borderRadius: 14, padding: '26px 30px', minWidth: 440, maxWidth: 560,
        boxShadow: '0 0 60px color-mix(in srgb, var(--high) 18%, transparent), 0 12px 40px rgba(0,0,0,0.65)',
        fontFamily: 'var(--font-ui)',
      }
    },
      React.createElement('div', { style: { display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 16 } },
        React.createElement('div', {
          style: {
            width: 36, height: 36, borderRadius: 8, flexShrink: 0,
            background: 'var(--high-bg)', border: '1px solid color-mix(in srgb, var(--high) 31%, transparent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
          }
        }, '⛔'),
        React.createElement('div', null,
          React.createElement('div', { style: { fontSize: 15, fontWeight: 700, color: 'var(--high)', letterSpacing: 0.2, marginBottom: 3 } },
            'Target Unreachable — Engagement Paused'),
          React.createElement('div', { style: { fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5 } },
            `${p.detail || 'The target is not reachable.'} Target: ${p.target || '(unknown)'}.`)
        )
      ),
      React.createElement('div', { style: { display: 'flex', gap: 8 } },
        React.createElement('button', {
          onClick: resume,
          style: { flex: 1, padding: '10px 0', borderRadius: 7, cursor: 'pointer',
                   border: '1px solid color-mix(in srgb, var(--accent) 35%, transparent)', background: 'var(--accent-subtle)',
                   color: 'var(--accent)', fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)' }
        }, 'Resume — connectivity restored'),
        React.createElement('button', {
          onClick: abort,
          style: { flex: 1, padding: '10px 0', borderRadius: 7, cursor: 'pointer',
                   border: '1px solid color-mix(in srgb, var(--high) 35%, transparent)', background: 'var(--high-bg)',
                   color: 'var(--high)', fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)' }
        }, 'Abort this target')
      )
    )
  );
}

// ─── Token Budget Modal ──────────────────────────────────────
// Per-target, human-set LLM-token cap. When a target hits the budget ARGUS
// PAUSES it and asks the operator to extend (raise the cap) or cut it off.
// ARGUS never moves the cap itself; if the human doesn't answer within the
// grace window the backend auto-cuts-off (conserving tokens). Mirrors
// ToolTimeoutModal — always mounted, renders only when a prompt is pending.
function TokenBudgetModal() {
  const { state, dispatch, sendWS } = window.useStore();
  const p = state.tokenBudgetPrompt;
  const [custom, setCustom] = (window.React && React.useState) ? React.useState('') : [null, null];
  if (!p) return null;

  const fmt = (n) => {
    n = Number(n) || 0;
    if (n >= 1000000) return (n / 1000000).toFixed(2) + 'M';
    if (n >= 1000)    return (n / 1000).toFixed(1) + 'k';
    return String(n);
  };
  function extend(extra) {
    sendWS({ type: 'token_extend', target: p.target || '', extra: extra });
    dispatch({ type: 'TOKEN_BUDGET_CLEAR' });
  }
  function cutOff() {
    sendWS({ type: 'token_stop', target: p.target || '' });
    dispatch({ type: 'TOKEN_BUDGET_CLEAR' });
  }

  return React.createElement('div', {
    style: {
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0,0,0,0.68)', backdropFilter: 'blur(5px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }
  },
    React.createElement('div', {
      style: {
        background: 'var(--bg-surface)', border: '1px solid var(--medium)',
        borderRadius: 14, padding: '26px 30px', minWidth: 440, maxWidth: 540,
        boxShadow: '0 0 60px color-mix(in srgb, var(--medium) 18%, transparent), 0 12px 40px rgba(0,0,0,0.65)',
        fontFamily: 'var(--font-ui)',
      }
    },
      React.createElement('div', { style: { display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 18 } },
        React.createElement('div', {
          style: {
            width: 36, height: 36, borderRadius: 8, flexShrink: 0,
            background: 'var(--medium-bg)', border: '1px solid color-mix(in srgb, var(--medium) 31%, transparent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
          }
        }, '🪙'),
        React.createElement('div', null,
          React.createElement('div', { style: { fontSize: 15, fontWeight: 700, color: 'var(--medium)', letterSpacing: 0.2, marginBottom: 3 } },
            'LLM Token Budget Reached'),
          React.createElement('div', { style: { fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5 } },
            `This target hit its token budget and is PAUSED. Extend the budget to keep going, or cut this target off (its report is written either way). No answer in ${Math.round((p.wait_sec || 1800) / 60)} min → auto cut-off.`)
        )
      ),

      React.createElement('div', {
        style: { background: 'var(--bg-panel)', borderRadius: 8, padding: '10px 14px', border: '1px solid var(--border-dim)', marginBottom: 20 }
      },
        [['Target', p.target || 'target', 'var(--cyan)'],
         ['Tokens used', fmt(p.tokens_used), 'var(--medium)'],
         ['Budget', fmt(p.budget), 'var(--text-primary)']].map(([lbl, val, color], i) =>
          React.createElement('div', {
            key: lbl,
            style: { display: 'flex', justifyContent: 'space-between', padding: '5px 0',
                     borderBottom: i < 2 ? '1px solid color-mix(in srgb, var(--border-dim) 33%, transparent)' : 'none' }
          },
            React.createElement('span', { style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, fontFamily: 'var(--font-mono)' } }, lbl),
            React.createElement('span', { style: { fontSize: 11, fontFamily: 'var(--font-mono)', color, fontWeight: 700 } }, val)
          )
        )
      ),

      React.createElement('div', { style: { fontSize: 10, color: 'var(--text-secondary)', marginBottom: 10, letterSpacing: 0.3 } },
        'Extend this target’s budget by:'),
      React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 8, marginBottom: 10 } },
        [{ label: '+50k', n: 50000 }, { label: '+100k', n: 100000 }, { label: '+250k', n: 250000 }, { label: '+500k', n: 500000 }].map(({ label, n }) =>
          React.createElement('button', {
            key: label, onClick: () => extend(n),
            style: { padding: '9px 0', borderRadius: 7, cursor: 'pointer',
                     border: '1px solid color-mix(in srgb, var(--accent) 31%, transparent)', background: 'var(--accent-subtle)',
                     color: 'var(--accent)', fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)' }
          }, label)
        )
      ),

      React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 12 } },
        React.createElement('input', {
          type: 'number', min: 1, placeholder: 'custom amount of tokens',
          value: custom || '', onChange: (e) => setCustom && setCustom(e.target.value),
          style: { flex: 1, padding: '9px 12px', borderRadius: 7, border: '1px solid var(--border-dim)',
                   background: 'var(--bg-panel)', color: 'var(--text-primary)', fontSize: 11, fontFamily: 'var(--font-mono)' }
        }),
        React.createElement('button', {
          onClick: () => { const v = parseInt(custom, 10); if (v > 0) extend(v); },
          style: { padding: '9px 16px', borderRadius: 7, cursor: 'pointer',
                   border: '1px solid color-mix(in srgb, var(--accent) 31%, transparent)', background: 'var(--accent-subtle)',
                   color: 'var(--accent)', fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)' }
        }, 'Extend')
      ),

      React.createElement('button', {
        onClick: cutOff,
        style: { width: '100%', padding: '10px 0', borderRadius: 7, cursor: 'pointer',
                 border: '1px solid var(--critical-bd)', background: 'var(--critical-bg)',
                 color: 'var(--critical)', fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: 0.5 }
      }, '■  Cut Off This Target')
    )
  );
}

// ─── Target Selection Modal ──────────────────────────────────
// Blocking gate: after ARGUS hunts a domain's subdomains it BLOCKS until the
// operator picks which to engage.  Mirrors ToolTimeoutModal — always mounted,
// renders only when state.targetSelection.active.
function TargetSelectionModal() {
  const { state, dispatch, sendWS } = window.useStore();
  const ts = state.targetSelection;
  const [picked, setPicked] = React.useState({});

  const selId = (ts && ts.selectionId) || '';
  const active = !!(ts && ts.active);
  React.useEffect(() => {
    if (active && ts && Array.isArray(ts.candidates)) {
      const init = {};
      ts.candidates.forEach(c => { init[c.host] = !!c.in_apex_network; });
      setPicked(init);
    }
  }, [selId, active]);

  if (!active) return null;
  const cands = (ts.candidates || []);
  const chosen = cands.filter(c => picked[c.host]).map(c => c.host);

  function toggle(host) { setPicked(p => ({ ...p, [host]: !p[host] })); }
  // Functional updates only.  The old version read `picked` from the render
  // closure, and "In-network only" ran setAll(false) then a setTimeout(setAll(true,
  // filter)) — the second call still saw the PRE-clear picked map, so a
  // third-party host the operator had ticked by hand survived a filter whose whole
  // job was to deselect it.  `exact` does it in one atomic update instead.
  function setAll(val, filterFn, exact) {
    setPicked(prev => {
      const next = {};
      cands.forEach(c => {
        next[c.host] = exact ? !!(filterFn ? filterFn(c) : val)
          : (filterFn ? (filterFn(c) ? val : !!prev[c.host]) : val);
      });
      return next;
    });
  }
  // ── Per-host AUTHORIZATION review (pre-launch) ────────────────────────────
  // ts.authorization holds the DERIVED grant per host; authzOverrides holds only what
  // the operator changed.  Untouched hosts keep the derived (fail-closed) grant.
  const authzMap = (ts.authorization && typeof ts.authorization === 'object') ? ts.authorization : {};
  const overrides = (ts.authzOverrides && typeof ts.authzOverrides === 'object') ? ts.authzOverrides : {};
  const PROFILES = (Array.isArray(ts.authzProfiles) && ts.authzProfiles.length)
    ? ts.authzProfiles
    : [{ id: 'passive_only', label: 'Passive only' }, { id: 'assess', label: 'Assess' },
       { id: 'external', label: 'External (approve exploits)' }, { id: 'full', label: 'Full autonomous' }];

  // Which profile a host is effectively running under.
  function effProfile(host) {
    if (overrides[host]) return overrides[host];
    const a = authzMap[host] || {};
    if (a.exploitation === 'allow') return 'full';
    if (a.exploitation === 'require_approval') return 'external';
    if (a.ceiling === 'light') return 'assess';
    return 'passive_only';
  }
  function setProfile(host, prof) {
    // Selecting the derived value clears the override (keeps provenance clean).
    const a = authzMap[host] || {};
    const derived = (a.exploitation === 'allow') ? 'full'
      : (a.exploitation === 'require_approval') ? 'external'
      : (a.ceiling === 'light') ? 'assess' : 'passive_only';
    dispatch({ type: 'TARGET_SELECTION_AUTHZ',
               payload: { host, profile: prof === derived ? '' : prof } });
  }
  const AUTHZ_COLOR = {
    passive_only: 'var(--text-muted)',
    assess:       'var(--info, #40a9ff)',
    external:     'var(--warning, #faad14)',
    full:         'var(--danger, #ff4d4f)',
  };
  const AUTHZ_SHORT = {
    passive_only: 'passive', assess: 'assess',
    external: 'approve-exploit', full: 'AUTONOMOUS',
  };

  function submit() {
    // Send ONLY the hosts being engaged, with the authorization the operator
    // reviewed.  Overrides for unselected hosts are irrelevant and dropped.
    const authz = {};
    chosen.forEach(h => { authz[h] = effProfile(h); });
    sendWS({ type: 'target_selection', selection_id: selId, selected: chosen, authz });
    dispatch({ type: 'TARGET_SELECTION_RESOLVE', payload: {} });
  }
  function cancel() {  // explicit "scan nothing"
    sendWS({ type: 'target_selection', selection_id: selId, selected: [] });
    dispatch({ type: 'TARGET_SELECTION_RESOLVE', payload: {} });
  }

  const flag = (c) => c.in_apex_network
    ? { t: 'in-network', col: 'var(--success, #73d13d)' }
    : (c.ips && c.ips.length)
      ? { t: 'third-party', col: 'var(--warning, #faad14)' }
      : { t: 'dangling', col: 'var(--text-muted)' };

  const btn = (label, onClick, primary, disabled) => React.createElement('button', {
    onClick: disabled ? undefined : onClick,
    style: {
      padding: '9px 16px', borderRadius: 8, cursor: disabled ? 'not-allowed' : 'pointer',
      fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: 0.4,
      opacity: disabled ? 0.45 : 1,
      border: `1px solid ${primary ? '#7B6CF6' : 'var(--border-light)'}`,
      background: primary ? '#7B6CF6' : 'transparent',
      color: primary ? '#fff' : 'var(--text-secondary)',
    }
  }, label);

  // Split the candidates: assets inside the apex network, and everything else.
  // The second group is what ARGUS excludes by default, and it is exactly the
  // group a human must eyeball — a forgotten subsidiary, an acquisition, a cloud
  // tenancy or a piece of shadow IT resolves outside the apex too, and silently
  // dropping it leaves a real hole in the assessment.
  const inNet    = cands.filter(c => c.in_apex_network);
  const external = cands.filter(c => !c.in_apex_network);
  const extPicked = external.filter(c => picked[c.host]).length;

  // Rich dialog shell — see static/css/avatars/_components.css (.a-dlg*).
  // Fixed header/footer with a single scrolling body, avatar-aware accent,
  // sticky group headers and a live selection summary. Structure was already
  // correct (a previous fix stopped the footer being pushed out); this makes
  // it a first-class, visually-rich surface across all six avatars.
  return React.createElement('div', {
    className: 'a-dlg-backdrop',
    role: 'presentation',
    'data-slot': 'dialog.targetSelection'
  },
    React.createElement('div', {
      className: 'a-dlg',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-label': `Select targets for ${ts.domain || 'engagement'}`
    },
      // ── HEADER (pinned) ──────────────────────────────────────────────────
      React.createElement('div', { className: 'a-dlg-head' },
        React.createElement('div', { className: 'a-dlg-title' },
          React.createElement('span', { 'aria-hidden': 'true' }, '◆'),
          React.createElement('span', null, 'Select Targets'),
          ts.domain ? React.createElement('span', {
            className: 'a-num',
            style: { fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500 }
          }, ts.domain) : null
        ),
        React.createElement('div', { className: 'a-dlg-sub' },
          React.createElement('b', { style: { color: 'var(--text-primary)' } }, String(cands.length)),
          ` candidate${cands.length === 1 ? '' : 's'} discovered · `,
          React.createElement('span', { style: { color: 'var(--low)' } }, `${inNet.length} in apex network`),
          ' · ',
          React.createElement('span', { style: { color: external.length ? 'var(--high)' : 'var(--text-muted)' } },
            `${external.length} outside it`),
          React.createElement('span', { style: { display: 'block', marginTop: 3, color: 'var(--text-muted)' } },
            'Nothing is touched until you confirm. Review the authorization column before launching.')
        )
      ),

      // ── BODY (the ONLY scrolling region) ─────────────────────────────────
      React.createElement('div', { className: 'a-dlg-body' },

      // DNS record sweep (DNSDumpster-equivalent) — context for the pick.
      // An OPEN ZONE TRANSFER is called out in red because it is the single
      // highest-value misconfiguration this pass can surface.
      (function renderDns() {
        const rec = ts.dnsRecords;
        if (!rec) return null;
        const s = rec.summary || ts.dnsSummary || {};
        const openAxfr = s.zone_transfer_open || [];
        const row = (label, val) => (val && (!Array.isArray(val) || val.length))
          ? React.createElement('div', { key: label, style: { display: 'flex', gap: 8, padding: '2px 0' } },
              React.createElement('span', { style: { fontSize: 9.5, fontWeight: 700, color: 'var(--text-muted)', minWidth: 52, fontFamily: 'var(--font-mono)' } }, label),
              React.createElement('span', { style: { fontSize: 10, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' } },
                Array.isArray(val) ? val.join(', ') : String(val)))
          : null;
        const pol = rec.txt_policies || {};
        return React.createElement('details', {
          open: openAxfr.length > 0,
          style: { border: `1px solid ${openAxfr.length ? 'var(--danger, #ff4d4f)' : 'var(--border-light)'}`,
                   borderRadius: 8, marginBottom: 10, padding: '8px 12px' }
        },
          React.createElement('summary', {
            style: { fontSize: 11, fontWeight: 700, cursor: 'pointer',
                     color: openAxfr.length ? 'var(--danger, #ff4d4f)' : '#7B6CF6' }
          }, openAxfr.length
              ? `⚠ DNS records — ZONE TRANSFER OPEN on ${openAxfr.join(', ')}`
              : `▤ DNS records (${s.addresses || 0} addr · ${s.nameservers || 0} NS · ${s.mail_exchangers || 0} MX · ${s.txt_records || 0} TXT)`),
          React.createElement('div', { style: { marginTop: 8, maxHeight: 180, overflowY: 'auto' } },
            row('A', rec.a), row('AAAA', rec.aaaa), row('NS', rec.ns),
            row('MX', (rec.mx || []).map(m => `${m.priority} ${m.host}`)),
            row('CNAME', rec.cname), row('CAA', rec.caa),
            row('SOA', rec.soa && rec.soa.mname ? `${rec.soa.mname} (serial ${rec.soa.serial})` : ''),
            row('SRV', (rec.srv || []).map(r => `${r.service || ''}:${r.port} → ${r.target}`)),
            row('TXT', rec.txt),
            row('SPF', pol.has_spf ? `present ${pol.spf_all_qualifier || ''}all` : 'MISSING'),
            row('DMARC', pol.has_dmarc ? `p=${pol.dmarc_policy || '?'}` : 'MISSING'),
            row('PTR', Object.keys(rec.ptr || {}).map(ip => `${ip} → ${(rec.ptr[ip] || []).join('/')}`)),
            rec.wildcard ? row('WILDCARD', 'yes — brute-force results are unreliable') : null,
            (rec.errors && rec.errors.length) ? row('NOTES', rec.errors) : null
          )
        );
      })(),

      // One row renderer, used by both groups.
      (function renderGroups() {
        const row = (c, i, last) => {
          const f = flag(c);
          return React.createElement('div', {
            key: c.host,
            className: 'a-dlg-row',
            'data-picked': picked[c.host] ? 'true' : 'false',
            role: 'checkbox',
            'aria-checked': picked[c.host] ? 'true' : 'false',
            tabIndex: 0,
            onKeyDown: (ev) => {
              if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(c.host); }
            },
            onClick: () => toggle(c.host)
          },
            React.createElement('input', {
              type: 'checkbox', checked: !!picked[c.host], readOnly: true, tabIndex: -1,
              style: { width: 15, height: 15, accentColor: 'var(--accent)', pointerEvents: 'none', flexShrink: 0 }
            }),
            React.createElement('div', { style: { flex: 1, minWidth: 0 } },
              React.createElement('div', { className: 'primary a-wrap-any' }, c.host),
              React.createElement('div', { className: 'secondary a-wrap-any' },
                `${(c.ips || []).join(', ') || 'unresolved'}${c.sources && c.sources.length ? '  ·  ' + c.sources.join('/') : ''}`)
            ),
            React.createElement('span', {
              className: 'a-dlg-tag', style: { color: f.col }
            }, f.t),
            // ── AUTHORIZATION control: what ARGUS may do to THIS host ──
            (function authzCell() {
              const prof = effProfile(c.host);
              const col = AUTHZ_COLOR[prof] || 'var(--text-muted)';
              const a = authzMap[c.host] || {};
              const isOverride = !!overrides[c.host];
              return React.createElement('select', {
                value: prof,
                title: (a.note || '') + (isOverride ? '  [OPERATOR-SET]' : '  [derived]'),
                onClick: (e) => e.stopPropagation(),   // don't toggle the row
                onChange: (e) => { e.stopPropagation(); setProfile(c.host, e.target.value); },
                style: {
                  fontSize: 9, fontWeight: 700, fontFamily: 'var(--font-mono)',
                  color: col, background: 'transparent',
                  border: `1px solid ${col}`, borderRadius: 5,
                  padding: '2px 4px', cursor: 'pointer', maxWidth: 152,
                  outline: isOverride ? `1px dashed ${col}` : 'none',
                }
              }, PROFILES.map(p => React.createElement('option', {
                key: p.id, value: p.id,
                style: { color: 'var(--text-primary)', background: 'var(--bg-surface)' }
              }, (AUTHZ_SHORT[p.id] || p.id) + (p.id === prof && isOverride ? ' *' : ''))));
            })()
          );
        };

        // Sticky group header + a note, then the rows. The header stays visible
        // while its group scrolls, so a long candidate list never loses context.
        const section = (title, note, list, accent) => list.length ? React.createElement('div', {
          key: title, style: { marginBottom: 14 }
        },
          React.createElement('div', {
            className: 'a-dlg-group', style: { color: accent }
          },
            React.createElement('span', null, title),
            React.createElement('span', { className: 'count' }, String(list.length)),
            React.createElement('span', {
              style: { flexBasis: '100%', fontSize: 9.5, fontWeight: 400, letterSpacing: 0,
                       textTransform: 'none', color: 'var(--text-muted)', lineHeight: 1.45 }
            }, note)
          ),
          list.map((c, i) => row(c, i, i === list.length - 1))
        ) : null;

        return React.createElement(React.Fragment, null,
          section('▣ IN APEX NETWORK', 'resolve inside the target’s own address space — selected by default',
                  inNet, 'var(--success, #73d13d)'),
          // The validation list.  Excluded by DEFAULT, never SILENTLY: a name that
          // resolves outside the apex is usually a CDN or a mail provider, but it
          // is also how a forgotten subsidiary, an acquisition, a cloud tenancy or
          // shadow IT looks.  Skipping one of those quietly is its own security
          // problem, so the operator is shown every one and confirms the call.
          section('⚠ OUTSIDE APEX — VALIDATE OWNERSHIP',
                  'excluded by default. Check each: a CDN/mail provider is correctly '
                  + 'left out, but an acquisition, cloud tenancy or shadow-IT asset '
                  + 'belongs IN scope — include it only if the engagement covers it',
                  external, 'var(--warning, #faad14)')
        );
      })(),

      // ── Pre-launch AUTHORIZATION summary ──────────────────────────────────
      // States plainly what will happen to the selected hosts, and calls out any
      // host escalated to autonomous exploitation — the one choice that removes the
      // human from the loop, so it must never be quiet.
      (function authzSummary() {
        if (!chosen.length) return null;
        const byProf = {};
        chosen.forEach(h => { const p = effProfile(h); (byProf[p] = byProf[p] || []).push(h); });
        const overridden = chosen.filter(h => overrides[h]);
        const autonomous = byProf['full'] || [];
        return React.createElement('div', {
          style: {
            border: `1px solid ${autonomous.length ? 'var(--danger, #ff4d4f)' : 'var(--border-light)'}`,
            // Capped + scrollable.  Uncapped, this block listed every selected host
            // by name and grew without limit — that is what pushed the buttons out
            // of the dialog once more than a handful of hosts were picked.
            borderRadius: 8, padding: '8px 12px', marginBottom: 4,
            maxHeight: 150, overflowY: 'auto',
          }
        },
          React.createElement('div', {
            style: { fontSize: 10, fontWeight: 700, color: '#7B6CF6', marginBottom: 5 }
          }, '⚖ AUTHORIZATION — reviewed before launch'),
          ...PROFILES.filter(p => (byProf[p.id] || []).length).map(p =>
            React.createElement('div', {
              key: p.id, style: { display: 'flex', gap: 8, padding: '1px 0' }
            },
              React.createElement('span', {
                style: { fontSize: 9, fontWeight: 700, minWidth: 116,
                         color: AUTHZ_COLOR[p.id], fontFamily: 'var(--font-mono)' }
              }, `${AUTHZ_SHORT[p.id] || p.id} (${(byProf[p.id] || []).length})`),
              React.createElement('span', {
                style: { fontSize: 9.5, color: 'var(--text-secondary)', wordBreak: 'break-all' }
              }, (byProf[p.id] || []).join(', '))
            )
          ),
          autonomous.length ? React.createElement('div', {
            style: { fontSize: 9.5, color: 'var(--danger, #ff4d4f)', marginTop: 5, fontWeight: 700 }
          }, `⚠ ${autonomous.length} host(s) set to AUTONOMOUS exploitation — no per-exploit `
             + `approval will be requested. Use only where the engagement authorizes it.`) : null,
          overridden.length ? React.createElement('div', {
            style: { fontSize: 9, color: 'var(--warning, #faad14)', marginTop: 4 }
          }, `${overridden.length} host(s) changed from the derived authorization `
             + `(recorded in the audit trail): ${overridden.join(', ')}`) : null
        );
      })(),

      ),   // ── end BODY ──────────────────────────────────────────────────

      // ── FOOTER (pinned — the buttons are ALWAYS reachable) ───────────────
      React.createElement('div', { className: 'a-dlg-foot', style: { flexDirection: 'column', alignItems: 'stretch' } },
        // Bulk-selection toolbar
        React.createElement('div', { className: 'a-chiprow' },
          React.createElement('span', { className: 'a-eyebrow', style: { marginRight: 2 } }, 'Select'),
          React.createElement('button', { className: 'a-dlg-btn', style: { padding: '5px 10px', fontSize: 10 },
            onClick: () => setAll(true) }, 'All'),
          React.createElement('button', { className: 'a-dlg-btn', style: { padding: '5px 10px', fontSize: 10 },
            onClick: () => setAll(false) }, 'None'),
          React.createElement('button', { className: 'a-dlg-btn', style: { padding: '5px 10px', fontSize: 10 },
            onClick: () => setAll(true, c => c.in_apex_network, true) }, 'In-network only')
        ),
        // Live summary + primary actions
        React.createElement('div', {
          style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                   gap: 12, flexWrap: 'wrap', marginTop: 4 }
        },
          React.createElement('div', { className: 'a-dlg-summary' },
            React.createElement('b', null, String(chosen.length)),
            ` of ${cands.length} selected`,
            external.length ? React.createElement('span', {
              className: extPicked ? 'a-dlg-warn' : undefined
            }, `  ·  ${extPicked}/${external.length} outside-apex included`) : null
          ),
          React.createElement('div', { style: { display: 'flex', gap: 8 } },
            React.createElement('button', { className: 'a-dlg-btn', onClick: cancel }, 'Scan nothing'),
            React.createElement('button', {
              className: 'a-dlg-btn', 'data-primary': 'true',
              disabled: chosen.length === 0,
              onClick: chosen.length === 0 ? undefined : submit
            }, `▶ Engage ${chosen.length} target${chosen.length === 1 ? '' : 's'}`)
          )
        )
      )
    )
  );
}

// ─── Command Palette (Ctrl/Cmd-K) ─────────────────────────────
function CommandPalette({ open, onClose, onNavigate }) {
  const [query, setQuery] = useState('');
  const inputRef = useRef(null);
  const [activeIdx, setActiveIdx] = useState(0);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  // Flatten HUBS into a searchable tab list for the palette.
  // Each entry preserves the legacy `tab.key` so onNavigate(tab.key) still works.
  const ALL_TABS = useMemo(() =>
    HUBS.flatMap(h => h.tabs.map(t => ({
      key:   t.key,
      label: t.label,
      icon:  h.icon,
      group: h.group,
      desc:  h.label,
    })))
  , []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return ALL_TABS;
    return ALL_TABS.filter(p =>
      p.label.toLowerCase().includes(q) ||
      p.group.toLowerCase().includes(q) ||
      (p.desc || '').toLowerCase().includes(q) ||
      p.key.includes(q)
    );
  }, [query, ALL_TABS]);

  useEffect(() => {
    if (!open) return;
    function onKey(e) {
      if (e.key === 'Escape') { onClose(); return; }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIdx(i => Math.min(filtered.length - 1, i + 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIdx(i => Math.max(0, i - 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const sel = filtered[activeIdx];
        if (sel) { onNavigate(sel.key); onClose(); }
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, filtered, activeIdx, onClose, onNavigate]);

  if (!open) return null;

  return React.createElement('div', {
    onClick: onClose,
    style: {
      position: 'fixed', inset: 0, zIndex: 10000,
      background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
      paddingTop: 100,
    }
  },
    React.createElement('div', {
      onClick: e => e.stopPropagation(),
      style: {
        width: 560, maxWidth: '90vw', maxHeight: '60vh',
        background: 'var(--bg-surface)', border: `1px solid ${'var(--border-bright)'}`,
        borderRadius: 14, boxShadow: '0 20px 60px rgba(0,0,0,0.7)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }
    },
      // Search input
      React.createElement('div', {
        style: {
          padding: '14px 16px', borderBottom: `1px solid ${'var(--border-dim)'}`,
          display: 'flex', alignItems: 'center', gap: 10,
        }
      },
        React.createElement('span', {
          style: { color: 'var(--text-muted)', fontSize: 14 }
        }, '⌕'),
        React.createElement('input', {
          ref: inputRef,
          value: query,
          onChange: e => { setQuery(e.target.value); setActiveIdx(0); },
          placeholder: 'Type to search pages…',
          style: {
            flex: 1, background: 'transparent', border: 'none', outline: 'none',
            color: 'var(--text-primary)', fontSize: 14, fontFamily: 'var(--font-ui)',
          }
        }),
        React.createElement('span', {
          style: {
            fontSize: 9, color: 'var(--text-muted)', padding: '2px 6px',
            borderRadius: 4, border: `1px solid ${'var(--border)'}`,
            fontFamily: 'var(--font-mono)', letterSpacing: 0.5,
          }
        }, 'ESC')
      ),
      // Results
      React.createElement('div', {
        style: { flex: 1, overflowY: 'auto', padding: 6 }
      },
        filtered.length === 0
          ? React.createElement('div', {
              style: { padding: 30, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }
            }, 'No matches')
          : filtered.map((p, i) => {
              const accent = GROUP_COLORS[p.group] || 'var(--accent)';
              const isActive = i === activeIdx;
              return React.createElement('div', {
                key: p.key,
                onMouseEnter: () => setActiveIdx(i),
                onClick: () => { onNavigate(p.key); onClose(); },
                style: {
                  display: 'flex', alignItems: 'center', gap: 12,
                  padding: '9px 12px', borderRadius: 8, cursor: 'pointer',
                  background: isActive ? `${accent}14` : 'transparent',
                  borderLeft: `3px solid ${isActive ? accent : 'transparent'}`,
                  transition: 'background 0.1s ease',
                }
              },
                React.createElement('span', {
                  style: { width: 22, fontSize: 14, color: accent, textAlign: 'center' }
                }, p.icon),
                React.createElement('div', { style: { flex: 1, minWidth: 0 } },
                  React.createElement('div', {
                    style: {
                      fontSize: 13, color: isActive ? 'var(--text-primary)' : 'var(--text-primary)',
                      fontWeight: 600, marginBottom: 2,
                    }
                  }, p.label),
                  React.createElement('div', {
                    style: {
                      fontSize: 10, color: 'var(--text-muted)',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }
                  }, p.desc)
                ),
                React.createElement('span', {
                  style: {
                    fontSize: 9, color: accent, padding: '2px 8px',
                    borderRadius: 10, background: `${accent}15`,
                    border: `1px solid ${accent}30`,
                    fontFamily: 'var(--font-mono)', letterSpacing: 0.6, fontWeight: 700,
                  }
                }, p.group),
              );
            })
      ),
      React.createElement('div', {
        style: {
          padding: '8px 14px', borderTop: `1px solid ${'var(--border-dim)'}`,
          display: 'flex', gap: 14, fontSize: 9, color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)', letterSpacing: 0.5,
        }
      },
        React.createElement('span', null, '↑↓  navigate'),
        React.createElement('span', null, '↵  select'),
        React.createElement('span', null, 'esc  close'),
        React.createElement('span', { style: { marginLeft: 'auto', color: 'var(--text-secondary)' } }, `${filtered.length} of ${ALL_TABS.length}`)
      )
    )
  );
}

// ─── PRESENT mode slide shell (T5B) ────────────────────────────
function PresentSlideShell() {
  const { state, dispatch } = window.useStore();
  const slide = PRESENT_SLIDES[state.present?.slide || 0] || PRESENT_SLIDES[0];

  useEffect(() => {
    function onKey(e) {
      if (state.viewMode !== 'PRESENT') return;
      const tag = (document.activeElement?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea') return;
      const cur = state.present?.slide || 0;
      if (e.key === 'ArrowRight' || e.key === ' ') {
        e.preventDefault();
        dispatch({ type: 'SET_PRESENT_SLIDE', payload: Math.min(cur + 1, PRESENT_SLIDES.length - 1) });
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        dispatch({ type: 'SET_PRESENT_SLIDE', payload: Math.max(cur - 1, 0) });
      } else if (e.key === 'Escape') {
        e.preventDefault();
        dispatch({ type: 'SET_VIEW_MODE', payload: 'OPERATOR' });
      } else if (e.key === 'a' || e.key === 'A') {
        dispatch({ type: 'TOGGLE_PRESENT_AUTO' });
      } else if (e.key === 'f' || e.key === 'F') {
        if (!document.fullscreenElement) {
          document.documentElement.requestFullscreen?.();
        } else {
          document.exitFullscreen?.();
        }
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [state.viewMode, state.present?.slide, dispatch]);

  // Auto-advance
  useEffect(() => {
    if (state.viewMode !== 'PRESENT' || !state.present?.autoAdvance) return;
    const id = setInterval(() => {
      const cur = state.present?.slide || 0;
      dispatch({ type: 'SET_PRESENT_SLIDE', payload: (cur + 1) % PRESENT_SLIDES.length });
    }, 12000);
    return () => clearInterval(id);
  }, [state.viewMode, state.present?.autoAdvance, state.present?.slide, dispatch]);

  const slideBody = renderPresentSlide(slide.id, state);

  return React.createElement('div', { className: 'present-shell' },
    slideBody,
    React.createElement('div', {
      style: {
        position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)',
        fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)',
        letterSpacing: 1.5, textAlign: 'center',
      }
    }, `${(state.present?.slide || 0) + 1} / ${PRESENT_SLIDES.length}    ←→ paginate · F fullscreen · A auto · ESC exit`)
  );
}

function renderPresentSlide(id, state) {
  const center = {
    height: '100vh', display: 'flex', flexDirection: 'column',
    alignItems: 'center', justifyContent: 'center', textAlign: 'center',
    color: 'var(--text-primary)',
  };
  const titleStyle = { fontSize: 64, fontWeight: 700, marginBottom: 16, letterSpacing: -1 };
  const subStyle = { fontSize: 20, color: 'var(--text-secondary)', letterSpacing: 1 };
  const fs = state.findingsSummary || { critical: 0, high: 0, medium: 0, low: 0 };
  const target = state.activeSession?.target_ip || state.activeSession?.target || '—';

  switch (id) {
    case 'title':
      return React.createElement('div', { style: center },
        React.createElement('div', { style: titleStyle }, 'A R G U S'),
        React.createElement('div', { style: subStyle }, `engagement · ${target}`),
      );
    case 'scope':
      return React.createElement('div', { style: center },
        React.createElement('div', { style: { ...titleStyle, fontSize: 48 } }, 'Scope'),
        React.createElement('div', { style: { ...subStyle, marginTop: 16 } }, `Target: ${target}`),
      );
    case 'risk': {
      const score = (fs.critical * 25) + (fs.high * 12) + (fs.medium * 5) + (fs.low * 2);
      return React.createElement('div', { style: center },
        React.createElement('div', { style: { fontSize: 200, fontWeight: 700, fontVariantNumeric: 'tabular-nums', color: score >= 70 ? 'var(--critical)' : 'var(--accent)' } }, Math.min(100, score)),
        React.createElement('div', { style: { ...subStyle, marginTop: 16 } }, score >= 70 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 15 ? 'MEDIUM' : 'BASELINE'),
      );
    }
    case 'crit':
      return React.createElement('div', { style: center },
        React.createElement('div', { style: titleStyle }, fs.critical),
        React.createElement('div', { style: subStyle }, 'critical findings'),
      );
    case 'high':
      return React.createElement('div', { style: center },
        React.createElement('div', { style: titleStyle }, fs.high),
        React.createElement('div', { style: subStyle }, 'high-severity findings'),
      );
    case 'kchain':
      return React.createElement('div', { style: center },
        React.createElement('div', { style: { ...titleStyle, fontSize: 36 } }, 'Kill Chain'),
        React.createElement('div', { style: { ...subStyle, marginTop: 16 } }, `current phase: ${state.currentPhase || 'idle'}`),
      );
    case 'graph':
      return React.createElement('div', { style: center },
        React.createElement('div', { style: { ...titleStyle, fontSize: 36 } }, 'Attack Graph'),
        React.createElement('div', { style: subStyle }, `${(state.attackGraph?.nodes || state.graphNodes || []).length} nodes`),
      );
    case 'recs':
      return React.createElement('div', { style: center },
        React.createElement('div', { style: { ...titleStyle, fontSize: 36 } }, 'Recommendations'),
        React.createElement('div', { style: { ...subStyle, marginTop: 16, maxWidth: 800 } }, 'Detailed remediation guidance is available in the full report.'),
      );
    case 'closing':
      return React.createElement('div', { style: center },
        React.createElement('div', { style: titleStyle }, 'Thank you.'),
        React.createElement('div', { style: subStyle }, `${fs.critical + fs.high + fs.medium + fs.low} total findings · ${(state.activeSubagents || []).length} agents engaged`),
      );
    default:
      return React.createElement('div', { style: center },
        React.createElement('div', { style: titleStyle }, '—'),
      );
  }
}

// ─── Boot splash (T6) ───────────────────────────────────────
function Splash() {
  const { state } = window.useStore();
  const [hidden, setHidden] = useState(false);
  const skipped = (() => {
    try { return localStorage.getItem('argus.skipSplash') === '1'; } catch { return false; }
  })();
  const [tickIdx, setTickIdx] = useState(0);

  useEffect(() => {
    if (skipped) { setHidden(true); return; }
    const id = setInterval(() => setTickIdx(i => i + 1), 800);
    return () => clearInterval(id);
  }, [skipped]);

  useEffect(() => {
    if (skipped) return;
    if (state.bootComplete) {
      const id = setTimeout(() => setHidden(true), 400);
      return () => clearTimeout(id);
    }
  }, [state.bootComplete, skipped]);

  // Defensive escape hatch — never let the splash trap the user.
  // If bootComplete hasn't fired within 5s (backend unreachable, status
  // poll hanging, etc.), force-hide so the app shell becomes interactive.
  useEffect(() => {
    if (skipped) return;
    const id = setTimeout(() => setHidden(true), 5000);
    return () => clearTimeout(id);
  }, [skipped]);

  if (hidden) return null;

  const messages = [
    'connecting to MCP …',
    'loading reasoning engine …',
    'pulling playbooks …',
    'warming reranker …',
  ];
  const msg = messages[tickIdx % messages.length];

  return React.createElement('div', { className: 'splash', 'data-hidden': hidden },
    React.createElement('div', { className: 'splash-orbital' }),
    React.createElement('div', { className: 'splash-title' }, 'A R G U S'),
    React.createElement('div', { className: 'splash-subtitle' }, 'pentest platform'),
    React.createElement('div', { className: 'splash-status' }, msg),
  );
}

// ─── App ─────────────────────────────────────────────────────
function App() {
  const initial = loadPrefs();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(!!initial.sidebarCollapsed);
  const [groupOpen, setGroupOpen] = useState(initial.groupOpen || {
    Overview: true, Analysis: true, Execution: true, Reporting: true,
  });
  const [theme, setTheme] = useState(initial.theme || 'midnight');
  const [paletteOpen, setPaletteOpen] = useState(false);
  const { state, dispatch } = window.useStore();
  const { sysStatus, activeSession, findingsSummary, wsConnected, currentPhase } = state;
  const currentHub = state.currentHub || 'risk';
  const currentTab = state.currentTab || 'risk';
  const inPresent  = state.viewMode === 'PRESENT';

  // Boot-complete dispatch (T6) — fires once the first system-status poll
  // returns (success or failure both flip sysStatus.mcp off 'unknown').
  // Decoupled from wsConnected because the WebSocket only opens after a
  // session starts — gating the splash on it would freeze the shell on
  // fresh loads with no active session.
  useEffect(() => {
    const mcp = state.sysStatus?.mcp;
    if (!state.bootComplete && mcp && mcp !== 'unknown') {
      dispatch({ type: 'SET_BOOT_COMPLETE' });
    }
  }, [state.sysStatus?.mcp, state.bootComplete]);

  // Mode transition cross-fade (T6) — briefly fades the root on viewMode change.
  const [transitioning, setTransitioning] = useState(false);
  useEffect(() => {
    setTransitioning(true);
    const id = setTimeout(() => setTransitioning(false), 600);
    return () => clearTimeout(id);
  }, [state.viewMode]);

  // Supernova flash on header CRIT-tally when critical-finding count increments.
  // Visual-only — drives the .motion-supernova class for one 2s flash.
  const [critPulse, setCritPulse] = useState(false);
  const lastCrit = useRef(state.findingsSummary?.critical || 0);
  useEffect(() => {
    const cur = state.findingsSummary?.critical || 0;
    if (cur > lastCrit.current) {
      setCritPulse(true);
      const id = setTimeout(() => setCritPulse(false), 2000);
      lastCrit.current = cur;
      return () => clearTimeout(id);
    }
    lastCrit.current = cur;
  }, [state.findingsSummary?.critical]);

  // Mote drift on finding_added — Spec §9.1 event 4.
  // Spawns a transient DOM node that drifts toward the header tally.
  // De-dupes via window.__moteSeen so a re-render with the same recentFindings
  // tail doesn't double-fire.
  useEffect(() => {
    const list = state.recentFindings || [];
    if (list.length === 0) return;
    const last = list[list.length - 1];
    if (!last) return;
    if (!window.__moteSeen) window.__moteSeen = new Set();
    if (window.__moteSeen.has(last.id)) return;
    window.__moteSeen.add(last.id);

    // Header tally is roughly top-right; estimate target coords.
    const targetX = window.innerWidth - 200;
    const targetY = 26;
    // Spawn at center of viewport (proxy for "source" — refined when
    // source-element refs become available).
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
    const id = setTimeout(() => { try { node.remove(); } catch (_) {} }, 1700);
    return () => clearTimeout(id);
  }, [state.recentFindings]);

  // Apply persisted theme on mount + whenever it changes.
  // When the avatar engine is present it owns the visual identity, so the
  // legacy data-theme attribute is cleared to avoid two competing token
  // sources. (Avatar CSS already wins on specificity + document order; this
  // just keeps the DOM honest about which system is in charge.)
  useEffect(() => {
    if (window.ArgusAvatar) {
      try { document.documentElement.removeAttribute('data-theme'); } catch (_) {}
      return;
    }
    applyTheme(theme);
  }, [theme]);

  // Legacy visual-skin cold boot. Superseded by the avatar engine: when
  // ArgusAvatar is present we clear the skin <link> so a stale skin
  // stylesheet cannot override avatar tokens. ArgusAvatar.boot() has
  // already migrated the saved skin id to its avatar equivalent.
  useEffect(() => {
    try {
      if (window.ArgusAvatar) {
        const legacy = document.getElementById('argus-skin');
        if (legacy) { legacy.removeAttribute('href'); }
        document.documentElement.removeAttribute('data-skin');
        return;
      }
      if (window.ArgusSkin) {
        window.ArgusSkin.apply(window.ArgusSkin.load());
      }
    } catch (_) {}
  }, []);

  // Persist UI prefs (localStorage write-through)
  useEffect(() => {
    savePrefs({
      currentHub, currentTab,
      hubTabMemory: state.hubTabMemory,
      sidebarCollapsed, groupOpen, theme,
      viewMode: state.viewMode, client: state.client, present: state.present,
    });
  }, [currentHub, currentTab, state.hubTabMemory, sidebarCollapsed, groupOpen, theme,
      state.viewMode, state.client, state.present]);

  // Mirror UI state to the server so it survives reboot + device switch.
  // Debounced — coalesce rapid prefs flips into one PATCH.  The server
  // is source-of-truth on next cold-boot; localStorage is a cache.
  useEffect(() => {
    if (!window.ArgusAuth?.me) return;          // auth not installed/required
    const csrf = (document.cookie.split('; ').find(c => c.startsWith('argus_csrf=')) || '')
                  .split('=')[1];
    if (!csrf) return;
    const skin = (typeof window.ArgusSkin?.current === 'function')
                  ? window.ArgusSkin.current() : null;
    const payload = {
      skin, theme,
      audience_mode: state.viewMode,
      sidebar_collapsed: sidebarCollapsed,
      current_hub: currentHub, current_tab: currentTab,
      hub_tab_memory: state.hubTabMemory,
      pinned_pentest_session_id: state.activeSession?.id || null,
    };
    const id = setTimeout(() => {
      // Belt-and-braces auth: try Bearer header if cookies fail
      const headers = { 'Content-Type': 'application/json',
                         'X-CSRF-Token': decodeURIComponent(csrf) };
      try {
        const tok = localStorage.getItem('argus.access_token');
        if (tok) headers['Authorization'] = 'Bearer ' + tok;
      } catch {}
      fetch('/auth/me/state', {
        method: 'PATCH', credentials: 'include',
        headers,
        body: JSON.stringify({ state: payload }),
      }).catch(() => {});                       // best-effort
    }, 800);
    return () => clearTimeout(id);
  }, [currentHub, currentTab, sidebarCollapsed, theme, state.viewMode,
      state.activeSession?.id, state.hubTabMemory]);

  // Restore audience-mode + client branding from prefs on cold boot (T5)
  useEffect(() => {
    const prefs = loadPrefs();
    if (prefs.viewMode && prefs.viewMode !== state.viewMode) {
      dispatch({ type: 'SET_VIEW_MODE', payload: prefs.viewMode });
    }
    if (prefs.client) {
      dispatch({ type: 'SET_CLIENT_BRAND', payload: prefs.client });
    }
  }, []);

  // One-time migration: old saved {page: '<key>'} → new {currentHub, currentTab}
  useEffect(() => {
    const prefs = loadPrefs();
    if (prefs.page && !prefs.currentHub) {
      const r = resolveLegacyKey(prefs.page);
      if (r) {
        dispatch({ type: 'SET_HUB_TAB', payload: { hub: r.hub, tab: r.tab } });
      }
      const { page: _p, ...rest } = prefs;
      savePrefs(rest);
    }
  }, []);

  // Restore hub/tab from prefs on warm reload
  useEffect(() => {
    const prefs = loadPrefs();
    if (prefs.currentHub && prefs.currentTab && (state.currentHub !== prefs.currentHub || state.currentTab !== prefs.currentTab)) {
      dispatch({ type: 'SET_HUB_TAB', payload: { hub: prefs.currentHub, tab: prefs.currentTab } });
    }
  }, []);

  function navigateHubTab(hubKey, tabKey) {
    const hub = HUBS.find(h => h.key === hubKey);
    if (!hub) return;
    const remembered = state.hubTabMemory?.[hubKey];
    const resolvedTab = tabKey
      || (remembered && hub.tabs.find(t => t.key === remembered) && remembered)
      || hub.tabs[0].key;
    dispatch({ type: 'SET_HUB_TAB', payload: { hub: hubKey, tab: resolvedTab } });
  }
  // Backwards-compat alias (some inline JSX uses navigateTo()).
  const navigateTo = (key) => {
    const r = resolveLegacyKey(key);
    if (r) navigateHubTab(r.hub, r.tab);
    else navigateHubTab(key);
  };

  // Custom navigate event (from RiskDashboard buttons + other pages)
  useEffect(() => {
    const handler = (e) => {
      const target = e.detail;
      const r = resolveLegacyKey(target);
      if (r) navigateHubTab(r.hub, r.tab);
      else {
        const hub = HUBS.find(h => h.key === target);
        if (hub) navigateHubTab(target);
      }
    };
    window.addEventListener('navigate', handler);
    return () => window.removeEventListener('navigate', handler);
  }, [state.hubTabMemory]);

  // Cmd-K / Ctrl-K to open palette
  useEffect(() => {
    function onKey(e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(p => !p);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // F1-F4 audience-mode shortcuts (T5)
  useEffect(() => {
    function onKey(e) {
      // Skip if focus is in a text input / contenteditable
      const tag = (document.activeElement?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || document.activeElement?.isContentEditable) return;
      const map = { F1: 'OPERATOR', F2: 'BRIEFING', F3: 'PRESENT', F4: 'CLIENT' };
      if (map[e.key]) {
        e.preventDefault();
        dispatch({ type: 'SET_VIEW_MODE', payload: map[e.key] });
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [dispatch]);

  // CLIENT mode: blend accent color with the customer's brand color (T5B)
  useEffect(() => {
    if (state.viewMode === 'CLIENT' && state.client?.brand) {
      document.documentElement.style.setProperty(
        '--accent',
        `color-mix(in srgb, ${state.client.brand} 25%, #4FA8FF)`
      );
    } else {
      document.documentElement.style.removeProperty('--accent');
    }
  }, [state.viewMode, state.client?.brand]);

  function toggleGroup(g)  { setGroupOpen(o => ({ ...o, [g]: !o[g] })); }

  function renderHub() {
    const hub = HUBS.find(h => h.key === currentHub) || HUBS[0];
    // If the current hub becomes invisible after a mode switch, fall back
    // gracefully to the first visible hub.  Schedule the dispatch out-of-frame
    // to avoid a render-loop (we return null this frame).
    if (!isHubVisible(hub.key, state.viewMode)) {
      const fallback = HUBS.find(h => isHubVisible(h.key, state.viewMode)) || HUBS[0];
      setTimeout(() => dispatch({ type: 'SET_HUB_TAB', payload: { hub: fallback.key, tab: fallback.tabs[0].key } }), 0);
      return null;
    }
    const tab = hub.tabs.find(t => t.key === currentTab) || hub.tabs[0];
    const Comp = COMP_FOR[tab.comp]?.();

    // ── Avatar layout hooks ────────────────────────────────────────────
    // Publish the active page/hub as root attributes so avatar stylesheets
    // can compose per-page layouts (:root[data-avatar=x][data-page=y]).
    // Deliberately an ATTRIBUTE, not a wrapper element: it adds zero DOM
    // depth, so no existing flex/grid parent-child relationship changes.
    // Idempotent and side-effect free beyond the attribute itself.
    try {
      document.documentElement.setAttribute('data-page', tab.comp);
      document.documentElement.setAttribute('data-hub', hub.key);
      if (window.ArgusSlots) window.ArgusSlots.seen('page:' + tab.comp);
    } catch (_) {}

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
          React.createElement(Comp, {
            sessionId:     state.sessionId,
            activeSession: state.activeSession,
            viewMode:      state.viewMode,
            client:        state.client,
          })
        );

    return React.createElement(React.Fragment, null, tabbar, body);
  }

  // ── Risk pill (header) ──────────────────────────────────────
  const summary = findingsSummary || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const severityScore =
    (summary.critical || 0) * 25 +
    (summary.high     || 0) * 12 +
    (summary.medium   || 0) * 5 +
    (summary.low      || 0) * 2;
  const riskScore = Math.min(100, severityScore);
  const riskColor = riskScore >= 70 ? 'var(--critical)' : riskScore >= 40 ? 'var(--high)' : riskScore >= 15 ? 'var(--medium)' : 'var(--low)';
  const riskLabel = riskScore >= 70 ? 'CRITICAL' : riskScore >= 40 ? 'HIGH' : riskScore >= 15 ? 'MEDIUM' : riskScore > 0 ? 'LOW' : 'BASELINE';

  // ── Render ──────────────────────────────────────────────────
  return React.createElement('div', {
    className: `argus-root${inPresent ? ' present-mode' : ''}${transitioning ? ' mode-transitioning' : ''}`,
    style: {
      height: '100vh', display: 'flex', flexDirection: 'column',
      overflow: 'hidden', background: 'transparent',
      fontFamily: 'var(--font-ui)', color: 'var(--text-primary)',
    }
  },

    // ════════════════════════════════ BOOT SPLASH (T6) ════════════
    React.createElement(Splash),

    // ════════════════════════════════ COSMOS BACKDROP (T2) ═══════
    React.createElement('div', { className: 'stellar-starfield' }),
    React.createElement('div', { className: 'stellar-nebula' }),
    React.createElement('div', { className: 'stellar-beam' }),

    React.createElement(ToolTimeoutModal),
    React.createElement(TokenBudgetModal),
    React.createElement(BlockerModal),
    React.createElement(TargetSelectionModal),
    React.createElement(CommandPalette, {
      open: paletteOpen,
      onClose: () => setPaletteOpen(false),
      onNavigate: navigateTo,
    }),

    // ════════════════════════════════ HEADER ════════════════════
    !inPresent && React.createElement('div', {
      style: {
        height: 52, flexShrink: 0,
        background: 'var(--bg-glass)', backdropFilter: 'blur(8px)',
        borderBottom: `1px solid ${'var(--border-dim)'}`,
        display: 'flex', alignItems: 'center',
        padding: '0 16px', gap: 14, zIndex: 100,
        position: 'relative',
      }
    },
      // Accent gradient line at very bottom
      React.createElement('div', {
        style: {
          position: 'absolute', bottom: 0, left: 0, right: 0, height: 1,
          background: 'linear-gradient(90deg, transparent 0%, color-mix(in srgb, var(--accent) 31%, transparent) 30%, color-mix(in srgb, var(--violet) 31%, transparent) 70%, transparent 100%)',
        }
      }),

      // Brand
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: 11, flexShrink: 0 }
      },
        React.createElement('div', {
          style: {
            width: 32, height: 32, borderRadius: 9, flexShrink: 0,
            background: `linear-gradient(135deg, ${'var(--accent)'}, ${'var(--violet)'})`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 16, color: '#0B0C12',
            fontWeight: 800,
            boxShadow: '0 0 20px var(--accent-glow)',
          }
        }, '◈'),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', lineHeight: 1 } },
          React.createElement('span', {
            style: { fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: 'var(--accent)', letterSpacing: 2.4 }
          }, 'ARGUS'),
          React.createElement('span', {
            style: { fontFamily: 'var(--font-ui)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 1.6, marginTop: 2 }
          }, 'PENTEST PLATFORM')
        )
      ),

      React.createElement('div', { style: { width: 1, height: 22, background: 'var(--border-dim)', flexShrink: 0, marginLeft: 4 } }),

      // Service status
      React.createElement('div', { style: { display: 'flex', gap: 6, alignItems: 'center' } },
        React.createElement(SvcDot, { label: 'MCP',   status: sysStatus.mcp }),
        React.createElement(SvcDot, { label: 'DB',    status: sysStatus.mongo }),
        React.createElement(SvcDot, { label: 'LLM',
          status: sysStatus.llm || sysStatus.ollama })
      ),

      // HUD telemetry strip + mission clock (T2.3)
      React.createElement(HudTelemetry),
      React.createElement(HudClock),

      // Command palette trigger (centered-ish)
      React.createElement('button', {
        onClick: () => setPaletteOpen(true),
        style: {
          marginLeft: 24, marginRight: 'auto',
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '5px 12px 5px 14px', borderRadius: 8,
          background: 'var(--bg-panel)', border: `1px solid ${'var(--border-dim)'}`,
          color: 'var(--text-muted)', cursor: 'pointer',
          fontSize: 11, fontFamily: 'var(--font-ui)',
          minWidth: 240, justifyContent: 'flex-start',
          transition: 'border-color 0.15s, color 0.15s',
        },
        onMouseEnter: e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-secondary)'; },
        onMouseLeave: e => { e.currentTarget.style.borderColor = 'var(--border-dim)'; e.currentTarget.style.color = 'var(--text-muted)'; },
      },
        React.createElement('span', null, '⌕'),
        React.createElement('span', null, 'Quick navigate…'),
        React.createElement('span', {
          style: {
            marginLeft: 'auto', padding: '1px 6px', borderRadius: 4,
            fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)',
            border: `1px solid ${'var(--border)'}`, letterSpacing: 0.5,
          }
        }, 'Ctrl K')
      ),

      // Risk pill — clickable → risk page
      activeSession && React.createElement('div', {
        onClick: () => navigateTo('risk'),
        style: {
          display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
          padding: '4px 12px', borderRadius: 20,
          background: `${riskColor}10`,
          border: `1px solid ${riskColor}38`,
          transition: 'all 0.15s',
        }
      },
        React.createElement('span', {
          style: { fontSize: 9, color: riskColor, fontWeight: 700, letterSpacing: 1, fontFamily: 'var(--font-mono)' }
        }, 'RISK'),
        React.createElement('span', {
          style: { color: riskColor, fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700 }
        }, riskScore),
        React.createElement('span', {
          style: { fontSize: 9, color: riskColor, fontWeight: 700, letterSpacing: 0.5, opacity: 0.8 }
        }, riskLabel)
      ),

      // Active session pill
      activeSession && React.createElement('div', {
        onClick: () => navigateTo('mission'),
        style: {
          display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
          padding: '4px 12px', borderRadius: 20,
          background: 'var(--accent-subtle)',
          border: '1px solid color-mix(in srgb, var(--accent) 19%, transparent)',
          transition: 'all 0.15s',
        }
      },
        React.createElement('span', {
          style: {
            width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
            background: wsConnected ? 'var(--low)' : 'var(--text-muted)',
            boxShadow: wsConnected ? `0 0 8px ${'var(--low)'}` : 'none',
          }
        }),
        React.createElement('span', {
          style: { color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700 }
        }, activeSession.target_ip),
        React.createElement('span', {
          style: {
            fontSize: 9, letterSpacing: 1, color: 'var(--text-muted)',
            background: 'var(--bg-panel)', border: `1px solid ${'var(--border-dim)'}`,
            padding: '1px 6px', borderRadius: 4,
            textTransform: 'uppercase', fontWeight: 600
          }
        }, currentPhase || 'IDLE')
      ),

      // Critical findings badge (only when > 0)
      findingsSummary.critical > 0 && React.createElement('div', {
        onClick: () => navigateTo('findings'),
        className: 'header-crit-tally' + (critPulse ? ' motion-supernova' : ''),
        style: {
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 12px', borderRadius: 20, cursor: 'pointer',
          background: 'var(--critical-bg)',
          border: '1px solid var(--critical-bd)',
          color: 'var(--critical)', fontSize: 11, fontWeight: 700,
          fontFamily: 'var(--font-mono)', letterSpacing: 0.5,
          animation: 'argus-pulse 2.4s ease-in-out infinite',
        }
      }, `⚠ ${findingsSummary.critical} CRIT`),

      // Audience-mode picker (T5) — sits left of the avatar switcher.
      // Mode (WHO is looking) and avatar (WHICH ARGUS) are orthogonal:
      // 6 avatars × 4 modes = 24 combinations, all supported.
      React.createElement(ModePicker),

      // ── AVATAR SWITCHER ────────────────────────────────────────────
      // Supersedes the legacy ThemeSwitcher (5 colour themes) and
      // SkinChooser (17 colour skins) with 6 full avatars — tokens,
      // typography, density, motion, texture, layout and copy register.
      // Legacy prefs are migrated automatically by ArgusAvatar.boot()
      // (see static/js/theme/avatars.js SKIN_TO_AVATAR / THEME_TO_AVATAR),
      // so no saved preference is orphaned.
      // ThemeSwitcher + SkinChooser remain defined and callable for
      // backward compatibility; they are simply no longer mounted here.
      window.AvatarSwitcher
        ? React.createElement(window.AvatarSwitcher)
        : React.createElement(ThemeSwitcher, { current: theme, onPick: setTheme }),

      // Auth user chip — only renders when window.ArgusAuth.me is set
      // (i.e. the auth module is installed AND user is authenticated).
      // Bypasses gracefully when /auth/me isn't mounted.
      window.UserChip ? React.createElement(window.UserChip) : null
    ),

    // ════════════════════════════════ CLIENT-MODE RIBBON (T5B) ══
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
        zIndex: 1101,
      }
    }, `[CLIENT — ${state.client.name}]`),

    // ════════════════════════════════ BODY ══════════════════════
    inPresent
      ? React.createElement(PresentSlideShell)
      : React.createElement('div', { style: { flex: 1, display: 'flex', overflow: 'hidden' } },

      // ══════════════════════ SIDEBAR ═══════════════════════════
      !inPresent && React.createElement('div', {
        style: {
          width: sidebarCollapsed ? 56 : 220,
          minWidth: sidebarCollapsed ? 56 : 220,
          flexShrink: 0,
          background: 'var(--bg-sidebar)',
          borderRight: `1px solid ${'var(--border-dim)'}`,
          display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
          transition: 'width 0.18s ease, min-width 0.18s ease',
        }
      },
        // Sidebar header w/ collapse toggle
        React.createElement('div', {
          style: {
            height: 36, padding: sidebarCollapsed ? '0 16px' : '0 14px',
            display: 'flex', alignItems: 'center',
            justifyContent: sidebarCollapsed ? 'center' : 'space-between',
            borderBottom: `1px solid ${'var(--border-dim)'}`,
          }
        },
          !sidebarCollapsed && React.createElement('span', {
            style: {
              fontSize: 9, color: 'var(--text-muted)', letterSpacing: 1.5,
              textTransform: 'uppercase', fontWeight: 700,
            }
          }, 'NAVIGATION'),
          React.createElement('button', {
            onClick: () => setSidebarCollapsed(c => !c),
            title: sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar',
            style: {
              background: 'transparent', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', fontSize: 13, padding: 0,
              transition: 'color 0.12s',
            },
            onMouseEnter: e => { e.currentTarget.style.color = 'var(--accent)'; },
            onMouseLeave: e => { e.currentTarget.style.color = 'var(--text-muted)'; },
          }, sidebarCollapsed ? '›' : '‹')
        ),

        // Scroll area
        React.createElement('div', {
          style: { flex: 1, overflowY: 'auto', padding: '6px 0' }
        },
          GROUP_ORDER.map(group => {
            const items = HUBS
              .filter(h => h.group === group)
              .filter(h => isHubVisible(h.key, state.viewMode));
            if (items.length === 0) return null;
            const groupColor = GROUP_COLORS[group];
            const isOpen = sidebarCollapsed ? true : (groupOpen[group] !== false);
            return React.createElement('div', { key: group, style: { marginBottom: 2 } },
              React.createElement(GroupHeader, {
                group, color: groupColor,
                collapsed: sidebarCollapsed,
                isOpen,
                onToggle: () => toggleGroup(group),
              }),
              isOpen && items.map(hub =>
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
        ),

        // Footer — session widget OR new-session CTA
        activeSession
          ? React.createElement('div', {
              style: {
                padding: sidebarCollapsed ? '8px 6px' : '10px 12px',
                borderTop: `1px solid ${'var(--border-dim)'}`, flexShrink: 0,
              }
            },
              sidebarCollapsed
                ? React.createElement('div', {
                    onClick: () => navigateTo('mission'),
                    title: `${activeSession.target_ip} · ${currentPhase || 'idle'}`,
                    style: {
                      width: 38, height: 38, borderRadius: 8, margin: '0 auto',
                      background: 'var(--accent-subtle)', border: '1px solid var(--accent-glow)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      cursor: 'pointer', position: 'relative',
                    }
                  },
                    React.createElement('span', {
                      style: {
                        position: 'absolute', top: 4, right: 4, width: 6, height: 6,
                        borderRadius: '50%', background: wsConnected ? 'var(--low)' : 'var(--text-muted)',
                        boxShadow: wsConnected ? `0 0 5px ${'var(--low)'}` : 'none',
                      }
                    }),
                    React.createElement('span', { style: { color: 'var(--accent)', fontSize: 14 } }, '◉')
                  )
                : React.createElement('div', {
                    onClick: () => navigateTo('mission'),
                    style: {
                      background: 'var(--bg-panel)',
                      border: `1px solid ${'var(--border)'}`,
                      borderRadius: 8, padding: '8px 10px', cursor: 'pointer',
                      transition: 'border-color 0.15s',
                    }
                  },
                    React.createElement('div', {
                      style: { fontSize: 9, letterSpacing: 1.2, color: 'var(--text-muted)',
                               textTransform: 'uppercase', fontWeight: 700, marginBottom: 4 }
                    }, '● Active Session'),
                    React.createElement('div', {
                      style: {
                        fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--accent)',
                        fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                      }
                    }, activeSession.target_ip),
                    React.createElement('div', {
                      style: { display: 'flex', justifyContent: 'space-between', marginTop: 5, fontSize: 10 }
                    },
                      React.createElement('span', {
                        style: { color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8 }
                      }, currentPhase || 'IDLE'),
                      React.createElement('span', {
                        style: { color: wsConnected ? 'var(--low)' : 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 600 }
                      }, wsConnected ? '● LIVE' : '○ OFF')
                    )
                  )
            )
          : !sidebarCollapsed && React.createElement('div', {
              style: { padding: '12px', borderTop: `1px solid ${'var(--border-dim)'}`, flexShrink: 0 }
            },
              React.createElement('div', {
                onClick: () => navigateTo('target'),
                style: {
                  background: 'var(--accent-subtle)',
                  border: '1px dashed var(--accent-glow)',
                  borderRadius: 8, padding: '8px 10px', cursor: 'pointer',
                  textAlign: 'center', transition: 'all 0.15s',
                }
              },
                React.createElement('div', {
                  style: { fontSize: 9, letterSpacing: 1, color: 'var(--accent)',
                           textTransform: 'uppercase', fontWeight: 700, marginBottom: 3 }
                }, '+ New Session'),
                React.createElement('div', {
                  style: { fontSize: 10, color: 'var(--text-muted)' }
                }, 'Configure target')
              )
            )
      ),

      // ═════════════════════ CONTENT ════════════════════════════
      React.createElement('div', {
        style: {
          flex: 1, overflowY: 'auto',
          background: 'var(--bg-base)',
          padding: 22,
        }
      },
        renderHub()
      )
    ),

    // ════════════════════════════════ HUD CONSUMABLES (T2.4) ═════
    state.viewMode === 'OPERATOR' && React.createElement(HudConsumables)
  );
}

// ─── Auth boundary ──────────────────────────────────────────────
// Gates the entire app behind /auth/me.  Renders the cinematic
// LoginPage when unauthenticated, the cockpit when authenticated.
// Hydrates persisted session state from the server so cockpit prefs
// (skin, audience mode, sidebar collapsed, current hub/tab) survive
// reboots + device switches.
//
// When the auth backend isn't installed (404 on /auth/me) the boundary
// falls through to the cockpit so the platform stays usable in dev
// without the auth module mounted.
function AuthBoundary({ children }) {
  const [phase, setPhase] = useState('checking');     // checking | login | authed | bypass
  const [me, setMe] = useState(null);
  const [showChangePw, setShowChangePw] = useState(false);

  function recheck() {
    setPhase('checking');
    // Send the access token as Bearer if we have one stashed in
    // localStorage from a prior login.  This is a belt-and-braces
    // fallback for environments where the session cookie didn't stick
    // (most commonly: http://localhost with AUTH_COOKIE_SECURE=true).
    let headers = {};
    try {
      const tok = localStorage.getItem('argus.access_token');
      if (tok) headers['Authorization'] = 'Bearer ' + tok;
    } catch {}
    fetch('/auth/me', { credentials: 'include', headers })
      .then(async (r) => {
        if (r.status === 401) { setPhase('login'); return null; }
        if (r.status === 404) {
          // Auth module not installed — fall through to cockpit
          console.info('[argus] /auth/me returned 404 — auth module not installed; bypassing.');
          setPhase('bypass'); return null;
        }
        if (!r.ok) throw new Error('unexpected status ' + r.status);
        return r.json();
      })
      .then((data) => {
        if (!data) return;
        setMe(data);
        // Hydrate persisted session state (server is source of truth)
        const st = data.session_state || {};
        if (st.skin && window.ArgusSkin) {
          try { window.ArgusSkin.save(st.skin); window.ArgusSkin.apply(st.skin); } catch {}
        } else if (window.ArgusSkin && !localStorage.getItem('argus.ui.skin.v1')) {
          // No saved skin — pick the default for the user's primary role
          const primary = (data.roles || [])[0];
          const defaults = {
            OWNER: 'stellar', PLATFORM_ADMIN: 'veteran',
            SECURITY_MANAGER: 'manager', OPERATOR: 'redcell',
            ANALYST: 'novice', EXECUTIVE: 'executive',
            AUDITOR: 'auditor', CLIENT: 'editorial',
          };
          const target = defaults[primary] || 'stellar';
          try { window.ArgusSkin.save(target); window.ArgusSkin.apply(target); } catch {}
        }
        if (st.viewMode || st.audience_mode) {
          // Merged into the existing local-prefs flow on next render
          try {
            const prefs = JSON.parse(localStorage.getItem('argus.ui.prefs.v2') || '{}');
            const next = { ...prefs, viewMode: st.viewMode || st.audience_mode, ...st };
            localStorage.setItem('argus.ui.prefs.v2', JSON.stringify(next));
          } catch {}
        }
        setPhase('authed');
      })
      .catch((err) => {
        console.warn('[argus] auth check error:', err);
        setPhase('bypass');
      });
  }
  useEffect(recheck, []);

  // Expose `me` + recheck globally so children + dev tools can read
  useEffect(() => {
    window.ArgusAuth = {
      me, refresh: recheck, logout: doLogout,
      openChangePassword: () => setShowChangePw(true),
    };
  }, [me]);

  // Force the change-password modal when must_change_password is set
  // (set by bootstrap.create_owner, admin reset-owner-password, or any
  // future "forced rotation" policy).  Forced mode disables the X
  // button and Escape so the operator MUST rotate before doing anything.
  const forcedChangePw = phase === 'authed' && me && me.must_change_password;

  async function doLogout() {
    try {
      const csrf = (document.cookie.split('; ').find(c => c.startsWith('argus_csrf=')) || '')
                    .split('=')[1];
      await fetch('/auth/logout', {
        method: 'POST', credentials: 'include',
        headers: csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {},
      });
    } catch {}
    try { localStorage.removeItem('argus.access_token'); } catch {}
    setMe(null); setPhase('login');
  }

  if (phase === 'checking') {
    // Cinematic in-place spinner — matches the auth stage aesthetic
    return React.createElement('div', { className: 'auth-stage' },
      React.createElement('div', { className: 'auth-stage-mesh', 'aria-hidden': 'true' }),
      React.createElement('div', { className: 'auth-stage-center' },
        React.createElement('div', {
          style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16,
                    color: 'var(--accent)' },
        },
          React.createElement('div', { className: 'auth-orbit',
            style: { width: 36, height: 36 } },
            React.createElement('div', { className: 'auth-orbit-ring' }),
            React.createElement('div', { className: 'auth-orbit-dot' }),
          ),
          React.createElement('div', {
            style: { fontFamily: 'var(--font-mono)', fontSize: 11,
                      letterSpacing: 3, textTransform: 'uppercase',
                      color: 'var(--text-secondary)' },
          }, 'Verifying session…'),
        )
      ),
    );
  }

  if (phase === 'login') {
    if (window.LoginPage) {
      return React.createElement(window.LoginPage, {
        onSuccess: () => { window.location.reload(); },
      });
    }
    // LoginPage hasn't loaded yet (race) — show spinner
    return React.createElement('div', null, 'Loading sign-in…');
  }

  // 'authed' or 'bypass' — show the cockpit, plus the optional
  // change-password modal (forced or self-service).
  const modalNode = (forcedChangePw || showChangePw) && window.ChangePasswordModal
    ? React.createElement(window.ChangePasswordModal, {
        forced: !!forcedChangePw,
        onClose: () => setShowChangePw(false),
        onSuccess: () => { setShowChangePw(false); recheck(); },
      })
    : null;
  return React.createElement(React.Fragment, null, children, modalNode);
}

// ─── User chip — shown in header when authenticated ─────────────
function UserChip() {
  const [open, setOpen] = useState(false);
  const [me, setMe] = useState(window.ArgusAuth?.me || null);
  const ref = useRef(null);

  useEffect(() => {
    function poll() {
      const m = window.ArgusAuth?.me;
      if (m && (!me || me.id !== m.id)) setMe(m);
    }
    const id = setInterval(poll, 500);
    return () => clearInterval(id);
  }, [me]);

  useEffect(() => {
    function close(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
    if (open) document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);

  if (!me) return null;
  const initials = (me.display_name || me.email || '?').split(/[\s@]+/).filter(Boolean)
                    .slice(0, 2).map(s => s[0].toUpperCase()).join('') || '?';
  const primaryRole = (me.roles || [])[0] || 'USER';

  return React.createElement('div', { ref, style: { position: 'relative' } },
    React.createElement('button', {
      className: 'auth-user-chip',
      onClick: () => setOpen(o => !o),
      title: `${me.email} · ${primaryRole}`,
    },
      React.createElement('span', { className: 'auth-user-chip-avatar' }, initials),
      React.createElement('span', null,
        React.createElement('span', { style: { fontWeight: 600 } }, me.display_name || me.email),
        React.createElement('span', {
          style: { display: 'block', fontSize: 9, opacity: 0.6,
                    letterSpacing: 1, textTransform: 'uppercase' }
        }, primaryRole),
      ),
      React.createElement('span', { style: { fontSize: 9, opacity: 0.5 } }, '▾'),
    ),
    open && React.createElement('div', { className: 'auth-user-menu' },
      React.createElement('div', {
        className: 'auth-user-menu-row',
        onClick: () => {
          setOpen(false);
          window.dispatchEvent(new CustomEvent('navigate', { detail: 'users' }));
        },
      }, '👥 User & access management'),
      React.createElement('div', {
        className: 'auth-user-menu-row',
        onClick: () => {
          setOpen(false);
          window.ArgusAuth?.openChangePassword?.();
        },
      }, '🔑 Change password'),
      React.createElement('div', {
        className: 'auth-user-menu-row',
        onClick: () => {
          setOpen(false);
          window.open('/auth/me', '_blank');
        },
      }, '🔐 My security'),
      React.createElement('div', {
        className: 'auth-user-menu-row',
        onClick: () => {
          setOpen(false);
          window.open('/auth/sessions', '_blank');
        },
      }, '📋 My sessions'),
      React.createElement('div', { className: 'auth-user-menu-divider' }),
      React.createElement('div', {
        className: 'auth-user-menu-row danger',
        onClick: () => { setOpen(false); window.ArgusAuth?.logout?.(); },
      }, '↪ Sign out'),
    )
  );
}

// Make components globally accessible to other files
window.UserChip = UserChip;
window.AuthBoundary = AuthBoundary;

// Bootstrap — wrap the cockpit in AuthBoundary so the cinematic login
// page renders for unauthenticated users.  Bypasses gracefully when
// the auth backend isn't installed (so dev without auth still works).
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  React.createElement(AuthBoundary, null,
    React.createElement(window.StoreProvider, null,
      React.createElement(App)
    )
  )
);
