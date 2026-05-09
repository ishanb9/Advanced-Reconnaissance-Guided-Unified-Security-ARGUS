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
// EVERY existing page is still registered in PAGE_COMPONENT.  Every
// dispatch action and WS handler from store.js is untouched.  This is
// a presentation layer refresh only.
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useCallback, useMemo, useRef } = React;

// ─── Design tokens ────────────────────────────────────────────
const T = {
  bgBase:       '#0B0C12',      // slightly deeper canvas
  bgSidebar:    '#0A0B11',
  bgSurface:    '#13151E',
  bgPanel:      '#1A1D28',
  bgElevated:   '#222638',
  bgGlass:      'rgba(19,21,30,0.78)',
  accent:       '#00E5A0',
  accentDim:    '#00A372',
  violet:       '#7B6CF6',
  cyan:         '#38BDF8',
  amber:        '#F5C842',
  critical:     '#FF4560',
  high:         '#FF8C42',
  medium:       '#F5C842',
  low:          '#4ADE80',
  border:       '#1D2135',
  borderLight:  '#262B40',
  borderBright: '#343B56',
  textPrimary:  '#E5EAF6',
  textSecondary:'#9098B0',
  textMuted:    '#525B76',
  fontUI:       "'Inter', system-ui, sans-serif",
  fontMono:     "'JetBrains Mono', 'Courier New', monospace",
};

// ─── Error boundary (unchanged behaviour) ─────────────────────
class PageErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(e) { return { error: e }; }
  render() {
    if (this.state.error) {
      return React.createElement('div', {
        style: { padding: 40, color: T.critical, fontFamily: T.fontMono, fontSize: 12 }
      },
        React.createElement('div', { style: { fontSize: 15, marginBottom: 12, fontWeight: 700 } }, '⚠ Page Error'),
        React.createElement('pre', {
          style: {
            background: T.bgPanel, padding: 14, borderRadius: 8,
            border: `1px solid ${T.critical}44`, whiteSpace: 'pre-wrap',
            wordBreak: 'break-word', fontSize: 11, color: T.textSecondary, margin: 0
          }
        }, this.state.error?.message || String(this.state.error)),
        React.createElement('button', {
          onClick: () => this.setState({ error: null }),
          style: {
            marginTop: 12, padding: '6px 14px', borderRadius: 6, cursor: 'pointer',
            border: `1px solid ${T.critical}55`, background: `${T.critical}15`,
            color: T.critical, fontSize: 11, fontFamily: T.fontUI
          }
        }, '↺ Retry')
      );
    }
    return this.props.children;
  }
}

// ─── Page registry ────────────────────────────────────────────
// `risk` is the new default landing page.  Mission Control is kept
// for operators who prefer the dense plan-step view.
const PAGES = [
  { key: 'risk',      icon: '◇', label: 'Risk Dashboard',         group: 'Overview',    desc: 'Aggregate risk score, kill-chain, severity treemap' },
  { key: 'mission',   icon: '⚡', label: 'Mission Control',         group: 'Overview',    desc: 'Phase plan, agent status, live feed' },
  { key: 'target',    icon: '⊕', label: 'Target Config',           group: 'Overview',    desc: 'Configure scope, credentials, mode' },
  { key: 'sessions',  icon: '◈', label: 'Session History',         group: 'Overview',    desc: 'Past engagements and resume points' },

  { key: 'agents',    icon: '◉', label: 'Agent Console',           group: 'Analysis',    desc: 'Live status of every running agent' },
  { key: 'reasoning', icon: '◐', label: 'Reasoning Engine',        group: 'Analysis',    desc: 'Hypothesis tree, decisions, attack paths' },
  { key: 'ai_obs',    icon: '◎', label: 'AI Observability',        group: 'Analysis',    desc: 'LLM calls, prompt traces, RAG queries' },
  { key: 'findings',  icon: '◆', label: 'Findings Board',          group: 'Analysis',    desc: 'All discovered findings, filterable' },
  { key: 'graph',     icon: '⬡', label: 'Attack Graph',            group: 'Analysis',    desc: 'Node-link graph of attack paths' },
  { key: 'web_test',  icon: '🕸', label: 'Web Testing',             group: 'Analysis',    desc: 'WSTG-aligned web app testing matrix' },
  { key: 'osint',     icon: '◍', label: 'OSINT Intel',             group: 'Analysis',    desc: 'External intelligence, dorks, breaches' },

  { key: 'lateral',   icon: '⇢', label: 'Lateral & Post-Ex',       group: 'Exploitation', desc: 'Pivot, lateral movement, persistence' },
  { key: 'creds',     icon: '⊛', label: 'Credentials Vault',       group: 'Exploitation', desc: 'Captured / cracked credentials' },
  { key: 'shells',    icon: '⊜', label: 'Shell Manager',           group: 'Exploitation', desc: 'Active reverse / SSH shells' },
  { key: 'payloads',  icon: '◧', label: 'Payload Builder',         group: 'Exploitation', desc: 'Generate msfvenom payloads' },
  { key: 'tools',     icon: '⊞', label: 'Tool Workshop',           group: 'Exploitation', desc: 'Run any tool from the MCP catalog' },

  { key: 'report',    icon: '◧', label: 'Report',                  group: 'Reporting',   desc: 'Generated HTML / PDF report' },
  { key: 'metrics',   icon: '◫', label: 'Metrics',                 group: 'Reporting',   desc: 'Engagement metrics & throughput' },
  { key: 'knowledge', icon: '⊕', label: 'Knowledge Base',          group: 'Knowledge',   desc: 'Curated playbooks and references' },
];

const PAGE_COMPONENT = {
  risk:      () => window.RiskDashboard,
  mission:   () => window.MissionControl,
  target:    () => window.TargetConfig,
  sessions:  () => window.SessionHistory,
  agents:    () => window.AgentConsole,
  ai_obs:    () => window.AIObservability,
  findings:  () => window.FindingsBoard,
  graph:     () => window.AttackGraph,
  web_test:  () => window.WebTesting,
  osint:     () => window.OsintIntel,
  lateral:   () => window.LateralPostPage,
  creds:     () => window.CredentialsPage,
  shells:    () => window.ShellManager,
  payloads:  () => window.PayloadBuilder,
  tools:     () => window.ToolWorkshop,
  report:    () => window.ReportPage,
  metrics:   () => window.MetricsDash,
  knowledge: () => window.KnowledgePage,
  reasoning: () => window.ReasoningEnginePage,
};

const GROUP_ORDER = ['Overview', 'Analysis', 'Exploitation', 'Reporting', 'Knowledge'];

const GROUP_COLORS = {
  Overview:     T.accent,
  Analysis:     T.cyan,
  Exploitation: T.critical,
  Reporting:    T.medium,
  Knowledge:    T.violet,
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
  { id: 'midnight', label: 'Midnight',  swatch: '#00E5A0', desc: 'Default — deep blue-black, teal accent' },
  { id: 'graphite', label: 'Graphite',  swatch: '#38BDF8', desc: 'Neutral charcoal, cyan accent' },
  { id: 'sapphire', label: 'Sapphire',  swatch: '#4F8DFD', desc: 'Saturated corporate blue' },
  { id: 'amber',    label: 'Amber',     swatch: '#FFB22A', desc: 'Hacker CRT vibe' },
  { id: 'contrast', label: 'Contrast',  swatch: '#FFE600', desc: 'High-contrast for accessibility' },
  { id: 'daylight', label: 'Daylight',  swatch: '#00A372', desc: 'Light theme for bright environments' },
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
        background: T.bgPanel, border: `1px solid ${T.border}`,
        color: T.textSecondary, fontSize: 11, fontFamily: T.fontUI,
        transition: 'border-color 0.15s, color 0.15s',
      },
      onMouseEnter: e => { e.currentTarget.style.borderColor = T.borderLight; e.currentTarget.style.color = T.textPrimary; },
      onMouseLeave: e => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.color = T.textSecondary; },
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
        background: T.bgSurface, border: `1px solid ${T.borderBright}`,
        boxShadow: '0 12px 32px rgba(0,0,0,0.6)',
      }
    },
      React.createElement('div', {
        style: { fontSize: 9, color: T.textMuted, padding: '6px 10px 8px',
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
          onMouseEnter: e => { if (!active) e.currentTarget.style.background = `${T.textPrimary}07`; },
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
              style: { fontSize: 12, fontWeight: 600, color: active ? t.swatch : T.textPrimary }
            }, t.label),
            React.createElement('div', {
              style: { fontSize: 10, color: T.textMuted,
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

// ─── Service status dot ──────────────────────────────────────
function SvcDot({ label, status, mini = false }) {
  const color = status === 'online' ? T.low
    : status === 'offline'          ? T.critical
    : T.medium;
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
      fontFamily: T.fontUI, letterSpacing: 0.4,
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
  const accent = GROUP_COLORS[item.group] || T.accent;

  return React.createElement('div', {
    onClick,
    onMouseEnter: () => setHovered(true),
    onMouseLeave: () => setHovered(false),
    title: isCollapsed ? `${item.label} — ${item.desc}` : item.desc,
    style: {
      display: 'flex', alignItems: 'center',
      gap: isCollapsed ? 0 : 10,
      margin: '1px 6px',
      padding: isCollapsed ? '8px 0' : '8px 11px',
      justifyContent: isCollapsed ? 'center' : 'flex-start',
      borderRadius: 8, cursor: 'pointer',
      fontFamily: T.fontUI, fontSize: 12, fontWeight: isActive ? 600 : 450,
      letterSpacing: 0.1,
      color: isActive ? accent : hovered ? T.textPrimary : T.textSecondary,
      background: isActive
        ? `${accent}14`
        : hovered ? `${T.textPrimary}08` : 'transparent',
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
        height: 1, background: T.border, margin: '6px 14px',
      }
    });
  }
  return React.createElement('div', {
    onClick: onToggle,
    style: {
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '10px 14px 5px',
      fontSize: 9, letterSpacing: 1.6,
      color: T.textMuted, textTransform: 'uppercase', fontWeight: 700,
      fontFamily: T.fontUI, cursor: 'pointer', userSelect: 'none',
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
        fontSize: 10, color: T.textMuted,
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
        background: T.bgSurface, border: `1px solid ${T.critical}`,
        borderRadius: 14, padding: '26px 30px', minWidth: 430, maxWidth: 530,
        boxShadow: `0 0 60px ${T.critical}30, 0 12px 40px rgba(0,0,0,0.65)`,
        fontFamily: T.fontUI,
      }
    },
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 18 }
      },
        React.createElement('div', {
          style: {
            width: 36, height: 36, borderRadius: 8, flexShrink: 0,
            background: `${T.critical}1F`, border: `1px solid ${T.critical}50`,
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
          }
        }, '⏱'),
        React.createElement('div', null,
          React.createElement('div', {
            style: { fontSize: 15, fontWeight: 700, color: T.critical, letterSpacing: 0.2, marginBottom: 3 }
          }, 'Tool Running Too Long'),
          React.createElement('div', {
            style: { fontSize: 11, color: T.textSecondary, lineHeight: 1.5 }
          }, 'This tool has exceeded its time limit. Choose to extend or stop it.')
        )
      ),

      React.createElement('div', {
        style: {
          background: T.bgPanel, borderRadius: 8, padding: '10px 14px',
          border: `1px solid ${T.border}`, marginBottom: 20,
        }
      },
        ['Tool', 'Subagent', 'Running for'].map((lbl, i) => {
          const val = i === 0 ? (warn.tool || 'unknown')
                    : i === 1 ? (warn.subagent || 'unknown')
                              : fmtElapsed(warn.elapsed_sec || 0);
          const color = i === 0 ? T.cyan : i === 1 ? T.textPrimary : T.medium;
          return React.createElement('div', {
            key: lbl,
            style: {
              display: 'flex', justifyContent: 'space-between', padding: '5px 0',
              borderBottom: i < 2 ? `1px solid ${T.border}55` : 'none',
            }
          },
            React.createElement('span', {
              style: { fontSize: 9, color: T.textMuted, textTransform: 'uppercase',
                       letterSpacing: 1, fontFamily: T.fontMono }
            }, lbl),
            React.createElement('span', {
              style: { fontSize: 11, fontFamily: T.fontMono, color, fontWeight: i === 0 || i === 2 ? 700 : 500 }
            }, val)
          );
        })
      ),

      React.createElement('div', {
        style: { fontSize: 10, color: T.textSecondary, marginBottom: 10, letterSpacing: 0.3 }
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
              border: `1px solid ${T.accent}50`, background: `${T.accent}10`,
              color: T.accent, fontSize: 11, fontWeight: 700, fontFamily: T.fontMono,
            }
          }, label)
        )
      ),

      React.createElement('button', {
        onClick: stopTool,
        style: {
          width: '100%', padding: '10px 0', borderRadius: 7, cursor: 'pointer',
          border: `1px solid ${T.critical}55`, background: `${T.critical}12`,
          color: T.critical, fontSize: 12, fontWeight: 700,
          fontFamily: T.fontMono, letterSpacing: 0.5,
        }
      }, '■  Stop This Tool')
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

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return PAGES;
    return PAGES.filter(p =>
      p.label.toLowerCase().includes(q) ||
      p.group.toLowerCase().includes(q) ||
      p.desc.toLowerCase().includes(q) ||
      p.key.includes(q)
    );
  }, [query]);

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
        background: T.bgSurface, border: `1px solid ${T.borderBright}`,
        borderRadius: 14, boxShadow: '0 20px 60px rgba(0,0,0,0.7)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }
    },
      // Search input
      React.createElement('div', {
        style: {
          padding: '14px 16px', borderBottom: `1px solid ${T.border}`,
          display: 'flex', alignItems: 'center', gap: 10,
        }
      },
        React.createElement('span', {
          style: { color: T.textMuted, fontSize: 14 }
        }, '⌕'),
        React.createElement('input', {
          ref: inputRef,
          value: query,
          onChange: e => { setQuery(e.target.value); setActiveIdx(0); },
          placeholder: 'Type to search pages…',
          style: {
            flex: 1, background: 'transparent', border: 'none', outline: 'none',
            color: T.textPrimary, fontSize: 14, fontFamily: T.fontUI,
          }
        }),
        React.createElement('span', {
          style: {
            fontSize: 9, color: T.textMuted, padding: '2px 6px',
            borderRadius: 4, border: `1px solid ${T.borderLight}`,
            fontFamily: T.fontMono, letterSpacing: 0.5,
          }
        }, 'ESC')
      ),
      // Results
      React.createElement('div', {
        style: { flex: 1, overflowY: 'auto', padding: 6 }
      },
        filtered.length === 0
          ? React.createElement('div', {
              style: { padding: 30, textAlign: 'center', color: T.textMuted, fontSize: 12 }
            }, 'No matches')
          : filtered.map((p, i) => {
              const accent = GROUP_COLORS[p.group] || T.accent;
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
                      fontSize: 13, color: isActive ? T.textPrimary : T.textPrimary,
                      fontWeight: 600, marginBottom: 2,
                    }
                  }, p.label),
                  React.createElement('div', {
                    style: {
                      fontSize: 10, color: T.textMuted,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }
                  }, p.desc)
                ),
                React.createElement('span', {
                  style: {
                    fontSize: 9, color: accent, padding: '2px 8px',
                    borderRadius: 10, background: `${accent}15`,
                    border: `1px solid ${accent}30`,
                    fontFamily: T.fontMono, letterSpacing: 0.6, fontWeight: 700,
                  }
                }, p.group),
              );
            })
      ),
      React.createElement('div', {
        style: {
          padding: '8px 14px', borderTop: `1px solid ${T.border}`,
          display: 'flex', gap: 14, fontSize: 9, color: T.textMuted,
          fontFamily: T.fontMono, letterSpacing: 0.5,
        }
      },
        React.createElement('span', null, '↑↓  navigate'),
        React.createElement('span', null, '↵  select'),
        React.createElement('span', null, 'esc  close'),
        React.createElement('span', { style: { marginLeft: 'auto', color: T.textSecondary } }, `${filtered.length} of ${PAGES.length}`)
      )
    )
  );
}

// ─── App ─────────────────────────────────────────────────────
function App() {
  const initial = loadPrefs();
  const [page, setPage] = useState(initial.page || 'risk');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(!!initial.sidebarCollapsed);
  const [groupOpen, setGroupOpen] = useState(initial.groupOpen || {
    Overview: true, Analysis: true, Exploitation: true, Reporting: true, Knowledge: true,
  });
  const [theme, setTheme] = useState(initial.theme || 'midnight');
  const [paletteOpen, setPaletteOpen] = useState(false);
  const { state } = window.useStore();
  const { sysStatus, activeSession, findingsSummary, wsConnected, currentPhase } = state;

  // Apply persisted theme on mount + whenever it changes
  useEffect(() => { applyTheme(theme); }, [theme]);

  // Persist UI prefs
  useEffect(() => {
    savePrefs({ page, sidebarCollapsed, groupOpen, theme });
  }, [page, sidebarCollapsed, groupOpen, theme]);

  // Custom navigate event (from RiskDashboard buttons + other pages)
  useEffect(() => {
    const handler = (e) => setPage(e.detail);
    window.addEventListener('navigate', handler);
    return () => window.removeEventListener('navigate', handler);
  }, []);

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

  const current  = PAGES.find(p => p.key === page) || PAGES[0];
  const PageComp = PAGE_COMPONENT[page]?.();

  function navigateTo(key) { setPage(key); }
  function toggleGroup(g)  { setGroupOpen(o => ({ ...o, [g]: !o[g] })); }

  function renderPage() {
    if (!PageComp) {
      return React.createElement('div', {
        style: {
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          justifyContent: 'center', height: '60vh',
          color: T.textMuted, fontFamily: T.fontMono, fontSize: 12
        }
      },
        React.createElement('div', { style: { fontSize: 32, marginBottom: 14, opacity: 0.2 } }, '○'),
        `Loading ${current.label}…`
      );
    }
    return React.createElement(PageErrorBoundary, { key: page },
      React.createElement(PageComp, { sessionId: state.sessionId, activeSession })
    );
  }

  // ── Risk pill (header) ──────────────────────────────────────
  const summary = findingsSummary || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const severityScore =
    (summary.critical || 0) * 25 +
    (summary.high     || 0) * 12 +
    (summary.medium   || 0) * 5 +
    (summary.low      || 0) * 2;
  const riskScore = Math.min(100, severityScore);
  const riskColor = riskScore >= 70 ? T.critical : riskScore >= 40 ? T.high : riskScore >= 15 ? T.medium : T.low;
  const riskLabel = riskScore >= 70 ? 'CRITICAL' : riskScore >= 40 ? 'HIGH' : riskScore >= 15 ? 'MEDIUM' : riskScore > 0 ? 'LOW' : 'BASELINE';

  // ── Render ──────────────────────────────────────────────────
  return React.createElement('div', {
    style: {
      height: '100vh', display: 'flex', flexDirection: 'column',
      overflow: 'hidden', background: T.bgBase,
      fontFamily: T.fontUI, color: T.textPrimary,
    }
  },

    React.createElement(ToolTimeoutModal),
    React.createElement(CommandPalette, {
      open: paletteOpen,
      onClose: () => setPaletteOpen(false),
      onNavigate: navigateTo,
    }),

    // ════════════════════════════════ HEADER ════════════════════
    React.createElement('div', {
      style: {
        height: 52, flexShrink: 0,
        background: T.bgGlass, backdropFilter: 'blur(8px)',
        borderBottom: `1px solid ${T.border}`,
        display: 'flex', alignItems: 'center',
        padding: '0 16px', gap: 14, zIndex: 100,
        position: 'relative',
      }
    },
      // Accent gradient line at very bottom
      React.createElement('div', {
        style: {
          position: 'absolute', bottom: 0, left: 0, right: 0, height: 1,
          background: `linear-gradient(90deg, transparent 0%, ${T.accent}50 30%, ${T.violet}50 70%, transparent 100%)`,
        }
      }),

      // Brand
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: 11, flexShrink: 0 }
      },
        React.createElement('div', {
          style: {
            width: 32, height: 32, borderRadius: 9, flexShrink: 0,
            background: `linear-gradient(135deg, ${T.accent}, ${T.violet})`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 16, color: '#0B0C12',
            fontWeight: 800,
            boxShadow: `0 0 20px ${T.accent}55`,
          }
        }, '◈'),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', lineHeight: 1 } },
          React.createElement('span', {
            style: { fontFamily: T.fontMono, fontSize: 13, fontWeight: 700, color: T.accent, letterSpacing: 2.4 }
          }, 'ARGUS'),
          React.createElement('span', {
            style: { fontFamily: T.fontUI, fontSize: 9, color: T.textMuted, letterSpacing: 1.6, marginTop: 2 }
          }, 'PENTEST PLATFORM')
        )
      ),

      React.createElement('div', { style: { width: 1, height: 22, background: T.border, flexShrink: 0, marginLeft: 4 } }),

      // Service status
      React.createElement('div', { style: { display: 'flex', gap: 6, alignItems: 'center' } },
        React.createElement(SvcDot, { label: 'MCP',   status: sysStatus.mcp }),
        React.createElement(SvcDot, { label: 'DB',    status: sysStatus.mongo }),
        React.createElement(SvcDot, { label: 'LLM',   status: sysStatus.ollama })
      ),

      // Command palette trigger (centered-ish)
      React.createElement('button', {
        onClick: () => setPaletteOpen(true),
        style: {
          marginLeft: 24, marginRight: 'auto',
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '5px 12px 5px 14px', borderRadius: 8,
          background: T.bgPanel, border: `1px solid ${T.border}`,
          color: T.textMuted, cursor: 'pointer',
          fontSize: 11, fontFamily: T.fontUI,
          minWidth: 240, justifyContent: 'flex-start',
          transition: 'border-color 0.15s, color 0.15s',
        },
        onMouseEnter: e => { e.currentTarget.style.borderColor = T.borderLight; e.currentTarget.style.color = T.textSecondary; },
        onMouseLeave: e => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.color = T.textMuted; },
      },
        React.createElement('span', null, '⌕'),
        React.createElement('span', null, 'Quick navigate…'),
        React.createElement('span', {
          style: {
            marginLeft: 'auto', padding: '1px 6px', borderRadius: 4,
            fontSize: 9, fontFamily: T.fontMono, color: T.textMuted,
            border: `1px solid ${T.borderLight}`, letterSpacing: 0.5,
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
          style: { fontSize: 9, color: riskColor, fontWeight: 700, letterSpacing: 1, fontFamily: T.fontMono }
        }, 'RISK'),
        React.createElement('span', {
          style: { color: riskColor, fontFamily: T.fontMono, fontSize: 13, fontWeight: 700 }
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
          background: `${T.accent}0D`,
          border: `1px solid ${T.accent}30`,
          transition: 'all 0.15s',
        }
      },
        React.createElement('span', {
          style: {
            width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
            background: wsConnected ? T.low : T.textMuted,
            boxShadow: wsConnected ? `0 0 8px ${T.low}` : 'none',
          }
        }),
        React.createElement('span', {
          style: { color: T.accent, fontFamily: T.fontMono, fontSize: 12, fontWeight: 700 }
        }, activeSession.target_ip),
        React.createElement('span', {
          style: {
            fontSize: 9, letterSpacing: 1, color: T.textMuted,
            background: T.bgPanel, border: `1px solid ${T.border}`,
            padding: '1px 6px', borderRadius: 4,
            textTransform: 'uppercase', fontWeight: 600
          }
        }, currentPhase || 'IDLE')
      ),

      // Critical findings badge (only when > 0)
      findingsSummary.critical > 0 && React.createElement('div', {
        onClick: () => navigateTo('findings'),
        style: {
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 12px', borderRadius: 20, cursor: 'pointer',
          background: `${T.critical}12`,
          border: `1px solid ${T.critical}40`,
          color: T.critical, fontSize: 11, fontWeight: 700,
          fontFamily: T.fontMono, letterSpacing: 0.5,
          animation: 'argus-pulse 2.4s ease-in-out infinite',
        }
      }, `⚠ ${findingsSummary.critical} CRIT`),

      // Theme switcher (always visible, right-most before logout-style icons)
      React.createElement(ThemeSwitcher, { current: theme, onPick: setTheme })
    ),

    // ════════════════════════════════ BODY ══════════════════════
    React.createElement('div', { style: { flex: 1, display: 'flex', overflow: 'hidden' } },

      // ══════════════════════ SIDEBAR ═══════════════════════════
      React.createElement('div', {
        style: {
          width: sidebarCollapsed ? 56 : 220,
          minWidth: sidebarCollapsed ? 56 : 220,
          flexShrink: 0,
          background: T.bgSidebar,
          borderRight: `1px solid ${T.border}`,
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
            borderBottom: `1px solid ${T.border}`,
          }
        },
          !sidebarCollapsed && React.createElement('span', {
            style: {
              fontSize: 9, color: T.textMuted, letterSpacing: 1.5,
              textTransform: 'uppercase', fontWeight: 700,
            }
          }, 'NAVIGATION'),
          React.createElement('button', {
            onClick: () => setSidebarCollapsed(c => !c),
            title: sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar',
            style: {
              background: 'transparent', border: 'none', cursor: 'pointer',
              color: T.textMuted, fontSize: 13, padding: 0,
              transition: 'color 0.12s',
            },
            onMouseEnter: e => { e.currentTarget.style.color = T.accent; },
            onMouseLeave: e => { e.currentTarget.style.color = T.textMuted; },
          }, sidebarCollapsed ? '›' : '‹')
        ),

        // Scroll area
        React.createElement('div', {
          style: { flex: 1, overflowY: 'auto', padding: '6px 0' }
        },
          GROUP_ORDER.map(group => {
            const items = PAGES.filter(p => p.group === group);
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
              isOpen && items.map(item =>
                React.createElement(NavItem, {
                  key: item.key,
                  item,
                  isActive: page === item.key,
                  isCollapsed: sidebarCollapsed,
                  onClick: () => navigateTo(item.key),
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
                borderTop: `1px solid ${T.border}`, flexShrink: 0,
              }
            },
              sidebarCollapsed
                ? React.createElement('div', {
                    onClick: () => navigateTo('mission'),
                    title: `${activeSession.target_ip} · ${currentPhase || 'idle'}`,
                    style: {
                      width: 38, height: 38, borderRadius: 8, margin: '0 auto',
                      background: `${T.accent}15`, border: `1px solid ${T.accent}40`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      cursor: 'pointer', position: 'relative',
                    }
                  },
                    React.createElement('span', {
                      style: {
                        position: 'absolute', top: 4, right: 4, width: 6, height: 6,
                        borderRadius: '50%', background: wsConnected ? T.low : T.textMuted,
                        boxShadow: wsConnected ? `0 0 5px ${T.low}` : 'none',
                      }
                    }),
                    React.createElement('span', { style: { color: T.accent, fontSize: 14 } }, '◉')
                  )
                : React.createElement('div', {
                    onClick: () => navigateTo('mission'),
                    style: {
                      background: T.bgPanel,
                      border: `1px solid ${T.borderLight}`,
                      borderRadius: 8, padding: '8px 10px', cursor: 'pointer',
                      transition: 'border-color 0.15s',
                    }
                  },
                    React.createElement('div', {
                      style: { fontSize: 9, letterSpacing: 1.2, color: T.textMuted,
                               textTransform: 'uppercase', fontWeight: 700, marginBottom: 4 }
                    }, '● Active Session'),
                    React.createElement('div', {
                      style: {
                        fontFamily: T.fontMono, fontSize: 13, color: T.accent,
                        fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                      }
                    }, activeSession.target_ip),
                    React.createElement('div', {
                      style: { display: 'flex', justifyContent: 'space-between', marginTop: 5, fontSize: 10 }
                    },
                      React.createElement('span', {
                        style: { color: T.textMuted, textTransform: 'uppercase', letterSpacing: 0.8 }
                      }, currentPhase || 'IDLE'),
                      React.createElement('span', {
                        style: { color: wsConnected ? T.low : T.textMuted, fontFamily: T.fontMono, fontWeight: 600 }
                      }, wsConnected ? '● LIVE' : '○ OFF')
                    )
                  )
            )
          : !sidebarCollapsed && React.createElement('div', {
              style: { padding: '12px', borderTop: `1px solid ${T.border}`, flexShrink: 0 }
            },
              React.createElement('div', {
                onClick: () => navigateTo('target'),
                style: {
                  background: `${T.accent}0E`,
                  border: `1px dashed ${T.accent}40`,
                  borderRadius: 8, padding: '8px 10px', cursor: 'pointer',
                  textAlign: 'center', transition: 'all 0.15s',
                }
              },
                React.createElement('div', {
                  style: { fontSize: 9, letterSpacing: 1, color: T.accent,
                           textTransform: 'uppercase', fontWeight: 700, marginBottom: 3 }
                }, '+ New Session'),
                React.createElement('div', {
                  style: { fontSize: 10, color: T.textMuted }
                }, 'Configure target')
              )
            )
      ),

      // ═════════════════════ CONTENT ════════════════════════════
      React.createElement('div', {
        style: {
          flex: 1, overflowY: 'auto',
          background: T.bgBase,
          padding: 22,
        }
      },
        renderPage()
      )
    )
  );
}

// Bootstrap
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  React.createElement(window.StoreProvider, null,
    React.createElement(App)
  )
);
