// ═══════════════════════════════════════════════════════════
// ARGUS Pentest Platform — Root App Shell
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useCallback } = React;

// ─── Design tokens (mirrored inline so they work regardless of CSS load order) ─
const T = {
  bgBase:     '#0D0E14',
  bgSidebar:  '#0A0B10',
  bgSurface:  '#13151E',
  bgPanel:    '#1A1D28',
  bgElevated: '#222638',
  accent:     '#00E5A0',
  accentDim:  '#00A372',
  violet:     '#7B6CF6',
  cyan:       '#38BDF8',
  critical:   '#FF4560',
  medium:     '#F5C842',
  low:        '#4ADE80',
  border:     '#1E2236',
  borderLight:'#262B40',
  textPrimary:'#E2E8F4',
  textSecondary:'#8892AA',
  textMuted:  '#4A5168',
  fontUI:     "'Inter', system-ui, sans-serif",
  fontMono:   "'JetBrains Mono', 'Courier New', monospace",
};

// ─── Error Boundary ──────────────────────────────────────────
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
const PAGES = [
  { key: 'mission',   icon: '⚡', label: 'Mission Control',        group: 'Operations'   },
  { key: 'target',    icon: '⊕',  label: 'Target Config',          group: 'Operations'   },
  { key: 'sessions',  icon: '◈',  label: 'Session History',        group: 'Operations'   },
  { key: 'agents',    icon: '◉',  label: 'Agent Console',          group: 'Analysis'     },
  { key: 'ai_obs',    icon: '◎',  label: 'AI Observability',       group: 'Analysis'     },
  { key: 'findings',  icon: '◆',  label: 'Findings Board',         group: 'Analysis'     },
  { key: 'graph',     icon: '⬡',  label: 'Attack Graph',           group: 'Analysis'     },
  { key: 'osint',     icon: '◍',  label: 'OSINT Intel',            group: 'Analysis'     },
  { key: 'lateral',   icon: '⇢',  label: 'Lateral & Post-Exploit', group: 'Exploitation' },
  { key: 'creds',     icon: '⊛',  label: 'Credentials Vault',      group: 'Exploitation' },
  { key: 'shells',    icon: '⊜',  label: 'Shell Manager',          group: 'Exploitation' },
  { key: 'payloads',  icon: '◈',  label: 'Payload Builder',        group: 'Exploitation' },
  { key: 'tools',     icon: '⊞',  label: 'Tool Workshop',          group: 'Exploitation' },
  { key: 'report',    icon: '◧',  label: 'Report',                 group: 'Reporting'    },
  { key: 'metrics',   icon: '◫',  label: 'Metrics',                group: 'Reporting'    },
  { key: 'knowledge', icon: '◉',  label: 'Knowledge Base',         group: 'Knowledge'    },
];

// Map keys to actual component references (preserving original window.* names)
const PAGE_COMPONENT = {
  mission:   () => window.MissionControl,
  target:    () => window.TargetConfig,
  sessions:  () => window.SessionHistory,
  agents:    () => window.AgentConsole,
  ai_obs:    () => window.AIObservability,
  findings:  () => window.FindingsBoard,
  graph:     () => window.AttackGraph,
  osint:     () => window.OsintIntel,
  lateral:   () => window.LateralPostPage,
  creds:     () => window.CredentialsPage,
  shells:    () => window.ShellManager,
  payloads:  () => window.PayloadBuilder,
  tools:     () => window.ToolWorkshop,
  report:    () => window.ReportPage,
  metrics:   () => window.MetricsDash,
  knowledge: () => window.KnowledgePage,
};

const GROUP_ORDER = ['Operations', 'Analysis', 'Exploitation', 'Reporting', 'Knowledge'];

const GROUP_COLORS = {
  Operations:   T.accent,
  Analysis:     T.cyan,
  Exploitation: T.critical,
  Reporting:    T.medium,
  Knowledge:    T.violet,
};

// ─── Service status dot ───────────────────────────────────────
function SvcDot({ label, status }) {
  const color = status === 'online' ? T.low
    : status === 'offline'          ? T.critical
    : T.medium;
  const isOnline = status === 'online';
  return React.createElement('div', {
    style: {
      display: 'flex', alignItems: 'center', gap: 5,
      padding: '3px 10px', borderRadius: 20,
      background: `${color}12`,
      border: `1px solid ${color}35`,
      fontSize: 10, fontWeight: 600, color,
      fontFamily: T.fontUI, letterSpacing: 0.4,
      cursor: 'default',
    }
  },
    React.createElement('span', {
      style: {
        width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0,
        boxShadow: isOnline ? `0 0 6px ${color}` : 'none',
      }
    }),
    label
  );
}

// ─── Nav item (tracks hover with local state) ─────────────────
function NavItem({ item, isActive, onClick }) {
  const [hovered, setHovered] = useState(false);

  const accentColor = GROUP_COLORS[item.group] || T.accent;

  return React.createElement('div', {
    onClick,
    onMouseEnter: () => setHovered(true),
    onMouseLeave: () => setHovered(false),
    title: item.label,
    style: {
      display: 'flex', alignItems: 'center', gap: 9,
      margin: '1px 8px', padding: '7px 10px',
      borderRadius: 7, cursor: 'pointer',
      fontFamily: T.fontUI, fontSize: 12, fontWeight: isActive ? 600 : 450,
      letterSpacing: 0.1,
      color: isActive ? accentColor : hovered ? T.textSecondary : T.textMuted,
      background: isActive
        ? `${accentColor}12`
        : hovered ? `${T.textPrimary}06` : 'transparent',
      borderLeft: `3px solid ${isActive ? accentColor : 'transparent'}`,
      transition: 'all 0.12s ease',
      userSelect: 'none',
    }
  },
    React.createElement('span', {
      style: {
        width: 18, textAlign: 'center', flexShrink: 0, fontSize: 13,
        opacity: isActive ? 1 : 0.65,
      }
    }, item.icon),
    React.createElement('span', { style: { flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } },
      item.label
    )
  );
}

// ─── Tool Timeout Modal ───────────────────────────────────────
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

  const OVERLAY = {
    position: 'fixed', inset: 0, zIndex: 9999,
    background: 'rgba(0,0,0,0.68)', backdropFilter: 'blur(5px)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
  };
  const CARD = {
    background: '#13151E', border: '1px solid #FF4560',
    borderRadius: 14, padding: '26px 30px', minWidth: 430, maxWidth: 530,
    boxShadow: '0 0 60px rgba(255,69,96,0.18), 0 12px 40px rgba(0,0,0,0.65)',
    fontFamily: "'Inter', system-ui, sans-serif",
  };
  const INFO_ROW = {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,0.04)',
  };
  const LABEL_STYLE = {
    fontSize: 9, color: '#4A5168', textTransform: 'uppercase',
    letterSpacing: 1, fontFamily: "'JetBrains Mono', monospace",
  };
  const VALUE_STYLE = {
    fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
  };

  return React.createElement('div', { style: OVERLAY },
    React.createElement('div', { style: CARD },

      // ── Header ────────────────────────────────────────────────
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 18 }
      },
        React.createElement('div', {
          style: {
            width: 36, height: 36, borderRadius: 8, flexShrink: 0,
            background: 'rgba(255,69,96,0.12)', border: '1px solid rgba(255,69,96,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
          }
        }, '⏱'),
        React.createElement('div', null,
          React.createElement('div', {
            style: { fontSize: 15, fontWeight: 700, color: '#FF4560', letterSpacing: 0.2, marginBottom: 3 }
          }, 'Tool Running Too Long'),
          React.createElement('div', {
            style: { fontSize: 11, color: '#8892AA', lineHeight: 1.5 }
          }, 'This tool has exceeded its time limit. Choose to extend or stop it.')
        )
      ),

      // ── Info block ────────────────────────────────────────────
      React.createElement('div', {
        style: {
          background: '#1A1D28', borderRadius: 8, padding: '10px 14px',
          border: '1px solid #1E2236', marginBottom: 20, display: 'flex', flexDirection: 'column', gap: 0,
        }
      },
        React.createElement('div', { style: INFO_ROW },
          React.createElement('span', { style: LABEL_STYLE }, 'Tool'),
          React.createElement('span', { style: { ...VALUE_STYLE, color: '#38BDF8', fontWeight: 600 } },
            warn.tool || 'unknown')
        ),
        React.createElement('div', { style: INFO_ROW },
          React.createElement('span', { style: LABEL_STYLE }, 'Subagent'),
          React.createElement('span', { style: { ...VALUE_STYLE, color: '#E2E8F4' } },
            warn.subagent || 'unknown')
        ),
        React.createElement('div', { style: { ...INFO_ROW, borderBottom: 'none' } },
          React.createElement('span', { style: LABEL_STYLE }, 'Running for'),
          React.createElement('span', { style: { ...VALUE_STYLE, color: '#F5C842', fontWeight: 700 } },
            fmtElapsed(warn.elapsed_sec || 0))
        )
      ),

      // ── Extend label ──────────────────────────────────────────
      React.createElement('div', {
        style: { fontSize: 10, color: '#8892AA', marginBottom: 10, letterSpacing: 0.3 }
      }, 'Extend the time limit or stop this tool:'),

      // ── Extension buttons ─────────────────────────────────────
      React.createElement('div', {
        style: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 8, marginBottom: 10 }
      },
        [
          { label: '+10 min', sec: 600  },
          { label: '+20 min', sec: 1200 },
          { label: '+30 min', sec: 1800 },
          { label: '+60 min', sec: 3600 },
        ].map(({ label, sec }) =>
          React.createElement('button', {
            key: label,
            onClick: () => extend(sec),
            style: {
              padding: '9px 0', borderRadius: 7, cursor: 'pointer',
              border: '1px solid rgba(0,229,160,0.3)',
              background: 'rgba(0,229,160,0.07)', color: '#00E5A0',
              fontSize: 11, fontWeight: 700,
              fontFamily: "'JetBrains Mono', monospace",
              transition: 'background 0.15s, border-color 0.15s',
            }
          }, label)
        )
      ),

      // ── Stop button ───────────────────────────────────────────
      React.createElement('button', {
        onClick: stopTool,
        style: {
          width: '100%', padding: '10px 0', borderRadius: 7, cursor: 'pointer',
          border: '1px solid rgba(255,69,96,0.35)',
          background: 'rgba(255,69,96,0.08)', color: '#FF4560',
          fontSize: 12, fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          letterSpacing: 0.5, marginTop: 2,
          transition: 'background 0.15s, border-color 0.15s',
        }
      }, '■  Stop This Tool')
    )
  );
}

// ─── App ──────────────────────────────────────────────────────
function App() {
  const [page, setPage] = useState('mission');
  const { state } = window.useStore();
  const { sysStatus, activeSession, findingsSummary, wsConnected, currentPhase } = state;

  useEffect(() => {
    const handler = (e) => setPage(e.detail);
    window.addEventListener('navigate', handler);
    return () => window.removeEventListener('navigate', handler);
  }, []);

  const current  = PAGES.find(p => p.key === page) || PAGES[0];
  const PageComp = PAGE_COMPONENT[page]?.();

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

  // ── Render ──────────────────────────────────────────────────
  return React.createElement('div', {
    style: {
      height: '100vh', display: 'flex', flexDirection: 'column',
      overflow: 'hidden', background: T.bgBase,
      fontFamily: T.fontUI, color: T.textPrimary,
    }
  },

    // ── Global overlay modals ────────────────────────────────────
    React.createElement(ToolTimeoutModal),

    // ════════════════════════════════ HEADER ════════════════════
    React.createElement('div', {
      style: {
        height: 50, flexShrink: 0,
        background: T.bgSidebar,
        borderBottom: `1px solid ${T.border}`,
        display: 'flex', alignItems: 'center',
        padding: '0 18px', gap: 14, zIndex: 100,
        position: 'relative',
      }
    },
      // Accent gradient line at very bottom
      React.createElement('div', {
        style: {
          position: 'absolute', bottom: 0, left: 0, right: 0, height: 1,
          background: `linear-gradient(90deg, transparent 0%, ${T.accent}60 30%, ${T.violet}60 70%, transparent 100%)`,
        }
      }),

      // ── Logo ────────────────────────────────────────────────
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }
      },
        // Icon box
        React.createElement('div', {
          style: {
            width: 30, height: 30, borderRadius: 8, flexShrink: 0,
            background: `linear-gradient(135deg, ${T.accentDim}, ${T.violet})`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 15, boxShadow: `0 0 16px ${T.accent}40`,
          }
        }, '◈'),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', lineHeight: 1 } },
          React.createElement('span', {
            style: { fontFamily: T.fontMono, fontSize: 12, fontWeight: 700, color: T.accent, letterSpacing: 2 }
          }, 'ARGUS'),
          React.createElement('span', {
            style: { fontFamily: T.fontUI, fontSize: 9, color: T.textMuted, letterSpacing: 1.5, marginTop: 1 }
          }, 'PENTEST PLATFORM')
        )
      ),

      // ── Divider ─────────────────────────────────────────────
      React.createElement('div', {
        style: { width: 1, height: 24, background: T.border, flexShrink: 0, marginLeft: 4 }
      }),

      // ── Service status ───────────────────────────────────────
      React.createElement('div', { style: { display: 'flex', gap: 6, alignItems: 'center' } },
        React.createElement(SvcDot, { label: 'MCP', status: sysStatus.mcp }),
        React.createElement(SvcDot, { label: 'DB',  status: sysStatus.mongo }),
        React.createElement(SvcDot, { label: 'LLM', status: sysStatus.ollama })
      ),

      // ── Right side ───────────────────────────────────────────
      React.createElement('div', {
        style: { display: 'flex', gap: 8, marginLeft: 'auto', alignItems: 'center' }
      },
        // Active session
        activeSession && React.createElement('div', {
          onClick: () => setPage('mission'),
          style: {
            display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
            padding: '4px 12px', borderRadius: 20,
            background: `${T.accent}0D`,
            border: `1px solid ${T.accent}35`,
            transition: 'all 0.15s',
          }
        },
          // Live dot
          React.createElement('span', {
            style: {
              width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
              background: wsConnected ? T.low : T.textMuted,
              boxShadow: wsConnected ? `0 0 8px ${T.low}` : 'none',
            }
          }),
          // Target IP
          React.createElement('span', {
            style: { color: T.accent, fontFamily: T.fontMono, fontSize: 12, fontWeight: 700 }
          }, activeSession.target_ip),
          // Phase badge
          React.createElement('span', {
            style: {
              fontSize: 9, letterSpacing: 1, color: T.textMuted,
              background: T.bgPanel, border: `1px solid ${T.border}`,
              padding: '1px 6px', borderRadius: 4,
              textTransform: 'uppercase', fontWeight: 600
            }
          }, currentPhase || 'IDLE'),
          // Live label
          React.createElement('span', {
            style: { fontSize: 10, color: wsConnected ? T.low : T.textMuted, fontFamily: T.fontMono }
          }, wsConnected ? '● LIVE' : '○')
        ),

        // Critical findings badge
        findingsSummary.critical > 0 && React.createElement('div', {
          onClick: () => setPage('findings'),
          style: {
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '4px 12px', borderRadius: 20, cursor: 'pointer',
            background: `${T.critical}12`,
            border: `1px solid ${T.critical}40`,
            color: T.critical, fontSize: 11, fontWeight: 700,
            fontFamily: T.fontMono, letterSpacing: 0.5,
          }
        }, `⚠ ${findingsSummary.critical} CRIT`)
      )
    ),

    // ════════════════════════════════ BODY ══════════════════════
    React.createElement('div', { style: { flex: 1, display: 'flex', overflow: 'hidden' } },

      // ══════════════════════ SIDEBAR ═══════════════════════════
      React.createElement('div', {
        style: {
          width: 216, minWidth: 216, flexShrink: 0,
          background: T.bgSidebar,
          borderRight: `1px solid ${T.border}`,
          display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
        }
      },
        // Scroll area
        React.createElement('div', {
          style: { flex: 1, overflowY: 'auto', padding: '10px 0 8px' }
        },
          GROUP_ORDER.map(group => {
            const items = PAGES.filter(p => p.group === group);
            const groupColor = GROUP_COLORS[group];
            return React.createElement('div', { key: group, style: { marginBottom: 4 } },
              // Group header
              React.createElement('div', {
                style: {
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '10px 16px 5px',
                  fontSize: 9, letterSpacing: 1.6,
                  color: T.textMuted, textTransform: 'uppercase', fontWeight: 700,
                  fontFamily: T.fontUI,
                }
              },
                // Color dot
                React.createElement('span', {
                  style: {
                    width: 5, height: 5, borderRadius: '50%',
                    background: groupColor, flexShrink: 0,
                    boxShadow: `0 0 4px ${groupColor}80`
                  }
                }),
                group,
                // Line
                React.createElement('div', {
                  style: { flex: 1, height: 1, background: T.border }
                })
              ),
              // Nav items
              items.map(item =>
                React.createElement(NavItem, {
                  key: item.key,
                  item,
                  isActive: page === item.key,
                  onClick: () => setPage(item.key),
                })
              )
            );
          })
        ),

        // Session info at bottom
        activeSession
          ? React.createElement('div', {
              style: {
                padding: '10px 12px',
                borderTop: `1px solid ${T.border}`,
                flexShrink: 0,
              }
            },
              React.createElement('div', {
                onClick: () => setPage('mission'),
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
                  style: { fontFamily: T.fontMono, fontSize: 13, color: T.accent,
                           fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
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
          : React.createElement('div', {
              style: {
                padding: '12px', borderTop: `1px solid ${T.border}`, flexShrink: 0,
              }
            },
              React.createElement('div', {
                onClick: () => setPage('target'),
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
          padding: 20,
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
