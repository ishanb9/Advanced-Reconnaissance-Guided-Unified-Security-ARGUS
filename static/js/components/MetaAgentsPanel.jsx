// MetaAgentsPanel.jsx — Live workings of IssueValidatorAgent + ErrorAnalyzerAgent.
// Fully custom dark-theme design — no Ant Design structural components.
// Matches ARGUS design language: bg layers, accent glows, mono type, status dots.
'use strict';

const { useState: _useState } = React;

// ─── Stat cell used in Summary tab ────────────────────────────────────────────
function _MetaStatCell({ value, label, color }) {
  return React.createElement('div', {
    style: {
      textAlign: 'center', padding: '10px 6px',
      background: 'var(--bg-base)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
    }
  },
    React.createElement('div', {
      style: {
        fontSize: 20, fontWeight: 700, lineHeight: 1,
        fontFamily: 'var(--font-mono)',
        color: color || 'var(--text-primary)',
      }
    }, value),
    React.createElement('div', {
      style: {
        fontSize: 8, color: 'var(--text-muted)', marginTop: 4,
        textTransform: 'uppercase', letterSpacing: 0.8,
      }
    }, label)
  );
}

// ─── Custom tab bar ────────────────────────────────────────────────────────────
function _MetaTabBar({ tabs, active, onSelect }) {
  return React.createElement('div', {
    style: {
      display: 'flex', gap: 0,
      borderBottom: '1px solid var(--border)',
      marginBottom: 10,
    }
  },
    tabs.map(t =>
      React.createElement('button', {
        key:     t.key,
        onClick: () => onSelect(t.key),
        style: {
          background:   'none',
          border:       'none',
          borderBottom: active === t.key ? `2px solid ${t.accentColor}` : '2px solid transparent',
          color:        active === t.key ? 'var(--text-primary)' : 'var(--text-muted)',
          fontFamily:   'var(--font-ui)',
          fontSize:     10,
          fontWeight:   active === t.key ? 600 : 400,
          padding:      '5px 11px',
          cursor:       'pointer',
          marginBottom: -1,
          whiteSpace:   'nowrap',
          transition:   'color 0.15s, border-color 0.15s',
          display:      'flex',
          alignItems:   'center',
          gap:          4,
        }
      },
        t.icon,
        t.label,
        t.badge > 0 && React.createElement('span', {
          style: {
            background:   t.badgeColor || 'var(--border-bright)',
            color:        '#fff',
            borderRadius: 8,
            padding:      '0 4px',
            fontSize:     8,
            fontWeight:   700,
            minWidth:     14,
            textAlign:    'center',
            lineHeight:   '14px',
          }
        }, t.badge)
      )
    )
  );
}

// ─── Single meta-agent sub-panel ──────────────────────────────────────────────
function _MetaSubPanel({ agentKey, label, icon, accentColor, agentState }) {
  const [activeTab, setActiveTab] = _useState('stream');

  if (!agentState) {
    return React.createElement('div', {
      style: {
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)', padding: 20,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--text-muted)', fontSize: 11,
      }
    }, 'Awaiting scan start…');
  }

  const { history = [], corrections = [], stats = {}, status, phase } = agentState;
  const isThinking    = status === 'thinking';
  const blockingCount = stats.blocking  || 0;
  const advisoryCount = stats.advisory  || 0;
  const totalCount    = stats.total     || 0;
  // The "corrections" badge must reflect the ACTUAL corrections shown in the
  // tab (gated findings), NOT the count of all findings the validator checked
  // (stats.total). Use the live list length, falling back to the stat-derived
  // correction count so it is never under-reported if the list is still filling.
  const correctionCount = Math.max(corrections.length, blockingCount + advisoryCount);
  const badgeColor    = blockingCount > 0 ? '#FF4560' : '#D97706';

  // Convert history to LiveTerminal lines
  const termLines = history.map(entry => ({
    line: entry.role === 'user'
      ? `[PROMPT] ${entry.content}`
      : `[RESPONSE] ${entry.content}`,
    type: entry.role === 'user' ? 'stderr' : 'stdout',
  }));

  const tabs = [
    { key: 'stream',      label: 'Stream',      icon: '💬', accentColor },
    {
      key:         'corrections',
      label:       'Corrections',
      icon:        correctionCount > 0 ? (blockingCount > 0 ? '⛔' : '💡') : '🔧',
      accentColor: blockingCount > 0 ? 'var(--critical)' : 'var(--medium)',
      badge:       correctionCount,
      badgeColor,
    },
    { key: 'summary', label: 'Summary', icon: '📊', accentColor },
  ];

  return React.createElement('div', {
    style: {
      background:   'var(--bg-surface)',
      border:       `1px solid var(--border)`,
      borderRadius: 'var(--radius-lg)',
      overflow:     'hidden',
      display:      'flex',
      flexDirection:'column',
    }
  },

    // ── Top accent line (animates when thinking) ─────────────────
    React.createElement('div', {
      style: {
        height:     2,
        background: isThinking
          ? `linear-gradient(90deg, ${accentColor} 0%, transparent 100%)`
          : `${accentColor}30`,
        transition: 'all 0.4s',
        animation:  isThinking ? 'pulse 1.5s infinite' : 'none',
      }
    }),

    // ── Agent header bar ─────────────────────────────────────────
    React.createElement('div', {
      style: {
        padding:      '9px 12px 8px',
        borderBottom: '1px solid var(--border)',
        background:   'var(--bg-panel)',
        display:      'flex',
        alignItems:   'center',
        gap:          8,
      }
    },
      // Icon bubble
      React.createElement('div', {
        style: {
          width: 30, height: 30, borderRadius: 7, flexShrink: 0,
          background: `${accentColor}16`,
          border:     `1px solid ${accentColor}35`,
          display:    'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 14,
          boxShadow: isThinking ? `0 0 10px ${accentColor}40` : 'none',
          transition: 'box-shadow 0.4s',
        }
      }, icon),

      // Label + status
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },
        React.createElement('div', {
          style: {
            fontSize: 10, fontWeight: 700,
            color: accentColor, letterSpacing: 0.5,
            textTransform: 'uppercase',
          }
        }, label),
        React.createElement('div', {
          style: {
            fontSize: 9, marginTop: 1,
            color: isThinking ? accentColor : 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            display: 'flex', alignItems: 'center', gap: 4,
            transition: 'color 0.3s',
          }
        },
          // Animated status dot
          React.createElement('span', {
            className: `status-dot ${isThinking ? 'thinking' : 'idle'}`,
            style: { flexShrink: 0 }
          }),
          isThinking
            ? `Thinking${phase ? ' · ' + phase : ''}…`
            : `Idle${phase ? ' · last: ' + phase : ''}`,
        )
      ),

      // Correction pill (top-right of header)
      totalCount > 0 && React.createElement('div', {
        style: {
          background:   blockingCount > 0 ? 'var(--critical-bg)' : 'rgba(245,200,66,0.10)',
          border:       `1px solid ${blockingCount > 0 ? 'var(--critical-bd)' : 'rgba(245,200,66,0.28)'}`,
          color:        blockingCount > 0 ? 'var(--critical)' : 'var(--medium)',
          borderRadius: 10,
          padding:      '1px 7px',
          fontSize:     9,
          fontWeight:   700,
          fontFamily:   'var(--font-mono)',
          flexShrink:   0,
        }
      }, `${correctionCount} ${correctionCount === 1 ? 'correction' : 'corrections'}`),
    ),

    // ── Tab bar + content ────────────────────────────────────────
    React.createElement('div', { style: { padding: '10px 12px 12px', flex: 1 } },
      React.createElement(_MetaTabBar, { tabs, active: activeTab, onSelect: setActiveTab }),

      // Thought Stream tab
      activeTab === 'stream' && React.createElement(window.LiveTerminal, {
        lines:      termLines,
        height:     236,
        agentColor: accentColor,
        title:      `${label} — LLM Conversation`,
      }),

      // Corrections tab
      activeTab === 'corrections' && React.createElement('div', {
        style: { maxHeight: 258, overflowY: 'auto', paddingRight: 2 }
      },
        corrections.length > 0
          ? corrections.map((c, i) =>
              React.createElement(window.CorrectionCard, { key: i, correction: c })
            )
          : React.createElement('div', {
              style: {
                padding: '28px 0', textAlign: 'center',
                color: 'var(--text-muted)', fontSize: 11,
              }
            },
              React.createElement('div', { style: { fontSize: 22, marginBottom: 6, opacity: 0.4 } }, '✓'),
              'No corrections issued yet.'
            ),
      ),

      // Summary tab
      activeTab === 'summary' && React.createElement('div', {
        style: {
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 7,
          marginTop: 2,
        }
      },
        React.createElement(_MetaStatCell, {
          value: totalCount,
          label: 'Total',
          color: 'var(--text-primary)',
        }),
        React.createElement(_MetaStatCell, {
          value: blockingCount,
          label: '⛔ Blocking',
          color: blockingCount > 0 ? 'var(--critical)' : 'var(--text-muted)',
        }),
        React.createElement(_MetaStatCell, {
          value: advisoryCount,
          label: '💡 Advisory',
          color: advisoryCount > 0 ? 'var(--medium)' : 'var(--text-muted)',
        }),
        agentKey === 'validator' && React.createElement(_MetaStatCell, {
          value: stats.toolsValidated || 0,
          label: 'Tools Validated',
          color: 'var(--text-secondary)',
        }),
        agentKey === 'validator' && React.createElement(_MetaStatCell, {
          value: stats.phasesValidated || 0,
          label: 'Phases Validated',
          color: 'var(--text-secondary)',
        }),
        agentKey === 'validator' && React.createElement(_MetaStatCell, {
          value: stats.accepted || 0,
          label: '✓ Verified',
          color: 'var(--low)',
        }),
        agentKey === 'validator' && React.createElement(_MetaStatCell, {
          value: stats.rejected || 0,
          label: '⛔ Gated out',
          color: (stats.rejected || 0) > 0 ? 'var(--high)' : 'var(--text-muted)',
        }),
        agentKey === 'error_analyzer' && React.createElement(_MetaStatCell, {
          value: stats.tool_missing || 0,
          label: 'Tool Missing',
          color: (stats.tool_missing || 0) > 0 ? 'var(--critical)' : 'var(--text-muted)',
        }),
        agentKey === 'error_analyzer' && React.createElement(_MetaStatCell, {
          value: stats.wrong_target || 0,
          label: 'Wrong Target',
          color: (stats.wrong_target || 0) > 0 ? 'var(--medium)' : 'var(--text-muted)',
        }),
        agentKey === 'error_analyzer' && React.createElement(_MetaStatCell, {
          value: stats.transient || 0,
          label: 'Transient',
          color: 'var(--text-secondary)',
        }),
      ),
    ),
  );
}

// ─── Outer collapsible panel ───────────────────────────────────────────────────
function MetaAgentsPanel() {
  const [open, setOpen] = _useState(false);
  const { state }       = window.useStore();

  const validatorState = state.metaValidatorState;
  const errorState     = state.metaErrorAnalyzerState;

  // Count ACTUAL corrections (the items shown in each agent's Corrections tab),
  // not every finding validated — the validator's gated count is its corrections.
  const validatorTotal  = (validatorState && Math.max(
                            (validatorState.corrections || []).length,
                            (validatorState.stats.blocking || 0) + (validatorState.stats.advisory || 0))) || 0;
  const errorTotal      = (errorState     && Math.max(
                            (errorState.corrections || []).length,
                            errorState.stats.total || 0)) || 0;
  const totalAll        = validatorTotal + errorTotal;
  const blockingTotal   = (
    ((validatorState && validatorState.stats.blocking) || 0) +
    ((errorState     && errorState.stats.blocking)     || 0)
  );
  const hasBlocking     = blockingTotal > 0;

  const validatorActive = validatorState && validatorState.status === 'thinking';
  const errorActive     = errorState     && errorState.status     === 'thinking';
  const anyActive       = validatorActive || errorActive;

  // Border tints based on state
  const outerBorder = hasBlocking
    ? 'var(--critical-bd)'
    : anyActive
      ? 'rgba(123,108,246,0.35)'
      : 'var(--border)';

  return React.createElement('div', {
    style: {
      marginTop:    12,
      background:   'var(--bg-surface)',
      border:       `1px solid ${outerBorder}`,
      borderRadius: 'var(--radius-lg)',
      overflow:     'hidden',
      transition:   'border-color 0.3s',
    }
  },

    // ── Top gradient accent line ──────────────────────────────────
    React.createElement('div', {
      style: {
        height:     2,
        background: hasBlocking
          ? 'var(--critical)'
          : 'linear-gradient(90deg, var(--violet) 0%, var(--cyan) 100%)',
        opacity:    anyActive ? 1 : 0.4,
        transition: 'opacity 0.4s',
        animation:  anyActive && !hasBlocking ? 'pulse 1.5s infinite' : 'none',
      }
    }),

    // ── Collapsible header ────────────────────────────────────────
    React.createElement('div', {
      onClick: () => setOpen(o => !o),
      style: {
        padding:      '10px 14px',
        display:      'flex',
        alignItems:   'center',
        gap:          10,
        cursor:       'pointer',
        background:   open ? 'var(--bg-panel)' : 'transparent',
        borderBottom: open ? '1px solid var(--border)' : '1px solid transparent',
        userSelect:   'none',
        transition:   'background 0.15s, border-color 0.15s',
      }
    },

      // Shield icon
      React.createElement('div', {
        style: {
          width:      32, height: 32, borderRadius: 8, flexShrink: 0,
          background: 'var(--violet-glow)',
          border:     '1px solid rgba(123,108,246,0.35)',
          display:    'flex', alignItems: 'center', justifyContent: 'center',
          fontSize:   15,
          boxShadow:  anyActive ? '0 0 14px rgba(123,108,246,0.35)' : 'none',
          transition: 'box-shadow 0.4s',
        }
      }, '🛡'),

      // Title block
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },
        React.createElement('div', {
          style: { display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }
        },
          React.createElement('span', {
            style: { fontSize: 12, fontWeight: 700, color: 'var(--violet)' }
          }, 'Meta-Agents'),
          React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, '—'),
          React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, 'Validator · Error Analyzer'),
          // Global correction badge
          totalAll > 0 && React.createElement('span', {
            style: {
              background:   hasBlocking ? 'var(--critical-bg)' : 'rgba(245,200,66,0.10)',
              border:       `1px solid ${hasBlocking ? 'var(--critical-bd)' : 'rgba(245,200,66,0.28)'}`,
              color:        hasBlocking ? 'var(--critical)' : 'var(--medium)',
              borderRadius: 10, padding: '0 7px',
              fontSize: 9, fontWeight: 700, fontFamily: 'var(--font-mono)',
            }
          }, `${totalAll} correction${totalAll !== 1 ? 's' : ''}${hasBlocking ? ' · ⛔ blocking' : ''}`),
        ),
        React.createElement('div', {
          style: {
            marginTop: 2, fontSize: 9,
            color: anyActive ? 'var(--violet)' : 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            display: 'flex', alignItems: 'center', gap: 5,
          }
        },
          anyActive && React.createElement('span', {
            className: 'status-dot thinking', style: { flexShrink: 0 }
          }),
          anyActive
            ? `${[validatorActive && 'Validator', errorActive && 'ErrorAnalyzer'].filter(Boolean).join(' + ')} active`
            : 'All agents idle — activate by starting a scan',
        ),
      ),

      // Per-agent status dots
      React.createElement('div', {
        style: { display: 'flex', gap: 4, alignItems: 'center', flexShrink: 0 }
      },
        React.createElement('span', {
          style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginRight: 2 }
        }, 'IV'),
        React.createElement('span', {
          className: `status-dot ${validatorActive ? 'running' : 'idle'}`,
          title:     'Issue Validator',
        }),
        React.createElement('span', {
          style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginLeft: 4, marginRight: 2 }
        }, 'EA'),
        React.createElement('span', {
          className: `status-dot ${errorActive ? 'thinking' : 'idle'}`,
          title:     'Error Analyzer',
        }),
      ),

      // Chevron toggle
      React.createElement('div', {
        style: {
          width: 20, height: 20, borderRadius: 4,
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--text-muted)', fontSize: 9,
          transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
          transition: 'transform 0.2s',
          flexShrink: 0,
        }
      }, '▼'),
    ),

    // ── Expanded: two agent panels side by side ───────────────────
    open && React.createElement('div', {
      style: {
        padding:             12,
        display:             'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap:                 12,
      }
    },
      React.createElement(_MetaSubPanel, {
        agentKey:    'validator',
        label:       'Issue Validator',
        icon:        '🔍',
        accentColor: 'var(--cyan)',
        agentState:  validatorState,
      }),
      React.createElement(_MetaSubPanel, {
        agentKey:    'error_analyzer',
        label:       'Error Analyzer',
        icon:        '🔧',
        accentColor: 'var(--medium)',
        agentState:  errorState,
      }),
    ),
  );
}

window.MetaAgentsPanel = MetaAgentsPanel;
