// ExpertPanel.jsx — Live workings of the RedTeamExpertAgent.
// Matches ARGUS dark-theme design language, but uses a crimson/red accent
// (distinct from the violet/cyan used by MetaAgentsPanel). This panel shows:
//   • Mission-objective progress bar (mission phase + % + current objective)
//   • Directive cards (priority-tiered: CRITICAL / HIGH / MEDIUM / LOW)
//   • LLM thought stream (history)
//   • Peer-feedback list (expert → MC / IV)
//   • Corrections the expert has issued
//   • Summary statistics
'use strict';

const { useState: _xUseState } = React;

// Accent used by the Red-Team Expert.
const EXPERT_ACCENT = '#E8435A';          // crimson
const EXPERT_GLOW   = 'rgba(232,67,90,0.28)';
const EXPERT_SOFT   = 'rgba(232,67,90,0.10)';
const EXPERT_BORDER = 'rgba(232,67,90,0.35)';

// ─── Priority colour helper ───────────────────────────────────────────────────
function _priorityColor(p) {
  const pk = String(p || 'medium').toLowerCase();
  if (pk === 'critical') return { fg: '#FF4560', bg: 'rgba(255,69,96,0.10)', bd: 'rgba(255,69,96,0.38)', icon: '🔥' };
  if (pk === 'high')     return { fg: '#FF7A45', bg: 'rgba(255,122,69,0.10)', bd: 'rgba(255,122,69,0.35)', icon: '⚡' };
  if (pk === 'low')      return { fg: '#9BA3AF', bg: 'rgba(155,163,175,0.08)', bd: 'rgba(155,163,175,0.28)', icon: '💭' };
  return { fg: '#F5C842', bg: 'rgba(245,200,66,0.10)', bd: 'rgba(245,200,66,0.28)', icon: '📌' };
}

// ─── Stat cell used in Summary tab ────────────────────────────────────────────
function _XStatCell({ value, label, color }) {
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

// ─── Custom tab bar ───────────────────────────────────────────────────────────
function _XTabBar({ tabs, active, onSelect }) {
  return React.createElement('div', {
    style: {
      display: 'flex', gap: 0,
      borderBottom: '1px solid var(--border)',
      marginBottom: 10,
      overflowX: 'auto',
    }
  },
    tabs.map(t =>
      React.createElement('button', {
        key:     t.key,
        onClick: () => onSelect(t.key),
        style: {
          background:   'none',
          border:       'none',
          borderBottom: active === t.key ? `2px solid ${EXPERT_ACCENT}` : '2px solid transparent',
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
            background:   t.badgeColor || EXPERT_ACCENT,
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

// ─── Mission objective bar (progress + phase) ─────────────────────────────────
function _MissionBar({ objectives }) {
  const phase = (objectives && objectives.mission_phase) || 'Awaiting mission kickoff…';
  const pct   = Math.max(0, Math.min(100, Math.round((objectives && objectives.progress_pct) || 0)));
  const items = (objectives && objectives.objectives) || [];

  return React.createElement('div', {
    style: {
      padding: '12px 14px',
      background: `linear-gradient(135deg, ${EXPERT_SOFT} 0%, var(--bg-base) 70%)`,
      border: `1px solid ${EXPERT_BORDER}`,
      borderRadius: 'var(--radius)',
      marginBottom: 10,
    }
  },
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }
    },
      React.createElement('div', {
        style: {
          fontSize: 9, fontWeight: 700, letterSpacing: 0.8, textTransform: 'uppercase',
          color: EXPERT_ACCENT, whiteSpace: 'nowrap',
        }
      }, 'Mission Phase'),
      React.createElement('div', {
        style: {
          fontSize: 11, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)',
          flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }
      }, phase),
      React.createElement('div', {
        style: {
          fontSize: 11, fontWeight: 700, color: EXPERT_ACCENT,
          fontFamily: 'var(--font-mono)', flexShrink: 0,
        }
      }, `${pct}%`),
    ),

    // Progress bar
    React.createElement('div', {
      style: {
        height: 6, background: 'var(--bg-base)',
        border: '1px solid var(--border)', borderRadius: 3, overflow: 'hidden',
      }
    },
      React.createElement('div', {
        style: {
          width: `${pct}%`, height: '100%',
          background: `linear-gradient(90deg, ${EXPERT_ACCENT} 0%, #FF7A45 100%)`,
          boxShadow: `0 0 8px ${EXPERT_GLOW}`,
          transition: 'width 0.6s ease',
        }
      })
    ),

    // Objective chips
    items.length > 0 && React.createElement('div', {
      style: {
        marginTop: 9, display: 'flex', gap: 5, flexWrap: 'wrap',
      }
    },
      items.slice(0, 6).map((o, i) =>
        React.createElement('span', {
          key: i,
          style: {
            fontSize: 8.5, fontFamily: 'var(--font-mono)',
            padding: '2px 7px',
            border: `1px solid ${o.done ? 'rgba(60,200,120,0.32)' : 'var(--border)'}`,
            background: o.done ? 'rgba(60,200,120,0.08)' : 'var(--bg-base)',
            color: o.done ? '#3CC878' : 'var(--text-secondary)',
            borderRadius: 10,
            textDecoration: o.done ? 'line-through' : 'none',
            opacity: o.done ? 0.75 : 1,
          }
        }, `${o.done ? '✓ ' : ''}${(o.name || o.text || String(o)).slice(0, 44)}`)
      )
    ),
  );
}

// ─── Directive card ───────────────────────────────────────────────────────────
function _DirectiveCard({ directive: d }) {
  const [expanded, setExpanded] = _xUseState(false);
  const col = _priorityColor(d.priority);
  const cmds = Array.isArray(d.recommended_cmds) ? d.recommended_cmds : [];
  const refs = Array.isArray(d.rag_refs) ? d.rag_refs : [];

  return React.createElement('div', {
    style: {
      background: 'var(--bg-base)',
      border: `1px solid ${col.bd}`,
      borderLeft: `3px solid ${col.fg}`,
      borderRadius: 'var(--radius)',
      padding: '9px 11px',
      marginBottom: 7,
      cursor: 'pointer',
      transition: 'background 0.15s, border-color 0.15s',
    },
    onClick: () => setExpanded(e => !e),
  },
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }
    },
      React.createElement('span', { style: { fontSize: 12, flexShrink: 0 } }, col.icon),
      React.createElement('span', {
        style: {
          fontSize: 8.5, fontWeight: 700, padding: '1px 6px',
          background: col.bg, color: col.fg, border: `1px solid ${col.bd}`,
          borderRadius: 8, fontFamily: 'var(--font-mono)', letterSpacing: 0.5,
          flexShrink: 0,
        }
      }, String(d.priority || 'medium').toUpperCase()),
      React.createElement('span', {
        style: {
          fontSize: 8.5, fontWeight: 600, padding: '1px 6px',
          background: 'var(--bg-elevated)', color: 'var(--text-secondary)',
          border: '1px solid var(--border)', borderRadius: 8,
          fontFamily: 'var(--font-mono)', flexShrink: 0,
        }
      }, (d.action_type || 'note').toUpperCase()),
      d.target_phase && React.createElement('span', {
        style: {
          fontSize: 8.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
          flexShrink: 0,
        }
      }, `→ ${d.target_phase}`),
      React.createElement('span', { style: { flex: 1 } }),
      React.createElement('span', {
        style: {
          fontSize: 9, color: 'var(--text-muted)',
          transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
          transition: 'transform 0.2s', flexShrink: 0,
        }
      }, '›'),
    ),

    React.createElement('div', {
      style: {
        fontSize: 11, color: 'var(--text-primary)', fontWeight: 500,
        lineHeight: 1.4,
      }
    }, d.title || '(no title)'),

    expanded && React.createElement('div', {
      style: {
        marginTop: 8, paddingTop: 8,
        borderTop: '1px dashed var(--border)',
        fontSize: 10.5, color: 'var(--text-secondary)',
      }
    },
      d.rationale && React.createElement('div', { style: { marginBottom: 6, lineHeight: 1.45 } },
        React.createElement('span', {
          style: { color: 'var(--text-muted)', fontSize: 8.5, letterSpacing: 0.5, textTransform: 'uppercase', marginRight: 6 }
        }, 'Rationale'),
        d.rationale
      ),
      d.expected_outcome && React.createElement('div', { style: { marginBottom: 6, lineHeight: 1.45 } },
        React.createElement('span', {
          style: { color: 'var(--text-muted)', fontSize: 8.5, letterSpacing: 0.5, textTransform: 'uppercase', marginRight: 6 }
        }, 'Expected'),
        d.expected_outcome
      ),
      cmds.length > 0 && React.createElement('div', { style: { marginBottom: 6 } },
        React.createElement('div', {
          style: { color: 'var(--text-muted)', fontSize: 8.5, letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 4 }
        }, 'Recommended'),
        cmds.map((c, i) =>
          React.createElement('div', {
            key: i,
            style: {
              fontFamily: 'var(--font-mono)', fontSize: 10,
              background: 'var(--bg-panel)', border: '1px solid var(--border)',
              borderRadius: 3, padding: '3px 7px', marginBottom: 3,
              color: 'var(--text-primary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }
          }, c)
        )
      ),
      refs.length > 0 && React.createElement('div', {
        style: { display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }
      },
        React.createElement('span', {
          style: { color: 'var(--text-muted)', fontSize: 8.5, letterSpacing: 0.5, textTransform: 'uppercase' }
        }, 'RAG'),
        refs.slice(0, 6).map((r, i) =>
          React.createElement('span', {
            key: i,
            style: {
              fontSize: 8.5, fontFamily: 'var(--font-mono)',
              padding: '1px 6px', background: EXPERT_SOFT,
              color: EXPERT_ACCENT, border: `1px solid ${EXPERT_BORDER}`,
              borderRadius: 8,
            }
          }, (typeof r === 'string' ? r : (r.title || r.id || 'ref')).slice(0, 24))
        )
      ),
    ),
  );
}

// ─── Peer-feedback line (expert → MC / IV) ────────────────────────────────────
function _FeedbackLine({ fb }) {
  const agent = (fb.target_agent || 'peer').toUpperCase();
  const aColor = agent.includes('CHECK') ? 'var(--violet)' :
                 agent.includes('VALID') ? 'var(--cyan)'   :
                 EXPERT_ACCENT;
  return React.createElement('div', {
    style: {
      padding: '7px 10px', marginBottom: 5,
      background: 'var(--bg-base)', border: '1px solid var(--border)',
      borderLeft: `2px solid ${aColor}`,
      borderRadius: 'var(--radius)',
      fontSize: 10.5,
    }
  },
    React.createElement('div', {
      style: { display: 'flex', gap: 6, alignItems: 'center', marginBottom: 3 }
    },
      React.createElement('span', { style: { fontSize: 10 } }, '🧭'),
      React.createElement('span', {
        style: {
          fontSize: 8.5, fontWeight: 700, color: aColor,
          letterSpacing: 0.6, textTransform: 'uppercase',
        }
      }, `→ ${agent}`),
      fb.severity && React.createElement('span', {
        style: {
          fontSize: 8.5, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)',
          marginLeft: 'auto',
        }
      }, fb.severity),
    ),
    React.createElement('div', {
      style: { color: 'var(--text-primary)', lineHeight: 1.4 }
    }, fb.message || fb.note || '(no message)'),
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────
function ExpertPanel() {
  const [open, setOpen]           = _xUseState(true);
  const [activeTab, setActiveTab] = _xUseState('directives');
  const { state }                 = window.useStore();

  const xs = state.expertState || {};
  const history     = xs.history     || [];
  const directives  = xs.directives  || [];
  const feedback    = xs.feedback    || [];
  const corrections = xs.corrections || [];
  const objectives  = xs.objectives  || { mission_phase: '', progress_pct: 0, objectives: [] };
  const stats       = xs.stats       || {};
  const status      = xs.status      || 'idle';
  const phase       = xs.phase       || '';
  const mode        = xs.mode        || '';
  const thinking    = status === 'thinking' || status === 'directing' || status === 'reviewing';

  const totalDirs   = directives.length;
  const blocking    = directives.filter(d => String(d.priority || '').toLowerCase() === 'critical').length;

  // Tabs
  const tabs = [
    { key: 'directives', label: 'Directives', icon: '📌', badge: totalDirs,
      badgeColor: blocking > 0 ? '#FF4560' : EXPERT_ACCENT },
    { key: 'stream',     label: 'Thought Stream', icon: '🧠' },
    { key: 'feedback',   label: 'Peer Feedback',  icon: '🧭', badge: feedback.length, badgeColor: 'var(--cyan)' },
    { key: 'corrections',label: 'Corrections',    icon: '⛑', badge: corrections.length, badgeColor: '#D97706' },
    { key: 'summary',    label: 'Summary',        icon: '📊' },
  ];

  // Convert thought history to LiveTerminal lines
  const termLines = history.map(entry => ({
    line: entry.role === 'user'
      ? `[PROMPT] ${entry.content}`
      : `[RESPONSE] ${entry.content}`,
    type: entry.role === 'user' ? 'stderr' : 'stdout',
  }));

  const outerBorder = blocking > 0 ? 'var(--critical-bd)'
                    : thinking    ? EXPERT_BORDER
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

    // ── Top accent line ─────────────────────────────────────────
    React.createElement('div', {
      style: {
        height:     2,
        background: thinking
          ? `linear-gradient(90deg, ${EXPERT_ACCENT} 0%, #FF7A45 50%, ${EXPERT_ACCENT} 100%)`
          : `${EXPERT_ACCENT}30`,
        opacity:    thinking ? 1 : 0.45,
        transition: 'opacity 0.4s',
        animation:  thinking ? 'pulse 1.5s infinite' : 'none',
      }
    }),

    // ── Collapsible header ──────────────────────────────────────
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
      // Crosshair icon
      React.createElement('div', {
        style: {
          width: 32, height: 32, borderRadius: 8, flexShrink: 0,
          background: EXPERT_SOFT,
          border:     `1px solid ${EXPERT_BORDER}`,
          display:    'flex', alignItems: 'center', justifyContent: 'center',
          fontSize:   15,
          boxShadow:  thinking ? `0 0 14px ${EXPERT_GLOW}` : 'none',
          transition: 'box-shadow 0.4s',
        }
      }, '🎯'),

      // Title block
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },
        React.createElement('div', {
          style: { display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }
        },
          React.createElement('span', {
            style: { fontSize: 12, fontWeight: 700, color: EXPERT_ACCENT }
          }, 'Red-Team Expert'),
          React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } }, '—'),
          React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)' } },
            'Tactician · Web · Network · AD · Cloud · IoT'),
          totalDirs > 0 && React.createElement('span', {
            style: {
              background:   blocking > 0 ? 'var(--critical-bg)' : EXPERT_SOFT,
              border:       `1px solid ${blocking > 0 ? 'var(--critical-bd)' : EXPERT_BORDER}`,
              color:        blocking > 0 ? 'var(--critical)' : EXPERT_ACCENT,
              borderRadius: 10, padding: '0 7px',
              fontSize: 9, fontWeight: 700, fontFamily: 'var(--font-mono)',
            }
          }, `${totalDirs} directive${totalDirs !== 1 ? 's' : ''}${blocking > 0 ? ' · 🔥 critical' : ''}`),
        ),
        React.createElement('div', {
          style: {
            marginTop: 2, fontSize: 9,
            color: thinking ? EXPERT_ACCENT : 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            display: 'flex', alignItems: 'center', gap: 5,
          }
        },
          React.createElement('span', {
            className: `status-dot ${thinking ? 'thinking' : 'idle'}`,
            style: { flexShrink: 0 }
          }),
          thinking
            ? `${status}${phase ? ' · ' + phase : ''}${mode ? ' · ' + mode : ''}`
            : 'Standing by — will direct on scan start',
        ),
      ),

      // Mini progress indicator
      typeof objectives.progress_pct === 'number' && React.createElement('div', {
        style: {
          flexShrink: 0,
          fontFamily: 'var(--font-mono)',
          fontSize: 10, fontWeight: 700, color: EXPERT_ACCENT,
          padding: '2px 8px',
          border: `1px solid ${EXPERT_BORDER}`,
          borderRadius: 10,
          background: EXPERT_SOFT,
        }
      }, `${Math.round(objectives.progress_pct || 0)}%`),

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

    // ── Expanded body ───────────────────────────────────────────
    open && React.createElement('div', { style: { padding: 12 } },
      // Mission bar (always visible when expanded)
      React.createElement(_MissionBar, { objectives }),

      // Tab bar + content
      React.createElement(_XTabBar, { tabs, active: activeTab, onSelect: setActiveTab }),

      // ── Directives tab ─────────────────────────────────────
      activeTab === 'directives' && React.createElement('div', {
        style: { maxHeight: 340, overflowY: 'auto', paddingRight: 2 }
      },
        directives.length > 0
          ? directives.slice().reverse().map((d, i) =>
              React.createElement(_DirectiveCard, { key: d.directive_id || i, directive: d })
            )
          : React.createElement('div', {
              style: {
                padding: '28px 0', textAlign: 'center',
                color: 'var(--text-muted)', fontSize: 11,
              }
            },
              React.createElement('div', { style: { fontSize: 22, marginBottom: 6, opacity: 0.4 } }, '🎯'),
              'Waiting for the engagement to begin…'
            ),
      ),

      // ── Thought stream ─────────────────────────────────────
      activeTab === 'stream' && React.createElement(window.LiveTerminal, {
        lines:      termLines,
        height:     300,
        agentColor: EXPERT_ACCENT,
        title:      'Red-Team Expert — Reasoning Stream',
      }),

      // ── Peer feedback ──────────────────────────────────────
      activeTab === 'feedback' && React.createElement('div', {
        style: { maxHeight: 340, overflowY: 'auto', paddingRight: 2 }
      },
        feedback.length > 0
          ? feedback.slice().reverse().map((fb, i) =>
              React.createElement(_FeedbackLine, { key: fb.feedback_id || i, fb })
            )
          : React.createElement('div', {
              style: {
                padding: '28px 0', textAlign: 'center',
                color: 'var(--text-muted)', fontSize: 11,
              }
            },
              React.createElement('div', { style: { fontSize: 22, marginBottom: 6, opacity: 0.4 } }, '🧭'),
              'No peer guidance yet — Expert will coach MC/IV as the engagement unfolds.'
            ),
      ),

      // ── Corrections ───────────────────────────────────────
      activeTab === 'corrections' && React.createElement('div', {
        style: { maxHeight: 340, overflowY: 'auto', paddingRight: 2 }
      },
        corrections.length > 0
          ? corrections.slice().reverse().map((c, i) =>
              React.createElement(window.CorrectionCard, { key: i, correction: c })
            )
          : React.createElement('div', {
              style: {
                padding: '28px 0', textAlign: 'center',
                color: 'var(--text-muted)', fontSize: 11,
              }
            },
              React.createElement('div', { style: { fontSize: 22, marginBottom: 6, opacity: 0.4 } }, '⛑'),
              'Expert has not issued corrections yet.'
            ),
      ),

      // ── Summary ───────────────────────────────────────────
      activeTab === 'summary' && React.createElement('div', {
        style: {
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 7, marginTop: 2,
        }
      },
        React.createElement(_XStatCell, {
          value: stats.directivesCount ?? totalDirs,
          label: 'Directives',
          color: 'var(--text-primary)',
        }),
        React.createElement(_XStatCell, {
          value: stats.blocking || blocking,
          label: '🔥 Critical',
          color: (stats.blocking || blocking) > 0 ? '#FF4560' : 'var(--text-muted)',
        }),
        React.createElement(_XStatCell, {
          value: stats.advisory || (totalDirs - blocking),
          label: '📌 Advisory',
          color: (stats.advisory || (totalDirs - blocking)) > 0 ? '#F5C842' : 'var(--text-muted)',
        }),
        React.createElement(_XStatCell, {
          value: stats.feedbackCount ?? feedback.length,
          label: 'Peer Coaching',
          color: 'var(--cyan)',
        }),
        React.createElement(_XStatCell, {
          value: stats.phasesReviewed || 0,
          label: 'Phases Overseen',
          color: 'var(--text-secondary)',
        }),
        React.createElement(_XStatCell, {
          value: corrections.length,
          label: 'Corrections',
          color: corrections.length > 0 ? '#D97706' : 'var(--text-muted)',
        }),
      ),
    ),
  );
}

window.ExpertPanel = ExpertPanel;
