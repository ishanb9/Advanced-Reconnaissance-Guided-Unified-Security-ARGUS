// ═══════════════════════════════════════════════════════════
// ReasoningEnginePage.jsx — Hypothesis-driven attack planning
//
// Displays the reasoning engine's live state:
//  - Hypothesis cards with confidence bars, evidence, MITRE tags
//  - Ranked attack paths with nodes and scoring
//  - Justified action history with pre-execution plans
//  - Negative memory (exhausted/failed paths)
//
// Reads exclusively from window.useStore() — no REST calls.
// No imports — uses global React and window.useStore.
// ═══════════════════════════════════════════════════════════

const { useState, useEffect, useCallback } = React;

// ─── Small reusable helpers ────────────────────────────────

function SectionHeader({ label, count, countColor }) {
  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.SectionHeader',
    style: {
      display: 'flex', alignItems: 'center', gap: 8,
      marginBottom: 10, flexShrink: 0,
    }
  },
    React.createElement('span', {
      style: {
        fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
        textTransform: 'uppercase', letterSpacing: 0.8,
        color: 'var(--text-muted)',
      }
    }, label),
    count !== undefined && React.createElement('span', {
      style: {
        padding: '1px 7px', borderRadius: 10, fontSize: 10,
        fontFamily: 'var(--font-mono)', fontWeight: 700,
        background: countColor ? `${countColor}22` : 'rgba(255,255,255,0.06)',
        border: `1px solid ${countColor || 'var(--border-light)'}`,
        color: countColor || 'var(--text-muted)',
      }
    }, count)
  );
}

function MutedEmpty({ text }) {
  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.MutedEmpty',
    style: {
      color: 'var(--text-muted)', fontStyle: 'italic', fontSize: 11,
      padding: '18px 4px', textAlign: 'center',
    }
  }, text);
}

function InlineBadge({ label, color, bg, border }) {
  return React.createElement('span', { 'data-slot': 'ReasoningEnginePage.InlineBadge',
    style: {
      display: 'inline-flex', alignItems: 'center',
      padding: '1px 7px', borderRadius: 4, fontSize: 9,
      fontFamily: 'var(--font-mono)', fontWeight: 700,
      letterSpacing: 0.5, textTransform: 'uppercase', whiteSpace: 'nowrap',
      color: color || 'var(--text-muted)',
      background: bg || 'rgba(255,255,255,0.05)',
      border: `1px solid ${border || 'var(--border-light)'}`,
    }
  }, label);
}

function ConfidenceBar({ value, height }) {
  // value: 0.0 – 1.0
  const pct = Math.min(100, Math.max(0, (value || 0) * 100));
  const color = value >= 0.7
    ? 'var(--accent)'
    : value >= 0.4
      ? 'var(--medium)'
      : 'var(--critical)';
  const h = height || 4;
  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.ConfidenceBar',
    style: {
      width: '100%', height: h, borderRadius: h / 2,
      background: 'var(--bg-panel)', overflow: 'hidden',
    }
  },
    React.createElement('div', {
      style: {
        height: '100%',
        width: `${pct}%`,
        borderRadius: h / 2,
        background: `linear-gradient(90deg, ${color}aa, ${color})`,
        transition: 'width 0.5s ease',
      }
    })
  );
}

// ─── Hypothesis Card ──────────────────────────────────────

function HypothesisCard({ hyp, pulse }) {
  const [open, setOpen] = useState(false);

  const conf = hyp.confidence || 0;
  const confPct = Math.round(conf * 100);
  const confColor = conf >= 0.7
    ? 'var(--accent)'
    : conf >= 0.4
      ? 'var(--medium)'
      : 'var(--critical)';

  const status = (hyp.status || 'pending').toLowerCase();
  const statusBadge = status === 'validated'
    ? { label: 'VALIDATED', color: 'var(--accent)', bg: 'rgba(0,229,160,0.10)', border: 'rgba(0,229,160,0.35)' }
    : status === 'invalidated'
      ? { label: 'INVALIDATED', color: 'var(--critical)', bg: 'rgba(255,69,96,0.10)', border: 'rgba(255,69,96,0.35)' }
      : { label: 'PENDING', color: 'var(--text-muted)', bg: 'rgba(255,255,255,0.05)', border: 'var(--border-light)' };

  const evidenceSupporting = hyp.evidence_supporting || [];
  const requiredEvidence   = hyp.required_evidence   || [];
  const nextActions        = hyp.recommended_next_actions || [];

  const hasExpandable = evidenceSupporting.length > 0
    || requiredEvidence.length > 0
    || nextActions.length > 0;

  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.HypothesisCard',
    className: pulse ? 'motion-phase-advance' : undefined,
    style: {
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: 14,
      transition: 'border-color 0.15s',
      cursor: hasExpandable ? 'default' : undefined,
    },
    onMouseEnter: e => { e.currentTarget.style.borderColor = 'var(--border-light)'; },
    onMouseLeave: e => { e.currentTarget.style.borderColor = 'var(--border)'; },
  },

    // ── Confidence bar (full width, at top) ───────────────
    React.createElement(ConfidenceBar, { value: conf, height: 5 }),

    // ── Confidence pct label ──────────────────────────────
    React.createElement('div', {
      style: {
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginTop: 6, marginBottom: 8,
      }
    },
      React.createElement('span', {
        style: {
          fontFamily: 'var(--font-mono)', fontSize: 10,
          fontWeight: 700, color: confColor,
        }
      }, `${confPct}% confidence`),
      hyp.iteration !== undefined && React.createElement('span', {
        style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
      }, `iter ${hyp.iteration}`)
    ),

    // ── Statement ─────────────────────────────────────────
    React.createElement('div', {
      style: {
        fontSize: 12, color: 'var(--text-primary)',
        fontWeight: 500, lineHeight: 1.55, marginBottom: 8,
      }
    }, hyp.statement || hyp.hypothesis || '(no statement)'),

    // ── Badge row ─────────────────────────────────────────
    React.createElement('div', {
      style: { display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: hasExpandable ? 8 : 0 }
    },
      // Status badge
      React.createElement(InlineBadge, {
        label: statusBadge.label,
        color: statusBadge.color,
        bg:    statusBadge.bg,
        border: statusBadge.border,
      }),
      // MITRE technique
      hyp.mitre_technique && React.createElement(InlineBadge, {
        label: hyp.mitre_technique,
        color: 'var(--cyan)',
        bg:    'rgba(56,189,248,0.10)',
        border: 'rgba(56,189,248,0.30)',
      }),
      // Attack phase
      hyp.attack_phase && React.createElement(InlineBadge, {
        label: hyp.attack_phase,
        color: 'var(--violet)',
        bg:    'rgba(123,108,246,0.10)',
        border: 'rgba(123,108,246,0.30)',
      })
    ),

    // ── Expandable section ────────────────────────────────
    hasExpandable && React.createElement('div', null,
      React.createElement('button', {
        onClick: () => setOpen(o => !o),
        style: {
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--text-muted)', fontSize: 10,
          fontFamily: 'var(--font-mono)', padding: '2px 0',
          display: 'flex', alignItems: 'center', gap: 4,
        }
      },
        React.createElement('span', null, open ? '▼' : '▶'),
        React.createElement('span', null, open ? 'Hide details' : 'Show details')
      ),

      open && React.createElement('div', {
        style: {
          marginTop: 8, paddingTop: 8,
          borderTop: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', gap: 10,
        }
      },

        // Evidence supporting
        evidenceSupporting.length > 0 && React.createElement('div', null,
          React.createElement('div', {
            style: {
              fontSize: 9, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
              letterSpacing: 0.7, color: 'var(--accent)', marginBottom: 4, fontWeight: 700,
            }
          }, 'Evidence'),
          evidenceSupporting.map((ev, i) =>
            React.createElement('div', {
              key: i,
              style: { fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5, paddingLeft: 10, position: 'relative' }
            },
              React.createElement('span', {
                style: { position: 'absolute', left: 0, color: 'var(--accent)' }
              }, '·'),
              ev
            )
          )
        ),

        // Required evidence
        requiredEvidence.length > 0 && React.createElement('div', null,
          React.createElement('div', {
            style: {
              fontSize: 9, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
              letterSpacing: 0.7, color: 'var(--medium)', marginBottom: 4, fontWeight: 700,
            }
          }, 'Required Evidence'),
          requiredEvidence.map((ev, i) =>
            React.createElement('div', {
              key: i,
              style: { fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5, paddingLeft: 10, position: 'relative' }
            },
              React.createElement('span', {
                style: { position: 'absolute', left: 0, color: 'var(--medium)' }
              }, '·'),
              ev
            )
          )
        ),

        // Next actions
        nextActions.length > 0 && React.createElement('div', null,
          React.createElement('div', {
            style: {
              fontSize: 9, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
              letterSpacing: 0.7, color: 'var(--violet)', marginBottom: 5, fontWeight: 700,
            }
          }, 'Next Actions'),
          React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 4 } },
            nextActions.map((act, i) =>
              React.createElement('span', {
                key: i,
                style: {
                  padding: '2px 8px', borderRadius: 4,
                  background: 'var(--bg-panel)',
                  border: '1px solid var(--border-light)',
                  fontFamily: 'var(--font-mono)', fontSize: 10,
                  color: 'var(--text-secondary)',
                }
              }, act)
            )
          )
        )
      )
    )
  );
}

// ─── Attack Path Node row ─────────────────────────────────

function PathNodeRow({ node }) {
  const score = ((node.likelihood || 0) * (node.impact || 0) * (node.ease || 0)).toFixed(3);
  const tools = node.tools || [];
  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.PathNodeRow',
    style: {
      padding: '6px 0', borderBottom: '1px solid var(--border)',
      fontSize: 11,
    }
  },
    // Finding name
    React.createElement('div', {
      style: { color: 'var(--text-primary)', marginBottom: 3, fontWeight: 500 }
    }, node.finding || node.name || '(node)'),

    // Score breakdown: likelihood × impact × ease = score
    React.createElement('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: 4,
        fontFamily: 'var(--font-mono)', fontSize: 9,
        color: 'var(--text-muted)', marginBottom: 3,
      }
    },
      React.createElement('span', null, `L:${(node.likelihood||0).toFixed(2)}`),
      React.createElement('span', { style: { color: 'var(--border-bright)' } }, '×'),
      React.createElement('span', null, `I:${(node.impact||0).toFixed(2)}`),
      React.createElement('span', { style: { color: 'var(--border-bright)' } }, '×'),
      React.createElement('span', null, `E:${(node.ease||0).toFixed(2)}`),
      React.createElement('span', { style: { color: 'var(--border-bright)' } }, '='),
      React.createElement('span', {
        style: { color: 'var(--accent)', fontWeight: 700 }
      }, score)
    ),

    // Tools + MITRE
    React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 4 } },
      tools.map((t, i) =>
        React.createElement('span', {
          key: i,
          style: {
            padding: '1px 6px', borderRadius: 3,
            background: 'rgba(56,189,248,0.08)',
            border: '1px solid rgba(56,189,248,0.20)',
            fontFamily: 'var(--font-mono)', fontSize: 9,
            color: 'var(--cyan)',
          }
        }, t)
      ),
      node.mitre && React.createElement('span', {
        style: {
          padding: '1px 6px', borderRadius: 3,
          background: 'rgba(123,108,246,0.08)',
          border: '1px solid rgba(123,108,246,0.22)',
          fontFamily: 'var(--font-mono)', fontSize: 9,
          color: 'var(--violet)',
        }
      }, node.mitre)
    )
  );
}

// ─── Ranked Attack Path Card ──────────────────────────────

function AttackPathCard({ path }) {
  const [open, setOpen] = useState(false);
  const score = typeof path.total_score === 'number' ? path.total_score.toFixed(2) : '—';
  const effort = (path.estimated_effort || 'medium').toLowerCase();
  const effortBadge = effort === 'low'
    ? { color: 'var(--accent)', bg: 'rgba(0,229,160,0.10)', border: 'rgba(0,229,160,0.30)' }
    : effort === 'high'
      ? { color: 'var(--critical)', bg: 'rgba(255,69,96,0.10)', border: 'rgba(255,69,96,0.30)' }
      : { color: 'var(--medium)', bg: 'rgba(245,200,66,0.08)', border: 'rgba(245,200,66,0.30)' };

  const nodes = path.nodes || [];
  const conf  = path.path_confidence || path.confidence || 0;

  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.AttackPathCard',
    style: {
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 8, padding: 14,
      transition: 'border-color 0.15s',
    },
    onMouseEnter: e => { e.currentTarget.style.borderColor = 'var(--border-light)'; },
    onMouseLeave: e => { e.currentTarget.style.borderColor = 'var(--border)'; },
  },

    // Score + description row
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 8 }
    },
      // Large score number
      React.createElement('div', {
        style: { flexShrink: 0, textAlign: 'center', minWidth: 44 }
      },
        React.createElement('div', {
          style: {
            fontFamily: 'var(--font-mono)', fontSize: 22, fontWeight: 700,
            color: 'var(--accent)', lineHeight: 1,
          }
        }, score),
        React.createElement('div', {
          style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: 0.5, marginTop: 2 }
        }, 'SCORE')
      ),
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },
        React.createElement('div', {
          style: {
            fontSize: 12, color: 'var(--text-primary)', fontWeight: 500,
            lineHeight: 1.45, marginBottom: 6,
          }
        }, path.description || path.name || '(no description)'),

        // Entry → Objective
        (path.entry_point || path.objective) && React.createElement('div', {
          style: {
            display: 'flex', alignItems: 'center', gap: 6,
            fontFamily: 'var(--font-mono)', fontSize: 10,
            color: 'var(--text-muted)', marginBottom: 6,
          }
        },
          path.entry_point && React.createElement('span', {
            style: { color: 'var(--cyan)' }
          }, path.entry_point),
          (path.entry_point && path.objective) && React.createElement('span', {
            style: { color: 'var(--border-bright)' }
          }, '→'),
          path.objective && React.createElement('span', {
            style: { color: 'var(--accent)' }
          }, path.objective)
        ),

        // Badge row
        React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 5 } },
          React.createElement(InlineBadge, {
            label: effort.toUpperCase(),
            color: effortBadge.color,
            bg: effortBadge.bg,
            border: effortBadge.border,
          })
        )
      )
    ),

    // Path confidence bar
    React.createElement('div', { style: { marginBottom: nodes.length > 0 ? 8 : 0 } },
      React.createElement('div', {
        style: {
          display: 'flex', justifyContent: 'space-between',
          fontSize: 9, color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)', marginBottom: 3,
        }
      },
        React.createElement('span', null, 'PATH CONFIDENCE'),
        React.createElement('span', null, `${Math.round(conf * 100)}%`)
      ),
      React.createElement(ConfidenceBar, { value: conf, height: 3 })
    ),

    // Nodes (collapsible)
    nodes.length > 0 && React.createElement('div', null,
      React.createElement('button', {
        onClick: () => setOpen(o => !o),
        style: {
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--text-muted)', fontSize: 10, marginTop: 6,
          fontFamily: 'var(--font-mono)', padding: '2px 0',
          display: 'flex', alignItems: 'center', gap: 4,
        }
      },
        React.createElement('span', null, open ? '▼' : '▶'),
        React.createElement('span', null, `${nodes.length} node${nodes.length !== 1 ? 's' : ''}`)
      ),
      open && React.createElement('div', {
        style: { marginTop: 6 }
      },
        nodes.map((node, i) =>
          React.createElement(PathNodeRow, { key: i, node })
        )
      )
    )
  );
}

// ─── Justified Action Card ────────────────────────────────

function JustifiedActionCard({ action }) {
  const [open, setOpen] = useState(false);

  const conf = action.confidence || 0;
  const confPct = Math.round(conf * 100);
  const confColor = conf >= 0.7
    ? 'var(--accent)'
    : conf >= 0.4
      ? 'var(--medium)'
      : 'var(--critical)';

  const riskLevel = (action.risk_level || action.pre_execution_plan?.risk_level || '').toLowerCase();
  const riskBadge = riskLevel === 'high'
    ? { color: 'var(--critical)', bg: 'rgba(255,69,96,0.10)', border: 'rgba(255,69,96,0.30)' }
    : riskLevel === 'medium'
      ? { color: 'var(--medium)', bg: 'rgba(245,200,66,0.08)', border: 'rgba(245,200,66,0.30)' }
      : riskLevel === 'low'
        ? { color: 'var(--accent)', bg: 'rgba(0,229,160,0.08)', border: 'rgba(0,229,160,0.28)' }
        : null;

  const plan = action.pre_execution_plan || {};
  const hasPlan = plan.objective || plan.path || riskLevel;

  const argStr = action.args
    ? (typeof action.args === 'string'
        ? action.args
        : JSON.stringify(action.args))
    : '';
  const argTrunc = argStr.length > 120 ? argStr.slice(0, 120) + '…' : argStr;

  const ts = action.timestamp
    ? new Date(action.timestamp).toLocaleTimeString()
    : null;

  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.JustifiedActionCard',
    style: {
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 8, padding: 14,
      transition: 'border-color 0.15s',
    },
    onMouseEnter: e => { e.currentTarget.style.borderColor = 'var(--border-light)'; },
    onMouseLeave: e => { e.currentTarget.style.borderColor = 'var(--border)'; },
  },

    // ── Header row: tool + badges + timestamp ─────────────
    React.createElement('div', {
      style: {
        display: 'flex', alignItems: 'center', flexWrap: 'wrap',
        gap: 8, marginBottom: 6,
      }
    },
      // Tool name (monospace, cyan)
      React.createElement('span', {
        style: {
          fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
          color: 'var(--cyan)',
        }
      }, action.tool || '(unknown tool)'),

      // Confidence badge
      React.createElement('span', {
        style: {
          padding: '1px 7px', borderRadius: 4, fontSize: 9,
          fontFamily: 'var(--font-mono)', fontWeight: 700,
          color: confColor,
          background: `${confColor}22`,
          border: `1px solid ${confColor}55`,
        }
      }, `${confPct}%`),

      // REQUIRES CONFIRMATION warning
      action.requires_confirmation && React.createElement('span', {
        style: {
          padding: '2px 8px', borderRadius: 4, fontSize: 9,
          fontFamily: 'var(--font-mono)', fontWeight: 700,
          color: 'var(--medium)',
          background: 'rgba(245,200,66,0.10)',
          border: '1px solid rgba(245,200,66,0.40)',
          letterSpacing: 0.4,
        }
      }, '⚠ REQUIRES CONFIRMATION'),

      React.createElement('div', { style: { flex: 1 } }),

      ts && React.createElement('span', {
        style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
      }, ts)
    ),

    // ── Args ──────────────────────────────────────────────
    argTrunc && React.createElement('div', {
      style: {
        fontFamily: 'var(--font-mono)', fontSize: 10,
        color: 'var(--text-muted)', marginBottom: 6,
        whiteSpace: 'pre-wrap', wordBreak: 'break-all',
      }
    }, argTrunc),

    // ── Reason ────────────────────────────────────────────
    action.reason && React.createElement('div', {
      style: {
        fontSize: 11, color: 'var(--text-secondary)',
        lineHeight: 1.55, marginBottom: 5,
      }
    }, action.reason),

    // ── Expected outcome (italic) ─────────────────────────
    action.expected_outcome && React.createElement('div', {
      style: {
        fontSize: 11, color: 'var(--text-muted)',
        fontStyle: 'italic', marginBottom: hasPlan ? 6 : 0,
      }
    }, action.expected_outcome),

    // ── Pre-execution plan (collapsible) ──────────────────
    hasPlan && React.createElement('div', null,
      React.createElement('button', {
        onClick: () => setOpen(o => !o),
        style: {
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--text-muted)', fontSize: 10,
          fontFamily: 'var(--font-mono)', padding: '2px 0',
          display: 'flex', alignItems: 'center', gap: 4,
        }
      },
        React.createElement('span', null, open ? '▼' : '▶'),
        React.createElement('span', null, 'Pre-execution plan')
      ),
      open && React.createElement('div', {
        style: {
          marginTop: 6, padding: '8px 10px', borderRadius: 6,
          background: 'var(--bg-panel)', border: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', gap: 5,
        }
      },
        plan.objective && React.createElement('div', {
          style: { fontSize: 11, color: 'var(--text-secondary)' }
        },
          React.createElement('span', {
            style: { fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginRight: 6, textTransform: 'uppercase' }
          }, 'Objective:'),
          plan.objective
        ),
        plan.path && React.createElement('div', {
          style: { fontSize: 11, color: 'var(--text-secondary)' }
        },
          React.createElement('span', {
            style: { fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginRight: 6, textTransform: 'uppercase' }
          }, 'Path:'),
          plan.path
        ),
        riskLevel && riskBadge && React.createElement('div', null,
          React.createElement(InlineBadge, {
            label: `RISK: ${riskLevel.toUpperCase()}`,
            color: riskBadge.color,
            bg: riskBadge.bg,
            border: riskBadge.border,
          })
        )
      )
    )
  );
}

// ─── Negative Memory Card ─────────────────────────────────

function NegativeMemoryCard({ item }) {
  const ts = item.timestamp
    ? new Date(item.timestamp).toLocaleTimeString()
    : null;

  const toolService = [item.tool, item.service].filter(Boolean).join(' : ');
  const attempts = item.attempt_count || item.attempts || 1;

  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.NegativeMemoryCard',
    style: {
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 8, padding: 12,
      display: 'flex', alignItems: 'flex-start', gap: 12,
      transition: 'border-color 0.15s',
    },
    onMouseEnter: e => { e.currentTarget.style.borderColor = 'var(--border-light)'; },
    onMouseLeave: e => { e.currentTarget.style.borderColor = 'var(--border)'; },
  },

    // Attempt count badge (left)
    React.createElement('div', {
      style: {
        flexShrink: 0, width: 32, height: 32, borderRadius: 6,
        background: 'rgba(255,69,96,0.10)', border: '1px solid rgba(255,69,96,0.28)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
        color: 'var(--critical)',
      }
    }, attempts),

    // Details
    React.createElement('div', { style: { flex: 1, minWidth: 0 } },
      // Tool:service
      toolService && React.createElement('div', {
        style: {
          fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
          color: 'var(--text-primary)', marginBottom: 3,
        }
      }, toolService),
      // Failure reason
      item.failure_reason && React.createElement('div', {
        style: { fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }
      }, item.failure_reason),
      // Timestamp
      ts && React.createElement('div', {
        style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 3 }
      }, ts)
    )
  );
}

// ─── Main Page ────────────────────────────────────────────

function ReasoningEnginePage() {
  const { state } = window.useStore();

  const hypotheses          = state.hypotheses          || [];
  const rankedPaths         = state.rankedPaths         || [];
  const actionScore         = state.actionScore         || 0;
  const justifiedActions    = state.justifiedActions    || [];
  const negativeMemory      = state.negativeMemory      || [];
  const reasoningIteration  = state.reasoningIteration  || 0;
  const reasoningEngineActive = state.reasoningEngineActive || false;

  // ── Hypothesis confirmation pulse (Spec §9.1 phase-advance) ─────────────
  // Fires .motion-phase-advance for ~1.2s when a hypothesis transitions to
  // status === 'validated' (the engine's term for "confirmed"). Conservative
  // adaptation per task brief — the codebase uses 'validated', not 'confirmed'.
  const [recentlyConfirmed, setRecentlyConfirmed] = useState({});
  useEffect(() => {
    const validated = (state.hypotheses || []).filter(h =>
      (h.status || '').toLowerCase() === 'validated'
    );
    validated.forEach(h => {
      const id = h.hypothesis_id || h.id;
      if (!id) return;
      if (!recentlyConfirmed[id]) {
        setRecentlyConfirmed(prev => ({ ...prev, [id]: Date.now() }));
        setTimeout(() => {
          setRecentlyConfirmed(prev => {
            const n = { ...prev };
            delete n[id];
            return n;
          });
        }, 1200);
      }
    });
  }, [state.hypotheses]);

  // ── Sort hypotheses: validated first → by confidence desc → invalidated last
  const sortedHypotheses = [...hypotheses].sort((a, b) => {
    const statusOrder = s => {
      const v = (s.status || 'pending').toLowerCase();
      if (v === 'validated')   return 0;
      if (v === 'pending')     return 1;
      if (v === 'invalidated') return 2;
      return 1;
    };
    const so = statusOrder(a) - statusOrder(b);
    if (so !== 0) return so;
    return (b.confidence || 0) - (a.confidence || 0);
  });

  // ── Sort ranked paths by total_score desc
  const sortedPaths = [...rankedPaths].sort((a, b) =>
    (b.total_score || 0) - (a.total_score || 0)
  );

  // ── Justified actions: newest first
  const sortedActions = [...justifiedActions].reverse();

  // ── Action score color
  const scoreColor = actionScore > 0
    ? 'var(--accent)'
    : actionScore < 0
      ? 'var(--critical)'
      : 'var(--text-muted)';
  const scoreLabel = actionScore > 0
    ? `+${actionScore}`
    : String(actionScore);

  return React.createElement('div', { 'data-slot': 'ReasoningEnginePage.ReasoningEnginePage',
    style: {
      display: 'flex', flexDirection: 'column', height: '100%',
      padding: 16, gap: 16, background: 'var(--bg-base)', overflowY: 'auto',
    }
  },

    // ══ 1. PAGE HEADER ════════════════════════════════════════
    React.createElement('div', { className: 'page-header', style: { flexShrink: 0, marginBottom: 0 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title' }, '🧠 Reasoning Engine'),
        React.createElement('div', { className: 'page-subtitle' }, 'Hypothesis-driven attack planning')
      ),

      // Right: status badge + iteration + action score
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }
      },

        // Status badge
        React.createElement('div', {
          style: {
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '4px 12px', borderRadius: 20,
            background: reasoningEngineActive
              ? 'rgba(0,229,160,0.10)'
              : 'rgba(255,255,255,0.04)',
            border: `1px solid ${reasoningEngineActive ? 'rgba(0,229,160,0.35)' : 'var(--border-light)'}`,
          }
        },
          // Pulsing dot
          React.createElement('span', {
            className: reasoningEngineActive ? 'status-dot running' : 'status-dot idle',
          }),
          React.createElement('span', {
            style: {
              fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
              color: reasoningEngineActive ? 'var(--accent)' : 'var(--text-muted)',
              letterSpacing: 0.5,
            }
          }, reasoningEngineActive ? 'ACTIVE' : 'IDLE')
        ),

        // Iteration counter
        React.createElement('div', {
          style: {
            padding: '4px 12px', borderRadius: 20,
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid var(--border-light)',
            fontSize: 10, fontFamily: 'var(--font-mono)',
            color: 'var(--text-secondary)',
          }
        }, `Iteration: ${reasoningIteration} / 50`),

        // Action score badge
        React.createElement('div', {
          style: {
            padding: '4px 12px', borderRadius: 20,
            background: `${scoreColor}15`,
            border: `1px solid ${scoreColor}44`,
            fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 700,
            color: scoreColor,
          }
        }, scoreLabel)
      )
    ),

    // ══ 2+3. HYPOTHESES + RANKED PATHS (two-column grid) ══════
    React.createElement('div', {
      style: {
        display: 'grid',
        gridTemplateColumns: '60% 40%',
        gap: 14,
        flexShrink: 0,
        minHeight: 0,
      }
    },

      // ── Left: Hypotheses ─────────────────────────────────
      React.createElement('div', {
        style: { display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0 }
      },
        React.createElement(SectionHeader, {
          label: 'Hypotheses',
          count: sortedHypotheses.length,
          countColor: 'var(--violet)',
        }),
        sortedHypotheses.length === 0
          ? React.createElement(MutedEmpty, {
              text: 'No hypotheses generated yet — start a pentest with reasoning loop enabled'
            })
          : sortedHypotheses.map((hyp, i) => {
              const hid = hyp.hypothesis_id || hyp.id;
              return React.createElement(HypothesisCard, {
                key: hyp.id || hyp.hypothesis_id || i,
                hyp,
                pulse: hid ? !!recentlyConfirmed[hid] : false,
              });
            })
      ),

      // ── Right: Ranked Attack Paths ────────────────────────
      React.createElement('div', {
        style: { display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0 }
      },
        React.createElement(SectionHeader, {
          label: 'Ranked Attack Paths',
          count: sortedPaths.length,
          countColor: 'var(--cyan)',
        }),
        sortedPaths.length === 0
          ? React.createElement(MutedEmpty, {
              text: 'No ranked attack paths available'
            })
          : sortedPaths.map((path, i) =>
              React.createElement(AttackPathCard, {
                key: path.id || path.path_id || i,
                path,
              })
            )
      )
    ),

    // ── Crosshair section divider ─────────────────────────────
    React.createElement('div', { className: 'crosshair' }),

    // ══ 4. ACTION HISTORY (full width) ════════════════════════
    React.createElement('div', {
      style: { display: 'flex', flexDirection: 'column', gap: 10, flexShrink: 0 }
    },
      React.createElement(SectionHeader, {
        label: 'Action History',
        count: sortedActions.length,
        countColor: 'var(--accent)',
      }),
      sortedActions.length === 0
        ? React.createElement(MutedEmpty, {
            text: 'No justified actions recorded yet'
          })
        : sortedActions.map((action, i) =>
            React.createElement(JustifiedActionCard, {
              key: action.id || action.action_id || i,
              action,
            })
          )
    ),

    // ══ 5. NEGATIVE MEMORY (full width) ═══════════════════════
    React.createElement('div', {
      style: { display: 'flex', flexDirection: 'column', gap: 10, flexShrink: 0 }
    },
      React.createElement(SectionHeader, {
        label: 'Negative Memory — Exhausted Paths',
        count: negativeMemory.length,
        countColor: 'var(--critical)',
      }),
      negativeMemory.length === 0
        ? React.createElement(MutedEmpty, {
            text: 'No exhausted paths recorded'
          })
        : negativeMemory.map((item, i) =>
            React.createElement(NegativeMemoryCard, {
              key: item.id || item.key || i,
              item,
            })
          )
    )
  );
}

window.ReasoningEnginePage = ReasoningEnginePage;
