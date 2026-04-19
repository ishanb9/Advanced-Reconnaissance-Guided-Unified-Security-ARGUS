// MissionControl.jsx — Main command dashboard with live attack plan tracker
const { useState, useEffect, useRef, useMemo } = React;

// ── Date/time utilities ───────────────────────────────────────────────────────
// Safely parse a date string as UTC even when the 'Z' suffix is missing
// (Python's datetime.utcnow().isoformat() produces naive strings; without Z
//  browsers interpret them as LOCAL time, skewing elapsed-time calculations).
function parseUTC(s) {
  if (!s) return NaN;
  let str = String(s).trim();
  if (!/Z$|[+-]\d{2}:?\d{2}$/.test(str)) str += 'Z';
  const t = new Date(str).getTime();
  return isNaN(t) ? NaN : t;
}

function fmtDuration(secs) {
  if (!secs || secs < 0) return '0s';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function fmtHHMM(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d)) return '';
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
}

const PHASES = [
  { key: 'recon',        label: 'Recon',        icon: '🔍' },
  { key: 'vuln_id',      label: 'Vuln ID',      icon: '🔬' },
  { key: 'exploit',      label: 'Exploit',      icon: '💥' },
  { key: 'post_exploit', label: 'Post Exploit', icon: '🎭' },
  { key: 'privesc',      label: 'Priv Esc',     icon: '⬆'  },
  { key: 'iot',          label: 'IoT',          icon: '📟' },
  { key: 'reporting',    label: 'Reporting',    icon: '📄' },
];

const AGENT_META = {
  master:  { icon: '⚡', color: 'var(--cyan)',   label: 'Master'  },
  recon:   { icon: '🔍', color: 'var(--green)',  label: 'Recon'   },
  vuln:    { icon: '🔬', color: 'var(--amber)',  label: 'Vuln'    },
  web:     { icon: '🌐', color: 'var(--cyan)',   label: 'Web'     },
  osint:   { icon: '🕵', color: 'var(--violet)',  label: 'OSINT'   },
  exploit: { icon: '💥', color: 'var(--red)',    label: 'Exploit' },
  privesc: { icon: '🔑', color: 'var(--high)',   label: 'Privesc' },
  iot:     { icon: '📟', color: '#73d13d',       label: 'IoT'     },
  shell:   { icon: '🐚', color: 'var(--cyan)',   label: 'Shell'   },
  payload: { icon: '📦', color: 'var(--amber)',  label: 'Payload' },
};

const STEP_STATUS = {
  pending: { color: 'var(--border-bright)', border: 'var(--border)',       icon: '○', label: 'PENDING'  },
  active:  { color: 'var(--cyan)',          border: 'var(--cyan)',         icon: '⟳', label: 'ACTIVE'   },
  done:    { color: 'var(--green)',         border: 'var(--green)',        icon: '✓', label: 'DONE'     },
  failed:  { color: 'var(--red)',           border: 'var(--red)',          icon: '✗', label: 'FAILED'   },
  skipped: { color: 'var(--text-muted)',    border: 'var(--border-bright)',icon: '—', label: 'SKIPPED'  },
};

// ── Attack Plan Step Card ────────────────────────────────────────────────────
function PlanStepCard({ step, index, isOptimal }) {
  const [expanded, setExpanded] = useState(false);
  const { state } = window.useStore();
  const st       = STEP_STATUS[step.status] || STEP_STATUS.pending;
  const isActive = step.status === 'active';
  const isDone   = step.status === 'done';
  const isFailed = step.status === 'failed';
  const isPending= step.status === 'pending';
  const isSub    = !!step.is_substep;

  // Find tool exit info for this step's tool across all subagents
  let toolExitInfo = null;
  if (step.tool && state.subagentStates) {
    for (const saState of Object.values(state.subagentStates)) {
      if (saState.toolExits && saState.toolExits[step.tool]) {
        toolExitInfo = saState.toolExits[step.tool];
        break;
      }
    }
  }

  const hasDetail = !!(step.detail || step.produces || step.mitre_name);

  // Status colours
  const borderColor = isActive ? st.color
    : isFailed ? 'rgba(255,68,102,0.5)'
    : isDone   ? 'rgba(0,255,136,0.25)'
    : isSub    ? 'var(--border)'
    : 'var(--border)';

  const bgColor = isActive ? `${st.color}10`
    : isFailed ? 'rgba(255,68,102,0.07)'
    : isDone   ? 'rgba(0,255,136,0.04)'
    : 'var(--bg-surface)';

  const labelColor = isActive ? 'var(--text-primary)'
    : isDone   ? 'var(--green)'
    : isFailed ? 'var(--critical)'
    : isPending ? 'var(--text-muted)'
    : 'var(--text-secondary)';

  return React.createElement('div', {
    onClick: hasDetail ? () => setExpanded(e => !e) : undefined,
    style: {
      borderRadius: isSub ? 5 : 8,
      border:       `1px solid ${borderColor}`,
      background:   bgColor,
      padding:      isSub ? '8px 10px 8px 24px' : '11px 14px',
      marginLeft:   isSub ? 16 : 0,
      cursor:       hasDetail ? 'pointer' : 'default',
      transition:   'border-color 0.2s, background 0.2s',
      position:     'relative',
    }
  },
    // Active top glow bar
    isActive && React.createElement('div', {
      style: {
        position: 'absolute', top: 0, left: 0, right: 0, height: 2,
        background: st.color, boxShadow: `0 0 10px ${st.color}`,
        animation: 'pulse 1.5s ease-in-out infinite', borderRadius: '8px 8px 0 0',
      }
    }),

    // Sub-step vertical connector
    isSub && React.createElement('div', {
      style: {
        position: 'absolute', left: 7, top: 0, bottom: 0, width: 1,
        background: isFailed ? 'rgba(255,68,102,0.3)' : isDone ? 'rgba(0,255,136,0.2)' : 'var(--border)',
      }
    }),
    isSub && React.createElement('div', {
      style: {
        position: 'absolute', left: 7, top: '50%', width: 10, height: 1,
        background: isFailed ? 'rgba(255,68,102,0.3)' : isDone ? 'rgba(0,255,136,0.2)' : 'var(--border)',
      }
    }),

    // ── Top row: number + icon + label + badges ──────────────
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'flex-start', gap: isSub ? 6 : 8 }
    },

      // Step number circle / sub-step dot
      !isSub
        ? React.createElement('div', {
            style: {
              width: 22, height: 22, borderRadius: '50%', flexShrink: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
              background: `${st.color}18`,
              color:  st.color,
              border: `1px solid ${st.color}50`,
              marginTop: 1,
            }
          }, isDone ? '✓' : isFailed ? '✗' : isActive ? '⟳' : String(index + 1))
        : React.createElement('div', {
            style: {
              width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
              background: isFailed ? 'rgba(255,68,102,0.6)' : isDone ? 'rgba(0,255,136,0.4)' : `${st.color}40`,
              marginTop: 5,
            }
          }),

      // Phase icon
      !isSub && React.createElement('span', {
        style: { fontSize: 15, flexShrink: 0, marginTop: 2 }
      }, step.icon || '◆'),

      // Label block — wraps naturally
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },

        // Main label — WRAPS, no truncation
        React.createElement('div', {
          style: {
            fontSize: isSub ? 11 : 12, fontWeight: isSub ? 500 : 700,
            color:     labelColor,
            lineHeight: 1.4,
            wordBreak: 'break-word',
          }
        }, step.label || ''),

        // Tool hint below label (main steps only)
        step.tool && !isSub && React.createElement('div', {
          style: {
            fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2,
          }
        }, step.tool),
      ),

      // Right badges — stacked vertically on small space
      React.createElement('div', {
        style: {
          display: 'flex', flexDirection: 'column', alignItems: 'flex-end',
          gap: 3, flexShrink: 0, marginTop: 1,
        }
      },
        // Status pill
        !(isSub && isPending) && React.createElement('span', {
          style: {
            fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
            background: `${st.color}18`,
            border:     `1px solid ${st.color}50`,
            color:      st.color,
            fontFamily: 'var(--font-mono)',
            animation:  isActive ? 'pulse 1.5s infinite' : 'none',
            whiteSpace: 'nowrap',
          }
        }, st.label),

        // Badges row
        React.createElement('div', { style: { display: 'flex', gap: 3, alignItems: 'center' } },
          // Optimal
          isOptimal && !isSub && React.createElement('span', {
            style: {
              fontSize: 8, padding: '1px 4px', borderRadius: 3,
              background: 'rgba(255,170,0,0.12)', border: '1px solid rgba(255,170,0,0.4)',
              color: 'var(--amber)',
            }
          }, '⭐'),
          // MITRE
          step.mitre_id && !isSub && React.createElement('span', {
            style: {
              fontSize: 8, padding: '1px 5px', borderRadius: 3,
              background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)',
              color: 'var(--cyan)', fontFamily: 'var(--font-mono)',
            }
          }, step.mitre_id),
          // Probability
          step.probability != null && React.createElement('span', {
            style: {
              fontSize: 9,
              color: step.probability >= 0.7 ? 'var(--green)'
                   : step.probability >= 0.4 ? 'var(--amber)' : 'var(--red)',
              fontFamily: 'var(--font-mono)',
            }
          }, `${Math.round(step.probability * 100)}%`),
        ),
      ),
    ),

    // ── Result / summary line ─────────────────────────────────
    step.result && (isDone || isFailed || isActive) && React.createElement('div', {
      style: {
        marginTop:  6,
        fontSize:   isSub ? 10 : 11,
        lineHeight: 1.55,
        color:      isDone ? 'var(--low)' : isFailed ? 'var(--critical)' : 'var(--text-secondary)',
        paddingLeft: isSub ? 14 : 30,
        paddingRight: 4,
        borderLeft: `2px solid ${isDone ? 'rgba(0,255,136,0.25)' : isFailed ? 'rgba(255,68,102,0.3)' : st.color + '25'}`,
        marginLeft: isSub ? 0 : 4,
        wordBreak:  'break-word',
      }
    }, step.result),

    // ── Tool exit status ──────────────────────────────────────
    toolExitInfo != null && React.createElement('div', {
      style: {
        marginTop: 5, paddingLeft: isSub ? 14 : 30,
        display: 'flex', alignItems: 'center', gap: 6,
      }
    },
      React.createElement('span', {
        style: {
          fontSize: 9, padding: '2px 7px', borderRadius: 3,
          fontFamily: 'var(--font-mono)', fontWeight: 700,
          background: toolExitInfo.success ? 'rgba(0,255,136,0.08)' : 'rgba(255,68,102,0.10)',
          border: `1px solid ${toolExitInfo.success ? 'rgba(0,255,136,0.3)' : 'rgba(255,68,102,0.4)'}`,
          color: toolExitInfo.success ? 'var(--green)' : 'var(--red)',
        }
      }, `${toolExitInfo.success ? '✓' : '✗'} ${step.tool} [exit ${toolExitInfo.exit_code}]`)
    ),

    // ── Found indicator ───────────────────────────────────────
    isDone && step.found != null && React.createElement('div', {
      style: {
        marginTop: 4, paddingLeft: isSub ? 14 : 30,
        fontSize: 10, fontWeight: 700,
        color: step.found ? 'var(--green)' : 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
      }
    }, step.found ? '✅ Found' : '⭕ Nothing found'),

    // ── Expanded detail ───────────────────────────────────────
    expanded && hasDetail && React.createElement('div', {
      style: {
        marginTop:  8, paddingTop: 8,
        paddingLeft: isSub ? 14 : 4,
        borderTop:  '1px solid var(--border)',
        display:    'flex', flexDirection: 'column', gap: 5,
      }
    },
      step.detail && React.createElement('div', {
        style: {
          fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
          lineHeight: 1.6, wordBreak: 'break-word',
          background: 'var(--bg-base)', padding: '5px 8px', borderRadius: 4,
        }
      }, step.detail),
      step.produces && React.createElement('div', { style: { fontSize: 10, display: 'flex', gap: 6 } },
        React.createElement('span', { style: { color: 'var(--text-muted)', flexShrink: 0 } }, 'Produces:'),
        React.createElement('span', { style: { color: 'var(--cyan)', fontFamily: 'var(--font-mono)' } }, step.produces)
      ),
      step.mitre_name && React.createElement('div', { style: { fontSize: 10, display: 'flex', gap: 6 } },
        React.createElement('span', { style: { color: 'var(--text-muted)', flexShrink: 0 } }, 'MITRE:'),
        React.createElement('span', { style: { color: 'var(--cyan)' } }, `${step.mitre_id} — ${step.mitre_name}`)
      )
    ),

    // Expand hint
    hasDetail && React.createElement('div', {
      style: { textAlign: 'right', fontSize: 8, color: 'var(--border-bright)', marginTop: 2 }
    }, expanded ? '▲ less' : '▼ more')
  );
}


// ── Attack Phase Panel — the main new component ──────────────────────────────
function AttackPhasePanel({ planSteps, currentPhase, attackTree, phasesCompleted, hypothesis, assessmentType }) {
  const [tab, setTab] = useState('steps'); // 'steps' | 'tree' | 'gantt'
  const optimal = attackTree?.optimal_path || [];
  const optimalSet = new Set(optimal);

  // ── Step timing tracking ─────────────────────────────────────────────────
  // Records wall-clock start/end for each step as status changes arrive.
  const stepTimingsRef    = useRef({}); // { stepId: { startedAt, completedAt } }
  const prevStepStatusRef = useRef({}); // { stepId: lastSeenStatus }

  useEffect(() => {
    const now = Date.now();
    (planSteps || []).forEach(step => {
      const prev = prevStepStatusRef.current[step.id];
      if (prev === step.status) return; // no change
      prevStepStatusRef.current[step.id] = step.status;
      const t = stepTimingsRef.current[step.id] || {};
      if (step.status === 'active' && !t.startedAt) {
        t.startedAt = now;
      }
      if ((step.status === 'done' || step.status === 'failed') && !t.completedAt) {
        t.completedAt = now;
        if (!t.startedAt) t.startedAt = now;
      }
      stepTimingsRef.current[step.id] = t;
    });
  }, [planSteps]);

  const hasSteps = planSteps && planSteps.length > 0;
  const hasTree  = attackTree && (attackTree.attack_nodes || []).length > 0;

  // Stats — exclude sub-steps from main counts (they're children of exploit)
  const mainSteps = planSteps.filter(s => !s.is_substep);
  const done    = mainSteps.filter(s => s.status === 'done').length;
  const failed  = mainSteps.filter(s => s.status === 'failed').length;
  const active  = mainSteps.filter(s => s.status === 'active').length;
  const pending = mainSteps.filter(s => s.status === 'pending').length;
  const subDone = planSteps.filter(s => s.is_substep && s.status === 'done').length;
  const subFail = planSteps.filter(s => s.is_substep && s.status === 'failed').length;

  const tabStyle = (key) => ({
    padding: '4px 12px', borderRadius: 5, cursor: 'pointer', fontSize: 10,
    fontFamily: 'var(--font-mono)', fontWeight: 600, letterSpacing: 0.5,
    border: tab === key ? '1px solid var(--cyan)' : '1px solid var(--border)',
    background: tab === key ? 'rgba(0,212,255,0.08)' : 'transparent',
    color: tab === key ? 'var(--cyan)' : 'var(--text-muted)',
  });

  return React.createElement('div', {
    style: { padding: '16px 18px', borderRadius: 10, background: 'var(--bg-surface)', border: '1px solid var(--border)', marginBottom: 16 }
  },

    // Header row
    React.createElement('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 } },
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10 } },
        React.createElement('div', { style: { fontSize: 12, fontWeight: 700, color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: 1 } },
          '⚔ Attack Phase'
        ),
        // Progress counts
        hasSteps && React.createElement('div', { style: { display: 'flex', gap: 6 } },
          done    > 0 && React.createElement('span', { style: { fontSize: 9, padding: '1px 6px', borderRadius: 10, background: 'rgba(0,255,136,0.1)', color: 'var(--green)', border: '1px solid rgba(0,255,136,0.3)' } }, `✓ ${done}`),
          active  > 0 && React.createElement('span', { style: { fontSize: 9, padding: '1px 6px', borderRadius: 10, background: 'rgba(0,212,255,0.1)', color: 'var(--cyan)',  border: '1px solid rgba(0,212,255,0.3)', animation: 'pulse 1.5s infinite' } }, `⟳ ${active}`),
          failed  > 0 && React.createElement('span', { style: { fontSize: 9, padding: '1px 6px', borderRadius: 10, background: 'rgba(255,68,102,0.1)',  color: 'var(--red)',   border: '1px solid rgba(255,68,102,0.3)' } }, `✗ ${failed}`),
          pending > 0 && React.createElement('span', { style: { fontSize: 9, padding: '1px 6px', borderRadius: 10, background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)' } }, `○ ${pending}`),
          // Sub-step summary (exploit vectors)
          (subDone + subFail) > 0 && React.createElement('span', {
            style: { fontSize: 9, padding: '1px 6px', borderRadius: 10,
                     background: 'rgba(255,100,0,0.08)', color: 'var(--high)',
                     border: '1px solid rgba(255,100,0,0.3)' }
          }, `vectors: ${subDone}✓ ${subFail}✗`),
        )
      ),
      // Tabs
      React.createElement('div', { style: { display: 'flex', gap: 4, alignItems: 'center' } },
        assessmentType && React.createElement('span', {
          style: { fontSize: 9, padding: '1px 7px', borderRadius: 10, marginRight: 4,
                   background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)',
                   color: 'var(--cyan)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }
        }, assessmentType),
        React.createElement('div', { style: tabStyle('steps'), onClick: () => setTab('steps') }, '📋 STEPS'),
        hasTree && React.createElement('div', { style: tabStyle('tree'), onClick: () => setTab('tree') }, '🌳 TREE'),
        hasSteps && React.createElement('div', { style: tabStyle('gantt'), onClick: () => setTab('gantt') }, '📊 GANTT'),
      )
    ),

    // Hypothesis banner (shown when plan is ready but tree not yet)
    hypothesis && React.createElement('div', {
      style: {
        marginBottom: 10, padding: '8px 12px', borderRadius: 6,
        background: 'rgba(255,170,0,0.05)', border: '1px solid rgba(255,170,0,0.2)',
        fontSize: 11, color: 'var(--amber)', lineHeight: 1.5,
        display: 'flex', gap: 8, alignItems: 'flex-start',
      }
    },
      React.createElement('span', { style: { flexShrink: 0 } }, '💡'),
      React.createElement('div', null,
        React.createElement('span', { style: { fontWeight: 700, marginRight: 6 } }, 'Master hypothesis:'),
        hypothesis
      )
    ),

    // Phase Progress Arc
    React.createElement(PhaseProgressArc, { currentPhase, phasesCompleted }),

    // Phase timeline strip
    React.createElement('div', { style: { display: 'flex', gap: 6, marginBottom: 14, overflowX: 'auto', flexWrap: 'wrap' } },
      PHASES.map((ph, i) => {
        const isDone   = phasesCompleted?.includes(ph.key);
        const isActive = currentPhase === ph.key;
        const ci       = PHASES.findIndex(p => p.key === currentPhase);
        const isPast   = ci > i;
        const st       = isDone || isPast ? 'done' : isActive ? 'active' : 'pending';
        const c = {
          done:    { bg: 'rgba(0,212,255,0.1)', border: 'var(--cyan)',  text: 'var(--cyan)' },
          active:  { bg: 'rgba(0,255,136,0.1)', border: 'var(--green)', text: 'var(--green)' },
          pending: { bg: 'transparent',          border: 'var(--border)', text: 'var(--text-muted)' },
        }[st];
        return React.createElement('div', {
          key: ph.key,
          style: {
            display: 'flex', alignItems: 'center', gap: 7,
            padding: '7px 13px', borderRadius: 7, whiteSpace: 'nowrap',
            border: `1px solid ${c.border}`,
            background: c.bg, color: c.text,
            fontSize: 11, fontFamily: 'var(--font-mono)',
            fontWeight: isDone || isActive ? 600 : 400,
            boxShadow: isActive ? `0 0 14px ${c.border}60` : 'none',
            transition: 'all 0.3s',
          }
        },
          React.createElement('span', {
            style: {
              width: 7, height: 7, borderRadius: '50%', background: c.text, flexShrink: 0,
              boxShadow: isActive ? `0 0 8px ${c.text}` : isDone ? `0 0 4px ${c.text}80` : 'none',
              animation: isActive ? 'pulse 1s infinite' : 'none',
            }
          }),
          ph.icon, ' ', ph.label,
          isDone   && React.createElement('span', { style: { fontSize: 11 } }, ' ✓'),
          isActive && React.createElement('span', { style: { fontSize: 11, animation: 'pulse 1s infinite' } }, ' ⟳'),
        );
      })
    ),

    // ── TAB: Steps ──────────────────────────────────────────────────────────
    tab === 'steps' && React.createElement('div', null,
      !hasSteps
        ? React.createElement('div', {
            style: { padding: '16px 0', display: 'flex', flexDirection: 'column', gap: 8 }
          },
            // Waiting for master plan
            React.createElement('div', {
              style: { display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
                       borderRadius: 7, border: '1px solid var(--border)', background: 'var(--bg-surface)' }
            },
              React.createElement('span', { style: { fontSize: 20 } }, '⚡'),
              React.createElement('div', null,
                React.createElement('div', { style: { fontSize: 11, fontWeight: 600, color: 'var(--cyan)' } }, 'Master Agent initializing...'),
                React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } }, 'Attack plan will appear within seconds of scan start')
              )
            )
          )
        : React.createElement('div', {
            style: {
              display: 'flex', flexDirection: 'column', gap: 6,
              maxHeight: 700, overflowY: 'auto', paddingRight: 4,
            }
          },
            (() => {
              // Give each non-substep a sequential number
              let mainIndex = 0;
              return planSteps.map((step, i) => {
                const idx = step.is_substep ? mainIndex : mainIndex++;
                return React.createElement(PlanStepCard, {
                  key:       step.id || i,
                  step,
                  index:     step.is_substep ? i : idx,
                  isOptimal: optimalSet.has(step.id),
                });
              });
            })()
          )
    ),

    // ── TAB: Tree ───────────────────────────────────────────────────────────
    tab === 'tree' && React.createElement('div', null,
      attackTree?.assessment_summary && React.createElement('div', {
        style: { fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: 12, padding: '8px 12px', borderRadius: 6, background: 'var(--bg-base)', border: '1px solid var(--border)' }
      }, attackTree.assessment_summary),

      // Optimal chain
      optimal.length > 0 && React.createElement('div', { style: { marginBottom: 12 } },
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 } }, '⭐ Optimal Attack Chain'),
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' } },
          ...optimal.map((nid, i) => {
            const node = (attackTree.attack_nodes || []).find(n => n.id === nid) || {};
            const status = planSteps.find(s => s.id === nid)?.status || 'pending';
            const stCol  = STEP_STATUS[status]?.color || 'var(--border-bright)';
            return [
              React.createElement('div', {
                key: nid,
                style: {
                  padding: '6px 12px', borderRadius: 6,
                  border: `1px solid ${stCol}60`,
                  background: `${stCol}10`,
                  textAlign: 'center', minWidth: 80,
                }
              },
                React.createElement('div', { style: { fontSize: 8, color: stCol, fontFamily: 'var(--font-mono)', marginBottom: 3 } },
                  node.mitre_id || `${i+1}`),
                React.createElement('div', { style: { fontSize: 10, color: 'var(--text-primary)', fontWeight: 600 } },
                  (node.technique || node.step || nid).slice(0, 24)),
                React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', marginTop: 2 } },
                  STEP_STATUS[status]?.icon + ' ' + (STEP_STATUS[status]?.label || ''))
              ),
              i < optimal.length - 1 && React.createElement('span', {
                key: `a${i}`, style: { color: 'var(--border-bright)', fontSize: 18, fontWeight: 300 }
              }, '→')
            ];
          }).flat().filter(Boolean)
        )
      ),

      // All chains
      (attackTree.attack_chains || []).length > 0 && React.createElement('div', null,
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 } }, 'All Attack Chains'),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 6 } },
          (attackTree.attack_chains || []).map((ch, i) =>
            React.createElement('div', {
              key: ch.chain_id || i,
              style: { padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-base)' }
            },
              React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 } },
                React.createElement('span', { style: { fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)' } }, ch.description || `Chain ${i+1}`),
                React.createElement('span', { style: { fontSize: 10, color: ch.combined_probability >= 0.6 ? 'var(--green)' : 'var(--amber)', fontFamily: 'var(--font-mono)' } },
                  `${Math.round((ch.combined_probability || 0) * 100)}%`)
              ),
              React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } },
                `Entry: ${ch.entry_point || '?'} → Objective: ${ch.objective || '?'}`)
            )
          )
        )
      ),

      // Immediate actions
      (attackTree.immediate_actions || []).length > 0 && React.createElement('div', { style: { marginTop: 12 } },
        React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 } }, 'Immediate Actions'),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 4 } },
          (attackTree.immediate_actions || []).map((action, i) =>
            React.createElement('div', { key: i, style: { fontSize: 11, color: 'var(--text-secondary)', display: 'flex', gap: 8 } },
              React.createElement('span', { style: { color: 'var(--cyan)', fontFamily: 'var(--font-mono)', flexShrink: 0 } }, `${i+1}.`),
              action
            )
          )
        )
      )
    ),

    // ── TAB: Gantt ──────────────────────────────────────────────────────────
    tab === 'gantt' && React.createElement('div', {
      style: { maxHeight: 520, overflowY: 'auto', paddingRight: 4 }
    },
      !hasSteps
        ? React.createElement('div', {
            style: { padding: '16px', color: 'var(--text-muted)', fontSize: 11, textAlign: 'center' }
          }, 'No steps to display')
        : (() => {
            const mainStepsOnly = planSteps.filter(s => !s.is_substep);
            const now = Date.now();

            // Compute durations for completed steps to scale bar widths relatively
            const durations = mainStepsOnly.map(step => {
              const t = stepTimingsRef.current[step.id] || {};
              if (t.startedAt && t.completedAt) return t.completedAt - t.startedAt;
              if (t.startedAt && step.status === 'active') return now - t.startedAt;
              return 0;
            });
            const maxDuration = Math.max(...durations, 1);

            // Legend row
            const legend = React.createElement('div', {
              style: {
                display: 'flex', gap: 16, marginBottom: 10,
                fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                borderBottom: '1px solid var(--border)', paddingBottom: 6,
              }
            },
              React.createElement('span', { style: { width: 100, flexShrink: 0, textAlign: 'right', paddingRight: 4 } }, 'STEP'),
              React.createElement('span', { style: { flex: 1, textAlign: 'center' } }, 'TIMELINE'),
              React.createElement('span', { style: { width: 44, flexShrink: 0, textAlign: 'center' } }, 'START'),
              React.createElement('span', { style: { width: 48, flexShrink: 0, textAlign: 'right' } }, 'DURATION'),
            );

            const rows = mainStepsOnly.map((step, i) => {
              const st       = STEP_STATUS[step.status] || STEP_STATUS.pending;
              const timing   = stepTimingsRef.current[step.id] || {};
              const isDone   = step.status === 'done';
              const isActive = step.status === 'active';
              const isFailed = step.status === 'failed';

              // Bar fill width — proportional to duration relative to longest step
              let barPct = 8; // minimum sliver for pending
              const dur = durations[i];
              if (isDone || isFailed)  barPct = Math.max(15, Math.round((dur / maxDuration) * 100));
              if (isActive)            barPct = Math.max(15, Math.min(92, Math.round((dur / maxDuration) * 100)));

              // Duration label
              let durLabel = '';
              if ((isDone || isFailed) && timing.startedAt && timing.completedAt) {
                durLabel = fmtDuration(Math.round((timing.completedAt - timing.startedAt) / 1000));
              } else if (isActive && timing.startedAt) {
                durLabel = fmtDuration(Math.round((now - timing.startedAt) / 1000)) + '…';
              }

              const startLabel = timing.startedAt ? fmtHHMM(timing.startedAt) : '';

              return React.createElement('div', {
                key: step.id || i,
                style: { display: 'flex', alignItems: 'center', gap: 8, minHeight: 28 }
              },
                // Step label
                React.createElement('div', {
                  style: {
                    width: 100, flexShrink: 0, fontSize: 9, fontFamily: 'var(--font-mono)',
                    color: st.color, textAlign: 'right', overflow: 'hidden',
                    textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 4,
                  }
                }, step.label || `Step ${i + 1}`),

                // Bar track
                React.createElement('div', {
                  style: {
                    flex: 1, height: 14, borderRadius: 4,
                    background: 'var(--bg-base)', border: '1px solid var(--border)',
                    position: 'relative', overflow: 'hidden',
                  }
                },
                  React.createElement('div', {
                    style: {
                      position: 'absolute', top: 0, left: 0, bottom: 0,
                      width: `${barPct}%`,
                      background: isDone
                        ? 'linear-gradient(90deg, var(--green), var(--cyan))'
                        : isActive ? 'var(--cyan)'
                        : isFailed ? 'var(--critical)'
                        : 'var(--border)',
                      borderRadius: 4,
                      opacity: step.status === 'pending' ? 0.3 : 1,
                      animation: isActive ? 'pulse 1.5s ease-in-out infinite' : 'none',
                      transition: 'width 0.6s ease',
                      boxShadow: isActive ? '0 0 8px var(--cyan)' : 'none',
                    }
                  })
                ),

                // Start time
                React.createElement('div', {
                  style: {
                    width: 44, flexShrink: 0, fontSize: 9, fontFamily: 'var(--font-mono)',
                    color: 'var(--text-muted)', textAlign: 'center',
                  }
                }, startLabel),

                // Duration
                React.createElement('div', {
                  style: {
                    width: 48, flexShrink: 0, fontSize: 9, fontFamily: 'var(--font-mono)',
                    color: isDone ? 'var(--cyan)' : isActive ? 'var(--low)' : 'var(--border-bright)',
                    textAlign: 'right',
                    animation: isActive ? 'pulse 1.5s infinite' : 'none',
                  }
                }, durLabel)
              );
            });

            return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 4 } },
              legend, ...rows
            );
          })()
    )
  );
}

// ── Supporting components ──────────────────────────────────────────────────

function AgentCard({ name, status = 'idle', phase, message, onClick }) {
  const [hov, setHov] = React.useState(false);
  const meta = AGENT_META[name] || { icon: '◆', color: 'var(--cyan)', label: name };
  const isActive = status === 'running' || status === 'thinking';
  const statusColors = {
    running: 'var(--low)', thinking: 'var(--cyan)',
    done: 'var(--low)', error: 'var(--critical)', idle: 'var(--border-bright)'
  };
  const dotColor = statusColors[status] || 'var(--border-bright)';

  return React.createElement('div', {
    onClick,
    onMouseEnter: () => setHov(true),
    onMouseLeave: () => setHov(false),
    style: {
      padding: '9px 11px', borderRadius: 8, cursor: onClick ? 'pointer' : 'default',
      border: `1px solid ${isActive ? meta.color + '55' : hov ? 'var(--border-light)' : 'var(--border)'}`,
      background: isActive ? `${meta.color}0A` : hov ? 'var(--bg-panel)' : 'var(--bg-elevated)',
      transition: 'all 0.15s', position: 'relative', overflow: 'hidden',
    }
  },
    // Active top bar
    isActive && React.createElement('div', {
      style: {
        position: 'absolute', top: 0, left: 0, right: 0, height: 2,
        background: meta.color, boxShadow: `0 0 10px ${meta.color}`,
        animation: 'pulse 1.5s infinite',
      }
    }),
    // Header row
    React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 } },
      React.createElement('span', { style: { fontSize: 13, lineHeight: 1 } }, meta.icon),
      React.createElement('span', { style: { fontSize: 10, fontWeight: 700, color: meta.color, letterSpacing: 0.8, flex: 1 } }, meta.label.toUpperCase()),
      React.createElement('span', {
        style: {
          fontSize: 8, padding: '1px 6px', borderRadius: 4,
          background: isActive ? `${dotColor}20` : 'transparent',
          color: dotColor, border: `1px solid ${isActive ? dotColor + '60' : 'var(--border)'}`,
          fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: 0.5,
        }
      }, status === 'running' ? '● RUN' : status === 'thinking' ? '◎ THINK' : status === 'done' ? '✓ DONE' : status === 'error' ? '✗ ERR' : '○ IDLE')
    ),
    // Message
    React.createElement('div', {
      style: {
        fontSize: 10, color: isActive ? 'var(--text-secondary)' : 'var(--text-muted)',
        fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', lineHeight: 1.4
      }
    }, message || 'Waiting…'),
    phase && React.createElement('div', {
      style: { fontSize: 8, color: 'var(--text-muted)', marginTop: 2, fontFamily: 'var(--font-mono)', letterSpacing: 0.5 }
    }, phase.toUpperCase())
  );
}

function StatTile({ label, value, color, sub }) {
  const isNumeric = typeof value === 'number';
  const displayRef = useRef(null);
  const rafRef = useRef(null);
  const prevValueRef = useRef(0);

  useEffect(() => {
    if (!isNumeric) return;
    const target = value;
    const start = prevValueRef.current;
    prevValueRef.current = target;
    if (rafRef.current) window.cancelAnimationFrame(rafRef.current);
    const duration = 800;
    const startTime = performance.now();
    function animate(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(start + (target - start) * eased);
      if (displayRef.current) displayRef.current.textContent = current;
      if (progress < 1) rafRef.current = window.requestAnimationFrame(animate);
    }
    rafRef.current = window.requestAnimationFrame(animate);
    return () => { if (rafRef.current) window.cancelAnimationFrame(rafRef.current); };
  }, [value]);

  return React.createElement('div', {
    style: {
      padding: '12px 16px', borderRadius: 10,
      background: 'var(--bg-surface)',
      border: `1px solid ${color}30`,
      textAlign: 'center', minWidth: 80, flex: 1,
      position: 'relative', overflow: 'hidden',
      transition: 'transform 0.15s, box-shadow 0.15s',
    }
  },
    // Top accent bar
    React.createElement('div', {
      style: { position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${color}, transparent)`, borderRadius: '10px 10px 0 0' }
    }),
    // Corner glow
    React.createElement('div', {
      style: { position: 'absolute', top: -20, right: -20, width: 70, height: 70, borderRadius: '50%', background: color, opacity: 0.05, pointerEvents: 'none' }
    }),
    React.createElement('div', {
      ref: isNumeric ? displayRef : undefined,
      style: { fontSize: typeof value === 'string' ? 16 : 28, fontWeight: 800, color, fontFamily: 'var(--font-mono)', lineHeight: 1, letterSpacing: -1 }
    }, isNumeric ? value : value),
    React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1.2, marginTop: 5, fontWeight: 600 } }, label),
    sub && React.createElement('div', { style: { fontSize: 9, color, opacity: 0.7, marginTop: 2 } }, sub)
  );
}

// ── Phase Progress Arc ────────────────────────────────────────────────────────
function PhaseProgressArc({ currentPhase, phasesCompleted }) {
  const completed = phasesCompleted || [];
  const currentIdx = PHASES.findIndex(p => p.key === currentPhase);

  return React.createElement('div', {
    style: { marginBottom: 14 }
  },
    // Segmented bar
    React.createElement('div', {
      style: { display: 'flex', gap: 3, height: 12, borderRadius: 6, overflow: 'hidden', marginBottom: 4 }
    },
      PHASES.map((ph, i) => {
        const isDone   = completed.includes(ph.key) || (currentIdx > i);
        const isActive = currentPhase === ph.key;
        const bg = isDone
          ? 'linear-gradient(90deg, var(--accent), var(--cyan))'
          : isActive
            ? 'var(--cyan)'
            : 'var(--bg-panel)';
        const border = isDone ? 'none' : isActive ? '1px solid var(--cyan)' : '1px solid var(--border)';
        return React.createElement('div', {
          key: ph.key,
          style: {
            flex: 1,
            background: bg,
            border,
            borderRadius: i === 0 ? '6px 0 0 6px' : i === PHASES.length - 1 ? '0 6px 6px 0' : 0,
            opacity: isDone ? 1 : isActive ? 0.9 : 0.3,
            animation: isActive ? 'pulse 1.5s ease-in-out infinite' : 'none',
            transition: 'all 0.3s',
            boxSizing: 'border-box',
          }
        });
      })
    ),
    // Phase labels
    React.createElement('div', {
      style: { display: 'flex', gap: 3 }
    },
      PHASES.map((ph, i) => {
        const isDone   = completed.includes(ph.key) || (currentIdx > i);
        const isActive = currentPhase === ph.key;
        return React.createElement('div', {
          key: ph.key,
          style: {
            flex: 1, textAlign: 'center',
            fontSize: 8, fontFamily: 'var(--font-mono)',
            color: isDone ? 'var(--cyan)' : isActive ? 'var(--green)' : 'var(--text-muted)',
            fontWeight: isActive ? 700 : 400,
            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
          }
        }, ph.label);
      })
    )
  );
}

// ── Agent Activity Rings ──────────────────────────────────────────────────────
function AgentRings({ agents }) {
  const agentNames = ['master', 'recon', 'vuln', 'web', 'osint', 'exploit', 'privesc', 'iot', 'shell', 'payload'];
  const r = 16;
  const circumference = 2 * Math.PI * r; // ~100.53

  return React.createElement('div', {
    style: {
      padding: '10px 12px',
      borderTop: '1px solid var(--border)',
      display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'space-around',
    }
  },
    agentNames.map(name => {
      const ag = agents[name] || {};
      const meta = AGENT_META[name] || { icon: '◆', color: 'var(--text-muted)', label: name };
      const status = ag.status || 'idle';
      const isActive = status === 'running' || status === 'thinking';
      const isDone = status === 'done';
      const fillRatio = isDone ? 1 : isActive ? 0.6 : 0.15;
      const dashArray = circumference;
      const dashOffset = circumference * (1 - fillRatio);

      return React.createElement('div', {
        key: name,
        style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, minWidth: 44 }
      },
        React.createElement('svg', {
          width: 42, height: 42, viewBox: '0 0 42 42',
          style: { display: 'block' }
        },
          // Background ring
          React.createElement('circle', {
            cx: 21, cy: 21, r: r,
            fill: 'none',
            stroke: 'var(--border)',
            strokeWidth: 3,
          }),
          // Agent icon text
          React.createElement('text', {
            x: 21, y: 25,
            textAnchor: 'middle',
            fontSize: 13,
            style: { userSelect: 'none' }
          }, meta.icon),
          // Filled arc
          React.createElement('circle', {
            cx: 21, cy: 21, r: r,
            fill: 'none',
            stroke: meta.color,
            strokeWidth: 3,
            strokeDasharray: dashArray,
            strokeDashoffset: dashOffset,
            strokeLinecap: 'round',
            transform: 'rotate(-90 21 21)',
            style: {
              transition: 'stroke-dashoffset 0.6s ease',
              opacity: isActive || isDone ? 1 : 0.4,
              filter: isActive ? `drop-shadow(0 0 4px ${meta.color})` : 'none',
              animation: isActive ? 'pulse 1.5s ease-in-out infinite' : 'none',
            }
          })
        ),
        React.createElement('div', {
          style: {
            fontSize: 7, fontFamily: 'var(--font-mono)', fontWeight: 700,
            color: isActive ? meta.color : isDone ? 'var(--green)' : 'var(--text-muted)',
            textTransform: 'uppercase', letterSpacing: 0.3, textAlign: 'center',
          }
        }, meta.label)
      );
    })
  );
}

// Agent Comms moved to AI Observability page (Analysis → 🔬 AI Observability)

// Agent Communications moved to Analysis → 🔬 AI Observability (AIObservability.jsx)

// ── Pentest Progress Bar ──────────────────────────────────────────────────────
function PentestProgressBar({ planSteps, sessionId, activeSession }) {
  const [elapsed, setElapsed] = React.useState(0); // seconds
  const timerRef          = React.useRef(null);
  const mountTimeRef      = React.useRef(Date.now()); // fallback origin

  // ── Safe UTC start time ───────────────────────────────────────────────────
  // Python's datetime.utcnow().isoformat() produces strings without 'Z'.
  // parseUTC (defined at module level) appends 'Z' so JS treats it as UTC.
  const startTime = React.useMemo(() => {
    const t = parseUTC(activeSession?.started_at) || parseUTC(activeSession?.created_at);
    if (!t || isNaN(t)) return mountTimeRef.current;
    const now = Date.now();
    // Sanity: reject times in the future or more than 48 h ago
    if (t > now + 10_000 || t < now - 48 * 3600 * 1000) return mountTimeRef.current;
    return t;
  }, [activeSession]);

  React.useEffect(() => {
    if (!sessionId || !startTime) { setElapsed(0); return; }
    const tick = () => setElapsed(Math.floor((Date.now() - startTime) / 1000));
    tick();
    timerRef.current = setInterval(tick, 1000);
    return () => clearInterval(timerRef.current);
  }, [sessionId, startTime]);

  // ── Per-step timing tracking ──────────────────────────────────────────────
  // Records wall-clock start/end for each step as status changes arrive.
  const stepTimingsRef    = React.useRef({});
  const prevStepStatusRef = React.useRef({});

  React.useEffect(() => {
    const now = Date.now();
    (planSteps || []).forEach(step => {
      const prev = prevStepStatusRef.current[step.id];
      if (prev === step.status) return;
      prevStepStatusRef.current[step.id] = step.status;
      const t = stepTimingsRef.current[step.id] || {};
      if (step.status === 'active' && !t.startedAt)    t.startedAt   = now;
      if ((step.status === 'done' || step.status === 'failed') && !t.completedAt) {
        t.completedAt = now;
        if (!t.startedAt) t.startedAt = now;
      }
      stepTimingsRef.current[step.id] = t;
    });
  }, [planSteps]);

  if (!sessionId || !activeSession) return null;

  // Show loading placeholder while plan is being generated
  if (!planSteps || planSteps.length === 0) {
    return React.createElement('div', {
      style: {
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        borderRadius: 10, padding: '14px 18px', marginBottom: 14,
        display: 'flex', alignItems: 'center', gap: 12, position: 'relative', overflow: 'hidden'
      }
    },
      React.createElement('div', { style: { position: 'absolute', left: 0, top: 0, bottom: 0, width: 3, background: 'var(--violet)', borderRadius: '10px 0 0 10px' } }),
      React.createElement('span', { style: { fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' } }, 'PENTEST PROGRESS'),
      React.createElement('span', { style: { fontSize: 11, color: 'var(--violet)', fontFamily: 'var(--font-mono)', animation: 'pulse 1.5s infinite' } }, '⟳ Generating attack plan...'),
      sessionId && elapsed > 0 && React.createElement('span', { style: { marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, `⏱ ${fmtDuration(elapsed)}`)
    );
  }

  const mainSteps = planSteps.filter(s => !s.is_substep);
  const total   = mainSteps.length;
  const done    = mainSteps.filter(s => s.status === 'done').length;
  const failed  = mainSteps.filter(s => s.status === 'failed').length;
  const active  = mainSteps.filter(s => s.status === 'active').length;
  const pending = total - done - failed - active;

  const pct = total > 0 ? Math.round(((done + failed) / total) * 100) : 0;
  const progressColor = failed > 0 && done === 0 ? 'var(--critical)'
    : pct >= 80 ? 'var(--accent)'
    : pct >= 40 ? 'var(--cyan)'
    : 'var(--violet)';

  // ── Smart ETA via rolling average of actual step durations ─────────────
  // Only kicks in once ≥2 steps have completed; uses the last 3 durations
  // so the estimate tracks recent pace rather than overall session time.
  const estRemaining = React.useMemo(() => {
    if (done + failed < 2 || pending === 0) return null;

    // Collect measured durations for finished main steps
    const durations = [];
    mainSteps.forEach(step => {
      const t = stepTimingsRef.current[step.id];
      if (t?.startedAt && t?.completedAt && t.completedAt > t.startedAt) {
        durations.push(t.completedAt - t.startedAt);
      }
    });

    let avgMs;
    if (durations.length >= 1) {
      // Rolling average of last 3 completed steps
      const recent = durations.slice(-3);
      avgMs = recent.reduce((a, b) => a + b, 0) / recent.length;
    } else {
      // No timing data yet — fall back to session-elapsed / done
      if (!done) return null;
      avgMs = (elapsed * 1000) / done;
    }

    // Subtract time already spent on currently active steps
    const activeSpent = mainSteps
      .filter(s => s.status === 'active')
      .reduce((sum, s) => {
        const t = stepTimingsRef.current[s.id];
        return sum + (t?.startedAt ? Date.now() - t.startedAt : 0);
      }, 0);

    const remainingMs = Math.max(0, pending * avgMs - activeSpent);
    return Math.round(remainingMs / 1000);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [planSteps, done, failed, pending, elapsed]);

  return React.createElement('div', {
    style: {
      background: 'var(--bg-surface)', border: '1px solid var(--border)',
      borderRadius: 10, padding: '14px 18px', marginBottom: 14, position: 'relative',
      overflow: 'hidden'
    }
  },
    // Subtle left accent bar
    React.createElement('div', {
      style: {
        position: 'absolute', left: 0, top: 0, bottom: 0, width: 3,
        background: progressColor, borderRadius: '10px 0 0 10px'
      }
    }),

    // Top row: label + % + time stats
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }
    },
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 10 } },
        React.createElement('span', { style: { fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' } }, 'PENTEST PROGRESS'),
        React.createElement('span', { style: {
          fontSize: 14, fontWeight: 800, color: progressColor, fontFamily: 'var(--font-mono)',
          background: `${progressColor}15`, padding: '2px 10px', borderRadius: 20,
          border: `1px solid ${progressColor}40`
        }}, `${pct}%`)
      ),
      React.createElement('div', { style: { display: 'flex', gap: 16, fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } },
        sessionId && elapsed > 0 && React.createElement('span', null, `⏱ ${fmtDuration(elapsed)}`),
        estRemaining != null && active > 0 && React.createElement('span', { style: { color: 'var(--cyan)' } }, `~ ${fmtDuration(estRemaining)} left`),
        React.createElement('span', { style: { color: 'var(--low)' } }, `✓ ${done}`),
        active > 0 && React.createElement('span', { style: { color: 'var(--cyan)', animation: 'pulse 1.5s infinite' } }, `⟳ ${active}`),
        failed > 0 && React.createElement('span', { style: { color: 'var(--critical)' } }, `✗ ${failed}`),
        pending > 0 && React.createElement('span', null, `○ ${pending}`)
      )
    ),

    // Progress track
    React.createElement('div', {
      style: {
        height: 8, background: 'var(--bg-elevated)', borderRadius: 4,
        border: '1px solid var(--border)', overflow: 'hidden', position: 'relative'
      }
    },
      // Done segment
      done > 0 && React.createElement('div', {
        style: {
          position: 'absolute', left: 0, top: 0, bottom: 0,
          width: `${(done / total) * 100}%`,
          background: `linear-gradient(90deg, ${progressColor}, ${progressColor}cc)`,
          borderRadius: 4, transition: 'width 0.5s ease',
          boxShadow: `0 0 8px ${progressColor}60`
        }
      }),
      // Active segment (animated)
      active > 0 && React.createElement('div', {
        style: {
          position: 'absolute', left: `${(done / total) * 100}%`, top: 0, bottom: 0,
          width: `${(active / total) * 100}%`,
          background: 'var(--cyan)', opacity: 0.6,
          animation: 'pulse 1.5s ease-in-out infinite',
          borderRadius: 4
        }
      }),
      // Failed segment
      failed > 0 && React.createElement('div', {
        style: {
          position: 'absolute', left: `${((done + active) / total) * 100}%`, top: 0, bottom: 0,
          width: `${(failed / total) * 100}%`,
          background: 'var(--critical)', opacity: 0.5, borderRadius: 4
        }
      })
    ),

    // Step labels below bar
    React.createElement('div', {
      style: { display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }
    },
      mainSteps.slice(0, 12).map((step, idx) => {
        const stColor = step.status === 'done' ? 'var(--low)'
          : step.status === 'active' ? 'var(--cyan)'
          : step.status === 'failed' ? 'var(--critical)'
          : 'var(--border-bright)';
        const stBg = step.status === 'done' ? 'rgba(74,222,128,0.08)'
          : step.status === 'active' ? 'rgba(56,189,248,0.1)'
          : step.status === 'failed' ? 'rgba(255,69,96,0.08)'
          : 'transparent';
        return React.createElement('div', {
          key: idx,
          style: {
            display: 'flex', alignItems: 'center', gap: 4, padding: '2px 7px',
            borderRadius: 10, border: `1px solid ${stColor}50`,
            background: stBg, fontSize: 9, color: stColor,
            fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
            animation: step.status === 'active' ? 'pulse 1.5s infinite' : 'none'
          }
        },
          React.createElement('span', null,
            step.status === 'done' ? '✓' : step.status === 'active' ? '⟳' : step.status === 'failed' ? '✗' : '○'),
          React.createElement('span', null, (step.label || step.id || '').slice(0, 14))
        );
      })
    )
  );
}

// ── HostSelector — shown only in CIDR/multi mode ─────────────────────────────
function HostSelector({ hosts, hostFilter, dispatch }) {
  if (!hosts || hosts.length <= 1) return null;

  const SEV_DOT = { critical: 'var(--critical)', high: '#ff6400', medium: 'var(--medium)', low: 'var(--low)' };

  function pill(ip, label, active, extra) {
    return React.createElement('button', {
      key: ip || 'all',
      onClick: () => dispatch({ type: 'SET_HOST_FILTER', payload: ip }),
      style: {
        padding: '4px 12px', borderRadius: 20, cursor: 'pointer',
        fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 600,
        border: active ? '1px solid var(--cyan)' : '1px solid var(--border-light)',
        background: active ? 'rgba(0,212,255,0.10)' : 'rgba(255,255,255,0.03)',
        color: active ? 'var(--cyan)' : 'var(--text-secondary)',
        display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0,
        transition: 'all 0.15s',
      }
    },
      label,
      extra
    );
  }

  return React.createElement('div', {
    style: {
      display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center',
      padding: '8px 12px', marginBottom: 12, borderRadius: 8,
      background: 'var(--bg-surface)', border: '1px solid var(--border)',
    }
  },
    React.createElement('span', { style: { fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8, flexShrink: 0, marginRight: 4 } }, '🌐 Hosts'),
    pill(null, 'ALL', hostFilter === null,
      React.createElement('span', { style: { fontSize: 9, padding: '0 5px', borderRadius: 8, background: 'rgba(0,212,255,0.15)', color: 'var(--cyan)' } }, hosts.length)
    ),
    ...hosts.map(h => {
      const active = hostFilter === h.ip;
      const statusDot = h.status === 'complete' ? '✓' : h.status === 'scanning' ? '●' : '○';
      const dotColor  = h.status === 'complete' ? 'var(--low)' : h.status === 'scanning' ? 'var(--amber)' : 'var(--text-muted)';
      const topSev = ['critical','high','medium','low'].find(s => (h.severity_counts||{})[s] > 0);
      return pill(h.ip, h.ip, active,
        React.createElement('span', { style: { display: 'flex', alignItems: 'center', gap: 3 } },
          React.createElement('span', { style: { color: dotColor, fontSize: 8 } }, statusDot),
          h.findings_count > 0 && React.createElement('span', { style: { fontSize: 9, padding: '0 4px', borderRadius: 6, background: `${SEV_DOT[topSev] || 'var(--border)'}20`, color: SEV_DOT[topSev] || 'var(--text-muted)' } }, h.findings_count),
        )
      );
    })
  );
}

// ── Operator Q&A Banner ──────────────────────────────────────────────────────
// Shown when the engagement context parser raised clarifying questions.
// Operator fills in answers and submits — scan proceeds with full context.
function OperatorQABanner({ questions, sessionId, dispatch }) {
  const [answers,    setAnswers]    = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [dismissed,  setDismissed]  = useState(false);

  if (dismissed) return null;

  const handleSubmit = async () => {
    if (!sessionId) return;
    setSubmitting(true);
    try {
      await fetch(`/sessions/${sessionId}/operator-response`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ answers }),
      });
      dispatch({ type: 'OPERATOR_QUESTIONS_SET', payload: [] });
    } catch (e) {
      console.error('operator-response error:', e);
    }
    setSubmitting(false);
  };

  return React.createElement('div', {
    style: {
      background: 'rgba(255,204,0,0.06)', border: '1px solid rgba(255,204,0,0.35)',
      borderRadius: 8, padding: '12px 16px', marginBottom: 12, flexShrink: 0,
    }
  },
    // Header
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }
    },
      React.createElement('span', { style: { fontSize: 14 } }, '❓'),
      React.createElement('span', {
        style: { fontSize: 12, fontWeight: 700, color: 'var(--amber)', flex: 1 }
      }, 'Clarification Needed'),
      React.createElement('span', {
        style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
      }, 'Scan is running with best-guess assumptions — answer to improve accuracy'),
      React.createElement('button', {
        onClick: () => setDismissed(true),
        style: { background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 14, lineHeight: 1, marginLeft: 8 }
      }, '✕')
    ),
    // Questions
    React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
      questions.map((q, i) =>
        React.createElement('div', { key: i, style: { display: 'flex', flexDirection: 'column', gap: 4 } },
          React.createElement('label', {
            style: { fontSize: 11, color: 'var(--text-secondary)', fontWeight: 500 }
          },
            React.createElement('span', {
              style: { fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginRight: 6 }
            }, `[${i + 1}]`),
            q
          ),
          React.createElement('input', {
            type: 'text',
            placeholder: 'Your answer…',
            value: answers[q] || '',
            onChange: e => setAnswers(prev => ({ ...prev, [q]: e.target.value })),
            style: {
              background: 'var(--bg-panel)', border: '1px solid var(--border)',
              borderRadius: 5, color: 'var(--text-primary)', fontSize: 11,
              padding: '5px 10px', outline: 'none', fontFamily: 'var(--font-mono)',
              width: '100%',
            }
          })
        )
      )
    ),
    // Submit row
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'flex-end', marginTop: 10 }
    },
      React.createElement('button', {
        onClick: handleSubmit,
        disabled: submitting,
        style: {
          padding: '6px 18px', borderRadius: 5, cursor: 'pointer', fontWeight: 700,
          border: '1px solid rgba(255,204,0,0.45)', background: 'rgba(255,204,0,0.12)',
          color: 'var(--amber)', fontSize: 11, fontFamily: 'var(--font-mono)',
          opacity: submitting ? 0.6 : 1,
        }
      }, submitting ? 'Sending…' : 'Submit Answers')
    )
  );
}

// ── Main MissionControl ──────────────────────────────────────────────────────
function MissionControl() {
  const { state, dispatch } = window.useStore();
  const {
    activeSession, agents, currentPhase, phasesCompleted,
    feedEntries, findingsSummary, flags, wsConnected,
    toolOutputs, smState, attackTree, mitreMap, llmThinking,
    planSteps, planHypothesis, planAssessment,
    credentials, sessionMode, discoveredHosts, hostFilter,
    webConfirmPending, phaseTimeExtension,
    reasoningEngineActive, reasoningIteration, hypotheses, actionScore,
    operatorQuestions, engagementContext,
  } = state;

  const [confirmVisible, setConfirmVisible] = useState(false);
  const [focusedAgent,   setFocusedAgent]   = useState('master');
  const [showGuidance,   setShowGuidance]   = useState(false);
  const feedRef = useRef(null);

  const needsConfirm  = feedEntries.some(e => e.eventType === 'awaiting_confirmation');
  const activeAgents  = Object.entries(agents).filter(([, a]) => a.status === 'running' || a.status === 'thinking');

  // Show a transient "Resuming…" banner for ~8 s after a checkpoint_restored event
  const [showResumeBanner, setShowResumeBanner] = useState(false);
  const resumeAfterRef = useRef(null);
  useEffect(() => {
    const latest = [...feedEntries].reverse().find(e => e.eventType === 'plan_skeleton_restore' || e.eventType === 'checkpoint_restored');
    if (!latest) return;
    setShowResumeBanner(true);
    clearTimeout(resumeAfterRef.current);
    resumeAfterRef.current = setTimeout(() => setShowResumeBanner(false), 8000);
  }, [feedEntries.filter(e => e.eventType === 'plan_skeleton_restore' || e.eventType === 'checkpoint_restored').length]);

  // Auto-focus running agent
  useEffect(() => {
    const running = Object.entries(agents).find(([, a]) => a.status === 'running');
    if (running) setFocusedAgent(running[0]);
  }, [agents]);

  // Auto-scroll feed
  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [feedEntries.length]);

  async function handleConfirm() {
    if (!activeSession) return;
    await window.API.sessions.confirm(activeSession.id, 'exploit');
    setConfirmVisible(false);
  }

  async function handleWebConfirm() {
    if (!activeSession) return;
    await window.API.sessions.confirm(activeSession.id, 'web_testing');
    dispatch({ type: 'WEB_CONFIRM_PENDING', payload: false });
  }

  async function handleWebSkip() {
    if (!activeSession) return;
    // Not confirming = skipping — backend will time out the wait eventually,
    // but we can also just dismiss the modal on the frontend
    dispatch({ type: 'WEB_CONFIRM_PENDING', payload: false });
  }

  async function handleExtendPhase() {
    if (!activeSession || !phaseTimeExtension) return;
    await window.API.sessions.extend(activeSession.id, phaseTimeExtension.phase);
    dispatch({ type: 'CLEAR_PHASE_TIME_EXTENSION' });
  }

  async function handleStopPhase() {
    if (!activeSession) return;
    dispatch({ type: 'CLEAR_PHASE_TIME_EXTENSION' });
    // Stopping the entire session is safest; backend will stop web agent on timeout anyway
    await window.API.sessions.stop(activeSession.id);
  }

  async function handleStop() {
    if (!activeSession) return;
    await window.API.sessions.stop(activeSession.id);
  }

  async function handlePause() {
    if (!activeSession) return;
    // Optimistically flip to paused immediately — don't wait for the WS event
    dispatch({ type: 'UPDATE_SESSION_STATUS', payload: 'paused' });
    try {
      await window.API.sessions.pause(activeSession.id);
    } catch (e) {
      // Roll back on failure
      dispatch({ type: 'UPDATE_SESSION_STATUS', payload: 'active' });
    }
  }

  async function handleResume() {
    if (!activeSession) return;
    // Optimistically flip to active immediately
    dispatch({ type: 'UPDATE_SESSION_STATUS', payload: 'active' });
    try {
      await window.API.sessions.resume(activeSession.id);
    } catch (e) {
      // Roll back on failure
      dispatch({ type: 'UPDATE_SESSION_STATUS', payload: 'paused' });
    }
  }

  const isPaused = activeSession?.status === 'paused' || activeSession?.status === 'stopped';

  const focusedLines = toolOutputs[focusedAgent] || [];
  const s = (v, d = 0) => v || d;
  const agentColor = (name) => (AGENT_META[name] || {}).color || 'var(--text-muted)';

  return React.createElement('div', {
    style: { padding: 16, height: '100%', overflowY: 'auto', background: 'var(--bg-base,#0a0a0a)' }
  },

    // ── Header ────────────────────────────────────────────────────────────
    React.createElement('div', { className: 'page-header', style: { marginBottom: 14 } },
      React.createElement('div', null,
        React.createElement('div', { className: 'page-title', style: { display: 'flex', alignItems: 'center', gap: 10 } },
          '⚔ Mission Control',
          wsConnected && React.createElement('span', {
            style: { fontSize: 9, padding: '2px 7px', borderRadius: 10,
                     background: 'rgba(0,255,136,0.08)', border: '1px solid var(--green)', color: 'var(--green)' }
          }, '● LIVE')
        ),
        activeSession && React.createElement('div', { className: 'page-subtitle', style: { display: 'flex', alignItems: 'center', gap: 8 } },
          `${activeSession.target_ip}  ·  ${(currentPhase||'idle').toUpperCase()}`,
          smState && smState !== 'INIT' && `  ·  ${smState}`,
          isPaused && React.createElement('span', {
            style: {
              fontSize: 9, padding: '1px 6px', borderRadius: 8,
              background: 'rgba(250,173,20,0.12)', border: '1px solid var(--medium-bd)',
              color: 'var(--medium)', marginLeft: 4
            }
          }, '⏸ PAUSED')
        )
      ),
      React.createElement('div', { style: { display: 'flex', gap: 8, alignItems: 'center' } },
        llmThinking && React.createElement('span', { style: { fontSize: 10, color: 'var(--cyan)', animation: 'pulse 1s infinite' } }, '🧠 Thinking...'),

        // ── Pause / Resume button — mutually exclusive with Stop ───────────
        activeSession && !isPaused && React.createElement('button', {
          onClick: handlePause,
          title: 'Pause scan at the next phase boundary — saves a checkpoint',
          style: {
            padding: '5px 14px', borderRadius: 6, cursor: 'pointer', fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-ui)',
            border: '1px solid var(--medium-bd)',
            background: 'var(--medium-bg)', color: 'var(--medium)',
          }
        }, '⏸ Pause'),

        activeSession && isPaused && React.createElement('button', {
          onClick: handleResume,
          title: 'Resume scan from last checkpoint',
          style: {
            padding: '5px 14px', borderRadius: 6, cursor: 'pointer', fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-ui)',
            border: '1px solid var(--green)',
            background: 'rgba(0,255,136,0.08)', color: 'var(--green)',
            animation: 'pulse 1.5s infinite',
          }
        }, '▶ Resume'),

        // ── Stop (hard-stop, checkpoint saved before kill) ─────────────────
        activeSession && React.createElement('button', {
          onClick: handleStop,
          title: 'Hard-stop scan (saves checkpoint for resume)',
          style: {
            padding: '5px 14px', borderRadius: 6, border: '1px solid var(--critical-bd)',
            background: 'var(--critical-bg)', color: 'var(--critical)',
            cursor: 'pointer', fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-ui)',
          }
        }, '■ Stop'),

        activeSession && React.createElement('button', {
          onClick: () => setShowGuidance(g => !g),
          style: {
            padding: '5px 14px', borderRadius: 6, cursor: 'pointer', fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-ui)',
            border: showGuidance ? '1px solid var(--accent)' : '1px solid var(--border-light)',
            background: showGuidance ? 'rgba(0,229,160,0.10)' : 'rgba(255,255,255,0.04)',
            color: showGuidance ? 'var(--accent)' : 'var(--text-secondary)',
          }
        }, showGuidance ? '✕ Console' : '◎ Operator Console'),
        needsConfirm && React.createElement('button', {
          onClick: () => setConfirmVisible(true),
          style: {
            padding: '5px 14px', borderRadius: 6, border: '1px solid var(--medium-bd)',
            background: 'var(--medium-bg)', color: 'var(--medium)',
            cursor: 'pointer', fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-ui)',
            animation: 'pulse 1.5s infinite',
          }
        }, '⚠ Confirm Exploit'),
        webConfirmPending && React.createElement('button', {
          onClick: handleWebConfirm,
          style: {
            padding: '5px 14px', borderRadius: 6, border: '1px solid rgba(0,212,255,0.5)',
            background: 'rgba(0,212,255,0.12)', color: 'var(--cyan)',
            cursor: 'pointer', fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-ui)',
            animation: 'pulse 1.5s infinite',
          }
        }, '⚠ Confirm Web Test'),
        phaseTimeExtension && React.createElement('button', {
          onClick: handleExtendPhase,
          style: {
            padding: '5px 14px', borderRadius: 6, border: '1px solid rgba(255,170,0,0.5)',
            background: 'rgba(255,170,0,0.12)', color: 'var(--amber)',
            cursor: 'pointer', fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-ui)',
            animation: 'pulse 1.5s infinite',
          }
        }, '⏱ Extend Phase')
      )
    ),

    // ── Resume banner (auto-dismisses after 8 s) ─────────────────────────
    showResumeBanner && React.createElement('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '8px 14px', borderRadius: 8, marginBottom: 12,
        background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.25)',
        color: 'var(--cyan)', fontSize: 12, fontFamily: 'var(--font-mono)',
      }
    },
      React.createElement('span', { style: { fontSize: 16 } }, '♻'),
      React.createElement('span', null,
        'Scan resumed from checkpoint — completed phases restored, continuing from next phase'
      ),
      React.createElement('button', {
        onClick: () => setShowResumeBanner(false),
        style: {
          marginLeft: 'auto', background: 'none', border: 'none',
          color: 'var(--text-muted)', cursor: 'pointer', fontSize: 14, lineHeight: 1,
        }
      }, '✕')
    ),

    // ── Reasoning Engine status banner (always shown during active sessions) ─
    activeSession && React.createElement('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '10px 16px', borderRadius: 8, marginBottom: 12,
        background: 'rgba(0,229,160,0.05)', border: '1px solid rgba(0,229,160,0.25)',
        fontSize: 12, fontFamily: 'var(--font-mono)',
      }
    },
      React.createElement('span', {
        style: {
          width: 8, height: 8, borderRadius: '50%',
          background: 'var(--accent)', boxShadow: '0 0 8px var(--accent)',
          animation: 'pulse 1.5s infinite', display: 'inline-block', flexShrink: 0,
        }
      }),
      React.createElement('span', { style: { color: 'var(--accent)', fontWeight: 700 } }, '🧠 Reasoning Engine'),
      React.createElement('span', { style: { color: 'var(--text-muted)' } }, '—'),
      React.createElement('span', { style: { color: 'var(--text-secondary)' } },
        `Iteration ${reasoningIteration || 0} / 50`),
      React.createElement('span', { style: { color: 'var(--text-muted)' } }, '·'),
      // Hypothesis count
      (hypotheses || []).length > 0 && React.createElement('span', { style: { color: 'var(--cyan)' } },
        `${(hypotheses || []).filter(h => !h.invalidated).length} active hypotheses`),
      (hypotheses || []).length > 0 && React.createElement('span', { style: { color: 'var(--text-muted)' } }, '·'),
      // Action score
      React.createElement('span', {
        style: {
          color: (actionScore || 0) >= 0 ? '#4ADE80' : '#FF4560',
          fontWeight: 700,
        }
      }, `Score: ${(actionScore || 0) >= 0 ? '+' : ''}${actionScore || 0}`),
      // Top hypothesis preview
      (hypotheses || []).length > 0 && (() => {
        const top = (hypotheses || []).filter(h => !h.invalidated).sort((a, b) => b.confidence - a.confidence)[0];
        return top ? React.createElement('span', {
          style: {
            marginLeft: 4, color: 'var(--text-muted)', overflow: 'hidden',
            textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 300,
          }
        }, `· ${(top.statement || '').slice(0, 80)}`) : null;
      })(),
      React.createElement('button', {
        onClick: () => window.dispatchEvent(new CustomEvent('navigate', { detail: 'reasoning' })),
        style: {
          marginLeft: 'auto', padding: '4px 10px', borderRadius: 5, cursor: 'pointer',
          border: '1px solid rgba(0,229,160,0.35)', background: 'rgba(0,229,160,0.08)',
          color: 'var(--accent)', fontSize: 10, fontFamily: 'var(--font-mono)',
        }
      }, '→ View Engine')
    ),

    // ── Operator Q&A banner (shown when system needs clarification) ────────
    activeSession && operatorQuestions && operatorQuestions.length > 0 &&
      React.createElement(OperatorQABanner, {
        questions: operatorQuestions,
        sessionId: state.sessionId,
        dispatch,
      }),

    // ── No session ────────────────────────────────────────────────────────
    !activeSession && React.createElement('div', {
      style: {
        padding: '40px 24px', borderRadius: 12,
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        textAlign: 'center', marginBottom: 16,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12,
      }
    },
      React.createElement('div', { style: { fontSize: 40, opacity: 0.2, lineHeight: 1 } }, '⊕'),
      React.createElement('div', { style: { fontSize: 15, fontWeight: 700, color: 'var(--text-secondary)' } }, 'No Active Session'),
      React.createElement('div', { style: { fontSize: 12, color: 'var(--text-muted)', maxWidth: 360, lineHeight: 1.7 } },
        'Configure a target and launch a pentest to begin. The attack plan, agent activity, and live findings will appear here.'
      ),
      React.createElement('div', {
        onClick: () => window.dispatchEvent(new CustomEvent('navigate', { detail: 'target' })),
        style: {
          marginTop: 4, padding: '8px 20px', borderRadius: 7, cursor: 'pointer',
          background: 'var(--accent)', color: '#0D0E14', fontSize: 12, fontWeight: 700,
          boxShadow: '0 0 16px var(--accent-glow)', letterSpacing: 0.3,
        }
      }, '⊕ Configure Target')
    ),

    // ── Reasoning Engine live panel (3-col) ──────────────────────────────
    (hypotheses || []).length > 0 && React.createElement('div', {
      style: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginBottom: 12 }
    },
      // Col 1 — Top hypothesis
      React.createElement('div', {
        style: {
          background: 'var(--bg-surface)', border: '1px solid var(--border)',
          borderRadius: 10, padding: '12px 14px',
        }
      },
        React.createElement('div', { style: { fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 } }, 'Top Hypothesis'),
        (() => {
          const topH = (hypotheses || [])
            .filter(h => h.status !== 'invalidated')
            .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))[0];
          if (!topH) return React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)' } }, 'Awaiting hypotheses…');
          const conf = Math.round((topH.confidence || 0) * 100);
          const barColor = conf >= 70 ? 'var(--green)' : conf >= 40 ? 'var(--amber)' : 'var(--red)';
          return React.createElement(React.Fragment, null,
            React.createElement('div', { style: { fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 6, lineHeight: 1.4 } },
              topH.description || topH.title || 'Unnamed hypothesis'
            ),
            topH.mitre_technique && React.createElement('div', {
              style: { display: 'inline-block', padding: '2px 6px', borderRadius: 4, background: 'rgba(0,229,160,0.1)', color: 'var(--accent)', fontSize: 9, fontWeight: 700, letterSpacing: 0.5, marginBottom: 8 }
            }, topH.mitre_technique),
            React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6 } },
              React.createElement('div', { style: { flex: 1, height: 5, background: 'var(--bg-card)', borderRadius: 3, overflow: 'hidden' } },
                React.createElement('div', { style: { width: `${conf}%`, height: '100%', background: barColor, borderRadius: 3, transition: 'width 0.4s ease' } })
              ),
              React.createElement('div', { style: { fontSize: 10, fontWeight: 700, color: barColor, minWidth: 28, textAlign: 'right' } }, `${conf}%`)
            )
          );
        })()
      ),
      // Col 2 — Engagement score + iteration
      React.createElement('div', {
        style: {
          background: 'var(--bg-surface)', border: '1px solid var(--border)',
          borderRadius: 10, padding: '12px 14px', textAlign: 'center',
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4
        }
      },
        React.createElement('div', { style: { fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8 } }, 'Engagement Score'),
        React.createElement('div', {
          style: {
            fontSize: 36, fontWeight: 900, lineHeight: 1.1,
            color: actionScore >= 0 ? 'var(--green)' : 'var(--red)',
            fontFamily: 'var(--font-mono)'
          }
        }, `${actionScore >= 0 ? '+' : ''}${actionScore}`),
        React.createElement('div', { style: { fontSize: 10, color: 'var(--text-muted)' } }, `Iteration ${reasoningIteration}`),
        React.createElement('div', { style: { display: 'flex', gap: 12, marginTop: 6 } },
          React.createElement('div', { style: { textAlign: 'center' } },
            React.createElement('div', { style: { fontSize: 14, fontWeight: 700, color: 'var(--green)' } },
              (hypotheses || []).filter(h => h.status === 'confirmed').length
            ),
            React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)' } }, 'Confirmed')
          ),
          React.createElement('div', { style: { textAlign: 'center' } },
            React.createElement('div', { style: { fontSize: 14, fontWeight: 700, color: 'var(--red)' } },
              (hypotheses || []).filter(h => h.status === 'invalidated').length
            ),
            React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)' } }, 'Ruled Out')
          )
        )
      ),
      // Col 3 — Hypothesis breakdown
      React.createElement('div', {
        style: {
          background: 'var(--bg-surface)', border: '1px solid var(--border)',
          borderRadius: 10, padding: '12px 14px',
        }
      },
        React.createElement('div', { style: { fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 } }, 'Hypothesis Status'),
        (() => {
          const hyps = hypotheses || [];
          const active    = hyps.filter(h => h.status === 'active' || !h.status).length;
          const confirmed = hyps.filter(h => h.status === 'confirmed').length;
          const ruledOut  = hyps.filter(h => h.status === 'invalidated').length;
          const total     = hyps.length || 1;
          return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 6 } },
            [
              { label: 'Active',     count: active,    color: 'var(--cyan)' },
              { label: 'Confirmed',  count: confirmed, color: 'var(--green)' },
              { label: 'Ruled Out',  count: ruledOut,  color: 'var(--red)' },
            ].map(({ label, count, color }) =>
              React.createElement('div', { key: label, style: { display: 'flex', alignItems: 'center', gap: 6 } },
                React.createElement('div', { style: { width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0 } }),
                React.createElement('div', { style: { flex: 1, fontSize: 11, color: 'var(--text-secondary)' } }, label),
                React.createElement('div', { style: { fontSize: 11, fontWeight: 700, color, fontFamily: 'var(--font-mono)' } }, count),
                React.createElement('div', { style: { flex: 1, height: 3, background: 'var(--bg-card)', borderRadius: 2, overflow: 'hidden', marginLeft: 4 } },
                  React.createElement('div', { style: { width: `${Math.round(count / total * 100)}%`, height: '100%', background: color, borderRadius: 2 } })
                )
              )
            )
          );
        })()
      )
    ),

    // ── Stats row ─────────────────────────────────────────────────────────
    React.createElement('div', { style: { display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' } },
      React.createElement(StatTile, { label: 'Critical', value: s(findingsSummary.critical), color: 'var(--red)'    }),
      React.createElement(StatTile, { label: 'High',     value: s(findingsSummary.high),     color: 'var(--high)'   }),
      React.createElement(StatTile, { label: 'Medium',   value: s(findingsSummary.medium),   color: 'var(--amber)'  }),
      React.createElement(StatTile, { label: 'Findings', value: s(findingsSummary.total),    color: 'var(--cyan)'   }),
      React.createElement(StatTile, { label: 'Flags',    value: flags.length,                color: 'var(--green)'  }),
      React.createElement(StatTile, { label: 'Agents',   value: activeAgents.length,         color: 'var(--violet)', sub: 'active' }),
      mitreMap.length > 0 && React.createElement(StatTile, { label: 'MITRE', value: mitreMap.length, color: 'var(--cyan)', sub: 'techniques' }),
      discoveredHosts.length > 1 && React.createElement(StatTile, { label: 'Hosts', value: discoveredHosts.length, color: 'var(--cyan)', sub: `${discoveredHosts.filter(h=>h.status==='complete').length} done` }),
    ),

    // ── Host selector (CIDR/multi mode only) ──────────────────────────────
    React.createElement(HostSelector, { hosts: discoveredHosts, hostFilter, dispatch }),

    // ── Pentest Progress Bar ──────────────────────────────────────────────
    React.createElement(PentestProgressBar, {
      planSteps: state.planSteps || [],
      sessionId: state.sessionId,
      activeSession: state.activeSession
    }),

    // ── Attack Phase panel (the big new component) ────────────────────────
    activeSession && React.createElement(AttackPhasePanel, {
      planSteps:       planSteps || [],
      currentPhase,
      attackTree,
      phasesCompleted,
      hypothesis:      planHypothesis,
      assessmentType:  planAssessment,
    }),

    // Agent Communications → see Analysis › 🔬 AI Observability

    // ── Agent grid + terminal ─────────────────────────────────────────────
    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 } },

      // Agents
      React.createElement('div', {
        style: { borderRadius: 10, background: 'var(--bg-surface)', border: '1px solid var(--border)', overflow: 'hidden' }
      },
        // Panel header
        React.createElement('div', {
          style: {
            padding: '10px 14px', background: 'var(--bg-panel)',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }
        },
          React.createElement('span', { style: { fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.8 } }, '◉ Agents'),
          activeAgents.length > 0
            ? React.createElement('span', {
                style: { fontSize: 9, padding: '2px 8px', borderRadius: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
                         background: 'rgba(0,229,160,0.12)', color: 'var(--accent)', border: '1px solid rgba(0,229,160,0.3)' }
              }, `${activeAgents.length} ACTIVE`)
            : React.createElement('span', { style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, 'all idle')
        ),
        React.createElement('div', { style: { padding: '10px 12px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 7 } },
          ...Object.entries(agents).map(([name, ag]) =>
            React.createElement(AgentCard, { key: name, name, ...ag, onClick: () => setFocusedAgent(name) })
          )
        ),
        React.createElement(AgentRings, { agents })
      ),

      // Terminal
      React.createElement('div', {
        style: { borderRadius: 10, background: '#08090F', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }
      },
        // Terminal bar
        React.createElement('div', {
          style: {
            padding: '8px 14px', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 10,
          }
        },
          // Traffic lights
          React.createElement('div', { style: { display: 'flex', gap: 5 } },
            React.createElement('span', { style: { width: 9, height: 9, borderRadius: '50%', background: '#FF5F57', display: 'block' } }),
            React.createElement('span', { style: { width: 9, height: 9, borderRadius: '50%', background: '#FFBD2E', display: 'block' } }),
            React.createElement('span', { style: { width: 9, height: 9, borderRadius: '50%', background: '#28CA41', display: 'block' } }),
          ),
          React.createElement('span', { style: { fontSize: 10, fontWeight: 700, color: agentColor(focusedAgent), fontFamily: 'var(--font-mono)', letterSpacing: 0.5 } },
            focusedAgent?.toUpperCase()
          ),
          React.createElement('span', { style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, '— click agent to focus')
        ),
        React.createElement('div', {
          style: { flex: 1, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10.5, lineHeight: 1.65, maxHeight: 280, padding: '10px 14px' }
        },
          focusedLines.length === 0
            ? React.createElement('span', { style: { color: 'var(--text-muted)', opacity: 0.4 } }, '— no output —')
            : focusedLines.slice(-300).map((l, i) =>
                React.createElement('div', {
                  key: i,
                  style: { color: l.type === 'stderr' ? 'var(--critical)' : l.line?.startsWith('[') ? 'var(--medium)' : '#8FC6A8', wordBreak: 'break-all' }
                }, l.line)
              )
        )
      )
    ),

    // ── Flags ─────────────────────────────────────────────────────────────
    flags.length > 0 && React.createElement('div', {
      style: { borderRadius: 10, border: '1px solid rgba(74,222,128,0.25)', overflow: 'hidden', marginBottom: 14, background: 'var(--bg-surface)' }
    },
      React.createElement('div', {
        style: {
          padding: '9px 14px', background: 'rgba(74,222,128,0.07)', borderBottom: '1px solid rgba(74,222,128,0.15)',
          display: 'flex', alignItems: 'center', gap: 8,
        }
      },
        React.createElement('span', { style: { fontSize: 12 } }, '🚩'),
        React.createElement('span', { style: { fontSize: 10, fontWeight: 800, color: 'var(--low)', textTransform: 'uppercase', letterSpacing: 1 } }, 'Flags Captured'),
        React.createElement('span', {
          style: { marginLeft: 'auto', fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--low)', fontWeight: 700 }
        }, flags.length)
      ),
      flags.map((f, i) => React.createElement('div', {
        key: i,
        style: {
          display: 'flex', gap: 10, padding: '8px 14px', fontSize: 11, alignItems: 'center',
          borderBottom: i < flags.length - 1 ? '1px solid rgba(74,222,128,0.08)' : 'none'
        }
      },
        React.createElement('span', {
          style: {
            padding: '1px 8px', borderRadius: 4, fontSize: 9, fontWeight: 700, fontFamily: 'var(--font-mono)',
            background: f.flag_type === 'root' ? 'var(--critical-bg)' : 'var(--medium-bg)',
            color: f.flag_type === 'root' ? 'var(--critical)' : 'var(--medium)',
            border: f.flag_type === 'root' ? '1px solid var(--critical-bd)' : '1px solid var(--medium-bd)',
            flexShrink: 0,
          }
        }, (f.flag_type || '?').toUpperCase()),
        React.createElement('span', { style: { fontFamily: 'var(--font-mono)', color: 'var(--low)', flex: 1, fontWeight: 600 } }, f.value),
        React.createElement('span', { style: { color: 'var(--text-muted)', fontSize: 10, flexShrink: 0, fontFamily: 'var(--font-mono)' } }, f.location)
      ))
    ),

    // ── Event feed ────────────────────────────────────────────────────────
    React.createElement('div', {
      style: { borderRadius: 10, background: 'var(--bg-surface)', border: '1px solid var(--border)', overflow: 'hidden' }
    },
      // Feed header
      React.createElement('div', {
        style: {
          padding: '10px 14px', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 8,
        }
      },
        React.createElement('span', { style: { fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.8 } }, '◎ Event Feed'),
        wsConnected && React.createElement('span', {
          style: { width: 6, height: 6, borderRadius: '50%', background: 'var(--low)', boxShadow: '0 0 6px var(--low)', display: 'inline-block' }
        }),
        feedEntries.length > 0 && React.createElement('span', {
          style: { marginLeft: 'auto', fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
        }, `${feedEntries.length} events`)
      ),
      React.createElement('div', {
        ref: feedRef,
        style: { height: 200, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 0, padding: '6px 0' }
      },
        feedEntries.length === 0
          ? React.createElement('div', {
              style: { display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontSize: 11 }
            }, '— waiting for events —')
          : [...feedEntries.slice(0, 150)].reverse().map((e, i) =>
              React.createElement('div', {
                key: i,
                style: {
                  display: 'flex', gap: 8, fontSize: 10.5, padding: '3px 14px', alignItems: 'flex-start',
                  borderBottom: i < Math.min(149, feedEntries.length - 1) ? '1px solid rgba(255,255,255,0.03)' : 'none',
                }
              },
                React.createElement('span', { style: { color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0, fontSize: 9, marginTop: 2, opacity: 0.6 } }, e.ts),
                e.agent && React.createElement('span', {
                  style: { color: agentColor(e.agent), fontFamily: 'var(--font-mono)', flexShrink: 0, minWidth: 52, fontSize: 9, fontWeight: 800, marginTop: 1, letterSpacing: 0.5 }
                }, e.agent.toUpperCase()),
                React.createElement('span', { style: { color: 'var(--text-secondary)', lineHeight: 1.5, wordBreak: 'break-word', flex: 1 } }, e.message)
              )
            )
      )
    ),

    // ── Confirm modal ─────────────────────────────────────────────────────
    confirmVisible && React.createElement('div', {
      style: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)',
               display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
      onClick: e => { if (e.target === e.currentTarget) setConfirmVisible(false); }
    },
      React.createElement('div', {
        style: { background: 'var(--bg-surface)', border: '1px solid rgba(255,170,0,0.4)', borderRadius: 10, width: 420, padding: 24 }
      },
        React.createElement('div', { style: { fontSize: 15, fontWeight: 700, color: 'var(--amber)', marginBottom: 12 } }, '⚠ Confirm Exploitation'),
        React.createElement('p', { style: { color: 'var(--text-muted)', fontSize: 13, marginBottom: 8 } },
          'The attack plan is ready. ExploitAgent will attempt initial access.'),
        React.createElement('p', { style: { color: 'var(--amber)', fontSize: 11, marginBottom: 20 } },
          'Only proceed on systems you have explicit written authorisation to test.'),
        React.createElement('div', { style: { display: 'flex', gap: 8, justifyContent: 'flex-end' } },
          React.createElement('button', {
            onClick: () => setConfirmVisible(false),
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--border-bright)', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 12 }
          }, 'Cancel'),
          React.createElement('button', {
            onClick: handleConfirm,
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--red)', background: 'rgba(255,68,102,0.2)', color: 'var(--red)', cursor: 'pointer', fontSize: 12, fontWeight: 700 }
          }, 'Proceed with Exploitation')
        )
      )
    ),

    // ── Web confirm modal ─────────────────────────────────────────────────
    webConfirmPending && React.createElement('div', {
      style: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)',
               display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
      onClick: e => { if (e.target === e.currentTarget) handleWebSkip(); }
    },
      React.createElement('div', {
        style: { background: 'var(--bg-surface)', border: '1px solid rgba(0,212,255,0.4)', borderRadius: 10, width: 440, padding: 24 }
      },
        React.createElement('div', { style: { fontSize: 15, fontWeight: 700, color: 'var(--cyan)', marginBottom: 12 } }, '⚠ Confirm Web Application Testing'),
        React.createElement('p', { style: { color: 'var(--text-muted)', fontSize: 13, marginBottom: 8 } },
          'Web application testing is ready to begin. The web agent will enumerate endpoints, test for injection vulnerabilities, check authentication, and scan web-specific attack surface.'),
        React.createElement('p', { style: { color: 'var(--amber)', fontSize: 11, marginBottom: 20 } },
          'Web testing can be intrusive. Only proceed on systems you have explicit written authorisation to test.'),
        React.createElement('div', { style: { display: 'flex', gap: 8, justifyContent: 'flex-end' } },
          React.createElement('button', {
            onClick: handleWebSkip,
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--border-bright)', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 12 }
          }, 'Skip Web Testing'),
          React.createElement('button', {
            onClick: handleWebConfirm,
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--cyan)', background: 'rgba(0,212,255,0.15)', color: 'var(--cyan)', cursor: 'pointer', fontSize: 12, fontWeight: 700 }
          }, 'Proceed with Web Testing')
        )
      )
    ),

    // ── Phase time-extension modal ─────────────────────────────────────────
    phaseTimeExtension && React.createElement('div', {
      style: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)',
               display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
    },
      React.createElement('div', {
        style: { background: 'var(--bg-surface)', border: '1px solid rgba(255,170,0,0.4)', borderRadius: 10, width: 440, padding: 24 }
      },
        React.createElement('div', { style: { fontSize: 15, fontWeight: 700, color: 'var(--amber)', marginBottom: 12 } },
          `⏱ Phase Timeout — ${(phaseTimeExtension.phase || '').replace('_', ' ').toUpperCase()}`),
        React.createElement('p', { style: { color: 'var(--text-muted)', fontSize: 13, marginBottom: 8 } },
          phaseTimeExtension.message || 'The phase has exceeded its time limit.'),
        React.createElement('p', { style: { color: 'var(--text-secondary)', fontSize: 11, marginBottom: 20 } },
          'Extend to allow the phase to continue running, or stop it now.'),
        React.createElement('div', { style: { display: 'flex', gap: 8, justifyContent: 'flex-end' } },
          React.createElement('button', {
            onClick: handleStopPhase,
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--red)', background: 'rgba(255,68,102,0.1)', color: 'var(--red)', cursor: 'pointer', fontSize: 12, fontWeight: 600 }
          }, 'Stop Phase'),
          React.createElement('button', {
            onClick: handleExtendPhase,
            style: { padding: '7px 16px', borderRadius: 5, border: '1px solid var(--amber)', background: 'rgba(255,170,0,0.15)', color: 'var(--amber)', cursor: 'pointer', fontSize: 12, fontWeight: 700 }
          }, 'Extend Time')
        )
      )
    ),

    // ── Operator Console (HITL) ────────────────────────────────────────────
    showGuidance && activeSession && React.createElement(OperatorConsole, {
      sessionId:      activeSession.id,
      currentPhase,
      onClose:        () => setShowGuidance(false),
      planSteps,
      agents,
      feedEntries,
      findingsSummary,
      credentials,
    }),

    // ── Ask Bar (bottom-left, always available during active session) ─────
    React.createElement(AskBar, { sessionId: activeSession && activeSession.id })
  );
}

// ── Operator Console (HITL Dashboard) ────────────────────────────────────────
function OperatorConsole({ sessionId, currentPhase, onClose, planSteps, agents, feedEntries, findingsSummary, credentials }) {
  const { state, dispatch } = window.useStore();
  const { operatorMode, guidanceHistory } = state;

  const [tab,       setTab]      = useState('note');
  const [note,      setNote]     = useState('');
  const [tool,      setTool]     = useState('');
  const [toolArgs,  setToolArgs] = useState('');
  const [skipPhase, setSkipPhase]= useState('');
  const [dnsHost,   setDnsHost]  = useState('');
  const [dnsIp,     setDnsIp]    = useState('');
  const [sending,   setSending]  = useState(false);
  const [feedback,  setFeedback] = useState('');

  const isAuto = operatorMode === 'auto';
  const ALL_PHASES = ['recon','vuln_id','web_testing','osint','exploit','post_exploit','privesc','iot'];

  const failedSteps = (planSteps || []).filter(s => s.status === 'failed');
  const activeAgents = Object.entries(agents || {}).filter(([, a]) => a.status === 'running' || a.status === 'thinking');
  const recentFindings = (feedEntries || []).filter(e => e.eventType === 'finding').slice(0, 5);

  async function send() {
    if (!sessionId || isAuto) return;
    setSending(true); setFeedback('');
    try {
      const body = { directive: tab };
      if (tab === 'note') body.note = note;
      if (tab === 'tool') { body.force_tool = tool; body.force_args = toolArgs; }
      if (tab === 'skip') body.skip_phase = skipPhase;
      if (tab === 'dns')  { body.directive = 'dns_entry'; body.dns_host = dnsHost; body.dns_ip = dnsIp; }
      await window.API.sessions.guidance(sessionId, body);
      setFeedback('✓ Guidance queued');
      dispatch({ type: 'GUIDANCE_SENT', payload: { directive: tab, note, tool, dns_host: dnsHost, dns_ip: dnsIp } });
      if (tab === 'note') setNote('');
      if (tab === 'dns')  { setDnsHost(''); setDnsIp(''); }
    } catch (e) { setFeedback(`✗ ${e.message}`); }
    setSending(false);
  }

  async function sendWithNote(prefill) {
    setTab('note'); setNote(prefill);
  }

  const inp = {
    width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)',
    borderRadius: 5, color: 'var(--text-primary)', fontSize: 10,
    padding: '6px 8px', outline: 'none', fontFamily: 'var(--font-mono)',
    boxSizing: 'border-box',
  };

  const tabBtn = (k, label) => React.createElement('div', {
    onClick: isAuto ? undefined : () => setTab(k),
    style: {
      padding: '3px 10px', borderRadius: 4, cursor: isAuto ? 'not-allowed' : 'pointer', fontSize: 9,
      fontFamily: 'var(--font-mono)', fontWeight: 600,
      border: tab === k ? '1px solid var(--cyan)' : '1px solid var(--border)',
      background: tab === k ? 'rgba(0,212,255,0.08)' : 'transparent',
      color: isAuto ? 'var(--border)' : tab === k ? 'var(--cyan)' : 'var(--text-muted)',
    }
  }, label);

  return React.createElement('div', {
    style: {
      position: 'fixed', bottom: 20, right: 20, width: 400, maxHeight: '85vh',
      zIndex: 500, background: 'var(--bg-base)',
      border: `1px solid ${isAuto ? 'var(--border)' : 'rgba(0,212,255,0.3)'}`,
      borderRadius: 10, boxShadow: '0 20px 60px rgba(0,0,0,0.85)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }
  },

    // ── Header ──────────────────────────────────────────────────────────
    React.createElement('div', {
      style: { padding: '9px 12px', background: 'var(--bg-surface)', borderBottom: '1px solid var(--border)',
               display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }
    },
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 7 } },
        React.createElement('span', { style: { fontSize: 13 } }, '🎯'),
        React.createElement('span', {
          style: { fontSize: 11, fontWeight: 700, color: isAuto ? 'var(--text-muted)' : 'var(--cyan)', letterSpacing: 0.5 }
        }, 'OPERATOR CONSOLE'),
        currentPhase && React.createElement('span', {
          style: { fontSize: 8, padding: '1px 5px', borderRadius: 3, fontFamily: 'var(--font-mono)',
                   background: 'rgba(0,212,255,0.08)', color: 'var(--cyan)' }
        }, currentPhase.toUpperCase()),
      ),
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6 } },
        // AUTO / GUIDED mode toggle
        React.createElement('div', {
          onClick: () => dispatch({ type: 'OPERATOR_MODE', payload: isAuto ? 'guided' : 'auto' }),
          style: { display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer' }
        },
          React.createElement('span', { style: { fontSize: 9, color: isAuto ? 'var(--text-muted)' : 'var(--cyan)', fontFamily: 'var(--font-mono)' } },
            isAuto ? 'AUTO' : 'GUIDED'),
          React.createElement('div', {
            style: { width: 28, height: 15, borderRadius: 8, position: 'relative',
                     background: isAuto ? 'var(--border)' : 'rgba(0,212,255,0.3)',
                     border: `1px solid ${isAuto ? 'var(--border-bright)' : 'var(--cyan)'}`, transition: 'all 0.2s' }
          },
            React.createElement('div', {
              style: { position: 'absolute', top: 2, width: 9, height: 9, borderRadius: '50%',
                       background: isAuto ? 'var(--text-muted)' : 'var(--cyan)', transition: 'left 0.2s',
                       left: isAuto ? 2 : 16 }
            })
          )
        ),
        React.createElement('button', {
          onClick: onClose,
          style: { background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 14, lineHeight: 1 }
        }, '✕')
      )
    ),

    // ── Scrollable body ──────────────────────────────────────────────────
    React.createElement('div', { style: { flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 0 } },

      // ── Status section ─────────────────────────────────────────────────
      React.createElement('div', {
        style: { padding: '8px 12px', borderBottom: '1px solid var(--border)', background: 'var(--bg-surface)' }
      },
        React.createElement('div', { style: { fontSize: 8, color: 'var(--border-bright)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 5 } }, 'Current Status'),
        React.createElement('div', { style: { display: 'flex', gap: 6, flexWrap: 'wrap' } },
          React.createElement('div', {
            style: { fontSize: 9, padding: '2px 8px', borderRadius: 4, fontFamily: 'var(--font-mono)',
                     background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.2)', color: 'var(--cyan)' }
          }, `Phase: ${(currentPhase || 'idle').toUpperCase()}`),
          activeAgents.map(([name, ag]) =>
            React.createElement('div', {
              key: name,
              style: { fontSize: 9, padding: '2px 8px', borderRadius: 4, fontFamily: 'var(--font-mono)',
                       background: 'rgba(0,255,136,0.04)', border: '1px solid rgba(0,255,136,0.2)', color: 'var(--green)' }
            }, `● ${name.toUpperCase()} ${ag.message ? `— ${ag.message.slice(0,30)}` : ''}`)
          ),
          activeAgents.length === 0 && React.createElement('span', { style: { fontSize: 9, color: 'var(--border)', fontFamily: 'var(--font-mono)' } }, '— agents idle —')
        )
      ),

      // ── Failure Alerts ────────────────────────────────────────────────
      failedSteps.length > 0 && React.createElement('div', {
        style: { padding: '8px 12px', borderBottom: '1px solid var(--border)', background: 'rgba(255,68,102,0.02)' }
      },
        React.createElement('div', {
          style: { fontSize: 8, color: 'var(--red)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 5 }
        }, `⚠ ${failedSteps.length} step${failedSteps.length > 1 ? 's' : ''} need attention`),
        ...failedSteps.slice(0, 4).map((s, i) =>
          React.createElement('div', {
            key: i,
            style: { display: 'flex', alignItems: 'flex-start', gap: 6, padding: '5px 0',
                     borderBottom: i < failedSteps.length - 1 ? '1px solid var(--border)' : 'none' }
          },
            React.createElement('span', { style: { fontSize: 9, color: 'var(--red)', flexShrink: 0, paddingTop: 1 } }, '✗'),
            React.createElement('div', { style: { flex: 1, minWidth: 0 } },
              React.createElement('div', { style: { fontSize: 10, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontWeight: 600 } }, s.label || s.id),
              s.result && React.createElement('div', {
                style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2,
                         whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }
              }, s.result),
            ),
            !isAuto && React.createElement('button', {
              onClick: () => sendWithNote(`Retry step "${s.label || s.id}" — previous attempt failed. ${s.result || ''}`),
              style: { padding: '2px 7px', borderRadius: 3, fontSize: 8, cursor: 'pointer',
                       border: '1px solid rgba(255,68,102,0.4)', background: 'rgba(255,68,102,0.08)',
                       color: 'var(--red)', fontFamily: 'var(--font-mono)', flexShrink: 0 }
            }, 'Assist')
          )
        )
      ),

      // ── Areas of Interest ────────────────────────────────────────────
      (recentFindings.length > 0 || findingsSummary?.total > 0) && React.createElement('div', {
        style: { padding: '8px 12px', borderBottom: '1px solid var(--border)' }
      },
        React.createElement('div', { style: { fontSize: 8, color: 'var(--border-bright)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 5 } }, 'Areas of Interest'),
        React.createElement('div', { style: { display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: recentFindings.length > 0 ? 6 : 0 } },
          [['critical', 'var(--red)'], ['high', 'var(--high)'], ['medium', 'var(--amber)']].map(([sev, col]) =>
            findingsSummary[sev] > 0 && React.createElement('span', {
              key: sev,
              style: { fontSize: 9, padding: '1px 7px', borderRadius: 3, fontFamily: 'var(--font-mono)',
                       background: `${col}10`, border: `1px solid ${col}30`, color: col }
            }, `${findingsSummary[sev]} ${sev}`)
          ).filter(Boolean)
        ),
        ...recentFindings.map((e, i) =>
          React.createElement('div', {
            key: i,
            style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', padding: '2px 0',
                     borderTop: i === 0 ? 'none' : '1px solid var(--border)',
                     whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }
          }, `• ${e.message || ''}`)
        )
      ),

      // ── AUTO mode banner ──────────────────────────────────────────────
      isAuto && React.createElement('div', {
        style: { padding: '14px 12px', textAlign: 'center', borderBottom: '1px solid var(--border)' }
      },
        React.createElement('div', { style: { fontSize: 22, marginBottom: 6 } }, '🤖'),
        React.createElement('div', { style: { fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 } }, 'AUTOMATED MODE'),
        React.createElement('div', { style: { fontSize: 9, color: 'var(--border)', marginTop: 4, lineHeight: 1.6 } },
          'Agents are running without operator input.\nToggle GUIDED above to provide context.')
      ),

      // ── Input section (GUIDED mode only) ─────────────────────────────
      !isAuto && React.createElement('div', { style: { padding: '8px 12px', borderBottom: '1px solid var(--border)' } },
        React.createElement('div', { style: { display: 'flex', gap: 4, marginBottom: 8, flexWrap: 'wrap' } },
          tabBtn('note', '📝 Note'),
          tabBtn('dns',  '🌐 DNS'),
          tabBtn('tool', '🔧 Force Tool'),
          tabBtn('skip', '⏭ Skip Phase'),
        ),

        // Note tab
        tab === 'note' && React.createElement('textarea', {
          style: { ...inp, minHeight: 72, resize: 'vertical' },
          placeholder: 'e.g. "Focus on /admin/login — try default creds admin:admin123 and SQLi on username"',
          value: note, onChange: e => setNote(e.target.value)
        }),

        // DNS tab
        tab === 'dns' && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 5 } },
          React.createElement('div', { style: { fontSize: 9, color: 'var(--text-muted)', marginBottom: 2 } },
            'Add a local DNS entry so agents resolve hostnames correctly.'),
          React.createElement('input', {
            style: inp, placeholder: 'Hostname (e.g. app.local, victim.htb)',
            value: dnsHost, onChange: e => setDnsHost(e.target.value)
          }),
          React.createElement('input', {
            style: { ...inp, marginTop: 2 }, placeholder: 'IP address (e.g. 10.10.10.5)',
            value: dnsIp, onChange: e => setDnsIp(e.target.value)
          }),
        ),

        // Force tool tab
        tab === 'tool' && React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 5 } },
          React.createElement('input', {
            style: inp, placeholder: 'Tool (e.g. sqlmap, nikto, hydra)',
            value: tool, onChange: e => setTool(e.target.value)
          }),
          React.createElement('input', {
            style: { ...inp, marginTop: 2 }, placeholder: 'Arguments (e.g. -u http://10.10.10.1/login --forms)',
            value: toolArgs, onChange: e => setToolArgs(e.target.value)
          }),
        ),

        // Skip phase tab
        tab === 'skip' && React.createElement('select', {
          style: { ...inp, cursor: 'pointer' },
          value: skipPhase, onChange: e => setSkipPhase(e.target.value)
        },
          React.createElement('option', { value: '' }, '— select phase to skip —'),
          ...ALL_PHASES.map(p => React.createElement('option', { key: p, value: p }, p.toUpperCase()))
        ),

        // Send button
        React.createElement('button', {
          onClick: send,
          disabled: sending || (tab === 'note' && !note) || (tab === 'tool' && !tool)
            || (tab === 'skip' && !skipPhase) || (tab === 'dns' && (!dnsHost || !dnsIp)),
          style: {
            marginTop: 7, width: '100%', padding: '7px', borderRadius: 5, fontWeight: 700,
            fontSize: 10, cursor: 'pointer', fontFamily: 'var(--font-mono)',
            border: '1px solid rgba(0,212,255,0.4)',
            background: 'rgba(0,212,255,0.1)', color: 'var(--cyan)',
            opacity: sending ? 0.5 : 1,
          }
        }, sending ? '⟳ Sending...' : '🎯 Send Guidance'),

        feedback && React.createElement('div', {
          style: {
            marginTop: 5, fontSize: 9, padding: '4px 8px', borderRadius: 4,
            fontFamily: 'var(--font-mono)',
            background: feedback.startsWith('✓') ? 'rgba(0,255,136,0.05)' : 'rgba(255,68,102,0.05)',
            border: `1px solid ${feedback.startsWith('✓') ? 'rgba(0,255,136,0.15)' : 'rgba(255,68,102,0.15)'}`,
            color: feedback.startsWith('✓') ? 'var(--green)' : 'var(--red)',
          }
        }, feedback),
      ),

      // ── Guidance History ──────────────────────────────────────────────
      guidanceHistory.length > 0 && React.createElement('div', {
        style: { padding: '8px 12px' }
      },
        React.createElement('div', { style: { fontSize: 8, color: 'var(--border)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 5 } }, 'Sent Guidance'),
        ...guidanceHistory.slice(0, 8).map((g, i) =>
          React.createElement('div', {
            key: i,
            style: { display: 'flex', gap: 6, alignItems: 'flex-start', padding: '3px 0',
                     borderTop: i === 0 ? 'none' : '1px solid var(--border)', fontSize: 9 }
          },
            React.createElement('span', { style: { color: 'var(--border)', fontFamily: 'var(--font-mono)', flexShrink: 0 } }, g.ts),
            React.createElement('span', { style: { color: 'var(--border)', fontFamily: 'var(--font-mono)', flexShrink: 0 } },
              g.directive === 'dns' ? '🌐' : g.directive === 'tool' ? '🔧' : g.directive === 'skip' ? '⏭' : '📝'),
            React.createElement('span', {
              style: { color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', lineHeight: 1.4,
                       whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 280 }
            }, g.note || g.tool || (g.dns_host && `${g.dns_host} → ${g.dns_ip}`) || g.directive)
          )
        )
      )
    )
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// AskBar — draggable, minimizable "Ask ARGUS" floating panel
// Drag by the header. Minimize to a compact pill. Expand to show answers.
// ══════════════════════════════════════════════════════════════════════════════
function AskBar({ sessionId }) {
  const { state, dispatch } = window.useStore();
  const { lastQuestionResult, questionHistory, activeSession } = state;

  const [question,  setQuestion]  = React.useState('');
  const [loading,   setLoading]   = React.useState(false);
  const [error,     setError]     = React.useState('');
  const [expanded,  setExpanded]  = React.useState(false);
  const [minimized, setMinimized] = React.useState(false);

  // Drag state — stored in refs to avoid re-render loops during drag
  const [pos, setPos] = React.useState({ x: 20, y: null, fromBottom: 20 });
  const dragging  = React.useRef(false);
  const dragStart = React.useRef({ mx: 0, my: 0, px: 0, py: 0 });
  const panelRef  = React.useRef(null);

  if (!activeSession) return null;

  // ── Drag handlers ─────────────────────────────────────────────────────────
  function onMouseDown(e) {
    // Only drag from header, ignore button clicks inside header
    if (e.target.closest('button')) return;
    e.preventDefault();
    dragging.current = true;
    const rect = panelRef.current.getBoundingClientRect();
    dragStart.current = { mx: e.clientX, my: e.clientY, px: rect.left, py: rect.top };
    // Switch from bottom-anchor to top-anchor when dragging starts
    setPos(p => {
      const currentTop = p.y !== null ? p.y : window.innerHeight - rect.height - p.fromBottom;
      return { x: p.x, y: currentTop, fromBottom: null };
    });
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup',   onMouseUp);
  }

  function onMouseMove(e) {
    if (!dragging.current) return;
    const dx = e.clientX - dragStart.current.mx;
    const dy = e.clientY - dragStart.current.my;
    const newX = Math.max(0, Math.min(window.innerWidth  - 390, dragStart.current.px + dx));
    const newY = Math.max(0, Math.min(window.innerHeight - 50,  dragStart.current.py + dy));
    setPos({ x: newX, y: newY, fromBottom: null });
  }

  function onMouseUp() {
    dragging.current = false;
    window.removeEventListener('mousemove', onMouseMove);
    window.removeEventListener('mouseup',   onMouseUp);
  }

  // ── Ask logic ─────────────────────────────────────────────────────────────
  async function ask() {
    const q = question.trim();
    if (!q || !sessionId || loading) return;
    setLoading(true); setError('');
    try {
      const res = await window.API.sessions.ask(sessionId, q);
      dispatch({ type: 'QUESTION_ANSWERED', payload: { ...res, question: q } });
      setQuestion('');
      setExpanded(true);
      if (minimized) setMinimized(false);
    } catch (e) {
      setError(`✗ ${e.message}`);
    }
    setLoading(false);
  }

  function handleKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(); }
  }

  const layerColor = (l) => l === 1 ? 'var(--green)' : l === 2 ? 'var(--cyan)' : 'var(--yellow)';
  const layerLabel = (l) => l === 1 ? 'L1·Det' : l === 2 ? 'L2·LLM' : 'L3·Tool';

  // Position style — use bottom-anchor until first drag
  const posStyle = pos.fromBottom !== null
    ? { left: pos.x, bottom: pos.fromBottom }
    : { left: pos.x, top: pos.y };

  // ── Minimized pill ────────────────────────────────────────────────────────
  if (minimized) {
    return React.createElement('div', {
      ref: panelRef,
      onMouseDown,
      style: {
        position: 'fixed', ...posStyle, zIndex: 490,
        background: 'var(--bg-surface)',
        border: '1px solid rgba(0,255,136,0.35)',
        borderRadius: 20, boxShadow: '0 8px 30px rgba(0,0,0,0.7)',
        display: 'flex', alignItems: 'center', gap: 7,
        padding: '6px 12px', cursor: 'grab', userSelect: 'none',
      }
    },
      React.createElement('span', { style: { fontSize: 11 } }, '🔎'),
      React.createElement('span', {
        style: { fontSize: 10, fontWeight: 700, color: 'var(--green)',
                 fontFamily: 'var(--font-mono)', letterSpacing: 0.5 }
      }, 'ASK ARGUS'),
      questionHistory.length > 0 && React.createElement('span', {
        style: { fontSize: 8, padding: '1px 5px', borderRadius: 10,
                 background: 'rgba(0,255,136,0.12)', color: 'var(--green)',
                 fontFamily: 'var(--font-mono)' }
      }, `${questionHistory.length}`),
      React.createElement('button', {
        onClick: (e) => { e.stopPropagation(); setMinimized(false); },
        style: {
          background: 'none', border: 'none', color: 'var(--text-muted)',
          cursor: 'pointer', fontSize: 11, lineHeight: 1, padding: '0 2px',
        }
      }, '⬆')
    );
  }

  // ── Full panel ────────────────────────────────────────────────────────────
  return React.createElement('div', {
    ref: panelRef,
    style: {
      position: 'fixed', ...posStyle, width: 380, zIndex: 490,
      background: 'var(--bg-base)',
      border: '1px solid rgba(0,255,136,0.25)',
      borderRadius: 10, boxShadow: '0 20px 60px rgba(0,0,0,0.85)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }
  },

    // ── Header (drag handle) ──────────────────────────────────────────────
    React.createElement('div', {
      onMouseDown,
      style: {
        padding: '8px 12px', background: 'var(--bg-surface)',
        borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        cursor: 'grab', userSelect: 'none', flexShrink: 0,
      }
    },
      // Left: title + badge
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 7 } },
        React.createElement('span', { style: { fontSize: 11 } }, '🔎'),
        React.createElement('span', {
          style: { fontSize: 11, fontWeight: 700, color: 'var(--green)', letterSpacing: 0.5 }
        }, 'ASK ARGUS'),
        questionHistory.length > 0 && React.createElement('span', {
          style: { fontSize: 8, padding: '1px 5px', borderRadius: 3,
                   fontFamily: 'var(--font-mono)',
                   background: 'rgba(0,255,136,0.08)', color: 'var(--green)' }
        }, `${questionHistory.length} answered`),
        // Drag hint
        React.createElement('span', {
          style: { fontSize: 8, color: 'var(--border)', fontFamily: 'var(--font-mono)', opacity: 0.5 }
        }, '⠿ drag')
      ),
      // Right: expand toggle + minimize
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: 6 } },
        React.createElement('button', {
          onClick: (e) => { e.stopPropagation(); setExpanded(!expanded); },
          title: expanded ? 'Collapse history' : 'Expand history',
          style: {
            background: 'none', border: 'none', color: 'var(--text-muted)',
            cursor: 'pointer', fontSize: 10, fontFamily: 'var(--font-mono)',
            padding: '0 3px',
          }
        }, expanded ? '▲' : '▼'),
        React.createElement('button', {
          onClick: (e) => { e.stopPropagation(); setMinimized(true); },
          title: 'Minimize to pill',
          style: {
            background: 'none', border: 'none', color: 'var(--text-muted)',
            cursor: 'pointer', fontSize: 12, lineHeight: 1, padding: '0 2px',
          }
        }, '–')
      )
    ),

    // ── Input row ─────────────────────────────────────────────────────────
    React.createElement('div', {
      style: { padding: '8px 10px', display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }
    },
      React.createElement('input', {
        value:       question,
        onChange:    e => setQuestion(e.target.value),
        onKeyDown:   handleKey,
        placeholder: 'Ask a question… (Enter to send)',
        style: {
          flex: 1, background: 'var(--bg-surface)', border: '1px solid var(--border)',
          borderRadius: 5, color: 'var(--text-primary)', fontSize: 10,
          padding: '6px 8px', outline: 'none', fontFamily: 'var(--font-mono)',
        }
      }),
      React.createElement('button', {
        onClick:  ask,
        disabled: !question.trim() || loading,
        style: {
          padding: '6px 10px', borderRadius: 5, border: 'none', cursor: 'pointer',
          fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700,
          background: (!question.trim() || loading) ? 'var(--bg-surface)' : 'rgba(0,255,136,0.15)',
          color:      (!question.trim() || loading) ? 'var(--text-muted)' : 'var(--green)',
          transition: 'all 0.15s',
        }
      }, loading ? '…' : 'Ask')
    ),

    // ── Error ─────────────────────────────────────────────────────────────
    error && React.createElement('div', {
      style: { padding: '0 10px 6px', fontSize: 9, color: 'var(--red)', fontFamily: 'var(--font-mono)' }
    }, error),

    // ── Latest result (always shown when available, below input) ──────────
    lastQuestionResult && React.createElement('div', {
      style: {
        margin: '0 8px 8px', padding: '7px 9px', borderRadius: 6,
        background: lastQuestionResult.state === 'answered'
          ? 'rgba(0,255,136,0.06)' : 'rgba(255,255,255,0.03)',
        border: `1px solid ${lastQuestionResult.state === 'answered'
          ? 'rgba(0,255,136,0.2)' : 'var(--border)'}`,
      }
    },
      React.createElement('div', {
        style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }
      },
        React.createElement('span', {
          style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                   flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                   marginRight: 6 }
        }, lastQuestionResult.question),
        lastQuestionResult.layer_used && React.createElement('span', {
          style: {
            fontSize: 8, padding: '1px 5px', borderRadius: 3, flexShrink: 0,
            background: 'rgba(0,0,0,0.35)',
            color: layerColor(lastQuestionResult.layer_used),
            fontFamily: 'var(--font-mono)',
          }
        }, layerLabel(lastQuestionResult.layer_used))
      ),
      lastQuestionResult.answer
        ? React.createElement('div', {
            style: { fontSize: 12, color: 'var(--green)', fontFamily: 'var(--font-mono)',
                     fontWeight: 700, wordBreak: 'break-all', lineHeight: 1.4 }
          }, lastQuestionResult.answer)
        : React.createElement('div', {
            style: { fontSize: 10, color: 'var(--text-muted)', fontStyle: 'italic' }
          }, 'No answer found — try running more tools first'),
      lastQuestionResult.evidence && React.createElement('div', {
        style: { fontSize: 8, color: 'var(--text-muted)', marginTop: 3,
                 fontFamily: 'var(--font-mono)', opacity: 0.65,
                 whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }
      }, `↳ ${lastQuestionResult.evidence}`)
    ),

    // ── Expanded history ──────────────────────────────────────────────────
    expanded && questionHistory.length > 1 && React.createElement('div', {
      style: { borderTop: '1px solid var(--border)', maxHeight: 220, overflowY: 'auto' }
    },
      React.createElement('div', {
        style: { padding: '5px 10px 3px', fontSize: 8, color: 'var(--border)',
                 fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: 1 }
      }, 'History'),
      ...questionHistory.slice(1, 8).map((q, i) =>
        React.createElement('div', {
          key: i,
          style: { padding: '5px 10px', borderTop: '1px solid var(--border)',
                   display: 'flex', gap: 6, alignItems: 'flex-start' }
        },
          React.createElement('span', {
            style: { fontSize: 9, flexShrink: 0, marginTop: 1,
                     color: q.state === 'answered' ? 'var(--green)' : 'var(--text-muted)' }
          }, q.state === 'answered' ? '✓' : '·'),
          React.createElement('div', { style: { flex: 1, minWidth: 0 } },
            React.createElement('div', {
              style: { fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                       whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }
            }, q.question),
            q.answer && React.createElement('div', {
              style: { fontSize: 9, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)',
                       whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginTop: 1 }
            }, q.answer)
          )
        )
      )
    )
  );
}


window.MissionControl = MissionControl;
window.AskBar = AskBar;
