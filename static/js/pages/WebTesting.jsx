// ═══════════════════════════════════════════════════════════
// WebTesting.jsx — WSTG-aligned web application testing dashboard
//
// Pure read-only consumer of state.wstgMatrix + state.wstgPhases
// emitted by the backend WebOrchestrator.  Shows:
//   • All 14 WSTG phases as a status matrix (pending / running / done / failed)
//   • Live phase timeline with finding counters
//   • Resolved targets (base URLs being tested)
//   • Per-phase evidence drawer when a phase is clicked
//   • Web-specific findings filtered from the global findings list
//
// Adding/removing this page CANNOT break the platform — it has no
// dispatch actions and no WS handlers of its own.
// ═══════════════════════════════════════════════════════════

(function () {
'use strict';

const { useState, useMemo } = React;

const T = {
  bgBase:       '#0D0E14',
  bgSurface:    '#13151E',
  bgPanel:      '#1A1D28',
  bgElevated:   '#222638',
  accent:       '#00E5A0',
  violet:       '#7B6CF6',
  cyan:         '#38BDF8',
  amber:        '#F5C842',
  critical:     '#FF4560',
  high:         '#FF8C42',
  medium:       '#F5C842',
  low:          '#4ADE80',
  info:         '#38BDF8',
  border:       '#1E2236',
  borderLight:  '#262B40',
  textPrimary:  '#E2E8F4',
  textSecondary:'#8892AA',
  textMuted:    '#4A5168',
  fontUI:       "'Inter', system-ui, sans-serif",
  fontMono:     "'JetBrains Mono', 'Courier New', monospace",
};

// Status → color + glyph
const STATUS_META = {
  pending: { color: T.textMuted, glyph: '○',  label: 'pending'  },
  running: { color: T.cyan,       glyph: '◐', label: 'running'  },
  done:    { color: T.low,        glyph: '✓', label: 'done'     },
  failed:  { color: T.critical,   glyph: '✗', label: 'failed'   },
  skipped: { color: T.amber,      glyph: '–', label: 'skipped'  },
};

// Default WSTG phase list — also surfaced from backend at runtime
const DEFAULT_PHASES = [
  { id: 'info',      label: 'Information Gathering',    wstg: 'WSTG-INFO' },
  { id: 'config',    label: 'Configuration Management', wstg: 'WSTG-CONF' },
  { id: 'identity',  label: 'Identity Management',      wstg: 'WSTG-IDNT' },
  { id: 'auth',      label: 'Authentication',           wstg: 'WSTG-ATHN' },
  { id: 'session',   label: 'Session Management',       wstg: 'WSTG-SESS' },
  { id: 'authz',     label: 'Authorization',            wstg: 'WSTG-ATHZ' },
  { id: 'input',     label: 'Input Validation',         wstg: 'WSTG-INPV' },
  { id: 'errors',    label: 'Error Handling',           wstg: 'WSTG-ERRH' },
  { id: 'crypto',    label: 'Cryptography',             wstg: 'WSTG-CRYP' },
  { id: 'biz_logic', label: 'Business Logic',           wstg: 'WSTG-BUSL' },
  { id: 'client',    label: 'Client-Side',              wstg: 'WSTG-CLNT' },
  { id: 'api',       label: 'API Testing',              wstg: 'WSTG-APIT' },
  { id: 'upload',    label: 'File Upload',              wstg: 'WSTG-FILE' },
  { id: 'cache',     label: 'Cache Poisoning',          wstg: 'WSTG-CACH' },
];

function StatusPill({ status }) {
  const meta = STATUS_META[status] || STATUS_META.pending;
  return React.createElement('span', {
    style: {
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 10, fontSize: 9, fontWeight: 700,
      letterSpacing: 0.6, fontFamily: T.fontMono,
      background: `${meta.color}15`, color: meta.color,
      border: `1px solid ${meta.color}40`,
      textTransform: 'uppercase',
    }
  }, meta.glyph, ' ', meta.label);
}

function PhaseCard({ phase, runtime, onClick, isOpen }) {
  const meta = STATUS_META[runtime?.status || 'pending'];
  return React.createElement('div', {
    onClick,
    style: {
      background: T.bgSurface,
      border: `1px solid ${isOpen ? meta.color : T.borderLight}`,
      borderLeft: `3px solid ${meta.color}`,
      borderRadius: 10, padding: '12px 14px', cursor: 'pointer',
      transition: 'border-color 0.15s, transform 0.12s',
    },
    onMouseEnter: e => { e.currentTarget.style.borderColor = meta.color; },
    onMouseLeave: e => { if (!isOpen) e.currentTarget.style.borderColor = T.borderLight; },
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }
    },
      React.createElement('span', {
        style: { fontSize: 9, color: T.textMuted, letterSpacing: 1.2, fontFamily: T.fontMono, fontWeight: 700 }
      }, phase.wstg),
      React.createElement(StatusPill, { status: runtime?.status || 'pending' })
    ),
    React.createElement('div', {
      style: { fontSize: 13, fontWeight: 600, color: T.textPrimary, marginBottom: 4 }
    }, phase.label),
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }
    },
      React.createElement('span', {
        style: { color: T.textMuted, fontFamily: T.fontMono }
      }, runtime?.findings ? `${runtime.findings} finding${runtime.findings !== 1 ? 's' : ''}` : 'no findings'),
      runtime?.completed_at && React.createElement('span', {
        style: { color: T.textMuted, fontFamily: T.fontMono, fontSize: 9 }
      }, runtime.completed_at.slice(11, 19))
    )
  );
}

function EvidenceDrawer({ phase, runtime }) {
  if (!phase) return null;
  const meta = STATUS_META[runtime?.status || 'pending'];
  return React.createElement('div', {
    style: {
      marginTop: 14, background: T.bgSurface,
      border: `1px solid ${meta.color}40`, borderRadius: 12, padding: 18,
    }
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 10 }
    },
      React.createElement('div', null,
        React.createElement('span', {
          style: { fontSize: 9, color: meta.color, letterSpacing: 1.5, fontWeight: 700, fontFamily: T.fontMono }
        }, phase.wstg),
        React.createElement('div', {
          style: { fontSize: 16, fontWeight: 700, color: T.textPrimary, marginTop: 2 }
        }, phase.label)
      ),
      React.createElement(StatusPill, { status: runtime?.status || 'pending' })
    ),
    runtime?.notes && React.createElement('div', {
      style: {
        background: T.bgPanel, padding: '8px 12px', borderRadius: 6,
        fontSize: 11, color: T.textSecondary, fontFamily: T.fontMono,
        marginBottom: 10,
        whiteSpace: 'pre-wrap', wordBreak: 'break-word',
      }
    }, runtime.notes),
    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 } },
      React.createElement('div', null,
        React.createElement('div', { style: { fontSize: 9, color: T.textMuted, letterSpacing: 1, fontWeight: 700, marginBottom: 4 } }, 'STARTED'),
        React.createElement('div', { style: { fontSize: 11, color: T.textPrimary, fontFamily: T.fontMono } }, runtime?.started_at?.slice(0, 19) || '—')
      ),
      React.createElement('div', null,
        React.createElement('div', { style: { fontSize: 9, color: T.textMuted, letterSpacing: 1, fontWeight: 700, marginBottom: 4 } }, 'COMPLETED'),
        React.createElement('div', { style: { fontSize: 11, color: T.textPrimary, fontFamily: T.fontMono } }, runtime?.completed_at?.slice(0, 19) || '—')
      ),
      React.createElement('div', null,
        React.createElement('div', { style: { fontSize: 9, color: T.textMuted, letterSpacing: 1, fontWeight: 700, marginBottom: 4 } }, 'FINDINGS'),
        React.createElement('div', { style: { fontSize: 16, color: meta.color, fontFamily: T.fontMono, fontWeight: 700 } }, runtime?.findings ?? 0)
      ),
      React.createElement('div', null,
        React.createElement('div', { style: { fontSize: 9, color: T.textMuted, letterSpacing: 1, fontWeight: 700, marginBottom: 4 } }, 'EVIDENCE KEYS'),
        React.createElement('div', { style: { fontSize: 11, color: T.textPrimary, fontFamily: T.fontMono } },
          (runtime?.evidence_keys || []).slice(0, 5).join(', ') || '—')
      )
    )
  );
}

function FindingsByPhase({ phaseId, findings }) {
  const matched = useMemo(() => {
    return (findings || []).filter(f => {
      const phase = (f.phase || '').toLowerCase();
      const tags  = (f.tags || []).map(t => t.toLowerCase());
      const cat   = (f.category || '').toLowerCase();
      return phase.includes(phaseId) || tags.some(t => t.includes(phaseId)) || cat.includes(phaseId);
    });
  }, [phaseId, findings]);
  if (!matched.length) return null;
  return React.createElement('div', {
    style: { marginTop: 10 }
  },
    React.createElement('div', {
      style: { fontSize: 9, color: T.textMuted, letterSpacing: 1, fontWeight: 700, marginBottom: 6 }
    }, `RELATED FINDINGS (${matched.length})`),
    React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 5 } },
      matched.slice(0, 6).map((f, i) => {
        const sev = (f.severity || 'info').toLowerCase();
        const c = sev === 'critical' ? T.critical : sev === 'high' ? T.high : sev === 'medium' ? T.medium : sev === 'low' ? T.low : T.info;
        return React.createElement('div', {
          key: f.id || i,
          style: {
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '6px 10px', background: T.bgPanel, borderRadius: 5,
            borderLeft: `2px solid ${c}`,
          }
        },
          React.createElement('span', {
            style: {
              padding: '1px 6px', borderRadius: 4, fontSize: 9, fontWeight: 700,
              background: `${c}15`, color: c, fontFamily: T.fontMono, letterSpacing: 0.5,
            }
          }, sev.toUpperCase()),
          React.createElement('span', {
            style: { fontSize: 11, color: T.textPrimary, flex: 1,
                     overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
          }, f.title || '(untitled)')
        );
      })
    )
  );
}

// ─── Main page ────────────────────────────────────────────────
function WebTesting({ sessionId, activeSession }) {
  const { state } = window.useStore();
  const phaseList   = state.wstgMatrix?.phases || DEFAULT_PHASES;
  const targets     = state.wstgMatrix?.targets || [];
  const phaseRuntime= state.wstgPhases || {};
  const findings    = state.findings || [];
  const [selected, setSelected] = useState(null);

  // Tally
  const tally = useMemo(() => {
    const t = { pending: 0, running: 0, done: 0, failed: 0, skipped: 0 };
    for (const ph of phaseList) {
      const r = phaseRuntime[ph.id];
      const s = r?.status || 'pending';
      if (t[s] !== undefined) t[s] += 1;
    }
    return t;
  }, [phaseList, phaseRuntime]);

  const totalFindings = Object.values(phaseRuntime || {})
    .reduce((acc, r) => acc + (r.findings || 0), 0);

  return React.createElement('div', {
    style: {
      maxWidth: 1400, margin: '0 auto',
      fontFamily: T.fontUI, color: T.textPrimary, padding: '4px 0',
    }
  },

    // ── Header ──────────────────────────────────────────────────
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 22 }
    },
      React.createElement('div', null,
        React.createElement('div', {
          style: { fontSize: 11, letterSpacing: 2, color: T.cyan, textTransform: 'uppercase', fontWeight: 700, marginBottom: 4 }
        }, '🕸 WSTG WEB APPLICATION TESTING'),
        React.createElement('div', {
          style: { fontSize: 24, fontWeight: 700, color: T.textPrimary }
        }, 'Web Testing Matrix'),
        React.createElement('div', {
          style: { fontSize: 12, color: T.textSecondary, marginTop: 4 }
        }, 'OWASP WSTG-aligned phase coverage with live evidence chaining.')
      ),
      activeSession && React.createElement('button', {
        onClick: () => window.dispatchEvent(new CustomEvent('navigate', { detail: 'findings' })),
        style: {
          background: `${T.accent}15`, border: `1px solid ${T.accent}40`,
          color: T.accent, padding: '8px 14px', borderRadius: 8,
          cursor: 'pointer', fontSize: 11, fontWeight: 700, letterSpacing: 0.5,
        }
      }, 'View All Findings →')
    ),

    // ── Stat row ─────────────────────────────────────────────────
    React.createElement('div', {
      style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 10, marginBottom: 18 }
    },
      [
        { label: 'Phases',    value: phaseList.length, color: T.textPrimary },
        { label: 'Targets',   value: targets.length,    color: T.cyan },
        { label: 'Done',      value: tally.done,        color: T.low },
        { label: 'Running',   value: tally.running,     color: T.cyan },
        { label: 'Failed',    value: tally.failed,      color: T.critical },
        { label: 'Findings',  value: totalFindings,     color: T.amber },
      ].map(s =>
        React.createElement('div', {
          key: s.label,
          style: {
            background: T.bgSurface, border: `1px solid ${T.borderLight}`,
            borderRadius: 10, padding: '12px 14px',
          }
        },
          React.createElement('div', {
            style: { fontSize: 9, color: T.textMuted, letterSpacing: 1.2, fontWeight: 700, textTransform: 'uppercase' }
          }, s.label),
          React.createElement('div', {
            style: { fontSize: 22, fontWeight: 700, fontFamily: T.fontMono, color: s.color, marginTop: 2 }
          }, s.value)
        )
      )
    ),

    // ── Targets list ────────────────────────────────────────────
    targets.length > 0 && React.createElement('div', {
      style: {
        background: T.bgSurface, border: `1px solid ${T.borderLight}`,
        borderRadius: 10, padding: '12px 14px', marginBottom: 18,
      }
    },
      React.createElement('div', {
        style: { fontSize: 9, color: T.textMuted, letterSpacing: 1.2, fontWeight: 700, marginBottom: 8 }
      }, 'TARGETS UNDER TEST'),
      React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 6 } },
        targets.map(url =>
          React.createElement('span', {
            key: url,
            style: {
              padding: '3px 10px', borderRadius: 12,
              background: `${T.cyan}10`, border: `1px solid ${T.cyan}40`,
              fontSize: 11, fontFamily: T.fontMono, color: T.cyan,
            }
          }, url)
        )
      )
    ),

    // ── Phase matrix ────────────────────────────────────────────
    !activeSession || phaseList.length === 0
      ? React.createElement('div', {
          style: {
            background: T.bgSurface, border: `1px dashed ${T.borderLight}`,
            borderRadius: 12, padding: 40, textAlign: 'center',
          }
        },
          React.createElement('div', { style: { fontSize: 32, color: T.textMuted, marginBottom: 8 } }, '🕸'),
          React.createElement('div', {
            style: { fontSize: 13, color: T.textMuted, marginBottom: 4 }
          }, !activeSession ? 'No active engagement' : 'Web orchestrator not yet engaged'),
          React.createElement('div', {
            style: { fontSize: 11, color: T.textMuted }
          }, 'Phase matrix populates the moment WebOrchestrator fires (start of Web Testing phase).')
        )
      : React.createElement('div', {
          style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10 }
        },
          phaseList.map(ph =>
            React.createElement(PhaseCard, {
              key: ph.id,
              phase: ph,
              runtime: phaseRuntime[ph.id],
              isOpen: selected === ph.id,
              onClick: () => setSelected(selected === ph.id ? null : ph.id),
            })
          )
        ),

    // ── Selected phase drawer ───────────────────────────────────
    selected && React.createElement(React.Fragment, null,
      React.createElement(EvidenceDrawer, {
        phase: phaseList.find(p => p.id === selected),
        runtime: phaseRuntime[selected],
      }),
      React.createElement(FindingsByPhase, { phaseId: selected, findings })
    )
  );
}

window.WebTesting = WebTesting;
})();
