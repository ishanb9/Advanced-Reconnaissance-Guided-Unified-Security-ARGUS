// PhaseTimeline — crash-proof version
// Accepts BOTH old props (current, completed) AND new props (currentPhase, phasesCompleted)
const _PT_PHASES = [
  { key: 'recon',        label: 'Recon',        icon: '🔍' },
  { key: 'scan',         label: 'Scan',         icon: '📡' },
  { key: 'vuln_id',      label: 'Vuln ID',      icon: '🔬' },
  { key: 'osint',        label: 'OSINT',        icon: '🌐' },
  { key: 'exploit',      label: 'Exploit',      icon: '💥' },
  { key: 'post_exploit', label: 'Post Exploit', icon: '🎭' },
  { key: 'privesc',      label: 'PrivEsc',      icon: '⬆'  },
  { key: 'persistence',  label: 'Persistence',  icon: '🔒' },
  { key: 'reporting',    label: 'Reporting',    icon: '📄' },
];

function PhaseTimeline(props) {
  // Accept both old (current/completed) and new (currentPhase/phasesCompleted) prop names
  var active    = props.currentPhase    || props.current    || null;
  var completed = props.phasesCompleted || props.completed  || [];
  var compact   = props.compact || false;

  // Track most-recent active-phase change to drive 1.2s phase-advance flash.
  var _useState  = (typeof React !== 'undefined' && React.useState)  ? React.useState  : null;
  var _useEffect = (typeof React !== 'undefined' && React.useEffect) ? React.useEffect : null;
  var recentlyAdvanced = null;
  var setRecentlyAdvanced = function() {};
  if (_useState && _useEffect) {
    var _ra = _useState(null);
    recentlyAdvanced = _ra[0];
    setRecentlyAdvanced = _ra[1];
    _useEffect(function() {
      if (active) {
        setRecentlyAdvanced(active);
        var id = setTimeout(function() { setRecentlyAdvanced(null); }, 1200);
        return function() { clearTimeout(id); };
      }
    }, [active]);
  }

  function getState(key) {
    if (!key) return 'pending';
    if (completed && completed.includes(key)) return 'done';
    if (key === active) return 'active';
    var ai = _PT_PHASES.findIndex(function(p) { return p.key === active; });
    var ti = _PT_PHASES.findIndex(function(p) { return p.key === key; });
    return (ai > -1 && ti < ai) ? 'done' : 'pending';
  }

  var COLORS = {
    done:    { bg: 'rgba(0,212,255,0.12)', border: 'var(--cyan)',    text: 'var(--cyan)'    },
    active:  { bg: 'rgba(74,222,128,0.10)', border: 'var(--low)',    text: 'var(--low)'     },
    pending: { bg: 'transparent',           border: 'var(--border)', text: 'var(--text-muted)' },
  };

  // ── Compact: horizontal pill strip ─────────────────────────────
  if (compact) {
    return React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', overflowX: 'auto', padding: '2px 0', gap: 4 }
    },
      _PT_PHASES.map(function(phase) {
        var state = getState(phase.key);
        var c = COLORS[state] || COLORS.pending;
        var _cls = 'phase-node' +
          (state === 'active' ? ' motion-breathe' : '') +
          (recentlyAdvanced === phase.key && state === 'active' ? ' motion-phase-advance' : '');
        return React.createElement('div', {
          key: phase.key,
          className: _cls,
          style: {
            display: 'flex', alignItems: 'center', gap: 4,
            padding: '3px 8px', fontSize: 10, whiteSpace: 'nowrap',
            border: '1px solid ' + c.border,
            borderRadius: 5,
            background: c.bg,
            color: c.text,
            fontFamily: 'var(--font-mono)',
          }
        },
          React.createElement('span', {
            style: {
              width: 5, height: 5, borderRadius: '50%',
              background: c.text, flexShrink: 0,
              boxShadow: state === 'active' ? '0 0 6px ' + c.text : 'none',
            }
          }),
          phase.label,
          state === 'active' && React.createElement('span', null, ' ⟳')
        );
      })
    );
  }

  // ── Full: vertical timeline ─────────────────────────────────────
  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: 0 } },
    _PT_PHASES.map(function(phase, idx) {
      var state   = getState(phase.key);
      var isLast  = idx === _PT_PHASES.length - 1;
      var isDone  = state === 'done';
      var isAct   = state === 'active';
      var dotColor = isDone ? 'var(--cyan)' : isAct ? 'var(--low)' : 'var(--border)';
      var txtColor = isDone ? 'var(--cyan)' : isAct ? 'var(--low)' : 'var(--text-muted)';

      var _cls = 'phase-node' +
        (isAct ? ' motion-breathe' : '') +
        (recentlyAdvanced === phase.key && isAct ? ' motion-phase-advance' : '');
      return React.createElement('div', {
        key: phase.key,
        className: _cls,
        style: { display: 'flex', alignItems: 'flex-start', gap: 10 }
      },
        // Dot + line
        React.createElement('div', {
          style: { display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }
        },
          React.createElement('div', {
            style: {
              width: 12, height: 12, borderRadius: '50%', marginTop: 2,
              background: dotColor, border: '2px solid ' + dotColor,
              boxShadow: isAct ? '0 0 8px ' + dotColor : 'none',
            }
          }),
          !isLast && React.createElement('div', {
            style: { width: 2, height: 28, marginTop: 2, background: isDone ? dotColor : 'var(--border)' }
          })
        ),
        // Label
        React.createElement('div', { style: { paddingBottom: isLast ? 0 : 18, flex: 1 } },
          React.createElement('div', {
            style: {
              display: 'flex', alignItems: 'center', gap: 6,
              color: txtColor, fontWeight: isAct ? 600 : 400, fontSize: 12,
            }
          },
            React.createElement('span', null, phase.icon || ''),
            React.createElement('span', { style: { fontFamily: 'var(--font-mono)', letterSpacing: 0.5 } },
              (phase.label || phase.key || '').toUpperCase()
            ),
            React.createElement('span', {
              style: {
                marginLeft: 'auto', fontSize: 9, padding: '1px 6px', borderRadius: 4,
                background: isDone ? 'rgba(0,212,255,0.12)' : isAct ? 'rgba(74,222,128,0.12)' : 'transparent',
                border: '1px solid ' + (isDone ? 'rgba(0,212,255,0.3)' : isAct ? 'rgba(74,222,128,0.3)' : 'transparent'),
                color: isDone ? 'var(--cyan)' : isAct ? 'var(--low)' : 'transparent',
              }
            }, isDone ? 'DONE' : isAct ? 'ACTIVE' : '')
          )
        )
      );
    })
  );
}

window.PhaseTimeline = PhaseTimeline;
