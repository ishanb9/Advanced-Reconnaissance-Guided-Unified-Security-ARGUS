// CorrectionCard.jsx — Expandable card showing one meta-agent correction.
// Used inside MetaAgentsPanel.
'use strict';

function CorrectionCard({ correction }) {
  const [expanded, setExpanded] = React.useState(false);
  if (!correction) return null;

  const isBlocking  = correction.tier === 'blocking';
  const icon        = isBlocking ? '⛔' : '💡';
  const borderColor = isBlocking ? 'var(--red)' : 'var(--amber)';
  const badgeColor  = isBlocking ? '#ff4d4f' : '#faad14';
  const pct         = ((correction.confidence || 0) * 100).toFixed(0);
  const ts          = correction.timestamp
    ? new Date(correction.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '';

  return React.createElement('div', {
    style: {
      borderLeft:   `3px solid ${borderColor}`,
      background:   'var(--bg-surface)',
      borderRadius: 'var(--radius)',
      padding:      '8px 12px',
      marginBottom: 6,
      cursor:       'pointer',
    },
    onClick: () => setExpanded(e => !e),
  },
    // Header row
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }
    },
      React.createElement('span', { style: { fontSize: 14 } }, icon),
      React.createElement('span', {
        style: {
          fontSize:      10,
          background:    badgeColor,
          color:         '#fff',
          borderRadius:  3,
          padding:       '1px 5px',
          fontWeight:    600,
          textTransform: 'uppercase',
        }
      }, correction.tier),
      React.createElement('span', {
        style: {
          fontSize:     10,
          color:        'var(--text-muted)',
          background:   'var(--bg-card)',
          borderRadius: 3,
          padding:      '1px 5px',
        }
      }, correction.issue_type || ''),
      React.createElement('span', {
        style: { fontSize: 10, color: 'var(--text-muted)', marginLeft: 'auto' }
      }, `${pct}% conf${ts ? ' · ' + ts : ''}`),
    ),

    // Description (always visible)
    React.createElement('div', {
      style: { fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }
    }, correction.description || ''),

    // Expanded: recommended action + affected finding IDs
    expanded && React.createElement('div', {
      style: {
        marginTop:  8,
        paddingTop: 8,
        borderTop:  '1px solid var(--border)',
        fontSize:   11,
      }
    },
      React.createElement('div', {
        style: { color: 'var(--cyan)', fontWeight: 600, marginBottom: 4 }
      }, '▸ Recommended action'),
      React.createElement('div', {
        style: { color: 'var(--text-primary)', whiteSpace: 'pre-wrap' }
      }, correction.recommended_action || '(none)'),

      correction.affected_finding_ids && correction.affected_finding_ids.length > 0 &&
        React.createElement('div', { style: { marginTop: 8 } },
          React.createElement('span', {
            style: { color: 'var(--text-muted)', fontSize: 10 }
          }, `Affected findings: ${correction.affected_finding_ids.join(', ')}`),
        ),
    ),
  );
}
window.CorrectionCard = CorrectionCard;
