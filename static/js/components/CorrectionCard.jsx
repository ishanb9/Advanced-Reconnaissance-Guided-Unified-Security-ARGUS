// CorrectionCard.jsx — Expandable correction card from meta-agents.
// Fully custom dark-theme design — no Ant Design components.
'use strict';

function CorrectionCard({ correction }) {
  const [expanded, setExpanded] = React.useState(false);
  if (!correction) return null;

  const isBlocking = correction.tier === 'blocking';
  const tierColor  = isBlocking ? 'var(--critical)' : 'var(--medium)';
  const tierBg     = isBlocking ? 'var(--critical-bg)' : 'rgba(245,200,66,0.10)';
  const tierBd     = isBlocking ? 'var(--critical-bd)' : 'rgba(245,200,66,0.28)';
  const pct        = ((correction.confidence || 0) * 100).toFixed(0);
  const ts         = correction.timestamp
    ? new Date(correction.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '';

  return React.createElement('div', { 'data-slot': 'CorrectionCard.CorrectionCard',
    onClick: () => setExpanded(e => !e),
    style: {
      background:   'var(--bg-panel)',
      borderRadius: '0 var(--radius) var(--radius) 0',
      borderTop:    '1px solid var(--border)',
      borderRight:  '1px solid var(--border)',
      borderBottom: '1px solid var(--border)',
      borderLeft:   `3px solid ${tierColor}`,
      marginBottom: 5,
      cursor:       'pointer',
      transition:   'background 0.15s',
      overflow:     'hidden',
    },
  },

    // ── Header ────────────────────────────────────────────────────
    React.createElement('div', {
      style: { padding: '7px 10px 5px' }
    },
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }
      },
        // Tier badge
        React.createElement('span', {
          style: {
            fontSize: 8, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: 0.8, fontFamily: 'var(--font-mono)',
            background: tierBg, color: tierColor, border: `1px solid ${tierBd}`,
            borderRadius: 3, padding: '1px 6px',
          }
        }, isBlocking ? '⛔ Blocking' : '💡 Advisory'),

        // Issue type tag
        correction.issue_type && React.createElement('span', {
          style: {
            fontSize: 8, fontFamily: 'var(--font-mono)',
            color: 'var(--text-muted)', background: 'var(--bg-elevated)',
            border: '1px solid var(--border)', borderRadius: 3, padding: '1px 5px',
          }
        }, correction.issue_type),

        // Confidence + timestamp pushed right
        React.createElement('div', {
          style: { marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 5 }
        },
          // Confidence mini-bar
          React.createElement('div', {
            style: {
              width: 32, height: 3, borderRadius: 2,
              background: 'var(--border)', overflow: 'hidden',
            }
          },
            React.createElement('div', {
              style: {
                width: `${pct}%`, height: '100%',
                background: tierColor, borderRadius: 2,
                transition: 'width 0.4s ease',
              }
            })
          ),
          React.createElement('span', {
            style: {
              fontSize: 8, fontFamily: 'var(--font-mono)',
              fontWeight: 600, color: tierColor,
            }
          }, `${pct}%`),
          ts && React.createElement('span', {
            style: { fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }
          }, `· ${ts}`),
          React.createElement('span', {
            style: {
              fontSize: 8, color: 'var(--text-muted)',
              transform: expanded ? 'rotate(180deg)' : 'none',
              display: 'inline-block', transition: 'transform 0.2s',
            }
          }, '▾'),
        ),
      ),

      // Description
      React.createElement('div', {
        style: {
          fontSize: 11, color: 'var(--text-secondary)',
          marginTop: 4, lineHeight: 1.5,
        }
      }, correction.description || ''),
    ),

    // ── Expanded detail ───────────────────────────────────────────
    expanded && React.createElement('div', {
      style: {
        padding: '8px 10px 8px',
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-base)',
      }
    },
      React.createElement('div', {
        style: {
          fontSize: 8, fontWeight: 700, color: 'var(--cyan)',
          textTransform: 'uppercase', letterSpacing: 0.8,
          fontFamily: 'var(--font-mono)', marginBottom: 5,
        }
      }, '▸ Recommended Action'),

      React.createElement('div', {
        style: {
          fontSize: 10, color: 'var(--text-primary)',
          whiteSpace: 'pre-wrap', lineHeight: 1.6,
          background: 'var(--bg-panel)',
          border: '1px solid var(--border)',
          borderRadius: 4, padding: '6px 8px',
          fontFamily: 'var(--font-mono)',
        }
      }, correction.recommended_action || '(none)'),

      correction.affected_finding_ids && correction.affected_finding_ids.length > 0 &&
        React.createElement('div', {
          style: { marginTop: 6, display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }
        },
          React.createElement('span', {
            style: {
              fontSize: 8, color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
              letterSpacing: 0.6,
            }
          }, 'Affected:'),
          ...correction.affected_finding_ids.map((id, i) =>
            React.createElement('span', {
              key: i,
              style: {
                fontSize: 8, fontFamily: 'var(--font-mono)',
                color: 'var(--cyan)',
                background: 'var(--cyan-glow)',
                border: '1px solid rgba(56,189,248,0.2)',
                borderRadius: 3, padding: '1px 5px',
              }
            }, id)
          ),
        ),
    ),
  );
}
window.CorrectionCard = CorrectionCard;
