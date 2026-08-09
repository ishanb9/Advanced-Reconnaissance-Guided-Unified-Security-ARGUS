// ═══════════════════════════════════════════════════════════════════════════
// MissionBriefBanner.jsx — Improvements #1 + #2
// Permanent header showing the formal mission brief and live win-condition
// tracker progress.  Always visible on Mission Control while a scan is active.
// ═══════════════════════════════════════════════════════════════════════════

const { useMemo } = React;

function MissionBriefBanner() {
  const { state } = window.useStore();
  const brief = state.missionBrief;
  const wc    = state.winConditions || {};

  if (!brief && (!wc.conditions || wc.conditions.length === 0)) return null;

  const blastColors = {
    passive:     '#4ade80',
    active:      '#fbbf24',
    destructive: '#ef4444',
  };
  const blast = (brief?.blast_radius || 'active').toLowerCase();
  const blastColor = blastColors[blast] || '#9ca3af';

  const progress = wc.progress_pct || 0;
  const achieved = wc.achieved_count || 0;
  const total    = wc.total || 0;
  const allDone  = !!wc.all_achieved;

  const barColor = allDone
    ? '#4ade80'
    : progress >= 66 ? '#22d3ee'
    : progress >= 33 ? '#fbbf24'
    : '#E8435A';

  return React.createElement('div', { 'data-slot': 'MissionBriefBanner.MissionBriefBanner',
    style: {
      borderRadius: 10,
      border: `1px solid ${allDone ? 'rgba(74,222,128,0.4)' : 'rgba(232,67,90,0.30)'}`,
      background: allDone
        ? 'linear-gradient(135deg, rgba(74,222,128,0.08), rgba(34,211,238,0.04))'
        : 'linear-gradient(135deg, rgba(232,67,90,0.06), rgba(0,0,0,0.0))',
      padding: '12px 16px',
      marginBottom: 12,
    }
  },
    // Header row: badge + objective + blast radius
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8, flexWrap: 'wrap' }
    },
      React.createElement('span', {
        style: {
          fontSize: 10, fontWeight: 700, letterSpacing: 0.8,
          padding: '3px 8px', borderRadius: 4,
          background: 'rgba(232,67,90,0.15)', color: '#E8435A',
          border: '1px solid rgba(232,67,90,0.4)', fontFamily: 'var(--font-mono)',
        }
      }, '🎖 MISSION BRIEF'),
      React.createElement('span', {
        style: { fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', flex: 1, minWidth: 200 }
      }, brief?.objective || '(no objective set)'),
      brief && React.createElement('span', {
        title: 'Blast radius',
        style: {
          fontSize: 9, padding: '2px 7px', borderRadius: 3,
          color: blastColor, border: `1px solid ${blastColor}50`,
          background: blastColor + '12', fontFamily: 'var(--font-mono)', fontWeight: 700,
        }
      }, `BLAST: ${blast.toUpperCase()}`),
      brief && React.createElement('span', {
        title: 'Time budget',
        style: {
          fontSize: 9, padding: '2px 7px', borderRadius: 3, color: 'var(--text-muted)',
          border: '1px solid var(--border)', fontFamily: 'var(--font-mono)',
        }
      }, brief.time_budget_min ? `⏱ ${brief.time_budget_min} min` : '⏱ unlimited'),
      brief && React.createElement('span', {
        title: 'Noise budget',
        style: {
          fontSize: 9, padding: '2px 7px', borderRadius: 3, color: 'var(--text-muted)',
          border: '1px solid var(--border)', fontFamily: 'var(--font-mono)',
        }
      }, `🔊 ${brief.noise_budget ?? '?'}/100`),
    ),

    // Progress row
    total > 0 && React.createElement('div', null,
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }
      },
        React.createElement('div', {
          style: { fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: 0.5 }
        }, `WIN CONDITIONS  ${achieved}/${total}`),
        React.createElement('div', { style: { flex: 1 } }),
        React.createElement('div', {
          style: { fontSize: 11, fontWeight: 700, color: barColor, fontFamily: 'var(--font-mono)' }
        }, `${progress}%`),
        allDone && React.createElement('span', {
          style: {
            fontSize: 9, padding: '1px 7px', borderRadius: 3,
            color: '#4ade80', background: 'rgba(74,222,128,0.15)',
            border: '1px solid rgba(74,222,128,0.4)', fontWeight: 700, letterSpacing: 0.6,
          }
        }, '🏁 COMPLETE')
      ),
      // Progress bar
      React.createElement('div', {
        style: {
          height: 6, borderRadius: 3, background: 'var(--bg-elevated)',
          overflow: 'hidden', position: 'relative',
        }
      },
        React.createElement('div', {
          style: {
            width: `${Math.max(0, Math.min(100, progress))}%`,
            height: '100%', background: barColor,
            transition: 'width 0.4s ease, background 0.4s ease',
            boxShadow: `0 0 8px ${barColor}80`,
          }
        })
      ),
      // Condition chips
      React.createElement('div', {
        style: { display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 8 }
      },
        wc.conditions.map((c, i) =>
          React.createElement('div', {
            key: i,
            title: c.evidence || (c.achieved ? 'achieved' : 'pending'),
            style: {
              display: 'flex', alignItems: 'center', gap: 5,
              fontSize: 10, padding: '2px 7px', borderRadius: 3,
              fontFamily: 'var(--font-mono)',
              color: c.achieved ? '#4ade80' : 'var(--text-muted)',
              background: c.achieved ? 'rgba(74,222,128,0.10)' : 'rgba(255,255,255,0.02)',
              border: `1px solid ${c.achieved ? 'rgba(74,222,128,0.35)' : 'var(--border)'}`,
            }
          },
            React.createElement('span', null, c.achieved ? '✓' : '○'),
            React.createElement('span', null, c.name)
          )
        )
      )
    )
  );
}

window.MissionBriefBanner = MissionBriefBanner;
