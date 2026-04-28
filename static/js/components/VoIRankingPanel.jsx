// ═══════════════════════════════════════════════════════════════════════════
// VoIRankingPanel.jsx — Improvement #3
// Live Value-of-Information ranking of candidate actions.  Shows operator the
// top-N actions the DecisionEngine considered, why each scored what it did,
// and which one was finally chosen.
// ═══════════════════════════════════════════════════════════════════════════

function VoIRankingPanel() {
  const { state } = window.useStore();
  const top = (state.voiRanking && state.voiRanking.top) || [];

  if (!top || top.length === 0) return null;

  const scoreColor = (s) => {
    if (s == null) return '#9ca3af';
    if (s >= 30)   return '#10b981';     // green
    if (s >= 10)   return '#22d3ee';     // cyan
    if (s >= 0)    return '#fbbf24';     // amber
    return '#ef4444';                    // red
  };

  return (
    <div style={{
      background:    'rgba(15, 23, 42, 0.55)',
      border:        '1px solid rgba(56, 189, 248, 0.20)',
      borderRadius:  10,
      padding:       '12px 14px',
      margin:        '12px 0',
      fontFamily:    "'Inter', sans-serif",
    }}>
      <div style={{
        display:        'flex',
        alignItems:     'center',
        justifyContent: 'space-between',
        marginBottom:   8,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: '#e2e8f0' }}>
            🎯 Action Ranking — Value of Information
          </span>
          <span style={{
            fontSize:    11,
            color:       '#94a3b8',
            background:  'rgba(56, 189, 248, 0.10)',
            padding:     '2px 8px',
            borderRadius: 8,
          }}>
            top {top.length}
          </span>
        </div>
        <span style={{ fontSize: 11, color: '#64748b' }}>
          chosen: <strong style={{ color: '#10b981' }}>#1</strong>
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {top.map((a, i) => {
          const isPicked = i === 0 && !a.voi_dropped;
          return (
            <div key={i} style={{
              display:       'grid',
              gridTemplateColumns: '36px 1fr auto',
              gap:           10,
              alignItems:    'center',
              padding:       '8px 10px',
              background:    isPicked
                              ? 'rgba(16, 185, 129, 0.08)'
                              : 'rgba(30, 41, 59, 0.45)',
              border:        isPicked
                              ? '1px solid rgba(16, 185, 129, 0.35)'
                              : '1px solid rgba(71, 85, 105, 0.25)',
              borderRadius:  6,
              fontSize:      12,
            }}>
              <div style={{
                fontFamily:  "'JetBrains Mono', monospace",
                fontWeight:  600,
                fontSize:    14,
                color:       scoreColor(a.voi_score),
                textAlign:   'center',
              }}>
                {a.voi_dropped ? '×' : (a.voi_score ?? '?')}
              </div>
              <div>
                <div style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  color:      '#e2e8f0',
                  fontSize:   12,
                }}>
                  <strong>{a.tool || '?'}</strong>
                  {a.target_service ? <span style={{ color: '#64748b' }}> → {a.target_service}</span> : null}
                  {a.args ? <span style={{ color: '#475569' }}> {String(a.args).slice(0, 60)}</span> : null}
                </div>
                {a.voi_reasons && a.voi_reasons.length > 0 ? (
                  <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 2 }}>
                    {a.voi_reasons.slice(0, 3).join(' · ')}
                  </div>
                ) : null}
              </div>
              <div style={{
                fontSize:   10,
                color:      '#64748b',
                textAlign:  'right',
                whiteSpace: 'nowrap',
              }}>
                {typeof a.confidence === 'number'
                  ? `conf ${a.confidence.toFixed(2)}`
                  : ''}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

window.VoIRankingPanel = VoIRankingPanel;
