// FindingCard — one finding row with severity badge and CVEs
function FindingCard({ finding, compact }) {
  const { severity, title, host, port, service, cves = [], tool_used, found_at } = finding;
  const ts = found_at ? new Date(found_at).toLocaleTimeString() : '';

  if (compact) {
    return React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--border)' }
    },
      React.createElement('span', { className: `sev-badge ${severity}` }, severity),
      React.createElement('span', { style: { flex: 1, fontSize: 12 } }, title),
      React.createElement('span', { style: { fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } },
        `${host}${port ? ':' + port : ''}`)
    );
  }

  return React.createElement('div', { style: { padding: '10px 0', borderBottom: '1px solid var(--border)' } },
    React.createElement('div', { style: { display: 'flex', alignItems: 'flex-start', gap: 10 } },
      React.createElement('span', { className: `sev-badge ${severity}` }, severity),
      React.createElement('div', { style: { flex: 1 } },
        React.createElement('div', { style: { fontWeight: 600, fontSize: 13, marginBottom: 4 } }, title),
        React.createElement('div', {
          style: { fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: 6 }
        }, `${host}${port ? ':' + port : ''}${service ? ' · ' + service : ''}${tool_used ? ' · ' + tool_used : ''}`),
        cves.length > 0 && React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 4 } },
          cves.map(cve => React.createElement('span', {
            key: cve, className: 'cve-badge',
            onClick: () => window.open(`https://nvd.nist.gov/vuln/detail/${cve}`, '_blank')
          }, cve))
        )
      ),
      React.createElement('span', { style: { fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' } }, ts)
    )
  );
}
window.FindingCard = FindingCard;
// PhaseTimeline intentionally NOT defined here — lives in PhaseTimeline.jsx only
