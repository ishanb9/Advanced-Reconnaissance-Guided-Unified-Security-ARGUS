// StatusBadge — system/agent status indicator
function StatusBadge({ status, label, size = 'sm', pulseSupernova }) {
  const colors = {
    online:   'var(--green)',
    running:  'var(--green)',
    active:   'var(--green)',
    offline:  'var(--red)',
    error:    'var(--red)',
    failed:   'var(--red)',
    thinking: 'var(--cyan)',
    idle:     'var(--border)',
    unknown:  'var(--amber)',
    paused:   'var(--amber)',
  };
  const color = colors[status] || colors.unknown;
  const text  = label || status || 'unknown';
  const cls   = 'status-badge' + (pulseSupernova ? ' motion-supernova' : '');

  return React.createElement('span', {
    className: cls,
    style: {
      display:     'inline-flex',
      alignItems:  'center',
      gap:         4,
      fontSize:    size === 'sm' ? 10 : 12,
      color,
      fontFamily:  'var(--font-mono)',
      borderRadius: 4,
    }
  },
    React.createElement('span', {
      style: {
        width:      6, height: 6, borderRadius: '50%',
        background: color, flexShrink: 0,
        boxShadow:  ['running','online','active','thinking'].includes(status)
                    ? `0 0 6px ${color}` : 'none',
      }
    }),
    text.toUpperCase()
  );
}
window.StatusBadge = StatusBadge;
