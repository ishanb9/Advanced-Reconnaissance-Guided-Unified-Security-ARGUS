// LiveTerminal — scrolling terminal output component
// Used by AgentConsole and MissionControl for live tool output
const { useEffect, useRef } = React;

function LiveTerminal({ lines = [], height = 280, agentColor = 'var(--green)', title = '' }) {
  const ref = useRef(null);

  // Auto-scroll to bottom on new lines
  useEffect(() => {
    if (ref.current) {
      ref.current.scrollTop = ref.current.scrollHeight;
    }
  }, [lines.length]);

  return React.createElement('div', {
    className: 'motion-scanline',
    style: {
      height,
      overflowY:   'auto',
      fontFamily:  'var(--font-mono)',
      fontSize:    10,
      lineHeight:  1.6,
      background:  'var(--bg-surface)',
      borderRadius: 'var(--radius)',
      border:       '1px solid var(--border)',
      padding:     '8px 10px',
    },
    ref,
  },
    title && React.createElement('div', {
      style: {
        fontSize:     9,
        color:        agentColor,
        marginBottom: 4,
        paddingBottom: 4,
        borderBottom: '1px solid var(--border)',
        letterSpacing: 0.5,
        textTransform: 'uppercase',
      }
    }, `▸ ${title}`),

    lines.length === 0
      ? React.createElement('span', { style: { color: 'var(--text-muted)' } }, '— no output —')
      : lines.slice(-500).map((l, i) => {
          const lineText  = typeof l === 'string' ? l : (l.line || l.text || '');
          const lineType  = typeof l === 'object' ? (l.type || 'stdout') : 'stdout';
          const lineColor = lineType === 'stderr'
            ? 'var(--red)'
            : lineText.startsWith('[+]') || lineText.startsWith('[*]')
            ? agentColor
            : lineText.startsWith('[-]') || lineText.startsWith('[!]')
            ? 'var(--medium)'
            : 'var(--text-secondary)';

          return React.createElement('div', {
            key:   i,
            style: { color: lineColor, wordBreak: 'break-all', lineHeight: 1.5 }
          }, lineText);
        })
  );
}
window.LiveTerminal = LiveTerminal;
