// AgentCard — standalone agent status card
// (Full implementation lives in MissionControl.jsx — this is available globally too)
const AGENT_META_GLOBAL = {
  master:  { icon: '⚡', color: 'var(--cyan)',   label: 'Master'  },
  recon:   { icon: '🔍', color: 'var(--green)',  label: 'Recon'   },
  vuln:    { icon: '🔬', color: 'var(--amber)',  label: 'Vuln'    },
  web:     { icon: '🌐', color: 'var(--cyan)',   label: 'Web'     },
  osint:   { icon: '🕵', color: 'var(--violet)',  label: 'OSINT'   },
  exploit: { icon: '💥', color: 'var(--red)',    label: 'Exploit' },
  privesc: { icon: '🔑', color: 'var(--high)',   label: 'Privesc' },
  shell:   { icon: '🐚', color: 'var(--cyan)',   label: 'Shell'   },
  payload: { icon: '📦', color: 'var(--amber)',  label: 'Payload' },
};

function AgentCardGlobal({ name, status = 'idle', phase, message, onClick }) {
  const meta     = AGENT_META_GLOBAL[name] || { icon: '◆', color: 'var(--cyan)', label: name };
  const isActive = status === 'running' || status === 'thinking';
  const isThinking = status === 'thinking';
  const statusColors = {
    running:  'var(--green)',
    thinking: 'var(--cyan)',
    done:     'var(--cyan)',
    error:    'var(--red)',
    idle:     'var(--border)',
  };
  const dotColor = statusColors[status] || 'var(--border)';

  return React.createElement('div', { 'data-slot': 'AgentCard.AgentCardGlobal',
    onClick,
    style: {
      padding:    '9px 12px',
      borderRadius: 7,
      cursor:     onClick ? 'pointer' : 'default',
      border:     `1px solid ${isActive ? meta.color : 'var(--border)'}`,
      background: isActive ? `${meta.color}08` : 'var(--bg-surface)',
      transition: 'all 0.2s',
      position:   'relative',
      overflow:   'hidden',
    }
  },
    isActive && React.createElement('div', {
      style: {
        position:  'absolute', top: 0, left: 0, right: 0, height: 2,
        background: meta.color, boxShadow: `0 0 8px ${meta.color}`,
        animation: 'pulse 1.5s infinite',
      }
    }),
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: 7, marginBottom: 3 }
    },
      React.createElement('span', {
        className: 'agent-avatar' + (isThinking ? ' motion-llm-ring' : ''),
        style: {
          fontSize: 14,
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 18, height: 18, lineHeight: 1,
        }
      }, meta.icon),
      React.createElement('span', {
        style: { fontSize: 10, fontWeight: 700, color: meta.color, letterSpacing: 0.5 }
      }, meta.label.toUpperCase()),
      React.createElement('span', {
        style: {
          marginLeft: 'auto', fontSize: 8, padding: '1px 5px', borderRadius: 3,
          background: isActive ? `${dotColor}20` : 'transparent',
          color: dotColor, border: `1px solid ${isActive ? dotColor : 'var(--border-light)'}`,
          fontFamily: 'var(--font-mono)',
        }
      }, status.toUpperCase())
    ),
    React.createElement('div', {
      style: {
        fontSize: 10, color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
        fontFamily: 'var(--font-mono)', overflow: 'hidden',
        textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }
    }, message || 'Idle'),
    phase && React.createElement('div', {
      style: { fontSize: 8, color: 'var(--text-muted)', marginTop: 1, fontFamily: 'var(--font-mono)' }
    }, phase.toUpperCase())
  );
}
window.AgentCard = AgentCardGlobal;
