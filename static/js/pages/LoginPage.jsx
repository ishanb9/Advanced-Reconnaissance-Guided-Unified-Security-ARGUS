/* ═══════════════════════════════════════════════════════════════
   LoginPage — cinematic first-impression for ARGUS
   ───────────────────────────────────────────────────────────────
   This is the landing page operators see before authentication.
   Visually it has to match the cockpit's "Stellar Ops" / Apollo /
   Tactical / Glass / WebGL aesthetic — anything less is a downgrade
   from the rest of the UI.

   Composition:
     Layer 0  — animated radial gradient mesh background
     Layer 1  — canvas particle network (150 drifting nodes
                with connections drawn when close)
     Layer 2  — scan-line + film-grain overlay (subtle)
     Layer 3  — glass card with frosted backdrop-filter
                  • ARGUS wordmark with chromatic split + soft pulse glow
                  • Status telemetry strip (MCP / Vector DB / TLS)
                  • Tabs: Local / Single Sign-On
                  • Inputs with bottom-border focus animation
                  • Primary button with hover lift + glow
                  • Per-error gentle shake
     Layer 4  — version + commit + environment chips bottom-left

   Skin-aware: every colour uses CSS custom properties from the
   active skin.  When a skin is loaded, the login page automatically
   re-themes (Apollo phosphor on Apollo, Bloomberg amber on Bloomberg,
   etc.).
   ─────────────────────────────────────────────────────────────── */
(function () {
  const { useState, useEffect, useRef, useCallback } = React;

  // ── Animated particle-network canvas ────────────────────────
  function ParticleField() {
    const canvasRef = useRef(null);
    const rafRef = useRef(null);

    useEffect(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      let w = 0, h = 0;
      const PARTICLE_COUNT = reduce ? 40 : 130;
      const MAX_DIST = 140;
      let particles = [];

      function resize() {
        const dpr = Math.min(2, window.devicePixelRatio || 1);
        w = canvas.width  = Math.floor(window.innerWidth * dpr);
        h = canvas.height = Math.floor(window.innerHeight * dpr);
        canvas.style.width  = window.innerWidth + 'px';
        canvas.style.height = window.innerHeight + 'px';
        ctx.scale(1, 1);
      }
      resize();
      window.addEventListener('resize', resize);

      function spawn() {
        particles = [];
        for (let i = 0; i < PARTICLE_COUNT; i++) {
          particles.push({
            x:  Math.random() * w,
            y:  Math.random() * h,
            vx: (Math.random() - 0.5) * 0.4,
            vy: (Math.random() - 0.5) * 0.4,
            r:  0.6 + Math.random() * 1.4,
          });
        }
      }
      spawn();

      // Read accent colour from CSS variables so the field re-themes
      // when a skin is applied.  Cached, refreshed on each frame.
      const styles = getComputedStyle(document.documentElement);
      function accentRgb() {
        const raw = (styles.getPropertyValue('--accent') || '#4FA8FF').trim();
        const m = raw.match(/#([0-9a-f]{3,6})/i);
        if (!m) return [79, 168, 255];
        let hex = m[1];
        if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
        return [
          parseInt(hex.slice(0, 2), 16),
          parseInt(hex.slice(2, 4), 16),
          parseInt(hex.slice(4, 6), 16),
        ];
      }

      function frame() {
        rafRef.current = requestAnimationFrame(frame);
        ctx.clearRect(0, 0, w, h);

        const [ar, ag, ab] = accentRgb();
        const max2 = MAX_DIST * MAX_DIST;

        // Move
        for (const p of particles) {
          p.x += p.vx;
          p.y += p.vy;
          if (p.x < 0) p.x = w; else if (p.x > w) p.x = 0;
          if (p.y < 0) p.y = h; else if (p.y > h) p.y = 0;
        }

        // Draw connection lines (only where close)
        ctx.lineWidth = 1;
        for (let i = 0; i < particles.length; i++) {
          for (let j = i + 1; j < particles.length; j++) {
            const a = particles[i], b = particles[j];
            const dx = a.x - b.x, dy = a.y - b.y;
            const d2 = dx * dx + dy * dy;
            if (d2 > max2) continue;
            const alpha = (1 - d2 / max2) * 0.28;
            ctx.strokeStyle = `rgba(${ar}, ${ag}, ${ab}, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }

        // Draw nodes
        for (const p of particles) {
          ctx.fillStyle = `rgba(${ar}, ${ag}, ${ab}, 0.65)`;
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      if (!reduce) rafRef.current = requestAnimationFrame(frame);
      else { // single-frame for reduced motion
        ctx.fillStyle = 'rgba(79, 168, 255, 0.25)';
        for (const p of particles) {
          ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
        }
      }

      return () => {
        cancelAnimationFrame(rafRef.current);
        window.removeEventListener('resize', resize);
      };
    }, []);

    return React.createElement('canvas', {
      ref: canvasRef,
      className: 'auth-stage-particles',
      'aria-hidden': 'true',
    });
  }

  // ── System status strip ─────────────────────────────────────
  function StatusStrip() {
    const [stats, setStats] = useState({
      mcp: 'checking', vector: 'checking', tls: 'ok',
      build: 'v3.0.0', env: 'unknown',
    });

    useEffect(() => {
      // Cheap probes — these endpoints exist on ARGUS already
      const probes = [
        fetch('/api/system/status').then(r => r.ok ? r.json() : {}).catch(() => ({})),
        fetch('/healthz/auth').then(r => ({ ok: r.ok })).catch(() => ({ ok: false })),
      ];
      Promise.all(probes).then(([sys, auth]) => {
        setStats(s => ({
          ...s,
          mcp:    (sys?.mcp || sys?.status === 'ok') ? 'ok' : 'warn',
          vector: (sys?.knowledge_ready || sys?.rag) ? 'ok' : 'warn',
          tls:    location.protocol === 'https:' ? 'ok' : 'dev',
          env:    sys?.env || (window.location.hostname === 'localhost' ? 'dev' : 'prod'),
        }));
      });
    }, []);

    const dot = (state) => {
      const color = state === 'ok' ? 'var(--low)'
                   : state === 'warn' ? 'var(--medium)'
                   : state === 'dev' ? 'var(--cyan)'
                   : 'var(--text-muted)';
      return React.createElement('span', {
        className: 'auth-status-dot',
        style: { background: color, boxShadow: `0 0 6px ${color}` },
      });
    };

    return React.createElement('div', { className: 'auth-status-strip' },
      React.createElement('span', { className: 'auth-status-item' }, dot(stats.mcp), 'MCP'),
      React.createElement('span', { className: 'auth-status-item' }, dot(stats.vector), 'VECTOR DB'),
      React.createElement('span', { className: 'auth-status-item' }, dot(stats.tls), 'TLS'),
      React.createElement('span', { className: 'auth-status-item' }, dot('ok'),
        'BUILD ', stats.build),
      React.createElement('span', { className: 'auth-status-item' }, dot('ok'),
        'ENV ', String(stats.env).toUpperCase()),
    );
  }

  // ── Typewriter tagline ───────────────────────────────────────
  function Typewriter({ text, speed = 38, cursor = true }) {
    const [shown, setShown] = useState('');
    useEffect(() => {
      let i = 0; setShown('');
      const id = setInterval(() => {
        i += 1;
        setShown(text.slice(0, i));
        if (i >= text.length) clearInterval(id);
      }, speed);
      return () => clearInterval(id);
    }, [text, speed]);
    return React.createElement('span', null,
      shown,
      cursor && React.createElement('span', { className: 'auth-cursor' }, '▌'),
    );
  }

  // ── Main LoginPage ───────────────────────────────────────────
  function LoginPage({ onSuccess }) {
    const [tab, setTab] = useState('local');
    const [providers, setProviders] = useState([]);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const [mfaToken, setMfaToken] = useState(null);
    const [factorTypes, setFactorTypes] = useState([]);
    const [shake, setShake] = useState(false);
    const cardRef = useRef(null);

    useEffect(() => {
      fetch('/auth/sso/providers')
        .then(r => r.ok ? r.json() : [])
        .then(setProviders)
        .catch(() => setProviders([]));
      const params = new URLSearchParams(window.location.search);
      const mt = params.get('mfa_token');
      if (mt) setMfaToken(mt);
    }, []);

    const triggerShake = useCallback(() => {
      setShake(true);
      setTimeout(() => setShake(false), 460);
    }, []);

    async function doLogin(e) {
      e.preventDefault();
      setError(null); setBusy(true);
      try {
        const r = await fetch('/auth/login', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        const data = await r.json().catch(() => ({}));
        if (r.status === 200 && data.access_token) {
          window.localStorage.setItem('argus.access_token', data.access_token);
          // Fade out before reload for smooth handoff
          cardRef.current && cardRef.current.classList.add('auth-card-success');
          setTimeout(() => onSuccess ? onSuccess() : window.location.reload(), 380);
          return;
        }
        if (r.status === 200 && data.status === 'mfa_required') {
          setMfaToken(data.mfa_token);
          setFactorTypes(data.factor_types || []);
          return;
        }
        if (data.code === 'mfa_enrolment_required') {
          setError('Multi-factor authentication is required for your role. ' +
                   'Contact a Platform Administrator to enrol your first factor.');
          triggerShake();
          return;
        }
        setError(data.detail || data.message || 'Sign-in failed.');
        triggerShake();
      } catch (err) {
        setError('Network error: ' + String(err));
        triggerShake();
      } finally {
        setBusy(false);
      }
    }

    // MFA challenge takes over
    if (mfaToken) {
      return React.createElement(window.MfaChallenge, {
        mfaToken, factorTypes,
        onSuccess: () => onSuccess ? onSuccess() : window.location.reload(),
        onCancel: () => { setMfaToken(null); setFactorTypes([]); },
      });
    }

    return React.createElement('div', { className: 'auth-stage' },
      // Layer 0 — gradient mesh background (CSS, no JS)
      React.createElement('div', { className: 'auth-stage-mesh', 'aria-hidden': 'true' }),
      // Layer 1 — particle network
      React.createElement(ParticleField),
      // Layer 2 — scan lines + grain overlay (CSS only)
      React.createElement('div', { className: 'auth-stage-overlay', 'aria-hidden': 'true' }),

      // Top status strip
      React.createElement('div', { className: 'auth-status-bar' },
        React.createElement(StatusStrip),
      ),

      // Bottom env chip
      React.createElement('div', { className: 'auth-stage-footnote' },
        '© ARGUS · Advanced Reconnaissance & Guided Unified Security · ',
        React.createElement('a', { href: '/healthz/auth', target: '_blank' }, 'system health'),
      ),

      // Layer 3 — glass card
      React.createElement('div', { className: 'auth-stage-center' },
        React.createElement('div', {
          ref: cardRef,
          className: 'auth-stage-card' + (shake ? ' auth-shake' : ''),
        },
          // Wordmark
          React.createElement('div', { className: 'auth-wordmark-block' },
            React.createElement('div', { className: 'auth-wordmark-mark' },
              React.createElement('svg', { viewBox: '0 0 64 64', width: '52', height: '52',
                'aria-hidden': 'true' },
                React.createElement('circle', { cx: 32, cy: 32, r: 28,
                  fill: 'none', stroke: 'currentColor', strokeWidth: 1, opacity: 0.4 }),
                React.createElement('circle', { cx: 32, cy: 32, r: 18,
                  fill: 'none', stroke: 'currentColor', strokeWidth: 1, opacity: 0.7 }),
                React.createElement('circle', { cx: 32, cy: 32, r: 5,
                  fill: 'currentColor' }),
                React.createElement('line', { x1: 32, y1: 4, x2: 32, y2: 16,
                  stroke: 'currentColor', strokeWidth: 1, opacity: 0.5 }),
                React.createElement('line', { x1: 32, y1: 48, x2: 32, y2: 60,
                  stroke: 'currentColor', strokeWidth: 1, opacity: 0.5 }),
                React.createElement('line', { x1: 4, y1: 32, x2: 16, y2: 32,
                  stroke: 'currentColor', strokeWidth: 1, opacity: 0.5 }),
                React.createElement('line', { x1: 48, y1: 32, x2: 60, y2: 32,
                  stroke: 'currentColor', strokeWidth: 1, opacity: 0.5 }),
              )
            ),
            React.createElement('div', { className: 'auth-wordmark' },
              React.createElement('div', { className: 'auth-wordmark-text',
                'data-text': 'ARGUS' }, 'ARGUS'),
              React.createElement('div', { className: 'auth-wordmark-tagline' },
                React.createElement(Typewriter, {
                  text: 'advanced reconnaissance · guided unified security',
                  speed: 28,
                }),
              ),
            ),
          ),

          // Tabs
          providers.length > 0 && React.createElement('div', { className: 'auth-tabs' },
            React.createElement('button', {
              type: 'button', className: 'auth-tab',
              'data-active': tab === 'local',
              onClick: () => setTab('local'),
            }, 'Credentials'),
            React.createElement('button', {
              type: 'button', className: 'auth-tab',
              'data-active': tab === 'sso',
              onClick: () => setTab('sso'),
            }, `Single Sign-On (${providers.length})`),
          ),

          // Form / SSO
          tab === 'local'
            ? React.createElement('form', { onSubmit: doLogin, className: 'auth-form-stage' },
                React.createElement('div', { className: 'auth-field' },
                  React.createElement('label', null, 'Email address'),
                  React.createElement('input', {
                    type: 'email', autoComplete: 'username', required: true,
                    placeholder: 'operator@argus.local',
                    value: email, onChange: e => setEmail(e.target.value),
                    autoFocus: true,
                  }),
                ),
                React.createElement('div', { className: 'auth-field' },
                  React.createElement('label', null, 'Password'),
                  React.createElement('input', {
                    type: 'password', autoComplete: 'current-password',
                    required: true, placeholder: '••••••••••••',
                    value: password, onChange: e => setPassword(e.target.value),
                  }),
                ),
                error && React.createElement('div', { className: 'auth-error-stage' },
                  React.createElement('span', { 'aria-hidden': 'true' }, '⚠ '),
                  error
                ),
                React.createElement('button', {
                  type: 'submit', disabled: busy,
                  className: 'auth-submit-stage' + (busy ? ' busy' : ''),
                },
                  busy ? React.createElement(OrbitSpinner) : null,
                  React.createElement('span', null,
                    busy ? 'Authenticating' : 'Sign In'),
                  !busy && React.createElement('span', { className: 'auth-submit-arrow' }, '→'),
                ),
              )
            : React.createElement('div', { className: 'auth-sso-stage' },
                providers.length === 0
                  ? React.createElement('div', { className: 'auth-muted' },
                      'No SSO providers configured for this tenant.')
                  : providers.map(p =>
                      React.createElement('a', {
                        key: p.id, className: 'auth-sso-btn-stage',
                        href: p.kind === 'OIDC'
                          ? `/auth/sso/oidc/${p.id}/start`
                          : `/auth/sso/saml/${p.id}/login`,
                      },
                        React.createElement('span', { className: 'auth-sso-kind' }, p.kind),
                        React.createElement('span', { className: 'auth-sso-name' },
                          `Continue with ${p.name}`),
                        React.createElement('span', { className: 'auth-submit-arrow' }, '→'),
                      )
                    )
              ),

          // Footer line
          React.createElement('div', { className: 'auth-card-footer' },
            React.createElement('div', null,
              'Need access? Contact a Platform Administrator.'),
            React.createElement('div', { className: 'auth-secure-badge' },
              React.createElement('span', { 'aria-hidden': 'true' }, '🛡 '),
              'Argon2id · TLS 1.3 · MFA-aware'),
          ),
        ),
      ),
    );
  }

  // ── Orbital spinner ──────────────────────────────────────────
  function OrbitSpinner() {
    return React.createElement('span', { className: 'auth-orbit', 'aria-hidden': 'true' },
      React.createElement('span', { className: 'auth-orbit-ring' }),
      React.createElement('span', { className: 'auth-orbit-dot' }),
    );
  }

  window.LoginPage = LoginPage;
})();
