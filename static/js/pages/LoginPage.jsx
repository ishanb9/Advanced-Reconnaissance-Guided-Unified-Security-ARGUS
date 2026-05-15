/* ═══════════════════════════════════════════════════════════════
   LoginPage — username/password + SSO entry points
   ───────────────────────────────────────────────────────────────
   The cockpit shell renders this page when the user is unauthenticated
   (no /auth/me success).  On successful login, the JWT is stored
   in-memory + cookies are set server-side, then we reload to mount
   the full app.

   Flow:
     POST /auth/login →
       • 200 + TokenResponse           — straight in
       • 202 + LoginInitialResponse    — MFA required, show challenge
       • 401/403                       — show error
   ─────────────────────────────────────────────────────────────── */
(function () {
  const { useState, useEffect } = React;

  function LoginPage() {
    const [tab, setTab] = useState('local');
    const [providers, setProviders] = useState([]);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const [mfaToken, setMfaToken] = useState(null);
    const [factorTypes, setFactorTypes] = useState([]);

    useEffect(() => {
      // Discover enabled SSO providers
      fetch('/auth/sso/providers')
        .then(r => r.ok ? r.json() : [])
        .then(setProviders)
        .catch(() => setProviders([]));

      // Honour mfa_token in URL (OIDC step-up flow)
      const params = new URLSearchParams(window.location.search);
      const mt = params.get('mfa_token');
      if (mt) setMfaToken(mt);
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
          window.location.reload();
          return;
        }
        if (r.status === 200 && data.status === 'mfa_required') {
          setMfaToken(data.mfa_token);
          setFactorTypes(data.factor_types || []);
          return;
        }
        if (data.code === 'mfa_enrolment_required') {
          setError('Multi-factor authentication is required for your role. ' +
                   'Visit /me/security to enrol after login by a Platform Admin.');
          return;
        }
        setError(data.detail || data.message || 'Login failed.');
      } catch (err) {
        setError(String(err));
      } finally {
        setBusy(false);
      }
    }

    if (mfaToken) {
      return React.createElement(window.MfaChallenge, {
        mfaToken,
        factorTypes,
        onSuccess: () => window.location.reload(),
        onCancel: () => { setMfaToken(null); setFactorTypes([]); },
      });
    }

    return React.createElement('div', { className: 'auth-shell' },
      React.createElement('div', { className: 'auth-card' },
        React.createElement('div', { className: 'auth-brand' },
          React.createElement('div', { className: 'auth-brand-mark' }, '◉'),
          React.createElement('div', { className: 'auth-brand-text' }, 'ARGUS'),
        ),
        React.createElement('div', { className: 'auth-subtitle' },
          'Sign in to continue'),

        // Tabs
        providers.length > 0 && React.createElement('div', { className: 'auth-tabs' },
          React.createElement('button', {
            type: 'button', className: 'auth-tab', 'data-active': tab === 'local',
            onClick: () => setTab('local'),
          }, 'Email & Password'),
          React.createElement('button', {
            type: 'button', className: 'auth-tab', 'data-active': tab === 'sso',
            onClick: () => setTab('sso'),
          }, 'Single Sign-On'),
        ),

        // Form / SSO list
        tab === 'local'
          ? React.createElement('form', { onSubmit: doLogin, className: 'auth-form' },
              React.createElement('label', { className: 'auth-label' }, 'Email',
                React.createElement('input', {
                  type: 'email', autoComplete: 'username',
                  required: true, value: email,
                  onChange: e => setEmail(e.target.value),
                })
              ),
              React.createElement('label', { className: 'auth-label' }, 'Password',
                React.createElement('input', {
                  type: 'password', autoComplete: 'current-password',
                  required: true, value: password,
                  onChange: e => setPassword(e.target.value),
                })
              ),
              error && React.createElement('div', { className: 'auth-error' }, error),
              React.createElement('button', {
                type: 'submit', disabled: busy, className: 'auth-submit',
              }, busy ? 'Signing in…' : 'Sign In'),
            )
          : React.createElement('div', { className: 'auth-sso' },
              providers.length === 0
                ? React.createElement('div', { className: 'auth-muted' },
                    'No SSO providers configured.')
                : providers.map(p =>
                    React.createElement('a', {
                      key: p.id, className: 'auth-sso-btn',
                      href: p.kind === 'OIDC'
                        ? `/auth/sso/oidc/${p.id}/start`
                        : `/auth/sso/saml/${p.id}/login`,
                    },
                      React.createElement('span', { className: 'auth-sso-kind' }, p.kind),
                      React.createElement('span', null, `Continue with ${p.name}`),
                    )
                  )
            ),

        // Footer
        React.createElement('div', { className: 'auth-footer' },
          React.createElement('span', null, 'Need an account? Contact your platform administrator.')
        ),
      ),
    );
  }

  window.LoginPage = LoginPage;
})();
