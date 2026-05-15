/* ═══════════════════════════════════════════════════════════════
   MfaChallenge — second-factor verification screen
   ───────────────────────────────────────────────────────────────
   Props:
     mfaToken      — opaque challenge token from /auth/login
     factorTypes   — ["TOTP", "WEBAUTHN", ...] for badge display
     onSuccess     — callback after successful verification
     onCancel      — callback to abort and return to login
   ─────────────────────────────────────────────────────────────── */
(function () {
  const { useState, useRef, useEffect } = React;

  function MfaChallenge({ mfaToken, factorTypes = [], onSuccess, onCancel }) {
    const [code, setCode] = useState('');
    const [useBackup, setUseBackup] = useState(false);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const inputRef = useRef(null);

    useEffect(() => {
      // Auto-focus on mount
      try { inputRef.current && inputRef.current.focus(); } catch {}
    }, []);

    async function submit(e) {
      e.preventDefault();
      setError(null); setBusy(true);
      try {
        const r = await fetch('/auth/mfa/verify', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mfa_token: mfaToken,
            code: code.trim(),
            is_backup: useBackup,
          }),
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data.access_token) {
          window.localStorage.setItem('argus.access_token', data.access_token);
          onSuccess && onSuccess();
          return;
        }
        const msg = data.detail?.message || data.detail || 'Verification failed.';
        setError(typeof msg === 'string' ? msg : 'Verification failed.');
      } catch (err) {
        setError(String(err));
      } finally {
        setBusy(false);
      }
    }

    return React.createElement('div', { className: 'auth-shell' },
      React.createElement('div', { className: 'auth-card' },
        React.createElement('div', { className: 'auth-brand' },
          React.createElement('div', { className: 'auth-brand-mark' }, '◐'),
          React.createElement('div', { className: 'auth-brand-text' }, 'Verify Identity'),
        ),
        React.createElement('div', { className: 'auth-subtitle' },
          useBackup
            ? 'Enter one of your single-use backup codes.'
            : 'Enter the 6-digit code from your authenticator app.'
        ),

        // Factor-type badges
        factorTypes.length > 0 && React.createElement('div', { className: 'auth-factor-row' },
          factorTypes.map(t =>
            React.createElement('span', {
              key: t, className: 'auth-factor-badge',
            }, t)
          )
        ),

        React.createElement('form', { onSubmit: submit, className: 'auth-form' },
          React.createElement('label', { className: 'auth-label' },
            useBackup ? 'Backup code' : 'Authenticator code',
            React.createElement('input', {
              ref: inputRef,
              type: 'text',
              inputMode: useBackup ? 'text' : 'numeric',
              autoComplete: 'one-time-code',
              pattern: useBackup ? null : '[0-9]*',
              maxLength: useBackup ? 12 : 8,
              required: true,
              value: code,
              onChange: e => setCode(e.target.value),
              style: { letterSpacing: '0.4em', fontFamily: 'var(--font-mono)',
                       textAlign: 'center', fontSize: '20px' },
            })
          ),
          error && React.createElement('div', { className: 'auth-error' }, error),
          React.createElement('button', {
            type: 'submit', disabled: busy || !code.trim(), className: 'auth-submit',
          }, busy ? 'Verifying…' : 'Verify'),
        ),

        React.createElement('div', { className: 'auth-mfa-switch' },
          React.createElement('button', {
            type: 'button',
            className: 'auth-link',
            onClick: () => { setUseBackup(!useBackup); setCode(''); setError(null); },
          }, useBackup
              ? 'Use authenticator code instead'
              : 'Use a backup code instead'),
        ),

        React.createElement('div', { className: 'auth-footer' },
          React.createElement('button', {
            type: 'button', className: 'auth-link',
            onClick: onCancel,
          }, 'Cancel and start over')
        )
      )
    );
  }

  window.MfaChallenge = MfaChallenge;
})();
