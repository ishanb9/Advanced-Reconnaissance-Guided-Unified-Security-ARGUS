/* ═══════════════════════════════════════════════════════════════
   MfaChallenge — 6-digit code entry, matches LoginPage aesthetic
   ───────────────────────────────────────────────────────────────
   • Same animated mesh + particle backdrop as the login page
   • Big 6-cell code entry (per-digit boxes with focus chevroning)
   • Switch between TOTP / backup-code
   • Auto-submit when 6 digits typed
   • Soft red error shake on bad code
   • Countdown ring around the brand mark hinting at challenge expiry
   ─────────────────────────────────────────────────────────────── */
(function () {
  const { useState, useEffect, useRef, useCallback } = React;

  function CodeInput({ length = 6, value, onChange, disabled, autoFocus }) {
    const refs = useRef([]);

    const handleChange = (i, v) => {
      const digit = (v || '').replace(/\D/g, '').slice(-1);
      const arr = (value || '').padEnd(length, ' ').split('');
      arr[i] = digit || ' ';
      const next = arr.join('').replace(/ +$/, '');
      onChange(next);
      if (digit && i < length - 1) refs.current[i + 1]?.focus();
    };

    const handleKey = (i, e) => {
      if (e.key === 'Backspace' && !value[i] && i > 0) {
        refs.current[i - 1]?.focus();
      } else if (e.key === 'ArrowLeft' && i > 0) {
        refs.current[i - 1]?.focus();
      } else if (e.key === 'ArrowRight' && i < length - 1) {
        refs.current[i + 1]?.focus();
      }
    };

    const handlePaste = (e) => {
      const t = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, length);
      if (t) {
        e.preventDefault();
        onChange(t);
        refs.current[Math.min(t.length, length - 1)]?.focus();
      }
    };

    return React.createElement('div', { className: 'auth-code-row' },
      Array.from({ length }, (_, i) =>
        React.createElement('input', {
          key: i,
          ref: el => (refs.current[i] = el),
          type: 'text',
          inputMode: 'numeric',
          autoComplete: i === 0 ? 'one-time-code' : 'off',
          maxLength: 1,
          disabled,
          autoFocus: autoFocus && i === 0,
          value: value[i] || '',
          onChange: e => handleChange(i, e.target.value),
          onKeyDown: e => handleKey(i, e),
          onPaste: handlePaste,
          className: 'auth-code-cell',
        })
      )
    );
  }

  function CountdownRing({ seconds = 300, onExpire }) {
    const [left, setLeft] = useState(seconds);
    useEffect(() => {
      const id = setInterval(() => {
        setLeft(s => {
          if (s <= 1) { clearInterval(id); onExpire && onExpire(); return 0; }
          return s - 1;
        });
      }, 1000);
      return () => clearInterval(id);
    }, []);
    const pct = (left / seconds);
    const circumference = 2 * Math.PI * 26;
    const dashOffset = circumference * (1 - pct);
    return React.createElement('svg', {
      className: 'auth-countdown', viewBox: '0 0 64 64',
      width: 64, height: 64, 'aria-hidden': 'true',
    },
      React.createElement('circle', {
        cx: 32, cy: 32, r: 26, fill: 'none',
        stroke: 'rgba(255,255,255,0.08)', strokeWidth: 2,
      }),
      React.createElement('circle', {
        cx: 32, cy: 32, r: 26, fill: 'none',
        stroke: 'currentColor', strokeWidth: 2,
        strokeDasharray: circumference,
        strokeDashoffset: dashOffset,
        transform: 'rotate(-90 32 32)',
        style: { transition: 'stroke-dashoffset 1s linear' },
      }),
      React.createElement('text', {
        x: 32, y: 36, textAnchor: 'middle', fontSize: 14,
        fontFamily: 'var(--font-mono)', fill: 'currentColor',
      }, Math.floor(left / 60) + ':' + String(left % 60).padStart(2, '0')),
    );
  }

  function MfaChallenge({ mfaToken, factorTypes = [], onSuccess, onCancel }) {
    const [code, setCode] = useState('');
    const [useBackup, setUseBackup] = useState(false);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const [shake, setShake] = useState(false);
    const [backupValue, setBackupValue] = useState('');
    const cardRef = useRef(null);

    const triggerShake = useCallback(() => {
      setShake(true);
      setTimeout(() => setShake(false), 460);
    }, []);

    async function submit(rawCode) {
      const send = useBackup ? backupValue.trim() : (rawCode || code).trim();
      if (!send) return;
      setError(null); setBusy(true);
      try {
        const r = await fetch('/auth/mfa/verify', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mfa_token: mfaToken,
            code: send,
            is_backup: useBackup,
          }),
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data.access_token) {
          window.localStorage.setItem('argus.access_token', data.access_token);
          cardRef.current && cardRef.current.classList.add('auth-card-success');
          setTimeout(() => onSuccess && onSuccess(), 380);
          return;
        }
        const msg = data.detail?.message || data.detail || 'Verification failed.';
        setError(typeof msg === 'string' ? msg : 'Verification failed.');
        setCode('');
        setBackupValue('');
        triggerShake();
      } catch (err) {
        setError('Network error: ' + String(err));
        triggerShake();
      } finally {
        setBusy(false);
      }
    }

    // Auto-submit when 6 digits typed (TOTP mode only)
    useEffect(() => {
      if (!useBackup && code.length === 6 && !busy) {
        submit(code);
      }
    }, [code, useBackup]);

    return React.createElement('div', { className: 'auth-stage' },
      React.createElement('div', { className: 'auth-stage-mesh', 'aria-hidden': 'true' }),
      React.createElement('div', { className: 'auth-stage-overlay', 'aria-hidden': 'true' }),

      React.createElement('div', { className: 'auth-stage-center' },
        React.createElement('div', {
          ref: cardRef,
          className: 'auth-stage-card' + (shake ? ' auth-shake' : ''),
        },
          React.createElement('div', { className: 'auth-wordmark-block' },
            React.createElement('div', { className: 'auth-wordmark-mark',
              style: { position: 'relative' } },
              React.createElement(CountdownRing, {
                seconds: 300,
                onExpire: () => onCancel && onCancel(),
              }),
            ),
            React.createElement('div', { className: 'auth-wordmark' },
              React.createElement('div', { className: 'auth-wordmark-text',
                'data-text': 'VERIFY',
                style: { fontSize: 28 } }, 'VERIFY'),
              React.createElement('div', { className: 'auth-wordmark-tagline' },
                useBackup
                  ? 'Enter one of your single-use backup codes.'
                  : 'Enter the 6-digit code from your authenticator.',
              ),
            ),
          ),

          factorTypes.length > 0 && React.createElement('div', { className: 'auth-factor-row',
            style: { justifyContent: 'center', marginBottom: 18 } },
            factorTypes.map(t =>
              React.createElement('span', {
                key: t, className: 'auth-factor-badge',
              }, t)
            )
          ),

          !useBackup
            ? React.createElement(CodeInput, {
                length: 6, value: code, onChange: setCode,
                disabled: busy, autoFocus: true,
              })
            : React.createElement('div', { className: 'auth-field',
                style: { marginBottom: 14 } },
                React.createElement('label', null, 'Backup code'),
                React.createElement('input', {
                  type: 'text',
                  placeholder: 'xxxx-xxxx',
                  autoComplete: 'one-time-code',
                  maxLength: 12,
                  value: backupValue,
                  onChange: e => setBackupValue(e.target.value),
                  style: { letterSpacing: '0.3em', fontFamily: 'var(--font-mono)',
                            textAlign: 'center', fontSize: 18 },
                }),
              ),

          error && React.createElement('div', { className: 'auth-error-stage' },
            React.createElement('span', { 'aria-hidden': 'true' }, '⚠ '),
            error
          ),

          useBackup && React.createElement('button', {
            type: 'button',
            className: 'auth-submit-stage' + (busy ? ' busy' : ''),
            disabled: busy || !backupValue.trim(),
            onClick: () => submit(),
            style: { marginTop: 4 },
          },
            React.createElement('span', null, busy ? 'Verifying' : 'Verify backup code'),
          ),

          React.createElement('div', { className: 'auth-mfa-switch' },
            React.createElement('button', {
              type: 'button', className: 'auth-link',
              onClick: () => {
                setUseBackup(!useBackup); setCode(''); setBackupValue(''); setError(null);
              },
            }, useBackup
                ? 'Use authenticator code instead'
                : 'Lost your device? Use a backup code'),
          ),

          React.createElement('div', { className: 'auth-card-footer' },
            React.createElement('button', {
              type: 'button', className: 'auth-link',
              onClick: onCancel,
            }, '← Cancel and start over'),
            React.createElement('div', { className: 'auth-secure-badge' },
              React.createElement('span', { 'aria-hidden': 'true' }, '🛡 '),
              'RFC 6238 · 30s window'),
          ),
        )
      )
    );
  }

  window.MfaChallenge = MfaChallenge;
})();
