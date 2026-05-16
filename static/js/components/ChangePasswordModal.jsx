/* ═══════════════════════════════════════════════════════════════
   ChangePasswordModal — used in two contexts
   ───────────────────────────────────────────────────────────────
   1. Forced mode: AuthBoundary detects me.must_change_password
      and renders this with `forced={true}`.  Operator cannot close
      it; the only exit is to successfully rotate the password.

   2. Self-service mode: UserChip menu → "Change password".  The X
      button + Escape key dismiss the modal.

   Both call POST /auth/me/change-password with the same payload.
   ─────────────────────────────────────────────────────────────── */
(function () {
  const { useState, useEffect, useRef } = React;

  function readCsrf() {
    try {
      const c = (document.cookie.split('; ').find(c => c.startsWith('argus_csrf=')) || '').split('=')[1];
      return c ? decodeURIComponent(c) : '';
    } catch { return ''; }
  }
  function readAccessToken() {
    try { return localStorage.getItem('argus.access_token') || ''; } catch { return ''; }
  }

  function ChangePasswordModal({ forced = false, onClose = () => {}, onSuccess = () => {} }) {
    const [current, setCurrent] = useState('');
    const [next, setNext] = useState('');
    const [confirm, setConfirm] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);
    const firstFieldRef = useRef(null);

    useEffect(() => {
      try { firstFieldRef.current && firstFieldRef.current.focus(); } catch {}
    }, []);

    useEffect(() => {
      if (forced) return;       // forced mode ignores Escape
      function onKey(e) { if (e.key === 'Escape') onClose(); }
      window.addEventListener('keydown', onKey);
      return () => window.removeEventListener('keydown', onKey);
    }, [forced, onClose]);

    async function submit(e) {
      e.preventDefault();
      setError(null);
      if (!current) return setError('Enter your current password.');
      if (!next || next.length < 12) return setError('New password must be at least 12 characters.');
      if (next !== confirm) return setError('New passwords do not match.');
      if (next === current) return setError('New password must be different from the current one.');
      setBusy(true);
      try {
        const csrf = readCsrf();
        const tok = readAccessToken();
        const headers = { 'Content-Type': 'application/json',
                           'X-CSRF-Token': csrf };
        if (tok) headers['Authorization'] = 'Bearer ' + tok;
        const r = await fetch('/auth/me/change-password', {
          method: 'POST', credentials: 'include',
          headers,
          body: JSON.stringify({ current_password: current, new_password: next }),
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok) {
          setSuccess(true);
          // After password change the backend revokes all other sessions
          // and clears must_change.  Refresh /auth/me on the parent.
          setTimeout(() => {
            if (forced) {
              // Re-load so AuthBoundary picks up must_change_password=false
              window.location.reload();
            } else {
              onSuccess();
              onClose();
            }
          }, 1100);
          return;
        }
        const msg = data.detail?.message || data.detail || data.message || 'Password change failed.';
        setError(typeof msg === 'string' ? msg : 'Password change failed.');
      } catch (err) {
        setError('Network error: ' + String(err));
      } finally {
        setBusy(false);
      }
    }

    return React.createElement('div', { className: 'cpm-backdrop',
      onClick: forced ? null : (e) => { if (e.target.className === 'cpm-backdrop') onClose(); } },
      React.createElement('div', { className: 'cpm-card', role: 'dialog',
        'aria-modal': 'true', 'aria-labelledby': 'cpm-title' },
        // Header
        React.createElement('div', { className: 'cpm-head' },
          React.createElement('span', { className: 'cpm-icon', 'aria-hidden': 'true' }, '🔑'),
          React.createElement('div', { style: { flex: 1, minWidth: 0 } },
            React.createElement('div', { id: 'cpm-title', className: 'cpm-title' },
              forced ? 'Password rotation required' : 'Change password'),
            React.createElement('div', { className: 'cpm-subtitle' },
              forced
                ? 'Your account requires a new password before you can continue.'
                : 'Choose a new password.  All other sessions will be signed out.')
          ),
          !forced && React.createElement('button', { type: 'button',
            className: 'cpm-close', onClick: onClose, 'aria-label': 'Close' }, '×')
        ),

        // Form
        success
          ? React.createElement('div', { className: 'cpm-success' },
              React.createElement('span', { 'aria-hidden': 'true' }, '✓'),
              React.createElement('span', null, 'Password updated.  Signing you in...'))
          : React.createElement('form', { onSubmit: submit, className: 'cpm-form' },
              React.createElement('label', { className: 'cpm-field' }, 'Current password',
                React.createElement('input', {
                  ref: firstFieldRef,
                  type: 'password', autoComplete: 'current-password',
                  required: true, value: current,
                  onChange: e => setCurrent(e.target.value),
                  disabled: busy,
                })
              ),
              React.createElement('label', { className: 'cpm-field' }, 'New password (min 12 chars)',
                React.createElement('input', {
                  type: 'password', autoComplete: 'new-password',
                  required: true, minLength: 12, value: next,
                  onChange: e => setNext(e.target.value),
                  disabled: busy,
                })
              ),
              React.createElement('label', { className: 'cpm-field' }, 'Confirm new password',
                React.createElement('input', {
                  type: 'password', autoComplete: 'new-password',
                  required: true, minLength: 12, value: confirm,
                  onChange: e => setConfirm(e.target.value),
                  disabled: busy,
                })
              ),
              error && React.createElement('div', { className: 'cpm-error' },
                React.createElement('span', { 'aria-hidden': 'true' }, '⚠ '), error),
              React.createElement('div', { className: 'cpm-actions' },
                !forced && React.createElement('button', {
                  type: 'button', className: 'cpm-btn-secondary',
                  onClick: onClose, disabled: busy,
                }, 'Cancel'),
                React.createElement('button', {
                  type: 'submit', className: 'cpm-btn-primary', disabled: busy,
                }, busy ? 'Saving...' : 'Update password')
              ),
              React.createElement('div', { className: 'cpm-hint' },
                'NIST 800-63B compliant: length-first.  No required character classes.  ',
                'No rotation requirement (the system only rotates on admin action or compromise).')
            )
      )
    );
  }

  window.ChangePasswordModal = ChangePasswordModal;
})();
