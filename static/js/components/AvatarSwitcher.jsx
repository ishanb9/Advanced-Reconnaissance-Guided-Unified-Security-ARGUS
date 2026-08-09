/* ═══════════════════════════════════════════════════════════════════════
   AvatarSwitcher — pick one of ARGUS's six avatars
   ───────────────────────────────────────────────────────────────────────
   An avatar is a point of view, not a palette: tokens + typography +
   density + motion + texture + layout archetype + copy register.

   Also exposes the two cross-cutting accessibility controls that every
   avatar carries: CONTRAST BOOST and TEXTURE INTENSITY.

   Presentation only — no store, no API, no dispatch.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  var useState = React.useState, useEffect = React.useEffect, useRef = React.useRef;
  var e = React.createElement;

  function AvatarSwitcher() {
    var api = window.ArgusAvatar;
    var avatars = api ? api.list() : [];

    var cur = useState(api ? api.current() : 'blacksite');
    var current = cur[0], setCurrent = cur[1];
    var varSt = useState(api ? api.variant() : null);
    var variant = varSt[0], setVariant = varSt[1];
    var opSt = useState(false); var open = opSt[0], setOpen = opSt[1];
    var ctSt = useState(api ? api.contrastOn() : false);
    var contrast = ctSt[0], setContrast = ctSt[1];
    var txSt = useState(api ? api.textureLevel() : 0);
    var texture = txSt[0], setTexture = txSt[1];

    var ref = useRef(null);

    useEffect(function () {
      function close(ev) { if (ref.current && !ref.current.contains(ev.target)) setOpen(false); }
      if (open) document.addEventListener('mousedown', close);
      return function () { document.removeEventListener('mousedown', close); };
    }, [open]);

    function pick(id) {
      if (!api) return;
      var m = api.meta(id);
      var defVar = (m && m.variants && m.variants.length) ? m.variants[0].id : null;
      api.apply(id, defVar);
      setCurrent(id); setVariant(defVar);
      setTexture(api.textureLevel());
    }
    function pickVariant(vid) {
      if (!api) return;
      api.apply(current, vid);
      setVariant(vid);
    }
    function toggleContrast() {
      if (!api) return;
      var next = !contrast; api.contrast(next); setContrast(next);
    }
    function onTexture(val) {
      if (!api) return;
      var v = Number(val); api.texture(v); setTexture(v);
    }

    var meta = null;
    for (var i = 0; i < avatars.length; i++) if (avatars[i].id === current) meta = avatars[i];
    if (!meta) meta = avatars[0] || { label: 'Blacksite', swatches: ['#070B14', '#35C8DE'], icon: '◈' };

    /* ── Trigger ─────────────────────────────────────────────────────── */
    var trigger = e('button', {
      onClick: function () { setOpen(!open); },
      title: 'ARGUS avatar: ' + meta.label + ' — ' + (meta.persona || ''),
      'aria-haspopup': 'true',
      'aria-expanded': open ? 'true' : 'false',
      style: {
        display: 'flex', alignItems: 'center', gap: 7,
        padding: '4px 10px', borderRadius: 18, cursor: 'pointer',
        background: 'var(--bg-panel)', border: '1px solid var(--border-dim)',
        color: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-ui)',
        transition: 'border-color .15s, color .15s'
      },
      onMouseEnter: function (ev) {
        ev.currentTarget.style.borderColor = 'var(--border)';
        ev.currentTarget.style.color = 'var(--text-primary)';
      },
      onMouseLeave: function (ev) {
        ev.currentTarget.style.borderColor = 'var(--border-dim)';
        ev.currentTarget.style.color = 'var(--text-secondary)';
      }
    },
      e('span', {
        style: { display: 'flex', gap: 2, alignItems: 'center', flexShrink: 0 }
      }, (meta.swatches || []).slice(0, 4).map(function (c, idx) {
        return e('span', {
          key: idx,
          style: {
            width: 7, height: 7, borderRadius: '50%', background: c,
            border: '1px solid rgba(255,255,255,0.10)'
          }
        });
      })),
      e('span', { style: { fontWeight: 600, letterSpacing: '.04em' } }, meta.label),
      e('span', { style: { fontSize: 9, opacity: .5 } }, '▾')
    );

    if (!open) return e('div', { ref: ref, style: { position: 'relative' } }, trigger);

    /* ── Popover ─────────────────────────────────────────────────────── */
    var rows = avatars.map(function (a) {
      var active = a.id === current;
      return e('div', {
        key: a.id,
        onClick: function () { pick(a.id); },
        role: 'button',
        tabIndex: 0,
        onKeyDown: function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(a.id); } },
        style: {
          display: 'flex', alignItems: 'flex-start', gap: 11,
          padding: '10px 10px', borderRadius: 8, cursor: 'pointer',
          background: active ? 'linear-gradient(90deg, ' + a.swatches[1] + '1F, transparent)' : 'transparent',
          borderLeft: active ? '3px solid ' + a.swatches[1] : '3px solid transparent',
          marginBottom: 2, transition: 'background .12s'
        },
        onMouseEnter: function (ev) { if (!active) ev.currentTarget.style.background = 'var(--state-hover-bg)'; },
        onMouseLeave: function (ev) { if (!active) ev.currentTarget.style.background = 'transparent'; }
      },
        e('div', {
          style: {
            width: 42, height: 42, borderRadius: 8, flexShrink: 0,
            background: 'linear-gradient(135deg, ' + a.swatches[0] + ' 0%, ' + a.swatches[1] + ' 130%)',
            border: '1px solid ' + a.swatches[1] + '66',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: a.swatches[2] || '#fff', fontSize: 19, fontFamily: 'var(--font-mono)',
            boxShadow: active ? '0 0 12px ' + a.swatches[1] + '55' : 'none'
          }
        }, a.icon),
        e('div', { style: { flex: 1, minWidth: 0 } },
          e('div', {
            style: {
              fontSize: 13, fontWeight: 700,
              color: active ? a.swatches[1] : 'var(--text-primary)'
            }
          }, a.label,
            e('span', {
              style: {
                marginLeft: 6, fontSize: 9, fontWeight: 600, letterSpacing: '.1em',
                textTransform: 'uppercase', color: 'var(--text-muted)'
              }
            }, a.persona)
          ),
          e('div', {
            style: { fontSize: 10, color: 'var(--text-muted)', marginTop: 2, lineHeight: 1.45 }
          }, a.tagline),
          e('div', {
            style: {
              display: 'flex', gap: 8, marginTop: 5, alignItems: 'center',
              fontSize: 9, color: 'var(--text-muted)', letterSpacing: '.06em',
              textTransform: 'uppercase', fontFamily: 'var(--font-mono)'
            }
          },
            e('span', null, a.density),
            e('span', { style: { opacity: .4 } }, '·'),
            e('span', null, 'motion: ' + a.motion),
            e('span', { style: { opacity: .4 } }, '·'),
            e('span', null, a.defaultMode)
          )
        ),
        active ? e('span', { style: { color: a.swatches[1], fontSize: 13, flexShrink: 0 } }, '✓') : null
      );
    });

    var variantRow = (meta.variants && meta.variants.length > 1)
      ? e('div', {
          style: {
            padding: '8px 12px', borderTop: '1px solid var(--border-dim)',
            display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap'
          }
        },
          e('span', { className: 'a-eyebrow' }, 'Variant'),
          meta.variants.map(function (v) {
            var on = (variant || (meta.variants[0] && meta.variants[0].id)) === v.id;
            return e('button', {
              key: v.id,
              onClick: function () { pickVariant(v.id); },
              style: {
                display: 'inline-flex', alignItems: 'center', gap: 5,
                padding: '3px 9px', borderRadius: 999, cursor: 'pointer',
                fontSize: 10, fontFamily: 'var(--font-mono)',
                background: on ? 'var(--state-selected-bg)' : 'transparent',
                border: '1px solid ' + (on ? 'var(--accent)' : 'var(--border-dim)'),
                color: on ? 'var(--accent)' : 'var(--text-secondary)'
              }
            },
              e('span', {
                style: {
                  width: 8, height: 8, borderRadius: '50%', background: v.swatch,
                  border: '1px solid rgba(255,255,255,.15)'
                }
              }),
              v.label
            );
          })
        )
      : null;

    var a11yRow = e('div', {
      style: { padding: '10px 12px', borderTop: '1px solid var(--border-dim)', display: 'grid', gap: 9 }
    },
      e('label', {
        style: {
          display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
          fontSize: 11, color: 'var(--text-secondary)'
        }
      },
        e('input', {
          type: 'checkbox', checked: contrast, onChange: toggleContrast,
          style: { accentColor: 'var(--accent)', cursor: 'pointer' }
        }),
        e('span', null, 'Contrast boost'),
        e('span', {
          style: { fontSize: 9, color: 'var(--text-muted)', marginLeft: 'auto' }
        }, 'WCAG AA+')
      ),
      e('div', { style: { display: 'flex', alignItems: 'center', gap: 8 } },
        e('span', { style: { fontSize: 11, color: 'var(--text-secondary)', minWidth: 62 } }, 'Texture'),
        e('input', {
          type: 'range', min: 0, max: 1, step: 0.05, value: texture,
          onChange: function (ev) { onTexture(ev.target.value); },
          style: { flex: 1, accentColor: 'var(--accent)', cursor: 'pointer' },
          'aria-label': 'Signature texture intensity'
        }),
        e('span', {
          className: 'a-num',
          style: { fontSize: 10, color: 'var(--text-muted)', minWidth: 30, textAlign: 'right' }
        }, Math.round(texture * 100) + '%')
      )
    );

    var popover = e('div', {
      role: 'dialog',
      'aria-label': 'Choose ARGUS avatar',
      style: {
        position: 'absolute', top: 'calc(100% + 6px)', right: 0, zIndex: 1300,
        width: 400, maxHeight: '80vh', display: 'flex', flexDirection: 'column',
        borderRadius: 12, overflow: 'hidden',
        background: 'var(--bg-surface)', border: '1px solid var(--border-bright)',
        boxShadow: '0 20px 48px rgba(0,0,0,.7)'
      }
    },
      e('div', {
        style: {
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '10px 13px', borderBottom: '1px solid var(--border-dim)', flexShrink: 0
        }
      },
        e('span', { className: 'a-eyebrow' }, 'ARGUS Avatar'),
        e('span', {
          style: { fontSize: 9, color: 'var(--text-muted)', letterSpacing: '.5px' }
        }, avatars.length + ' avatars · same capabilities')
      ),
      e('div', { style: { flex: 1, overflowY: 'auto', padding: 8 } }, rows),
      variantRow,
      a11yRow,
      e('div', {
        style: {
          padding: '8px 13px', fontSize: 9, color: 'var(--text-muted)',
          borderTop: '1px solid var(--border-dim)', lineHeight: 1.5, flexShrink: 0
        }
      }, 'Saved per-browser · Every avatar exposes every ARGUS feature — only composition, density and wording change.')
    );

    return e('div', { ref: ref, style: { position: 'relative' } }, trigger, popover);
  }

  window.AvatarSwitcher = AvatarSwitcher;
})();
