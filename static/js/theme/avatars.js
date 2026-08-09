/* ═══════════════════════════════════════════════════════════════════════
   ARGUS — AVATAR ENGINE
   ───────────────────────────────────────────────────────────────────────
   Six avatars. Each is a point of view, not a palette: tokens + typography
   + density + motion + texture + layout archetype + copy register.

   PUBLIC API (global, matches the existing window.ArgusSkin pattern):
     window.ArgusAvatar.list()        -> avatar catalog
     window.ArgusAvatar.current()     -> active avatar id
     window.ArgusAvatar.variant()     -> active accent/surface variant id
     window.ArgusAvatar.apply(id,var) -> apply + persist
     window.ArgusAvatar.boot()        -> cold-boot (runs legacy migration)
     window.ArgusAvatar.contrast(on)  -> contrast-boost toggle
     window.ArgusAvatar.texture(n)    -> texture intensity 0..1
     window.ArgusAvatar.meta(id)      -> one avatar's manifest

   SAFETY CONTRACT
     - Presentation only. Touches document attributes, one <link>, one
       decorative overlay <div>, and localStorage. Nothing else.
     - No store/API/WS/dispatch involvement whatsoever.
     - Legacy theme + skin preferences are MIGRATED, never orphaned.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  var AVATAR_KEY  = 'argus.ui.avatar.v1';
  var VARIANT_KEY = 'argus.ui.avatar.variant.v1';
  var CONTRAST_KEY= 'argus.ui.contrast.v1';
  var TEXTURE_KEY = 'argus.ui.texture.v1';

  /* ── Legacy keys we migrate from (must match existing code) ─────────── */
  var LEGACY_THEME_KEYS = ['argus.ui.theme', 'argus.ui.theme.v1', 'argus.theme'];
  var LEGACY_SKIN_KEY   = 'argus.ui.skin.v1';

  /* ═══ THE SIX AVATARS ═══════════════════════════════════════════════ */
  var AVATARS = [
    {
      id: 'blacksite',
      label: 'Blacksite',
      persona: 'Covert ops console',
      tagline: 'Default daily driver · cold, disciplined, dense',
      when: 'Live operations',
      layout: 'ops-stack',
      density: 'dense',
      motion: 'informational',
      texture: { className: 'a-tex-grid', defaultIntensity: 0.30 },
      defaultMode: 'OPERATOR',
      swatches: ['#070B14', '#35C8DE', '#4FE0F0', '#FF4560'],
      icon: '◈',
      variants: [
        { id: 'ice',   label: 'Ice',   swatch: '#35C8DE' },
        { id: 'azure', label: 'Azure', swatch: '#4FA8FF' }
      ]
    },
    {
      id: 'phosphor',
      label: 'Phosphor',
      persona: 'CRT terminal',
      tagline: 'Keyboard-first · mono grid · zero chrome, zero motion',
      when: 'Power operator, low-bandwidth',
      layout: 'panes',
      density: 'compact',
      motion: 'none',
      texture: { className: 'a-tex-scanlines', defaultIntensity: 0.55 },
      defaultMode: 'OPERATOR',
      swatches: ['#040604', '#33FF66', '#7CFFA8', '#FF4A4A'],
      icon: '▊',
      variants: [
        { id: 'green', label: 'Green',  swatch: '#33FF66' },
        { id: 'amber', label: 'Amber',  swatch: '#FFB22A' },
        { id: 'ice',   label: 'Ice',    swatch: '#7CE8FF' }
      ]
    },
    {
      id: 'redcell',
      label: 'Red Cell',
      persona: 'Offensive red-team rig',
      tagline: 'Threat-first · blood-and-black · angular strike console',
      when: 'Active exploitation',
      layout: 'threat-first',
      density: 'dense',
      motion: 'sharp',
      texture: { className: 'a-tex-hazard', defaultIntensity: 0.22 },
      defaultMode: 'OPERATOR',
      swatches: ['#0A0607', '#E02435', '#F2E6E0', '#C2884A'],
      icon: '◢',
      variants: [
        { id: 'blood', label: 'Blood', swatch: '#E02435' },
        { id: 'ember', label: 'Ember', swatch: '#FF7A2F' }
      ]
    },
    {
      id: 'ghostwire',
      label: 'Ghostwire',
      persona: 'Cyberpunk deck',
      tagline: 'War-room spectacle · holo gradients · cinematic',
      when: 'Demo, big screen',
      layout: 'centre-stage',
      density: 'relaxed',
      motion: 'cinematic',
      texture: { className: 'a-tex-scanlines', defaultIntensity: 0.35 },
      defaultMode: 'PRESENT',
      swatches: ['#0A0616', '#F056C8', '#3DE0F0', '#9B6BFF'],
      icon: '◇',
      variants: [
        { id: 'magenta', label: 'Magenta', swatch: '#F056C8' },
        { id: 'acid',    label: 'Acid',    swatch: '#4EF0A8' },
        { id: 'vapor',   label: 'Vapor',   swatch: '#9B6BFF' }
      ]
    },
    {
      id: 'dossier',
      label: 'Dossier',
      persona: 'Classified intel brief',
      tagline: 'Client readout · redacted field file · print-safe',
      when: 'Engagement deliverable, PDF',
      layout: 'narrative',
      density: 'relaxed',
      motion: 'restrained',
      texture: { className: 'a-tex-paper', defaultIntensity: 0.18 },
      defaultMode: 'CLIENT',
      swatches: ['#EDE9DF', '#A8321F', '#1C1A16', '#1F4D6B'],
      icon: '▤',
      variants: [
        { id: 'parchment', label: 'Parchment', swatch: '#EDE9DF' },
        { id: 'folder',    label: 'Dark folder', swatch: '#17150F' }
      ]
    },
    {
      id: 'warden',
      label: 'Warden',
      persona: 'Cyber risk & governance',
      tagline: 'Risk register · muted ramp · defensible numbers',
      when: 'CISO, board, audit committee',
      layout: 'risk-posture',
      density: 'relaxed',
      motion: 'restrained',
      texture: { className: 'a-tex-ledger', defaultIntensity: 0.12 },
      defaultMode: 'BRIEFING',
      swatches: ['#0F1114', '#C9A227', '#7FA8C9', '#C0392B'],
      icon: '⚖',
      variants: [
        { id: 'graphite', label: 'Graphite', swatch: '#0F1114' },
        { id: 'light',    label: 'Board pack (light)', swatch: '#F4F5F7' }
      ]
    }
  ];

  var DEFAULT_AVATAR = 'blacksite';

  /* ── Legacy migration map (plan §6 — nothing orphaned) ─────────────── */
  var SKIN_TO_AVATAR = {
    stellar: 'blacksite', bloomberg: 'blacksite', glass: 'blacksite',
    apollo: 'ghostwire', webgl: 'ghostwire', genz: 'ghostwire',
    veteran: 'phosphor', hunter: 'phosphor', ctf: 'phosphor',
    redcell: 'redcell', tactical: 'redcell',
    editorial: 'dossier', novice: 'dossier',
    executive: 'warden', cfo: 'warden', legal: 'warden',
    manager: 'warden', auditor: 'warden'
  };
  var THEME_TO_AVATAR = {
    midnight: 'blacksite', sapphire: 'blacksite', graphite: 'phosphor',
    amber: 'phosphor', contrast: 'blacksite' /* + contrast boost */
  };

  /* ── storage helpers (never throw) ─────────────────────────────────── */
  function get(k)   { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function set(k,v) { try { localStorage.setItem(k, v); } catch (e) {} }

  function meta(id) {
    for (var i = 0; i < AVATARS.length; i++) if (AVATARS[i].id === id) return AVATARS[i];
    return null;
  }

  function loadAvatar() {
    var v = get(AVATAR_KEY);
    return meta(v) ? v : null;
  }

  /* ── Legacy migration: run once, only if no avatar chosen yet ──────── */
  function migrateLegacy() {
    var skin = get(LEGACY_SKIN_KEY);
    if (skin && SKIN_TO_AVATAR[skin]) return { id: SKIN_TO_AVATAR[skin], from: 'skin:' + skin };

    for (var i = 0; i < LEGACY_THEME_KEYS.length; i++) {
      var t = get(LEGACY_THEME_KEYS[i]);
      if (t && THEME_TO_AVATAR[t]) {
        return {
          id: THEME_TO_AVATAR[t],
          from: 'theme:' + t,
          contrast: (t === 'contrast')
        };
      }
    }
    return null;
  }

  /* ── Texture overlay element (decorative, non-interactive) ─────────── */
  function ensureTextureEl() {
    var el = document.getElementById('argus-avatar-tex');
    if (!el) {
      el = document.createElement('div');
      el.id = 'argus-avatar-tex';
      el.setAttribute('aria-hidden', 'true');
      (document.body || document.documentElement).appendChild(el);
    }
    return el;
  }

  /* ── Apply ─────────────────────────────────────────────────────────────
     NOTE: all six avatar stylesheets are loaded statically in index.html,
     each scoped to :root[data-avatar="<id>"]. Applying an avatar is
     therefore a pure attribute flip — instant, no network fetch, and no
     flash of unstyled/incorrect identity. (An earlier revision swapped a
     single <link href>; browser verification showed the async fetch left
     tokens stale for one paint, so the static approach replaced it.)
     ──────────────────────────────────────────────────────────────────── */
  function applyAvatar(id, variantId, opts) {
    opts = opts || {};
    var m = meta(id) || meta(DEFAULT_AVATAR);
    var root = document.documentElement;

    root.setAttribute('data-avatar', m.id);
    root.setAttribute('data-density', m.density);
    root.setAttribute('data-motion', m.motion);
    root.setAttribute('data-layout', m.layout);

    var v = null;
    if (variantId && m.variants) {
      for (var i = 0; i < m.variants.length; i++) {
        if (m.variants[i].id === variantId) { v = m.variants[i]; break; }
      }
    }
    if (v) root.setAttribute('data-avatar-variant', v.id);
    else   root.removeAttribute('data-avatar-variant');

    // Texture overlay
    var tex = ensureTextureEl();
    tex.className = (m.texture && m.texture.className) || '';
    var stored = get(TEXTURE_KEY);
    var intensity = (stored !== null && stored !== '')
      ? parseFloat(stored)
      : (m.texture ? m.texture.defaultIntensity : 0);
    if (isNaN(intensity)) intensity = 0;
    root.style.setProperty('--tex-opacity', String(intensity));

    if (!opts.noPersist) {
      set(AVATAR_KEY, m.id);
      if (v) set(VARIANT_KEY, v.id); else set(VARIANT_KEY, '');
    }

    // Let React (and anything else) react to the change
    try {
      window.dispatchEvent(new CustomEvent('argus:avatar-changed', {
        detail: { id: m.id, variant: v ? v.id : null, meta: m }
      }));
    } catch (e) {}

    return m.id;
  }

  /* ── Contrast boost (available in EVERY avatar) ────────────────────── */
  function applyContrast(on) {
    var root = document.documentElement;
    if (on) { root.setAttribute('data-contrast', 'boost'); set(CONTRAST_KEY, '1'); }
    else    { root.removeAttribute('data-contrast');       set(CONTRAST_KEY, '0'); }
    try {
      window.dispatchEvent(new CustomEvent('argus:contrast-changed', { detail: { on: !!on } }));
    } catch (e) {}
  }

  /* ── Texture intensity ─────────────────────────────────────────────── */
  function applyTexture(n) {
    var v = Math.max(0, Math.min(1, Number(n)));
    if (isNaN(v)) v = 0;
    document.documentElement.style.setProperty('--tex-opacity', String(v));
    set(TEXTURE_KEY, String(v));
  }

  /* ── Cold boot ─────────────────────────────────────────────────────── */
  function boot() {
    var chosen = loadAvatar();
    var variant = get(VARIANT_KEY) || null;
    var migrated = null;

    if (!chosen) {
      migrated = migrateLegacy();
      if (migrated) {
        chosen = migrated.id;
        if (migrated.contrast) applyContrast(true);
        try { console.info('[ARGUS avatars] migrated legacy preference', migrated.from, '->', chosen); } catch (e) {}
      }
    }
    if (!chosen) chosen = DEFAULT_AVATAR;

    if (get(CONTRAST_KEY) === '1') applyContrast(true);
    applyAvatar(chosen, variant);
    return chosen;
  }

  window.ArgusAvatar = {
    list:     function () { return AVATARS.slice(); },
    meta:     meta,
    current:  function () { return document.documentElement.getAttribute('data-avatar') || loadAvatar() || DEFAULT_AVATAR; },
    variant:  function () { return document.documentElement.getAttribute('data-avatar-variant') || null; },
    apply:    applyAvatar,
    boot:     boot,
    contrast: applyContrast,
    contrastOn: function () { return document.documentElement.getAttribute('data-contrast') === 'boost'; },
    texture:  applyTexture,
    textureLevel: function () {
      var s = get(TEXTURE_KEY);
      if (s !== null && s !== '') return parseFloat(s);
      var m = meta(window.ArgusAvatar.current());
      return m && m.texture ? m.texture.defaultIntensity : 0;
    },
    DEFAULT:  DEFAULT_AVATAR
  };

  // Apply as early as possible to avoid a flash of the wrong avatar.
  try { boot(); } catch (e) {
    try { console.warn('[ARGUS avatars] boot failed, falling back to default', e); } catch (_) {}
    try { document.documentElement.setAttribute('data-avatar', DEFAULT_AVATAR); } catch (_) {}
  }
})();
