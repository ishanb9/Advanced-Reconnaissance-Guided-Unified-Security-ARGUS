/* ═══════════════════════════════════════════════════════════════════════
   ARGUS — AVATAR UI PRIMITIVES
   ───────────────────────────────────────────────────────────────────────
   Shared, avatar-aware building blocks. Exposed globally so pages can
   adopt them incrementally without any refactor.

   ★ ANTI-FABRICATION CONTRACT ★
   ARGUS must never render an invented figure. These primitives make the
   honest path the easy path:

     ArgusUI.Num({value})      -> renders "—" when value is null/undefined/NaN.
                                  It NEVER coerces missing data to 0.
     ArgusUI.NoData            -> inline "no data" marker
     ArgusUI.NoDataBlock       -> block empty state with the REASON
     ArgusUI.NotConfigured     -> "requires data ARGUS does not collect yet"
     ArgusUI.Unproven          -> unconfirmed-evidence badge
     ArgusUI.DegradedBanner    -> engine-degraded notice (never look clean)

   A measured zero and an absence of data are visually distinct, always.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  var e = React.createElement;
  function t(key, fb) {
    try { return (window.ArgusCopy && window.ArgusCopy.t(key, fb)) || fb || ''; }
    catch (err) { return fb || ''; }
  }

  /* ── Is this a real, renderable number? ────────────────────────────── */
  function hasValue(v) {
    if (v === null || v === undefined) return false;
    if (typeof v === 'number' && !isFinite(v)) return false;
    if (typeof v === 'string' && v.trim() === '') return false;
    return true;
  }

  /* ── Num — tabular figure that refuses to invent data ──────────────── */
  function Num(props) {
    props = props || {};
    var v = props.value;
    if (!hasValue(v)) {
      return e('span', {
        className: 'a-nodata',
        title: props.reason || t('data.none', 'No data'),
        'aria-label': props.reason || t('data.none', 'No data')
      });
    }
    var text = v;
    if (typeof v === 'number' && typeof props.decimals === 'number') {
      text = v.toFixed(props.decimals);
    }
    return e('span', {
      className: 'a-num ' + (props.className || ''),
      style: props.style || null
    },
      String(text),
      props.unit ? e('span', {
        style: { fontSize: '0.62em', opacity: 0.6, marginLeft: 3 }
      }, props.unit) : null
    );
  }

  /* ── Inline no-data marker ─────────────────────────────────────────── */
  function NoData(props) {
    props = props || {};
    var label = props.label || t('data.none', 'No data');
    return e('span', {
      className: 'a-nodata ' + (props.className || ''),
      title: props.reason || label,
      'aria-label': label
    }, props.showLabel ? label : null);
  }

  /* ── Block empty state — always states WHY ─────────────────────────── */
  function NoDataBlock(props) {
    props = props || {};
    return e('div', {
      className: 'a-nodata-block ' + (props.className || ''),
      role: 'status'
    },
      e('div', { className: 'a-nodata-title' },
        props.title || t('findings.empty', 'No data')),
      props.why ? e('div', { className: 'a-nodata-why' }, props.why) : null,
      props.action || null
    );
  }

  /* ── Not configured — capability ARGUS does not have YET ───────────── */
  function NotConfigured(props) {
    props = props || {};
    return e('div', {
      className: 'a-nodata-block a-notconfigured ' + (props.className || ''),
      role: 'status'
    },
      e('span', { className: 'a-nodata-tag' }, t('data.notConfigured', 'Not configured')),
      e('div', { className: 'a-nodata-title' }, props.what || t('data.notConfigured', 'Not configured')),
      e('div', { className: 'a-nodata-why' },
        props.why || t('data.notConfiguredWhy',
          'This view requires data ARGUS does not collect yet.')),
      props.action || null
    );
  }

  /* ── Unconfirmed evidence badge ────────────────────────────────────── */
  function Unproven(props) {
    props = props || {};
    return e('span', {
      className: 'a-unproven',
      title: props.title || 'Not backed by a successful tool result'
    }, props.label || t('findings.unproven', 'Unconfirmed'));
  }

  /* ── Engine degraded banner — a degraded run must never look clean ─── */
  function DegradedBanner(props) {
    props = props || {};
    if (!props.show) return null;
    return e('div', { className: 'a-degraded', role: 'alert' },
      e('span', null, t('scan.degraded', 'Engine degraded — results may be incomplete')),
      props.detail ? e('span', {
        style: { opacity: 0.75, fontWeight: 400 }
      }, ' · ' + props.detail) : null
    );
  }

  /* ── Section heading (layered IA) ──────────────────────────────────── */
  function SectionHeading(props) {
    props = props || {};
    return e('div', { className: 'a-section' },
      props.icon ? e('span', {
        style: { color: 'var(--accent)', fontSize: 12 }, 'aria-hidden': 'true'
      }, props.icon) : null,
      e('h2', { className: 'a-section-title' }, props.title || ''),
      e('span', { className: 'a-section-rule', 'aria-hidden': 'true' }),
      props.meta ? e('span', { className: 'a-section-meta' }, props.meta) : null
    );
  }

  /* ── Direction-aware delta chip ────────────────────────────────────── */
  function Delta(props) {
    props = props || {};
    if (!hasValue(props.value)) return e(NoData, { reason: props.reason });
    var n = Number(props.value);
    var dir = n > 0 ? 'up' : (n < 0 ? 'down' : 'flat');
    var goodWhen = props.goodWhen || 'down';
    var cls = 'is-flat';
    if (dir !== 'flat') cls = (dir === goodWhen) ? 'is-good' : 'is-bad';
    var arrow = dir === 'up' ? '▲' : (dir === 'down' ? '▼' : '—');
    return e('span', { className: 'a-delta ' + cls },
      e('span', { 'aria-hidden': 'true' }, arrow),
      e('span', null, (n > 0 ? '+' : '') + n + (props.unit || ''))
    );
  }

  /* ── Severity label with glyph (never hue alone) ───────────────────── */
  function Severity(props) {
    props = props || {};
    var sev = String(props.severity || 'info').toLowerCase();
    return e('span', {
      className: 'a-sev-' + sev + ' ' + (props.className || ''),
      style: { color: 'var(--' + (sev === 'info' ? 'info' : sev) + ')' }
    },
      e('span', { className: 'a-sev-glyph', 'aria-hidden': 'true' }),
      props.label || sev.toUpperCase()
    );
  }

  /* ── Avatar identity badge ─────────────────────────────────────────── */
  function AvatarBadge() {
    var id = 'blacksite';
    try { id = window.ArgusAvatar.current(); } catch (err) {}
    var m = null;
    try { m = window.ArgusAvatar.meta(id); } catch (err) {}
    return e('span', { className: 'a-avatar-badge', title: m ? m.persona : id },
      e('span', { className: 'dot', 'aria-hidden': 'true' }),
      m ? m.label : id
    );
  }

  window.ArgusUI = {
    hasValue: hasValue,
    Num: Num,
    NoData: NoData,
    NoDataBlock: NoDataBlock,
    NotConfigured: NotConfigured,
    Unproven: Unproven,
    DegradedBanner: DegradedBanner,
    SectionHeading: SectionHeading,
    Delta: Delta,
    Severity: Severity,
    AvatarBadge: AvatarBadge,
    t: t
  };
})();
