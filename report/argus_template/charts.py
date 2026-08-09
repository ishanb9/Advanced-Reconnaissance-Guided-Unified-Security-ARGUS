# -*- coding: utf-8 -*-
"""SVG chart generators. Colors reference CSS custom properties so they stay
centralized and theme-consistent. Geometry is computed here to avoid arc-math bugs."""
import math

SEV_VAR = {  # severity -> css var name
    "Critical": "--sev-crit", "High": "--sev-high", "Medium": "--sev-med",
    "Low": "--sev-low", "Info": "--sev-info",
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def donut(counts, total, size=260, thickness=34, gap_deg=3.2):
    """Severity donut. Stroke-arc segments with a surface gap between them."""
    cx = cy = size / 2
    r = (size - thickness) / 2 - 6
    # start at top (12 o'clock) = -90deg, go clockwise
    segs = [(s, counts.get(s, 0)) for s in SEV_ORDER if counts.get(s, 0) > 0]
    n_nonzero = len(segs)
    parts = []
    # faint track
    parts.append(
        '<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="var(--line)" '
        'stroke-width="%.1f"/>' % (cx, cy, r, thickness))
    angle = -90.0
    for sev, val in segs:
        frac = val / total
        sweep = frac * 360.0
        a1 = angle + gap_deg / 2
        a2 = angle + sweep - gap_deg / 2
        if a2 <= a1:  # tiny segment safeguard
            a2 = a1 + 0.4
        parts.append(_arc(cx, cy, r, a1, a2, thickness, "var(%s)" % SEV_VAR[sev],
                          klass="don-seg", title="%s · %d" % (sev, val)))
        angle += sweep
    inner = (
        '<text x="%.1f" y="%.1f" text-anchor="middle" class="don-num">%d</text>'
        '<text x="%.1f" y="%.1f" text-anchor="middle" class="don-lbl">FINDINGS</text>'
        % (cx, cy - 4, total, cx, cy + 18))
    return (
        '<svg viewBox="0 0 %d %d" class="donut" role="img" '
        'aria-label="Findings by severity: %s">%s%s</svg>'
        % (size, size, _aria(counts), "".join(parts), inner))


def _arc(cx, cy, r, a1, a2, width, color, klass="", title=""):
    """Stroke arc between two angles (degrees, clockwise, 0deg = +x, -90 = top)."""
    def pt(a):
        rad = math.radians(a)
        return cx + r * math.cos(rad), cy + r * math.sin(rad)
    x1, y1 = pt(a1)
    x2, y2 = pt(a2)
    large = 1 if (a2 - a1) > 180 else 0
    t = ('<title>%s</title>' % title) if title else ''
    return ('<path class="%s" d="M %.2f %.2f A %.2f %.2f 0 %d 1 %.2f %.2f" '
            'fill="none" stroke="%s" stroke-width="%.1f" stroke-linecap="butt">%s</path>'
            % (klass, x1, y1, r, r, large, x2, y2, color, width, t))


def _aria(counts):
    return ", ".join("%d %s" % (counts.get(s, 0), s) for s in SEV_ORDER)


def risk_gauge(level, size_w=300, size_h=176):
    """Semicircular 5-band risk gauge with a marker at `level`."""
    level = level.capitalize() if level.isupper() else level
    order = ["Info", "Low", "Medium", "High", "Critical"]  # left -> right
    cx, cy = size_w / 2, size_h - 16
    r = size_w / 2 - 22
    tw = 20  # track width
    seg = 180.0 / 5
    pad = 2.4
    parts = []
    for i, sev in enumerate(order):
        # left(180) -> right(0); segment i occupies [180 - i*seg , 180 - (i+1)*seg]
        a_start = 180 - i * seg
        a_end = 180 - (i + 1) * seg
        # convert to our arc convention (clockwise increasing). We draw upper semicircle
        # using negative angles so the arc bows upward.
        a1 = -a_start + pad
        a2 = -a_end - pad
        active = (sev == level)
        color = "var(%s)" % SEV_VAR[sev]
        op = "" if active else ' opacity="0.32"'
        parts.append(
            _arc_up(cx, cy, r, a1, a2, tw, color, extra=op, title="%s" % sev))
    # marker at center of the active band
    idx = order.index(level)
    mid = 180 - (idx + 0.5) * seg
    mrad = math.radians(mid)
    mx = cx + (r) * math.cos(mrad)
    my = cy - (r) * math.sin(mrad)
    ix = cx + (r - tw / 2 - 12) * math.cos(mrad)
    iy = cy - (r - tw / 2 - 12) * math.sin(mrad)
    parts.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="var(--ink)" '
                 'stroke-width="2.2" stroke-linecap="round"/>' % (cx, cy, ix, iy))
    parts.append('<circle cx="%.1f" cy="%.1f" r="4.6" fill="var(--ink)"/>' % (cx, cy))
    parts.append('<circle cx="%.1f" cy="%.1f" r="5.4" fill="var(%s)" stroke="var(--plane)" '
                 'stroke-width="2"/>' % (mx, my, SEV_VAR[level]))
    return ('<svg viewBox="0 0 %d %d" class="gauge" role="img" aria-label="Overall risk: %s">%s</svg>'
            % (size_w, size_h, level, "".join(parts)))


def _arc_up(cx, cy, r, a1, a2, width, color, extra="", title=""):
    """Arc on the upper semicircle. Angles in degrees with 0=+x, +90=up (math convention)."""
    def pt(a):
        rad = math.radians(a)
        return cx + r * math.cos(rad), cy - r * math.sin(rad)
    x1, y1 = pt(a1)
    x2, y2 = pt(a2)
    large = 1 if abs(a2 - a1) > 180 else 0
    sweep = 1 if a2 < a1 else 0
    t = ('<title>%s</title>' % title) if title else ''
    return ('<path d="M %.2f %.2f A %.2f %.2f 0 %d %d %.2f %.2f" fill="none" '
            'stroke="%s" stroke-width="%.1f" stroke-linecap="round"%s>%s</path>'
            % (x1, y1, r, r, large, sweep, x2, y2, color, width, extra, t))
