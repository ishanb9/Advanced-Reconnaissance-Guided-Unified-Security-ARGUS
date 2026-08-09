"""report/charts.py — pure, dependency-free inline-SVG chart engine for the ARGUS report.

WeasyPrint (the PDF engine) executes NO JavaScript, so every chart in the report is a
server-side inline ``<svg>`` string produced here at render time.  These functions take
PRIMITIVE inputs (count dicts, ratios, row lists) — the report generator adapts the real
scan data into those primitives — so this module is fully decoupled from the data schema
and unit-testable in isolation.

Design tokens match the report's "dark hero + light body" aesthetic.  Every function is
defensive: empty / zero / missing inputs yield a valid (if empty-state) SVG, never a crash.

Public API (all return a self-contained ``<svg …>…</svg>`` string):
  severity_donut(counts)          — donut of finding severities + center total
  risk_gauge(ratio, label, color) — 180° gauge for the overall risk rating
  hbar_chart(rows)                — horizontal bars (coverage outcomes, MITRE tactics, …)
  vbar_chart(rows)                — vertical bars
  stacked_severity_bar(counts)    — single stacked 100% bar of the severity mix
  donut_generic(rows)             — donut for arbitrary labelled rows
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

# ── Design tokens ────────────────────────────────────────────────────────────
SEV_COLORS: Dict[str, str] = {
    "critical": "#c0392b",
    "high":     "#e8743b",
    "medium":   "#d9a441",
    "low":      "#3d7fc1",
    "info":     "#7a8699",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

OUTCOME_COLORS: Dict[str, str] = {
    "success":  "#c0392b",   # a successful attack step is bad news for the client
    "negative": "#2f9e5f",   # confirmed-not-exploitable = good
    "blocked":  "#d9a441",
    "error":    "#7a8699",
}

INK      = "#1a2332"
MUTED    = "#8a94a6"
GRID     = "#e7ebf0"
TRACK    = "#eef1f5"
ACCENT   = "#15233b"
ACCENT2  = "#3d7fc1"

# Kill-chain phase → colour (substring match, first hit wins).
PHASE_COLORS: Dict[str, str] = {
    "recon": "#3d5a80", "scan": "#3d5a80", "enum": "#3d5a80", "osint": "#3d5a80",
    "discovery": "#3d5a80",
    "vuln": "#d9a441",
    "exploit": "#c0392b", "foothold": "#c0392b", "initial": "#c0392b", "rce": "#c0392b",
    "web": "#c0392b",
    "privesc": "#e8743b", "privilege": "#e8743b", "escalation": "#e8743b",
    "cred": "#e8743b",
    "post": "#8e2f8e", "loot": "#8e2f8e", "exfil": "#8e2f8e", "collection": "#8e2f8e",
    "persist": "#6a4fb3",
    "lateral": "#2f7d64", "pivot": "#2f7d64",
}


def _phase_color(p: Any) -> str:
    key = str(p or "").strip().lower().replace(" ", "_")
    for k, v in PHASE_COLORS.items():
        if k in key:
            return v
    return ACCENT2


# ── helpers ──────────────────────────────────────────────────────────────────
def _esc(s: Any) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _polar(cx: float, cy: float, r: float, ang_deg: float) -> "tuple[float, float]":
    a = math.radians(ang_deg)
    return (cx + r * math.cos(a), cy + r * math.sin(a))


def _arc_path(cx: float, cy: float, r: float, a0: float, a1: float) -> str:
    """SVG path ``d`` for a circular arc from angle a0→a1 (degrees, 0°=east, CW)."""
    x0, y0 = _polar(cx, cy, r, a0)
    x1, y1 = _polar(cx, cy, r, a1)
    large = 1 if abs(a1 - a0) > 180 else 0
    sweep = 1 if a1 > a0 else 0
    return f"M {x0:.2f} {y0:.2f} A {r:.2f} {r:.2f} 0 {large} {sweep} {x1:.2f} {y1:.2f}"


def _empty(w: int, h: int, msg: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
            f'width="{w}" height="{h}" role="img">'
            f'<text x="{w/2:.0f}" y="{h/2:.0f}" text-anchor="middle" '
            f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" font-size="12" '
            f'fill="{MUTED}">{_esc(msg)}</text></svg>')


# ── severity donut ───────────────────────────────────────────────────────────
def severity_donut(counts: Dict[str, Any], size: int = 210, thickness: int = 26) -> str:
    """Donut of finding severities with the total in the centre + a legend column."""
    c = {k: int(_num((counts or {}).get(k))) for k in SEV_ORDER}
    total = sum(c.values())
    cx, cy = size * 0.36, size / 2
    r = (size / 2) - thickness / 2 - 6
    parts: List[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'width="{size}" height="{size}" role="img" aria-label="Findings by severity">']
    # track ring
    parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="none" '
                 f'stroke="{TRACK}" stroke-width="{thickness}"/>')
    if total > 0:
        ang = -90.0
        for k in SEV_ORDER:
            if c[k] <= 0:
                continue
            frac = c[k] / total
            a1 = ang + frac * 360.0
            # a full-circle single segment needs a tiny gap so the arc renders
            draw_a1 = a1 - 0.001 if frac >= 0.999 else a1
            parts.append(f'<path d="{_arc_path(cx, cy, r, ang, draw_a1)}" fill="none" '
                         f'stroke="{SEV_COLORS[k]}" stroke-width="{thickness}" '
                         f'stroke-linecap="butt"/>')
            ang = a1
    # centre total
    parts.append(f'<text x="{cx:.1f}" y="{cy-2:.1f}" text-anchor="middle" '
                 f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                 f'font-size="{size*0.20:.0f}" font-weight="800" fill="{INK}">{total}</text>')
    parts.append(f'<text x="{cx:.1f}" y="{cy+size*0.11:.1f}" text-anchor="middle" '
                 f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                 f'font-size="10" letter-spacing="1.5" fill="{MUTED}">FINDINGS</text>')
    # legend
    lx = size * 0.70
    ly = size * 0.20
    step = (size * 0.62) / max(len(SEV_ORDER), 1)
    for k in SEV_ORDER:
        parts.append(f'<rect x="{lx:.1f}" y="{ly-9:.1f}" width="11" height="11" rx="2" '
                     f'fill="{SEV_COLORS[k]}"/>')
        parts.append(f'<text x="{lx+18:.1f}" y="{ly:.1f}" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="11" fill="{INK}">{k.capitalize()}</text>')
        parts.append(f'<text x="{size-10:.1f}" y="{ly:.1f}" text-anchor="end" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="11" font-weight="700" fill="{INK}">{c[k]}</text>')
        ly += step
    parts.append("</svg>")
    return "".join(parts)


# ── risk gauge ───────────────────────────────────────────────────────────────
def risk_gauge(ratio: float, label: str, color: str = "#c0392b",
               size: int = 220, sublabel: str = "OVERALL RISK") -> str:
    """A 180° gauge; ``ratio`` in [0,1] fills the arc, ``label`` sits in the centre."""
    ratio = max(0.0, min(1.0, _num(ratio)))
    color = color or "#c0392b"
    w = size
    h = int(size * 0.62)
    cx, cy = w / 2, h - 10
    r = w / 2 - 18
    thickness = 18
    a0, a1 = 180.0, 360.0            # left → right, top semicircle
    fill_a1 = a0 + (a1 - a0) * ratio
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'width="{w}" height="{h}" role="img" aria-label="Overall risk">',
        f'<path d="{_arc_path(cx, cy, r, a0, a1)}" fill="none" stroke="{TRACK}" '
        f'stroke-width="{thickness}" stroke-linecap="round"/>']
    if ratio > 0:
        parts.append(f'<path d="{_arc_path(cx, cy, r, a0, fill_a1)}" fill="none" '
                     f'stroke="{color}" stroke-width="{thickness}" stroke-linecap="round"/>')
    parts.append(f'<text x="{cx:.1f}" y="{cy-14:.1f}" text-anchor="middle" '
                 f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                 f'font-size="{size*0.11:.0f}" font-weight="800" fill="{color}">{_esc(label)}</text>')
    parts.append(f'<text x="{cx:.1f}" y="{cy+2:.1f}" text-anchor="middle" '
                 f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                 f'font-size="10" letter-spacing="1.5" fill="{MUTED}">{_esc(sublabel)}</text>')
    parts.append("</svg>")
    return "".join(parts)


# ── horizontal bars ──────────────────────────────────────────────────────────
def hbar_chart(rows: List[Dict[str, Any]], width: int = 300, bar_h: int = 22,
               gap: int = 12, max_value: Optional[float] = None,
               label_w: int = 110) -> str:
    """Horizontal bar chart. ``rows`` = [{label, value, color?}]. Defensive on empty.
    Author at the width it will actually render (no CSS down-scaling) so the baked-in
    SVG text stays crisp in the PDF."""
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return _empty(width, 80, "No data")
    vmax = _num(max_value) if max_value else max((_num(r.get("value")) for r in rows), default=0)
    vmax = vmax or 1.0
    track_x = label_w
    track_w = width - label_w - 28          # tighter value gutter → more bar
    h = len(rows) * (bar_h + gap) + gap
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {h}" '
             f'width="{width}" height="{h}" role="img">']
    y = gap
    for r in rows:
        val = _num(r.get("value"))
        col = r.get("color") or ACCENT
        bw = (val / vmax) * track_w
        parts.append(f'<text x="{label_w-10}" y="{y+bar_h*0.68:.0f}" text-anchor="end" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="11.5" fill="{INK}">{_esc(r.get("label",""))}</text>')
        parts.append(f'<rect x="{track_x}" y="{y}" width="{track_w}" height="{bar_h}" '
                     f'rx="3" fill="{TRACK}"/>')
        parts.append(f'<rect x="{track_x}" y="{y}" width="{max(bw,2):.1f}" height="{bar_h}" '
                     f'rx="3" fill="{_esc(col)}"/>')
        parts.append(f'<text x="{width-10}" y="{y+bar_h*0.68:.0f}" text-anchor="end" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="11.5" font-weight="700" fill="{INK}">{int(val) if val==int(val) else val}</text>')
        y += bar_h + gap
    parts.append("</svg>")
    return "".join(parts)


# ── vertical bars ────────────────────────────────────────────────────────────
def vbar_chart(rows: List[Dict[str, Any]], width: int = 460, height: int = 200,
               max_value: Optional[float] = None) -> str:
    """Vertical bar chart. ``rows`` = [{label, value, color?}]."""
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return _empty(width, height, "No data")
    vmax = _num(max_value) if max_value else max((_num(r.get("value")) for r in rows), default=0)
    vmax = vmax or 1.0
    pad_b, pad_t = 34, 18
    plot_h = height - pad_b - pad_t
    n = len(rows)
    slot = width / n
    bw = min(slot * 0.55, 64)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
             f'width="{width}" height="{height}" role="img">']
    parts.append(f'<line x1="0" y1="{pad_t+plot_h}" x2="{width}" y2="{pad_t+plot_h}" '
                 f'stroke="{GRID}" stroke-width="1"/>')
    for i, r in enumerate(rows):
        val = _num(r.get("value"))
        col = r.get("color") or ACCENT
        bh = (val / vmax) * plot_h
        cx = slot * i + slot / 2
        x = cx - bw / 2
        y = pad_t + plot_h - bh
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{max(bh,2):.1f}" '
                     f'rx="3" fill="{_esc(col)}"/>')
        parts.append(f'<text x="{cx:.1f}" y="{y-5:.1f}" text-anchor="middle" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="11" font-weight="700" fill="{INK}">{int(val) if val==int(val) else val}</text>')
        parts.append(f'<text x="{cx:.1f}" y="{pad_t+plot_h+18:.1f}" text-anchor="middle" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="10.5" fill="{MUTED}">{_esc(r.get("label",""))}</text>')
    parts.append("</svg>")
    return "".join(parts)


# ── stacked 100% severity bar ────────────────────────────────────────────────
def stacked_severity_bar(counts: Dict[str, Any], width: int = 460, height: int = 30) -> str:
    """A single 100%-stacked bar of the severity mix (compact severity distribution)."""
    c = {k: int(_num((counts or {}).get(k))) for k in SEV_ORDER}
    total = sum(c.values())
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
             f'width="{width}" height="{height}" role="img">']
    if total <= 0:
        parts.append(f'<rect x="0" y="0" width="{width}" height="{height}" rx="5" fill="{TRACK}"/>')
        parts.append("</svg>")
        return "".join(parts)
    x = 0.0
    for k in SEV_ORDER:
        if c[k] <= 0:
            continue
        seg = (c[k] / total) * width
        parts.append(f'<rect x="{x:.1f}" y="0" width="{seg:.1f}" height="{height}" '
                     f'fill="{SEV_COLORS[k]}"/>')
        if seg > 24:
            parts.append(f'<text x="{x+seg/2:.1f}" y="{height*0.66:.0f}" text-anchor="middle" '
                         f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                         f'font-size="11" font-weight="700" fill="#fff">{c[k]}</text>')
        x += seg
    parts.append(f'<rect x="0" y="0" width="{width}" height="{height}" rx="5" fill="none" '
                 f'stroke="{GRID}" stroke-width="1"/>')
    parts.append("</svg>")
    return "".join(parts)


# ── generic donut ────────────────────────────────────────────────────────────
def donut_generic(rows: List[Dict[str, Any]], size: int = 210, thickness: int = 26,
                  center_label: str = "", center_sub: str = "") -> str:
    """Donut for arbitrary labelled rows [{label, value, color}] with a legend column."""
    rows = [r for r in (rows or []) if isinstance(r, dict) and _num(r.get("value")) > 0]
    total = sum(_num(r.get("value")) for r in rows)
    cx, cy = size * 0.36, size / 2
    r = (size / 2) - thickness / 2 - 6
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
             f'width="{size}" height="{size}" role="img">']
    parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="none" '
                 f'stroke="{TRACK}" stroke-width="{thickness}"/>')
    ang = -90.0
    for row in rows:
        frac = _num(row.get("value")) / (total or 1)
        a1 = ang + frac * 360.0
        draw_a1 = a1 - 0.001 if frac >= 0.999 else a1
        parts.append(f'<path d="{_arc_path(cx, cy, r, ang, draw_a1)}" fill="none" '
                     f'stroke="{_esc(row.get("color") or ACCENT)}" stroke-width="{thickness}"/>')
        ang = a1
    if center_label:
        parts.append(f'<text x="{cx:.1f}" y="{cy-2:.1f}" text-anchor="middle" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="{size*0.19:.0f}" font-weight="800" fill="{INK}">{_esc(center_label)}</text>')
    if center_sub:
        parts.append(f'<text x="{cx:.1f}" y="{cy+size*0.11:.1f}" text-anchor="middle" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="10" letter-spacing="1.5" fill="{MUTED}">{_esc(center_sub)}</text>')
    lx = size * 0.70
    ly = size * 0.24
    step = (size * 0.54) / max(len(rows), 1)
    for row in rows:
        parts.append(f'<rect x="{lx:.1f}" y="{ly-9:.1f}" width="11" height="11" rx="2" '
                     f'fill="{_esc(row.get("color") or ACCENT)}"/>')
        parts.append(f'<text x="{lx+18:.1f}" y="{ly:.1f}" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="11" fill="{INK}">{_esc(row.get("label",""))}</text>')
        parts.append(f'<text x="{size-10:.1f}" y="{ly:.1f}" text-anchor="end" '
                     f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                     f'font-size="11" font-weight="700" fill="{INK}">{int(_num(row.get("value")))}</text>')
        ly += step
    parts.append("</svg>")
    return "".join(parts)


# ── attack path / kill-chain ─────────────────────────────────────────────────
def _phase_label(phase: Any) -> str:
    """Human-readable kill-chain phase for the node eyebrow.

    The generator may hand us a bare string ("chain_analysis") OR a Python enum's
    ``str()`` repr ("AttackPhase.RECON").  Strip any ``ClassName.`` prefix and the
    underscores so the eyebrow reads "RECON" / "CHAIN ANALYSIS" — never the raw,
    clipped enum ("ATTACKPHASE.RE")."""
    s = str(phase or "").strip()
    if "." in s:                       # AttackPhase.RECON -> RECON
        s = s.rsplit(".", 1)[-1]
    return s.replace("_", " ").strip().upper()[:14]


def _clean_label_glyphs(s: Any) -> str:
    """Drop symbol/emoji codepoints that the report's sans/serif fonts lack (they
    render as a 'tofu' box in the PDF, e.g. the ⌗ that appeared before some
    attack-path node labels).  Keeps ASCII plus the arrows / dashes / bullets that
    the fonts DO have, so 'Recon → Internal' stays intact."""
    keep_hi = {0x2013, 0x2014, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2026,
               0x2190, 0x2192, 0x00B7}   # – — ' ' " " • … ← → ·
    out = []
    for ch in str(s or ""):
        o = ord(ch)
        if o < 0x2000 or o in keep_hi:
            out.append(ch)
        # else: dingbat / misc-technical / emoji / symbol → drop (font can't render)
    return "".join(out)


def _wrap_label(text: str, limit: int = 18) -> List[str]:
    """Word-wrap a label into at most 2 lines that EACH fit ``limit`` characters.

    Guarantees no emitted line exceeds ``limit`` (a long unbroken token — e.g.
    "MSSQL/MySQL/PG/Mongo/Redis" or "512/513/514" — is hard-truncated with an
    ellipsis rather than overflowing the fixed-width node box).  This is what
    stops the attack-path node text spilling past its card border in the PDF."""
    words = _clean_label_glyphs(text).split()
    if not words:
        return [""]
    lines: List[str] = []
    cur = ""
    dropped = False
    for w in words:
        cand = (cur + " " + w).strip()
        if len(cand) <= limit or not cur:
            cur = cand
        else:
            lines.append(cur)
            cur = w
        if len(lines) == 2:
            dropped = True             # ran out of lines with words left
            break
    if cur and len(lines) < 2:
        lines.append(cur)
    lines = lines[:2]
    out: List[str] = []
    for i, ln in enumerate(lines):
        if len(ln) > limit:
            out.append(ln[:limit - 1] + "…")
        elif dropped and i == len(lines) - 1 and len(ln) + 1 <= limit:
            out.append(ln + "…")
        else:
            out.append(ln)
    return out or [""]


def killchain(steps: List[Dict[str, Any]], width: int = 640, per_row: int = 4,
              node_w: int = 132, node_h: int = 56, gap: int = 30, v_gap: int = 40) -> str:
    """Numbered attack-path / kill-chain diagram (server-side inline SVG).
    ``steps`` = [{label, phase, sub?}].  Nodes are colour-coded by phase, numbered so
    the sequence reads across wrapped rows, with in-row arrows.  Defensive on empty.

    The viewBox width is grown to fit the widest row (plus a margin) so NODES/ARROWS
    ARE NEVER CLIPPED; the container's ``max-width:100%`` then scales it to fit."""
    steps = [s for s in (steps or []) if isinstance(s, dict)]
    if not steps:
        return _empty(width, 90, "No attack path recorded for this engagement")
    steps = steps[:12]
    rows = [steps[i:i + per_row] for i in range(0, len(steps), per_row)]
    _cols = min(per_row, len(steps))
    _content_w = _cols * node_w + (_cols - 1) * gap
    width = max(width, _content_w + 28)          # 14px margin each side — never clip
    height = len(rows) * (node_h + v_gap) + v_gap
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
             f'width="{width}" height="{height}" role="img" aria-label="Attack path">',
             '<defs><marker id="ac-arrow" markerWidth="10" markerHeight="10" refX="7" '
             'refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#9aa6b5"/></marker></defs>']
    n = 0
    y = v_gap
    for row in rows:
        row_w = len(row) * node_w + (len(row) - 1) * gap
        x = (width - row_w) / 2
        for j, s in enumerate(row):
            n += 1
            col = _phase_color(s.get("phase"))
            parts.append(f'<rect x="{x:.1f}" y="{y}" width="{node_w}" height="{node_h}" '
                         f'rx="7" fill="{col}"/>')
            # step number chip
            parts.append(f'<circle cx="{x+13:.1f}" cy="{y+13:.1f}" r="9" fill="#ffffff" '
                         f'fill-opacity="0.9"/>')
            parts.append(f'<text x="{x+13:.1f}" y="{y+17:.1f}" text-anchor="middle" '
                         f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                         f'font-size="11" font-weight="800" fill="{col}">{n}</text>')
            # phase eyebrow (human label — never the raw enum repr)
            parts.append(f'<text x="{x+node_w-8:.1f}" y="{y+15:.1f}" text-anchor="end" '
                         f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                         f'font-size="9" letter-spacing="1" fill="#ffffff" fill-opacity="0.78">'
                         f'{_esc(_phase_label(s.get("phase")))}</text>')
            # label (up to 2 lines, each guaranteed to fit the node width)
            lines = _wrap_label(s.get("label", ""), 18)
            ly = y + node_h / 2 + (2 if len(lines) == 1 else -3)
            for li, ln in enumerate(lines):
                parts.append(f'<text x="{x+node_w/2:.1f}" y="{ly+li*13:.1f}" text-anchor="middle" '
                             f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
                             f'font-size="11" font-weight="700" fill="#ffffff">{_esc(ln)}</text>')
            if j < len(row) - 1:
                ax0 = x + node_w
                ax1 = x + node_w + gap - 4
                parts.append(f'<line x1="{ax0:.1f}" y1="{y+node_h/2:.1f}" x2="{ax1:.1f}" '
                             f'y2="{y+node_h/2:.1f}" stroke="#9aa6b5" stroke-width="2" '
                             f'marker-end="url(#ac-arrow)"/>')
            x += node_w + gap
        y += node_h + v_gap
    parts.append("</svg>")
    return "".join(parts)
