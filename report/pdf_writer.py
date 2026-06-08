"""
pdf_writer.py — dependency-free PDF generation for ARGUS reports.

Why this exists
---------------
The report endpoint used to shell out to `wkhtmltopdf`.  On a box where that
binary is absent (the common Kali case) `generate_pdf` returned None and the
server fell back to serving the HTML — which the frontend still saved with a
`.pdf` name.  The result was a "PDF" that began with `<!DOCTYPE html>` and would
not open in any PDF viewer ("corrupted PDF").

This module builds a REAL, valid PDF (proper `%PDF` header, object table, xref,
trailer) using only the Python standard library, so a downloadable, openable,
comprehensive report is ALWAYS produced regardless of what is installed.  It is
the guaranteed fallback; richer HTML-faithful engines (wkhtmltopdf / weasyprint /
reportlab) are still tried first by the caller when available.

It also contains `report_lines_from_context()` which turns the report context
(the same dict that feeds the HTML template) into a fully-structured, readable
document: target, scope, objectives + whether each was met, the attack
narrative (what was found → what was chosen to exploit and why → how root was
reached), every finding with its remediation, harvested credentials/loot, and
the captured flags.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

# A "line" is (kind, text).  kind ∈ {title, h1, h2, h3, body, bullet, small, rule, space}
Line = Tuple[str, str]

# ── A4 geometry (points) ─────────────────────────────────────────────────────
_PAGE_W, _PAGE_H = 595, 842
_MARGIN_L, _MARGIN_R, _MARGIN_T, _MARGIN_B = 50, 50, 800, 54
_USABLE_W = _PAGE_W - _MARGIN_L - _MARGIN_R

# Per-kind font size + line leading (vertical advance).
_SIZE = {"title": 22, "h1": 16, "h2": 13, "h3": 11,
         "body": 9.5, "bullet": 9.5, "small": 8, "rule": 2, "space": 6}
_LEAD = {"title": 30, "h1": 24, "h2": 19, "h3": 15,
         "body": 13, "bullet": 13, "small": 11, "rule": 8, "space": 8}
_BOLD = {"title", "h1", "h2", "h3"}


def _esc(s: str) -> str:
    """Escape text for a PDF literal string + drop non-Latin-1 chars."""
    out = []
    for ch in str(s):
        o = ord(ch)
        if ch in "\\()":
            out.append("\\" + ch)
        elif 32 <= o < 127 or 160 <= o <= 255:
            out.append(ch)
        else:
            out.append("?")          # non-Latin-1 (emoji, box-draw) → safe char
    return "".join(out)


def _wrap(text: str, size: float, indent: int = 0) -> List[str]:
    """Greedy word-wrap to the usable width (Helvetica avg char ≈ 0.5·size)."""
    avail = _USABLE_W - indent
    max_chars = max(8, int(avail / (size * 0.5)))
    words = str(text).replace("\t", "    ").split()
    if not words:
        return [""]
    lines, cur = [], ""
    for w in words:
        # Hard-split a single over-long token (e.g. a URL / base64 blob).
        while len(w) > max_chars:
            if cur:
                lines.append(cur); cur = ""
            lines.append(w[:max_chars]); w = w[max_chars:]
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= max_chars:
            cur += " " + w
        else:
            lines.append(cur); cur = w
    if cur:
        lines.append(cur)
    return lines


def lines_to_pdf(lines: List[Line], title: str = "ARGUS Report") -> bytes:
    """Render structured lines into a valid multi-page PDF (stdlib only)."""
    # 1. Flatten into wrapped, positioned draw-ops, paginating by height.
    pages: List[List[Tuple[float, float, float, bool, str]]] = []  # (x,y,size,bold,text)
    cur_ops: List[Tuple[float, float, float, bool, str]] = []
    y = _MARGIN_T

    def _new_page():
        nonlocal cur_ops, y
        if cur_ops:
            pages.append(cur_ops)
        cur_ops = []
        y = _MARGIN_T

    for kind, text in lines:
        size = _SIZE.get(kind, 9.5)
        lead = _LEAD.get(kind, 13)
        if kind == "space":
            y -= lead
            if y < _MARGIN_B:
                _new_page()
            continue
        if kind == "rule":
            if y - lead < _MARGIN_B:
                _new_page()
            # a rule is drawn as a thin row of underscores
            cur_ops.append((_MARGIN_L, y, 8, False,
                            "_" * max(8, int(_USABLE_W / 4))))
            y -= lead
            continue
        indent = 14 if kind == "bullet" else 0
        prefix = "- " if kind == "bullet" else ""
        wrapped = _wrap(prefix + str(text), size, indent)
        for i, wl in enumerate(wrapped):
            if y - lead < _MARGIN_B:
                _new_page()
            x = _MARGIN_L + (indent if (kind == "bullet" and i > 0) else 0)
            cur_ops.append((x, y, size, kind in _BOLD, wl))
            y -= lead
    _new_page()
    if not pages:
        pages = [[(_MARGIN_L, _MARGIN_T, 12, False, "(empty report)")]]

    # 2. Build the content stream for each page.
    def _stream_for(ops) -> bytes:
        parts = ["BT"]
        last_bold = None
        for (x, yv, size, bold, text) in ops:
            font = "/F2" if bold else "/F1"
            parts.append(f"{font} {size:.1f} Tf")
            parts.append(f"1 0 0 1 {x:.1f} {yv:.1f} Tm")
            parts.append(f"({_esc(text)}) Tj")
        parts.append("ET")
        return ("\n".join(parts)).encode("latin-1", "replace")

    # 3. Assemble objects.  Object numbering:
    #    1 Catalog, 2 Pages, 3 Font(Helvetica), 4 Font(Helvetica-Bold),
    #    then per page: Page object + Contents object.
    n_pages = len(pages)
    page_obj_ids = [5 + 2 * i for i in range(n_pages)]
    content_obj_ids = [6 + 2 * i for i in range(n_pages)]
    total_objs = 4 + 2 * n_pages

    objs: Dict[int, bytes] = {}
    objs[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objs[2] = f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode()
    objs[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    objs[4] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
    for i in range(n_pages):
        pid, cid = page_obj_ids[i], content_obj_ids[i]
        objs[pid] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {cid} 0 R >>"
        ).encode()
        stream = _stream_for(pages[i])
        objs[cid] = (f"<< /Length {len(stream)} >>\nstream\n".encode()
                     + stream + b"\nendstream")

    # 4. Serialise with a byte-accurate xref table.
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: Dict[int, int] = {}
    for oid in range(1, total_objs + 1):
        offsets[oid] = len(out)
        out += f"{oid} 0 obj\n".encode() + objs[oid] + b"\nendobj\n"

    xref_pos = len(out)
    out += f"xref\n0 {total_objs + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for oid in range(1, total_objs + 1):
        out += f"{offsets[oid]:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {total_objs + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF").encode()
    return bytes(out)


# ── Content: context dict → structured report lines ──────────────────────────
def _sev_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        str(sev or "info").lower(), 5)


def report_lines_from_context(ctx: Dict[str, Any]) -> List[Line]:
    """Turn the report context into a comprehensive, readable line list.

    Defensive: every field is optional; missing data degrades gracefully so the
    PDF is always produced.  This is the SAME data that feeds the HTML report —
    so the two stay consistent."""
    L: List[Line] = []
    sess = ctx.get("session") or {}
    target = sess.get("target") or sess.get("target_host") or ctx.get("target") or "the target"
    intel = ctx.get("intel") or {}
    findings = ctx.get("findings") or []
    flags = ctx.get("flags") or []
    creds = ctx.get("creds_summary") or []
    attack_path = ctx.get("attack_path") or []
    exploit_modules = ctx.get("exploit_modules") or []
    wc = ctx.get("win_conditions") or {}
    mb = ctx.get("mission_brief") or {}
    objectives = ctx.get("objectives") or []

    def add(kind, text=""):
        L.append((kind, text))

    # ── Cover ────────────────────────────────────────────────────────────────
    add("title", "ARGUS Penetration Test Report")
    add("space")
    add("h3", f"Target: {target}")
    add("body", f"Engagement type: {ctx.get('engagement_type', sess.get('target_type', 'pentest'))}")
    add("body", f"Generated: {ctx.get('generated_at', '')}")
    add("body", f"Duration: {ctx.get('duration', 'N/A')}")
    add("rule")
    add("space")

    # ── Executive summary ─────────────────────────────────────────────────────
    add("h1", "1. Executive Summary")
    es = ctx.get("executive_summary")
    if isinstance(es, dict):
        for k in ("overview", "summary", "narrative", "text"):
            if es.get(k):
                for para in str(es[k]).split("\n"):
                    if para.strip():
                        add("body", para.strip())
                break
        for key, label in (("risk_rating", "Overall risk"), ("posture", "Security posture")):
            if es.get(key):
                add("body", f"{label}: {es[key]}")
    elif es:
        for para in str(es).split("\n"):
            if para.strip():
                add("body", para.strip())
    if not es:
        n_crit = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
        add("body", f"ARGUS assessed {target} and recorded {len(findings)} finding(s) "
                    f"({n_crit} critical). {len(flags)} flag(s) were captured and "
                    f"{'an interactive foothold was' if intel.get('shell_access') else 'no foothold was'} "
                    "established. See the sections below for the full attack path and remediation.")
    add("space")

    # ── Objectives & outcomes ─────────────────────────────────────────────────
    add("h1", "2. Objectives & Outcomes")
    if mb.get("objective"):
        add("body", f"Stated objective: {mb['objective']}")
    if mb.get("notes"):
        add("body", f"Scope notes: {mb['notes']}")
    conds = wc.get("conditions") if isinstance(wc, dict) else None
    if conds:
        add("h3", f"Win conditions: {wc.get('achieved_count', 0)}/{wc.get('total', len(conds))} achieved "
                  f"({wc.get('progress_pct', 0)}%)")
        for c in conds:
            if not isinstance(c, dict):
                continue
            mark = "[ACHIEVED]" if c.get("achieved") else "[ not met ]"
            ev = f" — {c.get('evidence')}" if c.get("achieved") and c.get("evidence") else ""
            add("bullet", f"{mark} {c.get('name', '')}{ev}")
    elif objectives:
        for o in objectives:
            if isinstance(o, dict):
                mark = "[MET]" if o.get("answered") else "[open]"
                add("bullet", f"{mark} {o.get('question', '')}"
                              + (f" -> {o.get('answer')}" if o.get("answer") else ""))
    else:
        add("body", "No explicit objectives were recorded for this engagement.")
    add("space")

    # ── Target & attack surface ───────────────────────────────────────────────
    add("h1", "3. Target & Attack Surface")
    add("body", f"Operating system (guess): {intel.get('os_guess', 'unknown')}")
    ports = intel.get("open_ports") or []
    if ports:
        add("body", f"Open ports: {', '.join(str(p) for p in ports)}")
    svcs = intel.get("services") or {}
    if isinstance(svcs, dict) and svcs:
        add("h3", "Discovered services")
        for port, info in svcs.items():
            if isinstance(info, dict):
                add("bullet", f"{port}/tcp — {info.get('service', '?')} {info.get('version', '')}".rstrip())
            else:
                add("bullet", f"{port}/tcp — {info}")
    add("space")

    # ── Attack narrative ──────────────────────────────────────────────────────
    add("h1", "4. Attack Narrative")
    add("body", "How ARGUS progressed through the engagement, step by step:")
    if attack_path:
        for step in attack_path:
            if not isinstance(step, dict):
                continue
            ph = str(step.get("phase", "")).upper()
            add("h3", f"[{step.get('__step', '')}] {ph}")
            res = step.get("result") or step.get("detail") or ""
            for para in str(res).split("\n"):
                if para.strip():
                    add("body", para.strip())
    else:
        add("body", "(No step-by-step attack path was recorded.)")
    # which exploit was chosen + why
    if exploit_modules:
        add("h3", "Exploits considered & selected")
        for m in exploit_modules[:12]:
            if not isinstance(m, dict):
                continue
            cves = ", ".join(m.get("cves", []) or []) or m.get("product", "")
            url = m.get("url", "")
            used = " [SELECTED — drove the foothold]" if m.get("used") or m.get("selected") else ""
            add("bullet", f"{cves} {url}{used}".strip())
    add("space")

    # ── Findings ──────────────────────────────────────────────────────────────
    add("h1", "5. Findings")
    if findings:
        ordered = sorted(findings, key=lambda f: _sev_rank(f.get("severity")))
        for idx, f in enumerate(ordered, 1):
            sev = str(f.get("severity", "info")).upper()
            add("h2", f"5.{idx} [{sev}] {f.get('title', 'Untitled finding')}")
            desc = f.get("description") or f.get("detail") or ""
            for para in str(desc).split("\n"):
                if para.strip():
                    add("body", para.strip())
            if f.get("host") or f.get("port") or f.get("service"):
                loc = f"Affected: {f.get('host', target)}"
                if f.get("port"):
                    loc += f":{f.get('port')}"
                if f.get("service"):
                    loc += f" ({f.get('service')})"
                add("small", loc)
            rem = f.get("remediation") or f.get("recommendation") or _extract_remediation(desc)
            if rem:
                add("body", f"Remediation: {rem}")
            add("space")
    else:
        add("body", "No findings were recorded.")
    add("space")

    # ── Credentials & loot ────────────────────────────────────────────────────
    add("h1", "6. Credentials & Harvested Material")
    if creds:
        for c in creds:
            if not isinstance(c, dict):
                continue
            line = f"{c.get('user', '?')}"
            if c.get("domain"):
                line += f"@{c['domain']}"
            if c.get("password") and c["password"] not in ("(none)", "(see note)"):
                line += f" : {c['password']}"
            line += f"  (source: {c.get('source', 'unknown')})"
            add("bullet", line)
            if c.get("note"):
                add("small", str(c["note"]))
    else:
        add("body", "No credentials were harvested.")
    add("space")

    # ── Flags ─────────────────────────────────────────────────────────────────
    if flags:
        add("h1", "7. Captured Flags")
        for fl in flags:
            if isinstance(fl, dict):
                add("bullet", f"{str(fl.get('flag_type', '?')).upper()}: "
                              f"{fl.get('value', '')}  ({fl.get('location', '')})")
            else:
                add("bullet", str(fl))
        add("space")

    # ── Remediation roadmap ───────────────────────────────────────────────────
    add("h1", "8. Remediation Roadmap")
    crit_high = [f for f in findings if _sev_rank(f.get("severity")) <= 1]
    if crit_high:
        add("body", "Prioritised fixes (critical & high first):")
        for f in sorted(crit_high, key=lambda f: _sev_rank(f.get("severity"))):
            rem = f.get("remediation") or f.get("recommendation") or _extract_remediation(
                f.get("description") or "")
            add("bullet", f"[{str(f.get('severity', '')).upper()}] {f.get('title', '')}: "
                          f"{rem or 'Apply vendor patch / harden configuration.'}")
    else:
        add("body", "Address the findings in Section 5 in severity order; rotate any "
                    "exposed secrets and restrict network exposure of management services.")
    add("space")
    add("small", "Report generated by ARGUS. All testing was conducted against an "
                 "authorized, in-scope target.")
    return L


def _extract_remediation(desc: str) -> str:
    """Pull a 'Remediation: ...' / 'Fix: ...' clause out of a finding description."""
    if not desc:
        return ""
    low = str(desc)
    for marker in ("Remediation:", "remediation:", "Fix:", "Recommendation:", "Mitigation:"):
        i = low.find(marker)
        if i != -1:
            return low[i + len(marker):].strip()[:400]
    return ""
