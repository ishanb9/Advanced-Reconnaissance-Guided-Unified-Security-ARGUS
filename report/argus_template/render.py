"""Render the vendored dark/light ARGUS report design from a live
``ReportGenerator._build_context`` dict.

The design (``build_report.py`` + ``charts.py`` + ``fonts.py`` +
``assets_fonts.css``) is used UNCHANGED — the builder reads its data through
``import data as D``, so we repopulate that ``data`` module from the live scan
context (``data.apply(ctx)``) and then call ``build_report.build(theme, out=...)``.

Thread-safe: the builder reads process-global module state, so the
populate-then-build step is serialised with a lock (a report build is fast and
CPU-light, so this never bottlenecks a scan).
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
import threading

logger = logging.getLogger("argus_report")

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:                      # let the builder's bare imports resolve
    sys.path.insert(0, _HERE)

_LOCK = threading.Lock()
THEMES = ("dark", "light")


def render_html(ctx: dict, theme: str = "dark") -> str:
    """Return the full standalone HTML for ``theme`` ('dark'|'light'), built from
    ``ctx`` (an ARGUS _build_context dict).  Never raises — on any failure returns
    '' so the caller can fall back to the legacy template."""
    import traceback
    theme = theme if theme in THEMES else "dark"
    try:
        with _LOCK:
            import data as _data              # vendored data layer (ARGUS-driven)
            import build_report as _br         # vendored builder (verbatim)
            try:
                _data.apply(ctx or {})         # live scan → the builder's data model
            except Exception as exc:           # noqa: BLE001
                logger.error("argus_template data.apply FAILED (%s) — rendering with empty defaults\n%s",
                             exc, traceback.format_exc())
            fd, tmp = tempfile.mkstemp(suffix=".html", prefix="argus_report_")
            os.close(fd)
            try:
                _br.build(theme, out=tmp, fragment=False)
                with open(tmp, "r", encoding="utf-8") as f:
                    return f.read()
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    except Exception as exc:                   # noqa: BLE001
        # LOUD: if this fails the caller falls back to the LEGACY design, which looks
        # identical for dark and light — the exact "same old report" symptom.  Make the
        # real reason unmissable in the scan log instead of a silent downgrade.
        logger.error("argus_template render_html FAILED for theme=%s (%s) — the report will "
                     "fall back to the LEGACY design. Root cause:\n%s",
                     theme, exc, traceback.format_exc())
        return ""
