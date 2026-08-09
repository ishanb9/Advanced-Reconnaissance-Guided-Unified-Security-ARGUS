"""Selectable report themes.

Each theme is a Jinja2 template file in this package, rendered from the SAME
``ReportGenerator._build_context`` that feeds the legacy templates.  This is
override-not-delete: the professional/dark templates in ``report/`` remain the
guaranteed fallback when a theme file is missing or fails to render.

Public API
----------
THEMES         : ordered dict of {key: {name, file, description}}
DEFAULT_THEME  : the key used when none is chosen (env ARGUS_REPORT_THEME)
get_theme(key) : raw Jinja2 template string for a key (default on miss)
list_themes()  : [{key, name, description}] for the UI picker
theme_path(key): pathlib.Path to the template file
"""
from __future__ import annotations

import os
from pathlib import Path

_DIR = Path(__file__).resolve().parent

# ── Single canonical report ──────────────────────────────────────────────────
# ARGUS ships ONE definitive report ("argus"): dark hero + light body, server-side
# inline-SVG charts, and every section (compromise basis, reproduction steps, MITRE,
# coverage, loot, AI/LLM, …).  The previous 5 selectable themes were consolidated into
# this one.  The registry/API surface is kept (single-entry) for backward-compat so the
# legacy ?theme= param and /report/themes endpoint keep working.
# The ONLY selectable PDF reports are the operator-authored "dark" and "light"
# designs, rendered by the vendored builder in ``report/argus_template`` (used
# verbatim).  ``"builder": True`` tells ReportGenerator._render to route these to
# that builder instead of a Jinja .j2 file.  The legacy ``argus.html.j2`` stays on
# disk purely as an internal safety fallback if the builder ever fails — it is NOT
# offered to the operator.
THEMES = {
    "dark":  {"name": "ARGUS — Dark",  "builder": True,
              "description": "ARGUS engagement report — dark theme"},
    "light": {"name": "ARGUS — Light", "builder": True,
              "description": "ARGUS engagement report — light theme"},
}

# ``ARGUS_REPORT_THEME`` selects between them; anything else resolves to the default.
DEFAULT_THEME = os.environ.get("ARGUS_REPORT_THEME", "dark")
if DEFAULT_THEME not in THEMES:
    DEFAULT_THEME = "dark"


def theme_path(key: str) -> Path:
    info = THEMES.get(key) or THEMES[DEFAULT_THEME]
    # builder themes (dark/light) render via report/argus_template, not a .j2 file;
    # point at the legacy fallback so path-based callers never KeyError.
    return _DIR / info.get("file", "argus.html.j2")


def is_builder_theme(key: str) -> bool:
    """True when ``key`` is rendered by the vendored builder (report/argus_template)
    rather than a Jinja .j2 file."""
    info = THEMES.get(key) or THEMES.get(DEFAULT_THEME) or {}
    return bool(info.get("builder"))


def get_theme(key: str) -> str:
    """Raw Jinja2 template string for ``key`` (falls back to the default theme,
    then to '' if the file is absent — the caller then uses the legacy template).
    Builder themes (dark/light) have no .j2 and return '' so the caller routes them
    to the vendored builder instead."""
    if is_builder_theme(key if key in THEMES else DEFAULT_THEME):
        return ""
    p = theme_path(key if key in THEMES else DEFAULT_THEME)
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""


def get_canonical_theme(key: str) -> str:
    """Raw template string for ``key`` UNCONDITIONALLY.

    Unlike ``get_theme`` (which returns '' for builder themes so the caller routes
    them to the vendored builder), this always reads the file ``theme_path`` resolves
    to — for the builder themes that is the canonical ``argus.html.j2``.  [68] the
    report render fallback uses this so, when the vendored builder path fails, it
    routes to argus.html.j2 + the report/charts.py SVG engine (the documented themed
    template) BEFORE the legacy dark==light fallback, instead of skipping it entirely.
    """
    p = theme_path(key if key in THEMES else DEFAULT_THEME)
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""


def list_themes():
    return [{"key": k, "name": v["name"], "description": v["description"]}
            for k, v in THEMES.items()]
