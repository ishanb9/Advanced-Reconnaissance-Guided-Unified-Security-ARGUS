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

THEMES = {
    "executive":     {"name": "Executive Consultancy",
                      "file": "executive.html.j2",
                      "description": "Light, corporate, board-ready"},
    "operator_dark": {"name": "Operator Dark / SOC",
                      "file": "operator_dark.html.j2",
                      "description": "Premium dark SOC console (prints light)"},
    "editorial":     {"name": "Editorial Whitepaper",
                      "file": "editorial.html.j2",
                      "description": "Serif display, research-report typesetting"},
    "compliance":    {"name": "Compliance / Framework",
                      "file": "compliance.html.j2",
                      "description": "Audit-grade GRC, MITRE/OWASP/CVSS-forward"},
    "threat_intel":  {"name": "Threat-Intel / Kill-chain",
                      "file": "threat_intel.html.j2",
                      "description": "Infographic breach-story, hero kill-chain"},
}

DEFAULT_THEME = os.environ.get("ARGUS_REPORT_THEME", "executive")
if DEFAULT_THEME not in THEMES:
    DEFAULT_THEME = "executive"


def theme_path(key: str) -> Path:
    info = THEMES.get(key) or THEMES[DEFAULT_THEME]
    return _DIR / info["file"]


def get_theme(key: str) -> str:
    """Raw Jinja2 template string for ``key`` (falls back to the default theme,
    then to '' if the file is absent — the caller then uses the legacy template)."""
    p = theme_path(key if key in THEMES else DEFAULT_THEME)
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""


def list_themes():
    return [{"key": k, "name": v["name"], "description": v["description"]}
            for k, v in THEMES.items()]
