"""Vendored ARGUS report design (dark + light).

The user-authored report builder — ``build_report.py`` (layout + CSS + JS),
``charts.py`` (inline-SVG gauge/bars), ``fonts.py`` + ``assets_fonts.css``
(embedded webfonts) — is used **verbatim, unchanged**.  Only ``data.py`` (the
data layer the builder reads via ``import data as D``) is ARGUS-driven: it
exposes the same names but is repopulated from a live
``ReportGenerator._build_context`` dict via ``data.apply(ctx)``.

``render.py`` is the only glue: it puts this directory on ``sys.path`` (so the
builder's bare ``import data``/``charts``/``fonts`` resolve), feeds the live
context in, and returns the built HTML string.
"""
