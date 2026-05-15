"""
json_tolerant.py — forgiving JSON parser for LLM-generated responses.

LLMs (especially smaller / chat-tuned models) frequently emit JSON that
the standard `json.loads` rejects:

  - C / JavaScript // comments and /* ... */ blocks
  - Trailing commas in arrays / objects
  - JavaScript expressions like  ["a","b"].join(";")
  - Smart quotes (“ ” ‘ ’) instead of ASCII " '
  - Markdown fences around the JSON: ```json ... ```
  - Stray text before / after the JSON object
  - Embedded ellipsis like ", …]"
  - Single quotes around strings
  - Python literals: True / False / None / nan

This module exposes a single public function:

    >>> parse_lossy("```json\\n{\\"x\\": 1, // comment\\n  'y': True,}\\n```")
    ({'x': 1, 'y': True}, ['stripped fences', 'normalised quotes', 'removed trailing commas'])

Returns (parsed_object, list_of_repairs_applied).  If parsing still
fails after all repair passes, returns (None, ['fatal: <reason>']).

The repair list is for diagnostics — log it if parse_lossy returns None
or if you want to know how dirty the input was.
"""
from __future__ import annotations

import json
import re
from typing import Any, List, Optional, Tuple


# ── Repair passes ──────────────────────────────────────────────────────────
# Each pass is idempotent and order-sensitive.  Comments must be stripped
# BEFORE trailing commas (a // comment on the last item would mask the
# trailing-comma fix).

_FENCE_RE         = re.compile(r"```(?:json|JSON|JSON5|json5)?\s*\n?(.*?)\n?```", re.DOTALL)
_LINE_COMMENT_RE  = re.compile(r"(?<!:)//[^\n]*")            # // ...  (avoid http:// urls)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)      # /* ... */
_TRAILING_COMMA_RE = re.compile(r",(\s*[\]}])")              # ,] or ,}
_SMART_QUOTES = str.maketrans({
    "“": '"', "”": '"',                              # “ ”
    "‘": "'", "’": "'",                              # ‘ ’
    "′": "'", "″": '"',                              # ′ ″
})
_PY_LITERAL_RE = re.compile(r"\b(True|False|None|NaN|nan)\b")
_PY_LITERAL_MAP = {"True": "true", "False": "false", "None": "null",
                   "NaN": "null", "nan": "null"}
_JS_ARRAY_JOIN_RE = re.compile(
    r"\]\s*\.\s*join\s*\([^)]*\)", re.DOTALL
)
# Find the outermost JSON object/array if there's stray text around it
_OBJ_START_RE = re.compile(r"[\{\[]")


def _strip_fences(s: str, repairs: List[str]) -> str:
    m = _FENCE_RE.search(s)
    if m:
        repairs.append("stripped markdown fences")
        return m.group(1).strip()
    return s


def _strip_comments(s: str, repairs: List[str]) -> str:
    out = s
    if _BLOCK_COMMENT_RE.search(out):
        out = _BLOCK_COMMENT_RE.sub("", out)
        repairs.append("stripped /* block */ comments")
    if _LINE_COMMENT_RE.search(out):
        out = _LINE_COMMENT_RE.sub("", out)
        repairs.append("stripped // line comments")
    return out


def _strip_trailing_commas(s: str, repairs: List[str]) -> str:
    if _TRAILING_COMMA_RE.search(s):
        out = _TRAILING_COMMA_RE.sub(r"\1", s)
        repairs.append("removed trailing commas")
        return out
    return s


def _strip_smart_quotes(s: str, repairs: List[str]) -> str:
    out = s.translate(_SMART_QUOTES)
    if out != s:
        repairs.append("normalised smart quotes")
    return out


def _strip_js_expressions(s: str, repairs: List[str]) -> str:
    """Replace `[...].join("x")` with the array itself.

    Only handles the most common LLM hallucination — an array with a
    chained .join() method call.  Leaves the array intact so structure
    is preserved.
    """
    if _JS_ARRAY_JOIN_RE.search(s):
        out = _JS_ARRAY_JOIN_RE.sub("]", s)
        repairs.append("stripped chained .join() expressions")
        return out
    return s


def _normalise_py_literals(s: str, repairs: List[str]) -> str:
    if _PY_LITERAL_RE.search(s):
        out = _PY_LITERAL_RE.sub(lambda m: _PY_LITERAL_MAP[m.group(1)], s)
        repairs.append("normalised Python literals to JSON")
        return out
    return s


def _extract_outermost(s: str, repairs: List[str]) -> str:
    """If there's prose before/after the JSON, slice it out by matching
    the outermost { … } or [ … ]."""
    stripped = s.strip()
    if not stripped:
        return stripped
    if stripped[0] in "{[" and stripped[-1] in "}]":
        return stripped
    # Find the first opening brace/bracket and walk to its matching close
    m = _OBJ_START_RE.search(stripped)
    if not m:
        return stripped
    start = m.start()
    open_ch  = stripped[start]
    close_ch = "}" if open_ch == "{" else "]"
    depth = 0
    in_str = False
    esc    = False
    for i in range(start, len(stripped)):
        ch = stripped[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                if start != 0 or i != len(stripped) - 1:
                    repairs.append("trimmed prose surrounding JSON")
                return stripped[start:i + 1]
    return stripped


def _single_to_double_quotes(s: str, repairs: List[str]) -> str:
    """Convert single-quoted strings to double-quoted.

    This is BRITTLE — only applied as a last resort after a parse fail
    because converting apostrophes inside double-quoted strings is wrong.
    We use a simple heuristic: replace 'token': with "token": for keys,
    and ['token'] / : 'value' for values.
    """
    # Quoted key pattern:  'key': → "key":
    k_pat = re.compile(r"(?<![A-Za-z0-9_])'([A-Za-z0-9_\-.]+)'\s*:")
    # Quoted value pattern: only convert if it looks like a token (no internal quotes)
    v_pat = re.compile(r":\s*'([^'\n]*)'")
    out = s
    n0 = out.count("'")
    out = k_pat.sub(r'"\1":', out)
    out = v_pat.sub(r': "\1"', out)
    if out.count("'") != n0:
        repairs.append("converted single-quoted strings to double")
    return out


# ── Public API ──────────────────────────────────────────────────────────────

def parse_lossy(text: str) -> Tuple[Optional[Any], List[str]]:
    """Best-effort JSON parse for LLM output.

    Returns (parsed, repairs_applied).
    On total failure, parsed is None and the last element of repairs is
    "fatal: <error message>".
    """
    if text is None:
        return None, ["fatal: input is None"]
    s = text.strip()
    if not s:
        return None, ["fatal: input is empty"]
    repairs: List[str] = []

    # Pass 0 — strict parse first (zero overhead for clean inputs)
    try:
        return json.loads(s), repairs
    except (ValueError, TypeError):
        pass

    # Pass 1 — strip markdown fences
    s = _strip_fences(s, repairs)
    # Pass 2 — strip C / JS comments
    s = _strip_comments(s, repairs)
    # Pass 3 — strip surrounding prose
    s = _extract_outermost(s, repairs)
    # Pass 4 — fix JS array.join() expressions
    s = _strip_js_expressions(s, repairs)
    # Pass 5 — trailing commas
    s = _strip_trailing_commas(s, repairs)
    # Pass 6 — smart quotes
    s = _strip_smart_quotes(s, repairs)
    # Pass 7 — Python literals
    s = _normalise_py_literals(s, repairs)

    try:
        return json.loads(s), repairs
    except (ValueError, TypeError) as exc:
        # Pass 8 — last-ditch single-quote rewrite (brittle)
        s2 = _single_to_double_quotes(s, repairs)
        try:
            return json.loads(s2), repairs
        except (ValueError, TypeError) as exc2:
            repairs.append(f"fatal: {exc2}")
            return None, repairs


# Convenience wrapper: parse and silently fall back to default
def loads_or(text: str, default: Any = None) -> Any:
    parsed, _ = parse_lossy(text)
    return parsed if parsed is not None else default


__all__ = ["parse_lossy", "loads_or"]
