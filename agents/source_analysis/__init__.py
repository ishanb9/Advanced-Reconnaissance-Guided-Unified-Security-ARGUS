"""agents/source_analysis — source-available novel-bug discovery (Slice 2).

Static taint/variant analysis over a checked-out repo or decompiled source.  Surfaces
``CandidateSink`` records that the code-reasoning loop
(``agents/reasoning/code_hypothesis_engine.py``) navigates → hypothesises → proves via the
Slice-1 harness-build path.  All tools (semgrep/bandit/graudit) are local + optional, so a
missing tool degrades cleanly and never breaks the import.
"""
from __future__ import annotations
