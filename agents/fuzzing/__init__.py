"""Human-controlled fuzzing lab (client feedback #6).

A separate, operator-driven fuzzing surface that runs IN PARALLEL with the
autonomous engagement.  Targets are restricted to what ARGUS has already
identified as in-scope; the human picks the technology type + fuzzer + config
and presses Start.  Anything the fuzzer surfaces is fed back to the agents.
"""
from .fuzz_lab import (          # noqa: F401
    FuzzLab,
    CATALOG,
    tech_types,
    fuzzers_for,
    scope_for_agent,
    start_lab,
    stop_lab,
    get_lab,
    list_labs,
)
