"""finding_mapper.py — turn a probe verdict into a store_finding record.

AI-specific metrics (ASR, model, OWASP-LLM, ATLAS, attack vector) ride in the
finding's ``extra`` dict (forward-compatible — no schema change), so AI findings
flow through the same pipeline as network findings: the #1 Issue-Validator gate
(prose-evidence path) and the #2 report themes.
"""
from __future__ import annotations

from typing import Any, Dict

# Human-readable titles per OWASP-LLM attack class.
_TITLES = {
    "prompt_injection":     "Prompt injection",
    "indirect_injection":   "Indirect prompt injection",
    "jailbreak":            "Jailbreak / guardrail bypass",
    "system_prompt_leak":   "System-prompt leakage",
    "excessive_agency":     "Excessive agency / tool misuse",
    "insecure_output":      "Insecure output handling",
    "memory_poisoning":     "Memory poisoning / persistence",
    "unbounded_consumption": "Unbounded consumption / denial-of-wallet",
}

# Generic, content-agnostic remediation per class.
_REMED = {
    "prompt_injection":     "Enforce instruction/data separation; treat retrieved + tool-returned content as untrusted before the planner; re-apply output moderation.",
    "indirect_injection":   "Fence retrieved/tool content as data, never instructions; taint-track tool args back to untrusted sources.",
    "jailbreak":            "Layer input + output moderation; gate state-changing actions behind policy independent of the prompt.",
    "system_prompt_leak":   "Do not place secrets in the system prompt; server-side enforce schema; treat the prompt as non-confidential.",
    "excessive_agency":     "Least-privilege tool scoping; human-in-the-loop on external-egress / state-changing actions; authorize at the tool/data layer, not in the prompt.",
    "insecure_output":      "Encode/escape model output before it reaches a browser/shell/DB; never eval model output.",
    "memory_poisoning":     "Scan memory writes for instruction-like content; require provenance + integrity on long-term memory; isolate per-session.",
    "unbounded_consumption": "Rate-limit + budget per session/user; cap tool-call depth and output size.",
}

_SEV = {"critical", "high", "medium", "low", "info"}


def to_finding(probe: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    cat = str(probe.get("category", "") or "ai_finding")
    sev = str(probe.get("severity", "medium")).lower()
    if sev not in _SEV:
        sev = "medium"
    asr = result.get("asr", 0.0)
    title = _TITLES.get(cat, cat.replace("_", " ").title())
    transcript = str(result.get("transcript", ""))[:1500]
    return {
        "severity":    sev,
        "title":       title,
        "description": (f"{title} succeeded against the AI target "
                        f"(ASR {asr:.0%} over {result.get('trials', 0)} trials; "
                        f"OWASP {probe.get('owasp_llm','-')}, ATLAS {probe.get('atlas','-')}). "
                        "Probe: " + str(probe.get("id", "")) + "."),
        "evidence":    transcript or f"ASR {asr}",
        "remediation": _REMED.get(cat, "Apply AI-security controls for this class."),
        "tool_used":   "ai_red_team",
        "mitre":       str(probe.get("atlas", "") or ""),
        "extra": {
            "asr":           asr,
            "owasp_llm":     probe.get("owasp_llm", ""),
            "atlas":         probe.get("atlas", ""),
            "attack_vector": cat,
            "trials":        result.get("trials", 0),
            "successes":     result.get("successes", 0),
            "target_model":  result.get("target_model", ""),
            "ai_finding":    True,
        },
    }
