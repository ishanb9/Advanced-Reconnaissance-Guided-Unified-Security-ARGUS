"""engine.py — AIRedTeamEngine: drive a target_type='ai' engagement.

Loads the knowledge-driven probe catalog, runs each probe through the generic
harness against the human-configured target adapter, scores ASR with the dual
scorer, and records successful probes as findings through the SAME pipeline as
network findings (→ the #1 Issue-Validator gate → the #2 report themes).

Safe-by-default: destructive probes are gated behind ``_approve`` (off unless
ARGUS_AI_REDTEAM_AGGRESSIVE=1 or the operator approves).  The whole path is
behind ARGUS_AI_REDTEAM (default on); a non-AI engagement never reaches here.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from agents.ai_red_team import scorer
from agents.ai_red_team.finding_mapper import to_finding
from agents.ai_red_team.harness import run_probe
from agents.ai_red_team.probe_catalog import load_catalog
from agents.ai_red_team.target_adapter import make_adapter


class AIRedTeamEngine:
    def __init__(self, master, target_config: Dict[str, Any]):
        self.master = master
        self.cfg = target_config or {}

    def _approve(self, probe: Dict[str, Any]) -> bool:
        """Gate aggressive/destructive probes.  Default-deny unless the human
        opted in via ARGUS_AI_REDTEAM_AGGRESSIVE=1 (the autonomy/approval hook
        can be wired here later, mirroring the operator approval gate)."""
        return os.environ.get("ARGUS_AI_REDTEAM_AGGRESSIVE", "0") == "1"

    async def _emit(self, event: str, data: Dict[str, Any]) -> None:
        fn = getattr(self.master, "_emit", None)
        if fn is None:
            return
        try:
            await fn(event, data)
        except Exception:
            pass

    async def run(self, session_id: str) -> Dict[str, Any]:
        if os.environ.get("ARGUS_AI_REDTEAM", "1") == "0":
            return {"skipped": True}
        adapter = make_adapter(self.cfg)
        catalog = load_catalog()
        await self._emit("ai_red_team_start", {
            "session_id": session_id, "probes": len(catalog),
            "target": self.cfg.get("url") or self.cfg.get("model") or "ai-target",
            "adapter": self.cfg.get("type", "single_endpoint")})

        host = str(self.cfg.get("url") or self.cfg.get("model") or "ai-target")
        findings = 0
        try:
            from db.schemas import FindingSeverity as _FS
        except Exception:
            _FS = None

        for probe in catalog:
            try:
                res = await run_probe(probe, adapter, master=self.master,
                                      judge=scorer.judge, approve=self._approve)
            except Exception:
                continue
            if res.get("skipped"):
                continue
            await self._emit("ai_probe_result", {
                "session_id": session_id, "id": res.get("id"),
                "category": probe.get("category"), "asr": res.get("asr"),
                "success": res.get("success")})
            if res.get("success"):
                f = to_finding(probe, res)
                f["extra"]["target_model"] = self.cfg.get("model", "")
                sev = f["severity"]
                if _FS is not None:
                    sev = getattr(_FS, str(f["severity"]).upper(), _FS.MEDIUM)
                try:
                    await self.master.store_finding(
                        severity=sev, title=f["title"], description=f["description"],
                        host=host, tool_used=f["tool_used"], evidence=f["evidence"],
                        remediation=f["remediation"], extra=f["extra"])
                    findings += 1
                except Exception:
                    pass

        summary = {"session_id": session_id, "probes": len(catalog), "findings": findings}
        await self._emit("ai_red_team_summary", summary)
        return summary
