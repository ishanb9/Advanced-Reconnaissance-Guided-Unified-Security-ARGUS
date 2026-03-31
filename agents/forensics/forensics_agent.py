"""forensics_agent.py — Digital forensics orchestrator."""
from __future__ import annotations
import asyncio, logging
from typing import Any, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from agents.base_agent import BaseAgent, BroadcastFn
from agents.forensics.artifact_collect_subagent import ArtifactCollectSubagent
from agents.forensics.timeline_subagent          import TimelineSubagent
from agents.forensics.memory_analysis_subagent   import MemoryAnalysisSubagent
from db.schemas import AgentStatus

logger = logging.getLogger(__name__)


class ForensicsAgent(BaseAgent):
    LLM_ALLOWED = False

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__("forensics", broadcast)

    async def run(self, session_id: str, target: str,
                  db: Optional[AsyncIOMotorDatabase] = None,
                  os_type: str = "linux", dump_path: str = "",
                  attack_start: str = "", **kwargs: Any) -> dict:
        self._session_id = session_id
        result = {"all_findings": [], "errors": []}
        await self.set_status(AgentStatus.RUNNING, "Forensics assessment starting")
        kw = dict(session_id=session_id, target=target, broadcast=self.broadcast, db=db)

        # Collect artifacts first, then run timeline + memory in parallel
        await ArtifactCollectSubagent(**kw).execute(os_type=os_type)
        await asyncio.gather(
            TimelineSubagent(**kw).execute(os_type=os_type, attack_start=attack_start),
            MemoryAnalysisSubagent(**kw).execute(os_type=os_type, dump_path=dump_path),
            return_exceptions=True,
        )

        await self.set_status(AgentStatus.IDLE, "Forensics assessment complete")
        return result
