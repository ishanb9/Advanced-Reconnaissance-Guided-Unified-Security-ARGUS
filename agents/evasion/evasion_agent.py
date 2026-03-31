"""evasion_agent.py — AV/EDR evasion orchestrator."""
from __future__ import annotations
import asyncio, logging
from typing import Any, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from agents.base_agent import BaseAgent, BroadcastFn
from agents.evasion.amsi_bypass_subagent   import AmsiBypassSubagent
from agents.evasion.av_evasion_subagent    import AvEvasionSubagent
from agents.evasion.defense_enum_subagent  import DefenseEnumSubagent
from db.schemas import AgentStatus

logger = logging.getLogger(__name__)


class EvasionAgent(BaseAgent):
    LLM_ALLOWED = False

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__("evasion", broadcast)

    async def run(self, session_id: str, target: str,
                  db: Optional[AsyncIOMotorDatabase] = None,
                  os_type: str = "linux", lhost: str = "LHOST", lport: int = 4444,
                  **kwargs: Any) -> dict:
        self._session_id = session_id
        result = {"all_findings": [], "errors": []}
        await self.set_status(AgentStatus.RUNNING, "Evasion assessment starting")
        kw = dict(session_id=session_id, target=target, broadcast=self.broadcast, db=db)

        # Defense enum first, then payload generation
        await DefenseEnumSubagent(**kw).execute(os_type=os_type)
        tasks = [
            AvEvasionSubagent(**kw).execute(os_type=os_type, lhost=lhost, lport=lport),
        ]
        if os_type == "windows":
            tasks.append(AmsiBypassSubagent(**kw).execute())
        await asyncio.gather(*tasks, return_exceptions=True)

        await self.set_status(AgentStatus.IDLE, "Evasion assessment complete")
        return result
