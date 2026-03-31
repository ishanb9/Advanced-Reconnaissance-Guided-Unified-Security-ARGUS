"""
cloud_agent.py — Cloud infrastructure attack orchestrator.

Orchestrates AWS, Azure, and GCP enumeration subagents.
Auto-detects provider or runs all three in parallel.
LLM_ALLOWED = False — pure subagent orchestrator.
"""
from __future__ import annotations
import asyncio, logging
from typing import Any, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from agents.base_agent import BaseAgent, BroadcastFn
from agents.cloud.aws_enum_subagent   import AwsEnumSubagent
from agents.cloud.azure_enum_subagent import AzureEnumSubagent
from agents.cloud.gcp_enum_subagent   import GcpEnumSubagent
from db.schemas import AgentStatus

logger = logging.getLogger(__name__)


class CloudAgent(BaseAgent):
    LLM_ALLOWED = False

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__("cloud", broadcast)

    async def run(self, session_id: str, target: str,
                  db: Optional[AsyncIOMotorDatabase] = None,
                  providers: list[str] | None = None, **kwargs: Any) -> dict:
        self._session_id = session_id
        providers = providers or ["aws", "azure", "gcp"]
        result    = {"all_findings": [], "errors": []}

        await self.set_status(AgentStatus.RUNNING, f"Cloud enumeration starting")
        kw = dict(session_id=session_id, target=target, broadcast=self.broadcast, db=db)

        async def _run(cls, extra=None):
            try:
                inst = cls(**kw)
                r = await inst.execute(**(extra or {}))
                return r
            except Exception as e:
                result["errors"].append(f"{cls.__name__}: {e}")

        tasks = []
        if "aws"   in providers: tasks.append(_run(AwsEnumSubagent))
        if "azure" in providers: tasks.append(_run(AzureEnumSubagent))
        if "gcp"   in providers: tasks.append(_run(GcpEnumSubagent))

        await asyncio.gather(*tasks, return_exceptions=True)
        await self.set_status(AgentStatus.IDLE, "Cloud enumeration complete")
        return result
