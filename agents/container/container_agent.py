"""container_agent.py — Container security audit orchestrator (Docker + K8s)."""
from __future__ import annotations
import asyncio, logging
from typing import Any, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from agents.base_agent import BaseAgent, BroadcastFn
from agents.container.docker_audit_subagent import DockerAuditSubagent
from agents.container.k8s_audit_subagent    import K8sAuditSubagent
from db.schemas import AgentStatus

logger = logging.getLogger(__name__)


class ContainerAgent(BaseAgent):
    LLM_ALLOWED = False

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__("container", broadcast)

    async def run(self, session_id: str, target: str,
                  db: Optional[AsyncIOMotorDatabase] = None,
                  run_docker: bool = True, run_k8s: bool = True, **kwargs: Any) -> dict:
        self._session_id = session_id
        result = {"all_findings": [], "errors": []}
        await self.set_status(AgentStatus.RUNNING, "Container security audit starting")
        kw = dict(session_id=session_id, target=target, broadcast=self.broadcast, db=db)

        tasks = []
        if run_docker: tasks.append(DockerAuditSubagent(**kw).execute())
        if run_k8s:    tasks.append(K8sAuditSubagent(**kw).execute())
        await asyncio.gather(*tasks, return_exceptions=True)

        await self.set_status(AgentStatus.IDLE, "Container audit complete")
        return result
