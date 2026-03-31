"""evidence_agent.py — Evidence collection orchestrator."""
from __future__ import annotations
import asyncio, logging
from typing import Any, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from agents.base_agent import BaseAgent, BroadcastFn
from agents.evidence.screenshot_subagent  import ScreenshotSubagent
from agents.evidence.flag_capture_subagent import FlagCaptureSubagent
from db.schemas import AgentStatus

logger = logging.getLogger(__name__)


class EvidenceAgent(BaseAgent):
    LLM_ALLOWED = False

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__("evidence", broadcast)

    async def run(self, session_id: str, target: str,
                  db: Optional[AsyncIOMotorDatabase] = None,
                  os_type: str = "linux",
                  web_urls: list | None = None,
                  evidence_dir: str = "/tmp/pentest_evidence",
                  extra_flag_paths: list | None = None,
                  **kwargs: Any) -> dict:
        self._session_id = session_id
        result = {"all_findings": [], "errors": []}
        await self.set_status(AgentStatus.RUNNING, "Evidence collection starting")
        kw = dict(session_id=session_id, target=target, broadcast=self.broadcast, db=db)

        # Run both in parallel
        await asyncio.gather(
            ScreenshotSubagent(**kw).execute(
                os_type=os_type, web_urls=web_urls or [], evidence_dir=evidence_dir
            ),
            FlagCaptureSubagent(**kw).execute(
                os_type=os_type, evidence_dir=evidence_dir, extra_paths=extra_flag_paths or []
            ),
            return_exceptions=True,
        )

        await self.set_status(AgentStatus.IDLE, "Evidence collection complete")
        return result
