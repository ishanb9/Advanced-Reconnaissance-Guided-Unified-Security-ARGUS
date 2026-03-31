"""traffic_agent.py — Network traffic analysis and MITM orchestrator."""
from __future__ import annotations
import asyncio, logging
from typing import Any, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from agents.base_agent import BaseAgent, BroadcastFn
from agents.traffic.pcap_capture_subagent    import PcapCaptureSubagent
from agents.traffic.credential_sniff_subagent import CredentialSniffSubagent
from agents.traffic.mitm_subagent            import MitmSubagent
from db.schemas import AgentStatus

logger = logging.getLogger(__name__)


class TrafficAgent(BaseAgent):
    LLM_ALLOWED = False

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__("traffic", broadcast)

    async def run(self, session_id: str, target: str,
                  db: Optional[AsyncIOMotorDatabase] = None,
                  interface: str = "eth0",
                  duration: int = 30,
                  victim_ip: str = "",
                  gateway_ip: str = "",
                  do_mitm: bool = False,
                  evidence_dir: str = "/tmp/pentest_evidence",
                  **kwargs: Any) -> dict:
        self._session_id = session_id
        result = {"all_findings": [], "errors": []}
        await self.set_status(AgentStatus.RUNNING, "Traffic analysis starting")
        kw = dict(session_id=session_id, target=target, broadcast=self.broadcast, db=db)

        tasks = [
            PcapCaptureSubagent(**kw).execute(
                interface=interface, duration=duration, evidence_dir=evidence_dir
            ),
            CredentialSniffSubagent(**kw).execute(
                interface=interface, duration=duration, evidence_dir=evidence_dir
            ),
        ]

        if do_mitm:
            tasks.append(MitmSubagent(**kw).execute(
                interface=interface, victim_ip=victim_ip,
                gateway_ip=gateway_ip, duration=duration,
            ))

        await asyncio.gather(*tasks, return_exceptions=True)

        await self.set_status(AgentStatus.IDLE, "Traffic analysis complete")
        return result
