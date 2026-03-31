"""lateral_agent.py — Lateral movement orchestrator."""
from __future__ import annotations
import asyncio, logging
from typing import Any, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from agents.base_agent import BaseAgent, BroadcastFn
from agents.lateral.ad_enum_subagent    import AdEnumSubagent
from agents.lateral.kerberos_subagent   import KerberosSubagent
from agents.lateral.ntlm_capture_subagent import NtlmCaptureSubagent
from db.schemas import AgentStatus

logger = logging.getLogger(__name__)


class LateralAgent(BaseAgent):
    """
    Lateral movement phase orchestrator.

    Execution order:
      1. AD/domain enumeration (AD structure, users, shares, GPO)
      2. Kerberos attacks (Kerberoasting, AS-REP roasting) in parallel with
         NTLM capture (Responder loot, relay, credential reuse scanning)
    """
    LLM_ALLOWED = False

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__("lateral", broadcast)

    async def run(self, session_id: str, target: str,
                  db: Optional[AsyncIOMotorDatabase] = None,
                  domain: str = "",
                  dc_ip: str = "",
                  username: str = "",
                  password: str = "",
                  hashes: str = "",
                  interface: str = "eth0",
                  **kwargs: Any) -> dict:
        self._session_id = session_id
        result           = {"all_findings": [], "errors": []}

        await self.set_status(AgentStatus.RUNNING, "Lateral movement assessment starting")
        kw = dict(session_id=session_id, target=target, broadcast=self.broadcast, db=db)

        # Phase 1 — AD enumeration first (feeds Kerberos + NTLM stages)
        await AdEnumSubagent(**kw).execute(
            domain=domain, dc_ip=dc_ip,
            username=username, password=password,
        )

        # Phase 2 — Kerberos attacks + NTLM capture in parallel
        await asyncio.gather(
            KerberosSubagent(**kw).execute(
                domain=domain, dc_ip=dc_ip,
                username=username, password=password, hashes=hashes,
            ),
            NtlmCaptureSubagent(**kw).execute(
                interface=interface,
                domain=domain, dc_ip=dc_ip,
                username=username, password=password,
            ),
            return_exceptions=True,
        )

        await self.set_status(AgentStatus.IDLE, "Lateral movement assessment complete")
        return result
