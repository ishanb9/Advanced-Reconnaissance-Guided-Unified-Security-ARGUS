"""wireless_agent.py — Wireless security assessment orchestrator."""
from __future__ import annotations
import asyncio, logging
from typing import Any, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from agents.base_agent import BaseAgent, BroadcastFn
from agents.wireless.wifi_scan_subagent  import WifiScanSubagent
from agents.wireless.wpa2_crack_subagent import Wpa2CrackSubagent
from agents.wireless.evil_twin_subagent  import EvilTwinSubagent
from db.schemas import AgentStatus

logger = logging.getLogger(__name__)


class WirelessAgent(BaseAgent):
    LLM_ALLOWED = False

    def __init__(self, broadcast: Optional[BroadcastFn] = None):
        super().__init__("wireless", broadcast)

    async def run(self, session_id: str, target: str,
                  db: Optional[AsyncIOMotorDatabase] = None,
                  interface: str = "wlan0",
                  target_bssid: str = "",
                  target_ssid: str = "",
                  channel: int = 6,
                  wordlist: str = "/usr/share/wordlists/rockyou.txt",
                  do_evil_twin: bool = False,
                  evil_twin_mode: str = "wpe",
                  evidence_dir: str = "/tmp/pentest_evidence",
                  **kwargs: Any) -> dict:
        self._session_id = session_id
        result = {"all_findings": [], "errors": []}
        await self.set_status(AgentStatus.RUNNING, "Wireless assessment starting")
        kw = dict(session_id=session_id, target=target, broadcast=self.broadcast, db=db)

        # [67] Aggregate each subagent's SubagentResult into the returned dict — it was
        # built empty and returned empty because no .execute() result was ever captured,
        # so callers got {all_findings: [], errors: []} no matter what the run found.
        def _agg(res):
            if isinstance(res, Exception):
                result["errors"].append(f"{type(res).__name__}: {res}")
                return
            for _f in (getattr(res, "findings", None) or []):
                try:
                    result["all_findings"].append(_f.to_dict() if hasattr(_f, "to_dict") else _f)
                except Exception:
                    pass
            _e = getattr(res, "error", None)
            if _e:
                result["errors"].append(str(_e))

        # Phase 1: Scan
        _agg(await WifiScanSubagent(**kw).execute(
            interface=interface, evidence_dir=evidence_dir
        ))

        # Phase 2: WPA2 crack + optional evil twin in parallel
        tasks = [
            Wpa2CrackSubagent(**kw).execute(
                bssid=target_bssid, essid=target_ssid,
                channel=channel, interface=interface,
                wordlist=wordlist, evidence_dir=evidence_dir,
            ),
        ]
        if do_evil_twin:
            tasks.append(EvilTwinSubagent(**kw).execute(
                target_ssid=target_ssid, target_bssid=target_bssid,
                channel=channel, interface=interface,
                mode=evil_twin_mode, evidence_dir=evidence_dir,
            ))

        for _res in await asyncio.gather(*tasks, return_exceptions=True):
            _agg(_res)

        await self.set_status(AgentStatus.IDLE, "Wireless assessment complete")
        return result
