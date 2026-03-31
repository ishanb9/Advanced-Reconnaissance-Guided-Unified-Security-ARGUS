"""
iot_agent.py — IoT Assessment Orchestrator

Coordinates IoT-specific testing phases:
  1. Device Scan       — Fingerprint IoT device, discover protocols
  2. Default Creds     — Test default credentials across all services
  3. Protocol Testing  — Deep test MQTT, CoAP, Modbus, RTSP, TR-069, UPnP
  4. Firmware Analysis — Extract version info, correlate CVEs, run vuln scripts

Activated by MasterAgent when:
  - target_type == "iot"
  - OR IoT-characteristic ports discovered during recon
    (1883, 5683, 502, 47808, 7547, 554 etc.)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

import db.mongo_client as _db
from db.schemas import AgentName, AttackPhase, FindingSeverity, WebSocketMessage

from agents.iot.iot_device_scan_subagent import IoTDeviceScanSubagent
from agents.iot.iot_default_creds_subagent import IoTDefaultCredsSubagent
from agents.iot.iot_protocol_subagent import IoTProtocolSubagent
from agents.iot.iot_firmware_subagent import IoTFirmwareSubagent

logger = logging.getLogger(__name__)

# IoT-characteristic ports — if any found during recon, switch to IoT mode
IOT_INDICATOR_PORTS = {
    1883, 8883,   # MQTT
    5683,          # CoAP
    502,           # Modbus
    47808,         # BACnet
    7547,          # TR-069
    4840,          # OPC-UA
    554,           # RTSP
    161,           # SNMP (also common on routers/cameras)
    23,            # Telnet (still prevalent on embedded devices)
}


def is_iot_target(target_type: str, open_ports: list) -> bool:
    """Return True if the target should be treated as IoT."""
    if target_type and target_type.lower() in ("iot", "ics", "scada", "embedded"):
        return True
    port_ints = set()
    for p in open_ports:
        try:
            port_ints.add(int(str(p).split("/")[0]))
        except (ValueError, AttributeError):
            pass
    return bool(port_ints & IOT_INDICATOR_PORTS)


class IoTAgent:
    """
    Orchestrates all IoT-specific subagents for a single target IP.
    Called directly by MasterAgent when IoT mode is detected.
    """

    def __init__(
        self,
        session_id: str,
        target:     str,
        broadcast:  Callable[[Any], Coroutine[Any, Any, None]],
        db:         AsyncIOMotorDatabase,
    ) -> None:
        self.session_id = session_id
        self.target     = target
        self.broadcast  = broadcast
        self.db         = db
        self._stop      = False

    def request_stop(self) -> None:
        self._stop = True

    # ── Main entry point ───────────────────────────────────────────────────────

    async def run(
        self,
        open_ports: List[int] = None,
        services:   Dict      = None,
        **kwargs,
    ) -> Dict:
        """
        Run all IoT assessment phases sequentially.
        Returns a summary dict with finding counts per phase.
        """
        open_ports = open_ports or []
        services   = services   or {}
        summary    = {"device_scan": 0, "default_creds": 0, "protocol": 0, "firmware": 0}

        await self._emit("iot_phase_start", {
            "phase":   "iot",
            "target":  self.target,
            "message": f"Starting IoT assessment on {self.target} ({len(open_ports)} open ports)",
        })

        # ── Phase 1: Device fingerprinting ────────────────────────────────────
        if not self._stop:
            logger.info("[IoTAgent] Phase 1: Device scan on %s", self.target)
            scan_sa = IoTDeviceScanSubagent(
                session_id=self.session_id,
                target=self.target,
                broadcast=self._raw_broadcast,
                db=self.db,
            )
            scan_result = await scan_sa.run(self.target, open_ports=open_ports, services=services)
            await self._store_findings(scan_result.findings, AttackPhase.IOT)
            summary["device_scan"] = len(scan_result.findings)

            # Merge any newly discovered ports
            for f in scan_result.findings:
                if f.port and f.port not in open_ports:
                    open_ports.append(f.port)

        # ── Phase 2: Default credential testing ───────────────────────────────
        if not self._stop:
            logger.info("[IoTAgent] Phase 2: Default creds on %s", self.target)
            creds_sa = IoTDefaultCredsSubagent(
                session_id=self.session_id,
                target=self.target,
                broadcast=self._raw_broadcast,
                db=self.db,
            )
            creds_result = await creds_sa.run(
                self.target,
                open_ports=[str(p) for p in open_ports],
                services=services,
            )
            await self._store_findings(creds_result.findings, AttackPhase.IOT)
            summary["default_creds"] = len(creds_result.findings)

        # ── Phase 3: Protocol deep testing ────────────────────────────────────
        if not self._stop:
            logger.info("[IoTAgent] Phase 3: Protocol testing on %s", self.target)
            proto_sa = IoTProtocolSubagent(
                session_id=self.session_id,
                target=self.target,
                broadcast=self._raw_broadcast,
                db=self.db,
            )
            proto_result = await proto_sa.run(
                self.target,
                open_ports=[str(p) for p in open_ports],
            )
            await self._store_findings(proto_result.findings, AttackPhase.IOT)
            summary["protocol"] = len(proto_result.findings)

        # ── Phase 4: Firmware analysis & CVE correlation ──────────────────────
        if not self._stop:
            logger.info("[IoTAgent] Phase 4: Firmware analysis on %s", self.target)
            fw_sa = IoTFirmwareSubagent(
                session_id=self.session_id,
                target=self.target,
                broadcast=self._raw_broadcast,
                db=self.db,
            )
            fw_result = await fw_sa.run(
                self.target,
                open_ports=[str(p) for p in open_ports],
            )
            await self._store_findings(fw_result.findings, AttackPhase.IOT)
            summary["firmware"] = len(fw_result.findings)

        total = sum(summary.values())
        await self._emit("iot_phase_complete", {
            "phase":   "iot",
            "target":  self.target,
            "message": f"IoT assessment complete: {total} findings",
            "summary": summary,
        })

        logger.info("[IoTAgent] Complete on %s — %s", self.target, summary)
        return summary

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _store_findings(self, findings, phase: AttackPhase) -> None:
        """Persist subagent findings to MongoDB."""
        for f in findings:
            sev_map = {
                "CRITICAL": FindingSeverity.CRITICAL,
                "HIGH":     FindingSeverity.HIGH,
                "MEDIUM":   FindingSeverity.MEDIUM,
                "LOW":      FindingSeverity.LOW,
                "INFO":     FindingSeverity.INFO,
            }
            try:
                doc = await _db.store_finding(
                    session_id  = self.session_id,
                    agent       = AgentName.IOT,
                    phase       = phase,
                    severity    = sev_map.get(f.severity.upper(), FindingSeverity.INFO),
                    title       = f.title,
                    description = f.description,
                    host        = f.host or self.target,
                    port        = f.port,
                    service     = f.tool,
                    cves        = [f.cve] if f.cve else [],
                    tool_used   = f.tool,
                    raw_output  = f.evidence[:2000] if f.evidence else None,
                    extra       = {
                        "mitre_technique":  f.mitre_technique,
                        "exploit_suggestion": f.exploit_suggestion,
                        "finding_id":       f.finding_id,
                    },
                )
                await self._emit("subagent_finding", {"finding": doc})
            except Exception as exc:
                logger.warning("[IoTAgent] Failed to store finding '%s': %s", f.title, exc)

    async def _emit(self, event_type: str, data: dict) -> None:
        msg = WebSocketMessage(
            type       = event_type,
            session_id = self.session_id,
            agent      = AgentName.IOT,
            data       = data,
        )
        try:
            await self.broadcast(msg)
        except Exception as exc:
            logger.debug("[IoTAgent] broadcast failed: %s", exc)

    async def _raw_broadcast(self, event) -> None:
        """Adapter: subagents call broadcast(dict), we need broadcast(WebSocketMessage)."""
        if isinstance(event, dict):
            msg = WebSocketMessage(
                type       = event.get("type", "subagent_event"),
                session_id = event.get("session_id", self.session_id),
                agent      = event.get("agent", AgentName.IOT),
                data       = {k: v for k, v in event.items()
                              if k not in ("type", "session_id", "agent", "timestamp")},
            )
            await self.broadcast(msg)
        else:
            await self.broadcast(event)
