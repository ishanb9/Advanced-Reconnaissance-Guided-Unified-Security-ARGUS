"""
base_osint_subagent.py — Lightweight base class for all OSINT subagents.

Unlike BaseSubagent (MCP tool executor), OsintSubagentBase is designed for
HTTP API calls, CLI tool wrappers, and web scraping that return structured
intelligence data rather than raw tool output lines.

Usage
-----
    class MySourceSubagent(OsintSubagentBase):
        SOURCE_NAME  = "my_source"
        DISPLAY_NAME = "My Source"

        async def run(self) -> List[Dict]:
            resp = await self._get("https://api.example.com/...", params={...})
            if resp and resp.status_code == 200:
                await self._store(query=..., title=..., summary=...)
            return self._results
"""

from __future__ import annotations

import asyncio
import os
import re
import signal as _signal
from typing import Dict, List, Optional

import httpx

from db.schemas import FindingSeverity
import db.mongo_client as db


class OsintSubagentBase:
    """Base class for OSINT subagents."""

    SOURCE_NAME:  str = "unknown"   # Identifier stored in DB and shown on UI badge
    DISPLAY_NAME: str = "OSINT"     # Human-readable label

    def __init__(
        self,
        session_id:   str,
        target:       str,
        broadcast_fn  = None,
        stop_event:   asyncio.Event = None,
        discovery:    Optional[Dict] = None,
    ):
        self._session_id  = session_id
        self._target      = target
        self._broadcast   = broadcast_fn
        self._stop_event  = stop_event
        # Discovery context populated by recon/vuln/web phases. Subagents read
        # from here to drive queries with real artefacts (subdomains, SSL CNs,
        # web tech, emails, banners, service versions, etc.) rather than just
        # the root target string. Keys are optional; subagents degrade gracefully.
        self._discovery:  Dict         = discovery or {}
        self._results:    List[Dict] = []

    # ── Discovery accessors ────────────────────────────────────────

    def _disco(self, key: str, default=None):
        """Safe getter for discovery context."""
        return self._discovery.get(key, default) if isinstance(self._discovery, dict) else default

    def _disco_list(self, *keys: str) -> List[str]:
        """Aggregate list-valued discovery keys, dedup preserving order."""
        out: List[str] = []
        seen = set()
        for k in keys:
            v = self._disco(k, []) or []
            if isinstance(v, dict):
                v = list(v.values())
            if not isinstance(v, (list, tuple, set)):
                continue
            for item in v:
                s = str(item).strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
        return out

    def _target_domains(self) -> List[str]:
        """
        Return all domain/host strings worth querying: the primary target (if
        domain), plus hostnames, subdomains, SSL CNs/SANs, virtual hosts.
        De-duplicated, IPs excluded.
        """
        seeds: List[str] = []
        if self._is_domain(self._target):
            seeds.append(self._target)
        for item in self._disco_list(
            "hostnames", "subdomains", "virtual_hosts",
            "ssl_cns", "ssl_sans", "associated_domains",
        ):
            if self._is_domain(item) and item not in seeds:
                seeds.append(item)
        return seeds

    def _target_ips(self) -> List[str]:
        """Primary IP target + any additional IPs discovered during recon."""
        seeds: List[str] = []
        if self._is_ip(self._target):
            seeds.append(self._target)
        for item in self._disco_list("ips", "a_records", "resolved_ips"):
            if self._is_ip(item) and item not in seeds:
                seeds.append(item)
        return seeds

    # ── Abstract interface ─────────────────────────────────────────

    async def run(self) -> List[Dict]:
        """Override in subclass. Return list of stored result dicts."""
        raise NotImplementedError

    # ── Stop check ────────────────────────────────────────────────

    @property
    def _stopped(self) -> bool:
        return self._stop_event is not None and self._stop_event.is_set()

    # ── DB helper ─────────────────────────────────────────────────

    async def _store(
        self,
        query:     str,
        title:     str,
        summary:   str,
        url:       Optional[str]          = None,
        cves:      Optional[List[str]]    = None,
        exploits:  Optional[List[str]]    = None,
        severity:  FindingSeverity        = FindingSeverity.INFO,
        relevance: float                  = 0.5,
        raw:       Optional[Dict]         = None,
        data_type: Optional[str]          = None,
        tags:      Optional[List[str]]    = None,
        value:     Optional[str]          = None,
    ) -> Dict:
        """Persist an OSINT result and append it to self._results."""
        raw = dict(raw or {})
        if data_type:
            raw["data_type"] = data_type
        if tags:
            raw["tags"] = tags
        if value:
            raw["value"] = value

        doc = await db.store_osint_result(
            session_id = self._session_id,
            host       = self._target,
            query      = query,
            source     = self.SOURCE_NAME,
            title      = title,
            summary    = summary,
            url        = url,
            cves       = cves,
            exploits   = exploits,
            severity   = severity,
            relevance  = relevance,
            raw        = raw,
        )
        self._results.append(doc)
        await self._emit("osint_result", {
            "source": self.SOURCE_NAME,
            "title":  title,
            "target": self._target,
        })
        return doc

    # ── WebSocket helper ──────────────────────────────────────────

    async def _emit(self, event_type: str, data: Dict):
        if self._broadcast:
            try:
                await self._broadcast({"type": event_type, "agent": "osint", **data})
            except Exception:
                pass

    # ── HTTP helpers ──────────────────────────────────────────────

    async def _get(
        self,
        url:              str,
        params:           Optional[Dict] = None,
        headers:          Optional[Dict] = None,
        timeout:          int            = 20,
        follow_redirects: bool           = True,
    ) -> Optional[httpx.Response]:
        try:
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=follow_redirects
            ) as client:
                return await client.get(url, params=params, headers=headers)
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"[{self.SOURCE_NAME}] GET error: {exc}"
            })
            return None

    async def _post(
        self,
        url:     str,
        json_data: Optional[Dict] = None,
        form_data: Optional[Dict] = None,
        headers:   Optional[Dict] = None,
        timeout:   int            = 20,
    ) -> Optional[httpx.Response]:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                return await client.post(
                    url,
                    json=json_data,
                    data=form_data,
                    headers=headers,
                )
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"[{self.SOURCE_NAME}] POST error: {exc}"
            })
            return None

    # ── CLI helper ────────────────────────────────────────────────

    async def _run_cli(
        self,
        cmd:     List[str],
        timeout: int           = 60,
        cwd:     Optional[str] = None,
    ) -> str:
        """Run a subprocess command (list form) and return combined stdout+stderr."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=cwd,
                start_new_session=True,  # new process group → killpg kills all children
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return stdout.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                # Kill the process group so any children also die
                try:
                    os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                try:
                    proc.kill()
                except Exception:
                    pass
                await self._emit("osint_warning", {
                    "message": f"[{self.SOURCE_NAME}] CLI timeout: {cmd[0]}"
                })
                return ""
        except FileNotFoundError:
            await self._emit("osint_warning", {
                "message": f"[{self.SOURCE_NAME}] Tool not found: {cmd[0]}"
            })
            return ""
        except Exception as exc:
            await self._emit("osint_warning", {
                "message": f"[{self.SOURCE_NAME}] CLI error: {exc}"
            })
            return ""

    # ── Target type helpers ───────────────────────────────────────

    @staticmethod
    def _is_ip(s: str) -> bool:
        return bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s or ""))

    @staticmethod
    def _is_domain(s: str) -> bool:
        return bool(re.match(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$',
            s or ""
        ))

    @staticmethod
    def _is_email(s: str) -> bool:
        return bool(re.match(r'^[\w\.\-\+]+@[\w\.\-]+\.\w{2,}$', s or ""))
