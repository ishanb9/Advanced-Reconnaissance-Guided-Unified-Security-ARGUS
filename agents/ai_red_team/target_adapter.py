"""target_adapter.py — one interface, three target shapes.

The human picks the adapter at target-config; the engine then only calls
``await adapter.send(messages)`` regardless of shape:

  http_chat        OpenAI-compatible (/v1/chat/completions), Ollama (/api/chat),
                   or a generic JSON endpoint via request_template + response_path.
  agentic          a tool-using / MCP / function-calling agent: POST a task,
                   capture the agent's textual response (+ any tool-call trace).
  single_endpoint  a raw user-supplied request_template with a {{prompt}} slot
                   and a response_path / regex extractor — the universal fallback.

Network I/O is stdlib urllib in a worker thread (no new dependency); send()
never raises — it returns "" on any failure so the harness keeps going.  A
``mock_echo`` config returns the last user message so tests run offline.
"""
from __future__ import annotations

import asyncio
import json
import re
import urllib.request
from typing import Any, Dict, List, Optional


def _last_user(messages: List[Dict[str, str]]) -> str:
    for m in reversed(messages or []):
        if m.get("role") == "user":
            return str(m.get("content", ""))
    return str(messages[-1].get("content", "")) if messages else ""


def _dig(obj: Any, path: str) -> str:
    """Extract a value from a JSON object by a dotted path with [i] indexing,
    e.g. 'choices[0].message.content'."""
    cur = obj
    for part in re.split(r"\.", path or ""):
        if not part:
            continue
        m = re.match(r"^([^\[\]]+)((\[\d+\])*)$", part)
        if not m:
            return ""
        key, idxs = m.group(1), m.group(2)
        if isinstance(cur, dict):
            cur = cur.get(key)
        if idxs:
            for i in re.findall(r"\[(\d+)\]", idxs):
                if isinstance(cur, list) and int(i) < len(cur):
                    cur = cur[int(i)]
                else:
                    return ""
    return cur if isinstance(cur, str) else json.dumps(cur) if cur is not None else ""


def _http_post(url: str, body: Any, headers: Dict[str, str], timeout: float) -> str:
    data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


class Adapter:
    def __init__(self, config: Dict[str, Any]):
        self.cfg = config or {}
        self.kind = str(self.cfg.get("type", "single_endpoint"))
        self.timeout = float(self.cfg.get("timeout", 30))

    def _headers(self) -> Dict[str, str]:
        h = dict(self.cfg.get("headers") or {})
        auth = self.cfg.get("auth_header") or self.cfg.get("api_key")
        if auth and "Authorization" not in h:
            h["Authorization"] = auth if str(auth).lower().startswith("bearer") else f"Bearer {auth}"
        return h

    async def send(self, messages: List[Dict[str, str]]) -> str:
        if self.cfg.get("mock_echo"):
            return f"[echo] {_last_user(messages)}"
        try:
            return await asyncio.to_thread(self._send_sync, messages)
        except Exception:
            return ""

    def _send_sync(self, messages: List[Dict[str, str]]) -> str:
        url = str(self.cfg.get("url") or "")
        if not url:
            return ""
        model = self.cfg.get("model") or "gpt-3.5-turbo"
        if self.kind in ("http_chat", "agentic"):
            # OpenAI-compatible body by default; Ollama if the path says so.
            if "/api/chat" in url:                       # Ollama
                body = {"model": model, "messages": messages, "stream": False}
                path = self.cfg.get("response_path") or "message.content"
            else:                                        # OpenAI-compatible
                body = {"model": model, "messages": messages}
                path = self.cfg.get("response_path") or "choices[0].message.content"
            raw = _http_post(url, body, self._headers(), self.timeout)
            try:
                return _dig(json.loads(raw), path) or raw[:4000]
            except Exception:
                return raw[:4000]
        # single_endpoint — substitute {{prompt}} into a raw template.
        tmpl = self.cfg.get("request_template") or '{"prompt": "{{prompt}}"}'
        prompt = _last_user(messages).replace('"', '\\"')
        body_str = str(tmpl).replace("{{prompt}}", prompt)
        raw = _http_post(url, body_str.encode("utf-8"), self._headers(), self.timeout)
        path = self.cfg.get("response_path")
        if path:
            try:
                return _dig(json.loads(raw), path) or raw[:4000]
            except Exception:
                pass
        rx = self.cfg.get("response_regex")
        if rx:
            m = re.search(rx, raw)
            if m:
                return m.group(m.lastindex or 0)
        return raw[:4000]


def make_adapter(config: Dict[str, Any]) -> Adapter:
    """Factory — config['type'] in {http_chat, agentic, single_endpoint}."""
    return Adapter(config or {})
