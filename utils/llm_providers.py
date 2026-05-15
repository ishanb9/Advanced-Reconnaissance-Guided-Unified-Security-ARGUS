"""
llm_providers.py — pluggable LLM backend abstraction for ARGUS.

Originally the platform hard-coded Ollama at /api/chat.  This module
generalises that so the same agents can talk to any of:

  Zero-config (no signup, no API key):
    - Ollama                       (LLM_PROVIDER=ollama)
    - LM Studio (OpenAI-compat)    (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=http://localhost:1234/v1)
    - llama.cpp server             (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=http://localhost:8080/v1)
    - vLLM                         (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=http://localhost:8000/v1)

  Free-tier hosted (signup, free credits, no payment):
    - Anthropic Claude             (LLM_PROVIDER=anthropic, ANTHROPIC_API_KEY=sk-ant-…)
    - Google Gemini                (LLM_PROVIDER=gemini, GEMINI_API_KEY=…)
    - Groq (Llama-3.x at speed)    (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=https://api.groq.com/openai/v1, OPENAI_API_KEY=gsk_…)
    - OpenRouter (aggregator)      (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=https://openrouter.ai/api/v1, OPENAI_API_KEY=sk-or-…)
    - Together AI                  (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=https://api.together.xyz/v1)
    - HuggingFace TGI              (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=https://api-inference.huggingface.co/v1, OPENAI_API_KEY=hf_…)
    - Cloudflare Workers AI        (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=https://api.cloudflare.com/client/v4/accounts/<id>/ai/v1)

  Paid (full quota):
    - OpenAI                       (LLM_PROVIDER=openai-compat, OPENAI_BASE_URL=https://api.openai.com/v1)

Pick a provider with the LLM_PROVIDER env var (or LLM_PROVIDER=auto and
let the bootstrap pick the first working one).  Falls back to Ollama for
backward compatibility when nothing is configured.

Every provider exposes the same async streaming interface so the agents
can swap them at runtime without code changes:

    provider = get_provider()
    if await provider.check_available():
        async for token in provider.stream(messages):
            handle(token)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import AsyncIterator, Dict, List, Optional, Tuple

import httpx


logger = logging.getLogger("llm_providers")


# ── Configuration (env-var driven) ─────────────────────────────────────────

def _env(*names: str, default: str = "") -> str:
    """Return the first env-var that's set."""
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


# Provider selection ('ollama' | 'openai-compat' | 'anthropic' | 'gemini' | 'auto')
PROVIDER       = _env("LLM_PROVIDER", default="auto").lower().strip()

# Ollama
OLLAMA_URL     = _env("OLLAMA_URL",   default="http://localhost:11434")
OLLAMA_MODEL   = _env("OLLAMA_MODEL", "MODEL_NAME", default="llama3.1:8b")

# OpenAI-compatible (covers OpenAI proper + LM Studio + vLLM + Groq +
# OpenRouter + Together + HuggingFace TGI + Cloudflare Workers AI + ...)
OPENAI_BASE    = _env("OPENAI_BASE_URL", default="https://api.openai.com/v1").rstrip("/")
OPENAI_KEY     = _env("OPENAI_API_KEY",  default="")
OPENAI_MODEL   = _env("OPENAI_MODEL",    default="gpt-4o-mini")

# Anthropic
ANTHROPIC_KEY      = _env("ANTHROPIC_API_KEY",  default="")
ANTHROPIC_MODEL    = _env("ANTHROPIC_MODEL",    default="claude-sonnet-4-5-20250929")
ANTHROPIC_VERSION  = _env("ANTHROPIC_VERSION",  default="2023-06-01")
ANTHROPIC_BASE     = _env("ANTHROPIC_BASE_URL", default="https://api.anthropic.com").rstrip("/")
ANTHROPIC_MAX_TOK  = int(_env("ANTHROPIC_MAX_TOKENS", default="4096"))

# Google Gemini
GEMINI_KEY    = _env("GEMINI_API_KEY",   "GOOGLE_API_KEY", default="")
GEMINI_MODEL  = _env("GEMINI_MODEL",     default="gemini-2.0-flash")
GEMINI_BASE   = _env("GEMINI_BASE_URL",  default="https://generativelanguage.googleapis.com").rstrip("/")

# Claude Code CLI — uses claude.ai Pro/Max subscription via OAuth (no API key).
# Operator must run `claude login` once; credentials live in
# ~/.claude/.credentials.json after that.
CLAUDE_CODE_BIN   = _env("CLAUDE_CODE_BIN",   default="")   # absolute path; auto-detected if blank
CLAUDE_CODE_MODEL = _env("CLAUDE_CODE_MODEL", default="claude-sonnet-4-5")


# ── Provider base class ────────────────────────────────────────────────────

class LLMProvider:
    """Abstract base for an LLM backend."""
    name:  str = "abstract"
    model: str = ""

    async def check_available(self) -> Tuple[bool, str, List[str]]:
        """Return (ok, status_message, available_models).

        Implementations should be quick (a list-models call) and tolerant
        of transient errors — return False rather than raising.
        """
        raise NotImplementedError

    async def stream(self, messages: List[Dict[str, str]],
                     timeout: int = 600) -> AsyncIterator[str]:
        """Yield response text token-by-token (or chunk-by-chunk).

        ``messages`` is the OpenAI-style list:
            [{"role": "system" | "user" | "assistant", "content": "..."}]
        """
        raise NotImplementedError
        yield ""   # pragma: no cover — marks this as an async generator

    def describe(self) -> Dict[str, str]:
        return {"provider": self.name, "model": self.model}


# ── Ollama ─────────────────────────────────────────────────────────────────

class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, base_url: str = OLLAMA_URL, model: str = OLLAMA_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model    = model

    async def check_available(self) -> Tuple[bool, str, List[str]]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
            if resp.status_code != 200:
                return False, f"Ollama returned HTTP {resp.status_code}", []
            available = [m.get("name", "") for m in (resp.json() or {}).get("models", [])]
            base = self.model.split(":")[0]
            found = self.model in available or any(
                m == self.model or m.split(":")[0] == base for m in available
            )
            if not found:
                return False, (
                    f"Model '{self.model}' not pulled. Available: "
                    f"{', '.join(available[:10]) or '(none)'}. "
                    f"Run: ollama pull {self.model}"
                ), available
            return True, f"Ollama online — {self.model} at {self.base_url}", available
        except Exception as exc:
            return False, f"Ollama unreachable at {self.base_url}: {exc}", []

    async def stream(self, messages, timeout=600):
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15, read=timeout, write=30, pool=10)
        ) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json={"model": self.model, "messages": messages, "stream": True},
            ) as resp:
                resp.raise_for_status()
                async for raw_line in resp.aiter_lines():
                    if not raw_line.strip():
                        continue
                    try:
                        chunk = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue
                    tok = chunk.get("message", {}).get("content", "")
                    if tok:
                        yield tok
                    if chunk.get("done"):
                        break


# ── OpenAI-compatible (covers OpenAI + LM Studio + vLLM + Groq + …) ────────

class OpenAICompatProvider(LLMProvider):
    name = "openai-compat"

    def __init__(self, base_url: str = OPENAI_BASE, api_key: str = OPENAI_KEY,
                 model: str = OPENAI_MODEL):
        self.base_url = base_url.rstrip("/")
        self.api_key  = api_key
        self.model    = model

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def check_available(self) -> Tuple[bool, str, List[str]]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/models",
                                        headers=self._headers())
            if resp.status_code == 401:
                return False, "OpenAI-compat: 401 unauthorized (check OPENAI_API_KEY)", []
            if resp.status_code != 200:
                # Some local servers (Groq's old endpoints, certain proxies)
                # 404 on /models but still serve /chat/completions.  Treat
                # 404 as "available, can't list" rather than fatal.
                if resp.status_code == 404:
                    return True, f"OpenAI-compat at {self.base_url} (model list unavailable)", []
                return False, f"OpenAI-compat returned HTTP {resp.status_code}", []
            body = resp.json() or {}
            avail = [m.get("id") for m in (body.get("data") or []) if m.get("id")]
            return True, f"OpenAI-compat online — {self.model} at {self.base_url}", avail
        except Exception as exc:
            return False, f"OpenAI-compat unreachable at {self.base_url}: {exc}", []

    async def stream(self, messages, timeout=600):
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15, read=timeout, write=30, pool=10)
        ) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json={
                    "model":    self.model,
                    "messages": messages,
                    "stream":   True,
                },
            ) as resp:
                resp.raise_for_status()
                # OpenAI SSE: lines like "data: {…}" plus "data: [DONE]"
                async for raw_line in resp.aiter_lines():
                    if not raw_line:
                        continue
                    line = raw_line.strip()
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        chunk = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    try:
                        delta = chunk["choices"][0].get("delta") or {}
                    except (KeyError, IndexError, TypeError):
                        continue
                    tok = delta.get("content") or ""
                    if tok:
                        yield tok


# ── Anthropic Claude ───────────────────────────────────────────────────────

class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str = ANTHROPIC_KEY, model: str = ANTHROPIC_MODEL,
                 base_url: str = ANTHROPIC_BASE, max_tokens: int = ANTHROPIC_MAX_TOK):
        self.api_key    = api_key
        self.model      = model
        self.base_url   = base_url.rstrip("/")
        self.max_tokens = max_tokens

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type":      "application/json",
            "x-api-key":         self.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }

    @staticmethod
    def _split_system(messages: List[Dict[str, str]]) -> Tuple[str, List[Dict[str, str]]]:
        """Anthropic accepts system as a top-level field, not in messages."""
        sys_parts = []
        rest = []
        for m in messages:
            if m.get("role") == "system":
                sys_parts.append(m.get("content", ""))
            else:
                rest.append({"role": m.get("role"), "content": m.get("content", "")})
        return "\n".join(p for p in sys_parts if p), rest

    async def check_available(self) -> Tuple[bool, str, List[str]]:
        if not self.api_key:
            return False, "Anthropic: ANTHROPIC_API_KEY is not set", []
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/v1/models",
                                        headers=self._headers())
            if resp.status_code == 401:
                return False, "Anthropic: 401 unauthorized (invalid ANTHROPIC_API_KEY)", []
            if resp.status_code != 200:
                # /v1/models may not exist on all plans; a 404 here is fine,
                # we'll just skip the model-listing.
                if resp.status_code in (403, 404):
                    return True, f"Anthropic online — {self.model} (model list unavailable)", []
                return False, f"Anthropic returned HTTP {resp.status_code}", []
            avail = [m.get("id") for m in (resp.json() or {}).get("data", []) if m.get("id")]
            return True, f"Anthropic online — {self.model}", avail
        except Exception as exc:
            return False, f"Anthropic unreachable: {exc}", []

    async def stream(self, messages, timeout=600):
        system_text, msg_list = self._split_system(messages)
        body = {
            "model":      self.model,
            "max_tokens": self.max_tokens,
            "stream":     True,
            "messages":   msg_list,
        }
        if system_text:
            body["system"] = system_text
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15, read=timeout, write=30, pool=10)
        ) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/v1/messages",
                headers=self._headers(),
                json=body,
            ) as resp:
                resp.raise_for_status()
                # Anthropic SSE: "event: <type>\ndata: {…}\n\n" — we just
                # read data: lines and look at delta.text where present.
                async for raw_line in resp.aiter_lines():
                    if not raw_line:
                        continue
                    line = raw_line.strip()
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if not payload or payload == "[DONE]":
                        continue
                    try:
                        chunk = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    typ = chunk.get("type", "")
                    if typ == "content_block_delta":
                        delta = chunk.get("delta") or {}
                        tok = delta.get("text") or ""
                        if tok:
                            yield tok
                    elif typ == "message_stop":
                        break


# ── Google Gemini ──────────────────────────────────────────────────────────

class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, api_key: str = GEMINI_KEY, model: str = GEMINI_MODEL,
                 base_url: str = GEMINI_BASE):
        self.api_key  = api_key
        self.model    = model
        self.base_url = base_url.rstrip("/")

    @staticmethod
    def _translate(messages: List[Dict[str, str]]) -> Tuple[str, List[Dict[str, str]]]:
        sys_parts = []
        contents = []
        for m in messages:
            role = m.get("role", "user")
            txt  = m.get("content", "")
            if role == "system":
                sys_parts.append(txt)
                continue
            # Gemini uses 'user' / 'model' (not 'assistant')
            g_role = "model" if role == "assistant" else "user"
            contents.append({"role": g_role, "parts": [{"text": txt}]})
        return "\n".join(p for p in sys_parts if p), contents

    async def check_available(self) -> Tuple[bool, str, List[str]]:
        if not self.api_key:
            return False, "Gemini: GEMINI_API_KEY is not set", []
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.base_url}/v1beta/models?key={self.api_key}"
                )
            if resp.status_code == 403:
                return False, "Gemini: 403 forbidden (invalid GEMINI_API_KEY)", []
            if resp.status_code != 200:
                return False, f"Gemini returned HTTP {resp.status_code}", []
            avail = [
                (m.get("name") or "").replace("models/", "")
                for m in (resp.json() or {}).get("models", [])
            ]
            return True, f"Gemini online — {self.model}", [a for a in avail if a]
        except Exception as exc:
            return False, f"Gemini unreachable: {exc}", []

    async def stream(self, messages, timeout=600):
        system_text, contents = self._translate(messages)
        body = {"contents": contents}
        if system_text:
            body["systemInstruction"] = {"parts": [{"text": system_text}]}
        url = (
            f"{self.base_url}/v1beta/models/{self.model}:streamGenerateContent"
            f"?alt=sse&key={self.api_key}"
        )
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15, read=timeout, write=30, pool=10)
        ) as client:
            async with client.stream("POST", url,
                                     headers={"Content-Type": "application/json"},
                                     json=body) as resp:
                resp.raise_for_status()
                async for raw_line in resp.aiter_lines():
                    if not raw_line:
                        continue
                    line = raw_line.strip()
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if not payload:
                        continue
                    try:
                        chunk = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    # Walk to candidates[0].content.parts[*].text
                    cands = chunk.get("candidates") or []
                    for c in cands:
                        parts = ((c.get("content") or {}).get("parts")) or []
                        for p in parts:
                            tok = p.get("text") or ""
                            if tok:
                                yield tok


# ── Claude Code CLI (uses claude.ai subscription via OAuth) ────────────────

class ClaudeCodeProvider(LLMProvider):
    """Talk to Claude through the Claude Code CLI.

    Uses the operator's Pro/Max subscription quota via OAuth — no API key
    configured here.  The first time on a machine, run:

        npm install -g @anthropic-ai/claude-code
        claude login

    After login the credentials live in ~/.claude/.credentials.json and
    every subsequent `claude --print` invocation consumes subscription
    quota instead of an API key.

    Important caveats:
      - Each call spawns a subprocess (200-500 ms startup).
      - One-shot per call: multi-turn context is flattened into a single
        prompt with role-delimited sections.  ARGUS already keeps per-agent
        history in memory, so this is fine.
      - The CLI streams events via JSON-on-stdout; we collect text content
        blocks as they arrive so heartbeats still fire normally.
      - claude.ai web chat cannot be a backend - there is no public API
        for it and scraping it violates Anthropic's ToS.

    Security note: we invoke the binary with positional argv (asyncio's
    create_subprocess_exec, not _shell) so user-supplied prompt content
    never goes through a shell interpreter and cannot inject commands.
    """
    name = "claude-code"

    def __init__(self, cli_path: str = "", model: str = CLAUDE_CODE_MODEL):
        resolved = cli_path or CLAUDE_CODE_BIN or (shutil.which("claude") or "claude")
        self.cli_path = resolved
        self.model    = model

    @staticmethod
    def _messages_to_prompt(messages: List[Dict[str, str]]) -> str:
        """Flatten role-tagged messages into one prompt with delimiters."""
        parts: List[str] = []
        for m in messages:
            role = (m.get("role") or "user").lower()
            content = m.get("content") or ""
            if not content:
                continue
            if role == "system":
                parts.append(f"<system>\n{content}\n</system>")
            elif role == "assistant":
                parts.append(f"<assistant>\n{content}\n</assistant>")
            else:
                parts.append(f"<user>\n{content}\n</user>")
        return "\n\n".join(parts)

    def _creds_exist(self) -> bool:
        for p in (
            Path.home() / ".claude" / ".credentials.json",
            Path.home() / ".config" / "claude" / ".credentials.json",
        ):
            if p.exists():
                return True
        return False

    async def check_available(self) -> Tuple[bool, str, List[str]]:
        # 1) CLI binary present and runnable?
        try:
            proc = await asyncio.create_subprocess_exec(
                self.cli_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                return False, "Claude Code CLI timed out on --version", []
            if proc.returncode != 0:
                return False, (
                    f"Claude Code CLI not runnable at '{self.cli_path}'. "
                    f"Install: npm install -g @anthropic-ai/claude-code"
                ), []
            version = stdout.decode(errors="ignore").strip() or "unknown"
        except FileNotFoundError:
            return False, (
                f"Claude Code CLI not found ('{self.cli_path}'). "
                f"Install: npm install -g @anthropic-ai/claude-code "
                f"OR set CLAUDE_CODE_BIN=/path/to/claude"
            ), []
        except Exception as exc:
            return False, f"Claude Code CLI check failed: {exc}", []

        # 2) OAuth credentials present?
        if not self._creds_exist():
            return False, (
                "Claude Code CLI installed but not logged in. "
                "Run: claude login (uses your claude.ai Pro/Max subscription)"
            ), []

        return True, (
            f"Claude Code online - {self.model} via subscription (CLI {version})"
        ), [self.model]

    async def stream(self, messages, timeout=600):
        prompt = self._messages_to_prompt(messages)
        argv = [
            self.cli_path, "--print",
            "--model", self.model,
            "--output-format", "stream-json",
            "--verbose",
            "--permission-mode", "bypassPermissions",
            prompt,
        ]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        seen_text: Dict[Tuple[int, int], str] = {}
        ev_idx = 0
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
                if not line:
                    break
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if event.get("type") == "assistant":
                    msg = event.get("message") or {}
                    blocks = (msg.get("content") or [])
                    for bi, block in enumerate(blocks):
                        if (block or {}).get("type") != "text":
                            continue
                        text = block.get("text") or ""
                        key  = (ev_idx, bi)
                        prev = seen_text.get(key, "")
                        if text.startswith(prev):
                            new_chunk = text[len(prev):]
                            seen_text[key] = text
                            if new_chunk:
                                yield new_chunk
                        else:
                            seen_text[key] = text
                            yield text
                    ev_idx += 1
                elif event.get("type") == "result":
                    if event.get("is_error"):
                        err_msg = event.get("result") or "claude returned an error"
                        raise RuntimeError(f"Claude Code error: {err_msg}")
                    break
        finally:
            try:
                if proc.returncode is None:
                    proc.terminate()
                await proc.wait()
            except Exception:
                pass


# ── Factory ────────────────────────────────────────────────────────────────

_PROVIDER_CACHE: Optional[LLMProvider] = None


def _build_one(name: str) -> Optional[LLMProvider]:
    n = (name or "").lower().strip()
    if n in ("ollama", "ol"):
        return OllamaProvider()
    if n in ("openai-compat", "openai_compat", "openai", "lm-studio", "vllm",
             "groq", "openrouter", "together", "huggingface", "hf", "cloudflare"):
        return OpenAICompatProvider()
    if n in ("anthropic", "claude-api"):
        return AnthropicProvider()
    if n in ("gemini", "google"):
        return GeminiProvider()
    if n in ("claude-code", "claude", "claudecode", "cc"):
        return ClaudeCodeProvider()
    return None


async def _auto_detect() -> Optional[LLMProvider]:
    """Try providers in order; return the first one that's actually up.

    Order is biased toward zero-config + local-ish: ollama first
    (zero-config), Claude Code (subscription, no key), then OpenAI-compat
    (which covers LM Studio etc.), then keyed cloud providers.
    """
    candidates: List[LLMProvider] = [
        OllamaProvider(),
        ClaudeCodeProvider(),     # only succeeds if `claude login` has been run
        OpenAICompatProvider(),
    ]
    if ANTHROPIC_KEY:
        candidates.append(AnthropicProvider())
    if GEMINI_KEY:
        candidates.append(GeminiProvider())
    for p in candidates:
        ok, msg, _ = await p.check_available()
        logger.info("[llm] auto-detect %s: %s", p.name, msg)
        if ok:
            return p
    return None


def get_provider() -> LLMProvider:
    """Return the configured (or cached) LLMProvider.

    Honours LLM_PROVIDER env var.  If unset or 'auto', the first call
    will trigger _auto_detect() the next time check_available() is run
    by the caller.  Until then we default to OllamaProvider for backward
    compatibility with the existing single-provider deployments.
    """
    global _PROVIDER_CACHE
    if _PROVIDER_CACHE is not None:
        return _PROVIDER_CACHE

    chosen = _build_one(PROVIDER) if PROVIDER and PROVIDER != "auto" else None
    if chosen is None:
        # Backward-compat default: Ollama (matches the platform's history).
        chosen = OllamaProvider()
    _PROVIDER_CACHE = chosen
    return chosen


async def set_provider_auto() -> LLMProvider:
    """Re-run auto-detection and update the cache.  Caller responsibility
    to await this at startup when PROVIDER=='auto'."""
    global _PROVIDER_CACHE
    detected = await _auto_detect()
    if detected is not None:
        _PROVIDER_CACHE = detected
    return _PROVIDER_CACHE or get_provider()


__all__ = [
    "LLMProvider", "OllamaProvider", "OpenAICompatProvider",
    "AnthropicProvider", "GeminiProvider", "ClaudeCodeProvider",
    "get_provider", "set_provider_auto",
    "PROVIDER",
]
