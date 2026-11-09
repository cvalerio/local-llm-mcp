"""OpenAI-compatible client for the local worker(s): chunked digests, exact token counts, failover.

Two backends at most: the primary worker and an optional fallback (``LOCAL_LLM_MCP_FALLBACK_*``),
both required to be local endpoints. A call goes to the primary; if the primary is unreachable
or answers 5xx, the same call is made to the fallback and the primary is marked down for
``failover_cooldown`` seconds, during which calls go to the fallback first. Errors that a second
worker cannot fix (a rejected key, a model that returned no content) are not failed over.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import httpx

from .config import Config

log = logging.getLogger("local_llm_mcp.llm")


class LLMError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable  # another worker might succeed


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0
    chunks: int = 1

    def add(self, u: dict | None) -> None:
        self.calls += 1
        if u:
            self.prompt_tokens += int(u.get("prompt_tokens") or 0)
            self.completion_tokens += int(u.get("completion_tokens") or 0)


@dataclass
class Backend:
    name: str
    base_url: str
    model: str
    client: httpx.AsyncClient

    @property
    def root(self) -> str:
        """The server root (the tokenize endpoint lives beside /v1, not under it)."""
        return self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url


_UNREACHABLE = (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.RemoteProtocolError)


class LocalLLM:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.backends: list[Backend] = [self._backend("primary", cfg.base_url, cfg.model, cfg.api_key)]
        if cfg.fallback_base_url:
            self.backends.append(self._backend("fallback", cfg.fallback_base_url, cfg.fallback_model or cfg.model,
                                               cfg.fallback_api_key))
        self.primary_down_until = 0.0
        self.last_backend = self.backends[0]
        self._tokenize_off_until = 0.0

    def _backend(self, name: str, base_url: str, model: str, api_key: str) -> Backend:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        # trust_env=False: an HTTP(S)_PROXY in the environment must not carry private material off
        # the local network to a host assert_local_endpoint never saw.
        client = httpx.AsyncClient(base_url=base_url, headers=headers, trust_env=False,
                                   timeout=httpx.Timeout(self.cfg.llm_timeout, connect=10.0))
        return Backend(name, base_url, model, client)

    @property
    def client(self) -> httpx.AsyncClient:
        return self.backends[0].client

    @property
    def last_model(self) -> str:
        return self.last_backend.model

    async def aclose(self) -> None:
        for b in self.backends:
            await b.client.aclose()

    def tokens_for(self, max_output_chars: int) -> int:
        return max(400, min(self.cfg.max_tokens_cap, max_output_chars // 3 + 256))

    # ---- routing --------------------------------------------------------------

    def order(self) -> list[Backend]:
        """Primary first, unless it is marked down — then the fallback first, primary last."""
        if len(self.backends) > 1 and time.monotonic() < self.primary_down_until:
            return [self.backends[1], self.backends[0]]
        return list(self.backends)

    def worker_status(self) -> dict:
        p = self.backends[0]
        f = self.backends[1] if len(self.backends) > 1 else None
        return {
            "primary": {"model": p.model, "endpoint": p.base_url},
            "fallback": {"model": f.model, "endpoint": f.base_url} if f else None,
            "active": self.last_backend.name, "active_model": self.last_model,
            "primary_down_for_s": max(0, round(self.primary_down_until - time.monotonic())),
        }

    # ---- chat ------------------------------------------------------------------

    async def _chat_once(self, b: Backend, body: dict) -> tuple[str, dict]:
        body = {**body, "model": b.model}
        last_exc: Exception | None = None
        for attempt in (1, 2):
            try:
                r = await b.client.post("/chat/completions", json=body)
                if r.status_code == 401:
                    raise LLMError(f"{b.name} worker rejected the API key (401); check its key file")
                if r.status_code >= 500:
                    raise LLMError(f"{b.name} worker returned HTTP {r.status_code}: {r.text[:300]}", retryable=True)
                if r.status_code >= 400:
                    raise LLMError(f"{b.name} worker returned HTTP {r.status_code}: {r.text[:300]}")
                data = r.json()
                choice = (data.get("choices") or [{}])[0]
                msg = choice.get("message") or {}
                content = (msg.get("content") or "").strip()
                if not content:
                    reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
                    if reasoning:
                        raise LLMError("local model spent its budget on reasoning and returned no content; "
                                       "raise max_output_chars or keep LOCAL_LLM_MCP_THINKING=0")
                    raise LLMError(f"local model returned empty content (finish_reason={choice.get('finish_reason')})")
                return content, (data.get("usage") or {})
            except _UNREACHABLE as exc:
                last_exc = exc
                if attempt == 1:
                    await asyncio.sleep(1.0)
                    continue
                raise LLMError(f"{b.name} worker unreachable at {b.base_url}: {type(exc).__name__}: {exc}",
                               retryable=True) from exc
        raise LLMError(str(last_exc), retryable=True)

    async def chat(self, system: str, user: str, *, max_tokens: int, temperature: float = 0.2) -> tuple[str, dict]:
        body: dict = {
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if not self.cfg.thinking:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        order = self.order()
        errors: list[str] = []
        for b in order:
            try:
                content, usage = await self._chat_once(b, body)
            except LLMError as exc:
                if not exc.retryable or b is order[-1]:
                    if errors:
                        raise LLMError("; ".join(errors + [str(exc)]), retryable=exc.retryable) from exc
                    raise
                errors.append(str(exc))
                if b is self.backends[0]:
                    self.primary_down_until = time.monotonic() + self.cfg.failover_cooldown
                    log.warning("primary worker failed (%s); using the fallback for %.0fs", exc, self.cfg.failover_cooldown)
                continue
            if b is not self.last_backend:
                log.info("worker now %s (%s at %s)", b.name, b.model, b.base_url)
            self.last_backend = b
            if b is self.backends[0]:
                self.primary_down_until = 0.0
            return content, usage
        raise LLMError("; ".join(errors), retryable=True)

    async def probe(self) -> list[dict]:
        """One tiny call per backend, for --check."""
        out = []
        body = {"messages": [{"role": "system", "content": "Reply with exactly: OK"}, {"role": "user", "content": "ping"}],
                "max_tokens": 16, "temperature": 0.0}
        if not self.cfg.thinking:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        for b in self.backends:
            try:
                text, usage = await self._chat_once(b, body)
                out.append({"backend": b.name, "model": b.model, "endpoint": b.base_url, "ok": True,
                            "text": text[:40], "usage": usage})
            except LLMError as exc:
                out.append({"backend": b.name, "model": b.model, "endpoint": b.base_url, "ok": False, "error": str(exc)})
        return out

    # ---- tokens ----------------------------------------------------------------

    async def count_tokens(self, text: str) -> int | None:
        """Exact token count with the worker's own tokenizer, or None when no backend
        offers a tokenize endpoint (checked again after ten minutes). Tries the vLLM
        shape (``{"model","prompt"}`` → ``count``) then the llama.cpp shape
        (``{"content"}`` → ``tokens``)."""
        if not text:
            return 0
        if time.monotonic() < self._tokenize_off_until:
            return None
        timeout = httpx.Timeout(60.0, connect=10.0)
        for b in self.order():
            url = b.root + "/tokenize"
            try:
                r = await b.client.post(url, json={"model": b.model, "prompt": text, "add_special_tokens": False},
                                        timeout=timeout)
                if r.status_code == 200:
                    d = r.json()
                    if isinstance(d.get("count"), int):
                        return d["count"]
                    if isinstance(d.get("tokens"), list):
                        return len(d["tokens"])
                elif r.status_code in (400, 404, 405, 415, 422):
                    r = await b.client.post(url, json={"content": text}, timeout=timeout)
                    if r.status_code == 200 and isinstance(r.json().get("tokens"), list):
                        return len(r.json()["tokens"])
            except (httpx.HTTPError, ValueError) as exc:
                log.debug("tokenize via %s failed: %s", b.name, exc)
                continue
        self._tokenize_off_until = time.monotonic() + 600
        log.info("no usable /tokenize endpoint on any worker; token counts fall back to the chars estimate for 10 min")
        return None

    # ---- digests ---------------------------------------------------------------

    @staticmethod
    def split_chunks(text: str, chunk_chars: int) -> list[str]:
        if len(text) <= chunk_chars:
            return [text]
        chunks: list[str] = []
        pos = 0
        n = len(text)
        while pos < n:
            end = min(n, pos + chunk_chars)
            if end < n:
                nl = text.rfind("\n", pos + chunk_chars // 2, end)
                if nl > 0:
                    end = nl + 1
            chunks.append(text[pos:end])
            pos = end
        return chunks

    async def digest(self, system: str, task: str, material: str, source: str, *,
                     max_output_chars: int, render_user, render_reduce) -> tuple[str, Usage]:
        """Answer ``task`` over ``material``; map-reduce when the material exceeds one chunk."""
        usage = Usage()
        max_tokens = self.tokens_for(max_output_chars)
        chunks = self.split_chunks(material, self.cfg.chunk_chars)
        usage.chunks = len(chunks)
        if len(chunks) == 1:
            text, u = await self.chat(system, render_user(task, material, source, None), max_tokens=max_tokens)
            usage.add(u)
            return text, usage
        sem = asyncio.Semaphore(self.cfg.parallel_chunks)

        async def one(i: int, chunk: str) -> str:
            async with sem:
                part_note = f"part {i + 1} of {len(chunks)}"
                text, u = await self.chat(system, render_user(task, chunk, source, part_note),
                                          max_tokens=max_tokens)
                usage.add(u)
                return text

        parts = await asyncio.gather(*(one(i, c) for i, c in enumerate(chunks)))
        final, u = await self.chat(system, render_reduce(task, parts, source), max_tokens=max_tokens)
        usage.add(u)
        return final, usage
