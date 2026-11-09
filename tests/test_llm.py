"""Worker client: failover with cooldown, errors that must not fail over, exact token counts."""
import asyncio
import json
import time

import httpx
import pytest

from local_llm_mcp.config import Config
from local_llm_mcp.llm import LLMError, LocalLLM


def make_cfg(monkeypatch, tmp_path, fallback=True):
    monkeypatch.setenv("LOCAL_LLM_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LOCAL_LLM_MCP_SOCK_DIR", str(tmp_path / "sock"))
    monkeypatch.setenv("LOCAL_LLM_MCP_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("LOCAL_LLM_MCP_MODEL", "prim")
    monkeypatch.setenv("LOCAL_LLM_MCP_FAILOVER_COOLDOWN", "60")
    for k in ("FALLBACK_BASE_URL", "FALLBACK_MODEL", "FALLBACK_API_KEY", "FALLBACK_API_KEY_FILE", "API_KEY", "API_KEY_FILE", "RULES"):
        monkeypatch.delenv("LOCAL_LLM_MCP_" + k, raising=False)
    if fallback:
        monkeypatch.setenv("LOCAL_LLM_MCP_FALLBACK_BASE_URL", "http://127.0.0.1:8001/v1")
        monkeypatch.setenv("LOCAL_LLM_MCP_FALLBACK_MODEL", "fall")
    return Config.from_env()


def mock(llm: LocalLLM, handlers: dict) -> None:
    for b in llm.backends:
        b.client = httpx.AsyncClient(base_url=b.base_url, transport=httpx.MockTransport(handlers[b.name]))


def ok(model: str, text: str = "fine"):
    def h(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        if req.url.path == "/tokenize":
            return httpx.Response(200, json={"count": len(body["prompt"].split()), "tokens": []})
        assert body["model"] == model
        return httpx.Response(200, json={"choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                                         "usage": {"prompt_tokens": 3, "completion_tokens": 1}})
    return h


def down(req: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused")


def five(req: httpx.Request) -> httpx.Response:
    return httpx.Response(503, text="restarting")


def unauthorized(req: httpx.Request) -> httpx.Response:
    return httpx.Response(401, text="bad key")


def test_config_refuses_a_remote_fallback(monkeypatch, tmp_path):
    make_cfg(monkeypatch, tmp_path)
    monkeypatch.setenv("LOCAL_LLM_MCP_FALLBACK_BASE_URL", "https://api.example.com/v1")
    with pytest.raises(Exception):
        Config.from_env()


def test_failover_on_5xx_then_primary_recovers(monkeypatch, tmp_path):
    llm = LocalLLM(make_cfg(monkeypatch, tmp_path))
    mock(llm, {"primary": five, "fallback": ok("fall", "from fallback")})

    async def go():
        text, _ = await llm.chat("s", "u", max_tokens=8)
        assert text == "from fallback" and llm.last_model == "fall" and llm.last_backend.name == "fallback"
        st = llm.worker_status()
        assert st["active"] == "fallback" and st["primary_down_for_s"] > 0 and llm.order()[0].name == "fallback"
        # while the primary is marked down the fallback is asked first, primary not even tried
        mock(llm, {"primary": ok("prim", "from primary"), "fallback": ok("fall", "still fallback")})
        text, _ = await llm.chat("s", "u", max_tokens=8)
        assert text == "still fallback"
        # cooldown over: primary first again, and the mark clears on success
        llm.primary_down_until = time.monotonic() - 1
        text, _ = await llm.chat("s", "u", max_tokens=8)
        assert text == "from primary" and llm.last_backend.name == "primary" and llm.worker_status()["primary_down_for_s"] == 0
    asyncio.run(go())


def test_failover_on_unreachable_primary(monkeypatch, tmp_path):
    llm = LocalLLM(make_cfg(monkeypatch, tmp_path))
    mock(llm, {"primary": down, "fallback": ok("fall", "from fallback")})
    text, _ = asyncio.run(llm.chat("s", "u", max_tokens=8))
    assert text == "from fallback"


def test_no_failover_for_a_rejected_key(monkeypatch, tmp_path):
    llm = LocalLLM(make_cfg(monkeypatch, tmp_path))
    mock(llm, {"primary": unauthorized, "fallback": ok("fall")})
    with pytest.raises(LLMError) as e:
        asyncio.run(llm.chat("s", "u", max_tokens=8))
    assert "401" in str(e.value) and not e.value.retryable and llm.last_backend.name == "primary"


def test_both_workers_down_names_both(monkeypatch, tmp_path):
    llm = LocalLLM(make_cfg(monkeypatch, tmp_path))
    mock(llm, {"primary": five, "fallback": five})
    with pytest.raises(LLMError) as e:
        asyncio.run(llm.chat("s", "u", max_tokens=8))
    assert "primary" in str(e.value) and "fallback" in str(e.value) and e.value.retryable


def test_single_worker_without_fallback(monkeypatch, tmp_path):
    llm = LocalLLM(make_cfg(monkeypatch, tmp_path, fallback=False))
    assert len(llm.backends) == 1 and llm.worker_status()["fallback"] is None
    mock(llm, {"primary": five})
    with pytest.raises(LLMError):
        asyncio.run(llm.chat("s", "u", max_tokens=8))


def test_count_tokens_shapes(monkeypatch, tmp_path):
    llm = LocalLLM(make_cfg(monkeypatch, tmp_path))
    mock(llm, {"primary": ok("prim"), "fallback": ok("fall")})
    assert asyncio.run(llm.count_tokens("a b c")) == 3          # vLLM shape: count
    assert asyncio.run(llm.count_tokens("")) == 0

    def llama(req):
        body = json.loads(req.content)
        if "content" in body:
            return httpx.Response(200, json={"tokens": [1, 2, 3, 4]})
        return httpx.Response(404)
    mock(llm, {"primary": llama, "fallback": llama})
    assert asyncio.run(llm.count_tokens("anything")) == 4       # llama.cpp shape: tokens

    mock(llm, {"primary": lambda r: httpx.Response(404), "fallback": lambda r: httpx.Response(404)})
    assert asyncio.run(llm.count_tokens("x")) is None            # nobody tokenizes -> estimate
    assert llm._tokenize_off_until > time.monotonic()            # ...and not asked again for a while
    mock(llm, {"primary": ok("prim"), "fallback": ok("fall")})
    assert asyncio.run(llm.count_tokens("a b")) is None          # still off
    llm._tokenize_off_until = 0.0
    assert asyncio.run(llm.count_tokens("a b")) == 2


def test_count_tokens_follows_failover_order(monkeypatch, tmp_path):
    llm = LocalLLM(make_cfg(monkeypatch, tmp_path))
    mock(llm, {"primary": down, "fallback": ok("fall")})
    assert asyncio.run(llm.count_tokens("one two three four")) == 4


def test_a_proxy_in_the_environment_never_carries_worker_traffic(monkeypatch, tmp_path):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(var, "http://203.0.113.9:3128")
    llm = LocalLLM(make_cfg(monkeypatch, tmp_path))
    for b in llm.backends:
        assert b.client.trust_env is False and not b.client._mounts
