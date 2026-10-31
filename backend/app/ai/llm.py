"""Thin client for the local Ollama server. Every model call in the system goes through here.

Model-agnostic: callers ask for a *role* (extract, narrate, classify, copilot, reason, embed) and
config/models.json names the one model serving it. EWS_MODEL_<ROLE> environment variables override it
(e.g. EWS_MODEL_NARRATE=foundation-sec:8b-reasoning). There are deliberately no fallbacks.
"""

from __future__ import annotations

import functools
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODELS_CONFIG = Path(__file__).resolve().parents[3] / "config" / "models.json"


@functools.lru_cache(maxsize=1)
def _roles() -> dict[str, str]:
    return json.loads(MODELS_CONFIG.read_text(encoding="utf-8"))["roles"]


@functools.lru_cache(maxsize=None)
def resolve(role: str) -> str:
    """Return the model serving `role` (env override first). Fails loudly if it is not pulled."""
    name = os.environ.get(f"EWS_MODEL_{role.upper()}") or _roles()[role]
    have = available_models()
    if name not in have and f"{name}:latest" not in have:
        raise RuntimeError(f"model '{name}' for role '{role}' is not available in Ollama")
    return name


@dataclass
class LLMResult:
    content: str
    data: Any = None
    tool_calls: list = field(default_factory=list)
    seconds: float = 0.0
    tokens_out: int = 0
    tokens_per_s: float = 0.0
    error: str | None = None


def chat(
    messages: list[dict],
    *,
    role: str = "extract",
    model: str | None = None,
    schema: dict | None = None,
    tools: list[dict] | None = None,
    temperature: float = 0.0,
    num_ctx: int = 8192,
    max_tokens: int = 1024,
    think: bool = False,
    timeout: float = 300.0,
) -> LLMResult:
    payload: dict[str, Any] = {
        "model": model or resolve(role),
        "messages": messages,
        "stream": False,
        "think": think,
        # num_predict caps runaway generations (constrained decoding can loop on small models).
        "options": {"temperature": temperature, "num_ctx": num_ctx, "num_predict": max_tokens, "seed": 7},
    }
    if schema is not None:
        payload["format"] = schema
    if tools:
        payload["tools"] = tools

    started = time.perf_counter()
    try:
        resp = httpx.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=timeout)
        if resp.status_code == 400 and "think" in resp.text:
            # Non-reasoning models reject the think flag entirely; retry without it.
            payload.pop("think")
            resp = httpx.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=timeout)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        return LLMResult(content="", seconds=time.perf_counter() - started, error=repr(exc))

    body = resp.json()
    msg = body.get("message", {})
    content = msg.get("content", "")
    if "</think>" in content:
        # Some builds leak the reasoning trace into content even with think=False.
        content = content.split("</think>", 1)[1]
    result = LLMResult(
        content=content.strip(),
        tool_calls=msg.get("tool_calls") or [],
        seconds=time.perf_counter() - started,
        tokens_out=body.get("eval_count", 0),
    )
    if body.get("eval_duration"):
        result.tokens_per_s = result.tokens_out / (body["eval_duration"] / 1e9)
    if body.get("done_reason") == "length":
        result.error = "truncated: hit max_tokens"
    if schema is not None:
        try:
            result.data = json.loads(result.content)
        except json.JSONDecodeError as exc:
            result.error = f"invalid json: {exc}"
    elif not result.content and result.error is None:
        result.error = "empty response"
    return result


def embed(texts: list[str], *, model: str | None = None, timeout: float = 300.0) -> list[list[float]]:
    """Security-domain embeddings. Default: SecureBERT 2.0 bi-encoder on the CPU (backend.app.ai.embed);
    pass an Ollama embedding model name to use the GPU server instead."""
    if model is None:
        from .embed import encode
        return encode(texts).tolist()
    resp = httpx.post(f"{OLLAMA_URL}/api/embed", json={"model": model, "input": texts}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["embeddings"]


def available_models() -> set[str]:
    resp = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=10)
    resp.raise_for_status()
    return {m["name"] for m in resp.json().get("models", [])}
