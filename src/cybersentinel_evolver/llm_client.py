"""LLM Client for CyberSentinel Evolver.

Unified completion interface supporting:
- Anthropic Claude (primary, via ANTHROPIC_API_KEY)
- OpenAI-compatible fallback (OPENAI_API_KEY + OPENAI_BASE_URL)

Reads credentials exclusively from environment variables.

Usage:
    from cybersentinel_evolver.llm_client import get_llm_client
    client = get_llm_client()
    response = client.complete("Generate 3 attack scenarios ...")
"""
from __future__ import annotations

import os
from typing import Protocol


class LLMClient(Protocol):
    def complete(self, prompt: str, max_tokens: int = 4096) -> str: ...


class _AnthropicClient:
    """Anthropic Claude client via official SDK."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-5-20250929",
        base_url: str | None = None,
        timeout: float = 120.0,
        max_retries: int = 2,
    ):
        import anthropic

        kwargs = {"api_key": api_key, "timeout": timeout, "max_retries": max_retries}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)
        self._model = model

    def complete(self, prompt: str, max_tokens: int = 4096) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        # Concatenate all text block content
        parts = []
        for block in response.content:
            if getattr(block, "type", None) == "text":
                parts.append(block.text)
        return "".join(parts)


class _OpenAIClient:
    """OpenAI-compatible client (works with pxpipe, local models, etc.)."""

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        model: str = "claude-sonnet-4-5-20250929",
        timeout: float = 120.0,
        max_retries: int = 2,
    ):
        import openai

        kwargs = {"api_key": api_key, "timeout": timeout, "max_retries": max_retries}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = openai.OpenAI(**kwargs)
        self._model = model

    def complete(self, prompt: str, max_tokens: int = 4096) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""


class _EchoClient:
    """Fallback echo client — returns prompt back. Used for offline testing."""

    def complete(self, prompt: str, max_tokens: int = 4096) -> str:
        return (
            '[{"name": "echo_scenario", "abuse_type": "prompt_injection", '
            '"identity_source": "jwt_claim", "requests": []}]'
        )


def get_llm_client() -> LLMClient:
    """Factory: detect configured LLM provider from environment.

    Detection order:
    1. ANTHROPIC_API_KEY → _AnthropicClient (primary)
    2. OPENAI_API_KEY + OPENAI_BASE_URL → _OpenAIClient (pxpipe proxy)
    3. OPENAI_API_KEY only → _OpenAIClient (standard OpenAI)
    4. No key → raises RuntimeError with helpful message
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        base_url = os.environ.get("ANTHROPIC_BASE_URL")
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")
        return _AnthropicClient(
            api_key=anthropic_key,
            model=model,
            base_url=base_url,
        )

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        base_url = os.environ.get("OPENAI_BASE_URL")
        model = os.environ.get("OPENAI_MODEL", "claude-sonnet-4-5-20250929")
        return _OpenAIClient(
            api_key=openai_key,
            base_url=base_url,
            model=model,
        )

    raise RuntimeError(
        "No LLM API key. Set ANTHROPIC_API_KEY or OPENAI_API_KEY env var. "
        "For offline template-only mode, omit --llm flag."
    )


def get_echo_client() -> LLMClient:
    """Test-only client — deterministic, no API calls."""
    return _EchoClient()
