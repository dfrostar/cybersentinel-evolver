"""Tests for LLM Client — unit, mock, and optional live call."""
from __future__ import annotations

import os
import pytest

from cybersentinel_evolver.llm_client import (
    _AnthropicClient,
    _EchoClient,
    _OpenAIClient,
    get_echo_client,
    get_llm_client,
)


class TestEchoClient:
    def test_echo_returns_valid_json(self):
        client = get_echo_client()
        import json
        raw = client.complete("test prompt")
        parsed = json.loads(raw)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_echo_has_required_fields(self):
        client = get_echo_client()
        import json
        raw = client.complete("any prompt")
        parsed = json.loads(raw)
        scenario = parsed[0]
        assert "name" in scenario
        assert "abuse_type" in scenario
        assert "identity_source" in scenario
        assert "requests" in scenario


class TestGetLLMClient:
    def test_detects_anthropic_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        client = get_llm_client()
        assert isinstance(client, _AnthropicClient)

    def test_detects_openai_key_without_anthropic(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test-key")
        client = get_llm_client()
        assert isinstance(client, _OpenAIClient)

    def test_anthropic_takes_precedence(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-key")
        client = get_llm_client()
        assert isinstance(client, _AnthropicClient)

    def test_no_key_raises(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="No LLM API key"):
            get_llm_client()

    def test_custom_base_url(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-key")
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://localhost:47821")
        client = get_llm_client()
        assert isinstance(client, _AnthropicClient)
        # The Anthropic client was created with base_url — can't easily inspect
        # without reaching into private state, but we can verify it's callable
        assert hasattr(client, "complete")

    def test_custom_model(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-key")
        monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-4-20250514")
        client = get_llm_client()
        assert isinstance(client, _AnthropicClient)


class TestAnthropicClientUnit:
    def test_complete_returns_text_from_message(self, monkeypatch):
        """Verify complete() extracts text from Anthropic Messages API response."""
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "test response text"
        mock_response.content = [mock_block]
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            client = _AnthropicClient(api_key="test-key")
            result = client.complete("prompt")

        assert result == "test response text"
        mock_client.messages.create.assert_called_once()

    def test_complete_concatenates_multiple_text_blocks(self, monkeypatch):
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_response = MagicMock()
        block1 = MagicMock()
        block1.type = "text"
        block1.text = "part1 "
        block2 = MagicMock()
        block2.type = "text"
        block2.text = "part2"
        # Non-text block (e.g., tool_use) should be skipped
        block3 = MagicMock()
        block3.type = "tool_use"
        mock_response.content = [block1, block2, block3]
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            client = _AnthropicClient(api_key="test-key")
            result = client.complete("prompt")

        assert result == "part1 part2"

    def test_complete_uses_custom_base_url(self):
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_response = MagicMock()
        block = MagicMock()
        block.type = "text"
        block.text = "ok"
        mock_response.content = [block]
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = mock_client
            _AnthropicClient(api_key="key", base_url="http://localhost:8080")
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs["base_url"] == "http://localhost:8080"


class TestOpenAIClientUnit:
    def test_complete_returns_text(self):
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "openai response"
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client):
            client = _OpenAIClient(api_key="test-key")
            result = client.complete("prompt")

        assert result == "openai response"

    def test_complete_handles_null_content(self):
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = None
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client):
            client = _OpenAIClient(api_key="test-key")
            result = client.complete("prompt")

        assert result == ""


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set",
)
class TestLiveAnthropicCall:
    """Live integration test — runs only when ANTHROPIC_API_KEY is set."""

    def test_live_simple_completion(self):
        client = get_llm_client()
        result = client.complete(
            "Reply with exactly: '{\"status\": \"ok\"}'",
            max_tokens=128,
        )
        assert "ok" in result.lower()

    def test_live_scenario_generation(self):
        """Real scenario generation test — verifies LLM produces valid JSON."""
        import json
        client = get_llm_client()
        raw = client.complete(
            'Generate 1 attack scenario as JSON array. '
            'Each scenario must have: name, abuse_type, identity_source, requests (list of {method, path, headers, expected_outcome, timing_ms}). '
            'Output ONLY valid JSON array, no explanation.',
            max_tokens=2048,
        )
        # Tolerant parsing — find first [ ... ] in response
        start = raw.find("[")
        end = raw.rfind("]")
        assert start != -1 and end != -1 and start < end
        parsed = json.loads(raw[start : end + 1])
        assert isinstance(parsed, list)
        assert len(parsed) >= 1
        s = parsed[0]
        assert "name" in s
        assert "abuse_type" in s
        assert "identity_source" in s
        assert "requests" in s
