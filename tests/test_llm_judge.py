"""Tests for LLM-judge detector."""
from __future__ import annotations

import asyncio
import pytest

from cybersentinel_evolver.detection import DetectionResult
from cybersentinel_evolver.llm_judge import LLMJudgeDetector, _MockLLMClient
from cybersentinel_evolver.models import AttackRequest, Scenario


class TestMockLLMClient:
    def test_detects_high_block_rate(self):
        client = _MockLLMClient()
        raw = client.complete("Block-rate: 100.0%\nAllow-rate: 0.0%")
        import json
        data = json.loads(raw)
        assert data["verdict"] == "detected"

    def test_mostly_benign(self):
        client = _MockLLMClient()
        raw = client.complete("Block-rate: 0.0%\nAllow-rate: 100.0%")
        import json
        data = json.loads(raw)
        assert data["verdict"] == "missed"

    def test_ambiguous_when_equal(self):
        client = _MockLLMClient()
        raw = client.complete("Block-rate: 50.0%\nAllow-rate: 50.0%")
        import json
        data = json.loads(raw)
        assert data["verdict"] == "ambiguous"


class TestLLMJudgeDetector:
    def _make_scenario(self, outcome: str = "block", n: int = 10, timing_ms: int = 50) -> Scenario:
        return Scenario(
            id="test", name="test", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip",
            requests=[AttackRequest("POST", "/api/auth/login",
                                    headers={"Authorization": "Bearer x"},
                                    expected_outcome=outcome,
                                    timing_ms=timing_ms) for _ in range(n)],
        )

    @property
    def detector_id(self) -> str:
        return "llm_judge_claude_v1"

    def test_empty_scenario_missed(self):
        det = LLMJudgeDetector()
        scenario = Scenario(id="e", name="empty", source_feed="f",
                            abuse_type="credential_stuffing", cost_model_label="default",
                            identity_source="ip", requests=[])
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict == "missed"

    def test_all_block_detected_via_fallback(self):
        det = LLMJudgeDetector(fallback=True)
        scenario = self._make_scenario("block", n=20)
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict == "detected"
        assert result.confidence > 0.5

    def test_all_allow_missed_via_fallback(self):
        det = LLMJudgeDetector(fallback=True)
        scenario = self._make_scenario("allow", n=20)
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict == "missed"

    def test_with_mock_llm_client(self):
        class FixedLLM:
            def complete(self, prompt: str, max_tokens: int = 4096) -> str:
                return '{"verdict": "detected", "confidence": 0.95, "explanation": "mock"}'

        det = LLMJudgeDetector(llm_client=FixedLLM())
        scenario = self._make_scenario("block", n=10)
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict == "detected"
        assert result.confidence == 0.95
        assert "mock" in result.explanation

    def test_wrong_json_returns_ambiguous(self):
        class BadLLM:
            def complete(self, prompt: str, max_tokens: int = 4096) -> str:
                return "not json"

        det = LLMJudgeDetector(llm_client=BadLLM())
        scenario = self._make_scenario("block", n=10)
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict == "ambiguous"

    def test_llm_error_returns_ambiguous(self):
        class FailingLLM:
            def complete(self, prompt: str, max_tokens: int = 4096) -> str:
                raise RuntimeError("API down")

        det = LLMJudgeDetector(llm_client=FailingLLM())
        scenario = self._make_scenario("block", n=10)
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict == "ambiguous"
        assert "error" in result.explanation.lower()

    def test_parse_response_plain_json(self):
        det = LLMJudgeDetector()
        parsed = det._parse_response('{"verdict": "detected"}')
        assert parsed["verdict"] == "detected"

    def test_parse_response_markdown_fence(self):
        det = LLMJudgeDetector()
        parsed = det._parse_response('```json\n{"verdict": "missed"}\n```')
        assert parsed["verdict"] == "missed"

    def test_parse_response_invalid(self):
        det = LLMJudgeDetector()
        parsed = det._parse_response("random text")
        assert parsed == {}

    def test_integration_with_tournament(self):
        """LLMJudgeDetector can participate in a tournament."""
        from cybersentinel_evolver.detection import run_tournament
        det = LLMJudgeDetector(fallback=True)
        scenario = self._make_scenario("block", n=20)
        results = asyncio.run(run_tournament([det], [scenario]))
        assert len(results) == 1
        assert results[0].detector_id == "llm_judge_claude_v1"
