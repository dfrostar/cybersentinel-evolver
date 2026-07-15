"""LLM-judge detector — Claude-based adjudication for ambiguous scenarios.

Per TRD §1.2 (optional Claude Judge) and BRD §5.2 (LLM-judge as one of
3+ detection strategies). Wired as a drop-in DetectionStrategy.

Usage:
    from cybersentinel_evolver.llm_judge import LLMJudgeDetector

    detector = LLMJudgeDetector(api_key="sk-ant-...")
    result = await detector.evaluate(scenario)
    # result.verdict = "detected" | "missed" | "ambiguous"
"""
from __future__ import annotations

import json
from typing import Protocol

from .detection import DetectionResult
from .models import (
    AbuseType,
    AttackRequest,
    IdentityType,
    Scenario,
)


class LLMClient(Protocol):
    def complete(self, prompt: str, max_tokens: int = 4096) -> str: ...


class _MockLLMClient:
    """Offline fallback — uses block/allow rates extracted from the prompt."""

    def complete(self, prompt: str, max_tokens: int = 4096) -> str:
        # Extract rates from prompt lines like "Block-rate: 100.0%" and "Allow-rate: 0.0%"
        block_rate = self._extract_rate(prompt, "Block-rate")
        allow_rate = self._extract_rate(prompt, "Allow-rate")

        if block_rate > 0.5:
            return '{"verdict": "detected", "confidence": 0.8, "explanation": "high block rate"}'
        elif allow_rate > 0.5:
            return '{"verdict": "missed", "confidence": 0.6, "explanation": "mostly benign"}'
        return '{"verdict": "ambiguous", "confidence": 0.5, "explanation": "indeterminate"}'

    @staticmethod
    def _extract_rate(prompt: str, key: str) -> float:
        for line in prompt.split("\n"):
            if key in line:
                # Extract percentage like "100.0%" or "0.0%"
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[1].strip().replace("%", "")
                    try:
                        return float(val) / 100.0
                    except ValueError:
                        pass
        return 0.0


class LLMJudgeDetector:
    """Claude-backed detector for ambiguous abuse scenarios.

    Two modes:
    1. Full LLM (requires API key) — sends scenario to Claude, parses JSON verdict
    2. Fallback heuristic (no API key) — uses block/allow ratio

    The fallback is useful for offline testing, CI, and deployments where API
    access is not configured.
    """

    PROMPT_TEMPLATE = """You are a cybersecurity analyst evaluating API traffic scenarios.

Given the following attack scenario, determine whether it represents genuine abuse.

Scenario: {scenario_name}
Abuse type: {abuse_type}
Identity source: {identity_source}
Source feed: {source_feed}
Number of requests: {request_count}

Request summary:
- Methods: {methods}
- Unique paths: {unique_paths}
- Block-rate: {block_rate:.1%}
- Allow-rate: {allow_rate:.1%}
- Avg timing: {avg_timing:.0f}ms between requests
- Total duration: {total_timing:.0f}ms

Respond with a JSON object:
{{"verdict": "detected" | "missed" | "ambiguous", "confidence": 0.0-1.0, "explanation": "brief reason"}}

Only output the JSON object."""

    def __init__(
        self,
        api_key: str | None = None,
        llm_client: LLMClient | None = None,
        fallback: bool = False,
    ):
        if llm_client:
            self._client = llm_client
        elif api_key and not fallback:
            from .llm_client import _AnthropicClient
            self._client = _AnthropicClient(api_key=api_key)
        else:
            self._client = _MockLLMClient()

    @property
    def detector_id(self) -> str:
        return "llm_judge_claude_v1"

    async def evaluate(self, scenario: Scenario) -> DetectionResult:
        """Evaluate a scenario — LLM verdict translated to DetectionResult."""
        requests = scenario.requests
        if not requests:
            return DetectionResult("missed", [], 1.0, "No requests to evaluate")

        block_count = sum(1 for r in requests if r.expected_outcome in ("block", "throttle"))
        block_rate = block_count / len(requests)
        allow_count = sum(1 for r in requests if r.expected_outcome == "allow")
        allow_rate = allow_count / len(requests)
        methods = ", ".join(sorted(set(r.method for r in requests)))
        unique_paths = len(set(r.path for r in requests))
        avg_timing = sum(r.timing_ms for r in requests) / len(requests)

        prompt = self.PROMPT_TEMPLATE.format(
            scenario_name=scenario.name,
            abuse_type=scenario.abuse_type,
            identity_source=scenario.identity_source,
            source_feed=scenario.source_feed,
            request_count=len(requests),
            methods=methods,
            unique_paths=unique_paths,
            block_rate=block_rate,
            allow_rate=allow_rate,
            avg_timing=avg_timing,
            total_timing=sum(r.timing_ms for r in requests),
        )

        try:
            raw = self._client.complete(prompt, max_tokens=1024)
            parsed = self._parse_response(raw)
            verdict = parsed.get("verdict", "ambiguous")
            confidence = float(parsed.get("confidence", 0.5))
            explanation = parsed.get("explanation", "")

            per_request = ["blocked" if verdict == "detected" else "allowed"] * len(requests)
            return DetectionResult(verdict, per_request, confidence, explanation)
        except Exception as e:
            return DetectionResult("ambiguous", ["ambiguous"] * len(requests), 0.5, f"LLM error: {e}")

    def _parse_response(self, raw: str) -> dict:
        """Parse JSON from LLM response, tolerant of markdown fences."""
        if "```" in raw:
            parts = raw.split("```")
            for p in parts:
                p = p.strip()
                if p.startswith("json"):
                    p = p[4:].strip()
                if p.startswith("{"):
                    raw = p
                    break
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
        return {}
