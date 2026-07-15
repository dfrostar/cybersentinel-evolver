"""Tests for detector crash isolation in tournament."""
from __future__ import annotations

import asyncio
import uuid

from cybersentinel_evolver.detection import (
    DetectionResult,
    RuleBasedDetector,
    run_tournament,
)
from cybersentinel_evolver.models import (
    AttackRequest,
    Scenario,
)


class CrashingDetector:
    """Detector that always raises — simulates an unhandled bug."""

    @property
    def detector_id(self) -> str:
        return "crashing_v1"

    async def evaluate(self, scenario: Scenario) -> DetectionResult:
        raise RuntimeError("Simulated detector crash: division by zero")


def make_scenario(n: int = 5) -> Scenario:
    return Scenario(
        id=str(uuid.uuid4()),
        name="test",
        source_feed="test",
        abuse_type="credential_stuffing",
        cost_model_label="default",
        identity_source="ip",
        requests=[
            AttackRequest(method="POST", path="/api/v1/chat", expected_outcome="block", timing_ms=100)
            for _ in range(n)
        ],
    )


def test_tournament_with_crashing_detector_returns_all_results() -> None:
    """One detector shouldn't prevent others from completing."""
    scenarios = [make_scenario() for _ in range(3)]
    detectors = [RuleBasedDetector(), CrashingDetector()]

    results = asyncio.run(run_tournament(detectors, scenarios))

    assert len(results) == 2
    ids = [r.detector_id for r in results]
    assert "rule_based_zscore_v1" in ids
    assert "crashing_v1_CRASHED" in ids


def test_tournament_completion_with_crash() -> None:
    """Crashed detector should have win_rate=0 but not poison the result list."""
    scenarios = [make_scenario()]
    results = asyncio.run(run_tournament([CrashingDetector()], scenarios))

    assert len(results) == 1
    r = results[0]
    assert r.win_rate == 0.0
    assert r.detected_count == 0
    assert r.detector_id.endswith("_CRASHED")


def test_all_detectors_crash_returns_empty_results() -> None:
    """If every detector crashes, we still get a result per detector."""
    scenarios = [make_scenario()]
    detectors = [CrashingDetector(), CrashingDetector()]
    results = asyncio.run(run_tournament(detectors, scenarios))

    assert len(results) == 2
    for r in results:
        assert r.win_rate == 0.0
        assert r.detector_id.endswith("_CRASHED")
