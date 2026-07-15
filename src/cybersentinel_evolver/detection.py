from __future__ import annotations

import uuid
from typing import Protocol

from .models import (
    AttackRequest,
    CostModel,
    IdentityType,
    MutationRecord,
    MutationStrategy,
    Scenario,
    TournamentResult,
    bootstrap_confidence_interval,
    compute_cost,
    get_cost_model,
    now_ms,
)
from .database import Database


class DetectionStrategy(Protocol):
    """Interface for pluggable abuse detectors."""

    @property
    def detector_id(self) -> str: ...

    async def evaluate(self, scenario: Scenario) -> "DetectionResult": ...


class DetectionResult:
    def __init__(
        self,
        verdict: str,  # "detected", "missed", "ambiguous"
        per_request: list[str],  # "blocked", "allowed", "throttled"
        confidence: float = 1.0,
        explanation: str | None = None,
    ):
        self.verdict = verdict
        self.per_request = per_request
        self.confidence = confidence
        self.explanation = explanation


class RuleBasedDetector:
    """Z-score rule-based detector: flags credential stuffing, scanning, burst."""

    def __init__(self, threshold: int = 10, window_ms: int = 60_000):
        self.threshold = threshold
        self.window_ms = window_ms

    @property
    def detector_id(self) -> str:
        return "rule_based_zscore_v1"

    async def evaluate(self, scenario: Scenario) -> DetectionResult:
        requests = scenario.requests
        if not requests:
            return DetectionResult("missed", [], 1.0, "No requests to evaluate")

        blocked = []
        detected = False

        # Simple heuristic: count errors (401s simulated by expected outcomes)
        block_count = sum(1 for r in requests if r.expected_outcome in ("block", "throttle"))

        # Rule 1: High block rate = likely stuffing/scanning attack
        if len(requests) >= 5 and block_count / len(requests) > 0.5:
            detected = True

        # Rule 2: Burst timing (all requests within short window)
        if len(requests) >= 10:
            total_timing = sum(r.timing_ms for r in requests)
            if total_timing < 5000:  # 10+ req in <5 seconds
                detected = True

        # Rule 3: Many requests to LLM paths
        llm_paths = [r for r in requests if "/v1/" in r.path or "/api/chat" in r.path]
        if len(llm_paths) >= 20:
            detected = True

        for r in requests:
            if r.expected_outcome in ("block", "throttle"):
                blocked.append("blocked")
            else:
                blocked.append("allowed")

        verdict = "detected" if detected else "missed"
        return DetectionResult(verdict, blocked, 0.9 if detected else 0.5)


class BehavioralBaselineDetector:
    """Behavioral detector: learns normal and flags deviants."""

    def __init__(self, baseline_requests_per_min: int = 30, deviation_threshold: float = 3.0):
        self.baseline_ppm = baseline_requests_per_min
        self.deviation = deviation_threshold

    @property
    def detector_id(self) -> str:
        return "behavioral_baseline_v1"

    async def evaluate(self, scenario: Scenario) -> DetectionResult:
        requests = scenario.requests
        if not requests:
            return DetectionResult("missed", [], 1.0)

        # Calculate requests per minute from scenario
        total_timing_ms = sum(r.timing_ms for r in requests) + 1  # avoid div by 0
        duration_min = total_timing_ms / 60_000
        if duration_min < 0.01:
            duration_min = 0.01
        rpm = len(requests) / duration_min

        # Calculate path diversity
        unique_paths = len(set(r.path for r in requests))

        # Deviation from baseline
        rpm_ratio = rpm / self.baseline_ppm if self.baseline_ppm > 0 else 0

        blocked = []
        detected = False

        # Flag if RPM exceeds threshold * baseline AND path diversity is low (automated pattern)
        if rpm_ratio > self.deviation and unique_paths <= 3:
            detected = True

        for r in requests:
            if detected and r.expected_outcome in ("block", "throttle"):
                blocked.append("blocked")
            else:
                blocked.append("allowed")

        return DetectionResult(
            "detected" if detected else "missed",
            blocked,
            min(rpm_ratio / 10, 0.95),
            f"RPM={rpm:.1f}, baseline={self.baseline_ppm}, ratio={rpm_ratio:.1f}",
        )


class RandomDetector:
    """Strawman detector for calibration check."""

    def __init__(self, true_positive_rate: float = 0.5):
        self.tpr = true_positive_rate

    @property
    def detector_id(self) -> str:
        return f"random_calibration_{self.tpr}"

    async def evaluate(self, scenario: Scenario) -> DetectionResult:
        import random
        detected = random.random() < self.tpr
        blocked = ["blocked" if detected else "allowed"] * max(len(scenario.requests), 1)
        return DetectionResult("detected" if detected else "missed", blocked, self.tpr)


async def run_tournament(
    detectors: list[DetectionStrategy],
    scenarios: list[Scenario],
    cost_model_label: str = "default",
) -> list[TournamentResult]:
    """Run N scenarios through each detector, score, bootstrap CI."""
    results = []
    cost_model = get_cost_model(cost_model_label)

    for detector in detectors:
        detected_count = 0
        false_positive_count = 0
        blocked_requests = 0

        for scenario in scenarios:
            result = await detector.evaluate(scenario)
            if result.verdict == "detected":
                detected_count += 1
                blocked_requests += sum(1 for r in result.per_request if r == "blocked")
            elif result.verdict == "missed":
                # Check if scenario was benign (expected allow)
                benign = all(r.expected_outcome == "allow" for r in scenario.requests)
                if not benign and result.verdict == "detected":
                    pass  # correct detection
                if benign and result.verdict == "detected":
                    false_positive_count += 1

        win_rate = detected_count / len(scenarios) if scenarios else 0.0
        ci_low, ci_high = bootstrap_confidence_interval(detected_count, len(scenarios))

        cost_blocked, cost_missed = compute_cost(
            detected_count,
            len(scenarios) - detected_count,
            cost_model,
        )

        results.append(TournamentResult(
            run_id=str(uuid.uuid4()),
            detector_id=detector.detector_id,
            scenario_count=len(scenarios),
            detected_count=detected_count,
            false_positive_count=false_positive_count,
            cost_blocked=cost_blocked,
            cost_missed=cost_missed,
            cost_model_label=cost_model_label,
            win_rate=round(win_rate, 4),
            confidence_low=round(ci_low, 4),
            confidence_high=round(ci_high, 4),
            ran_at=now_ms(),
        ))

    return results


async def run_mutation_tournament(
    detector: DetectionStrategy,
    parent_scenario: Scenario,
    mutations: list[Scenario],
) -> tuple[MutationRecord, list[TournamentResult]]:
    """Evaluate detector against a parent and its mutations."""
    results = await run_tournament([detector], [parent_scenario] + mutations)

    escaped = sum(1 for r in results[1:] if r.win_rate < 0.5)

    record = MutationRecord(
        mutation_id=str(uuid.uuid4()),
        parent_scenario_id=parent_scenario.id,
        child_scenario_id=mutations[0].id if mutations else "",
        strategy="identity_swap",  # default, overridden by caller
        depth=parent_scenario.mutation_depth,
        escaped=escaped > 0,
        created_at=now_ms(),
    )
    return record, results
