"""Fuzz tests for detection and mutation logic.

Uses Hypothesis for property-based testing. No live API calls.
"""
from __future__ import annotations

import uuid
from typing import List

import pytest
from hypothesis import given, settings, strategies as st

from cybersentinel_evolver.attacks import AttackGenerator, MutationEngine
from cybersentinel_evolver.database import Database
from cybersentinel_evolver.detection import (
    BehavioralBaselineDetector,
    DetectionResult,
    RandomDetector,
    RuleBasedDetector,
)
from cybersentinel_evolver.models import (
    AbuseType,
    AttackRequest,
    IdentityType,
    OutcomeType,
    Scenario,
)


# ── Strategies ──────────────────────────────────────────────────────────

abuse_types: st.SearchStrategy[AbuseType] = st.sampled_from(
    [
        "credential_stuffing",
        "path_scanning",
        "error_spike",
        "traffic_spike",
        "agent_impersonation",
        "llm_token_scraping",
        "billing_abuse",
        "mcp_server_abuse",
        "prompt_injection",
        "rate_evasion_distributed",
        "shadow_agent_discovery",
        "request_smuggling",
    ]
)

identity_types: st.SearchStrategy[IdentityType] = st.sampled_from(
    ["ip", "jwt_claim", "user_agent", "mcp_agent_name", "oauth_client_id", "api_key_header", "composite_identity"]
)

methods: st.SearchStrategy[str] = st.sampled_from(["GET", "POST", "PUT", "DELETE"])

outcomes: st.SearchStrategy[OutcomeType] = st.sampled_from(["allow", "block", "throttle", "challenge"])


def make_requests(min_size: int = 1, max_size: int = 50) -> st.SearchStrategy[List[AttackRequest]]:
    """Generate a list of well-formed AttackRequests."""
    req = st.builds(
        AttackRequest,
        method=methods,
        path=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P"), min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=50,
        ),
        headers=st.dictionaries(
            st.text(min_size=1, max_size=20),
            st.text(min_size=0, max_size=20),
            max_size=5,
        ),
        expected_outcome=outcomes,
        timing_ms=st.integers(min_value=0, max_value=10_000),
    )
    return st.lists(req, min_size=min_size, max_size=max_size)


def make_scenario(min_reqs: int = 1, max_reqs: int = 30) -> st.SearchStrategy[Scenario]:
    return st.builds(
        Scenario,
        id=st.uuids().map(str),
        name=st.text(min_size=1, max_size=100),
        source_feed=st.text(min_size=1, max_size=50),
        abuse_type=abuse_types,
        cost_model_label=st.just("default"),
        identity_source=identity_types,
        requests=make_requests(min_reqs, max_reqs),
        parent_id=st.one_of(st.none(), st.uuids().map(str)),
        mutation_depth=st.integers(min_value=0, max_value=10),
        generation=st.integers(min_value=0, max_value=5),
        created_at=st.integers(min_value=0, max_value=2_000_000_000_000),
    )


# ── Tests: Detection always returns a valid result ──────────────────────

def make_scenario_detection(min_reqs: int = 1, max_reqs: int = 30) -> st.SearchStrategy[Scenario]:
    req = st.builds(
        AttackRequest,
        method=methods,
        path=st.text(alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")), min_size=1, max_size=30),
        headers=st.dictionaries(
            st.text(min_size=1, max_size=15),
            st.text(min_size=0, max_size=15),
            max_size=3,
        ),
        expected_outcome=outcomes,
        timing_ms=st.integers(min_value=0, max_value=10_000),
    )
    return st.builds(
        Scenario,
        id=st.uuids().map(str),
        name=st.text(min_size=1, max_size=80),
        source_feed=st.just("test"),
        abuse_type=abuse_types,
        cost_model_label=st.just("default"),
        identity_source=identity_types,
        requests=st.lists(req, min_size=min_reqs, max_size=max_reqs),
        parent_id=st.none(),
        mutation_depth=st.just(0),
        generation=st.just(0),
        created_at=st.integers(min_value=0, max_value=2_000_000_000_000),
    )


@pytest.fixture
def detectors():
    return [
        RuleBasedDetector(),
        BehavioralBaselineDetector(),
        RandomDetector(true_positive_rate=0.5),
    ]


@pytest.mark.parametrize(
    "detector_cls",
    [RuleBasedDetector, BehavioralBaselineDetector, RandomDetector],
)
@given(scenario=make_scenario_detection())
@settings(max_examples=50, deadline=5_000)
def test_detector_always_returns_valid_result(detector_cls: type, scenario: Scenario) -> None:
    """Every detector must return a DetectionResult for any scenario shape."""
    if detector_cls is RandomDetector:
        detector = detector_cls(true_positive_rate=0.5)
    else:
        detector = detector_cls()

    import asyncio
    result = asyncio.run(detector.evaluate(scenario))

    assert isinstance(result, DetectionResult)
    assert result.verdict in ("detected", "missed", "ambiguous")
    assert 0.0 <= result.confidence <= 1.0
    assert len(result.per_request) == len(scenario.requests)
    assert all(pr in ("blocked", "allowed", "throttled", "ambiguous") for pr in result.per_request)


# ── Tests: RuleBasedDetector deterministic on same input ────────────────

@given(scenario=make_scenario_detection())
@settings(max_examples=20, deadline=5_000)
def test_rule_based_deterministic(scenario: Scenario) -> None:
    """Same scenario → same verdict, no randomness leaked."""
    import asyncio
    d = RuleBasedDetector()
    r1 = asyncio.run(d.evaluate(scenario))
    r2 = asyncio.run(d.evaluate(scenario))
    assert r1.verdict == r2.verdict
    assert r1.per_request == r2.per_request


# ── Tests: RandomDetector always returns len(requests) per_request list ─

@given(scenario=make_scenario_detection())
@settings(max_examples=20, deadline=5_000)
def test_random_detector_per_request_length(scenario: Scenario) -> None:
    import asyncio
    d = RandomDetector(true_positive_rate=0.5)
    result = asyncio.run(d.evaluate(scenario))
    assert len(result.per_request) == max(len(scenario.requests), 1)


# ── Tests: Empty scenario handling ──────────────────────────────────────

def test_empty_scenario_no_crash() -> None:
    import asyncio
    scenario = Scenario(
        id=str(uuid.uuid4()),
        name="empty",
        source_feed="test",
        abuse_type="credential_stuffing",
        cost_model_label="default",
        identity_source="ip",
        requests=[],
    )
    for cls in [RuleBasedDetector, BehavioralBaselineDetector, RandomDetector]:
        if cls is RandomDetector:
            detector = cls(true_positive_rate=0.5)
        else:
            detector = cls()
        result = asyncio.run(detector.evaluate(scenario))
        assert result.verdict in ("detected", "missed", "ambiguous")


# ── Tests: Scenario with extreme timing ────────────────────────────────

@given(scenario=make_scenario_detection())
@settings(max_examples=20, deadline=5_000)
def test_extreme_timing_handled(scenario: Scenario) -> None:
    """Requests with zero or very large timing should not crash BehavioralBaselineDetector."""
    import asyncio
    for r in scenario.requests:
        r.timing_ms = 0  # edge case
    result = asyncio.run(BehavioralBaselineDetector().evaluate(scenario))
    assert result.verdict in ("detected", "missed", "ambiguous")


# ── Tests: Mutation engine produces valid children ──────────────────────

@given(
    scenario=make_scenario_detection(min_reqs=3, max_reqs=10),
    strategy=st.sampled_from(["identity_swap", "temporal_mutation", "protocol_mutation", "intent_preserving"]),
    n=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=20, deadline=10_000)
def test_mutation_engine_produces_valid_children(scenario: Scenario, strategy: str, n: int) -> None:
    from cybersentinel_evolver.models import MutationStrategy
    db = Database(":memory:")
    engine = MutationEngine(db)
    children = engine.mutate(scenario, strategy, n=n)
    children = list(children)
    assert len(children) == n
    for child in children:
        assert child.id != scenario.id
        assert child.parent_id == scenario.id
        assert child.generation == scenario.generation + 1
        assert child.mutation_depth == scenario.mutation_depth + 1
        assert len(child.requests) > 0
    db.close()
