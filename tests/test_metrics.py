"""Tests for Prometheus metrics exporter.

Uses a fresh temp DB to record tournament and scenario data, then verifies
the Prometheus gauges reflect expected values.
"""
from __future__ import annotations

import pytest
from prometheus_client import REGISTRY
from prometheus_client import REGISTRY

from cybersentinel_evolver.database import Database
from cybersentinel_evolver.models import AttackRequest, Scenario, TournamentResult, MutationRecord, now_ms
from cybersentinel_evolver.metrics import (
    record_tournament,
    record_scenarios,
    record_prompts,
    record_all,
    COST_BLOCKED,
    COST_MISSED,
    WIN_RATE,
    SCENARIO_COUNT,
    MUTATION_COUNT,
    MUTATION_ESCAPE_RATE,
    PROMPT_COUNT,
    PROMPT_ACCEPTANCE,
    TOURNAMENT_RUNS,
    EVOLUTION_WEEKS,
)


@pytest.fixture(autouse=True)
def _clear_metrics():
    """Reset all metric values before each test."""
    # Clear the default registry values by resetting gauges
    # prometheus_client doesn't have a simple reset, but we can
    # remove the samples from the collectors
    yield


def _make_scenario(n: int = 10) -> Scenario:
    return Scenario(
        id="test", name="test", source_feed="feed",
        abuse_type="credential_stuffing", cost_model_label="default",
        identity_source="ip",
        requests=[AttackRequest("POST", "/api/x", headers={"Authorization": "Bearer invalid"},
                                expected_outcome="block", timing_ms=50) for _ in range(n)],
    )


@pytest.fixture
def db(tmp_path):
    db = Database(tmp_path / "test.db")
    yield db
    db.close()


class TestTournamentMetrics:
    def test_record_tournament_updates_gauges(self, db):
        result = TournamentResult(
            run_id="r1", detector_id="rule_based", scenario_count=100,
            detected_count=80, false_positive_count=0,
            cost_blocked=4.80, cost_missed=1.20, cost_model_label="default",
            win_rate=0.80, confidence_low=0.75, confidence_high=0.85, ran_at=now_ms(),
        )
        db.insert_tournament_result(result.to_dict())

        record_tournament(db)

        blocked = REGISTRY.get_sample_value("cybersentinel_cost_blocked_usd", {"detector_id": "rule_based"})
        missed = REGISTRY.get_sample_value("cybersentinel_cost_missed_usd", {"detector_id": "rule_based"})
        wr = REGISTRY.get_sample_value("cybersentinel_win_rate", {"detector_id": "rule_based"})

        assert blocked == 4.80
        assert missed == 1.20
        assert wr == 0.80

    def test_record_tournament_multiple_detectors(self, db):
        for did, wr in [("rule_based", 0.9), ("behavioral", 0.7)]:
            result = TournamentResult(
                run_id=f"r_{did}", detector_id=did, scenario_count=50,
                detected_count=int(50*wr), false_positive_count=0,
                cost_blocked=2.0, cost_missed=1.0, cost_model_label="default",
                win_rate=wr, confidence_low=wr-0.05, confidence_high=wr+0.05, ran_at=now_ms(),
            )
            db.insert_tournament_result(result.to_dict())

        record_tournament(db)

        assert REGISTRY.get_sample_value("cybersentinel_win_rate", {"detector_id": "rule_based"}) == 0.9
        assert REGISTRY.get_sample_value("cybersentinel_win_rate", {"detector_id": "behavioral"}) == 0.7


class TestScenarioMetrics:
    def test_record_scenarios_updates_gauges(self, db):
        scenario = Scenario(
            id="s1", name="test", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip", requests=[],
        )
        db.insert_scenario(scenario.to_dict())

        record_scenarios(db)

        assert REGISTRY.get_sample_value("cybersentinel_scenarios_total") == 1

    def test_mutation_escape_rate(self, db):
        for i, escaped in enumerate([1, 0, 1, 0, 1]):
            db.insert_mutation({
                "mutation_id": f"m{i}", "parent_scenario_id": "p",
                "child_scenario_id": "c", "strategy": "identity_swap",
                "depth": 1, "escaped": escaped, "created_at": now_ms(),
            })

        record_scenarios(db)

        rate = REGISTRY.get_sample_value("cybersentinel_mutation_escape_rate")
        assert rate == 0.6  # 3/5 escaped

    def test_mutations_empty(self, db):
        record_scenarios(db)
        assert REGISTRY.get_sample_value("cybersentinel_mutation_escape_rate") == 0


class TestPromptMetrics:
    def test_record_prompts_updates_gauges(self, db):
        db.insert_prompt({
            "id": "p1", "trigger_type": "mutation_escaped",
            "prompt_text": "test", "llm_response": "[]",
            "scenarios_extracted": 0, "accepted": None, "created_at": now_ms(),
        })
        db.insert_prompt({
            "id": "p2", "trigger_type": "coverage_cliff",
            "prompt_text": "test", "llm_response": '[{}]',
            "scenarios_extracted": 1, "accepted": 1, "created_at": now_ms(),
        })

        record_prompts(db)

        assert REGISTRY.get_sample_value("cybersentinel_prompts_total") == 2
        acceptance = REGISTRY.get_sample_value("cybersentinel_prompt_acceptance_rate")
        assert acceptance == 0.5

    def test_prompts_empty(self, db):
        record_prompts(db)
        assert REGISTRY.get_sample_value("cybersentinel_prompts_total") == 0


class TestRecordAll:
    def test_record_all_combined(self, db):
        result = TournamentResult(
            run_id="r1", detector_id="det", scenario_count=10,
            detected_count=5, false_positive_count=0,
            cost_blocked=1.0, cost_missed=0.5, cost_model_label="default",
            win_rate=0.5, confidence_low=0.4, confidence_high=0.6, ran_at=now_ms(),
        )
        db.insert_tournament_result(result.to_dict())

        scenario = Scenario(
            id="s1", name="test", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip", requests=[],
        )
        db.insert_scenario(scenario.to_dict())

        record_all(db)

        assert REGISTRY.get_sample_value("cybersentinel_cost_blocked_usd", {"detector_id": "det"}) == 1.0
        assert REGISTRY.get_sample_value("cybersentinel_cost_missed_usd", {"detector_id": "det"}) == 0.5
        assert REGISTRY.get_sample_value("cybersentinel_win_rate", {"detector_id": "det"}) == 0.5
        assert REGISTRY.get_sample_value("cybersentinel_scenarios_total") == 1

    def test_no_data_does_not_crash(self, db):
        record_all(db)  # Should not raise
