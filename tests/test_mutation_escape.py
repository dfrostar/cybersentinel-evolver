"""Mutation escape-rate tests.

Per BRD §5.3 / E3: mutation engine must produce ≥ 30% escape rate.

This suite measures actual escape rates against the current detector set
(RuleBased z-score + Behavioral baseline) and fails if any new mutation
strategy falls below the threshold.
"""
from __future__ import annotations

import asyncio

import pytest

from cybersentinel_evolver.attacks import AttackGenerator, MutationEngine
from cybersentinel_evolver.database import Database
from cybersentinel_evolver.detection import (
    BehavioralBaselineDetector,
    RuleBasedDetector,
    run_tournament,
)
from cybersentinel_evolver.models import Scenario


@pytest.fixture
def db(tmp_path):
    db = Database(tmp_path / "test.db")
    yield db
    db.close()


@pytest.fixture
def populated_db(db):
    gen = AttackGenerator(db)
    gen.generate()
    return db


class TestMutationEscapeRate:
    """ME-E-001: New evasive mutation strategies achieve ≥30% escape rate."""

    @pytest.mark.parametrize("strategy", [
        "payload_fragmentation",
        "diurnal_pacing",
        "multi_identity_rotation",
        "path_diversification",
    ])
    def test_each_evasive_strategy_escapes_rule_based(self, populated_db, strategy):
        """Each evasive strategy must escape RuleBased detector ≥30% of time."""
        db = populated_db
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
        mut = MutationEngine(db)

        escape_count = 0
        total_trials = 0
        detector = RuleBasedDetector()

        for scenario in scenarios[:6]:  # sample 6 scenarios
            children = mut.mutate(scenario, strategy, n=3)
            for child in children:
                results = asyncio.run(run_tournament([detector], [child]))
                if results[0].win_rate < 1.0:
                    escape_count += 1
                total_trials += 1

        escape_rate = escape_count / total_trials if total_trials else 0
        assert escape_rate >= 0.30, (
            f"Strategy '{strategy}' escape rate {escape_rate:.0%} < 30%"
        )

    @pytest.mark.parametrize("strategy", [
        "payload_fragmentation",
        "diurnal_pacing",
        "multi_identity_rotation",
        "path_diversification",
    ])
    def test_each_evasive_strategy_escapes_behavioral(self, populated_db, strategy):
        """Each evasive strategy must escape Behavioral detector ≥30% of time."""
        db = populated_db
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
        mut = MutationEngine(db)

        escape_count = 0
        total_trials = 0
        detector = BehavioralBaselineDetector()

        for scenario in scenarios[:6]:
            children = mut.mutate(scenario, strategy, n=3)
            for child in children:
                results = asyncio.run(run_tournament([detector], [child]))
                if results[0].win_rate < 1.0:
                    escape_count += 1
                total_trials += 1

        escape_rate = escape_count / total_trials if total_trials else 0
        assert escape_rate >= 0.30, (
            f"Strategy '{strategy}' escape rate {escape_rate:.0%} < 30%"
        )


class TestMutationStrategiesProduceDifferentVariant:
    """ME-E-002: Each strategy produces semantically distinct mutations."""

    def test_payload_fragmentation_alters_body(self, populated_db):
        db = populated_db
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
        mut = MutationEngine(db)

        parent = next(s for s in scenarios if s.requests and s.requests[0].body_b64)
        children = mut.mutate(parent, "payload_fragmentation", n=1)
        child = children[0]

        # Fragmentation should strip most of body
        first_child_body = child.requests[0].body_b64
        first_parent_body = parent.requests[0].body_b64
        if first_parent_body and first_child_body:
            assert len(first_child_body) < len(first_parent_body)

    def test_diurnal_pacing_increases_timing_dramatically(self, populated_db):
        db = populated_db
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
        mut = MutationEngine(db)

        parent = scenarios[0]
        children = mut.mutate(parent, "diurnal_pacing", n=1)
        child = children[0]

        parent_timing = parent.requests[0].timing_ms
        child_timing = child.requests[0].timing_ms
        assert child_timing > parent_timing * 100  # 100x slower

    def test_multi_identity_rotation_clears_auth(self, populated_db):
        db = populated_db
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
        mut = MutationEngine(db)

        parent = scenarios[0]
        children = mut.mutate(parent, "multi_identity_rotation", n=1)
        child = children[0]

        if parent.requests and "Authorization" in parent.requests[0].headers:
            assert "Authorization" not in child.requests[0].headers

    def test_path_diversification_uses_benign_paths(self, populated_db):
        db = populated_db
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
        mut = MutationEngine(db)

        parent = scenarios[0]
        children = mut.mutate(parent, "path_diversification", n=1)
        child = children[0]

        child_path = child.requests[0].path
        assert child_path.startswith(("/status", "/healthz", "/readyz", "/ping",
                                     "/metrics", "/info", "/version", "/config", "/debug"))

    def test_evasive_strategies_mutually_exclusive_variants(self, populated_db):
        """Each strategy produces different request sequences than the others."""
        db = populated_db
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
        mut = MutationEngine(db)
        parent = scenarios[0]

        variants = {}
        for strategy in ["payload_fragmentation", "diurnal_pacing",
                         "multi_identity_rotation", "path_diversification"]:
            children = mut.mutate(parent, strategy, n=1)
            child = children[0]
            key = (child.requests[0].timing_ms, child.requests[0].path,
                   tuple(sorted(child.requests[0].headers.keys())))
            variants[strategy] = key

        # All four should be unique
        unique_variants = set(variants.values())
        assert len(unique_variants) == 4
