"""Benchmarks for performance-critical operations.

Run with: pytest tests/test_benchmarks.py --benchmark-only --benchmark-columns=mean,stddev,rounds
"""
from __future__ import annotations

import asyncio

import pytest

from cybersentinel_evolver.attacks import AttackGenerator, MutationEngine
from cybersentinel_evolver.database import Database
from cybersentinel_evolver.detection import (
    BehavioralBaselineDetector,
    RuleBasedDetector,
    RandomDetector,
    run_tournament,
)
from cybersentinel_evolver.gap_analyzer import GapAnalyzer
from cybersentinel_evolver.models import AttackRequest, MutationRecord, Scenario, TournamentResult, now_ms
from cybersentinel_evolver.self_promoter import SelfPromoter


@pytest.fixture
def db(tmp_path):
    db = Database(tmp_path / "test.db")
    yield db
    db.close()


def test_benchmark_scenario_generation(benchmark, db):
    gen = AttackGenerator(db)
    benchmark(gen.generate)


def test_benchmark_tournament(benchmark, db):
    gen = AttackGenerator(db)
    gen.generate()
    scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]

    def run():
        return asyncio.run(run_tournament(
            [RuleBasedDetector(), BehavioralBaselineDetector()],
            scenarios,
        ))

    result = benchmark(run)
    assert len(result) == 2


def test_benchmark_mutation_identity_swap(benchmark, db):
    gen = AttackGenerator(db)
    gen.generate()
    scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
    mut = MutationEngine(db)

    def run():
        return mut.mutate(scenarios[0], "identity_swap", n=3)

    result = benchmark(run)
    assert len(result) == 3


def test_benchmark_mutation_all_strategies(benchmark, db):
    gen = AttackGenerator(db)
    gen.generate()
    scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
    mut = MutationEngine(db)
    strategies: list[str] = [
        "identity_swap", "temporal_mutation", "protocol_mutation",
        "intent_preserving", "payload_fragmentation", "diurnal_pacing",
        "multi_identity_rotation", "path_diversification",
    ]

    all_results = []

    def run():
        all_results.clear()
        for s in scenarios[:3]:
            for strat in strategies:
                all_results.extend(mut.mutate(s, strat, n=2))

    benchmark(run)
    assert len(all_results) >= 48


def test_benchmark_gap_analysis_coverage(benchmark, db):
    gen = AttackGenerator(db)
    gen.generate()
    results = asyncio.run(run_tournament(
        [RuleBasedDetector(), BehavioralBaselineDetector()],
        [Scenario.from_dict_row(s) for s in db.get_scenarios()],
    ))
    for r in results:
        db.insert_tournament_result(r.to_dict())

    analyzer = GapAnalyzer(db)

    def run():
        return analyzer.analyze_coverage()

    result = benchmark(run)
    # Should produce results even if list is empty
    assert isinstance(result, list)


def test_benchmark_self_prompt_generation(benchmark, db):
    promoter = SelfPromoter(db=db)

    def run():
        return promoter.generate("mutation_escaped", {
            "scenario_name": "test",
            "mutation_strategy": "identity_swap",
            "failure_mode": "test gap",
        })

    record, parsed = benchmark(run)
    assert record.trigger_type == "mutation_escaped"


def test_benchmark_bootstrap_ci(benchmark):
    from cybersentinel_evolver.models import bootstrap_confidence_interval

    def run():
        return bootstrap_confidence_interval(wins=9000, total=10000)

    low, high = benchmark(run)
    assert high - low < 0.05


def test_benchmark_full_evolution_week(benchmark, db):
    """Benchmark one full evolution week: generate → tournament → mutate → re-tournament."""
    scenarios_list = []

    def setup():
        scenarios_list.clear()
        gen = AttackGenerator(db)
        gen.generate()
        scenarios_list.extend([Scenario.from_dict_row(s) for s in db.get_scenarios()])

    setup()

    def run():
        mut = MutationEngine(db)
        results = asyncio.run(run_tournament(
            [RuleBasedDetector(), BehavioralBaselineDetector()],
            scenarios_list,
        ))
        # Mutate survivors if perfectly caught
        for s in scenarios_list:
            if any(r.win_rate >= 1.0 for r in results):
                mut.mutate(s, "diurnal_pacing", n=2)
        return asyncio.run(run_tournament(
            [RuleBasedDetector(), BehavioralBaselineDetector()],
            scenarios_list,
        ))

    result = benchmark(run)
    assert len(result) == 2
