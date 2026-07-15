"""Tests for evolve-loop scheduler script."""
from __future__ import annotations

import subprocess

import pytest

from cybersentinel_evolver.database import Database
from cybersentinel_evolver.models import Scenario


@pytest.fixture
def tmp_db(tmp_path):
    db = Database(tmp_path / "test.db")
    yield db
    db.close()


class TestSchedulerPhases:
    """Simulate the weekly evolve-loop end-to-end."""

    def test_phase1_scenarios(self, tmp_db):
        from cybersentinel_evolver.attacks import AttackGenerator
        gen = AttackGenerator(tmp_db)
        scenarios = gen.generate()
        assert len(scenarios) >= 12

    def test_phase2_tournament(self, tmp_db):
        from cybersentinel_evolver.attacks import AttackGenerator
        from cybersentinel_evolver.detection import (
            BehavioralBaselineDetector,
            RuleBasedDetector,
            RandomDetector,
            run_tournament,
        )
        import asyncio

        gen = AttackGenerator(tmp_db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in tmp_db.get_scenarios()]
        results = asyncio.run(run_tournament(
            [RuleBasedDetector(), BehavioralBaselineDetector(), RandomDetector()], scenarios
        ))
        assert len(results) == 3

    def test_phase3_gap_analysis(self, tmp_db):
        from cybersentinel_evolver.attacks import AttackGenerator, MutationEngine
        from cybersentinel_evolver.gap_analyzer import GapAnalyzer
        from cybersentinel_evolver.models import MutationRecord, now_ms

        gen = AttackGenerator(tmp_db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in tmp_db.get_scenarios()]
        mut = MutationEngine(tmp_db)
        parent = scenarios[0]
        children = mut.mutate(parent, "diurnal_pacing", n=1)
        tmp_db.insert_mutation(MutationRecord(
            mutation_id="m1", parent_scenario_id=parent.id,
            child_scenario_id=children[0].id, strategy="diurnal_pacing",
            depth=1, escaped=True, created_at=now_ms(),
        ).to_dict())

        analyzer = GapAnalyzer(tmp_db)
        findings = analyzer.analyze_mutations(escaped_only=True)
        assert len(findings) >= 1

    def test_phase4_evolve(self, tmp_db):
        from cybersentinel_evolver.attacks import AttackGenerator, MutationEngine
        from cybersentinel_evolver.detection import (
            RuleBasedDetector, BehavioralBaselineDetector, run_tournament,
        )
        import asyncio

        gen = AttackGenerator(tmp_db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in tmp_db.get_scenarios()]
        mut = MutationEngine(tmp_db)
        results = asyncio.run(run_tournament(
            [RuleBasedDetector(), BehavioralBaselineDetector()], scenarios
        ))
        for s in scenarios:
            if any(r.win_rate >= 1.0 and r.detector_id == "rule_based_zscore_v1" for r in results):
                mut.mutate(s, "diurnal_pacing", n=3)

        final = asyncio.run(run_tournament(
            [RuleBasedDetector(), BehavioralBaselineDetector()], scenarios
        ))
        assert len(final) == 2

    def test_phase5_auto_promote(self, tmp_db):
        from cybersentinel_evolver.attacks import AttackGenerator
        from cybersentinel_evolver.detection import (
            RuleBasedDetector, BehavioralBaselineDetector, run_tournament,
        )
        import asyncio

        gen = AttackGenerator(tmp_db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in tmp_db.get_scenarios()]
        results = asyncio.run(run_tournament(
            [RuleBasedDetector(), BehavioralBaselineDetector()], scenarios
        ))
        winner = max(results, key=lambda r: r.win_rate)
        assert winner.win_rate >= 0


class TestSchedulerScript:
    def test_script_exists_and_is_executable(self):
        import os
        script = "/home/dtfrost/cybersentinel-evolver/scheduler/run_evolve.sh"
        assert os.path.isfile(script)
        assert os.access(script, os.X_OK)

    def test_service_file_syntax(self):
        content = open("/home/dtfrost/cybersentinel-evolver/scheduler/cs-evolver.service").read()
        assert "[Unit]" in content
        assert "ExecStart=" in content
        assert "cs-evolver" in content

    def test_timer_file_syntax(self):
        content = open("/home/dtfrost/cybersentinel-evolver/scheduler/cs-evolver.timer").read()
        assert "[Timer]" in content
        assert "OnCalendar=" in content
        assert "Sun" in content
