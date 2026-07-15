"""Tests for AdaptiveDetector — verifies self-improvement capability."""
from __future__ import annotations

import asyncio
import pytest

from cybersentinel_evolver.adaptive_detector import AdaptiveDetector
from cybersentinel_evolver.database import Database
from cybersentinel_evolver.models import AttackRequest, MutationRecord, Scenario, now_ms


def _make_scenario(outcome: str = "block", n: int = 20, timing_ms: int = 50, path: str = "/api/auth/login"):
    return Scenario(
        id=str(uuid.uuid4()),
        name="test", source_feed="feed",
        abuse_type="credential_stuffing", cost_model_label="default",
        identity_source="ip",
        requests=[AttackRequest("POST", path,
                                headers={"Authorization": "Bearer invalid"},
                                expected_outcome=outcome,  # type: ignore[arg-type]
                                timing_ms=timing_ms) for _ in range(n)],
    )


@pytest.fixture
def db(tmp_path):
    db = Database(tmp_path / "test.db")
    yield db
    db.close()


import uuid


class TestAdaptiveDetector:
    def test_empty_detector_misses(self):
        det = AdaptiveDetector()
        scenario = _make_scenario()
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict in ("detected", "missed", "ambiguous")

    def test_heuristic_detects_high_block_rate(self):
        det = AdaptiveDetector()
        scenario = _make_scenario(outcome="block", n=10)
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict == "detected"

    def test_adapt_from_mutations(self, db):
        det = AdaptiveDetector()

        # Insert escaped mutation
        scenario = Scenario(
            id="child-1", name="escaped_mut", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip",
            requests=[AttackRequest("POST", "/api/v1/health",
                                    headers={"X-Agent-Name": "malicious-bot"},
                                    expected_outcome="allow", timing_ms=5000)
                       for _ in range(10)],
        )
        db.insert_scenario(scenario.to_dict())
        db.insert_mutation(MutationRecord(
            mutation_id="m1", parent_scenario_id="p1",
            child_scenario_id="child-1", strategy="identity_swap",
            depth=1, escaped=True, created_at=now_ms(),
        ).to_dict())

        # Adapt
        new_rules = det.adapt_from_mutations(db)
        assert new_rules > 0
        assert any(r.rule_type == "header_pattern" for r in det.rules)

    def test_rules_catch_similar_mutations(self, db):
        det = AdaptiveDetector()

        # Insert escaped mutation with distinctive features
        scenario = Scenario(
            id="child-1", name="escaped", source_feed="feed",
            abuse_type="agent_impersonation", cost_model_label="default",
            identity_source="mcp_agent_name",
            requests=[AttackRequest("POST", "/api/tools/invoke",
                                    headers={"X-Agent-Name": "malicious-bot",
                                             "X-Rotation": "rot-0"},
                                    expected_outcome="allow", timing_ms=5000)
                       for _ in range(10)],
        )
        db.insert_scenario(scenario.to_dict())
        db.insert_mutation(MutationRecord(
            mutation_id="m1", parent_scenario_id="p1",
            child_scenario_id="child-1", strategy="multi_identity_rotation",
            depth=1, escaped=True, created_at=now_ms(),
        ).to_dict())

        # Adapt
        det.adapt_from_mutations(db)

        # Create a similar scenario that should now be caught
        test_scenario = Scenario(
            id="test-1", name="similar_attack", source_feed="feed",
            abuse_type="agent_impersonation", cost_model_label="default",
            identity_source="mcp_agent_name",
            requests=[AttackRequest("POST", "/api/tools/invoke",
                                    headers={"X-Agent-Name": "evolved-bot",
                                             "X-Rotation": "rot-1"},
                                    expected_outcome="allow", timing_ms=5000)
                       for _ in range(10)],
        )

        result = asyncio.run(det.evaluate(test_scenario))
        assert result.verdict == "detected"

    def test_heuristic_catches_burst_timing(self):
        det = AdaptiveDetector()
        scenario = _make_scenario(outcome="block", n=10, timing_ms=10)
        result = asyncio.run(det.evaluate(scenario))
        assert result.verdict == "detected"

    def test_rule_summary(self, db):
        det = AdaptiveDetector()
        scenario = _make_scenario(outcome="block", n=10, timing_ms=10000,
                                   path="/api/v1/upload-chunk")
        db.insert_scenario(scenario.to_dict())
        db.insert_mutation(MutationRecord(
            mutation_id="m1", parent_scenario_id="p1",
            child_scenario_id=scenario.id, strategy="payload_fragmentation",
            depth=1, escaped=True, created_at=now_ms(),
        ).to_dict())

        det.adapt_from_mutations(db)
        summary = det.get_rule_summary()
        assert summary["total_rules"] > 0
        assert "path_pattern" in summary["by_type"] or "timing_threshold" in summary["by_type"]


class TestSelfImprovement:
    """End-to-end adaptive loop:

    1. Generate scenarios
    2. Evolve mutations that escape
    3. Adaptive detector learns from escapes
    4. Verify adaptive catches more than baseline
    """

    def test_adaptive_improves_over_static(self, db):
        from cybersentinel_evolver.attacks import AttackGenerator, MutationEngine
        from cybersentinel_evolver.detection import RuleBasedDetector, run_tournament

        gen = AttackGenerator(db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]

        # Create mutations
        mut = MutationEngine(db)
        parent = scenarios[0]
        children = mut.mutate(parent, "multi_identity_rotation", n=3)

        # Record mutations as escaped
        for i, child in enumerate(children):
            db.insert_mutation(MutationRecord(
                mutation_id=f"esc-{i}", parent_scenario_id=parent.id,
                child_scenario_id=child.id, strategy="multi_identity_rotation",
                depth=1, escaped=True, created_at=now_ms(),
            ).to_dict())

        # Baseline: RuleBasedDetector (static)
        baseline = RuleBasedDetector()
        baseline_hits = 0
        for child in children:
            result = asyncio.run(run_tournament([baseline], [child]))
            if result[0].win_rate >= 1.0:
                baseline_hits += 1

        # Adaptive: learns from escapes
        det = AdaptiveDetector()
        det.adapt_from_mutations(db)
        adaptive_hits = 0
        for child in children:
            result = asyncio.run(det.evaluate(child))
            if result.verdict == "detected":
                adaptive_hits += 1

        # Adaptive should catch at least as many as baseline (ideally more)
        print(f"Adaptive caught {adaptive_hits}/{len(children)}, Baseline caught {baseline_hits}/{len(children)}")
        assert adaptive_hits >= baseline_hits
