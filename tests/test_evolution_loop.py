"""End-to-end evolution loop tests.

Full pipeline: scenarios → tournament → gap detection → self-prompt → lineage.
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
from cybersentinel_evolver.gap_analyzer import GapAnalyzer
from cybersentinel_evolver.models import (
    AttackRequest,
    MutationRecord,
    Scenario,
    TournamentResult,
    now_ms,
)
from cybersentinel_evolver.self_promoter import SelfPromoter


@pytest.fixture
def db(tmp_path):
    db = Database(tmp_path / "test.db")
    yield db
    db.close()


@pytest.fixture
def populated_db(db):
    """DB with scenarios + tournament results + escaped mutations."""
    gen = AttackGenerator(db)
    gen.generate()

    scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
    detectors = [RuleBasedDetector(), BehavioralBaselineDetector()]
    results = asyncio.run(run_tournament(detectors, scenarios))
    for r in results:
        db.insert_tournament_result(r.to_dict())

    # Mutate the first scenario and record it as escaped
    mut = MutationEngine(db)
    first = scenarios[0]
    children = mut.mutate(first, "identity_swap", n=3)
    record = MutationRecord(
        mutation_id="mut-1",
        parent_scenario_id=first.id,
        child_scenario_id=children[0].id,
        strategy="identity_swap",
        depth=first.mutation_depth + 1,
        escaped=True,
        created_at=now_ms(),
    )
    db.insert_mutation(record.to_dict())

    return db


class TestEndToEndEvolutionLoop:
    """E-E-001: Full pipeline from scenario generation to self-prompt."""

    def test_phase1_generate_scenarios(self, db):
        """Phase 1: Generate scenarios and persist to DB."""
        gen = AttackGenerator(db)
        scenarios = gen.generate()
        assert len(scenarios) >= 12  # MIN_SCENARIOS
        rows = db.get_scenarios()
        assert len(rows) == len(scenarios)

    def test_phase2_tournament(self, db):
        """Phase 2: Run tournament and persist results."""
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]
        detectors = [RuleBasedDetector(), BehavioralBaselineDetector()]
        results = asyncio.run(run_tournament(detectors, scenarios))

        assert len(results) == 2
        for r in results:
            assert isinstance(r, TournamentResult)
            assert 0.0 <= r.win_rate <= 1.0
            assert r.scenario_count == len(scenarios)
            db.insert_tournament_result(r.to_dict())

        persisted = db.get_tournament_results()
        assert len(persisted) == 2

    def test_phase3_mutation(self, db):
        """Phase 3: Mutate scenario and verify lineage."""
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]

        mut = MutationEngine(db)
        parent = scenarios[0]
        children = mut.mutate(parent, "temporal_mutation", n=3)

        assert len(children) == 3
        for child in children:
            assert child.parent_id == parent.id
            assert child.mutation_depth == parent.mutation_depth + 1
            assert child.generation == parent.generation + 1

        # Verify DB round-trip
        all_scenarios = db.get_scenarios()
        assert len(all_scenarios) == len(scenarios) + 3

    def test_phase4_gap_detection(self, populated_db):
        """Phase 4: Gap analysis detects escaped mutations."""
        db = populated_db
        analyzer = GapAnalyzer(db)
        findings = analyzer.analyze_mutations(escaped_only=True)

        assert len(findings) >= 1
        for f in findings:
            assert f.analysis_type == "coverage"
            assert f.severity > 0.0

        # Verify persisted
        persisted_gaps = db.get_gap_analysis()
        assert len(persisted_gaps) >= 1

    def test_phase5_self_prompt(self, populated_db):
        """Phase 5: Self-promoter generates prompt from gap context."""
        db = populated_db
        promoter = SelfPromoter(db=db)
        record, parsed = promoter.generate(
            "mutation_escaped",
            {
                "scenario_name": "cred_stuff_v1",
                "mutation_strategy": "identity_swap",
                "failure_mode": "detector tracks by IP only",
            },
        )

        assert record.trigger_type == "mutation_escaped"
        assert "cred_stuff_v1" in record.prompt_text
        assert parsed == []  # No LLM in template-only mode

        # Verify persistence
        prompts = db.get_prompts()
        assert len(prompts) == 1
        assert prompts[0]["trigger_type"] == "mutation_escaped"

    def test_phase5_self_prompt_with_mock_llm(self, populated_db):
        """Phase 5b: Self-promoter with mock LLM extracts scenarios."""
        db = populated_db

        class MockLLM:
            def complete(self, prompt, max_tokens=4096):
                return (
                    '[{"name": "llm_scenario_1", "abuse_type": "prompt_injection",'
                    ' "identity_source": "jwt_claim", "requests": []}]'
                )

        promoter = SelfPromoter(db=db, llm_client=MockLLM())
        record, parsed = promoter.generate("coverage_cliff", {"delta": 15.0, "abuse_types": ["x"]})

        assert record.scenarios_extracted == 1
        assert len(parsed) == 1
        assert parsed[0]["name"] == "llm_scenario_1"

        prompts = db.get_prompts()
        assert len(prompts) == 1
        assert prompts[0]["scenarios_extracted"] == 1

    def test_full_pipeline_in_one_flow(self, db):
        """E-E-002: Complete flow in a single test method."""
        # Generate
        gen = AttackGenerator(db)
        scenarios = gen.generate()
        assert len(scenarios) >= 12

        # Tournament
        detectors = [RuleBasedDetector(), BehavioralBaselineDetector()]
        results = asyncio.run(run_tournament(detectors, scenarios))
        for r in results:
            db.insert_tournament_result(r.to_dict())
        assert len(db.get_tournament_results()) == 2

        # Mutate + record escaped
        mut = MutationEngine(db)
        parent = scenarios[0]
        children = mut.mutate(parent, "protocol_mutation", n=2)
        db.insert_mutation(
            MutationRecord(
                mutation_id="m1",
                parent_scenario_id=parent.id,
                child_scenario_id=children[0].id,
                strategy="protocol_mutation",
                depth=1,
                escaped=True,
                created_at=now_ms(),
            ).to_dict()
        )

        # Gap detection
        analyzer = GapAnalyzer(db)
        findings = analyzer.analyze_mutations(escaped_only=True)
        assert len(findings) >= 1

        # Self-prompt
        promoter = SelfPromoter(db=db)
        record, _ = promoter.generate(
            "mutation_escaped",
            {"scenario_name": parent.name, "mutation_strategy": "protocol_mutation", "failure_mode": "test"},
        )
        assert record.id is not None

        # Verify DB state
        assert len(db.get_scenarios()) >= 14  # 12 + 2 mutations
        assert len(db.get_tournament_results()) == 2
        assert len(db.get_mutations()) == 1
        assert len(db.get_gap_analysis()) >= 1
        assert len(db.get_prompts()) == 1


class TestLineageVerification:
    """E-E-003: Verify mutation lineage chain is preserved."""

    def test_child_scenario_references_parent(self, db):
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]

        mut = MutationEngine(db)
        parent = scenarios[0]
        children = mut.mutate(parent, "identity_swap", n=1)
        child = children[0]

        # Verify in DB
        child_row = db.get_scenario(child.id)
        assert child_row is not None
        assert child_row["parent_id"] == parent.id
        assert child_row["generation"] == 1
        assert child_row["mutation_depth"] == 1

    def test_mutation_record_links_parent_child(self, db):
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]

        mut = MutationEngine(db)
        parent = scenarios[0]
        children = mut.mutate(parent, "identity_swap", n=1)

        record = MutationRecord(
            mutation_id="link-test",
            parent_scenario_id=parent.id,
            child_scenario_id=children[0].id,
            strategy="identity_swap",
            depth=1,
            escaped=False,
            created_at=now_ms(),
        )
        db.insert_mutation(record.to_dict())

        mutations = db.get_mutations()
        assert len(mutations) == 1
        assert mutations[0]["parent_scenario_id"] == parent.id
        assert mutations[0]["child_scenario_id"] == children[0].id


class TestGapAnalysisNoData:
    """E-E-004: Gap analysis returns empty when no data present."""

    def test_empty_db_no_gaps(self, db):
        analyzer = GapAnalyzer(db)
        assert analyzer.analyze_coverage() == []
        assert analyzer.analyze_mutations() == []

    def test_no_escaped_mutations(self, db):
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]

        mut = MutationEngine(db)
        parent = scenarios[0]
        children = mut.mutate(parent, "identity_swap", n=1)

        # Record as NOT escaped
        db.insert_mutation(
            MutationRecord(
                mutation_id="not-escaped",
                parent_scenario_id=parent.id,
                child_scenario_id=children[0].id,
                strategy="identity_swap",
                depth=1,
                escaped=False,
                created_at=now_ms(),
            ).to_dict()
        )

        analyzer = GapAnalyzer(db)
        findings = analyzer.analyze_mutations(escaped_only=True)
        assert findings == []


class TestEvolutionLoopWithMockLLM:
    """E-E-005: Full loop with mock LLM returning valid scenarios."""

    def test_llm_extracts_scenarios_that_can_be_persisted(self, db):
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = [Scenario.from_dict_row(s) for s in db.get_scenarios()]

        # Tournament
        detectors = [RuleBasedDetector(), BehavioralBaselineDetector()]
        results = asyncio.run(run_tournament(detectors, scenarios))
        for r in results:
            db.insert_tournament_result(r.to_dict())

        # Mutate
        mut = MutationEngine(db)
        parent = scenarios[0]
        children = mut.mutate(parent, "intent_preserving", n=2)
        db.insert_mutation(
            MutationRecord(
                mutation_id="llm-mut",
                parent_scenario_id=parent.id,
                child_scenario_id=children[0].id,
                strategy="intent_preserving",
                depth=1,
                escaped=True,
                created_at=now_ms(),
            ).to_dict()
        )

        # Gap
        analyzer = GapAnalyzer(db)
        findings = analyzer.analyze_mutations(escaped_only=True)

        # Self-prompt with mock LLM
        class RichLLM:
            def complete(self, prompt, max_tokens=4096):
                return (
                    '[{"name": "extracted_1", "abuse_type": "billing_abuse",'
                    ' "identity_source": "oauth_client_id",'
                    ' "requests": [{"method": "POST", "path": "/api/charge", "headers": {}, "expected_outcome": "block", "timing_ms": 100}]},'
                    ' {"name": "extracted_2", "abuse_type": "shadow_agent_discovery",'
                    ' "identity_source": "user_agent",'
                    ' "requests": [{"method": "GET", "path": "/api/schema", "headers": {}, "expected_outcome": "block", "timing_ms": 500}]}]'
                )

        promoter = SelfPromoter(db=db, llm_client=RichLLM())
        record, parsed = promoter.generate(
            "mutation_escaped",
            {
                "scenario_name": parent.name,
                "mutation_strategy": "intent_preserving",
                "failure_mode": "detector only checks path",
            },
        )

        assert record.scenarios_extracted == 2
        assert len(parsed) == 2
        assert parsed[0]["name"] == "extracted_1"
        assert parsed[1]["abuse_type"] == "shadow_agent_discovery"

        # Verify persisted
        prompts = db.get_prompts()
        assert len(prompts) == 1
        assert prompts[0]["scenarios_extracted"] == 2
        assert prompts[0]["accepted"] == 1  # True stored as 1
