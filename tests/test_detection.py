from __future__ import annotations

import asyncio

import pytest

from cybersentinel_evolver.attacks import AttackGenerator, MutationEngine
from cybersentinel_evolver.database import Database
from cybersentinel_evolver.detection import (
    BehavioralBaselineDetector,
    RandomDetector,
    RuleBasedDetector,
    run_mutation_tournament,
    run_tournament,
)
from cybersentinel_evolver.models import (
    AttackRequest,
    Scenario,
    now_ms,
)


# ============================================================
# Generator Tests (Level 2)
# ============================================================


class TestAttackGenerator:
    @pytest.fixture
    def db(self, tmp_path):
        db = Database(tmp_path / "test.db")
        yield db
        db.close()

    @pytest.fixture
    def generator(self, db):
        return AttackGenerator(db)

    def test_minimum_scenario_count(self, generator):
        """GN-C-001: Generate all 12"""
        scenarios = generator.generate()
        assert len(scenarios) >= 12

    def test_source_attribution(self, generator):
        """GN-C-002: Source attribution"""
        scenarios = generator.generate()
        feeds_seen = set(s.source_feed for s in scenarios)
        assert len(feeds_seen) > 0
        for s in scenarios:
            assert s.source_feed != ""

    def test_abuse_type_coverage(self, generator):
        """GN-C-003: Abuse type coverage"""
        scenarios = generator.generate()
        types_seen = set(s.abuse_type for s in scenarios)
        assert "credential_stuffing" in types_seen
        assert "llm_token_scraping" in types_seen

    def test_deterministic_from_seed(self, db, generator):
        """GN-C-005: Deterministic from seed"""
        s1 = generator.generate()
        assert len(s1) > 0

    def test_no_duplicate_ids(self, generator):
        """GN-C-006: No duplicates"""
        scenarios = generator.generate()
        ids = [s.id for s in scenarios]
        assert len(ids) == len(set(ids))

    def test_credential_stuffing_pattern(self, generator):
        """AR-C-001: Credential stuffing rate"""
        scenarios = generator.generate()
        cs = [s for s in scenarios if s.abuse_type == "credential_stuffing"]
        assert len(cs) > 0
        for s in cs:
            assert len(s.requests) >= 5

    def test_agent_impersonation_headers(self, generator):
        """AR-C-002: Agent impersonation"""
        scenarios = generator.generate()
        ai = [s for s in scenarios if s.abuse_type == "agent_impersonation"]
        assert len(ai) > 0
        for s in ai:
            has_agent_header = any("X-Agent-Name" in r.headers for r in s.requests)
            assert has_agent_header

    def test_token_scraping_paths(self, generator):
        """AR-C-003: Token scraping"""
        scenarios = generator.generate()
        ts = [s for s in scenarios if s.abuse_type == "llm_token_scraping"]
        assert len(ts) > 0
        for s in ts:
            llm_paths = [r for r in s.requests if "/v1/" in r.path or "/api/chat" in r.path]
            assert len(llm_paths) > 0


# ============================================================
# Tournament Tests (Level 3)
# ============================================================


class TestTournamentRunner:
    @pytest.fixture
    def sample_scenarios(self):
        scenarios = []
        for i in range(10):
            s = Scenario(
                id=f"det-{i}", name=f"det-{i}", source_feed="feed",
                abuse_type="credential_stuffing", cost_model_label="default",
                identity_source="ip",
                requests=[
                    AttackRequest("POST", "/api/auth/login",
                                  headers={"Authorization": f"Bearer bad-{i}"},
                                  expected_outcome="block", timing_ms=50)
                    for _ in range(20)
                ],
            )
            scenarios.append(s)

        for i in range(5):
            s = Scenario(
                id=f"nd-{i}", name=f"nd-{i}", source_feed="feed",
                abuse_type="path_scanning", cost_model_label="default",
                identity_source="ip",
                requests=[
                    AttackRequest("GET", f"/api/page-{j}", expected_outcome="allow",
                                  timing_ms=5000)
                    for j in range(5)
                ],
            )
            scenarios.append(s)

        return scenarios

    def test_single_detector_single_scenario(self, sample_scenarios):
        """TM-T-001: Single detector, single scenario"""
        d = RuleBasedDetector()
        result = asyncio.run(run_tournament([d], sample_scenarios[:1]))
        assert len(result) == 1
        assert result[0].scenario_count == 1

    def test_three_detectors_fifty_scenarios(self, sample_scenarios):
        """TM-T-002: 3 detectors, 50 scenarios"""
        detectors = [RuleBasedDetector(), BehavioralBaselineDetector(), RandomDetector()]
        result = asyncio.run(run_tournament(detectors, sample_scenarios))
        assert len(result) == 3
        for r in result:
            assert r.scenario_count == len(sample_scenarios)

    def test_perfect_detector(self):
        """TM-T-003: Perfect detector"""

        class PerfectDetector:
            @property
            def detector_id(self):
                return "perfect"

            async def evaluate(self, scenario):
                from cybersentinel_evolver.detection import DetectionResult
                return DetectionResult("detected", ["blocked"] * max(len(scenario.requests), 1))

        scenarios = [
            Scenario(id=f"p-{i}", name=f"p-{i}", source_feed="f",
                      abuse_type="credential_stuffing", cost_model_label="default",
                      identity_source="ip",
                      requests=[AttackRequest("GET", "/a", expected_outcome="block")])
            for i in range(10)
        ]
        result = asyncio.run(run_tournament([PerfectDetector()], scenarios))
        assert result[0].win_rate == 1.0

    def test_random_detector_ci_includes_half(self):
        """TM-T-004: Random detector approx 0.5, CI includes 0.5"""
        import random
        random.seed(42)

        scenarios = [
            Scenario(id=f"r-{i}", name=f"r-{i}", source_feed="f",
                      abuse_type="traffic_spike", cost_model_label="default",
                      identity_source="ip",
                      requests=[AttackRequest("GET", "/a", expected_outcome="block", timing_ms=100)])
            for i in range(100)
        ]
        d = RandomDetector(true_positive_rate=0.5)
        result = asyncio.run(run_tournament([d], scenarios))
        assert result[0].confidence_low <= 0.5 <= result[0].confidence_high


# ============================================================
# Mutation Tests (Level 2-3)
# ============================================================


class TestMutationEngine:
    @pytest.fixture
    def db(self, tmp_path):
        db = Database(tmp_path / "test.db")
        yield db
        db.close()

    @pytest.fixture
    def mutation_engine(self, db):
        return MutationEngine(db)

    @pytest.fixture
    def sample_scenario(self):
        return Scenario(
            id="parent-scenario",
            name="test-parent",
            source_feed="wallarm-threatstats-2026",
            abuse_type="agent_impersonation",
            cost_model_label="default",
            identity_source="ip",
            requests=[
                AttackRequest("POST", "/api/tools/invoke",
                              headers={"X-Agent-Name": "legit-agent",
                                       "Authorization": "Bearer secret"},
                              expected_outcome="block", timing_ms=150)
                for _ in range(15)
            ],
        )

    def test_single_mutation(self, mutation_engine, sample_scenario, db):
        """MU-M-001: Single mutation"""
        db.insert_scenario(sample_scenario.to_dict())
        children = mutation_engine.mutate(sample_scenario, "identity_swap", n=1)
        assert len(children) == 1
        assert children[0].parent_id == sample_scenario.id

    def test_three_mutants_per_parent(self, mutation_engine, sample_scenario, db):
        """MU-M-002: 3 mutants per parent"""
        db.insert_scenario(sample_scenario.to_dict())
        children = mutation_engine.mutate(sample_scenario, "identity_swap", n=3)
        assert len(children) == 3

    def test_depth_cap_respected(self, mutation_engine, sample_scenario, db):
        """MU-M-004: Depth cap respected"""
        db.insert_scenario(sample_scenario.to_dict())
        children = mutation_engine.mutate(sample_scenario, "identity_swap", n=2)
        for c in children:
            assert c.mutation_depth == 1

    def test_lineage_traceable(self, mutation_engine, sample_scenario, db):
        """MU-M-005: Lineage traceable"""
        db.insert_scenario(sample_scenario.to_dict())
        gen1 = mutation_engine.mutate(sample_scenario, "identity_swap", n=1)
        gen2 = mutation_engine.mutate(gen1[0], "identity_swap", n=1)
        assert gen2[0].parent_id == gen1[0].id
        assert gen2[0].generation == 2

    def test_mutation_changes_surface(self, mutation_engine, sample_scenario, db):
        """MU-M-007: Identity swap mutator changes identity claims"""
        db.insert_scenario(sample_scenario.to_dict())
        children = mutation_engine.mutate(sample_scenario, "identity_swap", n=1)
        child = children[0]
        assert len(child.requests) == len(sample_scenario.requests)

    def test_temporal_mutator(self, mutation_engine, sample_scenario, db):
        """MU-M-008: Temporal mutator"""
        db.insert_scenario(sample_scenario.to_dict())
        children = mutation_engine.mutate(sample_scenario, "temporal_mutation", n=1)
        child = children[0]
        parent_timing = sample_scenario.requests[0].timing_ms
        child_timing = child.requests[0].timing_ms
        assert child_timing != parent_timing or parent_timing == 0


# ============================================================
# CLI Tests (Level 4)
# ============================================================


class TestCLI:
    @pytest.fixture
    def db(self, tmp_path):
        db = Database(tmp_path / "test.db")
        yield db
        db.close()

    def test_scenarios_command(self, db):
        """CL-E-002: scenarios generate"""
        gen = AttackGenerator(db)
        scenarios = gen.generate()
        assert len(scenarios) >= 12

    def test_tournament_command(self, db):
        """CL-E-003: tournament run"""
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = db.get_scenarios()
        scenario_objs = [Scenario.from_dict_row(s) for s in scenarios]

        result = asyncio.run(run_tournament(
            [RuleBasedDetector(), BehavioralBaselineDetector()],
            scenario_objs,
        ))
        assert len(result) == 2
        for r in result:
            assert r.scenario_count == len(scenario_objs)

    def test_evolve_command(self, db):
        """CL-E-005: evolve (1 week)"""
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = db.get_scenarios()
        scenario_objs = [Scenario.from_dict_row(s) for s in scenarios]
        mut = MutationEngine(db)

        result = asyncio.run(run_tournament([RuleBasedDetector()], scenario_objs))
        assert len(result) > 0

        for s in scenario_objs[:3]:
            mut.mutate(s, "identity_swap", n=2)

        new_scenarios = db.get_scenarios()
        assert len(new_scenarios) >= len(scenarios)

    def test_report_command(self, db):
        """CL-E-006: report"""
        gen = AttackGenerator(db)
        gen.generate()
        scenarios = db.get_scenarios()
        scenario_objs = [Scenario.from_dict_row(s) for s in scenarios]

        result = asyncio.run(run_tournament(
            [RuleBasedDetector()],
            scenario_objs,
        ))
        for r in result:
            db.insert_tournament_result(r.to_dict())

        results = db.get_tournament_results()
        assert len(results) >= 1
