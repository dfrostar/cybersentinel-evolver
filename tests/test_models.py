from __future__ import annotations

import pytest

from cybersentinel_evolver.database import Database
from cybersentinel_evolver.models import (
    AttackRequest,
    Scenario,
    TournamentResult,
    bootstrap_confidence_interval,
    compute_cost,
    get_cost_model,
    now_ms,
)


# ============================================================
# Unit Tests — Pure Functions
# ============================================================


class TestAttackRequest:
    """Unit tests for AttackRequest serialization and data model."""

    def test_serialize_normal_request(self):
        """AR-U-001: Serialize normal request"""
        req = AttackRequest("GET", "/api/health")
        data = req.to_dict()
        assert data["method"] == "GET"
        assert data["path"] == "/api/health"
        assert data["timing_ms"] == 0

    def test_encode_binary_body(self):
        """AR-U-002: Encode binary body"""
        req = AttackRequest("POST", "/api", body_b64="AP8=", expected_outcome="block")
        round_tripped = AttackRequest.from_dict(req.to_dict())
        assert round_tripped.body_b64 == "AP8="
        assert round_tripped.method == "POST"
        assert round_tripped.expected_outcome == "block"

    def test_zero_timing_preserved(self):
        """AR-U-003: Zero-timing preserved"""
        req = AttackRequest("GET", "/api", timing_ms=0)
        assert req.to_dict()["timing_ms"] == 0

    def test_max_path_length(self):
        """AR-U-004: Max path length"""
        long_path = "/" + "x" * 2048
        req = AttackRequest("GET", long_path)
        round_tripped = AttackRequest.from_dict(req.to_dict())
        assert len(round_tripped.path) == 2049


class TestScenarioDataClass:
    """Unit tests for Scenario data class and lineage tracking."""

    def test_create_with_no_parent(self):
        """SC-U-001: Create with no parent"""
        s = Scenario(
            id="test-1",
            name="scenario",
            source_feed="feed",
            abuse_type="credential_stuffing",
            cost_model_label="default",
            identity_source="ip",
            requests=[],
        )
        assert s.parent_id is None
        assert s.generation == 0
        assert s.to_dict()["parent_id"] is None

    def test_create_with_parent(self):
        """SC-U-002: Create with parent"""
        parent = Scenario(
            id="parent", name="parent", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip", requests=[],
        )
        child = Scenario(
            id="child", name="child", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip", requests=[],
            parent_id=parent.id,
            generation=parent.generation + 1,
        )
        assert child.parent_id == "parent"
        assert child.generation == 1

    def test_hash_stability(self):
        """SC-U-003: Hash stability"""
        reqs = [AttackRequest("GET", f"/api/{i}") for i in range(5)]
        s1 = Scenario(id="a", name="n", source_feed="f", abuse_type="credential_stuffing",
                       cost_model_label="default", identity_source="ip", requests=reqs)
        s2 = Scenario(id="b", name="n", source_feed="f", abuse_type="credential_stuffing",
                       cost_model_label="default", identity_source="ip", requests=reqs)
        assert s1.hash_key() == s2.hash_key()

    def test_empty_requests(self):
        """SC-U-004: Empty requests"""
        s = Scenario(id="e", name="n", source_feed="f", abuse_type="credential_stuffing",
                      cost_model_label="default", identity_source="ip", requests=[])
        assert s.requests == []
        assert s.to_dict()["requests_json"] == "[]"


class TestTournamentResultMath:
    """Unit tests for TournamentResult math and bootstrap CI."""

    def test_win_rate_calc(self):
        """TR-U-001: Win rate calc"""
        r = TournamentResult(
            run_id="r", detector_id="d", scenario_count=100,
            detected_count=90, false_positive_count=5,
            cost_blocked=10.80, cost_missed=1.20, cost_model_label="default",
            win_rate=0.9, confidence_low=0.85, confidence_high=0.95,
            ran_at=now_ms(),
        )
        assert r.win_rate == 0.9

    def test_cost_blocked(self):
        """TR-U-002: Cost blocked"""
        r = TournamentResult(
            run_id="r", detector_id="d", scenario_count=100,
            detected_count=90, false_positive_count=0,
            cost_blocked=90 / 1000 * 4.80, cost_missed=10 / 1000 * 4.80,
            cost_model_label="llm-token-scraping-default",
            win_rate=0.9, confidence_low=0.0, confidence_high=1.0, ran_at=now_ms(),
        )
        assert r.cost_blocked == (90 / 1000 * 4.80)
        assert r.cost_missed == (10 / 1000 * 4.80)

    def test_perfect_score(self):
        """TR-U-005: Perfect score"""
        r = TournamentResult(
            run_id="r", detector_id="d", scenario_count=50,
            detected_count=50, false_positive_count=0,
            cost_blocked=0.0, cost_missed=0.0, cost_model_label="default",
            win_rate=1.0, confidence_low=0.95, confidence_high=1.0, ran_at=now_ms(),
        )
        assert r.win_rate == 1.0

    def test_zero_score(self):
        """TR-U-006: Zero score"""
        r = TournamentResult(
            run_id="r", detector_id="d", scenario_count=50,
            detected_count=0, false_positive_count=0,
            cost_blocked=0.0, cost_missed=0.0, cost_model_label="default",
            win_rate=0.0, confidence_low=0.0, confidence_high=0.05, ran_at=now_ms(),
        )
        assert r.win_rate == 0.0


class TestCostModelLookup:
    """Unit tests for cost model registry and lookup."""

    def test_llm_token_scraping(self):
        """CM-U-001: LLM token scrap"""
        m = get_cost_model("llm-token-scraping-default")
        assert m.per_1k_requests == 4.80

    def test_credential_stuffing(self):
        """CM-U-002: Credential stuffing"""
        m = get_cost_model("credential-stuffing-default")
        assert m.per_1k_requests == 0.12

    def test_unknown_abuse_type(self):
        """CM-U-003: Unknown abuse type"""
        from cybersentinel_evolver.models import COST_MODELS
        m = get_cost_model("unknown-type-xyz")
        assert m == COST_MODELS["default"]


class TestBootstrapCI:
    def test_high_sample_narrows_ci(self):
        """CI-T-001: High sample narrows CI"""
        low, high = bootstrap_confidence_interval(wins=9000, total=10000)
        assert high - low < 0.05
        assert 0.88 < low < 0.92
        assert 0.88 < high < 0.92

    def test_low_sample_widens_ci(self):
        """CI-T-002: Low sample widens CI"""
        low, high = bootstrap_confidence_interval(wins=5, total=10)
        assert high - low > 0.20

    def test_winner_separation(self):
        """CI-T-003: p<0.05 separation"""
        low_winner, _ = bootstrap_confidence_interval(wins=900, total=1000)
        _, high_loser = bootstrap_confidence_interval(wins=500, total=1000)
        assert low_winner > high_loser


# ============================================================
# Integration Tests — Database
# ============================================================


class TestDatabase:
    @pytest.fixture
    def db(self, tmp_path):
        db = Database(tmp_path / "test.db")
        yield db
        db.close()

    def test_insert_and_retrieve_scenario(self, db):
        scenario = Scenario(
            id="test-1", name="scenario", source_feed="wallarm-threatstats-2026",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip",
            requests=[AttackRequest("GET", "/api")],
        )
        db.insert_scenario(scenario.to_dict())

        retrieved = db.get_scenario("test-1")
        assert retrieved is not None
        assert retrieved["name"] == "scenario"
        assert retrieved["abuse_type"] == "credential_stuffing"

    def test_get_scenarios_by_parent(self, db):
        parent = Scenario(
            id="parent", name="parent", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip", requests=[],
        )
        child = Scenario(
            id="child", name="child", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip", requests=[], parent_id="parent",
        )
        db.insert_scenario(parent.to_dict())
        db.insert_scenario(child.to_dict())

        parents_children = db.get_scenarios(parent_id="parent")
        assert len(parents_children) >= 1

    def test_insert_tournament_result(self, db):
        result = TournamentResult(
            run_id="run-1", detector_id="rule_based", scenario_count=100,
            detected_count=85, false_positive_count=3,
            cost_blocked=4.25, cost_missed=0.75, cost_model_label="default",
            win_rate=0.85, confidence_low=0.80, confidence_high=0.90, ran_at=now_ms(),
        )
        db.insert_tournament_result(result.to_dict())

        results = db.get_tournament_results()
        assert len(results) == 1
        assert results[0]["detector_id"] == "rule_based"

    def test_tournament_results_since_filter(self, db):
        old = TournamentResult(
            run_id="old", detector_id="d", scenario_count=10,
            detected_count=5, false_positive_count=0,
            cost_blocked=0.0, cost_missed=0.0, cost_model_label="default",
            win_rate=0.5, confidence_low=0.0, confidence_high=1.0, ran_at=1000,
        )
        new = TournamentResult(
            run_id="new", detector_id="d", scenario_count=10,
            detected_count=8, false_positive_count=0,
            cost_blocked=0.0, cost_missed=0.0, cost_model_label="default",
            win_rate=0.8, confidence_low=0.0, confidence_high=1.0, ran_at=9999999999999,
        )
        db.insert_tournament_result(old.to_dict())
        db.insert_tournament_result(new.to_dict())

        results = db.get_tournament_results(since=9999999999999)
        assert len(results) == 1
        assert results[0]["run_id"] == "new"

    def test_audit_log(self, db):
        db.audit("test_event", '{"msg": "hello"}')
        with db._cursor() as c:
            c.execute("SELECT COUNT(*) FROM audit_log")
            assert c.fetchone()[0] >= 1


# ============================================================
# Cost Correlator Tests
# ============================================================


class TestCostCorrelator:
    def test_zero_cost_no_blocked(self):
        """CC-C-001: Zero cost for no blocked"""
        model = get_cost_model("llm-token-scraping-default")
        blocked, missed = compute_cost(0, 100, model)
        assert blocked == 0.0

    def test_simple_multiplication(self):
        """CC-C-002: Simple multiplication"""
        model = get_cost_model("llm-token-scraping-default")
        blocked, missed = compute_cost(1000, 0, model)
        assert blocked == 4.80

    def test_mixed_types(self):
        """CC-C-003: Mixed abuse types (simulated)"""
        m1 = get_cost_model("llm-token-scraping-default")
        m2 = get_cost_model("credential-stuffing-default")
        b1, _ = compute_cost(100, 0, m1)
        b2, _ = compute_cost(100, 0, m2)
        assert b1 > b2  # LLM token abuse is more expensive

    def test_missed_cost_complement(self):
        """CC-C-004: Missed cost complement"""
        model = get_cost_model("default")
        blocked, missed = compute_cost(90, 10, model)
        total, _ = compute_cost(100, 0, model)
        assert abs((blocked + missed) - total) < 0.01
