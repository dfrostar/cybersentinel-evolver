"""Tests for GapAnalyzer — coverage-boosting suite."""
from __future__ import annotations

import time
import uuid

import pytest

from cybersentinel_evolver.database import Database
from cybersentinel_evolver.gap_analyzer import GapAnalyzer


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "test.db")
    yield database
    database.close()


def insert_tournament(db, *, win_rate, ran_at, cost_model_label="default", detector_id="test"):
    """Helper to insert a tournament result."""
    db._conn.execute(
        """INSERT INTO tournament_results
           (run_id, detector_id, scenario_count, detected_count,
            false_positive_count, cost_blocked, cost_missed,
            cost_model_label, win_rate, confidence_low, confidence_high, ran_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), detector_id, 10, int(win_rate * 10), 0,
         100.0, 50.0, cost_model_label, win_rate, win_rate - 0.05,
         win_rate + 0.05, ran_at),
    )


def insert_mutation(db, *, strategy="identity_swap", escaped=True):
    """Helper to insert a mutation record."""
    db._conn.execute(
        """INSERT INTO mutation_records
           (mutation_id, parent_scenario_id, child_scenario_id,
            strategy, depth, escaped, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4()),
         strategy, 1, 1 if escaped else 0, int(time.time() * 1000)),
    )


class TestAnalyzeCoverage:
    def test_no_results_returns_empty(self, db):
        analyzer = GapAnalyzer(db)
        assert analyzer.analyze_coverage() == []

    def test_single_result_returns_empty(self, db):
        insert_tournament(db, win_rate=0.5, ran_at=int(time.time() * 1000))
        analyzer = GapAnalyzer(db)
        assert analyzer.analyze_coverage() == []

    def test_all_recent_no_older(self, db):
        now = int(time.time() * 1000)
        insert_tournament(db, win_rate=0.5, ran_at=now)
        insert_tournament(db, win_rate=0.4, ran_at=now - 1000)
        analyzer = GapAnalyzer(db)
        # All in recent window, no older → empty
        assert analyzer.analyze_coverage() == []

    def test_coverage_cliff_detected(self, db):
        now = int(time.time() * 1000)
        # Recent tournaments with lower win rate
        for _ in range(3):
            insert_tournament(db, win_rate=0.3, ran_at=now - 1000)
        # Older tournaments with higher win rate
        for _ in range(3):
            insert_tournament(db, win_rate=0.8, ran_at=now - 86400000 * 7)  # 7 days ago

        analyzer = GapAnalyzer(db, win_rate_threshold=0.10)
        findings = analyzer.analyze_coverage()

        assert len(findings) >= 1
        assert findings[0].analysis_type == "coverage"
        assert findings[0].severity > 0
        assert "coverage_cliff" in findings[0].recommended_prompt

    def test_persists_findings_to_db(self, db):
        now = int(time.time() * 1000)
        for _ in range(3):
            insert_tournament(db, win_rate=0.2, ran_at=now - 1000)
        for _ in range(3):
            insert_tournament(db, win_rate=0.9, ran_at=now - 86400000 * 7)

        analyzer = GapAnalyzer(db)
        analyzer.analyze_coverage()

        stored = db.get_gap_analysis()
        assert len(stored) >= 1


class TestAnalyzeMutations:
    def test_no_mutations_empty(self, db):
        analyzer = GapAnalyzer(db)
        assert analyzer.analyze_mutations() == []

    def test_escaped_mutations_only(self, db):
        insert_mutation(db, strategy="identity_swap", escaped=True)
        insert_mutation(db, strategy="temporal_mutation", escaped=True)

        analyzer = GapAnalyzer(db)
        findings = analyzer.analyze_mutations(escaped_only=True)

        assert len(findings) == 2
        assert findings[0].analysis_type == "coverage"
        assert findings[0].severity == 0.7

    def test_all_mutations_includes_non_escaped(self, db):
        insert_mutation(db, strategy="identity_swap", escaped=True)
        insert_mutation(db, strategy="protocol_mutation", escaped=False)

        analyzer = GapAnalyzer(db)
        findings = analyzer.analyze_mutations(escaped_only=False)

        assert len(findings) == 2

    def test_persists_mutations(self, db):
        insert_mutation(db, strategy="identity_swap", escaped=True)

        analyzer = GapAnalyzer(db)
        analyzer.analyze_mutations()

        stored = db.get_gap_analysis()
        assert len(stored) >= 1


class TestAnalyzeCostAccuracy:
    def test_returns_empty(self, db):
        analyzer = GapAnalyzer(db)
        assert analyzer.analyze_cost_accuracy() == []
