from __future__ import annotations

import pytest
from cybersentinel_evolver.database import Database


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "test.db"
    return Database(path)


def test_schema_v2_tables_exist(db):
    tables = {r[0] for r in db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    for required in {
        "scenarios", "tournament_results", "mutation_records", "audit_log",
        "prompts", "runs", "run_results", "gap_analysis", "cost_models",
        "schema_version",
    }:
        assert required in tables, f"missing table: {required}"


def test_schema_version_is_2(db):
    row = db._conn.execute("SELECT version FROM schema_version").fetchone()
    assert row[0] == 2


def test_insert_and_read_prompt(db):
    db.insert_prompt({
        "id": "p1",
        "trigger_type": "mutation_escaped",
        "prompt_text": "A mutation escaped...",
        "llm_response": "json here",
        "scenarios_extracted": 3,
        "accepted": True,
        "created_at": 1000,
    })
    prompts = db.get_prompts()
    assert len(prompts) == 1
    assert prompts[0]["id"] == "p1"
    assert prompts[0]["accepted"] == 1


def test_insert_prompt_accepted_none(db):
    db.insert_prompt({
        "id": "p2",
        "trigger_type": "coverage_cliff",
        "prompt_text": "cliff",
        "created_at": 1001,
    })
    prompts = db.get_prompts("coverage_cliff")
    assert len(prompts) == 1
    assert prompts[0]["accepted"] is None


def test_insert_and_read_run(db):
    # Insert scenario first to satisfy FK on run_results
    db.insert_scenario({
        "id": "s-1", "parent_id": None, "name": "test-scenario",
        "source_feed": "test", "abuse_type": "credential_stuffing",
        "cost_model_label": "default", "identity_source": "ip",
        "mutation_depth": 0, "generation": 0, "created_at": 1000,
        "requests_json": "[]",
    })
    db.insert_run({
        "id": "run-1",
        "run_type": "tournament",
        "status": "running",
        "config": "{}",
        "started_at": 1000,
    })
    db.update_run_status("run-1", "completed", 2000)
    db.insert_run_result({
        "id": "rr-1",
        "run_id": "run-1",
        "scenario_id": "s-1",
        "detector_id": "d-1",
        "verdict": "detected",
        "cost": 0.05,
    })
    results = db.get_run_results("run-1")
    assert len(results) == 1
    assert results[0]["verdict"] == "detected"


def test_insert_and_read_gap_analysis(db):
    db.insert_gap_analysis({
        "id": "g1",
        "analysis_type": "coverage",
        "findings": '{"delta": 0.15}',
        "recommended_prompts": '["coverage_cliff_x"]',
        "created_at": 5000,
    })
    gaps = db.get_gap_analysis("coverage")
    assert len(gaps) == 1


def test_insert_and_read_cost_model(db):
    db.insert_cost_model({
        "id": "cm-1",
        "label": "credential-stuffing-default",
        "per_request_base": 0.00012,
        "per_1k_requests": 0.12,
        "abuse_type": "credential_stuffing",
        "org_id": None,
        "source_notes": "test model",
        "created_at": 1000,
    })
    models = db.get_cost_models()
    assert len(models) == 1
    assert models[0]["label"] == "credential-stuffing-default"


def test_migration_from_v1_adds_tables(tmp_path):
    """Existing v1 DB should auto-migrate to v2."""
    path = tmp_path / "legacy.db"
    # Create a v1 schema manually
    import sqlite3
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (1);
        CREATE TABLE scenarios (
            id TEXT PRIMARY KEY, parent_id TEXT, name TEXT NOT NULL,
            source_feed TEXT NOT NULL, abuse_type TEXT NOT NULL,
            cost_model_label TEXT NOT NULL, identity_source TEXT NOT NULL,
            mutation_depth INTEGER NOT NULL DEFAULT 0,
            generation INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL, requests_json TEXT NOT NULL
        );
        CREATE TABLE tournament_results (
            run_id TEXT PRIMARY KEY, detector_id TEXT NOT NULL,
            scenario_count INTEGER NOT NULL, detected_count INTEGER NOT NULL,
            false_positive_count INTEGER NOT NULL, cost_blocked REAL NOT NULL,
            cost_missed REAL NOT NULL, cost_model_label TEXT NOT NULL,
            win_rate REAL NOT NULL, confidence_low REAL NOT NULL,
            confidence_high REAL NOT NULL, ran_at INTEGER NOT NULL
        );
        CREATE TABLE mutation_records (
            mutation_id TEXT PRIMARY KEY, parent_scenario_id TEXT NOT NULL,
            child_scenario_id TEXT NOT NULL, strategy TEXT NOT NULL,
            depth INTEGER NOT NULL, escaped INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
            payload TEXT NOT NULL, created_at INTEGER NOT NULL
        );
    """)
    conn.close()

    # Open with Database — triggers migration
    Database(path)
    conn = sqlite3.connect(str(path))
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    ver = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    conn.close()

    assert ver == 2
    assert "prompts" in tables
    assert "gap_analysis" in tables


def test_scenarios_source_feed_filter(db):
    db.insert_scenario({
        "id": "s1", "parent_id": None, "name": "a",
        "source_feed": "wallarm-threatstats-2026", "abuse_type": "credential_stuffing",
        "cost_model_label": "default", "identity_source": "ip",
        "mutation_depth": 0, "generation": 0, "created_at": 1000,
        "requests_json": "[]",
    })
    db.insert_scenario({
        "id": "s2", "parent_id": None, "name": "b",
        "source_feed": "self_prompt", "abuse_type": "llm_token_scraping",
        "cost_model_label": "default", "identity_source": "jwt_claim",
        "mutation_depth": 0, "generation": 0, "created_at": 1001,
        "requests_json": "[]",
    })
    wallarm = db.get_scenarios(source_feed="wallarm-threatstats-2026")
    assert len(wallarm) == 1
    assert wallarm[0]["id"] == "s1"
