from __future__ import annotations

import json
import pytest
from click.testing import CliRunner

from cybersentinel_evolver.cli import cli
from cybersentinel_evolver.database import Database


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Redirect the default db to the tmp dir."""
    db_path = tmp_path / "test.db"

    def fake_db(self, db="~/cybersentinel-evolver/data.db"):
        self.db_obj = Database(db_path)

    return db_path


def test_self_prompt_dry_run(runner, tmp_db):
    """self-prompt --trigger mutation_escaped (template-only mode) should work without LLM."""
    result = runner.invoke(cli, [
        "--db", str(tmp_db), "self-prompt", "--trigger", "mutation_escaped",
        "--context", json.dumps({"scenario_name": "cred_v1", "mutation_strategy": "identity_swap", "failure_mode": "IP tracking"})
    ])
    assert result.exit_code == 0, result.output
    assert "Prompt generated" in result.output
    assert "cred_v1" in result.output


def test_self_prompt_coverage_cliff(runner, tmp_db):
    result = runner.invoke(cli, [
        "--db", str(tmp_db), "self-prompt", "--trigger", "coverage_cliff",
        "--context", json.dumps({"delta": 15.3, "abuse_types": ["credential_stuffing", "llm_token_scraping"]})
    ])
    assert result.exit_code == 0, result.output
    assert "Prompt generated" in result.output


def test_self_prompt_persists_even_without_llm(runner, tmp_db):
    """Even in template-only mode (--no-llm), the PromptRecord is persisted to DB."""
    result = runner.invoke(cli, [
        "--db", str(tmp_db), "self-prompt", "--trigger", "tournament_tie",
        "--context", "{}"
    ])
    assert result.exit_code == 0

    # Verify via prompts list
    result2 = runner.invoke(cli, ["--db", str(tmp_db), "prompts"])
    assert result2.exit_code == 0
    assert "tournament_tie" in result2.output


def test_gap_analysis_shows_findings(runner, tmp_db):
    """Run gap-analysis --coverage and check no crashes (no data means no gaps)."""
    result = runner.invoke(cli, [
        "--db", str(tmp_db), "gap-analysis", "--type", "coverage"
    ])
    assert result.exit_code == 0, result.output
    # Initial state = no tournament results
    assert "No gaps detected" in result.output


def test_gap_analysis_mutations_empty(runner, tmp_db):
    result = runner.invoke(cli, [
        "--db", str(tmp_db), "gap-analysis", "--type", "mutations"
    ])
    assert result.exit_code == 0, result.output
    assert "No gaps detected" in result.output


def test_prompts_initial_empty(runner, tmp_db):
    result = runner.invoke(cli, ["--db", str(tmp_db), "prompts"])
    assert result.exit_code == 0
    assert "No prompts found" in result.output


def test_prompts_with_trigger_filter(runner, tmp_db):
    self_prompt_ctx = {"scenario_name": "s", "mutation_strategy": "t", "failure_mode": "f"}
    runner.invoke(cli, [
        "--db", str(tmp_db), "self-prompt", "--trigger", "mutation_escaped",
        "--context", json.dumps(self_prompt_ctx)
    ])

    # Filtered
    result = runner.invoke(cli, ["--db", str(tmp_db), "prompts", "--trigger-type", "mutation_escaped"])
    assert result.exit_code == 0
    assert "mutation_escaped" in result.output

    # Filtered to nonexistent trigger
    result2 = runner.invoke(cli, ["--db", str(tmp_db), "prompts", "--trigger-type", "coverage_cliff"])
    assert result2.exit_code == 0
    assert "No prompts found" in result2.output


def test_self_prompt_invalid_trigger(runner, tmp_db):
    result = runner.invoke(cli, [
        "--db", str(tmp_db), "self-prompt", "--trigger", "nonexistent", "--context", "{}"
    ])
    assert result.exit_code != 0  # click rejects invalid choices


def test_self_prompt_rejects_invalid_json_context(runner, tmp_db):
    """Invalid JSON context should fail with clear error."""
    result = runner.invoke(cli, [
        "--db", str(tmp_db), "self-prompt", "--trigger", "mutation_escaped",
        "--context", "{invalid json"
    ])
    assert result.exit_code != 0  # json.loads raises inside command
