"""End-to-end CLI smoke tests — exercises the full evolution loop.

These tests run the CLI commands in sequence to verify the complete
pipeline works end-to-end (not just individual unit tests).

Test: generate → tournament → gap-analysis → evolve → verify DB state
"""
from __future__ import annotations

import subprocess

import pytest

from cybersentinel_evolver.database import Database


def run_cli(db_path: str, *args: str) -> subprocess.CompletedProcess:
    """Run cs-evolver CLI command with a specific DB path."""
    return subprocess.run(
        ["python", "-m", "cybersentinel_evolver.cli", "--db", db_path, *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


class TestEndToEndCLISmoke:
    def test_full_pipeline(self, tmp_path):
        db_path = str(tmp_path / "test.db")

        # Phase 1: Generate scenarios
        result = run_cli(db_path, "scenarios")
        assert result.returncode == 0, result.stderr
        assert "Generated" in result.stdout
        assert "scenarios" in result.stdout

        # Phase 2: Run tournament
        result = run_cli(db_path, "tournament")
        assert result.returncode == 0, result.stderr
        assert "Tournament Results" in result.stdout

        # Phase 3: Gap analysis
        result = run_cli(db_path, "gap-analysis", "--type", "mutations")
        assert result.returncode == 0, result.stderr

        # Phase 4: Evolve
        result = run_cli(db_path, "evolve", "--weeks", "1")
        assert result.returncode == 0, result.stderr

        # Phase 5: Verify DB state
        db = Database(db_path)
        scenarios = db.get_scenarios()
        assert len(scenarios) >= 12

        tournaments = db.get_tournament_results()
        assert len(tournaments) >= 1

        db.close()

    def test_self_prompt_pipeline(self, tmp_path):
        db_path = str(tmp_path / "test.db")

        result = run_cli(db_path, "self-prompt", "--trigger", "mutation_escaped",
                          "--context", '{"scenario_name": "test"}')
        assert result.returncode == 0, result.stderr
        assert "Prompt generated" in result.stdout

        # Verify prompt persisted
        db = Database(db_path)
        prompts = db.get_prompts()
        assert len(prompts) == 1
        db.close()

    def test_prompts_listing(self, tmp_path):
        db_path = str(tmp_path / "test.db")

        # Generate a prompt first
        run_cli(db_path, "self-prompt", "--trigger", "coverage_cliff", "--context", "{}")

        # List prompts
        result = run_cli(db_path, "prompts")
        assert result.returncode == 0, result.stderr
        assert "coverage_cliff" in result.stdout

    def test_report(self, tmp_path):
        db_path = str(tmp_path / "test.db")

        run_cli(db_path, "scenarios")
        run_cli(db_path, "tournament")

        result = run_cli(db_path, "report")
        assert result.returncode == 0, result.stderr
        assert "Tournament History" in result.stdout

    def test_evolve_auto_promote(self, tmp_path):
        db_path = str(tmp_path / "test.db")

        run_cli(db_path, "scenarios")
        result = run_cli(db_path, "evolve", "--weeks", "1", "--auto-promote")
        assert result.returncode == 0, result.stderr
        assert "Winner" in result.stdout
