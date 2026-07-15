"""Tests for FastAPI REST server."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cybersentinel_evolver.database import Database
from cybersentinel_evolver.server import app, db


@pytest.fixture
def client(tmp_path):
    """Test client with a fresh temp DB."""
    test_db = Database(tmp_path / "test.db")
    # Monkeypatch the global db in server module
    import cybersentinel_evolver.server as server_module
    original_db = server_module.db
    server_module.db = test_db
    with TestClient(app) as c:
        yield c
    server_module.db = original_db
    test_db.close()


class TestHealth:
    def test_health_endpoint(self, client):
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"


class TestScenarios:
    def test_list_scenarios_empty(self, client):
        res = client.get("/api/scenarios")
        assert res.status_code == 200
        assert res.json() == []

    def test_generate_scenarios(self, client):
        res = client.post("/api/scenarios/generate")
        assert res.status_code == 200
        assert res.json()["count"] >= 12

    def test_list_scenarios_after_generate(self, client):
        client.post("/api/scenarios/generate")
        res = client.get("/api/scenarios")
        assert res.status_code == 200
        assert len(res.json()) >= 12


class TestTournaments:
    def test_list_tournaments_empty(self, client):
        res = client.get("/api/tournaments")
        assert res.status_code == 200
        assert res.json() == []

    def test_run_tournament_without_scenarios(self, client):
        res = client.post("/api/tournaments/run")
        assert res.status_code == 400

    def test_run_tournament_with_scenarios(self, client):
        client.post("/api/scenarios/generate")
        res = client.post("/api/tournaments/run")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert len(data["results"]) == 3


class TestGapAnalysis:
    def test_list_gap_analysis_empty(self, client):
        res = client.get("/api/gap-analysis")
        assert res.status_code == 200
        assert res.json() == []

    def test_run_gap_analysis_mutations(self, client):
        client.post("/api/scenarios/generate")
        res = client.post("/api/gap-analysis/run", json={"type": "mutations"})
        assert res.status_code == 200


class TestSelfPrompt:
    def test_self_prompt(self, client):
        res = client.post("/api/self-prompt", json={
            "trigger": "mutation_escaped",
            "context": "{}"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "record" in data


class TestMetrics:
    def test_metrics_empty(self, client):
        res = client.get("/api/metrics")
        assert res.status_code == 200
        data = res.json()
        assert data["total_scenarios"] == 0
        assert data["total_tournaments"] == 0

    def test_metrics_after_activity(self, client):
        client.post("/api/scenarios/generate")
        client.post("/api/tournaments/run")
        res = client.get("/api/metrics")
        assert res.status_code == 200
        data = res.json()
        assert data["total_scenarios"] >= 12
        assert data["total_tournaments"] == 3


class TestEvolve:
    def test_evolve(self, client):
        client.post("/api/scenarios/generate")
        res = client.post("/api/evolve?weeks=1")
        assert res.status_code == 200

    def test_evolve_auto_promote(self, client):
        client.post("/api/scenarios/generate")
        res = client.post("/api/evolve?weeks=1&auto_promote=true")
        assert res.status_code == 200
        assert res.json()["winner"] is not None
