"""Tests for CyberSentinel API integration client."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cybersentinel_evolver.cybersentinel_client import (
    CyberSentinelClient,
    RegressionReport,
    _Response,
)


class TestResponse:
    def test_json_parses(self):
        r = _Response(200, '{"status": "healthy"}')
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    def test_text_raw(self):
        r = _Response(500, "Internal Server Error")
        assert r.status_code == 500
        assert "Server Error" in r.text


class TestRegressionResult:
    def test_is_regression_true(self):
        from cybersentinel_evolver.cybersentinel_client import RegressionResult
        r = RegressionResult("1", "test", 0, "POST", "/api/x", 503, "", 0)
        assert r.is_regression()

    def test_is_regression_false_for_4xx(self):
        from cybersentinel_evolver.cybersentinel_client import RegressionResult
        r = RegressionResult("1", "test", 0, "POST", "/api/x", 404, "", 0)
        assert not r.is_regression()

    def test_is_regression_false_for_2xx(self):
        from cybersentinel_evolver.cybersentinel_client import RegressionResult
        r = RegressionResult("1", "test", 0, "POST", "/api/x", 200, "", 0)
        assert not r.is_regression()


class TestRegressionReport:
    def test_empty_report_no_regressions(self):
        report = RegressionReport("http://test")
        assert not report.has_regressions()
        assert report.summary() == "Target: http://test\nTotal requests: 0\n5xx regressions: 0\nRegression rate: 0.0%"

    def test_has_regressions_true(self):
        from cybersentinel_evolver.cybersentinel_client import RegressionResult
        report = RegressionReport("http://test")
        report.results.append(RegressionResult("1", "a", 0, "GET", "/", 500, "", 0))
        report.results.append(RegressionResult("2", "b", 0, "GET", "/", 200, "", 0))
        assert report.has_regressions()

    def test_report_summary_with_mixed(self):
        from cybersentinel_evolver.cybersentinel_client import RegressionResult
        report = RegressionReport("http://test")
        report.results.append(RegressionResult("1", "a", 0, "GET", "/", 500, "", 0))
        report.results.append(RegressionResult("2", "b", 0, "GET", "/", 200, "", 0))
        report.results.append(RegressionResult("3", "c", 0, "GET", "/", 503, "", 0))
        report.results.append(RegressionResult("4", "d", 0, "GET", "/", 401, "", 0))
        summary = report.summary()
        assert "5xx regressions: 2" in summary
        assert "Regression rate: 50.0%" in summary

    def test_auth_failed_summary(self):
        report = RegressionReport("http://test", auth_failed=True)
        assert "AUTH_FAILED" in report.summary()


class TestCyberSentinelClient:
    def test_authenticate_success(self):
        mock_transport = MagicMock()
        mock_transport.post.return_value = _Response(201, '{"token": "abc123", "tokenType": "Bearer"}')

        client = CyberSentinelClient("http://test", "client-1", transport=mock_transport)
        assert client.authenticate()
        assert client._token == "abc123"

    def test_authenticate_failure(self):
        mock_transport = MagicMock()
        mock_transport.post.return_value = _Response(401, "Unauthorized")

        client = CyberSentinelClient("http://test", "client-1", transport=mock_transport)
        assert not client.authenticate()

    def test_health_true(self):
        mock_transport = MagicMock()
        mock_transport.get.return_value = _Response(200)

        client = CyberSentinelClient("http://test", "client-1", transport=mock_transport)
        assert client.health()

    def test_health_false(self):
        mock_transport = MagicMock()
        mock_transport.get.return_value = _Response(503)

        client = CyberSentinelClient("http://test", "client-1", transport=mock_transport)
        assert not client.health()

    def test_scan_scenario_requests_detects_regressions(self):
        mock_transport = MagicMock()
        # First call: auth success, second+: session API returns 500
        mock_transport.post.side_effect = [
            _Response(201, '{"token": "tok", "tokenType": "Bearer"}'),
            _Response(500, "Internal Server Error"),
            _Response(503, "Service Unavailable"),
            _Response(201, "OK"),
        ]

        scenarios = [
            {"id": "s1", "name": "test_scenario", "requests": [
                {"method": "POST", "path": "/api/sessions", "headers": {}, "expected_outcome": "block"},
                {"method": "POST", "path": "/api/sessions", "headers": {}, "expected_outcome": "block"},
                {"method": "POST", "path": "/api/sessions", "headers": {}, "expected_outcome": "block"},
            ]},
        ]

        client = CyberSentinelClient("http://test", "c1", transport=mock_transport)
        client._token = "tok"
        report = client.scan_scenario_requests(scenarios)

        assert report.has_regressions()
        regressions = [r for r in report.results if r.is_regression()]
        assert len(regressions) == 2
        assert regressions[0].status_code == 500
        assert regressions[1].status_code == 503

    def test_scan_scenario_requests_auth_failure(self):
        mock_transport = MagicMock()
        mock_transport.post.return_value = _Response(401, "Unauthorized")

        client = CyberSentinelClient("http://test", "c1", transport=mock_transport)
        report = client.scan_scenario_requests([{"id": "s1", "name": "t", "requests": []}])

        assert report.auth_failed

    def test_max_requests_limits_output(self):
        mock_transport = MagicMock()
        mock_transport.post.side_effect = [
            _Response(201, '{"token": "tok", "tokenType": "Bearer"}'),
        ] + [_Response(200, "OK")] * 100

        scenarios = [
            {"id": "s1", "name": "t", "requests": [
                {"method": "POST", "path": "/api/sessions", "headers": {}, "expected_outcome": "block"}
            ] * 50},
        ]

        client = CyberSentinelClient("http://test", "c1", transport=mock_transport)
        client._token = "tok"
        report = client.scan_scenario_requests(scenarios, max_requests=10)

        assert len(report.results) == 10

    def test_load_scenarios_from_db(self, tmp_path):
        from cybersentinel_evolver.database import Database
        from cybersentinel_evolver.models import AttackRequest, Scenario
        db = Database(tmp_path / "test.db")
        scenario = Scenario(
            id="db-test", name="db_scenario", source_feed="feed",
            abuse_type="credential_stuffing", cost_model_label="default",
            identity_source="ip",
            requests=[AttackRequest("GET", "/api/x")],
        )
        db.insert_scenario(scenario.to_dict())
        db.close()

        # Now load via client
        client = CyberSentinelClient("http://test", "c1")
        rows = client.load_scenarios_from_db(str(tmp_path / "test.db"))
        assert len(rows) == 1
        assert rows[0]["id"] == "db-test"
