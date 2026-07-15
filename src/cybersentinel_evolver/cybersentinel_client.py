"""
CyberSentinel API Integration — 500-regression detector.

Module: cybersentinel_evolver.cybersentinel_client

Authenticates via POST /api/auth/token, then sends scenario request
sequences and flags 5xx responses as regressions.

Usage:
    from cybersentinel_evolver.cybersentinel_client import CyberSentinelClient

    client = CyberSentinelClient("http://localhost:3000", "test-client")
    results = client.load_scenarios_from_db("~/cybersentinel-evolver/data.db")
    report = client.run_regression_suite(results)
    print(report.summary())
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Protocol

import httpx


@dataclass
class RegressionResult:
    scenario_id: str
    scenario_name: str
    request_index: int
    method: str
    path: str
    status_code: int
    response_body: str
    elapsed_ms: float

    def is_regression(self) -> bool:
        return 500 <= self.status_code < 600


@dataclass
class RegressionReport:
    target_url: str
    results: list[RegressionResult] = field(default_factory=list)
    auth_failed: bool = False
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.auth_failed:
            return "AUTH_FAILED — could not obtain JWT token"
        if self.errors:
            return f"ERRORS: {'; '.join(self.errors[:3])}"
        regressions = [r for r in self.results if r.is_regression()]
        return (
            f"Target: {self.target_url}\n"
            f"Total requests: {len(self.results)}\n"
            f"5xx regressions: {len(regressions)}\n"
            f"Regression rate: {(len(regressions) / max(len(self.results), 1) * 100):.1f}%"
        )

    def has_regressions(self) -> bool:
        return any(r.is_regression() for r in self.results)


class HTTPTransport(Protocol):
    def post(self, url: str, json: dict | None = None, headers: dict | None = None) -> "_Response": ...
    def get(self, url: str, headers: dict | None = None) -> "_Response": ...


class _Response:
    def __init__(self, status: int, body: str = ""):
        self.status_code = status
        self.text = body

    def json(self):
        return json.loads(self.text)


class _HttpxTransport:
    def __init__(self, timeout: float = 30.0):
        self._client = httpx.Client(timeout=timeout)

    def post(self, url: str, json: dict | None = None, headers: dict | None = None):
        res = self._client.post(url, json=json, headers=headers)
        return _Response(res.status_code, res.text)

    def get(self, url: str, headers: dict | None = None):
        res = self._client.get(url, headers=headers)
        return _Response(res.status_code, res.text)


class CyberSentinelClient:
    """CyberSentinel API client for regression testing."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        transport: HTTPTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self._transport = transport or _HttpxTransport()
        self._token: str | None = None

    def authenticate(self) -> bool:
        """POST /api/auth/token — obtain JWT."""
        try:
            res = self._transport.post(
                f"{self.base_url}/api/auth/token",
                json={"clientId": self.client_id},
            )
            if res.status_code != 201:
                return False
            body = res.json()
            self._token = body.get("token")
            return self._token is not None
        except Exception:
            return False

    @property
    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def health(self) -> bool:
        """Check /health endpoint."""
        res = self._transport.get(f"{self.base_url}/health")
        return res.status_code == 200

    def send_request(
        self,
        method: str,
        path: str,
        headers: dict | None = None,
        body: dict | None = None,
    ) -> _Response:
        """Send an arbitrary request (proxied through the API if needed)."""
        req_headers = {**self._auth_headers, **(headers or {})}
        url = f"{self.base_url}{path}"
        return self._transport.post(url, json=body, headers=req_headers)

    def scan_scenario_requests(
        self,
        scenarios: list[dict],
        max_requests: int | None = None,
    ) -> RegressionReport:
        """
        Send each scenario's requests to CyberSentinel and flag 5xx responses.

        Uses the /api/sessions endpoint as the primary probe (it's the most
        complex and most likely to regress under adversarial input).
        """
        report = RegressionReport(target_url=self.base_url)

        if not self._token:
            if not self.authenticate():
                report.auth_failed = True
                return report

        endpoint = "/api/sessions"
        sent = 0

        for scenario in scenarios:
            if max_requests and sent >= max_requests:
                break
            reqs = scenario.get("requests", [])
            for i, req in enumerate(reqs):
                if max_requests and sent >= max_requests:
                    break
                try:
                    res = self._transport.post(
                        f"{self.base_url}{endpoint}",
                        json={
                            "method": req["method"],
                            "path": req["path"],
                            "headers": req.get("headers", {}),
                            "body_b64": req.get("body_b64"),
                        },
                        headers=self._auth_headers,
                    )
                    report.results.append(
                        RegressionResult(
                            scenario_id=scenario.get("id", "unknown"),
                            scenario_name=scenario.get("name", "unknown"),
                            request_index=i,
                            method=req["method"],
                            path=req["path"],
                            status_code=res.status_code,
                            response_body=res.text[:200],
                            elapsed_ms=0,
                        )
                    )
                except Exception as e:
                    report.errors.append(str(e))
                sent += 1

        return report

    def load_scenarios_from_db(self, db_path: str) -> list[dict]:
        """Load scenarios from the evolver SQLite DB."""
        from .database import Database

        db = Database(db_path)
        rows = db.get_scenarios()
        db.close()
        return rows
