"""Generate abuse scenarios grounded in threat intelligence feeds."""
from __future__ import annotations

import copy
import uuid
from typing import Callable

from .database import Database
from .models import (
    AttackRequest,
    AttackRequest as AttackReq,
    CostModel,
    IdentityType,
    MutationRecord,
    MutationStrategy,
    Scenario,
)


class AttackGenerator:
    """Generate abuse scenarios grounded in threat intelligence feeds.

    Per BRD §5.1 — produce ≥12 distinct abuse scenarios with high variant density:
      - credential stuffing: 10 variants
      - shadow-agent impersonation: 8 variants
      - LLM token scraping: 6 variants
      - billing abuse: 5 variants
      - MCP server abuse: 4 variants
      - prompt injection bypass: 4 variants
      - rate limit evasion via distributed agents: 4 variants
    Total: 41 variants.
    """

    # Minimum scenarios required to pass generator validation
    MIN_SCENARIOS = 12

    def __init__(self, db: Database):
        self.db = db
        self._templates = self._load_templates()

    def _load_templates(self) -> list[dict]:
        """Build scenario templates from embedded threat intelligence."""

        templates = []

        # ── Credential Stuffing (10 variants) ──────────────────────────
        credential_feeds = [
            "salt-security-2025", "owasp-api-top-10", "cisa-known-exploited",
            "crowdstrike-2026-ai", "wallarm-threatstats-2026", "imperva-thales-2025",
        ]
        credential_identity_sources = [
            "ip", "jwt_claim", "user_agent", "mcp_agent_name",
            "oauth_client_id", "api_key_header", "composite_identity",
            "ip", "jwt_claim", "user_agent",
        ]
        for i in range(10):
            templates.append({
                "name": f"credential_stuffing_v{i+1}",
                "abuse_type": "credential_stuffing",
                "identity_source": credential_identity_sources[i],
                "source_feed": credential_feeds[i % len(credential_feeds)],
                "cost_model_label": "credential-stuffing-default",
            })

        # ── Shadow Agent / Agent Impersonation (8 variants) ─────────────
        impersonation_feeds = [
            "crowdstrike-2026-ai", "wallarm-threatstats-2026",
            "imperva-thales-2025", "salt-security-2025",
        ]
        imp_id_sources = [
            "mcp_agent_name", "oauth_client_id", "api_key_header",
            "composite_identity", "jwt_claim", "mcp_agent_name",
            "oauth_client_id", "api_key_header",
        ]
        for i in range(8):
            templates.append({
                "name": f"shadow_agent_impersonation_v{i+1}",
                "abuse_type": "agent_impersonation",
                "identity_source": imp_id_sources[i],
                "source_feed": impersonation_feeds[i % len(impersonation_feeds)],
                "cost_model_label": "default",
            })

        # ── LLM Token Scraping (6 variants) ─────────────────────────────
        scraping_feeds = [
            "wallarm-threatstats-2026", "crowdstrike-2026-ai",
            "imperva-thales-2025", "salt-security-2025",
            "owasp-api-top-10", "cisa-known-exploited",
        ]
        scraping_id_sources = [
            "user_agent", "api_key_header", "composite_identity",
            "ip", "mcp_agent_name", "oauth_client_id",
        ]
        for i in range(6):
            templates.append({
                "name": f"llm_token_scraping_v{i+1}",
                "abuse_type": "llm_token_scraping",
                "identity_source": scraping_id_sources[i],
                "source_feed": scraping_feeds[i],
                "cost_model_label": "llm-token-scraping-default",
            })

        # ── Billing Abuse (5 variants) ──────────────────────────────────
        billing_feeds = [
            "imperva-thales-2025", "wallarm-threatstats-2026",
            "salt-security-2025", "crowdstrike-2026-ai", "cisa-known-exploited",
        ]
        billing_id_sources = [
            "ip", "jwt_claim", "user_agent", "oauth_client_id", "composite_identity",
        ]
        for i in range(5):
            templates.append({
                "name": f"billing_abuse_v{i+1}",
                "abuse_type": "billing_abuse",
                "identity_source": billing_id_sources[i],
                "source_feed": billing_feeds[i],
                "cost_model_label": "billing-abuse-default",
            })

        # ── MCP Server Abuse (4 variants) ───────────────────────────────
        mcp_feeds = [
            "crowdstrike-2026-ai", "wallarm-threatstats-2026",
            "salt-security-2025", "imperva-thales-2025",
        ]
        mcp_id_sources = [
            "mcp_agent_name", "oauth_client_id", "api_key_header", "composite_identity",
        ]
        for i in range(4):
            templates.append({
                "name": f"mcp_server_abuse_v{i+1}",
                "abuse_type": "mcp_server_abuse",
                "identity_source": mcp_id_sources[i],
                "source_feed": mcp_feeds[i],
                "cost_model_label": "mcp-server-abuse-default",
            })

        # ── Prompt Injection Bypass (4 variants) ────────────────────────
        pi_feeds = [
            "wallarm-threatstats-2026", "crowdstrike-2026-ai",
            "owasp-api-top-10", "salt-security-2025",
        ]
        pi_id_sources = [
            "user_agent", "api_key_header", "composite_identity", "mcp_agent_name",
        ]
        for i in range(4):
            templates.append({
                "name": f"prompt_injection_bypass_v{i+1}",
                "abuse_type": "prompt_injection",
                "identity_source": pi_id_sources[i],
                "source_feed": pi_feeds[i],
                "cost_model_label": "default",
            })

        # ── Rate Limit Evasion via Distributed Agents (4 variants) ──────
        rate_feeds = [
            "cisa-known-exploited", "wallarm-threatstats-2026",
            "crowdstrike-2026-ai", "imperva-thales-2025",
        ]
        rate_id_sources = [
            "ip", "user_agent", "composite_identity", "api_key_header",
        ]
        for i in range(4):
            templates.append({
                "name": f"rate_evasion_distributed_v{i+1}",
                "abuse_type": "rate_evasion_distributed",
                "identity_source": rate_id_sources[i],
                "source_feed": rate_feeds[i],
                "cost_model_label": "default",
            })

        # ── Additional classic API abuse types (4 variants) ─────────────
        for i, abuse in enumerate(["path_scanning", "error_spike", "traffic_spike", "request_smuggling"]):
            templates.append({
                "name": f"{abuse}_v{i+1}",
                "abuse_type": abuse,
                "identity_source": ["ip", "user_agent", "jwt_claim", "api_key_header"][i],
                "source_feed": [
                    "owasp-api-top-10", "salt-security-2025",
                    "imperva-thales-2025", "crowdstrike-2026-ai",
                ][i],
                "cost_model_label": "default",
            })

        return templates

    def generate(self) -> list[Scenario]:
        """Generate all scenarios. Returns list of persisted scenarios."""
        scenarios = []
        for tmpl in self._templates:
            requests = self._build_requests(tmpl["abuse_type"])
            scenario = Scenario(
                id=str(uuid.uuid4()),
                name=tmpl["name"],
                source_feed=tmpl["source_feed"],
                abuse_type=tmpl["abuse_type"],
                cost_model_label=tmpl["cost_model_label"],
                identity_source=tmpl["identity_source"],
                requests=requests,
            )
            self.db.insert_scenario(scenario.to_dict())
            scenarios.append(scenario)
        return scenarios

    def _build_requests(self, abuse_type: str) -> list[AttackRequest]:
        """Build request sequences for each abuse type."""
        if abuse_type == "credential_stuffing":
            return [
                AttackRequest("POST", "/api/auth/login",
                              headers={"Authorization": "Bearer invalid_token_<i>"},
                              expected_outcome="block", timing_ms=50)
                for i in range(20)
            ]
        elif abuse_type == "path_scanning":
            paths = ["/api/admin", "/.env", "/wp-admin", "/phpmyadmin", "/.git/config"]
            return [
                AttackRequest("GET", p, headers={"X-Scanner": "dirbuster-v2"},
                              expected_outcome="block", timing_ms=100)
                for p in paths for i in range(3)
            ]
        elif abuse_type == "llm_token_scraping":
            return [
                AttackRequest("POST", "/v1/chat/completions",
                              headers={"X-Agent": "scraper-bot-1", "Authorization": "Bearer sk-xxx"},
                              body_b64="eyJyb2...MifQ==",
                              expected_outcome="block", timing_ms=200)
                for _ in range(30)
            ]
        elif abuse_type == "agent_impersonation":
            return [
                AttackRequest("POST", "/api/tools/invoke",
                              headers={"X-Agent-Name": "legit-agent",
                                       "Authorization": "Bearer <spoofed>"},
                              expected_outcome="throttle", timing_ms=150)
                for _ in range(15)
            ]
        elif abuse_type == "mcp_server_abuse":
            return [
                AttackRequest("POST", "/mcp/tools/list",
                              headers={"X-MCP-Server": "malicious-server"},
                              expected_outcome="block", timing_ms=300)
                for _ in range(10)
            ]
        elif abuse_type == "billing_abuse":
            return [
                AttackRequest("POST", "/api/process-payment",
                              headers={"X-User-Id": "free-tier-user"},
                              body_b64="eyJhbW...OTl9",
                              expected_outcome="throttle", timing_ms=500)
                for _ in range(8)
            ]
        elif abuse_type == "prompt_injection":
            return [
                AttackRequest("POST", "/v1/chat/completions",
                              headers={"Content-Type": "application/json"},
                              body_b64="eyJyb2...4ifQ==",
                              expected_outcome="block", timing_ms=100)
                for _ in range(12)
            ]
        elif abuse_type == "rate_evasion_distributed":
            return [
                AttackRequest("GET", "/api/data",
                              headers={"X-Forwarded-For": f"10.0.0.{i % 50}"},
                              expected_outcome="allow", timing_ms=1000)
                for i in range(20)
            ]
        elif abuse_type == "shadow_agent_discovery":
            return [
                AttackRequest("GET", "/api/schema",
                              headers={"User-Agent": "ShadowAgent/1.0"},
                              expected_outcome="block", timing_ms=2000)
                for _ in range(6)
            ]
        elif abuse_type == "request_smuggling":
            return [
                AttackRequest("POST", "/api/proxy",
                              headers={"Content-Length": "100", "Transfer-Encoding": "chunked"},
                              body_b64="R0VUIC9hcGkvYWRtaW4gSFRUUC8xLjENCg==",
                              expected_outcome="block", timing_ms=100)
                for _ in range(5)
            ]
        else:  # error_spike or traffic_spike
            return [
                AttackRequest("GET", "/api/flaky-endpoint",
                              headers={"Authorization": "Bearer <expired>"},
                              expected_outcome="allow", timing_ms=10)
                for _ in range(50)
            ]


class MutationEngine:
    """Generate mutations of detected scenarios to test edge resilience."""

    def __init__(self, db: Database):
        self.db = db

    def mutate(self, parent: Scenario, strategy: MutationStrategy, n: int = 3) -> list[Scenario]:
        """Generate n mutated children for a given scenario."""
        children = []
        for i in range(n):
            child = self._apply_mutation(parent, strategy, i)
            self.db.insert_scenario(child.to_dict())
            children.append(child)
        return children

    def _apply_mutation(
        self,
        parent: Scenario,
        strategy: MutationStrategy,
        index: int,
    ) -> Scenario:
        """Apply a single mutation strategy to produce a child scenario."""
        child_requests = []

        for req in parent.requests:
            mutated = self._mutate_request(req, strategy, index)
            child_requests.append(mutated)

        return Scenario(
            id=str(uuid.uuid4()),
            name=f"{parent.name}_mut{index}_{strategy}",
            source_feed=parent.source_feed,
            abuse_type=parent.abuse_type,
            cost_model_label=parent.cost_model_label,
            identity_source=parent.identity_source,
            requests=child_requests,
            parent_id=parent.id,
            mutation_depth=parent.mutation_depth + 1,
            generation=parent.generation + 1,
        )

    def _mutate_request(
        self,
        req: AttackRequest,
        strategy: MutationStrategy,
        index: int,
    ) -> AttackRequest:
        """Apply mutation to a single request based on strategy."""
        headers = dict(req.headers)
        path = req.path
        body = req.body_b64
        timing = req.timing_ms

        if strategy == "identity_swap":
            # Rotate identity claims: IP → JWT → User-Agent → OAuth client
            if "Authorization" in headers:
                headers["Authorization"] = f"Bearer rotated_token_{index}"
            elif "X-Agent-Name" in headers:
                headers["X-Agent-Name"] = f"mutated-agent-{index}"
            else:
                headers["User-Agent"] = f"MutatedBot/{index}.0"

        elif strategy == "temporal_mutation":
            # Slow down by 10x or burst to near-zero
            timing = timing * 10 if index % 2 == 0 else max(1, timing // 10)

        elif strategy == "protocol_mutation":
            # Swap GET ↔ POST, reorder headers
            method = "POST" if req.method == "GET" else "GET"
            return AttackRequest(method, path, dict(reversed(list(headers.items()))),
                                 body, req.expected_outcome, timing)

        elif strategy == "intent_preserving":
            # Change surface but preserve attacker goal
            path_variants = ["/v1/chat", "/api/chat", "/chat/completions"]
            path = path_variants[index % len(path_variants)]

        return AttackRequest(req.method, path, headers, body,
                             req.expected_outcome, timing)
