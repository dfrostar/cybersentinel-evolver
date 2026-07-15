from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

AbuseType = Literal[
    "credential_stuffing",
    "path_scanning",
    "error_spike",
    "traffic_spike",
    "agent_impersonation",
    "llm_token_scraping",
    "billing_abuse",
    "mcp_server_abuse",
    "prompt_injection",
    "rate_evasion_distributed",
    "shadow_agent_discovery",
    "request_smuggling",
]

IdentityType = Literal[
    "ip",
    "jwt_claim",
    "user_agent",
    "mcp_agent_name",
    "oauth_client_id",
    "api_key_header",
    "composite_identity",
]

MutationStrategy = Literal[
    "identity_swap",
    "temporal_mutation",
    "protocol_mutation",
    "intent_preserving",
]

MethodType = Literal["GET", "POST", "PUT", "DELETE"]

OutcomeType = Literal["allow", "block", "throttle", "challenge"]


@dataclass
class AttackRequest:
    method: MethodType
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body_b64: str | None = None
    expected_outcome: OutcomeType = "block"
    timing_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body_b64": self.body_b64,
            "expected_outcome": self.expected_outcome,
            "timing_ms": self.timing_ms,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttackRequest":
        return cls(
            method=d["method"],
            path=d["path"],
            headers=d.get("headers", {}),
            body_b64=d.get("body_b64"),
            expected_outcome=d.get("expected_outcome", "block"),
            timing_ms=d.get("timing_ms", 0),
        )


@dataclass
class Scenario:
    id: str
    name: str
    source_feed: str
    abuse_type: AbuseType
    cost_model_label: str
    identity_source: IdentityType
    requests: list[AttackRequest]
    parent_id: str | None = None
    mutation_depth: int = 0
    generation: int = 0
    created_at: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "name": self.name,
            "source_feed": self.source_feed,
            "abuse_type": self.abuse_type,
            "cost_model_label": self.cost_model_label,
            "identity_source": self.identity_source,
            "mutation_depth": self.mutation_depth,
            "generation": self.generation,
            "created_at": self.created_at,
            "requests_json": json.dumps([r.to_dict() for r in self.requests]),
        }

    @classmethod
    def from_dict_row(cls, row: dict) -> "Scenario":
        reqs = json.loads(row["requests_json"])
        return cls(
            id=row["id"],
            name=row["name"],
            source_feed=row["source_feed"],
            abuse_type=row["abuse_type"],
            cost_model_label=row["cost_model_label"],
            identity_source=row["identity_source"],
            requests=[AttackRequest.from_dict(r) for r in reqs],
            parent_id=row.get("parent_id"),
            mutation_depth=row.get("mutation_depth", 0),
            generation=row.get("generation", 0),
            created_at=row.get("created_at", 0),
        )

    def hash_key(self) -> str:
        """Deterministic hash for deduplication based on requests."""
        import hashlib
        content = json.dumps([r.to_dict() for r in self.requests], sort_keys=True).encode()
        return hashlib.sha256(content).hexdigest()[:16]


@dataclass
class TournamentResult:
    run_id: str
    detector_id: str
    scenario_count: int
    detected_count: int
    false_positive_count: int
    cost_blocked: float
    cost_missed: float
    cost_model_label: str
    win_rate: float
    confidence_low: float
    confidence_high: float
    ran_at: int

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "detector_id": self.detector_id,
            "scenario_count": self.scenario_count,
            "detected_count": self.detected_count,
            "false_positive_count": self.false_positive_count,
            "cost_blocked": self.cost_blocked,
            "cost_missed": self.cost_missed,
            "cost_model_label": self.cost_model_label,
            "win_rate": self.win_rate,
            "confidence_low": self.confidence_low,
            "confidence_high": self.confidence_high,
            "ran_at": self.ran_at,
        }


@dataclass
class MutationRecord:
    mutation_id: str
    parent_scenario_id: str
    child_scenario_id: str
    strategy: MutationStrategy
    depth: int
    escaped: bool
    created_at: int

    def to_dict(self) -> dict:
        return {
            "mutation_id": self.mutation_id,
            "parent_scenario_id": self.parent_scenario_id,
            "child_scenario_id": self.child_scenario_id,
            "strategy": self.strategy,
            "depth": self.depth,
            "escaped": self.escaped,
            "created_at": self.created_at,
        }


@dataclass
class CostModel:
    label: str
    per_1k_requests: float
    source_notes: str


COST_MODELS: dict[str, CostModel] = {
    "credential-stuffing-default": CostModel(
        label="credential-stuffing-default",
        per_1k_requests=0.12,
        source_notes="Auth service compute + rate-limit mitigation per-request cost",
    ),
    "llm-token-scraping-default": CostModel(
        label="llm-token-scraping-default",
        per_1k_requests=4.80,
        source_notes="GPT-4o-mini input $0.15/1M tokens × avg 32K tokens/req, scaled per 1K",
    ),
    "billing-abuse-default": CostModel(
        label="billing-abuse-default",
        per_1k_requests=1.20,
        source_notes="Compute + payment processing fee per-request estimate",
    ),
    "mcp-server-abuse-default": CostModel(
        label="mcp-server-abuse-default",
        per_1k_requests=0.45,
        source_notes="Tool-call compute cost estimate based on function execution",
    ),
    "default": CostModel(
        label="default",
        per_1k_requests=0.50,
        source_notes="Generic fallback model, midpoint of known models",
    ),
}


def get_cost_model(label: str) -> CostModel:
    return COST_MODELS.get(label, COST_MODELS["default"])


def compute_cost(scenarios_detected: int, scenarios_missed: int, cost_model: CostModel) -> tuple[float, float]:
    detected_cost = (scenarios_detected / 1000) * cost_model.per_1k_requests
    missed_cost = (scenarios_missed / 1000) * cost_model.per_1k_requests
    return round(detected_cost, 4), round(missed_cost, 4)


def bootstrap_confidence_interval(
    wins: int,
    total: int,
    n_bootstrap: int = 10000,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Compute bootstrap confidence interval for win rate."""
    if total == 0:
        return (0.0, 1.0)
    import random
    rng = random.Random(42)
    results = []
    observations = [1] * wins + [0] * (total - wins)
    for _ in range(n_bootstrap):
        sample = rng.choices(observations, k=total)
        results.append(sum(sample) / total)
    results.sort()
    lower_idx = int((1 - confidence) / 2 * n_bootstrap)
    upper_idx = int((1 + confidence) / 2 * n_bootstrap)
    return (results[lower_idx], results[upper_idx])


def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)
