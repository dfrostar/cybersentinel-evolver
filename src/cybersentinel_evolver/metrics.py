"""Prometheus metrics export for tournament results and evolution tracking.

Phase 3 observability: exposes cost-blocked, cost-missed, win-rate,
scenario count, and mutation escape rate as Prometheus gauges/counters.

Usage:
    from cybersentinel_evolver.metrics import record_tournament, get_registry

    record_tournament(db)
    # Metrics now reflect latest tournament data

Scrape endpoint: GET /metrics (served via Prometheus client or pushgateway).
"""
from __future__ import annotations

from prometheus_client import Gauge, Counter, Histogram, CollectorRegistry, push_to_gateway, REGISTRY

from .database import Database

# Use the default global registry
registry = REGISTRY

# ── Tournament Metrics ────────────────────────────────────────────────

COST_BLOCKED = Gauge(
    "cybersentinel_cost_blocked_usd",
    "Total USD cost blocked by detectors",
    ["detector_id"],
    registry=registry,
)

COST_MISSED = Gauge(
    "cybersentinel_cost_missed_usd",
    "Total USD cost missed by detectors",
    ["detector_id"],
    registry=registry,
)

WIN_RATE = Gauge(
    "cybersentinel_win_rate",
    "Detector win rate (0.0-1.0)",
    ["detector_id"],
    registry=registry,
)

TOURNAMENT_RUNS = Counter(
    "cybersentinel_tournament_runs_total",
    "Total tournament runs",
    registry=registry,
)

# ── Scenario / Mutation Metrics ───────────────────────────────────────

SCENARIO_COUNT = Gauge(
    "cybersentinel_scenarios_total",
    "Current scenario count",
    registry=registry,
)

MUTATION_COUNT = Gauge(
    "cybersentinel_mutations_total",
    "Current mutation count",
    registry=registry,
)

MUTATION_ESCAPE_RATE = Gauge(
    "cybersentinel_mutation_escape_rate",
    "Fraction of mutations that escaped detection (0.0-1.0)",
    registry=registry,
)

EVOLUTION_WEEKS = Counter(
    "cybersentinel_evolution_weeks_total",
    "Total evolution weeks completed",
    registry=registry,
)

# ── Self-Prompt Metrics ───────────────────────────────────────────────

PROMPT_COUNT = Gauge(
    "cybersentinel_prompts_total",
    "Total self-prompts generated",
    registry=registry,
)

PROMPT_ACCEPTANCE = Gauge(
    "cybersentinel_prompt_acceptance_rate",
    "Fraction of self-prompts that produced scenarios",
    registry=registry,
)


def record_tournament(db: Database) -> None:
    """Update Prometheus metrics from latest tournament results."""
    results = db.get_tournament_results()
    if not results:
        return

    # Aggregate per-detector totals
    detector_totals: dict[str, dict] = {}
    for r in results:
        did = r["detector_id"]
        if did not in detector_totals:
            detector_totals[did] = {"cost_blocked": 0.0, "cost_missed": 0.0, "win_rates": []}
        detector_totals[did]["cost_blocked"] += r["cost_blocked"]
        detector_totals[did]["cost_missed"] += r["cost_missed"]
        detector_totals[did]["win_rates"].append(r["win_rate"])

    for did, data in detector_totals.items():
        COST_BLOCKED.labels(detector_id=did).set(data["cost_blocked"])
        COST_MISSED.labels(detector_id=did).set(data["cost_missed"])
        avg_wr = sum(data["win_rates"]) / len(data["win_rates"])
        WIN_RATE.labels(detector_id=did).set(round(avg_wr, 4))

    TOURNAMENT_RUNS.inc()


def record_scenarios(db: Database) -> None:
    """Update scenario/mutation metrics."""
    scenarios = db.get_scenarios()
    mutations = db.get_mutations()
    escaped = [m for m in mutations if m.get("escaped") == 1] or []

    SCENARIO_COUNT.set(len(scenarios))
    MUTATION_COUNT.set(len(mutations))

    if mutations:
        escape_rate = len(escaped) / len(mutations)
        MUTATION_ESCAPE_RATE.set(round(escape_rate, 4))
    else:
        MUTATION_ESCAPE_RATE.set(0)


def record_prompts(db: Database) -> None:
    """Update self-prompt metrics."""
    prompts = db.get_prompts()
    if not prompts:
        PROMPT_COUNT.set(0)
        PROMPT_ACCEPTANCE.set(0)
        return

    PROMPT_COUNT.set(len(prompts))
    accepted = sum(1 for p in prompts if p.get("accepted") == 1)
    PROMPT_ACCEPTANCE.set(round(accepted / len(prompts), 4))


def record_all(db: Database) -> None:
    """Record all metrics from DB."""
    record_tournament(db)
    record_scenarios(db)
    record_prompts(db)


def push_metrics(gateway: str = "localhost:9091") -> None:
    """Push metrics to Prometheus Pushgateway."""
    push_to_gateway(gateway, job="cybersentinel_evolver", registry=registry)
