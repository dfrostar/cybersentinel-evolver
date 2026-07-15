from __future__ import annotations

"""CyberSentinel Evolver — self-improving abuse detection testing platform."""

from .attacks import AttackGenerator, MutationEngine
from .database import Database
from .detection import (
    BehavioralBaselineDetector,
    RandomDetector,
    RuleBasedDetector,
    run_mutation_tournament,
    run_tournament,
)
from .models import (
    AttackRequest,
    CostModel,
    MutationRecord,
    MutationStrategy,
    Scenario,
    TournamentResult,
    bootstrap_confidence_interval,
    compute_cost,
    get_cost_model,
)

__version__ = "0.1.0"
__all__ = [
    "AttackGenerator",
    "AttackRequest",
    "BehavioralBaselineDetector",
    "CostModel",
    "Database",
    "MutationEngine",
    "MutationRecord",
    "MutationStrategy",
    "RandomDetector",
    "RuleBasedDetector",
    "Scenario",
    "TournamentResult",
    "bootstrap_confidence_interval",
    "compute_cost",
    "get_cost_model",
    "run_mutation_tournament",
    "run_tournament",
]
