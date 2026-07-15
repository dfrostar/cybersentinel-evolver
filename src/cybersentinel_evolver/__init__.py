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
from .gap_analyzer import GapAnalyzer
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
from .self_promoter import PromptRecord, SelfPromoter

__version__ = "0.2.0"  # v2 schema + self-prompting loop
__all__ = [
    "AttackGenerator",
    "AttackRequest",
    "BehavioralBaselineDetector",
    "CostModel",
    "Database",
    "GapAnalyzer",
    "MutationEngine",
    "MutationRecord",
    "MutationStrategy",
    "PromptRecord",
    "RandomDetector",
    "RuleBasedDetector",
    "Scenario",
    "SelfPromoter",
    "TournamentResult",
    "bootstrap_confidence_interval",
    "compute_cost",
    "get_cost_model",
    "run_mutation_tournament",
    "run_tournament",
]
