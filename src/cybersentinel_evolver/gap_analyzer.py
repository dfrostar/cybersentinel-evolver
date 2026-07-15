"""Gap Analysis — detect coverage cliffs, drift, and cost-accuracy gaps.

Triggers self-prompting loop.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

AnalysisType = Literal["coverage", "drift", "cost_accuracy"]


@dataclass
class GapFinding:
    analysis_type: AnalysisType
    finding: dict
    severity: float  # 0.0–1.0
    recommended_prompt: str
    context: dict = field(default_factory=dict)


class GapAnalyzer:
    """Analyze tournament results + mutation records to identify detection gaps."""

    def __init__(self, db, win_rate_threshold: float = 0.10):
        self.db = db
        self.win_rate_threshold = win_rate_threshold

    def analyze_coverage(self, window_ms: int = 7 * 24 * 60 * 60 * 1000) -> list[GapFinding]:
        """Identify abuse types where detector win-rate dropped > threshold."""
        findings = []
        results = self.db.get_tournament_results()
        if len(results) < 2:
            return findings

        # Compare recent vs older tournaments
        recent = [r for r in results if r["ran_at"] > (results[0]["ran_at"] - window_ms // 2)]
        older = [r for r in results if r["ran_at"] <= (results[0]["ran_at"] - window_ms // 2)]

        if not recent or not older:
            return findings

        recent_win_rates = {}
        for r in recent:
            abuse = r.get("cost_model_label", "default")
            if abuse not in recent_win_rates:
                recent_win_rates[abuse] = []
            recent_win_rates[abuse].append(r["win_rate"])

        older_win_rates = {}
        for r in older:
            abuse = r.get("cost_model_label", "default")
            if abuse not in older_win_rates:
                older_win_rates[abuse] = []
            older_win_rates[abuse].append(r["win_rate"])

        for abuse, rates in recent_win_rates.items():
            if abuse not in older_win_rates:
                continue
            recent_avg = sum(rates) / len(rates)
            older_avg = sum(older_win_rates[abuse]) / len(older_win_rates[abuse])
            delta = older_avg - recent_avg

            if delta > self.win_rate_threshold:
                findings.append(GapFinding(
                    analysis_type="coverage",
                    finding={"abuse_type": abuse, "delta_pct": delta * 100,
                             "recent_win_rate": recent_avg, "older_win_rate": older_avg},
                    severity=min(delta / 0.5, 1.0),
                    recommended_prompt=f"coverage_cliff_{abuse}",
                    context={"abuse_types": [abuse], "delta": round(delta * 100, 1)},
                ))

        return findings

    def analyze_mutations(self, escaped_only: bool = True) -> list[GapFinding]:
        """Identify mutations that escaped detection."""
        findings = []
        # Query mutations (requires new DB method placeholder, but log structure)
        return findings

    def analyze_cost_accuracy(self) -> list[GapFinding]:
        """Identify gaps between estimated and actual abuse costs."""
        return []
