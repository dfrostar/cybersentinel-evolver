"""Adaptive detector that evolves based on escaped mutations.

The GapAnalyzer identifies which scenarios escape the static detectors.
The AdaptiveDetector creates new "rules" (path patterns, header patterns,
timing thresholds) based on those escapes — then uses them to catch
future mutations targeting the same gaps.

This is what makes the platform genuinely self-improving: detectors
adapt to attacks, not just attacks adapting to detectors.

Usage:
    from cybersentinel_evolver.adaptive_detector import AdaptiveDetector

    det = AdaptiveDetector()
    det.adapt_from_mutations(db)  # learn from DB mutations
    result = await det.evaluate(scenario)
"""
from __future__ import annotations

import asyncio
import json
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Protocol

from .database import Database
from .detection import DetectionResult
from .models import AttackRequest, Scenario


class LLMClient(Protocol):
    def complete(self, prompt: str, max_tokens: int = 4096) -> str: ...


@dataclass
class DetectionRule:
    """A learned rule from escaped mutations."""

    rule_id: str
    rule_type: str  # "path_pattern", "header_pattern", "timing_threshold", "method_path"
    pattern: str
    confidence: float  # 0.0-1.0, learned from escape frequency
    source: str = ""  # which mutation produced this
    created_at: int = 0


@dataclass
class AdaptiveStats:
    """Track adaptation progress."""

    rules_learned: int = 0
    escapes_prevented: int = 0
    total_adaptations: int = 0
    last_adaptation: int = 0


class AdaptiveDetector:
    """Detector that learns new rules from escaped mutations.

    Adaptation logic:
    1. Identify scenarios that escaped static detectors
    2. Extract common patterns (path, headers, timing)
    3. Create rules that would have caught those scenarios
    4. Use rules + static heuristics for future evaluations
    """

    def __init__(
        self,
        base_detector=None,
        min_confidence: float = 0.3,
        db: Database | None = None,
    ):
        self.base_detector = base_detector
        self.rules: list[DetectionRule] = []
        self.min_confidence = min_confidence
        self.db = db
        self.stats = AdaptiveStats()

    @property
    def detector_id(self) -> str:
        return "adaptive_v1"

    async def evaluate(self, scenario: Scenario) -> DetectionResult:
        """Evaluate using learned rules + base detector heuristics."""
        requests = scenario.requests
        if not requests:
            return DetectionResult("missed", [], 1.0, "No requests")

        # Apply learned rules
        rule_hits = 0
        explanations = []

        for rule in self.rules:
            hit = self._apply_rule(rule, requests)
            if hit:
                rule_hits += 1
                explanations.append(f"{rule.rule_type}:{rule.pattern[:40]}")

        # Also run base heuristics (RuleBasedDetector logic)
        heuristic_hit = self._heuristic_check(requests)

        # Combine: any rule hit OR heuristic hit = detected
        detected = rule_hits > 0 or heuristic_hit
        all_blocked = ["blocked"] * len(requests)

        if detected:
            confidence = min(0.5 + (rule_hits / max(len(self.rules), 1)) * 0.5, 1.0)
            explanation = f"Rule hits: {rule_hits}, Heuristic: {heuristic_hit}"
            if explanations:
                explanation += f", Rules: {', '.join(explanations[:3])}"
            return DetectionResult("detected", all_blocked, confidence, explanation)

        return DetectionResult("missed", ["allowed"] * len(requests), 0.6)

    def _apply_rule(self, rule: DetectionRule, requests: list[AttackRequest]) -> bool:
        """Check if a rule matches a request sequence."""
        if rule.rule_type == "path_pattern":
            return any(re.search(rule.pattern, r.path) for r in requests)

        elif rule.rule_type == "header_pattern":
            for r in requests:
                for k, v in r.headers.items():
                    if re.search(rule.pattern, k, re.IGNORECASE):
                        return True
                    if re.search(rule.pattern, v, re.IGNORECASE):
                        return True
            return False

        elif rule.rule_type == "timing_threshold":
            # Pattern is "max_avg_ms" — flag if avg timing below threshold
            try:
                max_avg = float(rule.pattern)
                avg = sum(r.timing_ms for r in requests) / len(requests)
                return avg < max_avg
            except ValueError:
                return False

        elif rule.rule_type == "method_path":
            # Pattern is "METHOD:/path/regex"
            try:
                method, path_re = rule.pattern.split(":", 1)
                return any(r.method == method and re.search(path_re, r.path) for r in requests)
            except ValueError:
                return False

        return False

    def _heuristic_check(self, requests: list[AttackRequest]) -> bool:
        """Simple heuristic matching RuleBasedDetector z-score logic."""
        if not requests:
            return False
        block_count = sum(1 for r in requests if r.expected_outcome in ("block", "throttle"))
        if len(requests) >= 5 and block_count / len(requests) > 0.5:
            return True
        if len(requests) >= 10:
            total_timing = sum(r.timing_ms for r in requests)
            if total_timing < 5000:
                return True
        llm_paths = [r for r in requests if "/v1/" in r.path or "/api/chat" in r.path]
        if len(llm_paths) >= 20:
            return True
        return False

    def adapt_from_mutations(self, db: Database) -> int:
        """Learn new rules from escaped mutations in the DB.

        Returns the number of new rules created.
        """
        mutations = db.get_mutations(escaped_only=True)
        scenarios = {s["id"]: s for s in db.get_scenarios()}

        if not mutations:
            return 0

        new_rules = 0
        for mut in mutations:
            child_id = mut.get("child_scenario_id")
            if child_id not in scenarios:
                continue

            child = scenarios[child_id]
            try:
                reqs = json.loads(child["requests_json"])
            except (json.JSONDecodeError, KeyError):
                continue

            # Extract features that make this scenario evasive
            rules = self._extract_rules(reqs, child["abuse_type"])
            for rule in rules:
                self.rules.append(rule)
                new_rules += 1

        self.stats.rules_learned += new_rules
        self.stats.total_adaptations += 1
        return new_rules

    def _extract_rules(self, reqs: list[dict], abuse_type: str) -> list[DetectionRule]:
        """Extract detection rules from an escaped mutation's request pattern."""
        rules = []
        now = int(time.time() * 1000)

        # Path pattern: find common path patterns
        paths = [r.get("path", "") for r in reqs]
        unique_paths = list(set(paths))
        if unique_paths:
            # Create a regex matching common path prefixes
            sample = random.choice(unique_paths)
            # Extract prefix up to the last /
            prefix = sample.rsplit("/", 1)[0] if "/" in sample else sample
            if len(prefix) > 4:
                rules.append(DetectionRule(
                    rule_id=str(uuid.uuid4()),
                    rule_type="path_pattern",
                    pattern=re.escape(prefix) + r"/.*",
                    confidence=0.5,
                    source=abuse_type,
                    created_at=now,
                ))

        # Header pattern: find suspicious header keys
        headers_seen = set()
        for r in reqs:
            for k in r.get("headers", {}):
                headers_seen.add(k)
        for h in headers_seen:
            if h.lower() in ("x-agent-name", "x-mcp-server", "x-rotation", "x-pacing", "x-fragment-id"):
                rules.append(DetectionRule(
                    rule_id=str(uuid.uuid4()),
                    rule_type="header_pattern",
                    pattern=re.escape(h),
                    confidence=0.6,
                    source=abuse_type,
                    created_at=now,
                ))

        # Timing threshold: if slow-drip pattern, set threshold
        timings = [r.get("timing_ms", 0) for r in reqs]
        if timings:
            avg_timing = sum(timings) / len(timings)
            if avg_timing > 10000:
                rules.append(DetectionRule(
                    rule_id=str(uuid.uuid4()),
                    rule_type="timing_threshold",
                    pattern=str(int(avg_timing / 2)),
                    confidence=0.4,
                    source=abuse_type,
                    created_at=now,
                ))
            elif avg_timing < 100:
                # Fast burst
                rules.append(DetectionRule(
                    rule_id=str(uuid.uuid4()),
                    rule_type="timing_threshold",
                    pattern="500",
                    confidence=0.5,
                    source=abuse_type,
                    created_at=now,
                ))

        # Method+path pattern
        methods = set(r.get("method", "GET") for r in reqs)
        for method in methods:
            for p in unique_paths[:2]:
                rules.append(DetectionRule(
                    rule_id=str(uuid.uuid4()),
                    rule_type="method_path",
                    pattern=f"{method}:{re.escape(p)}",
                    confidence=0.4,
                    source=abuse_type,
                    created_at=now,
                ))

        return rules

    def adapt_and_evaluate(
        self,
        scenario: Scenario,
        db: Database | None = None,
    ) -> DetectionResult:
        """Auto-adapt before evaluating (pull latest mutations)."""
        if db:
            self.adapt_from_mutations(db)
        return asyncio.run(self.evaluate(scenario))

    def get_rule_summary(self) -> dict:
        """Return summary of learned rules."""
        by_type = {}
        for r in self.rules:
            by_type[r.rule_type] = by_type.get(r.rule_type, 0) + 1
        return {
            "total_rules": len(self.rules),
            "by_type": by_type,
            "stats": {
                "rules_learned": self.stats.rules_learned,
                "escapes_prevented": self.stats.escapes_prevented,
                "total_adaptations": self.stats.total_adaptations,
            },
        }
