"""Self-Promoter — LLM writes new scenarios from gap analysis.

Two modes:
1. LLM-backed (requires API key, writes real prompts)
2. Template-only (no external calls, always safe for tests) — default
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Protocol


class LLMClient(Protocol):
    def complete(self, prompt: str, max_tokens: int = 4096) -> str: ...


@dataclass
class PromptRecord:
    id: str
    trigger_type: str
    prompt_text: str
    llm_response: str
    scenarios_extracted: int
    accepted: bool | None
    created_at: int

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "trigger_type": self.trigger_type,
            "prompt_text": self.prompt_text,
            "llm_response": self.llm_response,
            "scenarios_extracted": self.scenarios_extracted,
            "accepted": self.accepted,
            "created_at": self.created_at,
        }


class SelfPromoter:
    """Write LLM prompts from gap analysis; parse response into Scenario objects."""

    PROMPT_TEMPLATES = {
        "mutation_escaped": (
            "A mutation escaped detection.\n"
            "Scenario: {scenario_name}\n"
            "Mutation strategy: {mutation_strategy}\n"
            "Detection gap: {failure_mode}\n\n"
            "Write 3 new attack scenarios (as JSON array) that exploit this same gap. "
            "Each must have: name, abuse_type, identity_source, "
            "requests (list of {{method, path, headers, expected_outcome, timing_ms}})"
        ),
        "coverage_cliff": (
            "Detection win-rate dropped {delta}% in the last tournament.\n"
            "Top 3 abuse types by cost-missed: {abuse_types}\n\n"
            "Generate 5 scenarios targeting the detection gap. "
            "Output JSON array with same schema."
        ),
        "tournament_tie": (
            "No tournament winner with p<0.05 between: {detectors}\n"
            "Shared failure modes: {failure_modes}\n\n"
            "Synthesize 3 discriminator scenarios. Output JSON array."
        ),
        "feed_update": (
            "New threat feed update: {feed_description}\n\n"
            "Produce 5 detection-grounded scenarios for the new patterns. "
            "Output JSON array."
        ),
    }

    def __init__(
        self,
        db,
        llm_client: LLMClient | None = None,
    ):
        self.db = db
        self.llm = llm_client

    def build_prompt(self, trigger: str, context: dict) -> str:
        template = self.PROMPT_TEMPLATES.get(trigger, self.PROMPT_TEMPLATES["mutation_escaped"])
        # Apply defaults for missing keys
        defaults = {
            "scenario_name": "UNKNOWN",
            "mutation_strategy": "UNKNOWN",
            "failure_mode": "UNKNOWN",
            "delta": 0,
            "abuse_types": [],
            "detectors": "",
            "failure_modes": "",
            "feed_description": "GENERIC",
        }
        merged = {**defaults, **context}
        return template.format(**merged)

    def generate(
        self,
        trigger_type: str,
        context: dict,
    ) -> tuple[PromptRecord, list[dict]]:
        """Generate prompt, optionally call LLM, parse response into scenarios.

        Returns (prompt_record, parsed_scenarios).
        """
        prompt_text = self.build_prompt(trigger_type, context)
        record = PromptRecord(
            id=str(uuid.uuid4()),
            trigger_type=trigger_type,
            prompt_text=prompt_text,
            llm_response="",
            scenarios_extracted=0,
            accepted=None,
            created_at=0,
        )

        if self.llm is None:
            return record, []

        try:
            raw = self.llm.complete(prompt_text)
            record.llm_response = raw
            parsed = self._extract_json(raw)
            record.scenarios_extracted = len(parsed)
            record.accepted = len(parsed) > 0
            return record, parsed
        except Exception as e:
            record.llm_response = f"ERROR: {e}"
            return record, []

    def _extract_json(self, raw: str) -> list[dict]:
        """Parse JSON array from LLM response, tolerant of markdown fences."""
        if "```" in raw:
            parts = raw.split("```")
            for p in parts:
                p = p.strip()
                if p.startswith("json"):
                    p = p[4:].strip()
                if p.startswith("["):
                    raw = p
                    break
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("scenarios", data.get("attacks", []))
        except json.JSONDecodeError:
            pass
        return []
