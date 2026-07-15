from __future__ import annotations

from cybersentinel_evolver.self_promoter import SelfPromoter, PromptRecord


class FakeDB:
    def __init__(self):
        self.scenarios = []
        self.prompts = []

    def insert_scenario(self, s):
        self.scenarios.append(s)


def test_build_prompt_mutation_escaped():
    db = FakeDB()
    sp = SelfPromoter(db)
    prompt = sp.build_prompt("mutation_escaped", {
        "scenario_name": "cred_stuff_v1",
        "mutation_strategy": "identity_swap",
        "failure_mode": "detector tracks by IP only",
    })
    assert "cred_stuff_v1" in prompt
    assert "identity_swap" in prompt
    assert "detector tracks by IP only" in prompt


def test_build_prompt_coverage_cliff():
    db = FakeDB()
    sp = SelfPromoter(db)
    prompt = sp.build_prompt("coverage_cliff", {
        "delta": 15.3,
        "abuse_types": ["credential_stuffing", "llm_token_scraping", "billing_abuse"],
    })
    assert "15.3" in prompt
    assert "credential_stuffing" in prompt


def test_generate_without_llm_returns_empty():
    db = FakeDB()
    sp = SelfPromoter(db)
    record, parsed = sp.generate("mutation_escaped", {})
    assert isinstance(record, PromptRecord)
    assert parsed == []
    assert record.llm_response == ""


def test_extract_json_plain_array():
    db = FakeDB()
    sp = SelfPromoter(db)
    result = sp._extract_json('[{"name": "test1"}, {"name": "test2"}]')
    assert len(result) == 2
    assert result[0]["name"] == "test1"


def test_extract_json_markdown_fences():
    db = FakeDB()
    sp = SelfPromoter(db)
    raw = '```json\n[{"scenarios": [{"name": "a"}, {"name": "b"}]}]\n```'
    result = sp._extract_json(raw)
    assert len(result) == 1


def test_extract_json_invalid_returns_empty():
    db = FakeDB()
    sp = SelfPromoter(db)
    assert sp._extract_json("not json here") == []


def test_generate_with_mock_llm():
    class MockLLM:
        def complete(self, prompt, max_tokens=4096):
            return '[{"name": "auto_scenario", "abuse_type": "credential_stuffing"}]'

    db = FakeDB()
    sp = SelfPromoter(db, llm_client=MockLLM())
    record, parsed = sp.generate("mutation_escaped", {"scenario_name": "x"})
    assert record.scenarios_extracted == 1
    assert len(parsed) == 1
    assert parsed[0]["abuse_type"] == "credential_stuffing"


def test_generate_llm_error_handling():
    class FailingLLM:
        def complete(self, prompt, max_tokens=4096):
            raise RuntimeError("API timeout")

    db = FakeDB()
    sp = SelfPromoter(db, llm_client=FailingLLM())
    record, parsed = sp.generate("mutation_escaped", {})
    assert "ERROR" in record.llm_response
    assert parsed == []
