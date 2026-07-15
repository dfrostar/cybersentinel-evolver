# Comprehensive Test Plan

**Product:** CyberSentinel Evolver  
**Version:** 1.0  
**Date:** 2026-07-14  

---

## 1. Test Strategy Overview

### 1.1 Test Levels

```
┌────────────────────────────────────────────────────────────────────┐
│  Level 5: Acceptance    ► Full evolution loop end-to-end            │
│  Level 4: Integration   ► Generator + Tournament + Mutation + Cost  │
│  Level 3: Tournament    ► Detector vs scenario at scale             │
│  Level 2: Component     ► Individual modules in isolation           │
│  Level 1: Unit          ► Pure functions, classes, methods           │
└────────────────────────────────────────────────────────────────────┘
```

### 1.2 Test Types

| Type | Scope | Tooling | Status |
|------|-------|---------|--------|
| **Unit** | Functions, classes, pure logic | pytest 9+ | **MVP — Level 1** |
| **Generator** | Scenario synthesis correctness | pytest + snapshot | **MVP — Level 2** |
| **Tournament** | CI, win rate accuracy | pytest + synthetic | **MVP — Level 2** |
| **Mutation** | Escape rate, lineage | pytest + mutation harness | **MVP — Level 2** |
| **Cost** | Cost normalization accuracy | pytest + reference fixtures | **MVP — Level 2** |
| **Evolution loop** | Full cron-like run | pytest + APScheduler mock | **MVP — Level 4** |
| **CLI** | End-to-end command invocation | subprocess + pexpect-style | **MVP — Level 5** |
| **Performance** | Throughput regressions | pytest-benchmark | **Phase 2** |
| **Fuzz** | Random scenario / detector combos | hypothesis | **Phase 2** |
| **Regression detector** | "Did week N+1 do worse than week N?" | sqlite-diff | **Phase 3** |

---

## 2. Unit Tests (Level 1)

### 2.1 AttackRequest Serialization

| ID | Test | Input | Expected |
|----|------|-------|----------|
| AR-U-001 | Serialize normal request | GET /api/health, no body | Round-trips through JSON |
| AR-U-002 | Encode binary body | POST /api, bytes=b"\x00\xff" | base64 encode/decode round-trips |
| AR-U-003 | Zero-timing preserved | timing_ms=0 | Valid (no negative guard needed) |
| AR-U-004 | Max path length | path="/" + "x"*2048 | Stored as-is |

### 2.2 Scenario Data Class

| ID | Test | Input | Expected |
|----|------|-------|----------|
| SC-U-001 | Create with no parent | name="test", abuse_type=credential_stuffing | parent_id=None, generation=0 |
| SC-U-002 | Create with parent | parent_id=<uuid> | generation=parent.generation+1 |
| SC-U-003 | Hash stability | Two identical scenarios produce same hash | Deterministic |
| SC-U-004 | Empty requests | requests=[] | Valid (empty scenario = meta-only) |

### 2.3 TournamentResult Math

| ID | Test | Input | Expected |
|----|------|-------|----------|
| TR-U-001 | Win rate calc | detected=90, scenarios=100 | win_rate=0.9 |
| TR-U-002 | Cost blocked | per_scenario=$0.12, detected=90 | cost_blocked=$10.80 |
| TR-U-003 | Missed cost | per_scenario=$4.80, missed=10 | cost_missed=$48.00 |
| TR-U-004 | CI bounds | win_rate=0.5, n=100 | CI_low<0.5<CI_high |
| TR-U-005 | Perfect score | detected=scenarios | win_rate=1.0 |
| TR-U-006 | Zero score | detected=0 | win_rate=0.0 |

### 2.4 Cost Model Lookup

| ID | Test | Input | Expected |
|----|------|-------|----------|
| CM-U-001 | LLM token scrap | abuse_type=llm_token_scraping | per_1k_requests=$4.80 |
| CM-U-002 | Credential stuffing | abuse_type=credential_stuffing | per_1k_requests=$0.12 |
| CM-U-003 | Unknown abuse type | abuse_type="unknown" | Falls back to default model |

---

## 3. Generator Tests (Level 2)

### 3.1 Scenario Generation

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| GN-C-001 | Generate all 12 | Feed="all" | 12+ distinct scenarios |
| GN-C-002 | Source attribution | Scenario from wallarm feed | source_feed="wallarm-threatstats-2026" |
| GN-C-003 | Abuse type coverage | Generate all | Every AbuseType present ≥1 |
| GN-C-004 | Tournament linkage | Generate then run tournament | TournamentResult rows created |
| GN-C-005 | Deterministic from seed | Same seed → same scenarios | Hash match |
| GN-C-006 | No duplicates | Generate 100x, dedupe | Unique scenario count stable |

### 3.2 Attack Request Patterns

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| AR-C-001 | Credential stuffing rate | Examine attack requests | Burst ≥10 req in ≤60s window |
| AR-C-002 | Agent impersonation | Headers include "X-Agent" | JWT agent claim present |
| AR-C-003 | Token scraping | Path pattern | Matches known LLM endpoint patterns |

---

## 4. Tournament Tests (Level 3)

### 4.1 Tournament Runner

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| TM-T-001 | Single detector, single scenario | Run | 1 TournamentResult row |
| TM-T-002 | 3 detectors, 50 scenarios | Run | 3 TournamentResult rows |
| TM-T-003 | Perfect detector | All scenarios caught | win_rate=1.0 |
| TM-T-004 | Random detector | Coin-flip detector | win_rate≈0.5, CI includes 0.5 |
| TM-T-005 | Time budget halt | 1000 scenarios, budget=5s | Partial results committed |
| TM-T-006 | Detector crash isolation | Detector raises mid-run | Other detectors unaffected |

### 4.2 Bootstrap CI

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| CI-T-001 | High sample narrows CI | n=10000, win_rate=0.9 | CI width < 0.05 |
| CI-T-002 | Low sample widens CI | n=10 | CI width > 0.20 |
| CI-T-003 | p<0.05 separation | Detector A=0.9, Detector B=0.5 | CI non-overlapping |

### 4.3 Detection Strategies

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| DS-T-001 | Rule-based z-score | Credential stuffing scenario | Detected |
| DS-T-002 | Behavioral baseline | Slow-drift attack (10%/hr) | NOT detected |
| DS-T-003 | LLM-judge (mocked) | Ambiguous scenario | Calls judge API ≤1 |

---

## 5. Mutation Tests (Level 2–3)

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| MU-M-001 | Single mutation | Mutate a caught scenario | ≥1 child produced |
| MU-M-002 | 3 mutants per parent | parent=perfectly caught | 3 children |
| MU-M-003 | Escape rate ≥30% | Tournament over mutations | ≥30% of mutants escape detector |
| MU-M-004 | Depth cap respected | depth_cap=2 | No mutations beyond depth 2 |
| MU-M-005 | Lineage traceable | Mutate child → grandchild | Path reconstructible |
| MU-M-006 | Determinism | Same seed + parent → same children | Hash match |
| MU-M-007 | Identity swap mutator | Mutate agent-impersonation | JWT claim → user-agent switch |
| MU-M-008 | Temporal mutator | Burst → slow-drip | Inter-request time increased ≥10x |
| MU-M-009 | Protocol mutator | GET → POST | Method changed, outcome preserved |
| MU-M-010 | Child detection | Tournament on children | New TournamentResult rows |

---

## 6. Cost Correlator Tests (Level 2)

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| CC-C-001 | Zero cost for no blocked | detected=0 | cost_blocked=$0.00 |
| CC-C-002 | Simple multiplication | 1000 req × $4.80/1K | cost_blocked=$4.80 |
| CC-C-003 | Mixed abuse types | Tournament across all types | Sums across cost models |
| CC-C-004 | Missed cost complement | 90% win rate | cost_missed = 10% of total |
| CC-C-005 | Custom deployment cost model | Configured per-deployment | Overrides default |
| CC-C-006 | Report output | CLI report | Valid JSON, fields match TournamentResult |

---

## 7. Evolution Loop Tests (Level 4)

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| EL-I-001 | Full dry run | Run 1 "week" | All 4 steps run, no errors |
| EL-I-002 | Surviving scenario mutation | Detector catches 80% | Mutations only on 80% |
| EL-I-003 | Promotion gate | Detector A > B by CI | A promoted to production |
| EL-I-004 | No regression detected | Week N+1 = Week N | No action taken |
| EL-I-005 | Regression triggers alert | Week N+1 costs more | Alert logged |
| EL-I-006 | Storage durability | Restart after crash | Results persisted |
| EL-I-007 | Concurrency safety | Two loop instances | WAL mode prevents corruption |

---

## 8. CLI Tests (Level 5)

| ID | Test | Steps | Expected |
|------|------|-------|----------|
| CL-E-001 | `--help` | cs-evolver --help | Exit 0, usage printed |
| CL-E-002 | `scenarios generate` | With `--feed all` | 12+ scenarios in DB |
| CL-E-003 | `tournament run` | With `--detectors rule_based` | 1 result row |
| CL-E-004 | `evolve` (1 week) | Run | Audit log has entries |
| CL-E-005 | `report` | `--format json` | Valid JSON, non-empty |
| CL-E-006 | `lineage show` | `--scenario <uuid>` | Depth, parent, strategy |
| CL-E-007 | Missing detector error | `--detectors nonexistent` | Helpful error message |
| CL-E-008 | Corrupt DB recovery | Empty file | Informs user, recreates |

---

## 9. Performance Tests (Phase 2)

| Metric | Tool | Target | Alert Below |
|--------|------|--------|------------|
| Scenario gen | pytest-benchmark | ≥ 100/sec | 80 |
| Tournament 500×3 | pytest-benchmark | 30 sec wall | 45 |
| Evolution 1 week | pytest-benchmark | 10 min | 15 |

---

## 10. Coverage Requirements

| Phase | Line Coverage | Branch Coverage |
|-------|---------------|-----------------|
| MVP (Phase 1) | 80% | 70% |
| Phase 2 | 85% | 75% |
| Phase 3+ | 90% | 80% |

Measured via `pytest --cov`, enforced in CI.

---

## 11. Test Data & Fixtures

| Fixture | Source |
|---------|--------|
| `fixtures/attack-request-1k.json` | Synthetic, generated by generator |
| `fixtures/tournament-result-sample.json` | From a reference run |
| `fixtures/lineage-tree-sample.json` | 3 generations deep |
| `fixtures/cost-model-defaults.json` | In `src/cost/models.py` |

---

## 12. Definition of Done

For any PR to `main`:

- [ ] All unit tests pass
- [ ] All component tests pass
- [ ] CLI smoke tests pass (exit 0)
- [ ] Phase-appropriate coverage met
- [ ] No lint errors (`ruff check`)
- [ ] No type errors (`mypy --strict`)
- [ ] No regression in evolution benchmarks
- [ ] Documentation updated for changed components
- [ ] PR description includes: what changed, what was tested, risk assessment

For a release:

- [ ] All of the above
- [ ] Full evolution loop end-to-end smoke test on staging
- [ ] Benchmark regression <5%
- [ ] Zero S1/S2 bugs open
- [ ] Release notes include: new scenarios covered, new detectors added, cost models updated
- [ ] QA sign-off in `docs/RELEASE_CHECKLIST.md`

---

## 13. Environments

| Environment | Purpose | Tooling |
|-------------|---------|---------|
| Local | Developer testing | pytest in venv |
| CI | GitHub Actions | Standard OSS tier |
| Staging | Weekly evolution dry-run | Docker image |

---

## 14. CI Pipeline

```yaml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e ".[dev]"
      - run: ruff check src tests
      - run: mypy --strict src
      - run: pytest --cov=src --cov-report=term-missing
      - run: pytest --cov-fail-under=80
```
