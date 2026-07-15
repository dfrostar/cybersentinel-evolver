# Technical Requirements Document (TRD)

**Product:** CyberSentinel Evolver  
**Version:** 1.0  
**Date:** 2026-07-14  

---

## 1. Architecture Overview

### 1.1 System Context

```
┌──────────────────────────────────────────────────────────────────┐
│                  CYBERSENTINEL EVOLVER                            │
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐    │
│  │ Attack      │───►│ Tournament   │───►│ Mutation Engine  │    │
│  │ Generator   │    │ Runner       │    │                  │    │
│  └─────┬───────┘    └──────┬───────┘    └────────┬─────────┘    │
│        │                   │                     │               │
│        ▼                   ▼                     ▼               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Evolution Loop                         │   │
│  │                     (cron scheduler)                      │   │
│  └──────────────────────────┬───────────────────────────────┘   │
│                             │                                    │
│  ┌─────────────┐            ▼            ┌──────────────────┐   │
│  │ Cost        │───► SQLite ◄──────────│ Detection        │   │
│  │ Correlator  │     Storage           │ Strategies      │   │
│  └─────────────┘                        │ (pluggable)     │   │
│                                         └──────────────────┘   │
│                                                                  │
│     ┌──────────────────────────────────────────────────────┐    │
│     │ Optional: Claude LLM Judge (background, for ambiguous) │    │
│     └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Breakdown

| Component | Technology | Responsibility |
|-----------|-----------|----------------|
| **Attack Generator** | Python 3.12, scenario library | Synthesizes attack requests from research-grounded templates |
| **Tournament Runner** | Python 3.12, asyncio | Runs detector-vs-scenario, tracks win rate and cost capture |
| **Mutation Engine** | Python 3.12, hash-based seeding | Produces children of surviving scenarios |
| **Cost Correlator** | Python 3.12, cost model tables | Maps blocked/missed requests to $ values |
| **Evolution Loop** | CronJob (systemd) or APScheduler | Weekly cycle: detect → mutate → run → record |
| **SQLite Storage** | sqlite3 (stdlib) | All runs, mutations, results |
| **Detection Strategies** | Python module API | Pluggable: rule-based z-score, behavioral baseline, LLM-judge |
| **Claude Judge (optional)** | Anthropic SDK | Background adjudication of ambiguous scenarios |

### 1.3 Data Model

#### Scenario
```python
@dataclass
class Scenario:
    id: str                          # UUID4
    parent_id: str | None            # None for research-born
    name: str                        # "credential_stuffing_oauth_rotation"
    source_feed: str                 # "wallarm-threatstats-2026"
    abuse_type: AbuseType            # enum: credential_stuffing, agent_impersonation, ...
    cost_model: CostModel            # per-request dollar weight
    identity_source: IdentityType     # ip, jwt_claim, user_agent, mcp_agent_name
    mutation_depth: int = 0
    generation: int = 0
    created_at: int                  # epoch ms
    requests: list[AttackRequest]    # ordered sequence
```

#### AttackRequest
```python
@dataclass
class AttackRequest:
    method: "GET" | "POST" | "PUT" | "DELETE"
    path: str
    headers: dict[str, str]
    body_b64: str | None
    expected_outcome: "allow" | "block" | "throttle" | "challenge"
    timing_ms: int                   # delay from previous request
```

#### TournamentResult
```python
@dataclass
class TournamentResult:
    run_id: str                      # UUID4
    detector_id: str
    scenario_count: int
    detected_count: int
    false_positive_count: int
    cost_blocked: float              # USD
    cost_missed: float               # USD
    cost_model: str                  # label of cost model used
    win_rate: float                  # 0.0-1.0
    confidence_low: float            # bootstrap CI
    confidence_high: float
    ran_at: int                      # epoch ms
```

#### MutationRecord
```python
@dataclass
class MutationRecord:
    mutation_id: str
    parent_scenario_id: str
    child_scenario_id: str
    strategy: MutationStrategy       # identity_swap | temporal | protocol | intent_preserving
    depth: int
    escaped: bool                    # true if detector failed to catch
    created_at: int
```

### 1.4 Strategy API

New detectors implement:

```python
class DetectionStrategy(ABC):
    @abstractmethod
    async def evaluate(self, scenario: Scenario) -> DetectionResult:
        """Return per-request outcomes and overall verdict."""
        ...

@dataclass
class DetectionResult:
    verdict: "detected" | "missed" | "ambiguous"
    per_request: list["blocked" | "allowed"]
    confidence: float = 1.0
    explanation: str | None = None
```

### 1.5 Tournament

```python
async def run_tournament(
    detectors: list[DetectionStrategy],
    scenarios: list[Scenario],
    cost_models: dict[str, CostModel],
) -> TournamentResult:
    """Run N scenarios through each detector, score, bootstrap CI."""
    ...
```

### 1.6 Mutation Algorithm

For each scenario where a detector's `win_rate == 1.0` (fully caught):
1. Generate `M` mutants (default `M=3`), each using a different `MutationStrategy`
2. Run detector against all mutants
3. Collect escaped mutants (detector missed)
4. Recurse up to `mutation_depth_cap` (default `= 3`)
5. Store lineage as graph in SQLite

### 1.7 Cost Model

```python
@dataclass
class CostModel:
    label: str                       # "llm-token-abuse-default"
    per_request_base: float          # USD cost per request for THIS abuse type
    per_1k_requests: float           # volume-scaled cost
    source_notes: str                # "Derived from $87B global estimate / annual API req count"
```

Default cost models:

| Model | Base per 1K req | Derived from |
|-------|-----------------|-------------|
| `credential-stuffing` | $0.12 | Auth-service compute + rate-limit mitigation cost |
| `llm-token-scraping` | $4.80 | OpenAI GPT-4o-mini input $0.15/1M tokens × avg 32K tokens/req |
| `billing-abuse` | $1.20 | Compute + payment processing fee |
| `mcp-server-abuse` | $0.45 | Tool-call compute cost estimate |

---

## 2. API Design

### 2.1 CLI

```bash
# Generate scenarios from research feeds
cs-evolver scenarios generate --feed wallarm-threatstats-2026

# Run a tournament
cs-evolver tournament run --detectors rule_based,behavioral,llm_judge --scenarios all

# Evolve: mutate survivors and re-run
cs-evolver evolve --weeks 1 --auto-promote

# Report: weekly cost-captured summary
cs-evolver report --format json --since "2026-07-01"

# Mutation lineage inspection
cs-evolver lineage show --scenario <uuid>
```

### 2.2 Python API

```python
from cybersentinel_evolver import Database, TournamentRunner, EvolutionLoop

db = Database("~/cybersentinel-evolver/data.db")
runner = TournamentRunner(db)
result = await runner.run(detectors=[RuleBased()], scenarios=db.scenarios.all())
print(result.cost_blocked)
```

---

## 3. Threat Intelligence Grounding

All research feeds are embedded in `src/attacks/feeds/` as structured data, cited:

| Feed | Scenarios Derived From | Source |
|------|----------------------|--------|
| wallarm-threatstats-2026 | Top 10 AI-vulnerability up 398% | wallarm.com |
| salt-security-2025 | 99% org incidents, 52% broken auth, 59% unauth vulns | salt.security |
| crowdstrike-2026-ai | AI-enabled adversary ops +89% YoY | crowdstrike.com |
| cisa-known-exploited | API-related CVE additions | cisa.gov |
| imperva-thales-2025 | $87B annual cost, shadow APIs 30-40% of footprint | imperva.com |
| owasp-api-top-10 | Classic API threat model | owasp.org |

---

## 4. Module Structure

```
cybersentinel-evolver/
├── src/
│   └── cybersentinel_evolver/
│       ├── __init__.py
│       ├── cli.py                 # CLI entry
│       ├── config.py              # Settings, cost models
│       ├── database.py            # SQLite layer
│       ├── main.py                # Evolver orchestration
│       ├── evolution/
│       │   ├── __init__.py
│       │   ├── engine.py          # Evolution loop
│       │   ├── scheduler.py       # APScheduler wrapper
│       │   └── metrics.py         # Aggregate metrics
│       ├── attacks/
│       │   ├── __init__.py
│       │   ├── generator.py       # Scenario synthesis
│       │   ├── scenarios.py       # Scenario data classes
│       │   ├── mutations.py       # Mutation strategies
│       │   ├── identity.py        # Identity-source swapper
│       │   ├── timing.py          # Temporal mutator
│       │   └── feeds/             # Embedded threat feeds
│       │       └── wallarm-threatstats-2026.json
│       ├── detection/
│       │   ├── __init__.py
│       │   ├── strategies.py      # DetectionStrategy ABC
│       │   ├── rule_based.py      # Z-score baseline
│       │   ├── behavioral.py      # Behavioral baseline
│       │   ├── judge.py           # LLM-judge wrapper
│       │   └── tournament.py      # Tournament runner + bootstrap CI
│       ├── cost/
│       │   ├── __init__.py
│       │   ├── correlator.py      # Cost normalization
│       │   ├── models.py          # CostModel definitions
│       │   └── report.py          # $ cost summary
│       └── storage/
│           ├── __init__.py
│           ├── schema.py          # Table definitions
│           └── repository.py      # CRUD layer
├── docs/
│   ├── BRD.md
│   ├── TRD.md
│   ├── TEST_PLAN.md
│   └── ROADMAP.md
├── tests/
│   ├── test_scenarios.py
│   ├── test_tournament.py
│   ├── test_mutations.py
│   ├── test_cost.py
│   └── test_evolution_loop.py
├── pyproject.toml
├── LICENSE (MIT)
└── README.md
```

---

## 5. Non-Functional Requirements

### 5.1 Performance

| Metric | Target | Measured At |
|--------|--------|------------|
| Scenario generation | ≥ 100/sec | Cold start |
| Tournament throughput | ≥ 500 scenarios/sec | Local |
| Mutation throughput | ≥ 50 mutations/sec | Local |
| LLM-judge throughput | Optional, ≤ 10 sec/req | Background |
| Weekly evolution runtime | ≤ 10 minutes | Cron end-to-end |

### 5.2 Reliability

- SQLite WAL mode for concurrent read during mutation
- Tournament interrupted mid-run safely committed (append-only)
- Scenarios immutable once created; mutations children only
- Zero network calls in default operation (no data leaves the host)

### 5.3 Security

- No raw attack payloads transmitted (detectors never see raw mutation bytes, only abstracted `AttackRequest`)
- Cost model values configurable per-deployment
- Optional LLM-judge API key via env var only (not stored locally)

### 5.4 Observability

- Structured JSON logs to stderr
- Prometheus metrics (Phase 3)
- Audit log in SQLite: every scenario creation, mutation, tournament result

---

## 6. Decision Log

| Decision | Rationale | Status |
|----------|-----------|--------|
| Python over Rust/Go | Maximize iteration speed; existing venv; Fast path later if needed | Accepted |
| SQLite over Postgres | Zero external dep; encryption-at-rest; single-node is sufficient for MVP | Accepted |
| APScheduler over cron direct | Survives restarts, supports backfill | Accepted |
| Cost in USD not abstract units | Buyer cares about dollars; derive from published research | Accepted |
| Claude-judge as background only | Avoids API dependency in critical path | Accepted |
| Public feeds from 2024-2025 published 2026 | Most recent available; 2026 year-end reports not yet out | Accepted |

---

## 7. Out of Scope

- Real CyberSentinel integration (direct promotion PR) — Phase 3+
- Real-time alerting on detected regression — Phase 3+
- Multi-node evolution (swarm tournament) — Phase 4+
- Direct pull from threat intelligence APIs — Phase 4+
- SNORT/Sigma rule export — Phase 4+
- Model-training (supervised fine-tuner for abuse) — Phase 5+
