# Business Requirements Document (BRD)

**Product:** CyberSentinel Evolver  
**Parent:** CyberSentinel (API abuse prevention platform)  
**Version:** 1.0  
**Date:** 2026-07-14  

---

## 1. Problem Statement

CyberSentinel prevents API abuse for AI-native B2B SaaS vendors. Existing testing approaches are:

- Static test suites that catch regressions but don't evolve
- Manual attack scenarios that become stale as abuse patterns mutate
- No ground-truth for *cost* accuracy (we don't know if our dollar-denominated abuse reports are actually correct)

**The gap:** A self-improving testing platform that grounds its attack scenarios in real market intelligence, runs tournaments between detection strategies, and proves its ROI by measuring dollars detected vs. dollars missed — continuously evolving as abuse patterns shift (as they did in 2025, when AI-enabled adversary ops surged 89% YoY per CrowdStrike).

### Market-Driven Evidence (Why This Matters)

| Market Signal | Implication for Testing |
|-------------|------------------------|
| 99% of orgs experienced API security incidents (Salt Security 2025) | Testing must cover all 99%, not just known signatures |
| $87B annual cost of API-related incidents (Imperva/Thales) | Cost-accurate evaluation is a board-level metric |
| APIs = #1 application attack vector (Gartner) 109% rise in API attacks | Test scenarios must track the 109% attack curve, not static OWASP lists |
| Agentic AI security market: $1.65B→$13.52B at 42% CAGR | AI agent abuse scenarios must stay current with the fastest-growing threat category |
| $3.6B across top-10 agentic AI security startups (2026) | Budget for LLM-based detection is real; tournament runners compete on accuracy |

---

## 2. Product Vision

One-liner:  
*"A self-improving abuse detection testing platform that grounds itself in real attack intelligence, runs tournaments between detection strategies, and continuously mutates its scenarios — measuring success in dollars detected."*

Promise to buyer (internal: CyberSentinel product team):
1. **No stale tests** — attack scenarios mutate from real threat intelligence feeds
2. **No guessing** — tournaments pit detector-vs-detector and auto-select winner
3. **No mere precision/recall** — we measure dollars captured, not just signals flagged
4. **No drift** — continuous runs, not manual test suites
5. **No secrets** — every run is auditable, every promotion decision traceable

---

## 3. Target Buyer (Internal)

| Persona | What they need from the Evolver |
|---------|-------------------------------|
| **CyberSentinel engineering lead** | Confidence that a new detector is better than the last, in production cost terms |
| **CyberSentinel QA lead** | Continuous regression coverage across all threat signals |
| **dfrostar (executive sponsor)** | Proof point: CyberSentinel Evolver costs less than a single breach prevented |
| **CyberSentinel SOC analyst** | New abuse signals generated before attackers ship them |
| **Future enterprise buyer** | Demonstrable SOTA detection, tested against evolving abuse intelligence |

---

## 4. Scope

### In Scope (MVP)

| ID | Feature | Priority | Acceptance Criteria |
|----|---------|----------|-------------------|
| **E1** | Research-grounded attack scenario generator | P0 | ≥ 12 distinct abuse scenarios derived from Wallarm ThreatStats 2026, Salt Security 2025, and CrowdStrike 2026 threat reports |
| **E2** | LLM-judge tournament runner | P0 | Compete 3+ detection strategies (rule-based z-score, behavioral baseline, LLM-judge) on same scenarios; output winner with p<0.05 confidence |
| **E3** | Mutation engine | P0 | Given a detector that catches scenario X, generate N mutated scenarios that evict the detector's assumptions; ≥ 30% mutation escape rate |
| **E4** | Cost-correlator | P1 | Every scenario carries a dollar-cost tuple; evaluate against baseline cost of $87B/year global API security incident value normalized per-request |
| **E5** | Continuous evolution loop (cron-scheduled) | P1 | Weekly automated: detect regressions, mutate surviving scenarios, run tournament, optionally promote |
| **E6** | Self-hosted SQLite storage | P0 | All runs, mutations, results persisted; no external dependencies; zero network calls during detection |

### Out of Scope (Future Phases)

| ID | Feature | When |
|----|---------|------|
| **O1** | Cloud-hosted multi-tenant Evolver SaaS | Phase 5+ |
| **O2** | External threat intelligence feed live-pull | Phase 4 |
| **O3** | Snort/Sigma/YARA export | Phase 4 |
| **O4** | Grafana dashboard for cost metrics | Phase 3 |
| **O5** | Direct CyberSentinel PR creation for promoted detectors | Phase 3 |

---

## 5. Functional Requirements

### 5.1 Attack Scenario Generator

- Produces realistic abuse traffic: credential stuffing (10 variants), shadow-agent impersonation (8 variants), LLM token scraping (6 variants), billing abuse (5 variants), MCP server abuse (4 variants), prompt injection bypass (4 variants), rate limit evasion via distributed agents (4 variants)
- Each scenario is a replayable request sequence with metadata: identity-source, cost-model, temporal pattern, mutation-difficulty
- Scenarios persisted and versioned

### 5.2 Tournament Runner

- Input: candidate detector, N scenarios
- Output: win/loss rate, cost capture %, false-positive rate, confidence (bootstrap CI)
- Supports detectors as: Python module, CLI binary, HTTP endpoint
- Pluggable LLM-judge (Claude-or-local) as optional meta-judge for ambiguous cases

### 5.3 Mutation Engine

- For each surviving scenario (not detected with 100% accuracy):
  - Swap identity source (IP → user-agent → JWT-claim spoof)
  - Temporal mutation (burst → slow-drip → diurnal shift)
  - Protocol mutation (GET→POST, header reorder, payload fragment)
  - Intent-preserving (attack achieves same goal) or simulating-detected (attack morphs)
- Minimum 3 mutants per parent; configurable depth
- Stops when: all mutations detected OR mutation-depth cap reached

### 5.4 Cost-Correlator

- Normalize global API incident cost ($87B) to per-request-model based on: endpoint type, LLM token count, bandwidth, compute
- Track: $ cost blocked, $ cost missed, net savings over tournament

### 5.5 Storage & Audit

- SQLite (embedded) with audit log of every run
- Tournament history, mutation lineage, promotion decisions
- Queryable for: "show me detectors that regressed in coverage last week"

---

## 6. Non-Functional Requirements

| # | Requirement | Target |
|---|------------|--------|
| **N1** | Runner throughput | ≥ 500 scenarios/sec (local) |
| **N2** | Tournament runtime | ≤ 60 sec for 500 scenarios × 3 detectors |
| **N3** | Storage | ≤ 100 MB/month of evolution history at default config |
| **N4** | LLM judge latency | Optional; ≤ 10 sec/scenario (background only) |
| **N5** | Idempotency | Scenario hashes detect duplicate-avoidance at mutation creation |
| **N6** | Reproducibility | All mutations deterministic from seed + scenario-id |
| **N7** | Extensibility | New detectors drop-in as Python module |
| **N8** | Observability | Structured logs (JSON), evolution dashboards (Phase 3) |

---

## 7. Acceptance Criteria (BRD Sign-Off)

- [ ] 12+ distinct attack scenarios generated, tagged with source intelligence feed
- [ ] Tournament runner compares 3 strategies on same scenarios with p<0.05 confidence
- [ ] Mutation engine produces ≥ 3 mutants/parent with escape rate ≥ 30%
- [ ] Cost-correlator outputs $ value blocked / missed per detection strategy
- [ ] Cron-scheduled weekly evolution loop runs end-to-end
- [ ] All results persisted to SQLite with full audit lineage
- [ ] Repo: `dfrostar/cybersentinel-evolver` with MIT license
