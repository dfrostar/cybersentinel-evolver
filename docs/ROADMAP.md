# ROADMAP — CyberSentinel Evolver

**Last updated:** 2026-07-14  
**Status:** Phase 0 → Phase 1 in progress  

---

## Phase 0: Scaffold & Database (Week 1)
- [x] Project structure
- [x] BRD / TRD / Test Plan
- [ ] pyproject.toml with dependencies
- [ ] SQLite schema creation
- [ ] Scenario, AttackRequest, TournamentResult, MutationRecord models
- [ ] Database connection + WAL mode

## Phase 1: MVP Core (Weeks 1-2)
- [ ] Attack scenario generator with embedded feeds
- [ ] Detection strategies: rule-based z-score + behavioral baseline
- [ ] Tournament runner with bootstrap CI
- [ ] Cost correlator with default cost models
- [ ] CLI: scenarios, tournament, report, lineage
- [ ] SQLite storage with audit
- [ ] 50+ tests passing

## Phase 2: Mutation Engine (Weeks 2-3)
- [ ] Mutation strategies: identity_swap, temporal, protocol, intent_preserving
- [ ] Escape rate measurement
- [ ] Lineage graph in SQLite
- [ ] Mutation correctness proofs
- [ ] 100+ tests passing

## Phase 3: Evolution Loop (Weeks 3-4)
- [ ] APScheduler-based weekly loop
- [ ] Promotion gate with CI-based advancement
- [ ] Regression detection across weeks
- [ ] Optional: direct CyberSentinel PR creation
- [ ] 150+ tests passing

## Phase 4: Production Hardening (Weeks 4-5)
- [ ] Performance benchmarks
- [ ] Fuzz testing with hypothesis
- [ ] Grafana metrics export
- [ ] Fault tolerance: detector crash isolation
- [ ] Phase 2+ test types live
- [ ] Coverage ≥ 90%

## Phase 5: External Integration (Weeks 5-7)
- [ ] Direct CyberSentinel classifier pull
- [ ] Live threat intelligence API pulls
- [ ] SNORT/Sigma/YARA export
- [ ] Multi-node swarm evolution
- [ ] SOC webhook integration

## Phase 6: Continuous Operation
- [ ] Weekly production evolution runs
- [ ] Mutation lineage review cadence
- [ ] Cost model tuning based on real deployment data
- [ ] Community detectors registry
- [ ] Security audit of evolver itself

---

## Acceptance Summary

| Phase | Signaling Success |
|-------|-------------------|
| 0 | `cs-evolver --help` exits 0 |
| 1 | `cs-evolver tournament run` produces valid TournamentResult |
| 2 | ≥ 30% escape rate on mutated scenarios |
| 3 | Week-over-week cost capture non-regressing |
| 4 | All test types green, benchmarks met |
| 5 | CyberSentinel test promotion via webhooks |
| 6 | Evolver runs in production for 30 days without manual intervention |
