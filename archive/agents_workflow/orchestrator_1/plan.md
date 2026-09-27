# Project Remediation Plan (P1 + P2)

## Overview
Remediate the CTI RAG corpus poisoning vulnerability benchmark addressing Class A methodological flaws and Class B measurement instrument defects across Requirements R1 through R5.

## Phase 0: Survey & Codebase Exploration
- Launch 3 parallel Explorers / Spec Miners:
  - **Explorer 1 (`explorer_survey_eval_budget`)**: Investigate evaluation pipeline, retrieval metrics, `RetrievalResult`, `poison_target_query` propagation, background contamination, attack generation, budget scaling (1, 3, 5), and `query_echo` options.
  - **Explorer 2 (`explorer_survey_graphrag`)**: Investigate GraphRAG architecture, entity extraction, node/document namespaces, Clean Recall@5 benchmarks, topological attack generation/graph interaction, and fallback mechanisms.
  - **Explorer 3 (`specminer_survey_judge_report`)**: Investigate LLM Judge implementation (error handling, coverage rate, assertions, deduplication), reporter/visualizer (`src/visualization/reporter.py`), Pareto ranking, McNemar test, latency timing, and report generation.

## Phase 1: Global Project Specification & Feature Inventory
- Synthesize findings into `PROJECT.md`.
- Establish exact interface contracts, code layout, and feature-to-milestone mappings.

## Phase 2: Dual Track Execution
### Track A: E2E Testing Track
- Test writer dispatches for Tiers 1 to 4:
  - Tier 1: Feature Coverage (>=5 per feature)
  - Tier 2: Boundary & Corner Cases (>=5 per feature)
  - Tier 3: Cross-Feature Interactions
  - Tier 4: Real-World Application Scenarios
- Publish `TEST_READY.md`.

### Track B: Implementation Track
- Milestone 1 (R1): Targeting-Aware Evaluation & Context Contamination Separation (A1, A6)
- Milestone 2 (R2): GraphRAG Entity Extraction & Namespace Separation (A4, B4, B3)
- Milestone 3 (R3): Experimental Factor Differentiation (Budget & Separability) (A3, A5)
- Milestone 4 (R4): LLM Judge Robustness & Reliability (A8, A9, B8, B9)
- Milestone 5 (R5): Metrological Reporting Rigor, Pareto Analysis, & Statistical Correctness (A2, A10, B1, B2, B5, B10)
Each milestone follows the iteration loop: Explorer -> Worker -> Reviewers (2) -> Challengers (2) -> Auditor (Forensic) -> Gate Check.

## Phase 3: Final Integration & E2E Acceptance Pass
- Phase 1: Run 100% of E2E test suite (Tiers 1-4). Worker fixes any residual failures.
- Phase 2: Tier 5 Adversarial Coverage Hardening with Challengers.

## Phase 4: Final Victory Audit & Completion
- Verify all Acceptance Criteria from `ORIGINAL_REQUEST.md`.
- Request Sentinel victory audit.
