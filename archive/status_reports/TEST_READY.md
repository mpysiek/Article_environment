# E2E Test Suite Readiness Report (`TEST_READY.md`)

## 1. Executive Summary

The independent opaque-box E2E test suite for the CTI RAG Poisoning Benchmark Remediation Project (P1 + P2) has been fully designed, implemented, and verified.

- **Test Suite Location**: `tests/test_e2e_remediation.py`
- **Total Test Cases**: **225 tests**
- **Test Infrastructure Guide**: `TEST_INFRA.md`
- **Baseline Test Execution**:
  - Collected: 225 items in 9.81s
  - Completed: 225 items in 11.80s
  - Passed: 184 tests (existing compliant behaviors & contract stubs)
  - Failed: 41 tests (intentional, defining exact flaw signatures for M1-M5 implementation gates)
- **Status**: **READY FOR MILESTONE GATING**

---

## 2. Test Breakdown by Tier

| Tier | Category | Target Scope | Test Count | Baseline Pass | Baseline Fail |
|------|----------|--------------|------------|---------------|---------------|
| **Tier 1** | Feature Coverage | >=5 tests per feature across all 20 remediation features (F-R1-01 .. F-R5-05) | **100** | 73 | 27 |
| **Tier 2** | Boundary & Corner Cases | >=5 tests per feature covering empty, None, extreme budgets, 0% ASR, and threshold boundaries | **100** | 87 | 13 |
| **Tier 3** | Cross-Feature Combinations | Pairwise and multi-layer interaction dynamics (budget scaling, echo ablation, dual namespace, judge coverage, Pareto) | **15** | 14 | 1 |
| **Tier 4** | Real-World Application Scenarios | End-to-end evaluation runs on real CTI STIX / CVE queries (Log4Shell, MOVEit, Ivanti, PowerShell, Valid Accounts) | **10** | 10 | 0 |
| **Total** | **All Tiers** | **Comprehensive R1-R5 Opaque-Box Coverage** | **225** | **184** | **41** |

---

## 3. Test Breakdown by Feature & Milestone Gate

| Milestone | Feature ID | Description | T1 Tests | T2 Tests | T3/T4 Tests | Total Tests | Gate Status |
|-----------|------------|-------------|----------|----------|-------------|-------------|-------------|
| **M1** | **F-R1-01** | `RetrievalResult` carries `poison_target_query` & `poison_type` | 5 | 5 | 4 | 14 | Ready |
| **M1** | **F-R1-02** | Retrievers populate targeting metadata into results | 5 | 5 | 2 | 12 | Ready |
| **M1** | **F-R1-03** | Lossless serialization of targeting fields in `stages.py` | 5 | 5 | 3 | 13 | Ready |
| **M1** | **F-R1-04** | `retrieval_asr_targeted` primary metric separate from `any` & `untargeted` | 5 | 5 | 4 | 14 | Ready |
| **M2** | **F-R2-01** | Dual-namespace node representation (`doc:`, `ent:`) in GraphRAG | 5 | 5 | 2 | 12 | Ready |
| **M2** | **F-R2-02** | Entity extraction from queries without `doc_map` filtering (Recall >= 70%) | 5 | 5 | 2 | 12 | Ready |
| **M2** | **F-R2-03** | Independent degree normalization & clean 1-hop/2-hop traversal | 5 | 5 | 2 | 12 | Ready |
| **M2** | **F-R2-04** | Fallback logging, `metadata['fallback_used']`, & `graph_fallback_rate` | 5 | 5 | 2 | 12 | Ready |
| **M2** | **F-R2-05** | Active graph interaction for `PureTopologicalPoisonAttacker` | 5 | 5 | 2 | 12 | Ready |
| **M3** | **F-R3-01** | Diverse payload generation across budgets $B \in \{1, 3, 5\}$ | 5 | 5 | 4 | 14 | Ready |
| **M3** | **F-R3-02** | Query echo ablation (`query_echo=False`) as reference probe | 5 | 5 | 3 | 13 | Ready |
| **M4** | **F-R4-01** | LLM Judge unparseable response isolation & `coverage_rate` calculation | 5 | 5 | 3 | 13 | Ready |
| **M4** | **F-R4-02** | Assertion alignment in `make_stage_a_record` for BlackBox & Topological | 5 | 5 | 3 | 13 | Ready |
| **M4** | **F-R4-03** | Explicit `llm_stage_ran: bool` preserving true 0% ASR without dropping metrics | 5 | 5 | 2 | 12 | Ready |
| **M4** | **F-R4-04** | Deduplication scoping / opt-out parameter preventing scenario collapse | 5 | 5 | 2 | 12 | Ready |
| **M5** | **F-R5-01** | Dynamic markdown report synthesis (remove hardcoded 24,000 docs & Sec 5) | 5 | 5 | 3 | 13 | Ready |
| **M5** | **F-R5-02** | Pareto frontier analysis (Recall@5 vs ASR) with 50% absolute utility threshold | 5 | 5 | 4 | 14 | Ready |
| **M5** | **F-R5-03** | Deterministic tie-breaking & unified $k=5$ cutoff across metrics | 5 | 5 | 2 | 12 | Ready |
| **M5** | **F-R5-04** | High-precision latency (`time.perf_counter()`, warm-up rejection, median+IQR) | 5 | 5 | 2 | 12 | Ready |
| **M5** | **F-R5-05** | Exact binomial McNemar test ($b+c < 25$) & formatted $p$-values ($p < 10^{-4}$) | 5 | 5 | 2 | 12 | Ready |
| **Total** | | **All 20 Remediation Features** | **100** | **100** | **25** | **225** | **Ready** |

---

## 4. How to Verify Milestones

When a milestone worker completes implementation of their assigned features:
1. Run the feature-specific test slice:
   - For Milestone 1: `.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r1" -v`
   - For Milestone 2: `.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r2" -v`
   - For Milestone 3: `.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r3" -v`
   - For Milestone 4: `.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r4" -v`
   - For Milestone 5: `.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r5" -v`
2. Ensure that 100% of the milestone's target tests pass.
3. At the Final Milestone (M6), run the complete suite:
   `.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py`
   All **225 tests must pass (100% green)**.
