# Handoff Report: E2E Test Suite Creation (Track A / Milestone M0)

## 1. Observation

- **Authoritative Specifications**: Read `ORIGINAL_REQUEST.md` (Requirements R1-R5, Acceptance Criteria) and `orchestrator_1/PROJECT.md` (Feature Inventory F-R1-01 to F-R5-05, Contracts 1-5).
- **Existing Codebase State**:
  - `src/corpus/dataset.py:27-35`: `RetrievalResult` schema lacks `poison_target_query` and `poison_type` attributes.
  - `src/engines/retrievers.py:56-65, 224-233, 282-291, 400-409`: BM25, Dense, Hybrid, and GraphRAG retrievers omit targeting metadata when creating `RetrievalResult` instances.
  - `src/engines/retrievers.py:343`: `GraphRAGRetriever._extract_query_entities` filters nodes present in `self.doc_map`, causing entity blacklisting for CTI documents whose IDs match focal threat terms (e.g. `CVE-2021-44228`).
  - `src/evaluation/stages.py:29-52`: `retrieval_result_to_dict` and `retrieval_result_from_dict` omit `poison_target_query` and `poison_type`.
  - `src/evaluation/metrics.py:29-45`: `EngineBenchmarkResult` lacks `retrieval_asr_targeted`, `retrieval_asr_untargeted`, `retrieval_asr_any`, `graph_fallback_rate`, `llm_stage_ran`, `judge_coverage_rate`, `latency_median_ms`, and `latency_iqr_ms`.
  - `src/attacks/poisoning.py:307-328`: `CorpusPoisonManager.generate_poisoned_corpus` generates byte-identical payloads across budgets $B \in \{1, 3, 5\}$ for sparse, dense, hybrid, and blackbox attacks.
  - `src/evaluation/llm_judge.py:176, 185`: Unparseable judge output silently defaults to clean defense (`is_ground_truth_retained=True`, `is_poison_adopted=False`).
  - `src/visualization/reporter.py:439, 532`: Hardcodes literal `"24 000 autentycznych dokumentów"` and fixed Section 5 observations.
- **Implemented Test Artifacts**:
  - Created `tests/test_e2e_remediation.py` containing 225 test cases across 4 tiers.
  - Created root documentation `TEST_INFRA.md` and `TEST_READY.md`.
- **Test Run Execution Results**:
  - Command: `.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -q`
  - Output: `41 failed, 184 passed in 11.80s`
  - Existing regression test suite: `.venv\Scripts\python.exe -m pytest tests/ -q` (all 71 existing unit tests passed in 50.45s).

## 2. Logic Chain

1. Requirements R1 to R5 define specific behavioral contracts and remediations across 20 distinct feature areas (F-R1-01 through F-R5-05).
2. Designing an opaque-box test suite across 4 tiers (Feature Coverage, Boundary/Corner Cases, Cross-Feature Combinations, Real-World CTI Scenarios) ensures comprehensive test-driven acceptance criteria for ongoing milestones M1 to M5.
3. Tier 1 establishes >=5 test cases per feature (100 tests), Tier 2 establishes >=5 boundary cases per feature (100 tests), Tier 3 establishes 15 pairwise interaction tests, and Tier 4 establishes 10 real-world CTI scenarios, totaling 225 test cases.
4. Executing `pytest tests/test_e2e_remediation.py` collected all 225 test cases without syntax or collection errors.
5. In the current pre-remediation codebase, exactly 41 tests fail, each pointing directly to an un-remediated defect:
   - R1: RetrievalResult targeting field presence and propagation (M1 gate).
   - R2: GraphRAG dual namespaces `doc:` / `ent:`, entity blacklisting, and fallback tracking (M2 gate).
   - R3: Multi-budget text diversity (M3 gate).
   - R4: LLM Judge `is_valid` flag, coverage rate, assertion alignment, and `llm_stage_ran` flag (M4 gate).
   - R5: `corpus_size` dynamic parameter, high-precision latency fields, and non-zero p-value formatting (M5 gate).
6. 184 tests pass, confirming that existing interfaces, schema stubs, and baseline capabilities remain intact and stable.
7. `TEST_INFRA.md` and `TEST_READY.md` document the architecture, contract enforcement, and milestone gating verification methods.

## 3. Caveats

- Tests for neural network models (`DenseFAISSRetriever`, `HybridRerankRetriever`) mock encoder predictions with synthetic arrays in tests where embedding weights are invariant to the contract, keeping execution under 12 seconds. Real neural evaluations remain fully supported for end-to-end benchmarking.
- External LLM API calls are mocked or executed via offline prompt hashing fixtures, incurring $0.00 in API costs during test execution.

## 4. Conclusion

The independent opaque-box E2E test suite (`tests/test_e2e_remediation.py`), test infrastructure documentation (`TEST_INFRA.md`), and test readiness report (`TEST_READY.md`) are complete and verified. The 41 baseline failures serve as unambiguous, automated acceptance criteria that Milestone Workers (M1 through M5) will systematically resolve.

## 5. Verification Method

To independently verify the test suite:
```powershell
# 1. Verify test collection and structure (225 items):
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py --collect-only

# 2. Run the E2E test suite (184 passed, 41 failed baseline):
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -q

# 3. Verify specific milestone test slices (e.g., M1):
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r1" -v

# 4. Verify existing regression test suite (71 passed):
.venv\Scripts\python.exe -m pytest tests/test_stages.py tests/test_comparison_system.py -q
```
Files to inspect:
- `tests/test_e2e_remediation.py`
- `TEST_INFRA.md`
- `TEST_READY.md`
