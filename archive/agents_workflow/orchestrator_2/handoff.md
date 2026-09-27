# Handoff Report — Project Orchestrator 2 (Recommendation 3: Isolated Evaluation Protocol)

**Orchestrator**: `orchestrator_2`  
**Parent**: `sentinel` (`0ba96de4-9e71-4efa-b97c-ba821f542393`)  
**Mission**: Completion of Recommendation 3 implementation (isolated evaluation protocol per query "1 target query per index instance") in CTI RAG poisoning benchmark.  
**Date**: 2026-09-07T11:27:30Z  
**Gate Verdict**: **PASS** (Unanimous approval: 2/2 Reviewers APPROVE, 2/2 Challengers APPROVE, Forensic Auditor CLEAN, 389/389 tests pass with 100% success rate).

---

## 1. Observation

### 1.1 Requirements Fulfillment Census
All requirements from `ORIGINAL_REQUEST.md` (section `## 2026-09-07T10:52:30Z`) have been implemented, verified, and stress-tested:

1. **R1. Integration of Isolated Protocol in Benchmark**:
   - **`scripts/run_comparison_benchmark.py`**:
     - Added `--isolated-targets` CLI flag (`action="store_true", default=False`).
     - Fixed latent argparse crash bug on `--cost-free` help string (escaped `%%` to eliminate `TypeError: %c requires int or char`).
     - When `--isolated-targets` is active, Phase 2 generates isolated query payloads (`poison_mgr.generate_isolated_poison_payloads`), and Phase 3 routes retrieval via `execute_isolated_retrieval` in `src/evaluation/stages.py`.
     - In isolated mode, each query $Q_i$ is evaluated against an index containing the clean corpus plus exclusively $Q_i$'s poison payloads ($B \in \{1, 3, 5\}$). No foreign payloads are present in the search index during evaluation of $Q_i$.
     - Propagates `isolated_targets` into `EngineBenchmarkResult` objects, JSON traces, Stage A records, and report generation.
   - **`src/evaluation/metrics.py`**:
     - Added `isolated_targets: bool = False` to `EngineBenchmarkResult` dataclass.
     - Updated `Evaluator.evaluate_engine` and `Evaluator.evaluate_engine_with_llm` to accept, propagate, and record `isolated_targets`.
   - **`src/visualization/reporter.py`**:
     - Updated `BenchmarkReporter.generate_markdown_report` to accept `isolated_targets: Optional[bool] = None` with automatic fallback to result metadata.
     - Integrated Pareto ranking in Section 3 table (`Status Pareto (Recall >= 50%)`: `VIABLE` vs `NON_VIABLE`, sorted viable first by lowest targeted ASR then highest recall).
     - Dynamically synthesized Observation 1 (Pareto viability), Observation 2 (GraphRAG clean recall & breakdown), Observation 3 (asymmetric profile), Observation 4 (targeted vs untargeted metrics), and Observation 5 (isolated protocol explanation and budget dynamics without background saturation).
     - Completely eliminated all hardcoded strings in Section 5 (F-R5-01): `(Sparse: 22.2%, Dense: 3.7%, Hybrid: 22.3%)`, `0.62`, `100%`, `72%`, `100.0%`, and fixed 24k corpus size references.

2. **R2. Unit and Integration Tests**:
   - Implemented `tests/test_isolated_protocol.py` (20 dedicated tests across 5 classes, 556 lines):
     - `TestZeroForeignPoisonIsolation` (5 tests): verifies payload partitioning, isolated corpus building, 0 foreign poison across all 4 retrievers, Evaluator invariants ($ASR_{\text{untargeted}} \equiv 0.0\%$, $ASR_{\text{targeted}} \equiv ASR_{\text{any}}$).
     - `TestBudgetSensitivity` (5 tests): verifies payload count scaling across $B \in \{1, 3, 5\}$, text/entity diversity, monotonic ASR sensitivity, non-saturation.
     - `TestCleanRecallPreservation` (4 tests): verifies isolated clean recall $\ge$ shared clean recall, clean recall preservation when attacks fail to match, graceful degradation under target hijack, clean ground truth retention.
     - `TestSharedModeBackwardCompatibility` (4 tests): verifies legacy shared mode runs unchanged, foreign contamination is preserved in shared mode, Stage A JSONL preserves `isolated_target: bool`, Evaluator handles legacy records.
     - `TestBenchmarkAndReporterIntegration` (2 tests): CLI `--isolated-targets` parsing and dynamic report formatting without crashes.
   - Additionally created adversarial stress suites during challenge phases:
     - `tests/test_isolated_adversarial_stress.py` (29 tests by `challenger_iso_1`).
     - `tests/test_challenger_iso_2_adversarial.py` (12 tests by `challenger_iso_2`).

3. **R3. Test Suite Integrity & Regression Safeguards**:
   - Total test inventory expanded from 328 to **389 tests**.
   - Test execution result: **389 passed, 0 failed, 1 warning** in 108.6s (100% success rate).
   - Zero test regressions across existing modules (`test_e2e_remediation.py`, `test_targeting_evaluation.py`, `test_stages.py`, `test_m1_adversarial_stress.py`, etc.).
   - All code modifications strictly contained within `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark`.

---

## 2. Logic Chain

1. **Metrological Invalidation of Shared Protocol (Defects A6 & A3)**:
   In the legacy shared corpus protocol, all poison payloads generated across all queries ($N \times B$) were combined into a single index. Consequently, when evaluating query $Q_i$, poison documents crafted for other queries $Q_j$ ($j \ne i$) leaked into $Q_i$'s Top-k context. This artificially inflated untargeted contamination, displaced clean documents, and caused budget curves to plateau prematurely at $B=1$ due to artificial background saturation.
2. **Recommendation 3 Isolation**:
   By enforcing "1 target query per index instance", each query $Q_i$ is evaluated against an index containing clean documents and exclusively the $B$ poison documents generated for $Q_i$.
   - Foreign contamination is strictly eliminated: $\text{ASR}_{\text{untargeted}} \equiv 0.0\%$.
   - Any poison retrieved is by definition targeted: $\text{ASR}_{\text{targeted}} \equiv \text{ASR}_{\text{any}}$.
   - Increasing budget $B \in \{1, 3, 5\}$ measures the authentic marginal power of attacker replication rather than cross-query noise accumulation.
3. **Multi-Engine Fast Paths & Performance**:
   All 4 retrievers (`BM25Retriever`, `DenseFAISSRetriever`, `HybridRerankRetriever`, `GraphRAGRetriever`) support lightweight dynamic index construction. For FAISS, embedding caches avoid recomputing embeddings, allowing isolated evaluation of test suites in under 15 seconds.
4. **Pareto Viability & Reporting Rigor**:
   `reporter.py` now directly surfaces Pareto viability (`VIABLE` if Clean Recall@5 $\ge$ 50% vs `NON_VIABLE`). All conclusions and numbers in Section 5 are dynamically synthesized from evaluation traces, eliminating all hardcoded figures.

---

## 3. Caveats

- **Isolated Mode Compute Overhead**:
  Evaluating large query counts (e.g. 100 queries) with `--isolated-targets` on real 24k CTI corpora requires rebuilding the volatile poison index slice per query. With caching enabled, this takes ~15–30 ms per query for BM25 and ~50–100 ms for FAISS, which remains fully feasible.
- **Shared Mode Invariant**:
  When `--isolated-targets` is omitted, the benchmark operates in legacy shared corpus mode. This behavior is deliberate to preserve backward compatibility and allow comparative studies between isolated and shared protocols.

---

## 4. Conclusion

Milestone 1 (Recommendation 3) is **fully completed and verified**:
- Requirements R1, R2, and R3 are 100% satisfied.
- All acceptance criteria are met.
- Independent verification quintet (2 Reviewers, 2 Challengers, 1 Forensic Auditor) has confirmed code quality, mathematical correctness, adversarial robustness, and forensic integrity.
- Total repository test suite passes with 389/389 tests (100%).

---

## 5. Verification Method

To verify the complete implementation independently, execute:

```powershell
# 1. Verify CLI argument parsing and help formatting (no %c crash)
.venv\Scripts\python.exe scripts/run_comparison_benchmark.py --help

# 2. Run dedicated isolated protocol test suite (20 tests)
.venv\Scripts\python.exe -m pytest tests/test_isolated_protocol.py -v

# 3. Run adversarial stress test suites
.venv\Scripts\python.exe -m pytest tests/test_isolated_adversarial_stress.py -v
.venv\Scripts\python.exe -m pytest tests/test_challenger_iso_2_adversarial.py -v

# 4. Run the full repository regression suite (389 tests)
.venv\Scripts\python.exe -m pytest tests/

# 5. Run end-to-end benchmark in isolated mode
.venv\Scripts\python.exe scripts/run_comparison_benchmark.py --corpus synthetic --queries 2 --cost-free --isolated-targets
```
