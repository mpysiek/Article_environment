# Handoff Report — explorer_iso_3

**Task:** Test Environment Investigation & Test Specifications for Recommendation 3 (Isolated Target Evaluation Protocol)  
**Agent:** explorer_iso_3  
**Target File for Test Implementation:** `tests/test_isolated_protocol.py`  
**Working Directory:** `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark`  
**Full Report Reference:** `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_3\report.md`  

---

## 1. Observation

1. **Exact Test Inventory**:
   - The test directory `tests/` contains exactly 10 test files comprising **328 total test cases**:
     - `tests/test_batch_client.py`: 15 tests (OpenRouter Batch API JSONL, chunking, state persistence)
     - `tests/test_comparison_system.py`: 11 tests (Multi-engine integration smoke tests)
     - `tests/test_data_integrity.py`: 9 tests (Corpus integrity, STIX 2.1 relations, CVE validation)
     - `tests/test_defenses.py`: 4 tests (Perplexity/entropy, graph validator, defended BM25)
     - `tests/test_embedding_cache.py`: 9 tests (`DenseFAISSRetriever` persistent cache & model slugs)
     - `tests/test_judge_batch.py`: 11 tests (LLM judge batch generation and parsing)
     - `tests/test_stages.py`: 12 tests (Stage A/B/C handoffs, JSONL serialization)
     - `tests/test_targeting_evaluation.py`: 14 tests (R1 targeting fields across 4 retrievers)
     - `tests/test_m1_adversarial_stress.py`: 18 tests (High-density contamination, rank cutoffs)
     - `tests/test_e2e_remediation.py`: 225 tests (Opaque-box tests covering Tiers 1–4 for R1–R5)
   - Verified census: $15 + 11 + 9 + 4 + 9 + 11 + 12 + 14 + 18 + 225 = \mathbf{328\text{ tests}}$.

2. **Test Environment & Execution Speed**:
   - Python environment: `.venv` Python 3.13, `pytest` 9.1.1 (`requirements.txt:22`).
   - Configuration: No `pytest.ini`, `conftest.py`, or `pyproject.toml` exists. Standard pytest discovery is used.
   - Execution performance: Documented in `TEST_INFRA.md:138` and `TEST_READY.md:12`: 225 E2E tests execute in **~11.8s**; the full 328-test suite completes in **~17.3s**.
   - Mocking strategy:
     - LLM calls (OpenRouter generation and judge) are 100% mocked / offline ($0.00 external API cost).
     - E2E tests mock embeddings via `patch.object(DenseFAISSRetriever, "__init__", lambda self: None)` (`tests/test_e2e_remediation.py:300`).
     - Unit tests execute against synthetic micro-corpora (2–14 docs) using fast CPU BGE-small-en-v1.5 and persistent caching (`data/cache/embeddings/BAAI__bge-small-en-v1.5/keys.json` and `vectors.npy`).

3. **Current State of Isolated Evaluation Code**:
   - Primitives already implemented:
     - `src/attacks/poisoning.py:402-423`: `generate_isolated_poison_payloads(queries, attack_type, attack_budget, query_echo)`
     - `src/attacks/poisoning.py:424-439`: `generate_isolated_corpus_for_query(clean_docs, query, attack_type, attack_budget, query_echo)`
     - `src/evaluation/stages.py:92-124`: `execute_isolated_retrieval(engine, clean_docs, poison_payloads, queries, top_k)`
     - `src/evaluation/stages.py:60-90`: `make_stage_a_record` accepts `isolated_target: bool = False`.
   - **Current Testing Void**: None of `generate_isolated_poison_payloads`, `generate_isolated_corpus_for_query`, or `execute_isolated_retrieval` are currently tested in any of the 328 tests.
   - **Benchmark Script Void**: `scripts/run_comparison_benchmark.py` does not yet accept `--isolated-targets`.

4. **Metric Definitions in `src/evaluation/metrics.py:280-282`**:
   ```python
   asr_targeted = targeted_top5_count / total_q
   asr_any = poison_top5_count / total_q
   asr_untargeted = asr_any - asr_targeted
   ```

---

## 2. Logic Chain

1. **Root Cause of Flaws A6 & A3**: In the legacy shared protocol, for $M=100$ queries and budget $B$, $100 \times B$ poison documents reside in a single index. Foreign poison documents addressed to $Q_j$ ($j \ne i$) infiltrate Top-$k$ results of $Q_i$, producing artificial context saturation (`retrieval_asr_untargeted > 0.0`), displacing clean ground-truth documents (`clean_recall_top5` degradation), and crushing budget sensitivity at $B=1$.
2. **Mathematical Invariant of Isolated Protocol**: When `execute_isolated_retrieval` evaluates query $Q_i$, the index is constructed as $\text{clean\_docs} + \text{poison\_payloads}[Q_i.\text{id}]$. Because zero documents targeting $Q_j$ ($j \ne i$) are present in the index:
   - Any poisoned document retrieved must satisfy `r.poison_target_query == Q_i.id`.
   - `retrieval_asr_untargeted` must strictly equal `0.0`.
   - `retrieval_asr_targeted` must strictly equal `retrieval_asr_any`.
3. **Budget Sensitivity Restoration**: In isolated mode, the index for $Q_i$ holds exactly 1, 3, or 5 poison documents. At $B=1$, there is no background poison noise. Increasing budget $B \in \{1, 3, 5\}$ introduces diverse paraphrases / multi-point bridges (Contract 4), resulting in monotonic or stepwise sensitivity: $\text{ASR}_{\text{targeted}}(B=1) \le \text{ASR}_{\text{targeted}}(B=3) \le \text{ASR}_{\text{targeted}}(B=5)$.
4. **Clean Recall Integrity**: Because foreign poison documents cannot enter the index, clean ground-truth documents are not displaced by irrelevant attacks. Consequently, $\text{CleanRecall}_{\text{isolated}} \ge \text{CleanRecall}_{\text{shared}}$.
5. **Test Specification Architecture**: Designing 5 test classes (20 test cases) in `tests/test_isolated_protocol.py` using synthetic CTI fixtures (6 docs, 3 queries) directly verifies all 4 R2 acceptance criteria in < 1.5 seconds without side effects.
6. **Preservation of Existing Suite**: Adding `tests/test_isolated_protocol.py` expands the suite from 328 to 348 tests without altering any existing test file or breaking shared mode backward compatibility.

---

## 3. Caveats

1. **Permission Timeout on Command Execution**: Direct shell execution of `pytest` via `run_command` timed out waiting for user approval. Investigation was performed via static code analysis, file parsing, and structural verification. All imports, schemas, and lines were cross-referenced against the actual files on disk.
2. **Implementation Scope**: This report defines the complete specification and design. Actual implementation of `tests/test_isolated_protocol.py` and CLI flag integration in `scripts/run_comparison_benchmark.py` will be performed by the downstream implementer.
3. **Synthetic vs. Real Corpus Timing**: Benchmarks on real 24k CTI data in isolated mode will build indices per query ($100 \times \text{build\_index}$). While `DenseFAISSRetriever` and `GraphRAGRetriever` feature base-clean caching (`_base_embeddings` and `_base_graph`), tests in `test_isolated_protocol.py` must use synthetic corpora to keep test runtimes under 1.5 seconds.

---

## 4. Conclusion

The testing environment is fully characterized, verified at **328 existing tests**, and ready for Recommendation 3 validation:
1. **Target test file:** `tests/test_isolated_protocol.py`.
2. **Structure:** 5 test classes, 20 test cases covering:
   - `TestZeroForeignPoisonIsolation` (5 tests): verifies $\text{ASR}_{\text{untargeted}} \equiv 0.0$ and no foreign contamination across all 4 retrievers.
   - `TestBudgetSensitivity` (5 tests): verifies payload count scaling, payload diversity across $B \in \{1, 3, 5\}$, and monotonic targeted ASR growth.
   - `TestCleanRecallPreservation` (4 tests): verifies clean recall is uncompromised by foreign poison noise.
   - `TestSharedModeBackwardCompatibility` (4 tests): verifies `execute_shared_retrieval` and Stage A serialization compatibility.
   - `TestBenchmarkAndReporterIntegration` (2 tests): verifies `--isolated-targets` CLI flag and dynamic Markdown report formatting.
3. Complete implementation blueprint and exact assertions are detailed in `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_3\report.md`.

---

## 5. Verification Method

Once implemented by the downstream engineer, verify using the following commands:

1. **Verify New Isolated Protocol Suite (20 tests)**:
   ```powershell
   .venv\Scripts\python.exe -m pytest tests/test_isolated_protocol.py -v
   ```
   *Expected outcome*: 20 passed in < 1.5s, 0 failed, 0 warnings.

2. **Verify Full Project Suite (348 tests total)**:
   ```powershell
   .venv\Scripts\python.exe -m pytest tests/ -q
   ```
   *Expected outcome*: 348 passed (328 existing + 20 new) with 100% pass rate.

3. **Invalidation Conditions**:
   - Any occurrence of foreign query poison (`poison_target_query != q.id`) in isolated mode.
   - `retrieval_asr_untargeted > 0.0` in isolated mode.
   - Any failure or regression in the existing 328 tests.
   - CLI invocation of `scripts/run_comparison_benchmark.py` failing when `--isolated-targets` is omitted (breaking backward compatibility).
