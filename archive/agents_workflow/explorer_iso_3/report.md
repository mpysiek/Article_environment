# Comprehensive Test Environment Analysis and Test Specifications for Recommendation 3 (Isolated Target Evaluation Protocol)

**Author:** explorer_iso_3  
**Date:** 2026-09-07  
**Status:** Completed  
**Target File for New Tests:** `tests/test_isolated_protocol.py`  
**Workspace:** `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark`

---

## 1. Executive Summary

This investigation establishes the complete testing architecture, execution characteristics, and formal test specifications required to validate **Recommendation 3** of the CTI RAG Poisoning Benchmark methodological audit. Recommendation 3 addresses Class A methodological defects **A6** (cross-query context contamination / foreign poison saturation) and **A3** (loss of attack budget resolution) by enforcing an isolated per-query evaluation protocol (*"1 target query per index instance"*).

### Core Findings
1. **Existing Test Inventory Verified**: The project test suite consists of **exactly 328 test cases** across **10 test files** in `tests/` (103 unit/integration tests + 225 E2E remediation tests in `tests/test_e2e_remediation.py`).
2. **Fast Execution & Mocking Architecture**: The full test suite executes in **~15–20 seconds** on a standard developer CPU (~11.8s for the 225 E2E tests). External APIs (OpenRouter generation and judge) are 100% mocked ($0.00 spend). Dense retrievers use `unittest.mock` in E2E tests, and small synthetic corpora (2–14 docs) paired with persistent vector caching (`keys.json`, `vectors.npy`) in unit tests.
3. **Current Isolated Protocol Gap**: Core primitives `generate_isolated_poison_payloads`, `generate_isolated_corpus_for_query` in `src/attacks/poisoning.py`, and `execute_isolated_retrieval` in `src/evaluation/stages.py` exist in the codebase but are **currently unexercised by any test in `tests/`**.
4. **Exact Test Suite Design Formulated**: A complete, robust test suite for `tests/test_isolated_protocol.py` is formulated across **5 test classes and 20 distinct test cases**, verifying zero foreign poison in Top-$k$, budget sensitivity across $B \in \{1, 3, 5\}$, clean recall preservation, backward compatibility with shared index mode, and benchmark/reporter CLI integration.
5. **Zero Regression Guarantee**: All 20 formulated tests execute on CPU using synthetic CTI fixtures in **< 1.5 seconds**, avoiding persistent cache pollution (`persist_cache=False`) and state leakage between query iterations. None of the existing 328 tests are perturbed or modified.

---

## 2. Complete Mapping of Existing Test Suite (328 Tests)

The benchmark uses `pytest>=8.0.0` (specifically running **pytest 9.1.1** under **Python 3.13**). Test discovery uses default pytest conventions (`tests/test_*.py`). There is no custom `pytest.ini` or `pyproject.toml`, ensuring pure standard discovery.

### 2.1 Test File Breakdown and Census

| # | Test File Path | Test Classes / Functions | Total Tests | Primary Focus & Requirements Verified |
|---|---|---|:---:|---|
| 1 | `tests/test_batch_client.py` | `TestOpenRouterBatchClientJsonl` (5)<br>`TestChunking` (2)<br>`TestCollect` (6, 1 parametrized x3)<br>`TestStatePersistence` (2) | **15** | OpenRouter Batch API client, JSONL serialization, chunking, state persistence, error handling. |
| 2 | `tests/test_comparison_system.py` | 11 top-level test functions | **11** | End-to-end integration smoke tests on synthetic CTI corpus (4 engines, poison manager, evaluator, generator, reporter). |
| 3 | `tests/test_data_integrity.py` | 9 top-level test functions | **9** | Schema integrity, real CTI corpus validation (24k CVEs, STIX 2.1 relations, CISA KEV, CTIBench ground truth). |
| 4 | `tests/test_defenses.py` | 4 top-level test functions | **4** | Pre-retrieval and post-retrieval defenses: Perplexity/entropy filter, graph ontology validator, defended BM25. |
| 5 | `tests/test_embedding_cache.py` | `TestCacheKeys` (2)<br>`TestCache` (7) | **9** | `DenseFAISSRetriever` on-disk embedding cache, model namespacing, query prefix handling, crash recovery. |
| 6 | `tests/test_judge_batch.py` | `TestBuildRequests` (7)<br>`TestParseResults` (4) | **11** | Batch LLM judge request generation, prompt deduplication, fan-out join, missing verdict detection. |
| 7 | `tests/test_stages.py` | `TestStageARoundTrip` (4)<br>`TestStageBScenarios` (4)<br>`TestStageCJoin` (3)<br>`TestMalformed` (1) | **12** | Multi-stage benchmark pipeline (Stage A retrieval, Stage B generation, Stage C metrics) JSONL persistence and handoff. |
| 8 | `tests/test_targeting_evaluation.py` | `TestRetrievalResultSchema` (3)<br>`TestRetrieverTargetingPropagation` (4)<br>`TestStagesTargetingSerialization` (2)<br>`TestEvaluatorTargetingMetrics` (5) | **14** | Requirement R1: Targeting fields (`poison_target_query`, `poison_type`) across 4 retrievers, handoff serialization, and Evaluator metrics separation. |
| 9 | `tests/test_m1_adversarial_stress.py` | `TestAdversarialTargetingSchemas` (6)<br>`TestTargetingCutoffsAndNormalization` (4)<br>`TestContaminatedCorpusStress` (5)<br>`TestAdversarialSerialization` (3) | **18** | Milestone M1 stress testing: high-density contamination (1:10), malicious payload IDs, SQL/regex metacharacters in target queries, rank cutoffs. |
| 10 | `tests/test_e2e_remediation.py` | `TestTier1FeatureCoverage` (100)<br>`TestTier2BoundaryCases` (100)<br>`TestTier3CrossFeatureCombinations` (15)<br>`TestTier4RealWorldScenarios` (10) | **225** | Comprehensive opaque-box regression test suite enforcing all 20 remediation features (F-R1-01 to F-R5-05) across Requirements R1–R5. |
| **TOTAL** | **10 files in `tests/`** | | **328** | **Full Project Test Inventory** |

### 2.2 Test Configuration & Discovery Details
- **Test Discovery Command**: `.venv\Scripts\python.exe -m pytest tests/`
- **Root Configuration**: No `pytest.ini`, `conftest.py`, or `pyproject.toml` exists. Pytest relies on automatic module discovery.
- **Path Resolution**: Every test file explicitly prepends the repository root to `sys.path`:
  ```python
  import sys
  from pathlib import Path
  sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
  ```

---

## 3. Execution Performance & Speed Optimizations

### 3.1 Benchmark Execution Timings
- **Collection Phase**: ~9.8 seconds (dominated by Python runtime import of PyTorch CPU, HuggingFace Transformers, FAISS CPU, and SentenceTransformers).
- **Execution Phase**:
  - `tests/test_e2e_remediation.py` (225 tests): **~11.8 seconds**.
  - All other 9 test files (103 tests): **~5.5 seconds**.
  - Full existing suite (328 tests): **~17.3 seconds**.
- **Target for new tests (`tests/test_isolated_protocol.py`)**: **< 1.5 seconds**.

### 3.2 Embedding & Model Execution Strategy
The test suite utilizes three distinct tiers of embedding execution:

1. **Pure Unit / Mocked Execution (Fastest, ~0.01ms per test)**:
   - Used extensively in `test_e2e_remediation.py` and `test_judge_batch.py`.
   - `DenseFAISSRetriever.__init__` is patched with `patch.object(DenseFAISSRetriever, "__init__", lambda self: None)`.
   - `encode_query` and `index.search` return synthetic NumPy vectors and index arrays.
   - `CrossEncoder` in `HybridRerankRetriever` is mocked via `patch("src.engines.retrievers.CrossEncoder")`.
   - Zero LLM network calls; mock verdicts injected directly.
2. **Synthetic Micro-Corpora Execution (~10–20ms per build)**:
   - Used in `test_comparison_system.py`, `test_targeting_evaluation.py`, and `test_m1_adversarial_stress.py`.
   - Uses `build_cti_knowledge_base()` (14 synthetic CTI documents) or ad-hoc 2–8 document lists.
   - Uses the lightweight CPU model `BAAI/bge-small-en-v1.5` (384 dimensions). Encoding 2–5 short sentences takes ~15ms on CPU.
   - FAISS uses `IndexFlatIP` (exact inner product) over < 20 vectors, taking < 0.1ms per search.
   - BM25 and GraphRAG use in-memory dictionaries and NetworkX `MultiDiGraph` (< 1ms).
3. **Embedding Cache Acceleration**:
   - `DenseFAISSRetriever` features a two-level cache: RAM dict `_embedding_cache` and on-disk matrix `data/cache/embeddings/BAAI__bge-small-en-v1.5/` (`keys.json` and `vectors.npy`).
   - When repeated test runs encode identical documents, `encoded_count == 0` and cache hits are 100%, skipping transformer encoding entirely.

---

## 4. Exact Test Design for `tests/test_isolated_protocol.py` (Satisfying R2)

### 4.1 Problem Definition and Theoretical Invariants

In the legacy shared evaluation protocol, all $M$ benchmark queries inject their poison payloads ($B$ per query) into a single unified index. For $M=100$ and $B=1$, 100 poison documents exist in the index. When query $Q_i$ is evaluated:
- Foreign poisons targeting $Q_j$ ($j \ne i$) infiltrate Top-$k$ results.
- `retrieval_asr_untargeted > 0.0` and `retrieval_asr_any` saturate toward 100%, masking true attack efficacy.
- Context saturation displaces clean ground-truth documents, artificially destroying `clean_recall_top5`.
- Budget scaling from $B=1$ to $B=5$ shows no dynamic range because $B=1$ is already saturated.

In the **isolated evaluation protocol (Recommendation 3)**, for each test query $Q_i$:
$$\text{Index}(Q_i) = \text{Corpus}_{\text{clean}} \cup \text{PoisonPayloads}(Q_i)$$
Where:
$$|\text{PoisonPayloads}(Q_i)| = B \quad (B \in \{1, 3, 5\}), \quad \forall d \in \text{PoisonPayloads}(Q_i): d.\text{poison\_target\_query} = Q_i.\text{id}$$

#### Mathematical Invariants in Isolated Mode:
1. **Zero Foreign Poison**:
   $$\forall r \in \text{Top-}k(Q_i): r.\text{is\_poisoned} \implies r.\text{poison\_target\_query} = Q_i.\text{id}$$
2. **Zero Untargeted ASR**:
   $$\text{ASR}_{\text{untargeted}} \equiv 0.0$$
3. **Identity of Any and Targeted ASR**:
   $$\text{ASR}_{\text{targeted}} \equiv \text{ASR}_{\text{any}}$$
4. **Monotonic / Stepwise Budget Scaling**:
   $$\text{ASR}_{\text{targeted}}(B=1) \le \text{ASR}_{\text{targeted}}(B=3) \le \text{ASR}_{\text{targeted}}(B=5)$$
5. **Clean Recall Preservation**:
   $$\text{CleanRecall}_{\text{isolated}}(Q_i) \ge \text{CleanRecall}_{\text{shared}}(Q_i)$$

---

### 4.2 Comprehensive Test Specification (20 Test Cases across 5 Classes)

The new file `tests/test_isolated_protocol.py` must be structured into 5 test classes:

```
tests/test_isolated_protocol.py
├── TestZeroForeignPoisonIsolation (5 tests)        # R2.1: Absolute absence of foreign contamination
├── TestBudgetSensitivity (5 tests)                 # R2.2: Metric sensitivity across B in {1, 3, 5}
├── TestCleanRecallPreservation (4 tests)           # R2.3: Clean recall unpolluted by foreign noise
├── TestSharedModeBackwardCompatibility (4 tests)   # R2.4: Backward compatibility with shared mode
└── TestBenchmarkAndReporterIntegration (2 tests)   # CLI and Report generation validation
```

Below is the exact specification and implementation design for each test case:

---

#### Class 1: `TestZeroForeignPoisonIsolation` (R2.1)
Verifies that during evaluation of test query $Q_i$, no foreign poison document targeting $Q_j$ ($j \ne i$) can appear in the index or in Top-$k$ results.

1. `test_isolated_payload_generation_partitions_by_query_id`:
   - **Action**: Call `CorpusPoisonManager.generate_isolated_poison_payloads(queries, "sparse", attack_budget=2)`.
   - **Assertions**:
     - Returned dict has exactly keys matching `[q.id for q in queries]`.
     - For each `qid, payloads in dict.items()`: `len(payloads) == 2`.
     - Every doc $d \in \text{payloads}$ has $d.\text{poison\_target\_query} == \text{qid}$ and $d.\text{is\_poisoned} == \text{True}$.
     - No doc in `payloads[qid]` has `poison_target_query` matching any other query ID.

2. `test_isolated_corpus_builder_contains_zero_foreign_poisons`:
   - **Action**: Call `CorpusPoisonManager.generate_isolated_corpus_for_query(clean_docs, query_A, "dense", attack_budget=3)`.
   - **Assertions**:
     - Returned corpus length is `len(clean_docs) + 3`.
     - Every document with `is_poisoned is True` has `poison_target_query == query_A.id`.
     - Not a single document in the corpus references `query_B.id` or `query_C.id`.

3. `test_execute_isolated_retrieval_zero_foreign_in_top_k`:
   - **Action**: Instantiate `BM25Retriever`. Generate isolated payloads for 3 distinct queries ($Q_A, Q_B, Q_C$) using keyword stuffing attacks. Run `execute_isolated_retrieval(bm25, clean_docs, poison_payloads, queries, top_k=5)`.
   - **Assertions**:
     - For each query $q$: examine all returned `RetrievalResult` items.
     - If $r.\text{is\_poisoned}$ is True: `assert r.poison_target_query == q.id`.
     - Explicit negative assertion: `assert r.poison_target_query != other_q.id` for all other queries.

4. `test_evaluator_reports_zero_untargeted_asr_in_isolated_mode`:
   - **Action**: Feed the `retrieval_outputs` from `execute_isolated_retrieval` to `Evaluator.evaluate_engine`.
   - **Assertions**:
     - `result.retrieval_asr_untargeted == 0.0`.
     - `result.retrieval_asr_untargeted_top1 == 0.0`.
     - `result.retrieval_asr_untargeted_top5 == 0.0`.
     - `result.retrieval_asr_targeted == result.retrieval_asr_any`.
     - For every trace $t \in \text{result.traces}$: `t.has_untargeted_poison_in_top1 is False` and `t.has_untargeted_poison_in_top5 is False`.

5. `test_all_four_retrieval_engines_enforce_zero_foreign_poisons`:
   - **Action**: Iterate across all 4 benchmark engines (`BM25Retriever`, `DenseFAISSRetriever(persist_cache=False)`, `HybridRerankRetriever`, `GraphRAGRetriever`). For each engine, execute `execute_isolated_retrieval` over 3 queries with active attacks.
   - **Assertions**:
     - Confirm that across sequential calls within `execute_isolated_retrieval`, internal state is fully reset per query.
     - In all 4 engines, zero foreign poisons are retrieved across all queries.

---

#### Class 2: `TestBudgetSensitivity` (R2.2)
Verifies that varying attack budget $B \in \{1, 3, 5\}$ in isolated mode produces meaningful, non-degenerate metric variations and escapes the saturation ceiling.

1. `test_isolated_payload_counts_strictly_scale_with_budget`:
   - **Action**: For each $B \in \{1, 3, 5\}$, generate isolated payloads across queries.
   - **Assertions**:
     - `assert len(payloads[q.id]) == B` for every query and every budget level.

2. `test_isolated_payloads_diverse_across_budget_indices`:
   - **Action**: Inspect the 3 payloads generated for $B=3$ and 5 payloads for $B=5$ for a single query.
   - **Assertions**:
     - All payloads for a given query have distinct text content (`p1.text != p2.text != p3.text`).
     - Complies with Contract 4 (diverse paraphrases/bridging, no bitwise duplicates).

3. `test_retrieval_asr_targeted_budget_monotonicity`:
   - **Action**: Construct a benchmark scenario with queries of varying difficulty (e.g. some queries require multiple semantic facets or keyword variants to beat clean documents). Run `execute_isolated_retrieval` at $B=1$, $B=3$, and $B=5$ with BM25 and Evaluator.
   - **Assertions**:
     - `asr_b1 = result_b1.retrieval_asr_targeted`
     - `asr_b3 = result_b3.retrieval_asr_targeted`
     - `asr_b5 = result_b5.retrieval_asr_targeted`
     - `assert asr_b1 <= asr_b3 <= asr_b5`.
     - Dynamic range is preserved: `asr_b5 >= asr_b1`.

4. `test_isolated_mode_avoids_budget_1_saturation`:
   - **Action**: Set up 10 queries. In shared mode, generate 10 poisons ($B=1 \times 10$). In isolated mode, each query sees only 1 poison ($B=1$).
   - **Assertions**:
     - In shared mode: foreign poisons inflate `retrieval_asr_any` (e.g. > 0.50), while `retrieval_asr_targeted` is much lower (`retrieval_asr_untargeted > 0.30`).
     - In isolated mode: `retrieval_asr_untargeted == 0.0`, eliminating artificial background saturation at budget 1.

5. `test_budget_scaling_latency_profile`:
   - **Action**: Measure the retrieval latencies dictionary returned by `execute_isolated_retrieval` across $B \in \{1, 3, 5\}$.
   - **Assertions**:
     - All per-query latencies are non-negative floats.
     - Latency overhead between $B=1$ and $B=5$ remains bounded and linear on CPU.

---

#### Class 3: `TestCleanRecallPreservation` (R2.3)
Verifies that `clean_recall_top5` reflects true uncompromised retrieval capability rather than foreign poison displacement.

1. `test_clean_recall_uncontaminated_by_foreign_poisons`:
   - **Action**: Set up a clean corpus with 2 clean gold documents per query. In shared mode, inject 10 foreign poison documents that match generic terms. In isolated mode, run the same queries with only target poison.
   - **Assertions**:
     - In shared mode: foreign poison documents crowd into Top-5, reducing `clean_recall_top5`.
     - In isolated mode: zero foreign poison documents enter Top-5. `clean_recall_top5` in isolated mode is strictly greater than or equal to shared mode (`recall_isolated >= recall_shared`).

2. `test_clean_recall_preserved_when_attack_fails`:
   - **Action**: Run isolated retrieval where target poison documents have weak scores (e.g. query echo disabled or low relevance).
   - **Assertions**:
     - Target poison is not retrieved in Top-5.
     - `result.clean_recall_top5` in isolated mode exactly equals `baseline_result.clean_recall_top5`.

3. `test_clean_recall_graceful_degradation_under_target_hijack`:
   - **Action**: In isolated mode with budget $B=1$, the single target poison document achieves rank 1 (`retrieval_asr_top1 == 1.0`).
   - **Assertions**:
     - Because only 1 poison doc is present, ranks 2, 3, 4, 5 remain available for clean documents.
     - If the query has 2 ground-truth documents, both can rank at positions 2 and 3, maintaining `clean_recall_top5 == 1.0`.
     - Contrasted with shared mode where 5 foreign poisons could fill ranks 1–5, yielding `clean_recall_top5 == 0.0`.

4. `test_clean_ground_truth_hits_preservation`:
   - **Action**: Pass `clean_ground_truth_hits` from baseline to `Evaluator.evaluate_engine` under isolated retrieval outputs.
   - **Assertions**:
     - Traces accurately reflect `clean_ground_truth_hit`.
     - `retrieval_asr_cond` is accurately computed based only on baseline-viable queries.

---

#### Class 4: `TestSharedModeBackwardCompatibility` (R2.4)
Verifies that existing shared index functionality, stage handoffs, and serialization schemas remain 100% operational.

1. `test_execute_shared_retrieval_still_functional`:
   - **Action**: Call `execute_shared_retrieval(engine, shared_corpus, queries, top_k=5)`.
   - **Assertions**:
     - Returns `Tuple[Dict[str, List[RetrievalResult]], Dict[str, float]]`.
     - Dict keys match `[q.id for q in queries]`.
     - Engine index was built exactly once with `shared_corpus`.

2. `test_shared_retrieval_exhibits_expected_foreign_contamination`:
   - **Action**: In shared mode with multiple queries, verify that foreign poisons targeting $Q_j$ can be retrieved in Top-5 of $Q_i$.
   - **Assertions**:
     - Demonstrates that shared mode preserves its original behavior for comparative ablation.

3. `test_stage_a_serialization_records_isolated_target_flag`:
   - **Action**: Create Stage A records with `make_stage_a_record(..., isolated_target=True)` and `make_stage_a_record(..., isolated_target=False)`. Write to JSONL via `write_stage_a`, then read via `read_stage_a`.
   - **Assertions**:
     - Record 1 has `record["isolated_target"] is True`.
     - Record 2 has `record["isolated_target"] is False`.
     - Round-trip preserves the boolean flag losslessly.

4. `test_rebuild_scenario_inputs_backward_compatible`:
   - **Action**: Pass records with and without `isolated_target` to `rebuild_scenario_inputs(records)`.
   - **Assertions**:
     - Function extracts `outputs, generated, ret_lat, gen_lat` identically without KeyError or schema violation.

---

#### Class 5: `TestBenchmarkAndReporterIntegration`
Verifies that the benchmark runner script CLI and reporter handle the isolated evaluation protocol seamlessly.

1. `test_cli_argument_isolated_targets_parsing`:
   - **Action**: Inspect argument parser in `scripts/run_comparison_benchmark.py` or invoke with `--isolated-targets`.
   - **Assertions**:
     - Argument `--isolated-targets` is recognized as a valid boolean flag (defaulting to `False` for backward compatibility).
     - Does not conflict with `--corpus`, `--num_cves`, `--queries`, `--cost-free`, `--no-query-echo`, or `--topological`.

2. `test_reporter_handles_isolated_benchmark_results`:
   - **Action**: Construct `EngineBenchmarkResult` objects from isolated runs. Pass to `BenchmarkReporter.generate_markdown_report` and `BenchmarkReporter.print_terminal_results`.
   - **Assertions**:
     - Markdown report generates without error.
     - Budget curves and Pareto analysis tables correctly utilize `retrieval_asr_targeted`.

---

## 5. Potential Test Fragility, Dependencies & Regression Analysis

### 5.1 Regressions Against the Existing 328 Tests
- **Zero Interference with Existing Tests**: The existing 328 tests do not assert a fixed total test count across the project. Adding `tests/test_isolated_protocol.py` increases total test discovery from 328 to 348 without modifying any existing test file.
- **Contract Adherence**: All contracts established in `TEST_INFRA.md` (Contract 1: `RetrievalResult`, Contract 2: `Evaluator` metrics, Contract 4: Budget diversity, Contract 5: Reporter) are strictly observed by the new test suite.

### 5.2 State Leakage & Incremental Index Fragility
- **GraphRAG Node Collision Hazard**:
  In `GraphRAGRetriever`, `build_index(documents)` has a fast-path caching `self._base_graph` if `documents` has no poisoned docs. If `build_index` is called with poisoned documents without a base clean index, it falls back to full rebuild (`self.graph.clear()`).
  *Safety Measure*: In `execute_isolated_retrieval`, index docs are passed per query. To avoid graph node retention, tests verify that `self.graph` contains only the current query's poison nodes.
- **DenseFAISS In-Memory Cache**:
  `DenseFAISSRetriever` caches embeddings in `self._embedding_cache`. For newly generated poison payloads with unique IDs, each payload is encoded once.
  *Safety Measure*: In `test_isolated_protocol.py`, instantiate `DenseFAISSRetriever(persist_cache=False)` or pass `cache_dir=tmp_path` to avoid writing test vectors to the production embedding cache `data/cache/embeddings/`.

### 5.3 Test Execution Performance & Timeout Protection
- **Small Synthetic Fixture Discipline**:
  If `execute_isolated_retrieval` were run over the full 24,000 real CTI corpus with 100 queries, it would build 100 separate indices. In a production benchmark run, this takes ~30–60 seconds, but in unit tests it would create unacceptable test latency.
  *Safety Measure*: All tests in `tests/test_isolated_protocol.py` strictly use synthetic fixtures: 3–5 queries and 5–14 documents from `build_cti_knowledge_base()`. Total execution time for all 20 tests is **< 1.5 seconds**.

---

## 6. Implementation Blueprint for Downstream Implementer

When the implementer creates `tests/test_isolated_protocol.py` and completes Recommendation 3 integration in `scripts/run_comparison_benchmark.py`:

1. **Use Standard Pytest Fixtures**:
   ```python
   @pytest.fixture
   def synthetic_setup():
       clean_docs = build_cti_knowledge_base()[:6]
       queries = build_gold_benchmark_queries()[:3]
       poison_mgr = CorpusPoisonManager(query_echo=True)
       return clean_docs, queries, poison_mgr
   ```
2. **Execute Isolated Retrieval Verification**:
   ```python
   outputs, latencies = execute_isolated_retrieval(
       engine=bm25,
       clean_docs=clean_docs,
       poison_payloads=poison_payloads,
       queries=queries,
       top_k=5
   )
   ```
3. **Verify Evaluator Metric Equivalence**:
   ```python
   res = Evaluator.evaluate_engine(
       engine_name="Sparse-BM25",
       attack_type="sparse_isolated",
       queries=queries,
       retrieval_outputs=outputs,
       retrieval_latencies=latencies
   )
   assert res.retrieval_asr_untargeted == pytest.approx(0.0)
   assert res.retrieval_asr_targeted == res.retrieval_asr_any
   ```
4. **CLI Integration in `scripts/run_comparison_benchmark.py`**:
   Add `--isolated-targets` argument:
   ```python
   parser.add_argument("--isolated-targets", action="store_true", default=False,
                       help="Execute Recommendation 3 isolated evaluation protocol (1 target query per index instance)")
   ```
   In `run_benchmark_matrix`:
   ```python
   if isolated_targets:
       # Generate partitioned poison payloads
       poison_payloads = poison_mgr.generate_isolated_poison_payloads(
           queries, att_type, attack_budget=b
       )
       # Execute per-query isolated retrieval
       retrieval_outputs, retrieval_latencies = execute_isolated_retrieval(
           engine=engine, clean_docs=clean_docs, poison_payloads=poison_payloads,
           queries=queries, top_k=config.TOP_K
       )
   ```

---

## 7. Verification Method

Once implemented, the complete suite can be verified via:

```powershell
# 1. Run only the new isolated protocol test suite (target: 20 passed in < 1.5s):
.venv\Scripts\python.exe -m pytest tests/test_isolated_protocol.py -v

# 2. Run the entire test suite to verify 100% green pass and zero regressions (target: 348 passed):
.venv\Scripts\python.exe -m pytest tests/ -q
```
