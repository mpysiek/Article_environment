# Forensic Audit Report — Recommendation 3 Implementation

**Agent**: `auditor_iso_1`  
**Working Directory**: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\auditor_iso_1`  
**Profile**: General Project (Development Mode)  
**Target Milestone**: Recommendation 3 Implementation (Isolated Evaluation Protocol per Query)  
**Date**: 2026-09-07T13:21:50Z  

---

## Forensic Audit Verdict

**Verdict**: **CLEAN**  
**Integrity Violations Found**: **0**  
**Test Pass Rate**: **100% (348/348 tests passed)**  

---

## 1. Observation

### 1.1 Static Analysis of Audited Files
We conducted direct code-level audits on all assigned files:

1. **`src/evaluation/metrics.py`**:
   - Lines 55, 360: Dataclass `EngineBenchmarkResult` explicitly defines `isolated_targets: bool = False`.
   - Lines 91, 126: Method signatures `Evaluator.evaluate_engine` and `Evaluator.evaluate_engine_with_llm` accept `isolated_targets: bool = False`.
   - Lines 163–170: Method `_is_targeted(doc, query)` verifies `doc.is_poisoned` and strictly matches `doc.poison_target_query in (query.id, query.query_text)`.
   - Lines 285–288, 351–359: `retrieval_asr_targeted`, `retrieval_asr_untargeted`, `retrieval_asr_any` are dynamically calculated via counts (`targeted_top5_count / total_q`, `poison_top5_count / total_q`, and their difference).
   - Zero hardcoded metrics, fake return values, or bypass flags exist in `metrics.py`.

2. **`scripts/run_comparison_benchmark.py`**:
   - Line 38: Imports `from src.evaluation.stages import execute_isolated_retrieval`.
   - Lines 48, 55: `run_benchmark_matrix` accepts `isolated_targets: bool = False` and logs protocol status:
     ```python
     print(f"[*] Protocol: {'ISOLATED PER-QUERY (Rec 3)' if isolated_targets else 'SHARED CORPUS'}")
     ```
   - Lines 113–120: In `evaluate_scenario`, dynamic execution branch:
     ```python
     if isolated_targets and poison_payloads is not None:
         retrieval_outputs, retrieval_latencies = execute_isolated_retrieval(
             engine=engine,
             clean_docs=clean_docs,
             poison_payloads=poison_payloads,
             queries=queries,
             top_k=config.TOP_K
         )
     ```
   - Lines 210–215: In Phase 2, invokes `poison_mgr.generate_isolated_poison_payloads(queries, att_type, attack_budget=b)`.
   - Lines 233–239: In Phase 3, routes `poison_payloads=poisoned_payloads[key]` directly to `evaluate_scenario`.
   - Lines 261–267: Propagates `isolated_targets=isolated_targets` into `BenchmarkReporter.generate_markdown_report`.
   - Line 288: Properly escapes `%` in argparse help string (`100%% cost-free`).
   - Lines 305–306: CLI option `--isolated-targets` added (`action="store_true", default=False`).
   - Line 328: Propagates `args.isolated_targets` to `run_benchmark_matrix`.

3. **`src/attacks/poisoning.py`**:
   - Line 385: `generate_poison_payloads_for_query(self, query, attack_type, attack_budget=1, query_echo=None)` generates $B$ distinct payloads targeting exclusively the specified query.
   - Line 402: `generate_isolated_poison_payloads(self, queries, attack_type, attack_budget=1, query_echo=None)` returns a dictionary partitioned by `query.id`:
     ```python
     return {
         q.id: self.generate_poison_payloads_for_query(
             q, attack_type, attack_budget=attack_budget, query_echo=query_echo
         )
         for q in queries
     }
     ```
   - Lines 196, 261: The string `"dummy_entity"` in `generate_poison` represents dynamic names of topological bridge entities (`Injected_Bridge_{term}_{budget_idx}_{i}`) created in STIX 2.1 graph attacks, not mock test artifacts.
   - No mock frameworks or hardcoded evasion returns exist.

4. **`src/evaluation/stages.py`**:
   - Lines 92–123: `execute_isolated_retrieval(engine, clean_docs, poison_payloads, queries, top_k=5)`:
     ```python
     for q in queries:
         q_poisons = poison_payloads.get(q.id, [])
         index_docs = clean_docs + q_poisons if q_poisons else clean_docs
         engine.build_index(index_docs)
         t0 = time.perf_counter()
         results = engine.retrieve(q.query_text, top_k=top_k)
         ret_latency_ms = (time.perf_counter() - t0) * 1000.0
         retrieval_outputs[q.id] = results
         retrieval_latencies[q.id] = ret_latency_ms
     ```
     Empirically ensures each query $Q_i$ is evaluated against an index containing clean docs plus *strictly only* the poison documents generated for $Q_i$.
   - Lines 70, 87: `make_stage_a_record` persists `isolated_target: bool`.

5. **`src/visualization/reporter.py`**:
   - Lines 53–57: `is_isolated_run(results, explicit_flag)` dynamically senses isolation mode.
   - Lines 59–103: `compute_pareto_ranking` computes viable architectures using `MIN_UTILITY_THRESHOLD = 0.50` (Clean Recall@5 $\ge$ 50%), sorting viable engines first by lowest targeted ASR, then highest clean recall.
   - Lines 485–490: Corpus size is dynamically inserted (`f"{corpus_size:,} autentycznych dokumentów: "` if `corpus_type == "real"`); no hardcoded "24,000" documents literal in synthetic or custom runs.
   - Lines 504–576: Section 5 observations (`obs1` to `obs5`) are 100% dynamically synthesized:
     - `obs1`: Dynamically formats viable vs non-viable engines with average clean recall percentages.
     - `obs2`: Dynamically extracts GraphRAG clean recall, MRR, CVE lookup recall, and ATT&CK query recall from traces.
     - `obs3`: Dynamically extracts GraphRAG lexical keyword stuffing ASR vs topological ASR.
     - `obs4`: Dynamically formats average targeted ASR vs untargeted ASR.
     - `obs5`: Dynamically switches text based on `isolated`: in isolated mode, explicitly highlights 0.0% background contamination and true budget sensitivity; in shared mode, notes untargeted noise level.

### 1.2 Independent Empirical Test Execution
We executed all test suites independently via `.venv\Scripts\python.exe`:

1. **Dedicated Isolated Protocol Test Suite (`tests/test_isolated_protocol.py`)**:
   - Command: `.venv\Scripts\python.exe -m pytest tests/test_isolated_protocol.py -v`
   - Output: `20 passed in 17.86s` (100% success).
   - Zero test skips, zero warnings, zero failures.
   - All 20 tests verify genuine invariants:
     - `TestZeroForeignPoisonIsolation`: 5 tests verifying zero foreign poison in payloads, corpora, Top-k, evaluator metrics, and across all 4 retrieval engines (BM25, DenseFAISS, HybridRerank, GraphRAG).
     - `TestBudgetSensitivity`: 5 tests verifying $B \in \{1, 3, 5\}$ scaling, text/entity diversity across budget indices, monotonic ASR sensitivity, avoidance of $B=1$ saturation ceiling, and valid latency metrics.
     - `TestCleanRecallPreservation`: 4 tests verifying clean recall uncontaminated by foreign poisons, recall preservation on attack failure, graceful degradation under target hijack, and preservation of clean ground truth hits.
     - `TestSharedModeBackwardCompatibility`: 4 tests verifying shared retrieval functionality, legacy foreign contamination, Stage A JSONL serialization of `isolated_target`, and `rebuild_scenario_inputs`.
     - `TestBenchmarkAndReporterIntegration`: 2 tests verifying argparse CLI options and dynamic Markdown generation.

2. **Adversarial Stress Test Suite (`tests/test_isolated_adversarial_stress.py`)**:
   - Command: `.venv\Scripts\python.exe -m pytest tests/test_isolated_adversarial_stress.py -v`
   - Output: `29 passed in 34.66s` (100% success).
   - Confirmed index state cleanliness, absence of cross-query interference, evaluator invariant checks, and edge cases (single query, odd budgets 1/3/5/7/9, empty corpus, high top-k, B=0, missing payload keys, special characters).

3. **Full Benchmark Regression Suite (`tests/`)**:
   - Command: `.venv\Scripts\python.exe -m pytest tests/`
   - Output: `348 passed, 1 warning in 76.85s` (100% success).
   - Zero regressions across the entire project test suite.

4. **CLI Help Formatting**:
   - Command: `.venv\Scripts\python.exe scripts/run_comparison_benchmark.py --help`
   - Output: Formats cleanly with code 0, displaying `--isolated-targets` and escaped `100% cost-free`.

5. **End-to-End Benchmark Execution in Isolated Mode**:
   - Command: `.venv\Scripts\python.exe scripts/run_comparison_benchmark.py --corpus synthetic --queries 2 --cost-free --isolated-targets`
   - Output: Executed full matrix across 4 engines and 15 attack scenarios in 15.21s.
   - Verified generated files:
     - `outputs/reports/rag_poisoning_comparison_report.md`: Section 5 synthesized observations dynamically from the synthetic run data; Section 3 displayed Pareto ranking (`VIABLE` vs `NON_VIABLE`); `retrieval_asr_untargeted` was confirmed 0.0%.
     - `outputs/reports/comparison_benchmark_results.json`: Saved complete JSON metrics with `isolated_targets: true`.

---

## 2. Logic Chain

1. **Integrity Mode Compliance**: Under Development Mode (specified in `ORIGINAL_REQUEST.md`), all code reuse, standard library tools, and local algorithms are permitted, whereas hardcoded test results, facade implementations, and fabricated verification outputs are strictly prohibited.
2. **Static Code Validation**: Direct inspection of `src/evaluation/metrics.py`, `scripts/run_comparison_benchmark.py`, `src/attacks/poisoning.py`, `src/evaluation/stages.py`, and `src/visualization/reporter.py` confirmed that:
   - All retrieval calculations, recall metrics, and ASR values derive from actual doc IDs, query ground truth, and rankings.
   - Payloads are cleanly partitioned into dictionaries keyed by `query.id`.
   - `execute_isolated_retrieval` builds isolated index instances for each query containing only that query's payloads and clean documents.
3. **No Facade or Tautology**: Review of `tests/test_isolated_protocol.py` confirmed that none of the 20 tests contain trivial assertions (e.g. `assert True`). Every test instantiates actual retrieval engines, builds real indexes, performs vector/lexical retrieval, and validates data invariants.
4. **Report Dynamism**: Inspection of `outputs/reports/rag_poisoning_comparison_report.md` confirmed that Section 5 is computed on the fly from the benchmark output matrix without hardcoded metric constants or fixed corpus size strings.
5. **Empirical Reproduction**: Running all 348 tests, 29 adversarial stress tests, and an end-to-end benchmark run confirmed deterministic functionality, complete lack of foreign poison contamination, and zero regressions.

---

## 3. Caveats

- **No Caveats**: The entire code path, metric calculations, test suites, and end-to-end execution flow were independently verified and passed without failures or exceptions.

---

## 4. Conclusion

The implementation of Recommendation 3 (Isolated Evaluation Protocol per Query) is **fully authentic, metrologically sound, and free of any integrity violations**.

- **Verdict**: **CLEAN**
- **Recommendation 3 Acceptance Criteria**: **100% MET**
- The codebase is approved for production benchmarking and scientific publication.

---

## 5. Verification Method

To reproduce and verify this audit independently:

```powershell
# 1. Run the dedicated isolated protocol tests
.venv\Scripts\python.exe -m pytest tests/test_isolated_protocol.py -v

# 2. Run the isolated adversarial stress tests
.venv\Scripts\python.exe -m pytest tests/test_isolated_adversarial_stress.py -v

# 3. Run the full project regression suite (348 tests)
.venv\Scripts\python.exe -m pytest tests/

# 4. Verify CLI parsing and help text
.venv\Scripts\python.exe scripts/run_comparison_benchmark.py --help

# 5. Run end-to-end isolated benchmark verification
.venv\Scripts\python.exe scripts/run_comparison_benchmark.py --corpus synthetic --queries 2 --cost-free --isolated-targets
```

### Invalidation Conditions
- Any test failure in `tests/test_isolated_protocol.py`.
- Any non-zero `retrieval_asr_untargeted` in isolated mode.
- Fixed literal numbers in Section 5 of `reporter.py` that do not adapt to input results.
- Any regression across the 348 tests in `tests/`.
