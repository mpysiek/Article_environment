# Review & Verification Handoff Report — Recommendation 3

**Agent**: `reviewer_iso_1`  
**Working Directory**: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\reviewer_iso_1`  
**Milestone**: Recommendation 3 Implementation Review  
**Date**: 2026-09-07T13:21:00Z  
**Verdict**: **APPROVE**  

---

## 1. Observation

### 1.1 Direct Inspection of Files and Changes

1. **CLI Argument & Argparse Escaping in `scripts/run_comparison_benchmark.py`**:
   - Line 298: `help="Force 100%% cost-free local evaluation ($0.00 API cost)"` correctly escapes `%` to avoid Python's argparse percent-format crash (`TypeError: %c requires int or char`).
   - Lines 305–306: Added `--isolated-targets` (`action="store_true", default=False, help="Run isolated target evaluation (1 target query per index instance, Recommendation 3)"`).
   - Lines 48, 55, 328: Passed `isolated_targets` from CLI to `run_benchmark_matrix(..., isolated_targets=args.isolated_targets)` and displayed `[*] Protocol: ISOLATED PER-QUERY (Rec 3)` when active.

2. **Isolated Routing Pipeline in `scripts/run_comparison_benchmark.py`**:
   - Line 38: Imported `execute_isolated_retrieval` from `src.evaluation.stages`.
   - Lines 113–120: In `evaluate_scenario`, if `isolated_targets and poison_payloads is not None:`, routes execution directly to:
     ```python
     retrieval_outputs, retrieval_latencies = execute_isolated_retrieval(
         engine=engine,
         clean_docs=clean_docs,
         poison_payloads=poison_payloads,
         queries=queries,
         top_k=config.TOP_K
     )
     ```
   - Lines 210–215: In Phase 2, when `isolated_targets` is enabled, generates isolated payloads via:
     ```python
     poisoned_payloads[key] = poison_mgr.generate_isolated_poison_payloads(
         queries, att_type, attack_budget=b
     )
     ```
   - Lines 233–239: In Phase 3, passes `poison_payloads=poisoned_payloads[key]` to `evaluate_scenario`.
   - Lines 164, 177, 179: Propagates `isolated_targets=isolated_targets` into `Evaluator.evaluate_engine` and `res.isolated_targets = isolated_targets`.
   - Line 266: Propagates `isolated_targets=isolated_targets` into `BenchmarkReporter.generate_markdown_report`.

3. **Metrics Definition and Propagation in `src/evaluation/metrics.py`**:
   - Line 55: Dataclass `EngineBenchmarkResult` explicitly defines `isolated_targets: bool = False`.
   - Lines 91, 111, 126, 155, 360: Propagated across `evaluate_engine`, `evaluate_engine_with_llm`, and returned instance.

4. **Isolated Protocol Execution in `src/evaluation/stages.py`**:
   - Lines 92–124: `execute_isolated_retrieval` isolates the index per query:
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

5. **Dynamic Reporting in `src/visualization/reporter.py`**:
   - Section 5 and Section 6 dynamically format observations and explanations based on `is_isolated_run(results, isolated_targets)`.
   - Pareto ranking with 50% baseline clean recall floor (`MIN_UTILITY_THRESHOLD = 0.50`) dynamically sorts viable engines by lowest targeted ASR and reports `VIABLE` / `NON_VIABLE`.
   - No hardcoded document counts or fixed textual synthesis remain.

### 1.2 Tool Commands and Execution Results

1. **CLI Help Formatting Verification**:
   Command: `.venv\Scripts\python.exe scripts/run_comparison_benchmark.py --help`  
   Result: Exit code 0.  
   Output snippet:
   ```text
   options:
     -h, --help            show this help message and exit
     --corpus {real,synthetic}
                           Corpus type: 'real' (authentic 24k CTI STIX 2.1) or 'synthetic'
     --num_cves NUM_CVES   Target corpus size for real CTI data (default: 24000)
     --queries QUERIES     Number of gold benchmark queries to evaluate (default: 100)
     --cost-free           Force 100% cost-free local evaluation ($0.00 API cost)
     --llm                 Enable OpenRouter LLM generation and judge
     --no-query-echo       Disable verbatim query echo in attack payloads (ablation study)
     --topological         Include PureTopologicalPoisonAttacker in benchmark
     --isolated-targets    Run isolated target evaluation (1 target query per index instance, Recommendation 3)
   ```
   No crash occurred. `--isolated-targets` is verified.

2. **Dedicated Isolated Protocol Test Suite (20 tests)**:
   Command: `.venv\Scripts\python.exe -m pytest tests/test_isolated_protocol.py -v`  
   Result: `============================= 20 passed in 17.74s =============================`

3. **Full Benchmark Regression Test Suite (348 tests)**:
   Command: `.venv\Scripts\python.exe -m pytest tests/`  
   Result: `================== 348 passed, 1 warning in 76.40s (0:01:16) ==================`  
   (Warning: PytestRemovedIn10Warning on a class-scoped fixture in test_m1_adversarial_stress.py; zero failures, zero errors).

---

## 2. Logic Chain

1. **Defect A6 / A3 Mitigation**: In the legacy shared-corpus setup, pooling $B$ payloads for all $N$ queries created an index containing $N \times B$ poison documents. Queries for $Q_i$ retrieved poisons intended for $Q_j$ ($j \ne i$), creating artificial untargeted contamination and causing context saturation that flattened budget sensitivity curves.
2. **Recommendation 3 Mechanics**: Under `--isolated-targets`, for each query $Q_i$, `execute_isolated_retrieval` builds an index containing only `clean_docs` plus the $B$ payloads targeting $Q_i$. Because zero foreign payloads exist in the index during $Q_i$'s evaluation, `retrieval_asr_untargeted` is mathematically and empirically $0.0\%$, and `retrieval_asr_targeted` equals `retrieval_asr_any`.
3. **Budget Resolution Restoration**: The test suite in `tests/test_isolated_protocol.py` (specifically `test_retrieval_asr_targeted_budget_monotonicity` and `test_isolated_mode_avoids_budget_1_saturation`) proves that scaling $B \in \{1, 3, 5\}$ results in varied, monotonic targeted attack impact without false saturation.
4. **Interface Integration**: The flag `--isolated-targets` is properly routed from CLI args to `run_benchmark_matrix`, through `evaluate_scenario`, into `execute_isolated_retrieval`, through `Evaluator` metrics calculation, down to `EngineBenchmarkResult.isolated_targets`, and finally to `BenchmarkReporter` and JSON export files.
5. **No Regressions**: Full regression testing confirmed that all existing 328 tests plus 20 new tests pass cleanly (348/348).

---

## 3. Caveats

1. **Per-Query Index Rebuild Latency**: In isolated evaluation mode on large corpora (e.g. 24,000 real documents), `execute_isolated_retrieval` rebuilds the index per query. For BM25 and GraphRAG, indexing overhead is minor (milliseconds per query). For Dense FAISS, repeated re-encoding of the 24k corpus is prevented by the persistent embedding cache (`DenseFAISSRetriever.embedding_cache`), but users running large matrices should keep this caching behavior in mind.
2. **CLI Parser Test Isolation**: In `tests/test_isolated_protocol.py::TestBenchmarkAndReporterIntegration::test_cli_argument_isolated_targets_parsing`, the test instantiates a standalone `argparse.ArgumentParser()` rather than importing an exported parser function from `scripts/run_comparison_benchmark.py`. However, our independent CLI execution of `python scripts/run_comparison_benchmark.py --help` verified that the actual production script parser functions correctly.

---

## 4. Conclusion & Verdict

**Verdict**: **APPROVE**

All requirements of Recommendation 3 specified in `ORIGINAL_REQUEST.md` (## 2026-09-07T10:52:30Z) and the assignment dispatch have been implemented cleanly, correctly, and robustly:
- `--isolated-targets` CLI argument added and tested without `%c` formatting crashes.
- Proper execution routing to `execute_isolated_retrieval`.
- Dataclass and trace propagation of `isolated_targets: bool`.
- Zero integrity violations detected (real logic, real indexing, real metrics).
- 100% test pass rate across both the 20-test dedicated isolated suite and the full 348-test suite.

---

## 5. Verification Method

To independently verify this approval:

1. **Verify CLI help parsing**:
   ```powershell
   .venv\Scripts\python.exe scripts/run_comparison_benchmark.py --help
   ```
   *Expected*: Exits 0, displays `--cost-free` (escaped percent) and `--isolated-targets`.

2. **Verify dedicated isolated protocol suite**:
   ```powershell
   .venv\Scripts\python.exe -m pytest tests/test_isolated_protocol.py -v
   ```
   *Expected*: 20 passed.

3. **Verify full regression suite**:
   ```powershell
   .venv\Scripts\python.exe -m pytest tests/
   ```
   *Expected*: 348 passed.

### Invalidation Conditions
- Any test in `tests/test_isolated_protocol.py` or `tests/` fails.
- `execute_isolated_retrieval` leaves payloads targeting $Q_j$ in the index during retrieval for $Q_i$.
- `retrieval_asr_untargeted > 0.0` when `isolated_targets=True`.
- Hardcoded literals found in Section 5 or Section 6 of `reporter.py`.
