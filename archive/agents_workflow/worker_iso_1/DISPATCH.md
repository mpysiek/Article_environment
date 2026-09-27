# Dispatch for worker_iso_1

## Mission
Implement and verify Recommendation 3 (isolated evaluation protocol per query "1 target query per index instance") in CTI RAG poisoning benchmark.

## Working Directory
`d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\worker_iso_1`

## Mandatory Path
Path to ORIGINAL_REQUEST.md: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md`. Read the section under `## 2026-09-07T10:52:30Z` and earlier sections.

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Explorer Reports to Study
1. `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1\report.md` & `handoff.md` (CLI, stages, index isolation)
2. `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_2\report.md` & `handoff.md` (Reporter, Pareto ranking, zero-hardcoding)
3. `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_3\report.md` & `handoff.md` (20 dedicated tests, backward compatibility, test execution)

## File Ownership
You exclusively own and modify:
- `scripts/run_comparison_benchmark.py`
- `src/evaluation/metrics.py`
- `src/visualization/reporter.py`
- `tests/test_isolated_protocol.py` (new test file)

## Exact Tasks
1. **`src/evaluation/metrics.py`**:
   - Add `isolated_targets: bool = False` to `EngineBenchmarkResult` dataclass.
2. **`scripts/run_comparison_benchmark.py`**:
   - Add CLI argument `--isolated-targets` (action="store_true", default=False, help="Run isolated target evaluation (1 target query per index instance, Recommendation 3)").
   - Fix latent crash bug on line 252 (escape `% c` to `%% c` or format string so `--help` does not crash).
   - In benchmark execution logic:
     - When `--isolated-targets` is active, call `execute_isolated_retrieval` (from `src/evaluation/stages.py`) instead of `execute_shared_retrieval`.
     - In result objects (`EngineBenchmarkResult`), set `isolated_targets=args.isolated_targets`.
     - Pass `isolated_targets=args.isolated_targets` to `BenchmarkReporter.generate_markdown_report`.
3. **`src/visualization/reporter.py`**:
   - Update `generate_markdown_report` to accept `isolated_targets: Optional[bool] = None`. Auto-detect from `results[0].isolated_targets` if `None`.
   - Update Section 1, Section 2 (footnotes), Section 2.3 (budget dynamics: $B \in \{1, 3, 5\}$ sensitivity and zero background saturation explanation), Section 5, and Section 6 dynamically.
   - Enforce Pareto ranking in Section 3 table (`VIABLE` vs `NON_VIABLE` status with `MIN_UTILITY_THRESHOLD = 0.50`).
   - Fix all hardcoded literals in Section 5 (F-R5-01): ensure all figures and conclusions are 100% dynamically synthesized from results.
4. **`tests/test_isolated_protocol.py`**:
   - Create comprehensive unit and integration test suite (20 tests across 5 classes as designed by Explorer 3):
     - `TestZeroForeignPoisonIsolation`: verify query payload partitioning, isolated corpus generation, Top-k search has 0 foreign poison across retrievers, and Evaluator invariants ($ASR_{\text{untargeted}} \equiv 0.0\%$, $ASR_{\text{targeted}} \equiv ASR_{\text{any}}$).
     - `TestBudgetSensitivity`: verify payload scaling, payload diversity across budget indices, monotonic ASR sensitivity across $B \in \{1, 3, 5\}$, avoidance of $B=1$ saturation ceiling, bounded latency.
     - `TestCleanRecallPreservation`: verify clean recall in isolated mode $\ge$ shared mode, matches baseline when attack fails, clean GT hits preserved.
     - `TestSharedModeBackwardCompatibility`: verify `execute_shared_retrieval` works unchanged, produces foreign contamination, Stage A JSONL preserves flags, Evaluator handles both modes.
     - `TestBenchmarkAndReporterIntegration`: verify `--isolated-targets` CLI parsing, report generation with isolated explanations, Pareto table status.
5. **Run Builds and Tests**:
   - Run `pytest tests/test_isolated_protocol.py -v`.
   - Run full regression test suite: `pytest tests/`.
   - Ensure all 348 tests pass with 100% success rate.

## Deliverables
Write your handoff report to `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\worker_iso_1\handoff.md` with:
- Summary of modifications made
- Test commands run and exact outputs
- Confirmation of 100% passing tests
When finished, send a message to parent.

## 2026-09-07T11:02:38Z
You are worker_iso_1.
Your working directory is: d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\worker_iso_1
Your task assignment is in: d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\worker_iso_1\DISPATCH.md
The original user request is in: d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md (read especially the section under ## 2026-09-07T10:52:30Z).

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Detailed guidance from survey explorers:
1. `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1\report.md` & `handoff.md` (CLI, stages, index isolation)
2. `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_2\report.md` & `handoff.md` (Reporter, Pareto ranking, zero-hardcoding)
3. `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_3\report.md` & `handoff.md` (20 dedicated tests, backward compatibility, test execution)

Your exclusive write ownership:
- `scripts/run_comparison_benchmark.py`
- `src/evaluation/metrics.py`
- `src/visualization/reporter.py`
- `tests/test_isolated_protocol.py`

Your tasks:
1. `src/evaluation/metrics.py`: Add `isolated_targets: bool = False` to `EngineBenchmarkResult`.
2. `scripts/run_comparison_benchmark.py`:
   - Add CLI argument `--isolated-targets` (default False, action="store_true").
   - Fix latent crash bug on line 252 (escape `% c` to `%% c` so `--help` does not fail).
   - In benchmark execution, when `--isolated-targets` is passed, call `execute_isolated_retrieval` instead of `execute_shared_retrieval`.
   - Propagate `isolated_targets=args.isolated_targets` into `EngineBenchmarkResult` and `generate_markdown_report`.
3. `src/visualization/reporter.py`:
   - Accept `isolated_targets: Optional[bool] = None` in `generate_markdown_report` (auto-detect if None).
   - Ensure dynamic description of isolated protocol, budget dynamics without background saturation, and Pareto status (`VIABLE` vs `NON_VIABLE` with 50% utility threshold).
   - Completely eliminate hardcoded strings in Section 5 (F-R5-01).
4. `tests/test_isolated_protocol.py`:
   - Implement the 20 dedicated unit and integration tests across 5 classes (as designed in Explorer 3's report).
5. Verification:
   - Run `pytest tests/test_isolated_protocol.py -v`
   - Run `pytest tests/` (all 348 tests must pass 100%).

Deliverables:
Write your handoff report to `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\worker_iso_1\handoff.md` with:
- Summary of modifications made
- Exact test commands run and outputs
- Confirmation of 100% passing tests
When finished, send a completion message to parent.
