# Dispatch for reviewer_iso_1

## Task
Review the code, logic, and interface integration of Recommendation 3 (isolated evaluation protocol per query):
- Files to examine: `scripts/run_comparison_benchmark.py`, `src/evaluation/metrics.py`, `src/evaluation/stages.py`, `worker_iso_1/handoff.md`.
- Path to ORIGINAL_REQUEST.md: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md` (read especially ## 2026-09-07T10:52:30Z).
- Working directory: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\reviewer_iso_1`.
- Review criteria:
  1. Correctness of CLI argument `--isolated-targets` and fix for argparse `% c` formatting crash on line 288.
  2. Correctness of routing to `execute_isolated_retrieval` in `scripts/run_comparison_benchmark.py`.
  3. Proper setting and propagation of `isolated_targets: bool` in `EngineBenchmarkResult` in `src/evaluation/metrics.py`.
  4. Robustness against regressions.
  5. Run or verify test execution (`pytest tests/test_isolated_protocol.py`, `pytest tests/`).
- Output:
  Write `handoff.md` to your working directory with explicit verdict: **APPROVE** or **REQUEST_CHANGES**, followed by detailed technical rationale.
  Send a message to parent with your verdict and summary.
