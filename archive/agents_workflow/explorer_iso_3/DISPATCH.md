# Dispatch for explorer_iso_3

## 2026-09-07T10:55:00Z

Task:
Investigate the testing environment and test specifications for Recommendation 3:
- Primary files: `tests/`, `pytest.ini` / test configuration, and existing stages/protocol tests.
- Investigate:
  1. Map the existing test suite: run / inspect current test inventory (how many tests, what test files exist, e.g. `tests/test_stages.py`, `tests/test_benchmark.py`, `tests/test_reporter.py`, etc.).
  2. How fast do existing tests run? Are embeddings mocked or fast?
  3. Formulate the exact test design for `tests/test_isolated_protocol.py` to satisfy R2:
     - Zero foreign query poison in Top-k results for test query Q_i in isolated mode.
     - Budget sensitivity of `retrieval_asr_targeted` across B in {1, 3, 5}.
     - Proper clean recall behavior (`clean_recall_top5`) with only target payloads present.
     - Backward compatibility with shared mode (shared index).
  4. Identify any potential test fragility, dependencies, or regressions against the existing 328 tests.

Output:
Write your full analysis report to `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_3\report.md` and handoff report to `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_3\handoff.md`.
When finished, send a completion message to parent.
