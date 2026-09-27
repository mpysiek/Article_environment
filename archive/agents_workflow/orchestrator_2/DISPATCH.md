# Dispatch Log

## 2026-09-07T10:54:09Z

You are the Project Orchestrator for the task defined in d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md under header '## 2026-09-07T10:52:30Z'.

Task: Completion of Recommendation 3 implementation (isolated evaluation protocol per query '1 target query per index instance') in CTI RAG poisoning benchmark.

Working directory: d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\orchestrator_2
Project root: d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark

Requirements:
- R1. Integration of Isolated Protocol in Benchmark:
  * Full integration of '--isolated-targets' (or isolated mode) in scripts/run_comparison_benchmark.py.
  * In isolated mode, for each test query Q_i, the search index contains the clean corpus and EXCLUSIVELY poisoned payloads generated for that specific query (B in {1, 3, 5}). No payloads addressed to other queries may be present in the index during evaluation of Q_i.
  * Leverage existing functions in src/attacks/poisoning.py (generate_isolated_poison_payloads, generate_poison_payloads_for_query) and src/evaluation/stages.py (execute_isolated_retrieval).
  * Ensure report generator src/visualization/reporter.py correctly presents and describes isolated mode results (budget dynamics, no artificial background saturation).
- R2. Unit and Integration Tests:
  * Dedicated test suite (e.g. tests/test_isolated_protocol.py) verifying:
    1. Zero foreign query poison in Top-k results for test query Q_i in isolated mode.
    2. Budget sensitivity of retrieval_asr_targeted across B in {1, 3, 5}.
    3. Proper clean recall behavior (clean_recall_top5) with only target payloads present.
    4. Backward compatibility with shared mode (shared index).
- R3. Test Suite Integrity:
  * 100% of tests must pass (pytest tests/ - existing 328 tests + new isolated protocol tests).
  * All modifications strictly within d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark.

Maintain BRIEFING.md and progress.md in your working directory (d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\orchestrator_2) so sentinel can monitor your progress.
When all tasks and acceptance criteria are completed and verified, report completion to the sentinel.
