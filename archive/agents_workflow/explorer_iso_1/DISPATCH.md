# Dispatch for explorer_iso_1

## Task
Investigate the integration of isolated evaluation protocol per query ('1 target query per index instance', Recommendation 3) across the retrieval and benchmark execution code:
- Primary files: `scripts/run_comparison_benchmark.py`, `src/evaluation/stages.py`, `src/attacks/poisoning.py`.
- Path to ORIGINAL_REQUEST.md: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md`. Read the section under `## 2026-09-07T10:52:30Z` and relevant parts of the earlier section.
- Investigate:
  1. How `scripts/run_comparison_benchmark.py` parses CLI arguments, builds indices, and runs queries. Does it have `--isolated-targets`? What is missing or broken for isolated mode?
  2. How `src/attacks/poisoning.py` implements `generate_isolated_poison_payloads` and `generate_poison_payloads_for_query`. Are they complete and functional?
  3. How `src/evaluation/stages.py` implements `execute_isolated_retrieval`. How does it interact with index building, vector databases, and GraphRAG?
  4. How the index is constructed per query $Q_i$ in isolated mode: clean corpus + EXCLUSIVELY poisoned payloads for $Q_i$ ($B \in \{1, 3, 5\}$). Verify that no payloads addressed to other queries are present during evaluation of $Q_i$.
  5. What exact modifications are required in `scripts/run_comparison_benchmark.py` to ensure seamless execution in both real and synthetic/mock benchmark modes?

Output:
Write a comprehensive report to `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1\report.md` and handoff to `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1\handoff.md`. Send a completion message when finished.

## 2026-09-07T10:55:02Z
Task Assignment received: Investigate integration of isolated evaluation protocol per query across retrieval and benchmark execution code (Recommendation 3).

## 2026-09-07T11:00:28Z
**Context**: Survey of retrieval stages and benchmark script
**Content**: Please do not block on interactive terminal commands. Complete your analysis by statically inspecting `scripts/run_comparison_benchmark.py`, `src/attacks/poisoning.py`, and `src/evaluation/stages.py`.
**Action**: Write your report to report.md and handoff.md, then send your completion message.


