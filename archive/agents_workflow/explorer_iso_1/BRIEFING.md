# BRIEFING — 2026-09-07T10:55:02Z

## Mission
Investigate the integration of isolated evaluation protocol per query ('1 target query per index instance', Recommendation 3) across retrieval and benchmark execution code.

## 🔒 My Identity
- Archetype: explorer
- Roles: investigation, synthesis, read-only analysis
- Working directory: d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1
- Original parent: e785adae-e1c8-436d-8410-99cd50361b58
- Milestone: Recommendation 3 Isolated Evaluation Protocol Integration Investigation

## 🔒 Key Constraints
- Read-only investigation — do NOT implement
- Write only to .agents/explorer_iso_1/
- Produce report.md and handoff.md in .agents/explorer_iso_1/
- Output must be actionable, detailed, and directly cite files and line numbers

## Current Parent
- Conversation ID: e785adae-e1c8-436d-8410-99cd50361b58
- Updated: 2026-09-07T10:55:02Z

## Investigation State
- **Explored paths**:
  - `scripts/run_comparison_benchmark.py` (CLI parsing, scenario loop, index building, reporting)
  - `src/attacks/poisoning.py` (`generate_isolated_poison_payloads`, `generate_poison_payloads_for_query`, `generate_isolated_corpus_for_query`)
  - `src/evaluation/stages.py` (`execute_isolated_retrieval`, `execute_shared_retrieval`, `make_stage_a_record`)
  - `src/engines/retrievers.py` (`build_index` lifecycle across BM25, DenseFAISS, HybridReranker, GraphRAG)
  - `src/evaluation/metrics.py` (`Evaluator`, `retrieval_asr_targeted`, `retrieval_asr_untargeted`, `retrieval_asr_any`)
  - `src/visualization/reporter.py` (`BenchmarkReporter`, markdown generation, tables, pareto ranking)
  - `tests/` (`test_stages.py`, `test_targeting_evaluation.py`, `test_comparison_system.py`)
- **Key findings**:
  - `scripts/run_comparison_benchmark.py` lacks `--isolated-targets` CLI flag and logic; currently only runs shared-corpus mode where all queries' poisons are pooled. Also has a latent argparse `%c` format crash on line 252 (`help="Force 100% cost-free..."`).
  - `src/attacks/poisoning.py` has complete, functional implementations of `generate_isolated_poison_payloads` and `generate_poison_payloads_for_query` properly setting `poison_target_query=query.id`, `is_poisoned=True`, and differentiating payloads per budget index $b \in \{0, 1, 2, 3, 4\}$.
  - `src/evaluation/stages.py` implements `execute_isolated_retrieval` which iterates over each query, constructs `clean_docs + q_poisons`, calls `engine.build_index(...)`, and runs `engine.retrieve(...)`.
  - All 4 retriever engines support fast per-query index rebuilds: `DenseFAISSRetriever` reuses `_base_embeddings` and FAISS `IndexFlatIP.add`; `GraphRAGRetriever` shallow-copies `_base_graph` and appends poison nodes/edges; `BM25Retriever` caches clean doc tokens in `_doc_token_cache`.
  - In isolated mode, the index for $Q_i$ contains exclusively clean docs and $Q_i$'s poison docs ($B \in \{1, 3, 5\}$). Foreign poisons are guaranteed absent ($Untargeted\ ASR = 0.0\%$).
  - Concrete modifications mapped for `scripts/run_comparison_benchmark.py`, `src/visualization/reporter.py`, and new tests `tests/test_isolated_protocol.py`.
- **Unexplored areas**: None for this milestone.

## Key Decisions Made
- Confirmed that `execute_isolated_retrieval` directly interfaces with `Evaluator.evaluate_engine` and `evaluate_engine_with_llm`.
- Detailed code diff proposals prepared for implementation agents.

## Artifact Index
- d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1\DISPATCH.md — Assignment instructions and messages
- d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1\progress.md — Liveness and execution tracking
- d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1\report.md — Full analysis report
- d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1\handoff.md — 5-component handoff report

