# Progress — challenger_iso_1

- **Status**: Complete — VERDICT: APPROVE
- **Last visited**: 2026-09-07T13:24:15Z

## Tasks
- [x] 1. Codebase inspection of isolated mode implementation
- [x] 2. Challenge 1: Zero Foreign Poison Invariant across BM25, DenseFAISS, HybridRerank, GraphRAG
  - Verified: Zero foreign poison leakage in Top-k under adversarial cross-stuffing and multi-query setups.
  - Verified: Internal index state (documents, FAISS vectors, NetworkX graph nodes) cleaned after every query.
- [x] 3. Challenge 2: Evaluator invariants (`retrieval_asr_untargeted == 0.0%`, `retrieval_asr_targeted == retrieval_asr_any`)
  - Verified: Strictly holds unconditionally in isolated mode across all 4 retrievers and mock trace configurations.
- [x] 4. Challenge 3: Budget sensitivity ($B \in \{1, 3, 5\}$) payload diversity & non-saturation
  - Verified: Payloads across all 6 attack vectors produce distinct doc IDs, texts, entities, relations.
  - Verified: B=1 context saturation eliminated (max 1 poison in Top-5, leaving >=4 clean docs).
- [x] 5. Challenge 4: Edge cases (1 query, odd budgets, empty clean corpus, high top_k, B=0, hostile text)
  - Verified: All edge cases pass cleanly across all retrievers and evaluator.
- [x] 6. End-to-end benchmark CLI verification (`scripts/run_comparison_benchmark.py --isolated-targets`)
  - Verified: Benchmark CLI runs cleanly in isolated mode, outputs Pareto ranking and dynamic report.
- [x] 7. Full regression test suite (`pytest tests/` - 377 passed)
- [x] 8. Final verdict and handoff report
