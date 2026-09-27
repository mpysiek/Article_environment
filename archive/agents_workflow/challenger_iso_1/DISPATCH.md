# Dispatch for challenger_iso_1

## Task
Adversarially challenge and stress-test the isolated evaluation protocol (Recommendation 3):
- Focus: Zero Foreign Poison Invariant and Budget Sensitivity ($B \in \{1, 3, 5\}$).
- Path to ORIGINAL_REQUEST.md: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md` (read especially ## 2026-09-07T10:52:30Z).
- Working directory: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\challenger_iso_1`.
- Challenge tasks:
  1. Inspect and test whether any poison document created for query $Q_j$ ($j \ne i$) can ever leak into the isolated index or the Top-k results when evaluating query $Q_i$, across all 4 retrievers (BM25, DenseFAISS, HybridRerank, GraphRAG).
  2. Verify Evaluator invariants: in isolated mode, is `retrieval_asr_untargeted` strictly 0.0%? Does `retrieval_asr_targeted == retrieval_asr_any` hold unconditionally?
  3. Stress-test budget sensitivity: verify that increasing budget from $B=1$ to $B=3$ to $B=5$ produces diverse payloads (not bitwise duplicates) and preserves metric sensitivity without premature saturation at $B=1$.
  4. Test edge cases: 1 query, odd budgets, empty clean corpus, high top_k.
- Output:
  Write `handoff.md` to your working directory with explicit verdict: **APPROVE** or **REJECT**, followed by empirical evidence.
  Send a message to parent with your verdict and findings.
