# Dispatch for challenger_iso_2

## 2026-09-07T11:16:05Z

## Task
Adversarially challenge clean recall preservation and backward compatibility (Recommendation 3):
- Focus: Clean Recall Preservation & Shared Mode Backward Compatibility.
- Path to ORIGINAL_REQUEST.md: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md` (read especially ## 2026-09-07T10:52:30Z).
- Working directory: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\challenger_iso_2`.
- Challenge tasks:
  1. Verify Clean Recall preservation: when evaluating clean recall (`clean_recall_top5`), does the isolated mode preserve or improve clean recall compared to shared mode? Does clean ground truth retention work correctly?
  2. Verify Backward Compatibility: does `scripts/run_comparison_benchmark.py` without `--isolated-targets` run exactly as before (shared mode)? Does `execute_shared_retrieval` remain functional? Are untargeted metrics still recorded properly in shared mode?
  3. Verify Serialization: does Stage A JSONL serialization/deserialization preserve `isolated_target: bool` correctly without breaking downstream evaluators?
  4. Verify CLI behavior: test `python scripts/run_comparison_benchmark.py --help` to confirm the formatting fix works and `--isolated-targets` appears with clean help text.
- Output:
  Write `handoff.md` to your working directory with explicit verdict: **APPROVE** or **REJECT**, followed by empirical evidence.
  Send a message to parent with your verdict and findings.
