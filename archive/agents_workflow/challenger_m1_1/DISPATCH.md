## 2026-09-06T20:09:51Z
You are Challenger 1 for Milestone 1 (Targeting-Aware Evaluation, R1).
Your working directory is:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\challenger_m1_1
Your parent orchestrator is: dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635

MANDATORY FIRST STEP: Read the authoritative user requirements:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md

Read the project specification:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\orchestrator_1\PROJECT.md

Read the worker handoff:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\worker_m1\handoff.md

Your task:
Adversarially stress-test the Milestone 1 implementation:
1. Write and execute empirical stress tests and edge cases against `RetrievalResult`, all 4 retrievers, `stages.py` serialization, and `Evaluator`:
   - Mix of targeted and untargeted poison documents in top-5 (e.g. rank 1 untargeted, rank 2 targeted).
   - Queries with special characters or IDs matching document substrings.
   - Corrupted or missing `poison_target_query` attributes.
   - High density background contamination (50+ foreign poisons).
2. Empirically verify that `retrieval_asr_targeted` never falsely flags foreign contamination as an attack success.
3. Output your stress test findings in `challenge.md` and deliver `handoff.md` with explicit Verdict: APPROVE or REJECT.
4. Send completion message to parent (dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635).
