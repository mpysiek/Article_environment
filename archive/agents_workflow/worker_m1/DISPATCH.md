## 2026-09-06T20:01:02Z
You are a Worker agent implementing Milestone 1 (Requirement R1: Targeting-Aware Evaluation and Context Contamination Separation, Flaws A1 & A6).
Your working directory is:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\worker_m1
Your parent orchestrator is: dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635

MANDATORY FIRST STEP: Read the authoritative user requirements:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\ORIGINAL_REQUEST.md

Read the project specification:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\orchestrator_1\PROJECT.md

Read the explorer analysis and handoff:
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_survey_1\analysis.md
d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_survey_1\handoff.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A forensic auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your scope and exclusive write ownership:
1. `src/corpus/dataset.py`:
   - In `RetrievalResult`, add fields:
     `poison_target_query: Optional[str] = None`
     `poison_type: Optional[str] = None`
2. `src/engines/retrievers.py`:
   - In `BM25Retriever.retrieve`, `DenseFAISSRetriever.retrieve`, `HybridRerankRetriever.retrieve`, and `GraphRAGRetriever.retrieve`:
     When constructing `RetrievalResult`, propagate `doc.poison_target_query` and `doc.poison_type` from `doc` (`CTIDocument`).
3. `src/evaluation/stages.py`:
   - In `retrieval_result_to_dict()` and `retrieval_result_from_dict()`:
     Serialize and deserialize `poison_target_query` and `poison_type` losslessly so Stage A -> Stage C handoffs retain targeting metadata.
4. `src/evaluation/metrics.py`:
   - In `EngineBenchmarkResult`, add:
     `retrieval_asr_targeted: float = 0.0`
     `retrieval_asr_untargeted: float = 0.0`
     `retrieval_asr_any: float = 0.0`
   - In `Evaluator.evaluate_engine_with_llm` and any retrieval evaluation methods:
     A document is a targeted attack success if `r.is_poisoned` AND `r.poison_target_query == q.id` (or `r.poison_target_query == q.query_text` if matched by query id/text).
     Calculate:
     `retrieval_asr_targeted`: proportion of queries where Top-k contains poison dedicated to this specific query.
     `retrieval_asr_any`: proportion of queries where Top-k contains any poison document.
     `retrieval_asr_untargeted`: `retrieval_asr_any - retrieval_asr_targeted`.
     Ensure backward compatibility: `retrieval_asr` can mirror `retrieval_asr_targeted` or be explicitly documented.
5. Create unit tests in `tests/test_targeting_evaluation.py` thoroughly validating:
   - Schema fields on `RetrievalResult`
   - Propagation across all 4 retrievers
   - Stage serialization round-trip
   - Metric calculation separating targeted ASR from foreign background contamination (e.g. Q1 poison retrieved by Q2 does NOT increment targeted ASR for Q2, but increments untargeted/any ASR).
6. Run build & test commands via `.\.venv\Scripts\python.exe -m pytest tests/` and confirm 100% pass rate.
