# Handoff Report: Milestone 1 — Targeting-Aware Evaluation and Context Contamination Separation (Requirement R1, Flaws A1 & A6)

**Agent:** Worker Agent (`worker_m1`)  
**Working Directory:** `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\worker_m1`  
**Parent Orchestrator:** `dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635`  
**Date:** 2026-09-06  
**Type:** Hard Handoff (Milestone 1 Implementation & Verification Complete)

---

## 1. Observation

### 1.1 Baseline Defect State
- In `src/corpus/dataset.py:27-35`, `RetrievalResult` lacked targeting metadata fields (`poison_target_query` and `poison_type`), despite `CTIDocument:13-14` declaring both fields.
- In `src/engines/retrievers.py:56-65, 224-233, 282-291, 400-409`, all four retrieval engines (`BM25Retriever`, `DenseFAISSRetriever`, `HybridRerankRetriever`, `GraphRAGRetriever`) dropped `doc.poison_target_query` and `doc.poison_type` when creating `RetrievalResult` instances.
- In `src/evaluation/stages.py:29-53`, `retrieval_result_to_dict()` and `retrieval_result_from_dict()` omitted targeting fields, stripping them during Stage A to Stage C pipeline handoffs.
- In `src/evaluation/metrics.py:121-133`, `Evaluator.evaluate_engine_with_llm()` computed Attack Success Rate (`retrieval_asr_top1`, `top3`, `top5`) solely via `any(r.is_poisoned for r in results[:k])`, counting foreign background contamination (e.g. payload targeting $Q_1$ appearing in the context for $Q_2$) as an attack success on $Q_2$. `EngineBenchmarkResult` lacked fields for `retrieval_asr_targeted`, `retrieval_asr_untargeted`, and `retrieval_asr_any`.

### 1.2 Implemented Changes
1. **`src/corpus/dataset.py` (lines 26-44):**
   - Added `poison_target_query: Optional[str] = None` and `poison_type: Optional[str] = None` to `RetrievalResult`.
   - Added `__post_init__` to gracefully handle legacy calls where a dictionary was passed as the 8th positional parameter (mapping it to `self.metadata`), preserving 100% backward compatibility with legacy test fixtures.
2. **`src/engines/retrievers.py` (lines 43-98, 245-260, 310-325, 430-445):**
   - Propagated `doc.poison_target_query` and `doc.poison_type` across all 4 retrievers:
     - `BM25Retriever.retrieve()`
     - `DenseFAISSRetriever.retrieve()`
     - `HybridRerankRetriever.retrieve()`
     - `GraphRAGRetriever.retrieve()`
   - Added graceful handling in `BM25Retriever` for empty corpus (`self.documents == []`) and empty token documents (`["__empty__"]`), preventing `ZeroDivisionError` in `rank_bm25`.
   - Implemented deterministic, stable tie-breaking in `BM25Retriever`: `sorted(range(len(scores)), key=lambda idx: (-scores[idx], idx))[:top_k]`.
3. **`src/evaluation/stages.py` (lines 29-57):**
   - Updated `retrieval_result_to_dict()` to serialize `"poison_target_query": r.poison_target_query` and `"poison_type": r.poison_type`.
   - Updated `retrieval_result_from_dict()` to read `d.get("poison_target_query")` and `d.get("poison_type")`.
4. **`src/evaluation/metrics.py` (lines 8-60, 105-300):**
   - Added `has_targeted_poison_in_top1`, `has_targeted_poison_in_top5`, `has_untargeted_poison_in_top1`, `has_untargeted_poison_in_top5` (all defaulting to `False`) to `GenerationTrace`.
   - Added `retrieval_asr_targeted: float = 0.0`, `retrieval_asr_untargeted: float = 0.0`, `retrieval_asr_any: float = 0.0`, along with Top-1 / Top-5 granular fields and `@property retrieval_asr` / `@property clean_recall_at_k` to `EngineBenchmarkResult`.
   - In `Evaluator.evaluate_engine_with_llm()`, defined targeted attack success as:
     `r.is_poisoned and (r.poison_target_query == q.id or r.poison_target_query == q.query_text)`
   - Computed:
     - `retrieval_asr_targeted = targeted_top5_count / total_q`
     - `retrieval_asr_any = poison_top5_count / total_q`
     - `retrieval_asr_untargeted = retrieval_asr_any - retrieval_asr_targeted`
5. **`tests/test_targeting_evaluation.py`:**
   - Created 14 unit tests validating schema fields, all 4 retrievers, stage serialization round-trip, and metric separation.

### 1.3 Execution Results
- `.\.venv\Scripts\python.exe -m pytest tests/test_targeting_evaluation.py`:
  - Output: `14 passed in 20.44s`
- `.\.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "_r1_"`:
  - Output: `40 passed, 185 deselected in 9.37s` (100% of all R1 tests in E2E suite passed)
- `.\.venv\Scripts\python.exe -m pytest tests/ --ignore=tests/test_e2e_remediation.py`:
  - Output: `85 passed in 57.50s` (all 71 legacy unit tests + 14 new tests passed with 0 regressions)

---

## 2. Logic Chain

1. **Step 1 (Schema & Retention):**
   - By declaring `poison_target_query` and `poison_type` on `RetrievalResult`, the data structure now matches Contract 1 of `PROJECT.md`.
   - Propagating these attributes in `BM25Retriever`, `DenseFAISSRetriever`, `HybridRerankRetriever`, and `GraphRAGRetriever` ensures that whenever an adversarial payload is retrieved, its intended target query is preserved directly on the result object.
2. **Step 2 (Serialization Fidelity):**
   - Including `poison_target_query` and `poison_type` in `retrieval_result_to_dict()` and `retrieval_result_from_dict()` guarantees that during asynchronous multi-stage evaluation (Stage A $\rightarrow$ Stage B $\rightarrow$ Stage C), targeting metadata survives JSONL serialization to disk without truncation.
3. **Step 3 (Metric Disaggregation - Addressing Flaws A1 & A6):**
   - When evaluating a query $Q_2$, if the retrieved Top-$k$ contains a poison document that was generated to target $Q_1$, `_is_targeted(r, Q2)` evaluates to `False`.
   - Consequently, $Q_2$ does not increment `targeted_top5_count`, preventing false-positive attack success attribution (Flaw A1).
   - Simultaneously, because $r$ is poisoned, $Q_2$ increments `poison_top5_count` (`retrieval_asr_any`).
   - The background contamination rate is accurately quantified by `retrieval_asr_untargeted = retrieval_asr_any - retrieval_asr_targeted`.
   - This cleanly separates genuine adversarial vulnerability from background distractor pollution, directly resolving Flaw A6.
4. **Step 4 (Backward Compatibility):**
   - Legacy code and scripts referencing `res.retrieval_asr_top1`, `res.retrieval_asr_top5`, or `res.retrieval_asr_cond` continue to function identically.
   - The new property `@property retrieval_asr` points to `self.retrieval_asr_targeted`, ensuring that any downstream consumer expecting a single scalar ASR receives the scientifically sound targeted metric.

---

## 3. Caveats

1. **E2E Suite Future Milestones:**
   - The file `tests/test_e2e_remediation.py` tests all project milestones (M1 through M5). Tests for M2 (GraphRAG namespace prefixes `doc:`/`ent:`), M3 (budget diversity & echo ablation), M4 (LLM judge unparseable response isolation), and M5 (dynamic report generator & McNemar binomial test) are failing as expected because those features belong to subsequent milestones.
   - For Milestone 1, 100% of R1 tests (40/40 tests across Tier 1 and Tier 2) pass.
2. **Backward Compatibility with Positional Calls:**
   - `RetrievalResult` retains compatibility with any legacy test fixture that passed a dictionary positionally as argument 8 via `__post_init__`.

---

## 4. Conclusion

Milestone 1 (Requirement R1: Targeting-Aware Evaluation and Context Contamination Separation, Flaws A1 & A6) is fully implemented, verified, and ready for review:
- `RetrievalResult` carries targeting metadata.
- All 4 engines propagate targeting metadata.
- Stages pipeline serializes and deserializes targeting losslessly.
- `Evaluator` calculates `retrieval_asr_targeted` as the primary metric, and `retrieval_asr_untargeted` / `retrieval_asr_any` as context contamination metrics.
- 100% pass rate achieved across all unit tests and all R1 E2E tests with zero regressions.

---

## 5. Verification Method

To independently verify Milestone 1:

1. **Run New Unit Tests:**
   ```powershell
   .\.venv\Scripts\python.exe -m pytest tests/test_targeting_evaluation.py -v
   ```
   *Expected result: 14 passed.*

2. **Run E2E Suite R1 Tests (Tiers 1 & 2):**
   ```powershell
   .\.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "_r1_" -v
   ```
   *Expected result: 40 passed.*

3. **Run Full Component Unit Test Suite:**
   ```powershell
   .\.venv\Scripts\python.exe -m pytest tests/ --ignore=tests/test_e2e_remediation.py
   ```
   *Expected result: 85 passed in ~58s.*

4. **Verify Targeting Separation Behavior Directly:**
   ```powershell
   .\.venv\Scripts\python.exe -c "
   from src.corpus.dataset import GoldQuery, RetrievalResult
   from src.evaluation.metrics import Evaluator

   q1 = GoldQuery('Q1', 'Query 1', 'cve', ['GT1'], 'Ans 1', 'Assert 1')
   q2 = GoldQuery('Q2', 'Query 2', 'cve', ['GT2'], 'Ans 2', 'Assert 2')

   # Q2 retrieves poison targeted at Q1
   outputs = {
       'Q1': [RetrievalResult('GT1', 1.0, 1, 'Clean', 'Text', False, 'cve')],
       'Q2': [RetrievalResult('P1', 1.0, 1, 'Poison', 'Text', True, 'poison', poison_target_query='Q1')]
   }
   res = Evaluator.evaluate_engine('BM25', 'sparse', [q1, q2], outputs)
   assert res.retrieval_asr_targeted == 0.0, 'Foreign poison must NOT count as targeted ASR'
   assert res.retrieval_asr_any == 0.5, 'Background contamination must be 0.5'
   assert res.retrieval_asr_untargeted == 0.5, 'Untargeted contamination must be 0.5'
   print('Targeting verification passed perfectly!')
   "
   ```
   *Expected output: `Targeting verification passed perfectly!`*
