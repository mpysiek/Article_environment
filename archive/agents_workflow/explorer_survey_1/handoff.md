# Handoff Report: Targeting-Aware Evaluation (R1) & Experimental Factor Differentiation (R3)

**Agent:** Explorer Survey Agent (`explorer_survey_1`)  
**Working Directory:** `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_survey_1`  
**Parent Orchestrator:** `dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635`  
**Date:** 2026-09-06  
**Type:** Hard Handoff (Investigation & Survey Complete)

---

## 1. Observation

1. **RetrievalResult Drops Targeting Metadata:**
   - In `src/corpus/dataset.py:27-35`, `RetrievalResult` defines:
     ```python
     @dataclass
     class RetrievalResult:
         doc_id: str
         score: float
         rank: int
         title: str
         text: str
         is_poisoned: bool
         doc_type: str
         metadata: Dict[str, Any] = field(default_factory=dict)
     ```
     `poison_target_query` and `poison_type` are present on `CTIDocument` (`src/corpus/dataset.py:13-14`) but completely omitted from `RetrievalResult`.
   - In `src/engines/retrievers.py`:
     - `BM25Retriever.retrieve` (lines 56-65) instantiates `RetrievalResult` passing only `doc.id`, `scores[idx]`, `rank`, `doc.title`, `doc.text`, `doc.is_poisoned`, `doc.doc_type`.
     - `DenseFAISSRetriever.retrieve` (lines 224-233) drops targeting fields.
     - `HybridRerankRetriever.retrieve` (lines 282-291) drops targeting fields.
     - `GraphRAGRetriever.retrieve` (lines 400-409) drops targeting fields.
   - In `src/evaluation/stages.py:29-53`:
     `retrieval_result_to_dict()` and `retrieval_result_from_dict()` serialize and deserialize without `poison_target_query`.

2. **ASR Conflates Targeted Success with Background Contamination:**
   - In `src/evaluation/metrics.py:121-133`:
     ```python
     for q in queries:
         results = retrieval_outputs.get(q.id, [])
         p_top1 = len(results) > 0 and results[0].is_poisoned
         p_top3 = any(r.is_poisoned for r in results[:3])
         p_top5 = any(r.is_poisoned for r in results[:5])

         if p_top1:
             poison_top1_count += 1
         if p_top3:
             poison_top3_count += 1
         if p_top5:
             poison_top5_count += 1
     ```
     `p_top1`, `p_top3`, and `p_top5` evaluate whether *any* retrieved document has `is_poisoned == True`. If query $Q_2$ retrieves a poison document specifically injected to attack $Q_1$, it is counted as a successful attack on $Q_2$.

3. **Attack Budget Generates Bit-Identical Byte-Duplicates:**
   - In `src/attacks/poisoning.py:307-328`:
     ```python
     for q in queries:
         for b in range(attack_budget):
             if attack_type == "sparse":
                 p_doc = self.sparse_attacker.generate_poison(q)
             elif attack_type == "dense":
                 p_doc = self.dense_attacker.generate_poison(q)
             elif attack_type == "hybrid":
                 p_doc = self.hybrid_attacker.generate_poison(q)
             ...
             elif attack_type == "blackbox":
                 p_doc = self.blackbox_attacker.generate_poison(q)
             ...
             if attack_budget > 1 and attack_type not in ("graph", "pure_topological", "topological"):
                 p_doc.id = f"{p_doc.id}_B{b}"
             poisoned_corpus.append(p_doc)
     ```
     For `sparse`, `dense`, `hybrid`, and `blackbox`, `generate_poison(q)` does not receive `b`. The document text and title are 100% byte-for-byte identical duplicates.

4. **Query Echo Confounding:**
   - In `src/attacks/poisoning.py:41, 71, 102, 165`, when `query_echo=True` (default across benchmark scripts), `query.query_text` is literally interpolated into the payload text.
   - In `src/engines/retrievers.py:388-393`, `GraphRAGRetriever` falls back to word-level matching (`sum(1 for w in query.lower().split() if w in doc.text.lower())`) if entity extraction yields no scores, silently matching the verbatim query text in the payload.

5. **Existing Test Suite Baseline:**
   - Executing `.\.venv\Scripts\python.exe -m pytest tests/` passed 71 of 71 tests in 49.06s.

---

## 2. Logic Chain

1. **Step 1 (Tracing Targeting Information Loss):**
   - Observation 1 demonstrates that `poison_target_query` is defined in `CTIDocument` but omitted in `RetrievalResult`, stripped by all retrievers, and omitted in stage serialization.
   - Therefore, by the time evaluation occurs in `Evaluator.evaluate_engine_with_llm`, `results` contains no record of which query each retrieved document was created to target.

2. **Step 2 (Deducing False Attack Attribution - Class A1):**
   - Observation 2 shows that `Evaluator` determines attack success solely based on `r.is_poisoned`.
   - In a benchmark evaluating 100 queries, 100 to 500 poison documents exist simultaneously in the corpus.
   - If query $Q_2$ retrieves in Top-k a poison targeting query $Q_1$, `r.is_poisoned` is `True`.
   - Therefore, the system attributes attack success to $Q_2$ for an untargeted/foreign payload, inflating ASR and conflating background noise with targeted vulnerability.

3. **Step 3 (Deducing Context Window Saturation - Class A6):**
   - Observation 3 shows that all queries' poisons across all budgets are pooled into a single index.
   - For 100 queries at budget 5, 500 poison documents are injected.
   - In test subsets of 500-1000 documents, poison documents constitute 33%-50% of the entire corpus.
   - Therefore, evaluation results reflect an unrealistic context saturation environment rather than realistic low-density enterprise RAG conditions.

4. **Step 4 (Deducing Budget Experimental Degeneration - Class A3):**
   - Observation 3 shows that loop `for b in range(attack_budget)` generates identical payloads with `_B{b}` suffix.
   - For dense retrievers, identical texts generate identical embeddings with distance 0.0.
   - For sparse BM25, identical texts generate identical term frequency profiles.
   - Therefore, scaling budget from 1 to 3 to 5 does not evaluate varied adversarial capacity (e.g. diverse paraphrasing, alternate semantic anchors, or multi-point relational bridging), invalidating the independent variable.

5. **Step 5 (Deducing Query Echo Confounding - Class A5):**
   - Observation 4 shows that verbatim `query.query_text` is embedded in the payload text by default.
   - Observation 4 also shows that GraphRAG falls back to lexical token matching when entity extraction yields no scores.
   - Therefore, GraphRAG's apparent vulnerability under default attacks is driven by lexical token matching of the echoed question, confounding graph vulnerability evaluation.

---

## 3. Caveats

1. **GraphRAG Entity Extraction Deep Dive:** GraphRAG entity matching and namespace separation (Requirement R2 / Class A4, B4, B3) is being surveyed in parallel by `explorer_survey_2`. Our survey focused strictly on where GraphRAG interacts with `RetrievalResult`, fallback query echo, and budget generation.
2. **LLM Judge Prompt Divergence:** Judge prompt mechanics and reporter Pareto/McNemar statistics (Requirements R4 & R5) are being surveyed in parallel by `specminer_survey_3`.
3. **Index Isolation vs Controlled Background Density:** Both strict per-query index isolation and controlled background contamination density (e.g. 1% uniform poison pool) solve context saturation. The project team should adopt strict isolation for unit/clean benchmarks, and controlled density for multi-query resilience benchmarks.

---

## 4. Conclusion

The benchmark currently suffers from:
- **Class A1 / A6:** Blindness to attack targeting, resulting in false-positive ASR from background noise and unrealistic context saturation.
- **Class A3 / A5:** Degenerate budget scaling (bit-for-bit duplicate payloads) and lexical confounding via verbatim query echo.

**Actionable Remediations:**
1. Add `poison_target_query: Optional[str] = None` and `poison_type: Optional[str] = None` to `RetrievalResult`.
2. Populate these fields in `BM25Retriever`, `DenseFAISSRetriever`, `HybridRerankRetriever`, and `GraphRAGRetriever`.
3. Update `stages.py` (`retrieval_result_to_dict`, `retrieval_result_from_dict`) to ensure lossless round-trip serialization.
4. Overhaul `Evaluator` to report `retrieval_asr_targeted` (primary metric) separated from `retrieval_asr_any` / `retrieval_asr_untargeted` (background contamination).
5. Refactor all attacker classes in `src/attacks/poisoning.py` to accept `budget_idx` and emit structurally, semantically, and topologically diverse payloads for budgets $B \in \{1, 3, 5\}$.
6. Standardize `query_echo=False` as the primary reference probe for semantic and graph selectivity.

Detailed technical design and code specifications are fully documented in `analysis.md`.

---

## 5. Verification Method

1. **Test Environment:**
   Run tests using the project virtual environment:
   ```powershell
   .\.venv\Scripts\python.exe -m pytest tests/
   ```
2. **Targeting Verification:**
   Inspect that for an injected document with `poison_target_query="Q1"`, running retrieval for query `"Q2"` returns `results[0].poison_target_query == "Q1"`, and `Evaluator` records `retrieval_asr_targeted == 0.0` while `retrieval_asr_any == 1.0`.
3. **Budget Diversity Verification:**
   Generate a corpus with `attack_budget=3` and verify:
   ```python
   texts = [doc.text for doc in poisoned_docs]
   assert len(set(texts)) == len(texts)  # Zero duplicates
   ```
4. **Serialization Round-Trip Verification:**
   Run `tests/test_stages.py` after schema update to confirm `poison_target_query` survives Stage A $\rightarrow$ Stage C handoff.

---
*End of Handoff Report.*
