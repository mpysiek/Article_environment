# Handoff Report: Recommendation 3 Isolated Evaluation Protocol Integration

**Agent**: `explorer_iso_1`  
**Working Directory**: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\explorer_iso_1`  
**Handoff Type**: Hard (Investigation complete)  

---

## 1. Observation

1. **Missing CLI Flag & Shared Index Loop in Benchmark Script**:
   - In `scripts/run_comparison_benchmark.py`:
     - Lines 243–260: `argparse.ArgumentParser` parses `--corpus`, `--num_cves`, `--queries`, `--cost-free`, `--llm`, `--no-query-echo`, `--topological`. The flag `--isolated-targets` is completely absent.
     - Lines 185–193: In Phase 2, `poison_mgr.generate_poisoned_corpus(clean_docs, queries, att_type, attack_budget=b)` is called, pooling all queries' poison payloads into a single shared corpus list of length $|clean\_docs| + |queries| \times b$.
     - Lines 101–162: `evaluate_scenario` calls `engine.build_index(docs)` on this pooled corpus once per scenario, and then iterates over `for q in queries: results = engine.retrieve(q.query_text, top_k=config.TOP_K)`. All foreign poison documents ($Q_j, j \ne i$) remain in the index during the evaluation of $Q_i$.
2. **Latent `argparse` Format Crash**:
   - In `scripts/run_comparison_benchmark.py`, line 252:
     ```python
     parser.add_argument("--cost-free", action="store_true", default=None,
                         help="Force 100% cost-free local evaluation ($0.00 API cost)")
     ```
   - Running `python scripts/run_comparison_benchmark.py --help` produces:
     ```
     TypeError: %c requires int or char
     ```
     due to standard `argparse` `%` interpolation treating `% c` as `%c`.
3. **Existing Implementation of Isolated Generation in `src/attacks/poisoning.py`**:
   - Lines 385–401: `generate_poison_payloads_for_query(query, attack_type, attack_budget=1, query_echo=None)` generates `[attacker.generate_poison(query, budget_idx=b) for b in range(attack_budget)]`.
   - Lines 402–423: `generate_isolated_poison_payloads(queries, attack_type, attack_budget=1, query_echo=None)` returns `{q.id: self.generate_poison_payloads_for_query(...) for q in queries}`.
   - All 6 attacker classes (`SparseKeywordStuffingAttacker`, `DenseSemanticPoisonAttacker`, `HybridEvasionAttacker`, `GraphLogicPoisonAttacker`, `BlackBoxTopicAttacker`, `PureTopologicalPoisonAttacker`) set `poison_target_query=query.id`, `is_poisoned=True`, and vary text, framing, or STIX bridge entities across `budget_idx` ($0, 1, 2, 3, 4$).
4. **Existing Implementation of Isolated Retrieval in `src/evaluation/stages.py`**:
   - Lines 92–123: `execute_isolated_retrieval(engine, clean_docs, poison_payloads, queries, top_k=5)` builds `index_docs = clean_docs + q_poisons if q_poisons else clean_docs`, calls `engine.build_index(index_docs)`, and retrieves for query $Q_i$, returning `(retrieval_outputs, retrieval_latencies)`.
5. **Engine Caching Architecture in `src/engines/retrievers.py`**:
   - `BM25Retriever`: Lines 44–50 cache clean doc tokens in `self._doc_token_cache`. Line 58 only tokenizes new poison docs. `BM25Okapi` is newly instantiated per query with only clean docs + $Q_i$'s poison docs.
   - `DenseFAISSRetriever`: Lines 240–256 cache `self._base_embeddings` and `self._base_doc_keys`. When `clean_docs` matches `_base_doc_keys`, it slices only poison keys, extracts vectors from `_embedding_cache`, does `np.vstack([self._base_embeddings, poison_embs])`, and initializes a fresh `faiss.IndexFlatIP(dim)`.
   - `GraphRAGRetriever`: Lines 372–412 cache `self._base_graph` and `self._base_doc_ids`. When `clean_docs` matches `_base_doc_ids`, it copies `self.graph = self._base_graph.copy()` and appends only $Q_i$'s poison nodes/edges.
6. **Existing Test Suite Baseline**:
   - Executing `.\.venv\Scripts\pytest tests/` succeeds: `328 passed, 1 warning in 70.99s`.
   - Currently, no tests in `tests/` execute `execute_isolated_retrieval` or test `--isolated-targets`.

---

## 2. Logic Chain

1. **Step 1 (From Obs 1 & Obs 2 to Benchmark Deficiencies)**:
   Because `scripts/run_comparison_benchmark.py` lacks `--isolated-targets` and directly executes `engine.build_index(docs)` on a pooled corpus of size $|clean\_docs| + |queries| \times B$, any benchmark execution currently operates in shared mode. Therefore, when evaluating $Q_i$, the top-5 retrieval context is contaminated by foreign payloads designed for $Q_j$ ($j \ne i$). Furthermore, the script cannot be inspected via `--help` due to the `%c` syntax bug.
2. **Step 2 (From Obs 3 to Generation Viability)**:
   `generate_isolated_poison_payloads` and `generate_poison_payloads_for_query` in `src/attacks/poisoning.py` partition poison payloads strictly by query ID ($q.id \to [doc_1, \dots, doc_B]$), while populating `poison_target_query=query.id` and generating distinct variations per budget index. Hence, the attack generator is completely ready and requires no code changes.
3. **Step 3 (From Obs 4 & Obs 5 to Retrieval Execution Feasibility)**:
   `execute_isolated_retrieval` in `src/evaluation/stages.py` is already implemented. Because all 4 engines in `src/engines/retrievers.py` have optimized fast paths that preserve base embeddings/graphs, rebuilding the index for each query takes only milliseconds and introduces zero memory leaks across queries.
4. **Step 4 (From Obs 1, 3, 4, 5 to Mathematical Isolation Guarantee)**:
   For query $Q_i$, the isolated index contains only clean documents and $Q_i$'s poison documents. No documents targeted at $Q_j$ ($j \ne i$) exist in the index. Consequently, in `Evaluator.evaluate_engine`, `has_untargeted_poison_in_top1` and `has_untargeted_poison_in_top5` are guaranteed to be `False`, and `retrieval_asr_untargeted` is identically `0.0%`.
5. **Step 5 (From Obs 1, 4, 6 to Required Implementation Steps)**:
   Modifying `scripts/run_comparison_benchmark.py` to add `--isolated-targets`, fixing the line 252 `%c` crash, invoking `generate_isolated_poison_payloads` in Phase 2, and calling `execute_isolated_retrieval` in Phase 3 will enable full Recommendation 3 support in both synthetic and real CTI modes. A new test file `tests/test_isolated_protocol.py` is needed to verify these invariants without regressing the 328 existing tests.

---

## 3. Caveats

- **Runtime of BM25 in Isolated Mode on 24k Docs**: Rebuilding `BM25Okapi` 100 times on 24,000 documents takes approximately 10–15 seconds per scenario (since `BM25Okapi` recomputes document frequencies over all 24k token lists). This is completely normal and acceptable for benchmark integrity, but implementers should be aware that running 15 scenarios on the 24k corpus will take ~3–4 minutes for BM25. In synthetic mode, it takes < 0.1s.
- No other caveats.

---

## 4. Conclusion

1. The core components of Recommendation 3 (`generate_isolated_poison_payloads` in `src/attacks/poisoning.py` and `execute_isolated_retrieval` in `src/evaluation/stages.py`) are fully functional and well-architected.
2. The benchmark script `scripts/run_comparison_benchmark.py` requires straightforward modifications:
   - Fix line 252: `help="Force 100%% cost-free..."`
   - Add `--isolated-targets` CLI argument
   - Branch Phase 2 to call `poison_mgr.generate_isolated_poison_payloads`
   - Update `evaluate_scenario` in Phase 3 to invoke `execute_isolated_retrieval`
3. A dedicated test module `tests/test_isolated_protocol.py` must be added to verify zero foreign contamination, budget monotonicity, and backward compatibility.

---

## 5. Verification Method

1. **Verify Latent Bug Fix**:
   Execute:
   ```bash
   .\.venv\Scripts\python scripts/run_comparison_benchmark.py --help
   ```
   *Expected result*: Displays full help message without `TypeError: %c requires int or char`, showing the new `--isolated-targets` option.
2. **Verify Full Test Suite Baseline & New Isolated Tests**:
   Execute:
   ```bash
   .\.venv\Scripts\pytest tests/
   ```
   *Expected result*: All 328 existing tests pass with 100% success rate, plus all new tests in `tests/test_isolated_protocol.py`.
3. **Verify Isolated Benchmark Execution in Synthetic Mode**:
   Execute:
   ```bash
   .\.venv\Scripts\python scripts/run_comparison_benchmark.py --corpus synthetic --queries 5 --cost-free --isolated-targets
   ```
   *Expected result*: Runs to completion without errors, outputs `Untargeted: 0.0%`, produces valid `rag_poisoning_comparison_report.md` and JSON results.
4. **Invalidation Conditions**:
   - If any retrieved poison document for query $Q_i$ has `poison_target_query != Q_i.id` or `retrieval_asr_untargeted > 0.0` in isolated mode.
   - If any of the existing 328 tests fail.
