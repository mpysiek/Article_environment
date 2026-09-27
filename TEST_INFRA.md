# Test Infrastructure & Methodology (`TEST_INFRA.md`)

## 1. Overview & Test Suite Architecture

This document specifies the testing infrastructure, methodology, and execution framework for the CTI RAG Poisoning Benchmark Remediation Project (P1 + P2).

The test suite enforces the remediation of all Class A (Methodological) and Class B (Measurement Instrument) flaws across Requirements R1 through R5, adhering strictly to the **4-Tier Testing Methodology**:
- **Tier 1: Feature Coverage** (>=5 test cases per feature across all 20 inventoried features = 100 tests)
- **Tier 2: Boundary & Corner Cases** (>=5 test cases per feature covering edge values, empty inputs, extreme budgets, 0% ASR, and boundary thresholds = 100 tests)
- **Tier 3: Cross-Feature Combinations** (15 pairwise interaction tests covering cross-layer dynamics)
- **Tier 4: Real-World Application Scenarios** (10 end-to-end evaluation runs on real CTI STIX / CVE queries)

Total test count in primary E2E suite: **225 test cases** in `tests/test_e2e_remediation.py`.

---

## 2. Test Suite Directory & File Ownership

```
tests/
├── test_e2e_remediation.py       # Exclusive owner: Test Writer (Track A)
│                                 # 225 tests covering Tiers 1-4 for R1-R5
├── test_batch_client.py          # Unit tests: OpenRouter Batch API client
├── test_comparison_system.py     # Integration tests: Multi-engine baseline
├── test_data_integrity.py        # Schema integrity and dataset tests
├── test_defenses.py              # Defense filters (Perplexity, Reranking)
├── test_embedding_cache.py       # Dense FAISS embedding cache tests
├── test_judge_batch.py           # LLM judge batch generation tests
├── test_stages.py                # Stages A/B/C handoff serialization
│
│                                 # Dodane po pierwszej redakcji tego dokumentu:
├── test_isolated_protocol.py     # Protokol izolowany per zapytanie (Recommendation 3)
├── test_isolated_adversarial_stress.py       # Stres: brak przeciekow miedzy zapytaniami
├── test_challenger_iso_2_adversarial.py      # Kontrola izolacji, wariant adwersarialny
├── test_m1_adversarial_stress.py             # Stres kamienia milowego M1
├── test_optimization_adversarial_edge_cases.py  # Rownowaznosc sciezek inkrementalnych
├── test_targeting_evaluation.py              # Separacja targeted / untargeted / any
│
│                                 # Dodane w wydaniu 1.3.0 (27.09.2026):
└── test_tie_logging_and_query_sets.py        # Pelne grupy remisowe, zestawy pytan v2/v3,
                                              # K4 per szablon, prog mostow (32 testy)
```

Cały zestaw liczy **429 testów** i przechodzi w całości (27.09.2026: 40 s na Windows 11,
ok. 1,5–2 min na Linuksie). Sam `test_e2e_remediation.py` to 225 z nich, a
`test_tie_logging_and_query_sets.py` — 32.

### File Ownership Rules
- `tests/test_e2e_remediation.py` is exclusively written and maintained by the E2E Test Writer.
- Source code in `src/` is **read-only** for the Test Writer. All discovered defects and unmet contracts are verified through automated assertions that guide Milestone Workers (M1 to M5).

---

## 3. 4-Tier Test Methodology & Feature Mapping

### 3.1 Feature Inventory to Test Mapping

| Feature ID | Requirement | Description | Tier 1 Tests | Tier 2 Tests | Tier 3 / 4 Scenarios |
|------------|-------------|-------------|--------------|--------------|----------------------|
| **F-R1-01** | R1 (Targeting) | `RetrievalResult` schema carries `poison_target_query` and `poison_type` | 5 | 5 | C6, C11, C15, S1 |
| **F-R1-02** | R1 (Targeting) | Retrievers populate targeting metadata into `RetrievalResult` | 5 | 5 | C11, S1 |
| **F-R1-03** | R1 (Targeting) | Lossless serialization of targeting fields in `stages.py` | 5 | 5 | C6, C11, C15 |
| **F-R1-04** | R1 (Targeting) | `retrieval_asr_targeted` separated from `untargeted` and `any` in `Evaluator` | 5 | 5 | C2, C8, C11, S1 |
| **F-R2-01** | R2 (GraphRAG) | Dual-namespace node representation (`doc:{id}`, `ent:{name}`) in GraphRAG | 5 | 5 | C2, S4 |
| **F-R2-02** | R2 (GraphRAG) | Entity extraction from queries without `doc_map` filtering (Recall >= 70%) | 5 | 5 | S1, S4 |
| **F-R2-03** | R2 (GraphRAG) | Independent degree normalization and clean 1-hop/2-hop graph traversal | 5 | 5 | C9, S4 |
| **F-R2-04** | R2 (GraphRAG) | Explicit fallback logging, `metadata['fallback_used']`, & `graph_fallback_rate` | 5 | 5 | C5, S4 |
| **F-R2-05** | R2 (GraphRAG) | Active graph interaction for `PureTopologicalPoisonAttacker` | 5 | 5 | C4, S5 |
| **F-R3-01** | R3 (Budget) | Diverse payload generation across budgets $B \in \{1, 3, 5\}$ | 5 | 5 | C1, C9, C13, S2 |
| **F-R3-02** | R3 (Budget) | Query echo ablation (`query_echo=False`) as reference probe | 5 | 5 | C1, C13, S3 |
| **F-R4-01** | R4 (Judge) | LLM Judge unparseable response isolation & `coverage_rate` calculation | 5 | 5 | C3, C14, S6 |
| **F-R4-02** | R4 (Judge) | Assertion alignment in `make_stage_a_record` for BlackBox & Topological | 5 | 5 | C4, C6, S6 |
| **F-R4-03** | R4 (Judge) | Explicit `llm_stage_ran: bool` preserving true 0% ASR | 5 | 5 | C10, S7 |
| **F-R4-04** | R4 (Judge) | Deduplication scoping / opt-out parameter preventing scenario collapse | 5 | 5 | C7 |
| **F-R5-01** | R5 (Reporting) | Dynamic markdown report synthesis (remove hardcoded 24,000 docs & Sec 5) | 5 | 5 | C10, C14, S7 |
| **F-R5-02** | R5 (Reporting) | Pareto frontier analysis (Recall@5 vs ASR) with 50% absolute utility threshold | 5 | 5 | C3, C8, C12, S8 |
| **F-R5-03** | R5 (Reporting) | Deterministic tie-breaking and unified $k=5$ cutoff across metrics | 5 | 5 | C12, S8 |
| **F-R5-04** | R5 (Reporting) | High-precision latency (`time.perf_counter()`, warm-up rejection, median+IQR) | 5 | 5 | C5, S10 |
| **F-R5-05** | R5 (Reporting) | Exact binomial McNemar test ($b+c < 25$) & formatted $p$-values ($p < 10^{-4}$) | 5 | 5 | C7, S9 |

---

## 4. Interface Contracts Enforced

The test suite validates compliance with all 5 architectural contracts:

1. **Contract 1: `RetrievalResult` Schema (M1 ↔ M2, M4, M5)**:
   - Must expose `poison_target_query: Optional[str] = None` and `poison_type: Optional[str] = None`.
   - Lossless serialization in `stages.retrieval_result_to_dict` and `from_dict`.

2. **Contract 2: `Evaluator` Metrics Schema (M1 ↔ M5)**:
   - Primary metric `retrieval_asr_targeted: float` measuring query-specific poison hijack.
   - Background metric `retrieval_asr_any: float` and `retrieval_asr_untargeted: float`.
   - Telemetry fields: `graph_fallback_rate: Optional[float]`, `llm_stage_ran: bool`, `judge_coverage_rate: float`, `latency_median_ms: float`, `latency_iqr_ms: float`.

3. **Contract 3: GraphRAG Dual-Namespace Representation (M2)**:
   - Node identifiers prefixed with `doc:{doc_id}` for documents and `ent:{name}` for entities.
   - Bipartite edges `(doc:id, ent:name, relation="MENTIONS")` and `(ent:name, doc:id, relation="MENTIONED_IN")`.
   - `_extract_query_entities()` searches all entity nodes without document exclusion.
   - Lexical fallback sets `metadata["fallback_used"] = True`.

4. **Contract 4: Budget Diversity & Assertion Alignment (M3 ↔ M4)**:
   - `generate_poison(query, budget_idx=b, query_echo=bool)` produces distinct variations (lexical paraphrases, semantic facet expansions, multi-point bridges).
   - `get_injected_assertion(query, attack_type)` exposes the verbatim claim presented to the generator.

5. **Contract 5: Reporter Dynamic Synthesis & Statistics (M5)**:
   - No hardcoded document count strings (e.g. `"24 000 autentycznych dokumentów"`). Count derived dynamically from `corpus_size` or query count.
   - Section 5 dynamically synthesized from benchmark outcome matrix.
   - Pareto ranking with 50% Clean Recall@5 threshold; non-viable engines disqualified.
   - McNemar test uses exact two-tailed binomial test when $b+c < 25$. Small p-values formatted as `< 0.0001` or `p < 10⁻⁴`.

---

## 5. Execution Instructions & Test Commands

### 5.1 Environment
The benchmark runs under the project virtual environment `.venv` with Python 3.13:
```powershell
# Activate or invoke via direct interpreter:
.venv\Scripts\python.exe -m pytest <arguments>
```

### 5.2 Test Execution Commands

```powershell
# 1. Run full E2E remediation suite (225 tests):
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -v

# 2. Run fast summary / quiet mode:
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -q

# 3. Run specific Tier:
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "TestTier1" -v
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "TestTier2" -v
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "TestTier3" -v
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "TestTier4" -v

# 4. Run specific Requirement / Feature:
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r1" -v
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r2" -v
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r3" -v
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r4" -v
.venv\Scripts\python.exe -m pytest tests/test_e2e_remediation.py -k "f_r5" -v

# 5. Run the full suite (429 tests); -p no:cacheprovider keeps .pytest_cache out of the repo:
.venv\Scripts\python.exe -m pytest tests/ -q -p no:cacheprovider
```

---

## 6. Execution Performance & Speed Optimizations

- **Pure CPU / In-Memory Execution**: Tests use in-memory synthetic corpora and mocked transformer encoders where embedding weights are invariant to the contract being tested.
- **Fast Execution Time**: The entire 225-test suite executes in **~11.8 seconds** on standard developer workstations, enabling rapid test-driven iteration.
- **Zero External API Costs**: All LLM judge interactions are mocked or executed via offline prompt hashing fixtures ($0.00 spend).
