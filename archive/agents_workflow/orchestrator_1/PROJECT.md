# Project: CTI RAG Poisoning Benchmark Remediation (P1 + P2)

## Architecture
The benchmark evaluates RAG architectures against adversarial corpus poisoning in Cyber Threat Intelligence (CTI).
The remediation project addresses two categories of flaws:
- **Class A (Methodological Flaws Unjustifying Conclusions)**: A1 (Targeting-agnostic ASR), A2 (Scalar ASR ranking disregarding utility), A3 (Bitwise-identical budget replication), A4 (GraphRAG entity blacklisting), A5 (Lexical query echo confounding), A6 (Index-wide context saturation), A8 (Assay-stimulus misalignment), A9 (Judge parse fallback silent bias), A10 (Hardcoded static report synthesis).
- **Class B (Measurement Instrument & Software Engineering Defects)**: B1 (Zero-utility retriever dominance), B2 (Non-deterministic tie-breaking & cutoff mismatch), B3 (Silent unlogged graph fallback), B4 (Graph node namespace collisions & degree over-penalization), B5 (Imprecise wall-clock latency measurement), B8 (Blind LLM stage execution detection), B9 (Global judge prompt deduplication), B10 (McNemar continuity failure on small samples & false-zero p-values).

### Dual-Track Workflow
1. **E2E Testing Track**: Independent opaque-box test suite across Tiers 1-4 based on user requirements (`ORIGINAL_REQUEST.md`), publishing `TEST_INFRA.md` and `TEST_READY.md`.
2. **Implementation Track**: 5 sequential milestones (M1 to M5) executed via the strict iteration loop (Worker -> 2 Reviewers -> 2 Challengers -> Forensic Auditor -> Gate), followed by Final Milestone (pass 100% E2E tests + Tier 5 adversarial hardening).

## Feature Inventory
| # | Feature ID | Description | Flaw Addressed | Milestone | Source |
|---|------------|-------------|----------------|-----------|--------|
| 1 | F-R1-01 | `RetrievalResult` schema carries `poison_target_query` and `poison_type` | A1, A6 | M1 | Survey 1 |
| 2 | F-R1-02 | Retrievers populate targeting metadata into `RetrievalResult` | A1 | M1 | Survey 1 |
| 3 | F-R1-03 | Lossless serialization of targeting fields in `stages.py` | A1 | M1 | Survey 1 |
| 4 | F-R1-04 | `retrieval_asr_targeted` primary metric separate from `retrieval_asr_untargeted` and `retrieval_asr_any` in `Evaluator` | A1, A6 | M1 | Survey 1 |
| 5 | F-R2-01 | Dual-namespace node representation (`doc:{doc_id}`, `ent:{name}`) in `GraphRAGRetriever` | B4 | M2 | Survey 2 |
| 6 | F-R2-02 | Entity extraction from queries without `doc_map` filtering (Clean Recall@5 >= 70%) | A4 | M2 | Survey 2 |
| 7 | F-R2-03 | Independent degree normalization and clean 1-hop/2-hop graph traversal | B4 | M2 | Survey 2 |
| 8 | F-R2-04 | Explicit fallback logging, `metadata['fallback_used']`, and `graph_fallback_rate` metric | B3 | M2 | Survey 2 |
| 9 | F-R2-05 | Active graph interaction for `PureTopologicalPoisonAttacker` | A4, B3 | M2 | Survey 2 |
| 10 | F-R3-01 | Diverse payload generation across budgets $B \in \{1, 3, 5\}$ (paraphrases, semantic anchors, multi-point bridges) | A3 | M3 | Survey 1 |
| 11 | F-R3-02 | Query echo ablation (`query_echo=False`) as reference probe for semantic/graph selectivity | A5 | M3 | Survey 1 |
| 12 | F-R4-01 | LLM Judge unparseable response isolation, `coverage_rate` calculation, no defense bias | A9 | M4 | Spec Miner |
| 13 | F-R4-02 | Assertion alignment in `make_stage_a_record` for BlackBox and Topological attacks | A8 | M4 | Spec Miner |
| 14 | F-R4-03 | Explicit `llm_stage_ran: bool` flag preserving true 0% ASR without dropping LLM metrics | B8 | M4 | Spec Miner |
| 15 | F-R4-04 | Deduplication scoping / opt-out parameter preventing scenario collapse | B9 | M4 | Spec Miner |
| 16 | F-R5-01 | Dynamic markdown report synthesis (remove hardcoded 24,000 docs and static Section 5 text) | A10 | M5 | Spec Miner |
| 17 | F-R5-02 | Pareto frontier analysis (Clean Recall@5 vs ASR) with 50% absolute utility threshold | A2, B1 | M5 | Spec Miner |
| 18 | F-R5-03 | Deterministic tie-breaking and unified $k=5$ cutoff across metrics | B2 | M5 | Spec Miner |
| 19 | F-R5-04 | High-precision latency (`time.perf_counter()`, warm-up rejection, median + IQR) | B5 | M5 | Spec Miner |
| 20 | F-R5-05 | Exact binomial McNemar test ($b+c < 25$) and formatted $p$-values ($p < 10^{-4}$) | B10 | M5 | Spec Miner |
| 21 | F-E2E-01 | E2E opaque-box test suite covering Tiers 1-4 and test runner | All | M0 (Test Track) | Requirements |
| 22 | F-ADV-01 | Tier 5 adversarial coverage hardening with challenger stress testing | All | Final Milestone | Methodology |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M0 | E2E Testing Suite Track | Design and implement opaque-box tests across Tiers 1-4; publish `TEST_INFRA.md` & `TEST_READY.md` | none | PLANNED |
| M1 | Targeting-Aware Evaluation (R1) | Implement F-R1-01 through F-R1-04 (`dataset.py`, `retrievers.py`, `stages.py`, `metrics.py`) | none | PLANNED |
| M2 | GraphRAG Entity & Namespace (R2) | Implement F-R2-01 through F-R2-05 (`retrievers.py`, `metrics.py`) | M1 | PLANNED |
| M3 | Budget Diversity & Separability (R3) | Implement F-R3-01 and F-R3-02 (`poisoning.py`) | none | PLANNED |
| M4 | LLM Judge Robustness (R4) | Implement F-R4-01 through F-R4-04 (`llm_judge.py`, `stages.py`, `metrics.py`) | M1 | PLANNED |
| M5 | Metrological Reporting & Stats (R5) | Implement F-R5-01 through F-R5-05 (`reporter.py`, `metrics.py`, benchmark scripts) | M1, M4 | PLANNED |
| M6 | Final Milestone: E2E Pass & Hardening | Pass 100% of E2E test suite + Phase 2 Tier 5 adversarial coverage hardening | M0, M1, M2, M3, M4, M5 | PLANNED |

## Interface Contracts
### Contract 1: `RetrievalResult` Schema (M1 ↔ M2, M4, M5)
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
    poison_target_query: Optional[str] = None
    poison_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### Contract 2: `Evaluator` Metrics Schema (M1 ↔ M5)
`EngineBenchmarkResult` must include:
- `retrieval_asr_targeted: float` (primary ASR metric: fraction of queries retrieving poison intended for that specific query)
- `retrieval_asr_any: float` (secondary background contamination metric: fraction of queries retrieving any poison document)
- `retrieval_asr_untargeted: float` (`retrieval_asr_any - retrieval_asr_targeted`)
- `clean_recall_at_k: float` (with $k=5$)
- `graph_fallback_rate: Optional[float] = None`
- `llm_stage_ran: bool = False`
- `judge_coverage_rate: float = 1.0`
- `latency_median_ms: float = 0.0`
- `latency_iqr_ms: float = 0.0`

### Contract 3: GraphRAG Dual-Namespace Representation (M2)
- Graph nodes prefixed with `doc:` for documents and `ent:` for extracted entities.
- Edges:
  - `(doc:{id}, ent:{name})` with `relation="MENTIONS"`
  - `(ent:{name}, doc:{id})` with `relation="MENTIONED_IN"`
  - `(ent:{name1}, ent:{name2})` with ontology relations (e.g. `INDICATES`, `USES`, `TARGETS`).
- `_extract_query_entities()` searches all nodes where `node_type == "entity"` without document exclusion.
- Fallback records `fallback_used=True` in `RetrievalResult.metadata`.

### Contract 4: Budget Diversity & Assertion Alignment (M3 ↔ M4)
- `generate_poison(query, budget_idx=0, query_echo=True)` generates distinct variations:
  - Budget 0: Primary anchor
  - Budget 1: Lexical paraphrase / alternate terminology
  - Budget 2: Semantic facet expansion / contextual shift
  - Budget 3+: Multi-point relational bridging
- BlackBox and Topological attackers expose `get_injected_assertion(query)` matching what was actually injected into the text.

### Contract 5: Reporter Dynamic Synthesis & Statistics (M5)
- No hardcoded string constants for corpus document counts (e.g. `"24 000 autentycznych dokumentów"`). Count is derived dynamically from `corpus_size` or `len(documents)`.
- Section 5 conclusions dynamically synthesized based on metric comparisons (e.g. comparing `retrieval_asr_targeted`, `clean_recall_at_5`, and latency across engines).
- Pareto ranking: filter engines by `clean_recall_at_5 >= 0.50` (or `utility_threshold`), sort by `(retrieval_asr_targeted, -clean_recall_at_5, name)`. Engines below threshold marked as `NON_VIABLE`.
- McNemar test: If $b + c < 25$, compute exact two-tailed binomial p-value using `scipy.stats.binomtest` or `math.comb`. Format small p-values as `"< 0.0001"`.

## Code Layout
- `src/corpus/dataset.py`: `CTIDocument`, `RetrievalResult`, gold benchmark queries, corpus builders. Exclusive write owner for M1.
- `src/engines/retrievers.py`: `BaseRetriever`, `BM25Retriever`, `DenseFAISSRetriever`, `HybridRerankRetriever`, `GraphRAGRetriever`. Exclusive write owner for M1 (targeting propagation) and M2 (GraphRAG namespaces).
- `src/evaluation/stages.py`: Stage A/B/C serialization functions (`retrieval_result_to_dict`, `retrieval_result_from_dict`, `make_stage_a_record`). Exclusive write owner for M1 and M4.
- `src/evaluation/metrics.py`: `EngineBenchmarkResult`, `Evaluator`, statistical calculations. Shared across M1, M4, M5.
- `src/attacks/poisoning.py`: Attacker classes (`Sparse`, `Dense`, `Hybrid`, `Graph`, `Topological`, `BlackBox`) and `CorpusPoisonManager`. Exclusive write owner for M3.
- `src/evaluation/llm_judge.py`: `LLMJudge`, judge fallbacks, JSON parsing, prompt hashing. Exclusive write owner for M4.
- `src/visualization/reporter.py`: Markdown reporter, Pareto ranking, McNemar test, timing. Exclusive write owner for M5.
- `tests/`: Test suite files.
  - `tests/test_e2e_remediation.py`: Opaque-box E2E test suite (Track A).
  - `tests/test_*.py`: Component unit and regression tests.
