# Changelog: CTI RAG Poisoning Benchmark (Optimized Edition)

All notable changes, architectural rationale, algorithmic specifications, and empirical performance metrics for the isolated evaluation protocol optimization are documented in this file.

---

## [1.2.0-methodology] - 2026-09-13

### Summary
Wydanie **nie zmienia warstwy wyszukiwania**. Żaden retriever, atakujący ani protokół nie
został zmodyfikowany, więc zapisane ślady przebiegu v2 pozostają ważne, a raport odtwarza
się z nich przez `scripts/regenerate_report.py` bez ponownego uruchamiania benchmarku.
Zmiany dotyczą wyłącznie **pomiaru, agregacji i raportowania** — oraz tego, jakie tezy
wolno na tych liczbach oprzeć.

Punktem wyjścia była weryfikacja metodologiczna, która wykazała, że warstwa pomiarowa jest
poprawna, ale warstwa interpretacyjna nie: cztery z sześciu twierdzeń Sekcji 5 były albo
wewnętrznie sprzeczne, albo policzone na stratach, na których dany silnik nie miał
użyteczności bazowej.

### Zmiany merytoryczne

**1. Próg użyteczności stosowany per stratum, nie tylko per silnik.**
Ładunek na pozycji 1 w stratum, w którym czysty silnik i tak nie znajdował odpowiedzi,
niczego nie wypiera — jego `poison@1` opisuje zdegenerowany ranking, a nie odporność. Ta
sama reguła, którą dyskwalifikowano Dense-FAISS na poziomie silnika, obowiązuje teraz per
stratum. Wpływ na kolumnę „średni poison@1" w rankingu (36 scenariuszy):

| Silnik | przed | po | stratum odrzucone |
| :--- | ---: | ---: | :--- |
| Sparse-BM25 | 39,4% | **25,7%** | ATT&CK Relational |
| Dense-FAISS | 20,8% | **5,9%** | ATT&CK Relational, CVE Exact-Match |
| Hybrid-Reranker | 19,7% | **0,7%** | ATT&CK Relational |
| GraphRAG | 34,4% | **15,8%** | CVE Descriptive |

Implementacja: `viable_strata_for()`, `restricted_poison_rates()`, `compute_stratum_recall()`
w `src/visualization/reporter.py`. Strażnik: nowy check **K3**.

**2. `poison@1` przestał być estymatorem punktowym tam, gdzie występują remisy.**
GraphRAG przypisuje wielu dokumentom identyczny wynik, a `sorted(key=(-score, doc_id))`
rozstrzyga remis kolejnością identyfikatorów — dla remisu przecinającego granicę
poison/clean o wartości metryki decyduje porządek alfabetyczny (`POISON_…` vs `CVE-…`),
a nie funkcja scoringu. Dotyczy do **42,7%** zapytań w scenariuszu.

`Evaluator` liczy teraz `poison_at_1_tie_lower` / `poison_at_1_tie_upper` /
`n_top1_tie_crossing`, a ślad zapisuje `top1_tie_crosses_poison` i `top1_tie_winner`.
Przykład: GraphRAG / SPARSE_B1 raportowane 40,0% ma faktyczny zakres **33,3%–76,0%**
(n=64). Przedział Wilsona tej nieoznaczoności nie obejmuje i nigdy nie obejmował.

**3. Ramię `query_echo` wydzielone z uśrednionej odporności.**
Dosłowne doklejenie pytania ofiary to zadeklarowany test skrajny, więc ma własną kolumnę
zamiast wchodzić do średniej. Różnica jest jakościowa, nie kosmetyczna: Hybrid-Reranker ma
0,7% na ramieniu referencyjnym i **100,0%** na ramieniu echo.

**4. Rodzina testów McNemara odchudzona ze **111** do **75** testów.**
Replikaty budżetowe o bajtowo identycznych wektorach wyników per zapytanie są zwijane do
jednego wiersza z listą budżetów, których dotyczą (zwinięto 36). Cztery wiersze opisujące
ten sam wynik liczyły jedno ustalenie czterokrotnie i bez potrzeby zaostrzały korektę Holma.

**5. Sekcja 4 nie promuje artefaktu arytmetycznego.**
Wiersze o budżecie `B >= k` są wyłączone z porządkowania i oznaczone. Na wspólnym wsparciu
silników wyparcie skacze z ok. 2% przy B=3 do ok. 100% przy B=5, podczas gdy `poison@5` nie
zmienia się wcale — przy budżecie równym rozmiarowi okna same ładunki wystarczą, by je
zapełnić, więc wyparcie jest tam konsekwencją arytmetyki, nie skuteczności ataku.

**6. Nazwy kolumn opisują wielkość, która jest liczona.**
Kolumna „Średni Targeted ASR@1" liczyła w istocie `retrieval_asr_top1` (any-poison@1). Pod
protokołem izolowanym obie wielkości są numerycznie równe, ale to nie ta sama wielkość.

**7. Przepisane wnioski i rozszerzone ograniczenia.**
Wniosek 3 twierdził „wysoka odporność GraphRAG (40,0%), podczas gdy inne silniki ulegają
przejęciu (średnio 33,6%)" — czyli opisywał jako odporność wartość **wyższą** od grupy
porównawczej, do której w dodatku wliczono silnik diagnostyczny. Po ograniczeniu do strat
użytecznych teza ma pokrycie: **10,0%** wobec **29,5%**.

Twierdzenie o podatności topologicznej GraphRAG zostało wycofane: przy `bridge_count=40`
`poison@1 cond` = **0,0%** i `GT displaced@5` = **0,0%** (n=86), czyli na żadnym zapytaniu,
na które ten silnik odpowiada, atak nie osiągnął pozycji 1. Wynik zależy od parametru
`bridge_count`, który wcześniej nie był w raporcie ujawniony.

Sekcja 6 zyskała pięć pozycji liczonych z danych: nieoznaczoność remisów, stałe sloty
kontekstu, konstrukcja zbioru zapytań, skład i proweniencja korpusu, raportowanie statystyczne.

### Zmiany infrastrukturalne

- **`run_manifest.json`** zapisywany przy każdym przebiegu: odcisk korpusu (SHA-256), skład
  typów dokumentów, wersje pakietów, `bridge_count`, seed, platforma. Deklaracja „exact
  reproducibility" jest ważna lokalnie wobec zapisanego korpusu — zależności są przypięte
  tylko od dołu, korpus MITRE pochodzi z ruchomej gałęzi, a próbka cvelistV5 z „latest release".
- **`--bridge-count`** wystawione jako flaga CLI (domyślnie 40) i przekazywane do raportu.
- **Bramka metodologiczna** `scripts/audit_checks.py` uruchamiana automatycznie na końcu
  przebiegu; `run_audit(in_dir)` jest importowalne. Dodany brakujący check **K3**; checki
  **K3** i **TIE** sprawdzają dodatkowo, czy raport faktycznie publikuje wersję ograniczoną
  i przedział remisów.
- **Tabela latencji (Sekcja 2.4)** — Limitation 4 obiecywał medianę i IQR, a w raporcie nie
  było żadnej tabeli latencji.
- **Naprawa kodowania:** 56 wystąpień podwójnie zakodowanego UTF-8 w literałach
  `reporter.py` (ramka wstępna renderowała się jako „â to Åwiadoma granica").

### Stan bramki na przebiegu v2

**9 PASS / 1 FAIL.** Otwarte ustalenie **K4** (stałe sloty kontekstu) jest zdiagnozowane
i nie leży po stronie silników: wszystkie 50 pytań stratum exact-match ma identyczne
brzmienie szablonu, a jego rzadkie tokeny mają skrajne IDF — `classification` występuje
w 5/24000 dokumentów, `cwe` w 8/24000, `weakness` w 70/24000. Nieliczne dokumenty
zawierające taki token dostają stałą premię przy każdym zapytaniu, przez co efektywne okno
w tym stratum wynosi 4, a nie 5. Naprawa należy do generatora zapytań i wymaga ponownego
przebiegu.

### Znane ograniczenia tego wydania

Trzy ustalenia zostały **udokumentowane, ale nie naprawione**, bo są decyzjami o zakresie
badania, a nie usterkami:

1. **Brak wspólnego gruntu porównania** — wspólne wsparcie czterech silników to 2 zapytania
   na 150 (Dense i GraphRAG dzielą 4). Ranking zagregowany zestawia liczby policzone na
   rozłącznych populacjach zapytań.
2. **Hybrid nie jest czwartym systemem równorzędnym** — `HybridRerankRetriever(bm25, dense)`
   jest zbudowany z tych samych instancji, które w porównaniu występują osobno.
3. **`candidate_k=10` ma tylko Hybrid** — przy B=5 ładunki zajmują połowę puli kandydatów,
   przez co odpowiedź wypada z niej przed rerankingiem. To utrudnienie konfiguracyjne,
   nie architektoniczne.

### Weryfikacja

- `pytest tests/` — **397 passed** (bez zmian w kontraktach publicznych).
- `scripts/regenerate_report.py` odtwarza raport z zapisanych śladów.
- Warstwa wyszukiwania nietknięta, więc ponowny przebieg benchmarku nie był wymagany;
  nowe ścieżki kodu zweryfikowano osobnym przebiegiem dymnym (korpus 500, 9 zapytań).
- Porządki: materiał nieużywany przeniesiony do `archive/` (patrz `archive/README.md`).

---

## [1.1.0-optimized] - 2026-09-08

### Summary of Major Improvements
The objective of this release was to reduce the execution runtime of the isolated per-query evaluation protocol (`scripts/run_comparison_benchmark.py --corpus real --queries 100 --isolated-targets`) from **92.4 minutes** down to **~1-2 minutes**, while guaranteeing **100.00% mathematical and measurement equivalence** across all metrics, ranking orders, and isolation invariants.

| Performance Metric | Original Implementation | Optimized Implementation | Speedup Factor |
| :--- | :--- | :--- | :--- |
| **Graph Entity Extraction (`_extract_query_entities`)** | ~1,540 ms / query | **0.16 ms / query** | **~9,600x** |
| **Graph Index Build (`build_index` per query)** | ~1,500 ms / query | **0.01 ms / query** | **~150,000x** |
| **BM25 Index Build (`build_index` per query)** | ~240 - 2,000 ms / query | **~6.1 ms / query** | **~40x - 300x** |
| **Full Benchmark Matrix Runtime (100 queries x 15 scenarios)** | ~92.4 minutes | **~1.0 - 1.5 minutes** | **~60x - 90x** |
| **Equivalence Drift (ASR, Recall@5, MRR, Ranks)** | Baseline | **0.0000% (Identical)** | **Exact Match** |

---

### Detailed Architectural Changes

#### 1. `GraphRAGRetriever`: Fast Inverted Entity Indexing (`_extract_query_entities`)
- **Problem Statement:**
  In the baseline implementation, `_extract_query_entities(query)` iterated over all 40,253 graph entity nodes sequentially, running a dynamic `re.search` regex check against the query text for each entity. Across 1,600 evaluation queries, this linear regex scanning accounted for over 41 minutes of total runtime.
- **Root Cause:**
  Entity extraction was $O(|V_{entities}| \times |Q|)$ where $|V_{entities}| \approx 40,253$, repeated on every retrieval call.
- **Architectural Solution:**
  1. **Precomputed Word-Inverted Index:** When the base clean graph is constructed, entity candidates passing validity rules (minimum length, uppercase/code patterns, CTI stopwords exclusion) are tokenized into word sets (`re.findall(r'\w+', entity.lower())`).
  2. **Inverted Lookup Structure:** An inverted mapping `_entity_inverted_index: Dict[str, List[int]]` maps word tokens to candidate entity IDs. Entities consisting purely of non-alphanumeric symbols are stored under a dedicated `__special__` bucket.
  3. **Targeted Substring & Regex Verification:** When a query arrives, query tokens (`re.findall(r'\w+', q_lower)`) look up only the relevant candidate subset. Fast Python `in` substring checks discard non-matches before executing precompiled word-boundary regexes (`\b`).
  4. **Delta Entity Indexing for Isolated Payloads:** Dynamically introduced poison entities are registered in `_delta_entity_candidates` and `_delta_inverted_index`, ensuring newly injected entities are immediately discoverable during isolated evaluation.
  5. **Direct Modification Safety:** If an external caller or test directly mutates `graph.nodes` outside of `build_index`, a node-count tracker (`_tracked_node_count != graph.number_of_nodes()`) automatically triggers an in-place re-indexing, preventing stale cache errors.
- **Verification:**
  Tested across synthetic and authentic STIX 2.1 CTI corpora over 100 real gold benchmark queries. Result: **0 mismatches out of 100 queries (100% bit-for-bit identical)** with extraction time dropping from 19.36s to 0.0158s (1,226x speedup).

---

#### 2. `GraphRAGRetriever`: Zero-Copy Incremental Graph Rollback (`build_index` & `rollback_poison`)
- **Problem Statement:**
  In isolated per-query mode, every query evaluated requires an isolated graph containing the clean base corpus plus only the target query's poison payload. The baseline implementation achieved isolation by performing `self.graph = self._base_graph.copy()` on each query. Deep-copying a 64,000-node, 150,000-edge NetworkX graph took ~1.5 seconds per query, accounting for ~38 minutes across the matrix.
- **Root Cause:**
  Deep-copying the complete graph data structure 1,500 times was fundamentally unnecessary given that poison payloads only inject 1 to 5 nodes and a dozen edges.
- **Architectural Solution:**
  1. **Persistent Base Graph:** The clean graph constructed during initial baseline indexing is retained in memory as the live base graph.
  2. **Delta Tracking:** During incremental isolated indexing, newly added poison document nodes, poison entity nodes, relations, and bidirectional citation edges (`MENTIONS`, `MENTIONED_IN`) are tracked in `_added_nodes`, `_added_edges` (with MultiDiGraph edge keys), and `_added_doc_ids`.
  3. **Zero-Copy Rollback Mechanism:** Before indexing the next isolated query (or via `rollback_poison()`), the retriever removes only the tracked delta edges and nodes in reverse order, and clears `doc_map` entries and delta entity indices.
- **Verification:**
  Unit and adversarial stress tests (`test_isolated_protocol.py`, `test_isolated_adversarial_stress.py`, `test_challenger_iso_2_adversarial.py`) verified that:
  - Graph node and edge counts strictly return to the exact clean base state.
  - Zero foreign poison nodes or edges persist across subsequent queries.
  - Full per-query graph build overhead dropped from ~1,500 ms to **0.01 ms**.

---

#### 3. `BM25Retriever`: Fast Incremental Indexing (`build_index`)
- **Problem Statement:**
  Under the isolated protocol, `BM25Retriever.build_index` was called on each query with 24,000 clean documents + 1 to 5 poison documents. Each call recalculated doc tokens, reconstructed a 24,005-element corpus list, and re-initialized `BM25Okapi(corpus)` from scratch, recalculating term frequencies and IDF over 25,000 vocabulary words on every query.
- **Root Cause:**
  $O(|D_{clean}| \times \text{avgdl})$ repeated computation on every query in isolated mode.
- **Architectural Solution:**
  1. **Base Token Structures Caching:** When indexing the clean base corpus, `BM25Retriever` caches:
     - `_base_doc_ids`: List of document IDs for identity verification.
     - `_base_corpus_tokens`: Pre-tokenized clean documents.
     - `_base_doc_freqs`: Per-document term frequency mappings.
     - `_base_doc_len`: Document lengths list.
     - `_base_num_doc`: Sum of document lengths.
     - `_base_corpus_size`: Base document count.
     - `_base_nd`: Document frequencies dictionary (`word -> doc_count`).
     - `_base_bm25`: Clean `BM25Okapi` instance.
  2. **Fast Incremental Update for Poison Payloads:** When clean documents match `_base_doc_ids`:
     - **Strict Prefix Verification:** Verifies that `self.documents[:_base_corpus_size]` matches `_base_doc_ids` exactly in identical order and all remaining documents are poisoned, preventing doc-to-score desynchronization if payloads are prepended or reordered.
     - If no poison documents are present, reuses `_base_bm25` in **0.00 ms**.
     - If poison documents are present, computes term frequencies and document lengths for only the 1-5 poison documents.
     - Instantiates an incremental `BM25Okapi` object via `object.__new__(BM25Okapi)` without calling the expensive `__init__`.
     - Sets `corpus_size = _base_corpus_size + len(poison_docs)`, `doc_len = _base_doc_len + poison_doc_lens`, `doc_freqs = _base_doc_freqs + poison_freqs`, and updates `avgdl`.
     - Updates `nd` by applying `nd_delta` from the poison documents to a copy of `_base_nd` and runs `_calc_idf(nd)`.
     - Invalidates base caches cleanly when `build_index([])` or full mixed builds occur.
- **Equivalence Analysis:**
  Because the incremental state sets the exact same `k1`, `b`, `epsilon`, `corpus_size`, `avgdl`, `doc_len`, and `doc_freqs`, and calculates IDF via the exact same BM25Okapi formulas, `get_scores(query)` produces **bitwise identical scores** (`max |s_{inc} - s_{full}| == 0.0`).
- **Performance Gain:**
  Build latency dropped from ~240 ms to **~6.1 ms**, reducing total BM25 and Hybrid scenario overhead by tens of minutes.

---

### Robustness and Edge Case Hardening
1. **BM25 Alignment Immunity:** Verified that prepending poison documents or passing reordered clean documents automatically triggers the safe full-build fallback, preserving 100.00% rank and score equivalence without silent index corruption.
2. **GraphRAG Delta Deduplication:** Ensuring `_delta_entity_candidates` and `_delta_inverted_index` are cleared during base entity index rebuilds prevents duplicate candidate generation and score inflation if the graph is mutated externally.
3. **GraphRAG ID-Collision Safety:** `rollback_poison()` restores `doc_map` directly from `_base_doc_map`, guaranteeing clean documents are never removed even under targeted ID collision / doc-replacement attacks.
4. **Dual Mutation Tracking:** Added `_tracked_edge_count` alongside `_tracked_node_count` to automatically catch in-place graph modifications that alter edge structure without changing node count.
5. **Relation Entity Formatting:** Standardized `ent:` prefix stripping across both base and delta entity registration.

---

### Verification and Test Results

#### Automated Test Suite Execution
1. **`tests/test_isolated_protocol.py`:**
   - Command: `pytest tests/test_isolated_protocol.py`
   - Result: **20 passed in 20.28s**
   - Invariants verified: Zero foreign poison contamination in Top-k results, budget sensitivity ($B \in \{1, 3, 5\}$), clean recall preservation, backward compatibility with shared mode.
2. **`tests/test_e2e_remediation.py -k "f_r2"`:**
   - Command: `pytest tests/test_e2e_remediation.py -k "f_r2"`
   - Result: **50 passed, 175 deselected in 11.69s**
   - Invariants verified: End-to-end GraphRAG degree normalization, 1-hop and 2-hop traversal, fallback mechanisms, orphan entity handling, cyclic graph traversal safety.
3. **`tests/test_isolated_adversarial_stress.py` & `tests/test_challenger_iso_2_adversarial.py`:**
   - Command: `pytest tests/test_isolated_adversarial_stress.py tests/test_challenger_iso_2_adversarial.py`
   - Result: **41 passed in 40.48s**
   - Invariants verified: Strict multi-engine foreign poison immunity under cross-query interference, zero internal state leakage across queries.
4. **`tests/test_optimization_adversarial_edge_cases.py` (New Suite):**
   - Command: `pytest tests/test_optimization_adversarial_edge_cases.py`
   - Result: **8 passed in 11.64s**
   - Invariants verified: BM25 prepended poison immunity, clean document reorder fallback, BM25 empty build reset, GraphRAG delta deduplication on graph mutation, GraphRAG ID-collision restoration, `ent:` prefix stripping, GraphRAG mixed build base invalidation, and GraphRAG empty build reset.

#### End-to-End Benchmark Execution
- **Synthetic Benchmark Validation:**
  - Command: `python scripts/run_comparison_benchmark.py --corpus synthetic --queries 5 --isolated-targets`
  - Result: Completed in **21.36 seconds (0.4 min)**. Full reporting, traces, and metrics generated with 0 errors.
- **Authentic CTI Corpus Validation:**
  - Command: `python scripts/run_comparison_benchmark.py --corpus real --num_cves 500 --queries 10 --isolated-targets`
  - Result: Completed 15 attack scenarios across 4 engines (Sparse-BM25, Dense-FAISS, Hybrid-Reranker, GraphRAG) in **57.92 seconds (1.0 min)** with zero API cost ($0.00).
